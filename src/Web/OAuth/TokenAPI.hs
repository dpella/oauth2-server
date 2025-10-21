{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module:      Web.OAuth.TokenAPI
-- Copyright:   (c) DPella AB 2025
-- License:     LicenseRef-AllRightsReserved
-- Maintainer:  <matti@dpella.io>, <lobo@dpella.io>
--
-- OAuth 2.1 Token Endpoint for DPella.
--
-- This module implements the OAuth 2.1 token endpoint that exchanges
-- authorization codes for access tokens and handles refresh token requests.
--
-- The implementation supports:
-- * Authorization code grant with PKCE verification
-- * Refresh token grant for obtaining new access tokens
-- * JWT-based access tokens signed by DPella
--
-- All tokens are validated against the registered client information
-- and PKCE challenges when applicable.
module Web.OAuth.TokenAPI where

import Control.Concurrent.MVar
import Control.Monad.IO.Class (liftIO)
import Crypto.Hash (Digest, SHA256 (..), hashWith)
import Data.Aeson
import Data.ByteArray qualified as BA
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL qualified as B64URL
import Data.ByteString.Lazy.Char8 qualified as BSL
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as T
import Data.Time.Clock
import GHC.Generics
import Web.OAuth.Types
import Servant
import Servant.Auth.Server
import Web.FormUrlEncoded (FromForm (..))
import Prelude hiding (error)

-- | Servant API type for the OAuth token endpoint.
--
-- Accepts form-encoded token requests and returns JSON responses
-- containing access tokens and optional refresh tokens.
type TokenAPI =
  "token"
    :> ReqBody '[FormUrlEncoded] TokenRequest
    :> Post '[JSON] TokenResponse

-- | Token request parameters as defined in RFC 6749.
--
-- Supports both authorization code and refresh token grants.
-- The required fields depend on the grant type being used.
data TokenRequest = TokenRequest
  { grant_type :: Text
  -- ^ The type of grant being requested ("authorization_code" or "refresh_token")
  , code :: Maybe Text
  -- ^ Authorization code (required for authorization_code grant)
  , refresh_token :: Maybe Text
  -- ^ Refresh token (required for refresh_token grant)
  , redirect_uri :: Maybe Text
  -- ^ Must match the redirect_uri used in authorization request
  , client_id :: Text
  -- ^ Client identifier
  , client_secret :: Maybe Text
  -- ^ Client secret (for confidential clients, client_secret_post)
  , code_verifier :: Maybe Text
  -- ^ PKCE code verifier (required if code_challenge was used)
  }
  deriving (Eq, Show, Generic)

instance FromForm TokenRequest

-- | Token response structure as defined in RFC 6749.
--
-- Contains the access token and associated metadata.
-- Refresh tokens are only included for authorization_code grants.
data TokenResponse = TokenResponse
  { access_token :: Text
  -- ^ The access token (JWT) that can be used to authenticate requests
  , token_type :: Text
  -- ^ Type of token (always "Bearer")
  , expires_in :: Int
  -- ^ Token lifetime in seconds (3600 = 1 hour)
  , refresh_token_resp :: Maybe Text
  -- ^ Refresh token for obtaining new access tokens
  , scope :: Maybe Text
  -- ^ Granted scope (may be less than requested)
  }
  deriving (Eq, Show, Generic)

instance ToJSON TokenResponse where
  toJSON TokenResponse{..} =
    object $
      [ "access_token" .= access_token
      , "token_type" .= token_type
      , "expires_in" .= expires_in
      ]
        <> ["refresh_token" .= rt | Just rt <- [refresh_token_resp]]
        <> ["scope" .= s | Just s <- [scope]]

-- | Handle OAuth token requests for both authorization code and refresh token grants.
--
-- For authorization code grant:
-- 1. Validates the authorization code exists and hasn't expired
-- 2. Verifies client_id and redirect_uri match the authorization request
-- 3. Validates PKCE code_verifier if code_challenge was used
-- 4. Issues a JWT access token and refresh token
-- 5. Deletes the used authorization code
--
-- For refresh token grant:
-- 1. Validates the refresh token exists
-- 2. Verifies client_id matches
-- 3. Issues a new JWT access token
--
-- Access tokens are JWTs signed by DPella with 1-hour expiry.
-- Authorization codes expire after 10 minutes.
handleTokenRequest
  :: forall usr ctxt
   . (ToJWT usr, HasContextEntry ctxt JWTSettings)
  => MVar (OAuthState usr)
  -> Context ctxt
  -> TokenRequest
  -> Handler TokenResponse
handleTokenRequest state_var ctxt TokenRequest{..} = do
  state <- liftIO $ readMVar state_var
  case Map.lookup client_id (registered_clients state) of
    Just RegisteredClient{..} -> do
      let check_grant =
            if grant_type `elem` registered_client_grant_types
              then case grant_type of
                "authorization_code" -> handleAuthCode state
                "refresh_token" -> handleRefreshToken state
                _ -> badTokenRequest "unsupported_grant_type" "Grant type not supported"
              else badTokenRequest "unauthorized_client" "Grant type not allowed for this client"
      if registered_client_token_endpoint_auth_method == "client_secret_post"
        then case (client_secret, registered_client_secret) of
          (Just provided, Just expected) ->
            if provided == expected
              then check_grant
              else tokenAuthFailure "invalid_client" "Invalid client secret"
          _ -> tokenAuthFailure "invalid_client" "Missing client secret"
        else
          if registered_client_token_endpoint_auth_method == "none"
            then check_grant
            else tokenAuthFailure "invalid_client" "Unsupported client authentication method"
    Nothing -> tokenAuthFailure "unauthorized_client" "Client not registered"
  where
    getUserToken :: usr -> Handler Text
    getUserToken user = do
      let jwt_cfg = getContextEntry ctxt
      now <- liftIO $ getCurrentTime
      jwt_res <- liftIO $ makeJWT user jwt_cfg $ Just (addUTCTime 3600 now)
      case jwt_res of
        Left _ -> internalServerError "Failed to sign access token"
        Right token ->
          return $ T.pack $ BSL.unpack token

    -- \| Verify PKCE code challenge according to RFC 7636.
    --
    -- Supports both "plain" and "S256" challenge methods:
    -- \* plain: code_verifier == code_challenge
    -- \* S256: BASE64URL(SHA256(code_verifier)) == code_challenge
    --
    -- If no method is specified, defaults to "plain" for backwards compatibility.
    verifyCodeChallenge :: Text -> Maybe Text -> Text -> Bool
    verifyCodeChallenge challenge method verifier =
      case method of
        Just "S256" ->
          let verifier_bs = T.encodeUtf8 verifier
              hash = hashWith SHA256 verifier_bs :: Digest SHA256
              hash_bs = BS.pack $ BA.unpack hash
              encoded = T.decodeUtf8 $ B64URL.encodeUnpadded hash_bs
          in  encoded == challenge
        Just "plain" -> challenge == verifier
        Nothing -> challenge == verifier -- default to plain
        _ -> False

    badTokenRequest :: Text -> Text -> Handler TokenResponse
    badTokenRequest error_code error_description =
      throwError err400{errBody = encode $ (oAuthError error_code){error_description = Just error_description}}

    tokenAuthFailure :: Text -> Text -> Handler TokenResponse
    tokenAuthFailure error_code error_description =
      throwError err401{errBody = encode $ (oAuthError error_code){error_description = Just error_description}}

    internalServerError :: Text -> Handler a
    internalServerError message =
      throwError err500{errBody = encode $ (oAuthError "server_error"){error_description = Just message}}

    handleAuthCode :: OAuthState usr -> Handler TokenResponse
    handleAuthCode state = do
      current_time <- liftIO getCurrentTime
      case code of
        Nothing -> badTokenRequest "invalid_request" "Missing authorization code"
        Just auth_code -> do
          case Map.lookup auth_code (auth_codes state) of
            Nothing -> badTokenRequest "invalid_grant" "Invalid authorization code"
            Just AuthCode{..} -> do
              if current_time > auth_code_expiry
                then badTokenRequest "invalid_grant" "Authorization code expired"
                else
                  if auth_code_client_id /= client_id
                    then badTokenRequest "invalid_grant" "Client ID mismatch"
                    else case redirect_uri of
                      Nothing -> badTokenRequest "invalid_request" "Missing redirect_uri"
                      Just ru ->
                        case Map.lookup client_id (registered_clients state) of
                          Nothing -> badTokenRequest "invalid_grant" "Client not registered"
                          Just RegisteredClient{..} ->
                            if ru `elem` registered_client_redirect_uris
                              then
                                if auth_code_redirect_uri /= ru
                                  then badTokenRequest "invalid_grant" "Redirect URI mismatch"
                                  else do
                                    -- Validate scope: must be subset of allowed
                                    let allowed_scopes = T.words registered_client_scope
                                        granted_scopes = T.words auth_code_scope
                                    if all (`elem` allowed_scopes) granted_scopes
                                      then case (auth_code_challenge, auth_code_challenge_method, code_verifier) of
                                        -- OAuth 2.1: Enforce PKCE for all clients: challenge and verifier must be present
                                        (Just challenge, method, Just verifier) ->
                                          if verifyCodeChallenge challenge method verifier
                                            then generate_tokens
                                            else badTokenRequest "invalid_grant" "Invalid code verifier"
                                        _ -> badTokenRequest "invalid_request" "PKCE required: missing code_challenge or code_verifier"
                                      else badTokenRequest "invalid_scope" "Invalid or excessive scope requested"
                              else badTokenRequest "invalid_grant" "redirect_uri not registered for client"
              where
                generate_tokens = do
                  access_token <- getUserToken auth_code_user
                  new_refresh_token <- liftIO generateToken
                  liftIO $ modifyMVar_ state_var $ \s -> do
                    let refresh_token' = RefreshToken new_refresh_token client_id auth_code_user auth_code_scope
                    persistRefreshToken (refresh_token_persistence state) refresh_token'
                    return s{auth_codes = Map.delete auth_code (auth_codes s)}
                  return
                    TokenResponse
                      { access_token = access_token
                      , token_type = "Bearer"
                      , expires_in = 3600
                      , refresh_token_resp = Just new_refresh_token
                      , scope = Just auth_code_scope
                      }

    handleRefreshToken :: OAuthState usr -> Handler TokenResponse
    handleRefreshToken state = do
      let p = refresh_token_persistence state
      case refresh_token of
        Nothing ->
          badTokenRequest "invalid_request" "Missing refresh token"
        Just rt -> do
          rt_m <- liftIO $ lookupRefreshToken p rt
          case rt_m of
            Nothing ->
              badTokenRequest "invalid_grant" "Invalid refresh token"
            Just RefreshToken{..} -> do
              if refresh_token_client_id /= client_id
                then
                  badTokenRequest "invalid_grant" "Client ID mismatch"
                else case Map.lookup client_id (registered_clients state) of
                  Nothing -> badTokenRequest "invalid_grant" "Client not registered"
                  Just RegisteredClient{..} ->
                    let allowed_scopes = T.words registered_client_scope
                        granted_scopes = T.words refresh_token_scope
                    in  if all (`elem` allowed_scopes) granted_scopes
                          then do
                            -- Rotate the refresh token: generate a new one, invalidate the old one
                            new_refresh_token <- liftIO generateToken
                            access_token <- getUserToken refresh_token_user
                            liftIO $ modifyMVar_ state_var $ \s -> do
                              let new_rt = RefreshToken new_refresh_token client_id refresh_token_user refresh_token_scope
                              -- Rotate via persistence handler (Map-backed by default)
                              deleteRefreshToken p rt
                              persistRefreshToken p new_rt
                              return s
                            return
                              TokenResponse
                                { access_token = access_token
                                , token_type = "Bearer"
                                , expires_in = 3600
                                , refresh_token_resp = Just new_refresh_token
                                , scope = Just refresh_token_scope
                                }
                          else badTokenRequest "invalid_scope" "Invalid or excessive scope requested"
