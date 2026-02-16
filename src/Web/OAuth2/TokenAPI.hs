{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module:      Web.OAuth2.TokenAPI
-- Copyright:   (c) DPella AB 2025
-- License:     MPL-2.0
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
module Web.OAuth2.TokenAPI where

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
import Web.OAuth2.Types
import Servant
import Servant.Auth.Server
import Web.FormUrlEncoded (FromForm (..))
import Prelude hiding (error)
import Data.ByteString.Char8 qualified as BS8

-- | Servant API type for the OAuth token endpoint.
--
-- Accepts form-encoded token requests and returns JSON responses
-- containing access tokens and optional refresh tokens.
type TokenAPI =
  "token"
    :> ReqBody '[FormUrlEncoded] TokenRequest
    :> Post
        '[JSON]
        (Headers '[Header "Cache-Control" Text, Header "Pragma" Text] TokenResponse)

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

type TokenResponseHeaders = Headers '[Header "Cache-Control" Text, Header "Pragma" Text] TokenResponse

-- | Handle OAuth token requests for both authorization code and refresh token grants.
--
-- For authorization code grant:
--
-- 1. Validates the authorization code exists and hasn't expired
-- 2. Verifies client_id and redirect_uri match the authorization request
-- 3. Validates PKCE code_verifier if code_challenge was used
-- 4. Issues a JWT access token and refresh token
-- 5. Deletes the used authorization code
--
-- For refresh token grant:
--
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
  -> Handler TokenResponseHeaders
handleTokenRequest state_var ctxt TokenRequest{..} = do
  let jwtCfg = getContextEntry ctxt
  result <-
    liftIO $
      modifyMVar state_var $ \state ->
        processRequest jwtCfg state
  case result of
    Left err -> throwError (attachNoStoreError err)
    Right resp -> pure (attachNoStoreHeaders resp)
  where
    attachNoStoreHeaders :: TokenResponse -> TokenResponseHeaders
    attachNoStoreHeaders resp =
      let withPragma :: Headers '[Header "Pragma" Text] TokenResponse
          withPragma = addHeader ("no-cache" :: Text) resp
      in  addHeader ("no-store" :: Text) withPragma

    attachNoStoreError :: ServerError -> ServerError
    attachNoStoreError err =
      let filtered =
            filter
              ( \ (name, _) ->
                  name /= "Cache-Control" && name /= "Pragma"
              )
              (errHeaders err)
      in  err{errHeaders = ("Cache-Control", "no-store") : ("Pragma", "no-cache") : filtered}

    processRequest
      :: JWTSettings
      -> OAuthState usr
      -> IO (OAuthState usr, Either ServerError TokenResponse)
    processRequest jwtCfg state =
      case Map.lookup client_id (registered_clients state) of
        Nothing ->
          pure (state, Left $ tokenAuthFailure "unauthorized_client" "Client not registered")
        Just client@RegisteredClient{} -> do
          authCheck <- authenticateClient client
          case authCheck of
            Left err -> pure (state, Left err)
            Right () -> processGrant jwtCfg state client

    authenticateClient :: RegisteredClient -> IO (Either ServerError ())
    authenticateClient RegisteredClient{..}
      | registered_client_token_endpoint_auth_method == "client_secret_post" =
          case (client_secret, registered_client_secret) of
            (Just provided, Just expected)
              | constTimeEq provided expected -> pure (Right ())
              | otherwise -> pure (Left $ tokenAuthFailure "invalid_client" "Invalid client secret")
            _ -> pure (Left $ tokenAuthFailure "invalid_client" "Missing client secret")
      | registered_client_token_endpoint_auth_method == "none" =
          pure (Right ())
      | otherwise =
          pure (Left $ tokenAuthFailure "invalid_client" "Unsupported client authentication method")

    processGrant
      :: JWTSettings
      -> OAuthState usr
      -> RegisteredClient
      -> IO (OAuthState usr, Either ServerError TokenResponse)
    processGrant jwtCfg state client@RegisteredClient{..}
      | grant_type `elem` registered_client_grant_types =
          case grant_type of
            "authorization_code" -> processAuthorizationCode jwtCfg state client
            "refresh_token" -> processRefreshTokenGrant jwtCfg state client
            _ -> pure (state, Left $ badTokenRequest "unsupported_grant_type" "Grant type not supported")
      | otherwise =
          pure (state, Left $ badTokenRequest "unauthorized_client" "Grant type not allowed for this client")

    processAuthorizationCode
      :: JWTSettings
      -> OAuthState usr
      -> RegisteredClient
      -> IO (OAuthState usr, Either ServerError TokenResponse)
    processAuthorizationCode jwtCfg state RegisteredClient{..} = do
      currentTime <- getCurrentTime
      case code of
        Nothing ->
          pure (state, Left $ badTokenRequest "invalid_request" "Missing authorization code")
        Just authCodeValue ->
          case Map.lookup authCodeValue (auth_codes state) of
            Nothing ->
              pure (state, Left $ badTokenRequest "invalid_grant" "Invalid authorization code")
            Just AuthCode{..}
              | currentTime > auth_code_expiry ->
                  pure (state, Left $ badTokenRequest "invalid_grant" "Authorization code expired")
              | auth_code_client_id /= client_id ->
                  pure (state, Left $ badTokenRequest "invalid_grant" "Client ID mismatch")
              | otherwise ->
                  case redirect_uri of
                    Nothing ->
                      pure (state, Left $ badTokenRequest "invalid_request" "Missing redirect_uri")
                    Just ru
                      | ru `notElem` registered_client_redirect_uris ->
                          pure (state, Left $ badTokenRequest "invalid_grant" "redirect_uri not registered for client")
                      | auth_code_redirect_uri /= ru ->
                          pure (state, Left $ badTokenRequest "invalid_grant" "Redirect URI mismatch")
                      | otherwise ->
                          let allowed_scopes = T.words registered_client_scope
                              granted_scopes = T.words auth_code_scope
                          in  if not (all (`elem` allowed_scopes) granted_scopes)
                                then pure (state, Left $ badTokenRequest "invalid_scope" "Invalid or excessive scope requested")
                                else
                                  case (auth_code_challenge, auth_code_challenge_method, code_verifier) of
                                    (Just challenge, method, Just verifier)
                                      | verifyCodeChallenge challenge method verifier -> do
                                          accessTokenResult <- issueAccessToken jwtCfg auth_code_user
                                          case accessTokenResult of
                                            Left err -> pure (state, Left err)
                                            Right accessToken -> do
                                              let refreshAllowed = "refresh_token" `elem` registered_client_grant_types
                                                  persistence = refresh_token_persistence state
                                                  cleanedState =
                                                    state
                                                      { auth_codes = Map.delete authCodeValue (auth_codes state)
                                                      }
                                              if refreshAllowed
                                                then do
                                                  newRefreshToken <- generateToken
                                                  let refreshRecord =
                                                        RefreshToken
                                                          { refresh_token_value = newRefreshToken
                                                          , refresh_token_client_id = client_id
                                                          , refresh_token_user = auth_code_user
                                                          , refresh_token_scope = auth_code_scope
                                                          }
                                                  persistRefreshToken persistence refreshRecord
                                                  pure
                                                    ( cleanedState
                                                    , Right
                                                        TokenResponse
                                                          { access_token = accessToken
                                                          , token_type = "Bearer"
                                                          , expires_in = 3600
                                                          , refresh_token_resp = Just newRefreshToken
                                                          , scope = Just auth_code_scope
                                                          }
                                                    )
                                                else
                                                  pure
                                                    ( cleanedState
                                                    , Right
                                                        TokenResponse
                                                          { access_token = accessToken
                                                          , token_type = "Bearer"
                                                          , expires_in = 3600
                                                          , refresh_token_resp = Nothing
                                                          , scope = Just auth_code_scope
                                                          }
                                                    )
                                      | otherwise ->
                                          pure (state, Left $ badTokenRequest "invalid_grant" "Invalid code verifier")
                                    _ ->
                                      pure (state, Left $ badTokenRequest "invalid_request" "PKCE required: missing code_challenge or code_verifier")

    processRefreshTokenGrant
      :: JWTSettings
      -> OAuthState usr
      -> RegisteredClient
      -> IO (OAuthState usr, Either ServerError TokenResponse)
    processRefreshTokenGrant jwtCfg state RegisteredClient{..} =
      case refresh_token of
        Nothing ->
          pure (state, Left $ badTokenRequest "invalid_request" "Missing refresh token")
        Just rtValue -> do
          let persistence = refresh_token_persistence state
          stored <- lookupRefreshToken persistence rtValue
          case stored of
            Nothing ->
              pure (state, Left $ badTokenRequest "invalid_grant" "Invalid refresh token")
            Just RefreshToken{..}
              | refresh_token_client_id /= client_id ->
                  pure (state, Left $ badTokenRequest "invalid_grant" "Client ID mismatch")
              | otherwise ->
                  let allowed_scopes = T.words registered_client_scope
                      granted_scopes = T.words refresh_token_scope
                  in  if not (all (`elem` allowed_scopes) granted_scopes)
                        then pure (state, Left $ badTokenRequest "invalid_scope" "Invalid or excessive scope requested")
                        else do
                          accessTokenResult <- issueAccessToken jwtCfg refresh_token_user
                          case accessTokenResult of
                            Left err -> pure (state, Left err)
                            Right accessToken -> do
                              newRefreshToken <- generateToken
                              let newToken =
                                    RefreshToken
                                      { refresh_token_value = newRefreshToken
                                      , refresh_token_client_id = client_id
                                      , refresh_token_user = refresh_token_user
                                      , refresh_token_scope = refresh_token_scope
                                      }
                              deleteRefreshToken persistence rtValue
                              persistRefreshToken persistence newToken
                              pure
                                ( state
                                , Right
                                    TokenResponse
                                      { access_token = accessToken
                                      , token_type = "Bearer"
                                      , expires_in = 3600
                                      , refresh_token_resp = Just newRefreshToken
                                      , scope = Just refresh_token_scope
                                      }
                                )

    issueAccessToken :: JWTSettings -> usr -> IO (Either ServerError Text)
    issueAccessToken jwtCfg user = do
      now <- getCurrentTime
      jwtRes <- makeJWT user jwtCfg $ Just (addUTCTime 3600 now)
      pure $
        case jwtRes of
          Left _ -> Left $ internalServerError "Failed to sign access token"
          Right token -> Right $ T.pack $ BSL.unpack token

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
        Nothing -> challenge == verifier
        _ -> False

    badTokenRequest :: Text -> Text -> ServerError
    badTokenRequest error_code error_description =
      oauthErrorResponse err400 error_code (Just error_description)

    tokenAuthFailure :: Text -> Text -> ServerError
    tokenAuthFailure error_code error_description =
      addAuthChallenge $
        oauthErrorResponse err401 error_code (Just error_description)

    internalServerError :: Text -> ServerError
    internalServerError message =
      oauthErrorResponse err500 "server_error" (Just message)

    addAuthChallenge :: ServerError -> ServerError
    addAuthChallenge err =
      let headerName = "WWW-Authenticate"
          challengeHeader = (headerName, BS8.pack "Basic realm=\"oauth\"")
          filteredHeaders = filter ((/= headerName) . fst) (errHeaders err)
      in  err{errHeaders = challengeHeader : filteredHeaders}
