{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module:      Web.OAuth.AuthorizeCallbackAPI
-- Copyright:   (c) DPella AB 2025
-- License:     MPL-2.0
-- Maintainer:  <matti@dpella.io>, <lobo@dpella.io>
--
-- OAuth 2.1 Authorization Callback Handler for DPella.
--
-- This module handles the POST callback from the authorization login form.
-- It validates user credentials, generates authorization codes, and redirects
-- the user back to the client application with the authorization code.
--
-- The module implements PKCE (Proof Key for Code Exchange) support as defined
-- in RFC 7636 to protect against authorization code interception attacks.
module Web.OAuth.AuthorizeCallbackAPI where

import Control.Concurrent.MVar
import Control.Monad (unless)
import Control.Monad.IO.Class (liftIO)
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Time.Clock
import GHC.Generics
import Network.URI (escapeURIString, isUnescapedInURIComponent)
import Web.OAuth.Types
import Servant
import Servant.Auth.Server (AuthResult (..))
import Servant.HTML.Blaze
import Text.Blaze.Html5 (Html)
import Web.FormUrlEncoded (FromForm (..), parseMaybe, parseUnique)
import Web.OAuth.AuthorizeAPI (validateScope)

-- | Form data submitted from the OAuth login page.
--
-- This data structure captures all the form fields from the login form,
-- including the original OAuth parameters that need to be preserved
-- throughout the authentication flow.
data LoginForm = LoginForm
  { username :: Text
  -- ^ User's login username
  , password :: Text
  -- ^ User's login password
  , login_client_id :: Text
  -- ^ OAuth client identifier
  , login_redirect_uri :: Text
  -- ^ Client's redirect URI
  , login_scope :: Text
  -- ^ Requested OAuth scopes
  , login_state :: Maybe Text
  -- ^ Client's state parameter (optional)
  , login_code_challenge :: Maybe Text
  -- ^ PKCE code challenge
  , login_code_challenge_method :: Maybe Text
  -- ^ PKCE challenge method (S256 or plain)
  }
  deriving (Eq, Show, Generic)

instance FromForm LoginForm where
  fromForm f =
    LoginForm
      <$> parseUnique "username" f
      <*> parseUnique "password" f
      <*> parseUnique "client_id" f
      <*> parseUnique "redirect_uri" f
      <*> parseUnique "scope" f
      <*> parseMaybe "state" f
      <*> parseMaybe "code_challenge" f
      <*> parseMaybe "code_challenge_method" f

-- | Servant API type for the authorization callback endpoint.
--
-- This endpoint receives the login form submission and processes
-- the authentication. It returns HTML that redirects the user
-- back to the client application.
type AuthorizeCallbackAPI =
  "authorize"
    :> "callback"
    :> ReqBody '[FormUrlEncoded] LoginForm
    :> Post '[HTML] Html

-- | Handle the authorization callback after user submits login credentials.
--
-- This function:
--
-- 1. Validates the user's credentials against the DPella authentication system
-- 2. If successful, generates a new authorization code with 10-minute expiry
-- 3. Stores the authorization code with associated PKCE parameters
-- 4. Redirects the user back to the client with the authorization code
-- 5. If authentication fails, redirects back to the login form with an error
--
-- Responses use HTTP redirects (303 See Other) with appropriate Location headers.
handleAuthorizeCallback
  :: (FormAuth usr, HasContextEntry ctxt (FormAuthSettings usr))
  => MVar (OAuthState usr)
  -> Context ctxt
  -> LoginForm
  -> Handler Html
handleAuthorizeCallback state_var ctxt LoginForm{..} = do
  auth_user <- liftIO $ runFormAuth ctxt username password
  case auth_user of
    Authenticated user -> do
      oauth_state <- liftIO $ readMVar state_var
      registeredClient <-
        case Map.lookup login_client_id (registered_clients oauth_state) of
          Nothing -> unauthorizedClient
          Just rc -> pure rc
      unless (login_redirect_uri `elem` registered_client_redirect_uris registeredClient) $
        invalidRequest "unauthorized_client" "Invalid redirect URI for client"
      unless (validateScope login_scope (registered_client_scope registeredClient)) $
        invalidRequest "invalid_scope" "Requested scope is not allowed for this client"
      case login_code_challenge of
        Nothing -> invalidRequest "invalid_request" "PKCE code_challenge required"
        Just _ -> pure ()
      let methodValid =
            maybe True (`elem` ["plain", "S256"]) login_code_challenge_method
      unless methodValid $
        invalidRequest "invalid_request" "Unsupported code_challenge_method"
      auth_code <- liftIO generateToken
      current_time <- liftIO getCurrentTime
      let expiry = addUTCTime 600 current_time
          new_auth_code =
            AuthCode
              auth_code
              login_client_id
              user
              login_redirect_uri
              login_scope
              expiry
              login_code_challenge
              login_code_challenge_method

      liftIO $ modifyMVar_ state_var $ \s ->
        return s{auth_codes = Map.insert auth_code new_auth_code (auth_codes s)}

      let redirect_url =
            buildRedirectUrl
              login_redirect_uri
              (("code", auth_code) : maybeParam "state" login_state)
      redirect303 redirect_url
    _ -> do
      let base = "../authorize"
          params =
            [ ("response_type", "code")
            , ("client_id", login_client_id)
            , ("redirect_uri", login_redirect_uri)
            , ("scope", login_scope)
            ]
              <> maybeParam "code_challenge" login_code_challenge
              <> maybeParam "code_challenge_method" login_code_challenge_method
              <> maybeParam "state" login_state
              <> [("error", "invalid_password")]
      redirect303 (buildRedirectUrl base params)
  where
    redirect303 :: Text -> Handler Html
    redirect303 location =
      throwError err303{errHeaders = [("Location", TE.encodeUtf8 location)]}

    maybeParam :: Text -> Maybe Text -> [(Text, Text)]
    maybeParam key = maybe [] (\value -> [(key, value)])

    buildRedirectUrl :: Text -> [(Text, Text)] -> Text
    buildRedirectUrl baseUri params =
      let (baseWithoutFragment, fragmentPart) = T.breakOn "#" baseUri
          fragmentSuffix =
            if T.null fragmentPart
              then ""
              else T.cons '#' (T.drop 1 fragmentPart)
          encodedParams =
            T.intercalate "&" $ fmap encodeParam params
          baseWithQuery
            | T.null encodedParams = baseWithoutFragment
            | "?" `T.isInfixOf` baseWithoutFragment = baseWithoutFragment <> "&" <> encodedParams
            | otherwise = baseWithoutFragment <> "?" <> encodedParams
      in  baseWithQuery <> fragmentSuffix

    encodeParam :: (Text, Text) -> Text
    encodeParam (key, value) =
      let pctEncode = T.pack . escapeURIString isUnescapedInURIComponent . T.unpack
      in  pctEncode key <> "=" <> pctEncode value

    invalidRequest :: Text -> Text -> Handler a
    invalidRequest errorCode errorDescription =
      throwError $ oauthErrorResponse err400 errorCode (Just errorDescription)

    unauthorizedClient :: Handler a
    unauthorizedClient =
      throwError $ oauthErrorResponse err401 "unauthorized_client" (Just "Client not registered or invalid client_id")
