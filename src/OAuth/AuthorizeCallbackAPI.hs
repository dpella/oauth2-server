{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module:      OAuth.AuthorizeCallbackAPI
-- Copyright:   (c) DPella AB 2025
-- License:     LicenseRef-AllRightsReserved
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
module OAuth.AuthorizeCallbackAPI where

import Control.Concurrent.MVar
import Control.Monad.IO.Class (liftIO)
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text qualified as T
import Data.Time.Clock
import GHC.Generics
import Network.URI (escapeURIString, isUnescapedInURIComponent)
import OAuth.Types
import Servant
import Servant.Auth.Server (AuthResult (..))
import Servant.HTML.Blaze
import Text.Blaze.Html5 qualified as H
import Text.Blaze.Html5.Attributes qualified as A
import Web.FormUrlEncoded (FromForm (..), parseMaybe, parseUnique)

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
  , login_state :: Text
  -- ^ Client's state parameter
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
      <*> parseUnique "state" f
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
    :> Post '[HTML] H.Html

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
-- The function uses meta refresh for redirects to ensure compatibility
-- with various client implementations.
handleAuthorizeCallback
  :: (FormAuth usr, HasContextEntry ctxt (FormAuthSettings usr))
  => MVar (OAuthState usr)
  -> Context ctxt
  -> LoginForm
  -> Handler H.Html
handleAuthorizeCallback state_var ctxt LoginForm{..} = do
  auth_user <- liftIO $ runFormAuth ctxt username password
  case auth_user of
    Authenticated user -> do
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
            T.unpack login_redirect_uri
              <> "?code="
              <> escapeURIString isUnescapedInURIComponent (T.unpack auth_code)
              <> "&state="
              <> escapeURIString isUnescapedInURIComponent (T.unpack login_state)

      return $ H.docTypeHtml $ do
        H.head $ do
          H.title "Redirecting..."
          H.meta H.! A.httpEquiv "refresh" H.! A.content (H.toValue $ "0; url=" <> redirect_url)
        H.body $ do
          H.p $ do
            "Redirecting to "
            H.a H.! A.href (H.toValue redirect_url) $ H.toHtml login_redirect_uri
            "..."
    _ -> do
      let redirect_url =
            "/authorize"
              <> "?response_type=code"
              <> "&client_id="
              <> escapeURIString isUnescapedInURIComponent (T.unpack login_client_id)
              <> "&redirect_uri="
              <> escapeURIString isUnescapedInURIComponent (T.unpack login_redirect_uri)
              <> "&scope="
              <> escapeURIString isUnescapedInURIComponent (T.unpack login_scope)
              <> "&state="
              <> escapeURIString isUnescapedInURIComponent (T.unpack login_state)
              <> maybe "" (\cc -> "&code_challenge=" <> escapeURIString isUnescapedInURIComponent (T.unpack cc)) login_code_challenge
              <> maybe
                ""
                (\ccm -> "&code_challenge_method=" <> escapeURIString isUnescapedInURIComponent (T.unpack ccm))
                login_code_challenge_method
              <> "&error=invalid_password"
      return $ H.docTypeHtml $ do
        H.head $ do
          H.title "Redirecting..."
          H.meta H.! A.httpEquiv "refresh" H.! A.content (H.toValue $ "0; url=" <> redirect_url)
        H.body $ do
          H.p "Invalid credentials. Redirecting back..."
