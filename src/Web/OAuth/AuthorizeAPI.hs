{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module:      Web.OAuth.AuthorizeAPI
-- Copyright:   (c) DPella AB 2025
-- License:     LicenseRef-AllRightsReserved
-- Maintainer:  <matti@dpella.io>, <lobo@dpella.io>
--
--  OAuth 2.1 Authorization Endpoint implementation for DPella.
--
-- This module implements the OAuth 2.1 authorization endpoint that handles
-- the initial step of the authorization code flow. It presents a login form
-- to users and validates their credentials against the DPella authentication
-- system.
--
-- The authorization flow follows RFC 6749 with PKCE (RFC 7636) support for
-- enhanced security in public clients.
module Web.OAuth.AuthorizeAPI where

import Control.Concurrent.MVar
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (encode)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import Web.OAuth.Types
import Servant
import Servant.HTML.Blaze
import Text.Blaze.Html5 qualified as H
import Text.Blaze.Html5.Attributes qualified as A
import Prelude hiding (error)

-- | Servant API type for the OAuth 2.1 authorization endpoint.
--
-- Query parameters:
-- * @response_type@ - Must be "code" for authorization code flow
-- * @client_id@ - The client identifier issued during registration
-- * @redirect_uri@ - Where to redirect after authorization
-- * @scope@ - Space-delimited list of requested scopes
-- * @state@ - Opaque value to maintain state between request and callback
-- * @code_challenge@ - PKCE challenge for public clients (RFC 7636)
-- * @code_challenge_method@ - Either "S256" or "plain" for PKCE
-- * @error@ - Error message to display (used for login retry)
type AuthorizeAPI =
  "authorize"
    :> QueryParam "response_type" Text
    :> QueryParam "client_id" Text
    :> QueryParam "redirect_uri" Text
    :> QueryParam "scope" Text
    :> QueryParam "state" Text
    :> QueryParam "code_challenge" Text
    :> QueryParam "code_challenge_method" Text
    :> QueryParam "error" Text
    :> Get '[HTML] H.Html

-- | Handle OAuth 2.1 authorization requests.
--
-- This function validates the authorization request parameters and displays
-- a login form to the user. It performs the following validations:
--
-- 1. Ensures @response_type@ is "code" (only authorization code flow is supported)
-- 2. Validates that the client is registered
-- 3. Checks that the redirect URI matches one registered for the client
-- 4. Validates that requested scopes are allowed for the client
--
-- If all validations pass, it returns an HTML login form. The form will POST
-- credentials to the callback endpoint for authentication.
handleAuthorize
  :: forall usr
   . MVar (OAuthState usr)
  -> Maybe Text
  -- ^ response_type parameter
  -> Maybe Text
  -- ^ client_id parameter
  -> Maybe Text
  -- ^ redirect_uri parameter
  -> Maybe Text
  -- ^ scope parameter
  -> Maybe Text
  -- ^ state parameter
  -> Maybe Text
  -- ^ code_challenge parameter (PKCE)
  -> Maybe Text
  -- ^ code_challenge_method parameter (PKCE)
  -> Maybe Text
  -- ^ error parameter (for retry display)
  -> Handler H.Html
handleAuthorize
  state_var
  _responseType@(Just "code")
  (Just cid)
  (Just redirect_uri)
  mb_scope
  mb_state
  code_challenge
  code_challenge_method
  error_msg = do
    -- Validate client and redirect URI
    oauth_state <- liftIO $ readMVar state_var
    -- Check if it's a registered client
    case Map.lookup cid (registered_clients oauth_state) of
      Just RegisteredClient{..} ->
        -- Validate redirect URI
        if redirect_uri `elem` registered_client_redirect_uris
          then
            -- Validate scope
            if validateScope scope registered_client_scope
              then return login_form
              else badRequest "invalid_scope" "Requested scope is not allowed for this client"
          else badRequest "unauthorized_client" "Invalid redirect URI for client"
      Nothing -> authError "unauthorized_client" "Client not registered or invalid client_id"
    where
      badRequest :: Text -> Text -> Handler H.Html
      badRequest error_code desc =
        throwError err400{errBody = encode $ (oAuthError error_code){error_description = Just desc}}
      authError :: Text -> Text -> Handler H.Html
      authError error_code desc =
        throwError err401{errBody = encode $ (oAuthError error_code){error_description = Just desc}}
      scope = fromMaybe "" mb_scope
      state = fromMaybe "" mb_state
      login_form :: H.Html
      login_form = H.docTypeHtml $ do
        H.head $ do
          H.title "DPella OAuth Login"
          H.style $
            H.toHtml $
              T.unlines
                [ "body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f0f0f0; }"
                , ".login-box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); width: 300px; text-align: center; }"
                , ".logo { width: 80px; height: 80px; margin: 0 auto 1.5rem; display: block; }"
                , "h2 { margin-top: 0; margin-bottom: 1.5rem; color: #333; }"
                , "input { width: 100%; padding: 0.5rem; margin: 0.5rem 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }"
                , "button { width: 100%; padding: 0.75rem; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; margin-top: 1rem; }"
                , "button:hover { background-color: #0056b3; }"
                , ".form-group { text-align: left; }"
                , ".error-message { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem; font-size: 0.9rem; }"
                ]
        H.body $ do
          H.div H.! A.class_ "login-box" $ do
            H.img H.! A.src "/static/logo.png" H.! A.alt "DPella Logo" H.! A.class_ "logo"
            H.h2 "DPella"
            case error_msg of
              Just "invalid_password" -> H.div H.! A.class_ "error-message" $ "Invalid username or password"
              Just err -> H.div H.! A.class_ "error-message" $ H.toHtml err
              Nothing -> mempty
            H.form H.! A.method "post" H.! A.action "/authorize/callback" $ do
              H.input H.! A.type_ "hidden" H.! A.name "client_id" H.! A.value (H.toValue cid)
              H.input H.! A.type_ "hidden" H.! A.name "redirect_uri" H.! A.value (H.toValue redirect_uri)
              H.input H.! A.type_ "hidden" H.! A.name "scope" H.! A.value (H.toValue scope)
              H.input H.! A.type_ "hidden" H.! A.name "state" H.! A.value (H.toValue state)
              case code_challenge of
                Just cc -> H.input H.! A.type_ "hidden" H.! A.name "code_challenge" H.! A.value (H.toValue cc)
                Nothing -> mempty
              case code_challenge_method of
                Just ccm -> H.input H.! A.type_ "hidden" H.! A.name "code_challenge_method" H.! A.value (H.toValue ccm)
                Nothing -> mempty

              H.div H.! A.class_ "form-group" $ do
                H.input H.! A.type_ "text" H.! A.name "username" H.! A.placeholder "Username" H.! A.required ""
                H.input H.! A.type_ "password" H.! A.name "password" H.! A.placeholder "Password" H.! A.required ""

              H.button H.! A.type_ "submit" $ "Sign In"
handleAuthorize _ _ _ _ _ _ _ _ _ = throwError err400{errBody = "Missing required parameters"}

-- | Validate that the requested scope is a subset of the client's allowed scopes.
--
-- Scopes are space-delimited strings. This function checks that every scope
-- requested by the client is present in the list of allowed scopes.
--
-- >>> validateScope "read" "read write admin"
-- True
--
-- >>> validateScope "read write" "read"
-- False
validateScope :: Text -> Text -> Bool
validateScope requested allowed =
  let requested_scopes = T.words requested
      allowed_scopes = T.words allowed
  in  all (`elem` allowed_scopes) requested_scopes
