{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module:      Web.OAuth.RegisterAPI
-- Copyright:   (c) DPella AB 2025
-- License:     LicenseRef-AllRightsReserved
-- Maintainer:  <matti@dpella.io>, <lobo@dpella.io>
--
-- OAuth 2.1 Dynamic Client Registration for DPella.
--
-- This module implements dynamic client registration as defined in RFC 7591.
-- It allows OAuth clients to register themselves programmatically with the
-- DPella authorization server.
--
-- Registered clients receive a unique client_id that must be used in all
-- subsequent OAuth flows. The registration process collects client metadata
-- including redirect URIs, grant types, and requested scopes.
module Web.OAuth.RegisterAPI where

import Control.Concurrent.MVar
import Control.Monad (forM_, when)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson
import Data.Map.Strict qualified as Map
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import GHC.Generics
import Network.URI qualified as URI
import Web.OAuth.Types
import Servant

-- | Servant API type for the OAuth dynamic client registration endpoint.
--
-- Accepts a JSON request body with client metadata and returns
-- the registered client information including the assigned client_id.
type RegisterAPI =
  "register"
    :> ReqBody '[JSON] ClientRegistrationRequest
    :> Post '[JSON] ClientRegistrationResponse

-- | Request payload for dynamic client registration.
--
-- Contains the client metadata that should be registered with
-- the authorization server. Most fields are optional and will
-- use sensible defaults if not provided.
data ClientRegistrationRequest = ClientRegistrationRequest
  { client_name :: Text
  -- ^ Human-readable name of the client
  , redirect_uris :: [Text]
  -- ^ List of allowed redirect URIs for this client
  , grant_types :: Maybe [Text]
  -- ^ OAuth grant types the client will use (default: ["authorization_code", "refresh_token"])
  , response_types :: Maybe [Text]
  -- ^ OAuth response types the client will use (default: ["code"])
  , scope :: Maybe Text
  -- ^ Space-delimited list of scopes the client may request (default: "read write")
  , token_endpoint_auth_method :: Maybe Text
  -- ^ Client authentication method at token endpoint (default: "none")
  }
  deriving (Eq, Show, Generic)

instance FromJSON ClientRegistrationRequest

instance ToJSON ClientRegistrationRequest

-- | Response returned after successful client registration.
--
-- Contains all the registered client metadata including the
-- newly assigned client_id that must be used in OAuth flows.
data ClientRegistrationResponse = ClientRegistrationResponse
  { reg_client_id :: Text
  -- ^ Unique identifier assigned to the client
  , reg_client_name :: Text
  -- ^ Registered human-readable name
  , reg_client_secret :: Maybe Text
  -- ^ Secret issued to confidential clients (Nothing for public clients)
  , reg_client_secret_expires_at :: Maybe Int
  -- ^ Epoch seconds when the secret expires (Nothing means unspecified)
  , reg_redirect_uris :: [Text]
  -- ^ Registered redirect URIs
  , reg_grant_types :: [Text]
  -- ^ Allowed grant types for this client
  , reg_response_types :: [Text]
  -- ^ Allowed response types for this client
  , reg_scope :: Text
  -- ^ Maximum scope this client can request
  , reg_token_endpoint_auth_method :: Text
  -- ^ Required authentication method at token endpoint
  }
  deriving (Eq, Show, Generic)

instance ToJSON ClientRegistrationResponse where
  toJSON ClientRegistrationResponse{..} =
    object $
      [ "client_id" .= reg_client_id
      , "client_name" .= reg_client_name
      , "redirect_uris" .= reg_redirect_uris
      , "grant_types" .= reg_grant_types
      , "response_types" .= reg_response_types
      , "scope" .= reg_scope
      , "token_endpoint_auth_method" .= reg_token_endpoint_auth_method
      ]
        <> maybe [] (\secret -> ["client_secret" .= secret]) reg_client_secret
        <> maybe [] (\expiry -> ["client_secret_expires_at" .= expiry]) reg_client_secret_expires_at

-- | Handle dynamic client registration requests.
--
-- This function:
--
-- 1. Generates a unique client_id with "client_" prefix
-- 2. Applies defaults for any optional parameters:
--    - grant_types: ["authorization_code", "refresh_token"]
--    - response_types: ["code"]
--    - scope: "read write"
--    - auth_method: "none"
-- 3. Stores the client registration in the OAuth state
-- 4. Returns the complete client registration details
--
-- The client_id is generated using a secure random token generator.
handleRegister :: forall usr. MVar (OAuthState usr) -> ClientRegistrationRequest -> Handler ClientRegistrationResponse
handleRegister state_var ClientRegistrationRequest{..} = do
  let default_auth_method = fromMaybe "none" token_endpoint_auth_method
  validateAuthMethod default_auth_method
  validateRedirectUris redirect_uris
  client_id <- ("client_" <>) <$> liftIO generateToken
  let default_grant_types = fromMaybe ["authorization_code", "refresh_token"] grant_types
      default_response_types = fromMaybe ["code"] response_types
      default_scope = fromMaybe "read write" scope
      -- For confidential clients, generate a secret
      secret = if default_auth_method /= "none" then Just <$> generateToken else pure Nothing
  secret' <- liftIO secret
  let new_client =
        RegisteredClient
          { registered_client_id = client_id
          , registered_client_name = client_name
          , registered_client_secret = secret'
          , registered_client_redirect_uris = redirect_uris
          , registered_client_grant_types = default_grant_types
          , registered_client_response_types = default_response_types
          , registered_client_scope = default_scope
          , registered_client_token_endpoint_auth_method = default_auth_method
          }

  liftIO $ modifyMVar_ state_var $ \s ->
    return
      s
        { registered_clients = Map.insert client_id new_client (registered_clients s)
        }

  return
    ClientRegistrationResponse
      { reg_client_id = client_id
      , reg_client_name = client_name
      , reg_client_secret = secret'
      , reg_client_secret_expires_at = fmap (const 0) secret'
      , reg_redirect_uris = redirect_uris
      , reg_grant_types = default_grant_types
      , reg_response_types = default_response_types
      , reg_scope = default_scope
      , reg_token_endpoint_auth_method = default_auth_method
      }
  where
    validateAuthMethod :: Text -> Handler ()
    validateAuthMethod method =
      when (method `notElem` ["none", "client_secret_post"]) $
        invalidMetadata "Unsupported token_endpoint_auth_method; expected \"none\" or \"client_secret_post\""

    validateRedirectUris :: [Text] -> Handler ()
    validateRedirectUris uris = do
      when (null uris) $
        invalidMetadata "redirect_uris must include at least one absolute URI"
      forM_ uris $ \uriText -> do
        parsedUri <- parseAbsolute uriText
        when (not (null (URI.uriFragment parsedUri))) $
          invalidMetadata "redirect_uris must not contain URI fragments"
        case URI.uriScheme parsedUri of
          "https:" -> ensureAuthority parsedUri
          "http:" ->
            case URI.uriAuthority parsedUri of
              Just auth
                | isLoopbackHost (URI.uriRegName auth) -> pure ()
                | otherwise -> invalidMetadata "http redirect_uris are only allowed for loopback clients"
              Nothing -> invalidMetadata "redirect_uris must include a network host component"
          _ -> invalidMetadata "redirect_uris must use https scheme"

    parseAbsolute :: Text -> Handler URI.URI
    parseAbsolute uriText =
      case URI.parseURI (T.unpack uriText) of
        Just parsed
          | not (null (URI.uriScheme parsed)) ->
              pure parsed
        _ -> invalidMetadata "redirect_uri is not an absolute URI"

    ensureAuthority :: URI.URI -> Handler ()
    ensureAuthority parsed =
      case URI.uriAuthority parsed of
        Just _ -> pure ()
        Nothing -> invalidMetadata "redirect_uri must include authority (host)"

    isLoopbackHost :: String -> Bool
    isLoopbackHost hostName =
      hostName == "localhost"
        || hostName == "127.0.0.1"
        || hostName == "[::1]"

    invalidMetadata :: Text -> Handler a
    invalidMetadata msg =
      throwError $ oauthErrorResponse err400 "invalid_client_metadata" (Just msg)
