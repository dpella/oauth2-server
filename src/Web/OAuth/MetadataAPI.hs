{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module:      Web.OAuth.MetadataAPI
-- Copyright:   (c) DPella AB 2025
-- License:     LicenseRef-AllRightsReserved
-- Maintainer:  <matti@dpella.io>, <lobo@dpella.io>
--
-- OAuth 2.1 Authorization Server Metadata Endpoint.
--
-- This module implements the OAuth 2.1 Authorization Server Metadata
-- endpoint as defined in RFC 8414. It provides clients with information
-- about the authorization server's capabilities and endpoints.
--
-- The metadata helps clients discover:
-- * Authorization and token endpoints
-- * Supported grant types and response types
-- * Authentication methods
-- * PKCE support
-- * Available scopes
module Web.OAuth.MetadataAPI where

import Control.Concurrent.MVar
import Control.Monad.IO.Class (liftIO)
import Data.Aeson
import Data.Text (Text)
import Data.Text qualified as T
import GHC.Generics
import Network.URI
import Servant
import Web.OAuth.Types

-- | OAuth 2.1 Authorization Server Metadata structure.
--
-- This structure contains all the metadata fields defined in RFC 8414
-- that are relevant for the DPella OAuth implementation.
data OAuthMetadata = OAuthMetadata
  { issuer :: Text
  -- ^ The authorization server's issuer identifier
  , authorization_endpoint :: Text
  -- ^ URL of the authorization endpoint
  , token_endpoint :: Text
  -- ^ URL of the token endpoint
  , registration_endpoint :: Text
  -- ^ URL of the dynamic client registration endpoint
  , grant_types_supported :: [Text]
  -- ^ List of supported OAuth 2.1 grant types
  , response_types_supported :: [Text]
  -- ^ List of supported response types
  , token_endpoint_auth_methods_supported :: [Text]
  -- ^ List of client authentication methods supported at token endpoint
  , code_challenge_methods_supported :: [Text]
  -- ^ List of PKCE code challenge methods supported
  , scopes_supported :: [Text]
  -- ^ List of supported scope values
  }
  deriving (Generic, Show)

instance ToJSON OAuthMetadata

-- | Servant API type for the OAuth metadata endpoint.
--
-- The endpoint is available at @/.well-known/oauth-authorization-server@
-- as specified in RFC 8414.
type MetadataAPI = ".well-known" :> "oauth-authorization-server" :> Get '[JSON] OAuthMetadata

-- | Handle requests for OAuth server metadata.
--
-- Returns a JSON object describing the capabilities and endpoints
-- of the DPella OAuth authorization server. The metadata includes:
--
-- * Server issuer URL constructed from base URL and port
-- * All OAuth endpoints (authorize, token, register)
-- * Supported grant types: "authorization_code" and "refresh_token"
-- * PKCE support with "S256" and "plain" methods
-- * Available scopes: "read" and "write"
handleMetadata :: forall usr. MVar (OAuthState usr) -> Handler OAuthMetadata
handleMetadata state_var = do
  OAuthState{..} <- liftIO $ readMVar state_var
  let baseUrl = normalizeBaseUrl oauth_url oauth_port
      baseForPaths = stripTrailingSlash baseUrl
  return $
    OAuthMetadata
      { issuer = baseUrl
      , authorization_endpoint = appendPathSegment baseForPaths "/authorize"
      , token_endpoint = appendPathSegment baseForPaths "/token"
      , registration_endpoint = appendPathSegment baseForPaths "/register"
      , grant_types_supported = ["authorization_code", "refresh_token"]
      , response_types_supported = ["code"]
      , token_endpoint_auth_methods_supported = ["none", "client_secret_post"]
      , code_challenge_methods_supported = ["S256", "plain"]
      , scopes_supported = ["read", "write"]
      }
  where
    normalizeBaseUrl :: Text -> Int -> Text
    normalizeBaseUrl rawUrl port =
      case parseURI (T.unpack rawUrl) of
        Just uri ->
          case uriAuthority uri of
            Just auth ->
              let hasPort = not (null (uriPort auth))
                  desiredPort = if port > 0 then ":" <> show port else ""
                  authWithPort =
                    if hasPort || null desiredPort
                      then auth
                      else auth{uriPort = desiredPort}
                  normalizedUri = uri{uriAuthority = Just authWithPort}
              in  T.pack (uriToString id normalizedUri "")
            Nothing -> appendPortFallback rawUrl port
        Nothing -> appendPortFallback rawUrl port

    appendPortFallback :: Text -> Int -> Text
    appendPortFallback rawUrl port =
      let portTxt = ":" <> T.pack (show port)
      in  if port <= 0 || portTxt `T.isInfixOf` rawUrl
            then rawUrl
            else
              let (prefix, suffix) = T.breakOn "/" rawUrl
              in  if T.null suffix
                    then rawUrl <> portTxt
                    else prefix <> portTxt <> suffix

    stripTrailingSlash :: Text -> Text
    stripTrailingSlash txt =
      T.dropWhileEnd (== '/') txt

    appendPathSegment :: Text -> Text -> Text
    appendPathSegment base segment =
      let (baseWithoutFragment, fragmentPart) = T.breakOn "#" base
          baseStripped =
            if T.null baseWithoutFragment
              then baseWithoutFragment
              else T.dropWhileEnd (== '/') baseWithoutFragment
          combined = baseStripped <> segment
      in  combined <> fragmentPart
