{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}

-- |
-- Module:      Web.OAuth.Types
-- Copyright:   (c) DPella AB 2025
-- License:     LicenseRef-AllRightsReserved
-- Maintainer:  <matti@dpella.io>, <lobo@dpella.io>
--
-- Core types and data structures for the DPella OAuth 2.1 implementation.
--
-- This module defines the fundamental types used throughout the OAuth system:
-- * Authorization codes with expiry and PKCE parameters
-- * Refresh tokens for long-lived access
-- * Client registrations with allowed grants and scopes
-- * Server state management
--
-- The types support the OAuth 2.1 authorization code flow with PKCE
-- as defined in RFC 6749 and RFC 7636.
module Web.OAuth.Types where

import Control.Concurrent.MVar (modifyMVar_, newMVar, readMVar)
import Data.Aeson (defaultOptions, omitNothingFields)
import Data.Aeson.TH (deriveJSON)
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text.Encoding qualified as TE
import Data.Time.Clock
import GHC.Generics
import Servant (Context, HasContextEntry)
import Servant.Auth.Server (AuthResult (..))
import Crypto.Random (getRandomBytes)
import Data.ByteString.Base64.URL qualified as B64URL

-- | Authorization code issued after successful authentication.
--
-- Authorization codes are short-lived (10 minutes) and single-use.
-- They must be exchanged for access tokens at the token endpoint.
data AuthCode usr = AuthCode
  { auth_code_value :: Text
  -- ^ The authorization code value
  , auth_code_client_id :: Text
  -- ^ Client that requested this code
  , auth_code_user :: usr
  -- ^ Authenticated user
  , auth_code_redirect_uri :: Text
  -- ^ Redirect URI that must match token request
  , auth_code_scope :: Text
  -- ^ Granted scope
  , auth_code_expiry :: UTCTime
  -- ^ When this code expires
  , auth_code_challenge :: Maybe Text
  -- ^ PKCE code challenge
  , auth_code_challenge_method :: Maybe Text
  -- ^ PKCE challenge method (S256 or plain)
  }

-- | Refresh token for obtaining new access tokens.
--
-- Refresh tokens are long-lived and can be used multiple times
-- to obtain new access tokens when the current one expires.
data RefreshToken usr = RefreshToken
  { refresh_token_value :: Text
  -- ^ The refresh token value
  , refresh_token_client_id :: Text
  -- ^ Client that owns this token
  , refresh_token_user :: usr
  -- ^ User associated with this token
  , refresh_token_scope :: Text
  -- ^ Maximum scope for new access tokens
  }

-- | Persistence callbacks for refresh tokens.
data RefreshTokenPersistence usr = RefreshTokenPersistence
  { persistRefreshToken :: RefreshToken usr -> IO ()
  -- ^ Persist a refresh token
  , deleteRefreshToken :: Text -> IO ()
  -- ^ Delete a persisted refresh token by its value
  , lookupRefreshToken :: Text -> IO (Maybe (RefreshToken usr))
  -- ^ Lookup a refresh token
  }

-- | Default Map-backed refresh token persistence implementation.
mkDefaultRefreshTokenPersistence :: IO (RefreshTokenPersistence usr)
mkDefaultRefreshTokenPersistence = do
  rt_st <- newMVar Map.empty
  pure
    RefreshTokenPersistence
      { persistRefreshToken = \rt -> modifyMVar_ rt_st $ \mp ->
          pure (Map.insert (refresh_token_value rt) rt mp)
      , deleteRefreshToken = \tok -> modifyMVar_ rt_st $ \mp ->
          pure (Map.delete tok mp)
      , lookupRefreshToken = \tok ->
          readMVar rt_st >>= \mp ->
            pure (Map.lookup tok mp)
      }

-- | OAuth client registration information.
--
-- Contains all metadata about a registered OAuth client including
-- allowed redirect URIs, grant types, and maximum requestable scope.
data RegisteredClient = RegisteredClient
  { registered_client_id :: Text
  -- ^ Unique registered_client identifier
  , registered_client_name :: Text
  -- ^ Human-readable registered_client name
  , registered_client_secret :: Maybe Text
  -- ^ Secret for confidential registered_clients (Nothing for public registered_clients)
  , registered_client_redirect_uris :: [Text]
  -- ^ Allowed redirect URIs
  , registered_client_grant_types :: [Text]
  -- ^ Allowed OAuth grant types
  , registered_client_response_types :: [Text]
  -- ^ Allowed OAuth response types
  , registered_client_scope :: Text
  -- ^ Maximum scope this registered_client can request
  , registered_client_token_endpoint_auth_method :: Text
  -- ^ Required auth method at token endpoint
  }
  deriving (Eq, Show)

-- | Global state for the OAuth authorization server.
--
-- Maintains all active authorization codes, refresh tokens,
-- and registered clients. This state is shared across all
-- OAuth endpoints via an MVar.
data OAuthState usr = OAuthState
  { auth_codes :: Map.Map Text (AuthCode usr)
  -- ^ Active authorization codes indexed by code value
  , refresh_token_persistence :: RefreshTokenPersistence usr
  -- ^ Persistence layer for refresh tokens
  , registered_clients :: Map.Map Text RegisteredClient
  -- ^ Registered clients indexed by client_idQ
  , oauth_url :: Text
  -- ^ Base URL for the OAuth server
  , oauth_port :: Int
  -- ^ Port for the OAuth server
  }

-- | Represents errors that can occur during the OAuth authentication process.
--
-- The 'OAuthError' type is used to capture and describe various error conditions
-- that may arise when handling OAuth flows, such as invalid credentials, expired tokens,
-- missing parameters, or network issues. Each constructor of this type provides
-- information about a specific kind of OAuth-related failure, which can be used
-- for error handling, logging, or user feedback.
data OAuthError = OAuthError
  { error :: Text
  , error_description :: Maybe Text
  , error_uri :: Maybe Text
  }
  deriving (Generic)

$( deriveJSON
    defaultOptions{omitNothingFields = True}
    ''OAuthError
 )

-- | Constructs an 'OAuthError' value with the given error message.
-- The resulting 'OAuthError' will have the provided error text,
-- and 'Nothing' for the optional description and URI fields.
oAuthError :: Text -> OAuthError
oAuthError err = OAuthError err Nothing Nothing

-- | Initialize an empty OAuth server state.
--
-- Creates a new OAuth state with no registered clients,
-- authorization codes, or refresh tokens.
initOAuthState :: forall usr. Text -> Int -> RefreshTokenPersistence usr -> OAuthState usr
initOAuthState url port rtp =
  OAuthState
    { auth_codes = Map.empty
    , refresh_token_persistence = rtp
    , registered_clients = Map.empty
    , oauth_url = url
    , oauth_port = port
    }

-- | Type alias for token values (authorization codes, refresh tokens, client IDs).
type Token = Text

-- | Generate a cryptographically secure random token.
--
-- Produces a Base64URL-encoded token derived from 32 bytes of
-- cryptographic entropy. The output is URL-safe and suitable for
-- use as authorization codes, refresh tokens, or client identifiers.
generateToken :: IO Token
generateToken = do
  bytes <- getRandomBytes 32
  pure $ TE.decodeUtf8 (B64URL.encodeUnpadded bytes)

-- | Class for verifying user credentials from username and password
class FormAuth usr where
  type FormAuthSettings usr
  runFormAuth
    :: (HasContextEntry ctxt (FormAuthSettings usr))
    => Context ctxt
    -> Text
    -> Text
    -> IO (AuthResult usr)
