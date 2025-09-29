{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module:      OAuth
-- Copyright:   (c) DPella AB 2025
-- License:     LicenseRef-AllRightsReserved
-- Maintainer:  <matti@dpella.io>, <lobo@dpella.io>
--
-- OAuth 2.1 server implementation module.
--
-- This module combines all OAuth endpoints into a single API type
-- and provides the server implementation that routes requests to
-- the appropriate handlers.
module OAuth (OAuthAPI, oAuthAPI, mkDefaultRefreshTokenPersistence) where

import Control.Concurrent.MVar (MVar)
import OAuth.AuthorizeAPI
import OAuth.AuthorizeCallbackAPI
import OAuth.MetadataAPI
import OAuth.RegisterAPI
import OAuth.TokenAPI
import OAuth.Types
import Servant
import Servant.Auth.Server

-- | Combined OAuth 2.1 API type.
--
-- Includes all OAuth endpoints:
-- * Metadata discovery endpoint
-- * Authorization endpoint
-- * Authorization callback endpoint
-- * Token exchange endpoint
-- * Dynamic client registration endpoint
type OAuthAPI = MetadataAPI :<|> AuthorizeAPI :<|> AuthorizeCallbackAPI :<|> TokenAPI :<|> RegisterAPI

-- | OAuth server implementation.
--
-- Takes an MVar containing the OAuth server state and returns
-- a Servant server that handles all OAuth endpoints. The state
-- is shared across all handlers to maintain authorization codes,
-- refresh tokens, and client registrations.
oAuthAPI
  :: ( FormAuth usr
     , ToJWT usr
     , HasContextEntry ctxt JWTSettings
     , HasContextEntry ctxt (FormAuthSettings usr)
     )
  => MVar (OAuthState usr)
  -> Context ctxt
  -> Server OAuthAPI
oAuthAPI state_var ctxt =
  handleMetadata state_var
    :<|> handleAuthorize state_var
    :<|> handleAuthorizeCallback state_var ctxt
    :<|> handleTokenRequest state_var ctxt
    :<|> handleRegister state_var
