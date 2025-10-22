-- |
-- Module:      Web.OAuth.Internal
-- Description: Project-internal surface area for testing.
--
-- This module exposes a minimal collection of internal functions
-- and data constructors that the test suite exercises. External
-- callers should treat this interface as unstable.
module Web.OAuth.Internal
  ( validateScope
  , LoginForm (..)
  , handleAuthorizeCallback
  , handleTokenRequest
  , TokenRequest (..)
  , TokenResponse (TokenResponse, access_token, token_type, expires_in, refresh_token_resp)
  , TokenResponseHeaders
  , handleRegister
  , registerServer
  , handleRegistrationGet
  , handleRegistrationUpdate
  , handleRegistrationDelete
  , ClientRegistrationRequest (..)
  , ClientRegistrationResponse (..)
  , handleMetadata
  , OAuthMetadata (..)
  ) where

import Web.OAuth.AuthorizeAPI (validateScope)
import Web.OAuth.AuthorizeCallbackAPI (LoginForm (..), handleAuthorizeCallback)
import Web.OAuth.MetadataAPI (OAuthMetadata (..), handleMetadata)
import Web.OAuth.RegisterAPI
  ( ClientRegistrationRequest (..)
  , ClientRegistrationResponse (..)
  , handleRegister
  , handleRegistrationDelete
  , handleRegistrationGet
  , handleRegistrationUpdate
  , registerServer
  )
import Web.OAuth.TokenAPI
  ( TokenRequest (..)
  , TokenResponse (TokenResponse, access_token, token_type, expires_in, refresh_token_resp)
  , TokenResponseHeaders
  , handleTokenRequest
  )
