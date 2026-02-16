{- |
Module:      Web.OAuth2.Internal
Description: Project-internal surface area for testing.

This module exposes a minimal collection of internal functions
and data constructors that the test suite exercises. External
callers should treat this interface as unstable.
-}
module Web.OAuth2.Internal (
    validateScope,
    defaultLoginFormRenderer,
    LoginForm (..),
    handleAuthorizeCallback,
    handleTokenRequest,
    TokenRequest (..),
    TokenResponse (TokenResponse, access_token, token_type, expires_in, refresh_token_resp),
    TokenResponseHeaders,
    handleRegister,
    registerServer,
    handleRegistrationGet,
    handleRegistrationUpdate,
    handleRegistrationDelete,
    ClientRegistrationRequest (..),
    ClientRegistrationResponse (..),
    handleMetadata,
    OAuthMetadata (..),
) where

import Web.OAuth2.AuthorizeAPI (defaultLoginFormRenderer, validateScope)
import Web.OAuth2.AuthorizeCallbackAPI (LoginForm (..), handleAuthorizeCallback)
import Web.OAuth2.MetadataAPI (OAuthMetadata (..), handleMetadata)
import Web.OAuth2.RegisterAPI (
    ClientRegistrationRequest (..),
    ClientRegistrationResponse (..),
    handleRegister,
    handleRegistrationDelete,
    handleRegistrationGet,
    handleRegistrationUpdate,
    registerServer,
 )
import Web.OAuth2.TokenAPI (
    TokenRequest (..),
    TokenResponse (TokenResponse, access_token, expires_in, refresh_token_resp, token_type),
    TokenResponseHeaders,
    handleTokenRequest,
 )
