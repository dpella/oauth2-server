# oauth2-server — OAuth 2.1 Authorization Server for Servant

[![Hackage](https://img.shields.io/hackage/v/oauth2-server.svg)](https://hackage.haskell.org/package/oauth2-server)

`oauth2-server` is a small, composable OAuth 2.1 authorization server for Haskell/Servant. It implements the core endpoints for authorization code with PKCE, dynamic client registration, token issuance and refresh, and discovery metadata. It integrates with `servant-auth-server` to mint JWT access tokens and lets you plug in your own username/password authentication via a simple typeclass.

This library is designed to be embedded inside your existing Servant application, mounting the OAuth routes alongside your APIs.

## Features

- OAuth 2.1 authorization code flow with PKCE (RFC 6749 + RFC 7636)
- Token endpoint with refresh token rotation
- Dynamic client registration (RFC 7591)
- Authorization server metadata discovery (RFC 8414)
- JWT access tokens via `servant-auth-server`
- Pluggable user authentication through a `FormAuth` typeclass
- In‑memory refresh token persistence by default, with an interface to plug your own store

## Endpoints

- `GET /.well-known/oauth-authorization-server` — discovery metadata
- `GET /authorize` — start authorization (renders a login form)
- `POST /authorize/callback` — handles login form submission and issues authorization codes
- `POST /token` — exchanges codes for tokens and refreshes tokens
- `POST /register` — dynamic client registration

PKCE is enforced for all clients using the authorization code grant. Use either `S256` or `plain` as the challenge method.

## Install

Add the package to your library or executable stanza:

```cabal
build-depends:
    base
  , servant
  , servant-server
  , servant-auth-server
  , blaze-html
  , text
  , aeson
  , containers
  , oauth2-server  -- this package
```

This project targets GHC 9.12 (see `cabal.project`).

## Quick Start

Below is a minimal Servant application that mounts the OAuth server. It defines a user type, a simple `FormAuth` instance, configures JWT settings, initializes the OAuth state, and serves the combined OAuth API.

```haskell
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Main where

import Control.Concurrent.MVar (newMVar)
import Data.Text (Text)
import GHC.Generics (Generic)
import Network.Wai (Application)
import Network.Wai.Handler.Warp (run)
import Servant
import Servant.Auth.Server
import Web.OAuth2 (OAuthAPI, oAuthAPI, defaultLoginFormRenderer)
import Web.OAuth2.Types

-- Your application user type and JWT instances
data User = User { userId :: Text } deriving (Show, Generic)
instance ToJWT User
instance FromJWT User

-- Plug in your authentication (username/password) logic
data MyAuthSettings = MyAuthSettings
instance FormAuth User where
  type FormAuthSettings User = MyAuthSettings
  runFormAuth _ "alice" "wonderland" = pure (Authenticated (User "alice"))
  runFormAuth _ _ _ = pure NoSuchUser

type Ctx = '[JWTSettings, MyAuthSettings]

mkApp :: IO Application
mkApp = do
  jwk <- generateKey
  let jwt = defaultJWTSettings jwk
      ctx = jwt :. MyAuthSettings :. EmptyContext

  -- In-memory refresh-token persistence (swap for your DB if needed)
  rtp <- mkDefaultRefreshTokenPersistence
  st  <- newMVar (initOAuthState @User "http://localhost" 8080 rtp defaultLoginFormRenderer)

  pure $ serveWithContext (Proxy :: Proxy OAuthAPI) ctx (oAuthAPI st ctx)

main :: IO ()
main = mkApp >>= run 8080
```

Notes:

- `initOAuthState` sets the base URL and port used in discovery metadata.
- Pass `defaultLoginFormRenderer` for the built-in login page, or supply your own `LoginFormParams -> Html` function to customise the look-and-feel.
- For production, provide a durable `RefreshTokenPersistence` (e.g. database) by implementing `persistRefreshToken`, `deleteRefreshToken`, and `lookupRefreshToken`.
- The default login page references `/static/logo.png` if present; it's optional.

## Short Tutorial

This walkthrough registers a client, runs a PKCE authorization code flow, exchanges the code for tokens, and refreshes the token. Replace placeholders as needed.

1) Register a client

```bash
curl -s http://localhost:8080/register \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "read write",
    "token_endpoint_auth_method": "none"
  }'
# => { "client_id": "client_...", ... }
```

2) Start authorization (PKCE)

For a simple demo, use `code_challenge_method=plain` and set both challenge and verifier to the same value, e.g. `testverifier`.

Open in your browser:

```
http://localhost:8080/authorize?response_type=code&client_id=CLIENT_ID\
&redirect_uri=http://localhost:3000/callback&scope=read&state=xyz\
&code_challenge=testverifier&code_challenge_method=plain
```

Log in with the credentials handled by your `FormAuth` instance (from the example above: username `alice`, password `wonderland`). You will be redirected to the `redirect_uri` with `?code=...&state=xyz`.

3) Exchange the code for tokens

```bash
curl -s http://localhost:8080/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=http://localhost:3000/callback&client_id=CLIENT_ID&code_verifier=testverifier"
# => { "access_token": "...", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "...", "scope": "read" }
```

4) Refresh the access token (rotation)

```bash
curl -s http://localhost:8080/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=refresh_token&refresh_token=REFRESH_TOKEN&client_id=CLIENT_ID"
# => { "access_token": "...", "refresh_token": "..." }
```

5) Discover server metadata (optional)

```bash
curl -s http://localhost:8080/.well-known/oauth-authorization-server | jq
```

## Key Types and APIs

- `OAuthAPI` — combined Servant API for all OAuth endpoints
- `oAuthAPI :: MVar (OAuthState usr) -> Context ctxt -> Server OAuthAPI` — server implementation
- `FormAuth usr` — plug‑in credential verification for your user type:
  - associated type `FormAuthSettings usr`
  - `runFormAuth :: Context ctxt -> Text -> Text -> IO (AuthResult usr)`
- `OAuthState usr` — holds authorization codes, client registry, refresh‑token persistence, and login form renderer
- `mkDefaultRefreshTokenPersistence` — in‑memory `RefreshToken` storage (replace in production)
- `initOAuthState` — construct initial state with base URL, port, and login form renderer
- `defaultLoginFormRenderer` — built-in login page; pass to `initOAuthState` or replace with your own
- `LoginFormParams` — parameters available to a custom login form renderer

See also:

- `tests/OAuth/FlowSpec.hs` — end‑to‑end flow covering registration, authorization, token exchange, and refresh
- `tests/OAuth/TestUtils.hs` — example `FormAuth` instance and JWT configuration

## Development

Run tests:

```bash
cabal build
cabal test
```

## Security Notes

- Always serve over HTTPS in production. Set `oauth_url` accordingly.
- Use a strong JWT signing key and appropriate token lifetimes.
- PKCE is required for authorization code exchanges. Prefer `S256` in real clients.
- The default refresh‑token store is in‑memory and not durable; implement your own for production.

## License

See `LICENSE` in this repository.
