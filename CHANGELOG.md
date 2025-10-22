# Changelog

# Unreleased
## Added
- Dynamic client management endpoint at `/register/{client_id}` supporting GET/PUT/DELETE for registrations authenticated via the issued `registration_access_token`.

## Security
- Token endpoint responses now include `Cache-Control: no-store` and `Pragma: no-cache`, preventing intermediaries from caching bearer tokens.
- Authorization login form no longer fabricates an empty `state` value; parameters are only echoed when provided by the client, preserving CSRF protection for state-less callers.
- Dynamic client registration now enforces absolute redirect URIs (https-only except localhost loopback) and rejects fragment-bearing or empty lists, preventing misconfigurations that lead to insecure redirects.
- Replaced predictable `StdGen` token generator with Base64URL-encoded output sourced from `cryptonite`'s `getRandomBytes`, ensuring authorization codes, refresh tokens, and client secrets draw from strong entropy.
- Registration endpoint now returns `client_secret` (and expiry metadata) for confidential clients so freshly issued credentials can be retrieved immediately.
- Authorization callback revalidates registered clients, redirect URIs, scopes, and PKCE parameters before minting authorization codes, closing the tampering vector that allowed arbitrary redirect destinations and scope escalation.
- Authorization code redemption inside the token endpoint now executes under a single state lock, preventing concurrent exchanges from reusing the same code.
- Refresh token rotation is now atomic, stopping concurrent refresh requests from returning multiple valid tokens for the same handle.
## Fixed
- Dynamic client registration omits `client_secret` and `client_secret_expires_at` when no secret is issued, matching RFC 7591 expectations.
- Registration now rejects unsupported `token_endpoint_auth_method` values instead of provisioning unusable clients.
- Token endpoint `invalid_client` responses include a `WWW-Authenticate` challenge so OAuth clients can discover the required authentication scheme.
- Authorization endpoint now emits OAuth error responses via 303 redirects to the validated `redirect_uri`, including the original `state` when present, so clients receive spec-compliant failure notifications.
- Authorization callback now performs RFC-compliant 303 redirects with correctly constructed `Location` headers instead of relying on HTML meta refresh, preserving existing redirect URI queries and fragments.
- Discovery metadata now preserves the configured base URL, appending the OAuth server port only when absent and constructing endpoint paths without producing malformed `host:port:port` strings.
- Token issuance no longer crashes the server on JWT signing failures; such errors now surface as OAuth `server_error` responses (HTTP 500).
- Discovery metadata advertises all supported token endpoint authentication methods, including `client_secret_post`, preventing metadata-driven clients from failing their confidential flows.
- Dynamic client registration accepts the RFC 7591 `scope` field and persists it, rather than silently defaulting every client to `"read write"`.
- OAuth error responses now set the `application/json` content type, allowing clients to parse structured failures reliably.
- The authorize endpoint now returns RFC-compliant `invalid_request` or `unsupported_response_type` errors when callers omit or mis-state required parameters.
- Authorization code exchanges no longer mint refresh tokens for clients that omit the `refresh_token` grant, aligning runtime behaviour with registered capabilities.
- Confidential client registrations now leave `client_secret_expires_at` unset for non-expiring secrets instead of reporting an immediately expired timestamp.
- Dynamic client registration replies with HTTP 201 Created, returning `registration_access_token` and `registration_client_uri` alongside the client metadata so RFC 7591 clients can manage their registrations.
- Authorization server metadata now reports the union of scopes registered by clients, ensuring discovery reflects dynamically configured scope values.

## Changed
- Source module headers now declare the MPL-2.0 license to match the package manifest.
- Added `Web.OAuth.Internal` to expose a stable-for-tests surface so the test suite can target internals without compiling the entire source tree.
- Restored the full suite of OAuth endpoint tests, including end-to-end flow coverage, after they were accidentally dropped during the namespace migration.

# 0.2.0.0
## Changed
- Renamed the exposed module hierarchy from `OAuth` to `Web.OAuth`.
- Updated package metadata and documentation to reflect the new namespace.
