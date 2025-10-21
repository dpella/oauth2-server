# Changelog

# Unreleased
## Security
- Replaced predictable `StdGen` token generator with Base64URL-encoded output sourced from `cryptonite`'s `getRandomBytes`, ensuring authorization codes, refresh tokens, and client secrets draw from strong entropy.
- Registration endpoint now returns `client_secret` (and expiry metadata) for confidential clients so freshly issued credentials can be retrieved immediately.
## Fixed
- Authorization callback now performs RFC-compliant 303 redirects with correctly constructed `Location` headers instead of relying on HTML meta refresh, preserving existing redirect URI queries and fragments.
- Discovery metadata now preserves the configured base URL, appending the OAuth server port only when absent and constructing endpoint paths without producing malformed `host:port:port` strings.
- Token issuance no longer crashes the server on JWT signing failures; such errors now surface as OAuth `server_error` responses (HTTP 500).

# 0.2.0.0
## Changed
- Renamed the exposed module hierarchy from `OAuth` to `Web.OAuth`.
- Updated package metadata and documentation to reflect the new namespace.
