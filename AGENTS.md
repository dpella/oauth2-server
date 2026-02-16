# Repository Guidelines

This repository implements an OAuth 2.1 authorization server as a Haskell library using Servant. Follow these concise guidelines to contribute effectively.

## Project Structure & Module Organization
- Source: `src/` (modules under `Web.OAuth2.*`, e.g., `src/Web/OAuth/TokenAPI.hs`).
- Types and state: `src/Web/OAuth/Types.hs`.
- Tests: `test/` (Tasty: unit/property and end-to-end; e.g., `test/Web/OAuth/FlowSpec.hs`, `test/Main.hs`).
- Build files: `oauth2-server.cabal`, `cabal.project`.
- Expose or list new modules in `oauth2-server.cabal` (`exposed-modules` or `other-modules`).

## Build, Test, and Development Commands
- `cabal build` — build the library and test suite.
- `cabal test` — run all tests (end-to-end flow included).
- `cabal repl oauth2-server` — open a REPL for the library (useful for quick iteration).
- Optional coverage: `cabal test --enable-coverage`.

## Coding Style & Naming Conventions
- Haskell2010 with project defaults; prefer existing extensions already enabled in `oauth2-server.cabal`.
- Indentation: 2 spaces, no tabs; keep lines ≤ 100 columns.
- Modules: `Web.OAuth2.*` (e.g., `Web.OAuth2.MetadataAPI`). One top-level export list per module.
- Names: Types in `TitleCase`; functions in `camelCase`; record fields follow existing `snake_case` pattern (e.g., `registered_client_grant_types`).
- Imports: qualified where helpful; group stdlib/external/local; avoid unused imports.

## Testing Guidelines
- Frameworks: `tasty`, `tasty-hunit`, `tasty-quickcheck`.
- Place tests under `test/Web/OAuth/*Spec.hs`; add to `other-modules` in `oauth2-server.cabal` if needed.
- Aim to cover new endpoints/branches; prefer property tests for token/PKCE helpers.
- Run `cabal test` before submitting; keep tests deterministic and hermetic (no network).

## Commit & Pull Request Guidelines
- Use Conventional Commits (recommended): `feat:`, `fix:`, `refactor:`, `test:`, `docs:`.
- PRs must include: clear description, rationale, linked issues, and tests for behavior changes.
- Update `oauth2-server.cabal` when adding/renaming modules; update README/examples if API changes.
- Keep diffs focused and minimal; avoid unrelated formatting churn.

## Security & Configuration Tips
- PKCE is required for auth code flows; prefer `S256` in examples.
- Never log secrets, tokens, or passwords; keep JWT keys out of the repo.
- The default refresh-token store is in-memory; provide a durable `RefreshTokenPersistence` in production.

## Agent-Specific Instructions
- Keep changes surgical; do not add license headers; follow the style above for any files you touch.
- Do not introduce new dependencies or language extensions without justification and consensus.

