# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-16

First release: Falak Core (milestones M1 to M3) and a minimal Falak Office (M4).

### Added

**Falak Core**

* The `falak` command line: `init`, `check`, `build`, `openapi`, `sync` (TypeScript client), `serve`, `dev`, `deploy`, `tenant add`, `policy explain`, `migrate plan|apply`, `doctor`, and `office enroll|status|rotate-key`.
* The schema compiler: entities, policies, commands and queries in YAML, compiled to an IR with a content hash and `falak.lock`. OpenAPI and a typed TypeScript client are generated from it.
* The authorization engine, default deny: owner, role and authenticated rules; attribute conditions (`where`) and field masks (`fields`); relationship rules (`related`, at most three `belongs_to` steps); per-row masks in SQL; the same answer (`404`) for a row you cannot see and one that does not exist.
* Three drivers behind one contract: SQLite, PostgreSQL 16 (with row-level security generated from the policies) and Cloudflare D1.
* Two runtimes: native (`falak serve`) and Cloudflare Workers.
* Tenancy: `none`, `row`, and `database` (one SQLite file or one D1 database per tenant).
* Migrations: saved schema snapshots, in-place column changes, table rebuilds for SQLite and D1, approval for anything destructive, applied atomically under a lock.
* Local identity: Argon2id passwords, rotating refresh tokens with reuse detection, Ed25519 access tokens, a published key set (JWKS), login throttling.
* Request limits (rate, body size, time), idempotency keys, and a hash-chained audit log.
* File storage routes (`/v1/_files`) over any S3-compatible store, with signed uploads and download-as-attachment.
* Examples: Notebook, Falak.me, Academy.

**Falak Office** (`falak-office`, one binary, SQLite or PostgreSQL)

* An app registry: single-use enrollment tokens, per-app Ed25519 keys, signed app passports, signed requests from apps.
* One sign-in for many apps: a short-lived token per app, with the app as its audience, from the person's membership.
* Sign-in through any OpenID Connect provider (Clerk, Auth0, Keycloak, Zitadel, Google, Entra) by trading its ID token (ADR-0011). Passkeys and multi-factor are the provider's.
* A signed, versioned revocation feed, and signing-key rotation with overlap (no failed request during a rotation, checked under load).
* Step-up: a fresh provider sign-in gives a short-lived `step_up` role.
* What an app does when Office is unreachable, by trust tier: tier 1 keeps working; tier 2 reads but pauses writes after a limit (default 5 minutes). Both runtimes, including Workers, which save Office's state in their own database.

**Web console and install**

* Office serves a web console at `/`: first-run setup with a one-time code printed on the terminal (or `falak-office setup` for scripts), then an overview dashboard (sign-ins, app tokens, failed sign-ins, people, with bar and line charts drawn as plain SVG), Apps (single-use enrollment codes with the exact command), People, Access, Sign-in (identity provider on or off, live), Keys and revocation, Activity. No dependencies and nothing loaded from outside; strict content security policy.
* `scripts/install.sh`: installs `falak`, `falak-office` and `falak-studio` from a release after checking `SHA256SUMS`.
* An image with Office and Studio (`deploy/office/`), published to GHCR on each release.

**Falak Studio** (`falak-studio`)

* One admin interface for every app, generated from each app's `GET /v1/_schema` and its `admin:` metadata. No code of its own for any app.
* Backend for frontend: an `HttpOnly`, `SameSite=Strict` cookie, CSRF header, same-origin check, strict content security policy.
* Personal data masked on the server, shown only by a separate audited call. Every sign-in, write and reveal goes to a hash-chained log with no values in it.
* Reaches data only through each app's own API, with an Office token for that app, so the app's policies decide.

### Specifications

SCHEMA, AUTHORIZATION (stages 1 to 3), DRIVER and API are frozen at 1.0 (ADR-0009, ADR-0010). FEDERATION is a candidate (Candidate 1) and is frozen with this release.

### Known limits

* Tier 3 (online check per sensitive command) is not built. Office refuses tier 3 apps.
* Office is one instance. Sessions and signing keys are per instance.
* Studio search is an exact match on the first search field.
* `/v1/_files` answers `501` on Workers.
* The edge runtime is 800 KiB gzipped (budget 900 KiB).
* Not tried: sign-in through Clerk or Auth0 themselves. It is checked against Dex, an independent OpenID Connect server. Clerk's default session value has no email: add it as a custom claim.
* No hosted Office exists yet: the container image is built and started in CI, but the project has not deployed it anywhere.
* Published to crates.io: `falak-cli` (the `falak` program), `falak-office`, `falak-studio` and the libraries they use. `falak deploy` needs a checkout of this repository (it builds the Worker from `crates/falak-runtime-edge`, which is not published), so run it from a clone.
