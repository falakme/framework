# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

* Dependency upgrades: argon2 0.6 (existing password hashes still verify), ureq 3 (redirects are not followed), jsonwebtoken 10 with the `aws_lc_rs` backend, hmac 0.13 with sha2 0.11, chacha20poly1305 0.11 (a test opens a key wrapped by the old version), p256 0.14, TypeScript 7, Vite 8, `@vitejs/plugin-react` 6, and GitHub Actions `checkout` and `setup-node` v7.

## [1.1.0] - 2026-11-17

Milestones M5 to M8 and a review of the whole code base. Every publishable crate is published to crates.io at this version.

### Added

* Durable cross-app events (M5): `events/*.yaml` and `workflows/*.yaml`, event contracts in the IR with a build-time compatibility check, the outbox and inbox written in the business transaction, a relay and consumer on the native runtime and on Workers (Cron Trigger), Office Events (persist before acknowledge, per-aggregate ordering, retries, dead-letter replay, saga orchestrator), Ed25519 event signing with Office-attested publisher keys, and contract-based subscriber authorisation. The FEDERATION specification is frozen at 1.0.
* AI readiness (M7b): an opt-in MCP projection that runs as the calling user through the policy engine (read-only by default; fields marked `pii: true` and encrypted fields omitted unless `FALAK_AI_EXPOSE_PII=1`), an egress allow-list (`FALAK_AI_ALLOW`) and a human approval gate for writes. `scripts/smoke/ai.sh` checks it end to end.
* GardenX (`examples/gardenx/`): orders and inventory across two apps, and `scripts/smoke/events.sh`.
* Operational maturity (M6): `falak upgrade` reports breaking changes before it applies them; two Office instances that share their keys through the database (high availability) with a failover smoke test; point-in-time restore scripts and `scripts/smoke/dr.sh`, a drill that destroys a database, restores it and reports the time taken and the data lost against the recovery targets; a hash-chained audit log that can be anchored outside the database; break-glass access with a reason, a time limit, an alert and a second approver for tier 3; vault commands to rotate an app credential and the data and key-encryption keys; service-level objectives with burn-rate alerts (`/metrics` behind `FALAK_METRICS_TOKEN`, `deploy/office/alerts.yml`); and Observatory pages in Studio.
* Heavy compute (M7a): job contracts in the schema and IR; an Office compute queue with leases, heartbeats, idempotent completion and a dead-letter queue; `falak-worker`, an outbound-only polling agent that runs each job in a non-root container or a process, with revocable worker credentials, short-lived credentials that are good for one job, and a per-job egress allow-list. `scripts/smoke/compute.sh` kills a worker mid-job and checks the job finishes once.
* Financial ledger (M8): `falak-ledger`, double-entry primitives (`transfer`, `reserve`, `capture`, `release`, `reverse`, `settle`) with checked arithmetic and currency checks; PostgreSQL execution at `SERIALIZABLE` with bounded retries, append-only tables, a deferred balance constraint and an idempotency table; `falak ledger init|import|reconcile`; tier 3 controls (sender-constrained tokens, an online check, a passkey assertion over the command hash, optional dual approval); a generic checkout saga runner over federated commands; and `scripts/smoke/ledger.sh`, a double-spend test. The primitives are not production ready, and a product built on them carries its own legal duties.
* `falak office enroll --token-env VAR` (or `FALAK_ENROLL_TOKEN`) reads the enrollment token from the environment. `--token <t>` still works and prints a warning, because it shows in the process list.
* `scripts/release/publish.py` publishes the crates to crates.io in dependency order, skips versions already there and waits out the rate limit. The "Publish crates" workflow and the release workflow use it. `--dry-run` prints the plan.

### Changed

* A list request with a filter that cannot be applied (an unknown field, or a value of the wrong type) now answers `400` with `invalid_filter`. A `page[after]` cursor that cannot be read answers `400` with `invalid_cursor`. Both were quietly ignored before.
* `falak dev` refuses to listen on an address that is not this machine. Use `falak serve` with `FALAK_HOST` to listen elsewhere (it warns that the server speaks plain HTTP). `FALAK_HOST` must be an IP address.
* An `Idempotency-Key` must be 1 to 255 characters, and keys are now kept per tenant as well as per person, method and path.
* A command is authorised as the action it performs: a `kind: delete` command needs `delete` and a `kind: create` command needs `create`. Before, every command was checked as `update`. A refused command answers as a refused delete or create does. A command is found only under the entity it is declared for.
* `GET /v1/_schema` lists only the fields the caller may read, and the `owner`, list columns and search fields that name them.
* The compose files in `deploy/office/` no longer publish plain-HTTP ports on every interface: the stack is reached through a proxy, and the high-availability file binds to `127.0.0.1` unless `OFFICE_BIND` says otherwise. Containers drop all capabilities and cannot gain new privileges.
* `falak` refuses to send a password, token or signed request to an Office URL that is not `https` (or `http` to this machine). `.falak/` is created readable by its owner only.
* `/metrics` on Office answers `404` unless `FALAK_METRICS_TOKEN` is set and not empty.
* A saga now survives Office stopping half way. Its id comes from the event that starts it, a publisher's retry starts it if the first attempt did not, and Office re-sends a step that was never stored or moves on a saga whose step was applied but never followed up. Before, such a saga could be lost or stay `running` for good.

### Security

Fixes from a review of the whole code base, most serious first. Each has a test.

**Authorisation and data access**

* A command of `kind: delete` or `kind: create` was authorised as `update`, so a person who could update a row could delete it through a command. It is now checked as the action it performs.
* A level-2 query (restricted SQL) could read a physical table by naming a `WITH` entry after it, as in `WITH docs AS (SELECT * FROM docs)`: the name was treated as a common table expression everywhere, so the table was never checked as an entity. A `WITH` name is now in scope only where SQL puts it, and quoting is compared the way PostgreSQL does.
* `GET /v1/_schema` listed fields the caller may not read, with their types and flags. It now lists only the readable ones.
* List filters that could not be applied (an unknown field, a value of the wrong type) were dropped, so the answer held rows the caller had asked to leave out. They are now refused. An unknown field answers the same as one the caller may not read.
* MCP filter and sort arguments could be used on `pii` and encrypted fields, which showed their values by match, order and cursor even though the fields were left out of responses. They are refused, and so is any name that is not a plain field name.
* Idempotency keys were not scoped by tenant, so a person with tokens for two tenants could replay a response stored in the other. Keys are scoped by tenant, limited to 255 characters, and the in-memory store expires keys and has a ceiling.

**Identity, Office and Studio**

* A subject revoked in the feed kept its Office admin session: the session kept refreshing and still opened Office's own routes. Every Office session route now checks the feed.
* One app could take another app's event id: a second publisher sending an id already stored was told "stored" and its event was dropped. It now gets `409` (`event_id_taken`).
* Refresh tokens could be used twice by two requests at once, because the rotation did not check that the session was still active. Rotation is now one conditional update, and the loser is treated as reuse of a rotated token (every session of the person ends).
* Studio's sign-in routes accepted requests from other sites, so a page elsewhere could sign a browser in as someone else. They now check the origin. Studio's session table has a ceiling, and Studio and Office no longer follow redirects when they fetch keys or call an app, so a token or key request cannot be sent on to another host.
* Studio's sort could rank by a personal (masked) field. It cannot.
* The Office provider key fetch could be started once per request through the public exchange route when the provider was down. Fetches are rate limited even when they fail. Tokens are checked for "not before".
* Office compute: a lease must be held by the calling worker and still be leased, ids from the path are checked, and the list of job kinds is bounded.
* The key file is written through a fresh, exclusive temporary file with mode `0600`, so a planted symlink is not followed and the secret is never readable by others, not even briefly. The same is done for the Office link (`office.json`) and the app key.

**URLs and outbound requests**

* "https or localhost" checks accepted `http://localhost:80@evil.example`, which names `evil.example`. The check in Office, Studio, the federation client and the CLI now requires a port and a path after the host.
* The egress check missed IPv6 addresses that name private IPv4 hosts (`::7f00:1`, `::a9fe:a9fe`), NAT64 and IETF assignment ranges. They are refused. One trailing dot on a host name is accepted and two are not.
* The worker's egress broker took the job's `method` and headers as they came: a method with a line break, or a `Host` or `Content-Length` header, could reframe the request. It allows the six usual methods, drops framing headers, and limits line length, header count, body size and open connections.
* The federation client and the Office key fetch do not follow redirects.

**Storage, files and data integrity**

* A transaction dropped without commit returned an open connection to the pool, carrying one request's tenant settings (PostgreSQL) or leaving later writes inside it (SQLite). Dropping it now closes the connection, and a row that cannot be converted rolls the transaction back.
* An uploaded file could be swapped after the content check, because the upload address stays valid. The size and content type are checked again on the copy that the client can no longer change, and a mismatch deletes both copies.
* Audit log truncation was not detected: removing the oldest entries left a chain that verified. A log that does not start at entry 1 now fails verification, and PostgreSQL refuses `TRUNCATE` on the audit table as it does `UPDATE` and `DELETE`. Hash text with a sign is no longer accepted as a hash.
* Ledger sums could overflow `bigint` for an account that only collects debits, which made every command on it fail. Sums are clamped. The ledger refuses to grant to the role `public` or a `pg_` role.
* Names in generated SQL are quoted with embedded quotes doubled, and migrations refuse an IR whose entity, table or field names are not plain names.
* A timestamp with a huge year or a negative part overflowed instead of being refused.
* Request ids from callers are limited to 128 plain characters before they reach logs and events.
* AI approvals: a person may have at most 50 proposals waiting, a proposal body is limited to 64 KiB, and expired ones are dropped.

**Workers, CLI, install and deployment**

* Worker image, name and id were passed to the container engine as they came: an image that began with `-` was read as an option such as `--privileged`, and an id could climb out of the scratch directory. They must be plain values. The job credential is no longer on the `docker run` command line.
* The CLI sent credentials to plain `http` Office URLs and put values taken from the command line into URL paths and a generated `wrangler` file. It refuses plain `http` (except to this machine) and accepts only plain app names, request ids and Cloudflare account ids. Enrollment tokens can come from the environment.
* Compose files published plain-HTTP ports on all interfaces (see "Changed").
* `scripts/install.sh` downloads over `https` only, accepts only a release tag as `FALAK_VERSION`, matches the checksum line by exact file name and takes only the three programs out of the archive.
* The PostgreSQL backup scripts create files readable by their owner only; the restore script no longer reports success when `pg_restore` failed and no longer skips an archive that has no checksum without saying so; the point-in-time restore script refuses quotes in its arguments.
* CI jobs no longer keep the repository token in the checkout.

**Dependencies**

* RUSTSEC-2026-0387 (`crypto-bigint`) is resolved by moving `falak-auth` to `p256` 0.14 and the crates it brings with it.

### Known limits

* Cursors are not signed. A forged `page[after]` cursor can only move the page position; it cannot read a row the caller's policy hides.
* Ledger idempotency keys are global, not per caller. Callers should prefix them (for example with the app and tenant).
* `finish_upload` must be made single-use per file id by the caller; the file flow does not remember which ids it has finished.
* `FALAK_AI_ALLOW` (the model host allow-list) has no connecting caller yet: nothing in the framework makes a model request, so it takes effect only when an app uses `falak-ai`'s egress policy.
* 1.1.0 is the first version in which all publishable crates are on crates.io (1.0.0 reached it for only five of them). `falak deploy` still needs a clone of this repository, because it builds the Worker from `crates/falak-runtime-edge`, which is not published.

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
* Install `falak-cli` (the `falak` program) from a clone of this repository, or with `scripts/install.sh`, until the crates.io release completes. `falak deploy` needs a checkout of this repository (it builds the Worker from `crates/falak-runtime-edge`, which is not published), so run it from a clone.
