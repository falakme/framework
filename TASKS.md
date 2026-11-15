# Falak Framework: Build Plan and Checklist

This is the working task list for building everything in [ARCHITECTURE.md](./ARCHITECTURE.md). Five developer agents (**Dev1** to **Dev5**) work on the repository in parallel. Each task has one owner, a list of tasks it needs first, and a "works when" check.

Tick a box in the same pull request that completes the task. Tick only your own tasks.

---

## 1. How "it works" is checked

The aim is working software, not a large test suite.

* **Per task:** the "works when" line. The owner demonstrates it and states the result in the pull request.
* **Per phase:** one end-to-end smoke script in `scripts/smoke/`, run by CI. A phase is done when its script passes and every box is ticked.
* **CI runs only:** format, lint, build for native and `wasm32`, and the smoke scripts.
* **Not in this plan:** the fuzzing, mutation, differential and snapshot suites described in ARCHITECTURE §6. They are deferred. Add them later if wanted.
* **Kept, because they are the product's core promises:** the wrong-user and wrong-tenant check (Phases 1 and 3), the event kill check (Phase 5) and the double-spend check (Phase 8). Each is part of its phase's smoke script.

---

## 2. Who owns what

An agent changes only the directories it owns. A change needed elsewhere is requested from that owner, or sent as a small pull request for that owner to review.

| Agent | Role | Owns |
| :-- | :-- | :-- |
| **Dev1** | Core and integration lead | `crates/falak-contracts`, `crates/falak-core`, `specifications/`, root `Cargo.toml`, CI config, phase gates in this file |
| **Dev2** | Native runtime and data | `crates/falak-runtime-native`, `crates/falak-driver-sqlite`, `crates/falak-driver-postgres`, `crates/falak-migrate`, `office/registry`, `office/events`, `office/compute` |
| **Dev3** | Edge runtime and CLI | `crates/falak-runtime-edge`, `crates/falak-driver-d1`, `crates/falak-cli`, `crates/falak-worker` |
| **Dev4** | Identity and security | `crates/falak-auth`, `crates/falak-storage`, `crates/falak-audit`, `office/identity`, `office/vault`, `SECURITY.md` |
| **Dev5** | SDK, Studio, apps and docs | `packages/`, `examples/`, `scripts/smoke/`, `docs/` |

## 3. Rules for working in parallel

1. Push small commits directly to `main`, as the project owner instructed. Run `git pull --rebase origin main` immediately before each push, and never force-push `main`. Commit only your own area (see §2).
2. `crates/falak-contracts` holds the provider traits, capability profile, IR types and error taxonomy. It is the interface between agents. Only Dev1 merges changes to it. Propose a change as a pull request labelled `contract` and wait for it before depending on it.
3. Code against the contract, not against another agent's unfinished crate. If a dependency is not ready, build against the trait with a stub and swap later.
4. Rebase on `main` before each push. On a `Cargo.lock` or `pnpm-lock.yaml` conflict, take `main`'s version and regenerate.
5. Keep commits to one task. A task that grows is split, and the new task is added here by Dev1.
6. Commit messages describe the change and carry no co-author trailers.
7. Do not start a phase's tasks before the previous phase's gate is ticked, except tasks marked *early start*.
8. The crate stubs declare no dependencies, because unused dependencies are a warning and CI treats warnings as errors. Add a dependency (including on another `falak-*` crate, via `workspace = true`) in the same pull request that first uses it. The Rust toolchain is pinned in `rust-toolchain.toml`; install it with `rustup` and run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo build --workspace` before opening a pull request.
9. Blocked for more than one working session: write the blocker under §6 and move to your next unblocked task.

## 4. Decisions needed from the project owner

Agents cannot do these. Phase 0 cannot close without the first two.

- [x] Accept or change the eight proposed decisions in ARCHITECTURE §3. *Accepted as proposed by Dev1 under discretion delegated by the owner (2026-11-15); the owner may revise by a new ADR.*
- [ ] Write the "why not existing tools" statement in ARCHITECTURE §2.
- [ ] Provide a Cloudflare account and API token for Workers and D1 (needed from T0.8).
- [ ] Provide a Coolify server and an R2 or S3 bucket (needed from Phase 3).
- [ ] Choose the OIDC provider that Office Identity wraps (needed before T4.8). Dev4 brings a recommendation.
- [ ] Take legal advice on BlockBanking (needed before Phase 8).

---

## 5. Tasks

### Phase 0: Foundation (M0)

Dev1's T0.1 and T0.3 unblock everyone. They go first; the other agents start on specs and spikes meanwhile.

**Dev1**
- [x] **T0.1** Monorepo skeleton: Cargo workspace with the crates in §2 as stubs, `packages/`, `office/`, `examples/`, `scripts/smoke/`, and CI. *Works when:* CI is green building every crate for native, and `falak-contracts` and `falak-core` for `wasm32`.
- [x] **T0.2** Write the eight ADRs into `specifications/adr/` as accepted or changed by the owner. *Needs:* owner decision. *Works when:* ARCHITECTURE §3 links to eight ADR files and no item is marked *Proposed*.
- [x] **T0.3** `falak-contracts`: provider traits, capability profile, IR types, error taxonomy. *Needs:* T0.1. *Works when:* every other crate compiles against it with stub implementations.
- [x] **T0.4** Draft `SCHEMA_SPECIFICATION.md` and JSON Schema files for each YAML file type. *Works when:* the Notebook YAML from T0.11 validates against the JSON Schemas in an editor. *Done:* the spec and four JSON Schemas are in `specifications/`, with a minimal example that validates and negative cases that are rejected; T0.11 will confirm against the Notebook fixture.

**Dev2**
- [x] **T0.5** Draft `DRIVER_SPECIFICATION.md` with capability profiles for SQLite and PostgreSQL. *Works when:* each capability in ARCHITECTURE §4.4 has a value for both drivers.
- [x] **T0.6** Draft `API_SPECIFICATION.md`: pagination, filters, error format, idempotency keys, `ETag`. *Works when:* Dev5 can write an example request and response for every Notebook operation from it.

**Dev3**
- [x] **T0.7** Verify current Cloudflare Workers and D1 limits and record them in the DRIVER spec (recorded in `specifications/CLOUDFLARE_LIMITS.md`, checked 2026-11-15; Dev2 folds it into the DRIVER spec with T0.5). *Works when:* each limit cites the vendor documentation page and the date checked.
- [ ] **T0.8** Spike: a stub of the portable core, built for `wasm32`, serving one hard-coded entity from D1 on Workers and from SQLite natively. *Needs:* T0.1, Cloudflare account. *Works when:* the same request returns the same JSON from both, and the WASM size is recorded.

**Dev4**
- [ ] **T0.9** `THREAT_MODEL.md` v1 and `SECURITY.md`. *Works when:* every boundary in ARCHITECTURE §4.7 has at least one named threat and its control.
- [ ] **T0.10** Draft `AUTHORIZATION_SPECIFICATION.md` covering ownership and roles, default deny. *Works when:* the Notebook policies from T0.11 can be written in it without ambiguity.

**Dev5**
- [x] **T0.11** Notebook app definition in `examples/notebook/` (entities, policies, commands). This is the shared fixture for Phases 1 and 2. *Works when:* Dev1 and Dev4 confirm it covers ownership, roles, a relation and one custom command.
- [ ] **T0.12** TypeScript workspace: `packages/sdk` and `packages/studio` stubs. *Works when:* `pnpm build` is green in CI.

**Gate (Dev1)**
- [ ] All Phase 0 boxes ticked, including the first two owner decisions in §4.
- [ ] The T0.8 spike result is recorded in the DRIVER spec, and any design change it forced is reflected in ARCHITECTURE.md.

---

### Phase 1: Core kernel on SQLite (M1)

Target: the Notebook app runs as one binary with no external service.

**Dev1**
- [x] **T1.1** *(early start: depends only on the schema spec)* Strict YAML parser with file, line and column diagnostics. *Works when:* a deliberately broken Notebook file reports the exact location and a suggested fix.
- [x] **T1.2** *(early start: depends only on the schema spec)* Typed AST and validation (types, relations, unknown and duplicate keys rejected). *Needs:* T1.1.
- [x] **T1.3** *(early start: depends only on the schema spec)* IR compile (`falak build`) with content hash, and `falak.lock`. *Needs:* T1.2. *Works when:* building Notebook twice gives the same hash.
- [x] **T1.4** *(early start: depends only on the schema spec)* Policy compiler for ownership and roles, producing SQL predicates, default deny. *Needs:* T1.2. *Works when:* an entity with no policy compiles to a query that returns nothing.
- [x] **T1.5** *(early start: depends only on the schema spec)* Query AST to parameterized SQL templates, with page-size, include-depth and filter limits. *Needs:* T1.3, T1.4.

**Dev2**
- [x] **T1.6** SQLite driver (WAL, `busy_timeout`, `BEGIN IMMEDIATE`, one writer and a reader pool). *Needs:* T0.3.
- [ ] **T1.7** Native runtime: REST CRUD and commands served from the IR, input validation, error format, keyset pagination, `ETag`, idempotency keys. *Needs:* T1.5, T1.6.
- [x] **T1.8** Create tables from the IR on first run (minimal `falak migrate`). *Needs:* T1.3, T1.6.
- [ ] **T1.9** Structured logs, traces, liveness and readiness endpoints, and a Litestream config. *Works when:* a restore from the Litestream replica brings back the Notebook data.

**Dev3**
- [ ] **T1.10** CLI: `init`, `check`, `build`, `dev` (watch and reload), `serve`, `doctor`. *Needs:* T1.3. *Works when:* `falak init` then `falak dev` serves a new app with no other steps.
- [x] **T1.11** OpenAPI 3.1 document generated from the IR. *Needs:* T1.3. *Works when:* the document loads in a standard OpenAPI viewer without errors.

**Dev4**
- [x] **T1.12** Local identity: sign-up, login, Argon2id, rate-limited attempts, revocable sessions, single-use reset tokens. *Needs:* T0.3.
- [x] **T1.13** Local key provider and `Ed25519` token issue and verify, with `kid` from the start. *Needs:* T0.3.
- [ ] **T1.14** Auth middleware that puts the verified subject into the request context, and secret references resolved at runtime. *Needs:* T1.7, T1.13. *Works when:* a request with a user id in a header but no valid token is rejected.

**Dev5**
- [ ] **T1.15** TypeScript SDK codegen (`falak sync`). *Needs:* T1.11.
- [ ] **T1.16** Notebook React frontend using the generated SDK. *Needs:* T1.15.
- [ ] **T1.17** `scripts/smoke/notebook.sh`: start the binary, create two users, create notes as each, and confirm each user sees only their own and gets 404 on the other's. *Needs:* T1.7, T1.14.
- [ ] **T1.18** Ten-minute quickstart in `docs/` and linked from the README. *Works when:* another agent follows it on a clean machine and reaches a running Notebook.

**Gate (Dev1)**
- [ ] `scripts/smoke/notebook.sh` passes in CI.
- [ ] Notebook runs as a single binary with no external service, and idle memory is recorded.

---

### Phase 2: Three drivers, two runtimes (M2)

Target: the same Notebook definition runs on SQLite, PostgreSQL and Workers with D1.

**Dev1**
- [ ] **T2.1** Build-time capability validator: reject an app whose needs exceed the driver's profile or limits. *Works when:* a command needing an interactive transaction fails to build for D1 with a clear message.
- [x] **T2.2** Compile read-then-write commands to a conditional batch with a version column. *Needs:* T2.1.
- [ ] **T2.3** Freeze SCHEMA, AUTHORIZATION, DRIVER and API specs at 1.0. *Needs:* Phase 2 smoke passing.

**Dev2**
- [ ] **T2.4** PostgreSQL driver: SQLx pool, one transaction per request. *early start*
- [ ] **T2.5** Docker image and compose file for Notebook on PostgreSQL. *Needs:* T2.4.

**Dev3**
- [ ] **T2.6** D1 driver: atomic batches, read-replica bookmarks. *early start*
- [ ] **T2.7** Edge runtime: `workers-rs` router serving the IR. *Needs:* T2.6.
- [ ] **T2.8** `falak deploy` for Workers, and a WASM size check in CI. *Needs:* T2.7.

**Dev4**
- [ ] **T2.9** Token verification on the edge with a cached JWKS, using WASM-compatible crypto. *Needs:* T2.7.
- [ ] **T2.10** Rate limits and request size and time limits on both runtimes.

**Dev5**
- [ ] **T2.11** Make the Notebook smoke script take a target (SQLite, PostgreSQL, Workers) and run all three in CI. *Needs:* T2.5, T2.8.
- [ ] **T2.12** SDK: typed errors, pagination helpers, automatic idempotency keys.

**Gate (Dev1)**
- [ ] The Notebook smoke script passes on all three targets with zero changes to `examples/notebook/`.
- [ ] Four specs frozen at 1.0.

---

### Phase 3: Isolation and migrations (M3)

Target: Falak.me, a multi-tenant app with file uploads.

**Dev1**
- [ ] **T3.1** Tenancy modes `none`, `row`, `database` in schema, IR and policy compiler.
- [ ] **T3.2** Attribute rules, field masks, and the side-channel rules (no filter or sort on unreadable fields, relation re-check, 404 for invisible rows). *Needs:* T3.1.
- [ ] **T3.3** Level-2 restricted SQL: build-time parser check (single, read-only, parameterized) and generated policy-filtered views for SQLite and D1.
- [ ] **T3.4** `falak policy explain` output: decision, matching rule and generated SQL. *Needs:* T3.2.

**Dev2**
- [ ] **T3.5** PostgreSQL RLS: generated policies with `USING` and `WITH CHECK`, forced RLS, non-owner runtime role, per-transaction `set_config`, build failure on a scoped table with no policy. *Needs:* T3.1.
- [ ] **T3.6** `falak migrate` for PostgreSQL and SQLite: diff, `plan`, expand and contract, advisory lock, checksums, drift detection.
- [ ] **T3.7** PostgreSQL backups to the bucket and a written restore procedure. *Works when:* a restore into an empty database is demonstrated.

**Dev3**
- [ ] **T3.8** D1 migrations, including table rebuilds. *Needs:* T3.6.
- [ ] **T3.9** `database` tenancy mode on D1 and SQLite: provisioning and routing a request to its tenant's database. *Needs:* T3.1.
- [ ] **T3.10** CLI commands `migrate plan`, `migrate apply`, `policy explain`. *Needs:* T3.4, T3.6.

**Dev4**
- [ ] **T3.11** Object storage: presigned upload and download, size and type conditions, quarantine prefix, magic-byte check, server-generated tenant-prefixed keys.
- [ ] **T3.12** Outbound allow-list with private and metadata addresses blocked after DNS resolution.
- [ ] **T3.13** Hash-chained, append-only audit log. *Works when:* editing a stored entry makes verification fail.

**Dev5**
- [ ] **T3.14** Falak.me app in `examples/falakme/`: portal, profiles, file assets, `row` tenancy.
- [ ] **T3.15** `scripts/smoke/isolation.sh`: as a user of tenant A, try every Falak.me endpoint, a level-2 query and a file download against tenant B's data, on all three drivers. All must fail. *Needs:* T3.5, T3.3, T3.11, T3.14.

**Gate (Dev1)**
- [ ] `scripts/smoke/isolation.sh` passes on all three drivers.
- [ ] A schema change to Falak.me is applied with `falak migrate` on a running app without downtime.
- [ ] Restore from backup demonstrated (T3.7).

---

### Phase 4: Minimal Falak Office (M4) and v1.0

Target: three apps share one login and one admin interface.

**Dev1**
- [ ] **T4.1** Relationship rules with bounded traversal depth.
- [ ] **T4.2** `admin:` presentation metadata in schema and IR.
- [ ] **T4.3** `FEDERATION_SPECIFICATION.md` to candidate. *Needs:* T4.5, T4.8 drafts.
- [ ] **T4.14** Release v1.0: tag, changelog, signed artefacts, SBOM. *Needs:* Phase 4 gate.

**Dev2**
- [ ] **T4.4** Office skeleton: one binary, one PostgreSQL database, built on Falak Core, deployed on Coolify.
- [ ] **T4.5** Registry: single-use enrollment tokens, asymmetric app keys, signed App Passports, `GET /v1/_office/manifest`, passport revocation. *Needs:* T4.4.

**Dev3**
- [ ] **T4.6** Federation client in both runtimes: enroll, present passport, fetch JWKS, consume the revocation feed, apply the per-tier outage behaviour. *Needs:* T4.5.
- [ ] **T4.7** CLI: `office enroll`, `office rotate-key`, `office status`. *Needs:* T4.6.

**Dev4**
- [ ] **T4.8** Office Identity wrapping the chosen OIDC provider: passkeys, per-app audiences, PKCE, refresh rotation with reuse detection. *Needs:* owner decision, T4.4.
- [ ] **T4.9** Signing-key rotation with overlap. *Works when:* a key is rotated under load with no failed request.
- [ ] **T4.10** Signed, versioned revocation feed and step-up authentication. *Needs:* T4.8.

**Dev5**
- [ ] **T4.11** Studio: admin UI generated from `admin:` metadata, backend-for-frontend with `HttpOnly` cookies, strict CSP, PII masking, audit of admin actions. Reaches app data only through each app's API. *Needs:* T4.2, T4.8.
- [ ] **T4.12** Academy app in `examples/academy/`: courses, enrollments, submissions.
- [ ] **T4.13** `scripts/smoke/office.sh`: log in once and reach Notebook, Falak.me and Academy; edit a record in two apps from Studio; rotate the signing key; stop Office and confirm each app behaves as its tier specifies. *Needs:* T4.6, T4.9, T4.11, T4.12.

**Gate (Dev1)**
- [ ] `scripts/smoke/office.sh` passes.
- [ ] Studio manages two apps with no app-specific dashboard code.
- [ ] v1.0 released (T4.14).

---

### Phase 5: Federation and durable events (M5)

- [ ] **T5.1 (Dev1)** Event contracts in schema and IR, with a build-time compatibility check between versions; saga definitions.
- [ ] **T5.2 (Dev2)** Outbox and inbox tables written in the business transaction, the native relay, retention and pruning.
- [ ] **T5.3 (Dev2)** Office Events: PostgreSQL store, persist before `ACK`, per-aggregate ordering, dead-letter replay, saga orchestrator. *Needs:* T5.2.
- [ ] **T5.4 (Dev3)** Edge relay using Cron Triggers or Queues. *Needs:* T5.2.
- [ ] **T5.5 (Dev4)** Event signing by the publisher, verification on receipt, subscriber authorisation from the contract.
- [ ] **T5.6 (Dev5)** GardenX app in `examples/gardenx/`: orders and inventory across two apps.
- [ ] **T5.7 (Dev5)** `scripts/smoke/events.sh`: place orders while killing Office Events and a consumer; after recovery, order and inventory counts match exactly. *Needs:* T5.3, T5.4, T5.6.

**Gate (Dev1)**
- [ ] `scripts/smoke/events.sh` passes on the native and edge runtimes.
- [ ] FEDERATION spec frozen at 1.0.

---

### Phase 6: Operational maturity (M6)

- [ ] **T6.1 (Dev1)** `falak upgrade`: report breaking changes between framework versions before applying.
- [ ] **T6.2 (Dev2)** Office high availability: a second instance and failover.
- [ ] **T6.3 (Dev2)** Disaster-recovery procedure and script: restore every database to a point in time.
- [ ] **T6.4 (Dev3)** Break-glass CLI: time-limited, reason required, alert raised, second approver for Tier 3.
- [ ] **T6.5 (Dev4)** Vault: app-credential and tenant-DEK rotation; external anchoring of the audit chain.
- [ ] **T6.6 (Dev4)** Service-level objectives and alerts from the telemetry already emitted.
- [ ] **T6.7 (Dev5)** DataMan app in `examples/dataman/` and the Observatory views in Studio.
- [ ] **T6.8 (Dev5)** `scripts/smoke/dr.sh`: destroy a database, restore it, rotate a compromised app credential, and report the time taken and data lost. *Needs:* T6.3, T6.5.

**Gate (Dev1)**
- [ ] `scripts/smoke/dr.sh` meets the RPO and RTO set in Phase 0.

---

### Phase 7a: Heavy compute (M7a)

- [ ] **T7.1 (Dev1)** Job contracts in schema and IR.
- [ ] **T7.2 (Dev2)** Office Compute queue: leases with visibility timeout and heartbeat, idempotent completion, dead-lettering.
- [ ] **T7.3 (Dev3)** `falak-worker`: outbound-only polling agent that runs each job in a non-root container with limits and hash-verified `uv` dependencies. *Needs:* T7.2.
- [ ] **T7.4 (Dev4)** Per-worker revocable credentials, job-scoped short-lived credentials, per-job egress allow-list.
- [ ] **T7.5 (Dev5)** SecuraBlock app and the ClarityAI document pipeline in `examples/`.
- [ ] **T7.6 (Dev5)** `scripts/smoke/compute.sh`: run a multi-minute job, kill the worker mid-job, and confirm the job finishes once and the worker host has no open inbound port. *Needs:* T7.3, T7.5.

**Gate (Dev1)**
- [ ] `scripts/smoke/compute.sh` passes.

### Phase 7b: AI readiness (M7b)

- [ ] **T7.7 (Dev1)** PII annotations in the schema and pseudonymization in the portable core.
- [ ] **T7.8 (Dev2)** NER scanning of unstructured documents as a compute job; encrypted, tenant-scoped mapping table. *Needs:* T7.2.
- [ ] **T7.9 (Dev3)** MCP server projection: opt-in, per-entity allowlist, runs as the calling user through the policy engine, read-only by default.
- [ ] **T7.10 (Dev4)** AI egress policy and the human approval gate for writes.
- [ ] **T7.11 (Dev5)** PulseAI and ThreatWeaver apps, and the ClarityAI PII shield UI.
- [ ] **T7.12 (Dev5)** `scripts/smoke/ai.sh`: a document containing injected instructions is processed, and the agent cannot read or write anything outside the caller's policy. *Needs:* T7.9, T7.10.

**Gate (Dev1)**
- [ ] `scripts/smoke/ai.sh` passes.

---

### Phase 8: Financial engine (M8)

Do not start until the legal-advice item in §4 is ticked.

- [ ] **T8.1 (Dev1)** Ledger primitives and commands (`transfer`, `reserve`, `capture`, `release`, `reverse`, `settle`, `reconcile`) with checked arithmetic and currency checks.
- [ ] **T8.2 (Dev2)** PostgreSQL `SERIALIZABLE` execution with bounded retries, no `UPDATE` or `DELETE` grant on posted tables, deferred balance constraint, idempotency table.
- [ ] **T8.3 (Dev3)** Statement import and `reconcile` CLI.
- [ ] **T8.4 (Dev4)** Tier 3 controls: sender-constrained tokens, online check per sensitive command, passkey assertion over the transaction hash, optional dual approval.
- [ ] **T8.5 (Dev5)** Horizon and BlockBanking apps, and GardenX and Academy checkout through Horizon's federated commands with compensating sagas.
- [ ] **T8.6 (Dev5)** `scripts/smoke/ledger.sh`: many concurrent transfers from one account that together exceed its balance; afterwards no account is negative, debits equal credits, and reconciliation against an external statement shows zero difference. *Needs:* T8.2, T8.5.

**Gate (Dev1)**
- [ ] `scripts/smoke/ledger.sh` passes.

---

## 6. Blockers

Write blockers here: task id, what is blocking, who can unblock it.

- **T0.8 (Dev3).** Needs a Cloudflare account and API token (owner decision in §4). Can be unblocked by the owner. Until then Dev3 can only run the Workers half locally (`wrangler dev`, no account), which does not satisfy "on Workers". It also needs Dev2's SQLite driver (T1.6) for the native half.
- **T2.6 (Dev3), status.** The D1 driver is written in `crates/falak-driver-d1` against the `falak-contracts` traits: batch, limits checks, error mapping, session bookmarks, and a `workers-rs` binding for `wasm32`. 25 unit tests pass against a fake binding and the crate lints clean for native and `wasm32`. It has not run against a real or local D1 database, so the box stays unticked until T2.7 can run it.
- **Shared working directory.** Several agents commit from one checkout, and a broad `git add` sweeps other agents' unfinished files into the wrong commit (Dev3's D1 files went into Dev1's commits). Stage by explicit path.

## 7. Interfaces available from Dev1

Use these instead of writing your own. All live in `falak-core` and build for `wasm32`.

* `falak_core::compile::compile(files, framework_version)`: sources in, `Compiled { ir, lock }` out, with diagnostics. `SourceFile { path, text }` paths are relative to the app root (`app.yaml`, `entities/x.yaml`, ...). Call this from `falak build` and `falak check`.
* `Diagnostic` implements `Display` as `file:line:col: error[code]: message` plus a `help:` line. Print it as is.
* `falak_core::policy::authorize(entity, action, principal)` returns `Access::{Denied, Unrestricted, OwnedBy(subject)}`.
* `falak_core::sql::{get, list, insert, update, delete}` take a `Request { ir, entity, dialect, access, scope }` and return `Ok(None)` when access is denied. Run nothing in that case: list gives an empty page, get/update/delete give `NotFound`, create gives `Forbidden`. `Scope` carries the verified tenant and subject. Placeholders are `?N` for SQLite and D1, `$N` for PostgreSQL. UUIDs are `Value::Uuid`; the driver converts them.
* `falak_core::sql::{resolve_sort, cursor_from_row}` support keyset paging. The runtime signs and encodes the cursor.
* `falak_core::command::plan(req, command, input, if_version, ctx)` turns a declarative command and its input into one conditional statement (`Plan::Run`) or `Plan::Denied`. Use it for `create`, `update` and `delete` commands; `custom` commands go to their handler.
* `falak_core::ddl::create_all(ir, dialect)` returns the `CREATE TABLE` and index statements in dependency order (T1.8).
* `falak_core::values::{parse_uuid, format_uuid, parse_timestamp, coerce_text, check_value}` convert and validate values.
* The IR is `falak_contracts::ir::Ir` (v1). It serialises with serde; `falak_core::build::verify_hash` checks it has not been altered.
* Input is not yet NFC-normalised. T1.7 should normalise text input before calling the builders.
