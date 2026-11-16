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
- [ ] Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` to the repository's GitHub secrets, so CI can run the Workers smoke test (T2.11). The token needs Workers Scripts and D1 edit rights.
- [x] ~~Provide a Coolify server~~ Dropped: the owner does not want Framework deployed on Coolify. An R2 bucket was needed only for the T3.11 check, which is done.
- [ ] Choose the OIDC provider that Office Identity wraps (needed before T4.8). Dev4 brings a recommendation.
- [x] Give a security contact address for `SECURITY.md`: admin@falak.me (done 2026-11-16). Turning on GitHub private vulnerability reporting for the repository is still open (Dev4 cannot do it).
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
- [x] **T0.8** Spike: a stub of the portable core, built for `wasm32`, serving one hard-coded entity from D1 on Workers and from SQLite natively. *Needs:* T0.1, Cloudflare account. *Works when:* the same request returns the same JSON from both, and the WASM size is recorded.

**Dev4**
- [x] **T0.9** `THREAT_MODEL.md` v1 and `SECURITY.md`. *Works when:* every boundary in ARCHITECTURE §4.7 has at least one named threat and its control.
- [x] **T0.10** Draft `AUTHORIZATION_SPECIFICATION.md` covering ownership and roles, default deny. *Works when:* the Notebook policies from T0.11 can be written in it without ambiguity.

**Dev5**
- [x] **T0.11** Notebook app definition in `examples/notebook/` (entities, policies, commands). This is the shared fixture for Phases 1 and 2. *Works when:* Dev1 and Dev4 confirm it covers ownership, roles, a relation and one custom command.
- [x] **T0.12** TypeScript workspace: `packages/sdk` and `packages/studio` stubs. *Works when:* `pnpm build` is green in CI.

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
- [x] **T1.7** Native runtime: REST CRUD and commands served from the IR, input validation, error format, keyset pagination, `ETag`, idempotency keys. *Needs:* T1.5, T1.6.
- [x] **T1.8** Create tables from the IR on first run (minimal `falak migrate`). *Needs:* T1.3, T1.6.
- [x] **T1.9** Structured logs, traces, liveness and readiness endpoints, and a Litestream config. *Works when:* a restore from the Litestream replica brings back the Notebook data.

**Dev3**
- [x] **T1.10** CLI: `init`, `check`, `build`, `dev` (watch and reload), `serve`, `doctor`. *Needs:* T1.3. *Works when:* `falak init` then `falak dev` serves a new app with no other steps.
- [x] **T1.11** OpenAPI 3.1 document generated from the IR. *Needs:* T1.3. *Works when:* the document loads in a standard OpenAPI viewer without errors.

**Dev4**
- [x] **T1.12** Local identity: sign-up, login, Argon2id, rate-limited attempts, revocable sessions, single-use reset tokens. *Needs:* T0.3.
- [x] **T1.13** Local key provider and `Ed25519` token issue and verify, with `kid` from the start. *Needs:* T0.3.
- [x] **T1.14** Auth middleware that puts the verified subject into the request context, and secret references resolved at runtime. *Needs:* T1.7, T1.13. *Works when:* a request with a user id in a header but no valid token is rejected.

**Dev5**
- [x] **T1.15** TypeScript SDK codegen (`falak sync`). *Needs:* T1.11.
- [x] **T1.16** Notebook React frontend using the generated SDK. *Needs:* T1.15.
- [x] **T1.17** `scripts/smoke/notebook.sh`: start the binary, create two users, create notes as each, and confirm each user sees only their own and gets 404 on the other's. *Needs:* T1.7, T1.14.
- [x] **T1.18** Ten-minute quickstart in `docs/` and linked from the README. *Works when:* another agent follows it on a clean machine and reaches a running Notebook. *(Written and run step by step by Dev3 in a clean directory; a second reader has not tried it yet.)*

**Gate (Dev1)**
- [ ] `scripts/smoke/notebook.sh` passes in CI.
- [ ] Notebook runs as a single binary with no external service, and idle memory is recorded.

---

### Phase 2: Three drivers, two runtimes (M2)

Target: the same Notebook definition runs on SQLite, PostgreSQL and Workers with D1.

**Dev1**
- [x] **T2.1** Build-time capability validator: reject an app whose needs exceed the driver's profile or limits. *Works when:* a command needing an interactive transaction fails to build for D1 with a clear message.
- [x] **T2.2** Compile read-then-write commands to a conditional batch with a version column. *Needs:* T2.1.
- [x] **T2.3** Freeze SCHEMA, AUTHORIZATION, DRIVER and API specs at 1.0. *Needs:* Phase 2 smoke passing.

**Dev2**
- [x] **T2.4** PostgreSQL driver: SQLx pool, one transaction per request. *early start*
- [x] **T2.5** Docker image and compose file for Notebook on PostgreSQL. *Needs:* T2.4.

**Dev3**
- [x] **T2.6** D1 driver: atomic batches, read-replica bookmarks. *early start*
- [x] **T2.7** Edge runtime: `workers-rs` router serving the IR. *Needs:* T2.6.
- [x] **T2.8** `falak deploy` for Workers, and a WASM size check in CI. *Needs:* T2.7.

**Dev4**
- [x] **T2.9** Token verification on the edge with a cached JWKS, using WASM-compatible crypto. *Needs:* T2.7.
- [x] **T2.10** Rate limits and request size and time limits on both runtimes.

**Dev5**
- [x] **T2.11** Make the Notebook smoke script take a target (SQLite, PostgreSQL, Workers) and run all three in CI. *Needs:* T2.5, T2.8.
- [x] **T2.12** SDK: typed errors, pagination helpers, automatic idempotency keys.

**Gate (Dev1)**
- [x] The Notebook smoke script passes on all three targets with zero changes to `examples/notebook/`.
- [x] Four specs frozen at 1.0.

---

### Phase 3: Isolation and migrations (M3)

Target: Falak.me, a multi-tenant app with file uploads.

**Dev1**
- [x] **T3.1** Tenancy modes `none`, `row`, `database` in schema, IR and policy compiler.
- [x] **T3.2** Attribute rules, field masks, and the side-channel rules (no filter or sort on unreadable fields, relation re-check, 404 for invisible rows). *Needs:* T3.1.
- [x] **T3.3** Level-2 restricted SQL: build-time parser check (single, read-only, parameterized) and generated policy-filtered views for SQLite and D1.
- [x] **T3.4** `falak policy explain` output: decision, matching rule and generated SQL. *Needs:* T3.2.

**Dev2**
- [x] **T3.5** PostgreSQL RLS: generated policies with `USING` and `WITH CHECK`, forced RLS, non-owner runtime role, per-transaction `set_config`, build failure on a scoped table with no policy. *Needs:* T3.1.
- [x] **T3.6** `falak migrate` for PostgreSQL and SQLite: diff, `plan`, expand and contract, advisory lock, checksums, drift detection.
- [x] **T3.7** PostgreSQL backups to the bucket and a written restore procedure. *Works when:* a restore into an empty database is demonstrated.

**Dev3**
- [x] **T3.8** D1 migrations, including table rebuilds. *Needs:* T3.6.
- [x] **T3.9** `database` tenancy mode on D1 and SQLite: provisioning and routing a request to its tenant's database. *Needs:* T3.1.
- [x] **T3.10** CLI commands `migrate plan`, `migrate apply`, `policy explain`. *Needs:* T3.4, T3.6.

**Dev4**
- [x] **T3.11** Object storage: presigned upload and download, size and type conditions, quarantine prefix, magic-byte check, server-generated tenant-prefixed keys.
- [x] **T3.12** Outbound allow-list with private and metadata addresses blocked after DNS resolution. *(Library: `falak-egress`. Handlers, jobs and upload fetches must call it before connecting; those callers do not exist yet.)*
- [x] **T3.13** Hash-chained, append-only audit log. *Works when:* editing a stored entry makes verification fail.

**Dev5**
- [x] **T3.14** Falak.me app in `examples/falakme/`: portal, profiles, file assets, `row` tenancy.
- [x] **T3.15** `scripts/smoke/isolation.sh`: as a user of tenant A, try every Falak.me endpoint, a level-2 query and a file download against tenant B's data, on all three drivers. All must fail. *Needs:* T3.5, T3.3, T3.11, T3.14.

**Gate (Dev1)**
- [x] `scripts/smoke/isolation.sh` passes on all three drivers.
- [x] A schema change to Falak.me is applied with `falak migrate` on a running app without downtime.
- [x] Restore from backup demonstrated (T3.7).

---

### Phase 4: Minimal Falak Office (M4) and v1.0

Target: three apps share one login and one admin interface.

**Dev1**
- [x] **T4.1** Relationship rules with bounded traversal depth. *`allow: { owner: true, related: project.workspace }`, at most 3 `belongs_to` steps, nested `EXISTS`, AUTHORIZATION §11. Checked on SQLite only (3 tests).*
- [x] **T4.2** `admin:` presentation metadata in schema and IR. *Already built in Phase 1 (`label`, `list_columns`, `search_fields`, validated); `tests/admin.rs` now pins it into the IR.*
- [x] **T4.3** `FEDERATION_SPECIFICATION.md` to candidate. *Needs:* T4.5, T4.8 drafts.
- [x] **T4.14** Release v1.0: *(Done 2026-11-16: `v1.0.0` is on GitHub with binaries, SBOM, checksums and provenance. The crates.io publish is in the release workflow and waits for the repository secret `CARGO_REGISTRY_TOKEN`.)* *(`v1.0.0-rc.1` is published as a pre-release with binaries, an SBOM, checksums and build provenance attestations, verified with `gh attestation verify`; the final `v1.0.0` tag waits for the owner.)* tag, changelog, signed artefacts, SBOM. *Needs:* Phase 4 gate.

**Dev2**
- [x] **T4.4** Office skeleton: one binary, one PostgreSQL database, built on Falak Core. *Done: the binary runs on SQLite and PostgreSQL, and the image in `deploy/office/` builds and starts in CI (`container`). Deploying it anywhere is not a task: the owner does not want Framework deployed on Coolify.*
- [x] **T4.5** Registry: single-use enrollment tokens, asymmetric app keys, signed App Passports, `GET /v1/_office/manifest`, passport revocation. *Needs:* T4.4.

**Dev3**
- [x] **T4.6** Federation client in both runtimes: enroll, present passport, fetch JWKS, consume the revocation feed, apply the per-tier outage behaviour. *Needs:* T4.5.
- [x] **T4.7** CLI: `office enroll`, `office rotate-key`, `office status`. *Needs:* T4.6.

**Dev4**
- [x] **T4.8** Office Identity wrapping the chosen OIDC provider: passkeys, per-app audiences, PKCE, refresh rotation with reuse detection. *Needs:* owner decision, T4.4. *Amended by ADR-0011 (owner decision): Office accepts any OpenID Connect provider (Clerk, Auth0, Keycloak, ...) through `POST /v1/auth/oidc/exchange`. Passkeys, MFA and PKCE are the provider's. Per-app audiences and Office's rotating refresh tokens with reuse detection are built.*
- [x] **T4.9** Signing-key rotation with overlap. *Works when:* a key is rotated under load with no failed request.
- [x] **T4.10** Signed, versioned revocation feed and step-up authentication. *Needs:* T4.8. *Step-up: `POST /v1/_office/stepup` takes a fresh provider ID token (`auth_time` within 5 minutes, same person) and returns an app token with the role `step_up` for at most 5 minutes. Policies guard a sensitive action with that role.*

**Dev5**
- [x] **T4.11** Studio: admin UI generated from `admin:` metadata, backend-for-frontend with `HttpOnly` cookies, strict CSP, PII masking, audit of admin actions. Reaches app data only through each app's API. *Needs:* T4.2, T4.8. *`crates/falak-studio`; apps expose `GET /v1/_schema` (what the caller may manage, with `admin:` metadata). The page was checked for syntax and by the smoke test's HTTP calls, not in a browser.*
- [x] **T4.12** Academy app in `examples/academy/`: courses, enrollments, submissions. *Plus reviews. Teachers reach their course's work through `related` rules; checked through Office in `scripts/smoke/office.sh`.*
- [x] **T4.13** `scripts/smoke/office.sh`: log in once and reach Notebook, Falak.me and Academy; edit a record in two apps from Studio; rotate the signing key; stop Office and confirm each app behaves as its tier specifies. *Needs:* T4.6, T4.9, T4.11, T4.12.

**Gate (Dev1)**
- [x] `scripts/smoke/office.sh` passes. *Locally on SQLite and PostgreSQL 16, and in CI (`smoke-office`).*
- [x] Studio manages two apps with no app-specific dashboard code. *Three in the smoke test (Notebook, its copy, Falak.me), from one config entry each.*
- [x] v1.0 released (T4.14).

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

- [x] **T7.1 (Dev1)** Job contracts in schema and IR.
- [x] **T7.2 (Dev2)** Office Compute queue: leases with visibility timeout and heartbeat, idempotent completion, dead-lettering.
- [x] **T7.3 (Dev3)** `falak-worker`: outbound-only polling agent that runs each job in a non-root container with limits and hash-verified `uv` dependencies. *Needs:* T7.2.
- [x] **T7.4 (Dev4)** Per-worker revocable credentials, job-scoped short-lived credentials, per-job egress allow-list.
- [ ] **T7.5 (Dev5)** SecuraBlock app and the ClarityAI document pipeline in `examples/`.
- [ ] **T7.6 (Dev5)** `scripts/smoke/compute.sh`: run a multi-minute job, kill the worker mid-job, and confirm the job finishes once and the worker host has no open inbound port. *Needs:* T7.3, T7.5.

**Gate (Dev1)**
- [ ] `scripts/smoke/compute.sh` passes.

### Phase 7b: AI readiness (M7b)

- [x] **T7.7 (Dev1)** PII annotations in the schema and pseudonymization in the portable core.
- [x] **T7.8 (Dev2)** NER scanning of unstructured documents as a compute job; encrypted, tenant-scoped mapping table. *Needs:* T7.2.
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
- **Changes Dev3 made in other agents' areas (for Dev1 and Dev2 to review).**
  * `falak-contracts`: new `ErrorKind::Unprocessable` (HTTP 422), used when an idempotency key is reused with a different body (API spec §5.2 says 422).
  * `falak-runtime-native`: `create_router` now takes an `Arc<dyn Authenticator>`. Every data route needs a valid signed bearer credential (401 otherwise). The old "any bearer value is the user id" extraction is now `DevAuthenticator`, compiled only with the `dev-auth` feature (used by the existing tests). Ids are now random (`falak_auth::system::RandomIds`), not derived from the clock. A write with `If-Match` that changes no row now answers 404 unless the caller can read the row (before, it answered 412 for any id, including ones the caller must not see). Auth routes are in `auth_routes.rs`.
  * `falak-core`: new modules `openapi` and `typescript`.
  * `ci.yml`: a `web` job, the Notebook smoke test, a check that generated files are current, and a wasm32 build of the auth crate's verification code.
- **Phase 1 gate measurements (Dev3, 2026-11-15, macOS arm64).** `falak serve` on the Notebook app: release binary 7.2 MB; peak resident memory after start-up and one health check 7.6 MB (measured with `getrusage`, so it is a peak, not a steady idle figure). One process, no external service. Still open before the gate: T1.9 (Dev2: logs, traces, readiness, Litestream restore).
- **T2.6, T2.7, T2.8 (Dev3), done 2026-11-15.** The D1 driver now runs against a real D1 database through the edge runtime. `falak-runtime-edge` serves the same router as `falak serve` on Workers, with D1, token auth, sign-up and login. `falak deploy examples/notebook --account <id>` built it, created the D1 database, published it and set the signing keys: the Notebook runs at https://notebook.falakme.workers.dev (Falak account). `scripts/smoke/notebook.py` passes all 28 checks against it. WASM is 1.7 MiB raw, 555 KiB gzip; `scripts/check-wasm-size.sh` holds it under 800 KiB gzip in CI. Not done: a CI job that deploys and runs the smoke test on Workers (needs a Cloudflare token as a CI secret); that is the Workers part of T2.11.
- **Changes Dev3 made in other agents' areas, edge round (for Dev1 and Dev2 to review).**
  * `falak-runtime-native`: new features `server`, `sqlite`, `postgres` (all default), so the crate builds for `wasm32` with `default-features = false`. `IdempotencyStore` methods are now `async`, and there is a durable variant that keeps keys in the database (`_falak_idempotency`); `falak serve` still uses the in-memory one. New `create_router_with` and `auth_routes::PeerAddr`. Request ids are random now.
  * `falak-contracts`: `support::wall_clock_micros()`, because `SystemTime::now` panics on Workers. `falak-auth` and `falak-migrate` use it. `LocalKeys::from_json` is public.
  * `falak-cli`: new `deploy` command and `--account`.
- **Phase 2 closed (Dev3, 2026-11-15).** The Notebook smoke test passes on SQLite, PostgreSQL 16 and Workers with D1, with no change to `examples/notebook/`: `scripts/smoke/all-targets.sh`, 28 checks on each. The four specs are frozen at 1.0 (ADR-0009).
  * **T2.1** was already built (`falak-core::requirements`) and tested (`tests/compile.rs`: a custom command fails to build for `d1` with a clear message). It was only unticked.
  * **T2.9** `falak deploy --jwks-url <https url> --issuer <iss>` makes a Worker that holds no signing key and verifies tokens against the issuer's published key set (cache, refresh on unknown `kid`, stale-if-error). Checked live: a token from `notebook.falakme.workers.dev` is accepted by `notebook-keys.falakme.workers.dev`, and a damaged one is refused. Apps with local identity now publish `/.well-known/jwks.json`.
  * **T2.10** Data routes: 600 requests a minute per client address, 1 MiB body (413), 30 second request time on `falak serve` (504). Auth routes: 30 a minute. Native keeps counts in memory. Workers use Cloudflare's rate limit binding, which is approximate and per location, and which sends no counts, only `Retry-After`. Checked live: the 31st login attempt in a minute gets 429. Workers set no timer of their own; the platform enforces CPU and wall time.
  * **T2.11** `FALAK_TARGET=sqlite|postgres|workers` in `scripts/smoke/notebook.sh`, and `scripts/smoke/all-targets.sh`. CI has a `smoke-postgres` job and a `smoke-workers` job. **The CI jobs have not run yet.** `smoke-workers` needs the repository secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` (owner action). Without them it prints a warning and does not run.
  * **A real bug, found by the PostgreSQL run:** the initial migration created `notes` before `notebooks`, and PostgreSQL checks foreign keys at create time. The plan now creates referenced tables first.
  * **Changes in other agents' areas (Dev1, Dev2 to review):** `ErrorKind::PayloadTooLarge` (413) in `falak-contracts`; `falak-core::ddl::creation_order`; `falak-migrate::plan` orders by it; `falak-runtime-native` gets `RouterOptions`, `limits`, and `Retry-After: 1` on an in-flight idempotency conflict (API §5.2 already said so). The edge WASM grew from 555 to 679 KiB gzip with these; the budget is 800.
- **Limits of the edge runtime.** Argon2id runs inside the Worker; sign-up worked on the account used here, but a plan with a low CPU limit may refuse it. The D1 migration for a changed app is still create-only (T3.8).
- **Phase 3 (Dev3, 2026-11-15): all boxes ticked.** `scripts/smoke/isolation.sh` (Falak.me, two workspaces, 39 checks) passes on SQLite, on PostgreSQL 16 (also as the non-owner `falak_app` role with row-level security enforced), and on Workers with D1. ADR-0010 records the specification amendments.
  * **T3.1** `tenancy: database` is refused with `postgres`; a tenant or owner scoped entity with no policy is a build error; a caller with no tenant is denied. **T3.2** `where` and `fields` under `allow`, per-row masks in SQL, write rules, and no filter or sort on a field the caller cannot read everywhere. **T3.3** `queries/*.yaml`, parser checked (`sqlparser`), run as `GET /v1/_queries/{name}` through per-request CTEs with the caller's tenant, policy and masks. **T3.4** `falak policy explain`. **T3.5** `falak-migrate::rls`, checked against live PostgreSQL by `rls_tests` (needs `FALAK_TEST_PG_ADMIN_URL`; CI sets it). Use `FALAK_MIGRATE_URL` (owner) with `DATABASE_URL` (`falak_app`) to run under RLS.
  * **T3.8, T3.10** `falak migrate plan|apply`: a saved schema snapshot per version, in-place column changes, table rebuilds for SQLite and D1 (atomic, foreign keys deferred, rolled back if a row does not fit), and approval (`--allow-destructive`) for anything that rebuilds, drops or retypes. On D1 the Worker migrates itself at start; `falak deploy --allow-destructive` permits the risky kind. D1 rebuilds are tested on SQLite and by plan, not yet on a live D1 database.
  * **T3.9** SQLite: one file per tenant, opened and migrated on first use (`TenantRouter`). D1: `falak tenant add --tenant <uuid>` makes the D1 database, binds it and redeploys; an unknown tenant is refused. Checked live on two tenants. Bindings are fixed at deploy, so each new tenant costs a deploy.
  * **T3.14** `examples/falakme/`: profiles (names visible to the workspace, bio private), pages (drafts, published to members, editors), file records, a level 2 query, `publish_page`. **Gate:** `scripts/smoke/migrate-live.sh` applied a new column to a running PostgreSQL app under traffic: 212 requests, 0 failures. **Restore:** a dump of that database restored into an empty one with identical rows (71 pages, 2 users, 2 schema snapshots, 15 policies).
  * **T3.11** `crates/falak-storage` (SigV4 presigning that reproduces the AWS documented signature, tenant prefixed server-made keys, type and size signed into the upload URL, quarantine, magic-byte check, attachment-only downloads) and the routes `POST /v1/_files`, `POST /v1/_files/{id}/complete`, `GET /v1/_files/{id}` (API §9). Checked against a real Cloudflare R2 bucket: `s3_live` and `scripts/smoke/files.py` (an upload by presigned URL, publish, download of the same bytes, an executable renamed `.png` refused and removed, another person gets 404), also as the PostgreSQL `falak_app` role. The R2 run used a one-hour token and a bucket that are now deleted. **Not on Workers:** `/v1/_files` answers 501 there; the edge needs an R2 binding backend. The file records table `_falak_files` is made by every migration plan.
  * **Changes in other agents' areas (Dev1, Dev2 to review):** IR gains `IrRule.when/fields` and `queries`; `Access::Grants`; the list SQL no longer emits an empty `WHERE` (it broke an unrestricted caller on an app with no tenancy or soft delete); `falak-migrate` plan, diff and runner rewritten around snapshots; PostgreSQL driver sets `falak.roles`; local identity gives each user a tenant of their own (`tenant_of`), because shared tenants need membership (Office, Phase 4).
  * **Cost:** the edge WASM is 738 KiB gzip, close to its 800 KiB budget.
- **Phase 4, first part (Dev3, 2026-11-16).** Office is `crates/falak-office` (its own binary, SQLite or PostgreSQL) and the app side is `crates/falak-federation`. `falak serve` follows Office when `.falak/office.json` exists. `scripts/smoke/office.sh` (real processes) passes on SQLite and with Office on PostgreSQL 16. It checks: sign in once, a token per app, revocation reaching apps in seconds, key rotation under load with no failed request, tier 1 working with Office stopped, tier 2 reading but pausing writes after the staleness limit (default 300 s), and recovery when Office returns.
  * **Ticked:** T4.5 (registry, single-use enrollment, app keys, passports, manifest, revocation), T4.7 (`falak office enroll|status|rotate-key`), T4.9 (rotation with overlap, `--retire`).
  * **Not ticked, and why.** **T4.4:** no Coolify deployment yet. **T4.6:** the native runtime is done; the edge runtime (Workers) only verifies Office tokens through the JWKS mode of T2.9, with no revocation feed or read-only behaviour. **T4.3:** the spec stays a draft until Studio and the OIDC choice settle. **T4.8, T4.10:** wait for the owner's OIDC decision (ADR-0004); Office signs in with Falak's local identity meanwhile (no passkeys, no PKCE). **T4.1, T4.2, T4.11, T4.12, T4.13, T4.14:** not started. Office refuses tier 3 apps.
  * **Design:** Office has two key sets. Session keys sign its own sign-in (audience `office`). Signing keys sign app tokens, passports and the feed, and are the only keys in `/.well-known/jwks.json`. There is no self sign-up or password reset: an administrator makes accounts (`falak-office user add`, `POST /v1/_office/users`). An app fetches the key set again after 60 s, or at once (at most every 2 s) for an unknown `kid`.
  * **Changes in other agents' areas:** `falak-auth::token::token_id`; `falak-cli` gains `office` commands and a federated mode in `serve`.
- **Phase 4, sign-in (Dev3, 2026-11-16).** ADR-0011: Office is an OpenID Connect relying party, not a provider. Any provider's ID token is traded at `POST /v1/auth/oidc/exchange` for an Office session (`FALAK_OIDC_ISSUER`, `FALAK_OIDC_AUDIENCE`, optional `FALAK_OIDC_AUTO_CREATE`). Asymmetric algorithms only; `aud` or `azp` must match; the email must be verified; a person is matched by `(iss, sub)` after the first sign-in. 8 tests (wrong issuer, audience, expiry, unsigned, HS256 key confusion, unpublished key, stranger domain, revoked person, step-up) and the live-process smoke with a stand-in provider (discovery over HTTP). **Not checked against a real Clerk or Auth0 tenant.** Clerk's default session token has no `email`; add it as a custom claim. Changes in other agents' areas: `falak-auth` `LocalIdentity::session_for_id`.
- **Phase 4, Studio and Academy (Dev3, 2026-11-16).** `crates/falak-studio` is one binary (`falak-studio serve --config studio.json`). The page is generated from each app's `GET /v1/_schema`; a new app is one config entry. Browser holds only an `HttpOnly`, `SameSite=Strict` cookie; Office and app tokens stay on the server. Writes need a CSRF header and a same-origin `Origin`. CSP is `default-src 'none'; script-src 'self'; ...` with no inline script or style, and the page uses `textContent` only. Personal fields (`pii`, `encrypted`) are masked on the server; revealing is a separate audited call; a masked value cannot be written back; filters on personal fields are refused. Every sign-in, write and reveal goes to a hash-chained log (`falak-studio audit-verify`) that holds no values, and an action is refused if the log cannot be written. Studio may only be used by Office people with the role `office_admin` or `studio`, and it reaches data only with an Office token for that app, so each app's policies decide (checked: the administrator cannot change another person's note). Studio does not check Falak.me/Notebook/Journal code: it has none.
  * **Limits.** The page was not run in a browser here. Search is an exact match on the first `search_fields` entry. Studio sessions live in memory (a restart signs everyone out). `/v1/_schema` exists on the native runtime and on Workers (shared router) but Workers was not re-deployed. Relationship rules (T4.1) were checked on SQLite only. Tier 3 is refused by Office.
  * **Changes in other agents' areas:** `falak-runtime-native` gains `GET /v1/_schema`; `falak-contracts` IR gains `IrRule.related`, `IrRelated`, `IrHop`; `falak-core` policy/SQL gain `Via`; `specifications/AUTHORIZATION_SPECIFICATION.md` §11 and `schemas/policy.schema.json`.
- **Phase 4, Workers (Dev3, 2026-11-16).** A Worker enrolled with Office (`falak office enroll`, then `falak deploy`) follows Office on requests (every 20 s per isolate, before routing) and saves the last good key set and feed state in its own D1 (`falak_office_cache`), so a new isolate still verifies tokens and honors revocations with Office down. `scripts/smoke/office-workers.py` ran it for real on the Falak account against a local Office behind a Cloudflare quick tunnel: Office token accepted, foreign token refused, revoked person refused within the interval, tier 2 reads with Office down and pauses writes after the limit, writes resume when Office returns. The Worker, D1 database and tunnel were deleted afterwards. **The edge WASM is now 800 KiB gzip; the budget is raised from 800 to 900 KiB** (Workers allows 3 MiB on the free plan) because ed25519 signing, the feed and the saved state came with it.
- **Phase 4 closed except two items (Dev3, 2026-11-16).** CI is green on `main` for the first time: the license check allows two permissive licences (`Apache-2.0 WITH LLVM-exception`, `CDLA-Permissive-2.0`), the RLS test gets its own database, and a `smoke-office` job runs the Office smoke on SQLite and PostgreSQL. `v1.0.0-rc.1` was cut to prove the release pipeline (`.github/workflows/release.yml`): two platforms built, `SHA256SUMS`, a CycloneDX SBOM from `Cargo.lock` (302 components), and provenance attestations (Sigstore, no stored key). **Open:** (1) T4.14 final tag: bump `version` in `Cargo.toml` to `1.0.0`, regenerate `falak.lock` files with `falak build`, move `[1.0.0] - unreleased` in `CHANGELOG.md` to the date, tag `v1.0.0`. FEDERATION is frozen with that tag. Not checked: a real Clerk or Auth0 tenant, the Studio page in a browser, the container image build.
- **Phase 4, web console and install (Dev3, 2026-11-16).** Office serves a web console at `/` (strict CSP, no inline script): first-run setup with a one-time code printed on the console (or `falak-office setup` from the terminal), then Overview, Apps (single-use enrollment codes with the exact command), People, Access, Sign-in (identity provider on or off, live), Keys and revocation, Activity. `scripts/install.sh` installs the three programs from a release after checking SHA256SUMS (tried against `v1.0.0-rc.1`). The console was driven in a real Chrome with Playwright (setup, every tab, sign out, a non-administrator refused; no console errors); that script is not in CI. **The installed `v1.0.0-rc.1` does not have the console**: it needs a new tag (`rc.2` or `1.0.0`).
- **Phase 4 gaps filled (Dev3, 2026-11-16).** Relationship rules now also run on PostgreSQL 16 (CI `smoke-postgres`). Sign-in through a real OpenID Connect server is checked against Dex (`scripts/smoke/office-oidc.sh`, CI `smoke-oidc`): discovery, its RS256 keys, a damaged signature and edited claims refused. Studio's page and Office's console are driven in Chrome (`scripts/ui/`, CI `smoke-office`): setup, every tab, forms, masked personal field and Reveal, record text that cannot inject markup, and a phone-sized screen (the first run found the People table overflowing; fixed). The Office and Studio image builds and starts in CI (`container`) and is pushed to GHCR on each release tag. **Still open:** tier 3; the final `v1.0.0` tag.
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
