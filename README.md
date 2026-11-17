# Falak Framework

**Falak Framework** (`falak` CLI + **Falak Office**) is a metadata-driven application framework with an optional federated control plane. You describe entities, policies, commands and events in Git-tracked YAML; Falak compiles them into a policy-enforced API that runs as a single local binary, on a Linux server with PostgreSQL, or on Cloudflare Workers with D1.

It is built as three independently versioned products:

* **Falak Core:** schema compiler, parameterized Query AST, authorization policy engine and runtime adapters. Apps run standalone with no control plane.
* **Falak Office (optional):** shared identity, app registry, generated Admin Studio, durable cross-app events, compute workers, observability and key vault.
* **Ecosystem apps:** applications pinned to Falak Core that can federate into Falak Office without changing application code.

## Status

**v1.1.0 is the current release and covers milestones M0 to M8.** Core runs on SQLite, PostgreSQL and Cloudflare Workers with D1. Falak Office (sign in once, app registry, revocation, key rotation) and Falak Studio (a generated admin interface) are in `crates/falak-office` and `crates/falak-studio`. The SCHEMA, AUTHORIZATION, DRIVER and API specifications are frozen at 1.0; the foundational decisions are ADRs ([ARCHITECTURE.md §3](./ARCHITECTURE.md#3-open-decisions)).

v1.0.0 covered M0 to M4; v1.1.0 adds M5 to M8 and the security fixes from a review of the whole code base. Changes are listed in [CHANGELOG.md](./CHANGELOG.md).

Known gaps in M5 to M8:

* **Edge events relay:** `scripts/smoke/events-workers.sh` is written but has not passed. The edge relay has not been run on Cloudflare.
* **Financial ledger (M8):** the primitives and example apps are not production ready. Do not use them with real money. The CI job for `scripts/smoke/ledger.sh` has not run.

Known limits of v1.1.0 (full list in [CHANGELOG.md](./CHANGELOG.md)):

* **Tier 3** (online check per sensitive command) is not built. Office refuses tier 3 apps.
* **`/v1/_files`** answers `501` on Workers.
* **Office** is one instance. Sessions and signing keys are per instance. No hosted Office exists yet.
* Studio search is an exact match on the first search field.
* Sign-in through Clerk or Auth0 itself has not been tried. It is checked against Dex, an independent OpenID Connect server.

## Design

[ARCHITECTURE.md](./ARCHITECTURE.md) is the single source of truth: products, runtimes, security boundaries, specifications, roadmap and glossary.

[TASKS.md](./TASKS.md) is the build plan and checklist: every task, its owner and how it is checked.

## v1 Technology Stack

* **Core:** Rust, portable across native targets and `wasm32`
* **Native runtime:** Axum, Tokio, SQLx with PostgreSQL or SQLite
* **Edge runtime:** `workers-rs` with Cloudflare D1
* **Frontend & SDKs:** React, TypeScript (generated SDK via `falak sync`)

## Roadmap

Nine acceptance-gated milestones. Gates, scope and validation apps are in [ARCHITECTURE.md §8](./ARCHITECTURE.md#8-milestone-roadmap-m0m8).

| Milestone | Focus | Status |
| :--- | :--- | :--- |
| **M0** | Decisions, draft contracts and a portable-core spike | Released in v1.0.0 |
| **M1** | Standalone core kernel on SQLite | Released in v1.0.0 |
| **M2** | PostgreSQL and Cloudflare Workers/D1 portability | Released in v1.0.0 |
| **M3** | Isolation, migrations and backups | Released in v1.0.0 |
| **M4** | Minimal Falak Office: identity, registry, Studio | Released in v1.0.0 |
| **M5** | Federation and durable events | Released in v1.1.0 |
| **M6** | Operational maturity and disaster recovery | Released in v1.1.0 |
| **M7a** | Heavy compute workers | Released in v1.1.0 |
| **M7b** | AI readiness: opt-in MCP projection, egress allow-list and approval gate | Released in v1.1.0 |
| **M8** | Financial ledger engine | Released in v1.1.0; not production ready |

## Quickstart

[`docs/quickstart.md`](./docs/quickstart.md) takes you from nothing to a running app in ten minutes (`falak deploy` still needs a clone of this repository, because `falak-runtime-edge` is not published; to install from a clone, run `cargo install --path crates/falak-cli --locked`):

```sh
cargo install falak-cli --locked
falak init todo && cd todo
falak dev
```

## Licence

Copyright © 2026 Falak.me. Licensed under the [Apache License 2.0](./LICENSE); see also [NOTICE](./NOTICE).

Everything in this repository, including Falak Office, is licensed under Apache-2.0. Outside contributions are not accepted until a contributor sign-off process (DCO or CLA) is in place.
