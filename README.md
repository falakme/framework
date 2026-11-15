# Falak Framework

**Falak Framework** (`falak` CLI + **Falak Office**) is a metadata-driven application framework with an optional federated control plane. You describe entities, policies, commands and events in Git-tracked YAML; Falak compiles them into a policy-enforced API that runs as a single local binary, on a Linux server with PostgreSQL, or on Cloudflare Workers with D1.

It is built as three independently versioned products:

* **Falak Core:** schema compiler, parameterized Query AST, authorization policy engine and runtime adapters. Apps run standalone with no control plane.
* **Falak Office (optional):** shared identity, app registry, generated Admin Studio, durable cross-app events, compute workers, observability and key vault.
* **Ecosystem apps:** applications pinned to Falak Core that can federate into Falak Office without changing application code.

## Status

**Design stage (`M0`).** The foundational decisions are recorded as ADRs ([ARCHITECTURE.md §3](./ARCHITECTURE.md#3-open-decisions)); the workspace skeleton and shared contracts exist, and no specification is frozen yet.

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

| Milestone | Focus |
| :--- | :--- |
| **M0** | Decisions, draft contracts and a portable-core spike |
| **M1** | Standalone core kernel on SQLite |
| **M2** | PostgreSQL and Cloudflare Workers/D1 portability |
| **M3** | Isolation, migrations and backups |
| **M4** | Minimal Falak Office: identity, registry, Studio |
| | *v1.0 release* |
| **M5** | Federation and durable events |
| **M6** | Operational maturity and disaster recovery |
| **M7a** | Heavy compute workers |
| **M7b** | AI readiness: PII shield and opt-in MCP |
| **M8** | Financial ledger engine |

## Quickstart

Not available yet. A ten-minute quickstart ending in a running Notebook app is part of the `M1` gate.

## Licence

Copyright © 2026 Falak.me. Licensed under the [Apache License 2.0](./LICENSE); see also [NOTICE](./NOTICE).

The licence of Falak Office (the optional control plane) will be decided before `M4`; until then everything in this repository is Apache-2.0. Outside contributions are not accepted until a contributor sign-off process (DCO or CLA) is in place.
