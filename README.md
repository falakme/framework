# Falak Framework

Falak is a framework for building data-driven applications. You describe your entities,
access policies, commands and events in YAML files that live in Git. The `falak` CLI
compiles them into an HTTP API where every request is checked against the policy before
any data is read or written.

Falak runs as a single local binary on SQLite, on a Linux server with PostgreSQL, or on
Cloudflare Workers with D1. The same app runs on all three.

## Components

Falak is made of three parts, each versioned separately:

* **Falak Core**: the schema compiler, the query engine, the authorization engine and the
  runtime adapters. An app built on Core runs on its own, with no other service.
* **Falak Office** (optional): shared sign-in for several apps, an app registry, key
  rotation and revocation, durable events between apps, compute workers, and a key vault.
  It also serves Falak Studio, a generated admin interface for each app.
* **Ecosystem apps**: applications built on Core that can join an Office installation
  without changes to their code.

## Quick start

You need Rust 1.100 or later.

```sh
cargo install falak-cli --locked
falak init todo && cd todo
falak dev
```

`falak dev` serves the app on `http://127.0.0.1:8787` and reloads it when a file changes.
The [quickstart](./docs/quickstart.md) builds a small notes app from scratch, with sign-up,
login and per-person data.

## An example

An entity, in `entities/note.yaml`:

```yaml
schema_version: 1
entity: note
owner: owner_id
fields:
  title: { type: text, required: true, max_length: 200 }
  body: { type: text, max_length: 20000 }
  owner_id: { type: uuid, required: true, indexed: true }
```

Who may use it, in `policies/note.yaml`:

```yaml
schema_version: 1
entity: note
rules:
  - id: owner_full_access
    actions: [read, create, update, delete]
    allow: { owner: true }
```

With these two files a signed-in person can create and read their own notes. Nobody else
sees them, and an action that no rule grants is refused. The server fills in the owner,
so a client cannot choose it.

## What you get

* A REST API with keyset pagination, filters, sorting, sparse fieldsets, sideloading,
  ETags with `If-Match`, and idempotency keys, described in
  [`specifications/API_SPECIFICATION.md`](./specifications/API_SPECIFICATION.md).
* Authentication with Argon2id password hashes, Ed25519-signed tokens, refresh-token
  rotation with reuse detection, and OpenID Connect sign-in.
* Authorization that is enforced in the runtime and, on PostgreSQL, again by row-level
  security. See [`specifications/AUTHORIZATION_SPECIFICATION.md`](./specifications/AUTHORIZATION_SPECIFICATION.md).
* Schema migrations with a plan you can read before anything runs (`falak migrate plan`).
* A hash-chained audit log, and point-in-time restore scripts for PostgreSQL.
* A generated OpenAPI description and a typed TypeScript client (`falak sync`).
* Optional: durable events and sagas between apps, heavy-compute jobs on outbound-only
  workers, and an AI integration that exposes an app to agents through the same policy
  engine, with a human approval step for writes.

## Documentation

| Document | For |
| :-- | :-- |
| [docs/quickstart.md](./docs/quickstart.md) | Building and running your first app |
| [AGENTS.md](./AGENTS.md) | AI agents and tools that write Falak apps |
| [docs/operations.md](./docs/operations.md) | Running Falak in production |
| [docs/postgres-backup-and-restore.md](./docs/postgres-backup-and-restore.md) | Backups and restore |
| [specifications/](./specifications) | Schema, authorization, driver, API and federation specifications |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Design, security boundaries and decisions |
| [CHANGELOG.md](./CHANGELOG.md) | What changed in each release |
| [SECURITY.md](./SECURITY.md) | Reporting a vulnerability |

## Repository layout

```text
crates/          Rust crates: falak-core, falak-cli, falak-runtime-native,
                 falak-runtime-edge, falak-auth, falak-office, falak-studio,
                 falak-ledger and the rest
packages/        TypeScript packages, including @falak/sdk
examples/        Sample apps: notebook (the reference), gardenx and others
specifications/  Normative specifications
scripts/         Smoke tests, backup and release scripts
deploy/          Docker Compose files for Falak Office
docs/            Guides
```

## Development

```sh
cargo test --workspace
pnpm install && pnpm -r build
```

Smoke tests live in `scripts/smoke/`, and CI runs them, including the PostgreSQL ones. Read
[CONTRIBUTING.md](./CONTRIBUTING.md) before you open a pull request.

## Status

Version 1.1.0 is the current release. Core runs on SQLite, PostgreSQL and Cloudflare Workers
with D1. The schema, authorization, driver and API specifications are frozen at 1.0. The
release history is in [CHANGELOG.md](./CHANGELOG.md).

### Limitations

* **Financial ledger:** the double-entry primitives and the example apps are not production
  ready. Do not use them with real money. The CI job for the ledger smoke test has not run.
* **Edge events relay:** the Workers relay has not yet passed its smoke test
  (`scripts/smoke/events-workers.sh`) and has not run on Cloudflare.
* **Tier 3 sensitive commands** (an online check on each command) are not built. Falak Office
  refuses tier 3 apps.
* **Office** runs as a single instance. Sessions and signing keys are per instance. There is
  no hosted Office.
* **`/v1/_files`** answers `501` on Workers.
* **Studio search** is an exact match on the first search field.
* **Sign-in through Clerk or Auth0** has not been tested. Sign-in is tested against Dex, an
  independent OpenID Connect server.
* **AI egress allow-list:** `FALAK_AI_ALLOW` is parsed, but no code in this release makes a
  model call, so it is not enforced.

The full list is in [CHANGELOG.md](./CHANGELOG.md).

## Contributing

Bug reports and pull requests are welcome. Outside contributions are not accepted until a
contributor sign-off process (DCO or CLA) is in place; until then, open an issue and discuss
the change first.

## Licence

Copyright © 2026 Falak.me. Licensed under the [Apache License 2.0](./LICENSE). See also
[NOTICE](./NOTICE). Everything in this repository, including Falak Office, is Apache-2.0.
