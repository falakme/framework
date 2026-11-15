# ADR-0010: Phase 3 amendments to the frozen specifications

* **Status:** Accepted (2026-11-15, by Dev3 under discretion delegated by the project owner; the owner may revise)
* **Blocks:** none

## Context

ADR-0009 froze SCHEMA, AUTHORIZATION, DRIVER and API at 1.0 and said stage 2 of the policy language and later features would extend them compatibly (ADR-0007). Phase 3 built them.

## Decision

All changes are additive. An app written for 1.0 compiles to the same IR hash and behaves the same.

* **AUTHORIZATION §10:** `where` and `fields` under `allow`; per-row field masks; write rules; side-channel rules; tenancy checks; PostgreSQL row-level security.
* **SCHEMA §13:** `queries/` (level 2 SQL), `tenancy: database` refused with `postgres`, and a build error for a tenant or owner scoped entity with no policy. The last one is the only rule that rejects an app 1.0 accepted: an owner-scoped entity with no policy used to build and deny everything.
* **API:** `GET /v1/_queries/{name}`; `413 payload_too_large` (ADR-0009).
* **Migrations:** `falak migrate plan` and `apply`, with a saved schema snapshot per applied version, table rebuilds on SQLite and D1, and an approval step (`--allow-destructive`) for anything that rebuilds, drops or retypes data. Not a specification change.
* **Identity:** apps with tenancy get a tenant per user, computed by the server (`falak_auth::identity::tenant_of`). A tenant with several members needs membership, which Office provides.

## Consequences

* The runtime and PostgreSQL enforce the same rules in two places. A change to the policy language touches both.
* `ErrorKind` and the IR gained members; both are additive.
