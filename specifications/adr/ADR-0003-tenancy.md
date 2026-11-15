# ADR-0003: Tenancy is declared per app: none, row or database

* **Status:** Accepted (2026-11-15, by Dev1 under discretion delegated by the project owner; the owner may revise)
* **Blocks:** SCHEMA spec, AUTHORIZATION spec, drivers

## Context

Documents use user isolation, tenants and tenant keys without defining a tenant. PostgreSQL can enforce row isolation with RLS; SQLite and D1 cannot.

## Decision

`app.yaml` declares `tenancy` as one of: `none` (rows are owned by users), `row` (every tenant-scoped entity carries `tenant_id`, enforced by policy on all drivers and by RLS on PostgreSQL), or `database` (one database per tenant, recommended for sensitive apps on SQLite and D1). The tenant of a request comes only from a verified token and a server-side membership check.

## Consequences

* Isolation strength is explicit and checked at build time against the driver profile.
* `database` mode needs per-tenant provisioning and routing (task T3.9).
* Per-tenant data keys make tenant deletion a key deletion.
