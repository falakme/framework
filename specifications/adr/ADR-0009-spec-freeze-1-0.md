# ADR-0009: SCHEMA, AUTHORIZATION, DRIVER and API specifications frozen at 1.0

* **Status:** Accepted (2026-11-15, by Dev3 under discretion delegated by the project owner; the owner may revise)
* **Blocks:** Phase 3

## Context

ARCHITECTURE §5 freezes the four core specifications at the M2 exit, after an implementation has exercised them. The M2 exit is: the Notebook smoke test passes on SQLite, PostgreSQL and Workers with D1, with no change to `examples/notebook/`.

That held on 2026-11-15:

* SQLite: `scripts/smoke/notebook.sh` (`FALAK_TARGET=sqlite`), 28 checks.
* PostgreSQL 16: the same script with `FALAK_TARGET=postgres`, 28 checks.
* Workers with D1: the same checks against `https://notebook.falakme.workers.dev`, deployed by `falak deploy`, 28 checks.

Running on PostgreSQL found one defect that the other two targets hid: the initial migration created `notes` before `notebooks`, and PostgreSQL checks a foreign key when the table is made. The plan now creates referenced tables first (`falak_core::ddl::creation_order`).

## Decision

SCHEMA, AUTHORIZATION, DRIVER and API are frozen at version 1.0. From now on they change only by ADR, and a change that breaks a conforming app needs a major version.

Amendments made at the freeze, because the implementation had moved past the drafts:

* **API §6.2:** the error table lists `PayloadTooLarge` (413) and `Unprocessable` (422).
* **API §5.2:** where idempotency keys live (memory for one process, the database for Workers), and the 120 second rule for a key left in flight.
* **API §7:** a limiter that cannot count (Workers) sends `Retry-After` and no made-up `RateLimit-*` headers. New §7.1 (limits) and §7.2 (public key set at `/.well-known/jwks.json`).
* **DRIVER §8:** the T0.8 spike result.
* The code was changed to match the spec in one place: a request that meets a running request with the same idempotency key now gets `Retry-After: 1`, as API §5.2 already said.

## Not frozen

* AUTHORIZATION stages 2 and 3 (attribute rules, field masks, relationships) are specified as additions to stage 1 (ADR-0007). They add keys; they do not change stage 1.
* FEDERATION (M5) and THREAT_MODEL (never).

## Consequences

* Phase 3 builds on fixed ground. A needed change costs an ADR.
* `ErrorKind::PayloadTooLarge` is a contract addition. It is additive: existing matches on `ErrorKind` elsewhere in the repository did not need to change.
* The Workers target depends on Cloudflare's rate limit binding, which counts per location and is approximate. It is an abuse limit, not a quota.
