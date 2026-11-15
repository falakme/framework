# ADR-0006: PostgreSQL is the v1 event store

* **Status:** Accepted (2026-11-15, by Dev1 under discretion delegated by the project owner; the owner may revise)
* **Blocks:** FEDERATION spec, M5

## Context

Events need durable storage, per-aggregate ordering, replay and dead-lettering. A broker adds an operational dependency.

## Decision

Outbox and inbox tables plus PostgreSQL-backed delivery using `SKIP LOCKED` consumers. NATS stays possible behind the `EventPublisher` trait and is not built in v1.

## Consequences

* One fewer system to run.
* Throughput is bounded by PostgreSQL; revisit if measured load requires a broker.
* Delivery is at-least-once, ordered per aggregate; consumers deduplicate through the inbox.
