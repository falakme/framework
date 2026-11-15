# ADR-0005: Falak Office is a modular monolith

* **Status:** Accepted (2026-11-15, by Dev1 under discretion delegated by the project owner; the owner may revise)
* **Blocks:** Office, M4

## Context

Office has identity, registry, studio, events, compute, observatory and vault. Seven services would multiply deployment and failure modes for a small team.

## Decision

Office is one binary on one PostgreSQL database, built on Falak Core itself, with one module per concern. A module is split into its own service only when measured load forces it.

## Consequences

* Office dogfoods Core.
* A single failure domain until high availability (task T6.2).
* Module boundaries are enforced in code so a later split is mechanical.
