# ADR-0007: The policy language is built in stages

* **Status:** Accepted (2026-11-15, by Dev1 under discretion delegated by the project owner; the owner may revise)
* **Blocks:** AUTHORIZATION spec, M1 to M4

## Context

Compiling RBAC, ABAC, ReBAC, ownership and field masks to SQL in one step is the riskiest single component and the security core.

## Decision

Stage 1 (M1): ownership and roles. Stage 2 (M3): attribute rules and field masks. Stage 3 (M4): relationship rules with a bounded traversal depth. Default deny throughout; an entity with no policy returns nothing.

## Consequences

* Each stage ships with its negative isolation checks.
* The AUTHORIZATION spec is frozen only after stage 1 and PostgreSQL RLS have run on three drivers (M2 exit); later stages extend it compatibly.
