# ADR-0002: Custom handlers are Rust crates linked into the app

* **Status:** Accepted (2026-11-15, by Dev1 under discretion delegated by the project owner; the owner may revise)
* **Blocks:** SCHEMA spec, runtime

## Context

Declarative commands cover most mutations, but some business logic needs code. The options are a single supported language linked in, WASM components in several languages, or an external process.

## Decision

Declarative commands handle the common case. Custom logic is a Rust crate linked into the app binary against a small handler API that exposes only the policy-checked data layer, never a raw connection. Handler crates `forbid(unsafe_code)`. WASM-component handlers in other languages are deferred until an app requires them.

## Consequences

* Handlers are trusted in-process code: the boundary is code review, not sandboxing (ARCHITECTURE §4.7).
* Custom handlers are not available on the edge runtime until they compile to `wasm32`; the build rejects an edge app whose handler does not.
* No inter-process or plugin ABI to design in v1.
