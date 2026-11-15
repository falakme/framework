# ADR-0001: Compile to an IR; the runtime never parses YAML

* **Status:** Accepted (2026-11-15, by Dev1 under discretion delegated by the project owner; the owner may revise)
* **Blocks:** SCHEMA spec, every runtime

## Context

The framework can interpret YAML at request time, generate Rust source per app, or compile YAML once into a data artefact that a generic runtime loads. The edge runtime has a tight bundle-size and CPU budget, and the artefact that is tested should be the artefact that is deployed.

## Decision

`falak build` compiles an app's YAML into a validated intermediate representation (IR) with a content hash. SQL templates for every query, policy predicate and command are generated at build time and stored in the IR. A generic runtime loads the IR and binds parameters; it never parses YAML or compiles anything per request. The IR is signed at deploy and verified on load.

## Consequences

* Edge bundles stay small: no YAML parser or compiler in the runtime.
* The same hashed IR is tested, signed and deployed.
* The IR shape is a shared contract (`falak-contracts::ir`) and changes through `contract` commits.
* Editing an app needs a rebuild; `falak dev` watches and rebuilds so this stays fast.
