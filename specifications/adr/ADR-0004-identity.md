# ADR-0004: Office Identity wraps an existing OIDC provider

* **Status:** Accepted (2026-11-15, by Dev1 under discretion delegated by the project owner; the owner may revise)
* **Blocks:** Office, M4

## Context

Building login, passkeys, MFA and recovery from scratch is the largest security liability in the plan and contradicts the rule of integrating commodity infrastructure.

## Decision

Office Identity wraps an existing open-source OIDC provider for login, passkeys, MFA and account recovery, and adds only what is Falak-specific: per-app audiences, App Passports, trust-tier claims and the revocation feed. The provider sits behind the `IdentityProvider` trait. The specific provider is chosen before task T4.8. **Amended by ADR-0011:** Office accepts any OpenID Connect provider and keeps no passkeys.

## Consequences

* Less security-critical code to write and audit.
* Adds an operational dependency, kept replaceable by the trait.
* Standalone apps (no Office) still use Falak's own hardened local identity (task T1.12).
