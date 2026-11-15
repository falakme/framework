# ADR-0011: Office accepts any OpenID Connect provider and does not do passkeys

* **Status:** Accepted (2026-11-16, by the project owner: "find a middle ground that works with Clerk, Auth0 and the like; don't handle passkeys")
* **Amends:** ADR-0004 (the provider it left to be chosen)

## Context

ADR-0004 said Office wraps one open-source OIDC provider and left the choice open. Choosing one would tie every Falak install to that product. Teams already use Clerk, Auth0, Keycloak, Zitadel, Google or Entra, and these already do passkeys, multi-factor, social login and recovery well.

## Decision

Office is an OpenID Connect **relying party**, not a provider. It runs no login screen and keeps no passkeys.

1. The person signs in with the provider's own SDK.
2. The front end sends the ID token to `POST /v1/auth/oidc/exchange`.
3. Office checks it against the provider's published keys and returns its own session. Per-app tokens, revocation and key rotation are unchanged.

Rules:

* Configured by `FALAK_OIDC_ISSUER` and `FALAK_OIDC_AUDIENCE`. The issuer is `https` (or loopback `http` in development). Keys come from discovery, and the discovery document must name the same issuer.
* Only asymmetric algorithms (RS256, RS384, RS512, ES256, EdDSA). Never `none` or shared-secret algorithms.
* The token's `aud` or `azp` must equal the configured audience, and the provider must say the email is verified (`FALAK_OIDC_TRUST_UNVERIFIED_EMAIL=1` relaxes this).
* A person is matched by `(issuer, subject)` after the first sign-in, so a changed email does not change who they are. The first sign-in links to the existing account with that verified email. An account is made only if the email domain is in `FALAK_OIDC_AUTO_CREATE`. Anyone else is refused.
* Every refusal is the same `401`.
* Falak's local identity (passwords) stays for installs with no provider, and for the administrator who sets Office up.

## Consequences

* Works with any standards-compliant provider, with no vendor lock-in.
* Passkeys, MFA, recovery and social login are the provider's. Office adds none of that code.
* Step-up authentication (T4.10) is the provider's `acr`/`max_age` claims, checked by Office when an app asks for it. Not built yet.
* The provider must put a verified `email` in the ID token. Clerk's default session token has none: add it as a custom claim.
* Refresh and PKCE belong to the provider's SDK. Office's own refresh tokens (rotating, reuse-detecting) cover the Office session.
