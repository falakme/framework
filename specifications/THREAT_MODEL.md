# Threat Model

* **Status:** v1 (Phase 0). Reviewed at each phase gate.
* **Owner:** Dev4.
* **Method:** for each trust boundary in ARCHITECTURE §4.7, the realistic threats, the control that answers each, and the task that builds the control. "Built" means code and a test exist on `main`; otherwise the task id says when it will.

Threat classes use STRIDE: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of service, **E**levation of privilege.

## 1. What we protect

| Asset | Why it matters |
| :-- | :-- |
| User and tenant data | The product's whole purpose is to keep it apart and correct. |
| Credentials and keys (passwords, signing keys, data keys, app keys) | One leaked key can undo every other control. |
| Cross-app events | Cross-app state must be applied exactly once. |
| The audit log | The only record of who did what. |
| Availability of the app and of Office | Users depend on it. |

## 2. Attackers considered

| Attacker | Capability |
| :-- | :-- |
| Anonymous internet user | Any request to a public endpoint. |
| Authenticated user | A valid account, trying to reach another user's or tenant's data. |
| Malicious tenant admin | Admin rights inside one tenant. |
| Compromised app or worker | Holds that app's credentials, trying to reach other apps or Office. |
| Malicious uploaded content | A file or a record that is hostile when a person or program later reads it. |
| Malicious dependency or CI change | Code that runs at build or deploy. |
| Insider with repository access | Can propose changes, including to policy and handlers. |

Not considered: a compromised host operating system, and a malicious infrastructure provider. The design limits the damage (encryption, key separation) but does not defend against them.

## 3. Boundaries

### B1. Client to API

| Threat | Class | Control | Task |
| :-- | :-- | :-- | :-- |
| Request with a forged user id or role in a header or body | S, E | Identity comes only from a verified token. Header and body ids are ignored. | T1.14 |
| Stolen or replayed access token | S | Short lifetime (15 minutes), audience and issuer checked, revocable sessions, sender-constrained tokens for Tier 3. | T1.12, T1.13 built; T8.4 |
| Token for another app accepted | S | `aud` must equal this app. | T1.13 built |
| Algorithm confusion (`none`, HS256) | S | Algorithm fixed to EdDSA, never read from the token. Key found by `kid` in a server-held set. | T1.13 built |
| Credential stuffing and guessing | S | Argon2id; five failures per email per 15 minutes then refusal; the same error for unknown email and wrong password, with equal timing. | T1.12 built |
| Injection through filters, sort or fields | T, I | Parameterized Query AST only. Field and operator names come from the IR, never from the request. Limits on predicates, `IN` size, `LIKE` length. | T1.5 built |
| Oversized or deeply nested body, request floods | D | Body size, depth and array limits; per-identity and per-IP rate limits; request time limits. | T2.10 |
| Verbose errors reveal internals | I | Error taxonomy with a safe public message; the cause stays internal and is never in `Display`. | T0.3 built |
| Probing for other users' rows by status code | I | Rows the caller may not see return 404, never 403. | T1.7 |
| Replay of a write | T | Idempotency keys scoped to caller, method, path and key; payload fingerprint. | T1.7 |
| Lost update | T | `If-Match` with the row version; 412 on mismatch. | T1.7 |

### B2. API to storage

| Threat | Class | Control | Task |
| :-- | :-- | :-- | :-- |
| SQL built from user input | T, I, E | Drivers accept only parameterized statements; SQL text comes from templates compiled into the IR. | T0.3, T1.5 |
| One tenant reads another (PostgreSQL) | I | Row-level security with `USING` and `WITH CHECK`, forced, non-owner runtime role, per-transaction context, build failure on a table with no policy. | T3.5 |
| One tenant reads another (SQLite, D1) | I | Policy predicates compiled into every statement; policy-filtered views for restricted SQL; `database` tenancy for strong separation. | T1.4, T3.3, T3.9 |
| Runtime has schema-changing rights | E | Migrations run under a separate privileged role whose credentials exist only in the deploy pipeline. | T3.6 |
| Data read from a stolen disk or backup | I | Encryption at rest; `encrypted` fields use envelope encryption with the tenant key; backups encrypted with a separate key. | T3.7, T6.5 |
| Integer rounding changes an amount | T | `decimal_minor` is an integer; the D1 driver refuses integers above 2^53 − 1 instead of rounding. | T2.6 built |
| Partial write | T | Writes are atomic batches or transactions. | T1.6, T2.6 |

### B3. Policy and compilation

| Threat | Class | Control | Task |
| :-- | :-- | :-- | :-- |
| Entity ships with no policy | E | Default deny; an entity with no policy returns nothing. | T1.4 built |
| Policy compiles to the wrong predicate | E | Negative isolation tests in the Phase 1 and 3 smoke scripts; `falak policy explain`. | T1.17, T3.4, T3.15 |
| Tampered IR at deploy | T | Content hash in `falak.lock`; signed IR verified at deploy. | T1.3 built; T4.14 |
| Custom handler bypasses checks | E | Handlers are trusted code: review is the control. They get only the policy-checked data layer, no raw connection, and crates forbid `unsafe`. | ADR-0002 |

### B4. Local identity

| Threat | Class | Control | Task |
| :-- | :-- | :-- | :-- |
| Password database leak | I | Argon2id hashes; session and reset tokens stored only as SHA-256 hashes of 256-bit random values. | T1.12 built |
| Stolen refresh token | S | Rotation on every use; presenting a rotated token ends every session of that user. | T1.12 built |
| Reset-link abuse | S, E | Single use, one-hour expiry, ends all sessions, atomic consume. | T1.12 built |
| Account lockout used against a victim | D | Window is 15 minutes and per email, so the harm is bounded. Operators can raise the limit. | T1.12 built |
| Signing key theft from the key file | S | File mode 0600, never logged (`Debug` hides secrets); rotation with overlap; vault-backed provider for Office apps. | T1.13 built; T6.5 |

### B5. Office and federation

| Threat | Class | Control | Task |
| :-- | :-- | :-- | :-- |
| Rogue app enrolls | S | Single-use, short-lived enrollment tokens; asymmetric app keys. | T4.5 |
| Passport or token replay | S | Timestamp and unique id on every request; replay rejected; revocation feed. | T4.5, T4.10 |
| Office compromise reaches every app | E | Apps verify tokens locally with cached keys; Office holds no app data; Tier 1 apps keep working with Office down; Tier 3 apps check online. | T4.6 |
| Key rotation breaks requests | D | Overlap period with both keys valid. | T4.9 |

### B6. Studio (admin)

| Threat | Class | Control | Task |
| :-- | :-- | :-- | :-- |
| Stored XSS from record content | T, E | All record content escaped; strict CSP; `HttpOnly`, `Secure`, `SameSite` cookies behind a backend-for-frontend. | T4.11 |
| Admin reads data directly | I | Studio reaches data only through each app's API and policy engine. | T4.11 |
| Silent admin abuse | R | Every admin action is audited; break-glass is time-limited, needs a reason, raises an alert and (Tier 3) a second approver. | T3.13, T6.4 |

### B7. Uploads and outbound requests

| Threat | Class | Control | Task |
| :-- | :-- | :-- | :-- |
| Malware or wrong type uploaded | T, E | Size and type in presign conditions, magic-byte check, quarantine prefix until checked, separate origin served as attachment. | T3.11 |
| Cross-tenant object access | I | Server-generated keys under a tenant prefix; short presign lifetime. | T3.11 |
| Server-side request forgery | I, E | Outbound allow-list; private, loopback, link-local and metadata addresses blocked after DNS resolution; redirects re-checked. | T3.12 built (library); callers T3.11, T7.x |

### B8. Events and workers

| Threat | Class | Control | Task |
| :-- | :-- | :-- | :-- |
| Forged event | S | Publisher signs, subscriber verifies, authorisation comes from the contract. | T5.5 |
| Event lost or applied twice | T | Outbox and inbox in the business transaction; persist before acknowledge; idempotent consumers. | T5.2, T5.3 |
| Hostile job input or result | T, E | Job payloads validated against the contract; results treated as untrusted; non-root container with limits and an egress allow-list; per-worker revocable credential. | T7.2, T7.3, T7.4 |
| Prompt injection through documents (Phase 7b) | E, I | The agent runs as the calling user through the policy engine; writes need human approval; egress policy. | T7.9, T7.10 |

### B9. Supply chain and operations

| Threat | Class | Control | Task |
| :-- | :-- | :-- | :-- |
| Malicious or vulnerable dependency | T, E | Committed lockfiles, `cargo-deny` in CI (licences, advisories, sources), minimum versions declared. | T0.1 built |
| CI action hijacked | T | Actions pinned by commit hash. | T0.1 built |
| Secret committed | I | Secrets only by reference; secret scanning in CI. | T0.1; open |
| Release tampering | T | Signed artefacts with an SBOM. | T4.14 |
| Audit log edited | R | Hash chain, append-only for the runtime role, external anchoring. | T3.13, T6.5 |
| Secrets in logs | I | Tokens, keys, passwords and PII-marked fields never logged. | T1.9 |

## 4. Known gaps and accepted risks

| Item | Status |
| :-- | :-- |
| Secret scanning in CI is not set up | Open. Owner: Dev1. |
| Rate limits (T2.10) are not built; until then a standalone app is exposed to floods | Open, Phase 2. |
| Lockout can be used to deny a known email for 15 minutes | Accepted, bounded by the window. |
| Access tokens stay valid until they expire after a session is revoked | Accepted; lifetime is 15 minutes. Tier 3 apps check online (T8.4). |
| Custom handlers are trusted code | Accepted, by design (ADR-0002). |
| The SQLite advisory RUSTSEC-2026-0459 is ignored in `deny.toml` | Accepted until `sqlx` allows a patched `libsqlite3-sys`; Falak opens only its own database files. Review by 2026-12-15. |
| D1 and PostgreSQL isolation is only as good as the compiled predicates and RLS | Verified by T3.15 on all three drivers. |

## 5. Review

* At each phase gate, Dev4 checks every row marked with that phase's tasks and updates "Built".
* Any new boundary, runtime or driver adds a section before it ships.
