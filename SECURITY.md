# Security Policy

## Reporting a vulnerability

Please report security problems privately. Do not open a public issue or pull request.

* Email admin@falak.me.
* Or use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability").

Include what you found, how to reproduce it, which version or commit you tested, and what an attacker could do with it. A working proof of concept helps but is not required.

### What to expect

| Step | Target |
| :-- | :-- |
| We acknowledge your report | within 3 working days |
| We tell you whether we accept it as a vulnerability | within 10 working days |
| We fix it or give a date | within 90 days for most reports |
| We publish an advisory and credit you, if you want | when the fix is released |

We ask that you keep the details private until a fix is released or 90 days pass, whichever comes first, and that you do not read, change or delete data that is not yours while testing.

## Scope

In scope: everything in this repository, including the compiler, runtimes, drivers, identity code, the CLI, the SDK and the example apps.

Of particular interest, because they are the product's core promises:

* one user or tenant reading or changing another's data;
* a request being accepted without a valid token, or with a token meant for another app;
* the policy engine allowing an action the policy denies;
* an event or payment being lost, duplicated or applied twice;
* secrets, tokens or personal data in logs, errors or the IR;
* a bypass of the SQL boundary (SQL built from user input).

Out of scope: findings that need a compromised host or stolen credentials, denial of service by raw traffic volume, missing security headers on the example apps, and reports from automated scanners with no demonstrated impact.

## Supported versions

Falak has not reached 1.0. Security fixes go to the `main` branch. After 1.0 the latest minor release and the one before it will receive fixes.

## How we handle secrets and dependencies

* Secrets are never committed. Configuration refers to secrets by name.
* Dependencies are locked (`Cargo.lock`, `pnpm-lock.yaml`) and checked in CI with `cargo-deny`.
* CI actions are pinned by commit hash.
* The threat model is in [`specifications/THREAT_MODEL.md`](./specifications/THREAT_MODEL.md).
