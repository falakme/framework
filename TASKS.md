# Falak Framework: Open Work

What is still open, as of the 1.1.1 release work. The architecture is in [ARCHITECTURE.md](./ARCHITECTURE.md). Release history is in [CHANGELOG.md](./CHANGELOG.md).

## Release

- [x] Published 1.1.1 to crates.io (16 crates), tagged `v1.1.1`, created the GitHub release.
- [x] Yanked `falak-ledger` 1.1.0 from crates.io.

## Verification

- [x] The notebook image (`examples/notebook/Dockerfile`) builds on Coolify, on `main` at `808c31f`.
- [ ] The Coolify test app ("Falak workspace tests") is disposable. Its test database was deleted, so its next build fails until a database is linked again. It is not needed for the release.

## Known limits

These are documented in the README and the changelog. Each is a feature that is not built yet:

- The Workers relay for cross-app events has not passed its smoke test on Cloudflare.
- Tier 3 apps are not supported by Office. Office runs as a single instance, with no hosted version.
- `/v1/_files` returns 501 on Workers.
- Studio search is an exact match on the first search field.
- Sign-in through Clerk or Auth0 is untested. Sign-in is tested against Dex.
- `page[before]` is not implemented.
- The Workers smoke test in CI needs `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` set as repository secrets. Check they exist before relying on that job.

## Owner decisions

- Write the statement of why existing tools do not meet the need. It goes in [ARCHITECTURE.md](./ARCHITECTURE.md) §10.
- Decide whether to add branch protection on `main`. It is a repository setting.
