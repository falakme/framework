# Falak Framework: Open Work

What is still open, as of the 1.1.1 release work. The architecture is in [ARCHITECTURE.md](./ARCHITECTURE.md). Release history is in [CHANGELOG.md](./CHANGELOG.md).

## Release 1.1.1

- [ ] Publish the 16 workspace crates to crates.io at 1.1.1 with `scripts/release/publish.py`. The owner's token is needed.
- [ ] Tag `v1.1.1` and create the GitHub release.
- [ ] Yank `falak-ledger` 1.1.0 from crates.io (`cargo yank --version 1.1.0 falak-ledger`). The crate was removed from the framework.

## Verification

- [ ] Build `examples/notebook/Dockerfile` on a machine with about 6 GB of Docker memory, or on Coolify. The local build ran out of memory.
- [ ] Re-run the Coolify workspace test build after any change to `main`.

## Security follow-up

- [ ] Rotate the password of the Coolify test database `falak-test-db-2`. It appeared in tool output during the test-infrastructure work. The database holds test data only.

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
