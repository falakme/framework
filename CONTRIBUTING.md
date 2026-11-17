# Contributing

Outside contributions are not accepted yet. There is no contributor sign-off process (DCO or CLA) in place.

## Prerequisites

* **Rust:** the toolchain pinned in [`rust-toolchain.toml`](./rust-toolchain.toml). `rustup` installs it on first use in the repository.
* **Node and pnpm:** Node 22.18 or later, and the pnpm version in the `packageManager` field of [`package.json`](./package.json).

## Checking a change

Run these from the repository root before you commit:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
pnpm install && pnpm -r build && pnpm -r test
```

The smoke scripts in [`scripts/smoke/`](./scripts/smoke/) run each phase end to end. For example:

```sh
bash scripts/smoke/notebook.sh
```

Some scripts need extra services, such as a PostgreSQL URL or a Cloudflare account. Read the top of a script before you run it.

## Committing

Stage files by explicit path, for example `git add crates/falak-core/src/lib.rs`. Do not use a broad `git add` (`git add .` or `git add -A`), which can pick up unrelated files.

## Publishing crates

Releases are cut by a maintainer. After the version tag exists, the "Publish crates" workflow (Actions, manual run) takes the tag as input and runs `scripts/release/publish.py` with the repository secret `CARGO_REGISTRY_TOKEN`. The workflow checks that the tag matches the version in `Cargo.toml`.

The script publishes the crates in dependency order and skips any crate whose exact version is already on crates.io, so running it again after a failure or a timeout is safe. When crates.io answers with a rate limit (HTTP 429) it waits until the time crates.io names, within a total budget. Any other error stops it at once, naming the crate. The token is read by cargo from the environment and is never put on a command line.

To see the plan and which versions are already published without publishing anything, run the workflow with "dry run" ticked, or locally:

```sh
python3 scripts/release/publish.py --dry-run
python3 scripts/release/test_publish.py
```

## Security

Do not report security problems in a public issue or pull request. Follow the process in [SECURITY.md](./SECURITY.md).
