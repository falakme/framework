//! Cloudflare Workers runtime (T2.7).
//!
//! The same router as `falak serve` (`falak-runtime-native`) running on Workers, with
//! D1 as the storage driver. The compiled app is embedded at build time
//! (`FALAK_IR_FILE`, set by `falak deploy`). Signing keys come from the Worker secret
//! `FALAK_KEYS`, in the same format as `.falak/keys.json`.
//!
//! Workers run one thread and their futures are not `Send`, while the shared router
//! needs `Send` futures. [`driver::EdgeDriver`] and [`auth::EdgeAuth`] bridge the two
//! with `worker::send`, which is sound only because a Worker isolate has no second
//! thread.
//!
//! Known limits in this first version:
//! * The idempotency cache and the auth rate limiter live in isolate memory, so they do
//!   not hold across isolates. T2.10 moves them to shared storage.
//! * Argon2id runs in the Worker, so a plan with a very low CPU limit cannot sign up.

#![cfg(target_arch = "wasm32")]
// The router needs `Send` futures; see the module note above.
#![allow(clippy::future_not_send)]

mod auth;
mod driver;
mod entry;
