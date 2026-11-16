//! Identity and tokens for standalone Falak apps.
//!
//! * [`token`]: Ed25519 access tokens, issued and verified (T1.13).
//! * [`keys`]: the local key provider with rotation.
//! * [`password`]: Argon2id hashing and the password rules.
//! * [`store`]: storage for users, sessions and reset tokens, in memory or in the
//!   app's database.
//! * [`identity`]: sign-up, login, refresh, logout and reset (T1.12).
//!
//! * [`tier3`]: controls for sensitive commands: sender-constrained tokens, an online
//!   check, a passkey assertion over the transaction hash and dual approval (T8.4).
//! * [`ratelimit`]: per-key request limits with the standard headers (T2.10).
//! * [`jwks`]: a cached key set for verifying tokens on the edge (T2.9).
//!
//! Verification of tokens (`token::Verifier`) uses no randomness and no database, so
//! the same code can run on the edge.

// Workers futures are not `Send`, so the traits carry no `Send` bound (as in falak-contracts).
#![allow(async_fn_in_trait)]

#[cfg(feature = "native")]
pub mod identity;
pub mod jwks;
#[cfg(feature = "native")]
pub mod keys;
#[cfg(feature = "native")]
pub mod password;
pub mod ratelimit;
#[cfg(feature = "native")]
pub mod store;
#[cfg(feature = "native")]
pub mod system;
#[cfg(feature = "native")]
pub mod tier3;
pub mod token;
