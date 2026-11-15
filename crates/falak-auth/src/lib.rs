//! Identity and tokens for standalone Falak apps.
//!
//! * [`token`]: Ed25519 access tokens, issued and verified (T1.13).
//! * [`keys`]: the local key provider with rotation.
//! * [`password`]: Argon2id hashing and the password rules.
//! * [`store`]: storage for users, sessions and reset tokens, in memory or in the
//!   app's database.
//! * [`identity`]: sign-up, login, refresh, logout and reset (T1.12).
//!
//! Verification of tokens (`token::Verifier`) uses no randomness and no database, so
//! the same code can run on the edge.

// Workers futures are not `Send`, so the traits carry no `Send` bound (as in falak-contracts).
#![allow(async_fn_in_trait)]

#[cfg(feature = "native")]
pub mod identity;
#[cfg(feature = "native")]
pub mod keys;
#[cfg(feature = "native")]
pub mod password;
#[cfg(feature = "native")]
pub mod store;
pub mod token;
