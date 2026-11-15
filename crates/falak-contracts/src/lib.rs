//! Shared contracts for every Falak crate.
//!
//! This crate is the interface between the developer agents and between Falak Core
//! and Falak Office. It holds traits, plain data types and the error taxonomy. It
//! performs no I/O, depends on no async runtime and builds for `wasm32`.
//!
//! Changes to this crate go through a pull request labelled `contract`, merged by Dev1.

// The traits deliberately carry no `Send` bound: Cloudflare Workers futures are not
// `Send`. Native callers that need `Send` use concrete types or generics.
#![allow(async_fn_in_trait)]

pub mod admin;
pub mod capability;
pub mod driver;
pub mod error;
pub mod events;
pub mod identity;
pub mod ir;
pub mod jobs;
pub mod keys;
pub mod objects;
pub mod support;
pub mod telemetry;

pub use error::{Error, ErrorKind, Result};
