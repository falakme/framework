//! Portable semantic core: schema parsing and validation, the policy compiler and the
//! Query AST. Performs no I/O and builds for `wasm32`.

pub mod diagnostics;
pub mod load;
pub mod reader;
pub mod schema;
pub mod yaml;
