//! Portable semantic core: schema parsing and validation, the policy compiler and the
//! Query AST. Performs no I/O and builds for `wasm32`.

pub mod build;
pub mod command;
pub mod compile;
pub mod ddl;
pub mod diagnostics;
pub mod jobs;
pub mod load;
pub mod lock;
pub mod openapi;
pub mod policy;
pub mod pseudonymize;
pub mod reader;
pub mod requirements;
pub mod restricted;
pub mod schema;
pub mod sql;
pub mod typescript;
pub mod values;
pub mod yaml;
