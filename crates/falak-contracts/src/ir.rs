//! Intermediate representation (IR): the compiled, content-hashed form of an app that
//! runtimes load. **Draft v0**: only the shape needed to start. The compiler tasks
//! (T1.2, T1.3) extend it through `contract` pull requests.

use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change to the IR shape.
pub const IR_VERSION: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tenancy {
    None,
    Row,
    Database,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Uuid,
    Int64,
    /// Integer minor units (for example cents). Never a float.
    DecimalMinor,
    Text,
    Bool,
    Timestamptz,
    Bytes,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrField {
    pub name: String,
    pub ty: FieldType,
    pub nullable: bool,
    /// Marked as personal data: masked in Studio, redacted in telemetry.
    pub pii: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrEntity {
    pub name: String,
    pub fields: Vec<IrField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrApp {
    pub name: String,
    pub tenancy: Tenancy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ir {
    pub ir_version: u32,
    /// Lowercase hex SHA-256 over the canonical serialization of everything below.
    pub content_hash: String,
    pub app: IrApp,
    pub entities: Vec<IrEntity>,
}
