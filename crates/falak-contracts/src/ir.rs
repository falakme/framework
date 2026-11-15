//! Intermediate representation (IR): the compiled, content-hashed form of an app that
//! runtimes load (ADR-0001). Built by `falak_core::build`; never written by hand.
//!
//! Version 1. Any incompatible change bumps [`IR_VERSION`] and goes through a
//! `contract` commit.

use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change to the IR shape.
pub const IR_VERSION: u32 = 1;

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
#[serde(rename_all = "snake_case")]
pub enum IrDefault {
    Bool(bool),
    Int(i64),
    Text(String),
    /// The current time at insert.
    Now,
    /// A new random UUID at insert.
    NewUuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrField {
    pub name: String,
    pub ty: FieldType,
    pub nullable: bool,
    pub unique: bool,
    pub indexed: bool,
    /// Marked as personal data: masked in Studio, redacted in telemetry.
    pub pii: bool,
    pub encrypted: bool,
    pub max_length: Option<u32>,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub default: Option<IrDefault>,
    /// `(entity, field)`
    pub references: Option<(String, String)>,
    /// Added by the compiler (`id`, `version`, `created_at`, ...), not declared by the app.
    pub builtin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrAction {
    Read,
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrAllow {
    /// The row's owner field equals the principal's subject.
    Owner,
    /// The principal holds this role.
    Role(String),
    /// Any verified principal.
    Authenticated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrRule {
    pub id: String,
    pub actions: Vec<IrAction>,
    pub allow: IrAllow,
    /// Attribute conditions (stage 2). The rule applies only to rows that satisfy every
    /// one of them. Empty for a stage 1 rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub when: Vec<IrCondition>,
    /// Field mask (stage 2). The rule grants only these declared fields. `None` grants
    /// every field. Built-in fields are always included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrCmp {
    Eq,
    Ne,
    In,
}

/// A value an attribute condition compares a field with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrCondValue {
    Bool(bool),
    Int(i64),
    Text(String),
    /// The verified caller's subject.
    Subject,
}

/// `field <cmp> values`. `Eq` and `Ne` have one value; `In` has one or more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrCondition {
    pub field: String,
    pub cmp: IrCmp,
    pub values: Vec<IrCondValue>,
}

/// Rules for one entity. Empty means every action is denied.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrPolicy {
    pub rules: Vec<IrRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrRelationKind {
    BelongsTo,
    HasMany,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrRelation {
    pub name: String,
    pub kind: IrRelationKind,
    pub entity: String,
    pub field: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrAdmin {
    pub label: Option<String>,
    pub list_columns: Vec<String>,
    pub search_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrEntity {
    pub name: String,
    pub table: String,
    /// Field holding the owning user's id.
    pub owner: Option<String>,
    /// All columns in table order: `id`, declared fields, `tenant_id` (row tenancy),
    /// `version`, `created_at`, `updated_at`, `deleted_at` (soft delete).
    pub fields: Vec<IrField>,
    pub relations: Vec<IrRelation>,
    pub policy: IrPolicy,
    pub admin: IrAdmin,
    pub soft_delete: bool,
    pub retention_days: Option<u32>,
    pub erasable: bool,
}

impl IrEntity {
    pub fn field(&self, name: &str) -> Option<&IrField> {
        self.fields.iter().find(|f| f.name == name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrCommandKind {
    Create,
    Update,
    Delete,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrInput {
    pub name: String,
    pub ty: FieldType,
    pub required: bool,
    pub max_length: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrSetValue {
    Bool(bool),
    Int(i64),
    Text(String),
    Now,
    /// `$input.<name>`
    Input(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrCommand {
    pub name: String,
    pub entity: String,
    pub kind: IrCommandKind,
    pub input: Vec<IrInput>,
    pub target: Option<String>,
    pub set: Vec<(String, IrSetValue)>,
    pub handler: Option<String>,
    pub idempotent: bool,
}

/// A level 2 query (ARCHITECTURE §4.7): fixed SQL over entities, with bound parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrQuery {
    pub name: String,
    pub params: Vec<IrInput>,
    /// The SQL as written, with `:name` parameters. Reads entities by name.
    pub sql: String,
    /// The entities it reads, sorted.
    pub entities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrApp {
    pub name: String,
    pub version: String,
    pub tenancy: Tenancy,
    /// `standard`, `sensitive` or `high_assurance`.
    pub trust_tier: String,
    /// Driver names the app was checked against, sorted.
    pub drivers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ir {
    pub ir_version: u32,
    /// Lowercase hex SHA-256 of the canonical JSON of this value with `content_hash`
    /// set to the empty string.
    pub content_hash: String,
    pub app: IrApp,
    /// Sorted by name.
    pub entities: Vec<IrEntity>,
    /// Sorted by name.
    pub commands: Vec<IrCommand>,
    /// Sorted by name. Omitted from the IR when empty, so apps without queries keep
    /// their hash.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queries: Vec<IrQuery>,
}

impl Ir {
    pub fn entity(&self, name: &str) -> Option<&IrEntity> {
        self.entities.iter().find(|e| e.name == name)
    }
}
