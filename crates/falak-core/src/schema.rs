//! Typed AST for an app, produced by [`crate::load`]. Everything here has already passed
//! structural and cross-file validation.

use falak_contracts::{
    capability::Capability,
    identity::TrustTier,
    ir::{FieldType, Tenancy},
};

use crate::diagnostics::Position;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DriverKind {
    Sqlite,
    Postgres,
    D1,
}

impl DriverKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
            Self::D1 => "d1",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct App {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub tenancy: Tenancy,
    pub trust_tier: TrustTier,
    pub drivers: Vec<DriverKind>,
    pub requires: Vec<Capability>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DefaultValue {
    Bool(bool),
    Int(i64),
    Text(String),
    /// Generator: the current time (`timestamptz`).
    Now,
    /// Generator: a new random UUID (`uuid`).
    NewUuid,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub name: String,
    pub ty: FieldType,
    pub required: bool,
    pub unique: bool,
    pub indexed: bool,
    pub default: Option<DefaultValue>,
    pub max_length: Option<u32>,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub pii: bool,
    pub encrypted: bool,
    /// `(entity, field)`.
    pub references: Option<(String, String)>,
    pub position: Position,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationKind {
    BelongsTo,
    HasMany,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Relation {
    pub name: String,
    pub kind: RelationKind,
    pub entity: String,
    pub field: String,
    pub position: Position,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AdminMeta {
    pub label: Option<String>,
    pub list_columns: Vec<String>,
    pub search_fields: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Lifecycle {
    pub soft_delete: bool,
    pub retention_days: Option<u32>,
    pub erasable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entity {
    pub name: String,
    pub table: String,
    pub owner: Option<String>,
    /// Declared fields only; built-in fields are added by the compiler.
    pub fields: Vec<Field>,
    pub relations: Vec<Relation>,
    pub admin: AdminMeta,
    pub lifecycle: Lifecycle,
    pub position: Position,
}

impl Entity {
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Read,
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allow {
    Owner,
    Role(String),
    Authenticated,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub id: String,
    pub actions: Vec<Action>,
    pub allow: Allow,
    pub when: Vec<falak_contracts::ir::IrCondition>,
    pub fields: Option<Vec<String>>,
    /// Relation names to follow (`belongs_to`), outermost first. Empty: none.
    pub related: Vec<String>,
    pub position: Position,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub entity: String,
    pub rules: Vec<Rule>,
    pub position: Position,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    Create,
    Update,
    Delete,
    Custom,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InputField {
    pub name: String,
    pub ty: FieldType,
    pub required: bool,
    pub max_length: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SetValue {
    Bool(bool),
    Int(i64),
    Text(String),
    /// The current time.
    Now,
    /// `$input.<name>`
    Input(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Command {
    pub name: String,
    pub entity: String,
    pub kind: CommandKind,
    pub input: Vec<InputField>,
    pub target: Option<String>,
    pub set: Vec<(String, SetValue)>,
    pub handler: Option<String>,
    pub idempotent: bool,
    pub position: Position,
}

/// A level 2 query file.
#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub name: String,
    pub params: Vec<falak_contracts::ir::IrInput>,
    pub sql: String,
    /// Entities the SQL reads, filled in by the checker.
    pub entities: Vec<String>,
    pub position: Position,
}

/// A fully validated app.
#[derive(Debug, Clone, PartialEq)]
pub struct Project {
    pub app: App,
    pub entities: Vec<Entity>,
    pub policies: Vec<Policy>,
    pub commands: Vec<Command>,
    pub queries: Vec<Query>,
    pub federation: Federation,
    pub jobs: Vec<falak_contracts::ir::IrJob>,
}

impl Project {
    pub fn entity(&self, name: &str) -> Option<&Entity> {
        self.entities.iter().find(|e| e.name == name)
    }

    pub fn policy(&self, entity: &str) -> Option<&Policy> {
        self.policies.iter().find(|p| p.entity == entity)
    }
}

/// An event the app publishes (`events/<name>.yaml` with `publish:`).
#[derive(Debug, Clone, PartialEq)]
pub struct Publish {
    pub name: String,
    pub entity: String,
    pub on: falak_contracts::ir::IrEventOn,
    pub version: u32,
    pub fields: Vec<String>,
    pub subscribers: Vec<String>,
    pub position: Position,
}

/// An event the app consumes (`events/<name>.yaml` with `consume:`).
#[derive(Debug, Clone, PartialEq)]
pub struct Subscribe {
    pub event: String,
    pub from: String,
    pub version: u32,
    pub handler: String,
    pub position: Position,
}

/// A saga (`workflows/<name>.yaml`).
#[derive(Debug, Clone, PartialEq)]
pub struct Saga {
    pub name: String,
    pub start: String,
    pub steps: Vec<falak_contracts::ir::IrSagaStep>,
    pub position: Position,
}

/// Events and sagas of an app.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Federation {
    pub publishes: Vec<Publish>,
    pub subscribes: Vec<Subscribe>,
    pub sagas: Vec<Saga>,
}
