//! Loads an app from its YAML files into a validated [`Project`].
//!
//! The core does no I/O: callers pass file contents. Problems are reported with file,
//! line and column; all problems found are returned, not just the first.

use std::collections::{HashMap, HashSet};

use falak_contracts::{
    capability::Capability,
    identity::TrustTier,
    ir::{FieldType, IrCmp, IrCondValue, IrCondition, Tenancy},
};

use crate::{
    diagnostics::{Diagnostic, Position, has_errors},
    reader::{
        Ctx, MapReader, closest, is_app_name, read_bool, read_int, read_list, read_name, read_str,
        read_u32,
    },
    schema::*,
    yaml::{self, Node, Value},
};

pub const MAX_ENTITIES: usize = 200;
pub const MAX_FIELDS: usize = 100;
pub const MAX_COMMANDS: usize = 100;
pub const DEFAULT_TEXT_MAX: u32 = 4096;

/// Names the compiler adds to every entity.
pub const BUILTIN_FIELDS: [&str; 6] = [
    "id",
    "version",
    "created_at",
    "updated_at",
    "tenant_id",
    "deleted_at",
];

/// SQL keywords that cannot be entity or field names.
pub const RESERVED_WORDS: &[&str] = &[
    "all",
    "alter",
    "and",
    "any",
    "as",
    "asc",
    "between",
    "by",
    "case",
    "check",
    "column",
    "constraint",
    "create",
    "cross",
    "current",
    "default",
    "delete",
    "desc",
    "distinct",
    "drop",
    "else",
    "end",
    "exists",
    "false",
    "for",
    "foreign",
    "from",
    "full",
    "grant",
    "group",
    "having",
    "in",
    "index",
    "inner",
    "insert",
    "intersect",
    "into",
    "is",
    "join",
    "key",
    "left",
    "like",
    "limit",
    "not",
    "null",
    "offset",
    "on",
    "or",
    "order",
    "outer",
    "primary",
    "references",
    "right",
    "select",
    "set",
    "table",
    "then",
    "to",
    "true",
    "union",
    "unique",
    "update",
    "user",
    "using",
    "values",
    "view",
    "when",
    "where",
    "with",
];

/// One input file. `path` is relative to the app root, with `/` separators.
#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: String,
    pub text: String,
}

enum Kind<'a> {
    App,
    Entity(&'a str),
    Policy(&'a str),
    Command(&'a str),
}

fn classify(path: &str) -> Result<Kind<'_>, (&'static str, String)> {
    if path == "app.yaml" {
        return Ok(Kind::App);
    }
    let Some((dir, file)) = path.split_once('/') else {
        return Err((
            "unexpected_file",
            format!("`{path}` is not a recognised app file"),
        ));
    };
    if matches!(dir, "workflows" | "events" | "jobs") {
        return Err((
            "reserved_directory",
            format!("`{dir}/` is reserved and must be empty until it is specified"),
        ));
    }
    let Some(stem) = file.strip_suffix(".yaml") else {
        let help = if file.ends_with(".yml") {
            " (rename it to `.yaml`)"
        } else {
            ""
        };
        return Err((
            "unexpected_file",
            format!("`{path}` is not a `.yaml` file{help}"),
        ));
    };
    if stem.contains('/') {
        return Err(("unexpected_file", format!("`{path}` is nested too deeply")));
    }
    match dir {
        "entities" => Ok(Kind::Entity(stem)),
        "policies" => Ok(Kind::Policy(stem)),
        "commands" => Ok(Kind::Command(stem)),
        _ => Err((
            "unexpected_file",
            format!("`{path}` is not in a recognised directory"),
        )),
    }
}

fn origin() -> Position {
    Position { line: 1, column: 1 }
}

/// Load and validate an app. The project is `Some` only when there are no errors;
/// warnings accompany a successful load.
pub fn load_project(files: &[SourceFile]) -> (Option<Project>, Vec<Diagnostic>) {
    let mut diags = Vec::new();
    let mut app: Option<App> = None;
    let mut entities: Vec<(String, Entity)> = Vec::new();
    let mut policies: Vec<(String, Policy)> = Vec::new();
    let mut commands: Vec<(String, Command)> = Vec::new();

    for f in files {
        let kind = match classify(&f.path) {
            Ok(k) => k,
            Err((code, msg)) => {
                diags.push(Diagnostic::error(code, &f.path, origin(), msg));
                continue;
            }
        };
        let node = match yaml::parse(&f.path, &f.text) {
            Ok(n) => n,
            Err(d) => {
                diags.extend(d);
                continue;
            }
        };
        let mut ctx = Ctx {
            file: &f.path,
            diags: &mut diags,
        };
        match kind {
            Kind::App => app = read_app(&mut ctx, &node),
            Kind::Entity(stem) => {
                if let Some(e) = read_entity(&mut ctx, &node, stem) {
                    entities.push((f.path.clone(), e));
                }
            }
            Kind::Policy(stem) => {
                if let Some(p) = read_policy(&mut ctx, &node, stem) {
                    policies.push((f.path.clone(), p));
                }
            }
            Kind::Command(stem) => {
                if let Some(c) = read_command(&mut ctx, &node, stem) {
                    commands.push((f.path.clone(), c));
                }
            }
        }
    }

    if !files.iter().any(|f| f.path == "app.yaml") {
        diags.push(
            Diagnostic::error(
                "missing_app",
                "app.yaml",
                origin(),
                "the app has no `app.yaml`",
            )
            .with_suggestion("create `app.yaml` with `schema_version`, `name` and `version`"),
        );
    }

    validate_entities(&mut diags, &entities);
    let tenancy = app.as_ref().map_or(Tenancy::None, |a| a.tenancy);
    validate_policies(&mut diags, tenancy, &entities, &policies);
    validate_commands(&mut diags, &entities, &mut commands);

    if entities.len() > MAX_ENTITIES {
        diags.push(Diagnostic::error(
            "too_many_entities",
            "app.yaml",
            origin(),
            format!(
                "an app may have at most {MAX_ENTITIES} entities, found {}",
                entities.len()
            ),
        ));
    }
    if commands.len() > MAX_COMMANDS {
        diags.push(Diagnostic::error(
            "too_many_commands",
            "app.yaml",
            origin(),
            format!(
                "an app may have at most {MAX_COMMANDS} commands, found {}",
                commands.len()
            ),
        ));
    }

    if has_errors(&diags) {
        return (None, diags);
    }
    let Some(app) = app else {
        return (None, diags);
    };
    let project = Project {
        app,
        entities: entities.into_iter().map(|(_, e)| e).collect(),
        policies: policies.into_iter().map(|(_, p)| p).collect(),
        commands: commands.into_iter().map(|(_, c)| c).collect(),
    };
    (Some(project), diags)
}

// ---------------------------------------------------------------- shared readers

fn check_version(ctx: &mut Ctx, map: &mut MapReader) {
    if let Some(n) = map.require(ctx, "schema_version") {
        match &n.value {
            Value::Int(1) => {}
            Value::Int(v) => ctx.error_help(
                "unsupported_schema_version",
                n.position,
                format!("schema_version {v} is not supported"),
                "the supported version is 1",
            ),
            _ => ctx.error(
                "wrong_type",
                n.position,
                "schema_version must be the integer 1",
            ),
        }
    }
}

fn parse_type(ctx: &mut Ctx, node: &Node) -> Option<FieldType> {
    const NAMES: [&str; 8] = [
        "uuid",
        "int64",
        "decimal_minor",
        "text",
        "bool",
        "timestamptz",
        "bytes",
        "json",
    ];
    let s = read_str(ctx, node, "type")?;
    let ty = match s {
        "uuid" => FieldType::Uuid,
        "int64" => FieldType::Int64,
        "decimal_minor" => FieldType::DecimalMinor,
        "text" => FieldType::Text,
        "bool" => FieldType::Bool,
        "timestamptz" => FieldType::Timestamptz,
        "bytes" => FieldType::Bytes,
        "json" => FieldType::Json,
        other => {
            let help = if matches!(
                other,
                "float" | "double" | "real" | "decimal" | "number" | "numeric"
            ) {
                "there is no float type in v1; use `decimal_minor` for money and exact quantities, or `int64`"
                    .to_string()
            } else {
                match closest(other, &NAMES) {
                    Some(c) => format!("did you mean `{c}`?"),
                    None => format!("types: {}", NAMES.join(", ")),
                }
            };
            ctx.error_help(
                "unknown_type",
                node.position,
                format!("unknown type `{other}`"),
                help,
            );
            return None;
        }
    };
    Some(ty)
}

fn is_int_type(t: &FieldType) -> bool {
    matches!(t, FieldType::Int64 | FieldType::DecimalMinor)
}

// ---------------------------------------------------------------- app.yaml

fn read_app(ctx: &mut Ctx, node: &Node) -> Option<App> {
    let mut m = MapReader::new(
        ctx,
        node,
        "app.yaml",
        &[
            "schema_version",
            "name",
            "version",
            "description",
            "tenancy",
            "trust_tier",
            "drivers",
            "requires",
        ],
    )?;
    check_version(ctx, &mut m);
    let name = m.require(ctx, "name").and_then(|n| {
        let s = read_str(ctx, n, "name")?;
        if is_app_name(s) {
            Some(s.to_string())
        } else {
            ctx.error_help(
                "invalid_name",
                n.position,
                format!("app name `{s}` is not valid"),
                "use 2 to 40 characters: lowercase letters, digits, `_` or `-`, starting with a letter",
            );
            None
        }
    });
    let version = m.require(ctx, "version").and_then(|n| {
        let s = read_str(ctx, n, "version")?;
        let ok = s.split('.').count() == 3
            && s.split('.')
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        if ok {
            Some(s.to_string())
        } else {
            ctx.error_help(
                "invalid_version",
                n.position,
                format!("version `{s}` is not MAJOR.MINOR.PATCH"),
                "write it as a quoted string such as \"0.1.0\"",
            );
            None
        }
    });
    let description = m.take("description").and_then(|n| {
        let s = read_str(ctx, n, "description")?;
        if s.chars().count() > 300 {
            ctx.error(
                "out_of_range",
                n.position,
                "description is longer than 300 characters",
            );
            return None;
        }
        Some(s.to_string())
    });
    let tenancy = m
        .take("tenancy")
        .and_then(|n| {
            enum_value(
                ctx,
                n,
                "tenancy",
                &[
                    ("none", Tenancy::None),
                    ("row", Tenancy::Row),
                    ("database", Tenancy::Database),
                ],
            )
        })
        .unwrap_or(Tenancy::None);
    let trust_tier = m
        .take("trust_tier")
        .and_then(|n| {
            enum_value(
                ctx,
                n,
                "trust_tier",
                &[
                    ("standard", TrustTier::Standard),
                    ("sensitive", TrustTier::Sensitive),
                    ("high_assurance", TrustTier::HighAssurance),
                ],
            )
        })
        .unwrap_or(TrustTier::Standard);
    let drivers = match m.take("drivers") {
        Some(n) => {
            let list = read_list(ctx, n, "drivers", |ctx, n| {
                enum_value(
                    ctx,
                    n,
                    "driver",
                    &[
                        ("sqlite", DriverKind::Sqlite),
                        ("postgres", DriverKind::Postgres),
                        ("d1", DriverKind::D1),
                    ],
                )
            });
            if list.is_empty() {
                ctx.error(
                    "empty_list",
                    n.position,
                    "`drivers` must list at least one driver",
                );
            }
            list
        }
        None => vec![DriverKind::Sqlite, DriverKind::Postgres, DriverKind::D1],
    };
    let requires = m
        .take("requires")
        .map(|n| {
            read_list(ctx, n, "requires", |ctx, n| {
                let s = read_str(ctx, n, "capability")?;
                match Capability::from_name(s) {
                    Some(c) => Some(c),
                    None => {
                        let names: Vec<&str> = falak_contracts::capability::ALL_CAPABILITIES
                            .iter()
                            .map(|c| c.name())
                            .collect();
                        let help = closest(s, &names).map_or_else(
                            || format!("capabilities: {}", names.join(", ")),
                            |c| format!("did you mean `{c}`?"),
                        );
                        ctx.error_help(
                            "unknown_capability",
                            n.position,
                            format!("unknown capability `{s}`"),
                            help,
                        );
                        None
                    }
                }
            })
        })
        .unwrap_or_default();
    m.finish(ctx);
    Some(App {
        name: name?,
        version: version?,
        description,
        tenancy,
        trust_tier,
        drivers,
        requires,
    })
}

fn enum_value<T: Copy>(ctx: &mut Ctx, node: &Node, what: &str, options: &[(&str, T)]) -> Option<T> {
    let s = read_str(ctx, node, what)?;
    if let Some((_, v)) = options.iter().find(|(n, _)| *n == s) {
        return Some(*v);
    }
    let names: Vec<&str> = options.iter().map(|(n, _)| *n).collect();
    let help = closest(s, &names).map_or_else(
        || format!("allowed: {}", names.join(", ")),
        |c| format!("did you mean `{c}`?"),
    );
    ctx.error_help(
        "invalid_value",
        node.position,
        format!("`{s}` is not a valid {what}"),
        help,
    );
    None
}

// ---------------------------------------------------------------- entities

fn read_entity(ctx: &mut Ctx, node: &Node, stem: &str) -> Option<Entity> {
    let mut m = MapReader::new(
        ctx,
        node,
        "an entity file",
        &[
            "schema_version",
            "entity",
            "table",
            "owner",
            "fields",
            "relations",
            "admin",
            "lifecycle",
        ],
    )?;
    check_version(ctx, &mut m);
    let name_node = m.require(ctx, "entity");
    let name = name_node.and_then(|n| read_name(ctx, n, "entity"));
    if let (Some(name), Some(n)) = (&name, name_node)
        && name != stem
    {
        ctx.error_help(
            "name_mismatch",
            n.position,
            format!("entity `{name}` must be defined in `entities/{name}.yaml`"),
            format!("rename the file or change `entity` to `{stem}`"),
        );
    }
    if let Some(name) = &name {
        check_reserved(
            ctx,
            name_node.map_or(node.position, |n| n.position),
            name,
            "entity",
        );
    }
    let table = m.take("table").and_then(|n| read_name(ctx, n, "table"));
    let owner = m.take("owner").and_then(|n| read_name(ctx, n, "owner"));

    let mut fields = Vec::new();
    if let Some(n) = m.require(ctx, "fields")
        && let Some(fm) = MapReader::new(ctx, n, "fields", &[])
    {
        if fm.entries().is_empty() {
            ctx.error(
                "empty_fields",
                n.position,
                "an entity needs at least one field",
            );
        }
        if fm.entries().len() > MAX_FIELDS {
            ctx.error(
                "too_many_fields",
                n.position,
                format!("an entity may have at most {MAX_FIELDS} fields"),
            );
        }
        for e in fm.entries() {
            if !crate::reader::is_name(&e.key) {
                ctx.error_help(
                    "invalid_name",
                    e.key_position,
                    format!("field name `{}` is not valid", e.key),
                    "use lowercase letters, digits and underscores, starting with a letter",
                );
                continue;
            }
            check_reserved(ctx, e.key_position, &e.key, "field");
            if let Some(f) = read_field(ctx, &e.key, e.key_position, &e.value) {
                fields.push(f);
            }
        }
    }

    let mut relations = Vec::new();
    if let Some(n) = m.take("relations")
        && let Some(rm) = MapReader::new(ctx, n, "relations", &[])
    {
        for e in rm.entries() {
            if let Some(r) = read_relation(ctx, &e.key, e.key_position, &e.value) {
                relations.push(r);
            }
        }
    }

    let admin = m
        .take("admin")
        .map(|n| read_admin(ctx, n))
        .unwrap_or_default();
    let lifecycle = m
        .take("lifecycle")
        .map(|n| read_lifecycle(ctx, n))
        .unwrap_or_default();
    m.finish(ctx);

    let name = name?;
    Some(Entity {
        table: table.unwrap_or_else(|| format!("{name}s")),
        name,
        owner,
        fields,
        relations,
        admin,
        lifecycle,
        position: node.position,
    })
}

fn check_reserved(ctx: &mut Ctx, position: Position, name: &str, what: &str) {
    if BUILTIN_FIELDS.contains(&name) {
        ctx.error_help(
            "reserved_name",
            position,
            format!(
                "`{name}` is added to every entity automatically and cannot be declared as a {what}"
            ),
            "remove it, or choose another name",
        );
    } else if RESERVED_WORDS.contains(&name) {
        ctx.error_help(
            "reserved_name",
            position,
            format!("`{name}` is a SQL keyword and cannot be used as a {what} name"),
            format!("try `{name}_value` or a more specific name"),
        );
    }
}

const FIELD_KEYS: &[&str] = &[
    "type",
    "required",
    "unique",
    "indexed",
    "default",
    "max_length",
    "min",
    "max",
    "pii",
    "encrypted",
    "references",
];

fn read_field(ctx: &mut Ctx, name: &str, key_position: Position, node: &Node) -> Option<Field> {
    let mut m = MapReader::new(ctx, node, &format!("field `{name}`"), FIELD_KEYS)?;
    let ty = m.require(ctx, "type").and_then(|n| parse_type(ctx, n));
    let flag = |ctx: &mut Ctx, m: &mut MapReader, key: &'static str| -> (bool, Position) {
        match m.take(key) {
            Some(n) => (read_bool(ctx, n, key).unwrap_or(false), n.position),
            None => (false, key_position),
        }
    };
    let (required, _) = flag(ctx, &mut m, "required");
    let (unique, unique_pos) = flag(ctx, &mut m, "unique");
    let (indexed, _) = flag(ctx, &mut m, "indexed");
    let (pii, _) = flag(ctx, &mut m, "pii");
    let (encrypted, enc_pos) = flag(ctx, &mut m, "encrypted");
    let max_length_node = m.take("max_length");
    let max_length = max_length_node.and_then(|n| read_u32(ctx, n, "max_length", 1, 1_048_576));
    let min_node = m.take("min");
    let max_node = m.take("max");
    let min = min_node.and_then(|n| read_int(ctx, n, "min"));
    let max = max_node.and_then(|n| read_int(ctx, n, "max"));
    let default_node = m.take("default");
    let references = m.take("references").and_then(|n| {
        let s = read_str(ctx, n, "references")?;
        match s.split_once('.') {
            Some((e, f)) if crate::reader::is_name(e) && crate::reader::is_name(f) => {
                Some((e.to_string(), f.to_string()))
            }
            _ => {
                ctx.error_help(
                    "invalid_reference",
                    n.position,
                    format!("`{s}` is not an `entity.field` reference"),
                    "for example `references: note.id`",
                );
                None
            }
        }
    });
    m.finish(ctx);

    let ty = ty?;
    // Attribute applicability.
    if let Some(n) = max_length_node
        && !matches!(ty, FieldType::Text | FieldType::Bytes)
    {
        ctx.error(
            "invalid_attribute",
            n.position,
            "`max_length` applies only to `text` and `bytes`",
        );
    }
    for n in [min_node, max_node].into_iter().flatten() {
        if !is_int_type(&ty) {
            ctx.error(
                "invalid_attribute",
                n.position,
                "`min` and `max` apply only to `int64` and `decimal_minor`",
            );
        }
    }
    if let (Some(lo), Some(hi)) = (min, max)
        && lo > hi
    {
        ctx.error(
            "out_of_range",
            node.position,
            format!("`min` ({lo}) is greater than `max` ({hi})"),
        );
    }
    if encrypted {
        if !matches!(ty, FieldType::Text | FieldType::Bytes | FieldType::Json) {
            ctx.error(
                "invalid_attribute",
                enc_pos,
                "`encrypted` applies only to `text`, `bytes` and `json`",
            );
        }
        if unique || indexed {
            ctx.error_help(
                "invalid_attribute",
                if unique { unique_pos } else { enc_pos },
                "an encrypted field cannot be `unique` or `indexed`",
                "remove `unique`/`indexed`, or remove `encrypted`",
            );
        }
    }
    if references.is_some() && ty != FieldType::Uuid {
        ctx.error(
            "invalid_attribute",
            node.position,
            "`references` applies only to `uuid` fields",
        );
    }
    if ty == FieldType::Json && (unique || indexed) {
        ctx.error(
            "invalid_attribute",
            node.position,
            "`json` fields cannot be `unique` or `indexed`",
        );
    }

    let default = default_node.and_then(|n| read_default(ctx, n, &ty, max_length, min, max));
    Some(Field {
        name: name.to_string(),
        ty,
        required,
        unique,
        indexed,
        default,
        max_length,
        min,
        max,
        pii,
        encrypted,
        references,
        position: key_position,
    })
}

fn read_default(
    ctx: &mut Ctx,
    n: &Node,
    ty: &FieldType,
    max_length: Option<u32>,
    min: Option<i64>,
    max: Option<i64>,
) -> Option<DefaultValue> {
    let mismatch = |ctx: &mut Ctx, what: &str| {
        ctx.error(
            "invalid_default",
            n.position,
            format!("default {what} does not match the field type"),
        );
        None
    };
    match (&n.value, ty) {
        (Value::Bool(b), FieldType::Bool) => Some(DefaultValue::Bool(*b)),
        (Value::Int(i), t) if is_int_type(t) => {
            if min.is_some_and(|m| *i < m) || max.is_some_and(|m| *i > m) {
                ctx.error(
                    "invalid_default",
                    n.position,
                    "default is outside `min`/`max`",
                );
                return None;
            }
            Some(DefaultValue::Int(*i))
        }
        (Value::Str(s), FieldType::Text) => {
            let limit = max_length.unwrap_or(DEFAULT_TEXT_MAX) as usize;
            if s.chars().count() > limit {
                ctx.error(
                    "invalid_default",
                    n.position,
                    format!("default is longer than max_length ({limit})"),
                );
                return None;
            }
            Some(DefaultValue::Text(s.clone()))
        }
        (Value::Str(s), FieldType::Timestamptz) if s == "now" => Some(DefaultValue::Now),
        (Value::Str(s), FieldType::Uuid) if s == "uuid" => Some(DefaultValue::NewUuid),
        (Value::Bool(_), _) => mismatch(ctx, "(a boolean)"),
        (Value::Int(_), _) => mismatch(ctx, "(an integer)"),
        (Value::Str(_), FieldType::Timestamptz) => {
            ctx.error_help(
                "invalid_default",
                n.position,
                "a timestamp default must be the generator `now`",
                "use `default: now`",
            );
            None
        }
        (Value::Str(_), FieldType::Uuid) => {
            ctx.error_help(
                "invalid_default",
                n.position,
                "a uuid default must be the generator `uuid`",
                "use `default: uuid`",
            );
            None
        }
        (Value::Str(_), _) => mismatch(ctx, "(a string)"),
        _ => {
            ctx.error(
                "invalid_default",
                n.position,
                "default must be a boolean, integer or string",
            );
            None
        }
    }
}

fn read_relation(
    ctx: &mut Ctx,
    name: &str,
    key_position: Position,
    node: &Node,
) -> Option<Relation> {
    if !crate::reader::is_name(name) {
        ctx.error(
            "invalid_name",
            key_position,
            format!("relation name `{name}` is not valid"),
        );
        return None;
    }
    let mut m = MapReader::new(
        ctx,
        node,
        &format!("relation `{name}`"),
        &["kind", "entity", "field"],
    )?;
    let kind = m.require(ctx, "kind").and_then(|n| {
        enum_value(
            ctx,
            n,
            "relation kind",
            &[
                ("belongs_to", RelationKind::BelongsTo),
                ("has_many", RelationKind::HasMany),
            ],
        )
    });
    let entity = m
        .require(ctx, "entity")
        .and_then(|n| read_name(ctx, n, "entity"));
    let field = m
        .require(ctx, "field")
        .and_then(|n| read_name(ctx, n, "field"));
    m.finish(ctx);
    Some(Relation {
        name: name.to_string(),
        kind: kind?,
        entity: entity?,
        field: field?,
        position: key_position,
    })
}

fn read_admin(ctx: &mut Ctx, node: &Node) -> AdminMeta {
    let Some(mut m) = MapReader::new(
        ctx,
        node,
        "admin",
        &["label", "list_columns", "search_fields"],
    ) else {
        return AdminMeta::default();
    };
    let label = m.take("label").and_then(|n| {
        let s = read_str(ctx, n, "label")?;
        if s.chars().count() > 80 {
            ctx.error(
                "out_of_range",
                n.position,
                "label is longer than 80 characters",
            );
            return None;
        }
        Some(s.to_string())
    });
    let list_columns = m
        .take("list_columns")
        .map(|n| read_list(ctx, n, "list_columns", |c, n| read_name(c, n, "column")))
        .unwrap_or_default();
    let search_fields = m
        .take("search_fields")
        .map(|n| read_list(ctx, n, "search_fields", |c, n| read_name(c, n, "field")))
        .unwrap_or_default();
    m.finish(ctx);
    AdminMeta {
        label,
        list_columns,
        search_fields,
    }
}

fn read_lifecycle(ctx: &mut Ctx, node: &Node) -> Lifecycle {
    let Some(mut m) = MapReader::new(
        ctx,
        node,
        "lifecycle",
        &["soft_delete", "retention_days", "erasable"],
    ) else {
        return Lifecycle::default();
    };
    let soft_delete = m
        .take("soft_delete")
        .and_then(|n| read_bool(ctx, n, "soft_delete"))
        .unwrap_or(false);
    let retention_days = m
        .take("retention_days")
        .and_then(|n| read_u32(ctx, n, "retention_days", 1, 36_500));
    let erasable = m
        .take("erasable")
        .and_then(|n| read_bool(ctx, n, "erasable"))
        .unwrap_or(false);
    m.finish(ctx);
    Lifecycle {
        soft_delete,
        retention_days,
        erasable,
    }
}

// ---------------------------------------------------------------- policies

fn read_policy(ctx: &mut Ctx, node: &Node, stem: &str) -> Option<Policy> {
    let mut m = MapReader::new(
        ctx,
        node,
        "a policy file",
        &["schema_version", "entity", "rules"],
    )?;
    check_version(ctx, &mut m);
    let name_node = m.require(ctx, "entity");
    let entity = name_node.and_then(|n| read_name(ctx, n, "entity"));
    if let (Some(e), Some(n)) = (&entity, name_node)
        && e != stem
    {
        ctx.error_help(
            "name_mismatch",
            n.position,
            format!("the policy for `{e}` must be in `policies/{e}.yaml`"),
            format!("rename the file or change `entity` to `{stem}`"),
        );
    }
    let mut rules = Vec::new();
    if let Some(n) = m.require(ctx, "rules") {
        match &n.value {
            Value::Seq(items) if items.is_empty() => {
                ctx.error(
                    "empty_list",
                    n.position,
                    "`rules` must contain at least one rule",
                );
            }
            Value::Seq(items) => {
                let mut ids: HashSet<String> = HashSet::new();
                for item in items {
                    if let Some(r) = read_rule(ctx, item) {
                        if ids.insert(r.id.clone()) {
                            rules.push(r);
                        } else {
                            ctx.error(
                                "duplicate_rule",
                                r.position,
                                format!("rule id `{}` is used twice", r.id),
                            );
                        }
                    }
                }
            }
            other => ctx.error(
                "wrong_type",
                n.position,
                format!(
                    "`rules` must be a list, found {}",
                    crate::reader::kind_name(other)
                ),
            ),
        }
    }
    m.finish(ctx);
    Some(Policy {
        entity: entity?,
        rules,
        position: node.position,
    })
}

fn read_rule(ctx: &mut Ctx, node: &Node) -> Option<Rule> {
    let mut m = MapReader::new(ctx, node, "a rule", &["id", "actions", "allow"])?;
    let id = m
        .require(ctx, "id")
        .and_then(|n| read_name(ctx, n, "rule id"));
    let actions = m
        .require(ctx, "actions")
        .map(|n| {
            let list = read_list(ctx, n, "actions", |ctx, n| {
                enum_value(
                    ctx,
                    n,
                    "action",
                    &[
                        ("read", Action::Read),
                        ("create", Action::Create),
                        ("update", Action::Update),
                        ("delete", Action::Delete),
                    ],
                )
            });
            if list.is_empty() {
                ctx.error(
                    "empty_list",
                    n.position,
                    "`actions` must list at least one action",
                );
            }
            list
        })
        .unwrap_or_default();
    let mut when: Vec<IrCondition> = Vec::new();
    let mut fields: Option<Vec<String>> = None;
    let allow = m.require(ctx, "allow").and_then(|n| {
        let mut a = MapReader::new(
            ctx,
            n,
            "allow",
            &["owner", "role", "authenticated", "where", "fields"],
        )?;
        let owner = a.take("owner");
        let role = a.take("role");
        let authenticated = a.take("authenticated");
        if let Some(w) = a.take("where") {
            when = read_when(ctx, w);
        }
        if let Some(f) = a.take("fields") {
            let list = read_list(ctx, f, "fields", |ctx, n| read_name(ctx, n, "field"));
            if list.is_empty() {
                ctx.error(
                    "empty_list",
                    f.position,
                    "`fields` must list at least one field",
                );
            }
            fields = Some(list);
        }
        let count = [owner, role, authenticated]
            .iter()
            .filter(|x| x.is_some())
            .count();
        a.finish(ctx);
        if count != 1 {
            ctx.error_help(
                "invalid_allow",
                n.position,
                "`allow` must have exactly one condition",
                "use one of `owner: true`, `role: <name>` or `authenticated: true`",
            );
            return None;
        }
        if let Some(o) = owner {
            return match read_bool(ctx, o, "owner")? {
                true => Some(Allow::Owner),
                false => {
                    ctx.error(
                        "invalid_allow",
                        o.position,
                        "`owner` must be `true` (there are no deny rules)",
                    );
                    None
                }
            };
        }
        if let Some(r) = role {
            return read_name(ctx, r, "role").map(Allow::Role);
        }
        let au = authenticated?;
        match read_bool(ctx, au, "authenticated")? {
            true => Some(Allow::Authenticated),
            false => {
                ctx.error(
                    "invalid_allow",
                    au.position,
                    "`authenticated` must be `true` (there are no deny rules)",
                );
                None
            }
        }
    });
    m.finish(ctx);
    Some(Rule {
        id: id?,
        actions,
        allow: allow?,
        when,
        fields,
        position: node.position,
    })
}

/// `where:` under `allow`. Each key is a field; the value is a literal (equals), `$subject`
/// (equals the caller), `{ in: [..] }` or `{ ne: <value> }`.
fn read_when(ctx: &mut Ctx, node: &Node) -> Vec<IrCondition> {
    let Some(entries) = node.as_map() else {
        ctx.error(
            "invalid_where",
            node.position,
            "`where` must be a map of field to value",
        );
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries {
        let scalar = |ctx: &mut Ctx, n: &Node| -> Option<IrCondValue> {
            match &n.value {
                Value::Bool(b) => Some(IrCondValue::Bool(*b)),
                Value::Int(i) => Some(IrCondValue::Int(*i)),
                Value::Str(s) if s == "$subject" => Some(IrCondValue::Subject),
                Value::Str(s) if s.starts_with('$') => {
                    ctx.error_help(
                        "invalid_where",
                        n.position,
                        format!("unknown variable `{s}`"),
                        "the only variable is `$subject`",
                    );
                    None
                }
                Value::Str(s) => Some(IrCondValue::Text(s.clone())),
                _ => {
                    ctx.error(
                        "invalid_where",
                        n.position,
                        "a value must be text, a number, true or false",
                    );
                    None
                }
            }
        };
        let cond = match e.value.as_map() {
            Some([single]) if single.key == "in" => {
                let values = read_list(ctx, &single.value, "in", |ctx, n| scalar(ctx, n));
                if values.is_empty() {
                    ctx.error(
                        "invalid_where",
                        single.value.position,
                        "`in` needs at least one value",
                    );
                    continue;
                }
                IrCondition {
                    field: e.key.clone(),
                    cmp: IrCmp::In,
                    values,
                }
            }
            Some([single]) if single.key == "ne" => {
                let Some(v) = scalar(ctx, &single.value) else {
                    continue;
                };
                IrCondition {
                    field: e.key.clone(),
                    cmp: IrCmp::Ne,
                    values: vec![v],
                }
            }
            Some(_) => {
                ctx.error_help(
                    "invalid_where",
                    e.value.position,
                    format!("cannot read the condition for `{}`", e.key),
                    "use a value, `{ in: [..] }` or `{ ne: <value> }`",
                );
                continue;
            }
            None => {
                let Some(v) = scalar(ctx, &e.value) else {
                    continue;
                };
                IrCondition {
                    field: e.key.clone(),
                    cmp: IrCmp::Eq,
                    values: vec![v],
                }
            }
        };
        out.push(cond);
    }
    out
}

// ---------------------------------------------------------------- commands

fn read_command(ctx: &mut Ctx, node: &Node, stem: &str) -> Option<Command> {
    let mut m = MapReader::new(
        ctx,
        node,
        "a command file",
        &[
            "schema_version",
            "command",
            "entity",
            "kind",
            "input",
            "target",
            "set",
            "handler",
            "idempotent",
        ],
    )?;
    check_version(ctx, &mut m);
    let name_node = m.require(ctx, "command");
    let name = name_node.and_then(|n| read_name(ctx, n, "command"));
    if let (Some(c), Some(n)) = (&name, name_node)
        && c != stem
    {
        ctx.error_help(
            "name_mismatch",
            n.position,
            format!("command `{c}` must be defined in `commands/{c}.yaml`"),
            format!("rename the file or change `command` to `{stem}`"),
        );
    }
    let entity = m
        .require(ctx, "entity")
        .and_then(|n| read_name(ctx, n, "entity"));
    let kind = m.require(ctx, "kind").and_then(|n| {
        enum_value(
            ctx,
            n,
            "command kind",
            &[
                ("create", CommandKind::Create),
                ("update", CommandKind::Update),
                ("delete", CommandKind::Delete),
                ("custom", CommandKind::Custom),
            ],
        )
    });

    let mut input = Vec::new();
    if let Some(n) = m.take("input")
        && let Some(im) = MapReader::new(ctx, n, "input", &[])
    {
        for e in im.entries() {
            if !crate::reader::is_name(&e.key) {
                ctx.error(
                    "invalid_name",
                    e.key_position,
                    format!("input name `{}` is not valid", e.key),
                );
                continue;
            }
            let Some(mut fm) = MapReader::new(
                ctx,
                &e.value,
                &format!("input `{}`", e.key),
                &["type", "required", "max_length"],
            ) else {
                continue;
            };
            let ty = fm.require(ctx, "type").and_then(|n| parse_type(ctx, n));
            let required = fm
                .take("required")
                .and_then(|n| read_bool(ctx, n, "required"))
                .unwrap_or(false);
            let max_length = fm
                .take("max_length")
                .and_then(|n| read_u32(ctx, n, "max_length", 1, 1_048_576));
            fm.finish(ctx);
            if let Some(ty) = ty {
                input.push(InputField {
                    name: e.key.clone(),
                    ty,
                    required,
                    max_length,
                });
            }
        }
    }
    let target = m.take("target").and_then(|n| read_name(ctx, n, "target"));
    let mut set = Vec::new();
    if let Some(n) = m.take("set")
        && let Some(sm) = MapReader::new(ctx, n, "set", &[])
    {
        for e in sm.entries() {
            let v = match &e.value.value {
                Value::Bool(b) => SetValue::Bool(*b),
                Value::Int(i) => SetValue::Int(*i),
                Value::Str(s) => match s.strip_prefix("$input.") {
                    Some(name) if crate::reader::is_name(name) => SetValue::Input(name.to_string()),
                    Some(_) => {
                        ctx.error(
                            "invalid_reference",
                            e.value.position,
                            format!("`{s}` does not name an input"),
                        );
                        continue;
                    }
                    None => SetValue::Text(s.clone()),
                },
                other => {
                    ctx.error(
                        "wrong_type",
                        e.value.position,
                        format!(
                            "a `set` value must be a boolean, integer or string, found {}",
                            crate::reader::kind_name(other)
                        ),
                    );
                    continue;
                }
            };
            set.push((e.key.clone(), v));
        }
    }
    let handler = m.take("handler").and_then(|n| read_name(ctx, n, "handler"));
    let idempotent = m
        .take("idempotent")
        .and_then(|n| read_bool(ctx, n, "idempotent"))
        .unwrap_or(false);
    m.finish(ctx);
    Some(Command {
        name: name?,
        entity: entity?,
        kind: kind?,
        input,
        target,
        set,
        handler,
        idempotent,
        position: node.position,
    })
}

// ---------------------------------------------------------------- cross-file validation

fn validate_entities(diags: &mut Vec<Diagnostic>, entities: &[(String, Entity)]) {
    let by_name: HashMap<&str, &Entity> =
        entities.iter().map(|(_, e)| (e.name.as_str(), e)).collect();
    let mut names = HashSet::new();
    let mut tables = HashSet::new();
    for (path, e) in entities {
        let mut ctx = Ctx { file: path, diags };
        if !names.insert(e.name.as_str()) {
            ctx.error(
                "duplicate_entity",
                e.position,
                format!("entity `{}` is defined twice", e.name),
            );
        }
        if !tables.insert(e.table.as_str()) {
            ctx.error(
                "duplicate_table",
                e.position,
                format!("table `{}` is used by another entity", e.table),
            );
        }
        let mut seen = HashSet::new();
        for f in &e.fields {
            if !seen.insert(f.name.as_str()) {
                ctx.error(
                    "duplicate_field",
                    f.position,
                    format!("field `{}` is defined twice", f.name),
                );
            }
            if let Some((te, tf)) = &f.references {
                match by_name.get(te.as_str()) {
                    None => ctx.error_help(
                        "unknown_entity",
                        f.position,
                        format!("`{}` references unknown entity `{te}`", f.name),
                        closest_help(te, by_name.keys().copied()),
                    ),
                    Some(target) => {
                        if tf != "id" {
                            match target.field(tf) {
                                None => ctx.error(
                                    "unknown_field",
                                    f.position,
                                    format!("entity `{te}` has no field `{tf}`"),
                                ),
                                Some(tfld) if tfld.ty != f.ty => ctx.error(
                                    "reference_type_mismatch",
                                    f.position,
                                    format!("`{}` is a uuid but `{te}.{tf}` is not", f.name),
                                ),
                                Some(_) => {}
                            }
                        }
                    }
                }
            }
        }
        if let Some(owner) = &e.owner {
            match e.field(owner) {
                None => ctx.error_help(
                    "unknown_field",
                    e.position,
                    format!(
                        "`owner` names `{owner}`, which is not a field of `{}`",
                        e.name
                    ),
                    format!("declare `{owner}: {{ type: uuid, required: true }}`"),
                ),
                Some(f) if f.ty != FieldType::Uuid || f.encrypted => {
                    ctx.error(
                        "invalid_owner",
                        f.position,
                        format!("owner field `{owner}` must be an unencrypted uuid"),
                    );
                }
                Some(_) => {}
            }
        }
        for r in &e.relations {
            let Some(target) = by_name.get(r.entity.as_str()) else {
                ctx.error(
                    "unknown_entity",
                    r.position,
                    format!(
                        "relation `{}` refers to unknown entity `{}`",
                        r.name, r.entity
                    ),
                );
                continue;
            };
            match r.kind {
                RelationKind::BelongsTo => match e.field(&r.field) {
                    Some(f) if f.references.as_ref().is_some_and(|(te, _)| *te == r.entity) => {}
                    Some(_) => ctx.error_help(
                        "relation_mismatch",
                        r.position,
                        format!(
                            "`{}` must reference `{}` for relation `{}`",
                            r.field, r.entity, r.name
                        ),
                        format!("add `references: {}.id` to `{}`", r.entity, r.field),
                    ),
                    None => ctx.error(
                        "unknown_field",
                        r.position,
                        format!("`{}` is not a field of `{}`", r.field, e.name),
                    ),
                },
                RelationKind::HasMany => match target.field(&r.field) {
                    Some(f) if f.references.as_ref().is_some_and(|(te, _)| *te == e.name) => {}
                    Some(_) => ctx.error_help(
                        "relation_mismatch",
                        r.position,
                        format!(
                            "`{}.{}` must reference `{}` for relation `{}`",
                            r.entity, r.field, e.name, r.name
                        ),
                        format!(
                            "add `references: {}.id` to `{}.{}`",
                            e.name, r.entity, r.field
                        ),
                    ),
                    None => ctx.error(
                        "unknown_field",
                        r.position,
                        format!("`{}` is not a field of `{}`", r.field, r.entity),
                    ),
                },
            }
        }
        let visible = |n: &str| -> Option<bool> {
            // Some(encrypted?) if the column exists.
            if ["id", "created_at", "updated_at", "version"].contains(&n) {
                Some(false)
            } else {
                e.field(n).map(|f| f.encrypted)
            }
        };
        for (what, list) in [
            ("list_columns", &e.admin.list_columns),
            ("search_fields", &e.admin.search_fields),
        ] {
            for n in list {
                match visible(n) {
                    None => ctx.error(
                        "unknown_field",
                        e.position,
                        format!(
                            "admin `{what}` names `{n}`, which is not a field of `{}`",
                            e.name
                        ),
                    ),
                    Some(true) => ctx.error(
                        "invalid_attribute",
                        e.position,
                        format!("admin `{what}` cannot include encrypted field `{n}`"),
                    ),
                    Some(false) => {}
                }
            }
        }
    }
}

fn closest_help<'a>(word: &str, candidates: impl Iterator<Item = &'a str>) -> String {
    let all: Vec<&str> = candidates.collect();
    closest(word, &all).map_or_else(
        || "define it in `entities/`".to_string(),
        |c| format!("did you mean `{c}`?"),
    )
}

/// Attribute conditions and field masks (stage 2) must name declared fields and compare
/// them with values of the right type.
fn validate_stage2(ctx: &mut Ctx, entity: &Entity, r: &Rule) {
    for c in &r.when {
        let Some(f) = entity.field(&c.field) else {
            ctx.error_help(
                "unknown_where_field",
                r.position,
                format!(
                    "rule `{}`: `where` names `{}`, which `{}` does not declare",
                    r.id, c.field, entity.name
                ),
                closest_help(&c.field, entity.fields.iter().map(|f| f.name.as_str())),
            );
            continue;
        };
        if f.encrypted || matches!(f.ty, FieldType::Json | FieldType::Bytes) {
            ctx.error(
                "invalid_where",
                r.position,
                format!(
                    "rule `{}`: `where` cannot use `{}` (encrypted, json and bytes fields cannot be compared)",
                    r.id, c.field
                ),
            );
            continue;
        }
        for v in &c.values {
            let fits = match (v, &f.ty) {
                (IrCondValue::Bool(_), FieldType::Bool) => true,
                (IrCondValue::Int(_), t) => is_int_type(t),
                (IrCondValue::Text(_), FieldType::Text) => true,
                (IrCondValue::Text(s), FieldType::Uuid) => crate::values::parse_uuid(s).is_some(),
                (IrCondValue::Subject, FieldType::Uuid | FieldType::Text) => true,
                _ => false,
            };
            if !fits {
                ctx.error(
                    "invalid_where",
                    r.position,
                    format!(
                        "rule `{}`: a value in `where` does not fit the type of `{}`",
                        r.id, c.field
                    ),
                );
            }
        }
    }
    if let Some(fields) = &r.fields {
        for name in fields {
            match entity.field(name) {
                Some(_) => {}
                None => ctx.error_help(
                    "unknown_mask_field",
                    r.position,
                    format!(
                        "rule `{}`: `fields` names `{name}`, which `{}` does not declare",
                        r.id, entity.name
                    ),
                    closest_help(name, entity.fields.iter().map(|f| f.name.as_str())),
                ),
            }
        }
    }
}

fn validate_policies(
    diags: &mut Vec<Diagnostic>,
    tenancy: Tenancy,
    entities: &[(String, Entity)],
    policies: &[(String, Policy)],
) {
    let by_name: HashMap<&str, &Entity> =
        entities.iter().map(|(_, e)| (e.name.as_str(), e)).collect();
    let mut seen = HashSet::new();
    for (path, p) in policies {
        let mut ctx = Ctx { file: path, diags };
        if !seen.insert(p.entity.as_str()) {
            ctx.error(
                "duplicate_policy",
                p.position,
                format!("entity `{}` has two policy files", p.entity),
            );
        }
        let Some(entity) = by_name.get(p.entity.as_str()) else {
            ctx.error_help(
                "unknown_entity",
                p.position,
                format!("policy refers to unknown entity `{}`", p.entity),
                closest_help(&p.entity, by_name.keys().copied()),
            );
            continue;
        };
        for r in &p.rules {
            validate_stage2(&mut ctx, entity, r);
            if r.allow == Allow::Owner && entity.owner.is_none() {
                ctx.error_help(
                    "owner_without_owner_field",
                    r.position,
                    format!(
                        "rule `{}` uses `owner`, but `{}` declares no `owner` field",
                        r.id, entity.name
                    ),
                    format!("add `owner: <field>` to `entities/{}.yaml`", entity.name),
                );
            }
        }
        if !p.rules.iter().any(|r| r.actions.contains(&Action::Read)) {
            ctx.warn(
                "no_read_rule",
                p.position,
                format!(
                    "no rule grants `read` on `{}`; nobody can read it",
                    entity.name
                ),
            );
        }
    }
    for (path, e) in entities {
        if !policies.iter().any(|(_, p)| p.entity == e.name) {
            let mut ctx = Ctx { file: path, diags };
            // A table that holds tenant or owner data and has no policy is almost always
            // a mistake, and PostgreSQL row-level security is generated from policies.
            if tenancy != Tenancy::None || e.owner.is_some() {
                ctx.error_help(
                    "scoped_without_policy",
                    e.position,
                    format!(
                        "entity `{}` is tenant or owner scoped but has no policy",
                        e.name
                    ),
                    format!("add `policies/{}.yaml`", e.name),
                );
            } else {
                ctx.warn(
                    "no_policy",
                    e.position,
                    format!("entity `{}` has no policy; all access is denied", e.name),
                );
            }
        }
    }
}

fn validate_commands(
    diags: &mut Vec<Diagnostic>,
    entities: &[(String, Entity)],
    commands: &mut [(String, Command)],
) {
    let by_name: HashMap<&str, &Entity> =
        entities.iter().map(|(_, e)| (e.name.as_str(), e)).collect();
    let mut seen = HashSet::new();
    for (path, c) in commands.iter_mut() {
        let mut ctx = Ctx { file: path, diags };
        if !seen.insert(c.name.clone()) {
            ctx.error(
                "duplicate_command",
                c.position,
                format!("command `{}` is defined twice", c.name),
            );
        }
        let Some(entity) = by_name.get(c.entity.as_str()) else {
            ctx.error_help(
                "unknown_entity",
                c.position,
                format!("command refers to unknown entity `{}`", c.entity),
                closest_help(&c.entity, by_name.keys().copied()),
            );
            continue;
        };
        let pos = c.position;
        match c.kind {
            CommandKind::Custom => {
                if c.handler.is_none() {
                    ctx.error_help(
                        "missing_key",
                        pos,
                        "a `custom` command needs a `handler`",
                        "add `handler: <name>`",
                    );
                }
                if !c.set.is_empty() || c.target.is_some() {
                    ctx.error(
                        "invalid_attribute",
                        pos,
                        "a `custom` command cannot have `set` or `target`",
                    );
                }
            }
            kind => {
                if c.handler.is_some() {
                    ctx.error(
                        "invalid_attribute",
                        pos,
                        "`handler` is only for `custom` commands",
                    );
                }
                if matches!(kind, CommandKind::Update | CommandKind::Delete) {
                    match &c.target {
                        None => ctx.error_help(
                            "missing_key",
                            pos,
                            "`update` and `delete` commands need a `target`",
                            "add `target: <input field holding the row id>`",
                        ),
                        Some(t) => match c.input.iter().find(|i| &i.name == t) {
                            None => ctx.error(
                                "unknown_input",
                                pos,
                                format!("`target` names `{t}`, which is not an input"),
                            ),
                            Some(i) if i.ty != FieldType::Uuid => ctx.error(
                                "invalid_target",
                                pos,
                                format!("target input `{t}` must be a uuid"),
                            ),
                            Some(_) => {}
                        },
                    }
                } else if c.target.is_some() {
                    ctx.error(
                        "invalid_attribute",
                        pos,
                        "`target` is only for `update` and `delete` commands",
                    );
                }
                if kind == CommandKind::Delete && !c.set.is_empty() {
                    ctx.error(
                        "invalid_attribute",
                        pos,
                        "a `delete` command cannot have `set`",
                    );
                }
                if kind == CommandKind::Update && c.set.is_empty() {
                    ctx.error("missing_key", pos, "an `update` command needs a `set`");
                }
            }
        }
        let mut used_inputs: HashSet<String> = c.target.iter().cloned().collect();
        let mut set_names = HashSet::new();
        for (field, value) in &mut c.set {
            set_names.insert(field.clone());
            let Some(f) = entity.field(field) else {
                let hint = if BUILTIN_FIELDS.contains(&field.as_str()) {
                    "built-in fields are managed by the server".to_string()
                } else {
                    closest_help(field, entity.fields.iter().map(|f| f.name.as_str()))
                };
                ctx.error_help(
                    "unknown_field",
                    pos,
                    format!(
                        "`set` names `{field}`, which cannot be set on `{}`",
                        entity.name
                    ),
                    hint,
                );
                continue;
            };
            if entity.owner.as_deref() == Some(field.as_str()) {
                ctx.error_help(
                    "server_managed_field",
                    pos,
                    format!("`{field}` is the owner field and is set by the server"),
                    "remove it from `set`",
                );
                continue;
            }
            match value {
                SetValue::Input(name) => {
                    used_inputs.insert(name.clone());
                    match c.input.iter().find(|i| &i.name == name) {
                        None => ctx.error(
                            "unknown_input",
                            pos,
                            format!("`$input.{name}` is not declared under `input`"),
                        ),
                        Some(i) if i.ty != f.ty => ctx.error(
                            "type_mismatch",
                            pos,
                            format!("input `{name}` and field `{field}` have different types"),
                        ),
                        Some(_) => {}
                    }
                }
                SetValue::Text(s) if f.ty == FieldType::Timestamptz && s == "now" => {
                    *value = SetValue::Now
                }
                SetValue::Bool(_) if f.ty == FieldType::Bool => {}
                SetValue::Int(_) if is_int_type(&f.ty) => {}
                SetValue::Text(_) if f.ty == FieldType::Text => {}
                _ => ctx.error(
                    "type_mismatch",
                    pos,
                    format!("the value for `{field}` does not match its type"),
                ),
            }
        }
        if c.kind == CommandKind::Create {
            for f in &entity.fields {
                let server = entity.owner.as_deref() == Some(f.name.as_str());
                if f.required && f.default.is_none() && !server && !set_names.contains(&f.name) {
                    ctx.error_help(
                        "missing_required_field",
                        pos,
                        format!("a `create` command must set required field `{}`", f.name),
                        format!("add `{}: $input.{}`", f.name, f.name),
                    );
                }
            }
        }
        for i in &c.input {
            if !used_inputs.contains(&i.name) && c.kind != CommandKind::Custom {
                ctx.warn(
                    "unused_input",
                    pos,
                    format!("input `{}` is never used", i.name),
                );
            }
        }
    }
}
