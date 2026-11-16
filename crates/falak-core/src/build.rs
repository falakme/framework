//! Compiles a validated [`Project`] into the IR and computes its content hash.

use falak_contracts::{identity::TrustTier, ir::*};
use sha2::{Digest, Sha256};

use crate::schema::{self, Project};

fn builtin(name: &str, ty: FieldType, nullable: bool, default: Option<IrDefault>) -> IrField {
    IrField {
        name: name.to_string(),
        ty,
        nullable,
        unique: false,
        indexed: false,
        pii: false,
        encrypted: false,
        max_length: None,
        min: None,
        max: None,
        default,
        references: None,
        builtin: true,
    }
}

fn convert_field(f: &schema::Field) -> IrField {
    IrField {
        name: f.name.clone(),
        ty: f.ty.clone(),
        nullable: !f.required,
        unique: f.unique,
        indexed: f.indexed,
        pii: f.pii,
        encrypted: f.encrypted,
        max_length: f.max_length,
        min: f.min,
        max: f.max,
        default: f.default.as_ref().map(|d| match d {
            schema::DefaultValue::Bool(b) => IrDefault::Bool(*b),
            schema::DefaultValue::Int(i) => IrDefault::Int(*i),
            schema::DefaultValue::Text(s) => IrDefault::Text(s.clone()),
            schema::DefaultValue::Now => IrDefault::Now,
            schema::DefaultValue::NewUuid => IrDefault::NewUuid,
        }),
        references: f.references.clone(),
        builtin: false,
    }
}

fn convert_action(a: schema::Action) -> IrAction {
    match a {
        schema::Action::Read => IrAction::Read,
        schema::Action::Create => IrAction::Create,
        schema::Action::Update => IrAction::Update,
        schema::Action::Delete => IrAction::Delete,
    }
}

fn convert_entity(project: &Project, e: &schema::Entity) -> IrEntity {
    let mut fields = vec![builtin(
        "id",
        FieldType::Uuid,
        false,
        Some(IrDefault::NewUuid),
    )];
    fields.extend(e.fields.iter().map(convert_field));
    if project.app.tenancy == Tenancy::Row {
        fields.push(builtin("tenant_id", FieldType::Uuid, false, None));
    }
    fields.push(builtin(
        "version",
        FieldType::Int64,
        false,
        Some(IrDefault::Int(1)),
    ));
    fields.push(builtin(
        "created_at",
        FieldType::Timestamptz,
        false,
        Some(IrDefault::Now),
    ));
    fields.push(builtin(
        "updated_at",
        FieldType::Timestamptz,
        false,
        Some(IrDefault::Now),
    ));
    if e.lifecycle.soft_delete {
        fields.push(builtin("deleted_at", FieldType::Timestamptz, true, None));
    }
    let policy = project
        .policy(&e.name)
        .map_or_else(IrPolicy::default, |p| IrPolicy {
            rules: p
                .rules
                .iter()
                // A relationship rule whose path does not resolve is dropped, never
                // widened into an ordinary owner rule.
                .filter(|r| {
                    r.related.is_empty() || related_of(project, &e.name, &r.related).is_some()
                })
                .map(|r| IrRule {
                    id: r.id.clone(),
                    actions: r.actions.iter().copied().map(convert_action).collect(),
                    when: r.when.clone(),
                    fields: r.fields.clone(),
                    related: related_of(project, &e.name, &r.related),
                    allow: match &r.allow {
                        schema::Allow::Owner => IrAllow::Owner,
                        schema::Allow::Role(n) => IrAllow::Role(n.clone()),
                        schema::Allow::Authenticated => IrAllow::Authenticated,
                    },
                })
                .collect(),
        });
    IrEntity {
        name: e.name.clone(),
        table: e.table.clone(),
        owner: e.owner.clone(),
        fields,
        relations: e
            .relations
            .iter()
            .map(|r| IrRelation {
                name: r.name.clone(),
                kind: match r.kind {
                    schema::RelationKind::BelongsTo => IrRelationKind::BelongsTo,
                    schema::RelationKind::HasMany => IrRelationKind::HasMany,
                },
                entity: r.entity.clone(),
                field: r.field.clone(),
            })
            .collect(),
        policy,
        admin: IrAdmin {
            label: e.admin.label.clone(),
            list_columns: e.admin.list_columns.clone(),
            search_fields: e.admin.search_fields.clone(),
        },
        soft_delete: e.lifecycle.soft_delete,
        retention_days: e.lifecycle.retention_days,
        erasable: e.lifecycle.erasable,
    }
}

fn convert_command(c: &schema::Command) -> IrCommand {
    IrCommand {
        name: c.name.clone(),
        entity: c.entity.clone(),
        kind: match c.kind {
            schema::CommandKind::Create => IrCommandKind::Create,
            schema::CommandKind::Update => IrCommandKind::Update,
            schema::CommandKind::Delete => IrCommandKind::Delete,
            schema::CommandKind::Custom => IrCommandKind::Custom,
        },
        input: c
            .input
            .iter()
            .map(|i| IrInput {
                name: i.name.clone(),
                ty: i.ty.clone(),
                required: i.required,
                max_length: i.max_length,
            })
            .collect(),
        target: c.target.clone(),
        set: c
            .set
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    match v {
                        schema::SetValue::Bool(b) => IrSetValue::Bool(*b),
                        schema::SetValue::Int(i) => IrSetValue::Int(*i),
                        schema::SetValue::Text(s) => IrSetValue::Text(s.clone()),
                        schema::SetValue::Now => IrSetValue::Now,
                        schema::SetValue::Input(n) => IrSetValue::Input(n.clone()),
                    },
                )
            })
            .collect(),
        handler: c.handler.clone(),
        idempotent: c.idempotent,
    }
}

/// Compile a validated project into the IR, including its content hash.
pub fn build_ir(project: &Project) -> Ir {
    let mut entities: Vec<IrEntity> = project
        .entities
        .iter()
        .map(|e| convert_entity(project, e))
        .collect();
    entities.sort_by(|a, b| a.name.cmp(&b.name));
    let mut commands: Vec<IrCommand> = project.commands.iter().map(convert_command).collect();
    commands.sort_by(|a, b| a.name.cmp(&b.name));
    let mut queries: Vec<falak_contracts::ir::IrQuery> = project
        .queries
        .iter()
        .map(|q| falak_contracts::ir::IrQuery {
            name: q.name.clone(),
            params: q.params.clone(),
            sql: q.sql.clone(),
            entities: q.entities.clone(),
        })
        .collect();
    queries.sort_by(|a, b| a.name.cmp(&b.name));
    let (events, subscriptions, sagas) = federation_ir(project);
    let mut jobs = project.jobs.clone();
    jobs.sort_by(|a, b| a.name.cmp(&b.name));
    let mut drivers: Vec<String> = project
        .app
        .drivers
        .iter()
        .map(|d| d.name().to_string())
        .collect();
    drivers.sort();
    let mut ir = Ir {
        ir_version: IR_VERSION,
        content_hash: String::new(),
        app: IrApp {
            name: project.app.name.clone(),
            version: project.app.version.clone(),
            tenancy: project.app.tenancy,
            trust_tier: match project.app.trust_tier {
                TrustTier::Standard => "standard",
                TrustTier::Sensitive => "sensitive",
                TrustTier::HighAssurance => "high_assurance",
            }
            .to_string(),
            drivers,
        },
        entities,
        commands,
        queries,
        events,
        subscriptions,
        sagas,
        jobs,
    };
    ir.content_hash = compute_hash(&ir);
    ir
}

/// SHA-256 over the canonical JSON of the IR with `content_hash` blank. Structs
/// serialise in declaration order and collections are sorted by the builder, so the
/// bytes depend only on the app's content.
pub fn compute_hash(ir: &Ir) -> String {
    let mut blank = ir.clone();
    blank.content_hash = String::new();
    let bytes = serde_json::to_vec(&blank).expect("the IR always serialises");
    hex(&Sha256::digest(bytes))
}

/// True if the IR's recorded hash matches its content.
pub fn verify_hash(ir: &Ir) -> bool {
    ir.content_hash == compute_hash(ir)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The steps of a relationship rule, resolved to tables and columns. The loader has
/// already checked the path, so a path that does not resolve yields `None` and the rule
/// then reaches nothing (fail closed).
fn related_of(project: &Project, entity: &str, path: &[String]) -> Option<IrRelated> {
    if path.is_empty() {
        return None;
    }
    let mut current = project.entity(entity)?;
    let mut hops = Vec::new();
    for name in path {
        let rel = current.relations.iter().find(|r| r.name == *name)?;
        let next = project.entity(&rel.entity)?;
        hops.push(IrHop {
            column: rel.field.clone(),
            table: next.table.clone(),
            soft_delete: next.lifecycle.soft_delete,
        });
        current = next;
    }
    Some(IrRelated {
        path: path.to_vec(),
        hops,
        owner_column: current.owner.clone()?,
        tenant_scoped: project.app.tenancy == Tenancy::Row,
    })
}

/// Events, subscriptions and sagas in IR form. Payload field types are taken from the
/// entity as it is now, so the compatibility check sees a type change.
fn federation_ir(project: &Project) -> (Vec<IrEvent>, Vec<IrSubscription>, Vec<IrSaga>) {
    let mut events: Vec<IrEvent> = project
        .federation
        .publishes
        .iter()
        .map(|p| {
            let entity = project.entity(&p.entity);
            let mut subscribers = p.subscribers.clone();
            subscribers.sort();
            IrEvent {
                name: p.name.clone(),
                entity: p.entity.clone(),
                on: p.on,
                version: p.version,
                fields: p
                    .fields
                    .iter()
                    .filter_map(|f| {
                        entity.and_then(|e| e.field(f)).map(|f| IrEventField {
                            name: f.name.clone(),
                            ty: f.ty.clone(),
                        })
                    })
                    .collect(),
                subscribers,
            }
        })
        .collect();
    events.sort_by(|a, b| a.name.cmp(&b.name));
    let mut subs: Vec<IrSubscription> = project
        .federation
        .subscribes
        .iter()
        .map(|s| IrSubscription {
            event: s.event.clone(),
            from: s.from.clone(),
            version: s.version,
            handler: s.handler.clone(),
        })
        .collect();
    subs.sort_by(|a, b| (&a.from, &a.event).cmp(&(&b.from, &b.event)));
    let mut sagas: Vec<IrSaga> = project
        .federation
        .sagas
        .iter()
        .map(|s| IrSaga {
            name: s.name.clone(),
            start: s.start.clone(),
            steps: s.steps.clone(),
        })
        .collect();
    sagas.sort_by(|a, b| a.name.cmp(&b.name));
    (events, subs, sagas)
}
