//! Durable events on the app side (FEDERATION §13): the outbox written with each change,
//! the relay that sends it, and the inbox that applies what arrives exactly once.

use falak_contracts::support::IdGenerator as _;
use falak_contracts::{
    Error, ErrorKind, Result,
    driver::{Statement, Value},
    identity::{Principal, RequestContext},
    ir::{FieldType, Ir, IrCommandKind, IrDefault, IrEntity, IrEvent, IrEventOn, IrField},
};
use falak_core::{
    command::{self, Plan},
    outbox::{self, OutboxRow},
    policy::authorize,
    sql::{Dialect, Request, Scope, WriteContext},
    values::format_uuid,
};
use serde_json::{Map, Value as Json, json};

use crate::{
    driver::NativeDriver,
    json::{format_timestamp, json_to_driver_value},
};

/// The role an event handler's write runs with. A policy on the handler's entity must
/// allow it (`allow: { role: event_consumer }`) for events to be applied.
pub const CONSUMER_ROLE: &str = "event_consumer";

fn value_json(v: &Value) -> Json {
    match v {
        Value::Null => Json::Null,
        Value::Bool(b) => json!(b),
        Value::Int64(i) => json!(i),
        Value::Float64(f) => json!(f),
        Value::Text(s) => json!(s),
        Value::Bytes(b) => json!(hex::encode(b)),
        Value::Uuid(u) => json!(format_uuid(u)),
        Value::TimestampMicros(t) => json!(format_timestamp(*t)),
    }
}

fn default_json(f: &IrField, now: i64) -> Option<Json> {
    match f.default.as_ref()? {
        IrDefault::Bool(b) => Some(json!(b)),
        IrDefault::Int(i) => Some(json!(i)),
        IrDefault::Text(s) => Some(json!(s)),
        IrDefault::Now => Some(json!(format_timestamp(now))),
        IrDefault::NewUuid => None,
    }
}

/// The payload of `event` for a change: its declared fields among the values the change
/// carries (on create, a declared default fills a missing one), plus `id`.
fn payload(
    ev: &IrEvent,
    entity: &IrEntity,
    id: [u8; 16],
    known: &[(String, Value)],
    on: IrEventOn,
    now: i64,
) -> String {
    let mut m = Map::new();
    m.insert("id".into(), json!(format_uuid(&id)));
    for f in &ev.fields {
        let v = known
            .iter()
            .find(|(n, _)| *n == f.name)
            .map(|(_, v)| value_json(v));
        let v = v.or_else(|| {
            (on == IrEventOn::Create)
                .then(|| entity.field(&f.name).and_then(|ef| default_json(ef, now)))
                .flatten()
        });
        if let Some(v) = v {
            m.insert(f.name.clone(), v);
        }
    }
    Json::Object(m).to_string()
}

/// Outbox inserts to put in the same batch as a change. Empty if the app raises no event
/// for it.
#[allow(clippy::too_many_arguments)]
pub fn outbox_statements(
    ir: &Ir,
    dialect: Dialect,
    entity: &IrEntity,
    on: IrEventOn,
    aggregate_id: [u8; 16],
    write: &WriteContext,
    known: &[(String, Value)],
) -> Vec<Statement> {
    if ir.events.is_empty() {
        return Vec::new();
    }
    outbox::record(
        ir,
        dialect,
        entity,
        on,
        aggregate_id,
        write.new_id,
        write.now_micros,
        |ev| payload(ev, entity, aggregate_id, known, on, write.now_micros),
    )
}

// ---------------------------------------------------------------- relay

/// What one relay pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RelayReport {
    pub sent: usize,
    /// Why the pass stopped early. The rows stay in the outbox for the next pass.
    pub stopped: Option<String>,
}

fn system_ctx(name: &str) -> RequestContext {
    RequestContext {
        principal: None,
        request_id: name.to_owned(),
    }
}

/// Send unsent outbox rows in write order, stopping at the first failure so order is
/// kept. `send` must return only after Office has stored the event (persist before
/// acknowledge); only then is the row marked sent. Sending the same event twice is safe:
/// Office deduplicates by id.
pub async fn relay_once<D: NativeDriver>(
    driver: &D,
    dialect: Dialect,
    limit: u32,
    now_micros: i64,
    send: impl AsyncFn(&OutboxRow) -> std::result::Result<(), String>,
) -> Result<RelayReport> {
    let ctx = system_ctx("falak-relay");
    let rows = driver.query(&ctx, outbox::pending(dialect, limit)).await?;
    let mut report = RelayReport::default();
    for r in rows.rows.iter().filter_map(|r| outbox::parse_row(r)) {
        if let Err(why) = send(&r).await {
            report.stopped = Some(why);
            return Ok(report);
        }
        driver
            .batch(&ctx, vec![outbox::mark_sent(dialect, r.seq, now_micros)])
            .await?;
        report.sent += 1;
    }
    // Retention: sent rows and old inbox rows are removed.
    driver
        .batch(&ctx, outbox::prune(dialect, now_micros))
        .await?;
    Ok(report)
}

// ---------------------------------------------------------------- inbox

/// An event delivered to this app, already checked for authenticity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub id: String,
    pub publisher: String,
    pub name: String,
    pub version: u32,
    /// The payload as JSON text.
    pub payload: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// The handler ran and the event is recorded.
    Applied,
    /// The inbox had it already; nothing ran.
    Duplicate,
    /// The app does not subscribe to this event.
    Ignored,
}

/// Why an event was not applied. `Retry` may succeed later; `Permanent` will not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError {
    Retry(String),
    Permanent(String),
}

/// Apply a delivered event: run the subscription's handler and record the event in the
/// inbox in one atomic batch, so it takes effect once however often it is delivered.
pub async fn apply<D: NativeDriver>(
    driver: &D,
    ir: &Ir,
    dialect: Dialect,
    d: &Delivery,
    now_micros: i64,
) -> std::result::Result<Applied, ApplyError> {
    let Some(sub) = ir
        .subscriptions
        .iter()
        .find(|s| s.from == d.publisher && s.event == d.name)
    else {
        return Ok(Applied::Ignored);
    };
    if sub.version != d.version {
        return Err(ApplyError::Permanent(format!(
            "event `{}` is version {}, this app consumes version {}",
            d.name, d.version, sub.version
        )));
    }
    let principal = Principal {
        subject: format!("event:{}", d.publisher),
        tenant: None,
        roles: vec![CONSUMER_ROLE.to_owned()],
    };
    let ctx = RequestContext {
        principal: Some(principal.clone()),
        request_id: format!("event:{}", d.id),
    };
    let retry = |e: Error| ApplyError::Retry(e.public_message().to_owned());
    let seen = driver
        .query(&ctx, outbox::inbox_seen(dialect, &d.id))
        .await
        .map_err(retry)?;
    if !seen.rows.is_empty() {
        return Ok(Applied::Duplicate);
    }
    let command = ir
        .commands
        .iter()
        .find(|c| c.name == sub.handler)
        .filter(|c| c.kind == IrCommandKind::Create)
        .ok_or_else(|| ApplyError::Permanent("the handler is not a create command".into()))?;
    let entity = ir
        .entity(&command.entity)
        .ok_or_else(|| ApplyError::Permanent("the handler's entity is missing".into()))?;
    let body: Json = serde_json::from_str(&d.payload)
        .map_err(|_| ApplyError::Permanent("the payload is not JSON".into()))?;
    let body = body
        .as_object()
        .ok_or_else(|| ApplyError::Permanent("the payload is not an object".into()))?;
    let mut inputs = Vec::new();
    for inp in &command.input {
        let Some(v) = body.get(&inp.name) else {
            continue;
        };
        let field = IrField {
            name: inp.name.clone(),
            ty: inp.ty.clone(),
            nullable: !inp.required,
            unique: false,
            indexed: false,
            pii: false,
            encrypted: false,
            max_length: inp.max_length,
            min: None,
            max: None,
            default: None,
            references: None,
            builtin: false,
        };
        let value = json_to_driver_value(v, &field)
            .map_err(|e| ApplyError::Permanent(e.public_message().to_owned()))?;
        inputs.push((inp.name.clone(), value));
    }
    let access = authorize(
        entity,
        falak_contracts::ir::IrAction::Create,
        Some(&principal),
    );
    let scope = Scope {
        tenant: None,
        subject: Some(principal.subject.clone()),
    };
    let write = WriteContext {
        now_micros,
        new_id: falak_auth::system::RandomIds.new_id(),
    };
    let req = Request {
        ir,
        entity,
        dialect,
        access: &access,
        scope: &scope,
    };
    let stmt = match command::plan(req, command, &inputs, None, &write) {
        Ok(Plan::Run(s)) => s,
        Ok(Plan::Denied) => {
            return Err(ApplyError::Permanent(
                "the app's policy does not let `event_consumer` create this row".into(),
            ));
        }
        Err(e) => return Err(ApplyError::Permanent(e.public_message().to_owned())),
    };
    let batch = vec![
        outbox::inbox_record(dialect, &d.id, &d.publisher, &d.name, now_micros),
        stmt,
    ];
    match driver.batch(&ctx, batch).await {
        Ok(_) => Ok(Applied::Applied),
        Err(e) => {
            // A concurrent delivery may have won: then the event is applied.
            let seen = driver
                .query(&ctx, outbox::inbox_seen(dialect, &d.id))
                .await
                .map_err(retry)?;
            if !seen.rows.is_empty() {
                Ok(Applied::Duplicate)
            } else if matches!(e.kind(), ErrorKind::InvalidInput | ErrorKind::Forbidden) {
                Err(ApplyError::Permanent(e.public_message().to_owned()))
            } else {
                Err(retry(e))
            }
        }
    }
}

/// The field types a payload carries, for tests and tools.
pub fn payload_types(ev: &IrEvent) -> Vec<(&str, &FieldType)> {
    ev.fields.iter().map(|f| (f.name.as_str(), &f.ty)).collect()
}
