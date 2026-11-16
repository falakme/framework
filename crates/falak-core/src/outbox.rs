//! The outbox and inbox (FEDERATION §13.2): SQL for the two tables an app that uses
//! events gets, and the statements that fill them.
//!
//! The outbox row is written in the same atomic batch as the business write, so a change
//! and its event happen together or not at all. The inbox row is written in the same
//! batch as the handler's write, so an event is applied once however often it arrives.

use falak_contracts::{
    driver::{Statement, Value},
    ir::{Ir, IrEntity, IrEvent, IrEventOn},
};

use crate::{sql::Dialect, values::format_uuid};

pub const OUTBOX: &str = "_falak_outbox";
pub const INBOX: &str = "_falak_inbox";

/// How long a sent outbox row is kept, in seconds (a week).
pub const OUTBOX_RETENTION_SECS: i64 = 7 * 86_400;
/// How long an inbox row is kept, in seconds. Longer than Office keeps an event, so a
/// redelivery within Office's horizon is always recognised.
pub const INBOX_RETENTION_SECS: i64 = 30 * 86_400;

fn ph(d: Dialect, n: usize) -> String {
    match d {
        Dialect::Postgres => format!("${n}"),
        Dialect::Sqlite | Dialect::D1 => format!("?{n}"),
    }
}

/// `CREATE TABLE` statements for the outbox and inbox. Idempotent.
pub fn tables(d: Dialect) -> Vec<String> {
    let (pk, int) = if d == Dialect::Postgres {
        ("BIGSERIAL PRIMARY KEY", "bigint")
    } else {
        ("INTEGER PRIMARY KEY AUTOINCREMENT", "INTEGER")
    };
    vec![
        format!(
            "CREATE TABLE IF NOT EXISTS \"{OUTBOX}\" (\"seq\" {pk}, \"id\" TEXT NOT NULL UNIQUE, \"event\" TEXT NOT NULL, \"entity\" TEXT NOT NULL, \"aggregate_id\" TEXT NOT NULL, \"revision\" {int} NOT NULL, \"schema_version\" {int} NOT NULL, \"payload\" TEXT NOT NULL, \"occurred_at\" {int} NOT NULL, \"sent_at\" {int})"
        ),
        format!(
            "CREATE INDEX IF NOT EXISTS \"idx_{OUTBOX}_unsent\" ON \"{OUTBOX}\" (\"sent_at\", \"seq\")"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS \"{INBOX}\" (\"event_id\" TEXT NOT NULL PRIMARY KEY, \"publisher\" TEXT NOT NULL, \"name\" TEXT NOT NULL, \"received_at\" {int} NOT NULL)"
        ),
    ]
}

/// The events an app raises for `on` a change to `entity`.
pub fn events_for<'a>(
    ir: &'a Ir,
    entity: &'a IrEntity,
    on: IrEventOn,
) -> impl Iterator<Item = &'a IrEvent> {
    ir.events
        .iter()
        .filter(move |e| e.entity == entity.name && e.on == on)
}

/// Outbox inserts for one change, to run in the same batch as the change itself.
/// `payload_of` gives the payload JSON for an event. `request_id` is a fresh id for this
/// change (the write's new id); with the event name it makes the event id.
///
/// After a create the row is known to exist because the batch is atomic. After an update
/// or delete the insert selects from the table with `updated_at` equal to this write's
/// timestamp, so it adds a row only if the write changed one.
#[allow(clippy::too_many_arguments)]
pub fn record(
    ir: &Ir,
    d: Dialect,
    entity: &IrEntity,
    on: IrEventOn,
    aggregate_id: [u8; 16],
    request_id: [u8; 16],
    now_micros: i64,
    mut payload_of: impl FnMut(&IrEvent) -> String,
) -> Vec<Statement> {
    events_for(ir, entity, on)
        .map(|ev| {
            let id = format!("{}:{}", format_uuid(&request_id), ev.name);
            let agg = format_uuid(&aggregate_id);
            let payload = payload_of(ev);
            let cols = "\"id\", \"event\", \"entity\", \"aggregate_id\", \"revision\", \"schema_version\", \"payload\", \"occurred_at\"";
            let mut params = vec![
                Value::Text(id),
                Value::Text(ev.name.clone()),
                Value::Text(entity.name.clone()),
                Value::Text(agg),
            ];
            let sql = if on == IrEventOn::Create {
                params.extend([
                    Value::Int64(1),
                    Value::Int64(i64::from(ev.version)),
                    Value::Text(payload),
                    Value::Int64(now_micros),
                ]);
                let vals: Vec<String> = (1..=params.len()).map(|n| ph(d, n)).collect();
                format!(
                    "INSERT INTO \"{OUTBOX}\" ({cols}) VALUES ({})",
                    vals.join(", ")
                )
            } else {
                params.extend([
                    Value::Int64(i64::from(ev.version)),
                    Value::Text(payload),
                    Value::Int64(now_micros),
                    Value::Uuid(aggregate_id),
                    Value::TimestampMicros(now_micros),
                ]);
                format!(
                    "INSERT INTO \"{OUTBOX}\" ({cols}) SELECT {}, {}, {}, {}, t.\"version\", {}, {}, {} FROM \"{}\" t WHERE t.\"id\" = {} AND t.\"updated_at\" = {}",
                    ph(d, 1),
                    ph(d, 2),
                    ph(d, 3),
                    ph(d, 4),
                    ph(d, 5),
                    ph(d, 6),
                    ph(d, 7),
                    entity.table,
                    ph(d, 8),
                    ph(d, 9),
                )
            };
            Statement::new(sql, params)
        })
        .collect()
}

/// An outbox row waiting to be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    pub seq: i64,
    pub id: String,
    pub event: String,
    pub entity: String,
    pub aggregate_id: String,
    pub revision: i64,
    pub schema_version: i64,
    pub payload: String,
    pub occurred_at: i64,
}

/// The oldest `limit` unsent rows, in write order.
pub fn pending(d: Dialect, limit: u32) -> Statement {
    let _ = d;
    Statement::new(
        format!(
            "SELECT \"seq\", \"id\", \"event\", \"entity\", \"aggregate_id\", \"revision\", \"schema_version\", \"payload\", \"occurred_at\" FROM \"{OUTBOX}\" WHERE \"sent_at\" IS NULL ORDER BY \"seq\" LIMIT {limit}"
        ),
        vec![],
    )
}

pub fn parse_row(row: &[Value]) -> Option<OutboxRow> {
    let int = |v: &Value| match v {
        Value::Int64(n) | Value::TimestampMicros(n) => Some(*n),
        _ => None,
    };
    let text = |v: &Value| match v {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    };
    Some(OutboxRow {
        seq: int(row.first()?)?,
        id: text(row.get(1)?)?,
        event: text(row.get(2)?)?,
        entity: text(row.get(3)?)?,
        aggregate_id: text(row.get(4)?)?,
        revision: int(row.get(5)?)?,
        schema_version: int(row.get(6)?)?,
        payload: text(row.get(7)?)?,
        occurred_at: int(row.get(8)?)?,
    })
}

pub fn mark_sent(d: Dialect, seq: i64, now_micros: i64) -> Statement {
    Statement::new(
        format!(
            "UPDATE \"{OUTBOX}\" SET \"sent_at\" = {} WHERE \"seq\" = {}",
            ph(d, 1),
            ph(d, 2)
        ),
        vec![Value::Int64(now_micros), Value::Int64(seq)],
    )
}

/// Delete sent rows older than the retention period.
pub fn prune(d: Dialect, now_micros: i64) -> Vec<Statement> {
    let cut = |secs: i64| Value::Int64(now_micros - secs * 1_000_000);
    vec![
        Statement::new(
            format!(
                "DELETE FROM \"{OUTBOX}\" WHERE \"sent_at\" IS NOT NULL AND \"sent_at\" < {}",
                ph(d, 1)
            ),
            vec![cut(OUTBOX_RETENTION_SECS)],
        ),
        Statement::new(
            format!(
                "DELETE FROM \"{INBOX}\" WHERE \"received_at\" < {}",
                ph(d, 1)
            ),
            vec![cut(INBOX_RETENTION_SECS)],
        ),
    ]
}

/// Whether the inbox has seen this event.
pub fn inbox_seen(d: Dialect, event_id: &str) -> Statement {
    Statement::new(
        format!(
            "SELECT 1 FROM \"{INBOX}\" WHERE \"event_id\" = {}",
            ph(d, 1)
        ),
        vec![Value::Text(event_id.to_owned())],
    )
}

/// Record an event as applied. Run first in the handler's batch: a repeat violates the
/// primary key and the whole batch, including the handler's write, is rolled back.
pub fn inbox_record(
    d: Dialect,
    event_id: &str,
    publisher: &str,
    name: &str,
    now_micros: i64,
) -> Statement {
    Statement::new(
        format!(
            "INSERT INTO \"{INBOX}\" (\"event_id\", \"publisher\", \"name\", \"received_at\") VALUES ({}, {}, {}, {})",
            ph(d, 1),
            ph(d, 2),
            ph(d, 3),
            ph(d, 4)
        ),
        vec![
            Value::Text(event_id.to_owned()),
            Value::Text(publisher.to_owned()),
            Value::Text(name.to_owned()),
            Value::Int64(now_micros),
        ],
    )
}

/// The text a publisher signs for an event (FEDERATION §13.4). It covers the identity of
/// the event, what it is about and a hash of the payload, so none of them can be changed
/// in transit.
#[allow(clippy::too_many_arguments)]
pub fn signing_message(
    publisher: &str,
    id: &str,
    event: &str,
    aggregate_type: &str,
    aggregate_id: &str,
    revision: i64,
    version: i64,
    occurred_at: i64,
    payload_sha256: &str,
) -> String {
    format!(
        "falak-event\n{publisher}\n{id}\n{event}\n{aggregate_type}\n{aggregate_id}\n{revision}\n{version}\n{occurred_at}\n{payload_sha256}"
    )
}
