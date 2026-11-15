//! Cross-app events. Delivery is at-least-once and ordered per aggregate; consumers
//! deduplicate by event id.

use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub id: [u8; 16],
    pub aggregate_type: String,
    pub aggregate_id: String,
    /// Increases by one per change to the aggregate.
    pub revision: u64,
    pub kind: String,
    /// Version of the event contract the payload follows.
    pub schema_version: u32,
    /// JSON bytes.
    pub payload: Vec<u8>,
    pub occurred_at_micros: i64,
}

pub trait EventPublisher {
    /// Returns only after the events are durably recorded.
    async fn publish(&self, events: Vec<Event>) -> Result<()>;
}
