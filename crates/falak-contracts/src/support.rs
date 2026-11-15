//! Injected sources of time and identifiers, so behaviour is deterministic in tests.

pub trait Clock {
    /// Microseconds since the Unix epoch, UTC.
    fn now_micros(&self) -> i64;
}

pub trait IdGenerator {
    /// A new unique identifier (UUID bytes).
    fn new_id(&self) -> [u8; 16];
}
