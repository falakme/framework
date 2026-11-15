//! Injected sources of time and identifiers, so behaviour is deterministic in tests.

/// The wall clock in microseconds since the Unix epoch, UTC.
///
/// `SystemTime::now` panics on `wasm32-unknown-unknown`, so on the edge this reads
/// JavaScript's `Date` instead. Use this, not `SystemTime`, in code that can run there.
pub fn wall_clock_micros() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() * 1000.0) as i64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
    }
}

pub trait Clock {
    /// Microseconds since the Unix epoch, UTC.
    fn now_micros(&self) -> i64;
}

pub trait IdGenerator {
    /// A new unique identifier (UUID bytes).
    fn new_id(&self) -> [u8; 16];
}
