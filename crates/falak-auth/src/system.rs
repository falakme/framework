//! Real clock and random ids for production use.

use falak_contracts::support::{Clock, IdGenerator};
use rand_core::{OsRng, RngCore};

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_micros(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
    }
}

/// Random version 4 UUIDs from the operating system's random source.
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomIds;

impl IdGenerator for RandomIds {
    fn new_id(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        OsRng.fill_bytes(&mut b);
        b[6] = (b[6] & 0x0f) | 0x40; // version 4
        b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_version_4_and_unique() {
        let g = RandomIds;
        let (a, b) = (g.new_id(), g.new_id());
        assert_ne!(a, b);
        assert_eq!(a[6] >> 4, 4);
        assert_eq!(a[8] >> 6, 0b10);
    }

    #[test]
    fn the_clock_is_after_2025() {
        assert!(SystemClock.now_micros() > 1_735_000_000_000_000);
    }
}
