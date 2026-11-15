//! Request rate limiting (T2.10).
//!
//! A *generic cell rate algorithm* (GCRA) limiter: each key holds one number, the time
//! its "bucket" will be empty again. That makes a check O(1), the state tiny, and the
//! result exact for bursts and steady rates.
//!
//! * `limit` requests are allowed per `window`. A caller may burst up to `limit`, then is
//!   held to `limit / window`.
//! * Keys are chosen by the caller: the verified subject for signed-in requests, the IP
//!   address otherwise. Never a header the client controls for signed-in requests.
//! * The state is per process. On Cloudflare Workers each isolate has its own copy, so
//!   this limits one isolate only. For a global limit use the Workers Rate Limiting
//!   binding or a Durable Object behind the same [`Decision`] type.
//! * The number of tracked keys is capped, so an attacker who varies the key (for example
//!   with many IP addresses) cannot make memory grow without bound. When the cap is
//!   reached, expired keys are dropped first, then the request is limited as if the key
//!   were full, which fails closed.
//!
//! Time is passed in, so tests need no clock.

use std::collections::HashMap;

/// Settings for one limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// Requests allowed per window (also the largest burst).
    pub limit: u32,
    /// Window length, in seconds.
    pub window_secs: u32,
}

/// What to tell the caller. Fields map to the headers in API specification §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    /// `RateLimit-Limit`.
    pub limit: u32,
    /// `RateLimit-Remaining`.
    pub remaining: u32,
    /// `RateLimit-Reset`: seconds until the bucket is full again.
    pub reset_secs: u32,
    /// `Retry-After`: seconds to wait before retrying. `0` when allowed.
    pub retry_after_secs: u32,
}

impl Decision {
    /// Headers to add to the response, as `(name, value)`. `Retry-After` appears only when
    /// the request was refused.
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let mut h = vec![
            ("RateLimit-Limit", self.limit.to_string()),
            ("RateLimit-Remaining", self.remaining.to_string()),
            ("RateLimit-Reset", self.reset_secs.to_string()),
        ];
        if !self.allowed {
            h.push(("Retry-After", self.retry_after_secs.to_string()));
        }
        h
    }
}

/// An in-memory limiter.
#[derive(Debug)]
pub struct Limiter {
    rate: Rate,
    /// Microseconds each request "costs".
    interval_us: i64,
    /// Key to the time (micros) its bucket is empty again.
    tat: HashMap<String, i64>,
    max_keys: usize,
}

const US: i64 = 1_000_000;

impl Limiter {
    /// `max_keys` caps memory; 100,000 is a reasonable value.
    ///
    /// # Panics
    /// If `limit` or `window_secs` is zero: a limiter that allows nothing is a mistake.
    pub fn new(rate: Rate, max_keys: usize) -> Self {
        assert!(
            rate.limit > 0 && rate.window_secs > 0,
            "rate must be positive"
        );
        Self {
            rate,
            interval_us: i64::from(rate.window_secs) * US / i64::from(rate.limit),
            tat: HashMap::new(),
            max_keys: max_keys.max(1),
        }
    }

    /// Count one request from `key` at `now_micros` and decide.
    pub fn check(&mut self, key: &str, now_micros: i64) -> Decision {
        let window_us = i64::from(self.rate.window_secs) * US;
        let current = self
            .tat
            .get(key)
            .copied()
            .unwrap_or(now_micros)
            .max(now_micros);
        // The bucket is full of requests when `tat - now` reaches the window.
        let new_tat = current + self.interval_us;
        let backlog = new_tat - now_micros;

        if backlog > window_us {
            let retry_us = backlog - window_us;
            return Decision {
                allowed: false,
                limit: self.rate.limit,
                remaining: 0,
                reset_secs: secs_up(current - now_micros),
                retry_after_secs: secs_up(retry_us).max(1),
            };
        }

        if !self.tat.contains_key(key) && self.tat.len() >= self.max_keys {
            self.tat.retain(|_, t| *t > now_micros);
            if self.tat.len() >= self.max_keys {
                // Table full of live keys: refuse rather than grow.
                return Decision {
                    allowed: false,
                    limit: self.rate.limit,
                    remaining: 0,
                    reset_secs: self.rate.window_secs,
                    retry_after_secs: 1,
                };
            }
        }
        self.tat.insert(key.to_owned(), new_tat);
        let used = backlog / self.interval_us.max(1);
        let remaining = i64::from(self.rate.limit) - used;
        Decision {
            allowed: true,
            limit: self.rate.limit,
            remaining: u32::try_from(remaining.max(0)).unwrap_or(0),
            reset_secs: secs_up(backlog),
            retry_after_secs: 0,
        }
    }

    /// Forget keys whose bucket is empty. Call now and then to keep memory small.
    pub fn sweep(&mut self, now_micros: i64) {
        self.tat.retain(|_, t| *t > now_micros);
    }

    /// Keys currently tracked.
    pub fn len(&self) -> usize {
        self.tat.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tat.is_empty()
    }
}

fn secs_up(micros: i64) -> u32 {
    u32::try_from((micros.max(0) + US - 1) / US).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 1_000_000;

    fn limiter(limit: u32, window: u32) -> Limiter {
        Limiter::new(
            Rate {
                limit,
                window_secs: window,
            },
            1000,
        )
    }

    #[test]
    fn allows_a_burst_up_to_the_limit_then_refuses() {
        let mut l = limiter(5, 10);
        for i in 0..5 {
            let d = l.check("a", 0);
            assert!(d.allowed, "request {i}");
            assert_eq!(d.remaining, 4 - i);
        }
        let d = l.check("a", 0);
        assert!(!d.allowed);
        assert_eq!(d.remaining, 0);
        assert!(d.retry_after_secs >= 1);
    }

    #[test]
    fn refills_at_the_steady_rate() {
        let mut l = limiter(5, 10); // one request every 2 seconds
        for _ in 0..5 {
            assert!(l.check("a", 0).allowed);
        }
        assert!(!l.check("a", 0).allowed);
        assert!(!l.check("a", S).allowed, "1s: not yet");
        assert!(l.check("a", 2 * S).allowed, "2s: one slot back");
        assert!(!l.check("a", 2 * S).allowed);
        // After a full window everything is back.
        for _ in 0..5 {
            assert!(l.check("a", 100 * S).allowed);
        }
    }

    #[test]
    fn retry_after_is_honest() {
        let mut l = limiter(2, 10); // one every 5 seconds
        assert!(l.check("a", 0).allowed);
        assert!(l.check("a", 0).allowed);
        let d = l.check("a", 0);
        assert!(!d.allowed);
        assert_eq!(d.retry_after_secs, 5);
        assert!(l.check("a", 5 * S).allowed, "waiting that long works");
    }

    #[test]
    fn keys_are_independent() {
        let mut l = limiter(1, 60);
        assert!(l.check("a", 0).allowed);
        assert!(!l.check("a", 0).allowed);
        assert!(l.check("b", 0).allowed);
    }

    #[test]
    fn refused_requests_do_not_push_the_bucket_further() {
        let mut l = limiter(2, 10);
        l.check("a", 0);
        l.check("a", 0);
        for _ in 0..1000 {
            assert!(!l.check("a", 0).allowed);
        }
        // One interval later a request is allowed again; the refusals cost nothing.
        assert!(l.check("a", 5 * S).allowed);
    }

    #[test]
    fn headers_follow_the_api_specification() {
        let mut l = limiter(2, 10);
        let ok = l.check("a", 0).headers();
        assert_eq!(ok[0], ("RateLimit-Limit", "2".to_string()));
        assert_eq!(ok[1], ("RateLimit-Remaining", "1".to_string()));
        assert!(ok.iter().all(|(n, _)| *n != "Retry-After"));
        l.check("a", 0);
        let refused = l.check("a", 0).headers();
        assert_eq!(refused.last().unwrap().0, "Retry-After");
    }

    #[test]
    fn memory_is_capped_and_fails_closed() {
        let mut l = Limiter::new(
            Rate {
                limit: 1,
                window_secs: 60,
            },
            3,
        );
        for k in ["a", "b", "c"] {
            assert!(l.check(k, 0).allowed);
        }
        assert_eq!(l.len(), 3);
        // A fourth live key is refused, and the table does not grow.
        assert!(!l.check("d", 0).allowed);
        assert_eq!(l.len(), 3);
        // Known keys are still tracked normally.
        assert!(!l.check("a", 0).allowed);
        // Once old buckets empty, room appears.
        assert!(l.check("d", 61 * S).allowed);
        assert!(l.len() <= 3);
    }

    #[test]
    fn sweep_drops_empty_buckets() {
        let mut l = limiter(1, 10);
        l.check("a", 0);
        l.check("b", 0);
        assert_eq!(l.len(), 2);
        l.sweep(5 * S);
        assert_eq!(l.len(), 2);
        l.sweep(11 * S);
        assert!(l.is_empty());
    }

    #[test]
    #[should_panic(expected = "rate must be positive")]
    fn zero_rate_is_a_mistake() {
        let _ = limiter(0, 10);
    }

    #[test]
    fn extreme_times_do_not_overflow() {
        let mut l = limiter(100, 1);
        let _ = l.check("a", i64::MAX / 4);
        let _ = l.check("a", 0);
    }
}
