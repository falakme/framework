//! Rate limits on the edge, backed by Cloudflare's rate limit binding (T2.10).
//!
//! Isolates share no memory, so a counter in memory would limit one isolate, not the
//! client. The binding counts per Cloudflare location. It is approximate, which is
//! enough for abuse limits, and it tells us only yes or no, so the response carries no
//! `RateLimit-*` headers, only `Retry-After` when refused.

use std::{future::Future, pin::Pin};

use falak_auth::ratelimit::Decision;
use falak_runtime_native::limits::RateGate;
use worker::{RateLimiter, send::SendFuture};

pub struct EdgeGate {
    limiter: RateLimiter,
    /// Keeps two apps that share a binding namespace apart.
    prefix: String,
    /// The binding's period, for `Retry-After`.
    period_secs: u32,
}

impl EdgeGate {
    pub fn new(limiter: RateLimiter, app: &str, period_secs: u32) -> Self {
        Self {
            limiter,
            prefix: app.to_owned(),
            period_secs,
        }
    }
}

impl RateGate for EdgeGate {
    fn check<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>> {
        Box::pin(SendFuture::new(async move {
            let allowed = match self.limiter.limit(format!("{}:{key}", self.prefix)).await {
                Ok(outcome) => outcome.success,
                // If the binding fails, let the request through: a limiter outage must
                // not take the app down. The platform's own protections still apply.
                Err(_) => true,
            };
            // `limit: 0` means the counts are unknown.
            Decision {
                allowed,
                limit: 0,
                remaining: 0,
                reset_secs: self.period_secs,
                retry_after_secs: if allowed { 0 } else { self.period_secs },
            }
        }))
    }
}
