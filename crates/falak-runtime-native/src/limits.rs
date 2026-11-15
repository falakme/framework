//! Request limits for both runtimes (T2.10): how often, how big, how long.
//!
//! * **Rate.** A [`RateGate`] counts requests per client address. `falak serve` uses
//!   [`MemoryGate`]. The edge runtime plugs in Cloudflare's rate limit binding, because
//!   isolates share no memory.
//! * **Size.** Request bodies over [`Limits::max_body_bytes`] are refused with 413.
//! * **Time.** `falak serve` ends a request that runs longer than [`Limits::timeout`]
//!   with 504. Workers enforce their own CPU and wall time limits, so the edge sets no
//!   timer.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use falak_auth::ratelimit::{Decision, Limiter, Rate};
use falak_contracts::{Error, ErrorKind, support::wall_clock_micros};

use crate::{auth_routes::peer_ip, context::extract_request_id, error::problem_response};

/// Requests per minute per client address on the data routes.
pub const DATA_RATE: Rate = Rate {
    limit: 600,
    window_secs: 60,
};

/// Largest request body on the data routes.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Longest a request may run under `falak serve`.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Counts requests per key and says whether to let one through.
pub trait RateGate: Send + Sync + 'static {
    fn check<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>>;
}

/// A gate that keeps its counts in this process.
pub struct MemoryGate {
    limiter: Mutex<Limiter>,
}

impl MemoryGate {
    pub fn new(rate: Rate) -> Self {
        Self {
            limiter: Mutex::new(Limiter::new(rate, 100_000)),
        }
    }
}

impl RateGate for MemoryGate {
    fn check<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>> {
        Box::pin(async move {
            self.limiter
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .check(key, wall_clock_micros())
        })
    }
}

/// What to enforce on the data routes.
#[derive(Clone)]
pub struct Limits {
    /// `None` turns the rate limit off.
    pub rate: Option<Arc<dyn RateGate>>,
    pub max_body_bytes: usize,
    /// `None` sets no timer. Used by the edge, which has the platform's own limits.
    pub timeout: Option<Duration>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            rate: Some(Arc::new(MemoryGate::new(DATA_RATE))),
            max_body_bytes: MAX_BODY_BYTES,
            timeout: if cfg!(feature = "server") {
                Some(REQUEST_TIMEOUT)
            } else {
                None
            },
        }
    }
}

/// The rate limit and its headers, as a layer for the data routes.
pub async fn rate_limit(
    State(gate): State<Arc<dyn RateGate>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_owned();
    // Probes must work when a client is being limited.
    if path == "/healthz" || path == "/readyz" {
        return next.run(req).await;
    }
    let request_id = extract_request_id(req.headers());
    let key = peer_ip(&req).map_or_else(|| "unknown".to_owned(), |ip| ip.to_string());
    let decision = gate.check(&key).await;

    let mut res = if decision.allowed {
        next.run(req).await
    } else {
        problem_response(
            &Error::new(
                ErrorKind::RateLimited,
                "rate_limited",
                "Too many requests. Please retry later.",
            ),
            &path,
            &request_id,
            vec![],
        )
    };
    for (name, value) in decision.headers() {
        // `limit: 0` means the gate does not know its counts (the edge binding says only
        // yes or no): send `Retry-After` when refused, and no made-up counts.
        if decision.limit == 0 && name != "Retry-After" {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            res.headers_mut().insert(n, v);
        }
    }
    res
}

/// Turn the 413 that Axum's body limit produces into a problem document, like every
/// other error.
pub async fn problem_for_oversize(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let request_id = extract_request_id(req.headers());
    let res = next.run(req).await;
    if res.status() == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        return problem_response(
            &Error::new(
                ErrorKind::PayloadTooLarge,
                "payload_too_large",
                "The request body is too large.",
            ),
            &path,
            &request_id,
            vec![],
        );
    }
    res
}

/// End a request that runs longer than the limit with a 504 problem document.
#[cfg(feature = "server")]
pub async fn time_limit(State(limit): State<Duration>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let request_id = extract_request_id(req.headers());
    match tokio::time::timeout(limit, next.run(req)).await {
        Ok(res) => res,
        Err(_) => problem_response(
            &Error::new(
                ErrorKind::Timeout,
                "execution_timeout",
                "The operation timed out.",
            ),
            &path,
            &request_id,
            vec![],
        ),
    }
}
