//! Service-level objectives and alerts, from the telemetry Office already emits (T6.6).
//!
//! Three sources, none of them new instrumentation of the business logic:
//!
//! * every HTTP response (status and latency), counted in one-minute buckets in memory
//!   by a single middleware. These give the availability and latency objectives;
//! * the readiness probe (`SELECT 1` on the database), which is what `/readyz` runs;
//! * the counters and tables Office already keeps: the audit chain's newest anchor and
//!   the age of the signing key set.
//!
//! `evaluate` turns them into [`Status`]es; `Alerter` sends one alert when an objective
//! starts burning and a recovery notice when it stops (audit entry, a log line, and the
//! webhook in `FALAK_ALERT_WEBHOOK` if set). Prometheus users get the same numbers at
//! `/metrics` and the rules in `deploy/office/alerts.yml`.
//!
//! Burn rate is the error rate divided by the error budget (1 - objective). A fast burn
//! (both the last 5 and the last 60 minutes at 14.4x) would use a 30-day budget in two
//! days: page. A slow burn (60 minutes at 6x) opens a ticket.

use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use serde::Serialize;

use crate::{Office, now};

/// Minutes of history kept.
const WINDOW: usize = 120;
/// A response slower than this counts against the latency objective.
pub const SLOW_MS: u64 = 500;

#[derive(Clone, Copy, Default)]
struct Bucket {
    minute: i64,
    total: u64,
    errors: u64,
    slow: u64,
}

/// Process-wide response counters.
pub struct Metrics {
    buckets: Mutex<Vec<Bucket>>,
    total: AtomicU64,
    errors: AtomicU64,
    slow: AtomicU64,
    ready_fail: AtomicU64,
    ready_total: AtomicU64,
}

static METRICS: Metrics = Metrics {
    buckets: Mutex::new(Vec::new()),
    total: AtomicU64::new(0),
    errors: AtomicU64::new(0),
    slow: AtomicU64::new(0),
    ready_fail: AtomicU64::new(0),
    ready_total: AtomicU64::new(0),
};

pub fn metrics() -> &'static Metrics {
    &METRICS
}

impl Metrics {
    /// Count one response. A 5xx is an error; so is a slow one for the latency SLO.
    pub fn record(&self, status: u16, millis: u64) {
        self.record_at(now() / 60, status, millis);
    }

    pub fn record_at(&self, minute: i64, status: u16, millis: u64) {
        let error = status >= 500;
        let slow = millis > SLOW_MS;
        self.total.fetch_add(1, Ordering::Relaxed);
        if error {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        if slow {
            self.slow.fetch_add(1, Ordering::Relaxed);
        }
        let mut b = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if b.is_empty() {
            b.resize(WINDOW, Bucket::default());
        }
        let slot = &mut b[usize::try_from(minute.rem_euclid(WINDOW as i64)).unwrap_or(0)];
        if slot.minute != minute {
            *slot = Bucket {
                minute,
                ..Bucket::default()
            };
        }
        slot.total += 1;
        slot.errors += u64::from(error);
        slot.slow += u64::from(slow);
    }

    pub fn record_ready(&self, ok: bool) {
        self.ready_total.fetch_add(1, Ordering::Relaxed);
        if !ok {
            self.ready_fail.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `(requests, 5xx, slow)` over the last `minutes` minutes ending at `minute`.
    pub fn window_at(&self, minute: i64, minutes: i64) -> (u64, u64, u64) {
        let b = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        b.iter()
            .filter(|x| x.total > 0 && x.minute > minute - minutes && x.minute <= minute)
            .fold((0, 0, 0), |a, x| {
                (a.0 + x.total, a.1 + x.errors, a.2 + x.slow)
            })
    }

    pub fn window(&self, minutes: i64) -> (u64, u64, u64) {
        self.window_at(now() / 60, minutes)
    }

    /// Prometheus text exposition.
    pub fn prometheus(&self) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "# TYPE falak_office_http_requests_total counter\nfalak_office_http_requests_total {}\n\
             # TYPE falak_office_http_errors_total counter\nfalak_office_http_errors_total {}\n\
             # TYPE falak_office_http_slow_total counter\nfalak_office_http_slow_total {}\n\
             # TYPE falak_office_ready_checks_total counter\nfalak_office_ready_checks_total {}\n\
             # TYPE falak_office_ready_failures_total counter\nfalak_office_ready_failures_total {}\n",
            g(&self.total),
            g(&self.errors),
            g(&self.slow),
            g(&self.ready_total),
            g(&self.ready_fail),
        )
    }
}

/// Where an objective stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Ok,
    /// Burning slowly: open a ticket.
    Ticket,
    /// Burning fast: page someone.
    Page,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub name: &'static str,
    pub objective: &'static str,
    pub state: State,
    pub detail: String,
}

/// Burn rate of an error ratio against an objective: 1.0 spends the budget exactly.
pub fn burn(bad: u64, total: u64, objective: f64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (bad as f64 / total as f64) / (1.0 - objective)
}

/// The multi-window rule: page when both windows burn at 14.4x or more, ticket when
/// the long window burns at 6x or more.
pub fn classify(short: f64, long: f64) -> State {
    if short >= 14.4 && long >= 14.4 {
        State::Page
    } else if long >= 6.0 {
        State::Ticket
    } else {
        State::Ok
    }
}

pub const AVAILABILITY: f64 = 0.999;
pub const LATENCY: f64 = 0.99;
/// An anchor older than this is a ticket (the loop anchors every five minutes).
pub const ANCHOR_MAX_AGE_SECS: i64 = 3600;
/// A signing key set unchanged for this long is a ticket.
pub const KEY_MAX_AGE_SECS: i64 = 90 * 24 * 3600;

/// Evaluate every objective now.
pub async fn evaluate(o: &Office) -> Vec<Status> {
    let m = metrics();
    let (t5, e5, s5) = m.window(5);
    let (t60, e60, s60) = m.window(60);
    let mut out = vec![
        Status {
            name: "availability",
            objective: "99.9% of responses are not 5xx",
            state: classify(burn(e5, t5, AVAILABILITY), burn(e60, t60, AVAILABILITY)),
            detail: format!("last 60 min: {e60} errors in {t60} requests"),
        },
        Status {
            name: "latency",
            objective: "99% of responses under 500 ms",
            state: classify(burn(s5, t5, LATENCY), burn(s60, t60, LATENCY)),
            detail: format!("last 60 min: {s60} slow in {t60} requests"),
        },
    ];
    let ready = o.db.rows("SELECT 1", vec![]).await.is_ok();
    m.record_ready(ready);
    out.push(Status {
        name: "database",
        objective: "the database answers",
        state: if ready { State::Ok } else { State::Page },
        detail: if ready { "ready" } else { "SELECT 1 failed" }.into(),
    });
    if std::env::var_os("FALAK_AUDIT_ANCHOR_DIR").is_some()
        || std::env::var_os("FALAK_AUDIT_ANCHOR_URL").is_some()
    {
        let age = o.last_anchor_at().await.ok().flatten().map(|at| now() - at);
        let head = o.audit_head().await.ok().flatten();
        let stale = match (age, head) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(a), Some(_)) => a > ANCHOR_MAX_AGE_SECS && o.anchor_pending().await,
        };
        out.push(Status {
            name: "audit_anchor",
            objective: "the audit chain is anchored outside the database within an hour",
            state: if stale { State::Ticket } else { State::Ok },
            detail: age.map_or("never anchored".into(), |a| format!("last anchor {a}s ago")),
        });
    }
    let age = now() - o.keys_changed_at();
    out.push(Status {
        name: "signing_key_age",
        objective: "the signing keys rotate at least every 90 days",
        state: if age > KEY_MAX_AGE_SECS {
            State::Ticket
        } else {
            State::Ok
        },
        detail: format!("{} days since the last rotation", age / 86_400),
    });
    out
}

/// Sends an alert on a change of state, not on every evaluation.
#[derive(Default)]
pub struct Alerter {
    last: Mutex<BTreeMap<&'static str, State>>,
}

impl Alerter {
    /// Returns the alerts raised: `(name, new state, detail)`.
    pub fn changes(&self, now: &[Status]) -> Vec<(&'static str, State, String)> {
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        let mut out = vec![];
        for s in now {
            let before = last.insert(s.name, s.state).unwrap_or(State::Ok);
            if before != s.state {
                out.push((s.name, s.state, s.detail.clone()));
            }
        }
        out
    }
}

impl Office {
    /// Raise an alert: an audit entry, a log line, and the webhook if one is set. Never
    /// fails the caller.
    pub async fn alert(&self, severity: &str, name: &str, detail: &str) {
        self.audit(
            "alert",
            &format!("alert_{severity}"),
            &format!("{name}: {detail}"),
        )
        .await;
        eprintln!(
            "{}",
            serde_json::json!({"alert": name, "severity": severity, "detail": detail, "at": now()})
        );
        if let Ok(url) = std::env::var("FALAK_ALERT_WEBHOOK") {
            let body = serde_json::json!({
                "text": format!("[{severity}] Falak Office {name}: {detail}"),
                "severity": severity, "name": name, "detail": detail,
            })
            .to_string();
            let _ = tokio::task::spawn_blocking(move || {
                let agent: ureq::Agent = ureq::Agent::config_builder()
                    .timeout_global(Some(Duration::from_secs(5)))
                    .build()
                    .into();
                let _ = agent
                    .post(&url)
                    .header("content-type", "application/json")
                    .send(&body);
            })
            .await;
        }
    }

    /// Evaluate the objectives and alert on changes. Run from a loop.
    pub async fn watch_slos(&self, alerter: &Alerter) {
        let now = evaluate(self).await;
        for (name, state, detail) in alerter.changes(&now) {
            let severity = match state {
                State::Ok => "resolved",
                State::Ticket => "ticket",
                State::Page => "page",
            };
            self.alert(severity, name, &detail).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burn_rates_follow_the_budget() {
        // 1.44% errors against a 99.9% objective burns at 14.4x.
        assert!((burn(144, 10_000, 0.999) - 14.4).abs() < 1e-9);
        assert_eq!(burn(0, 0, 0.999), 0.0);
        assert_eq!(classify(15.0, 15.0), State::Page);
        assert_eq!(classify(0.0, 15.0), State::Ticket);
        assert_eq!(classify(20.0, 2.0), State::Ok);
    }

    #[test]
    fn windows_count_only_their_minutes() {
        let m = Metrics {
            buckets: Mutex::new(Vec::new()),
            total: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            slow: AtomicU64::new(0),
            ready_fail: AtomicU64::new(0),
            ready_total: AtomicU64::new(0),
        };
        m.record_at(100, 200, 10);
        m.record_at(100, 503, 10);
        m.record_at(97, 200, 900);
        assert_eq!(m.window_at(100, 5), (3, 1, 1));
        assert_eq!(m.window_at(100, 2), (2, 1, 0));
        // Old minutes are overwritten when the ring wraps.
        m.record_at(100 + WINDOW as i64, 200, 1);
        assert_eq!(m.window_at(100 + WINDOW as i64, 5), (1, 0, 0));
    }

    #[test]
    fn an_alert_fires_on_a_change_only() {
        let a = Alerter::default();
        let s = |state| Status {
            name: "availability",
            objective: "",
            state,
            detail: String::new(),
        };
        assert!(a.changes(&[s(State::Ok)]).is_empty());
        assert_eq!(a.changes(&[s(State::Page)]).len(), 1);
        assert!(a.changes(&[s(State::Page)]).is_empty());
        assert_eq!(a.changes(&[s(State::Ok)]).len(), 1);
    }
}
