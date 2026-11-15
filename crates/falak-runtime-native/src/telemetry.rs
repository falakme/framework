//! Structured logging, traces, and telemetry exporter.

use falak_contracts::telemetry::{Level, LogRecord, TelemetryExporter};
use tracing::{debug, error, info, warn};

/// Output format for telemetry logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TelemetryFormat {
    #[default]
    Json,
    Text,
}

/// Initialize tracing subscriber with structured JSON or text output.
pub fn init_telemetry(format: TelemetryFormat) {
    match format {
        TelemetryFormat::Json => {
            let subscriber = tracing_subscriber::fmt()
                .json()
                .with_target(false)
                .with_current_span(true)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
        TelemetryFormat::Text => {
            let subscriber = tracing_subscriber::fmt()
                .with_target(false)
                .with_ansi(true)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
    }
}

/// Telemetry exporter integrating with the `tracing` ecosystem.
///
/// Follows the privacy requirement: callers must never put tokens, keys or passwords
/// in fields, and any sensitive / PII field is scrubbed before emission.
#[derive(Clone, Default)]
pub struct TracingTelemetryExporter;

impl TracingTelemetryExporter {
    pub fn new() -> Self {
        Self
    }

    fn is_pii_field(key: &str) -> bool {
        let k = key.to_lowercase();
        k.contains("password")
            || k.contains("token")
            || k.contains("secret")
            || k.contains("key")
            || k.contains("auth")
            || k.contains("cookie")
            || k.contains("credential")
    }
}

impl TelemetryExporter for TracingTelemetryExporter {
    fn log(&self, record: LogRecord) {
        let req_id = record.request_id.as_deref().unwrap_or("none");
        let safe_fields: Vec<(String, String)> = record
            .fields
            .into_iter()
            .map(|(k, v)| {
                if Self::is_pii_field(&k) {
                    (k, "[REDACTED]".to_string())
                } else {
                    (k, v)
                }
            })
            .collect();

        match record.level {
            Level::Debug => {
                debug!(request_id = %req_id, fields = ?safe_fields, "{}", record.message);
            }
            Level::Info => {
                info!(request_id = %req_id, fields = ?safe_fields, "{}", record.message);
            }
            Level::Warn => {
                warn!(request_id = %req_id, fields = ?safe_fields, "{}", record.message);
            }
            Level::Error => {
                error!(request_id = %req_id, fields = ?safe_fields, "{}", record.message);
            }
        }
    }

    fn metric(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        info!(
            metric_name = %name,
            metric_value = %value,
            labels = ?labels,
            "metric: {name} = {value}"
        );
    }
}
