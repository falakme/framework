//! Logs and metrics. Implementations must drop any field the schema marks as PII, and
//! callers must never put tokens, keys or passwords in fields.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    pub level: Level,
    pub message: String,
    pub request_id: Option<String>,
    pub fields: Vec<(String, String)>,
}

pub trait TelemetryExporter {
    fn log(&self, record: LogRecord);
    fn metric(&self, name: &str, value: f64, labels: &[(&str, &str)]);
}
