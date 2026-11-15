//! The error taxonomy shared by every runtime.
//!
//! An [`Error`] has a stable machine-readable `code`, a `public_message` that is safe to
//! show to callers, and an optional internal `source` that is never shown. Runtimes map
//! [`ErrorKind`] to a status code with [`ErrorKind::http_status`].

use std::fmt;

/// Broad class of failure. Stable: add variants only through a `contract` pull request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The request is malformed or fails validation.
    InvalidInput,
    /// No valid credentials were presented.
    Unauthenticated,
    /// Credentials are valid but policy denies the action.
    Forbidden,
    /// The target does not exist or is not visible to the caller.
    NotFound,
    /// The request conflicts with current state (for example a unique key).
    Conflict,
    /// An `If-Match` or version precondition failed.
    PreconditionFailed,
    /// A rate limit was exceeded.
    RateLimited,
    /// The request body is larger than the runtime accepts.
    PayloadTooLarge,
    /// The request is well formed but cannot be processed (for example an idempotency
    /// key reused with a different body).
    Unprocessable,
    /// The driver or runtime lacks a required capability.
    Unsupported,
    /// A dependency did not answer in time.
    Timeout,
    /// A dependency is unavailable.
    Unavailable,
    /// A bug or unexpected failure.
    Internal,
}

impl ErrorKind {
    /// HTTP status code a runtime should use for this kind.
    pub fn http_status(self) -> u16 {
        match self {
            Self::InvalidInput => 400,
            Self::Unauthenticated => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::PreconditionFailed => 412,
            Self::PayloadTooLarge => 413,
            Self::Unprocessable => 422,
            Self::RateLimited => 429,
            Self::Unsupported => 501,
            Self::Unavailable => 503,
            Self::Timeout => 504,
            Self::Internal => 500,
        }
    }

    /// Whether retrying the same request unchanged can reasonably succeed.
    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::Conflict | Self::RateLimited | Self::Timeout | Self::Unavailable
        )
    }
}

/// Boxed internal cause. Never shown to callers.
pub type Source = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A Falak error.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    code: &'static str,
    public_message: String,
    source: Option<Source>,
}

/// Result alias using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Create an error. `code` is a stable snake_case identifier such as `policy_denied`.
    pub fn new(kind: ErrorKind, code: &'static str, public_message: impl Into<String>) -> Self {
        Self {
            kind,
            code,
            public_message: public_message.into(),
            source: None,
        }
    }

    /// Attach an internal cause. It is kept for logs and never included in `Display`.
    pub fn with_source(mut self, source: impl Into<Source>) -> Self {
        self.source = Some(source.into());
        self
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Message that is safe to return to a caller. Never contains SQL or internals.
    pub fn public_message(&self) -> &str {
        &self.public_message
    }

    /// Internal cause, for logging only.
    pub fn internal_source(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.source.as_deref()
    }

    pub fn invalid_input(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidInput, code, message)
    }

    pub fn unauthenticated() -> Self {
        Self::new(
            ErrorKind::Unauthenticated,
            "unauthenticated",
            "Authentication is required.",
        )
    }

    pub fn forbidden() -> Self {
        Self::new(ErrorKind::Forbidden, "forbidden", "Not permitted.")
    }

    /// Also used for rows the caller may not see, so existence is not revealed.
    pub fn not_found() -> Self {
        Self::new(ErrorKind::NotFound, "not_found", "Not found.")
    }

    pub fn unsupported(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unsupported, code, message)
    }

    /// Wrap an unexpected failure. The caller sees only a generic message.
    pub fn internal(source: impl Into<Source>) -> Self {
        Self::new(ErrorKind::Internal, "internal", "Internal error.").with_source(source)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.public_message)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // The cause is deliberately not exposed through the standard chain, so generic
        // error printers cannot leak it. Use `internal_source` for logging.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_hides_internal_cause() {
        let e = Error::internal("SELECT secret FROM users failed");
        assert_eq!(e.to_string(), "internal: Internal error.");
        assert!(e.internal_source().is_some());
        assert_eq!(e.kind().http_status(), 500);
    }

    #[test]
    fn statuses_and_retry() {
        assert_eq!(ErrorKind::NotFound.http_status(), 404);
        assert_eq!(ErrorKind::PreconditionFailed.http_status(), 412);
        assert_eq!(ErrorKind::PayloadTooLarge.http_status(), 413);
        assert!(ErrorKind::Timeout.retryable());
        assert!(!ErrorKind::Forbidden.retryable());
    }
}
