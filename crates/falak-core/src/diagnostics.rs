//! Compiler diagnostics. Every message points at an exact file, line and column, says
//! what is wrong, and suggests a fix where one exists.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// A source position. Lines and columns are 1-based; columns count characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Position {
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    /// Stable identifier such as `yaml_duplicate_key`, safe to match on.
    pub code: &'static str,
    pub message: String,
    pub file: String,
    pub position: Position,
    pub suggestion: Option<String>,
}

impl Diagnostic {
    pub fn error(
        code: &'static str,
        file: &str,
        position: Position,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity: Severity::Error,
            code,
            message: message.into(),
            file: file.to_string(),
            position,
            suggestion: None,
        }
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(
            f,
            "{}:{}:{}: {}[{}]: {}",
            self.file, self.position.line, self.position.column, level, self.code, self.message
        )?;
        if let Some(s) = &self.suggestion {
            write!(f, "\n  help: {s}")?;
        }
        Ok(())
    }
}

/// True if any diagnostic is an error.
pub fn has_errors(diagnostics: &[Diagnostic]) -> bool {
    diagnostics.iter().any(|d| d.severity == Severity::Error)
}
