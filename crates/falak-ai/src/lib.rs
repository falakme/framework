//! AI readiness (Phase 7b): what lets an AI agent work with an app's data without being
//! able to do more than the person it acts for.
//!
//! * [`mcp`]: the MCP server projection (T7.9).
//! * [`egress`]: the AI egress policy: which providers, and no raw personal data (T7.10).
//! * [`approval`]: the human approval gate for writes (T7.10).

pub mod approval;
pub mod egress;
pub mod mcp;
