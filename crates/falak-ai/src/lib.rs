//! AI access (Phase 7b): an MCP server that lets an AI agent use an app's REST API.
//!
//! * [`mcp`]: the MCP server. Each tool call is a REST request sent as the signed-in user,
//!   so the app's policies decide what the agent can read or change.

pub mod mcp;
