//! Native runtime (Axum, Tokio) serving a compiled app.

pub mod app;
pub mod auth_routes;
pub mod context;
pub mod driver;
pub mod error;
pub mod handlers;
pub mod idempotency;
pub mod json;

pub use app::{AppState, create_router};
pub use driver::NativeDriver;
pub use error::{InvalidParam, ProblemDetails};
pub use idempotency::IdempotencyStore;
