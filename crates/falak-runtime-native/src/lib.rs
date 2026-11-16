//! Native runtime (Axum, Tokio) serving a compiled app.

pub mod app;
pub mod auth_routes;
pub mod context;
pub mod driver;
pub mod error;
pub mod events;
pub mod files;
pub mod handlers;
pub mod idempotency;
pub mod json;
pub mod limits;
#[cfg(feature = "server")]
pub mod telemetry;
pub mod tenants;

pub use app::{AppState, RouterOptions, create_router, create_router_with};
pub use driver::NativeDriver;
pub use error::{InvalidParam, ProblemDetails};
pub use idempotency::IdempotencyStore;
#[cfg(feature = "server")]
pub use telemetry::{TelemetryFormat, TracingTelemetryExporter, init_telemetry};
