//! Native runtime application router configuration.

use std::sync::Arc;

use axum::{
    Router,
    http::Request,
    routing::{get, post},
};
use falak_contracts::ir::Ir;

use crate::{
    context::Authenticator,
    driver::NativeDriver,
    error::problem_response,
    handlers::{
        command_handler, create_handler, delete_handler, get_handler, list_handler, query_handler,
        update_handler,
    },
    idempotency::IdempotencyStore,
    limits::Limits,
};

pub struct AppState<D: NativeDriver> {
    pub ir: Arc<Ir>,
    pub driver: Arc<D>,
    pub idempotency: IdempotencyStore,
    pub auth: Arc<dyn Authenticator>,
}

/// What differs between runtimes: where idempotency keys live and which limits apply.
/// The edge runtime passes a durable store and a rate gate backed by Cloudflare, because
/// its isolates share no memory.
#[derive(Clone, Default)]
pub struct RouterOptions {
    pub idempotency: IdempotencyStore,
    pub limits: Limits,
}

pub fn create_router<D: NativeDriver>(
    ir: Arc<Ir>,
    driver: Arc<D>,
    auth: Arc<dyn Authenticator>,
) -> Router {
    create_router_with(ir, driver, auth, RouterOptions::default())
}

pub fn create_router_with<D: NativeDriver>(
    ir: Arc<Ir>,
    driver: Arc<D>,
    auth: Arc<dyn Authenticator>,
    options: RouterOptions,
) -> Router {
    let RouterOptions {
        idempotency,
        limits,
    } = options;
    let state = Arc::new(AppState {
        ir,
        driver,
        idempotency,
        auth,
    });

    let router = Router::<Arc<AppState<D>>>::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(
                |axum::extract::State(state): axum::extract::State<Arc<AppState<D>>>| async move {
                    use axum::response::IntoResponse;
                    let ctx = falak_contracts::identity::RequestContext {
                        principal: None,
                        request_id: "readyz_check".to_string(),
                    };
                    match state
                        .driver
                        .query(
                            &ctx,
                            falak_contracts::driver::Statement::new("SELECT 1;", vec![]),
                        )
                        .await
                    {
                        Ok(_) => (axum::http::StatusCode::OK, "ok").into_response(),
                        Err(_) => (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            "database unavailable",
                        )
                            .into_response(),
                    }
                },
            ),
        )
        .route("/v1/_queries/{name}", get(query_handler::<D>))
        .route(
            "/v1/{entity}",
            get(list_handler::<D>).post(create_handler::<D>),
        )
        .route(
            "/v1/{entity}/{id}",
            get(get_handler::<D>)
                .patch(update_handler::<D>)
                .put(update_handler::<D>)
                .delete(delete_handler::<D>),
        )
        .route("/v1/{entity}/{id}/{cmd}", post(command_handler::<D>))
        .fallback(|req: Request<axum::body::Body>| async move {
            let path = req.uri().path().to_string();
            problem_response(
                &falak_contracts::Error::not_found(),
                &path,
                "req_not_found",
                vec![],
            )
        })
        .with_state(state);
    let router = router
        .layer(axum::extract::DefaultBodyLimit::max(limits.max_body_bytes))
        .layer(axum::middleware::from_fn(
            crate::limits::problem_for_oversize,
        ));
    let router = match limits.rate {
        Some(gate) => router.layer(axum::middleware::from_fn_with_state(
            gate,
            crate::limits::rate_limit,
        )),
        None => router,
    };
    #[cfg(feature = "server")]
    let router = match limits.timeout {
        Some(limit) => router.layer(axum::middleware::from_fn_with_state(
            limit,
            crate::limits::time_limit,
        )),
        None => router,
    };
    // `TraceLayer` reads `Instant::now`, which panics on `wasm32-unknown-unknown`.
    #[cfg(feature = "server")]
    let router = router.layer(tower_http::trace::TraceLayer::new_for_http());
    router
}
