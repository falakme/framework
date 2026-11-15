//! Native runtime application router configuration.

use std::sync::Arc;

use axum::{
    Router,
    http::Request,
    routing::{get, post},
};
use falak_contracts::ir::Ir;

use crate::{
    driver::NativeDriver,
    error::problem_response,
    handlers::{
        command_handler, create_handler, delete_handler, get_handler, list_handler, update_handler,
    },
    idempotency::IdempotencyStore,
};

pub struct AppState<D: NativeDriver> {
    pub ir: Arc<Ir>,
    pub driver: Arc<D>,
    pub idempotency: IdempotencyStore,
}

pub fn create_router<D: NativeDriver>(ir: Arc<Ir>, driver: Arc<D>) -> Router {
    let state = Arc::new(AppState {
        ir,
        driver,
        idempotency: IdempotencyStore::new(),
    });

    Router::<Arc<AppState<D>>>::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
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
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}
