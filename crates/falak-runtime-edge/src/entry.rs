//! The Worker's `fetch` handler.

use std::{cell::RefCell, net::IpAddr, sync::Arc};

use axum::{
    Router,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use falak_auth::{
    identity::{LocalIdentity, Policy},
    keys::LocalKeys,
    store::{Placeholders, SqlStore},
    system::{RandomIds, SystemClock},
    token::{TokenConfig, Verifier},
};
use falak_contracts::{driver::StorageDriver, identity::RequestContext, ir::Ir};
use falak_runtime_native::{
    IdempotencyStore, NativeDriver,
    auth_routes::{PeerAddr, auth_router},
    context::TokenAuthenticator,
    create_router_with,
};
use tower_service::Service;
use worker::{Context, Env, HttpRequest, event, send::SendWrapper};

use crate::{
    auth::{EdgeAuth, Identity},
    driver::EdgeDriver,
};

/// The compiled app, embedded by `build.rs`. Empty if the Worker was built without one.
const IR_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/ir.json"));

/// Seconds of clock difference allowed when checking a token. Same as `falak serve`.
const LEEWAY_SECS: i64 = 30;

thread_local! {
    // One router per isolate, built on the first request. `Router` is cheap to clone.
    static APP: RefCell<Option<Router>> = const { RefCell::new(None) };
}

fn request_context() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "falak-edge".into(),
    }
}

async fn build_app(env: &Env) -> Result<Router, String> {
    if IR_JSON.is_empty() {
        return Err("this Worker was built without an app".into());
    }
    let ir: Ir = serde_json::from_str(IR_JSON).map_err(|e| format!("bad embedded app: {e}"))?;

    let db = env
        .d1("DB")
        .map_err(|e| format!("no D1 binding `DB`: {e}"))?;
    let keys_text = env
        .secret("FALAK_KEYS")
        .map_err(|e| format!("no secret `FALAK_KEYS`: {e}"))?
        .to_string();
    let keys = LocalKeys::from_json(&keys_text).map_err(|e| format!("bad signing keys: {e}"))?;

    let config = TokenConfig {
        issuer: "falak-local".into(),
        audience: ir.app.name.clone(),
        leeway_secs: LEEWAY_SECS,
    };
    let mut verifier = Verifier::new(config.clone());
    keys.trust_all(&mut verifier);

    let driver = EdgeDriver::new(db);
    let ctx = request_context();

    // Create the tables the first time this version of the app runs.
    let store = SqlStore::new(driver.clone(), Placeholders::Question);
    store
        .migrate()
        .await
        .map_err(|e| format!("cannot prepare the identity tables: {e}"))?;
    falak_migrate::apply_initial_migration(&driver, &ctx, &ir)
        .await
        .map_err(|e| format!("cannot create the tables: {e}"))?;
    // Fail early, with a clear message, if the database is not reachable.
    StorageDriver::query(
        &driver,
        &ctx,
        falak_contracts::driver::Statement::new("SELECT 1", vec![]),
    )
    .await
    .map_err(|e| format!("the database is not reachable: {e}"))?;

    let identity: Identity = LocalIdentity::new(
        SqlStore::new(driver.clone(), Placeholders::Question),
        keys,
        config,
        Policy::default(),
        SystemClock,
        RandomIds,
    );
    let auth = Arc::new(EdgeAuth(SendWrapper::new(identity)));
    let authenticator = Arc::new(TokenAuthenticator::new(verifier, SystemClock));

    let shared: Arc<dyn NativeDriver> = Arc::new(driver.clone());
    let idempotency = IdempotencyStore::durable(shared);
    idempotency
        .migrate()
        .await
        .map_err(|e| format!("cannot prepare the idempotency table: {e}"))?;

    let openapi = falak_core::openapi::generate(&ir).to_string();
    let router = create_router_with(Arc::new(ir), Arc::new(driver), authenticator, idempotency)
        .merge(auth_router(auth, Arc::new(|_, _| {})))
        .route(
            "/openapi.json",
            get(move || {
                let body = openapi.clone();
                async move {
                    let mut res = body.into_response();
                    res.headers_mut().insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    );
                    res
                }
            }),
        );
    Ok(router)
}

async fn app(env: &Env) -> Result<Router, String> {
    if let Some(router) = APP.with(|a| a.borrow().clone()) {
        return Ok(router);
    }
    let router = build_app(env).await?;
    APP.with(|a| *a.borrow_mut() = Some(router.clone()));
    Ok(router)
}

fn unavailable() -> http::Response<axum::body::Body> {
    // The reason is logged, not returned: it can name bindings and internals.
    (StatusCode::SERVICE_UNAVAILABLE, "service unavailable").into_response()
}

#[event(fetch)]
async fn fetch(
    mut req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> worker::Result<http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();

    let mut router = match app(&env).await {
        Ok(r) => r,
        Err(why) => {
            worker::console_error!("falak: {why}");
            return Ok(unavailable());
        }
    };

    // Cloudflare sets this header and overwrites any value the client sends. The auth
    // routes rate limit by it.
    let peer: Option<IpAddr> = req
        .headers()
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    if let Some(ip) = peer {
        req.extensions_mut().insert(PeerAddr(ip));
    }

    Ok(router.call(req).await?)
}
