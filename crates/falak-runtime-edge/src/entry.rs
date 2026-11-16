//! The Worker's `fetch` handler.
//!
//! Two modes, chosen by the Worker's configuration:
//! * **Local identity** (default): the Worker signs tokens with `FALAK_KEYS` and serves
//!   `/v1/auth/*`, like `falak serve`.
//! * **Key set** (`FALAK_JWKS_URL` and `FALAK_ISSUER` set): the Worker only verifies
//!   tokens, against the issuer's published public keys. No signing key, no auth routes.

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
    IdempotencyStore, NativeDriver, RouterOptions,
    auth_routes::{PeerAddr, auth_router_with},
    context::{Authenticator, TokenAuthenticator, bearer_token},
    create_router_with,
    limits::{Limits, RateGate},
    tenants::TenantRouter,
};
use tower_service::Service;
use worker::{Context, Env, HttpRequest, event, send::SendWrapper};

use crate::{
    auth::{EdgeAuth, Identity},
    driver::EdgeDriver,
    events::EdgeEvents,
    gate::EdgeGate,
    jwks::JwksAuth,
    office::OfficeLink,
    tenants::EdgeTenants,
};

/// The compiled app, embedded by `build.rs`. Empty if the Worker was built without one.
const IR_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/ir.json"));

/// Seconds of clock difference allowed when checking a token. Same as `falak serve`.
const LEEWAY_SECS: i64 = 30;

/// Window of the Cloudflare rate limit bindings, in seconds. Cloudflare allows 10 or 60.
const GATE_PERIOD_SECS: u32 = 60;

#[derive(Clone)]
struct App {
    router: Router,
    /// Present in key set mode: it must fetch keys before a request is routed.
    jwks: Option<Arc<JwksAuth>>,
    /// Present when the app is enrolled with Office: it follows Office's keys and feed.
    office: Option<Arc<OfficeLink>>,
    /// Present when the app publishes or consumes events (T5.4).
    events: Option<Arc<EdgeEvents>>,
}

thread_local! {
    // One app per isolate, built on the first request. `Router` is cheap to clone.
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

fn request_context() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "falak-edge".into(),
    }
}

fn var(env: &Env, name: &str) -> Option<String> {
    env.var(name)
        .ok()
        .map(|v| v.to_string())
        .filter(|v| !v.is_empty())
}

/// A rate gate from the binding `name`, if the Worker has it.
fn gate(env: &Env, name: &str, app: &str) -> Option<Arc<dyn RateGate>> {
    let limiter = env.rate_limiter(name).ok()?;
    Some(Arc::new(EdgeGate::new(limiter, app, GATE_PERIOD_SECS)))
}

async fn build_app(env: &Env) -> Result<App, String> {
    if IR_JSON.is_empty() {
        return Err("this Worker was built without an app".into());
    }
    let ir: Ir = serde_json::from_str(IR_JSON).map_err(|e| format!("bad embedded app: {e}"))?;

    let db = env
        .d1("DB")
        .map_err(|e| format!("no D1 binding `DB`: {e}"))?;
    let driver = EdgeDriver::new(db);
    let ctx = request_context();

    // Create the tables the first time this version of the app runs.
    let store = SqlStore::new(driver.clone(), Placeholders::Question);
    store
        .migrate()
        .await
        .map_err(|e| format!("cannot prepare the identity tables: {e}"))?;
    // A changed app is migrated here, when the first request reaches a new version. A
    // change that rebuilds, drops or retypes data waits for `falak deploy
    // --allow-destructive`, which sets `FALAK_ALLOW_DESTRUCTIVE` for that deploy.
    let options = falak_migrate::MigrateOptions {
        allow_destructive: var(env, "FALAK_ALLOW_DESTRUCTIVE").is_some(),
    };
    let migrate_options = options;
    // Under `database` tenancy the app's tables live in each tenant's own database, which
    // is brought up to date on first use. The main database holds identity only.
    if ir.app.tenancy != falak_contracts::ir::Tenancy::Database {
        falak_migrate::migrate(&driver, &ctx, &ir, options)
            .await
            .map_err(|e| format!("cannot update the tables: {}", e.public_message()))?;
    }
    // Fail early, with a clear message, if the database is not reachable.
    StorageDriver::query(
        &driver,
        &ctx,
        falak_contracts::driver::Statement::new("SELECT 1", vec![]),
    )
    .await
    .map_err(|e| format!("the database is not reachable: {e}"))?;

    // Idempotency keys must be shared by every isolate, so they live in D1.
    let shared: Arc<dyn NativeDriver> = Arc::new(driver.clone());
    let idempotency = IdempotencyStore::durable(shared);
    idempotency
        .migrate()
        .await
        .map_err(|e| format!("cannot prepare the idempotency table: {e}"))?;

    let mut limits = Limits {
        timeout: None, // Workers enforce their own CPU and wall time limits.
        ..Limits::default()
    };
    if let Some(g) = gate(env, "RATE_LIMITER", &ir.app.name) {
        limits.rate = Some(g);
    }
    let auth_gate = gate(env, "AUTH_RATE_LIMITER", &ir.app.name);

    let options = RouterOptions {
        idempotency,
        limits,
        // File storage is not wired on Workers yet: `/v1/_files` answers 501.
        files: None,
    };
    let openapi = falak_core::openapi::generate(&ir).to_string();
    let ir = Arc::new(ir);
    let data: Arc<dyn NativeDriver> = if ir.app.tenancy == falak_contracts::ir::Tenancy::Database {
        let map = var(env, "FALAK_TENANTS").unwrap_or_else(|| "{}".to_owned());
        let tenants = EdgeTenants::from_env(env, &map, ir.clone(), migrate_options)?;
        Arc::new(TenantRouter::new(
            Arc::new(driver.clone()),
            Arc::new(tenants),
        ))
    } else {
        Arc::new(driver.clone())
    };

    let mut office_link = None;
    let (router, jwks) = if let Some(config) = var(env, "FALAK_OFFICE_CONFIG") {
        let key = env
            .secret("FALAK_APP_KEY")
            .map_err(|e| format!("no secret `FALAK_APP_KEY`: {e}"))?
            .to_string();
        let staleness = var(env, "FALAK_OFFICE_MAX_STALENESS")
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(falak_federation::DEFAULT_MAX_STALENESS_SECS);
        let link = Arc::new(OfficeLink::new(
            &config,
            &key,
            staleness,
            Arc::new(data.clone()),
        )?);
        let fed = link.federation();
        if fed.app != ir.app.name {
            return Err(format!(
                "this Worker is enrolled with Office as `{}` but the app is `{}`",
                fed.app, ir.app.name
            ));
        }
        let authenticator: Arc<dyn Authenticator> =
            Arc::new(falak_federation::FederatedAuthenticator(fed.clone()));
        let router =
            create_router_with(ir.clone(), Arc::new(data.clone()), authenticator, options).layer(
                axum::middleware::from_fn_with_state(fed, falak_federation::read_only_gate),
            );
        office_link = Some(link);
        (router, None)
    } else if let Some(url) = var(env, "FALAK_JWKS_URL") {
        let issuer =
            var(env, "FALAK_ISSUER").ok_or("FALAK_JWKS_URL is set but FALAK_ISSUER is not")?;
        let config = TokenConfig {
            issuer,
            audience: ir.app.name.clone(),
            leeway_secs: LEEWAY_SECS,
        };
        let auth = Arc::new(JwksAuth::new(&url, config)?);
        let authenticator: Arc<dyn Authenticator> = auth.clone();
        let router = create_router_with(ir.clone(), Arc::new(data.clone()), authenticator, options);
        (router, Some(auth))
    } else {
        let keys_text = env
            .secret("FALAK_KEYS")
            .map_err(|e| format!("no secret `FALAK_KEYS`: {e}"))?
            .to_string();
        let keys =
            LocalKeys::from_json(&keys_text).map_err(|e| format!("bad signing keys: {e}"))?;
        let config = TokenConfig {
            issuer: "falak-local".into(),
            audience: ir.app.name.clone(),
            leeway_secs: LEEWAY_SECS,
        };
        let mut verifier = Verifier::new(config.clone());
        keys.trust_all(&mut verifier);

        let identity: Identity = LocalIdentity::new(
            SqlStore::new(driver.clone(), Placeholders::Question),
            keys,
            config,
            Policy::default(),
            SystemClock,
            RandomIds,
        );
        let identity = if ir.app.tenancy == falak_contracts::ir::Tenancy::None {
            identity
        } else {
            identity.with_per_user_tenants()
        };
        let auth = Arc::new(EdgeAuth(SendWrapper::new(identity)));
        let authenticator = Arc::new(TokenAuthenticator::new(verifier, SystemClock));
        let data = create_router_with(ir.clone(), Arc::new(data.clone()), authenticator, options);
        let router = match auth_gate {
            Some(g) => data.merge(auth_router_with(auth, Arc::new(|_, _| {}), g)),
            None => data.merge(falak_runtime_native::auth_routes::auth_router(
                auth,
                Arc::new(|_, _| {}),
            )),
        };
        (router, None)
    };

    let router = router.route(
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
    let events = match (&office_link, ir.uses_events()) {
        (Some(link), true) => Some(Arc::new(EdgeEvents::new(
            ir.clone(),
            Arc::new(driver.clone()),
            link.clone(),
        ))),
        (None, true) => {
            worker::console_error!("falak: this app uses events, which need Office");
            None
        }
        _ => None,
    };
    Ok(App {
        router,
        jwks,
        office: office_link,
        events,
    })
}

async fn app(env: &Env) -> Result<App, String> {
    if let Some(app) = APP.with(|a| a.borrow().clone()) {
        return Ok(app);
    }
    let app = build_app(env).await?;
    APP.with(|a| *a.borrow_mut() = Some(app.clone()));
    Ok(app)
}

fn unavailable() -> http::Response<axum::body::Body> {
    // The reason is logged, not returned: it can name bindings and internals.
    (StatusCode::SERVICE_UNAVAILABLE, "service unavailable").into_response()
}

#[event(fetch)]
async fn fetch(
    mut req: HttpRequest,
    env: Env,
    ctx: Context,
) -> worker::Result<http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();

    let app = match app(&env).await {
        Ok(a) => a,
        Err(why) => {
            worker::console_error!("falak: {why}");
            return Ok(unavailable());
        }
    };

    if let Some(office) = &app.office {
        let token = bearer_token(req.headers()).map(str::to_owned);
        office.refresh_if_needed(token.as_deref()).await;
    }
    if let Some(jwks) = &app.jwks {
        let token = bearer_token(req.headers()).map(str::to_owned);
        jwks.refresh_if_needed(token.as_deref()).await;
    }

    // Cloudflare sets this header and overwrites any value the client sends. The rate
    // limits use it.
    let peer: Option<IpAddr> = req
        .headers()
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    if let Some(ip) = peer {
        req.extensions_mut().insert(PeerAddr(ip));
    }

    let wrote = !matches!(
        *req.method(),
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS
    );
    let mut router = app.router;
    let response = router.call(req).await?;
    // A change may have raised an event: start a relay pass now rather than at the next
    // cron tick. The response does not wait for it.
    if wrote
        && response.status().is_success()
        && let Some(events) = app.events
    {
        ctx.wait_until(async move { events.run_once().await });
    }
    Ok(response)
}

/// The Cron Trigger: a relay pass, so events move even when nobody is calling the app.
#[event(scheduled)]
async fn scheduled(_event: worker::ScheduledEvent, env: Env, _ctx: worker::ScheduleContext) {
    console_error_panic_hook::set_once();
    match app(&env).await {
        Ok(app) => {
            if let Some(events) = app.events {
                events.run_once().await;
            }
        }
        Err(why) => worker::console_error!("falak: {why}"),
    }
}
