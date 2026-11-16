//! `falak serve` and `falak dev`.
//!
//! Serves the app from `<dir>` on `127.0.0.1` only, with SQLite in `<dir>/.falak/`:
//!
//! * `data.db`: the app's tables and the identity tables;
//! * `keys.json`: the token signing keys (mode 0600).
//!
//! `dev` also watches the source files and swaps in a freshly built router when the
//! compiled app changes. A change to the data model creates new tables but does not alter
//! existing ones (migrations arrive with T3.6); the server says so.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    Router,
    extract::Request,
    http::{HeaderValue, header},
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
use falak_contracts::{identity::RequestContext, ir::Ir};
use falak_driver_postgres::{PostgresConfig, PostgresDriver};
use falak_driver_sqlite::{SqliteConfig, SqliteDriver};
use falak_federation::{
    AppKey, DEFAULT_MAX_STALENESS_SECS, FederatedAuthenticator, Federation, OfficeConfig,
};
use falak_migrate::{MigrateOptions, migrate};
use falak_runtime_native::{
    NativeDriver, RouterOptions,
    auth_routes::{ResetSink, auth_router},
    context::{Authenticator, TokenAuthenticator},
    create_router_with,
    files::{FileApi, S3Files},
    tenants::{SqliteTenants, TenantRouter},
};
use tower::ServiceExt;

use crate::{project, watch};

/// Seconds a token's expiry may be off because of clock differences.
const LEEWAY_SECS: i64 = 30;

pub fn run(dir: &Path, port: u16, dev: bool) -> Result<u8, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the async runtime: {e}"))?;
    runtime.block_on(serve(dir.to_path_buf(), port, dev))
}

/// Everything that outlives a rebuild of the app.
#[derive(Clone)]
enum DriverStack {
    Sqlite {
        driver: Arc<SqliteDriver>,
        identity: Arc<LocalIdentity<SqlStore<SqliteDriver>, SystemClock, RandomIds>>,
    },
    Postgres {
        driver: Arc<PostgresDriver>,
        identity: Arc<LocalIdentity<SqlStore<PostgresDriver>, SystemClock, RandomIds>>,
    },
}

#[derive(Clone)]
struct Stack {
    driver_stack: DriverStack,
    /// Where `tenancy: database` keeps one database file per tenant.
    tenant_dir: PathBuf,
    authenticator: Arc<dyn Authenticator>,
    reset_sink: ResetSink,
    /// Set when the app is enrolled with Falak Office: sign-in is Office's.
    office: Option<Office>,
}

#[derive(Clone)]
struct Office {
    fed: Arc<Federation>,
    config: OfficeConfig,
    key: Arc<AppKey>,
    /// One key set fetch at a time when a rotation reaches many requests at once.
    fetching: Arc<tokio::sync::Mutex<()>>,
}

fn request_context() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "falak-serve".into(),
    }
}

async fn open_stack(dir: &Path, ir: &Ir, dev: bool) -> Result<Stack, String> {
    let data = project::out_dir(dir);
    std::fs::create_dir_all(&data)
        .map_err(|e| format!("cannot create `{}`: {e}", data.display()))?;

    let keys = LocalKeys::load_or_create(&data.join("keys.json"))
        .map_err(|e| format!("cannot load the signing keys: {e}"))?;
    let config = TokenConfig {
        issuer: "falak-local".into(),
        audience: ir.app.name.clone(),
        leeway_secs: LEEWAY_SECS,
    };
    let mut verifier = Verifier::new(config.clone());
    keys.trust_all(&mut verifier);

    let reset_sink: ResetSink = if dev {
        Arc::new(|email, token| {
            eprintln!("[dev] password reset token for {email}: {token}");
        })
    } else {
        // No mail is configured in v1, so the token is dropped rather than logged.
        Arc::new(|_, _| {})
    };

    let scoped = ir.app.tenancy != falak_contracts::ir::Tenancy::None;
    let database_url = std::env::var("DATABASE_URL").ok();
    let is_postgres = database_url
        .as_ref()
        .is_some_and(|url| url.starts_with("postgres://") || url.starts_with("postgresql://"));

    let driver_stack = if is_postgres {
        let pg_url = database_url.unwrap();
        let driver = PostgresDriver::open(PostgresConfig {
            url: pg_url,
            ..PostgresConfig::default()
        })
        .await
        .map_err(|e| format!("cannot open the postgres database: {e}"))?;

        let store = SqlStore::new(driver.clone(), Placeholders::Numbered);
        // The identity tables are made by the owner role when there is one: the runtime
        // role (`falak_app`) owns nothing and cannot create tables.
        match std::env::var("FALAK_MIGRATE_URL") {
            Ok(url) => {
                let owner = PostgresDriver::open(PostgresConfig {
                    url,
                    ..PostgresConfig::default()
                })
                .await
                .map_err(|e| format!("cannot open the migration database: {e}"))?;
                SqlStore::new(owner, Placeholders::Numbered)
                    .migrate()
                    .await
                    .map_err(|e| format!("cannot prepare the identity tables: {e}"))?;
            }
            Err(_) => store
                .migrate()
                .await
                .map_err(|e| format!("cannot prepare the identity tables: {e}"))?,
        }

        let identity = LocalIdentity::new(
            store,
            keys,
            config,
            Policy::default(),
            SystemClock,
            RandomIds,
        );
        let identity = if scoped {
            identity.with_per_user_tenants()
        } else {
            identity
        };
        DriverStack::Postgres {
            driver: Arc::new(driver),
            identity: Arc::new(identity),
        }
    } else {
        let db = data.join("data.db");
        let driver = SqliteDriver::open(SqliteConfig {
            url: format!("sqlite://{}", db.display()),
            ..SqliteConfig::default()
        })
        .await
        .map_err(|e| format!("cannot open the database: {e}"))?;

        let store = SqlStore::new(driver.clone(), Placeholders::Question);
        store
            .migrate()
            .await
            .map_err(|e| format!("cannot prepare the identity tables: {e}"))?;

        let identity = LocalIdentity::new(
            store,
            keys,
            config,
            Policy::default(),
            SystemClock,
            RandomIds,
        );
        let identity = if scoped {
            identity.with_per_user_tenants()
        } else {
            identity
        };
        DriverStack::Sqlite {
            driver: Arc::new(driver),
            identity: Arc::new(identity),
        }
    };

    let office = match crate::office_cmd::load(dir)? {
        Some((config, key)) => {
            if config.app != ir.app.name {
                return Err(format!(
                    "this app is enrolled with Office as `{}` but is named `{}`",
                    config.app, ir.app.name
                ));
            }
            let staleness = env_secs("FALAK_OFFICE_MAX_STALENESS", DEFAULT_MAX_STALENESS_SECS);
            Some(Office {
                fed: Arc::new(Federation::new(&config, staleness)),
                config,
                key: Arc::new(key),
                fetching: Arc::default(),
            })
        }
        None => None,
    };
    let authenticator: Arc<dyn Authenticator> = match &office {
        Some(o) => Arc::new(FederatedAuthenticator(o.fed.clone())),
        None => Arc::new(TokenAuthenticator::new(verifier, SystemClock)),
    };

    Ok(Stack {
        tenant_dir: data.join("tenants"),
        driver_stack,
        authenticator,
        reset_sink,
        office,
    })
}

/// Bring the database to this version of the app. The first version creates the tables;
/// a later one applies the planned change. In `falak dev` anything goes, since the data
/// is a scratch copy; in `falak serve` a change that rebuilds, drops or retypes data
/// stops the server and says how to apply it on purpose (`falak migrate apply`).
async fn prepare_tables(stack: &Stack, ir: &Ir, dev: bool) -> Result<(), String> {
    if ir.app.tenancy == falak_contracts::ir::Tenancy::Database {
        // The app's tables live in each tenant's own database, made when the tenant is
        // first seen. This database holds identity only.
        return match &stack.driver_stack {
            DriverStack::Sqlite { .. } => Ok(()),
            DriverStack::Postgres { .. } => Err(
                "`tenancy: database` runs on SQLite and D1, not PostgreSQL. Use `tenancy: row` there"
                    .to_owned(),
            ),
        };
    }
    let ctx = request_context();
    let options = MigrateOptions {
        allow_destructive: dev,
    };
    let result = match &stack.driver_stack {
        DriverStack::Sqlite { driver, .. } => migrate(&**driver, &ctx, ir, options).await,
        DriverStack::Postgres { driver, .. } => {
            // With `FALAK_MIGRATE_URL` the schema is changed by the owner role, and the
            // runtime connects as `falak_app` (no ownership, no BYPASSRLS). The owner's
            // credentials are then needed only here, not by the request path.
            match std::env::var("FALAK_MIGRATE_URL") {
                Ok(url) => match PostgresDriver::open(PostgresConfig {
                    url,
                    ..PostgresConfig::default()
                })
                .await
                {
                    Ok(owner) => migrate(&owner, &ctx, ir, options).await,
                    Err(e) => Err(e),
                },
                Err(_) => migrate(&**driver, &ctx, ir, options).await,
            }
        }
    };
    result
        .map(|_| ())
        .map_err(|e| format!("cannot update the tables: {}", e.public_message()))
}

/// Router options from the environment: file storage when `FALAK_S3_*` is set.
fn options() -> RouterOptions {
    RouterOptions {
        files: S3Files::from_env().map(|f| Arc::new(f) as Arc<dyn FileApi>),
        ..RouterOptions::default()
    }
}

/// The app's own sign-in routes, unless Office does sign-in.
fn local_auth<S: falak_runtime_native::auth_routes::AuthService>(
    federated: bool,
    identity: Arc<S>,
    sink: &ResetSink,
) -> Router {
    if federated {
        Router::new()
    } else {
        auth_router(identity, sink.clone())
    }
}

fn env_secs(name: &str, default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

/// Fetch Office's key set at once when a token names a key the app has not seen.
async fn follow_keys(
    axum::extract::State(o): axum::extract::State<Office>,
    req: Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let token = falak_runtime_native::context::bearer_token(req.headers()).map(str::to_owned);
    if let Some(token) = token {
        let t = falak_federation::now();
        if o.fed.wants_jwks_for(&token, t) {
            let _one_at_a_time = o.fetching.lock().await;
            // Another request may have fetched while this one waited.
            if !o.fed.wants_jwks_for(&token, falak_federation::now()) {
                return next.run(req).await;
            }
            let (fed, config) = (o.fed.clone(), o.config.clone());
            let _ = tokio::task::spawn_blocking(move || {
                if let Ok(text) = falak_federation::http::fetch_jwks(&config) {
                    let _ = fed.load_jwks(&text, falak_federation::now());
                }
            })
            .await;
        }
    }
    next.run(req).await
}

/// Keep up with Office: once now (so the first request works), then on a timer.
async fn sync_office(o: Office) {
    let every = env_secs("FALAK_OFFICE_SYNC_SECS", 20);
    let mut first = true;
    loop {
        let (fed, config, key) = (o.fed.clone(), o.config.clone(), o.key.clone());
        let result = tokio::task::spawn_blocking(move || {
            falak_federation::http::sync_once(&fed, &config, &key)
        })
        .await;
        match result {
            Ok(Ok(())) if first => eprintln!("office: linked to {}", o.config.office_url),
            Ok(Err(e)) if first => eprintln!("office: not reachable yet ({e})"),
            _ => {}
        }
        first = false;
        tokio::time::sleep(Duration::from_secs(u64::try_from(every).unwrap_or(20))).await;
    }
}

/// The MCP allow-list from `FALAK_MCP_ENTITIES`. An unknown entity name stops the server
/// from offering MCP at all, and says why.
fn mcp_config(ir: &Ir) -> Option<falak_ai::mcp::McpConfig> {
    let list = std::env::var("FALAK_MCP_ENTITIES").ok()?;
    let names: Vec<String> = list
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    match falak_ai::mcp::McpConfig::new(ir, &names) {
        Ok(mut c) if !c.entities.is_empty() => {
            // Writes are proposals a person approves (FALAK_MCP_WRITES=approval). PII fields
            // are tokens unless FALAK_AI_EXPOSE_PII=1. FALAK_AI_ALLOW lists model hosts.
            c.writes = std::env::var("FALAK_MCP_WRITES").as_deref() == Ok("approval");
            c.policy = falak_ai::egress::AiPolicy::from_env();
            c.policy.expose_pii = std::env::var("FALAK_AI_EXPOSE_PII").as_deref() == Ok("1");
            if let Ok(k) = std::env::var("FALAK_PII_KEY") {
                c.pii_key = k.into_bytes();
            }
            Some(c)
        }
        Ok(_) => None,
        Err(e) => {
            eprintln!("mcp: not served: {e}");
            None
        }
    }
}

fn build_router(stack: &Stack, ir: &Ir) -> Router {
    let ir_arc = Arc::new(ir.clone());
    let ir_mcp = ir_arc.clone();
    let openapi = falak_core::openapi::generate(ir).to_string();

    let federated = stack.office.is_some();
    let router = match &stack.driver_stack {
        DriverStack::Sqlite { driver, identity } => {
            let data = if ir.app.tenancy == falak_contracts::ir::Tenancy::Database {
                let tenants = SqliteTenants::new(stack.tenant_dir.clone(), ir_arc.clone());
                Arc::new(TenantRouter::new(driver.clone(), Arc::new(tenants)))
                    as Arc<dyn NativeDriver>
            } else {
                driver.clone() as Arc<dyn NativeDriver>
            };
            create_router_with(
                ir_arc,
                Arc::new(data),
                stack.authenticator.clone(),
                options(),
            )
            .merge(local_auth(federated, identity.clone(), &stack.reset_sink))
        }
        DriverStack::Postgres { driver, identity } => create_router_with(
            ir_arc,
            driver.clone(),
            stack.authenticator.clone(),
            options(),
        )
        .merge(local_auth(federated, identity.clone(), &stack.reset_sink)),
    };
    // Enrolled: sign-in is Office's. Keys follow Office (an unknown `kid` fetches the
    // key set at once, so a rotation costs no request), and a tier 2 app that has lost
    // Office for too long only reads.
    let router = match &stack.office {
        Some(o) => router
            .layer(axum::middleware::from_fn_with_state(
                o.fed.clone(),
                falak_federation::read_only_gate,
            ))
            .layer(axum::middleware::from_fn_with_state(o.clone(), follow_keys)),
        None => router,
    };

    // MCP projection (T7.9): opt in with FALAK_MCP_ENTITIES=note,notebook. Off by default.
    let router = match mcp_config(ir) {
        Some(config) => {
            falak_ai::mcp::mcp_router(ir_mcp, config, stack.authenticator.clone(), router)
        }
        None => router,
    };

    router.route(
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
    )
}

async fn serve(dir: PathBuf, port: u16, dev: bool) -> Result<u8, String> {
    // Build once. In `dev`, a broken app waits for a fix; in `serve` it is an error.
    let mut compiled = project::build(&dir)?;
    if compiled.is_none() && !dev {
        return Ok(1);
    }
    let mut fingerprint = watch::fingerprint(&dir);
    while compiled.is_none() {
        eprintln!("waiting for the errors above to be fixed...");
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let now = watch::fingerprint(&dir);
            if now != fingerprint {
                fingerprint = now;
                break;
            }
        }
        compiled = project::build(&dir)?;
    }
    let first = compiled.ok_or("internal: no compiled app")?;

    let stack = open_stack(&dir, &first.ir, dev).await?;
    prepare_tables(&stack, &first.ir, dev).await?;

    if let Some(o) = &stack.office {
        // Learn the key set before the first request, then keep following.
        let (fed, config) = (o.fed.clone(), o.config.clone());
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(text) = falak_federation::http::fetch_jwks(&config) {
                let _ = fed.load_jwks(&text, falak_federation::now());
            }
        })
        .await;
        tokio::spawn(sync_office(o.clone()));
        println!(
            "  Office:  {} (tier {}); sign-in is Office's",
            o.config.office_url, o.config.tier
        );
    }

    let current: Arc<RwLock<Router>> = Arc::new(RwLock::new(build_router(&stack, &first.ir)));
    let app = {
        let current = current.clone();
        Router::new().fallback(move |req: Request| {
            let router = current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            async move {
                match router.oneshot(req).await {
                    Ok(res) => res,
                    Err(never) => match never {},
                }
            }
        })
    };

    let host_ip: std::net::IpAddr = std::env::var("FALAK_HOST")
        .or_else(|_| std::env::var("HOST"))
        .ok()
        .and_then(|h| h.parse().ok())
        .unwrap_or_else(|| [127, 0, 0, 1].into());
    let addr = SocketAddr::new(host_ip, port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot listen on {addr}: {e} (use --port to pick another)"))?;
    println!(
        "serving {} {} on http://{addr}  (ir sha256:{})",
        first.ir.app.name, first.ir.app.version, first.ir.content_hash
    );
    println!("  API:     http://{addr}/v1/   OpenAPI: http://{addr}/openapi.json");
    if dev {
        println!("  watching {} for changes (Ctrl-C to stop)", dir.display());
    }

    if dev {
        let (dir, stack) = (dir.clone(), stack.clone());
        let (current, name, mut hash) = (current, first.ir.app.name.clone(), first.ir.content_hash);
        tokio::spawn(async move {
            let mut last = watch::fingerprint(&dir);
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let now = watch::fingerprint(&dir);
                if now == last {
                    continue;
                }
                last = now;
                let built = match project::build(&dir) {
                    Ok(Some(c)) => c,
                    Ok(None) => {
                        eprintln!("the app has errors; still serving the last good version");
                        continue;
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        continue;
                    }
                };
                if built.ir.app.name != name {
                    eprintln!("the app was renamed; restart `falak dev` to apply it");
                    continue;
                }
                if built.ir.content_hash == hash {
                    continue;
                }
                if let Err(e) = prepare_tables(&stack, &built.ir, dev).await {
                    eprintln!("error: {e}");
                    continue;
                }
                *current
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    build_router(&stack, &built.ir);
                hash = built.ir.content_hash.clone();
                println!("reloaded (ir sha256:{hash})");
            }
        });
    }

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        println!("\nstopping");
    })
    .await
    .map_err(|e| format!("server error: {e}"))?;
    Ok(0)
}
