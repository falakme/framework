//! HTTP endpoints for local identity (T1.12 over HTTP).
//!
//! | Route | Body | Reply |
//! | :-- | :-- | :-- |
//! | `POST /v1/auth/signup` | `{email, password}` | `201 {id}` |
//! | `POST /v1/auth/login` | `{email, password}` | `200` tokens |
//! | `POST /v1/auth/refresh` | `{refresh_token}` | `200` tokens |
//! | `POST /v1/auth/logout` | `{refresh_token}` | `204` |
//! | `POST /v1/auth/password-reset` | `{email}` | `202 {}` always |
//! | `POST /v1/auth/password-reset/confirm` | `{token, new_password}` | `204` |
//!
//! Tokens are `{access_token, refresh_token, expires_in, token_type: "Bearer"}`.
//! Errors are RFC 9457 problem documents like every other route.
//!
//! These routes sit outside the token check: they are how a caller gets a token. They
//! are rate limited per client address, on top of the per-email lockout in the identity
//! service.

// An `Err` here is a finished HTTP response, returned straight to the client.
#![allow(clippy::result_large_err)]

use std::{future::Future, net::IpAddr, pin::Pin, sync::Arc};

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
#[cfg(any(feature = "sqlite", feature = "postgres"))]
use falak_auth::store::SqlStore;
use falak_auth::{
    identity::{LocalIdentity, Tokens},
    ratelimit::Rate,
    store::MemoryStore,
    system::{RandomIds, SystemClock},
};
use falak_contracts::{Error, ErrorKind, Result};
#[cfg(feature = "postgres")]
use falak_driver_postgres::PostgresDriver;
#[cfg(feature = "sqlite")]
use falak_driver_sqlite::SqliteDriver;
use serde_json::{Value, json};

use crate::{
    context::extract_request_id,
    error::problem_response,
    limits::{MemoryGate, RateGate},
};

type Boxed<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// What the routes need from an identity service. Futures are boxed and `Send` so Axum
/// can run them on any thread.
pub trait AuthService: Send + Sync + 'static {
    fn signup<'a>(&'a self, email: &'a str, password: &'a str) -> Boxed<'a, String>;
    fn login<'a>(&'a self, email: &'a str, password: &'a str) -> Boxed<'a, Tokens>;
    fn refresh<'a>(&'a self, refresh_token: &'a str) -> Boxed<'a, Tokens>;
    fn logout<'a>(&'a self, refresh_token: &'a str) -> Boxed<'a, ()>;
    /// The reset token to deliver, or `None` if the email has no account.
    fn request_reset<'a>(&'a self, email: &'a str) -> Boxed<'a, Option<String>>;
    fn reset_password<'a>(&'a self, token: &'a str, new_password: &'a str) -> Boxed<'a, ()>;
    /// The public keys that verify this service's tokens, as a JSON Web Key Set.
    fn jwks(&self) -> Value;
}

macro_rules! impl_auth_service {
    ($store:ty) => {
        impl AuthService for LocalIdentity<$store, SystemClock, RandomIds> {
            fn signup<'a>(&'a self, email: &'a str, password: &'a str) -> Boxed<'a, String> {
                Box::pin(LocalIdentity::signup(self, email, password))
            }
            fn login<'a>(&'a self, email: &'a str, password: &'a str) -> Boxed<'a, Tokens> {
                Box::pin(LocalIdentity::login(self, email, password))
            }
            fn refresh<'a>(&'a self, refresh_token: &'a str) -> Boxed<'a, Tokens> {
                Box::pin(LocalIdentity::refresh(self, refresh_token))
            }
            fn logout<'a>(&'a self, refresh_token: &'a str) -> Boxed<'a, ()> {
                Box::pin(LocalIdentity::logout(self, refresh_token))
            }
            fn request_reset<'a>(&'a self, email: &'a str) -> Boxed<'a, Option<String>> {
                Box::pin(LocalIdentity::request_reset(self, email))
            }
            fn reset_password<'a>(
                &'a self,
                token: &'a str,
                new_password: &'a str,
            ) -> Boxed<'a, ()> {
                Box::pin(LocalIdentity::reset_password(self, token, new_password))
            }
            fn jwks(&self) -> Value {
                LocalIdentity::verifier(self).jwks()
            }
        }
    };
}

#[cfg(feature = "sqlite")]
impl_auth_service!(SqlStore<SqliteDriver>);
#[cfg(feature = "postgres")]
impl_auth_service!(SqlStore<PostgresDriver>);
impl_auth_service!(MemoryStore);

/// Delivers a password reset token to its owner (for example by mail). The default for
/// `falak serve` drops it; `falak dev` prints it.
pub type ResetSink = Arc<dyn Fn(&str, &str) + Send + Sync>;

pub struct AuthState {
    service: Arc<dyn AuthService>,
    gate: Arc<dyn RateGate>,
    reset_sink: ResetSink,
}

/// Requests per minute per client address on the auth routes.
pub const AUTH_RATE: Rate = Rate {
    limit: 30,
    window_secs: 60,
};

/// Largest body the auth routes read.
const MAX_BODY_BYTES: usize = 8 * 1024;

pub fn auth_router(service: Arc<dyn AuthService>, reset_sink: ResetSink) -> Router {
    auth_router_with(service, reset_sink, Arc::new(MemoryGate::new(AUTH_RATE)))
}

/// Like [`auth_router`], with the rate gate to use (the edge runtime passes one backed
/// by Cloudflare).
pub fn auth_router_with(
    service: Arc<dyn AuthService>,
    reset_sink: ResetSink,
    gate: Arc<dyn RateGate>,
) -> Router {
    let state = Arc::new(AuthState {
        service,
        gate,
        reset_sink,
    });
    Router::new()
        .route("/.well-known/jwks.json", get(jwks))
        .route("/v1/auth/signup", post(signup))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/refresh", post(refresh))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/password-reset", post(request_reset))
        .route("/v1/auth/password-reset/confirm", post(confirm_reset))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

// ---------------------------------------------------------------- plumbing

struct Call {
    request_id: String,
    instance: &'static str,
}

fn too_many() -> Error {
    Error::new(
        ErrorKind::RateLimited,
        "rate_limited",
        "Too many requests. Please retry later.",
    )
}

/// The client address, set by whatever sits in front of the router: [`PeerAddr`] on the
/// edge, Axum's connect info for `falak serve`.
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub IpAddr);

pub(crate) fn peer_ip(req: &Request) -> Option<IpAddr> {
    if let Some(p) = req.extensions().get::<PeerAddr>() {
        return Some(p.0);
    }
    #[cfg(feature = "server")]
    if let Some(c) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return Some(c.0.ip());
    }
    None
}

/// Rate limit, then read the JSON object body.
async fn read(
    state: &AuthState,
    req: Request,
    instance: &'static str,
) -> std::result::Result<(Call, Value), Response> {
    let peer = peer_ip(&req);
    let request_id = extract_request_id(req.headers());
    let key = peer.map_or_else(|| "unknown".to_owned(), |ip| ip.to_string());
    let decision = state.gate.check(&key).await;
    if !decision.allowed {
        let mut res = problem_response(&too_many(), instance, &request_id, vec![]);
        for (name, value) in decision.headers() {
            if decision.limit == 0 && name != "Retry-After" {
                continue;
            }
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()),
                HeaderValue::from_str(&value),
            ) {
                res.headers_mut().insert(n, v);
            }
        }
        return Err(res);
    }
    let invalid = |why: &'static str| {
        problem_response(
            &Error::invalid_input("invalid_body", why),
            instance,
            &request_id,
            vec![],
        )
    };
    let Ok(body) = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await else {
        return Err(invalid("The request body is missing or too large."));
    };
    match serde_json::from_slice::<Value>(&body) {
        Ok(v) if v.is_object() => Ok((
            Call {
                request_id: request_id.clone(),
                instance,
            },
            v,
        )),
        _ => Err(invalid("The request body must be a JSON object.")),
    }
}

/// A string field, or an error naming the field.
fn field<'a>(
    call: &Call,
    body: &'a Value,
    name: &'static str,
) -> std::result::Result<&'a str, Response> {
    body.get(name).and_then(Value::as_str).ok_or_else(|| {
        problem_response(
            &Error::invalid_input("invalid_body", "A required field is missing or not text."),
            call.instance,
            &call.request_id,
            vec![crate::error::InvalidParam {
                name: name.to_owned(),
                reason: "A text value is required.".to_owned(),
                code: "required".to_owned(),
            }],
        )
    })
}

fn json_response(status: StatusCode, body: &Value, request_id: &str) -> Response {
    let mut res = (status, body.to_string()).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(request_id) {
        h.insert("x-request-id", v);
    }
    res
}

fn empty(status: StatusCode, request_id: &str) -> Response {
    let mut res = status.into_response();
    if let Ok(v) = HeaderValue::from_str(request_id) {
        res.headers_mut().insert("x-request-id", v);
    }
    res
}

fn fail(call: &Call, error: &Error) -> Response {
    problem_response(error, call.instance, &call.request_id, vec![])
}

fn tokens_json(t: &Tokens) -> Value {
    json!({
        "access_token": t.access_token,
        "refresh_token": t.refresh_token,
        "expires_in": t.expires_in,
        "token_type": "Bearer",
    })
}

// ---------------------------------------------------------------- handlers

/// The public keys, so another service can verify this one's tokens (T2.9). Public
/// keys only; safe to cache.
async fn jwks(State(s): State<Arc<AuthState>>) -> Response {
    let mut res = s.service.jwks().to_string().into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    res
}

async fn signup(State(s): State<Arc<AuthState>>, req: Request) -> Response {
    let (call, v) = match read(&s, req, "/v1/auth/signup").await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let (email, password) = match (field(&call, &v, "email"), field(&call, &v, "password")) {
        (Ok(e), Ok(p)) => (e, p),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    match s.service.signup(email, password).await {
        Ok(id) => json_response(StatusCode::CREATED, &json!({ "id": id }), &call.request_id),
        Err(e) => fail(&call, &e),
    }
}

async fn login(State(s): State<Arc<AuthState>>, req: Request) -> Response {
    let (call, v) = match read(&s, req, "/v1/auth/login").await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let (email, password) = match (field(&call, &v, "email"), field(&call, &v, "password")) {
        (Ok(e), Ok(p)) => (e, p),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    match s.service.login(email, password).await {
        Ok(t) => json_response(StatusCode::OK, &tokens_json(&t), &call.request_id),
        Err(e) => fail(&call, &e),
    }
}

async fn refresh(State(s): State<Arc<AuthState>>, req: Request) -> Response {
    let (call, v) = match read(&s, req, "/v1/auth/refresh").await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let token = match field(&call, &v, "refresh_token") {
        Ok(t) => t,
        Err(r) => return r,
    };
    match s.service.refresh(token).await {
        Ok(t) => json_response(StatusCode::OK, &tokens_json(&t), &call.request_id),
        Err(e) => fail(&call, &e),
    }
}

async fn logout(State(s): State<Arc<AuthState>>, req: Request) -> Response {
    let (call, v) = match read(&s, req, "/v1/auth/logout").await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let token = match field(&call, &v, "refresh_token") {
        Ok(t) => t,
        Err(r) => return r,
    };
    match s.service.logout(token).await {
        Ok(()) => empty(StatusCode::NO_CONTENT, &call.request_id),
        Err(e) => fail(&call, &e),
    }
}

async fn request_reset(State(s): State<Arc<AuthState>>, req: Request) -> Response {
    let (call, v) = match read(&s, req, "/v1/auth/password-reset").await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let email = match field(&call, &v, "email") {
        Ok(e) => e,
        Err(r) => return r,
    };
    match s.service.request_reset(email).await {
        Ok(token) => {
            if let Some(token) = token {
                (s.reset_sink)(email, &token);
            }
            // The same answer whether or not the address has an account.
            json_response(StatusCode::ACCEPTED, &json!({}), &call.request_id)
        }
        Err(e) => fail(&call, &e),
    }
}

async fn confirm_reset(State(s): State<Arc<AuthState>>, req: Request) -> Response {
    let (call, v) = match read(&s, req, "/v1/auth/password-reset/confirm").await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let (token, password) = match (field(&call, &v, "token"), field(&call, &v, "new_password")) {
        (Ok(t), Ok(p)) => (t, p),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    match s.service.reset_password(token, password).await {
        Ok(()) => empty(StatusCode::NO_CONTENT, &call.request_id),
        Err(e) => fail(&call, &e),
    }
}
