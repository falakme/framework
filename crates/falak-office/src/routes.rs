//! Office's HTTP routes (FEDERATION specification).

use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use falak_auth::token::Claims;
use falak_contracts::{Error, Result, driver::Value, identity::Principal};
use falak_runtime_native::{
    auth_routes::{AuthService, auth_router},
    context::{bearer_token, extract_request_id},
    error::problem_response,
};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

use crate::{
    ENROLLMENT_SECS, FEED_TTL_SECS, Office, PASSPORT_SECS, SKEW_SECS, TIER1_TOKEN_SECS,
    TIER2_TOKEN_SECS, conflict,
    db::{int, t, text},
    now,
};

mod compute;
mod console;
mod events;
mod ops;

type Shared = Arc<Office>;

/// The role a step-up token carries, and how long the proof and the token last.
const STEP_UP_ROLE: &str = "step_up";
const STEP_UP_SECS: i64 = 300;

/// Everything Office serves. `login` is the sign-in service behind `/v1/auth/*`.
pub fn router(office: Shared, login: Arc<dyn AuthService>) -> Router {
    let auth = auth_router(login, Arc::new(|_, _| {})).layer(axum::middleware::from_fn_with_state(
        office.clone(),
        // Accounts are made by an administrator. There is no sign-up and no self-service
        // reset in Office. Sign-ins are counted for the console.
        |State(o): State<Shared>, req: Request, next: Next| async move {
            let p = req.uri().path().to_owned();
            if p.ends_with("/signup") || p.contains("/password-reset") {
                return StatusCode::NOT_FOUND.into_response();
            }
            let is_login = req.method() == Method::POST && p.ends_with("/login");
            let res = next.run(req).await;
            if is_login {
                if res.status().is_success() {
                    o.tally("sign_in", "-").await;
                } else {
                    o.tally("sign_in_failed", "-").await;
                }
            }
            res
        },
    ));
    Router::new()
        .route("/", get(console::page))
        .route("/office.js", get(console::script))
        .route("/office.css", get(console::style))
        .route("/v1/_office/status", get(console::status))
        .route("/v1/_office/setup", post(console::setup))
        .route("/v1/_office/overview", get(console::overview))
        .route("/v1/_office/users", get(console::people).post(make_user))
        .route("/v1/_office/audit", get(console::audit_log))
        .route("/v1/_office/stats", get(console::stats))
        .route("/v1/_office/settings/oidc", put(console::set_oidc))
        .route("/v1/_office/settings/address", put(console::set_address))
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(ready))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/v1/_office/enroll", post(enroll))
        .route("/v1/_office/enrollments", post(make_enrollment))
        .route("/v1/_office/manifest", get(manifest))
        .route("/v1/auth/oidc/exchange", post(oidc_exchange))
        .route("/v1/_office/token", post(token))
        .route("/v1/_office/stepup", post(step_up))
        .route(
            "/v1/_office/memberships",
            get(console::memberships)
                .put(membership)
                .delete(console::remove_membership),
        )
        .route("/v1/_office/revocations", get(feed).post(revoke))
        .route("/v1/_office/keys/rotate", post(rotate))
        .route("/v1/_office/keys/retire", post(retire))
        .route("/v1/_office/events", post(events::publish))
        .route("/v1/_office/events/contract", put(events::put_contract))
        .route("/v1/_office/events/claim", post(events::claim))
        .route("/v1/_office/events/ack", post(events::ack))
        .route("/v1/_office/events/dead", get(events::dead))
        .route("/v1/_office/events/replay", post(events::replay))
        .route("/v1/_office/sagas", get(events::sagas))
        .route("/v1/_office/apps", get(apps))
        .route("/v1/_office/apps/{name}/revoke", post(revoke_app))
        .merge(ops::routes())
        .merge(compute::routes())
        .with_state(office)
        .layer(axum::middleware::from_fn(console::secure_headers))
        .layer(axum::middleware::from_fn(ops::record))
        // Sign-in routes come last: Office's own `/.well-known/jwks.json` (the keys it
        // signs app tokens with) must win over the session keys' set.
        .fallback_service(auth)
}

// ---------------------------------------------------------------- plumbing

fn json_response(status: StatusCode, body: &Json, request_id: &str) -> Response {
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

fn fail(e: &Error, instance: &str, request_id: &str) -> Response {
    problem_response(e, instance, request_id, vec![])
}

fn random(n: usize) -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    b
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn new_id() -> String {
    hex::encode(random(16))
}

fn body_json(body: &Bytes) -> Result<Json> {
    serde_json::from_slice::<Json>(body)
        .ok()
        .filter(Json::is_object)
        .ok_or_else(|| Error::invalid_input("invalid_body", "The body must be a JSON object."))
}

fn field<'a>(v: &'a Json, name: &str) -> Result<&'a str> {
    v[name].as_str().ok_or_else(|| {
        Error::invalid_input(
            "invalid_body",
            format!("`{name}` is required and must be text."),
        )
    })
}

fn valid_app(name: &str) -> bool {
    let b = name.as_bytes();
    (2..=40).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

fn tier_lifetime(tier: i64) -> i64 {
    if tier == 1 {
        TIER1_TOKEN_SECS
    } else {
        TIER2_TOKEN_SECS
    }
}

impl Office {
    /// Count one event for today (`day` is days since 1970, UTC). The console draws these.
    /// A failure to count never stops what is being counted.
    pub async fn tally(&self, kind: &str, app: &str) {
        let _ = self
            .db
            .run(
                "INSERT INTO office_stats (day, kind, app, n) VALUES (?, ?, ?, 1) \
                 ON CONFLICT (day, kind, app) DO UPDATE SET n = office_stats.n + 1",
                vec![Value::Int64(now() / 86_400), t(kind), t(app)],
            )
            .await;
    }

    /// The caller, from an Office session token. A subject revoked in the feed is refused
    /// here too: its sessions keep refreshing, but they open nothing in Office.
    async fn session(&self, headers: &HeaderMap) -> Result<Principal> {
        let token = bearer_token(headers).ok_or_else(Error::unauthenticated)?;
        let p = self.session_verifier().verify(token, now())?;
        if self.is_subject_revoked(&p.subject).await? {
            return Err(Error::unauthenticated());
        }
        Ok(p)
    }

    async fn admin(&self, headers: &HeaderMap) -> Result<Principal> {
        let p = self.session(headers).await?;
        if p.roles.iter().any(|r| r == "office_admin") {
            Ok(p)
        } else {
            Err(Error::forbidden())
        }
    }

    /// Record an administrative action in the hash-chained audit table.
    pub(crate) async fn audit(&self, actor: &str, action: &str, detail: &str) {
        let at = now();
        for _ in 0..3 {
            let last = self
                .db
                .rows(
                    "SELECT seq, hash FROM office_audit ORDER BY seq DESC LIMIT 1",
                    vec![],
                )
                .await
                .unwrap_or_default();
            let (seq, prev) = last
                .first()
                .map_or((0, String::new()), |r| (int(r.first()), text(r.get(1))));
            let seq = seq + 1;
            let hash =
                sha256_hex(format!("{prev}|{seq}|{at}|{actor}|{action}|{detail}").as_bytes());
            let done = self
                .db
                .run(
                    "INSERT INTO office_audit (seq, at, actor, action, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    vec![
                        Value::Int64(seq),
                        Value::Int64(at),
                        t(actor),
                        t(action),
                        t(detail),
                        t(&prev),
                        t(&hash),
                    ],
                )
                .await;
            if done.is_ok() {
                return;
            }
        }
    }

    async fn feed_version(&self) -> Result<i64> {
        let r = self
            .db
            .rows(
                "SELECT COALESCE(MAX(version), 0) FROM office_revocations",
                vec![],
            )
            .await?;
        Ok(r.first().map_or(0, |r| int(r.first())))
    }

    pub async fn add_revocation(&self, kind: &str, id: &str) -> Result<i64> {
        for _ in 0..5 {
            let done = self
                .db
                .run(
                    "INSERT INTO office_revocations (version, kind, id, at) SELECT COALESCE(MAX(version), 0) + 1, ?, ?, ? FROM office_revocations",
                    vec![t(kind), t(id), Value::Int64(now())],
                )
                .await;
            if done.is_ok() {
                return self.feed_version().await;
            }
        }
        Err(conflict("revocation_busy", "Try again."))
    }

    async fn is_subject_revoked(&self, sub: &str) -> Result<bool> {
        Ok(!self
            .db
            .rows(
                "SELECT version FROM office_revocations WHERE kind = 'subject' AND id = ?",
                vec![t(sub)],
            )
            .await?
            .is_empty())
    }

    /// Sign a JWS-style document with the active key.
    fn sign_document(&self, typ: &str, payload: &Json) -> String {
        let header = json!({ "alg": "EdDSA", "typ": typ, "kid": self.active_kid() });
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(payload.to_string())
        );
        let (_, sig) = self.sign(input.as_bytes());
        format!("{input}.{}", B64.encode(sig))
    }
}

struct AppRow {
    name: String,
    tier: i64,
    public_key: [u8; 32],
}

impl Office {
    async fn app(&self, name: &str) -> Result<Option<(AppRow, String)>> {
        let rows = self
            .db
            .rows(
                "SELECT name, tier, public_key, status FROM office_apps WHERE name = ?",
                vec![t(name)],
            )
            .await?;
        let Some(r) = rows.first() else {
            return Ok(None);
        };
        let key = B64
            .decode(text(r.get(2)))
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| Error::internal("a stored app key is not valid"))?;
        Ok(Some((
            AppRow {
                name: text(r.first()),
                tier: int(r.get(1)),
                public_key: key,
            },
            text(r.get(3)),
        )))
    }

    /// Check a signed request from an enrolled app (FEDERATION §4).
    async fn app_request(
        &self,
        method: &Method,
        uri: &axum::http::Uri,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<AppRow> {
        let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("");
        let (name, ts, nonce, sig) = (
            h("x-falak-app"),
            h("x-falak-timestamp"),
            h("x-falak-nonce"),
            h("x-falak-signature"),
        );
        let ts: i64 = ts.parse().map_err(|_| Error::unauthenticated())?;
        if (now() - ts).abs() > SKEW_SECS || nonce.len() < 16 || nonce.len() > 128 {
            return Err(Error::unauthenticated());
        }
        let Some((app, status)) = self.app(name).await? else {
            return Err(Error::unauthenticated());
        };
        if status != "active" {
            return Err(Error::unauthenticated());
        }
        let message = format!(
            "{}\n{}\n{ts}\n{nonce}\n{}",
            method,
            uri.path_and_query().map_or("/", |p| p.as_str()),
            sha256_hex(body)
        );
        let key =
            VerifyingKey::from_bytes(&app.public_key).map_err(|_| Error::unauthenticated())?;
        let sig = B64
            .decode(sig)
            .ok()
            .and_then(|b| Signature::from_slice(&b).ok())
            .ok_or_else(Error::unauthenticated)?;
        key.verify(message.as_bytes(), &sig)
            .map_err(|_| Error::unauthenticated())?;
        // A nonce is good once. Old ones are swept as we go.
        let _ = self
            .db
            .run(
                "DELETE FROM office_nonces WHERE seen_at < ?",
                vec![Value::Int64(now() - 2 * SKEW_SECS - 60)],
            )
            .await;
        let fresh = self
            .db
            .run(
                "INSERT INTO office_nonces (app, nonce, seen_at) VALUES (?, ?, ?)",
                vec![t(name), t(nonce), Value::Int64(now())],
            )
            .await;
        if fresh.is_err() {
            return Err(Error::unauthenticated());
        }
        Ok(app)
    }
}

// ---------------------------------------------------------------- handlers

async fn ready(State(o): State<Shared>) -> Response {
    match o.db.rows("SELECT 1", vec![]).await {
        Ok(_) => "ok".into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "database unavailable").into_response(),
    }
}

async fn jwks(State(o): State<Shared>) -> Response {
    let mut res = o.jwks().to_string().into_response();
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

async fn make_enrollment(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/enrollments");
    let run = async {
        let admin = o.admin(&headers).await?;
        let v = body_json(&body)?;
        let app = field(&v, "app")?;
        let tier = v["tier"].as_i64().unwrap_or(1);
        if !valid_app(app) || !(1..=3).contains(&tier) {
            return Err(Error::invalid_input(
                "invalid_app",
                "An app name is lower case letters, digits, `-` and `_`; the tier is 1, 2 or 3.",
            ));
        }
        if tier == 3 {
            return Err(Error::unsupported(
                "tier_3_unsupported",
                "Tier 3 apps are not supported by this version of Office.",
            ));
        }
        let caps = v["capabilities"].to_string();
        let token = B64.encode(random(32));
        let expires = now() + ENROLLMENT_SECS;
        o.db.run(
            "INSERT INTO office_enrollments (token_hash, app, tier, capabilities, expires_at) VALUES (?, ?, ?, ?, ?)",
            vec![
                t(&sha256_hex(token.as_bytes())),
                t(app),
                Value::Int64(tier),
                t(&caps),
                Value::Int64(expires),
            ],
        )
        .await?;
        o.audit(&admin.subject, "enrollment_created", app).await;
        Ok(json!({"token": token, "app": app, "tier": tier, "expires_at": expires}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::CREATED, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

async fn enroll(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/enroll");
    let run = async {
        let v = body_json(&body)?;
        let (token, app, public_key, nonce, sig) = (
            field(&v, "token")?,
            field(&v, "app")?,
            field(&v, "public_key")?,
            field(&v, "nonce")?,
            field(&v, "signature")?,
        );
        let ts = v["timestamp"].as_i64().ok_or_else(Error::unauthenticated)?;
        // Every refusal below is the same answer: a caller learns nothing about which
        // check failed.
        let refuse = Error::unauthenticated;
        if (now() - ts).abs() > SKEW_SECS || nonce.len() < 16 || !valid_app(app) {
            return Err(refuse());
        }
        let key_bytes = B64
            .decode(public_key)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(refuse)?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| refuse())?;
        let signature = B64
            .decode(sig)
            .ok()
            .and_then(|b| Signature::from_slice(&b).ok())
            .ok_or_else(refuse)?;
        let message = format!("falak-enroll\n{app}\n{public_key}\n{nonce}\n{ts}");
        key.verify(message.as_bytes(), &signature)
            .map_err(|_| refuse())?;

        let hash = sha256_hex(token.as_bytes());
        let rows = o
            .db
            .rows(
                "SELECT app, tier, capabilities, expires_at, used_by FROM office_enrollments WHERE token_hash = ?",
                vec![t(&hash)],
            )
            .await?;
        let row = rows.first().ok_or_else(refuse)?;
        if text(row.first()) != app
            || int(row.get(3)) < now()
            || row.get(4).is_some_and(|u| !matches!(u, Value::Null))
        {
            return Err(refuse());
        }
        let (tier, caps) = (int(row.get(1)), text(row.get(2)));
        let marker = new_id();
        let jti = new_id();
        let kid = hex::encode(&Sha256::digest(key_bytes)[..6]);
        // Use the token and make the app in one transaction. The insert runs only if this
        // request is the one that used the token.
        let out = o
            .db
            .batch(vec![
                o.db.stmt(
                    "UPDATE office_enrollments SET used_by = ? WHERE token_hash = ? AND used_by IS NULL AND expires_at >= ?",
                    vec![t(&marker), t(&hash), Value::Int64(now())],
                ),
                o.db.stmt(
                    "INSERT INTO office_apps (name, tier, public_key, kid, capabilities, passport_jti, status, created_at) \
                     SELECT ?, ?, ?, ?, ?, ?, 'active', ? WHERE EXISTS (SELECT 1 FROM office_enrollments WHERE token_hash = ? AND used_by = ?)",
                    vec![
                        t(app),
                        Value::Int64(tier),
                        t(public_key),
                        t(&kid),
                        t(&caps),
                        t(&jti),
                        Value::Int64(now()),
                        t(&hash),
                        t(&marker),
                    ],
                ),
            ])
            .await
            .map_err(|_| conflict("app_exists", "That app name is already enrolled."))?;
        if out.get(1).map_or(0, |o| o.rows_affected) != 1 {
            return Err(refuse());
        }
        let iat = now();
        let capabilities: Json = serde_json::from_str(&caps).unwrap_or(Json::Null);
        let passport = o.sign_document(
            "falak-passport",
            &json!({
                "iss": o.issuer, "sub": app, "kind": "passport", "tier": tier,
                "capabilities": capabilities, "app_key": public_key,
                "iat": iat, "exp": iat + PASSPORT_SECS, "jti": jti,
            }),
        );
        o.audit("enroll", "app_enrolled", app).await;
        Ok(json!({
            "app": app, "tier": tier, "passport": passport,
            "issuer": o.issuer, "jwks_url": format!("{}/.well-known/jwks.json", o.issuer),
        }))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::CREATED, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

async fn manifest(State(o): State<Shared>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rid = extract_request_id(&parts.headers);
    let inst = "/v1/_office/manifest";
    let bytes = axum::body::to_bytes(body, 1024).await.unwrap_or_default();
    let run = async {
        let app = o
            .app_request(&parts.method, &parts.uri, &parts.headers, &bytes)
            .await?;
        Ok::<_, Error>(json!({
            "issuer": o.issuer, "audience": app.name, "tier": app.tier,
            "jwks_url": format!("{}/.well-known/jwks.json", o.issuer),
            "revocations_url": format!("{}/v1/_office/revocations", o.issuer),
            "feed_version": o.feed_version().await?, "now": now(),
        }))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

async fn token(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/token");
    let run = async {
        let me = o.session(&headers).await?;
        let v = body_json(&body)?;
        app_token(&o, &me.subject, field(&v, "audience")?, false).await
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

/// The token for one app, from the person's membership. `step_up` adds the role
/// `step_up` and shortens the life: the person has just proven themselves again.
async fn app_token(o: &Office, subject: &str, audience: &str, step_up: bool) -> Result<Json> {
    if o.is_subject_revoked(subject).await? {
        return Err(Error::unauthenticated());
    }
    let Some((app, status)) = o.app(audience).await? else {
        return Err(Error::forbidden());
    };
    let member =
        o.db.rows(
            "SELECT tenant, roles FROM office_memberships WHERE user_id = ? AND app = ?",
            vec![t(subject), t(audience)],
        )
        .await?;
    // An app that is revoked, or one this person has no membership for, gets the same
    // answer.
    let Some(m) = member.first().filter(|_| status == "active") else {
        return Err(Error::forbidden());
    };
    let tenant = match m.first() {
        Some(Value::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let mut roles: Vec<String> = text(m.get(1))
        .split(',')
        .filter(|r| !r.is_empty() && *r != STEP_UP_ROLE)
        .map(str::to_owned)
        .collect();
    let mut lifetime = tier_lifetime(app.tier);
    if step_up {
        roles.push(STEP_UP_ROLE.to_owned());
        lifetime = lifetime.min(STEP_UP_SECS);
    }
    let issued_at = now();
    let access = o.issue(
        audience,
        &Claims {
            subject: subject.to_owned(),
            tenant,
            roles,
            issued_at,
            expires_at: issued_at + lifetime,
            token_id: new_id(),
        },
    );
    o.tally("app_token", audience).await;
    Ok(json!({"access_token": access, "token_type": "Bearer", "expires_in": lifetime}))
}

/// Step-up: the person proves themselves again at the identity provider, and gets an
/// app token that carries the role `step_up` for a few minutes. Policies that guard a
/// sensitive action ask for that role. The proof is a fresh ID token for the same
/// provider identity (`auth_time` within five minutes).
async fn step_up(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/stepup");
    let Some(oidc) = o.oidc() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let run = async {
        let me = o.session(&headers).await?;
        let v = body_json(&body)?;
        let (audience, id_token) = (field(&v, "audience")?, field(&v, "id_token")?.to_owned());
        if oidc.wants_refresh(&id_token, now()) {
            let fetch = oidc.clone();
            let _ = tokio::task::spawn_blocking(move || fetch.refresh_blocking(now())).await;
        }
        let who = oidc.verify(&id_token).map_err(|why| {
            eprintln!("oidc: refused a step-up token ({why})");
            Error::unauthenticated()
        })?;
        // Fresh: the person signed in just now, not a session that has simply kept going.
        if !who
            .auth_time
            .is_some_and(|t| now() - t <= STEP_UP_SECS && t <= now() + 30)
        {
            return Err(Error::unauthenticated());
        }
        // And it is the same person as this Office session.
        let linked =
            o.db.rows(
                "SELECT user_id FROM office_identities WHERE issuer = ? AND subject = ?",
                vec![t(&who.issuer), t(&who.subject)],
            )
            .await?;
        if linked.first().map(|r| text(r.first())).as_deref() != Some(me.subject.as_str()) {
            return Err(Error::unauthenticated());
        }
        let out = app_token(&o, &me.subject, audience, true).await?;
        o.audit(&me.subject, "step_up", audience).await;
        Ok(out)
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

async fn make_user(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/users");
    let run = async {
        let admin = o.admin(&headers).await?;
        let v = body_json(&body)?;
        let (email, password) = (field(&v, "email")?, field(&v, "password")?);
        let roles: Vec<String> = v["roles"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|r| r.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let id = o.users.create(email, password, &roles).await?;
        o.audit(&admin.subject, "user_created", &id).await;
        Ok(json!({"id": id}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::CREATED, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

/// Trade an ID token from the configured OpenID Connect provider for an Office session.
/// Every refusal looks the same from outside.
async fn oidc_exchange(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/auth/oidc/exchange");
    let Some(oidc) = o.oidc() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let run = async {
        let v = body_json(&body)?;
        let token = field(&v, "id_token")?.to_owned();
        if oidc.wants_refresh(&token, now()) {
            let fetch = oidc.clone();
            let _ = tokio::task::spawn_blocking(move || fetch.refresh_blocking(now())).await;
        }
        let who = oidc.verify(&token).map_err(|why| {
            eprintln!("oidc: refused a token ({why})");
            Error::unauthenticated()
        })?;
        let (issuer, subject) = (who.issuer.as_str(), who.subject.as_str());

        // The same person again: found by the provider's own id, not by email.
        let linked =
            o.db.rows(
                "SELECT user_id FROM office_identities WHERE issuer = ? AND subject = ?",
                vec![t(issuer), t(subject)],
            )
            .await?;
        let user = if let Some(row) = linked.first() {
            text(row.first())
        } else {
            // First time: link to the account with this (verified) email, or make one
            // if the email's domain is allowed. Anyone else is refused.
            let id = match o.users.find(&who.email).await? {
                Some(id) => id,
                None if oidc.may_create(&who.email) => o.users.create_linked(&who.email).await?,
                None => return Err(Error::unauthenticated()),
            };
            o.db.run(
                "INSERT INTO office_identities (issuer, subject, user_id, linked_at) VALUES (?, ?, ?, ?)",
                vec![t(issuer), t(subject), t(&id), Value::Int64(now())],
            )
            .await
            .map_err(|_| Error::unauthenticated())?;
            o.audit("oidc", "identity_linked", &id).await;
            id
        };
        if o.is_subject_revoked(&user).await? {
            return Err(Error::unauthenticated());
        }
        let tokens = o
            .users
            .session_for(&user)
            .await?
            .ok_or_else(Error::unauthenticated)?;
        Ok::<_, Error>(json!({
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "expires_in": tokens.expires_in,
            "token_type": "Bearer",
        }))
    };
    match run.await {
        Ok(v) => {
            o.tally("sign_in_provider", "-").await;
            json_response(StatusCode::OK, &v, &rid)
        }
        Err(e) => {
            o.tally("sign_in_failed", "-").await;
            fail(&e, inst, &rid)
        }
    }
}

async fn membership(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/memberships");
    let run = async {
        let admin = o.admin(&headers).await?;
        let v = body_json(&body)?;
        let app = field(&v, "app")?;
        let user = match v["user_id"].as_str() {
            Some(id) => id.to_owned(),
            None => o
                .users
                .find(field(&v, "email")?)
                .await?
                .ok_or_else(Error::not_found)?,
        };
        let tenant = v["tenant"].as_str().unwrap_or("");
        let roles: Vec<&str> = v["roles"]
            .as_array()
            .map(|a| a.iter().filter_map(Json::as_str).collect())
            .unwrap_or_default();
        if roles.iter().any(|r| r.contains(',') || r.is_empty()) {
            return Err(Error::invalid_input(
                "invalid_roles",
                "A role is a plain name.",
            ));
        }
        if o.app(app).await?.is_none() {
            return Err(Error::not_found());
        }
        let tenant_value = if tenant.is_empty() {
            Value::Null
        } else {
            t(tenant)
        };
        o.db.batch(vec![
            o.db.stmt(
                "DELETE FROM office_memberships WHERE user_id = ? AND app = ?",
                vec![t(&user), t(app)],
            ),
            o.db.stmt(
                "INSERT INTO office_memberships (user_id, app, tenant, roles) VALUES (?, ?, ?, ?)",
                vec![t(&user), t(app), tenant_value, t(&roles.join(","))],
            ),
        ])
        .await?;
        o.audit(&admin.subject, "membership_set", &format!("{user}:{app}"))
            .await;
        Ok(json!({"user_id": user, "app": app, "tenant": tenant, "roles": roles}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

async fn feed(State(o): State<Shared>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rid = extract_request_id(&parts.headers);
    let inst = "/v1/_office/revocations";
    let bytes = axum::body::to_bytes(body, 1024).await.unwrap_or_default();
    let run = async {
        let who = o
            .app_request(&parts.method, &parts.uri, &parts.headers, &bytes)
            .await?;
        o.tally("app_sync", &who.name).await;
        let since: i64 = parts
            .uri
            .query()
            .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("since=")))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let rows = o
            .db
            .rows(
                "SELECT version, kind, id, at FROM office_revocations WHERE version > ? ORDER BY version",
                vec![Value::Int64(since)],
            )
            .await?;
        let entries: Vec<Json> = rows
            .iter()
            .map(|r| json!({"kind": text(r.get(1)), "id": text(r.get(2)), "at": int(r.get(3))}))
            .collect();
        let payload = json!({
            "version": o.feed_version().await?, "issued_at": now(),
            "ttl_secs": FEED_TTL_SECS, "entries": entries,
        })
        .to_string();
        let (kid, sig) = o.sign(payload.as_bytes());
        Ok::<_, Error>(json!({"payload": payload, "kid": kid, "signature": B64.encode(sig)}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

async fn revoke(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/revocations");
    let run = async {
        let admin = o.admin(&headers).await?;
        let v = body_json(&body)?;
        let (kind, id) = (field(&v, "kind")?, field(&v, "id")?);
        if !["token", "subject", "app", "passport"].contains(&kind)
            || id.is_empty()
            || id.len() > 200
        {
            return Err(Error::invalid_input(
                "invalid_revocation",
                "Unknown kind or empty id.",
            ));
        }
        let version = o.add_revocation(kind, id).await?;
        o.audit(&admin.subject, "revoked", &format!("{kind}:{id}"))
            .await;
        Ok(json!({"version": version}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::CREATED, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

async fn rotate(State(o): State<Shared>, headers: HeaderMap) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/keys/rotate");
    let run = async {
        let admin = o.admin(&headers).await?;
        let kid = o.rotate()?;
        o.persist_keys().await?;
        o.audit(&admin.subject, "key_rotated", &kid).await;
        Ok(json!({"kid": kid, "keys": o.key_count()}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

async fn retire(State(o): State<Shared>, headers: HeaderMap) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/keys/retire");
    let run = async {
        let admin = o.admin(&headers).await?;
        o.retire()?;
        o.persist_keys().await?;
        o.audit(&admin.subject, "keys_retired", "").await;
        Ok::<_, Error>(json!({"keys": o.key_count()}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

async fn apps(State(o): State<Shared>, headers: HeaderMap) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/apps");
    let run = async {
        o.admin(&headers).await?;
        let rows =
            o.db.rows(
                "SELECT name, tier, status, created_at FROM office_apps ORDER BY name",
                vec![],
            )
            .await?;
        Ok::<_, Error>(json!({"data": rows.iter().map(|r| json!({
            "name": text(r.first()), "tier": int(r.get(1)),
            "status": text(r.get(2)), "created_at": int(r.get(3)),
        })).collect::<Vec<_>>()}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

async fn revoke_app(
    State(o): State<Shared>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let (rid, inst) = (
        extract_request_id(&headers),
        format!("/v1/_office/apps/{name}/revoke"),
    );
    let run = async {
        let admin = o.admin(&headers).await?;
        if o.app(&name).await?.is_none() {
            return Err(Error::not_found());
        }
        o.db.run(
            "UPDATE office_apps SET status = 'revoked' WHERE name = ?",
            vec![t(&name)],
        )
        .await?;
        let version = o.add_revocation("app", &name).await?;
        o.audit(&admin.subject, "app_revoked", &name).await;
        Ok::<_, Error>(json!({"app": name, "version": version}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, &inst, &rid),
    }
}
