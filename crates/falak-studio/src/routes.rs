//! Studio's HTTP surface: the static page, and `/api/*` for the page to call.
#![allow(clippy::result_large_err)] // the error is the response to send, built once

use std::{collections::HashMap, sync::Arc, sync::Mutex};

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};

use crate::{
    ABSOLUTE_SECS, Audit, Config, IDLE_SECS, MASK, STUDIO_ROLES, mask_rows, now, random_id,
};

const COOKIE: &str = "studio_session";
/// Sessions held at once. Ended ones are swept at each sign-in; past this, sign-in waits.
const MAX_SESSIONS: usize = 1000;
const INDEX: &str = include_str!("../static/index.html");
const SCRIPT: &str = include_str!("../static/studio.js");
const STYLE: &str = include_str!("../static/studio.css");
/// The strictest policy the page works under: its own script and style, nothing inline,
/// no framing, no other origin.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

struct Session {
    label: String,
    csrf: String,
    access: String,
    refresh: String,
    access_exp: i64,
    app_tokens: HashMap<String, (String, i64)>,
    schemas: HashMap<String, (Value, i64)>,
    created: i64,
    seen: i64,
}

pub struct Studio {
    pub cfg: Config,
    pub audit: Audit,
    sessions: Mutex<HashMap<String, Session>>,
}

impl Studio {
    pub fn new(cfg: Config, audit: Audit) -> Self {
        Self {
            cfg,
            audit,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner())
    }
}

type Shared = Arc<Studio>;

pub fn router(studio: Shared) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { asset(INDEX, "text/html; charset=utf-8") }),
        )
        .route(
            "/studio.js",
            get(|| async { asset(SCRIPT, "text/javascript; charset=utf-8") }),
        )
        .route(
            "/studio.css",
            get(|| async { asset(STYLE, "text/css; charset=utf-8") }),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/login", post(login))
        .route("/api/oidc", post(oidc))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/observatory/{view}", get(observatory))
        .route("/api/apps/{app}/schema", get(schema))
        .route("/api/apps/{app}/{entity}", get(list).post(create))
        .route(
            "/api/apps/{app}/{entity}/{id}",
            axum::routing::patch(update).delete(remove),
        )
        .route("/api/apps/{app}/{entity}/{id}/reveal", post(reveal))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .layer(axum::middleware::from_fn(secure_headers))
        .with_state(studio)
}

fn asset(body: &'static str, kind: &'static str) -> Response {
    let mut r = body.into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
    r
}

async fn secure_headers(req: Request, next: Next) -> Response {
    let api = req.uri().path().starts_with("/api/");
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    for (k, v) in [
        ("content-security-policy", CSP),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()",
        ),
    ] {
        h.insert(HeaderName::from_static(k), HeaderValue::from_static(v));
    }
    if api {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

// ---------------------------------------------------------------- plumbing

fn reply(status: u16, body: &Value) -> Response {
    let mut r = (
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
        body.to_string(),
    )
        .into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    r
}

fn problem(status: u16, detail: &str) -> Response {
    reply(
        status,
        &json!({"status": status, "title": detail, "detail": detail}),
    )
}

type Out<T> = Result<T, Response>;

/// A call to Office or an app, off the async threads.
async fn upstream(
    method: &'static str,
    url: String,
    bearer: Option<String>,
    headers: Vec<(&'static str, String)>,
    body: Option<Value>,
) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        // A refusal (4xx, 5xx) is an answer whose body the caller wants, not an error.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            // A configured app or Office must not be able to send the person's token on
            // to another address with a redirect.
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into();
        let mut req = ureq::http::Request::builder()
            .method(method)
            .uri(url.as_str());
        if let Some(t) = bearer {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        for (k, v) in &headers {
            req = req.header(*k, v.as_str());
        }
        let res = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(b.to_string())
                .map_err(|_| ())
                .and_then(|r| agent.run(r).map_err(|_| ())),
            None => req
                .body(())
                .map_err(|_| ())
                .and_then(|r| agent.run(r).map_err(|_| ())),
        };
        match res {
            Ok(mut r) => (
                r.status().as_u16(),
                r.body_mut().read_json().unwrap_or(Value::Null),
            ),
            Err(_) => (502, json!({"title": "The service did not answer."})),
        }
    })
    .await
    .unwrap_or((502, json!({"title": "The service did not answer."})))
}

fn cookie_of(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_owned())
}

fn set_cookie(studio: &Studio, value: &str, max_age: i64) -> HeaderValue {
    let secure = if studio.cfg.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "{COOKIE}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true; // not a browser cross-site request
    };
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let origin_host = origin.split_once("://").map(|(_, h)| h);
    host.is_some() && origin_host == host
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

struct Who {
    sid: String,
    label: String,
    csrf: String,
}

/// The signed-in person, or the refusal to send. Unsafe methods also need the CSRF
/// header and a same-origin `Origin`.
fn guard(studio: &Studio, headers: &HeaderMap, write: bool) -> Out<Who> {
    let Some(sid) = cookie_of(headers) else {
        return Err(problem(401, "Sign in first."));
    };
    let t = now();
    let mut all = studio.sessions();
    let Some(s) = all.get_mut(&sid) else {
        return Err(problem(401, "Sign in first."));
    };
    if t - s.seen > IDLE_SECS || t - s.created > ABSOLUTE_SECS {
        all.remove(&sid);
        return Err(problem(401, "Your session ended. Sign in again."));
    }
    if write {
        let sent = headers
            .get("x-studio-csrf")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if !same(sent, &s.csrf) || !same_origin(headers) {
            return Err(problem(403, "Request refused."));
        }
    }
    s.seen = t;
    Ok(Who {
        sid,
        label: s.label.clone(),
        csrf: s.csrf.clone(),
    })
}

fn app_url(studio: &Studio, app: &str) -> Out<String> {
    studio
        .cfg
        .apps
        .iter()
        .find(|a| a.name == app)
        .map(|a| a.url.trim_end_matches('/').to_owned())
        .ok_or_else(|| problem(404, "No such app."))
}

fn payload(token: &str) -> Value {
    token
        .split('.')
        .nth(1)
        .and_then(|p| B64.decode(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null)
}

fn audit(studio: &Studio, actor: &str, action: &str, target: &str) -> Out<()> {
    studio
        .audit
        .record(actor, action, target)
        .map_err(|_| problem(503, "The audit log is unavailable, so nothing was done."))
}

// ---------------------------------------------------------------- Office

/// Keep the Office access token fresh, and return it.
async fn office_access(studio: &Studio, sid: &str) -> Out<String> {
    let (access, refresh, exp) = {
        let all = studio.sessions();
        let s = all.get(sid).ok_or_else(|| problem(401, "Sign in first."))?;
        (s.access.clone(), s.refresh.clone(), s.access_exp)
    };
    if now() < exp - 30 {
        return Ok(access);
    }
    let url = format!(
        "{}/v1/auth/refresh",
        studio.cfg.office_url.trim_end_matches('/')
    );
    let (code, body) = upstream(
        "POST",
        url,
        None,
        vec![],
        Some(json!({"refresh_token": refresh})),
    )
    .await;
    let (Some(a), Some(r)) = (
        body["access_token"].as_str(),
        body["refresh_token"].as_str(),
    ) else {
        studio.sessions().remove(sid);
        let _ = code;
        return Err(problem(401, "Your session ended. Sign in again."));
    };
    let mut all = studio.sessions();
    let s = all
        .get_mut(sid)
        .ok_or_else(|| problem(401, "Sign in first."))?;
    s.access = a.to_owned();
    s.refresh = r.to_owned();
    s.access_exp = now() + body["expires_in"].as_i64().unwrap_or(300);
    Ok(a.to_owned())
}

async fn app_token(studio: &Studio, sid: &str, app: &str, fresh: bool) -> Out<String> {
    if !fresh {
        let all = studio.sessions();
        if let Some((t, exp)) = all.get(sid).and_then(|s| s.app_tokens.get(app))
            && now() < *exp - 30
        {
            return Ok(t.clone());
        }
    }
    let access = office_access(studio, sid).await?;
    let url = format!(
        "{}/v1/_office/token",
        studio.cfg.office_url.trim_end_matches('/')
    );
    let (code, body) = upstream(
        "POST",
        url,
        Some(access),
        vec![],
        Some(json!({"audience": app})),
    )
    .await;
    match (code, body["access_token"].as_str()) {
        (200, Some(t)) => {
            let exp = now() + body["expires_in"].as_i64().unwrap_or(300);
            if let Some(s) = studio.sessions().get_mut(sid) {
                s.app_tokens.insert(app.to_owned(), (t.to_owned(), exp));
            }
            Ok(t.to_owned())
        }
        (403, _) => Err(problem(403, "You have no access to this app.")),
        _ => Err(problem(502, "Office could not give a token for this app.")),
    }
}

/// A call to an app's API as this person.
async fn app_call(
    studio: &Studio,
    sid: &str,
    app: &str,
    method: &'static str,
    path: &str,
    headers: Vec<(&'static str, String)>,
    body: Option<Value>,
) -> Out<(u16, Value)> {
    let base = app_url(studio, app)?;
    for attempt in 0..2 {
        let token = app_token(studio, sid, app, attempt == 1).await?;
        let (code, out) = upstream(
            method,
            format!("{base}{path}"),
            Some(token),
            headers.clone(),
            body.clone(),
        )
        .await;
        if code != 401 || attempt == 1 {
            return Ok((code, out));
        }
    }
    Err(problem(502, "The app did not answer."))
}

// ---------------------------------------------------------------- sign-in

async fn finish_login(studio: &Studio, code: u16, body: &Value, label: Option<&str>) -> Response {
    let refused = || problem(401, "Sign-in failed. Check your details and try again.");
    let (Some(access), Some(refresh)) = (
        body["access_token"].as_str(),
        body["refresh_token"].as_str(),
    ) else {
        let _ = studio.audit.record("-", "login_failed", "-");
        return if code >= 500 || code == 0 {
            problem(502, "Office did not answer.")
        } else {
            refused()
        };
    };
    let claims = payload(access);
    let allowed = claims["roles"].as_array().is_some_and(|r| {
        r.iter()
            .any(|x| x.as_str().is_some_and(|x| STUDIO_ROLES.contains(&x)))
    });
    let subject = claims["sub"].as_str().unwrap_or("-").to_owned();
    if !allowed {
        let _ = studio
            .audit
            .record(&subject, "login_refused", "no studio role");
        return refused();
    }
    let label = label.unwrap_or(&subject).to_owned();
    if audit(studio, &subject, "login", "-").is_err() {
        return problem(503, "The audit log is unavailable, so nothing was done.");
    }
    let sid = random_id();
    let csrf = random_id();
    let t = now();
    let mut all = studio.sessions();
    all.retain(|_, s| t - s.seen <= IDLE_SECS && t - s.created <= ABSOLUTE_SECS);
    if all.len() >= MAX_SESSIONS {
        return problem(503, "Too many people are signed in. Try again later.");
    }
    all.insert(
        sid.clone(),
        Session {
            label: label.clone(),
            csrf: csrf.clone(),
            access: access.to_owned(),
            refresh: refresh.to_owned(),
            access_exp: t + body["expires_in"].as_i64().unwrap_or(300),
            app_tokens: HashMap::new(),
            schemas: HashMap::new(),
            created: t,
            seen: t,
        },
    );
    drop(all);
    let mut res = reply(200, &me_body(studio, &label, &csrf));
    res.headers_mut()
        .insert(header::SET_COOKIE, set_cookie(studio, &sid, ABSOLUTE_SECS));
    res
}

fn me_body(studio: &Studio, label: &str, csrf: &str) -> Value {
    json!({
        "email": label, "csrf": csrf,
        "apps": studio.cfg.apps.iter().map(|a| a.name.clone()).collect::<Vec<_>>(),
    })
}

async fn login(State(studio): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    // A page on another site must not be able to sign a browser in as someone else.
    if !same_origin(&headers) {
        return problem(403, "Request refused.");
    }
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return problem(400, "Send email and password.");
    };
    let (Some(email), Some(password)) = (v["email"].as_str(), v["password"].as_str()) else {
        return problem(400, "Send email and password.");
    };
    let url = format!(
        "{}/v1/auth/login",
        studio.cfg.office_url.trim_end_matches('/')
    );
    let (code, out) = upstream(
        "POST",
        url,
        None,
        vec![],
        Some(json!({"email": email, "password": password})),
    )
    .await;
    finish_login(&studio, code, &out, Some(&email.trim().to_lowercase())).await
}

/// Sign in with an ID token from the identity provider Office trusts.
async fn oidc(State(studio): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    if !same_origin(&headers) {
        return problem(403, "Request refused.");
    }
    let Some(token) = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v["id_token"].as_str().map(str::to_owned))
    else {
        return problem(400, "Send an id_token.");
    };
    let url = format!(
        "{}/v1/auth/oidc/exchange",
        studio.cfg.office_url.trim_end_matches('/')
    );
    let (code, out) = upstream("POST", url, None, vec![], Some(json!({"id_token": token}))).await;
    finish_login(&studio, code, &out, None).await
}

async fn logout(State(studio): State<Shared>, headers: HeaderMap) -> Response {
    let who = match guard(&studio, &headers, true) {
        Ok(w) => w,
        Err(r) => return r,
    };
    let _ = studio.audit.record(&who.label, "logout", "-");
    studio.sessions().remove(&who.sid);
    let mut res = reply(200, &json!({}));
    res.headers_mut()
        .insert(header::SET_COOKIE, set_cookie(&studio, "", 0));
    res
}

async fn me(State(studio): State<Shared>, headers: HeaderMap) -> Response {
    match guard(&studio, &headers, false) {
        Ok(w) => reply(200, &me_body(&studio, &w.label, &w.csrf)),
        Err(r) => r,
    }
}

// ---------------------------------------------------------------- observatory

/// Observatory: the service objectives, the audit chain and break-glass requests of
/// Office, shown to Office administrators. Studio only passes the person's own Office
/// token on, so Office decides who may see them.
async fn observatory(
    State(studio): State<Shared>,
    headers: HeaderMap,
    Path(view): Path<String>,
) -> Response {
    let who = match guard(&studio, &headers, false) {
        Ok(w) => w,
        Err(r) => return r,
    };
    let path = match view.as_str() {
        "slo" => "/v1/_office/slo",
        "audit" => "/v1/_office/audit",
        "verify" => "/v1/_office/audit/verify",
        "breakglass" => "/v1/_office/breakglass",
        "stats" => "/v1/_office/stats",
        _ => return problem(404, "No such view."),
    };
    let access = match office_access(&studio, &who.sid).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let url = format!("{}{path}", studio.cfg.office_url.trim_end_matches('/'));
    let (code, body) = upstream("GET", url, Some(access), vec![], None).await;
    match code {
        200 => reply(200, &body),
        // A chain that does not verify is an answer, not a failure of the request.
        409 if view == "verify" => {
            let mut b = body;
            b["ok"] = json!(false);
            reply(200, &b)
        }
        401 | 403 => problem(403, "The Observatory is for Office administrators."),
        _ => problem(502, "Office did not answer."),
    }
}

// ---------------------------------------------------------------- data

/// The app's schema for this person, cached for a minute.
async fn schema_of(studio: &Studio, sid: &str, app: &str) -> Out<Value> {
    {
        let all = studio.sessions();
        if let Some((v, at)) = all.get(sid).and_then(|s| s.schemas.get(app))
            && now() - *at < 60
        {
            return Ok(v.clone());
        }
    }
    let (code, v) = app_call(studio, sid, app, "GET", "/v1/_schema", vec![], None).await?;
    if code != 200 {
        return Err(problem(code, "The app would not describe itself."));
    }
    if let Some(s) = studio.sessions().get_mut(sid) {
        s.schemas.insert(app.to_owned(), (v.clone(), now()));
    }
    Ok(v)
}

struct Entity {
    path: String,
    sensitive: Vec<String>,
    fields: Vec<String>,
}

fn entity_of(schema: &Value, path: &str) -> Out<Entity> {
    let e = schema["entities"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["path"] == path))
        .ok_or_else(|| problem(404, "No such record type."))?;
    let fields = e["fields"].as_array().cloned().unwrap_or_default();
    Ok(Entity {
        path: path.to_owned(),
        sensitive: fields
            .iter()
            .filter(|f| f["pii"] == true || f["encrypted"] == true)
            .filter_map(|f| f["name"].as_str().map(str::to_owned))
            .collect(),
        fields: fields
            .iter()
            .filter_map(|f| f["name"].as_str().map(str::to_owned))
            .collect(),
    })
}

fn plain_id(id: &str) -> bool {
    (32..=36).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-')
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

async fn schema(
    State(studio): State<Shared>,
    headers: HeaderMap,
    Path(app): Path<String>,
) -> Response {
    let who = match guard(&studio, &headers, false) {
        Ok(w) => w,
        Err(r) => return r,
    };
    match schema_of(&studio, &who.sid, &app).await {
        Ok(v) => reply(200, &v),
        Err(r) => r,
    }
}

async fn list(
    State(studio): State<Shared>,
    headers: HeaderMap,
    Path((app, entity)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let run = async {
        let who = guard(&studio, &headers, false)?;
        let e = entity_of(&schema_of(&studio, &who.sid, &app).await?, &entity)?;
        // Only the paging, sorting and exact-match filters the page offers. A filter on a
        // personal field is refused: matching would reveal the value.
        let mut q = Vec::new();
        for (k, v) in &params {
            let ok = match k.as_str() {
                "page[size]" => v.parse::<u32>().is_ok_and(|n| (1..=100).contains(&n)),
                "page[after]" => v.bytes().all(|c| c.is_ascii_hexdigit()),
                // Sorting by a personal field would show the order of the hidden values.
                "sort" => v.split(',').all(|p| {
                    let f = p.trim_start_matches('-');
                    e.fields.iter().any(|x| x == f) && !e.sensitive.iter().any(|x| x == f)
                }),
                other => other
                    .strip_prefix("filter[")
                    .and_then(|r| r.strip_suffix(']'))
                    .is_some_and(|f| {
                        e.fields.iter().any(|x| x == f) && !e.sensitive.iter().any(|x| x == f)
                    }),
            };
            if !ok {
                return Err(problem(400, "That filter or sort is not allowed."));
            }
            q.push(format!("{k}={}", encode(v)));
        }
        let query = if q.is_empty() {
            String::new()
        } else {
            format!("?{}", q.join("&"))
        };
        let (code, mut body) = app_call(
            &studio,
            &who.sid,
            &app,
            "GET",
            &format!("/v1/{}{query}", e.path),
            vec![],
            None,
        )
        .await?;
        if code == 200 {
            mask_rows(&mut body, &e.sensitive);
        }
        Ok::<_, Response>(reply(code, &body))
    };
    run.await.unwrap_or_else(|r| r)
}

/// A write may not carry a masked value back: that would overwrite the real one.
fn writable(values: &Value, e: &Entity) -> bool {
    values.as_object().is_some_and(|o| {
        o.iter().all(|(k, v)| {
            e.fields.iter().any(|f| f == k)
                && !(e.sensitive.iter().any(|s| s == k)
                    && v.as_str().is_some_and(|s| s.contains(MASK)))
        })
    })
}

async fn create(
    State(studio): State<Shared>,
    headers: HeaderMap,
    Path((app, entity)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let run = async {
        let who = guard(&studio, &headers, true)?;
        let e = entity_of(&schema_of(&studio, &who.sid, &app).await?, &entity)?;
        let values = serde_json::from_slice::<Value>(&body)
            .ok()
            .map(|v| v["values"].clone())
            .unwrap_or(Value::Null);
        if !writable(&values, &e) {
            return Err(problem(400, "Those values cannot be saved."));
        }
        audit(&studio, &who.label, "create", &format!("{app}/{}", e.path))?;
        let (code, mut out) = app_call(
            &studio,
            &who.sid,
            &app,
            "POST",
            &format!("/v1/{}", e.path),
            vec![("idempotency-key", random_id())],
            Some(values),
        )
        .await?;
        if code == 200 || code == 201 {
            mask_rows(&mut out, &e.sensitive);
        } else {
            let _ = studio.audit.record(
                &who.label,
                "create_refused",
                &format!("{app}/{}:{code}", e.path),
            );
        }
        Ok::<_, Response>(reply(code, &out))
    };
    run.await.unwrap_or_else(|r| r)
}

async fn update(
    State(studio): State<Shared>,
    headers: HeaderMap,
    Path((app, entity, id)): Path<(String, String, String)>,
    body: Bytes,
) -> Response {
    let run = async {
        let who = guard(&studio, &headers, true)?;
        if !plain_id(&id) {
            return Err(problem(400, "Not a record id."));
        }
        let e = entity_of(&schema_of(&studio, &who.sid, &app).await?, &entity)?;
        let v = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
        let (changes, version) = (v["changes"].clone(), v["version"].as_i64());
        let Some(version) = version else {
            return Err(problem(400, "Send the version you read."));
        };
        if !writable(&changes, &e) {
            return Err(problem(400, "Those changes cannot be saved."));
        }
        let fields = changes
            .as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>().join(","))
            .unwrap_or_default();
        audit(
            &studio,
            &who.label,
            "update",
            &format!("{app}/{}/{id}:{fields}", e.path),
        )?;
        let (code, mut out) = app_call(
            &studio,
            &who.sid,
            &app,
            "PATCH",
            &format!("/v1/{}/{id}", e.path),
            vec![("if-match", format!("\"{version}\""))],
            Some(changes),
        )
        .await?;
        if code == 200 {
            mask_rows(&mut out, &e.sensitive);
        } else {
            let _ = studio.audit.record(
                &who.label,
                "update_refused",
                &format!("{app}/{}/{id}:{code}", e.path),
            );
        }
        Ok::<_, Response>(reply(code, &out))
    };
    run.await.unwrap_or_else(|r| r)
}

async fn remove(
    State(studio): State<Shared>,
    headers: HeaderMap,
    Path((app, entity, id)): Path<(String, String, String)>,
) -> Response {
    let run = async {
        let who = guard(&studio, &headers, true)?;
        if !plain_id(&id) {
            return Err(problem(400, "Not a record id."));
        }
        let e = entity_of(&schema_of(&studio, &who.sid, &app).await?, &entity)?;
        audit(
            &studio,
            &who.label,
            "delete",
            &format!("{app}/{}/{id}", e.path),
        )?;
        let (code, out) = app_call(
            &studio,
            &who.sid,
            &app,
            "DELETE",
            &format!("/v1/{}/{id}", e.path),
            vec![],
            None,
        )
        .await?;
        if !(200..300).contains(&code) {
            let _ = studio.audit.record(
                &who.label,
                "delete_refused",
                &format!("{app}/{}/{id}:{code}", e.path),
            );
        }
        Ok::<_, Response>(reply(
            if code == 204 { 200 } else { code },
            &if out.is_null() { json!({}) } else { out },
        ))
    };
    run.await.unwrap_or_else(|r| r)
}

/// Show the personal fields of one record. A separate, recorded step.
async fn reveal(
    State(studio): State<Shared>,
    headers: HeaderMap,
    Path((app, entity, id)): Path<(String, String, String)>,
) -> Response {
    let run = async {
        let who = guard(&studio, &headers, true)?;
        if !plain_id(&id) {
            return Err(problem(400, "Not a record id."));
        }
        let e = entity_of(&schema_of(&studio, &who.sid, &app).await?, &entity)?;
        let shown: Vec<String> = e.sensitive.clone();
        audit(
            &studio,
            &who.label,
            "reveal",
            &format!("{app}/{}/{id}:{}", e.path, shown.join(",")),
        )?;
        let (code, rec) = app_call(
            &studio,
            &who.sid,
            &app,
            "GET",
            &format!("/v1/{}/{id}", e.path),
            vec![],
            None,
        )
        .await?;
        if code != 200 {
            return Err(problem(code, "Not found."));
        }
        let data: serde_json::Map<String, Value> = shown
            .iter()
            .filter_map(|f| rec.get(f).map(|v| (f.clone(), v.clone())))
            .collect();
        Ok::<_, Response>(reply(200, &json!({"data": data})))
    };
    run.await.unwrap_or_else(|r| r)
}
