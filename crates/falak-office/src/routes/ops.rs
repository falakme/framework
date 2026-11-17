//! Operations endpoints (Phase 6): health and SLOs, audit anchoring, vault rotation,
//! app-credential rotation and break-glass access.

use std::time::Instant;

use axum::{
    Router,
    body::Bytes,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::Engine as _;
use falak_auth::token::Claims;
use falak_contracts::{Error, driver::Value};
use falak_runtime_native::context::extract_request_id;
use serde_json::{Value as Json, json};

use super::{Shared, body_json, fail, field, json_response, new_id, sha256_hex, valid_app};
use crate::{
    ENROLLMENT_SECS, conflict,
    db::{int, t, text},
    now, observe, vault,
};

/// A break-glass request can be approved and claimed for this long after it is made.
pub const BREAKGLASS_REQUEST_SECS: i64 = 30 * 60;
pub const BREAKGLASS_MAX_MINUTES: i64 = 60;
pub const BREAKGLASS_TIER3_MAX_MINUTES: i64 = 30;
pub const BREAKGLASS_ROLE: &str = "break_glass";

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/v1/_office/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/_office/slo", get(slo))
        .route("/v1/_office/audit/anchor", post(anchor))
        .route("/v1/_office/audit/verify", get(verify))
        .route(
            "/v1/_office/apps/{name}/rotate-credential",
            post(rotate_credential),
        )
        .route("/v1/_office/vault/dek", post(app_dek))
        .route(
            "/v1/_office/vault/deks/{tenant}",
            get(list_deks).delete(destroy_deks),
        )
        .route("/v1/_office/vault/deks/{tenant}/rotate", post(rotate_dek))
        .route(
            "/v1/_office/vault/deks/{tenant}/retire-old",
            post(retire_old_deks),
        )
        .route("/v1/_office/vault/kek/rotate", post(rotate_kek))
        .route("/v1/_office/breakglass", get(bg_list).post(bg_request))
        .route("/v1/_office/breakglass/{id}/approve", post(bg_approve))
        .route("/v1/_office/breakglass/{id}/claim", post(bg_claim))
        .route("/v1/_office/breakglass/{id}", delete(bg_end))
}

/// Counts every response for the availability and latency objectives.
pub async fn record(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let res = next.run(req).await;
    observe::metrics().record(
        res.status().as_u16(),
        u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
    );
    res
}

macro_rules! admin_route {
    ($o:ident, $headers:ident, $inst:expr, $admin:ident, $body:block) => {{
        let (rid, inst) = (extract_request_id(&$headers), $inst);
        let run = async {
            let $admin = $o.admin(&$headers).await?;
            $body
        };
        match run.await {
            Ok((status, v)) => json_response(status, &v, &rid),
            Err(e) => fail(&e, &inst, &rid),
        }
    }};
}

async fn health(State(o): State<Shared>) -> Response {
    let db = o.db.rows("SELECT 1", vec![]).await.is_ok();
    let body = json!({
        "status": if db { "ok" } else { "degraded" },
        "database": db,
        "active_kid": o.active_kid(),
        "keys": o.key_count(),
    });
    json_response(
        if db {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        &body,
        "health",
    )
}

/// Prometheus scrape. Off (404) unless `FALAK_METRICS_TOKEN` is set and not empty; then
/// it needs that token. The tokens are compared as SHA-256 digests.
async fn metrics(headers: HeaderMap) -> Response {
    let want = match std::env::var("FALAK_METRICS_TOKEN") {
        Ok(w) if !w.is_empty() => w,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if sha256_hex(given.as_bytes()) != sha256_hex(want.as_bytes()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        observe::metrics().prometheus(),
    )
        .into_response()
}

async fn slo(State(o): State<Shared>, headers: HeaderMap) -> Response {
    admin_route!(o, headers, "/v1/_office/slo".to_owned(), _admin, {
        let statuses = observe::evaluate(&o).await;
        Ok::<_, Error>((StatusCode::OK, json!({"data": statuses})))
    })
}

async fn anchor(State(o): State<Shared>, headers: HeaderMap) -> Response {
    admin_route!(o, headers, "/v1/_office/audit/anchor".to_owned(), admin, {
        o.audit(&admin.subject, "audit_anchor_requested", "").await;
        let a = o.anchor_now().await?;
        Ok::<_, Error>((
            StatusCode::OK,
            json!({"anchored": a.as_ref().map(|a| json!({"seq": a.seq, "hash": a.hash, "at": a.at}))}),
        ))
    })
}

async fn verify(State(o): State<Shared>, headers: HeaderMap) -> Response {
    admin_route!(o, headers, "/v1/_office/audit/verify".to_owned(), _admin, {
        let r = o.verify_audit(None).await?;
        Ok::<_, Error>((
            if r.ok() {
                StatusCode::OK
            } else {
                StatusCode::CONFLICT
            },
            serde_json::to_value(&r).unwrap_or(Json::Null),
        ))
    })
}

/// Replace a compromised app credential: the app's key stops working at once, its
/// passport is revoked, and a one-time enrollment token is issued so the real app can
/// enroll again with a new key.
async fn rotate_credential(
    State(o): State<Shared>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    admin_route!(
        o,
        headers,
        format!("/v1/_office/apps/{name}/rotate-credential"),
        admin,
        {
            let row =
                o.db.rows(
                    "SELECT passport_jti, tier, capabilities FROM office_apps WHERE name = ?",
                    vec![t(&name)],
                )
                .await?;
            let Some(r) = row.first() else {
                return Err(Error::not_found());
            };
            let (jti, tier, caps) = (text(r.first()), int(r.get(1)), text(r.get(2)));
            let token = super::B64.encode(super::random(32));
            let expires = now() + ENROLLMENT_SECS;
            // The old key is gone and the new enrollment exists, or neither.
            o.db.batch(vec![
                o.db.stmt("DELETE FROM office_apps WHERE name = ?", vec![t(&name)]),
                o.db.stmt(
                    "INSERT INTO office_enrollments (token_hash, app, tier, capabilities, expires_at) VALUES (?, ?, ?, ?, ?)",
                    vec![
                        t(&sha256_hex(token.as_bytes())),
                        t(&name),
                        Value::Int64(tier),
                        t(&caps),
                        Value::Int64(expires),
                    ],
                ),
            ])
            .await?;
            let version = o.add_revocation("passport", &jti).await?;
            o.audit(&admin.subject, "app_credential_rotated", &name)
                .await;
            o.tally("credential_rotated", &name).await;
            Ok::<_, Error>((
                StatusCode::OK,
                json!({"app": name, "enrollment_token": token, "expires_at": expires, "revocation_version": version}),
            ))
        }
    )
}

// ---------------------------------------------------------------- vault

/// The vault key for an app's tenant. An app can only reach its own.
fn dek_id(app: &str, tenant: &str) -> String {
    format!("{app}:{tenant}")
}

fn valid_tenant(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 100
        && t.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b':' | b'.'))
}

/// An enrolled app asks for its tenant's data key (signed request, like the feed).
async fn app_dek(State(o): State<Shared>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rid = extract_request_id(&parts.headers);
    let inst = "/v1/_office/vault/dek";
    let bytes = axum::body::to_bytes(body, 4096).await.unwrap_or_default();
    let run = async {
        let who = o
            .app_request(&parts.method, &parts.uri, &parts.headers, &bytes)
            .await?;
        let v = body_json(&Bytes::from(bytes.to_vec()))?;
        let tenant = field(&v, "tenant")?;
        if !valid_tenant(tenant) {
            return Err(Error::invalid_input("invalid_tenant", "Not a tenant id."));
        }
        let id = dek_id(&who.name, tenant);
        let kek = o.kek.read().unwrap_or_else(|p| p.into_inner()).clone();
        let version = v["version"].as_i64();
        // First use creates the tenant's first key.
        let opened = match vault::open_dek(&o.db, &kek, &id, version).await? {
            Some(k) => k,
            None if version.is_none() => vault::rotate_dek(&o.db, &kek, &id).await?,
            None => return Err(Error::not_found()),
        };
        o.tally("dek_issued", &who.name).await;
        Ok::<_, Error>(json!({"version": opened.0, "key": hex::encode(opened.1)}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

async fn list_deks(
    State(o): State<Shared>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Response {
    admin_route!(
        o,
        headers,
        format!("/v1/_office/vault/deks/{tenant}"),
        _a,
        {
            let v = vault::list_deks(&o.db, &tenant).await?;
            Ok::<_, Error>((
                StatusCode::OK,
                json!({"data": v.iter().map(|d| json!({
                "version": d.version, "status": d.status, "kek": d.kek, "created_at": d.created_at,
            })).collect::<Vec<_>>()}),
            ))
        }
    )
}

async fn rotate_dek(
    State(o): State<Shared>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Response {
    admin_route!(
        o,
        headers,
        format!("/v1/_office/vault/deks/{tenant}/rotate"),
        admin,
        {
            if !valid_tenant(&tenant) {
                return Err(Error::invalid_input("invalid_tenant", "Not a tenant id."));
            }
            let kek = o.kek.read().unwrap_or_else(|p| p.into_inner()).clone();
            // The plaintext is not returned: apps fetch it signed, over `/vault/dek`.
            let (version, _) = vault::rotate_dek(&o.db, &kek, &tenant).await?;
            o.audit(
                &admin.subject,
                "dek_rotated",
                &format!("{tenant}@{version}"),
            )
            .await;
            Ok::<_, Error>((
                StatusCode::OK,
                json!({"tenant": tenant, "version": version}),
            ))
        }
    )
}

async fn retire_old_deks(
    State(o): State<Shared>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Response {
    admin_route!(
        o,
        headers,
        format!("/v1/_office/vault/deks/{tenant}/retire-old"),
        admin,
        {
            let n = vault::retire_old(&o.db, &tenant).await?;
            o.audit(&admin.subject, "deks_retired", &tenant).await;
            Ok::<_, Error>((StatusCode::OK, json!({"removed": n})))
        }
    )
}

async fn destroy_deks(
    State(o): State<Shared>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Response {
    admin_route!(
        o,
        headers,
        format!("/v1/_office/vault/deks/{tenant}"),
        admin,
        {
            let n = vault::destroy(&o.db, &tenant).await?;
            o.audit(&admin.subject, "deks_destroyed", &tenant).await;
            Ok::<_, Error>((StatusCode::OK, json!({"removed": n})))
        }
    )
}

async fn rotate_kek(State(o): State<Shared>, headers: HeaderMap) -> Response {
    admin_route!(
        o,
        headers,
        "/v1/_office/vault/kek/rotate".to_owned(),
        admin,
        {
            let dir = o
            .data_dir()
            .map(std::path::Path::to_path_buf)
            .filter(|_| {
                !o.kek
                    .read()
                    .unwrap_or_else(|p| p.into_inner())
                    .is_env()
            })
            .ok_or_else(|| {
                Error::unsupported(
                    "kek_external",
                    "The KEK comes from the environment: rotate it in the secret manager, restart with FALAK_VAULT_KEK_PREVIOUS unset, then re-wrap.",
                )
            })?;
            let mut kek = o.kek.read().unwrap_or_else(|p| p.into_inner()).clone();
            let (new, n) = vault::rotate_kek(&o.db, &mut kek).await?;
            // Both KEKs are live until the swap, so nothing in flight fails to unwrap.
            kek.save(&dir).map_err(Error::internal)?;
            *o.kek.write().unwrap_or_else(|p| p.into_inner()) = kek.clone();
            kek.drop_old();
            kek.save(&dir).map_err(Error::internal)?;
            *o.kek.write().unwrap_or_else(|p| p.into_inner()) = kek;
            o.audit(
                &admin.subject,
                "kek_rotated",
                &format!("{new}: {n} data keys"),
            )
            .await;
            Ok::<_, Error>((StatusCode::OK, json!({"kek": new, "rewrapped": n})))
        }
    )
}

// ---------------------------------------------------------------- break glass

async fn bg_request(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    admin_route!(o, headers, "/v1/_office/breakglass".to_owned(), admin, {
        let v = body_json(&body)?;
        let app = field(&v, "app")?;
        let reason = field(&v, "reason")?.trim();
        if !valid_app(app) {
            return Err(Error::invalid_input("invalid_app", "Not an app name."));
        }
        if !(10..=500).contains(&reason.chars().count()) {
            return Err(Error::invalid_input(
                "reason_required",
                "Say why, in at least 10 characters: it goes in the audit log and the alert.",
            ));
        }
        let Some((row, _)) = o.app(app).await? else {
            return Err(Error::not_found());
        };
        let tier = row.tier.max(v["tier"].as_i64().unwrap_or(1).clamp(1, 3));
        let cap = if tier == 3 {
            BREAKGLASS_TIER3_MAX_MINUTES
        } else {
            BREAKGLASS_MAX_MINUTES
        };
        let minutes = v["minutes"].as_i64().unwrap_or(15);
        if !(1..=cap).contains(&minutes) {
            return Err(Error::invalid_input(
                "invalid_minutes",
                format!("Break-glass access lasts 1 to {cap} minutes for a tier {tier} app."),
            ));
        }
        let id = new_id();
        // Tiers 1 and 2: the requester alone. Tier 3: a second administrator approves.
        let status = if tier == 3 { "pending" } else { "approved" };
        o.db.run(
            "INSERT INTO office_breakglass (id, app, tier, reason, requester, status, minutes, requested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                t(&id),
                t(app),
                Value::Int64(tier),
                t(reason),
                t(&admin.subject),
                t(status),
                Value::Int64(minutes),
                Value::Int64(now()),
            ],
        )
        .await?;
        o.audit(
            &admin.subject,
            "breakglass_requested",
            &format!("{id} app={app} tier={tier} minutes={minutes} reason={reason}"),
        )
        .await;
        o.alert(
            "page",
            "breakglass_requested",
            &format!(
                "{} asked for emergency access to {app} (tier {tier}, {minutes} min): {reason}",
                admin.subject
            ),
        )
        .await;
        Ok::<_, Error>((
            StatusCode::CREATED,
            json!({"id": id, "app": app, "tier": tier, "status": status, "minutes": minutes,
                   "needs_second_approver": tier == 3}),
        ))
    })
}

async fn bg_list(State(o): State<Shared>, headers: HeaderMap) -> Response {
    admin_route!(o, headers, "/v1/_office/breakglass".to_owned(), _a, {
        let rows =
            o.db.rows(
                "SELECT id, app, tier, status, requester, approver, minutes, requested_at, expires_at, reason FROM office_breakglass ORDER BY requested_at DESC LIMIT 100",
                vec![],
            )
            .await?;
        Ok::<_, Error>((
            StatusCode::OK,
            json!({"data": rows.iter().map(|r| {
                let status = text(r.get(3));
                let exp = int(r.get(8));
                json!({
                    "id": text(r.first()), "app": text(r.get(1)), "tier": int(r.get(2)),
                    "status": if status == "claimed" && exp > 0 && exp < now() { "expired".to_owned() } else { status },
                    "requester": text(r.get(4)),
                    "approver": match r.get(5) { Some(Value::Text(s)) => Json::from(s.clone()), _ => Json::Null },
                    "minutes": int(r.get(6)), "requested_at": int(r.get(7)),
                    "expires_at": exp, "reason": text(r.get(9)),
                })
            }).collect::<Vec<_>>()}),
        ))
    })
}

async fn bg_approve(
    State(o): State<Shared>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    admin_route!(
        o,
        headers,
        format!("/v1/_office/breakglass/{id}/approve"),
        admin,
        {
            // The approver must be someone other than the requester.
            let n =
                o.db.run(
                    "UPDATE office_breakglass SET status = 'approved', approver = ?, approved_at = ? WHERE id = ? AND status = 'pending' AND requester <> ? AND requested_at >= ?",
                    vec![
                        t(&admin.subject),
                        Value::Int64(now()),
                        t(&id),
                        t(&admin.subject),
                        Value::Int64(now() - BREAKGLASS_REQUEST_SECS),
                    ],
                )
                .await?;
            if n != 1 {
                return Err(conflict(
                    "not_approvable",
                    "That request is not waiting for you: it is already decided, it expired, or you made it.",
                ));
            }
            o.audit(&admin.subject, "breakglass_approved", &id).await;
            o.alert(
                "page",
                "breakglass_approved",
                &format!("{} approved {id}", admin.subject),
            )
            .await;
            Ok::<_, Error>((StatusCode::OK, json!({"id": id, "status": "approved"})))
        }
    )
}

/// The requester collects the token. It carries the role `break_glass`, is signed for the
/// app, and lives for the minutes asked, no longer.
async fn bg_claim(State(o): State<Shared>, Path(id): Path<String>, headers: HeaderMap) -> Response {
    admin_route!(
        o,
        headers,
        format!("/v1/_office/breakglass/{id}/claim"),
        admin,
        {
            let rows =
                o.db.rows(
                    "SELECT app, minutes, tier FROM office_breakglass WHERE id = ? AND requester = ? AND status = 'approved' AND requested_at >= ?",
                    vec![
                        t(&id),
                        t(&admin.subject),
                        Value::Int64(now() - BREAKGLASS_REQUEST_SECS),
                    ],
                )
                .await?;
            let Some(r) = rows.first() else {
                return Err(conflict(
                    "not_claimable",
                    "Nothing to claim: it is not approved yet, it expired, it was already claimed, or it is not yours.",
                ));
            };
            let (app, minutes) = (text(r.first()), int(r.get(1)));
            let issued_at = now();
            let expires_at = issued_at + minutes * 60;
            let jti = new_id();
            let n =
                o.db.run(
                    "UPDATE office_breakglass SET status = 'claimed', claimed_at = ?, expires_at = ?, jti = ? WHERE id = ? AND status = 'approved'",
                    vec![
                        Value::Int64(issued_at),
                        Value::Int64(expires_at),
                        t(&jti),
                        t(&id),
                    ],
                )
                .await?;
            if n != 1 {
                return Err(conflict("not_claimable", "Already claimed."));
            }
            let access = o.issue(
                &app,
                &Claims {
                    subject: admin.subject.clone(),
                    tenant: None,
                    roles: vec![BREAKGLASS_ROLE.to_owned()],
                    issued_at,
                    expires_at,
                    token_id: jti.clone(),
                },
            );
            o.audit(
                &admin.subject,
                "breakglass_used",
                &format!("{id} app={app} until={expires_at}"),
            )
            .await;
            o.alert(
                "page",
                "breakglass_used",
                &format!(
                    "{} holds emergency access to {app} until {expires_at}",
                    admin.subject
                ),
            )
            .await;
            Ok::<_, Error>((
                StatusCode::OK,
                json!({"access_token": access, "token_type": "Bearer", "app": app,
                       "expires_in": minutes * 60, "expires_at": expires_at}),
            ))
        }
    )
}

/// End access early: the token is revoked in the feed, so apps stop honouring it.
async fn bg_end(State(o): State<Shared>, Path(id): Path<String>, headers: HeaderMap) -> Response {
    admin_route!(o, headers, format!("/v1/_office/breakglass/{id}"), admin, {
        let rows =
            o.db.rows(
                "SELECT jti FROM office_breakglass WHERE id = ? AND status = 'claimed'",
                vec![t(&id)],
            )
            .await?;
        let Some(r) = rows.first() else {
            return Err(Error::not_found());
        };
        o.add_revocation("token", &text(r.first())).await?;
        o.db.run(
            "UPDATE office_breakglass SET status = 'ended', expires_at = ? WHERE id = ?",
            vec![Value::Int64(now()), t(&id)],
        )
        .await?;
        o.audit(&admin.subject, "breakglass_ended", &id).await;
        Ok::<_, Error>((StatusCode::OK, json!({"id": id, "status": "ended"})))
    })
}
