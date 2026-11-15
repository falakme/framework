//! What Office's web console needs (the pages in `static/`): first-run setup, an overview,
//! lists of people, memberships and the audit log, and settings. Everything but `status`
//! and `setup` needs an administrator.

use super::*;
use crate::{
    oidc::OidcConfig,
    settings::{SavedOidc, Settings, valid_address},
};

const INDEX: &str = include_str!("../../static/index.html");
const SCRIPT: &str = include_str!("../../static/office.js");
const STYLE: &str = include_str!("../../static/office.css");
/// The strictest policy the pages work under: their own script and style, nothing inline,
/// no framing, no other origin.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

pub fn asset(body: &'static str, kind: &'static str) -> Response {
    let mut r = body.into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
    r
}

pub async fn page() -> Response {
    asset(INDEX, "text/html; charset=utf-8")
}
pub async fn script() -> Response {
    asset(SCRIPT, "text/javascript; charset=utf-8")
}
pub async fn style() -> Response {
    asset(STYLE, "text/css; charset=utf-8")
}

/// Headers every Office response carries. `no-store` keeps tokens out of caches.
pub async fn secure_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    for (k, v) in [
        ("content-security-policy", CSP),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("cross-origin-opener-policy", "same-origin"),
    ] {
        h.insert(
            axum::http::HeaderName::from_static(k),
            HeaderValue::from_static(v),
        );
    }
    res
}

fn count(rows: &[Vec<Value>]) -> i64 {
    rows.first().map_or(0, |r| int(r.first()))
}

/// Whether Office needs setting up, and nothing else. Public: the page asks it first.
pub async fn status(State(o): State<Shared>) -> Response {
    json_response(
        StatusCode::OK,
        &json!({
            "setup_needed": o.setup_open(),
            "version": env!("CARGO_PKG_VERSION"),
            "sign_in_with_provider": o.oidc().is_some(),
        }),
        "-",
    )
}

/// First-run setup from a browser: the one-time token from the console, then the first
/// administrator. Works only while nobody has an account.
pub async fn setup(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/setup");
    let run = async {
        let v = body_json(&body)?;
        let given = field(&v, "token")?.to_owned();
        // Taken at once, so two people cannot both use it; given back if setup fails.
        if !o.take_setup_token(&given) {
            // The same words for a wrong token and for setup being closed.
            return Err(Error::forbidden());
        }
        let made = setup_account(&o, &v).await;
        if made.is_err() {
            o.return_setup_token(&given);
        }
        made
    };
    match run.await {
        Ok(v) => json_response(StatusCode::CREATED, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

async fn setup_account(o: &Office, v: &Json) -> Result<Json> {
    {
        let (email, password) = (field(v, "email")?, field(v, "password")?);
        let address = v["issuer"].as_str().filter(|a| !a.is_empty());
        if let Some(a) = address
            && !valid_address(a)
        {
            return Err(Error::invalid_input(
                "invalid_address",
                "The public address is https (or http to this machine) and has no trailing slash.",
            ));
        }
        let id = o
            .users
            .create(email, password, &["office_admin".to_owned()])
            .await?;
        o.audit(&id, "setup", "first administrator").await;
        let mut restart = false;
        if let Some(a) = address
            && a != o.issuer
        {
            o.save_settings(|s| s.issuer = Some(a.to_owned()))?;
            restart = true;
        }
        Ok(json!({"ok": true, "restart_needed": restart}))
    }
}

impl Office {
    /// Change `settings.json`. Without a data directory (tests) nothing is saved.
    pub(crate) fn save_settings(&self, change: impl FnOnce(&mut Settings)) -> Result<()> {
        let Some(dir) = self.data_dir() else {
            return Ok(());
        };
        let mut s =
            Settings::load(dir).map_err(|e| Error::invalid_input("settings_unreadable", e))?;
        change(&mut s);
        s.save(dir)
            .map_err(|e| Error::invalid_input("settings_not_saved", e))
    }

    fn saved_settings(&self) -> Settings {
        self.data_dir()
            .and_then(|d| Settings::load(d).ok())
            .unwrap_or_default()
    }
}

pub async fn overview(State(o): State<Shared>, headers: HeaderMap) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/overview");
    let run = async {
        o.admin(&headers)?;
        let users = count(
            &o.db
                .rows("SELECT COUNT(*) FROM falak_auth_users", vec![])
                .await?,
        );
        let apps = count(
            &o.db
                .rows("SELECT COUNT(*) FROM office_apps", vec![])
                .await?,
        );
        let members = count(
            &o.db
                .rows("SELECT COUNT(*) FROM office_memberships", vec![])
                .await?,
        );
        let saved = o.saved_settings();
        let restart = saved.issuer.as_deref().is_some_and(|a| a != o.issuer);
        let oidc = o.oidc().map(|x| {
            json!({
                "issuer": x.config.issuer, "audience": x.config.audience,
                "auto_create_domains": x.config.auto_create_domains,
            })
        });
        Ok::<_, Error>(json!({
            "issuer": o.issuer,
            "saved_issuer": saved.issuer,
            "restart_needed": restart,
            "jwks_url": format!("{}/.well-known/jwks.json", o.issuer),
            "version": env!("CARGO_PKG_VERSION"),
            "counts": {"people": users, "apps": apps, "memberships": members},
            "signing_keys": o.key_count(),
            "feed_version": o.feed_version().await?,
            "oidc": oidc,
            "can_save": o.data_dir().is_some(),
        }))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

pub async fn people(State(o): State<Shared>, headers: HeaderMap) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/users");
    let run = async {
        o.admin(&headers)?;
        let rows =
            o.db.rows(
                "SELECT id, email, roles, created_at FROM falak_auth_users ORDER BY email LIMIT 500",
                vec![],
            )
            .await?;
        Ok::<_, Error>(json!({"data": rows.iter().map(|r| json!({
            "id": text(r.first()), "email": text(r.get(1)),
            "roles": text(r.get(2)).split(',').filter(|x| !x.is_empty()).collect::<Vec<_>>(),
            "created_at": int(r.get(3)),
        })).collect::<Vec<_>>()}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

pub async fn memberships(State(o): State<Shared>, headers: HeaderMap) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/memberships");
    let run = async {
        o.admin(&headers)?;
        let rows =
            o.db.rows(
                "SELECT m.user_id, u.email, m.app, m.tenant, m.roles FROM office_memberships m \
                 JOIN falak_auth_users u ON u.id = m.user_id ORDER BY m.app, u.email LIMIT 1000",
                vec![],
            )
            .await?;
        Ok::<_, Error>(json!({"data": rows.iter().map(|r| json!({
            "user_id": text(r.first()), "email": text(r.get(1)), "app": text(r.get(2)),
            "tenant": text(r.get(3)),
            "roles": text(r.get(4)).split(',').filter(|x| !x.is_empty()).collect::<Vec<_>>(),
        })).collect::<Vec<_>>()}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

pub async fn remove_membership(
    State(o): State<Shared>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/memberships");
    let run = async {
        let admin = o.admin(&headers)?;
        let v = body_json(&body)?;
        let (user, app) = (field(&v, "user_id")?, field(&v, "app")?);
        let n =
            o.db.run(
                "DELETE FROM office_memberships WHERE user_id = ? AND app = ?",
                vec![t(user), t(app)],
            )
            .await?;
        o.audit(
            &admin.subject,
            "membership_removed",
            &format!("{user}:{app}"),
        )
        .await;
        Ok::<_, Error>(json!({"removed": n}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

pub async fn audit_log(State(o): State<Shared>, headers: HeaderMap) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/audit");
    let run = async {
        o.admin(&headers)?;
        let rows =
            o.db.rows(
                "SELECT seq, at, actor, action, detail FROM office_audit ORDER BY seq DESC LIMIT 100",
                vec![],
            )
            .await?;
        Ok::<_, Error>(json!({"data": rows.iter().map(|r| json!({
            "seq": int(r.first()), "at": int(r.get(1)), "actor": text(r.get(2)),
            "action": text(r.get(3)), "detail": text(r.get(4)),
        })).collect::<Vec<_>>()}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

/// Turn sign-in through an identity provider on, change it, or off. Applies at once and
/// is saved. Reports whether the provider answered, so a typo shows up here.
pub async fn set_oidc(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/settings/oidc");
    let run = async {
        let admin = o.admin(&headers)?;
        let v = body_json(&body)?;
        if v["enabled"] == false {
            o.set_oidc(None);
            o.save_settings(|s| s.oidc = None)?;
            o.audit(&admin.subject, "oidc_off", "").await;
            return Ok(json!({"enabled": false}));
        }
        let saved = SavedOidc {
            issuer: field(&v, "issuer")?.trim().to_owned(),
            audience: field(&v, "audience")?.trim().to_owned(),
            auto_create_domains: v["auto_create_domains"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .map(|d| d.trim().to_lowercase())
                        .filter(|d| !d.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        };
        let cfg: OidcConfig = saved.config();
        cfg.validate()
            .map_err(|e| Error::invalid_input("invalid_oidc", e))?;
        o.set_oidc(Some(cfg));
        o.save_settings(|s| s.oidc = Some(saved))?;
        o.audit(
            &admin.subject,
            "oidc_on",
            &o.oidc()
                .map(|x| x.config.issuer.clone())
                .unwrap_or_default(),
        )
        .await;
        // Does the provider answer, and does it name itself as configured?
        let check = o.oidc();
        let reach = tokio::task::spawn_blocking(move || {
            check.map_or(Err("off".to_owned()), |c| c.refresh_blocking(now()))
        })
        .await
        .unwrap_or_else(|_| Err("the check did not finish".into()));
        Ok::<_, Error>(json!({
            "enabled": true,
            "reachable": reach.is_ok(),
            "problem": reach.err(),
        }))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

/// Save the public address. It is part of every token, so it applies at the next start.
pub async fn set_address(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/settings/address");
    let run = async {
        let admin = o.admin(&headers)?;
        let v = body_json(&body)?;
        let address = field(&v, "issuer")?.trim().to_owned();
        if !valid_address(&address) {
            return Err(Error::invalid_input(
                "invalid_address",
                "The public address is https (or http to this machine) and has no trailing slash.",
            ));
        }
        if o.data_dir().is_none() {
            return Err(Error::invalid_input(
                "cannot_save",
                "This Office keeps no settings file.",
            ));
        }
        o.save_settings(|s| s.issuer = Some(address.clone()))?;
        o.audit(&admin.subject, "address_saved", &address).await;
        Ok::<_, Error>(json!({"issuer": address, "restart_needed": address != o.issuer}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

const KINDS: [&str; 4] = ["sign_in", "sign_in_provider", "sign_in_failed", "app_token"];

/// Numbers for the overview: what happened each day in a window (7 to 90 days), the
/// window before it for comparison, and what each app has been doing.
pub async fn stats(
    State(o): State<Shared>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/stats");
    let run = async {
        o.admin(&headers)?;
        let days: i64 = q
            .get("days")
            .and_then(|d| d.parse().ok())
            .filter(|d| (7..=90).contains(d))
            .unwrap_or(14);
        let today = now() / 86_400;
        let first = today - days + 1;
        let before = first - days;
        let rows =
            o.db.rows(
                "SELECT day, kind, app, n FROM office_stats WHERE day >= ?",
                vec![Value::Int64(before)],
            )
            .await?;
        let width = usize::try_from(days).unwrap_or(14);
        let mut series: std::collections::BTreeMap<&str, Vec<i64>> =
            KINDS.iter().map(|k| (*k, vec![0; width])).collect();
        let mut previous: std::collections::BTreeMap<&str, i64> =
            KINDS.iter().map(|k| (*k, 0)).collect();
        let mut apps: std::collections::BTreeMap<String, (i64, i64)> =
            std::collections::BTreeMap::new();
        for r in &rows {
            let (day, kind, app, n) = (
                int(r.first()),
                text(r.get(1)),
                text(r.get(2)),
                int(r.get(3)),
            );
            let Some(k) = KINDS.iter().find(|k| **k == kind) else {
                if kind == "app_sync" && day >= first {
                    apps.entry(app).or_default().1 += n;
                }
                continue;
            };
            if day >= first {
                if let Some(slot) = usize::try_from(day - first)
                    .ok()
                    .and_then(|i| series.get_mut(k)?.get_mut(i))
                {
                    *slot += n;
                }
                if *k == "app_token" {
                    apps.entry(app).or_default().0 += n;
                }
            } else {
                *previous.entry(k).or_default() += n;
            }
        }
        let last_seen =
            o.db.rows(
                "SELECT app, MAX(day) FROM office_stats WHERE kind = 'app_sync' GROUP BY app",
                vec![],
            )
            .await?;
        let seen: std::collections::HashMap<String, i64> = last_seen
            .iter()
            .map(|r| (text(r.first()), int(r.get(1))))
            .collect();
        let listed =
            o.db.rows(
                "SELECT name, tier, status FROM office_apps ORDER BY name",
                vec![],
            )
            .await?;
        let new_people = count(
            &o.db
                .rows(
                    "SELECT COUNT(*) FROM falak_auth_users WHERE created_at >= ?",
                    vec![Value::Int64(now() - 7 * 86_400)],
                )
                .await?,
        );
        let totals: std::collections::BTreeMap<&str, i64> =
            series.iter().map(|(k, v)| (*k, v.iter().sum())).collect();
        Ok::<_, Error>(json!({
            "days": days,
            "first_day": first,
            "series": series,
            "totals": totals,
            "previous": previous,
            "new_people_7d": new_people,
            "apps": listed.iter().map(|r| {
                let name = text(r.first());
                let (tokens, syncs) = apps.get(&name).copied().unwrap_or_default();
                json!({
                    "name": name, "tier": int(r.get(1)), "status": text(r.get(2)),
                    "tokens": tokens, "syncs": syncs, "last_seen_day": seen.get(&name),
                })
            }).collect::<Vec<_>>(),
        }))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}
