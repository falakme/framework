//! Phase 6 operations, in process: break-glass, vault rotation, credential rotation,
//! audit anchoring, keys shared between instances, and the objectives.
#![allow(dead_code)]

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use falak_auth::{
    keys::LocalKeys,
    token::{TokenConfig, Verifier},
};
use falak_driver_sqlite::SqliteDriver;
use falak_federation::{AppKey, enroll_request, now, random_nonce, request_headers};
use falak_office::{Office, db::Db, router, users::open_sqlite};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const PASSWORD: &str = "correct horse battery staple 42";

struct Env {
    app: Router,
    office: Arc<Office>,
    admin: String,
}

async fn env() -> Env {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let session_config = TokenConfig {
        issuer: "http://office.test#session".into(),
        audience: "office".into(),
        leeway_secs: 30,
    };
    let dir = std::env::temp_dir().join(format!(
        "falak-office-test-{}-{}",
        std::process::id(),
        random_nonce().replace(['-', '_'], "x")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let session_path = dir.join("session.json");
    let keys_path = dir.join("keys.json");
    let session_keys = LocalKeys::load_or_create(&session_path).unwrap();
    let mut verifier = Verifier::new(session_config.clone());
    LocalKeys::load_or_create(&session_path)
        .unwrap()
        .trust_all(&mut verifier);
    let (login, users) = open_sqlite(driver.clone(), session_keys, session_config);
    let db = Db::new(Arc::new(driver));
    db.migrate().await.unwrap();
    users.migrate().await.unwrap();
    let office = Arc::new(Office::new(
        "http://office.test".into(),
        db,
        LocalKeys::load_or_create(&keys_path).unwrap(),
        Some(keys_path),
        verifier,
        users.clone(),
    ));
    users
        .create("admin@example.com", PASSWORD, &["office_admin".to_owned()])
        .await
        .unwrap();
    let app = router(office.clone(), login);
    let mut e = Env {
        app,
        office,
        admin: String::new(),
    };
    e.admin = e.login("admin@example.com").await;
    e
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn json_req(method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
        .unwrap()
}

impl Env {
    async fn login(&self, email: &str) -> String {
        let (s, v) = send(
            &self.app,
            json_req(
                "POST",
                "/v1/auth/login",
                None,
                Some(json!({"email": email, "password": PASSWORD})),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v["access_token"].as_str().unwrap().to_owned()
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        send(&self.app, json_req(method, uri, token, body)).await
    }

    /// A request signed as an enrolled app.
    async fn as_app(&self, key: &AppKey, app: &str, uri: &str) -> (StatusCode, Value) {
        self.as_app_at(key, app, uri, now(), &random_nonce()).await
    }

    async fn as_app_at(
        &self,
        key: &AppKey,
        app: &str,
        uri: &str,
        at: i64,
        nonce: &str,
    ) -> (StatusCode, Value) {
        let mut b = Request::builder().method("GET").uri(uri);
        for (k, v) in request_headers(key, app, "GET", uri, b"", at, nonce) {
            b = b.header(k, v);
        }
        send(&self.app, b.body(Body::empty()).unwrap()).await
    }

    async fn enroll(&self, app: &str, tier: i64) -> (AppKey, Value) {
        let (s, v) = self
            .call(
                "POST",
                "/v1/_office/enrollments",
                Some(&self.admin),
                Some(json!({"app": app, "tier": tier})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        let key = AppKey::generate();
        let body = enroll_request(
            &key,
            v["token"].as_str().unwrap(),
            app,
            now(),
            &random_nonce(),
        );
        let (s, passport) = self
            .call("POST", "/v1/_office/enroll", None, Some(body))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{passport}");
        (key, passport)
    }

    async fn person(&self, email: &str, app: &str, tenant: &str, roles: &[&str]) -> String {
        let (s, _) = self
            .call(
                "POST",
                "/v1/_office/users",
                Some(&self.admin),
                Some(json!({"email": email, "password": PASSWORD})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED);
        let (s, v) = self
            .call(
                "PUT",
                "/v1/_office/memberships",
                Some(&self.admin),
                Some(json!({"email": email, "app": app, "tenant": tenant, "roles": roles})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        self.login(email).await
    }

    fn verifier(&self, audience: &str) -> Verifier {
        let jwks = self.office.jwks();
        let mut v = Verifier::new(TokenConfig {
            issuer: "http://office.test".into(),
            audience: audience.into(),
            leeway_secs: 0,
        });
        for k in jwks["keys"].as_array().unwrap() {
            let x = k["x"].as_str().unwrap();
            let bytes = base64_url(x);
            v.add_key(
                k["kid"].as_str().unwrap(),
                ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap(),
            );
        }
        v
    }
}

fn base64_url(s: &str) -> [u8; 32] {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(s).unwrap().try_into().unwrap()
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(s).unwrap()
}

use falak_contracts::driver::Value as Db_Value;
use falak_office::{observe, vault};

fn dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "falak-ops-{}-{}",
        std::process::id(),
        random_nonce().replace(['-', '_'], "x")
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test]
async fn break_glass_is_timed_reasoned_alerted_and_tier_3_needs_a_second_person() {
    let e = env().await;
    e.enroll("notebook", 1).await;
    let bg = |body: Value| json_req("POST", "/v1/_office/breakglass", Some(&e.admin), Some(body));

    // A reason is required, and a sane duration.
    let (s, _) = send(&e.app, bg(json!({"app": "notebook", "reason": "x"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = send(
        &e.app,
        bg(json!({"app": "notebook", "reason": "database is on fire", "minutes": 600})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Tier 1: the requester claims at once; the token is for the app, short, and marked.
    let (s, v) = send(
        &e.app,
        bg(json!({"app": "notebook", "reason": "database is on fire", "minutes": 10})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["status"], "approved");
    let id = v["id"].as_str().unwrap().to_owned();
    let (s, v) = e
        .call(
            "POST",
            &format!("/v1/_office/breakglass/{id}/claim"),
            Some(&e.admin),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["expires_in"], 600);
    let p = e
        .verifier("notebook")
        .verify(v["access_token"].as_str().unwrap(), now())
        .unwrap();
    assert_eq!(p.roles, ["break_glass"]);
    // Only once.
    let (s, _) = e
        .call(
            "POST",
            &format!("/v1/_office/breakglass/{id}/claim"),
            Some(&e.admin),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Tier 3: nobody, including the requester, gets a token until someone else approves.
    let (s, v) = send(
        &e.app,
        bg(json!({"app": "notebook", "tier": 3, "reason": "ledger is stuck, auditors waiting", "minutes": 20})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["status"], "pending");
    let id = v["id"].as_str().unwrap().to_owned();
    let claim = format!("/v1/_office/breakglass/{id}/claim");
    let approve = format!("/v1/_office/breakglass/{id}/approve");
    assert_eq!(
        e.call("POST", &claim, Some(&e.admin), None).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        e.call("POST", &approve, Some(&e.admin), None).await.0,
        StatusCode::CONFLICT,
        "self approval"
    );
    let (s, _) = send(
        &e.app,
        bg(json!({"app": "notebook", "tier": 3, "reason": "ledger is stuck, auditors waiting", "minutes": 45})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "tier 3 is capped at 30 minutes");

    e.office
        .users
        .create("second@example.com", PASSWORD, &["office_admin".to_owned()])
        .await
        .unwrap();
    let second = e.login("second@example.com").await;
    assert_eq!(
        e.call("POST", &approve, Some(&second), None).await.0,
        StatusCode::OK
    );
    // The approver cannot take the requester's token.
    assert_eq!(
        e.call("POST", &claim, Some(&second), None).await.0,
        StatusCode::CONFLICT
    );
    let (s, v) = e.call("POST", &claim, Some(&e.admin), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["expires_in"], 1200);

    // It can be ended early: the token goes in the revocation feed.
    let before = e
        .office
        .db
        .rows("SELECT COUNT(*) FROM office_revocations", vec![])
        .await
        .unwrap();
    let (s, _) = e
        .call(
            "DELETE",
            &format!("/v1/_office/breakglass/{id}"),
            Some(&e.admin),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let after = e
        .office
        .db
        .rows("SELECT COUNT(*) FROM office_revocations", vec![])
        .await
        .unwrap();
    assert_ne!(before, after);

    // Every step is in the audit chain, and the chain verifies.
    let (s, v) = e
        .call("GET", "/v1/_office/audit", Some(&e.admin), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let text = v.to_string();
    for a in [
        "breakglass_requested",
        "breakglass_approved",
        "breakglass_used",
        "breakglass_ended",
        "alert_page",
    ] {
        assert!(text.contains(a), "{a} missing from {text}");
    }
    assert!(e.office.verify_audit(None).await.unwrap().ok());
    let (s, v) = e
        .call("GET", "/v1/_office/breakglass", Some(&e.admin), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["data"].as_array().unwrap().len(), 2);
    // A person who is not an administrator can use none of it.
    let user = e
        .person("u@example.com", "notebook", "t1", &["member"])
        .await;
    assert_eq!(
        e.call("GET", "/v1/_office/breakglass", Some(&user), None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn a_compromised_app_credential_is_replaced() {
    let e = env().await;
    let (old, passport) = e.enroll("notebook", 2).await;
    let jti = {
        let p: Value = serde_json::from_slice(&base64_decode(
            passport["passport"]
                .as_str()
                .unwrap()
                .split('.')
                .nth(1)
                .unwrap(),
        ))
        .unwrap();
        p["jti"].as_str().unwrap().to_owned()
    };
    let feed = "/v1/_office/revocations?since=0";
    assert_eq!(e.as_app(&old, "notebook", feed).await.0, StatusCode::OK);
    let (s, v) = e
        .call(
            "POST",
            "/v1/_office/apps/notebook/rotate-credential",
            Some(&e.admin),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The stolen key is dead at once.
    assert_eq!(
        e.as_app(&old, "notebook", feed).await.0,
        StatusCode::UNAUTHORIZED
    );
    // The old passport is in the feed.
    let rows = e
        .office
        .db
        .rows(
            "SELECT id FROM office_revocations WHERE kind = 'passport'",
            vec![],
        )
        .await
        .unwrap();
    assert!(
        rows.iter()
            .any(|r| matches!(r.first(), Some(Db_Value::Text(t)) if *t == jti))
    );
    // The real app enrolls again with a new key and the one-time token.
    let fresh = AppKey::generate();
    let body = enroll_request(
        &fresh,
        v["enrollment_token"].as_str().unwrap(),
        "notebook",
        now(),
        &random_nonce(),
    );
    let (s, _) = e.call("POST", "/v1/_office/enroll", None, Some(body)).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(e.as_app(&fresh, "notebook", feed).await.0, StatusCode::OK);
    assert_eq!(
        e.as_app(&old, "notebook", feed).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        e.call(
            "POST",
            "/v1/_office/apps/nope/rotate-credential",
            Some(&e.admin),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn data_keys_rotate_and_the_kek_rewraps_without_changing_them() {
    let e = env().await;
    let db = &e.office.db;
    let mut kek = vault::KekSet::ephemeral();
    let (v1, k1) = vault::rotate_dek(db, &kek, "notebook:t1").await.unwrap();
    let (v2, k2) = vault::rotate_dek(db, &kek, "notebook:t1").await.unwrap();
    assert_eq!((v1, v2), (1, 2));
    assert_ne!(k1, k2);
    let list = vault::list_deks(db, "notebook:t1").await.unwrap();
    assert_eq!(
        list.iter().map(|d| d.status.as_str()).collect::<Vec<_>>(),
        ["retired", "active"]
    );
    // The active one is the default; the retired one still opens, to re-encrypt with.
    assert_eq!(
        vault::open_dek(db, &kek, "notebook:t1", None)
            .await
            .unwrap()
            .unwrap(),
        (2, k2.clone())
    );
    assert_eq!(
        vault::open_dek(db, &kek, "notebook:t1", Some(1))
            .await
            .unwrap()
            .unwrap()
            .1,
        k1
    );
    // Rotating the KEK keeps every DEK the same.
    let (new, n) = vault::rotate_kek(db, &mut kek).await.unwrap();
    assert_eq!(n, 2);
    assert!(
        vault::list_deks(db, "notebook:t1")
            .await
            .unwrap()
            .iter()
            .all(|d| d.kek == new)
    );
    kek.drop_old();
    assert_eq!(
        vault::open_dek(db, &kek, "notebook:t1", None)
            .await
            .unwrap()
            .unwrap()
            .1,
        k2
    );
    // After re-encryption the retired version is deleted; destroying a tenant erases it.
    assert_eq!(vault::retire_old(db, "notebook:t1").await.unwrap(), 1);
    assert!(
        vault::open_dek(db, &kek, "notebook:t1", Some(1))
            .await
            .unwrap()
            .is_none()
    );
    vault::destroy(db, "notebook:t1").await.unwrap();
    assert!(
        vault::open_dek(db, &kek, "notebook:t1", None)
            .await
            .unwrap()
            .is_none()
    );
    // The admin API rotates too, and never returns a key.
    let (s, v) = e
        .call(
            "POST",
            "/v1/_office/vault/deks/notebook:t9/rotate",
            Some(&e.admin),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v.get("key").is_none());
}

#[tokio::test]
async fn the_audit_chain_is_anchored_outside_and_rewriting_it_is_caught() {
    use falak_office::db::{int, t, text};
    let e = env().await;
    e.enroll("notebook", 1).await;
    e.enroll("journal", 2).await;
    let anchors = dir();
    let a = e
        .office
        .anchor_to(Some(anchors.clone()), None)
        .await
        .unwrap()
        .unwrap();
    assert!(a.seq >= 2);
    // Nothing new, nothing to anchor.
    assert!(
        e.office
            .anchor_to(Some(anchors.clone()), None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(std::fs::read_dir(&anchors).unwrap().count(), 1);
    let r = e.office.verify_audit(Some(&anchors)).await.unwrap();
    assert!(r.ok(), "{:?}", r.problems);
    assert_eq!(r.anchors_checked, 1);
    e.enroll("third", 1).await;
    e.office
        .anchor_to(Some(anchors.clone()), None)
        .await
        .unwrap();

    // Someone with database access edits an old entry: the chain alone catches it.
    e.office
        .db
        .run(
            "UPDATE office_audit SET actor = 'nobody' WHERE seq = 1",
            vec![],
        )
        .await
        .unwrap();
    let r = e.office.verify_audit(Some(&anchors)).await.unwrap();
    assert!(
        r.problems.iter().any(|p| p.contains("entry 1 was changed")),
        "{:?}",
        r.problems
    );

    // Smarter: they recompute every hash after the edit. Only the outside anchor catches it.
    let rows = e
        .office
        .db
        .rows(
            "SELECT seq, at, actor, action, detail FROM office_audit ORDER BY seq",
            vec![],
        )
        .await
        .unwrap();
    let mut prev = String::new();
    for r in &rows {
        let (seq, at) = (int(r.first()), int(r.get(1)));
        let (actor, action, mut detail) = (text(r.get(2)), text(r.get(3)), text(r.get(4)));
        if seq == 1 {
            detail = "forged".into();
        }
        let h = falak_office::anchor::entry_hash(&prev, seq, at, &actor, &action, &detail);
        e.office
            .db
            .run(
                "UPDATE office_audit SET detail = ?, prev_hash = ?, hash = ? WHERE seq = ?",
                vec![t(&detail), t(&prev), t(&h), Db_Value::Int64(seq)],
            )
            .await
            .unwrap();
        prev = h;
    }
    // They also wipe the anchors kept in the database, which they can reach.
    e.office
        .db
        .run("DELETE FROM office_anchors", vec![])
        .await
        .unwrap();
    let r = e.office.verify_audit(None).await.unwrap();
    assert!(
        r.ok(),
        "a consistent forgery passes the chain alone: {:?}",
        r.problems
    );
    let r = e.office.verify_audit(Some(&anchors)).await.unwrap();
    assert!(
        r.problems
            .iter()
            .any(|p| p.contains("rewritten after it was anchored")),
        "{:?}",
        r.problems
    );

    // Or they cut the tail off.
    e.office
        .db
        .run("DELETE FROM office_audit WHERE seq > 2", vec![])
        .await
        .unwrap();
    let r = e.office.verify_audit(Some(&anchors)).await.unwrap();
    assert!(
        r.problems.iter().any(|p| p.contains("cut short")),
        "{:?}",
        r.problems
    );

    // An anchor not signed by Office is not believed.
    std::fs::write(
        anchors.join("999-forged.json"),
        json!({"seq": 1, "hash": "00", "at": 1, "kid": "x", "signature": "00"}).to_string(),
    )
    .unwrap();
    let r = e.office.verify_audit(Some(&anchors)).await.unwrap();
    assert!(
        r.problems
            .iter()
            .any(|p| p.contains("not signed by Office"))
    );
}

#[tokio::test]
async fn two_instances_share_keys_and_a_rotation_reaches_the_other() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let make = |d: SqliteDriver| async move {
        let db = Db::new(Arc::new(d.clone()));
        db.migrate().await.unwrap();
        let p = dir().join("k.json");
        let keys = falak_office::keystore::shared_keys(&db, "signing", &p)
            .await
            .unwrap();
        let session_keys =
            falak_office::keystore::shared_keys(&db, "session", &dir().join("s.json"))
                .await
                .unwrap();
        let cfg = TokenConfig {
            issuer: "http://office.test#session".into(),
            audience: "office".into(),
            leeway_secs: 30,
        };
        let mut v = Verifier::new(cfg.clone());
        session_keys.trust_all(&mut v);
        let (_, users) = open_sqlite(d, session_keys, cfg);
        users.migrate().await.unwrap();
        Office::new("http://office.test".into(), db, keys, Some(p), v, users)
    };
    let a = make(driver.clone()).await;
    let b = make(driver.clone()).await;
    // Starting in either order gives the same keys, so each verifies what the other signs.
    assert_eq!(a.active_kid(), b.active_kid());
    assert_eq!(a.jwks(), b.jwks());

    // A rotates; B does not know yet, then picks it up without a restart.
    let kid = a.rotate().unwrap();
    a.persist_keys().await.unwrap();
    assert_ne!(b.active_kid(), kid);
    assert!(b.refresh_keys().await.unwrap());
    assert_eq!(b.active_kid(), kid);
    assert_eq!(a.jwks(), b.jwks());
    assert!(!b.refresh_keys().await.unwrap());
    // What A signs after the rotation, B verifies (the old key is kept for overlap).
    let sig = a.sign(b"hello");
    assert!(b.verify_signature(&sig.0, b"hello", &sig.1));
    assert_eq!(b.key_count(), 2);
}

#[tokio::test]
async fn objectives_page_on_a_fast_burn_and_alert_once() {
    let e = env().await;
    let m = observe::metrics();
    let minute = now() / 60;
    for i in 0..200 {
        m.record_at(minute, if i % 10 == 0 { 503 } else { 200 }, 20);
    }
    let alerter = observe::Alerter::default();
    let statuses = observe::evaluate(&e.office).await;
    let availability = statuses.iter().find(|s| s.name == "availability").unwrap();
    assert_eq!(availability.state, observe::State::Page, "{availability:?}");
    assert_eq!(
        statuses
            .iter()
            .find(|s| s.name == "database")
            .unwrap()
            .state,
        observe::State::Ok
    );
    assert_eq!(alerter.changes(&statuses).len(), 1);
    assert!(
        alerter
            .changes(&observe::evaluate(&e.office).await)
            .is_empty(),
        "no repeat while it stays bad"
    );
    let (s, v) = e.call("GET", "/v1/_office/slo", Some(&e.admin), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["data"].as_array().unwrap().len() >= 3);
    // The scrape endpoint is off without a token.
    assert_eq!(
        e.call("GET", "/metrics", None, None).await.0,
        StatusCode::NOT_FOUND
    );
}
