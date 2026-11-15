//! Office end to end, in process: enrollment, passports, signing in once, per-app tokens,
//! the revocation feed and key rotation (FEDERATION specification).

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
use falak_federation::{
    AppKey, OfficeConfig, enroll_request, now, random_nonce, request_headers, verify_feed,
};
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

#[tokio::test]
async fn an_app_enrolls_once_with_a_single_use_token() {
    let e = env().await;
    let (s, v) = e
        .call(
            "POST",
            "/v1/_office/enrollments",
            Some(&e.admin),
            Some(json!({"app": "notebook", "tier": 1})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let token = v["token"].as_str().unwrap().to_owned();
    let key = AppKey::generate();

    // A proof by another key, the wrong app, and a stale timestamp are all refused alike.
    let other = AppKey::generate();
    let mut forged = enroll_request(&key, &token, "notebook", now(), &random_nonce());
    forged["signature"] =
        enroll_request(&other, &token, "notebook", now(), "x".repeat(20).as_str())["signature"]
            .clone();
    let wrong_app = enroll_request(&key, &token, "other-app", now(), &random_nonce());
    let stale = enroll_request(&key, &token, "notebook", now() - 3600, &random_nonce());
    for body in [forged, wrong_app, stale] {
        let (s, _) = e.call("POST", "/v1/_office/enroll", None, Some(body)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }

    let good = enroll_request(&key, &token, "notebook", now(), &random_nonce());
    let (s, v) = e.call("POST", "/v1/_office/enroll", None, Some(good)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["app"], "notebook");

    // The passport is signed by Office and names the app and its key.
    let passport = v["passport"].as_str().unwrap();
    let parts: Vec<&str> = passport.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload: Value = serde_json::from_slice(&base64_decode(parts[1])).unwrap();
    assert_eq!(payload["sub"], "notebook");
    assert_eq!(payload["kind"], "passport");
    assert_eq!(payload["app_key"], key.public());

    // The token cannot enroll again, not even with a fresh key.
    let again = enroll_request(
        &AppKey::generate(),
        &token,
        "notebook",
        now(),
        &random_nonce(),
    );
    let (s, _) = e
        .call("POST", "/v1/_office/enroll", None, Some(again))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // And only an administrator makes tokens.
    let (s, _) = e
        .call(
            "POST",
            "/v1/_office/enrollments",
            None,
            Some(json!({"app": "x1", "tier": 1})),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(s).unwrap()
}

#[tokio::test]
async fn one_sign_in_reaches_each_app_with_a_token_for_its_audience() {
    let e = env().await;
    e.enroll("notebook", 1).await;
    e.enroll("academy", 2).await;
    let tenant = "00000000-0000-0000-0000-0000000000a1";
    let session = e
        .person("bob@example.com", "notebook", tenant, &["reviewer"])
        .await;

    let (s, v) = e
        .call(
            "POST",
            "/v1/_office/token",
            Some(&session),
            Some(json!({"audience": "notebook"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["expires_in"], 900, "tier 1 tokens live 15 minutes");
    let p = e
        .verifier("notebook")
        .verify(v["access_token"].as_str().unwrap(), now())
        .unwrap();
    assert_eq!(p.tenant.as_deref(), Some(tenant));
    assert_eq!(p.roles, ["reviewer"]);

    // The token is for one audience only.
    assert!(
        e.verifier("academy")
            .verify(v["access_token"].as_str().unwrap(), now())
            .is_err()
    );

    // No membership for academy: refused, the same as for an app that does not exist.
    for audience in ["academy", "nonesuch"] {
        let (s, _) = e
            .call(
                "POST",
                "/v1/_office/token",
                Some(&session),
                Some(json!({"audience": audience})),
            )
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{audience}");
    }
    // No session, no token.
    let (s, _) = e
        .call(
            "POST",
            "/v1/_office/token",
            None,
            Some(json!({"audience": "notebook"})),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // A tier 2 app's tokens live 5 minutes.
    let admin_member = e
        .call(
            "PUT",
            "/v1/_office/memberships",
            Some(&e.admin),
            Some(json!({"email": "bob@example.com", "app": "academy", "roles": ["student"]})),
        )
        .await;
    assert_eq!(admin_member.0, StatusCode::OK);
    let (_, v) = e
        .call(
            "POST",
            "/v1/_office/token",
            Some(&session),
            Some(json!({"audience": "academy"})),
        )
        .await;
    assert_eq!(v["expires_in"], 300);
}

#[tokio::test]
async fn there_is_no_sign_up_and_a_session_cannot_do_admin_work() {
    let e = env().await;
    let (s, _) = e
        .call(
            "POST",
            "/v1/auth/signup",
            None,
            Some(json!({"email": "x@example.com", "password": PASSWORD})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = e
        .call(
            "POST",
            "/v1/auth/password-reset",
            None,
            Some(json!({"email": "admin@example.com"})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    e.enroll("notebook", 1).await;
    let bob = e.person("bob@example.com", "notebook", "", &[]).await;
    for (method, path) in [
        ("POST", "/v1/_office/enrollments"),
        ("POST", "/v1/_office/keys/rotate"),
        ("POST", "/v1/_office/revocations"),
        ("GET", "/v1/_office/apps"),
    ] {
        let (s, _) = e.call(method, path, Some(&bob), Some(json!({}))).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{path}");
    }
}

#[tokio::test]
async fn a_signed_request_must_be_fresh_unrepeated_and_from_the_right_key() {
    let e = env().await;
    let (key, _) = e.enroll("notebook", 1).await;
    let (s, v) = e.as_app(&key, "notebook", "/v1/_office/manifest").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["audience"], "notebook");
    assert_eq!(v["tier"], 1);

    // The same nonce twice is a replay.
    let nonce = random_nonce();
    let at = now();
    assert_eq!(
        e.as_app_at(&key, "notebook", "/v1/_office/manifest", at, &nonce)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        e.as_app_at(&key, "notebook", "/v1/_office/manifest", at, &nonce)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // A request from long ago, or the future.
    assert_eq!(
        e.as_app_at(
            &key,
            "notebook",
            "/v1/_office/manifest",
            at - 600,
            &random_nonce()
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        e.as_app_at(
            &key,
            "notebook",
            "/v1/_office/manifest",
            at + 600,
            &random_nonce()
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    // Another key, claiming to be the app.
    assert_eq!(
        e.as_app(&AppKey::generate(), "notebook", "/v1/_office/manifest")
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // A signature for one path does not work on another.
    let mut b = Request::builder()
        .method("GET")
        .uri("/v1/_office/revocations?since=0");
    for (k, v) in request_headers(
        &key,
        "notebook",
        "GET",
        "/v1/_office/manifest",
        b"",
        now(),
        &random_nonce(),
    ) {
        b = b.header(k, v);
    }
    assert_eq!(
        send(&e.app, b.body(Body::empty()).unwrap()).await.0,
        StatusCode::UNAUTHORIZED
    );
    // An app that does not exist.
    assert_eq!(
        e.as_app(&key, "ghost", "/v1/_office/manifest").await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn revocations_reach_apps_through_a_signed_versioned_feed() {
    let e = env().await;
    let (key, _) = e.enroll("notebook", 2).await;
    let session = e.person("bob@example.com", "notebook", "", &[]).await;
    let (_, me) = e
        .call(
            "POST",
            "/v1/_office/token",
            Some(&session),
            Some(json!({"audience": "notebook"})),
        )
        .await;
    assert!(me["access_token"].is_string());

    let (s, v) = e
        .as_app(&key, "notebook", "/v1/_office/revocations?since=0")
        .await;
    assert_eq!(s, StatusCode::OK);
    let keys = falak_auth::jwks::parse_jwks(&e.office.jwks().to_string()).unwrap();
    let feed = verify_feed(&v, &keys).unwrap();
    assert_eq!(feed.version, 0);

    // Revoke bob (by subject, read from his token) and a token id.
    let subject = {
        let p = e
            .verifier("notebook")
            .verify(me["access_token"].as_str().unwrap(), now())
            .unwrap();
        p.subject
    };
    let (s, r) = e
        .call(
            "POST",
            "/v1/_office/revocations",
            Some(&e.admin),
            Some(json!({"kind": "subject", "id": subject})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{r}");
    assert_eq!(r["version"], 1);
    e.call(
        "POST",
        "/v1/_office/revocations",
        Some(&e.admin),
        Some(json!({"kind": "token", "id": "abc"})),
    )
    .await;

    let (_, v) = e
        .as_app(&key, "notebook", "/v1/_office/revocations?since=1")
        .await;
    let feed = verify_feed(&v, &keys).unwrap();
    assert_eq!(feed.version, 2);
    assert_eq!(feed.entries.len(), 1, "only what came after version 1");
    assert_eq!(feed.entries[0].kind, "token");

    // A feed that was changed on the way is refused.
    let mut tampered = v.clone();
    tampered["payload"] = Value::String(
        tampered["payload"]
            .as_str()
            .unwrap()
            .replace("\"version\":2", "\"version\":9"),
    );
    assert!(verify_feed(&tampered, &keys).is_err());

    // A revoked person gets no new tokens.
    let (s, _) = e
        .call(
            "POST",
            "/v1/_office/token",
            Some(&session),
            Some(json!({"audience": "notebook"})),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_revoked_app_loses_access_and_cannot_get_tokens_issued() {
    let e = env().await;
    let (key, _) = e.enroll("notebook", 1).await;
    let session = e.person("bob@example.com", "notebook", "", &[]).await;
    let (s, _) = e
        .call(
            "POST",
            "/v1/_office/apps/notebook/revoke",
            Some(&e.admin),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        e.as_app(&key, "notebook", "/v1/_office/manifest").await.0,
        StatusCode::UNAUTHORIZED
    );
    let (s, _) = e
        .call(
            "POST",
            "/v1/_office/token",
            Some(&session),
            Some(json!({"audience": "notebook"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rotating_the_signing_key_breaks_nothing_until_the_old_key_is_retired() {
    let e = env().await;
    e.enroll("notebook", 1).await;
    let session = e.person("bob@example.com", "notebook", "", &[]).await;
    let (_, before) = e
        .call(
            "POST",
            "/v1/_office/token",
            Some(&session),
            Some(json!({"audience": "notebook"})),
        )
        .await;
    let old_token = before["access_token"].as_str().unwrap().to_owned();
    let old_kid = e.office.active_kid();

    let (s, r) = e
        .call("POST", "/v1/_office/keys/rotate", Some(&e.admin), None)
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["keys"], 2);
    assert_ne!(e.office.active_kid(), old_kid);

    // The key set now has both. Old tokens still verify; new ones use the new key.
    let verifier = e.verifier("notebook");
    assert!(verifier.verify(&old_token, now()).is_ok());
    let (_, after) = e
        .call(
            "POST",
            "/v1/_office/token",
            Some(&session),
            Some(json!({"audience": "notebook"})),
        )
        .await;
    let new_token = after["access_token"].as_str().unwrap();
    assert!(verifier.verify(new_token, now()).is_ok());
    assert_ne!(
        falak_auth::jwks::JwksCache::kid_of(new_token),
        falak_auth::jwks::JwksCache::kid_of(&old_token)
    );

    // Retiring leaves only the new key: old tokens stop verifying, new ones keep going.
    let (s, r) = e
        .call("POST", "/v1/_office/keys/retire", Some(&e.admin), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["keys"], 1);
    let verifier = e.verifier("notebook");
    assert!(verifier.verify(&old_token, now()).is_err());
    assert!(verifier.verify(new_token, now()).is_ok());
}

#[tokio::test]
async fn the_public_key_set_has_no_secrets_and_tier_three_is_refused() {
    let e = env().await;
    let (s, v) = e.call("GET", "/.well-known/jwks.json", None, None).await;
    assert_eq!(s, StatusCode::OK);
    for k in v["keys"].as_array().unwrap() {
        assert_eq!(k["kty"], "OKP");
        assert!(k.get("d").is_none());
    }
    let (s, _) = e
        .call(
            "POST",
            "/v1/_office/enrollments",
            Some(&e.admin),
            Some(json!({"app": "ledger", "tier": 3})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_IMPLEMENTED);
}

#[allow(dead_code)]
fn _config(_: OfficeConfig) {}
