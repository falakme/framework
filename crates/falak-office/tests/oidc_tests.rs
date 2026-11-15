//! Sign in through an outside OpenID Connect provider (ADR-0011). The provider here is a
//! fixed RSA key; its key set is loaded directly, so no network is involved.

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
use falak_office::{
    Office,
    db::Db,
    now,
    oidc::{Oidc, OidcConfig},
    router,
    users::open_sqlite,
};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use tower::ServiceExt;

const ISSUER: &str = "https://idp.example.com";
const AUDIENCE: &str = "falak-office";
const KEY: &str = include_str!("fixtures/oidc_test_key.pem");
const JWKS: &str = include_str!("fixtures/oidc_test_jwks.json");

struct Env {
    app: Router,
    office: Arc<Office>,
}

async fn env(oidc: Option<OidcConfig>) -> Env {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let session_config = TokenConfig {
        issuer: "http://office.test#session".into(),
        audience: "office".into(),
        leeway_secs: 30,
    };
    let dir = std::env::temp_dir().join(format!(
        "falak-office-oidc-{}-{}",
        std::process::id(),
        now()
    ));
    let dir = dir.join(format!("{:p}", &driver));
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
    users
        .create("alice@corp.test", "correct horse battery staple 42", &[])
        .await
        .unwrap();
    let mut office = Office::new(
        "http://office.test".into(),
        db,
        LocalKeys::load_or_create(&keys_path).unwrap(),
        Some(keys_path),
        verifier,
        users,
    );
    if let Some(cfg) = oidc {
        office = office.with_oidc(cfg);
        office.oidc().unwrap().load_jwks(JWKS, now()).unwrap();
    }
    let office = Arc::new(office);
    Env {
        app: router(office.clone(), login),
        office,
    }
}

fn config(domains: &[&str]) -> OidcConfig {
    OidcConfig {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        auto_create_domains: domains.iter().map(|d| (*d).to_owned()).collect(),
        trust_unverified_email: false,
    }
}

fn id_token(claims: &Value) -> String {
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some("test-1".into());
    encode(
        &h,
        claims,
        &EncodingKey::from_rsa_pem(KEY.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn claims(sub: &str, email: &str) -> Value {
    json!({
        "iss": ISSUER, "aud": AUDIENCE, "sub": sub, "email": email,
        "email_verified": true, "iat": now(), "exp": now() + 300,
    })
}

async fn exchange(e: &Env, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/oidc/exchange")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({"id_token": token}).to_string()))
        .unwrap();
    let res = e.app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn subject_of(e: &Env, body: &Value) -> String {
    e.office
        .session_verifier()
        .verify(body["access_token"].as_str().unwrap(), now())
        .unwrap()
        .subject
}

#[tokio::test]
async fn a_person_the_provider_vouches_for_gets_an_office_session() {
    let e = env(Some(config(&[]))).await;
    let (s, v) = exchange(&e, &id_token(&claims("user_1", "Alice@Corp.test"))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["refresh_token"].is_string());
    let id = subject_of(&e, &v);
    let alice = e.office.users.find("alice@corp.test").await.unwrap();
    assert_eq!(Some(id), alice, "linked to the account with that email");
}

#[tokio::test]
async fn the_same_provider_id_stays_the_same_person_when_the_email_changes() {
    let e = env(Some(config(&[]))).await;
    let (_, first) = exchange(&e, &id_token(&claims("user_1", "alice@corp.test"))).await;
    let (s, second) = exchange(&e, &id_token(&claims("user_1", "renamed@corp.test"))).await;
    assert_eq!(s, StatusCode::OK, "{second}");
    assert_eq!(subject_of(&e, &first), subject_of(&e, &second));
}

#[tokio::test]
async fn strangers_are_refused_unless_their_domain_is_allowed() {
    let closed = env(Some(config(&[]))).await;
    let (s, _) = exchange(&closed, &id_token(&claims("u9", "new@corp.test"))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let open = env(Some(config(&["corp.test"]))).await;
    let (s, v) = exchange(&open, &id_token(&claims("u9", "new@corp.test"))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        open.office
            .users
            .find("new@corp.test")
            .await
            .unwrap()
            .is_some()
    );
    let (s, _) = exchange(&open, &id_token(&claims("u10", "x@elsewhere.test"))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "another domain");
}

#[tokio::test]
async fn tokens_that_are_not_right_are_all_refused() {
    let e = env(Some(config(&["corp.test"]))).await;
    let base = claims("user_1", "alice@corp.test");
    let with = |k: &str, v: Value| {
        let mut c = base.clone();
        c[k] = v;
        id_token(&c)
    };
    let without = |k: &str| {
        let mut c = base.clone();
        c.as_object_mut().unwrap().remove(k);
        id_token(&c)
    };
    let cases = [
        ("wrong issuer", with("iss", json!("https://evil.test"))),
        ("wrong audience", with("aud", json!("someone-else"))),
        ("expired", with("exp", json!(now() - 3600))),
        ("email not verified", with("email_verified", json!(false))),
        ("no verified flag", without("email_verified")),
        ("no email", without("email")),
        ("no expiry", without("exp")),
        ("not a token", "abc.def.ghi".to_owned()),
    ];
    for (name, token) in cases {
        let (s, _) = exchange(&e, &token).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{name}");
    }

    // A token signed with a key the provider never published.
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some("not-published".into());
    let forged = encode(
        &h,
        &base,
        &EncodingKey::from_rsa_pem(KEY.as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(exchange(&e, &forged).await.0, StatusCode::UNAUTHORIZED);

    // A shared-secret token that uses the public key as the secret must not pass.
    let mut h = Header::new(Algorithm::HS256);
    h.kid = Some("test-1".into());
    let hs = encode(&h, &base, &EncodingKey::from_secret(JWKS.as_bytes())).unwrap();
    assert_eq!(exchange(&e, &hs).await.0, StatusCode::UNAUTHORIZED);

    // An unsigned token.
    let none = format!(
        "{}.{}.",
        "eyJhbGciOiJub25lIiwia2lkIjoidGVzdC0xIiwidHlwIjoiSldUIn0",
        {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            URL_SAFE_NO_PAD.encode(base.to_string())
        }
    );
    assert_eq!(exchange(&e, &none).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_provider_that_sends_azp_and_no_aud_works_and_an_unverified_flag_can_be_trusted() {
    let mut cfg = config(&[]);
    cfg.trust_unverified_email = true;
    let e = env(Some(cfg)).await;
    let mut c = claims("user_1", "alice@corp.test");
    c.as_object_mut().unwrap().remove("aud");
    c.as_object_mut().unwrap().remove("email_verified");
    c["azp"] = json!(AUDIENCE);
    assert_eq!(exchange(&e, &id_token(&c)).await.0, StatusCode::OK);
}

#[tokio::test]
async fn a_revoked_person_cannot_sign_in_again_and_without_a_provider_the_route_is_absent() {
    let e = env(Some(config(&[]))).await;
    let (_, v) = exchange(&e, &id_token(&claims("user_1", "alice@corp.test"))).await;
    let id = subject_of(&e, &v);
    e.office.add_revocation("subject", &id).await.unwrap();
    let (s, _) = exchange(&e, &id_token(&claims("user_1", "alice@corp.test"))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let none = env(None).await;
    let (s, _) = exchange(&none, &id_token(&claims("user_1", "alice@corp.test"))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[test]
fn the_config_wants_https_and_the_key_set_refreshes_when_it_should() {
    assert!(config(&[]).validate().is_ok());
    let mut bad = config(&[]);
    bad.issuer = "http://idp.example.com".into();
    assert!(bad.validate().is_err());
    bad.issuer = "http://127.0.0.1:9000".into();
    assert!(bad.validate().is_ok());

    let o = Oidc::new(config(&[]));
    let t = id_token(&claims("u", "a@b.test"));
    assert!(o.wants_refresh(&t, 1000), "nothing loaded yet");
    o.load_jwks(JWKS, 1000).unwrap();
    assert!(!o.wants_refresh(&t, 1100), "known key, fresh set");
    assert!(o.wants_refresh(&t, 1600), "old set");
    assert!(o.load_jwks("{\"keys\":[]}", 1001).is_err());
    assert!(o.load_jwks("nope", 1001).is_err());
}

async fn call(e: &Env, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let res = e.app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn step_up_needs_a_fresh_sign_in_by_the_same_person_and_adds_a_short_lived_role() {
    use falak_office::db::t;
    let e = env(Some(config(&[]))).await;
    // An app, and Alice's membership of it.
    let key = falak_federation::AppKey::generate();
    let (_, v) = exchange(&e, &id_token(&claims("user_1", "alice@corp.test"))).await;
    let session = v["access_token"].as_str().unwrap().to_owned();
    let alice = subject_of(&e, &v);
    e.office
        .db
        .run(
            "INSERT INTO office_apps (name, tier, public_key, kid, capabilities, passport_jti, status, created_at) VALUES (?, 1, ?, 'k', '{}', 'j', 'active', 0)",
            vec![t("bank"), t(&key.public())],
        )
        .await
        .unwrap();
    e.office
        .db
        .run(
            "INSERT INTO office_memberships (user_id, app, tenant, roles) VALUES (?, 'bank', NULL, 'member,step_up')",
            vec![t(&alice)],
        )
        .await
        .unwrap();

    let roles_of = |token: &str| {
        let payload = token.split('.').nth(1).unwrap();
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let v: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        (
            v["roles"].clone(),
            v["exp"].as_i64().unwrap() - v["iat"].as_i64().unwrap(),
        )
    };

    // A plain token never has the role, even if an administrator wrote it down.
    let (s, plain) = call(
        &e,
        "/v1/_office/token",
        &session,
        json!({"audience": "bank"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{plain}");
    assert_eq!(
        roles_of(plain["access_token"].as_str().unwrap()).0,
        json!(["member"])
    );

    let fresh = || {
        let mut c = claims("user_1", "alice@corp.test");
        c["auth_time"] = json!(now() - 10);
        c
    };
    let (s, up) = call(
        &e,
        "/v1/_office/stepup",
        &session,
        json!({"audience": "bank", "id_token": id_token(&fresh())}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{up}");
    let (roles, life) = roles_of(up["access_token"].as_str().unwrap());
    assert_eq!(roles, json!(["member", "step_up"]));
    assert!(life <= 300);

    let refused = |name: &'static str, c: Value| {
        let (e, session) = (&e, session.clone());
        async move {
            let (s, _) = call(
                e,
                "/v1/_office/stepup",
                &session,
                json!({"audience": "bank", "id_token": id_token(&c)}),
            )
            .await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{name}");
        }
    };
    let mut old = fresh();
    old["auth_time"] = json!(now() - 3600);
    refused("an old sign-in", old).await;
    let mut none = fresh();
    none.as_object_mut().unwrap().remove("auth_time");
    refused("no auth_time", none).await;
    let mut other = fresh();
    other["sub"] = json!("someone_else");
    refused("a different provider identity", other).await;
    // No Office session at all.
    let (s, _) = call(
        &e,
        "/v1/_office/stepup",
        "garbage",
        json!({"audience": "bank", "id_token": id_token(&fresh())}),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
