//! Office's web console: first-run setup, the lists it shows and the settings it saves.

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
use falak_office::{Office, db::Db, router, users::open_sqlite};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const PASSWORD: &str = "correct horse battery staple 42";

struct Env {
    app: Router,
    office: Arc<Office>,
    dir: std::path::PathBuf,
}

async fn env(save_settings: bool) -> Env {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let session_config = TokenConfig {
        issuer: "http://office.test#session".into(),
        audience: "office".into(),
        leeway_secs: 30,
    };
    let dir = std::env::temp_dir().join(format!(
        "falak-office-console-{}-{:p}",
        std::process::id(),
        &driver
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
    let mut office = Office::new(
        "http://office.test".into(),
        db,
        LocalKeys::load_or_create(&keys_path).unwrap(),
        Some(keys_path),
        verifier,
        users,
    );
    if save_settings {
        office = office.with_data_dir(dir.join("data"));
    }
    let office = Arc::new(office);
    Env {
        app: router(office.clone(), login),
        office,
        dir,
    }
}

async fn call(
    e: &Env,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    let res = e
        .app
        .clone()
        .oneshot(
            b.body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn login(e: &Env, email: &str) -> String {
    let (s, v) = call(
        e,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"email": email, "password": PASSWORD})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["access_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn pages_are_served_with_a_strict_policy() {
    let e = env(false).await;
    for path in ["/", "/office.js", "/office.css"] {
        let res = e
            .app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{path}");
        let csp = res.headers()["content-security-policy"].to_str().unwrap();
        assert!(
            csp.contains("script-src 'self'") && !csp.contains("unsafe-inline"),
            "{csp}"
        );
        assert_eq!(res.headers()["x-content-type-options"], "nosniff");
    }
}

#[tokio::test]
async fn first_run_setup_needs_the_code_makes_one_administrator_and_closes() {
    let e = env(true).await;
    let (s, v) = call(&e, "GET", "/v1/_office/status", None, None).await;
    assert_eq!(
        (s, &v["setup_needed"]),
        (StatusCode::OK, &json!(false)),
        "not armed yet"
    );

    let code = e
        .office
        .arm_setup()
        .await
        .unwrap()
        .expect("nobody has an account");
    let (_, v) = call(&e, "GET", "/v1/_office/status", None, None).await;
    assert_eq!(v["setup_needed"], true);

    let body = |token: &str, password: &str| json!({"token": token, "email": "boss@example.com", "password": password, "issuer": "https://office.example.com"});
    let (s, _) = call(
        &e,
        "POST",
        "/v1/_office/setup",
        None,
        Some(body("wrong", PASSWORD)),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a wrong code");
    // A weak password is refused, and the code still works afterwards.
    let (s, _) = call(
        &e,
        "POST",
        "/v1/_office/setup",
        None,
        Some(body(&code, "short")),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        e.office.setup_open(),
        "the code is given back after a failed attempt"
    );
    let (s, v) = call(
        &e,
        "POST",
        "/v1/_office/setup",
        None,
        Some(body(&code, PASSWORD)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["restart_needed"], true, "the public address changed");
    let saved = std::fs::read_to_string(e.dir.join("data/settings.json")).unwrap();
    assert!(saved.contains("https://office.example.com"));

    // Closed: the same code, and any other, no longer works.
    let (s, _) = call(
        &e,
        "POST",
        "/v1/_office/setup",
        None,
        Some(body(&code, PASSWORD)),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(!e.office.setup_open());
    assert!(
        e.office.arm_setup().await.unwrap().is_none(),
        "there is an account now"
    );

    let token = login(&e, "boss@example.com").await;
    let (s, v) = call(&e, "GET", "/v1/_office/overview", Some(&token), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["counts"]["people"], 1);
    assert_eq!(v["restart_needed"], true);
    assert_eq!(v["saved_issuer"], "https://office.example.com");
}

#[tokio::test]
async fn the_lists_and_settings_are_for_administrators_only() {
    let e = env(true).await;
    let code = e.office.arm_setup().await.unwrap().unwrap();
    let (s, _) = call(
        &e,
        "POST",
        "/v1/_office/setup",
        None,
        Some(json!({"token": code, "email": "boss@example.com", "password": PASSWORD})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let admin = login(&e, "boss@example.com").await;

    let (s, _) = call(
        &e,
        "POST",
        "/v1/_office/users",
        Some(&admin),
        Some(json!({"email": "pat@example.com", "password": PASSWORD})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let pat = login(&e, "pat@example.com").await;

    for (method, path) in [
        ("GET", "/v1/_office/overview"),
        ("GET", "/v1/_office/users"),
        ("GET", "/v1/_office/memberships"),
        ("GET", "/v1/_office/audit"),
        ("PUT", "/v1/_office/settings/oidc"),
        ("PUT", "/v1/_office/settings/address"),
    ] {
        let (s, _) = call(&e, method, path, None, Some(json!({}))).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path} with no session");
        let (s, _) = call(&e, method, path, Some(&pat), Some(json!({}))).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{path} for an ordinary person");
    }

    let (_, v) = call(&e, "GET", "/v1/_office/users", Some(&admin), None).await;
    let emails: Vec<&str> = v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["email"].as_str().unwrap())
        .collect();
    assert_eq!(emails, ["boss@example.com", "pat@example.com"]);
    assert_eq!(v["data"][0]["roles"], json!(["office_admin"]));

    // An app, a membership, then the list and a removal.
    let (s, tok) = call(
        &e,
        "POST",
        "/v1/_office/enrollments",
        Some(&admin),
        Some(json!({"app": "notes", "tier": 1})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{tok}");
    e.office
        .db
        .run(
            "INSERT INTO office_apps (name, tier, public_key, kid, capabilities, passport_jti, status, created_at) VALUES ('notes', 1, ?, 'k', '{}', 'j', 'active', 0)",
            vec![falak_contracts::driver::Value::Text(
                falak_federation::AppKey::generate().public(),
            )],
        )
        .await
        .unwrap();
    let (s, v) = call(
        &e,
        "PUT",
        "/v1/_office/memberships",
        Some(&admin),
        Some(json!({"email": "pat@example.com", "app": "notes", "roles": ["editor"]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, v) = call(&e, "GET", "/v1/_office/memberships", Some(&admin), None).await;
    assert_eq!(v["data"][0]["email"], "pat@example.com");
    assert_eq!(v["data"][0]["roles"], json!(["editor"]));
    let uid = v["data"][0]["user_id"].as_str().unwrap().to_owned();
    let (s, v) = call(
        &e,
        "DELETE",
        "/v1/_office/memberships",
        Some(&admin),
        Some(json!({"user_id": uid, "app": "notes"})),
    )
    .await;
    assert_eq!((s, &v["removed"]), (StatusCode::OK, &json!(1)));
    let (_, v) = call(&e, "GET", "/v1/_office/memberships", Some(&admin), None).await;
    assert!(v["data"].as_array().unwrap().is_empty());

    let (_, v) = call(&e, "GET", "/v1/_office/audit", Some(&admin), None).await;
    let actions: Vec<&str> = v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["action"].as_str().unwrap())
        .collect();
    assert!(
        actions.contains(&"setup") && actions.contains(&"membership_removed"),
        "{actions:?}"
    );
}

#[tokio::test]
async fn the_provider_can_be_turned_on_and_off_without_a_restart_and_is_saved() {
    let e = env(true).await;
    let code = e.office.arm_setup().await.unwrap().unwrap();
    call(
        &e,
        "POST",
        "/v1/_office/setup",
        None,
        Some(json!({"token": code, "email": "boss@example.com", "password": PASSWORD})),
    )
    .await;
    let admin = login(&e, "boss@example.com").await;
    assert!(e.office.oidc().is_none());

    // A provider address that is not https is refused.
    let (s, _) = call(
        &e,
        "PUT",
        "/v1/_office/settings/oidc",
        Some(&admin),
        Some(json!({"issuer": "http://idp.example.com", "audience": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(e.office.oidc().is_none());

    // A good one is on at once. Nothing answers at that address here, and the reply says so.
    let (s, v) = call(
        &e,
        "PUT",
        "/v1/_office/settings/oidc",
        Some(&admin),
        Some(json!({"issuer": "http://127.0.0.1:9", "audience": "office", "auto_create_domains": ["Example.com"]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (&v["enabled"], &v["reachable"]),
        (&json!(true), &json!(false))
    );
    assert_eq!(
        e.office.oidc().unwrap().config.auto_create_domains,
        ["example.com"]
    );
    let saved = std::fs::read_to_string(e.dir.join("data/settings.json")).unwrap();
    assert!(
        saved.contains("127.0.0.1:9") && saved.contains("example.com"),
        "{saved}"
    );
    let (_, v) = call(&e, "GET", "/v1/_office/overview", Some(&admin), None).await;
    assert_eq!(v["oidc"]["audience"], "office");

    let (s, _) = call(
        &e,
        "PUT",
        "/v1/_office/settings/oidc",
        Some(&admin),
        Some(json!({"enabled": false})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(e.office.oidc().is_none());
    assert!(
        !std::fs::read_to_string(e.dir.join("data/settings.json"))
            .unwrap()
            .contains("oidc")
    );

    let (s, v) = call(
        &e,
        "PUT",
        "/v1/_office/settings/address",
        Some(&admin),
        Some(json!({"issuer": "https://office.example.com/"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}: no trailing slash");
    let (s, v) = call(
        &e,
        "PUT",
        "/v1/_office/settings/address",
        Some(&admin),
        Some(json!({"issuer": "https://office.example.com"})),
    )
    .await;
    assert_eq!((s, &v["restart_needed"]), (StatusCode::OK, &json!(true)));
}

#[tokio::test]
async fn the_overview_numbers_count_sign_ins_tokens_and_failures_by_day() {
    let e = env(false).await;
    let code = e.office.arm_setup().await.unwrap().unwrap();
    call(
        &e,
        "POST",
        "/v1/_office/setup",
        None,
        Some(json!({"token": code, "email": "boss@example.com", "password": PASSWORD})),
    )
    .await;
    let admin = login(&e, "boss@example.com").await; // one sign-in
    let (s, _) = call(
        &e,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"email": "boss@example.com", "password": "wrong wrong wrong"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    e.office
        .db
        .run(
            "INSERT INTO office_apps (name, tier, public_key, kid, capabilities, passport_jti, status, created_at) VALUES ('notes', 1, ?, 'k', '{}', 'j', 'active', 0)",
            vec![falak_contracts::driver::Value::Text(
                falak_federation::AppKey::generate().public(),
            )],
        )
        .await
        .unwrap();
    call(
        &e,
        "PUT",
        "/v1/_office/memberships",
        Some(&admin),
        Some(json!({"email": "boss@example.com", "app": "notes", "roles": []})),
    )
    .await;
    for _ in 0..3 {
        let (s, _) = call(
            &e,
            "POST",
            "/v1/_office/token",
            Some(&admin),
            Some(json!({"audience": "notes"})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
    }

    let (s, v) = call(&e, "GET", "/v1/_office/stats?days=7", Some(&admin), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["days"], 7);
    assert_eq!(v["series"]["sign_in"].as_array().unwrap().len(), 7);
    assert_eq!(v["totals"]["sign_in"], 1);
    assert_eq!(v["totals"]["sign_in_failed"], 1);
    assert_eq!(v["totals"]["app_token"], 3);
    assert_eq!(v["series"]["app_token"][6], 3, "today is the last day");
    assert_eq!(v["previous"]["app_token"], 0);
    assert_eq!(v["new_people_7d"], 1);
    let app = &v["apps"][0];
    assert_eq!((&app["name"], &app["tokens"]), (&json!("notes"), &json!(3)));

    // A window outside 7 to 90 days falls back to 14. Ordinary people cannot read it.
    let (_, v) = call(&e, "GET", "/v1/_office/stats?days=500", Some(&admin), None).await;
    assert_eq!(v["days"], 14);
    let (s, _) = call(&e, "GET", "/v1/_office/stats", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
