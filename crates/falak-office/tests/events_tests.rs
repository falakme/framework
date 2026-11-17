//! Office Events end to end, in process: contracts, signed publish, claim, ack, ordering,
//! dead letters and sagas (T5.3).

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
use falak_core::outbox::signing_message;
use falak_driver_sqlite::SqliteDriver;
use falak_federation::{AppKey, enroll_request, now, random_nonce, request_headers};
use falak_office::{Office, db::Db, router, users::open_sqlite};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const PASSWORD: &str = "correct horse battery staple 42";

struct Env {
    app: Router,
    admin: String,
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

fn plain(method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> Request<Body> {
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

async fn env() -> Env {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let session_config = TokenConfig {
        issuer: "http://office.test#session".into(),
        audience: "office".into(),
        leeway_secs: 30,
    };
    let dir = std::env::temp_dir().join(format!(
        "falak-office-events-{}-{}",
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
    let app = router(office, login);
    let (s, v) = send(
        &app,
        plain(
            "POST",
            "/v1/auth/login",
            None,
            Some(json!({"email": "admin@example.com", "password": PASSWORD})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    Env {
        app,
        admin: v["access_token"].as_str().unwrap().to_owned(),
    }
}

impl Env {
    async fn enroll(&self, app: &str) -> AppKey {
        let (s, v) = send(
            &self.app,
            plain(
                "POST",
                "/v1/_office/enrollments",
                Some(&self.admin),
                Some(json!({"app": app, "tier": 1})),
            ),
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
        let (s, v) = send(
            &self.app,
            plain("POST", "/v1/_office/enroll", None, Some(body)),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        key
    }

    async fn signed(
        &self,
        key: &AppKey,
        app: &str,
        method: &str,
        uri: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let text = body.to_string();
        let mut b = Request::builder().method(method).uri(uri);
        for (k, v) in request_headers(
            key,
            app,
            method,
            uri,
            text.as_bytes(),
            now(),
            &random_nonce(),
        ) {
            b = b.header(k, v);
        }
        send(
            &self.app,
            b.header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(text))
                .unwrap(),
        )
        .await
    }

    async fn signed_admin(
        &self,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        send(&self.app, plain(method, uri, Some(&self.admin), body)).await
    }

    async fn contract(&self, key: &AppKey, app: &str, c: Value) {
        let (s, v) = self
            .signed(key, app, "PUT", "/v1/_office/events/contract", c)
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }

    async fn publish(
        &self,
        key: &AppKey,
        app: &str,
        id: &str,
        agg: &str,
        payload: &str,
    ) -> (StatusCode, Value) {
        self.publish_as(key, app, app, id, "order_placed", agg, payload)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn publish_as(
        &self,
        key: &AppKey,
        app: &str,
        claimed: &str,
        id: &str,
        event: &str,
        agg: &str,
        payload: &str,
    ) -> (StatusCode, Value) {
        let occurred = 1_700_000_000_000_000;
        let msg = signing_message(
            claimed,
            id,
            event,
            "purchase",
            agg,
            1,
            1,
            occurred,
            &hex::encode(Sha256::digest(payload.as_bytes())),
        );
        let body = json!({"id": id, "event": event, "aggregate_type": "purchase", "aggregate_id": agg,
            "revision": 1, "version": 1, "occurred_at": occurred, "payload": payload, "signature": key.sign(msg.as_bytes())});
        self.signed(key, app, "POST", "/v1/_office/events", body)
            .await
    }

    async fn claim(&self, key: &AppKey, app: &str) -> Vec<Value> {
        let (s, v) = self
            .signed(
                key,
                app,
                "POST",
                "/v1/_office/events/claim",
                json!({"limit": 50}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v["events"].as_array().unwrap().clone()
    }

    async fn ack(&self, key: &AppKey, app: &str, seq: i64, outcome: &str) -> Value {
        let (s, v) = self
            .signed(
                key,
                app,
                "POST",
                "/v1/_office/events/ack",
                json!({"seq": seq, "outcome": outcome, "error": "boom"}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v
    }
}

fn orders_contract() -> Value {
    json!({"events": [{"name": "order_placed", "version": 1, "subscribers": ["inventory"]}]})
}

fn inventory_contract() -> Value {
    json!({"subscriptions": [{"event": "order_placed", "from": "orders", "version": 1}]})
}

#[tokio::test]
async fn an_event_is_stored_before_the_ack_and_delivered_to_its_subscriber_only() {
    let e = env().await;
    let orders = e.enroll("orders").await;
    let inventory = e.enroll("inventory").await;
    let other = e.enroll("billing").await;
    e.contract(&orders, "orders", orders_contract()).await;
    e.contract(&inventory, "inventory", inventory_contract())
        .await;

    let (s, v) = e
        .publish(
            &orders,
            "orders",
            "r1:order_placed",
            "a1",
            "{\"id\":\"a1\"}",
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let seq = v["seq"].as_i64().unwrap();
    // Publishing again is safe and changes nothing.
    let (s, v) = e
        .publish(
            &orders,
            "orders",
            "r1:order_placed",
            "a1",
            "{\"id\":\"a1\"}",
        )
        .await;
    assert_eq!((s, v["seq"].as_i64()), (StatusCode::OK, Some(seq)));

    // Forged: signed by another app's key, or an event the contract does not declare.
    let (s, _) = e
        .publish(&other, "orders", "r2:order_placed", "a2", "{}")
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = e
        .publish_as(
            &orders,
            "orders",
            "orders",
            "r3:other",
            "other_event",
            "a3",
            "{}",
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Another app's name on an event it did not sign fails the signature check.
    let (s, _) = e
        .publish_as(
            &orders,
            "orders",
            "inventory",
            "r4:order_placed",
            "order_placed",
            "a4",
            "{}",
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Only the named subscriber receives it, with what it needs to verify it.
    assert!(e.claim(&other, "billing").await.is_empty());
    assert!(e.claim(&orders, "orders").await.is_empty());
    let got = e.claim(&inventory, "inventory").await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["publisher"], "orders");
    assert!(got[0]["publisher_key"].is_string() && got[0]["key_attestation"].is_string());
    // Until acknowledged it comes back (at least once).
    assert_eq!(e.claim(&inventory, "inventory").await.len(), 1);
    assert_eq!(
        e.ack(&inventory, "inventory", seq, "ok").await["status"],
        "done"
    );
    assert!(e.claim(&inventory, "inventory").await.is_empty());
    // Someone else's delivery cannot be acknowledged.
    let (s, _) = e
        .signed(
            &other,
            "billing",
            "POST",
            "/v1/_office/events/ack",
            json!({"seq": seq, "outcome": "ok"}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn events_for_one_aggregate_arrive_in_order_and_a_dead_one_blocks_until_replayed() {
    let e = env().await;
    let orders = e.enroll("orders").await;
    let inventory = e.enroll("inventory").await;
    e.contract(&orders, "orders", orders_contract()).await;
    e.contract(&inventory, "inventory", inventory_contract())
        .await;
    let first = e
        .publish(&orders, "orders", "e1", "agg", "{\"n\":1}")
        .await
        .1["seq"]
        .as_i64()
        .unwrap();
    e.publish(&orders, "orders", "e2", "agg", "{\"n\":2}").await;
    e.publish(&orders, "orders", "e3", "other", "{\"n\":3}")
        .await;

    // The second event of `agg` waits for the first; another aggregate does not.
    let got = e.claim(&inventory, "inventory").await;
    let ids: Vec<&str> = got.iter().map(|g| g["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["e1", "e3"]);

    // A retry backs off, and the second event keeps waiting behind it.
    // The backoff is whole seconds from the wall clock, so `e1` may be due again if the
    // clock ticked over during the test. It must not come back before its backoff.
    let retried_at = falak_office::now();
    assert_eq!(
        e.ack(&inventory, "inventory", first, "retry").await["status"],
        "pending"
    );
    let ids: Vec<String> = e
        .claim(&inventory, "inventory")
        .await
        .iter()
        .map(|g| g["id"].as_str().unwrap().to_owned())
        .collect();
    assert!(ids.iter().any(|id| id == "e3"), "{ids:?}");
    assert!(ids.iter().all(|id| id != "e2"), "{ids:?}");
    if ids.iter().any(|id| id == "e1") {
        assert!(
            falak_office::now() > retried_at,
            "e1 came back before its backoff: {ids:?}"
        );
    }

    // A failure that cannot be fixed goes to the dead-letter queue and still blocks.
    assert_eq!(
        e.ack(&inventory, "inventory", first, "fail").await["status"],
        "dead"
    );
    assert!(
        e.claim(&inventory, "inventory")
            .await
            .iter()
            .all(|g| g["id"] != "e2")
    );
    let (s, v) = e.signed_admin("GET", "/v1/_office/events/dead", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["data"][0]["subscriber"], "inventory");
    assert_eq!(v["data"][0]["error"], "boom");

    // Replay puts it back; then the order is kept: e1, and only after it e2.
    let (s, _) = e
        .signed_admin(
            "POST",
            "/v1/_office/events/replay",
            Some(json!({"seq": first, "subscriber": "inventory"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let ids: Vec<String> = e
        .claim(&inventory, "inventory")
        .await
        .iter()
        .map(|g| g["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, ["e1", "e3"]);
    e.ack(&inventory, "inventory", first, "ok").await;
    let ids: Vec<String> = e
        .claim(&inventory, "inventory")
        .await
        .iter()
        .map(|g| g["id"].as_str().unwrap().to_owned())
        .collect();
    assert!(ids.contains(&"e2".to_owned()), "{ids:?}");
}

#[tokio::test]
async fn a_saga_runs_its_steps_and_compensates_the_ones_done_when_a_later_step_fails() {
    let e = env().await;
    let orders = e.enroll("orders").await;
    let inventory = e.enroll("inventory").await;
    let billing = e.enroll("billing").await;
    e.contract(
        &orders,
        "orders",
        json!({
            "events": [{"name": "order_placed", "version": 1, "subscribers": []}],
            "sagas": [{"name": "fulfil", "start": "order_placed", "steps": [
                {"name": "reserve", "command": "inventory.reserve_stock", "compensate": "inventory.release_stock"},
                {"name": "charge", "command": "billing.charge", "compensate": "billing.refund"}]}],
        }),
    )
    .await;
    e.contract(
        &inventory,
        "inventory",
        json!({"subscriptions": [
            {"event": "reserve_stock", "from": "orders", "version": 1},
            {"event": "release_stock", "from": "orders", "version": 1}]}),
    )
    .await;
    e.contract(
        &billing,
        "billing",
        json!({"subscriptions": [{"event": "charge", "from": "orders", "version": 1}]}),
    )
    .await;
    let (s, _) = e
        .publish(
            &orders,
            "orders",
            "o1:order_placed",
            "o1",
            "{\"sku\":\"rose\"}",
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    // Step one goes to inventory, signed by Office itself.
    let got = e.claim(&inventory, "inventory").await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["event"], "reserve_stock");
    assert_eq!(got[0]["signer"], "office");
    assert!(
        e.claim(&billing, "billing").await.is_empty(),
        "step two waits for step one"
    );
    e.ack(
        &inventory,
        "inventory",
        got[0]["seq"].as_i64().unwrap(),
        "ok",
    )
    .await;

    // Step two fails for good: inventory is told to undo step one.
    let got = e.claim(&billing, "billing").await;
    assert_eq!(got[0]["event"], "charge");
    e.ack(&billing, "billing", got[0]["seq"].as_i64().unwrap(), "fail")
        .await;
    let got = e.claim(&inventory, "inventory").await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["event"], "release_stock");
    let (_, v) = e.signed_admin("GET", "/v1/_office/sagas", None).await;
    assert_eq!(v["data"][0]["status"], "compensating");
    e.ack(
        &inventory,
        "inventory",
        got[0]["seq"].as_i64().unwrap(),
        "ok",
    )
    .await;
    let (_, v) = e.signed_admin("GET", "/v1/_office/sagas", None).await;
    assert_eq!(v["data"][0]["status"], "compensated");

    // A saga whose steps all succeed completes.
    e.publish(&orders, "orders", "o2:order_placed", "o2", "{}")
        .await;
    let got = e.claim(&inventory, "inventory").await;
    e.ack(
        &inventory,
        "inventory",
        got[0]["seq"].as_i64().unwrap(),
        "ok",
    )
    .await;
    let got = e.claim(&billing, "billing").await;
    e.ack(&billing, "billing", got[0]["seq"].as_i64().unwrap(), "ok")
        .await;
    let (_, v) = e.signed_admin("GET", "/v1/_office/sagas", None).await;
    assert!(
        v["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["status"] == "completed")
    );
}

#[tokio::test]
async fn another_publisher_cannot_take_an_event_id_that_is_already_stored() {
    let e = env().await;
    let orders = e.enroll("orders").await;
    let inventory = e.enroll("inventory").await;
    let rival = e.enroll("rival").await;
    e.contract(&orders, "orders", orders_contract()).await;
    e.contract(&inventory, "inventory", inventory_contract())
        .await;
    e.contract(&rival, "rival", orders_contract()).await;

    let (s, first) = e
        .publish(&orders, "orders", "r1:order_placed", "a1", "{}")
        .await;
    assert_eq!(s, StatusCode::OK, "{first}");
    // The rival sends the same id with a valid signature of its own. It must not be told
    // "stored" for an event that was never kept: it is refused.
    let (s, v) = e
        .publish(&rival, "rival", "r1:order_placed", "a1", "{\"x\":1}")
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    // The genuine publisher is unaffected: a repeat still answers with the same seq.
    let (s, again) = e
        .publish(&orders, "orders", "r1:order_placed", "a1", "{}")
        .await;
    assert_eq!((s, &again["seq"]), (StatusCode::OK, &first["seq"]));
}
