//! The PII mapping table (T7.8): encrypted at rest, scoped to a tenant.

use std::sync::Arc;

use falak_contracts::driver::Value;
use falak_driver_sqlite::SqliteDriver;
use falak_office::{
    db::Db,
    pii::{PiiKey, Vault},
};
use serde_json::json;

async fn db() -> Db {
    let db = Db::new(Arc::new(SqliteDriver::in_memory().await.unwrap()));
    db.migrate().await.unwrap();
    db
}

fn scan() -> serde_json::Value {
    json!({
        "document_id": "d1",
        "pii_entities": [
            {"kind": "EMAIL", "start": 3, "end": 19, "original": "jane@example.com"},
            {"kind": "PERSON", "start": 30, "end": 40, "original": "Dr. Jane Smith"}
        ]
    })
}

#[tokio::test]
async fn originals_leave_the_result_and_land_encrypted() {
    let db = db().await;
    let key = PiiKey::from_bytes([7; 32]);
    let vault = Vault { db: &db, key: &key };
    let out = vault.sanitize("acme", scan()).await.unwrap();
    let text = out.to_string();
    assert!(!text.contains("jane@example.com") && !text.contains("Jane Smith"));
    let token = out["pii_entities"][0]["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("EMAIL_"));
    assert_eq!(out["pii_entities"][0]["start"], 3);

    // At rest: no plaintext in any column.
    let rows = db
        .rows(
            "SELECT tenant, token, nonce, ciphertext FROM pii_mappings",
            vec![],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    let dump = format!("{rows:?}");
    assert!(!dump.contains("jane@example.com") && !dump.contains("Smith"));

    // The right tenant reads it back; another tenant cannot.
    assert_eq!(
        vault.reveal("acme", &token).await.unwrap().as_deref(),
        Some("jane@example.com")
    );
    assert_eq!(vault.reveal("globex", &token).await.unwrap(), None);
}

#[tokio::test]
async fn the_same_value_has_one_token_per_tenant_and_a_new_key_cannot_read_it() {
    let db = db().await;
    let key = PiiKey::from_bytes([7; 32]);
    let vault = Vault { db: &db, key: &key };
    let a1 = vault.sanitize("acme", scan()).await.unwrap();
    let a2 = vault.sanitize("acme", scan()).await.unwrap();
    let g = vault.sanitize("globex", scan()).await.unwrap();
    assert_eq!(a1, a2);
    assert_ne!(
        a1["pii_entities"][0]["token"],
        g["pii_entities"][0]["token"]
    );
    // Two tenants, two entities each; the repeat in `acme` added nothing.
    let n = db
        .rows("SELECT COUNT(*) FROM pii_mappings", vec![])
        .await
        .unwrap();
    assert_eq!(n[0][0], Value::Int64(4));

    let other = PiiKey::from_bytes([8; 32]);
    let token = a1["pii_entities"][0]["token"].as_str().unwrap();
    assert!(
        Vault {
            db: &db,
            key: &other
        }
        .reveal("acme", token)
        .await
        .is_err()
    );
}

#[tokio::test]
async fn a_row_moved_to_another_tenant_does_not_decrypt() {
    let db = db().await;
    let key = PiiKey::from_bytes([7; 32]);
    let vault = Vault { db: &db, key: &key };
    let out = vault.sanitize("acme", scan()).await.unwrap();
    let token = out["pii_entities"][0]["token"].as_str().unwrap();
    db.run(
        "UPDATE pii_mappings SET tenant = ? WHERE token = ?",
        vec![Value::Text("globex".into()), Value::Text(token.into())],
    )
    .await
    .unwrap();
    assert!(vault.reveal("globex", token).await.is_err());
}

#[tokio::test]
async fn a_result_with_no_personal_data_is_untouched() {
    let db = db().await;
    let key = PiiKey::from_bytes([7; 32]);
    let vault = Vault { db: &db, key: &key };
    let r = json!({"words": 12});
    assert_eq!(vault.sanitize("acme", r.clone()).await.unwrap(), r);
}
