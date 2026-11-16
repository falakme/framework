//! Signed events (FEDERATION §13.4): the publisher signs each event, the subscriber
//! verifies it before applying, and an app's contract says who may receive what.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use falak_contracts::ir::Ir;
use falak_core::outbox::{OutboxRow, signing_message};
use falak_runtime_native::events::Delivery;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::AppKey;

fn payload_hash(payload: &str) -> String {
    hex::encode(Sha256::digest(payload.as_bytes()))
}

/// The body of `POST /v1/_office/events` for an outbox row, signed by the publisher.
pub fn publish_body(key: &AppKey, app: &str, row: &OutboxRow) -> Value {
    let msg = signing_message(
        app,
        &row.id,
        &row.event,
        &row.entity,
        &row.aggregate_id,
        row.revision,
        row.schema_version,
        row.occurred_at,
        &payload_hash(&row.payload),
    );
    json!({
        "id": row.id, "event": row.event, "aggregate_type": row.entity,
        "aggregate_id": row.aggregate_id, "revision": row.revision,
        "version": row.schema_version, "occurred_at": row.occurred_at,
        "payload": row.payload, "signature": key.sign(msg.as_bytes()),
    })
}

/// The body of `PUT /v1/_office/events/contract`: what this app publishes, consumes and
/// orchestrates, from its compiled IR.
pub fn contract_body(ir: &Ir) -> Value {
    json!({
        "events": ir.events.iter().map(|e| json!({
            "name": e.name, "version": e.version, "subscribers": e.subscribers,
        })).collect::<Vec<_>>(),
        "subscriptions": ir.subscriptions.iter().map(|s| json!({
            "event": s.event, "from": s.from, "version": s.version,
        })).collect::<Vec<_>>(),
        "sagas": ir.sagas.iter().map(|s| json!({
            "name": s.name, "start": s.start,
            "steps": s.steps.iter().map(|st| json!({
                "name": st.name, "command": st.command, "compensate": st.compensate,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

fn verify(key: &VerifyingKey, message: &str, sig: &str) -> bool {
    B64.decode(sig)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .is_some_and(|s| key.verify(message.as_bytes(), &s).is_ok())
}

/// Check a delivery from Office and turn it into the event to apply. `office_keys` are
/// the keys of the issuer this app trusts (its cached key set).
///
/// An event signed by its publisher is accepted only with Office's attestation of the
/// publisher's key, and an event Office signed itself (a saga command) only with an
/// Office key. Anything else, including a changed payload, is refused.
pub fn verify_delivery(
    item: &Value,
    office_keys: &[(String, VerifyingKey)],
) -> Result<Delivery, String> {
    let s = |k: &str| item[k].as_str().ok_or_else(|| format!("`{k}` is missing"));
    let i = |k: &str| item[k].as_i64().ok_or_else(|| format!("`{k}` is missing"));
    let (publisher, signer, id, event, payload, sig) = (
        s("publisher")?,
        s("signer")?,
        s("id")?,
        s("event")?,
        s("payload")?,
        s("signature")?,
    );
    let mut msg = signing_message(
        publisher,
        id,
        event,
        s("aggregate_type")?,
        s("aggregate_id")?,
        i("revision")?,
        i("version")?,
        i("occurred_at")?,
        &payload_hash(payload),
    );
    let kid = s("kid")?;
    let office_key = office_keys
        .iter()
        .find(|(k, _)| k == kid)
        .map(|(_, k)| k)
        .ok_or("the event names a key this app does not trust")?;
    let ok = if signer == "office" {
        msg.insert_str(0, "office\n");
        verify(office_key, &msg, sig)
    } else {
        if signer != publisher {
            return Err("the signer is not the publisher".into());
        }
        let pk = s("publisher_key")?;
        let attested = verify(
            office_key,
            &format!("falak-app-key\n{signer}\n{pk}"),
            s("key_attestation")?,
        );
        let key = B64
            .decode(pk)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok());
        attested && key.is_some_and(|k| verify(&k, &msg, sig))
    };
    if !ok {
        return Err("the event's signature does not verify".into());
    }
    Ok(Delivery {
        id: id.to_owned(),
        publisher: publisher.to_owned(),
        name: event.to_owned(),
        version: u32::try_from(i("version")?).map_err(|_| "bad version")?,
        payload: payload.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn office() -> (SigningKey, Vec<(String, VerifyingKey)>) {
        let sk = SigningKey::from_bytes(&[7; 32]);
        let keys = vec![("k1".to_owned(), sk.verifying_key())];
        (sk, keys)
    }

    fn row() -> OutboxRow {
        OutboxRow {
            seq: 1,
            id: "r:order_placed".into(),
            event: "order_placed".into(),
            entity: "purchase".into(),
            aggregate_id: "a1".into(),
            revision: 1,
            schema_version: 1,
            payload: "{\"id\":\"a1\"}".into(),
            occurred_at: 5,
        }
    }

    /// What Office hands a subscriber for an event `app` published.
    fn delivery(app_key: &AppKey, office_sk: &SigningKey, row: &OutboxRow) -> Value {
        let body = publish_body(app_key, "orders", row);
        let pk = app_key.public();
        let att = B64.encode(
            office_sk
                .sign(format!("falak-app-key\norders\n{pk}").as_bytes())
                .to_bytes(),
        );
        json!({
            "publisher": "orders", "signer": "orders", "id": body["id"], "event": body["event"],
            "aggregate_type": body["aggregate_type"], "aggregate_id": body["aggregate_id"],
            "revision": body["revision"], "version": body["version"],
            "occurred_at": body["occurred_at"], "payload": body["payload"],
            "signature": body["signature"], "publisher_key": pk, "kid": "k1",
            "key_attestation": att,
        })
    }

    #[test]
    fn a_genuine_event_verifies_and_any_change_breaks_it() {
        let (osk, keys) = office();
        let app = AppKey::generate();
        let d = delivery(&app, &osk, &row());
        let got = verify_delivery(&d, &keys).unwrap();
        assert_eq!((got.publisher.as_str(), got.version), ("orders", 1));

        let mut forged = d.clone();
        forged["payload"] = json!("{\"id\":\"a1\",\"qty\":9999}");
        assert!(verify_delivery(&forged, &keys).is_err());
        let mut forged = d.clone();
        forged["event"] = json!("other");
        assert!(verify_delivery(&forged, &keys).is_err());
        // Signed by a different key than the one Office vouched for.
        let mut forged = delivery(&AppKey::generate(), &osk, &row());
        forged["publisher_key"] = d["publisher_key"].clone();
        assert!(verify_delivery(&forged, &keys).is_err());
        // An attestation from a key the subscriber does not trust.
        let stranger = SigningKey::from_bytes(&[9; 32]);
        assert!(verify_delivery(&delivery(&app, &stranger, &row()), &keys).is_err());
        // Someone who relays an event under another publisher's name.
        let mut forged = d;
        forged["publisher"] = json!("billing");
        assert!(verify_delivery(&forged, &keys).is_err());
    }

    #[test]
    fn an_office_signed_saga_event_verifies_only_with_an_office_key() {
        let (osk, keys) = office();
        let payload = "{\"sku\":\"rose\"}";
        let msg = format!(
            "office\n{}",
            signing_message(
                "orders",
                "s:step:0",
                "reserve_stock",
                "saga",
                "s",
                0,
                1,
                9,
                &payload_hash(payload)
            )
        );
        let d = json!({
            "publisher": "orders", "signer": "office", "id": "s:step:0", "event": "reserve_stock",
            "aggregate_type": "saga", "aggregate_id": "s", "revision": 0, "version": 1,
            "occurred_at": 9, "payload": payload, "kid": "k1",
            "signature": B64.encode(osk.sign(msg.as_bytes()).to_bytes()),
        });
        assert!(verify_delivery(&d, &keys).is_ok());
        assert!(verify_delivery(&d, &[]).is_err());
        let mut bad = d;
        bad["signer"] = json!("orders");
        assert!(verify_delivery(&bad, &keys).is_err());
    }
}
