//! AI writes need a person (T7.10), and what reaches a model carries no raw personal data.

mod common;

use std::{net::IpAddr, sync::Arc};

use axum::http::StatusCode;
use common::*;
use falak_ai::{
    egress::AiPolicy,
    mcp::{McpConfig, mcp_router},
};
use falak_runtime_native::context::DevAuthenticator;
use serde_json::{Value, json};

fn alice_step_up() -> String {
    format!("sub:{ALICE},role:step_up")
}

async fn with_writes() -> (axum::Router, String, String) {
    let w = world().await;
    let (alice_note, bob_note) = seed(&w.app).await;
    let mut config = McpConfig::new(&w.ir, &["note".to_owned()]).unwrap();
    config.writes = true;
    let app = mcp_router(w.ir.clone(), config, Arc::new(DevAuthenticator), w.app);
    (app, alice_note, bob_note)
}

fn payload(v: &Value) -> Value {
    serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap_or("{}"))
        .unwrap_or(Value::Null)
}

async fn notes_of(app: &axum::Router, who: &str) -> Vec<String> {
    let (_, v) = rest(app, who, "GET", "/v1/notes", None).await;
    v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["title"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn write_tools_exist_only_when_switched_on_and_only_queue_a_proposal() {
    let (app, _, _) = with_writes().await;
    let (_, v) = rpc(&app, Some(ALICE), "tools/list", json!({})).await;
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"create_note") && names.contains(&"delete_note"));

    let (_, v) = call_tool(
        &app,
        ALICE,
        "create_note",
        json!({"fields": {"title": "from the agent"}}),
    )
    .await;
    let p = payload(&v);
    assert_eq!(p["status"], "pending_approval", "{v}");
    // Nothing changed.
    assert_eq!(notes_of(&app, ALICE).await, vec!["alice's secret plan"]);
}

#[tokio::test]
async fn the_agents_own_token_cannot_approve_its_proposal() {
    let (app, _, _) = with_writes().await;
    let (_, v) = call_tool(
        &app,
        ALICE,
        "create_note",
        json!({"fields": {"title": "x", "notebook_id": "n"}}),
    )
    .await;
    let p = payload(&v);
    let path = format!("/mcp/approvals/{}/approve", p["id"].as_str().unwrap());
    // The agent holds Alice's ordinary token: no step-up, no approval.
    let (s, _) = rest(
        &app,
        ALICE,
        "POST",
        &path,
        Some(json!({"digest": p["digest"]})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(notes_of(&app, ALICE).await.len(), 1);
}

#[tokio::test]
async fn only_the_person_it_acts_for_can_approve_and_only_what_they_were_shown() {
    let (app, _, _) = with_writes().await;
    let (_, nb) = rest(&app, ALICE, "GET", "/v1/notebooks", None).await;
    let notebook = nb["data"][0]["id"].as_str().unwrap().to_owned();
    let (_, v) = call_tool(
        &app,
        ALICE,
        "create_note",
        json!({"fields": {"title": "approved note", "notebook_id": notebook}}),
    )
    .await;
    let p = payload(&v);
    let id = p["id"].as_str().unwrap();
    let path = format!("/mcp/approvals/{id}/approve");

    // Bob, even with a step-up, cannot see or approve Alice's proposal.
    let bob = format!("sub:{BOB},role:step_up");
    let (s, _) = rest(
        &app,
        &bob,
        "POST",
        &path,
        Some(json!({"digest": p["digest"]})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, v) = rest(&app, &bob, "GET", "/mcp/approvals", None).await;
    assert_eq!(v["proposals"].as_array().unwrap().len(), 0);

    // Alice sees it in her queue, in full.
    let (_, v) = rest(&app, ALICE, "GET", "/mcp/approvals", None).await;
    assert!(
        v["proposals"][0]["summary"]
            .as_str()
            .unwrap()
            .contains("approved note")
    );

    // A wrong digest approves nothing.
    let (s, _) = rest(
        &app,
        &alice_step_up(),
        "POST",
        &path,
        Some(json!({"digest": "0".repeat(64)})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(notes_of(&app, ALICE).await.len(), 1);

    // The right digest, with a step-up, runs it as Alice.
    let (s, v) = rest(
        &app,
        &alice_step_up(),
        "POST",
        &path,
        Some(json!({"digest": p["digest"]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["outcome"]["ok"], true, "{v}");
    assert!(
        notes_of(&app, ALICE)
            .await
            .contains(&"approved note".to_owned())
    );

    // One time only.
    let (s, _) = rest(
        &app,
        &alice_step_up(),
        "POST",
        &path,
        Some(json!({"digest": p["digest"]})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(notes_of(&app, ALICE).await.len(), 2);
}

#[tokio::test]
async fn an_approved_write_still_goes_through_the_policy_engine() {
    let (app, _, bob_note) = with_writes().await;
    // Alice's agent proposes to change Bob's note; Alice approves; the engine refuses.
    let (_, v) = call_tool(
        &app,
        ALICE,
        "update_note",
        json!({"id": bob_note, "fields": {"title": "defaced"}}),
    )
    .await;
    let p = payload(&v);
    let path = format!("/mcp/approvals/{}/approve", p["id"].as_str().unwrap());
    let (_, v) = rest(
        &app,
        &alice_step_up(),
        "POST",
        &path,
        Some(json!({"digest": p["digest"]})),
    )
    .await;
    assert_eq!(v["outcome"]["ok"], false, "{v}");
    assert_eq!(notes_of(&app, BOB).await, vec!["bob's shopping"]);
}

#[tokio::test]
async fn a_rejected_proposal_never_runs() {
    let (app, alice_note, _) = with_writes().await;
    let (_, v) = call_tool(&app, ALICE, "delete_note", json!({"id": alice_note})).await;
    let p = payload(&v);
    let id = p["id"].as_str().unwrap();
    let (s, v) = rest(
        &app,
        ALICE,
        "POST",
        &format!("/mcp/approvals/{id}/reject"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["state"], "rejected");
    let (s, _) = rest(
        &app,
        &alice_step_up(),
        "POST",
        &format!("/mcp/approvals/{id}/approve"),
        Some(json!({"digest": p["digest"]})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(notes_of(&app, ALICE).await.len(), 1);
}

#[tokio::test]
async fn personal_data_fields_are_always_omitted() {
    {
        let w = world_with(clarity_ir()).await;
        let (s, doc) = rest(
            &w.app,
            ALICE,
            "POST",
            "/v1/documents",
            Some(json!({"title": "contract", "body": "Call Jane Smith on +44 20 7946 0958"})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{doc}");
        let config = McpConfig::new(&w.ir, &["document".to_owned()]).unwrap();
        let app = mcp_router(w.ir.clone(), config, Arc::new(DevAuthenticator), w.app);

        let (_, v) = call_tool(&app, ALICE, "list_document", json!({})).await;
        let text = v["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_owned();
        let (_, one) = call_tool(&app, ALICE, "get_document", json!({"id": doc["id"]})).await;
        let one = one["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_owned();
        for t in [&text, &one] {
            assert!(t.contains("contract"), "non-PII fields stay readable");
            assert!(!t.contains("Jane Smith"), "{t}");
            assert!(!t.contains("\"body\""), "{t}");
        }
    }
}

struct Dns;

impl falak_egress::Resolver for Dns {
    fn resolve(&self, host: &str) -> falak_contracts::Result<Vec<IpAddr>> {
        Ok(match host {
            "api.provider.test" => vec!["93.184.216.34".parse().unwrap()],
            "rebind.provider.test" => vec!["169.254.169.254".parse().unwrap()],
            _ => vec![],
        })
    }
}

#[test]
fn a_model_provider_must_be_listed_and_public() {
    let p = AiPolicy::new(&["api.provider.test".into(), "rebind.provider.test".into()]);
    assert!(
        p.check_url("https://api.provider.test/v1/messages", &Dns)
            .is_ok()
    );
    // Not listed, plain http, a name that points at the metadata address.
    assert!(p.check_url("https://other.test/", &Dns).is_err());
    assert!(p.check_url("http://api.provider.test/", &Dns).is_err());
    assert!(p.check_url("https://rebind.provider.test/", &Dns).is_err());
    // Nothing is allowed until the operator lists a provider.
    assert!(
        AiPolicy::default()
            .check_url("https://api.provider.test/", &Dns)
            .is_err()
    );
}

async fn clarity_app(writes: bool) -> axum::Router {
    let w = world_with(clarity_ir()).await;
    let mut config = McpConfig::new(&w.ir, &["document".to_owned()]).unwrap();
    config.writes = writes;
    mcp_router(w.ir.clone(), config, Arc::new(DevAuthenticator), w.app)
}

#[tokio::test]
async fn personal_data_cannot_be_probed_by_filtering_or_sorting_or_read_from_the_schema() {
    let app = clarity_app(false).await;
    for (title, body) in [("a", "zzz secret one"), ("b", "aaa secret two")] {
        let (s, _) = rest(
            &app,
            ALICE,
            "POST",
            "/v1/documents",
            Some(json!({"title": title, "body": body})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
    }
    // Neither the description nor the schema names the hidden field.
    let (_, v) = rpc(&app, Some(ALICE), "tools/list", json!({})).await;
    assert!(!v.to_string().contains("body"), "{v}");

    // A filter on it is a yes/no question about its value; a sort ranks it and the
    // next-page cursor would carry the last value. All are refused.
    for args in [
        json!({"filters": {"body": "zzz secret one"}}),
        json!({"filters": {"BODY": "zzz secret one"}}),
        json!({"filters": {"body][eq": "x"}}),
        json!({"sort": "body"}),
        json!({"sort": "-body"}),
        json!({"sort": "title,-body", "page_size": 1}),
    ] {
        let (_, v) = call_tool(&app, ALICE, "list_document", args.clone()).await;
        assert_eq!(v["result"]["isError"], true, "{args}: {v}");
        assert!(!v.to_string().contains("secret"), "{args}: {v}");
    }
    // Ordinary filters and sorts still work.
    let (_, v) = call_tool(
        &app,
        ALICE,
        "list_document",
        json!({"filters": {"title": "a"}, "sort": "-title"}),
    )
    .await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    assert!(!v.to_string().contains("secret"));
}

#[tokio::test]
async fn an_agent_cannot_queue_proposals_without_bound() {
    let (app, alice_note, _) = with_writes().await;
    let mut refused = false;
    for _ in 0..(falak_ai::approval::MAX_PENDING_PER_SUBJECT + 5) {
        let (_, v) = call_tool(&app, ALICE, "delete_note", json!({"id": alice_note})).await;
        if v["result"]["isError"] == true {
            refused = true;
            break;
        }
    }
    assert!(refused, "the queue must have a limit");
    // Bob's queue is separate: Alice's agent cannot crowd him out.
    let (_, v) = call_tool(&app, BOB, "delete_note", json!({"id": alice_note})).await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    let (_, listed) = rest(&app, ALICE, "GET", "/mcp/approvals", None).await;
    assert_eq!(
        listed["proposals"].as_array().unwrap().len(),
        falak_ai::approval::MAX_PENDING_PER_SUBJECT
    );
}
