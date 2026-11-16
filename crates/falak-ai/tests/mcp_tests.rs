mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use common::*;
use falak_ai::mcp::{McpConfig, mcp_router};
use falak_runtime_native::context::DevAuthenticator;
use serde_json::{Value, json};

async fn with_mcp(entities: &[&str]) -> (axum::Router, String, String) {
    let w = world().await;
    let (alice_note, bob_note) = seed(&w.app).await;
    let names: Vec<String> = entities.iter().map(|s| (*s).to_owned()).collect();
    let config = McpConfig::new(&w.ir, &names).unwrap();
    let app = mcp_router(w.ir.clone(), config, Arc::new(DevAuthenticator), w.app);
    (app, alice_note, bob_note)
}

fn text_of(v: &Value) -> String {
    v["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn nothing_is_served_until_the_operator_opts_in() {
    let (app, _, _) = with_mcp(&[]).await;
    let (s, _) = rpc(&app, Some(ALICE), "tools/list", json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_allow_list_naming_a_missing_entity_is_refused() {
    let w = world().await;
    assert!(McpConfig::new(&w.ir, &["nope".to_owned()]).is_err());
}

#[tokio::test]
async fn the_agent_must_act_as_someone() {
    let (app, _, _) = with_mcp(&["note"]).await;
    let (s, _) = rpc(&app, None, "tools/list", json!({})).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn only_allow_listed_entities_get_read_only_tools() {
    let (app, _, _) = with_mcp(&["note"]).await;
    let (_, init) = rpc(&app, Some(ALICE), "initialize", json!({})).await;
    assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
    let (_, v) = rpc(&app, Some(ALICE), "tools/list", json!({})).await;
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["list_note", "get_note"]);
    for t in v["result"]["tools"].as_array().unwrap() {
        assert_eq!(t["annotations"]["readOnlyHint"], true);
    }
    // A tool for an entity off the list, and any write tool, simply does not exist.
    for tool in [
        "list_notebook",
        "create_note",
        "update_note",
        "delete_note",
        "archive_note",
    ] {
        let (_, v) = call_tool(&app, ALICE, tool, json!({})).await;
        assert_eq!(v["error"]["message"], "unknown tool", "{tool}: {v}");
    }
}

#[tokio::test]
async fn a_tool_call_runs_as_the_calling_user_through_the_policy_engine() {
    let (app, alice_note, bob_note) = with_mcp(&["note"]).await;

    let (_, v) = call_tool(&app, ALICE, "list_note", json!({})).await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    let listed = text_of(&v);
    assert!(listed.contains("alice's secret plan"));
    assert!(
        !listed.contains("bob's shopping"),
        "Alice sees only her own notes"
    );

    let (_, v) = call_tool(&app, BOB, "list_note", json!({})).await;
    assert!(text_of(&v).contains("bob's shopping") && !text_of(&v).contains("alice"));

    // Reading someone else's note by id is refused exactly as it is over REST.
    let (_, v) = call_tool(&app, BOB, "get_note", json!({"id": alice_note})).await;
    assert_eq!(v["result"]["isError"], true, "{v}");
    assert!(!text_of(&v).contains("secret plan"));
    let (_, v) = call_tool(&app, ALICE, "get_note", json!({"id": alice_note})).await;
    assert_eq!(v["result"]["isError"], false);
    assert!(text_of(&v).contains("secret plan"));
    let (_, v) = call_tool(&app, ALICE, "get_note", json!({"id": bob_note})).await;
    assert_eq!(v["result"]["isError"], true);

    // An administrator reads everything, because the policy says so: the agent gets
    // what the person gets, no more and no less.
    let admin = "sub:cccccccc-0000-4000-8000-000000000003,role:admin";
    let (_, v) = call_tool(&app, admin, "list_note", json!({})).await;
    assert!(text_of(&v).contains("secret plan") && text_of(&v).contains("shopping"));

    // Filters and paging reach the same engine.
    let (_, v) = call_tool(
        &app,
        ALICE,
        "list_note",
        json!({"page_size": 1, "sort": "-title"}),
    )
    .await;
    assert_eq!(v["result"]["isError"], false, "{v}");
}

#[tokio::test]
async fn bad_arguments_and_methods_are_reported_not_executed() {
    let (app, _, _) = with_mcp(&["note"]).await;
    let (_, v) = call_tool(&app, ALICE, "get_note", json!({})).await;
    assert_eq!(v["result"]["isError"], true);
    let (_, v) = call_tool(&app, ALICE, "list_note", json!({"filters": {"title": 5}})).await;
    assert_eq!(v["result"]["isError"], true);
    let (_, v) = rpc(&app, Some(ALICE), "resources/list", json!({})).await;
    assert_eq!(v["error"]["code"], -32601);
}
