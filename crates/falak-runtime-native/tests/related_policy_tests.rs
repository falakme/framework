//! Stage 3 policies: relationship rules (`related`), end to end on SQLite. A project has
//! no owner of its own: the person who owns its workspace reaches it. A task is reached
//! through its project's workspace, two steps away.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use falak_contracts::identity::RequestContext;
use falak_core::{
    build::build_ir,
    compile::compile,
    diagnostics::Severity,
    load::{SourceFile, load_project},
};
use falak_driver_sqlite::SqliteDriver;
use falak_migrate::apply_initial_migration;
use falak_runtime_native::{context::DevAuthenticator, create_router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const ALICE: &str = "00000000-0000-0000-0000-00000000000a";
const BOB: &str = "00000000-0000-0000-0000-00000000000b";

const APP: &str = "schema_version: 1\nname: work\nversion: 0.1.0\ntenancy: none\ntrust_tier: standard\ndrivers: [sqlite, postgres, d1]\n";
const WORKSPACE: &str = "schema_version: 1\nentity: workspace\nowner: owner_id\nfields:\n  name: { type: text, required: true, max_length: 100 }\n  owner_id: { type: uuid, required: true, indexed: true }\n";
const PROJECT: &str = "schema_version: 1\nentity: project\nfields:\n  name: { type: text, required: true, max_length: 100 }\n  workspace_id: { type: uuid, required: true, indexed: true, references: workspace.id }\nrelations:\n  workspace: { kind: belongs_to, entity: workspace, field: workspace_id }\nlifecycle:\n  soft_delete: true\n";
const TASK: &str = "schema_version: 1\nentity: task\nfields:\n  title: { type: text, required: true, max_length: 100 }\n  project_id: { type: uuid, required: true, indexed: true, references: project.id }\nrelations:\n  project: { kind: belongs_to, entity: project, field: project_id }\n";
const WORKSPACE_POLICY: &str = "schema_version: 1\nentity: workspace\nrules:\n  - id: mine\n    actions: [read, create, update, delete]\n    allow: { owner: true }\n";
const PROJECT_POLICY: &str = "\
schema_version: 1
entity: project
rules:
  - id: staff_create
    actions: [create, read]
    allow: { role: staff }
  - id: workspace_owner
    actions: [read, update]
    allow: { owner: true, related: workspace }
";
const TASK_POLICY: &str = "\
schema_version: 1
entity: task
rules:
  - id: staff_create
    actions: [create, read]
    allow: { role: staff }
  - id: via_project_workspace
    actions: [read, update, delete]
    allow: { owner: true, related: project.workspace }
";

fn f(p: &str, t: &str) -> SourceFile {
    SourceFile {
        path: p.into(),
        text: t.into(),
    }
}

fn files(project_policy: &str, task_policy: &str) -> Vec<SourceFile> {
    vec![
        f("app.yaml", APP),
        f("entities/workspace.yaml", WORKSPACE),
        f("entities/project.yaml", PROJECT),
        f("entities/task.yaml", TASK),
        f("policies/workspace.yaml", WORKSPACE_POLICY),
        f("policies/project.yaml", project_policy),
        f("policies/task.yaml", task_policy),
    ]
}

async fn app() -> Router {
    app_on(Arc::new(SqliteDriver::in_memory().await.unwrap())).await
}

/// The app on any driver, with its tables made.
async fn app_on<D: falak_runtime_native::NativeDriver + falak_contracts::driver::StorageDriver>(
    driver: Arc<D>,
) -> Router {
    let (project, diags) = load_project(&files(PROJECT_POLICY, TASK_POLICY));
    assert!(!falak_core::diagnostics::has_errors(&diags), "{diags:?}");
    let ir = Arc::new(build_ir(&project.unwrap()));
    let ctx = RequestContext {
        principal: None,
        request_id: "t".into(),
    };
    apply_initial_migration(&*driver, &ctx, &ir).await.unwrap();
    create_router(ir, driver, Arc::new(DevAuthenticator))
}

fn token(subject: &str, roles: &[&str]) -> String {
    let mut t = format!("sub:{subject}");
    for r in roles {
        t.push_str(&format!(",role:{r}"));
    }
    t
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    let req = b
        .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

struct World {
    app: Router,
    /// (project id, task id) in Alice's and in Bob's workspace.
    alice: (String, String),
    bob: (String, String),
}

async fn world() -> World {
    world_on(app().await).await
}

async fn world_on(app: Router) -> World {
    let staff = token("00000000-0000-0000-0000-0000000000ff", &["staff"]);
    let mut out = Vec::new();
    for (who, name) in [(ALICE, "A"), (BOB, "B")] {
        let (s, ws) = call(
            &app,
            "POST",
            "/v1/workspaces",
            &token(who, &[]),
            Some(json!({"name": name})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{ws}");
        let (s, p) = call(
            &app,
            "POST",
            "/v1/projects",
            &staff,
            Some(json!({"name": format!("project {name}"), "workspace_id": ws["id"]})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{p}");
        let (s, t) = call(
            &app,
            "POST",
            "/v1/tasks",
            &staff,
            Some(json!({"title": format!("task {name}"), "project_id": p["id"]})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{t}");
        out.push((
            p["id"].as_str().unwrap().to_owned(),
            t["id"].as_str().unwrap().to_owned(),
        ));
    }
    let bob = out.pop().unwrap();
    let alice = out.pop().unwrap();
    World { app, alice, bob }
}

fn names(page: &Value, key: &str) -> Vec<String> {
    let mut v: Vec<String> = page["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r[key].as_str().unwrap().to_owned())
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn an_owner_reaches_rows_through_one_and_two_steps_and_no_others() {
    reads(world().await).await;
}

async fn reads(w: World) {
    let alice = token(ALICE, &[]);

    let (s, page) = call(&w.app, "GET", "/v1/projects", &alice, None).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert_eq!(names(&page, "name"), ["project A"], "one step");
    let (s, page) = call(&w.app, "GET", "/v1/tasks", &alice, None).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert_eq!(names(&page, "title"), ["task A"], "two steps");

    let (s, _) = call(
        &w.app,
        "GET",
        &format!("/v1/projects/{}", w.alice.0),
        &alice,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &w.app,
        "GET",
        &format!("/v1/projects/{}", w.bob.0),
        &alice,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "someone else's project");
    let (s, _) = call(
        &w.app,
        "GET",
        &format!("/v1/tasks/{}", w.bob.1),
        &alice,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "someone else's task");

    // A stranger reaches nothing.
    let nobody = token("00000000-0000-0000-0000-0000000000cc", &[]);
    let (_, page) = call(&w.app, "GET", "/v1/projects", &nobody, None).await;
    assert!(page["data"].as_array().unwrap().is_empty());
    let (_, page) = call(&w.app, "GET", "/v1/tasks", &nobody, None).await;
    assert!(page["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn writes_follow_the_same_path_and_only_the_actions_the_rule_lists() {
    writes(world().await).await;
}

async fn writes(w: World) {
    let alice = token(ALICE, &[]);

    let (_, got) = call(
        &w.app,
        "GET",
        &format!("/v1/projects/{}", w.alice.0),
        &alice,
        None,
    )
    .await;
    let (s, v) = call(
        &w.app,
        "PATCH",
        &format!("/v1/projects/{}", w.alice.0),
        &alice,
        Some(json!({"name": "renamed"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v} {got}");
    let (s, _) = call(
        &w.app,
        "PATCH",
        &format!("/v1/projects/{}", w.bob.0),
        &alice,
        Some(json!({"name": "hacked"})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "not hers to change");

    // The project rule lists no `delete`; the task rule does.
    let (s, _) = call(
        &w.app,
        "DELETE",
        &format!("/v1/projects/{}", w.alice.0),
        &alice,
        None,
    )
    .await;
    assert!(
        s == StatusCode::FORBIDDEN || s == StatusCode::NOT_FOUND,
        "{s}"
    );
    let (s, _) = call(
        &w.app,
        "DELETE",
        &format!("/v1/tasks/{}", w.bob.1),
        &alice,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(
        &w.app,
        "DELETE",
        &format!("/v1/tasks/{}", w.alice.1),
        &alice,
        None,
    )
    .await;
    assert!(s == StatusCode::NO_CONTENT || s == StatusCode::OK, "{s}");

    // Bob's project is untouched.
    let bob = token(BOB, &[]);
    let (_, p) = call(
        &w.app,
        "GET",
        &format!("/v1/projects/{}", w.bob.0),
        &bob,
        None,
    )
    .await;
    assert_eq!(p["name"], "project B");
}

fn errors(project_policy: &str, task_policy: &str) -> Vec<String> {
    let (_, diags) = compile(&files(project_policy, task_policy), "0.0.0");
    diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.to_string())
        .collect()
}

#[test]
fn bad_relationship_rules_are_build_errors() {
    let rule = |actions: &str, allow: &str| {
        format!(
            "schema_version: 1\nentity: task\nrules:\n  - id: r\n    actions: {actions}\n    allow: {allow}\n"
        )
    };
    let bad = [
        (
            "no such relation",
            rule("[read]", "{ owner: true, related: nope }"),
        ),
        (
            "end has no owner",
            rule("[read]", "{ owner: true, related: project }"),
        ),
        (
            "on create",
            rule("[create]", "{ owner: true, related: project.workspace }"),
        ),
        (
            "not with a role",
            rule("[read]", "{ role: staff, related: project.workspace }"),
        ),
        (
            "too deep",
            rule("[read]", "{ owner: true, related: project.workspace.a.b }"),
        ),
    ];
    for (name, policy) in bad {
        assert!(!errors(PROJECT_POLICY, &policy).is_empty(), "{name}");
    }
    assert!(errors(PROJECT_POLICY, TASK_POLICY).is_empty());
}

/// The same two scenarios on PostgreSQL 16, each in a database of its own. Runs when
/// `FALAK_TEST_PG_ADMIN_URL` names a server and a role that may create databases.
#[tokio::test]
async fn the_same_rules_hold_on_postgresql() {
    use falak_contracts::driver::Statement;
    use falak_driver_postgres::{PostgresConfig, PostgresDriver};

    let Ok(admin_url) = std::env::var("FALAK_TEST_PG_ADMIN_URL") else {
        eprintln!("skipped: FALAK_TEST_PG_ADMIN_URL is not set");
        return;
    };
    let open = |url: String| async move {
        PostgresDriver::open(PostgresConfig {
            url,
            ..PostgresConfig::default()
        })
        .await
        .unwrap()
    };
    let admin = open(admin_url.clone()).await;
    let ctx = RequestContext {
        principal: None,
        request_id: "t".into(),
    };
    let (base, _) = admin_url.rsplit_once('/').unwrap();
    for (name, scenario) in [("reads", 0), ("writes", 1)] {
        let db = format!("related_{name}_{}", std::process::id());
        use falak_contracts::driver::StorageDriver as _;
        admin
            .batch(
                &ctx,
                vec![Statement::new(format!("CREATE DATABASE \"{db}\""), vec![])],
            )
            .await
            .unwrap();
        let driver = open(format!("{base}/{db}")).await;
        let w = world_on(app_on(Arc::new(driver)).await).await;
        if scenario == 0 {
            reads(w).await;
        } else {
            writes(w).await;
        }
    }
}
