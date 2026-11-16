//! Event contracts, sagas and the compatibility check (T5.1).

use falak_core::{compat, compile::compile, diagnostics::Severity, load::SourceFile};

fn f(p: &str, t: &str) -> SourceFile {
    SourceFile {
        path: p.into(),
        text: t.into(),
    }
}

const APP: &str = "schema_version: 1\nname: orders\nversion: 0.1.0\ntenancy: none\ntrust_tier: standard\ndrivers: [sqlite]\n";
const ENTITY: &str = "schema_version: 1\nentity: purchase\nfields:\n  item: { type: text, required: true }\n  qty: { type: int64, required: true }\n";
const POLICY: &str = "schema_version: 1\nentity: purchase\nrules:\n  - id: any\n    actions: [read, create]\n    allow: { authenticated: true }\n";

fn event(version: u32, fields: &str) -> String {
    format!(
        "schema_version: 1\nevent: order_placed\npublish:\n  entity: purchase\n  on: create\n  version: {version}\n  fields: [{fields}]\n  subscribers: [inventory]\n"
    )
}

fn files(event_text: &str) -> Vec<SourceFile> {
    vec![
        f("app.yaml", APP),
        f("entities/purchase.yaml", ENTITY),
        f("policies/purchase.yaml", POLICY),
        f("events/order_placed.yaml", event_text),
    ]
}

fn errors(files: &[SourceFile]) -> Vec<&'static str> {
    compile(files, "0.0.0")
        .1
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.code)
        .collect()
}

#[test]
fn a_published_event_reaches_the_ir_and_keeps_old_hashes() {
    let (out, d) = compile(&files(&event(1, "item, qty")), "0.0.0");
    assert!(d.iter().all(|d| d.severity != Severity::Error), "{d:?}");
    let ir = out.unwrap().ir;
    assert_eq!(ir.events.len(), 1);
    assert_eq!(ir.events[0].fields.len(), 2);
    assert_eq!(ir.events[0].subscribers, ["inventory"]);
    // An app without events has none of the new keys in its canonical JSON.
    let plain = compile(&files(&event(1, "item"))[..3], "0.0.0")
        .0
        .unwrap()
        .ir;
    let json = serde_json::to_string(&plain).unwrap();
    assert!(!json.contains("events") && !json.contains("sagas"));
}

#[test]
fn bad_events_are_rejected() {
    assert!(errors(&files(&event(1, "nope"))).contains(&"unknown_field"));
    let no_subs = event(1, "item").replace("subscribers: [inventory]", "subscribers: []");
    assert!(errors(&files(&no_subs)).contains(&"missing_subscribers"));
    let del = event(1, "item").replace("create", "delete");
    assert!(errors(&files(&del)).contains(&"invalid_event"));
}

#[test]
fn a_consumer_needs_a_create_handler() {
    let app = "schema_version: 1\nname: inventory\nversion: 0.1.0\ntenancy: none\ntrust_tier: standard\ndrivers: [sqlite]\n";
    let ent = "schema_version: 1\nentity: reservation\nfields:\n  order_ref: { type: uuid, required: true }\n";
    let cmd = "schema_version: 1\ncommand: reserve\nentity: reservation\nkind: create\ninput:\n  id: { type: uuid, required: true }\nset:\n  order_ref: $input.id\n";
    let consume = "schema_version: 1\nevent: order_placed\nconsume:\n  from: orders\n  version: 1\n  handler: reserve\n";
    let ok = vec![
        f("app.yaml", app),
        f("entities/reservation.yaml", ent),
        f("commands/reserve.yaml", cmd),
        f("events/order_placed.yaml", consume),
    ];
    assert!(errors(&ok).is_empty(), "{:?}", errors(&ok));
    let ir = compile(&ok, "0.0.0").0.unwrap().ir;
    assert_eq!(ir.subscriptions[0].from, "orders");
    let bad = consume.replace("reserve", "ghost");
    let mut v = ok.clone();
    v[3] = f("events/order_placed.yaml", &bad);
    assert!(errors(&v).contains(&"unknown_command"));
}

#[test]
fn sagas_load_and_must_start_on_a_published_event() {
    let saga = "schema_version: 1\nsaga: fulfil\nstart: order_placed\nsteps:\n  - name: reserve\n    command: inventory.reserve_stock\n    compensate: inventory.release_stock\n  - name: charge\n    command: billing.charge\n";
    let mut v = files(&event(1, "item"));
    v.push(f("workflows/fulfil.yaml", saga));
    let ir = compile(&v, "0.0.0").0.expect("compiles").ir;
    assert_eq!(ir.sagas[0].steps.len(), 2);
    assert_eq!(
        ir.sagas[0].steps[0].compensate.as_deref(),
        Some("inventory.release_stock")
    );
    let mut bad = files(&event(1, "item"));
    bad.push(f(
        "workflows/fulfil.yaml",
        &saga.replace("start: order_placed", "start: ghost"),
    ));
    assert!(errors(&bad).contains(&"unknown_event"));
    let mut bad = files(&event(1, "item"));
    bad.push(f(
        "workflows/fulfil.yaml",
        &saga.replace("inventory.reserve_stock", "reserve_stock"),
    ));
    assert!(errors(&bad).contains(&"invalid_name"));
}

#[test]
fn a_breaking_change_needs_a_version_bump() {
    let old = compile(&files(&event(1, "item, qty")), "0.0.0")
        .0
        .unwrap()
        .ir;
    // Adding a field is fine at the same version.
    let wider = compile(&files(&event(1, "item, qty")), "0.0.0")
        .0
        .unwrap()
        .ir;
    assert!(compat::check(&old, &wider).is_empty());
    // Dropping a field at the same version is not.
    let narrower = compile(&files(&event(1, "item")), "0.0.0").0.unwrap().ir;
    let problems = compat::check(&old, &narrower);
    assert_eq!(problems.len(), 1);
    assert!(problems[0].message.contains("Raise `version`"));
    // With a bump it is.
    let bumped = compile(&files(&event(2, "item")), "0.0.0").0.unwrap().ir;
    assert!(compat::check(&old, &bumped).is_empty());
    // Going back down, or removing the event, is not.
    assert!(!compat::check(&bumped, &narrower).is_empty());
    let mut gone = narrower.clone();
    gone.events.clear();
    assert!(!compat::check(&old, &gone).is_empty());
}
