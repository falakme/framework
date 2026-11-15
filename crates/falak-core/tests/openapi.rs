//! The OpenAPI document generated for the Notebook example.

use std::{fs, path::Path};

use falak_core::{compile::compile, load::SourceFile, openapi::generate};
use serde_json::Value;

fn notebook_files() -> Vec<SourceFile> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/notebook");
    let mut files = vec![SourceFile {
        path: "app.yaml".into(),
        text: fs::read_to_string(root.join("app.yaml")).unwrap(),
    }];
    for dir in ["entities", "policies", "commands"] {
        for entry in fs::read_dir(root.join(dir)).unwrap() {
            let entry = entry.unwrap();
            files.push(SourceFile {
                path: format!("{dir}/{}", entry.file_name().to_string_lossy()),
                text: fs::read_to_string(entry.path()).unwrap(),
            });
        }
    }
    files
}

fn document() -> Value {
    let (compiled, diagnostics) = compile(&notebook_files(), "0.0.0");
    let compiled = compiled.unwrap_or_else(|| panic!("notebook must compile: {diagnostics:?}"));
    generate(&compiled.ir)
}

/// Every `$ref` must point at something that exists.
fn check_refs(doc: &Value, node: &Value) {
    match node {
        Value::Object(map) => {
            if let Some(Value::String(r)) = map.get("$ref") {
                let pointer = r.strip_prefix('#').expect("local reference");
                assert!(doc.pointer(pointer).is_some(), "dangling reference {r}");
            }
            map.values().for_each(|v| check_refs(doc, v));
        }
        Value::Array(items) => items.iter().for_each(|v| check_refs(doc, v)),
        _ => {}
    }
}

#[test]
fn is_openapi_3_1_with_the_app_identity() {
    let doc = document();
    assert_eq!(doc["openapi"], "3.1.0");
    assert_eq!(doc["info"]["title"], "notebook");
    assert_eq!(doc["info"]["version"], "0.1.0");
    assert!(
        doc["info"]["x-falak-ir-hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
}

#[test]
fn every_reference_resolves() {
    let doc = document();
    check_refs(&doc, &doc);
}

#[test]
fn routes_follow_the_api_specification() {
    let doc = document();
    let paths = doc["paths"].as_object().unwrap();
    for p in [
        "/v1/notes",
        "/v1/notes/{id}",
        "/v1/notebooks",
        "/v1/notebooks/{id}",
        "/v1/notes/{id}/archive_note",
        "/v1/notes/{id}/restore_note",
    ] {
        assert!(paths.contains_key(p), "missing {p}");
    }
    let list = &doc["paths"]["/v1/notes"]["get"];
    assert_eq!(list["operationId"], "list_notes");
    assert!(list["responses"]["200"].is_object());
    assert!(doc["paths"]["/v1/notes/{id}"]["patch"]["responses"]["412"].is_object());
}

#[test]
fn create_body_leaves_out_owner_and_built_in_fields() {
    let doc = document();
    let create = &doc["components"]["schemas"]["NoteCreate"];
    let props = create["properties"].as_object().unwrap();
    for set_by_server in ["id", "owner_id", "version", "created_at", "updated_at"] {
        assert!(!props.contains_key(set_by_server), "{set_by_server}");
    }
    assert!(props.contains_key("title") && props.contains_key("notebook_id"));
    let required: Vec<&str> = create["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(required.contains(&"title") && required.contains(&"notebook_id"));
    // `archived` has a default, so it is optional.
    assert!(!required.contains(&"archived"));
}

#[test]
fn command_takes_its_target_from_the_path() {
    let doc = document();
    let op = &doc["paths"]["/v1/notes/{id}/archive_note"]["post"];
    let body = &op["requestBody"]["content"]["application/json"]["schema"];
    assert!(body["properties"].as_object().unwrap().is_empty());
    let names: Vec<&str> = op["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["$ref"].as_str().unwrap())
        .collect();
    assert!(names.iter().any(|n| n.ends_with("IdempotencyKey")));
}

#[test]
fn output_is_stable() {
    assert_eq!(document(), document());
}
