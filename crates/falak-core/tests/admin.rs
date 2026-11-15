//! `admin:` presentation metadata reaches the IR (T4.2). Studio reads it from there.

use falak_core::{compile::compile, diagnostics::Severity, load::SourceFile};

const APP: &str = "schema_version: 1\nname: docs\nversion: 0.1.0\ntenancy: none\ntrust_tier: standard\ndrivers: [sqlite]\n";

fn files(admin: &str) -> Vec<SourceFile> {
    let entity = format!(
        "schema_version: 1\nentity: doc\nowner: owner_id\nfields:\n  title: {{ type: text, required: true, max_length: 200 }}\n  body: {{ type: text }}\n  secret: {{ type: text, encrypted: true }}\n  owner_id: {{ type: uuid, required: true }}\n{admin}"
    );
    let policy = "schema_version: 1\nentity: doc\nrules:\n  - id: mine\n    actions: [read]\n    allow: { owner: true }\n";
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    vec![
        f("app.yaml", APP),
        f("entities/doc.yaml", &entity),
        f("policies/doc.yaml", policy),
    ]
}

fn errors(admin: &str) -> Vec<String> {
    let (_, diags) = compile(&files(admin), "0.0.0");
    diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.code.to_string())
        .collect()
}

#[test]
fn label_columns_and_search_fields_are_in_the_ir() {
    let admin =
        "admin:\n  label: Documents\n  list_columns: [title, body]\n  search_fields: [title]\n";
    let (out, diags) = compile(&files(admin), "0.0.0");
    assert!(
        diags.iter().all(|d| d.severity != Severity::Error),
        "{diags:?}"
    );
    let ir = out.unwrap().ir;
    let a = &ir.entities[0].admin;
    assert_eq!(a.label.as_deref(), Some("Documents"));
    assert_eq!(a.list_columns, ["title", "body"]);
    assert_eq!(a.search_fields, ["title"]);

    // No `admin:` means empty metadata, which Studio fills with defaults.
    let (out, _) = compile(&files(""), "0.0.0");
    let ir = out.unwrap().ir;
    assert!(ir.entities[0].admin.label.is_none());
    assert!(ir.entities[0].admin.list_columns.is_empty());
}

#[test]
fn admin_metadata_cannot_name_missing_or_encrypted_fields() {
    assert!(!errors("admin:\n  list_columns: [nope]\n").is_empty());
    assert!(!errors("admin:\n  search_fields: [secret]\n").is_empty());
    assert!(!errors("admin:\n  label: x\n  colour: red\n").is_empty());
}
