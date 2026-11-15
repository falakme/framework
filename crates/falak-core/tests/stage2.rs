//! Compiler checks for stage 2 policy keys (`where`, `fields`).

use falak_core::{compile::compile, diagnostics::Severity, load::SourceFile};

const APP: &str = "schema_version: 1\nname: docs\nversion: 0.1.0\ntenancy: none\ntrust_tier: standard\ndrivers: [sqlite]\n";
const ENTITY: &str = "schema_version: 1\nentity: doc\nowner: owner_id\nfields:\n  title: { type: text, required: true, max_length: 200 }\n  status: { type: text, required: true, max_length: 20 }\n  rank: { type: int64 }\n  secret: { type: text, encrypted: true }\n  owner_id: { type: uuid, required: true }\n";

fn files(rule: &str) -> Vec<SourceFile> {
    let policy = format!(
        "schema_version: 1\nentity: doc\nrules:\n  - id: r\n    actions: [read]\n    allow:\n{rule}"
    );
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    vec![
        f("app.yaml", APP),
        f("entities/doc.yaml", ENTITY),
        f("policies/doc.yaml", &policy),
    ]
}

fn errors(rule: &str) -> Vec<String> {
    let (_, diags) = compile(&files(rule), "0.0.0");
    diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.to_string())
        .collect()
}

#[test]
fn a_valid_condition_and_mask_compile() {
    let rule = "      role: reviewer\n      where:\n        status: published\n        rank: { in: [1, 2] }\n        title: { ne: hidden }\n        owner_id: $subject\n      fields: [title, status]\n";
    let (out, diags) = compile(&files(rule), "0.0.0");
    assert!(
        diags.iter().all(|d| d.severity != Severity::Error),
        "{diags:#?}"
    );
    let ir = out.unwrap().ir;
    let rule = &ir.entities[0].policy.rules[0];
    assert_eq!(rule.when.len(), 4);
    assert_eq!(
        rule.fields.as_deref(),
        Some(&["title".to_string(), "status".to_string()][..])
    );
}

#[test]
fn an_unknown_field_in_where_or_fields_is_an_error() {
    let e = errors("      authenticated: true\n      where: { nope: 1 }\n");
    assert!(e.iter().any(|m| m.contains("unknown_where_field")), "{e:?}");
    let e = errors("      authenticated: true\n      fields: [title, nope]\n");
    assert!(e.iter().any(|m| m.contains("unknown_mask_field")), "{e:?}");
}

#[test]
fn a_value_of_the_wrong_type_is_an_error() {
    let e = errors("      authenticated: true\n      where: { rank: banana }\n");
    assert!(e.iter().any(|m| m.contains("invalid_where")), "{e:?}");
    let e = errors("      authenticated: true\n      where: { status: 3 }\n");
    assert!(e.iter().any(|m| m.contains("invalid_where")), "{e:?}");
}

#[test]
fn encrypted_fields_cannot_be_compared() {
    let e = errors("      authenticated: true\n      where: { secret: x }\n");
    assert!(e.iter().any(|m| m.contains("invalid_where")), "{e:?}");
}

#[test]
fn an_unknown_variable_is_an_error() {
    let e = errors("      authenticated: true\n      where: { owner_id: $tenant }\n");
    assert!(e.iter().any(|m| m.contains("invalid_where")), "{e:?}");
}

#[test]
fn stage_one_apps_keep_their_ir_hash() {
    // Rules without `where` or `fields` serialise exactly as before.
    let rule = "      authenticated: true\n";
    let (out, _) = compile(&files(rule), "0.0.0");
    let json = serde_json::to_string(&out.unwrap().ir).unwrap();
    assert!(!json.contains("\"when\""));
    assert!(!json.contains("\"fields\":null"));
}
