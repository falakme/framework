//! Tenancy modes in the compiler (T3.1).

use falak_core::{compile::compile, diagnostics::Severity, load::SourceFile};

fn app(tenancy: &str, drivers: &str) -> String {
    format!(
        "schema_version: 1\nname: docs\nversion: 0.1.0\ntenancy: {tenancy}\ntrust_tier: standard\ndrivers: [{drivers}]\n"
    )
}

const ENTITY: &str = "schema_version: 1\nentity: doc\nfields:\n  title: { type: text, required: true, max_length: 200 }\n";
const OWNED: &str = "schema_version: 1\nentity: doc\nowner: owner_id\nfields:\n  title: { type: text, required: true, max_length: 200 }\n  owner_id: { type: uuid, required: true }\n";
const POLICY: &str = "schema_version: 1\nentity: doc\nrules:\n  - id: any\n    actions: [read]\n    allow: { authenticated: true }\n";

fn files(app_yaml: String, entity: &str, policy: Option<&str>) -> Vec<SourceFile> {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let mut v = vec![f("app.yaml", &app_yaml), f("entities/doc.yaml", entity)];
    if let Some(p) = policy {
        v.push(f("policies/doc.yaml", p));
    }
    v
}

fn codes(files: &[SourceFile], severity: Severity) -> Vec<String> {
    let (_, diags) = compile(files, "0.0.0");
    diags
        .iter()
        .filter(|d| d.severity == severity)
        .map(|d| d.to_string())
        .collect()
}

#[test]
fn database_tenancy_compiles_for_sqlite_and_d1_without_a_tenant_column() {
    let (out, diags) = compile(
        &files(app("database", "sqlite, d1"), ENTITY, Some(POLICY)),
        "0.0.0",
    );
    assert!(
        diags.iter().all(|d| d.severity != Severity::Error),
        "{diags:#?}"
    );
    let ir = out.unwrap().ir;
    assert!(ir.entities[0].field("tenant_id").is_none());
}

#[test]
fn row_tenancy_adds_a_tenant_column() {
    let (out, _) = compile(&files(app("row", "sqlite"), ENTITY, Some(POLICY)), "0.0.0");
    assert!(out.unwrap().ir.entities[0].field("tenant_id").is_some());
}

#[test]
fn database_tenancy_is_refused_on_postgres() {
    let e = codes(
        &files(app("database", "sqlite, postgres"), ENTITY, Some(POLICY)),
        Severity::Error,
    );
    assert!(e.iter().any(|m| m.contains("tenancy_unsupported")), "{e:?}");
}

#[test]
fn a_tenant_scoped_entity_without_a_policy_is_an_error() {
    for tenancy in ["row", "database"] {
        let e = codes(
            &files(app(tenancy, "sqlite"), ENTITY, None),
            Severity::Error,
        );
        assert!(
            e.iter().any(|m| m.contains("scoped_without_policy")),
            "{tenancy}: {e:?}"
        );
    }
}

#[test]
fn an_owned_entity_without_a_policy_is_an_error_even_without_tenancy() {
    let e = codes(&files(app("none", "sqlite"), OWNED, None), Severity::Error);
    assert!(
        e.iter().any(|m| m.contains("scoped_without_policy")),
        "{e:?}"
    );
}

#[test]
fn an_unscoped_entity_without_a_policy_is_only_a_warning() {
    let files = files(app("none", "sqlite"), ENTITY, None);
    assert!(codes(&files, Severity::Error).is_empty());
    let w = codes(&files, Severity::Warning);
    assert!(w.iter().any(|m| m.contains("no_policy")), "{w:?}");
}
