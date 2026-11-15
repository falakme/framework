use falak_contracts::ir::*;
use falak_core::{
    build::{build_ir, verify_hash},
    load::{SourceFile, load_project},
    lock,
};

fn minimal() -> Vec<SourceFile> {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    vec![
        f(
            "app.yaml",
            include_str!("../../../specifications/examples/minimal/app.yaml"),
        ),
        f(
            "entities/note.yaml",
            include_str!("../../../specifications/examples/minimal/entities/note.yaml"),
        ),
        f(
            "policies/note.yaml",
            include_str!("../../../specifications/examples/minimal/policies/note.yaml"),
        ),
        f(
            "commands/archive_note.yaml",
            include_str!("../../../specifications/examples/minimal/commands/archive_note.yaml"),
        ),
    ]
}

fn build(files: &[SourceFile]) -> Ir {
    build_ir(&load_project(files).0.expect("minimal example is valid"))
}

#[test]
fn building_twice_gives_the_same_hash_regardless_of_file_order() {
    let a = build(&minimal());
    let mut shuffled = minimal();
    shuffled.reverse();
    let b = build(&shuffled);
    assert_eq!(a.content_hash, b.content_hash);
    assert_eq!(a.content_hash.len(), 64);
    assert!(verify_hash(&a));
}

#[test]
fn any_change_changes_the_hash() {
    let mut files = minimal();
    let before = build(&files).content_hash;
    files[1].text = files[1].text.replace("max_length: 200", "max_length: 201");
    assert_ne!(before, build(&files).content_hash);
}

#[test]
fn tampering_is_detected() {
    let mut ir = build(&minimal());
    ir.entities[0].table = "other".into();
    assert!(!verify_hash(&ir));
}

#[test]
fn builtin_fields_are_resolved_in_order() {
    let ir = build(&minimal());
    let names: Vec<_> = ir
        .entity("note")
        .unwrap()
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "id",
            "title",
            "body",
            "archived",
            "owner_id",
            "version",
            "created_at",
            "updated_at",
            "deleted_at"
        ]
    );
    let note = ir.entity("note").unwrap();
    assert!(note.field("id").unwrap().builtin);
    assert!(!note.field("title").unwrap().nullable);
    assert!(note.field("deleted_at").unwrap().nullable);
}

#[test]
fn row_tenancy_adds_a_tenant_column() {
    let mut files = minimal();
    files[0].text = files[0].text.replace("tenancy: none", "tenancy: row");
    let ir = build(&files);
    let f = ir.entity("note").unwrap().field("tenant_id").unwrap();
    assert_eq!(f.ty, FieldType::Uuid);
    assert!(!f.nullable);
}

#[test]
fn an_entity_without_a_policy_has_no_rules() {
    let files: Vec<_> = minimal()
        .into_iter()
        .filter(|f| f.path != "policies/note.yaml")
        .collect();
    assert!(
        build(&files)
            .entity("note")
            .unwrap()
            .policy
            .rules
            .is_empty()
    );
}

#[test]
fn the_ir_round_trips_through_json() {
    let ir = build(&minimal());
    let back: Ir = serde_json::from_str(&serde_json::to_string(&ir).unwrap()).unwrap();
    assert_eq!(ir, back);
    assert!(verify_hash(&back));
}

#[test]
fn the_lock_file_records_the_hash_and_is_stable() {
    let files = minimal();
    let ir = build(&files);
    let a = lock::render(&ir, "0.0.0", &files);
    let mut rev = files.clone();
    rev.reverse();
    assert_eq!(a, lock::render(&ir, "0.0.0", &rev));
    assert_eq!(lock::recorded_ir_hash(&a), Some(ir.content_hash.as_str()));
    assert!(a.contains("\"entities/note.yaml\" = \"sha256:"));
}
