use falak_core::{
    diagnostics::{Severity, has_errors},
    load::{SourceFile, load_project},
    schema::*,
};

fn file(path: &str, text: &str) -> SourceFile {
    SourceFile {
        path: path.into(),
        text: text.into(),
    }
}

fn minimal() -> Vec<SourceFile> {
    vec![
        file(
            "app.yaml",
            include_str!("../../../specifications/examples/minimal/app.yaml"),
        ),
        file(
            "entities/note.yaml",
            include_str!("../../../specifications/examples/minimal/entities/note.yaml"),
        ),
        file(
            "policies/note.yaml",
            include_str!("../../../specifications/examples/minimal/policies/note.yaml"),
        ),
        file(
            "commands/archive_note.yaml",
            include_str!("../../../specifications/examples/minimal/commands/archive_note.yaml"),
        ),
    ]
}

fn codes(files: &[SourceFile]) -> Vec<&'static str> {
    let (project, diags) = load_project(files);
    assert!(project.is_none(), "expected a failure, got {diags:?}");
    diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.code)
        .collect()
}

fn replace(files: &mut [SourceFile], path: &str, from: &str, to: &str) {
    let f = files.iter_mut().find(|f| f.path == path).unwrap();
    assert!(f.text.contains(from), "{from} not in {path}");
    f.text = f.text.replace(from, to);
}

#[test]
fn the_minimal_example_loads_cleanly() {
    let (project, diags) = load_project(&minimal());
    assert!(diags.is_empty(), "{diags:#?}");
    let p = project.unwrap();
    assert_eq!(p.app.name, "minimal");
    let note = p.entity("note").unwrap();
    assert_eq!(note.table, "notes");
    assert_eq!(note.owner.as_deref(), Some("owner_id"));
    assert_eq!(note.fields.len(), 4);
    assert!(note.lifecycle.soft_delete);
    assert_eq!(p.policy("note").unwrap().rules.len(), 2);
    assert_eq!(p.commands[0].kind, CommandKind::Update);
    assert_eq!(
        p.commands[0].set,
        vec![("archived".to_string(), SetValue::Bool(true))]
    );
}

#[test]
fn unknown_keys_get_a_did_you_mean() {
    let mut f = minimal();
    replace(
        &mut f,
        "entities/note.yaml",
        "required: true, max_length: 200",
        "requird: true, max_length: 200",
    );
    let (_, diags) = load_project(&f);
    let d = diags.iter().find(|d| d.code == "unknown_key").unwrap();
    assert_eq!(d.file, "entities/note.yaml");
    assert_eq!(d.position.line, 5);
    assert!(d.suggestion.as_deref().unwrap().contains("required"));
}

#[test]
fn a_float_type_is_rejected_with_help() {
    let mut f = minimal();
    replace(
        &mut f,
        "entities/note.yaml",
        "body: { type: text }",
        "body: { type: float }",
    );
    let (_, diags) = load_project(&f);
    let d = diags.iter().find(|d| d.code == "unknown_type").unwrap();
    assert!(d.suggestion.as_deref().unwrap().contains("no float type"));
}

#[test]
fn owner_rule_needs_an_owner_field() {
    let mut f = minimal();
    replace(&mut f, "entities/note.yaml", "owner: owner_id\n", "");
    assert!(codes(&f).contains(&"owner_without_owner_field"));
}

#[test]
fn file_name_must_match_the_entity() {
    let mut f = minimal();
    f[1].path = "entities/memo.yaml".into();
    assert!(codes(&f).contains(&"name_mismatch"));
}

#[test]
fn builtin_and_sql_names_are_reserved() {
    let mut f = minimal();
    replace(
        &mut f,
        "entities/note.yaml",
        "body: { type: text }",
        "id: { type: uuid }\n  order: { type: text }",
    );
    let c = codes(&f);
    assert_eq!(c.iter().filter(|c| **c == "reserved_name").count(), 2);
}

#[test]
fn encrypted_fields_cannot_be_indexed_or_listed() {
    let mut f = minimal();
    replace(
        &mut f,
        "entities/note.yaml",
        "body: { type: text }",
        "body: { type: text, encrypted: true, indexed: true }",
    );
    replace(
        &mut f,
        "entities/note.yaml",
        "list_columns: [title, archived]",
        "list_columns: [title, body]",
    );
    let c = codes(&f);
    assert!(c.contains(&"invalid_attribute"));
}

#[test]
fn commands_are_checked_against_their_entity() {
    let mut f = minimal();
    replace(
        &mut f,
        "commands/archive_note.yaml",
        "archived: true",
        "archivd: true",
    );
    assert!(codes(&f).contains(&"unknown_field"));

    let mut f = minimal();
    replace(
        &mut f,
        "commands/archive_note.yaml",
        "target: id",
        "target: nothing",
    );
    assert!(codes(&f).contains(&"unknown_input"));

    let mut f = minimal();
    replace(
        &mut f,
        "commands/archive_note.yaml",
        "archived: true",
        "owner_id: $input.id",
    );
    assert!(codes(&f).contains(&"server_managed_field"));

    let mut f = minimal();
    replace(
        &mut f,
        "commands/archive_note.yaml",
        "archived: true",
        "archived: 3",
    );
    assert!(codes(&f).contains(&"type_mismatch"));
}

#[test]
fn create_commands_must_set_required_fields() {
    let mut f = minimal();
    f.push(file(
        "commands/make_note.yaml",
        "schema_version: 1\ncommand: make_note\nentity: note\nkind: create\ninput:\n  body: { type: text }\nset:\n  body: $input.body\n",
    ));
    let (_, diags) = load_project(&f);
    let d = diags
        .iter()
        .find(|d| d.code == "missing_required_field")
        .unwrap();
    assert!(d.message.contains("title"));
}

#[test]
fn project_level_problems_are_reported() {
    // missing app.yaml
    let f: Vec<_> = minimal()
        .into_iter()
        .filter(|f| f.path != "app.yaml")
        .collect();
    assert!(codes(&f).contains(&"missing_app"));
    // reserved directory and stray files
    let mut f = minimal();
    f.push(file("events/x.yaml", "schema_version: 1\n"));
    f.push(file("notes.txt", "x"));
    let c = codes(&f);
    assert!(c.contains(&"reserved_directory") && c.contains(&"unexpected_file"));
    // unsupported version
    let mut f = minimal();
    replace(&mut f, "app.yaml", "schema_version: 1", "schema_version: 2");
    assert!(codes(&f).contains(&"unsupported_schema_version"));
}

#[test]
fn an_entity_without_a_policy_is_a_warning_not_an_error() {
    let f: Vec<_> = minimal()
        .into_iter()
        .filter(|f| f.path != "policies/note.yaml")
        .collect();
    let (project, diags) = load_project(&f);
    assert!(project.is_some());
    assert!(!has_errors(&diags));
    assert!(
        diags
            .iter()
            .any(|d| d.code == "no_policy" && d.severity == Severity::Warning)
    );
}

#[test]
fn relations_must_agree_with_references() {
    let mut f = minimal();
    f.push(file(
        "entities/tag.yaml",
        "schema_version: 1\nentity: tag\nfields:\n  note_id: { type: uuid, references: note.id }\n  label: { type: text }\n",
    ));
    replace(
        &mut f,
        "entities/note.yaml",
        "admin:",
        "relations:\n  tags: { kind: has_many, entity: tag, field: note_id }\nadmin:",
    );
    let (project, diags) = load_project(&f);
    assert!(project.is_some(), "{diags:#?}");
    // break the back-reference
    replace(&mut f, "entities/tag.yaml", ", references: note.id", "");
    assert!(codes(&f).contains(&"relation_mismatch"));
}
