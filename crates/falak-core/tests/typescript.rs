//! The TypeScript client generated for the Notebook example.

use std::{fs, path::Path};

use falak_core::{compile::compile, load::SourceFile, typescript::generate};

fn notebook() -> String {
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
    let (compiled, diagnostics) = compile(&files, "0.0.0");
    generate(&compiled.unwrap_or_else(|| panic!("{diagnostics:?}")).ir)
}

#[test]
fn record_types_follow_the_ir() {
    let ts = notebook();
    assert!(ts.contains("export interface Note {"));
    assert!(ts.contains("  id: string;"));
    assert!(ts.contains("  title: string;"));
    assert!(ts.contains("  body: string | null;"));
    assert!(ts.contains("  archived: boolean | null;") || ts.contains("  archived: boolean;"));
    assert!(ts.contains("  version: number;"));
    assert!(ts.contains("  deleted_at: string | null;"));
}

#[test]
fn create_body_omits_owner_and_server_fields_and_marks_defaults_optional() {
    let ts = notebook();
    let create = ts
        .split("export interface NoteCreate {")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .unwrap();
    assert!(create.contains("title: string;"));
    assert!(create.contains("notebook_id: string;"));
    assert!(create.contains("archived?:"), "has a default, so optional");
    assert!(create.contains("body?:"), "nullable, so optional");
    let names: Vec<&str> = create
        .lines()
        .filter_map(|l| l.trim().split([':', '?']).next())
        .collect();
    for server_set in ["owner_id", "version", "created_at", "id"] {
        assert!(!names.contains(&server_set), "{server_set}");
    }
}

#[test]
fn commands_become_methods_and_the_client_has_one_property_per_entity() {
    let ts = notebook();
    assert!(ts.contains("archiveNote(id: string, options?: WriteOptions): Promise<Note>"));
    assert!(ts.contains("this.run(id, \"archive_note\", {}, options)"));
    assert!(ts.contains("readonly notes: NoteApi;"));
    assert!(ts.contains("readonly notebooks: NotebookApi;"));
    assert!(ts.contains("export function createClient(options: ClientOptions): NotebookClient"));
}

#[test]
fn output_is_stable() {
    assert_eq!(notebook(), notebook());
}
