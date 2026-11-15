use falak_core::{compile::compile, diagnostics::Severity, load::SourceFile};

fn files() -> Vec<SourceFile> {
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

fn errors(files: &[SourceFile]) -> Vec<String> {
    let (out, diags) = compile(files, "0.0.0");
    assert!(out.is_none());
    diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.to_string())
        .collect()
}

#[test]
fn the_minimal_app_compiles_for_all_three_drivers() {
    let (out, diags) = compile(&files(), "0.0.0");
    assert!(diags.is_empty(), "{diags:#?}");
    let c = out.unwrap();
    assert_eq!(c.ir.app.drivers, ["d1", "postgres", "sqlite"]);
    assert!(
        c.lock
            .contains(&format!("ir_hash = \"sha256:{}\"", c.ir.content_hash))
    );
}

#[test]
fn a_custom_command_cannot_target_d1() {
    let mut f = files();
    f.push(SourceFile {
        path: "commands/merge_notes.yaml".into(),
        text: "schema_version: 1\ncommand: merge_notes\nentity: note\nkind: custom\nhandler: merge_notes\n".into(),
    });
    let e = errors(&f);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(
        e[0].contains("`d1` does not provide `interactive_transactions`"),
        "{}",
        e[0]
    );
    assert!(e[0].contains("custom command `merge_notes`"));
    assert!(e[0].contains("help: remove `d1` from `drivers`"));
    // dropping d1 from the targets makes it build
    f[0].text = f[0]
        .text
        .replace("[sqlite, postgres, d1]", "[sqlite, postgres]");
    assert!(compile(&f, "0.0.0").0.is_some());
}

#[test]
fn high_assurance_apps_cannot_target_d1_or_need_explicit_requirements_met() {
    let mut f = files();
    f[0].text = f[0]
        .text
        .replace("trust_tier: standard", "trust_tier: high_assurance");
    let e = errors(&f);
    assert!(
        e.iter()
            .any(|m| m.contains("`d1` does not provide `serializable_isolation`")),
        "{e:?}"
    );
    assert!(
        !e.iter()
            .any(|m| m.contains("`postgres`") || m.contains("`sqlite`"))
    );
}

#[test]
fn explicit_requires_are_checked() {
    let mut f = files();
    f[0].text.push_str("requires: [native_rls]\n");
    let e = errors(&f);
    assert!(
        e.iter()
            .any(|m| m.contains("`sqlite` does not provide `native_rls`")),
        "{e:?}"
    );
    assert!(
        e.iter()
            .any(|m| m.contains("`d1` does not provide `native_rls`"))
    );
}

#[test]
fn an_entity_wider_than_the_d1_parameter_limit_is_rejected() {
    let mut f = files();
    f.retain(|x| x.path != "commands/archive_note.yaml");
    let cols: String = (0..100)
        .map(|i| format!("  c{i}: {{ type: int64 }}\n"))
        .collect();
    f[1].text = format!(
        "schema_version: 1\nentity: note\nowner: owner_id\nfields:\n  owner_id: {{ type: uuid, required: true }}\n{cols}"
    );
    let e = errors(&f);
    assert!(
        e.iter()
            .any(|m| m.contains("max_bound_params") && m.contains("`d1` allows 100")),
        "{e:?}"
    );
}
