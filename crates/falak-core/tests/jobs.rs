use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
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

fn job(extra: &str) -> SourceFile {
    file(
        "jobs/scan.yaml",
        &format!(
            "schema_version: 1\njob: scan\ninput:\n  document_id: {{ type: uuid }}\nimage: example/scan:1\ncommand: [python, main.py]\n{extra}"
        ),
    )
}

#[test]
fn a_job_contract_compiles_into_the_ir_and_is_omitted_when_absent() {
    let base = build_ir(&load_project(&minimal()).0.unwrap());
    assert!(base.jobs.is_empty());
    assert!(!serde_json::to_string(&base).unwrap().contains("\"jobs\""));
    let mut f = minimal();
    f.push(job("egress: [api.example.com]\ntimeout_seconds: 90\n"));
    let (p, d) = load_project(&f);
    assert!(p.is_some(), "{d:?}");
    let ir = build_ir(&p.unwrap());
    assert_eq!(ir.jobs.len(), 1);
    assert_eq!(ir.jobs[0].timeout_seconds, 90);
    assert_eq!(ir.jobs[0].max_attempts, 3);
    assert_eq!(ir.jobs[0].egress, vec!["api.example.com"]);
    assert_ne!(ir.content_hash, base.content_hash);
}

#[test]
fn a_bad_job_contract_is_rejected() {
    let mut f = minimal();
    f.push(job(
        "egress: [\"http://x.com/a\"]\nmemory_mb: 1\nsurprise: 1\n",
    ));
    let codes: Vec<&str> = load_project(&f).1.iter().map(|d| d.code).collect();
    assert!(codes.contains(&"invalid_egress"), "{codes:?}");
    assert!(codes.contains(&"out_of_range"));
    assert!(codes.contains(&"unknown_key"));
}
