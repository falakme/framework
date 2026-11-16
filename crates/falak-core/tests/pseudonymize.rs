use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
    pseudonymize::{Mapping, Pseudonymizer, Span, hmac_sha256, leaks, pii_fields, restore},
};
use serde_json::json;

fn span(kind: &str, start: usize, end: usize) -> Span {
    Span {
        kind: kind.into(),
        start,
        end,
    }
}

#[test]
fn tokens_are_stable_per_tenant_and_differ_across_tenants_and_keys() {
    let a = Pseudonymizer::new(b"operator-secret-key", "acme");
    let b = Pseudonymizer::new(b"operator-secret-key", "globex");
    let c = Pseudonymizer::new(b"another-secret-key!", "acme");
    let t = a.token("EMAIL", "jane@example.com");
    assert_eq!(t, a.token("email", " jane@example.com "));
    assert_ne!(t, b.token("EMAIL", "jane@example.com"));
    assert_ne!(t, c.token("EMAIL", "jane@example.com"));
    assert_ne!(t, a.token("EMAIL", "joe@example.com"));
    assert!(t.starts_with("EMAIL_") && t.len() == "EMAIL_".len() + 16);
    assert!(!t.contains("jane"));
}

#[test]
fn text_is_pseudonymized_and_restored() {
    let p = Pseudonymizer::new(b"operator-secret-key", "acme");
    let text = "Mail Jane <jane@example.com> or call +44 20 7946 0958. Jane again.";
    let spans = [
        span("EMAIL", 11, 27),
        span("PHONE", 38, 54),
        // Overlaps the email: ignored. Past the end: ignored. Empty: ignored.
        span("PERSON", 20, 30),
        span("PERSON", 1000, 1010),
        span("PERSON", 3, 3),
    ];
    let (out, mapping) = p.apply(text, &spans);
    assert!(!out.contains("jane@example.com") && !out.contains("7946"));
    assert!(out.contains("Mail Jane <EMAIL_"));
    assert_eq!(mapping.len(), 2);
    assert_eq!(restore(&out, &mapping), text);
    assert!(!leaks(&out, &mapping));
    assert!(leaks(text, &mapping));
}

#[test]
fn offsets_count_characters_not_bytes() {
    let p = Pseudonymizer::new(b"operator-secret-key", "");
    let (out, m) = p.apply("Ünal Çelik writes", &[span("PERSON", 0, 10)]);
    assert!(out.starts_with("PERSON_") && out.ends_with(" writes"));
    assert_eq!(m.values().next().unwrap(), "Ünal Çelik");
}

#[test]
fn schema_marked_fields_are_pseudonymized_in_a_row() {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let files = vec![
        f(
            "app.yaml",
            "schema_version: 1\nname: demo\nversion: 0.1.0\ntenancy: none\ntrust_tier: standard\ndrivers: [sqlite]\n",
        ),
        f(
            "entities/doc.yaml",
            "schema_version: 1\nentity: doc\nowner: owner_id\nfields:\n  title: { type: text }\n  body: { type: text, pii: true }\n  owner_id: { type: uuid, required: true }\n",
        ),
        f(
            "policies/doc.yaml",
            "schema_version: 1\nentity: doc\nrules:\n  - id: o\n    actions: [read]\n    allow: { owner: true }\n",
        ),
    ];
    let ir = build_ir(&load_project(&files).0.expect("valid"));
    let doc = ir.entity("doc").unwrap();
    assert_eq!(pii_fields(doc), vec!["body"]);
    let p = Pseudonymizer::new(b"operator-secret-key", "acme");
    let mut row = json!({"title": "Q3 review", "body": "Jane Smith, jane@example.com"});
    let m: Mapping = p.apply_row(doc, row.as_object_mut().unwrap());
    assert_eq!(row["title"], "Q3 review");
    assert!(row["body"].as_str().unwrap().starts_with("BODY_"));
    assert_eq!(m.values().next().unwrap(), "Jane Smith, jane@example.com");
}

#[test]
fn hmac_matches_rfc_4231_case_2() {
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}
