use falak_contracts::{identity::Principal, ir::*};
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
    policy::{Access, authorize},
};

fn ir(drop_policy: bool) -> Ir {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let files = vec![
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
    ];
    let mut ir = build_ir(&load_project(&files).0.unwrap());
    if drop_policy {
        // The compiler refuses an owner-scoped entity with no policy, but the runtime
        // must still deny when an IR from elsewhere has none.
        for e in &mut ir.entities {
            e.policy.rules.clear();
        }
    }
    ir
}

fn who(subject: &str, roles: &[&str]) -> Principal {
    Principal {
        subject: subject.into(),
        tenant: None,
        roles: roles.iter().map(|r| r.to_string()).collect(),
    }
}

#[test]
fn an_entity_with_no_policy_denies_everything() {
    let ir = ir(true);
    let note = ir.entity("note").unwrap();
    for a in [
        IrAction::Read,
        IrAction::Create,
        IrAction::Update,
        IrAction::Delete,
    ] {
        assert_eq!(
            authorize(note, a, Some(&who("u1", &["admin"]))),
            Access::Denied
        );
    }
}

#[test]
fn anonymous_callers_are_denied() {
    let ir = ir(false);
    assert_eq!(
        authorize(ir.entity("note").unwrap(), IrAction::Read, None),
        Access::Denied
    );
}

#[test]
fn owners_get_their_own_rows_and_admins_read_all() {
    let ir = ir(false);
    let note = ir.entity("note").unwrap();
    let user = who("u1", &[]);
    for a in [
        IrAction::Read,
        IrAction::Create,
        IrAction::Update,
        IrAction::Delete,
    ] {
        assert_eq!(
            authorize(note, a, Some(&user)),
            Access::OwnedBy("u1".into())
        );
    }
    let admin = who("a1", &["admin"]);
    assert_eq!(
        authorize(note, IrAction::Read, Some(&admin)),
        Access::Unrestricted
    );
    // the admin rule covers read only; writes fall back to ownership
    assert_eq!(
        authorize(note, IrAction::Update, Some(&admin)),
        Access::OwnedBy("a1".into())
    );
}

#[test]
fn an_owner_rule_without_an_owner_field_fails_closed() {
    let mut ir = ir(false);
    ir.entities[0].owner = None;
    let user = who("u1", &[]);
    assert_eq!(
        authorize(&ir.entities[0], IrAction::Read, Some(&user)),
        Access::Denied
    );
}
