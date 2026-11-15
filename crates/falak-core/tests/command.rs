use falak_contracts::{driver::Value, ir::Ir};
use falak_core::{
    build::build_ir,
    command::{Plan, plan},
    load::{SourceFile, load_project},
    policy::Access,
    sql::{Dialect, Request, Scope, WriteContext},
};

const USER: &str = "11111111-1111-4111-8111-111111111111";

fn ir() -> Ir {
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
        f(
            "commands/archive_note.yaml",
            include_str!("../../../specifications/examples/minimal/commands/archive_note.yaml"),
        ),
    ];
    build_ir(&load_project(&files).0.unwrap())
}

#[test]
fn archive_note_compiles_to_one_conditional_update() {
    let ir = ir();
    let sc = Scope {
        tenant: None,
        subject: Some(USER.into()),
    };
    let access = Access::OwnedBy(USER.into());
    let req = Request {
        ir: &ir,
        entity: ir.entity("note").unwrap(),
        dialect: Dialect::D1,
        access: &access,
        scope: &sc,
    };
    let ctx = WriteContext {
        now_micros: 5,
        new_id: [0; 16],
    };
    let cmd = &ir.commands[0];
    let id = [3u8; 16];
    let Plan::Run(st) = plan(req, cmd, &[("id".into(), Value::Uuid(id))], Some(4), &ctx).unwrap()
    else {
        panic!("expected a statement");
    };
    assert!(
        st.sql
            .starts_with("UPDATE \"notes\" SET \"archived\" = ?1, \"version\" = \"version\" + ?2")
    );
    assert!(st.sql.contains("\"version\" = ?"));
    assert!(st.params.contains(&Value::Bool(true)));
    assert!(st.params.contains(&Value::Int64(4)));
    assert!(st.params.contains(&Value::Uuid(id)));
}

#[test]
fn denied_access_plans_nothing_and_bad_input_is_rejected() {
    let ir = ir();
    let sc = Scope::default();
    let denied = Access::Denied;
    let req = Request {
        ir: &ir,
        entity: ir.entity("note").unwrap(),
        dialect: Dialect::Sqlite,
        access: &denied,
        scope: &sc,
    };
    let ctx = WriteContext {
        now_micros: 5,
        new_id: [0; 16],
    };
    let cmd = &ir.commands[0];
    assert_eq!(
        plan(req, cmd, &[("id".into(), Value::Uuid([3; 16]))], None, &ctx).unwrap(),
        Plan::Denied
    );
    assert_eq!(
        plan(req, cmd, &[], None, &ctx).unwrap_err().code(),
        "invalid_input"
    );
    assert_eq!(
        plan(
            req,
            cmd,
            &[("id".into(), Value::Text("x".into()))],
            None,
            &ctx
        )
        .unwrap_err()
        .code(),
        "invalid_input"
    );
    assert_eq!(
        plan(
            req,
            cmd,
            &[
                ("id".into(), Value::Uuid([3; 16])),
                ("zzz".into(), Value::Null)
            ],
            None,
            &ctx
        )
        .unwrap_err()
        .code(),
        "invalid_input"
    );
}
