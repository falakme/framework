use falak_contracts::{driver::Value, ir::*};
use falak_core::{
    build::build_ir,
    ddl,
    load::{SourceFile, load_project},
    policy::Access,
    sql::*,
    values::parse_uuid,
};

const USER: &str = "11111111-1111-4111-8111-111111111111";
const TENANT: &str = "22222222-2222-4222-8222-222222222222";
const NOTE: [u8; 16] = [7; 16];

fn ir_with(tenancy: &str) -> Ir {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let files = vec![
        f(
            "app.yaml",
            &include_str!("../../../specifications/examples/minimal/app.yaml")
                .replace("tenancy: none", &format!("tenancy: {tenancy}")),
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
    build_ir(&load_project(&files).0.unwrap())
}

fn owner() -> Access {
    Access::OwnedBy(USER.into())
}

fn scope() -> Scope {
    Scope {
        tenant: Some(TENANT.into()),
        subject: Some(USER.into()),
    }
}

fn req<'a>(ir: &'a Ir, dialect: Dialect, access: &'a Access, scope: &'a Scope) -> Request<'a> {
    Request {
        ir,
        entity: ir.entity("note").unwrap(),
        dialect,
        access,
        scope,
    }
}

fn wctx() -> WriteContext {
    WriteContext {
        now_micros: 1_000,
        new_id: [9; 16],
    }
}

fn uuid(s: &str) -> Value {
    Value::Uuid(parse_uuid(s).unwrap())
}

#[test]
fn get_restricts_to_the_owner_and_skips_soft_deleted_rows() {
    let ir = ir_with("none");
    let sc = scope();
    let st = get(req(&ir, Dialect::Sqlite, &owner(), &sc), NOTE)
        .unwrap()
        .unwrap();
    assert!(st.sql.starts_with(
        "SELECT \"id\", \"title\", \"body\", \"archived\", \"owner_id\", \"version\""
    ));
    assert!(st.sql.contains("\"deleted_at\" IS NULL"));
    assert!(st.sql.contains("\"owner_id\" = ?1"));
    assert!(st.sql.contains("\"id\" = ?2"));
    assert_eq!(st.params, vec![uuid(USER), Value::Uuid(NOTE)]);
}

#[test]
fn unrestricted_access_has_no_owner_predicate_and_postgres_uses_dollar_params() {
    let ir = ir_with("none");
    let sc = scope();
    let st = get(
        req(&ir, Dialect::Postgres, &Access::Unrestricted, &sc),
        NOTE,
    )
    .unwrap()
    .unwrap();
    assert!(!st.sql.contains("owner_id\" ="));
    assert!(st.sql.contains("\"id\" = $1"));
}

#[test]
fn denied_access_runs_nothing() {
    let ir = ir_with("none");
    let sc = scope();
    let r = req(&ir, Dialect::Sqlite, &Access::Denied, &sc);
    assert!(get(r, NOTE).unwrap().is_none());
    assert!(list(r, &ListQuery::default()).unwrap().is_none());
    assert!(insert(r, &[], &wctx()).unwrap().is_none());
    assert!(
        update(
            r,
            NOTE,
            &[("title".into(), Value::Text("x".into()))],
            None,
            &wctx()
        )
        .unwrap()
        .is_none()
    );
    assert!(delete(r, NOTE, None, &wctx()).unwrap().is_none());
}

#[test]
fn row_tenancy_always_filters_by_tenant_and_refuses_without_one() {
    let ir = ir_with("row");
    let sc = scope();
    let st = get(req(&ir, Dialect::Sqlite, &Access::Unrestricted, &sc), NOTE)
        .unwrap()
        .unwrap();
    assert!(st.sql.contains("\"tenant_id\" = ?1"));
    assert_eq!(st.params[0], uuid(TENANT));
    let none = Scope {
        tenant: None,
        subject: Some(USER.into()),
    };
    assert!(
        get(
            req(&ir, Dialect::Sqlite, &Access::Unrestricted, &none),
            NOTE
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn list_builds_filters_sort_and_keyset_paging() {
    let ir = ir_with("none");
    let sc = scope();
    let q = ListQuery {
        filters: vec![
            Filter {
                field: "archived".into(),
                condition: Condition::Compare(Op::Eq, Value::Bool(false)),
            },
            Filter {
                field: "title".into(),
                condition: Condition::Compare(Op::Like, Value::Text("proj%".into())),
            },
        ],
        sort: vec![SortKey {
            field: "created_at".into(),
            descending: true,
        }],
        page_size: Some(5),
        after: Some(vec![Value::TimestampMicros(500), Value::Uuid(NOTE)]),
    };
    let plan = list(req(&ir, Dialect::Sqlite, &owner(), &sc), &q)
        .unwrap()
        .unwrap();
    assert_eq!(plan.fetch, 6);
    assert_eq!(plan.sort.last().unwrap().field, "id");
    let sql = &plan.statement.sql;
    assert!(sql.contains("\"archived\" = ?"));
    assert!(sql.contains("\"title\" LIKE ?"));
    assert!(sql.contains("(\"created_at\" < ?"), "{sql}");
    assert!(sql.contains("\"created_at\" = ?"), "{sql}");
    assert!(sql.contains("ORDER BY \"created_at\" DESC, \"id\" ASC LIMIT 6"));
}

#[test]
fn list_rejects_unsafe_or_unknown_requests() {
    let ir = ir_with("none");
    let sc = scope();
    let own = owner();
    let r = req(&ir, Dialect::Sqlite, &own, &sc);
    let code = |q: ListQuery| list(r, &q).unwrap_err().code();
    let eq = |f: &str| Filter {
        field: f.into(),
        condition: Condition::Compare(Op::Eq, Value::Text("x".into())),
    };
    assert_eq!(
        code(ListQuery {
            filters: vec![eq("nope")],
            ..Default::default()
        }),
        "invalid_filter"
    );
    assert_eq!(
        code(ListQuery {
            filters: vec![eq("title\"; DROP TABLE notes; --")],
            ..Default::default()
        }),
        "invalid_filter"
    );
    assert_eq!(
        code(ListQuery {
            filters: vec![eq("archived")],
            ..Default::default()
        }),
        "invalid_filter"
    ); // text value on a bool
    assert_eq!(
        code(ListQuery {
            sort: vec![SortKey {
                field: "body".into(),
                descending: false
            }],
            ..Default::default()
        }),
        "invalid_sort"
    ); // nullable
    assert_eq!(
        code(ListQuery {
            page_size: Some(101),
            ..Default::default()
        }),
        "invalid_page_size"
    );
    assert_eq!(
        code(ListQuery {
            page_size: Some(0),
            ..Default::default()
        }),
        "invalid_page_size"
    );
    let leading = Filter {
        field: "title".into(),
        condition: Condition::Compare(Op::Like, Value::Text("%x".into())),
    };
    assert_eq!(
        code(ListQuery {
            filters: vec![leading],
            ..Default::default()
        }),
        "invalid_filter"
    );
    let many = (0..11).map(|_| eq("title")).collect();
    assert_eq!(
        code(ListQuery {
            filters: many,
            ..Default::default()
        }),
        "invalid_filter"
    );
    assert_eq!(
        code(ListQuery {
            after: Some(vec![Value::Null]),
            ..Default::default()
        }),
        "invalid_cursor"
    );
}

#[test]
fn values_are_never_spliced_into_sql_and_d1_enforces_its_parameter_limit() {
    let ir = ir_with("none");
    let sc = scope();
    let evil = "x'; DROP TABLE notes; --";
    let q = ListQuery {
        filters: vec![Filter {
            field: "title".into(),
            condition: Condition::Compare(Op::Eq, Value::Text(evil.into())),
        }],
        ..Default::default()
    };
    let plan = list(req(&ir, Dialect::Sqlite, &owner(), &sc), &q)
        .unwrap()
        .unwrap();
    assert!(!plan.statement.sql.contains("DROP"));
    assert!(plan.statement.params.contains(&Value::Text(evil.into())));

    let ins = |n: usize| Filter {
        field: "title".into(),
        condition: Condition::In((0..n).map(|i| Value::Text(i.to_string())).collect()),
    };
    let q = ListQuery {
        filters: vec![ins(20), ins(20), ins(20), ins(20), ins(20)],
        ..Default::default()
    };
    assert_eq!(
        list(req(&ir, Dialect::D1, &owner(), &sc), &q)
            .unwrap_err()
            .code(),
        "too_many_parameters"
    );
    assert!(
        list(req(&ir, Dialect::Postgres, &owner(), &sc), &q)
            .unwrap()
            .is_some()
    );
}

#[test]
fn insert_sets_server_fields_and_owner() {
    let ir = ir_with("row");
    let sc = scope();
    let input = vec![("title".to_string(), Value::Text("Hello".into()))];
    let st = insert(req(&ir, Dialect::Sqlite, &owner(), &sc), &input, &wctx())
        .unwrap()
        .unwrap();
    assert!(st.sql.starts_with("INSERT INTO \"notes\""));
    assert!(st.sql.contains("RETURNING"));
    // default for `archived` applied, owner and tenant taken from the verified context
    assert!(st.params.contains(&Value::Bool(false)));
    assert!(st.params.contains(&uuid(USER)));
    assert!(st.params.contains(&uuid(TENANT)));
    assert!(st.params.contains(&Value::Uuid([9; 16])));
    assert!(st.params.contains(&Value::Int64(1)));
}

#[test]
fn insert_rejects_bad_input() {
    let ir = ir_with("none");
    let sc = scope();
    let own = owner();
    let r = req(&ir, Dialect::Sqlite, &own, &sc);
    let code = |input: Vec<(String, Value)>| insert(r, &input, &wctx()).unwrap_err().code();
    let t = |v: &str| ("title".to_string(), Value::Text(v.into()));
    assert_eq!(code(vec![]), "invalid_field"); // title required
    assert_eq!(
        code(vec![t("a"), ("id".into(), Value::Uuid([1; 16]))]),
        "invalid_field"
    ); // server-managed
    assert_eq!(
        code(vec![t("a"), ("owner_id".into(), uuid(USER))]),
        "invalid_field"
    ); // owner is server-set
    assert_eq!(
        code(vec![t("a"), ("nope".into(), Value::Bool(true))]),
        "invalid_field"
    );
    assert_eq!(code(vec![t(&"x".repeat(201))]), "invalid_field"); // max_length 200
    assert_eq!(code(vec![t("a"), t("b")]), "invalid_field"); // twice
    assert_eq!(code(vec![("title".into(), Value::Null)]), "invalid_field");
}

#[test]
fn an_unrestricted_writer_owns_what_they_create() {
    let ir = ir_with("none");
    let sc = scope();
    let input = vec![("title".to_string(), Value::Text("Hi".into()))];
    let st = insert(
        req(&ir, Dialect::Sqlite, &Access::Unrestricted, &sc),
        &input,
        &wctx(),
    )
    .unwrap()
    .unwrap();
    assert!(st.params.contains(&uuid(USER)));
}

#[test]
fn update_bumps_version_and_can_require_a_matching_version() {
    let ir = ir_with("none");
    let sc = scope();
    let own = owner();
    let r = req(&ir, Dialect::Sqlite, &own, &sc);
    let ch = vec![("title".to_string(), Value::Text("New".into()))];
    let st = update(r, NOTE, &ch, Some(3), &wctx()).unwrap().unwrap();
    assert!(st.sql.starts_with(
        "UPDATE \"notes\" SET \"title\" = ?1, \"version\" = \"version\" + ?2, \"updated_at\" = ?3"
    ));
    assert!(st.sql.contains("\"version\" = ?"));
    assert!(st.sql.ends_with(&format!(
        "RETURNING {}",
        st.sql.split("RETURNING ").nth(1).unwrap()
    )));
    assert!(st.params.contains(&Value::Int64(3)));
    for bad in ["id", "version", "owner_id", "created_at", "nope"] {
        let e = update(
            r,
            NOTE,
            &[(bad.to_string(), Value::Int64(1))],
            None,
            &wctx(),
        )
        .unwrap_err();
        assert_eq!(e.code(), "invalid_field", "{bad}");
    }
    assert!(update(r, NOTE, &[], None, &wctx()).is_err());
}

#[test]
fn delete_is_soft_when_configured_and_hard_otherwise() {
    let mut ir = ir_with("none");
    let sc = scope();
    let st = delete(
        req(&ir, Dialect::Sqlite, &owner(), &sc),
        NOTE,
        None,
        &wctx(),
    )
    .unwrap()
    .unwrap();
    assert!(
        st.sql
            .starts_with("UPDATE \"notes\" SET \"deleted_at\" = ?1, \"updated_at\" = ?1")
    );
    ir.entities[0].soft_delete = false;
    ir.entities[0].fields.retain(|f| f.name != "deleted_at");
    let st = delete(
        req(&ir, Dialect::Sqlite, &owner(), &sc),
        NOTE,
        None,
        &wctx(),
    )
    .unwrap()
    .unwrap();
    assert!(st.sql.starts_with("DELETE FROM \"notes\" WHERE"));
}

#[test]
fn ddl_follows_the_type_mapping() {
    let ir = ir_with("row");
    let sqlite = ddl::create_all(&ir, Dialect::Sqlite).join(";\n");
    assert!(sqlite.contains("\"id\" TEXT PRIMARY KEY"));
    assert!(sqlite.contains("\"created_at\" INTEGER NOT NULL"));
    assert!(sqlite.contains("\"archived\" INTEGER CHECK (\"archived\" IN (0, 1))"));
    assert!(sqlite.contains("CHECK (length(\"title\") <= 200)"));
    assert!(sqlite.contains("CREATE INDEX IF NOT EXISTS \"idx_notes_owner_id\" ON \"notes\" (\"tenant_id\", \"owner_id\")"));
    let pg = ddl::create_all(&ir, Dialect::Postgres).join(";\n");
    assert!(pg.contains("\"id\" uuid PRIMARY KEY"));
    assert!(pg.contains("\"created_at\" timestamptz NOT NULL"));
    assert!(pg.contains("\"archived\" boolean"));
    assert!(pg.contains("char_length(\"title\")"));
}
