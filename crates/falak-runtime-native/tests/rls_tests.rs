//! PostgreSQL row-level security, against a live database (T3.5).
//!
//! Needs a PostgreSQL superuser URL in `FALAK_TEST_PG_ADMIN_URL`; without it the tests
//! say so and pass. CI sets it. The statements here are raw SQL with none of the
//! runtime's predicates: the database alone has to refuse another tenant's rows.

use falak_contracts::{
    driver::{Statement, StorageDriver, Value},
    identity::{Principal, RequestContext},
};
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
};
use falak_driver_postgres::{PostgresConfig, PostgresDriver};
use falak_migrate::{MigrateOptions, migrate, rls::unprotected_tables_sql};

const APP: &str = "schema_version: 1\nname: rlsdocs\nversion: 0.1.0\ntenancy: row\ntrust_tier: standard\ndrivers: [postgres]\n";
const ENTITY: &str = "schema_version: 1\nentity: rlsdoc\nowner: owner_id\nfields:\n  title: { type: text, required: true, max_length: 200 }\n  owner_id: { type: uuid, required: true }\n";
const POLICY: &str = "schema_version: 1\nentity: rlsdoc\nrules:\n  - id: own\n    actions: [read, create, update, delete]\n    allow: { owner: true }\n  - id: auditors\n    actions: [read]\n    allow: { role: auditor }\n";

fn admin_url() -> Option<String> {
    std::env::var("FALAK_TEST_PG_ADMIN_URL").ok()
}

fn ctx(tenant: Option<&str>, subject: Option<&str>, roles: &[&str]) -> RequestContext {
    RequestContext {
        principal: subject.map(|s| Principal {
            subject: s.into(),
            tenant: tenant.map(str::to_owned),
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        }),
        request_id: "rls".into(),
    }
}

async fn open(url: &str) -> PostgresDriver {
    PostgresDriver::open(PostgresConfig {
        url: url.into(),
        ..PostgresConfig::default()
    })
    .await
    .unwrap()
}

fn uuid(n: u8) -> String {
    format!("00000000-0000-0000-0000-0000000000{n:02x}")
}

fn insert(tenant: &str, owner: &str, id: &str, title: &str) -> Statement {
    Statement::new(
        "INSERT INTO \"rlsdocs\" (\"id\",\"title\",\"owner_id\",\"tenant_id\",\"version\",\"created_at\",\"updated_at\") \
         VALUES ($1::uuid,$2,$3::uuid,$4::uuid,1,now(),now())",
        vec![
            Value::Text(id.into()),
            Value::Text(title.into()),
            Value::Text(owner.into()),
            Value::Text(tenant.into()),
        ],
    )
}

async fn titles(db: &PostgresDriver, c: &RequestContext) -> Vec<String> {
    // Raw SQL, no tenant or owner predicate: only the database stands in the way.
    let rows = db
        .query(
            c,
            Statement::new("SELECT \"title\" FROM \"rlsdocs\" ORDER BY 1", vec![]),
        )
        .await
        .unwrap();
    rows.rows
        .iter()
        .map(|r| match &r[0] {
            Value::Text(t) => t.clone(),
            other => panic!("{other:?}"),
        })
        .collect()
}

#[tokio::test]
async fn the_database_refuses_other_tenants_and_other_owners() {
    let Some(admin_url) = admin_url() else {
        eprintln!("skipped: FALAK_TEST_PG_ADMIN_URL is not set");
        return;
    };
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let (project, diags) = load_project(&[
        f("app.yaml", APP),
        f("entities/rlsdoc.yaml", ENTITY),
        f("policies/rlsdoc.yaml", POLICY),
    ]);
    assert!(!falak_core::diagnostics::has_errors(&diags), "{diags:?}");
    let ir = build_ir(&project.unwrap());

    // The owner role builds the schema and the policies.
    let admin = open(&admin_url).await;
    let admin_ctx = ctx(None, None, &[]);
    migrate(&admin, &admin_ctx, &ir, MigrateOptions::default())
        .await
        .unwrap();

    // The runtime connects as `falak_app`: no ownership, no BYPASSRLS.
    admin
        .batch(
            &admin_ctx,
            vec![Statement::new(
                "ALTER ROLE falak_app LOGIN PASSWORD 'falak_app_pw'",
                vec![],
            )],
        )
        .await
        .unwrap();
    let app_url = {
        let (scheme_user, rest) = admin_url.split_once('@').unwrap();
        let scheme = scheme_user.split("://").next().unwrap();
        format!("{scheme}://falak_app:falak_app_pw@{rest}")
    };
    let app = open(&app_url).await;

    // Conformance: every entity table has RLS enabled and forced, and the runtime role
    // is not a superuser and cannot bypass.
    let unprotected = admin
        .query(
            &admin_ctx,
            Statement::new(unprotected_tables_sql(&ir), vec![]),
        )
        .await
        .unwrap();
    assert!(unprotected.rows.is_empty(), "{:?}", unprotected.rows);
    let role = admin
        .query(
            &admin_ctx,
            Statement::new(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'falak_app'",
                vec![],
            ),
        )
        .await
        .unwrap();
    assert_eq!(role.rows[0], vec![Value::Bool(false), Value::Bool(false)]);

    // Fresh ids for each run.
    let run = (std::process::id() % 200) as u8;
    let (t1, t2) = (uuid(0xa0 + (run % 8)), uuid(0xb0 + (run % 8)));
    let (alice, bob) = (uuid(0xc1), uuid(0xc2));
    let tag = format!("run{}", std::process::id());
    let (id_a, id_b, id_c) = (
        format!(
            "{}-aaaa-4000-8000-0000000000a1",
            &format!("{:08x}", std::process::id())
        ),
        format!(
            "{}-bbbb-4000-8000-0000000000b1",
            &format!("{:08x}", std::process::id())
        ),
        format!(
            "{}-cccc-4000-8000-0000000000c1",
            &format!("{:08x}", std::process::id())
        ),
    );

    let as_alice_t1 = ctx(Some(&t1), Some(&alice), &[]);
    let as_bob_t1 = ctx(Some(&t1), Some(&bob), &[]);
    let as_bob_t2 = ctx(Some(&t2), Some(&bob), &[]);

    app.batch(
        &as_alice_t1,
        vec![insert(&t1, &alice, &id_a, &format!("{tag} alice t1"))],
    )
    .await
    .unwrap();
    app.batch(
        &as_bob_t2,
        vec![insert(&t2, &bob, &id_b, &format!("{tag} bob t2"))],
    )
    .await
    .unwrap();

    // Each caller sees only their own row.
    let mine = |all: Vec<String>| {
        all.into_iter()
            .filter(|t| t.starts_with(&tag))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        mine(titles(&app, &as_alice_t1).await),
        [format!("{tag} alice t1")]
    );
    assert_eq!(
        mine(titles(&app, &as_bob_t2).await),
        [format!("{tag} bob t2")]
    );
    // Same tenant, another owner: not visible.
    assert!(mine(titles(&app, &as_bob_t1).await).is_empty());
    // No principal: nothing, not an error.
    assert!(mine(titles(&app, &ctx(None, None, &[])).await).is_empty());

    // Writing into another tenant, or as another owner, fails the WITH CHECK.
    assert!(
        app.batch(
            &as_alice_t1,
            vec![insert(&t2, &alice, &id_c, "cross tenant")]
        )
        .await
        .is_err(),
        "a row for another tenant must be refused"
    );
    assert!(
        app.batch(
            &as_alice_t1,
            vec![insert(&t1, &bob, &id_c, "as someone else")]
        )
        .await
        .is_err(),
        "a row owned by someone else must be refused"
    );

    // An auditor reads every row of their own tenant, and nothing of another's.
    let auditor_t1 = ctx(Some(&t1), Some(&uuid(0xc9)), &["auditor"]);
    assert_eq!(
        mine(titles(&app, &auditor_t1).await),
        [format!("{tag} alice t1")]
    );
    // ... but may not change them.
    let changed = app
        .batch(
            &auditor_t1,
            vec![Statement::new(
                "UPDATE \"rlsdocs\" SET \"title\" = 'hijacked' WHERE \"title\" LIKE $1",
                vec![Value::Text(format!("{tag}%"))],
            )],
        )
        .await
        .unwrap();
    assert_eq!(changed[0].rows_affected, 0);

    // Another tenant cannot update or delete a row it cannot see.
    for sql in [
        "UPDATE \"rlsdocs\" SET \"title\" = 'x'",
        "DELETE FROM \"rlsdocs\"",
    ] {
        let out = app
            .batch(&as_bob_t1, vec![Statement::new(sql, vec![])])
            .await
            .unwrap();
        assert_eq!(out[0].rows_affected, 0, "{sql}");
    }
    assert_eq!(
        mine(titles(&app, &as_alice_t1).await),
        [format!("{tag} alice t1")]
    );
}
