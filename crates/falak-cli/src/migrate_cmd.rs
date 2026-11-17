//! `falak migrate plan` and `falak migrate apply`.
//!
//! `plan` shows what bringing a database to this version of the app would run, with each
//! statement's lock impact and risk, and runs nothing. `apply` runs it as one atomic
//! batch under the migration lock, and records the schema it produced.
//!
//! SQLite files and PostgreSQL are reached directly. D1 is reached through Cloudflare:
//! `plan` reads the saved schema with `wrangler`, and a Worker applies its own migrations
//! when it starts, so on D1 `falak deploy` is the apply (`--allow-destructive` there
//! permits rebuilds and drops for that one deploy).

use std::{path::Path, process::Command};

use falak_contracts::{driver::StorageDriver, identity::RequestContext, ir::Ir};
use falak_core::sql::Dialect;
use falak_driver_postgres::{PostgresConfig, PostgresDriver};
use falak_driver_sqlite::{SqliteConfig, SqliteDriver};
use falak_migrate::{
    Destructiveness, MigrateOptions, MigrationPhase, MigrationPlan, migrate, plan_migration,
    plan_to,
};

use crate::project;

pub struct Options {
    pub driver: Option<String>,
    pub database_url: Option<String>,
    pub allow_destructive: bool,
    pub apply: bool,
    pub account: Option<String>,
    pub name: Option<String>,
}

fn ctx() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "falak-migrate".into(),
    }
}

enum Target {
    Sqlite(String),
    Postgres(String),
    D1,
}

fn target(dir: &Path, o: &Options) -> Result<Target, String> {
    let url = o
        .database_url
        .clone()
        .or_else(|| std::env::var("DATABASE_URL").ok());
    match o.driver.as_deref() {
        Some("d1") => Ok(Target::D1),
        Some("postgres") => url
            .map(Target::Postgres)
            .ok_or_else(|| "`--driver postgres` needs `--database-url` or DATABASE_URL".into()),
        Some("sqlite") => Ok(Target::Sqlite(
            o.database_url
                .clone()
                .unwrap_or_else(|| default_sqlite(dir)),
        )),
        Some(other) => Err(format!("`{other}` is not a driver (sqlite, postgres, d1)")),
        None => match url {
            Some(u) if u.starts_with("postgres://") || u.starts_with("postgresql://") => {
                Ok(Target::Postgres(u))
            }
            _ => Ok(Target::Sqlite(default_sqlite(dir))),
        },
    }
}

fn default_sqlite(dir: &Path) -> String {
    format!(
        "sqlite://{}",
        project::out_dir(dir).join("data.db").display()
    )
}

fn print_plan(plan: &MigrationPlan, dialect: Dialect) {
    println!(
        "from {} to {} ({dialect:?})",
        plan.from_hash
            .as_deref()
            .map_or("(empty database)", |h| &h[..12.min(h.len())]),
        &plan.to_hash[..12.min(plan.to_hash.len())]
    );
    if plan.statements.is_empty() {
        println!("nothing to do");
    }
    for (phase, label) in [
        (MigrationPhase::Expand, "expand"),
        (MigrationPhase::Contract, "contract"),
    ] {
        let list: Vec<_> = plan
            .statements
            .iter()
            .filter(|s| s.phase == phase)
            .collect();
        if list.is_empty() {
            continue;
        }
        println!("{label}:");
        for s in list {
            let risk = match s.destructiveness {
                Destructiveness::Safe => "safe",
                Destructiveness::Caution => "CAUTION",
                Destructiveness::Breaking => "BREAKING",
            };
            println!("  [{risk:<8}] [{:?}] {}", s.lock_impact, s.description);
            for line in s.sql.lines() {
                println!("      {line}");
            }
        }
    }
    for u in &plan.unsupported {
        println!("CANNOT PLAN: {u}");
    }
    println!("checksum {}", plan.checksum);
}

async fn show_or_apply<D: StorageDriver>(
    driver: &D,
    ir: &Ir,
    dialect: Dialect,
    o: &Options,
) -> Result<u8, String> {
    if o.apply {
        let out = migrate(
            driver,
            &ctx(),
            ir,
            MigrateOptions {
                allow_destructive: o.allow_destructive,
            },
        )
        .await
        .map_err(|e| e.public_message().to_owned())?;
        if out.applied {
            print_plan(&out.plan, dialect);
            println!("applied");
        } else {
            println!("already up to date");
        }
        return Ok(0);
    }
    let plan = plan_to(driver, &ctx(), ir)
        .await
        .map_err(|e| e.public_message().to_owned())?;
    print_plan(&plan, dialect);
    Ok(u8::from(!plan.unsupported.is_empty()))
}

pub fn run(dir: &Path, o: &Options) -> Result<u8, String> {
    let Some(compiled) = project::build(dir)? else {
        return Ok(1);
    };
    let ir = compiled.ir;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the async runtime: {e}"))?;
    runtime.block_on(async {
        match target(dir, o)? {
            Target::Sqlite(url) => {
                if let Some(path) = url.strip_prefix("sqlite://")
                    && let Some(parent) = Path::new(path).parent()
                {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                let driver = SqliteDriver::open(SqliteConfig {
                    url,
                    ..SqliteConfig::default()
                })
                .await
                .map_err(|e| format!("cannot open the database: {}", e.public_message()))?;
                show_or_apply(&driver, &ir, Dialect::Sqlite, o).await
            }
            Target::Postgres(url) => {
                let driver = PostgresDriver::open(PostgresConfig {
                    url,
                    ..PostgresConfig::default()
                })
                .await
                .map_err(|e| format!("cannot open the database: {}", e.public_message()))?;
                show_or_apply(&driver, &ir, Dialect::Postgres, o).await
            }
            Target::D1 => d1(dir, &ir, o),
        }
    })
}

/// D1: read the schema the Worker saved, then plan against it.
fn d1(dir: &Path, ir: &Ir, o: &Options) -> Result<u8, String> {
    if o.apply {
        println!(
            "On D1 the Worker applies its own migrations when it starts. Run `falak deploy{}` to apply this one.",
            if o.allow_destructive {
                " --allow-destructive"
            } else {
                ""
            }
        );
        return Ok(0);
    }
    // The same cleaning `falak deploy` applies, so the name cannot be read as a wrangler option.
    let name = crate::deploy::worker_name(o.name.as_deref().unwrap_or(&ir.app.name));
    if name.is_empty() {
        return Err("the app name cannot be used as a Worker name; pass one with --name".into());
    }
    let account = crate::deploy::resolve_account(o.account.as_deref())?;
    let database = format!("{name}-db");
    let mut cmd = Command::new("npx");
    cmd.args([
        "--yes",
        "wrangler@4",
        "d1",
        "execute",
        &database,
        "--remote",
        "--json",
        "--command",
        "SELECT ir FROM _falak_schema ORDER BY applied_at DESC LIMIT 1",
    ])
    .current_dir(project::out_dir(dir).parent().unwrap_or(dir));
    if let Some(a) = account.as_deref() {
        cmd.env("CLOUDFLARE_ACCOUNT_ID", a);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("cannot run wrangler: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let previous: Option<Ir> = text
        .find('[')
        .and_then(|i| serde_json::from_str::<serde_json::Value>(&text[i..]).ok())
        .and_then(|v| v[0]["results"][0]["ir"].as_str().map(str::to_owned))
        .and_then(|s| serde_json::from_str(&s).ok());
    if previous.is_none() && !out.status.success() {
        println!("(no saved schema found in `{database}`: planning from an empty database)");
    }
    let plan = plan_migration(previous.as_ref(), ir, Dialect::D1);
    print_plan(&plan, Dialect::D1);
    Ok(u8::from(!plan.unsupported.is_empty()))
}
