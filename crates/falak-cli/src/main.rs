//! The `falak` command line.

mod args;
mod deploy;
mod doctor;
mod init;
mod migrate_cmd;
mod office_cmd;
mod policy_cmd;
mod project;
mod serve;
mod watch;

use std::{path::PathBuf, process::ExitCode};

use args::{Command, parse};

const USAGE: &str = "\
falak: build and run Falak apps

USAGE:
    falak <command> [directory] [options]

COMMANDS:
    init [dir] [--name <name>]   Create a new app (default: the current directory)
    check [dir]                  Validate the app and print diagnostics
    build [dir]                  Compile; write falak.lock and .falak/ir.json
    openapi [dir]                Write .falak/openapi.json
    sync [dir] [--out <file>]    Write the TypeScript client (default .falak/client.ts)
    serve [dir] [options]        Serve the app
    dev [dir] [options]          Serve, and rebuild and reload when a file changes
    deploy [dir] [options]       Publish to Cloudflare Workers with a D1 database
    tenant add [dir] --tenant <uuid> [--account <id>]
                                 Give a tenant a D1 database of its own (`tenancy: database`)
    policy explain [dir] --entity <e> [--action <a>] [--subject <id>] [--role <r>]...
                                 Show the decision, the matching rules and the SQL
    migrate plan [dir] [--driver <d>] [--database-url <u>]
                                 Show what bringing a database to this version would run
    migrate apply [dir] [--driver <d>] [--database-url <u>] [--allow-destructive]
                                 Run it, atomically, under the migration lock
    office enroll [dir] --office <url> --token <t> [--name <app>]
                                 Join the app to Falak Office (sign in once, many apps)
    office status [dir]          Check the link to Office
    office rotate-key --office <url> --email <e> --password-env <VAR> [--retire]
                                 Rotate Office's signing key (--retire drops the old one)
    doctor [dir] [--port <n>]    Check this machine and the app

OPTIONS:
    --port <n>     Port to listen on (default 8787)
    --name <name>  App name for `init`, or the Worker name for `deploy`
    --account <id> Cloudflare account for `deploy` (or CLOUDFLARE_ACCOUNT_ID)
    --jwks-url <u> `deploy`: verify tokens against this key set instead of signing them
    --issuer <iss> `deploy`: the `iss` of those tokens (needed with --jwks-url)
    -h, --help     Show this help
    -V, --version  Show the version
";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(
        args.command,
        &args.dir,
        args.port,
        args.name,
        args.out,
        deploy::Options {
            name: None,
            account: args.account,
            jwks_url: args.jwks_url,
            issuer: args.issuer,
            allow_destructive: args.extra.allow_destructive,
        },
        args.extra,
    ) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(
    command: Command,
    dir: &PathBuf,
    port: u16,
    name: Option<String>,
    out: Option<PathBuf>,
    mut deploy_options: deploy::Options,
    extra: args::Extra,
) -> Result<u8, String> {
    match command {
        Command::Help => {
            print!("{USAGE}");
            Ok(0)
        }
        Command::Version => {
            println!("falak {}", project::FRAMEWORK_VERSION);
            Ok(0)
        }
        Command::Init => {
            let name = match name {
                Some(n) => n,
                None => default_name(dir)?,
            };
            init::init(dir, &name)?;
            println!("Created app `{name}` in {}", dir.display());
            println!("Next: falak dev {}", dir.display());
            Ok(0)
        }
        Command::Check => {
            let outcome = project::compile_dir(dir)?;
            let (errors, warnings) = project::print_diagnostics(&outcome.diagnostics);
            if outcome.compiled.is_some() {
                println!("ok: {} files, {warnings} warning(s)", outcome.sources);
                Ok(0)
            } else {
                eprintln!("failed: {errors} error(s), {warnings} warning(s)");
                Ok(1)
            }
        }
        Command::Build => match project::build(dir)? {
            Some(c) => {
                println!(
                    "built {} {} (ir sha256:{})",
                    c.ir.app.name, c.ir.app.version, c.ir.content_hash
                );
                Ok(0)
            }
            None => Ok(1),
        },
        Command::Openapi => match project::build(dir)? {
            Some(c) => {
                let doc = falak_core::openapi::generate(&c.ir);
                let text = serde_json::to_string_pretty(&doc)
                    .map_err(|e| format!("cannot render the OpenAPI document: {e}"))?;
                let path = project::out_dir(dir).join("openapi.json");
                std::fs::write(&path, text)
                    .map_err(|e| format!("cannot write `{}`: {e}", path.display()))?;
                println!("wrote {}", path.display());
                Ok(0)
            }
            None => Ok(1),
        },
        Command::Sync => match project::build(dir)? {
            Some(c) => {
                let path = out.unwrap_or_else(|| project::out_dir(dir).join("client.ts"));
                if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("cannot create `{}`: {e}", parent.display()))?;
                }
                std::fs::write(&path, falak_core::typescript::generate(&c.ir))
                    .map_err(|e| format!("cannot write `{}`: {e}", path.display()))?;
                println!("wrote {}", path.display());
                Ok(0)
            }
            None => Ok(1),
        },
        Command::Doctor => {
            let checks = doctor::run(dir, port);
            let mut failed = false;
            for c in &checks {
                println!(
                    "{} {:<18} {}",
                    if c.ok { "ok  " } else { "FAIL" },
                    c.name,
                    c.detail
                );
                failed |= !c.ok;
            }
            Ok(u8::from(failed))
        }
        Command::Serve => serve::run(dir, port, false),
        Command::Dev => serve::run(dir, port, true),
        Command::PolicyExplain => policy_cmd::run(
            dir,
            &policy_cmd::Options {
                entity: extra.entity,
                action: extra.action,
                subject: extra.subject,
                roles: extra.roles,
                tenant: extra.tenant,
                dialect: extra.driver,
                anonymous: extra.anonymous,
            },
        ),
        Command::MigratePlan | Command::MigrateApply => migrate_cmd::run(
            dir,
            &migrate_cmd::Options {
                driver: extra.driver,
                database_url: extra.database_url,
                allow_destructive: extra.allow_destructive,
                apply: command == Command::MigrateApply,
                account: deploy_options.account.clone(),
                name,
            },
        ),
        Command::TenantAdd => {
            deploy_options.name = name;
            let tenant = extra.tenant.ok_or("`--tenant <uuid>` is required")?;
            deploy::add_tenant(dir, &deploy_options, &tenant)
        }
        Command::OfficeEnroll | Command::OfficeStatus | Command::OfficeRotateKey => {
            let options = office_cmd::Options {
                office: extra.office,
                token: extra.token,
                name: name.clone(),
                email: extra.email,
                password_env: extra.password_env,
                retire: extra.retire,
            };
            match command {
                Command::OfficeEnroll => {
                    let default = match &name {
                        Some(n) => n.clone(),
                        None => default_name(dir)?,
                    };
                    office_cmd::enroll(dir, &options, &default)
                }
                Command::OfficeStatus => office_cmd::status(dir),
                _ => office_cmd::rotate_key(&options),
            }
        }
        Command::Deploy => {
            deploy_options.name = name;
            deploy::run(dir, &deploy_options)
        }
    }
}

/// Name an app after its directory, turning anything that is not allowed in a name
/// into `-`.
fn default_name(dir: &PathBuf) -> Result<String, String> {
    let absolute = std::fs::canonicalize(dir)
        .or_else(|_| std::env::current_dir().map(|c| c.join(dir)))
        .map_err(|e| format!("cannot resolve `{}`: {e}", dir.display()))?;
    let raw = absolute
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('-').to_string();
    if init::valid_app_name(&cleaned) {
        Ok(cleaned)
    } else {
        Err(format!(
            "cannot use `{raw}` as an app name; pass one with --name"
        ))
    }
}
