//! Command-line parsing. Hand-written: the grammar is small and this keeps the
//! dependency tree short.

use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Init,
    Check,
    Build,
    Openapi,
    Sync,
    Serve,
    Dev,
    Deploy,
    PolicyExplain,
    MigratePlan,
    MigrateApply,
    TenantAdd,
    OfficeEnroll,
    OfficeStatus,
    OfficeRotateKey,
    OfficeRotateCredential,
    Upgrade,
    BreakGlassRequest,
    BreakGlassApprove,
    BreakGlassClaim,
    BreakGlassList,
    LedgerInit,
    LedgerImport,
    LedgerReconcile,
    Doctor,
    Help,
    Version,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub command: Command,
    pub dir: PathBuf,
    pub port: u16,
    pub name: Option<String>,
    pub out: Option<PathBuf>,
    pub account: Option<String>,
    pub jwks_url: Option<String>,
    pub issuer: Option<String>,
    pub extra: Extra,
}

/// Options for `policy explain` and `migrate`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Extra {
    pub driver: Option<String>,
    pub database_url: Option<String>,
    pub allow_destructive: bool,
    pub entity: Option<String>,
    pub action: Option<String>,
    pub subject: Option<String>,
    pub roles: Vec<String>,
    pub tenant: Option<String>,
    pub anonymous: bool,
    pub office: Option<String>,
    pub token: Option<String>,
    pub email: Option<String>,
    pub password_env: Option<String>,
    pub retire: bool,
    pub to: Option<String>,
    pub apply: bool,
    pub reason: Option<String>,
    pub minutes: Option<u32>,
    pub id: Option<String>,
    pub app: Option<String>,
    pub tier: Option<u8>,
    pub statement: Option<PathBuf>,
    pub statement_id: Option<String>,
    pub ledger_account: Option<String>,
    pub app_role: Option<String>,
}

pub const DEFAULT_PORT: u16 = 8787;

pub fn parse(argv: &[String]) -> Result<Args, String> {
    let mut it = argv.iter();
    let command = match it.next().map(String::as_str) {
        None | Some("-h" | "--help" | "help") => Command::Help,
        Some("-V" | "--version" | "version") => Command::Version,
        Some("init") => Command::Init,
        Some("check") => Command::Check,
        Some("build") => Command::Build,
        Some("openapi") => Command::Openapi,
        Some("sync") => Command::Sync,
        Some("serve") => Command::Serve,
        Some("dev") => Command::Dev,
        Some("deploy") => Command::Deploy,
        Some("policy") => match it.next().map(String::as_str) {
            Some("explain") => Command::PolicyExplain,
            _ => return Err("`policy` needs a subcommand: explain".into()),
        },
        Some("tenant") => match it.next().map(String::as_str) {
            Some("add") => Command::TenantAdd,
            _ => return Err("`tenant` needs a subcommand: add".into()),
        },
        Some("migrate") => match it.next().map(String::as_str) {
            Some("plan") => Command::MigratePlan,
            Some("apply") => Command::MigrateApply,
            _ => return Err("`migrate` needs a subcommand: plan or apply".into()),
        },
        Some("office") => match it.next().map(String::as_str) {
            Some("enroll") => Command::OfficeEnroll,
            Some("status") => Command::OfficeStatus,
            Some("rotate-key") => Command::OfficeRotateKey,
            Some("rotate-credential") => Command::OfficeRotateCredential,
            _ => {
                return Err(
                    "`office` needs a subcommand: enroll, status, rotate-key or rotate-credential"
                        .into(),
                );
            }
        },
        Some("upgrade") => Command::Upgrade,
        Some("breakglass") => match it.next().map(String::as_str) {
            Some("request") => Command::BreakGlassRequest,
            Some("approve") => Command::BreakGlassApprove,
            Some("claim") => Command::BreakGlassClaim,
            Some("list") => Command::BreakGlassList,
            _ => {
                return Err(
                    "`breakglass` needs a subcommand: request, approve, claim or list".into(),
                );
            }
        },
        Some("ledger") => match it.next().map(String::as_str) {
            Some("init") => Command::LedgerInit,
            Some("import") => Command::LedgerImport,
            Some("reconcile") => Command::LedgerReconcile,
            _ => return Err("`ledger` needs a subcommand: init, import or reconcile".into()),
        },
        Some("doctor") => Command::Doctor,
        Some(other) => return Err(format!("unknown command `{other}`")),
    };
    let mut args = Args {
        command,
        dir: PathBuf::from("."),
        port: DEFAULT_PORT,
        name: None,
        out: None,
        account: None,
        jwks_url: None,
        issuer: None,
        extra: Extra::default(),
    };
    let mut dir_set = false;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--port" => {
                let v = it.next().ok_or("`--port` needs a value")?;
                args.port = v
                    .parse::<u16>()
                    .ok()
                    .filter(|p| *p != 0)
                    .ok_or_else(|| format!("`{v}` is not a valid port"))?;
            }
            "--name" => {
                args.name = Some(it.next().ok_or("`--name` needs a value")?.clone());
            }
            "--account" => {
                args.account = Some(it.next().ok_or("`--account` needs a value")?.clone());
            }
            "--driver" => {
                args.extra.driver = Some(it.next().ok_or("`--driver` needs a value")?.clone());
            }
            "--database-url" => {
                args.extra.database_url =
                    Some(it.next().ok_or("`--database-url` needs a value")?.clone());
            }
            "--allow-destructive" => args.extra.allow_destructive = true,
            "--anonymous" => args.extra.anonymous = true,
            "--entity" => {
                args.extra.entity = Some(it.next().ok_or("`--entity` needs a value")?.clone());
            }
            "--action" => {
                args.extra.action = Some(it.next().ok_or("`--action` needs a value")?.clone());
            }
            "--subject" => {
                args.extra.subject = Some(it.next().ok_or("`--subject` needs a value")?.clone());
            }
            "--role" => {
                args.extra
                    .roles
                    .push(it.next().ok_or("`--role` needs a value")?.clone());
            }
            "--tenant" => {
                args.extra.tenant = Some(it.next().ok_or("`--tenant` needs a value")?.clone());
            }
            "--office" => {
                args.extra.office = Some(it.next().ok_or("`--office` needs a value")?.clone());
            }
            "--token" => {
                args.extra.token = Some(it.next().ok_or("`--token` needs a value")?.clone());
            }
            "--email" => {
                args.extra.email = Some(it.next().ok_or("`--email` needs a value")?.clone());
            }
            "--password-env" => {
                args.extra.password_env =
                    Some(it.next().ok_or("`--password-env` needs a value")?.clone());
            }
            "--retire" => args.extra.retire = true,
            "--apply" => args.extra.apply = true,
            "--to" => args.extra.to = Some(it.next().ok_or("`--to` needs a value")?.clone()),
            "--reason" => {
                args.extra.reason = Some(it.next().ok_or("`--reason` needs a value")?.clone());
            }
            "--id" => args.extra.id = Some(it.next().ok_or("`--id` needs a value")?.clone()),
            "--app" => args.extra.app = Some(it.next().ok_or("`--app` needs a value")?.clone()),
            "--minutes" => {
                let v = it.next().ok_or("`--minutes` needs a value")?;
                args.extra.minutes = Some(
                    v.parse()
                        .map_err(|_| format!("`{v}` is not a number of minutes"))?,
                );
            }
            "--tier" => {
                let v = it.next().ok_or("`--tier` needs a value")?;
                args.extra.tier = Some(
                    v.parse()
                        .ok()
                        .filter(|t| (1..=3).contains(t))
                        .ok_or_else(|| format!("`{v}` is not a tier (1, 2 or 3)"))?,
                );
            }
            "--statement" => {
                args.extra.statement = Some(PathBuf::from(
                    it.next().ok_or("`--statement` needs a value")?,
                ));
            }
            "--statement-id" => {
                args.extra.statement_id =
                    Some(it.next().ok_or("`--statement-id` needs a value")?.clone());
            }
            "--ledger-account" => {
                args.extra.ledger_account =
                    Some(it.next().ok_or("`--ledger-account` needs a value")?.clone());
            }
            "--app-role" => {
                args.extra.app_role = Some(it.next().ok_or("`--app-role` needs a value")?.clone());
            }
            "--jwks-url" => {
                args.jwks_url = Some(it.next().ok_or("`--jwks-url` needs a value")?.clone());
            }
            "--issuer" => {
                args.issuer = Some(it.next().ok_or("`--issuer` needs a value")?.clone());
            }
            "--out" => {
                args.out = Some(PathBuf::from(it.next().ok_or("`--out` needs a value")?));
            }
            "-h" | "--help" => args.command = Command::Help,
            flag if flag.starts_with('-') => return Err(format!("unknown option `{flag}`")),
            path => {
                if dir_set {
                    return Err(format!("unexpected extra argument `{path}`"));
                }
                args.dir = PathBuf::from(path);
                dir_set = true;
            }
        }
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Args, String> {
        parse(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn defaults() {
        let a = p("dev").unwrap();
        assert_eq!(a.command, Command::Dev);
        assert_eq!(a.dir, PathBuf::from("."));
        assert_eq!(a.port, 8787);
    }

    #[test]
    fn dir_port_and_name() {
        let a = p("init my/app --name todo --port 9000").unwrap();
        assert_eq!(a.command, Command::Init);
        assert_eq!(a.dir, PathBuf::from("my/app"));
        assert_eq!(a.name.as_deref(), Some("todo"));
        assert_eq!(a.port, 9000);
    }

    #[test]
    fn office_commands() {
        let a = p("office enroll app --office https://o.test --token abc --name nb").unwrap();
        assert_eq!(a.command, Command::OfficeEnroll);
        assert_eq!(a.extra.office.as_deref(), Some("https://o.test"));
        assert_eq!(a.extra.token.as_deref(), Some("abc"));
        assert_eq!(a.name.as_deref(), Some("nb"));
        assert_eq!(p("office status").unwrap().command, Command::OfficeStatus);
        let r =
            p("office rotate-key --office https://o.test --email a@b.c --password-env PW --retire")
                .unwrap();
        assert_eq!(r.command, Command::OfficeRotateKey);
        assert!(r.extra.retire);
        assert_eq!(r.extra.password_env.as_deref(), Some("PW"));
    }

    #[test]
    fn upgrade_and_breakglass() {
        let a = p("upgrade app --apply --to 1.0.0").unwrap();
        assert_eq!(a.command, Command::Upgrade);
        assert!(a.extra.apply);
        assert_eq!(a.extra.to.as_deref(), Some("1.0.0"));
        let b = p("breakglass request --app x --reason r --minutes 20 --tier 3").unwrap();
        assert_eq!(b.command, Command::BreakGlassRequest);
        assert_eq!((b.extra.minutes, b.extra.tier), (Some(20), Some(3)));
        assert!(p("breakglass").is_err());
        assert!(p("breakglass request --tier 4").is_err());
    }

    #[test]
    fn no_arguments_shows_help() {
        assert_eq!(p("").unwrap().command, Command::Help);
        assert_eq!(p("check --help").unwrap().command, Command::Help);
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "frobnicate",
            "check --nope",
            "check a b",
            "serve --port",
            "serve --port 0",
            "serve --port 99999",
            "serve --port abc",
            "sync --out",
            "policy",
            "migrate",
            "migrate nope",
            "policy explain --entity",
            "deploy --account",
            "deploy --jwks-url",
            "deploy --issuer",
            "office",
            "office nope",
            "office enroll --office",
            "office enroll --token",
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
    }
}

#[cfg(test)]
mod ledger_tests {
    use super::*;

    #[test]
    fn ledger_subcommands() {
        let argv = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
        let a = parse(&argv(
            "ledger import --statement s.csv --statement-id st1 --ledger-account rail",
        ))
        .unwrap();
        assert_eq!(a.command, Command::LedgerImport);
        assert_eq!(a.extra.statement_id.as_deref(), Some("st1"));
        assert_eq!(a.extra.ledger_account.as_deref(), Some("rail"));
        assert_eq!(
            parse(&argv("ledger reconcile")).unwrap().command,
            Command::LedgerReconcile
        );
        assert!(parse(&argv("ledger nope")).is_err());
    }
}
