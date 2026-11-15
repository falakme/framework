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
            _ => return Err("`office` needs a subcommand: enroll, status or rotate-key".into()),
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
