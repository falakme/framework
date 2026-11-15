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
            "deploy --account",
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
    }
}
