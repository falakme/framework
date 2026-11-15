//! `falak doctor`: check that this machine and this app are ready.

use std::{fs, net::TcpListener, path::Path};

use falak_core::diagnostics::Severity;

use crate::project::{FRAMEWORK_VERSION, compile_dir, out_dir};

/// One line of the report.
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn check(name: &'static str, ok: bool, detail: impl Into<String>) -> Check {
    Check {
        name,
        ok,
        detail: detail.into(),
    }
}

/// Run every check. The app checks report a failure when `dir` has no `app.yaml`.
pub fn run(dir: &Path, port: u16) -> Vec<Check> {
    let mut checks = vec![check("falak version", true, FRAMEWORK_VERSION)];

    checks.push(match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => check("port", true, format!("127.0.0.1:{port} is free")),
        Err(e) => check(
            "port",
            false,
            format!("127.0.0.1:{port} is not available ({e}); pass --port to use another"),
        ),
    });

    if !dir.join("app.yaml").is_file() {
        checks.push(check(
            "app",
            false,
            format!("no app.yaml in `{}`; run `falak init`", dir.display()),
        ));
        return checks;
    }

    match compile_dir(dir) {
        Ok(outcome) => {
            let errors = outcome
                .diagnostics
                .iter()
                .filter(|d| d.severity == Severity::Error)
                .count();
            checks.push(check(
                "app",
                errors == 0,
                if errors == 0 {
                    format!("{} source files compile", outcome.sources)
                } else {
                    format!("{errors} error(s); run `falak check` for details")
                },
            ));
        }
        Err(e) => checks.push(check("app", false, e)),
    }

    let out = out_dir(dir);
    let writable = fs::create_dir_all(&out)
        .and_then(|()| fs::write(out.join(".doctor"), b"ok"))
        .and_then(|()| fs::remove_file(out.join(".doctor")))
        .is_ok();
    checks.push(check(
        "output directory",
        writable,
        format!(
            "{} {}",
            out.display(),
            if writable {
                "is writable"
            } else {
                "is not writable"
            }
        ),
    ));
    checks
}
