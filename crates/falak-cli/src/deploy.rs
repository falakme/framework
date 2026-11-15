//! `falak deploy`: build the app and publish it to Cloudflare Workers with a D1 database.
//!
//! Steps: compile the app, embed it in the edge runtime and build that for `wasm32`,
//! find or create the D1 database, publish, then make sure the Worker has its signing
//! keys. The keys are made once and kept in `.falak/edge-keys.json` (owner-only), so
//! later deploys keep existing tokens valid. They go to the Worker as a secret and are
//! never printed.
//!
//! It runs `worker-build` and `wrangler` as child processes. Log in first with
//! `wrangler login`, or set `CLOUDFLARE_API_TOKEN`. When the login has more than one
//! account, pass `--account <id>` or set `CLOUDFLARE_ACCOUNT_ID`.

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use falak_auth::keys::LocalKeys;
use serde_json::Value;

use crate::project;

/// Pinned so a deploy does not change behaviour under you.
const COMPATIBILITY_DATE: &str = "2026-11-01";
const WRANGLER: &str = "wrangler@4";
const KEYS_SECRET: &str = "FALAK_KEYS";

pub struct Options {
    pub name: Option<String>,
    pub account: Option<String>,
    /// Key set mode: verify tokens against this published key set (`https`).
    pub jwks_url: Option<String>,
    /// The `iss` those tokens carry.
    pub issuer: Option<String>,
}

/// How the Worker identifies callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// The Worker signs tokens with its own keys and serves `/v1/auth/*`.
    Local,
    /// The Worker only verifies tokens, against another service's key set.
    KeySet { jwks_url: String, issuer: String },
}

impl Options {
    fn identity(&self) -> Result<Identity, String> {
        match (&self.jwks_url, &self.issuer) {
            (None, None) => Ok(Identity::Local),
            (Some(url), Some(issuer)) => {
                if !url.starts_with("https://") {
                    return Err("`--jwks-url` must start with https://".into());
                }
                if issuer.trim().is_empty() {
                    return Err("`--issuer` cannot be empty".into());
                }
                Ok(Identity::KeySet {
                    jwks_url: url.clone(),
                    issuer: issuer.clone(),
                })
            }
            _ => Err("`--jwks-url` and `--issuer` go together".into()),
        }
    }
}

/// Requests per minute per client address, on the data routes and on the auth routes.
/// Cloudflare's binding allows a period of 10 or 60 seconds.
const DATA_LIMIT: u32 = 600;
const AUTH_LIMIT: u32 = 30;

/// Workers names allow lowercase letters, digits and hyphens.
pub fn worker_name(app: &str) -> String {
    let cleaned: String = app
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect();
    cleaned.trim_matches('-').to_string()
}

/// The wrangler configuration for one deploy.
pub fn wrangler_config(
    worker: &str,
    main: &Path,
    account: Option<&str>,
    database: &str,
    database_id: &str,
    identity: &Identity,
) -> String {
    let mut out = String::new();
    out.push_str("# Written by `falak deploy`. Changes are overwritten.\n");
    out.push_str(&format!("name = \"{worker}\"\n"));
    out.push_str(&format!(
        "main = {}\n",
        toml_string(&main.to_string_lossy())
    ));
    out.push_str(&format!("compatibility_date = \"{COMPATIBILITY_DATE}\"\n"));
    // `fetch` reaches only the public internet, never another Worker through a shortcut
    // on the same zone. The key set fetch needs this to reach an issuer on workers.dev.
    out.push_str("compatibility_flags = [\"global_fetch_strictly_public\"]\n");
    if let Some(account) = account {
        out.push_str(&format!("account_id = \"{account}\"\n"));
    }
    out.push_str("workers_dev = true\n\n");
    out.push_str("[[d1_databases]]\nbinding = \"DB\"\n");
    out.push_str(&format!("database_name = \"{database}\"\n"));
    out.push_str(&format!("database_id = \"{database_id}\"\n"));
    out.push_str(&format!(
        "\n[[ratelimits]]\nname = \"RATE_LIMITER\"\nnamespace_id = \"1001\"\n\
         [ratelimits.simple]\nlimit = {DATA_LIMIT}\nperiod = 60\n"
    ));
    out.push_str(&format!(
        "\n[[ratelimits]]\nname = \"AUTH_RATE_LIMITER\"\nnamespace_id = \"1002\"\n\
         [ratelimits.simple]\nlimit = {AUTH_LIMIT}\nperiod = 60\n"
    ));
    if let Identity::KeySet { jwks_url, issuer } = identity {
        out.push_str(&format!(
            "\n[vars]\nFALAK_JWKS_URL = {}\nFALAK_ISSUER = {}\n",
            toml_string(jwks_url),
            toml_string(issuer)
        ));
    }
    out
}

fn toml_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Run a program and return its stdout. On failure the error carries the tail of
/// stderr. `stdin` is written to the child's input and never echoed.
fn run_cmd(
    program: &str,
    args: &[&str],
    cwd: &Path,
    envs: &[(&str, &str)],
    stdin: Option<&str>,
) -> Result<String, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot run `{program}`: {e}"))?;
    if let (Some(text), Some(mut input)) = (stdin, child.stdin.take()) {
        input
            .write_all(text.as_bytes())
            .map_err(|e| format!("cannot write to `{program}`: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("`{program}` failed: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: Vec<&str> = stderr.lines().rev().take(12).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        Err(format!(
            "`{program} {}` failed:\n{}\n{}",
            args.first().copied().unwrap_or(""),
            tail.join("\n"),
            stdout.lines().rev().take(6).collect::<Vec<_>>().join("\n")
        ))
    }
}

fn wrangler(
    args: &[&str],
    cwd: &Path,
    envs: &[(&str, &str)],
    stdin: Option<&str>,
) -> Result<String, String> {
    let mut full = vec!["--yes", WRANGLER];
    full.extend_from_slice(args);
    run_cmd("npx", &full, cwd, envs, stdin)
}

/// The edge runtime crate that ships with this checkout of the framework.
fn edge_crate() -> Result<PathBuf, String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../falak-runtime-edge");
    dir.canonicalize().map_err(|_| {
        "cannot find the edge runtime. `falak deploy` runs from a checkout of the framework."
            .to_string()
    })
}

/// The id of the D1 database called `name`, if the account has one.
fn find_database(name: &str, cwd: &Path, envs: &[(&str, &str)]) -> Result<Option<String>, String> {
    let text = wrangler(&["d1", "list", "--json"], cwd, envs, None)?;
    let start = text
        .find('[')
        .ok_or("unexpected output from `wrangler d1 list`")?;
    let list: Value = serde_json::from_str(&text[start..])
        .map_err(|e| format!("cannot read `wrangler d1 list`: {e}"))?;
    Ok(list.as_array().and_then(|items| {
        items
            .iter()
            .find(|d| d["name"] == name)
            .and_then(|d| d["uuid"].as_str())
            .map(str::to_string)
    }))
}

pub fn run(dir: &Path, options: &Options) -> Result<u8, String> {
    let identity = options.identity()?;
    let Some(compiled) = project::build(dir)? else {
        return Ok(1);
    };
    let dir = dir
        .canonicalize()
        .map_err(|e| format!("cannot resolve `{}`: {e}", dir.display()))?;
    let worker = worker_name(options.name.as_deref().unwrap_or(&compiled.ir.app.name));
    if worker.is_empty() {
        return Err("the app name cannot be used as a Worker name; pass one with --name".into());
    }
    let database = format!("{worker}-db");
    let account = options
        .account
        .clone()
        .or_else(|| std::env::var("CLOUDFLARE_ACCOUNT_ID").ok());
    let envs: Vec<(&str, &str)> = account
        .as_deref()
        .map(|a| vec![("CLOUDFLARE_ACCOUNT_ID", a)])
        .unwrap_or_default();

    // 1. Build the Worker with the app inside it.
    let edge = edge_crate()?;
    let ir_file = project::out_dir(&dir).join("ir.json");
    println!("building the Worker for `{worker}` (this takes a while the first time)");
    let ir_path = ir_file.to_string_lossy().into_owned();
    let mut build_envs = envs.clone();
    build_envs.push(("FALAK_IR_FILE", &ir_path));
    run_cmd("worker-build", &["--release"], &edge, &build_envs, None).map_err(|e| {
        format!("{e}\nInstall the builder with `cargo install worker-build --locked`.")
    })?;
    let main = edge.join("build/worker/shim.mjs");
    let wasm = edge.join("build/index_bg.wasm");
    if let Ok(meta) = std::fs::metadata(&wasm) {
        println!("  wasm: {} KiB", meta.len() / 1024);
    }

    // 2. The database.
    let edge_out = project::out_dir(&dir).join("edge");
    std::fs::create_dir_all(&edge_out)
        .map_err(|e| format!("cannot create `{}`: {e}", edge_out.display()))?;
    let database_id = match find_database(&database, &edge_out, &envs)? {
        Some(id) => id,
        None => {
            println!("creating the D1 database `{database}`");
            wrangler(&["d1", "create", &database], &edge_out, &envs, None)?;
            find_database(&database, &edge_out, &envs)?
                .ok_or("the D1 database was created but cannot be found")?
        }
    };

    // 3. Signing keys, made once and kept. Key set mode has none: it holds no secret.
    let keys_path = project::out_dir(&dir).join("edge-keys.json");
    if identity == Identity::Local {
        let keys = LocalKeys::load_or_create(&keys_path)
            .map_err(|e| format!("cannot prepare the signing keys: {e}"))?;
        drop(keys);
    }

    // 4. Publish.
    let config_path = edge_out.join("wrangler.toml");
    std::fs::write(
        &config_path,
        wrangler_config(
            &worker,
            &main,
            account.as_deref(),
            &database,
            &database_id,
            &identity,
        ),
    )
    .map_err(|e| format!("cannot write `{}`: {e}", config_path.display()))?;
    let config_arg = config_path.to_string_lossy().into_owned();
    println!("publishing");
    let published = wrangler(&["deploy", "--config", &config_arg], &edge_out, &envs, None)?;

    // 5. The keys secret, only if the Worker does not have it yet.
    if identity != Identity::Local {
        println!("deployed: {}", deployed_url(&published));
        return Ok(0);
    }
    let secrets = wrangler(
        &[
            "secret",
            "list",
            "--config",
            &config_arg,
            "--format",
            "json",
        ],
        &edge_out,
        &envs,
        None,
    )?;
    let has_keys = secrets
        .find('[')
        .and_then(|i| serde_json::from_str::<Value>(&secrets[i..]).ok())
        .and_then(|v| v.as_array().cloned())
        .is_some_and(|items| items.iter().any(|s| s["name"] == KEYS_SECRET));
    if !has_keys {
        println!("setting the signing keys");
        let text = std::fs::read_to_string(&keys_path)
            .map_err(|e| format!("cannot read the signing keys: {e}"))?;
        let bulk = serde_json::json!({ KEYS_SECRET: text }).to_string();
        wrangler(
            &["secret", "bulk", "--config", &config_arg],
            &edge_out,
            &envs,
            Some(&bulk),
        )?;
    }

    println!("deployed: {}", deployed_url(&published));
    Ok(0)
}

fn deployed_url(wrangler_output: &str) -> &str {
    wrangler_output
        .split_whitespace()
        .find(|w| w.starts_with("https://") && w.contains("workers.dev"))
        .unwrap_or("(see the wrangler output)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_names_are_dns_safe() {
        assert_eq!(worker_name("My_App"), "my-app");
        assert_eq!(worker_name("notebook"), "notebook");
        assert_eq!(worker_name("__"), "");
    }

    #[test]
    fn config_has_the_database_binding_and_no_secrets() {
        let text = wrangler_config(
            "notebook",
            Path::new("/x/shim.mjs"),
            Some("acc123"),
            "notebook-db",
            "uuid-1",
            &Identity::Local,
        );
        assert!(text.contains("name = \"notebook\""));
        assert!(text.contains("account_id = \"acc123\""));
        assert!(text.contains("binding = \"DB\""));
        assert!(text.contains("global_fetch_strictly_public"));
        assert!(text.contains("database_id = \"uuid-1\""));
        assert!(!text.contains("FALAK_KEYS"));
        assert!(text.contains("name = \"RATE_LIMITER\""));
        assert!(text.contains("name = \"AUTH_RATE_LIMITER\""));
        assert!(!text.contains("FALAK_JWKS_URL"));
    }

    #[test]
    fn key_set_mode_sets_the_issuer_and_url_as_plain_vars() {
        let id = Identity::KeySet {
            jwks_url: "https://a.example/.well-known/jwks.json".into(),
            issuer: "falak-local".into(),
        };
        let text = wrangler_config("a", Path::new("/s.mjs"), None, "a-db", "u", &id);
        assert!(text.contains("FALAK_JWKS_URL = \"https://a.example/.well-known/jwks.json\""));
        assert!(text.contains("FALAK_ISSUER = \"falak-local\""));
    }

    fn opts(url: Option<&str>, iss: Option<&str>) -> Options {
        Options {
            name: None,
            account: None,
            jwks_url: url.map(str::to_owned),
            issuer: iss.map(str::to_owned),
        }
    }

    #[test]
    fn identity_options_must_be_complete_and_https() {
        assert_eq!(opts(None, None).identity(), Ok(Identity::Local));
        assert!(opts(Some("https://x/jwks"), None).identity().is_err());
        assert!(opts(None, Some("iss")).identity().is_err());
        assert!(opts(Some("http://x/jwks"), Some("iss")).identity().is_err());
        assert!(opts(Some("https://x/jwks"), Some(" ")).identity().is_err());
        assert!(opts(Some("https://x/jwks"), Some("iss")).identity().is_ok());
    }

    #[test]
    fn config_without_an_account_leaves_it_out() {
        let text = wrangler_config(
            "a",
            Path::new("/s.mjs"),
            None,
            "a-db",
            "u",
            &Identity::Local,
        );
        assert!(!text.contains("account_id"));
    }
}
