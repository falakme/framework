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
    /// Let this deploy rebuild, drop or retype data to match a changed app.
    pub allow_destructive: bool,
}

/// How the Worker identifies callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// The Worker signs tokens with its own keys and serves `/v1/auth/*`.
    Local,
    /// The Worker only verifies tokens, against another service's key set.
    KeySet { jwks_url: String, issuer: String },
    /// The app is enrolled with Falak Office: sign-in is Office's, and the Worker follows
    /// its key set and revocation feed. `config` is `.falak/office.json`.
    Office { config: String },
}

const APP_KEY_SECRET: &str = "FALAK_APP_KEY";

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

/// A tenant's own D1 database (`tenancy: database`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TenantDb {
    pub tenant: String,
    pub binding: String,
    pub database_name: String,
    pub database_id: String,
}

fn tenants_path(dir: &Path) -> PathBuf {
    project::out_dir(dir).join("edge").join("tenants.json")
}

fn load_tenants(dir: &Path) -> Result<Vec<TenantDb>, String> {
    match std::fs::read_to_string(tenants_path(dir)) {
        Ok(text) => {
            serde_json::from_str(&text).map_err(|e| format!("tenants.json is not valid: {e}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("cannot read tenants.json: {e}")),
    }
}

fn save_tenants(dir: &Path, tenants: &[TenantDb]) -> Result<(), String> {
    let path = tenants_path(dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(tenants).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| format!("cannot write `{}`: {e}", path.display()))
}

/// The wrangler configuration for one deploy.
#[allow(clippy::too_many_arguments)]
pub fn wrangler_config(
    worker: &str,
    main: &Path,
    account: Option<&str>,
    database: &str,
    database_id: &str,
    identity: &Identity,
    allow_destructive: bool,
    tenants: &[TenantDb],
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
    for t in tenants {
        out.push_str(&format!(
            "\n[[d1_databases]]\nbinding = \"{}\"\ndatabase_name = \"{}\"\ndatabase_id = \"{}\"\n",
            t.binding, t.database_name, t.database_id
        ));
    }
    let mut vars = Vec::new();
    if !tenants.is_empty() {
        let map: serde_json::Map<String, serde_json::Value> = tenants
            .iter()
            .map(|t| {
                (
                    t.tenant.clone(),
                    serde_json::Value::String(t.binding.clone()),
                )
            })
            .collect();
        vars.push(format!(
            "FALAK_TENANTS = {}",
            toml_string(&serde_json::Value::Object(map).to_string())
        ));
    }
    if let Identity::KeySet { jwks_url, issuer } = identity {
        vars.push(format!("FALAK_JWKS_URL = {}", toml_string(jwks_url)));
        vars.push(format!("FALAK_ISSUER = {}", toml_string(issuer)));
    }
    if let Identity::Office { config } = identity {
        vars.push(format!("FALAK_OFFICE_CONFIG = {}", toml_string(config)));
        // How long a tier 2 Worker keeps writing without a fresh feed (seconds).
        if let Some(n) = std::env::var("FALAK_OFFICE_MAX_STALENESS")
            .ok()
            .filter(|v| v.parse::<u32>().is_ok_and(|n| n > 0))
        {
            vars.push(format!("FALAK_OFFICE_MAX_STALENESS = \"{n}\""));
        }
    }
    if allow_destructive {
        vars.push("FALAK_ALLOW_DESTRUCTIVE = \"1\"".to_owned());
    }
    if !vars.is_empty() {
        out.push_str(&format!("\n[vars]\n{}\n", vars.join("\n")));
    }
    out
}

/// Cron Trigger for apps that publish or consume events (T5.4).
const EVENTS_CRON: &str = "\n[triggers]\ncrons = [\"* * * * *\"]\n";

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

/// `falak tenant add`: make a D1 database for a tenant, bind it, and publish again.
pub fn add_tenant(dir: &Path, options: &Options, tenant: &str) -> Result<u8, String> {
    if !falak_runtime_native::tenants::valid_tenant(tenant) {
        return Err(
            "a tenant id is a lower case UUID, like 00000000-0000-0000-0000-000000000001".into(),
        );
    }
    let Some(compiled) = project::build(dir)? else {
        return Ok(1);
    };
    if compiled.ir.app.tenancy != falak_contracts::ir::Tenancy::Database {
        return Err("this app does not use `tenancy: database`".into());
    }
    let dir = dir
        .canonicalize()
        .map_err(|e| format!("cannot resolve `{}`: {e}", dir.display()))?;
    let worker = worker_name(options.name.as_deref().unwrap_or(&compiled.ir.app.name));
    let mut tenants = load_tenants(&dir)?;
    if tenants.iter().any(|t| t.tenant == tenant) {
        println!("tenant {tenant} already has a database");
        return Ok(0);
    }
    let account = options
        .account
        .clone()
        .or_else(|| std::env::var("CLOUDFLARE_ACCOUNT_ID").ok());
    let envs: Vec<(&str, &str)> = account
        .as_deref()
        .map(|a| vec![("CLOUDFLARE_ACCOUNT_ID", a)])
        .unwrap_or_default();
    let edge_out = project::out_dir(&dir).join("edge");
    std::fs::create_dir_all(&edge_out).map_err(|e| e.to_string())?;
    let database_name = format!("{worker}-t-{tenant}");
    println!("creating the D1 database `{database_name}`");
    if find_database(&database_name, &edge_out, &envs)?.is_none() {
        wrangler(&["d1", "create", &database_name], &edge_out, &envs, None)?;
    }
    let database_id = find_database(&database_name, &edge_out, &envs)?
        .ok_or("the D1 database was created but cannot be found")?;
    tenants.push(TenantDb {
        tenant: tenant.to_owned(),
        binding: format!("TENANT_{}", tenants.len() + 1),
        database_name,
        database_id,
    });
    save_tenants(&dir, &tenants)?;
    run(&dir, options)
}

pub fn run(dir: &Path, options: &Options) -> Result<u8, String> {
    let identity = match options.identity()? {
        // No flags, but enrolled with Office: follow Office.
        Identity::Local => match crate::office_cmd::load(dir)? {
            Some((cfg, _)) => Identity::Office {
                config: serde_json::to_string(&cfg).map_err(|e| e.to_string())?,
            },
            None => Identity::Local,
        },
        other => other,
    };
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
    let mut config = wrangler_config(
        &worker,
        &main,
        account.as_deref(),
        &database,
        &database_id,
        &identity,
        options.allow_destructive,
        &load_tenants(&dir)?,
    );
    if compiled.ir.uses_events() {
        // The edge relay: every minute the Worker sends its outbox to Office and applies
        // what Office delivers. A write also starts a pass at once.
        config.push_str(EVENTS_CRON);
    }
    std::fs::write(&config_path, config)
        .map_err(|e| format!("cannot write `{}`: {e}", config_path.display()))?;
    let config_arg = config_path.to_string_lossy().into_owned();
    println!("publishing");
    let published = wrangler(&["deploy", "--config", &config_arg], &edge_out, &envs, None)?;

    // 5. The secret the Worker needs, only if it does not have it yet: its signing keys,
    // or (enrolled with Office) the app's own key.
    let (secret_name, secret_path) = match &identity {
        Identity::Local => (KEYS_SECRET, keys_path.clone()),
        Identity::Office { .. } => (APP_KEY_SECRET, crate::office_cmd::key_path(&dir)),
        Identity::KeySet { .. } => {
            println!("deployed: {}", deployed_url(&published));
            return Ok(0);
        }
    };
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
        .is_some_and(|items| items.iter().any(|s| s["name"] == secret_name));
    if !has_keys {
        println!("setting `{secret_name}`");
        let text = std::fs::read_to_string(&secret_path)
            .map_err(|e| format!("cannot read `{}`: {e}", secret_path.display()))?;
        let bulk = serde_json::json!({ secret_name: text }).to_string();
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
            false,
            &[],
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
        let text = wrangler_config("a", Path::new("/s.mjs"), None, "a-db", "u", &id, false, &[]);
        assert!(text.contains("FALAK_JWKS_URL = \"https://a.example/.well-known/jwks.json\""));
        assert!(text.contains("FALAK_ISSUER = \"falak-local\""));
    }

    fn opts(url: Option<&str>, iss: Option<&str>) -> Options {
        Options {
            name: None,
            account: None,
            jwks_url: url.map(str::to_owned),
            issuer: iss.map(str::to_owned),
            allow_destructive: false,
        }
    }

    #[test]
    fn an_office_worker_gets_the_config_as_a_variable_and_no_key_in_the_file() {
        let text = wrangler_config(
            "app",
            Path::new("/s.mjs"),
            None,
            "app-db",
            "u",
            &Identity::Office {
                config: "{\"app\":\"app\"}".into(),
            },
            false,
            &[],
        );
        assert!(
            text.contains("FALAK_OFFICE_CONFIG = \"{\\\"app\\\":\\\"app\\\"}\""),
            "{text}"
        );
        assert!(!text.contains("FALAK_APP_KEY") && !text.contains("FALAK_KEYS"));
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
    fn tenant_databases_become_bindings_and_a_map() {
        let t = TenantDb {
            tenant: "00000000-0000-0000-0000-0000000000a1".into(),
            binding: "TENANT_1".into(),
            database_name: "app-t-00000000-0000-0000-0000-0000000000a1".into(),
            database_id: "db-1".into(),
        };
        let text = wrangler_config(
            "app",
            Path::new("/s.mjs"),
            None,
            "app-db",
            "u",
            &Identity::Local,
            false,
            &[t],
        );
        assert!(text.contains("binding = \"TENANT_1\""));
        assert!(text.contains("database_id = \"db-1\""));
        assert!(text.contains("FALAK_TENANTS ="));
        assert!(text.contains("00000000-0000-0000-0000-0000000000a1"));
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
            false,
            &[],
        );
        assert!(!text.contains("account_id"));
    }
}
