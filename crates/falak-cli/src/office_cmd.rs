//! `falak office ...`: join an app to Falak Office, look at the link, rotate Office's key.

use std::path::{Path, PathBuf};

use falak_federation::{AppKey, OfficeConfig, http};
use serde_json::{Value, json};

use crate::project;

pub const KEY_FILE: &str = "office-app-key.json";
pub const CONFIG_FILE: &str = "office.json";

pub fn config_path(dir: &Path) -> PathBuf {
    project::out_dir(dir).join(CONFIG_FILE)
}

pub fn key_path(dir: &Path) -> PathBuf {
    project::out_dir(dir).join(KEY_FILE)
}

/// Load what `falak office enroll` saved, if the app has been enrolled.
pub fn load(dir: &Path) -> Result<Option<(OfficeConfig, AppKey)>, String> {
    let path = config_path(dir);
    if !path.exists() {
        return Ok(None);
    }
    let cfg = OfficeConfig::load(&path)?;
    let key = AppKey::load_or_create(&key_path(dir))?;
    Ok(Some((cfg, key)))
}

/// The base address of Office, trailing slash removed. Passwords and enrollment tokens are
/// sent to it, so it must be `https`, or `http` to this machine in development (the same
/// rule as the key set address in `.falak/office.json`).
pub fn secure_base(url: &str) -> Result<String, String> {
    // What follows the host must be a port and then a path: `http://localhost:80@evil.test`
    // names `evil.test` and is refused. (The same rule as the keys' address in
    // `falak-federation`, kept here so the CLI builds against the published library.)
    let ok = url.starts_with("https://")
        || ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|p| {
                url.strip_prefix(p).is_some_and(|rest| {
                    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
                    authority.is_empty()
                        || authority
                            .strip_prefix(':')
                            .is_some_and(|port| port.bytes().all(|b| b.is_ascii_digit()))
                })
            });
    if !ok {
        return Err(format!(
            "`{url}` must be https (or http to this machine): credentials are sent to it"
        ));
    }
    Ok(url.trim_end_matches('/').to_owned())
}

/// A value that goes into an Office URL path (an app name, a request id): one segment,
/// no `/`, `?`, `#` or `..`.
pub fn path_segment<'a>(value: &'a str, what: &str) -> Result<&'a str, String> {
    let ok = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(value)
    } else {
        Err(format!(
            "`{value}` is not a valid {what}: use letters, digits, `-`, `_` and `.`"
        ))
    }
}

pub struct Options {
    pub office: Option<String>,
    pub token: Option<String>,
    /// The name of a variable that holds the enrollment token (keeps it out of `ps`).
    pub token_env: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub password_env: Option<String>,
    pub retire: bool,
}

/// What Office answered, turned into the file the app keeps.
pub fn config_from(office_url: &str, app: &str, answer: &Value) -> Result<OfficeConfig, String> {
    let text = |k: &str| {
        answer[k]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("Office's answer has no `{k}`"))
    };
    let cfg = OfficeConfig {
        office_url: office_url.trim_end_matches('/').to_owned(),
        app: app.to_owned(),
        tier: answer["tier"]
            .as_u64()
            .and_then(|t| u8::try_from(t).ok())
            .ok_or("Office's answer has no `tier`")?,
        issuer: text("issuer")?,
        jwks_url: text("jwks_url")?,
        passport: text("passport")?,
    };
    cfg.validate()?;
    Ok(cfg)
}

pub fn enroll(dir: &Path, o: &Options, default_name: &str) -> Result<u8, String> {
    let office = o.office.as_deref().ok_or("`--office <url>` is required")?;
    let office = secure_base(office)?;
    let office = office.as_str();
    let from_env = match o.token_env.as_deref() {
        Some(var) => Some(std::env::var(var).map_err(|_| format!("`{var}` is not set"))?),
        None => std::env::var("FALAK_ENROLL_TOKEN")
            .ok()
            .filter(|t| !t.is_empty()),
    };
    let token = match (&o.token, from_env) {
        (Some(t), _) => {
            eprintln!(
                "warning: `--token` is visible to other users of this machine (process list, shell history). \
                 Prefer `--token-env <VAR>` or the FALAK_ENROLL_TOKEN variable"
            );
            t.clone()
        }
        (None, Some(t)) => t,
        (None, None) => {
            return Err(
                "an enrollment token is required: `--token-env <VAR>` (an admin makes one in Office)"
                    .into(),
            );
        }
    };
    let token = token.as_str();
    let name = o.name.as_deref().unwrap_or(default_name);
    if config_path(dir).exists() {
        return Err(format!(
            "this app is already enrolled (`{}`). Delete it to enroll again",
            config_path(dir).display()
        ));
    }
    project::ensure_private_out_dir(dir)?;
    let key = AppKey::load_or_create(&key_path(dir))?;
    let answer = http::enroll(office, token, name, &key)?;
    let cfg = config_from(office, name, &answer)?;
    cfg.save(&config_path(dir))?;
    restrict(&config_path(dir));
    println!(
        "enrolled `{}` with Office at {} (tier {})",
        cfg.app, cfg.office_url, cfg.tier
    );
    println!("`falak serve` now takes sign-ins from Office.");
    Ok(0)
}

/// The link file holds no private key, but there is no reason for other users to read it.
fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

pub fn status(dir: &Path) -> Result<u8, String> {
    let (cfg, key) = load(dir)?.ok_or("this app is not enrolled. Run `falak office enroll`")?;
    let manifest = http::signed_get(&cfg, &key, "/v1/_office/manifest")?;
    println!("office:    {}", cfg.office_url);
    println!("app:       {} (tier {})", cfg.app, cfg.tier);
    println!(
        "feed:      version {}",
        manifest["feed_version"].as_i64().unwrap_or(0)
    );
    println!("link:      ok");
    Ok(0)
}

pub fn rotate_key(o: &Options) -> Result<u8, String> {
    let office = o.office.as_deref().ok_or("`--office <url>` is required")?;
    let email = o.email.as_deref().ok_or("`--email` is required")?;
    let var = o
        .password_env
        .as_deref()
        .ok_or("`--password-env <VAR>` is required: the name of a variable holding the password")?;
    let password = std::env::var(var).map_err(|_| format!("`{var}` is not set"))?;
    let base = secure_base(office)?;
    let base = base.as_str();
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let login: Value = agent
        .post(&format!("{base}/v1/auth/login"))
        .send_json(json!({"email": email, "password": password}))
        .map_err(|e| format!("sign-in to Office failed: {e}"))?
        .into_json()
        .map_err(|e| e.to_string())?;
    let session = login["access_token"]
        .as_str()
        .ok_or("Office gave no session token")?;
    let path = if o.retire {
        "keys/retire"
    } else {
        "keys/rotate"
    };
    let out: Value = agent
        .post(&format!("{base}/v1/_office/{path}"))
        .set("authorization", &format!("Bearer {session}"))
        .send_string("")
        .map_err(|e| format!("Office refused: {e}"))?
        .into_json()
        .map_err(|e| e.to_string())?;
    println!("{out}");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_becomes_a_config_and_a_bad_one_is_refused() {
        let ok = json!({
            "app": "notebook", "tier": 2, "passport": "p",
            "issuer": "https://office.test",
            "jwks_url": "https://office.test/.well-known/jwks.json",
        });
        let cfg = config_from("https://office.test/", "notebook", &ok).unwrap();
        assert_eq!(cfg.office_url, "https://office.test");
        assert_eq!(cfg.tier, 2);

        let mut plain = ok.clone();
        plain["jwks_url"] = json!("http://office.test/jwks");
        assert!(config_from("https://office.test", "notebook", &plain).is_err());
        let mut tier3 = ok.clone();
        tier3["tier"] = json!(3);
        assert!(config_from("https://office.test", "notebook", &tier3).is_err());
        assert!(config_from("https://office.test", "notebook", &json!({})).is_err());
    }

    #[test]
    fn enrolling_needs_an_office_and_a_token_and_never_twice() {
        let dir = std::env::temp_dir().join(format!("falak-office-cmd-{}", std::process::id()));
        std::fs::create_dir_all(project::out_dir(&dir)).unwrap();
        let none = Options {
            office: None,
            token: None,
            token_env: None,
            name: None,
            email: None,
            password_env: None,
            retire: false,
        };
        assert!(enroll(&dir, &none, "app").is_err());
        let office_only = Options {
            office: Some("https://office.test".into()),
            ..none
        };
        assert!(enroll(&dir, &office_only, "app").is_err());
        std::fs::write(config_path(&dir), "{}").unwrap();
        let both = Options {
            token: Some("t".into()),
            ..office_only
        };
        let err = enroll(&dir, &both, "app").unwrap_err();
        assert!(err.contains("already enrolled"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credentials_go_only_to_https_or_this_machine() {
        assert_eq!(
            secure_base("https://office.test/").unwrap(),
            "https://office.test"
        );
        assert!(secure_base("http://localhost:8788").is_ok());
        assert!(secure_base("http://127.0.0.1:8788/").is_ok());
        assert!(secure_base("http://office.test").is_err());
        assert!(secure_base("http://localhost.evil.test").is_err());
        assert!(secure_base("ftp://x").is_err());
        assert!(secure_base("http://localhost:80@evil.test").is_err());
        assert!(secure_base("http://127.0.0.1@evil.test/x").is_err());
    }

    #[test]
    fn url_path_values_are_one_plain_segment() {
        assert!(path_segment("notebook-2", "app").is_ok());
        for bad in ["", "..", "a/b", "a?x=1", "a#b", "../x", "a b"] {
            assert!(path_segment(bad, "app").is_err(), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_out_dir_and_the_link_file_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("falak-private-{}", std::process::id()));
        std::fs::create_dir_all(project::out_dir(&dir)).unwrap();
        project::ensure_private_out_dir(&dir).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&project::out_dir(&dir)), 0o700);
        std::fs::write(config_path(&dir), "{}").unwrap();
        restrict(&config_path(&dir));
        assert_eq!(mode(&config_path(&dir)), 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }
}
