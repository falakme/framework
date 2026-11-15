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

pub struct Options {
    pub office: Option<String>,
    pub token: Option<String>,
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
    let token = o
        .token
        .as_deref()
        .ok_or("`--token <enrollment token>` is required (an admin makes one in Office)")?;
    let name = o.name.as_deref().unwrap_or(default_name);
    if config_path(dir).exists() {
        return Err(format!(
            "this app is already enrolled (`{}`). Delete it to enroll again",
            config_path(dir).display()
        ));
    }
    let key = AppKey::load_or_create(&key_path(dir))?;
    let answer = http::enroll(office, token, name, &key)?;
    let cfg = config_from(office, name, &answer)?;
    cfg.save(&config_path(dir))?;
    println!(
        "enrolled `{}` with Office at {} (tier {})",
        cfg.app, cfg.office_url, cfg.tier
    );
    println!("`falak serve` now takes sign-ins from Office.");
    Ok(0)
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
    let base = office.trim_end_matches('/');
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
}
