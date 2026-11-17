//! What the web setup saves: `settings.json` in the data directory.
//!
//! * `issuer`: the public address of Office. It is part of every token, so a change
//!   takes effect when Office restarts. A flag or `FALAK_OFFICE_ISSUER` still wins.
//! * `oidc`: sign-in through an identity provider. It applies at once. The environment
//!   (`FALAK_OIDC_*`) wins over it at start.
//!
//! There are no secrets in it.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::oidc::OidcConfig;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<SavedOidc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedOidc {
    pub issuer: String,
    pub audience: String,
    #[serde(default)]
    pub auto_create_domains: Vec<String>,
}

impl SavedOidc {
    pub fn config(&self) -> OidcConfig {
        OidcConfig {
            issuer: self.issuer.trim_end_matches('/').to_owned(),
            audience: self.audience.clone(),
            auto_create_domains: self
                .auto_create_domains
                .iter()
                .map(|d| d.trim().to_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
            trust_unverified_email: false,
        }
    }
}

const FILE: &str = "settings.json";

impl Settings {
    /// Missing file: nothing saved. A damaged file is an error, not a silent reset.
    pub fn load(dir: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(dir.join(FILE)) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| format!("`{}` is not valid: {e}", dir.join(FILE).display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("cannot read `{}`: {e}", dir.join(FILE).display())),
        }
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let tmp = dir.join("settings.json.tmp");
        std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, dir.join(FILE)).map_err(|e| e.to_string())
    }
}

/// An address Office may call itself: `https`, or `http` to this machine.
pub fn valid_address(url: &str) -> bool {
    crate::oidc::trusted_url(url) && !url.ends_with('/') && !url.contains(['?', '#', ' '])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_and_loads_and_refuses_a_damaged_file() {
        let dir =
            std::env::temp_dir().join(format!("falak-office-settings-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(Settings::load(&dir).unwrap(), Settings::default());
        let s = Settings {
            issuer: Some("https://office.test".into()),
            oidc: Some(SavedOidc {
                issuer: "https://idp.test/".into(),
                audience: "office".into(),
                auto_create_domains: vec![" Corp.Test ".into(), String::new()],
            }),
        };
        s.save(&dir).unwrap();
        assert_eq!(Settings::load(&dir).unwrap(), s);
        let cfg = s.oidc.unwrap().config();
        assert_eq!(cfg.issuer, "https://idp.test");
        assert_eq!(cfg.auto_create_domains, ["corp.test"]);
        std::fs::write(dir.join("settings.json"), "{nope").unwrap();
        assert!(Settings::load(&dir).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn addresses_are_https_or_this_machine_and_have_no_trailing_slash() {
        assert!(valid_address("https://office.example.com"));
        assert!(valid_address("http://127.0.0.1:8788"));
        assert!(!valid_address("http://office.example.com"));
        assert!(!valid_address("https://office.example.com/"));
        assert!(!valid_address("https://office.example.com/x?y"));
        assert!(!valid_address("ftp://x"));
        assert!(!valid_address("http://localhost:80@evil.example"));
        assert!(!crate::oidc::trusted_url(
            "http://127.0.0.1@evil.example/keys"
        ));
        assert!(crate::oidc::trusted_url("http://localhost:8080/keys"));
    }
}
