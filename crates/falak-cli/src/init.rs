//! `falak init`: write a small working app.

use std::{fs, path::Path};

/// True if `name` is a valid app name: `^[a-z][a-z0-9_-]{1,39}$`.
pub fn valid_app_name(name: &str) -> bool {
    let b = name.as_bytes();
    (2..=40).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

/// Create the app in `dir`. Refuses to overwrite an existing `app.yaml`.
pub fn init(dir: &Path, name: &str) -> Result<(), String> {
    if !valid_app_name(name) {
        return Err(format!(
            "`{name}` is not a valid app name: use 2 to 40 characters, start with a lowercase letter, then lowercase letters, digits, `-` or `_`"
        ));
    }
    if dir.join("app.yaml").exists() {
        return Err(format!(
            "`{}` already has an app.yaml; nothing was changed",
            dir.display()
        ));
    }
    for sub in ["entities", "policies", "commands"] {
        fs::create_dir_all(dir.join(sub))
            .map_err(|e| format!("cannot create `{}`: {e}", dir.join(sub).display()))?;
    }
    let files: [(&str, String); 5] = [
        (
            "app.yaml",
            format!(
                "schema_version: 1\nname: {name}\nversion: 0.1.0\ntenancy: none\ntrust_tier: standard\ndrivers: [sqlite, postgres, d1]\n"
            ),
        ),
        (
            "entities/note.yaml",
            "schema_version: 1\nentity: note\nowner: owner_id\nfields:\n  title: { type: text, required: true, max_length: 200 }\n  body: { type: text, max_length: 20000 }\n  owner_id: { type: uuid, required: true, indexed: true }\n".into(),
        ),
        (
            "policies/note.yaml",
            "schema_version: 1\nentity: note\nrules:\n  - id: owner_full_access\n    actions: [read, create, update, delete]\n    allow: { owner: true }\n".into(),
        ),
        (".gitignore", ".falak/\n*.db\n*.db-wal\n*.db-shm\n".into()),
        (
            "README.md",
            format!(
                "# {name}\n\nA Falak app.\n\n```sh\nfalak check   # validate the files\nfalak build   # compile, write falak.lock\nfalak dev     # serve and reload on change\n```\n"
            ),
        ),
    ];
    for (rel, text) in files {
        let path = dir.join(rel);
        fs::write(&path, text).map_err(|e| format!("cannot write `{}`: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["notebook", "my-app", "a1", "app_2"] {
            assert!(valid_app_name(ok), "{ok}");
        }
        for bad in ["", "a", "App", "1app", "my app", "-x", &"a".repeat(41)] {
            assert!(!valid_app_name(bad), "{bad}");
        }
    }
}
