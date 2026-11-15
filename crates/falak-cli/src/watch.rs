//! Change detection for `falak dev`, by polling file modification times.
//!
//! Polling needs no extra dependency and behaves the same on every platform. App
//! directories are small, so a scan every half second is cheap.

use std::{fs, path::Path, time::SystemTime};

/// One source file: path, size and modification time.
pub type Entry = (String, u64, Option<SystemTime>);

/// A fingerprint of every `.yaml` file under `dir`. Hidden entries and `falak.lock`
/// are ignored, so writing the lock does not trigger another reload.
pub fn fingerprint(dir: &Path) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name == "target" || name == "falak.lock" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if name.ends_with(".yaml") {
                let meta = entry.metadata().ok();
                out.push((
                    path.strip_prefix(dir)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .into_owned(),
                    meta.as_ref().map_or(0, fs::Metadata::len),
                    meta.and_then(|m| m.modified().ok()),
                ));
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_change_and_ignores_the_lock() {
        let dir = std::env::temp_dir().join(format!("falak-watch-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("app.yaml"), "a").unwrap();
        let before = fingerprint(&dir);
        fs::write(dir.join("falak.lock"), "x").unwrap();
        assert_eq!(fingerprint(&dir), before);
        fs::write(dir.join("app.yaml"), "changed").unwrap();
        assert_ne!(fingerprint(&dir), before);
        fs::remove_dir_all(&dir).unwrap();
    }
}
