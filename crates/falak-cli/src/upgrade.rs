//! `falak upgrade`: say what an upgrade would break, then (with `--apply`) do it.
//!
//! The report has three sources, so it does not depend on anyone remembering to write
//! release notes:
//!
//! 1. the breaking-change table (`breaking-changes.txt`) for every release after the
//!    version the app was last built with, up to the target;
//! 2. the app compiled with this CLI: errors are breaking, warnings are deprecations;
//! 3. drift: the IR hash the new compiler produces from unchanged sources. If it differs
//!    from `falak.lock`, the generated schema, API or policies change, and `migrate plan`
//!    must be read before deploying.
//!
//! Without `--apply` nothing is written.

use std::{fs, path::Path};

use falak_core::{
    diagnostics::{Severity, has_errors},
    lock::recorded_ir_hash,
};

use crate::project::{self, FRAMEWORK_VERSION};

const TABLE: &str = include_str!("../breaking-changes.txt");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub version: String,
    pub kind: String,
    pub what: String,
    pub action: String,
}

pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.split(['-', '+']).next()?;
    let mut it = core.split('.');
    let out = (
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    );
    it.next().is_none().then_some(out)
}

pub fn parse_table(text: &str) -> Result<Vec<Change>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, '|').map(str::trim).collect();
        if parts.len() != 4 || parse_version(parts[0]).is_none() {
            return Err(format!("breaking-changes line {} is malformed", n + 1));
        }
        out.push(Change {
            version: parts[0].into(),
            kind: parts[1].into(),
            what: parts[2].into(),
            action: parts[3].into(),
        });
    }
    Ok(out)
}

/// Changes introduced after `from` and up to and including `to`, oldest first.
pub fn between(table: &[Change], from: &str, to: &str) -> Vec<Change> {
    let (Some(from), Some(to)) = (parse_version(from), parse_version(to)) else {
        return vec![];
    };
    let mut hits: Vec<Change> = table
        .iter()
        .filter(|c| parse_version(&c.version).is_some_and(|v| v > from && v <= to))
        .cloned()
        .collect();
    hits.sort_by_key(|c| parse_version(&c.version));
    hits
}

fn lock_value(lock: &str, key: &str) -> Option<String> {
    lock.lines().find_map(|l| {
        l.strip_prefix(key)?
            .trim_start()
            .strip_prefix('=')
            .map(|v| v.trim().trim_matches('"').to_owned())
    })
}

pub struct Options {
    pub to: Option<String>,
    pub apply: bool,
}

/// Exit code: 0 nothing to read, 1 the app cannot be upgraded as it is, 3 upgradable
/// but the report lists changes to read first.
pub fn run(dir: &Path, o: &Options) -> Result<u8, String> {
    let table = parse_table(TABLE)?;
    let target = o.to.clone().unwrap_or_else(|| FRAMEWORK_VERSION.to_owned());
    let Some(target_v) = parse_version(&target) else {
        return Err(format!("`{target}` is not a version like 1.2.3"));
    };
    if target != FRAMEWORK_VERSION {
        return Err(format!(
            "this CLI is {FRAMEWORK_VERSION}; it can only upgrade an app to itself. \
             Install {target} and run `falak upgrade` with that."
        ));
    }
    let lock = fs::read_to_string(dir.join("falak.lock")).ok();
    let from = lock
        .as_deref()
        .and_then(|l| lock_value(l, "framework"))
        .ok_or("no falak.lock with a framework version: run `falak build` first")?;
    let Some(from_v) = parse_version(&from) else {
        return Err(format!(
            "falak.lock records `{from}`, which is not a version"
        ));
    };
    if from_v > target_v {
        return Err(format!(
            "the app was built with {from}, which is newer than this CLI ({target}): downgrades are not supported"
        ));
    }

    println!("upgrade {} : {from} -> {target}\n", dir.display());
    let mut to_read = 0usize;

    let listed = between(&table, &from, &target);
    println!("Documented changes ({}):", listed.len());
    for c in &listed {
        println!(
            "  [{}] {}  ({})\n      do: {}",
            c.kind, c.what, c.version, c.action
        );
    }
    to_read += listed.len();

    let outcome = project::compile_dir(dir)?;
    let errors = outcome
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();
    let warnings = outcome.diagnostics.len() - errors;
    println!("\nThis app under {target}: {errors} error(s), {warnings} warning(s)");
    for d in &outcome.diagnostics {
        println!("  {d}");
    }
    to_read += errors + warnings;

    let mut drift = false;
    if let (Some(compiled), Some(lock)) = (&outcome.compiled, &lock) {
        let sources_same = project::read_sources(dir)?.iter().all(|s| {
            lock_value(lock, &format!("\"{}\"", s.path)).is_some_and(|h| {
                h == format!(
                    "sha256:{}",
                    falak_core::build::sha256_hex(s.text.as_bytes())
                )
            })
        });
        let recorded = recorded_ir_hash(lock).unwrap_or_default();
        if sources_same && recorded != compiled.ir.content_hash {
            drift = true;
            println!(
                "\nGenerated output changes: the same sources now compile to ir sha256:{} (lock has {recorded}).\n  do: run `falak migrate plan` and read it before deploying.",
                compiled.ir.content_hash
            );
        } else if !sources_same {
            println!("\nSources changed since the last build; the lock is refreshed on apply.");
        }
    }

    if has_errors(&outcome.diagnostics) {
        println!("\nResult: BLOCKED. Fix the errors above first; nothing was changed.");
        return Ok(1);
    }
    if !o.apply {
        println!(
            "\nResult: {to_read} item(s) to read{}. Nothing was changed. Run with --apply to rebuild falak.lock under {target}.",
            if drift { ", and the output drifts" } else { "" }
        );
        return Ok(if to_read > 0 || drift { 3 } else { 0 });
    }
    match project::build(dir)? {
        Some(c) => {
            println!(
                "\nApplied: falak.lock now records framework {target} (ir sha256:{}).",
                c.ir.content_hash
            );
            Ok(0)
        }
        None => Ok(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_order_and_reject() {
        assert!(parse_version("1.10.0") > parse_version("1.9.9"));
        assert_eq!(parse_version("1.0.0-rc.1"), Some((1, 0, 0)));
        assert_eq!(parse_version("1.0"), None);
    }

    #[test]
    fn table_filters_by_range() {
        let t = parse_table(
            "1.1.0 | schema | a | do a\n1.2.0 | api | b | do b\n2.0.0 | data | c | do c\n",
        )
        .unwrap();
        let hits = between(&t, "1.0.0", "1.2.0");
        assert_eq!(
            hits.iter().map(|c| c.what.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(between(&t, "1.2.0", "1.2.0").is_empty());
    }

    #[test]
    fn shipped_table_parses() {
        parse_table(TABLE).unwrap();
        assert!(parse_table("garbage").is_err());
    }
}
