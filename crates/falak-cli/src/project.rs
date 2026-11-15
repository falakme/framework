//! Find an app's files on disk and compile them.

use std::{
    fs,
    path::{Path, PathBuf},
};

use falak_core::{
    compile::{Compiled, compile},
    diagnostics::{Diagnostic, Severity, has_errors},
    load::SourceFile,
};

/// Version recorded in `falak.lock`.
pub const FRAMEWORK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Directories whose files are app sources. `workflows`, `events` and `jobs` are
/// reserved: they are read so the compiler can reject anything placed in them.
const SOURCE_DIRS: [&str; 6] = [
    "entities",
    "policies",
    "commands",
    "workflows",
    "events",
    "jobs",
];

/// Read every app source under `dir`. Paths are relative with forward slashes.
/// Hidden files (such as `.gitkeep`) are skipped.
pub fn read_sources(dir: &Path) -> Result<Vec<SourceFile>, String> {
    if !dir.is_dir() {
        return Err(format!("`{}` is not a directory", dir.display()));
    }
    let mut files = Vec::new();
    let app = dir.join("app.yaml");
    if app.is_file() {
        files.push(read_one(&app, "app.yaml".into())?);
    }
    for sub in SOURCE_DIRS {
        let path = dir.join(sub);
        if !path.is_dir() {
            continue;
        }
        let mut names: Vec<String> = fs::read_dir(&path)
            .map_err(|e| format!("cannot read `{}`: {e}", path.display()))?
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| !n.starts_with('.'))
            .collect();
        names.sort();
        for name in names {
            files.push(read_one(&path.join(&name), format!("{sub}/{name}"))?);
        }
    }
    Ok(files)
}

fn read_one(path: &Path, relative: String) -> Result<SourceFile, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read `{}`: {e}", path.display()))?;
    Ok(SourceFile {
        path: relative,
        text,
    })
}

/// Result of compiling an app directory.
pub struct Outcome {
    pub compiled: Option<Compiled>,
    pub diagnostics: Vec<Diagnostic>,
    pub sources: usize,
}

pub fn compile_dir(dir: &Path) -> Result<Outcome, String> {
    let files = read_sources(dir)?;
    if files.is_empty() {
        return Err(format!(
            "no app found in `{}`: there is no app.yaml (run `falak init` to create one)",
            dir.display()
        ));
    }
    let (compiled, diagnostics) = compile(&files, FRAMEWORK_VERSION);
    Ok(Outcome {
        compiled,
        diagnostics,
        sources: files.len(),
    })
}

/// Print diagnostics to standard error. Returns `(errors, warnings)`.
pub fn print_diagnostics(diagnostics: &[Diagnostic]) -> (usize, usize) {
    let mut errors = 0;
    let mut warnings = 0;
    for d in diagnostics {
        match d.severity {
            Severity::Error => errors += 1,
            Severity::Warning => warnings += 1,
        }
        eprintln!("{d}");
    }
    (errors, warnings)
}

/// Directory where build output goes.
pub fn out_dir(dir: &Path) -> PathBuf {
    dir.join(".falak")
}

/// Compile and write `falak.lock` and `.falak/ir.json`. Returns the compiled app.
pub fn build(dir: &Path) -> Result<Option<Compiled>, String> {
    let outcome = compile_dir(dir)?;
    let (errors, warnings) = print_diagnostics(&outcome.diagnostics);
    let Some(compiled) = outcome.compiled else {
        eprintln!("build failed: {errors} error(s), {warnings} warning(s)");
        return Ok(None);
    };
    debug_assert!(!has_errors(&outcome.diagnostics));
    fs::write(dir.join("falak.lock"), &compiled.lock)
        .map_err(|e| format!("cannot write falak.lock: {e}"))?;
    let out = out_dir(dir);
    fs::create_dir_all(&out).map_err(|e| format!("cannot create `{}`: {e}", out.display()))?;
    let json = serde_json::to_string_pretty(&compiled.ir)
        .map_err(|e| format!("cannot serialize the IR: {e}"))?;
    fs::write(out.join("ir.json"), json).map_err(|e| format!("cannot write ir.json: {e}"))?;
    Ok(Some(compiled))
}
