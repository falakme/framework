//! The single entry point the CLI and runtimes use: sources in, IR and lock out.

use falak_contracts::ir::Ir;

use crate::{
    build::build_ir,
    diagnostics::{Diagnostic, has_errors},
    load::{SourceFile, load_project},
    lock,
    requirements::check_drivers,
};

#[derive(Debug)]
pub struct Compiled {
    pub ir: Ir,
    /// Contents of `falak.lock`.
    pub lock: String,
}

/// Load, validate, check against the target drivers, build the IR and render the lock.
/// `output` is `Some` only if there are no errors; warnings are always returned.
pub fn compile(
    files: &[SourceFile],
    framework_version: &str,
) -> (Option<Compiled>, Vec<Diagnostic>) {
    let (project, mut diagnostics) = load_project(files);
    let Some(project) = project else {
        return (None, diagnostics);
    };
    let ir = build_ir(&project);
    diagnostics.extend(check_drivers(&project, &ir));
    if has_errors(&diagnostics) {
        return (None, diagnostics);
    }
    let lock = lock::render(&ir, framework_version, files);
    (Some(Compiled { ir, lock }), diagnostics)
}
