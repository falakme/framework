//! Embeds the compiled app. `falak deploy` sets `FALAK_IR_FILE` to the app's
//! `.falak/ir.json`. Without it the crate still builds, and the Worker answers 503.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=FALAK_IR_FILE");
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("ir.json");
    match env::var("FALAK_IR_FILE") {
        Ok(path) => {
            println!("cargo:rerun-if-changed={path}");
            fs::copy(&path, &out)
                .unwrap_or_else(|e| panic!("cannot read FALAK_IR_FILE {path}: {e}"));
        }
        Err(_) => fs::write(&out, "").expect("write placeholder"),
    }
}
