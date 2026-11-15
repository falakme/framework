//! `falak serve` and `falak dev`.
//!
//! Waiting on the native runtime (T1.7, Dev2). Until it is merged this only validates
//! the app, so `falak dev` already reports errors as files change.

use std::{path::Path, thread, time::Duration};

use crate::{project, watch};

pub fn run(dir: &Path, port: u16, watch_files: bool) -> Result<u8, String> {
    let _ = port;
    if !watch_files {
        return Err(not_ready());
    }
    // Rebuild on change so diagnostics appear while editing. The server joins this
    // loop when the runtime lands.
    let mut last = watch::fingerprint(dir);
    let ok = project::build(dir)?.is_some();
    println!("{}", if ok { "built" } else { "waiting for fixes" });
    eprintln!("{}", not_ready());
    loop {
        thread::sleep(Duration::from_millis(500));
        let now = watch::fingerprint(dir);
        if now != last {
            last = now;
            let ok = project::build(dir)?.is_some();
            println!("{}", if ok { "rebuilt" } else { "waiting for fixes" });
        }
    }
}

fn not_ready() -> String {
    "serving needs the native runtime (T1.7), which is not merged yet".into()
}
