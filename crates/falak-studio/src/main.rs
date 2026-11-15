//! `falak-studio serve --config studio.json [--port 8790] [--data DIR]`
//! `falak-studio audit-verify <audit.jsonl>`

use std::{path::PathBuf, sync::Arc};

use falak_studio::{Audit, Config, Studio, router};

fn usage() -> String {
    "usage: falak-studio serve --config studio.json [--port 8790] [--data DIR]\n       falak-studio audit-verify <audit.jsonl>".into()
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

async fn run() -> Result<(), String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("audit-verify") => {
            let path = argv.get(1).ok_or_else(usage)?;
            let n = Audit::verify(std::path::Path::new(path))?;
            println!("ok: {n} entries, each commits to the one before");
            Ok(())
        }
        Some("serve") => {
            let (mut config, mut listen, mut data) =
                (None, 8790u16, PathBuf::from(".falak-studio"));
            let mut it = argv.iter().skip(1);
            while let Some(a) = it.next() {
                let mut value =
                    |name: &str| it.next().cloned().ok_or(format!("`{name}` needs a value"));
                match a.as_str() {
                    "--config" => config = Some(PathBuf::from(value("--config")?)),
                    "--port" => {
                        listen = value("--port")?
                            .parse()
                            .map_err(|_| "`--port` is not a number".to_owned())?;
                    }
                    "--data" => data = PathBuf::from(value("--data")?),
                    other => return Err(format!("unknown option `{other}`\n{}", usage())),
                }
            }
            let cfg = Config::load(&config.ok_or_else(usage)?)?;
            let audit = Audit::open(Some(data.join("audit.jsonl")))?;
            let studio = Arc::new(Studio::new(cfg, audit));
            let socket = tokio::net::TcpListener::bind(("127.0.0.1", listen))
                .await
                .map_err(|e| format!("cannot listen on {listen}: {e}"))?;
            println!("falak-studio on http://127.0.0.1:{listen}");
            axum::serve(socket, router(studio))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
                .map_err(|e| e.to_string())
        }
        _ => Err(usage()),
    }
}
