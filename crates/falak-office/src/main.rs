//! `falak-office`: run Office.
//!
//!   falak-office serve [--port 8788] [--data DIR] [--issuer URL]
//!   falak-office setup --email E --password-env VAR [--issuer URL]   (the first administrator)
//!   falak-office user add --email E --password-env VAR [--role office_admin]...
//!
//! `DATABASE_URL` selects PostgreSQL; without it Office keeps a SQLite file in the data
//! directory (for development). Signing keys live in the data directory with owner-only
//! permissions. In a container, set `FALAK_OFFICE_HOST=0.0.0.0`, `FALAK_OFFICE_PORT`,
//! `FALAK_OFFICE_DATA` and `FALAK_OFFICE_ISSUER` instead of flags.

use std::{path::PathBuf, sync::Arc};

use falak_auth::token::{TokenConfig, Verifier};
use falak_driver_postgres::{PostgresConfig, PostgresDriver};
use falak_driver_sqlite::{SqliteConfig, SqliteDriver};
use falak_office::{
    OFFICE_AUDIENCE, Office,
    db::Db,
    router,
    users::{open_postgres, open_sqlite},
};
use falak_runtime_native::{NativeDriver, auth_routes::AuthService};

struct Args {
    command: Vec<String>,
    host: String,
    port: u16,
    data: PathBuf,
    issuer: Option<String>,
    email: Option<String>,
    password_env: Option<String>,
    roles: Vec<String>,
    anchors: Option<PathBuf>,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        command: vec![],
        host: std::env::var("FALAK_OFFICE_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
        port: std::env::var("FALAK_OFFICE_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8788),
        data: PathBuf::from(
            std::env::var("FALAK_OFFICE_DATA").unwrap_or_else(|_| ".falak-office".into()),
        ),
        issuer: std::env::var("FALAK_OFFICE_ISSUER")
            .ok()
            .filter(|v| !v.is_empty()),
        email: None,
        password_env: None,
        roles: vec![],
        anchors: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("`{name}` needs a value"));
        match arg.as_str() {
            "--host" => a.host = value("--host")?,
            "--port" => a.port = value("--port")?.parse().map_err(|_| "bad port")?,
            "--data" => a.data = PathBuf::from(value("--data")?),
            "--issuer" => a.issuer = Some(value("--issuer")?),
            "--email" => a.email = Some(value("--email")?),
            "--password-env" => a.password_env = Some(value("--password-env")?),
            "--role" => a.roles.push(value("--role")?),
            "--anchors" => a.anchors = Some(PathBuf::from(value("--anchors")?)),
            other if other.starts_with('-') => return Err(format!("unknown option `{other}`")),
            other => a.command.push(other.to_owned()),
        }
    }
    Ok(a)
}

/// Everything Office needs, over the chosen database.
async fn open(a: &Args) -> Result<(Arc<Office>, Arc<dyn AuthService>), String> {
    std::fs::create_dir_all(&a.data)
        .map_err(|e| format!("cannot create the data directory: {e}"))?;
    let keys_path = a.data.join("signing-keys.json");
    let session_path = a.data.join("session-keys.json");
    let settings = falak_office::settings::Settings::load(&a.data)?;
    let issuer = a
        .issuer
        .clone()
        .or_else(|| settings.issuer.clone())
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", a.port));

    let session_config = TokenConfig {
        issuer: format!("{issuer}#session"),
        audience: OFFICE_AUDIENCE.into(),
        leeway_secs: 30,
    };
    let pg = |e: falak_contracts::Error| e.public_message().to_owned();
    let (driver, db): (Arc<dyn NativeDriver>, Db);
    let (pg_driver, sqlite_driver) = match std::env::var("DATABASE_URL") {
        Ok(url) if url.starts_with("postgres") => (
            Some(
                PostgresDriver::open(PostgresConfig {
                    url,
                    ..PostgresConfig::default()
                })
                .await
                .map_err(pg)?,
            ),
            None,
        ),
        _ => {
            let url = format!("sqlite://{}", a.data.join("office.db").display());
            (
                None,
                Some(
                    SqliteDriver::open(SqliteConfig {
                        url,
                        ..SqliteConfig::default()
                    })
                    .await
                    .map_err(pg)?,
                ),
            )
        }
    };
    if let Some(d) = &pg_driver {
        driver = Arc::new(d.clone());
    } else if let Some(d) = &sqlite_driver {
        driver = Arc::new(d.clone());
    } else {
        unreachable!("one driver is always opened");
    }
    db = Db::new(driver.clone());
    db.migrate().await.map_err(pg)?;
    // Keys live in the database so that any number of instances can run (HA); the files
    // in the data directory seed it the first time and stay as a local copy.
    let keys = falak_office::keystore::shared_keys(&db, "signing", &keys_path)
        .await
        .map_err(pg)?;
    let session_keys = falak_office::keystore::shared_keys(&db, "session", &session_path)
        .await
        .map_err(pg)?;
    let mut verifier = Verifier::new(session_config.clone());
    session_keys.trust_all(&mut verifier);
    let (login, users): (Arc<dyn AuthService>, _) = if let Some(d) = pg_driver {
        open_postgres(d, session_keys, session_config)
    } else if let Some(d) = sqlite_driver {
        open_sqlite(d, session_keys, session_config)
    } else {
        unreachable!("one driver is always opened");
    };
    users.migrate().await.map_err(pg)?;
    let mut office = Office::new(issuer, db, keys, Some(keys_path), verifier, users)
        .with_data_dir(a.data.clone())
        .with_kek(falak_office::vault::KekSet::load(&a.data)?);
    // The environment wins over what the web setup saved.
    if let Some(cfg) = falak_office::oidc::OidcConfig::from_env()? {
        println!("sign-in through {} is on", cfg.issuer);
        office = office.with_oidc(cfg);
    } else if let Some(saved) = &settings.oidc {
        let cfg = saved.config();
        cfg.validate()?;
        println!("sign-in through {} is on", cfg.issuer);
        office = office.with_oidc(cfg);
    }
    let office = Arc::new(office);
    office.refresh_keys().await.map_err(pg)?;
    Ok((office, login))
}

/// The loops a serving instance runs: pick up keys another instance rotated, anchor the
/// audit chain, and watch the service-level objectives.
fn spawn_background(office: Arc<Office>) {
    let o = office.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let _ = o.refresh_keys().await;
        }
    });
    let every: u64 = std::env::var("FALAK_AUDIT_ANCHOR_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(300);
    let o = office.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = o.anchor_now().await {
                eprintln!("audit anchoring failed: {}", e.public_message());
            }
            tokio::time::sleep(std::time::Duration::from_secs(every)).await;
        }
    });
    tokio::spawn(async move {
        let alerter = falak_office::observe::Alerter::default();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            office.watch_slos(&alerter).await;
        }
    });
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let a = match parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    match run(a).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

async fn run(a: Args) -> Result<(), String> {
    let cmd: Vec<&str> = a.command.iter().map(String::as_str).collect();
    match cmd.as_slice() {
        ["serve"] => {
            let (office, login) = open(&a).await?;
            let app = router(office.clone(), login);
            let listener = tokio::net::TcpListener::bind((a.host.as_str(), a.port))
                .await
                .map_err(|e| format!("cannot listen on port {}: {e}", a.port))?;
            println!(
                "falak-office on http://{}:{} (issuer {})",
                a.host, a.port, office.issuer
            );
            // Nobody has an account yet: say how to set Office up from a browser.
            if let Some(code) = office
                .arm_setup()
                .await
                .map_err(|e| e.public_message().to_owned())?
            {
                let shown = if a.host == "0.0.0.0" { "localhost" } else { a.host.as_str() };
                println!();
                println!("  Office is not set up yet. Open this in your browser:");
                println!("    http://{shown}:{}/?setup={code}", a.port);
                println!("  (or set up from the terminal: falak-office setup --email you@example.com --password-env PASSWORD_VAR)");
                println!();
            }
            spawn_background(office.clone());
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
                .map_err(|e| e.to_string())
        }
        ["setup"] => {
            // The same as the browser setup, for scripts and servers: the first
            // administrator, and optionally the public address.
            let (office, _) = open(&a).await?;
            let email = a.email.as_deref().ok_or("`--email` is required")?;
            let var = a.password_env.as_deref().ok_or(
                "`--password-env <VAR>` is required (the password is read from that variable)",
            )?;
            let password = std::env::var(var).map_err(|_| format!("`{var}` is not set"))?;
            if office
                .arm_setup()
                .await
                .map_err(|e| e.public_message().to_owned())?
                .is_none()
            {
                return Err("Office is already set up (it has accounts). Add people with `falak-office user add`.".into());
            }
            let id = office
                .users
                .create(email, &password, &["office_admin".to_owned()])
                .await
                .map_err(|e| e.public_message().to_owned())?;
            if let Some(addr) = &a.issuer {
                if !falak_office::settings::valid_address(addr) {
                    return Err("the public address is https (or http to this machine) with no trailing slash".into());
                }
                let mut s = falak_office::settings::Settings::load(&a.data)?;
                s.issuer = Some(addr.clone());
                s.save(&a.data)?;
            }
            println!("created the administrator {email} ({id})");
            println!("Start Office with: falak-office serve");
            println!("Then open it in a browser and sign in.");
            Ok(())
        }
        ["user", "add"] => {
            let (office, _) = open(&a).await?;
            let email = a.email.as_deref().ok_or("`--email` is required")?;
            let var = a.password_env.as_deref().ok_or(
                "`--password-env <VAR>` is required (the password is read from that variable)",
            )?;
            let password = std::env::var(var).map_err(|_| format!("`{var}` is not set"))?;
            let id = office
                .users
                .create(email, &password, &a.roles)
                .await
                .map_err(|e| e.public_message().to_owned())?;
            println!("created {email} ({id})");
            Ok(())
        }
        ["audit", "anchor"] => {
            let (office, _) = open(&a).await?;
            match office
                .anchor_now()
                .await
                .map_err(|e| e.public_message().to_owned())?
            {
                Some(x) => println!("anchored entry {} ({})", x.seq, x.hash),
                None => println!("nothing new to anchor"),
            }
            Ok(())
        }
        ["audit", "verify"] => {
            let (office, _) = open(&a).await?;
            let r = office
                .verify_audit(a.anchors.as_deref())
                .await
                .map_err(|e| e.public_message().to_owned())?;
            println!(
                "{} entries, {} anchors checked",
                r.entries, r.anchors_checked
            );
            for p in &r.problems {
                println!("PROBLEM: {p}");
            }
            if r.ok() {
                println!("the audit chain is intact");
                Ok(())
            } else {
                Err("the audit chain does not verify".into())
            }
        }
        _ => Err(
            "usage: falak-office serve | audit anchor | audit verify [--anchors DIR] | setup --email E --password-env VAR [--issuer URL] | user add --email E --password-env VAR [--role R]".into(),
        ),
    }
}
