//! `falak-office`: run Office.
//!
//!   falak-office serve [--port 8788] [--data DIR] [--issuer URL]
//!   falak-office user add --email E --password-env VAR [--role office_admin]...
//!
//! `DATABASE_URL` selects PostgreSQL; without it Office keeps a SQLite file in the data
//! directory (for development). Signing keys live in the data directory with owner-only
//! permissions.

use std::{path::PathBuf, sync::Arc};

use falak_auth::{
    keys::LocalKeys,
    token::{TokenConfig, Verifier},
};
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
    port: u16,
    data: PathBuf,
    issuer: Option<String>,
    email: Option<String>,
    password_env: Option<String>,
    roles: Vec<String>,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        command: vec![],
        port: 8788,
        data: PathBuf::from(".falak-office"),
        issuer: None,
        email: None,
        password_env: None,
        roles: vec![],
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("`{name}` needs a value"));
        match arg.as_str() {
            "--port" => a.port = value("--port")?.parse().map_err(|_| "bad port")?,
            "--data" => a.data = PathBuf::from(value("--data")?),
            "--issuer" => a.issuer = Some(value("--issuer")?),
            "--email" => a.email = Some(value("--email")?),
            "--password-env" => a.password_env = Some(value("--password-env")?),
            "--role" => a.roles.push(value("--role")?),
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
    let keys = LocalKeys::load_or_create(&keys_path).map_err(|e| e.public_message().to_owned())?;
    let session_keys =
        LocalKeys::load_or_create(&session_path).map_err(|e| e.public_message().to_owned())?;
    let issuer = a
        .issuer
        .clone()
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", a.port));

    let session_config = TokenConfig {
        issuer: format!("{issuer}#session"),
        audience: OFFICE_AUDIENCE.into(),
        leeway_secs: 30,
    };
    let mut verifier = Verifier::new(session_config.clone());
    LocalKeys::load_or_create(&session_path)
        .map_err(|e| e.public_message().to_owned())?
        .trust_all(&mut verifier);

    let (driver, login, users): (Arc<dyn NativeDriver>, Arc<dyn AuthService>, _) =
        match std::env::var("DATABASE_URL") {
            Ok(url) if url.starts_with("postgres") => {
                let d = PostgresDriver::open(PostgresConfig {
                    url,
                    ..PostgresConfig::default()
                })
                .await
                .map_err(|e| e.public_message().to_owned())?;
                let (login, users) = open_postgres(d.clone(), session_keys, session_config);
                (Arc::new(d), login, users)
            }
            _ => {
                let url = format!("sqlite://{}", a.data.join("office.db").display());
                let d = SqliteDriver::open(SqliteConfig {
                    url,
                    ..SqliteConfig::default()
                })
                .await
                .map_err(|e| e.public_message().to_owned())?;
                let (login, users) = open_sqlite(d.clone(), session_keys, session_config);
                (Arc::new(d), login, users)
            }
        };
    let db = Db::new(driver);
    db.migrate()
        .await
        .map_err(|e| e.public_message().to_owned())?;
    users
        .migrate()
        .await
        .map_err(|e| e.public_message().to_owned())?;
    let office = Arc::new(Office::new(
        issuer,
        db,
        keys,
        Some(keys_path),
        verifier,
        users,
    ));
    Ok((office, login))
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
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", a.port))
                .await
                .map_err(|e| format!("cannot listen on port {}: {e}", a.port))?;
            println!(
                "falak-office on http://127.0.0.1:{} (issuer {})",
                a.port, office.issuer
            );
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
                .map_err(|e| e.to_string())
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
        _ => Err(
            "usage: falak-office serve | user add --email E --password-env VAR [--role R]".into(),
        ),
    }
}
