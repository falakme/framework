//! `falak-worker --office URL --kinds a,b [--runner container|process] ...`
//!
//! The credential is read from `FALAK_WORKER_CREDENTIAL`, never from the command line
//! (it would show in the process list).

use std::{path::PathBuf, process::ExitCode, sync::atomic::AtomicBool, time::Duration};

use falak_worker::{
    Agent, Config, Stop,
    client::Office,
    runner::{ContainerRunner, ProcessRunner, Runner},
};

const USAGE: &str = "usage: falak-worker --office URL --kinds KIND[,KIND...] [--runner container|process]
                    [--engine docker|podman] [--requirements-dir DIR] [--lease-ms N] [--poll-ms N] [--once]
environment: FALAK_WORKER_CREDENTIAL (required)
             FALAK_WORKER_UNSAFE_PROCESS=1 (required for --runner process, which does not isolate jobs)";

fn run(args: Vec<String>) -> Result<(), String> {
    let mut office = std::env::var("FALAK_OFFICE_URL").unwrap_or_default();
    let mut kinds: Vec<String> = vec![];
    let mut runner = "container".to_owned();
    let mut engine = "docker".to_owned();
    let mut requirements_dir: Option<PathBuf> = None;
    let (mut lease_ms, mut poll_ms, mut once) = (60_000u64, 2_000u64, false);
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match a.as_str() {
            "--office" => office = value("--office")?,
            "--kinds" => {
                kinds = value("--kinds")?
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "--runner" => runner = value("--runner")?,
            "--engine" => engine = value("--engine")?,
            "--requirements-dir" => requirements_dir = Some(value("--requirements-dir")?.into()),
            "--lease-ms" => {
                lease_ms = value("--lease-ms")?.parse().map_err(|_| "bad --lease-ms")?
            }
            "--poll-ms" => poll_ms = value("--poll-ms")?.parse().map_err(|_| "bad --poll-ms")?,
            "--once" => once = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unknown argument `{other}`\n{USAGE}")),
        }
    }
    if office.is_empty() || kinds.is_empty() {
        return Err(format!("--office and --kinds are required\n{USAGE}"));
    }
    let credential = std::env::var("FALAK_WORKER_CREDENTIAL")
        .map_err(|_| "set FALAK_WORKER_CREDENTIAL to the worker's credential")?;
    let config = Config {
        kinds,
        lease_millis: lease_ms,
        poll: Duration::from_millis(poll_ms),
        scratch: std::env::temp_dir(),
    };
    match runner.as_str() {
        "container" => drive(
            Agent {
                office: Office::new(&office, &credential),
                runner: ContainerRunner {
                    engine,
                    requirements_dir,
                },
                config,
            },
            once,
        ),
        "process" => {
            if std::env::var("FALAK_WORKER_UNSAFE_PROCESS").as_deref() != Ok("1") {
                return Err(
                    "--runner process runs jobs without isolation; set FALAK_WORKER_UNSAFE_PROCESS=1 to use it for tests"
                        .into(),
                );
            }
            drive(
                Agent {
                    office: Office::new(&office, &credential),
                    runner: ProcessRunner { requirements_dir },
                    config,
                },
                once,
            )
        }
        other => Err(format!("unknown runner `{other}`")),
    }
}

fn drive<R: Runner>(agent: Agent<R>, once: bool) -> Result<(), String> {
    let stop = AtomicBool::new(false);
    let result = if once {
        agent.run_once().map(|_| ())
    } else {
        agent.run_forever(&stop)
    };
    match result {
        Ok(()) => Ok(()),
        Err(Stop::Revoked) => Err("Office revoked this worker's credential".into()),
        Err(Stop::Transport(e)) => Err(e),
    }
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("falak-worker: {e}");
            ExitCode::from(1)
        }
    }
}
