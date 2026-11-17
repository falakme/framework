//! Running one job. The agent talks to a [`Runner`]; production uses
//! [`ContainerRunner`] and tests use [`ProcessRunner`].
//!
//! A job reads its payload (JSON) on standard input and prints its result (a JSON
//! value) as the last line of standard output. Anything else it writes is a log.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use falak_contracts::ir::IrJob;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// What the runner needs to know about one job.
pub struct RunRequest<'a> {
    pub job_id: &'a str,
    pub kind: &'a str,
    pub payload: &'a str,
    pub spec: &'a IrJob,
    /// The job's own credential.
    pub credential: &'a str,
    pub office_url: &'a str,
    /// Where the job reaches the allow-listed hosts (see `egress`), if it may reach any.
    pub egress_socket: Option<&'a Path>,
}

#[derive(Debug)]
pub enum RunError {
    /// Worth another attempt.
    Failed(String),
    /// Retrying cannot help.
    Fatal(String),
    /// The agent stopped the job (lost lease or revoked credential).
    Cancelled,
}

pub trait Runner: Send + Sync {
    fn run(&self, req: &RunRequest, cancel: &AtomicBool) -> Result<Option<Value>, RunError>;
}

/// Refuse a job whose identifiers would reach the container engine or the file system as
/// something other than a plain value: a job id or name with `/`, `:` or `..`, an image
/// that starts with `-` (the engine would read it as an option such as `--privileged`).
pub fn validate(req: &RunRequest) -> Result<(), RunError> {
    let image = &req.spec.image;
    if !crate::egress::safe_id(req.job_id)
        || !crate::egress::safe_id(&req.spec.name)
        || image.is_empty()
        || image.starts_with('-')
        || image.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(RunError::Fatal(
            "the job's id, name or image is not a plain value".into(),
        ));
    }
    Ok(())
}

/// Hash check for a job's pinned `uv` requirements: the file the worker would mount must
/// be exactly the one the contract names.
pub fn verify_requirements(dir: Option<&Path>, spec: &IrJob) -> Result<Option<PathBuf>, RunError> {
    let Some(want) = &spec.requirements_sha256 else {
        return Ok(None);
    };
    let dir = dir.ok_or_else(|| {
        RunError::Fatal("the job pins requirements but the worker has no --requirements-dir".into())
    })?;
    let path = dir.join(format!("{}.txt", spec.name));
    let bytes = std::fs::read(&path)
        .map_err(|e| RunError::Fatal(format!("cannot read {}: {e}", path.display())))?;
    let got = hex::encode(Sha256::digest(&bytes));
    if &got != want {
        return Err(RunError::Fatal(format!(
            "requirements for `{}` do not match the contract's sha256",
            spec.name
        )));
    }
    Ok(Some(path))
}

/// Run `child` to the end: feed it the payload, collect output, enforce the timeout and
/// obey `cancel`. `kill` is called when the job must be stopped.
fn supervise(
    mut child: Child,
    payload: &str,
    timeout: Duration,
    cancel: &AtomicBool,
    kill: &dyn Fn(&mut Child),
) -> Result<Option<Value>, RunError> {
    if let Some(mut stdin) = child.stdin.take() {
        let data = payload.to_owned();
        // A job that never reads its input must not block the supervisor.
        thread::spawn(move || {
            let _ = stdin.write_all(data.as_bytes());
        });
    }
    let reader = |mut r: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = r.by_ref().take(4 * 1024 * 1024).read_to_end(&mut buf);
            // Keep draining so the job never blocks on a full pipe.
            let _ = std::io::copy(&mut r, &mut std::io::sink());
            String::from_utf8_lossy(&buf).into_owned()
        })
    };
    let out = child.stdout.take().map(|s| reader(Box::new(s)));
    let err = child.stderr.take().map(|s| reader(Box::new(s)));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => return Err(RunError::Failed(e.to_string())),
        }
        if cancel.load(Ordering::SeqCst) {
            kill(&mut child);
            let _ = child.wait();
            return Err(RunError::Cancelled);
        }
        if started.elapsed() > timeout {
            kill(&mut child);
            let _ = child.wait();
            return Err(RunError::Failed(format!(
                "timed out after {}s",
                timeout.as_secs()
            )));
        }
        thread::sleep(Duration::from_millis(50));
    };
    let stdout = out.and_then(|h| h.join().ok()).unwrap_or_default();
    let stderr = err.and_then(|h| h.join().ok()).unwrap_or_default();
    if !status.success() {
        let tail: String = stderr
            .chars()
            .rev()
            .take(400)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        return Err(RunError::Failed(format!("exit {status}: {}", tail.trim())));
    }
    Ok(stdout
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| serde_json::from_str::<Value>(l).ok()))
}

fn timeout_of(spec: &IrJob) -> Duration {
    Duration::from_secs(u64::from(spec.timeout_seconds))
}

// ---------------------------------------------------------------- process (tests)

/// Runs the contract's `command` as a plain child process. **Not isolated**: for tests and
/// local development only. The binary refuses it unless the operator says so.
pub struct ProcessRunner {
    pub requirements_dir: Option<PathBuf>,
}

impl Runner for ProcessRunner {
    fn run(&self, req: &RunRequest, cancel: &AtomicBool) -> Result<Option<Value>, RunError> {
        validate(req)?;
        let req_file = verify_requirements(self.requirements_dir.as_deref(), req.spec)?;
        let (program, args) = req
            .spec
            .command
            .split_first()
            .ok_or_else(|| RunError::Fatal("the job has no command".into()))?;
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("FALAK_JOB_ID", req.job_id)
            .env("FALAK_JOB_KIND", req.kind)
            .env("FALAK_JOB_TOKEN", req.credential)
            .env("FALAK_OFFICE_URL", req.office_url)
            .env("FALAK_EGRESS_ALLOW", req.spec.egress.join(","))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(s) = req.egress_socket {
            cmd.env("FALAK_EGRESS_SOCKET", s);
        }
        if let Some(r) = req_file {
            cmd.env("FALAK_REQUIREMENTS", r);
        }
        let child = cmd
            .spawn()
            .map_err(|e| RunError::Failed(format!("cannot start `{program}`: {e}")))?;
        supervise(child, req.payload, timeout_of(req.spec), cancel, &|c| {
            let _ = c.kill();
        })
    }
}

// ---------------------------------------------------------------- containers

/// Runs each job in its own container: a non-root user, a read-only root file system, no
/// capabilities, no new privileges, memory/CPU/process limits, and no network at all
/// (the allow-listed hosts are reached through the worker's egress socket).
pub struct ContainerRunner {
    /// `docker` or `podman`.
    pub engine: String,
    pub requirements_dir: Option<PathBuf>,
}

/// The container engine's arguments for one job. Pure, so the isolation it asks for can
/// be tested without an engine.
pub fn container_args(req: &RunRequest, name: &str, requirements: Option<&Path>) -> Vec<String> {
    let s = req.spec;
    let mut a: Vec<String> = [
        "run",
        "--rm",
        "-i",
        "--user",
        "65534:65534",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--network",
        "none",
    ]
    .iter()
    .map(|x| (*x).to_owned())
    .collect();
    a.extend(["--name".into(), name.to_owned()]);
    a.extend(["--memory".into(), format!("{}m", s.memory_mb)]);
    a.extend(["--memory-swap".into(), format!("{}m", s.memory_mb)]);
    a.extend(["--cpus".into(), s.cpus.to_string()]);
    for (k, v) in [("FALAK_JOB_ID", req.job_id), ("FALAK_JOB_KIND", req.kind)] {
        a.extend(["-e".into(), format!("{k}={v}")]);
    }
    // No value: the engine takes it from its own environment (see `ContainerRunner`), so
    // the job's credential is not on a command line that `ps` shows to other users.
    a.extend(["-e".into(), "FALAK_JOB_TOKEN".into()]);
    a.extend([
        "-e".into(),
        format!("FALAK_EGRESS_ALLOW={}", s.egress.join(",")),
    ]);
    if let Some(sock) = req.egress_socket
        && let Some(dir) = sock.parent()
    {
        a.extend(["-v".into(), format!("{}:/run/falak", dir.display())]);
        a.extend([
            "-e".into(),
            "FALAK_EGRESS_SOCKET=/run/falak/egress.sock".into(),
        ]);
    }
    if let Some(r) = requirements {
        a.extend(["-v".into(), format!("{}:/requirements.txt:ro", r.display())]);
        a.extend(["-e".into(), "FALAK_REQUIREMENTS=/requirements.txt".into()]);
        a.extend(["-e".into(), "UV_REQUIRE_HASHES=1".into()]);
    }
    a.push(s.image.clone());
    a.extend(s.command.iter().cloned());
    a
}

impl Runner for ContainerRunner {
    fn run(&self, req: &RunRequest, cancel: &AtomicBool) -> Result<Option<Value>, RunError> {
        validate(req)?;
        let requirements = verify_requirements(self.requirements_dir.as_deref(), req.spec)?;
        let name = format!("falak-job-{}", req.job_id);
        let child = Command::new(&self.engine)
            .args(container_args(req, &name, requirements.as_deref()))
            .env("FALAK_JOB_TOKEN", req.credential)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| RunError::Failed(format!("cannot start {}: {e}", self.engine)))?;
        let engine = self.engine.clone();
        supervise(
            child,
            req.payload,
            timeout_of(req.spec),
            cancel,
            &move |c| {
                // Killing the client leaves the container running, so stop the container.
                let _ = Command::new(&engine).args(["kill", &name]).output();
                let _ = c.kill();
            },
        )
    }
}
