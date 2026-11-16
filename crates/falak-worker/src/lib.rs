//! `falak-worker` (T7.3): an outbound-only agent for Office Compute.
//!
//! The worker **polls** Office for jobs, runs each in an isolated container (see
//! [`runner`]), keeps its lease alive with heartbeats, and reports the outcome. It opens
//! no listening socket, so the host needs no inbound firewall rule. If it dies, the lease
//! lapses and Office gives the job to another worker; if Office revokes its credential,
//! the next heartbeat is refused and the worker stops the job and exits.

pub mod client;
pub mod egress;
pub mod runner;

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use client::{ClientError, Leased, Office};
use runner::{RunError, RunRequest, Runner};

pub struct Config {
    pub kinds: Vec<String>,
    pub lease_millis: u64,
    pub poll: Duration,
    /// Where per-job egress sockets are made.
    pub scratch: PathBuf,
}

#[derive(Debug)]
pub enum Stop {
    /// Office refused our credential: it was revoked.
    Revoked,
    Transport(String),
}

pub struct Agent<R: Runner> {
    pub office: Office,
    pub runner: R,
    pub config: Config,
}

impl<R: Runner> Agent<R> {
    /// Lease at most one job and run it to the end. Returns whether a job was run.
    pub fn run_once(&self) -> Result<bool, Stop> {
        let leased = self
            .office
            .lease(&self.config.kinds, 1, self.config.lease_millis)
            .map_err(stop_of)?;
        let Some(job) = leased.into_iter().next() else {
            return Ok(false);
        };
        self.process(&job)?;
        Ok(true)
    }

    /// Poll until `stop` is set or Office revokes this worker.
    pub fn run_forever(&self, stop: &AtomicBool) -> Result<(), Stop> {
        while !stop.load(Ordering::SeqCst) {
            match self.run_once() {
                Ok(true) => continue,
                Ok(false) => {}
                // Office being unreachable is ordinary: try again later.
                Err(Stop::Transport(e)) => eprintln!("falak-worker: {e}"),
                Err(s) => return Err(s),
            }
            thread::sleep(self.config.poll);
        }
        Ok(())
    }

    fn process(&self, job: &Leased) -> Result<(), Stop> {
        let broker = if job.spec.egress.is_empty() {
            None
        } else {
            egress::Broker::start(&self.config.scratch, &job.job_id, &job.spec.egress).ok()
        };
        let payload = job.payload.to_string();
        let req = RunRequest {
            job_id: &job.job_id,
            kind: &job.kind,
            payload: &payload,
            spec: &job.spec,
            credential: &job.credential,
            office_url: &self.office.base,
            egress_socket: broker.as_ref().map(|b| b.socket.as_path()),
        };
        let cancel = AtomicBool::new(false);
        let every = Duration::from_millis((self.config.lease_millis / 3).max(200));
        let (tx, rx) = mpsc::channel();
        let mut verdict = Ok(());
        let outcome = thread::scope(|s| {
            s.spawn(|| {
                let _ = tx.send(self.runner.run(&req, &cancel));
            });
            loop {
                match rx.recv_timeout(every) {
                    Ok(o) => break o,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        match self
                            .office
                            .heartbeat(&job.lease_id, self.config.lease_millis)
                        {
                            Ok(()) => {}
                            // The lease is gone or the credential revoked: stop the job.
                            Err(ClientError::Rejected(code)) => {
                                cancel.store(true, Ordering::SeqCst);
                                if code == 401 || code == 403 {
                                    verdict = Err(Stop::Revoked);
                                }
                            }
                            Err(ClientError::Transport(e)) => {
                                eprintln!("falak-worker: heartbeat: {e}");
                            }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break Err(RunError::Cancelled),
                }
            }
        });
        verdict?;
        // Report, retrying a transport failure: a result that is not delivered is a job
        // that runs again.
        let report = |f: &dyn Fn() -> Result<(), ClientError>| {
            for attempt in 0..5u64 {
                match f() {
                    Err(ClientError::Transport(_)) => {
                        thread::sleep(Duration::from_millis(500 * (attempt + 1)));
                    }
                    // A refusal here means the lease was lost meanwhile; nothing to do.
                    other => return other,
                }
            }
            Ok(())
        };
        let done = match outcome {
            Ok(result) => report(&|| self.office.complete(&job.lease_id, result.as_ref())),
            Err(RunError::Failed(why)) => report(&|| self.office.fail(&job.lease_id, true, &why)),
            Err(RunError::Fatal(why)) => report(&|| self.office.fail(&job.lease_id, false, &why)),
            Err(RunError::Cancelled) => Ok(()),
        };
        match done {
            Err(ClientError::Rejected(401 | 403)) => Err(Stop::Revoked),
            _ => Ok(()),
        }
    }
}

fn stop_of(e: ClientError) -> Stop {
    match e {
        ClientError::Rejected(401 | 403) => Stop::Revoked,
        other => Stop::Transport(other.to_string()),
    }
}
