//! Per-job egress (T7.4). A job's container has no network. A job that lists hosts in its
//! contract gets a Unix socket instead, and asks the worker to fetch for it:
//!
//! ```text
//! POST /fetch   {"method": "GET", "url": "https://api.example.com/x", "body": "..."}
//! -> {"status": 200, "body": "..."}      or   {"status": 403, "error": "egress_not_listed"}
//! ```
//!
//! The worker checks each URL against the contract's allow-list with `falak-egress`
//! (listed host, `https`, no private or metadata address after DNS) and connects to the
//! addresses that check returned, so a name cannot be re-pointed between check and
//! connect. Redirects are not followed: the job asks again, and the new URL is checked.
//! A Unix socket is not a network port: the worker host still accepts no connections.

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, ToSocketAddrs},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use falak_egress::{Entry, Policy, Resolver};
use serde_json::{Value, json};

const MAX_BODY: u64 = 4 * 1024 * 1024;

struct System;

impl Resolver for System {
    fn resolve(&self, host: &str) -> falak_contracts::Result<Vec<std::net::IpAddr>> {
        (host, 443)
            .to_socket_addrs()
            .map(|a| a.map(|s| s.ip()).collect())
            .map_err(|_| falak_contracts::Error::not_found())
    }
}

/// Connects only to the addresses the policy approved.
struct Pinned(Vec<SocketAddr>);

impl ureq::Resolver for Pinned {
    fn resolve(&self, _netloc: &str) -> io::Result<Vec<SocketAddr>> {
        Ok(self.0.clone())
    }
}

/// The allow-list for a job. Entries that do not parse are dropped (a typo permits
/// nothing).
pub fn policy(hosts: &[String]) -> Policy {
    Policy::new(hosts.iter().filter_map(|h| Entry::parse(h).ok()).collect())
}

/// Decide a fetch and perform it. Pure of the socket, so it is testable.
pub fn fetch(policy: &Policy, request: &Value) -> Value {
    let url = request["url"].as_str().unwrap_or_default();
    let permit = match policy.check(url, &System) {
        Ok(p) => p,
        Err(e) => return json!({"status": 403, "error": e.code()}),
    };
    let addrs: Vec<SocketAddr> = permit
        .addrs
        .iter()
        .map(|ip| SocketAddr::new(*ip, permit.port))
        .collect();
    let agent = ureq::AgentBuilder::new()
        .resolver(Pinned(addrs))
        .redirects(0)
        .timeout(Duration::from_secs(60))
        .build();
    let method = request["method"].as_str().unwrap_or("GET").to_uppercase();
    let mut call = agent.request(&method, url);
    for (k, v) in request["headers"].as_object().into_iter().flatten() {
        if let Some(v) = v.as_str() {
            call = call.set(k, v);
        }
    }
    let res = match request["body"].as_str() {
        Some(b) => call.send_string(b),
        None => call.call(),
    };
    let res = match res {
        Ok(r) | Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return json!({"status": 502, "error": e.to_string()}),
    };
    let status = res.status();
    let location = res.header("location").map(str::to_owned);
    let mut body = String::new();
    let _ = res.into_reader().take(MAX_BODY).read_to_string(&mut body);
    json!({"status": status, "body": body, "location": location})
}

fn handle(policy: &Policy, stream: std::os::unix::net::UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut length = 0usize;
    loop {
        let mut h = String::new();
        reader.read_line(&mut h)?;
        if h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':')
            && k.eq_ignore_ascii_case("content-length")
        {
            length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; length.min(MAX_BODY as usize)];
    reader.read_exact(&mut body)?;
    let out = match serde_json::from_slice::<Value>(&body) {
        Ok(v) if line.starts_with("POST /fetch") => fetch(policy, &v),
        _ => json!({"status": 400, "error": "expected POST /fetch with a JSON body"}),
    };
    let text = out.to_string();
    let mut w = stream;
    write!(
        w,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
        text.len()
    )
}

/// The socket one job talks to. Dropping it closes the socket and removes the files.
pub struct Broker {
    pub socket: PathBuf,
    dir: PathBuf,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Broker {
    pub fn start(parent: &Path, job_id: &str, hosts: &[String]) -> io::Result<Self> {
        let dir = parent.join(format!("falak-egress-{job_id}"));
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        let socket = dir.join("egress.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket)?;
        // The job runs as another user and must be able to connect.
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let policy = Arc::new(policy(hosts));
        let flag = stop.clone();
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((s, _)) => {
                        let _ = s.set_nonblocking(false);
                        let p = policy.clone();
                        thread::spawn(move || {
                            let _ = handle(&p, s);
                        });
                    }
                    Err(_) => thread::sleep(Duration::from_millis(50)),
                }
            }
        });
        Ok(Self {
            socket,
            dir,
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listed_public_https_hosts_are_fetched() {
        let p = policy(&["api.example.com".into(), "*.good.example".into()]);
        let refused = |url: &str| {
            let r = fetch(&p, &json!({"url": url}));
            assert_eq!(r["status"], 403, "{url}: {r}");
            r["error"].as_str().unwrap().to_owned()
        };
        assert_eq!(refused("https://evil.example.org/x"), "egress_not_listed");
        assert_eq!(refused("http://api.example.com/x"), "egress_scheme");
        assert_eq!(
            refused("https://169.254.169.254/latest"),
            "egress_not_listed"
        );
        assert_eq!(refused("https://user:pw@api.example.com/"), "egress_bad_url");
    }

    #[test]
    fn an_empty_list_permits_nothing() {
        let r = fetch(&policy(&[]), &json!({"url": "https://api.example.com/"}));
        assert_eq!(r["status"], 403);
    }

    #[test]
    fn the_socket_answers_and_cleans_up() {
        use std::os::unix::net::UnixStream;
        let dir = std::env::temp_dir();
        let broker = Broker::start(&dir, &format!("t{}", std::process::id()), &[]).unwrap();
        let mut s = UnixStream::connect(&broker.socket).unwrap();
        let body = r#"{"url":"https://api.example.com/"}"#;
        write!(
            s,
            "POST /fetch HTTP/1.1\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.contains("\"status\":403"), "{out}");
        let path = broker.socket.clone();
        drop(broker);
        assert!(!path.exists());
    }
}
