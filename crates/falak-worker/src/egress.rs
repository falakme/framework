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
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use falak_egress::{Entry, Policy, Resolver};
use serde_json::{Value, json};

const MAX_BODY: u64 = 4 * 1024 * 1024;
/// The longest request line or header line the socket accepts, and how many headers.
const MAX_LINE: u64 = 8 * 1024;
const MAX_HEADERS: usize = 64;
/// Requests served at once per job. The job is untrusted code and must not be able to
/// exhaust the worker with connections.
const MAX_CONNECTIONS: usize = 8;

const METHODS: [&str; 6] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

/// Headers the job may not set: they would change how the request is framed or routed
/// rather than what it says, so a listed address could be asked for another virtual host.
fn header_allowed(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    !matches!(
        n.as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "upgrade"
            | "te"
            | "trailer"
            | "expect"
            | "proxy-authorization"
            | "proxy-connection"
    )
}

/// A job id is used in a path and a mount argument: letters, digits, `-` and `_` only.
pub fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

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
#[derive(Debug)]
struct Pinned(Vec<SocketAddr>);

impl ureq::unversioned::resolver::Resolver for Pinned {
    fn resolve(
        &self,
        _uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let mut out = self.empty();
        // The resolver holds at most 16 addresses.
        for a in self.0.iter().take(16) {
            out.push(*a);
        }
        if out.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(out)
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
    let method = request["method"].as_str().unwrap_or("GET").to_uppercase();
    if !METHODS.contains(&method.as_str()) {
        return json!({"status": 400, "error": "egress_bad_method"});
    }
    let permit = match policy.check(url, &System) {
        Ok(p) => p,
        Err(e) => return json!({"status": 403, "error": e.code()}),
    };
    let addrs: Vec<SocketAddr> = permit
        .addrs
        .iter()
        .map(|ip| SocketAddr::new(*ip, permit.port))
        .collect();
    // Connect only to the approved addresses; a refusal (4xx, 5xx) is an answer to pass
    // back, not an error; and a redirect is returned, never followed.
    let config = ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(60)))
        .build();
    let agent = ureq::Agent::with_parts(
        config,
        ureq::unversioned::transport::DefaultConnector::default(),
        Pinned(addrs),
    );
    let mut call = ureq::http::Request::builder()
        .method(method.as_str())
        .uri(url);
    for (k, v) in request["headers"].as_object().into_iter().flatten() {
        if let Some(v) = v.as_str()
            && header_allowed(k)
        {
            call = call.header(k.as_str(), v);
        }
    }
    let sent = match request["body"].as_str() {
        Some(b) => call.body(b.to_owned()).map(|r| agent.run(r)),
        None => call.body(()).map(|r| agent.run(r)),
    };
    let res = match sent {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return json!({"status": 502, "error": e.to_string()}),
        Err(e) => return json!({"status": 502, "error": e.to_string()}),
    };
    let status = res.status().as_u16();
    let location = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut body = String::new();
    let _ = res
        .into_body()
        .into_reader()
        .take(MAX_BODY)
        .read_to_string(&mut body);
    json!({"status": status, "body": body, "location": location})
}

fn handle(policy: &Policy, stream: std::os::unix::net::UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.by_ref().take(MAX_LINE).read_line(&mut line)?;
    let mut length = 0usize;
    for count in 0.. {
        let mut h = String::new();
        let n = reader.by_ref().take(MAX_LINE).read_line(&mut h)?;
        if h.trim().is_empty() {
            break;
        }
        if n as u64 >= MAX_LINE || count >= MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        if let Some((k, v)) = h.split_once(':')
            && k.eq_ignore_ascii_case("content-length")
        {
            length = v.trim().parse().unwrap_or(0);
        }
    }
    if length as u64 > MAX_BODY {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
    }
    let mut body = vec![0u8; length];
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
        // The id names a directory that is removed on drop and is mounted into the
        // container; it must not be able to climb out or add mount options.
        if !safe_id(job_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the job id is not a plain identifier",
            ));
        }
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
        let active = Arc::new(AtomicUsize::new(0));
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((s, _)) => {
                        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                            active.fetch_sub(1, Ordering::SeqCst);
                            continue;
                        }
                        let _ = s.set_nonblocking(false);
                        let p = policy.clone();
                        let a = active.clone();
                        thread::spawn(move || {
                            let _ = handle(&p, s);
                            a.fetch_sub(1, Ordering::SeqCst);
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
        assert_eq!(
            refused("https://user:pw@api.example.com/"),
            "egress_bad_url"
        );
    }

    #[test]
    fn a_job_cannot_smuggle_a_method_or_reframe_a_request() {
        let p = policy(&["api.example.com".into()]);
        let r = fetch(
            &p,
            &json!({"url": "https://api.example.com/", "method": "GET /x HTTP/1.1\r\nHost: evil"}),
        );
        assert_eq!(r["error"], "egress_bad_method");
        for h in ["Host", "content-length", "Transfer-Encoding", "CONNECTION"] {
            assert!(!header_allowed(h), "{h}");
        }
        assert!(header_allowed("authorization"));
    }

    #[test]
    fn a_job_id_cannot_climb_out_of_the_scratch_directory() {
        let dir = std::env::temp_dir();
        for bad in ["../..", "a/b", "x:/etc", "", "a b"] {
            assert!(Broker::start(&dir, bad, &[]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_endless_header_line_is_refused_not_buffered() {
        use std::os::unix::net::UnixStream;
        let dir = std::env::temp_dir();
        let broker = Broker::start(&dir, &format!("big{}", std::process::id()), &[]).unwrap();
        let mut s = UnixStream::connect(&broker.socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let junk = "a".repeat(64 * 1024);
        let _ = write!(s, "POST /fetch HTTP/1.1\r\nx-junk: {junk}\r\n\r\n");
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert!(!out.contains("\"status\""), "{out}");
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
