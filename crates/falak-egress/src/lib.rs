//! Outbound request control (T3.12).
//!
//! Handlers, jobs and upload fetches may call only hosts on a declared allow-list, and
//! never a private, loopback, link-local or cloud-metadata address. The address check
//! happens **after** DNS resolution, because a name on the allow-list can still point at
//! `169.254.169.254` (or be changed to, between check and connect: DNS rebinding). So
//! the caller must connect to the addresses this crate returns, not resolve again.
//!
//! This crate makes the decision and does no network I/O. The caller supplies a
//! [`Resolver`].
//!
//! Rules:
//! 1. Only `https` (or `http` if the allow-list entry says so explicitly).
//! 2. The URL has no user name or password.
//! 3. The host matches an allow-list entry: an exact name, or `*.example.com` for any
//!    subdomain (not the bare domain).
//! 4. A literal IP host is refused unless an entry lists that exact address, and even
//!    then it must pass the address check.
//! 5. Every resolved address must pass the address check. If any fails, the request is
//!    refused, so a name cannot hide a private address among public ones.
//! 6. Redirects are checked as new requests, from rule 1, and capped.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use falak_contracts::{Error, ErrorKind, Result};

/// Most redirects followed.
pub const MAX_REDIRECTS: u8 = 3;

fn refused(code: &'static str) -> Error {
    Error::new(
        ErrorKind::Forbidden,
        code,
        "The request to this address is not allowed.",
    )
}

// ---------------------------------------------------------------- addresses

/// True if `ip` may be contacted: it is a public, globally routable address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()                      // 0.0.0.0
        || ip.is_loopback()                    // 127.0.0.0/8
        || ip.is_private()                     // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()                  // 169.254/16, includes cloud metadata
        || ip.is_broadcast()
        || ip.is_multicast()                   // 224/4
        || a == 0                              // 0.0.0.0/8 "this network"
        || (a == 100 && (64..=127).contains(&b)) // 100.64/10 carrier-grade NAT
        || (a == 192 && b == 0 && c == 0)      // 192.0.0.0/24 IETF protocol assignments
        || (a == 192 && b == 0 && c == 2)      // 192.0.2.0/24 documentation
        || (a == 198 && (b == 18 || b == 19))  // 198.18/15 benchmarking
        || (a == 198 && b == 51 && c == 100)   // 198.51.100.0/24 documentation
        || (a == 203 && b == 0 && c == 113)    // 203.0.113.0/24 documentation
        || a >= 240) // 240/4 reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    // An IPv4 address carried inside IPv6 is judged as that IPv4 address.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let s = ip.segments();
    // 64:ff9b::/96 (NAT64) and 2002::/16 (6to4) embed an IPv4 address.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        let v4 = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
        return is_public_v4(v4);
    }
    if s[0] == 0x2002 {
        let v4 = Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8);
        return is_public_v4(v4);
    }
    !(ip.is_unspecified()                      // ::
        || ip.is_loopback()                    // ::1
        || ip.is_multicast()                   // ff00::/8
        || (s[0] & 0xfe00) == 0xfc00           // fc00::/7 unique local
        || (s[0] & 0xffc0) == 0xfe80           // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0           // fec0::/10 site-local (deprecated)
        || (s[0] == 0x2001 && s[1] == 0x0db8)  // 2001:db8::/32 documentation
        || (s[0] == 0x0100 && s[1..4] == [0, 0, 0]) // 100::/64 discard
        || (s[0] == 0x2001 && s[1] == 0 )) // 2001::/32 Teredo
}

// ---------------------------------------------------------------- allow-list

/// One allowed destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    host: HostPattern,
    allow_http: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPattern {
    /// `api.example.com`
    Exact(String),
    /// `*.example.com`: stored as `.example.com`.
    Subdomains(String),
    /// A literal address.
    Ip(IpAddr),
}

impl Entry {
    /// Parse `api.example.com`, `*.example.com` or a literal IP. Names are compared
    /// case-insensitively. Anything else is an error, so a typo does not become a
    /// wide-open rule.
    pub fn parse(text: &str) -> Result<Self> {
        let bad = || {
            Error::invalid_input(
                "invalid_egress_entry",
                "An outbound allow-list entry is not valid.",
            )
        };
        let text = text.trim().to_ascii_lowercase();
        if let Ok(ip) = text.parse::<IpAddr>() {
            return Ok(Self {
                host: HostPattern::Ip(ip),
                allow_http: false,
            });
        }
        let (pattern, name) = match text.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, text.as_str()),
        };
        if !valid_hostname(name) || (pattern && !name.contains('.')) {
            return Err(bad());
        }
        Ok(Self {
            host: if pattern {
                HostPattern::Subdomains(format!(".{name}"))
            } else {
                HostPattern::Exact(name.to_owned())
            },
            allow_http: false,
        })
    }

    /// Also allow plain `http` to this destination. Use only for private test targets
    /// that the address check would still refuse, so this rarely matters.
    #[must_use]
    pub fn allow_http(mut self) -> Self {
        self.allow_http = true;
        self
    }

    fn matches(&self, host: &Host) -> bool {
        match (&self.host, host) {
            (HostPattern::Exact(e), Host::Name(n)) => e == n,
            (HostPattern::Subdomains(suffix), Host::Name(n)) => {
                n.len() > suffix.len() && n.ends_with(suffix.as_str())
            }
            (HostPattern::Ip(a), Host::Ip(b)) => a == b,
            _ => false,
        }
    }
}

fn valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

// ---------------------------------------------------------------- URLs

#[derive(Debug, Clone, PartialEq, Eq)]
enum Host {
    Name(String),
    Ip(IpAddr),
}

/// The parts of a URL the policy needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub https: bool,
    host: Host,
    pub port: u16,
}

impl Target {
    /// The host as text (without brackets), for passing to a resolver.
    pub fn host(&self) -> String {
        match &self.host {
            Host::Name(n) => n.clone(),
            Host::Ip(ip) => ip.to_string(),
        }
    }
}

/// Parse an absolute `http` or `https` URL. Deliberately small: it rejects what it does
/// not understand instead of guessing.
pub fn parse_url(url: &str) -> Result<Target> {
    let deny = |c| refused(c);
    if url
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return Err(deny("egress_bad_url"));
    }
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(deny("egress_scheme"));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(deny("egress_bad_url"));
    }
    let default_port = if https { 443 } else { 80 };
    let (host_text, port) = if let Some(inner) = authority.strip_prefix('[') {
        // [v6]:port
        let (h, after) = inner
            .split_once(']')
            .ok_or_else(|| deny("egress_bad_url"))?;
        let port = match after.strip_prefix(':') {
            None if after.is_empty() => default_port,
            Some(p) => p.parse().map_err(|_| deny("egress_bad_url"))?,
            None => return Err(deny("egress_bad_url")),
        };
        (h, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| deny("egress_bad_url"))?),
            None => (authority, default_port),
        }
    };
    if port == 0 {
        return Err(deny("egress_bad_url"));
    }
    let host = if let Ok(ip) = host_text.parse::<IpAddr>() {
        Host::Ip(ip)
    } else if host_text
        .bytes()
        .all(|b| b.is_ascii_digit() || b == b'.' || b == b'x' || b == b'X')
        || host_text.starts_with("0x")
    {
        // Forms like `2130706433`, `0x7f.1` or `127.1` that some stacks read as IPv4.
        return Err(deny("egress_bad_url"));
    } else {
        let name = host_text.trim_end_matches('.').to_ascii_lowercase();
        if !valid_hostname(&name) {
            return Err(deny("egress_bad_url"));
        }
        Host::Name(name)
    };
    Ok(Target { https, host, port })
}

// ---------------------------------------------------------------- policy

/// Looks up a name. The caller implements it with the platform's resolver.
pub trait Resolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>>;
}

/// The allow-list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    entries: Vec<Entry>,
}

/// A permitted destination: connect to one of `addrs` on `port`, and do not resolve the
/// name again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permit {
    pub addrs: Vec<IpAddr>,
    pub port: u16,
    pub https: bool,
}

impl Policy {
    /// An empty policy permits nothing.
    pub fn new(entries: Vec<Entry>) -> Self {
        Self { entries }
    }

    /// Check a URL and return where to connect.
    pub fn check(&self, url: &str, resolver: &impl Resolver) -> Result<Permit> {
        let target = parse_url(url)?;
        let entry = self
            .entries
            .iter()
            .find(|e| e.matches(&target.host))
            .ok_or_else(|| refused("egress_not_listed"))?;
        if !target.https && !entry.allow_http {
            return Err(refused("egress_scheme"));
        }
        let addrs = match &target.host {
            Host::Ip(ip) => vec![*ip],
            Host::Name(name) => resolver.resolve(name)?,
        };
        if addrs.is_empty() {
            return Err(refused("egress_no_address"));
        }
        // Every address must pass: one private address among public ones is refused.
        if addrs.iter().any(|ip| !is_public(*ip)) {
            return Err(refused("egress_private_address"));
        }
        Ok(Permit {
            addrs,
            port: target.port,
            https: target.https,
        })
    }

    /// Check a redirect. `hops` is how many redirects were already followed. The new
    /// location is checked from scratch: it is a new request.
    pub fn check_redirect(
        &self,
        location: &str,
        hops: u8,
        resolver: &impl Resolver,
    ) -> Result<Permit> {
        if hops >= MAX_REDIRECTS {
            return Err(refused("egress_too_many_redirects"));
        }
        self.check(location, resolver)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct Fixed(HashMap<&'static str, Vec<IpAddr>>);
    impl Resolver for Fixed {
        fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
            Ok(self.0.get(host).cloned().unwrap_or_default())
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn dns(list: &[(&'static str, &[&str])]) -> Fixed {
        Fixed(
            list.iter()
                .map(|(h, ips)| (*h, ips.iter().map(|s| ip(s)).collect()))
                .collect(),
        )
    }

    fn policy(entries: &[&str]) -> Policy {
        Policy::new(entries.iter().map(|e| Entry::parse(e).unwrap()).collect())
    }

    #[test]
    fn public_and_private_addresses() {
        for public in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(is_public(ip(public)), "{public}");
        }
        for private in [
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "203.0.113.5",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
            "fec0::1",
        ] {
            assert!(!is_public(ip(private)), "{private}");
        }
    }

    #[test]
    fn the_edges_of_the_private_ranges() {
        assert!(is_public(ip("172.15.255.255")));
        assert!(!is_public(ip("172.16.0.0")));
        assert!(!is_public(ip("172.31.255.255")));
        assert!(is_public(ip("172.32.0.0")));
        assert!(is_public(ip("100.63.255.255")));
        assert!(is_public(ip("100.128.0.0")));
    }

    #[test]
    fn allows_a_listed_host_with_a_public_address() {
        let p = policy(&["api.example.com"]);
        let r = dns(&[("api.example.com", &["93.184.216.34"])]);
        let permit = p.check("https://API.example.com/v1/x?y=1", &r).unwrap();
        assert_eq!(permit.addrs, [ip("93.184.216.34")]);
        assert_eq!(permit.port, 443);
        assert!(permit.https);
    }

    #[test]
    fn refuses_an_unlisted_host() {
        let p = policy(&["api.example.com"]);
        let r = dns(&[("evil.example.com", &["93.184.216.34"])]);
        for url in [
            "https://evil.example.com/",
            "https://example.com/",
            "https://api.example.com.evil.com/",
        ] {
            assert_eq!(
                p.check(url, &r).unwrap_err().code(),
                "egress_not_listed",
                "{url}"
            );
        }
        assert_eq!(
            Policy::default()
                .check("https://api.example.com/", &r)
                .unwrap_err()
                .code(),
            "egress_not_listed"
        );
    }

    #[test]
    fn wildcards_match_subdomains_only() {
        let p = policy(&["*.example.com"]);
        let r = dns(&[
            ("a.example.com", &["93.184.216.34"]),
            ("x.y.example.com", &["93.184.216.34"]),
            ("example.com", &["93.184.216.34"]),
            ("badexample.com", &["93.184.216.34"]),
        ]);
        assert!(p.check("https://a.example.com/", &r).is_ok());
        assert!(p.check("https://x.y.example.com/", &r).is_ok());
        assert!(p.check("https://example.com/", &r).is_err());
        assert!(p.check("https://badexample.com/", &r).is_err());
    }

    #[test]
    fn a_listed_name_that_resolves_to_a_private_address_is_refused() {
        let p = policy(&["api.example.com"]);
        for bad in ["169.254.169.254", "127.0.0.1", "10.1.2.3", "::1", "fd00::1"] {
            let r = dns(&[("api.example.com", &[bad])]);
            assert_eq!(
                p.check("https://api.example.com/", &r).unwrap_err().code(),
                "egress_private_address",
                "{bad}"
            );
        }
    }

    #[test]
    fn one_private_address_among_public_ones_refuses_the_whole_name() {
        let p = policy(&["api.example.com"]);
        let r = dns(&[("api.example.com", &["93.184.216.34", "10.0.0.5"])]);
        assert!(p.check("https://api.example.com/", &r).is_err());
    }

    #[test]
    fn no_address_is_a_refusal() {
        let p = policy(&["api.example.com"]);
        let r = dns(&[]);
        assert_eq!(
            p.check("https://api.example.com/", &r).unwrap_err().code(),
            "egress_no_address"
        );
    }

    #[test]
    fn literal_ips_need_their_own_entry_and_still_must_be_public() {
        let r = dns(&[]);
        assert!(
            policy(&["api.example.com"])
                .check("https://8.8.8.8/", &r)
                .is_err()
        );
        assert!(policy(&["8.8.8.8"]).check("https://8.8.8.8/", &r).is_ok());
        assert_eq!(
            policy(&["127.0.0.1"])
                .check("https://127.0.0.1/", &r)
                .unwrap_err()
                .code(),
            "egress_private_address"
        );
        assert!(
            policy(&["2606:4700:4700::1111"])
                .check("https://[2606:4700:4700::1111]:8443/x", &r)
                .is_ok()
        );
    }

    #[test]
    fn disguised_ip_forms_are_refused() {
        let p = policy(&["*.example.com", "api.example.com"]);
        let r = dns(&[]);
        for url in [
            "https://2130706433/", // decimal 127.0.0.1
            "https://0x7f000001/",
            "https://0x7f.0.0.1/",
            "https://127.1/",
            "https://017700000001/",
            "https://[::ffff:7f00:1]/",
            "https://localhost/",
        ] {
            assert!(p.check(url, &r).is_err(), "{url}");
        }
    }

    #[test]
    fn malformed_urls_are_refused() {
        let p = policy(&["api.example.com"]);
        let r = dns(&[("api.example.com", &["93.184.216.34"])]);
        for url in [
            "",
            "api.example.com",
            "ftp://api.example.com/",
            "file:///etc/passwd",
            "gopher://x/",
            "https://",
            "https:///x",
            "https://user@api.example.com/",
            "https://user:pw@api.example.com/",
            "https://api.example.com@evil.com/",
            "https://api.example.com:0/",
            "https://api.example.com:99999/",
            "https://api.example.com\\@evil.com/",
            "https://api.example.com/\n",
            "https://api example.com/",
            "https://[::1/",
            "//api.example.com/",
            "javascript:alert(1)",
        ] {
            assert!(p.check(url, &r).is_err(), "{url:?}");
        }
    }

    #[test]
    fn http_needs_an_explicit_opt_in() {
        let r = dns(&[("api.example.com", &["93.184.216.34"])]);
        assert_eq!(
            policy(&["api.example.com"])
                .check("http://api.example.com/", &r)
                .unwrap_err()
                .code(),
            "egress_scheme"
        );
        let p = Policy::new(vec![Entry::parse("api.example.com").unwrap().allow_http()]);
        let permit = p.check("http://api.example.com:8080/", &r).unwrap();
        assert!(!permit.https);
        assert_eq!(permit.port, 8080);
    }

    #[test]
    fn redirects_are_checked_again_and_capped() {
        let p = policy(&["api.example.com"]);
        let r = dns(&[
            ("api.example.com", &["93.184.216.34"]),
            ("internal.example.net", &["10.0.0.9"]),
        ]);
        assert!(
            p.check_redirect("https://api.example.com/next", 0, &r)
                .is_ok()
        );
        assert!(
            p.check_redirect("https://internal.example.net/", 0, &r)
                .is_err()
        );
        assert!(
            p.check_redirect("http://169.254.169.254/latest/meta-data", 0, &r)
                .is_err()
        );
        assert_eq!(
            p.check_redirect("https://api.example.com/next", MAX_REDIRECTS, &r)
                .unwrap_err()
                .code(),
            "egress_too_many_redirects"
        );
    }

    #[test]
    fn bad_entries_are_rejected() {
        for bad in [
            "",
            "*",
            "*.com.",
            "*.",
            "a b",
            "-x.com",
            "x..com",
            "https://x.com",
            "x.com/path",
            "ex*mple.com",
            "*example.com",
        ] {
            assert!(Entry::parse(bad).is_err(), "{bad:?}");
        }
        assert!(Entry::parse("  API.Example.COM ").is_ok());
        assert!(Entry::parse("*.example.com").is_ok());
    }
}
