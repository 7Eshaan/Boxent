//! Profiles: which hosts and ports a sandbox may reach.

use std::net::IpAddr;

use serde::Deserialize;

/// An operator-defined egress profile. Agents pick one by name; they cannot change its rules.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    /// Hosts allowed: `example.com` exactly, or `*.example.com` for any subdomain (not the
    /// apex itself).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Destination ports allowed. Default: 443 and 80.
    #[serde(default = "default_ports")]
    pub ports: Vec<u16>,
}

fn default_ports() -> Vec<u16> {
    vec![443, 80]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// The profile does not list this host.
    NotAllowed,
    Port(u16),
    /// The target was an IP address rather than a name.
    IpLiteral,
    /// The name resolved to an address the sandbox must never reach.
    PrivateAddress(IpAddr),
    ResolveFailed,
    /// The TLS SNI named a different host than the tunnel.
    SniMismatch(String),
    BadRequest(&'static str),
}

impl Denied {
    pub fn reason(&self) -> String {
        match self {
            Self::NotAllowed => "host not in the profile's allowlist".into(),
            Self::Port(p) => format!("port {p} not allowed"),
            Self::IpLiteral => "IP addresses are not allowed; use a host name".into(),
            Self::PrivateAddress(ip) => format!("resolves to a non-public address ({ip})"),
            Self::ResolveFailed => "host name does not resolve".into(),
            Self::SniMismatch(sni) => format!("TLS server name {sni} does not match the tunnel"),
            Self::BadRequest(why) => format!("bad proxy request: {why}"),
        }
    }
}

impl Profile {
    /// The built-in default: no egress at all.
    pub fn deny_all(name: &str) -> Self {
        Self {
            name: name.into(),
            allow: Vec::new(),
            ports: default_ports(),
        }
    }

    /// Checks the profile's own rules; called by the operator's config loader.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty()
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!(
                "profile name {:?} must be letters, digits, - or _",
                self.name
            ));
        }
        for p in &self.allow {
            let host = p.strip_prefix("*.").unwrap_or(p);
            if normalize_host(host) != Ok(host.to_owned()) {
                return Err(format!(
                    "profile {}: bad allow pattern {p:?} (lowercase host or *.host)",
                    self.name
                ));
            }
        }
        if self.ports.is_empty() || self.ports.contains(&0) {
            return Err(format!(
                "profile {}: ports must be non-empty and non-zero",
                self.name
            ));
        }
        Ok(())
    }

    /// Checks a host (already normalised) and port against the allowlist.
    pub fn check(&self, host: &str, port: u16) -> Result<(), Denied> {
        if !self.ports.contains(&port) {
            return Err(Denied::Port(port));
        }
        let allowed = self.allow.iter().any(|p| match p.strip_prefix("*.") {
            Some(suffix) => {
                host.len() > suffix.len() + 1
                    && host.ends_with(suffix)
                    && host[..host.len() - suffix.len()].ends_with('.')
            }
            None => host == p,
        });
        if allowed {
            Ok(())
        } else {
            Err(Denied::NotAllowed)
        }
    }
}

/// Lowercases a host name, drops a trailing dot, and rejects IP literals and malformed names.
pub fn normalize_host(raw: &str) -> Result<String, Denied> {
    let h = raw.trim_end_matches('.').to_ascii_lowercase();
    let unbracketed = h.trim_start_matches('[').trim_end_matches(']');
    if unbracketed.parse::<IpAddr>().is_ok() || looks_like_ipv4(&h) {
        return Err(Denied::IpLiteral);
    }
    let ok = !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if ok {
        Ok(h)
    } else {
        Err(Denied::BadRequest("malformed host name"))
    }
}

/// Catches numeric forms that inet_aton accepts but `IpAddr` does not (`2130706433`, `0x7f.1`).
fn looks_like_ipv4(h: &str) -> bool {
    h.split('.').all(|part| {
        !part.is_empty()
            && (part.bytes().all(|b| b.is_ascii_digit())
                || (part.starts_with("0x") && part[2..].bytes().all(|b| b.is_ascii_hexdigit())))
    })
}

/// True only for globally routable unicast addresses.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 carrier-grade NAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 protocol assignments
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
                || o[0] >= 240) // reserved
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64
                || s[0] == 0) // IPv4-compatible and other reserved
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(allow: &[&str]) -> Profile {
        Profile {
            name: "t".into(),
            allow: allow.iter().map(|s| (*s).to_owned()).collect(),
            ports: vec![443, 80],
        }
    }

    #[test]
    fn exact_and_wildcard_matching() {
        let p = profile(&["pypi.org", "*.githubusercontent.com"]);
        assert_eq!(p.check("pypi.org", 443), Ok(()));
        assert_eq!(p.check("evil-pypi.org", 443), Err(Denied::NotAllowed));
        assert_eq!(p.check("files.pypi.org", 443), Err(Denied::NotAllowed));
        assert_eq!(p.check("raw.githubusercontent.com", 443), Ok(()));
        assert_eq!(p.check("a.b.githubusercontent.com", 80), Ok(()));
        assert_eq!(
            p.check("githubusercontent.com", 443),
            Err(Denied::NotAllowed)
        );
        assert_eq!(
            p.check("evilgithubusercontent.com", 443),
            Err(Denied::NotAllowed)
        );
        assert_eq!(p.check("pypi.org", 22), Err(Denied::Port(22)));
        assert_eq!(
            Profile::deny_all("default").check("pypi.org", 443),
            Err(Denied::NotAllowed)
        );
    }

    #[test]
    fn host_normalisation() {
        assert_eq!(normalize_host("PyPI.org."), Ok("pypi.org".into()));
        for ip in [
            "1.2.3.4",
            "[::1]",
            "::1",
            "2130706433",
            "0x7f.0.0.1",
            "127.1",
        ] {
            assert_eq!(normalize_host(ip), Err(Denied::IpLiteral), "{ip}");
        }
        for bad in ["", "a..b", "-a.com", "a_b.com", "a b.com", &"x".repeat(64)] {
            assert!(
                matches!(normalize_host(bad), Err(Denied::BadRequest(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn only_public_addresses_pass() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.5.2",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "64:ff9b::1.2.3.4",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip} must be blocked");
        }
        for ip in [
            "93.184.215.14",
            "1.1.1.1",
            "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip} must be allowed");
        }
    }

    #[test]
    fn profile_validation() {
        assert!(profile(&["pypi.org", "*.github.com"]).validate().is_ok());
        assert!(profile(&["PyPI.org"]).validate().is_err());
        assert!(profile(&["*"]).validate().is_err());
        assert!(profile(&["10.0.0.1"]).validate().is_err());
        assert!(
            Profile {
                name: "bad name".into(),
                ..profile(&[])
            }
            .validate()
            .is_err()
        );
    }
}
