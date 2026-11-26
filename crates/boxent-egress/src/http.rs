//! Just enough HTTP/1.x to proxy: parse a request head and rewrite it for the origin server.

use crate::policy::{Denied, normalize_host};

/// Largest request head accepted from a sandbox.
pub const MAX_HEAD: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    /// `CONNECT host:port`: a tunnel.
    Connect { host: String, port: u16 },
    /// A plain-HTTP request in absolute form, rewritten to origin form for the server.
    Http {
        host: String,
        port: u16,
        head: Vec<u8>,
    },
}

/// Index just past the blank line ending the head, if present.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Parses a complete request head.
pub fn parse(head: &[u8]) -> Result<Target, Denied> {
    let text =
        std::str::from_utf8(head).map_err(|_| Denied::BadRequest("request head is not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let request = lines.next().unwrap_or_default();
    let mut parts = request.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Denied::BadRequest("malformed request line"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(Denied::BadRequest("only HTTP/1.x is supported"));
    }
    if method == "CONNECT" {
        let (host, port) = split_authority(target, None)?;
        return Ok(Target::Connect { host, port });
    }
    let Some(rest) = target.strip_prefix("http://") else {
        return Err(Denied::BadRequest(
            "only CONNECT or absolute http:// requests are supported",
        ));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.contains('@') {
        return Err(Denied::BadRequest("credentials in URLs are not supported"));
    }
    let (host, port) = split_authority(authority, Some(80))?;
    let mut out = format!("{method} {path} {version}\r\n");
    for line in lines.take_while(|l| !l.is_empty()) {
        let name = line
            .split(':')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        // Hop-by-hop and proxy headers stay here; the host header comes from the URL.
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "proxy-connection"
                | "proxy-authorization"
                | "keep-alive"
                | "upgrade"
                | "te"
        ) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    let host_header = if port == 80 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    out.push_str(&format!("Host: {host_header}\r\nConnection: close\r\n\r\n"));
    Ok(Target::Http {
        host,
        port,
        head: out.into_bytes(),
    })
}

fn split_authority(authority: &str, default_port: Option<u16>) -> Result<(String, u16), Denied> {
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.to_owned()),
        None => (
            authority,
            default_port.map(|d| d.to_string()).unwrap_or_default(),
        ),
    };
    let port: u16 = port
        .parse()
        .map_err(|_| Denied::BadRequest("missing or invalid port"))?;
    Ok((normalize_host(host)?, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_requests() {
        let t = parse(b"CONNECT PyPI.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n").unwrap();
        assert_eq!(
            t,
            Target::Connect {
                host: "pypi.org".into(),
                port: 443
            }
        );
        assert_eq!(
            parse(b"CONNECT pypi.org HTTP/1.1\r\n\r\n"),
            Err(Denied::BadRequest("missing or invalid port"))
        );
        assert_eq!(
            parse(b"CONNECT 1.2.3.4:443 HTTP/1.1\r\n\r\n"),
            Err(Denied::IpLiteral)
        );
        assert_eq!(
            parse(b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n"),
            Err(Denied::IpLiteral)
        );
    }

    #[test]
    fn absolute_http_is_rewritten() {
        let t = parse(b"GET http://Example.com/a?b=1 HTTP/1.1\r\nHost: evil.com\r\nAccept: */*\r\nProxy-Connection: keep-alive\r\n\r\n").unwrap();
        let Target::Http { host, port, head } = t else {
            panic!()
        };
        assert_eq!((host.as_str(), port), ("example.com", 80));
        assert_eq!(
            String::from_utf8(head).unwrap(),
            "GET /a?b=1 HTTP/1.1\r\nAccept: */*\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
        let Target::Http { port, head, .. } =
            parse(b"GET http://example.com:8080 HTTP/1.0\r\n\r\n").unwrap()
        else {
            panic!()
        };
        assert_eq!(port, 8080);
        assert!(
            String::from_utf8(head)
                .unwrap()
                .starts_with("GET / HTTP/1.0\r\nHost: example.com:8080\r\n")
        );
    }

    #[test]
    fn rejects_everything_else() {
        assert!(parse(b"GET https://example.com/ HTTP/1.1\r\n\r\n").is_err());
        assert!(parse(b"GET / HTTP/1.1\r\n\r\n").is_err());
        assert!(parse(b"GET http://user:pw@example.com/ HTTP/1.1\r\n\r\n").is_err());
        assert!(parse(b"GET http://example.com/ HTTP/2\r\n\r\n").is_err());
        assert!(parse(b"garbage\r\n\r\n").is_err());
        assert!(parse(&[0xff, 0xfe, b'\r', b'\n', b'\r', b'\n']).is_err());
    }

    #[test]
    fn finds_the_end_of_the_head() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\n"), None);
    }
}
