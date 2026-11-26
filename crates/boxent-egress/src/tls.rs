//! Reads the server name (SNI) from a TLS ClientHello without terminating TLS.

/// What the first bytes of a tunnel say about TLS.
#[derive(Debug, PartialEq, Eq)]
pub enum Hello {
    /// Not a TLS handshake (plain protocol over the tunnel).
    NotTls,
    /// A complete ClientHello; the server name if it carries one.
    Sni(Option<String>),
    /// Looks like TLS but more bytes are needed.
    Incomplete,
}

pub fn parse_client_hello(buf: &[u8]) -> Hello {
    // TLS record: type 22 (handshake), version 3.x, length.
    if buf.is_empty() {
        return Hello::Incomplete;
    }
    if buf[0] != 0x16 {
        return Hello::NotTls;
    }
    if buf.len() < 5 {
        return Hello::Incomplete;
    }
    if buf[1] != 3 {
        return Hello::NotTls;
    }
    let record_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    if buf.len() < 5 + record_len {
        return Hello::Incomplete;
    }
    let mut r = Reader {
        b: &buf[5..5 + record_len],
    };
    match sni(&mut r) {
        Some(name) => Hello::Sni(name),
        None => Hello::Sni(None),
    }
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.b.len() < n {
            return None;
        }
        let (head, rest) = self.b.split_at(n);
        self.b = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<usize> {
        self.take(1).map(|b| usize::from(b[0]))
    }
    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
}

/// Returns `Some(None)` for a hello without SNI, `None` if the hello is malformed.
fn sni(r: &mut Reader<'_>) -> Option<Option<String>> {
    if r.u8()? != 1 {
        return None; // not a ClientHello
    }
    let len = (r.u8()? << 16) | r.u16()?;
    let mut h = Reader { b: r.take(len)? };
    h.take(2 + 32)?; // version, random
    h.vec8()?; // session id
    h.vec16()?; // cipher suites
    h.vec8()?; // compression methods
    if h.b.is_empty() {
        return Some(None);
    }
    let mut ext = Reader { b: h.vec16()? };
    while !ext.b.is_empty() {
        let kind = ext.u16()?;
        let body = ext.vec16()?;
        if kind == 0 {
            let mut list = Reader {
                b: Reader { b: body }.vec16()?,
            };
            while !list.b.is_empty() {
                let name_type = list.u8()?;
                let name = list.vec16()?;
                if name_type == 0 {
                    return Some(Some(
                        String::from_utf8(name.to_vec()).ok()?.to_ascii_lowercase(),
                    ));
                }
            }
        }
    }
    Some(None)
}

/// Builds a minimal ClientHello (for tests).
#[doc(hidden)]
pub fn client_hello(sni: Option<&str>) -> Vec<u8> {
    let mut exts = Vec::new();
    if let Some(name) = sni {
        let n = name.as_bytes();
        let mut entry = vec![0u8];
        entry.extend((n.len() as u16).to_be_bytes());
        entry.extend(n);
        let mut list = (entry.len() as u16).to_be_bytes().to_vec();
        list.extend(entry);
        exts.extend(0u16.to_be_bytes());
        exts.extend((list.len() as u16).to_be_bytes());
        exts.extend(list);
    }
    // An unrelated extension (supported_versions) to make sure the parser skips it.
    exts.extend([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    let mut body = vec![3, 3];
    body.extend([7u8; 32]);
    body.push(0); // session id
    body.extend([0, 2, 0x13, 0x01]); // one cipher suite
    body.extend([1, 0]); // compression
    body.extend((exts.len() as u16).to_be_bytes());
    body.extend(exts);
    let mut hs = vec![1u8, 0];
    hs.extend((body.len() as u16).to_be_bytes());
    hs.extend(body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend((hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_sni() {
        assert_eq!(
            parse_client_hello(&client_hello(Some("Example.COM"))),
            Hello::Sni(Some("example.com".into()))
        );
        assert_eq!(parse_client_hello(&client_hello(None)), Hello::Sni(None));
    }

    #[test]
    fn partial_and_non_tls_input() {
        let full = client_hello(Some("example.com"));
        for cut in [0, 1, 4, 20, full.len() - 1] {
            assert_eq!(
                parse_client_hello(&full[..cut]),
                Hello::Incomplete,
                "cut at {cut}"
            );
        }
        assert_eq!(parse_client_hello(b"GET / HTTP/1.1\r\n"), Hello::NotTls);
        assert_eq!(parse_client_hello(b"SSH-2.0-OpenSSH"), Hello::NotTls);
        let mut garbage = full.clone();
        garbage[9] = 0xff; // corrupt a length
        assert!(matches!(
            parse_client_hello(&garbage),
            Hello::Sni(_) | Hello::Incomplete
        ));
    }
}
