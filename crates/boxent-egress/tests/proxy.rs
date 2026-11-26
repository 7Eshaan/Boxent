//! The proxy end to end on loopback: a fake sandbox client, the proxy, and a local upstream.

use std::net::SocketAddr;

use boxent_egress::{Profile, ProxyOptions, serve, tls};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An upstream that records what it receives and answers "pong".
async fn upstream() -> (u16, tokio::sync::mpsc::Receiver<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(buf[..n].to_vec()).await;
                let _ = s.write_all(b"pong").await;
            });
        }
    });
    (port, rx)
}

fn proxy(
    allow: &[&str],
    port: u16,
    block_private: bool,
) -> (SocketAddr, boxent_egress::ProxyHandle) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let profile = Profile {
        name: "test".into(),
        allow: allow.iter().map(|s| (*s).to_owned()).collect(),
        ports: vec![port],
    };
    let opts = ProxyOptions {
        block_private,
        ..ProxyOptions::default()
    };
    (addr, serve(l, "sb-test".into(), profile, opts).unwrap())
}

async fn send(proxy: SocketAddr, bytes: &[u8]) -> (TcpStream, String) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(bytes).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.unwrap();
    (s, String::from_utf8_lossy(&buf[..n]).into_owned())
}

#[tokio::test]
async fn connect_tunnel_carries_tls_with_matching_sni() {
    let (port, mut seen) = upstream().await;
    let (addr, _h) = proxy(&["localhost"], port, false);
    let (mut s, resp) = send(
        addr,
        format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    let hello = tls::client_hello(Some("localhost"));
    s.write_all(&hello).await.unwrap();
    assert_eq!(seen.recv().await.unwrap(), hello);
    let mut pong = [0u8; 4];
    s.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong");
}

#[tokio::test]
async fn sni_mismatch_closes_the_tunnel() {
    let (port, mut seen) = upstream().await;
    let (addr, _h) = proxy(&["localhost"], port, false);
    let (mut s, resp) = send(
        addr,
        format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"));
    s.write_all(&tls::client_hello(Some("evil.example")))
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(s.read(&mut buf).await.unwrap_or(0), 0, "tunnel must close");
    assert!(seen.try_recv().is_err(), "nothing may reach the upstream");
}

#[tokio::test]
async fn plain_http_is_rewritten_and_forwarded() {
    let (port, mut seen) = upstream().await;
    let (addr, _h) = proxy(&["localhost"], port, false);
    let req = format!(
        "GET http://localhost:{port}/x?y=1 HTTP/1.1\r\nHost: other\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    let (_s, resp) = send(addr, req.as_bytes()).await;
    assert_eq!(resp, "pong");
    let got = String::from_utf8(seen.recv().await.unwrap()).unwrap();
    assert_eq!(
        got,
        format!("GET /x?y=1 HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n")
    );
}

#[tokio::test]
async fn denials_are_403_with_a_reason() {
    let (port, _seen) = upstream().await;
    let (addr, _h) = proxy(&["localhost"], port, true);
    for (req, why) in [
        (
            format!("CONNECT example.org:{port} HTTP/1.1\r\n\r\n"),
            "not in the profile",
        ),
        (
            format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n"),
            "IP addresses are not allowed",
        ),
        (
            "CONNECT localhost:1 HTTP/1.1\r\n\r\n".to_owned(),
            "port 1 not allowed",
        ),
        // Allowed by name, but it resolves to loopback.
        (
            format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n"),
            "non-public address",
        ),
    ] {
        let (_s, resp) = send(addr, req.as_bytes()).await;
        assert!(resp.starts_with("HTTP/1.1 403"), "{req}: {resp}");
        assert!(resp.contains(why), "{req}: {resp}");
        assert!(resp.contains("profile 'test'"), "{resp}");
    }
    let (_s, resp) = send(addr, b"GET / HTTP/1.1\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
}

#[tokio::test]
async fn profile_can_be_swapped_at_claim_time() {
    let (port, _seen) = upstream().await;
    let (addr, h) = proxy(&[], port, false);
    let (_s, resp) = send(
        addr,
        format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 403"));
    h.set_profile(Profile {
        name: "now".into(),
        allow: vec!["localhost".into()],
        ports: vec![port],
    });
    let (_s, resp) = send(
        addr,
        format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
}

#[tokio::test]
async fn dropping_the_handle_stops_the_proxy() {
    let (port, _seen) = upstream().await;
    let (addr, h) = proxy(&["localhost"], port, false);
    let (mut tunnel, resp) = send(
        addr,
        format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"));
    drop(h);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = [0u8; 8];
    assert_eq!(
        tunnel.read(&mut buf).await.unwrap_or(0),
        0,
        "open tunnels must close with the proxy"
    );
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "the listener must be gone"
    );
}
