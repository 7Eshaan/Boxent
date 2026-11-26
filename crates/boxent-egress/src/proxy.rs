//! The proxy server for one sandbox.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::http::{self, MAX_HEAD, Target};
use crate::policy::{Denied, Profile, is_public};
use crate::tls::{Hello, parse_client_hello};

/// Where the listener sits inside every sandbox: 127.0.0.1:3128.
pub const PROXY_PORT: u16 = 3128;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct ProxyOptions {
    /// Connections open at once for one sandbox.
    pub max_connections: usize,
    /// Refuse names that resolve to non-public addresses. Only tests turn this off, to reach a
    /// local upstream.
    pub block_private: bool,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            max_connections: 64,
            block_private: true,
        }
    }
}

/// A running proxy for one sandbox. Dropping it stops the proxy and every open connection.
pub struct ProxyHandle {
    profile: Arc<RwLock<Arc<Profile>>>,
    task: tokio::task::JoinHandle<()>,
}

impl ProxyHandle {
    /// Changes the rules for new connections (used when a warm sandbox is claimed).
    pub fn set_profile(&self, profile: Profile) {
        *self.profile.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(profile);
    }

    pub fn profile(&self) -> Arc<Profile> {
        Arc::clone(&self.profile.read().unwrap_or_else(|e| e.into_inner()))
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Serves the proxy on a listener the engine created inside the sandbox's network namespace.
/// Must be called inside a Tokio runtime.
pub fn serve(
    listener: std::net::TcpListener,
    sandbox_id: String,
    profile: Profile,
    opts: ProxyOptions,
) -> std::io::Result<ProxyHandle> {
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    let profile = Arc::new(RwLock::new(Arc::new(profile)));
    let shared = Arc::clone(&profile);
    let task = tokio::spawn(async move {
        let limit = Arc::new(Semaphore::new(opts.max_connections));
        let mut conns = JoinSet::new(); // aborted with this task, so no tunnel outlives the sandbox
        let sandbox: Arc<str> = sandbox_id.into();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((client, _)) = accepted else { continue };
                    let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
                        tracing::warn!(event = "egress_overloaded", sandbox_id = %sandbox);
                        conns.spawn(async move { let _ = reject(client, 503, "too many connections").await; });
                        continue;
                    };
                    let p = Arc::clone(&shared.read().unwrap_or_else(|e| e.into_inner()));
                    let (sandbox, opts) = (Arc::clone(&sandbox), opts.clone());
                    conns.spawn(async move {
                        handle(client, &sandbox, &p, &opts).await;
                        drop(permit);
                    });
                }
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
            }
        }
    });
    Ok(ProxyHandle { profile, task })
}

async fn handle(mut client: TcpStream, sandbox: &str, profile: &Profile, opts: &ProxyOptions) {
    let mut buf = Vec::with_capacity(1024);
    let head_len = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client, &mut buf)).await
    {
        Ok(Ok(n)) => n,
        Ok(Err(why)) => {
            let _ = reject(client, 400, why).await;
            return;
        }
        Err(_) => return,
    };
    let target = match http::parse(&buf[..head_len]) {
        Ok(t) => t,
        Err(d) => {
            log(sandbox, profile, "-", 0, Some(&d));
            let msg = format!(
                "boxent: egress denied: {} (profile '{}')",
                d.reason(),
                profile.name
            );
            let _ = reject(client, status_for(&d), &msg).await;
            return;
        }
    };
    let (host, port) = match &target {
        Target::Connect { host, port } | Target::Http { host, port, .. } => (host.clone(), *port),
    };
    let addrs = match vet(&host, port, profile, opts).await {
        Ok(a) => a,
        Err(d) => {
            log(sandbox, profile, &host, port, Some(&d));
            let msg = format!(
                "boxent: egress to {host}:{port} denied: {} (profile '{}')",
                d.reason(),
                profile.name
            );
            let _ = reject(client, status_for(&d), &msg).await;
            return;
        }
    };
    let early = buf.split_off(head_len); // bytes the client sent after the head
    let mut upstream = match target {
        Target::Connect { .. } => {
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            let Some(first) = first_bytes(&mut client, early).await else {
                return;
            };
            if let Hello::Sni(Some(sni)) = parse_client_hello(&first)
                && sni.trim_end_matches('.') != host
            {
                log(
                    sandbox,
                    profile,
                    &host,
                    port,
                    Some(&Denied::SniMismatch(sni)),
                );
                return; // the tunnel is already open; closing it is the only answer left
            }
            // Only now is the destination contacted.
            let Some(mut upstream) = connect(&addrs, port).await else {
                return;
            };
            log(sandbox, profile, &host, port, None);
            if upstream.write_all(&first).await.is_err() {
                return;
            }
            upstream
        }
        Target::Http { head, .. } => {
            let Some(mut upstream) = connect(&addrs, port).await else {
                let _ = reject(
                    client,
                    502,
                    &format!("boxent: could not connect to {host}:{port}"),
                )
                .await;
                return;
            };
            log(sandbox, profile, &host, port, None);
            if upstream.write_all(&head).await.is_err() || upstream.write_all(&early).await.is_err()
            {
                return;
            }
            upstream
        }
    };
    let _ = copy_bidirectional(&mut client, &mut upstream).await;
}

/// Reads until the end of the request head; returns its length.
async fn read_head(client: &mut TcpStream, buf: &mut Vec<u8>) -> Result<usize, &'static str> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = http::head_end(buf) {
            return Ok(end);
        }
        if buf.len() >= MAX_HEAD {
            return Err("request head too large");
        }
        let n = client.read(&mut chunk).await.map_err(|_| "read error")?;
        if n == 0 {
            return Err("connection closed before the request was complete");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Collects enough of the tunnel's first bytes to read a TLS ClientHello, if it is one.
async fn first_bytes(client: &mut TcpStream, mut buf: Vec<u8>) -> Option<Vec<u8>> {
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + HELLO_TIMEOUT;
    while parse_client_hello(&buf) == Hello::Incomplete && buf.len() < MAX_HEAD {
        let n = tokio::time::timeout_at(deadline, client.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Some(buf)
}

/// Applies the profile, resolves the name here (never in the sandbox) and refuses non-public
/// addresses. The caller connects only to the addresses returned, so a second lookup cannot be
/// raced.
async fn vet(
    host: &str,
    port: u16,
    profile: &Profile,
    opts: &ProxyOptions,
) -> Result<Vec<IpAddr>, Denied> {
    profile.check(host, port)?;
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| Denied::ResolveFailed)?
        .map(|a| a.ip())
        .collect();
    if addrs.is_empty() {
        return Err(Denied::ResolveFailed);
    }
    if opts.block_private
        && let Some(bad) = addrs.iter().find(|ip| !is_public(**ip))
    {
        // One bad answer taints the name: refuse rather than pick among them.
        return Err(Denied::PrivateAddress(*bad));
    }
    Ok(addrs)
}

async fn connect(addrs: &[IpAddr], port: u16) -> Option<TcpStream> {
    for ip in addrs {
        let attempt = TcpStream::connect(SocketAddr::new(*ip, port));
        if let Ok(Ok(s)) = tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
            return Some(s);
        }
    }
    None
}

fn status_for(d: &Denied) -> u16 {
    match d {
        Denied::BadRequest(_) => 400,
        _ => 403,
    }
}

async fn reject(mut client: TcpStream, code: u16, msg: &str) -> std::io::Result<()> {
    let reason = match code {
        400 => "Bad Request",
        403 => "Forbidden",
        502 => "Bad Gateway",
        _ => "Service Unavailable",
    };
    let body = format!("{msg}\n");
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(resp.as_bytes()).await?;
    client.shutdown().await
}

fn log(sandbox: &str, profile: &Profile, host: &str, port: u16, denied: Option<&Denied>) {
    match denied {
        None => {
            tracing::info!(event = "egress_decision", sandbox_id = sandbox, profile = %profile.name, host, port, allowed = true)
        }
        Some(d) => tracing::info!(
            event = "egress_decision",
            sandbox_id = sandbox,
            profile = %profile.name,
            host,
            port,
            allowed = false,
            reason = %d.reason()
        ),
    }
}
