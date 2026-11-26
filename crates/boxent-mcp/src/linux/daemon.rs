//! The daemon: one engine, MCP sessions over a Unix socket.
//!
//! Each accepted connection speaks MCP's stdio framing (newline-delimited JSON-RPC), so the
//! `boxent mcp` relay is a plain byte copy between its stdio and this socket.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use boxent_core::{Engine, EngineConfig, EngineError};
use rmcp::ServiceExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};

use super::server::{BoxentServer, Session};

#[derive(Debug, Clone)]
pub struct DaemonOptions {
    pub socket: PathBuf,
    /// Owner of the socket (the VM's login user, so Lima can forward it). Root when unset.
    pub socket_uid: Option<u32>,
    /// How long a closed session's sandboxes survive, so a client that reconnects with an
    /// explicit sandbox_id can carry on.
    pub session_grace: Duration,
    pub engine: EngineConfig,
}

static SESSIONS: AtomicU64 = AtomicU64::new(1);

/// Runs until SIGTERM or SIGINT, then destroys every sandbox.
pub async fn run(opts: DaemonOptions) -> Result<(), EngineError> {
    let engine = Engine::start(opts.engine.clone()).await?;
    let _ = std::fs::remove_file(&opts.socket);
    if let Some(dir) = opts.socket.parent() {
        std::fs::create_dir_all(dir).map_err(EngineError::internal)?;
    }
    let listener = UnixListener::bind(&opts.socket).map_err(EngineError::internal)?;
    std::fs::set_permissions(&opts.socket, std::fs::Permissions::from_mode(0o600))
        .map_err(EngineError::internal)?;
    if let Some(uid) = opts.socket_uid {
        std::os::unix::fs::chown(&opts.socket, Some(uid), None).map_err(EngineError::internal)?;
    }
    tracing::info!(event = "daemon_listening", socket = %opts.socket.display());

    let mut term = signal(SignalKind::terminate()).map_err(EngineError::internal)?;
    let mut int = signal(SignalKind::interrupt()).map_err(EngineError::internal)?;
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    tokio::spawn(serve_connection(engine.clone(), stream, opts.session_grace));
                }
                Err(e) => tracing::warn!(event = "accept_failed", error = %e),
            },
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }
    tracing::info!(event = "daemon_stopping");
    let _ = std::fs::remove_file(&opts.socket);
    engine.shutdown().await;
    Ok(())
}

/// Serves one MCP session until the client disconnects, then schedules cleanup of the
/// sandboxes it created.
pub async fn serve_connection<S>(engine: Engine, stream: S, grace: Duration)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let n = SESSIONS.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    tracing::info!(event = "session_opened", session = n);
    let session = Arc::new(Session::default());
    let server = BoxentServer::new(engine.clone(), Arc::clone(&session));
    match server.serve(stream).await {
        Ok(running) => {
            if let Err(e) = running.waiting().await {
                tracing::warn!(event = "session_error", session = n, error = %e);
            }
        }
        Err(e) => tracing::warn!(event = "session_handshake_failed", session = n, error = %e),
    }
    let owned = session.owned();
    tracing::info!(
        event = "session_closed",
        session = n,
        duration_ms = started.elapsed().as_millis() as u64,
        sandboxes = owned.len()
    );
    if owned.is_empty() {
        return;
    }
    tokio::time::sleep(grace).await;
    for id in owned {
        if engine.destroy(&id).await.is_ok() {
            tracing::info!(event = "session_sandbox_destroyed", session = n, sandbox_id = %id);
        }
    }
}
