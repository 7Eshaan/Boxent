//! `boxent daemon` (Linux): runs the engine and serves MCP sessions on a Unix socket.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use boxent_core::EngineConfig;
use boxent_mcp::DaemonOptions;
use clap::Args;

#[derive(Args)]
pub struct DaemonArgs {
    #[arg(long, default_value = "/run/boxent/boxent.sock")]
    socket: PathBuf,
    /// Owner of the socket; in the Lima VM, the login user, so Lima can forward it.
    #[arg(long, env = "BOXENT_SOCKET_UID")]
    socket_uid: Option<u32>,
    /// Warm sandboxes kept ready.
    #[arg(long, default_value_t = 4)]
    pool_size: usize,
    #[arg(long, default_value_t = 32)]
    max_sandboxes: usize,
    /// Hard lifetime of a sandbox, in seconds.
    #[arg(long, default_value_t = 1800)]
    ttl_secs: u64,
    /// Seconds without calls after which a sandbox is destroyed.
    #[arg(long, default_value_t = 300)]
    idle_secs: u64,
    /// Seconds a disconnected session's sandboxes are kept.
    #[arg(long, default_value_t = 30)]
    session_grace_secs: u64,
}

pub fn run(a: DaemonArgs) -> Result<bool> {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(std::env::var("BOXENT_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let opts = DaemonOptions {
        socket: a.socket,
        socket_uid: a.socket_uid,
        session_grace: Duration::from_secs(a.session_grace_secs),
        engine: EngineConfig {
            pool_size: a.pool_size,
            max_sandboxes: a.max_sandboxes,
            ttl: Duration::from_secs(a.ttl_secs),
            idle_timeout: Duration::from_secs(a.idle_secs),
            ..EngineConfig::default()
        },
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(boxent_mcp::run_daemon(opts))?;
    Ok(true)
}
