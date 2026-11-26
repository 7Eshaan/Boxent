//! `boxent daemon` (Linux): runs the engine and serves MCP sessions on a Unix socket.
//!
//! Settings come from built-in defaults, then the config file (`/etc/boxent/boxent.toml` if it
//! exists), then command-line flags. Egress profiles can only be defined in the config file:
//! agents choose among them but cannot add their own.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use boxent_core::{EngineConfig, Profile};
use boxent_mcp::DaemonOptions;
use clap::Args;
use serde::Deserialize;

const DEFAULT_CONFIG: &str = "/etc/boxent/boxent.toml";
const DEFAULT_TOKEN_FILE: &str = "/etc/boxent/http-token";

/// Reads the HTTP bearer token, or creates one (256 random bits, readable by root only).
fn load_or_create_token(path: &Path) -> Result<String> {
    if let Ok(t) = std::fs::read_to_string(path) {
        return Ok(t.trim().to_owned());
    }
    let mut b = [0u8; 32];
    // SAFETY: fills the buffer with random bytes.
    if unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) } != 32 {
        anyhow::bail!("getrandom failed");
    }
    let token: String = b.iter().map(|x| format!("{x:02x}")).collect();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?
        .write_all(format!("{token}\n").as_bytes())?;
    Ok(token)
}

#[derive(Args)]
pub struct DaemonArgs {
    /// Config file. Defaults to /etc/boxent/boxent.toml when it exists.
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Owner of the socket; in the Lima VM, the login user, so Lima can forward it.
    #[arg(long, env = "BOXENT_SOCKET_UID")]
    socket_uid: Option<u32>,
    /// Warm sandboxes kept ready.
    #[arg(long)]
    pool_size: Option<usize>,
    #[arg(long)]
    max_sandboxes: Option<usize>,
    /// Hard lifetime of a sandbox, in seconds.
    #[arg(long)]
    ttl_secs: Option<u64>,
    /// Seconds without calls after which a sandbox is destroyed.
    #[arg(long)]
    idle_secs: Option<u64>,
    /// Seconds a disconnected session's sandboxes are kept.
    #[arg(long)]
    session_grace_secs: Option<u64>,
}

/// The config file. Every field is optional.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    daemon: DaemonSection,
    #[serde(default)]
    limits: LimitsSection,
    #[serde(default)]
    http: HttpSection,
    #[serde(default, rename = "profile")]
    profiles: Vec<Profile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DaemonSection {
    socket: Option<PathBuf>,
    pool_size: Option<usize>,
    max_sandboxes: Option<usize>,
    ttl_secs: Option<u64>,
    idle_secs: Option<u64>,
    session_grace_secs: Option<u64>,
    max_snapshots: Option<usize>,
}

/// Streamable HTTP. Off unless `listen` is set.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpSection {
    /// Loopback address and port, e.g. "127.0.0.1:7788".
    listen: Option<std::net::SocketAddr>,
    /// File holding the bearer token; created with a random token if missing.
    token_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsSection {
    cpus: Option<f64>,
    memory_mib: Option<u64>,
    pids: Option<u32>,
    disk_mib: Option<u64>,
    tmp_mib: Option<u64>,
}

fn load(path: Option<&Path>) -> Result<FileConfig> {
    let path = match path {
        Some(p) => p,
        None if Path::new(DEFAULT_CONFIG).exists() => Path::new(DEFAULT_CONFIG),
        None => return Ok(FileConfig::default()),
    };
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

pub fn run(a: DaemonArgs) -> Result<bool> {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(std::env::var("BOXENT_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let file = load(a.config.as_deref())?;
    let d = &file.daemon;
    let defaults = EngineConfig::default();
    let mut limits = defaults.limits;
    let l = &file.limits;
    limits.cpus = l.cpus.unwrap_or(limits.cpus);
    limits.memory_bytes = l.memory_mib.map_or(limits.memory_bytes, |m| m << 20);
    limits.pids = l.pids.unwrap_or(limits.pids);
    limits.disk_bytes = l.disk_mib.map_or(limits.disk_bytes, |m| m << 20);
    limits.tmp_bytes = l.tmp_mib.map_or(limits.tmp_bytes, |m| m << 20);
    let secs = |flag: Option<u64>, file: Option<u64>, default: Duration| {
        flag.or(file).map_or(default, Duration::from_secs)
    };
    let http = match file.http.listen {
        None => None,
        Some(listen) => {
            let path = file
                .http
                .token_file
                .clone()
                .unwrap_or_else(|| DEFAULT_TOKEN_FILE.into());
            Some(boxent_mcp::HttpOptions {
                listen,
                token: load_or_create_token(&path)?,
            })
        }
    };
    let opts = DaemonOptions {
        http,
        socket: a
            .socket
            .or(d.socket.clone())
            .unwrap_or_else(|| "/run/boxent/boxent.sock".into()),
        socket_uid: a.socket_uid,
        session_grace: secs(
            a.session_grace_secs,
            d.session_grace_secs,
            Duration::from_secs(30),
        ),
        engine: EngineConfig {
            pool_size: a.pool_size.or(d.pool_size).unwrap_or(defaults.pool_size),
            max_sandboxes: a
                .max_sandboxes
                .or(d.max_sandboxes)
                .unwrap_or(defaults.max_sandboxes),
            ttl: secs(a.ttl_secs, d.ttl_secs, defaults.ttl),
            idle_timeout: secs(a.idle_secs, d.idle_secs, defaults.idle_timeout),
            max_snapshots: d.max_snapshots.unwrap_or(defaults.max_snapshots),
            limits,
            profiles: file.profiles,
            ..defaults
        },
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(boxent_mcp::run_daemon(opts))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../config/boxent.example.toml");
        let cfg: FileConfig = toml::from_str(text).unwrap();
        assert!(!cfg.profiles.is_empty());
        for p in &cfg.profiles {
            p.validate().unwrap();
        }
    }

    #[test]
    fn unknown_keys_are_errors() {
        assert!(toml::from_str::<FileConfig>("[daemon]\npool_sise = 3\n").is_err());
        assert!(toml::from_str::<FileConfig>("[[profile]]\nname = \"x\"\nalow = []\n").is_err());
    }
}
