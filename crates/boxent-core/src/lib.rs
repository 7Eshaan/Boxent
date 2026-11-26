//! The Boxent engine: a warm pool of sandboxes, their lifecycle, and the operations the MCP layer
//! exposes. The MCP layer depends only on [`Engine`]'s methods and [`EngineError`]; nothing here
//! knows about MCP.
//!
//! Lifecycle of a sandbox:
//!
//! ```text
//! Provisioning -> Warm -> Active -> Reaping -> Reaped
//!       \           \        \
//!        `-----------`--------`--> (failed or retired) -> Reaping
//! ```
//!
//! Sandboxes are single-use: once claimed, a sandbox is never returned to the pool. It is reaped
//! when destroyed, when idle too long, when its hard TTL passes, or when its agent stops
//! answering. On start the engine reaps everything a previous engine left behind.

mod error;

pub use error::{EngineError, ErrorCode, ReapReason};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{
    Engine, EngineConfig, ExecOutcome, ExecSpec, PoolStats, SandboxInfo, SnapshotInfo,
};
