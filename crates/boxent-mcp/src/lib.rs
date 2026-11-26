//! Boxent's MCP layer. It depends on the engine's public API only (`boxent_core::Engine`); the
//! engine knows nothing about MCP.
//!
//! - [`schema`]: tool arguments and results, from which the JSON schemas are generated.
//! - `server` (Linux): the tools, and session routing to a default sandbox per connection.
//! - `daemon` (Linux): the Unix-socket listener that `boxent mcp` relays stdio to.

pub mod schema;

#[cfg(target_os = "linux")]
mod linux {
    pub mod daemon;
    pub mod server;
}

#[cfg(target_os = "linux")]
pub use linux::daemon::{DaemonOptions, run as run_daemon, serve_connection};
#[cfg(target_os = "linux")]
pub use linux::server::{BoxentServer, Session};
