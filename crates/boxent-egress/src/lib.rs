//! Boxent's egress proxy. Sandboxes have no network interface besides loopback; the only way out
//! is an HTTP proxy whose listening socket the engine created inside the sandbox's network
//! namespace (127.0.0.1:3128) and serves from the host. Every connection is checked against the
//! sandbox's profile, an operator-defined allowlist of domains and ports:
//!
//! - only `CONNECT host:port` tunnels and plain `http://` requests are accepted;
//! - IP literals are refused: rules are about names;
//! - the proxy resolves names itself and refuses any that resolve to loopback, private,
//!   link-local, metadata or other non-public addresses, then connects to the address it
//!   checked (no second lookup the sandbox could race);
//! - for TLS, the SNI in the client's hello must match the CONNECT host, so an allowed tunnel
//!   cannot be pointed at another site;
//! - DNS from the sandbox goes nowhere: there is no resolver to exfiltrate through.

pub mod http;
pub mod policy;
mod proxy;
pub mod tls;

pub use policy::{Denied, Profile};
pub use proxy::{EgressStats, PROXY_PORT, ProxyHandle, ProxyOptions, serve};
