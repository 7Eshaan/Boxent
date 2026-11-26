//! Boxent's isolation driver, built on crun.
//!
//! Each sandbox gets:
//! - a user namespace created by the driver, mapping container IDs 0-65535 to a host range unique
//!   to that sandbox, so root inside is an unprivileged, otherwise unused UID outside;
//! - a network namespace created by the driver and owned by the host, holding only a loopback
//!   interface; root in the sandbox has no capabilities over it, so it cannot add interfaces;
//! - the shared base image as a read-only, idmapped root filesystem;
//! - a Btrfs subvolume for `/workspace` and `/home/sandbox`, idmapped the same way;
//! - a cgroup with CPU, memory, swap and PID limits, delegated to the sandbox's root;
//! - a seccomp allowlist, no capabilities beyond the three the agent needs to drop privileges,
//!   and the Boxent agent as PID 1, reached over an inherited socket.
//!
//! The pieces are wired together in [`OciDriver::create`].

pub mod seccomp;
pub mod spec;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{OciDriver, Sandbox, image};

pub use spec::{DriverConfig, Limits};
