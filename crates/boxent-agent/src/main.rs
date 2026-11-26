//! In-sandbox PID 1 agent for Boxent.
//!
//! The engine starts the agent as the first process of every sandbox and talks to it over a
//! socket passed as an inherited file descriptor (no path exists inside the sandbox to connect
//! to). The agent reaps orphaned processes, runs commands in per-command cgroups as the sandbox
//! user, and reads and writes files with that user's permissions.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("boxent-agent only runs on Linux, inside a Boxent sandbox");
    std::process::exit(2);
}
