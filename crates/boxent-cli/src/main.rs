//! The `boxent` command.
//!
//! `doctor` checks the environment, `vm` manages the Lima VM that hosts the engine on macOS, and
//! on Linux `image` and `sandbox` are development helpers. `daemon` and `mcp` arrive in M3 and M4.

#[cfg(target_os = "linux")]
mod dev;
mod doctor;
mod vm;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Default location of the Btrfs pool that holds images, workspaces and snapshots.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/boxent";

#[derive(Parser)]
#[command(
    name = "boxent",
    version,
    about = "Local sandbox engine for AI agents, served over MCP"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check that this machine has every kernel feature and tool the engine needs.
    ///
    /// On Linux this checks the local kernel. On macOS it checks the Lima setup and then runs
    /// the Linux checks inside the VM.
    Doctor {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
        /// Only run the macOS host checks, not the checks inside the VM.
        #[arg(long)]
        host: bool,
        /// Btrfs data directory to check (Linux only).
        #[arg(long, default_value = DEFAULT_DATA_DIR)]
        data_dir: PathBuf,
    },
    /// Manage the Lima VM that runs the engine on macOS.
    Vm {
        #[command(subcommand)]
        command: vm::VmCommand,
    },
    /// Build root filesystem images (Linux, as root).
    #[cfg(target_os = "linux")]
    Image {
        #[command(subcommand)]
        command: dev::ImageCommand,
    },
    /// Development helpers for single sandboxes (Linux, as root).
    #[cfg(target_os = "linux")]
    Sandbox {
        #[command(subcommand)]
        command: dev::SandboxCommand,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Doctor {
            json,
            host,
            data_dir,
        } => doctor::run(&doctor::Options {
            json,
            host_only: host,
            data_dir,
        }),
        Command::Vm { command } => vm::run(command).map(|()| true),
        #[cfg(target_os = "linux")]
        Command::Image { command } => dev::image(command),
        #[cfg(target_os = "linux")]
        Command::Sandbox { command } => dev::sandbox(command),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}
