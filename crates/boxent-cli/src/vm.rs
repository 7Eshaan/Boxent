//! `boxent vm`: creates and manages the Lima VM that runs the engine on macOS.
//!
//! The VM has no host mounts. Its Btrfs data disk is a separate Lima disk, so the VM can be
//! recreated without reformatting it (and deleted with `boxent vm delete --yes`).

use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde_json::Value;

pub const INSTANCE: &str = "boxent";
pub const DATA_DISK: &str = "boxent-data";
const TEMPLATE: &str = include_str!("../../../deploy/lima/boxent.yaml");

#[derive(Subcommand)]
pub enum VmCommand {
    /// Create the VM on first use, otherwise start it.
    Up {
        /// Virtual CPUs (only applied when the VM is created).
        #[arg(long, default_value_t = 4)]
        cpus: u32,
        /// Memory in GiB (only applied when the VM is created).
        #[arg(long, default_value_t = 6)]
        memory: u32,
        /// Size of the Btrfs data disk in GiB (only applied when the disk is created).
        #[arg(long, default_value_t = 40)]
        data_disk: u32,
    },
    /// Stop the VM. Sandboxes inside it are discarded.
    Down,
    /// Show whether the VM exists and is running.
    Status,
    /// Open a shell in the VM, or run a command there.
    Shell {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Delete the VM and its data disk.
    Delete {
        /// Required: confirms that the VM and all data on its disk are destroyed.
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(cmd: VmCommand) -> Result<()> {
    ensure_limactl()?;
    match cmd {
        VmCommand::Up {
            cpus,
            memory,
            data_disk,
        } => up(cpus, memory, data_disk),
        VmCommand::Down => limactl(&["stop", INSTANCE]),
        VmCommand::Status => {
            match instance()? {
                Some(i) => println!(
                    "{INSTANCE}: {} ({} CPUs, {} GiB memory)",
                    str_field(&i, "status"),
                    i.get("cpus").and_then(Value::as_u64).unwrap_or(0),
                    i.get("memory").and_then(Value::as_u64).unwrap_or(0) >> 30,
                ),
                None => println!("{INSTANCE}: not created (run `boxent vm up`)"),
            }
            Ok(())
        }
        VmCommand::Shell { args } => {
            let mut full = vec!["shell", "--workdir", "/", INSTANCE];
            full.extend(args.iter().map(String::as_str));
            limactl(&full)
        }
        VmCommand::Delete { yes } => {
            if !yes {
                bail!("this deletes the VM and its data disk; rerun with --yes to confirm");
            }
            if instance()?.is_some() {
                limactl(&["delete", "--force", INSTANCE])?;
            }
            if disk_exists()? {
                limactl(&["disk", "delete", DATA_DISK])?;
            }
            Ok(())
        }
    }
}

fn up(cpus: u32, memory: u32, data_disk: u32) -> Result<()> {
    match instance()? {
        Some(i) if str_field(&i, "status") == "Running" => {
            println!("{INSTANCE} is already running");
            Ok(())
        }
        Some(_) => limactl(&["start", "--tty=false", INSTANCE]),
        None => {
            if !disk_exists()? {
                let size = format!("{data_disk}GiB");
                limactl(&[
                    "disk", "create", DATA_DISK, "--size", &size, "--format", "raw",
                ])?;
            }
            let path = write_template()?;
            let path = path.to_str().context("template path is not UTF-8")?;
            let (cpus, memory) = (cpus.to_string(), memory.to_string());
            limactl(&[
                "start",
                "--tty=false",
                "--name",
                INSTANCE,
                "--cpus",
                &cpus,
                "--memory",
                &memory,
                path,
            ])
        }
    }
}

/// Writes the embedded template to `~/.boxent/lima/boxent.yaml` so the user can inspect it.
fn write_template() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    let dir = PathBuf::from(home).join(".boxent").join("lima");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join("boxent.yaml");
    std::fs::write(&path, TEMPLATE).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub fn ensure_limactl() -> Result<()> {
    match Command::new("limactl")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
    {
        Ok(s) if s.success() => Ok(()),
        _ => bail!("limactl not found; install Lima with `brew install lima`"),
    }
}

fn limactl(args: &[&str]) -> Result<()> {
    let status = Command::new("limactl")
        .args(args)
        .status()
        .with_context(|| format!("running limactl {}", args.join(" ")))?;
    if !status.success() {
        bail!("limactl {} failed with {status}", args.join(" "));
    }
    Ok(())
}

/// Runs a limactl command and parses its JSON-lines output.
pub fn limactl_json(args: &[&str]) -> Result<Vec<Value>> {
    let out = Command::new("limactl")
        .args(args)
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("running limactl {}", args.join(" ")))?;
    if !out.status.success() {
        bail!("limactl {} failed with {}", args.join(" "), out.status);
    }
    parse_json_lines(&String::from_utf8_lossy(&out.stdout))
}

pub fn parse_json_lines(text: &str) -> Result<Vec<Value>> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).context("parsing limactl JSON output"))
        .collect()
}

/// The `boxent` instance from `limactl list --json`, if it exists.
pub fn instance() -> Result<Option<Value>> {
    Ok(limactl_json(&["list", "--json"])?
        .into_iter()
        .find(|v| str_field(v, "name") == INSTANCE))
}

fn disk_exists() -> Result<bool> {
    Ok(limactl_json(&["disk", "list", "--json"])?
        .iter()
        .any(|v| str_field(v, "name") == DATA_DISK))
}

pub fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_has_safety_settings() {
        assert!(
            TEMPLATE.contains("mounts: []"),
            "the VM must not mount host directories"
        );
        assert!(TEMPLATE.contains("vmType: vz"));
        assert!(TEMPLATE.contains(DATA_DISK));
        assert!(TEMPLATE.contains("guestSocket: /run/boxent/boxent.sock"));
    }

    #[test]
    fn json_lines() {
        let v =
            parse_json_lines("{\"name\":\"a\"}\n\n{\"name\":\"boxent\",\"status\":\"Running\"}\n")
                .unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(str_field(&v[1], "status"), "Running");
        assert_eq!(str_field(&v[0], "status"), "");
    }
}
