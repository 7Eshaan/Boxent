//! Btrfs subvolume operations via btrfs-progs. M5 replaces these with ioctls and adds snapshots
//! and quotas.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

fn btrfs(args: &[&std::ffi::OsStr]) -> Result<()> {
    let out = Command::new("btrfs")
        .args(args)
        .output()
        .context("running btrfs (is btrfs-progs installed?)")?;
    if !out.status.success() {
        bail!(
            "btrfs {} failed: {}",
            args.iter()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

pub fn create_subvolume(p: &Path) -> Result<()> {
    btrfs(&["subvolume".as_ref(), "create".as_ref(), p.as_os_str()])
}

pub fn delete_subvolume(p: &Path) -> Result<()> {
    btrfs(&["subvolume".as_ref(), "delete".as_ref(), p.as_os_str()])
}

pub fn set_readonly(p: &Path) -> Result<()> {
    btrfs(&[
        "property".as_ref(),
        "set".as_ref(),
        "-ts".as_ref(),
        p.as_os_str(),
        "ro".as_ref(),
        "true".as_ref(),
    ])
}
