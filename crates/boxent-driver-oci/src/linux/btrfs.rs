//! Btrfs operations via btrfs-progs: subvolumes, read-only snapshots, and simple-quota budgets.
//!
//! Each sandbox gets a level-1 qgroup holding its live subvolume and all its snapshots, with a
//! limit. Simple quotas charge an extent to the subvolume that wrote it for its whole life, so
//! data pinned by a snapshot keeps counting against the sandbox after it is deleted from the
//! workspace: a write-snapshot-delete loop cannot exceed the budget.

use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

fn btrfs(args: &[&std::ffi::OsStr]) -> Result<String> {
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
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn create_subvolume(p: &Path) -> Result<()> {
    btrfs(&["subvolume".as_ref(), "create".as_ref(), p.as_os_str()]).map(drop)
}

/// Creates a subvolume inside the given level-1 qgroup.
pub fn create_subvolume_in(p: &Path, qgroup: &str) -> Result<()> {
    btrfs(&[
        "subvolume".as_ref(),
        "create".as_ref(),
        "-i".as_ref(),
        qgroup.as_ref(),
        p.as_os_str(),
    ])
    .map(drop)
}

/// Snapshots `src` to `dst` (read-only if asked), inside the given level-1 qgroup.
pub fn snapshot(src: &Path, dst: &Path, readonly: bool, qgroup: &str) -> Result<()> {
    let mut args: Vec<&std::ffi::OsStr> = vec!["subvolume".as_ref(), "snapshot".as_ref()];
    if readonly {
        args.push("-r".as_ref());
    }
    args.extend([
        "-i".as_ref(),
        qgroup.as_ref(),
        src.as_os_str(),
        dst.as_os_str(),
    ]);
    btrfs(&args).map(drop)
}

pub fn delete_subvolume(p: &Path) -> Result<()> {
    btrfs(&["subvolume".as_ref(), "delete".as_ref(), p.as_os_str()]).map(drop)
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
    .map(drop)
}

/// Creates a level-1 qgroup with a byte limit, for one sandbox.
pub fn create_budget(fs: &Path, qgroup: &str, bytes: u64) -> Result<()> {
    btrfs(&[
        "qgroup".as_ref(),
        "create".as_ref(),
        qgroup.as_ref(),
        fs.as_os_str(),
    ])?;
    btrfs(&[
        "qgroup".as_ref(),
        "limit".as_ref(),
        bytes.to_string().as_ref(),
        qgroup.as_ref(),
        fs.as_os_str(),
    ])
    .map(drop)
}

static BUDGETS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Queues a dead sandbox's qgroup for removal. Btrfs cleans deleted subvolumes in the
/// background (up to a transaction interval later) and refuses to drop their qgroup before
/// that, so removal is retried by [`gc_budgets`] rather than waited for.
pub fn retire_budget(data_dir: &Path, qgroup: &str) -> Result<()> {
    let _guard = BUDGETS.lock().unwrap_or_else(|e| e.into_inner());
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join(".retired-qgroups"))?;
    writeln!(f, "{qgroup}")?;
    Ok(())
}

/// Drops every retired qgroup Btrfs is done with; keeps the rest for next time.
pub fn gc_budgets(data_dir: &Path) {
    let _guard = BUDGETS.lock().unwrap_or_else(|e| e.into_inner());
    let path = data_dir.join(".retired-qgroups");
    let Ok(list) = std::fs::read_to_string(&path) else {
        return;
    };
    let _ = btrfs(&[
        "qgroup".as_ref(),
        "clear-stale".as_ref(),
        data_dir.as_os_str(),
    ]);
    for q in list.lines().map(str::trim).filter(|q| !q.is_empty()) {
        let _ = btrfs(&[
            "qgroup".as_ref(),
            "destroy".as_ref(),
            q.as_ref(),
            data_dir.as_os_str(),
        ]);
    }
    let remaining = level1_qgroups(data_dir);
    let pending: Vec<&str> = list
        .lines()
        .map(str::trim)
        .filter(|q| remaining.iter().any(|r| r == q))
        .collect();
    let _ = std::fs::write(
        &path,
        pending.iter().map(|q| format!("{q}\n")).collect::<String>(),
    );
}

/// Level-1 qgroups currently defined (for the orphan sweep).
pub fn level1_qgroups(fs: &Path) -> Vec<String> {
    btrfs(&[
        "qgroup".as_ref(),
        "show".as_ref(),
        "--raw".as_ref(),
        fs.as_os_str(),
    ])
    .map(|out| {
        out.lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|id| id.starts_with("1/"))
            .map(str::to_owned)
            .collect()
    })
    .unwrap_or_default()
}

/// Hands out level-1 qgroup ids that are never reused (a counter kept on the pool), so a new
/// sandbox never meets a qgroup still being cleaned up after an old one.
pub fn next_qgroup(data_dir: &Path) -> Result<String> {
    static SEQ: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = SEQ.lock().unwrap_or_else(|e| e.into_inner());
    let path = data_dir.join(".qgroup-seq");
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    let n: u64 = s.trim().parse().unwrap_or(1000) + 1;
    f.rewind()?;
    f.set_len(0)?;
    f.write_all_at(n.to_string().as_bytes(), 0)?;
    f.flush()?;
    Ok(format!("1/{n}"))
}
