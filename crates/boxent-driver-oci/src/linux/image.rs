//! Base images: root filesystems built with mmdebstrap into read-only Btrfs subvolumes under
//! `<data_dir>/images/<name>`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use super::btrfs;

const BASE_RECIPE: &str = include_str!("../../../../images/base/build.sh");

pub fn path(data_dir: &Path, name: &str) -> PathBuf {
    data_dir.join("images").join(name)
}

pub fn exists(data_dir: &Path, name: &str) -> bool {
    path(data_dir, name).join("usr").is_dir()
}

/// Builds an image. Only `base` has a recipe for now. Replacing an image that sandboxes are
/// using is refused by Btrfs (the subvolume is busy), so `force` is safe to try.
pub fn build(data_dir: &Path, name: &str, force: bool) -> Result<PathBuf> {
    if name != "base" {
        bail!("no recipe for image '{name}' (only 'base')");
    }
    let images = data_dir.join("images");
    std::fs::create_dir_all(&images)?;
    let target = path(data_dir, name);
    if exists(data_dir, name) && !force {
        return Ok(target);
    }
    let staging = images.join(format!(".{name}.building"));
    if staging.exists() {
        btrfs::delete_subvolume(&staging)?;
    }
    btrfs::create_subvolume(&staging)?;
    let mut child = Command::new("bash")
        .args(["-s", "--"])
        .arg(&staging)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .stdin(Stdio::piped())
        .spawn()
        .context("running the image recipe")?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(BASE_RECIPE.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        let _ = btrfs::delete_subvolume(&staging);
        bail!("image recipe failed with {status}");
    }
    btrfs::set_readonly(&staging)?;
    if target.exists() {
        btrfs::delete_subvolume(&target).context("replacing the old image (is it in use?)")?;
    }
    std::fs::rename(&staging, &target)?;
    Ok(target)
}
