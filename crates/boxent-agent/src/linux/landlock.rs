//! Landlock rules for user commands: the whole filesystem is readable and executable, but only
//! the writable roots (workspace, home, /tmp) and device files can be written.
//!
//! This holds even where file permissions would allow a write, for example to the user's own
//! entries under /proc. The ruleset is built fresh for every command, so a workspace that was
//! swapped by a restore is covered by the new mount, not the old one.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: u32 = 1;

const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const REFER: u64 = 1 << 13;
const TRUNCATE: u64 = 1 << 14;
const IOCTL_DEV: u64 = 1 << 15;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// The Landlock ABI version the kernel supports, or 0 if Landlock is unavailable.
pub fn abi() -> i64 {
    // SAFETY: with the VERSION flag the kernel ignores the attr pointer and size.
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    v.max(0)
}

fn handled_for(abi: i64) -> u64 {
    let mut h = (1u64 << 13) - 1; // ABI 1: execute .. make_sym
    if abi >= 2 {
        h |= REFER;
    }
    if abi >= 3 {
        h |= TRUNCATE;
    }
    if abi >= 5 {
        h |= IOCTL_DEV;
    }
    h
}

/// Builds the ruleset. Returns `None` when the kernel has no Landlock.
pub fn ruleset(writable: &[PathBuf]) -> io::Result<Option<OwnedFd>> {
    let abi = abi();
    if abi < 1 {
        return Ok(None);
    }
    let handled = handled_for(abi);
    let attr = RulesetAttr {
        handled_access_fs: handled,
    };
    // SAFETY: attr is a valid ruleset_attr prefix of the size we pass.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel returned a new descriptor that we now own.
    let ruleset = unsafe { OwnedFd::from_raw_fd(fd as i32) };

    allow(&ruleset, Path::new("/"), EXECUTE | READ_FILE | READ_DIR)?;
    // Device files: /dev/null, /dev/tty and friends; `> /dev/null` needs truncate.
    allow(
        &ruleset,
        Path::new("/dev"),
        (READ_FILE | WRITE_FILE | READ_DIR | TRUNCATE | IOCTL_DEV) & handled,
    )?;
    for root in writable
        .iter()
        .map(PathBuf::as_path)
        .chain([Path::new("/dev/shm")])
    {
        allow(&ruleset, root, handled)?;
    }
    Ok(Some(ruleset))
}

/// Adds a rule for `path` and everything beneath it. Missing paths are skipped.
fn allow(ruleset: &OwnedFd, path: &Path, access: u64) -> io::Result<()> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: c is NUL-terminated; the fd is closed when `dir` drops.
    let raw = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if raw < 0 {
        let err = io::Error::last_os_error();
        return if err.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(err)
        };
    }
    let dir = unsafe { OwnedFd::from_raw_fd(raw) };
    let rule = PathBeneathAttr {
        allowed_access: access,
        parent_fd: dir.as_raw_fd(),
    };
    // SAFETY: rule is a valid, packed path_beneath_attr.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            &raw const rule,
            0u32,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Applies the ruleset to the calling process. Async-signal-safe: one syscall.
pub fn restrict_self(ruleset: libc::c_int) -> libc::c_long {
    // SAFETY: plain syscall; no_new_privs is already set by the caller.
    unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handled_rights_grow_with_abi() {
        assert_eq!(handled_for(1), 0x1fff);
        assert_eq!(handled_for(2), 0x3fff);
        assert_eq!(handled_for(4), 0x7fff);
        assert_eq!(handled_for(8), 0xffff);
        assert_eq!(std::mem::size_of::<PathBeneathAttr>(), 12);
    }
}
