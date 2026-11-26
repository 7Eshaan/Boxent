//! File reads and writes on behalf of the engine, with the sandbox user's permissions.
//!
//! These run on one thread whose filesystem UID and GID are the sandbox user's (setfsuid is
//! per-thread), so the kernel checks every access exactly as it would for the user's own
//! commands: the agent's root privileges never apply. On top of that:
//! - paths may not contain `..`, and magic links (`/proc/*/fd`, `/proc/*/root`) are refused;
//! - writes must land inside a writable root (the workspace, home, /tmp), resolved with
//!   `RESOLVE_BENEATH`, so a symlink cannot redirect a write outside it;
//! - writes go to a temp file that is renamed into place, so readers never see half a file.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use boxent_proto::{
    AgentError, ErrorCode, MAX_FILE, ReadFileRequest, ReadFileResult, WriteFileRequest,
};

use super::{Config, sys};

const MAX_PATH: usize = 4096;
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn write(cfg: &Config, req: &WriteFileRequest) -> Result<u64, AgentError> {
    if req.content.len() > MAX_FILE as usize {
        return Err(AgentError::new(
            ErrorCode::TooLarge,
            format!("content exceeds {MAX_FILE} bytes"),
        ));
    }
    // setuid and setgid bits are dropped; sticky and permission bits are kept.
    let mode = req.mode.unwrap_or(0o644) & 0o1777;
    let abs = resolve(cfg, &req.path)?;
    let (root, rel) = cfg
        .writable_roots
        .iter()
        .filter_map(|r| abs.strip_prefix(r).ok().map(|rel| (r, rel)))
        .max_by_key(|(r, _)| r.as_os_str().len())
        .ok_or_else(|| {
            AgentError::new(
                ErrorCode::InvalidPath,
                format!("{} is outside the writable directories", abs.display()),
            )
        })?;
    let comps: Vec<&OsStr> = rel.components().map(Component::as_os_str).collect();
    let Some((name, parents)) = comps.split_last() else {
        return Err(AgentError::new(ErrorCode::WrongType, "path is a directory"));
    };
    let ctx = |e: io::Error| map_err(e, &abs);

    let root_fd = sys::openat2(
        libc::AT_FDCWD,
        &cstr(root.as_os_str())?,
        libc::O_PATH | libc::O_DIRECTORY,
        0,
        libc::RESOLVE_NO_MAGICLINKS,
    )
    .map_err(ctx)?;
    let parent = open_parent(&root_fd, parents).map_err(ctx)?;

    let name = cstr(name)?;
    let tmp = cstr(OsStr::new(&format!(
        ".boxent-{}-{}.tmp",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    )))?;
    let fd = sys::openat2(
        parent.as_raw_fd(),
        &tmp,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        mode,
        libc::RESOLVE_BENEATH,
    )
    .map_err(ctx)?;
    let written = (|| {
        let mut f = File::from(fd);
        f.write_all(&req.content)?;
        sys::fchmod(f.as_raw_fd(), mode)?;
        drop(f);
        sys::renameat(parent.as_raw_fd(), &tmp, &name)
    })();
    if let Err(e) = written {
        sys::unlinkat(parent.as_raw_fd(), &tmp);
        return Err(ctx(e));
    }
    Ok(req.content.len() as u64)
}

pub fn read(cfg: &Config, req: &ReadFileRequest) -> Result<ReadFileResult, AgentError> {
    if req.max_bytes > MAX_FILE {
        return Err(AgentError::new(
            ErrorCode::TooLarge,
            format!("max_bytes exceeds {MAX_FILE}"),
        ));
    }
    let abs = resolve(cfg, &req.path)?;
    let ctx = |e: io::Error| map_err(e, &abs);
    // O_NONBLOCK so opening a FIFO cannot hang the file thread; non-regular files are refused.
    let fd = sys::openat2(
        libc::AT_FDCWD,
        &cstr(abs.as_os_str())?,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
        0,
        libc::RESOLVE_NO_MAGICLINKS,
    )
    .map_err(ctx)?;
    let st = sys::fstat(fd.as_raw_fd()).map_err(ctx)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(AgentError::new(
            ErrorCode::WrongType,
            format!("{} is not a regular file", abs.display()),
        ));
    }
    let size = st.st_size as u64;
    let file = File::from(fd);
    let want = (req.max_bytes as u64).min(size.saturating_sub(req.offset)) as usize;
    let mut content = vec![0u8; want];
    let mut got = 0;
    while got < want {
        match file.read_at(&mut content[got..], req.offset + got as u64) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ctx(e)),
        }
    }
    content.truncate(got);
    Ok(ReadFileResult {
        truncated: req.offset + (got as u64) < size,
        content,
        size,
    })
}

/// Turns a request path into an absolute path: relative paths are under the workspace, `..` is
/// refused outright.
fn resolve(cfg: &Config, path: &str) -> Result<PathBuf, AgentError> {
    if path.is_empty() || path.len() > MAX_PATH || path.contains('\0') {
        return Err(AgentError::new(
            ErrorCode::InvalidPath,
            "path is empty, too long or contains NUL",
        ));
    }
    let p = Path::new(path);
    if p.components().any(|c| c == Component::ParentDir) {
        return Err(AgentError::new(
            ErrorCode::InvalidPath,
            "path must not contain '..'",
        ));
    }
    Ok(if p.is_absolute() {
        p.to_path_buf()
    } else {
        cfg.workdir.join(p)
    })
}

/// Opens (creating as needed) the parent directory, never leaving `root`.
fn open_parent(root: &OwnedFd, parents: &[&OsStr]) -> io::Result<OwnedFd> {
    let flags = libc::O_PATH | libc::O_DIRECTORY;
    let resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS;
    let open = |n: usize| -> io::Result<OwnedFd> {
        let rel = if n == 0 {
            PathBuf::from(".")
        } else {
            parents[..n].iter().collect()
        };
        let c = CString::new(rel.as_os_str().as_bytes()).map_err(io::Error::other)?;
        sys::openat2(root.as_raw_fd(), &c, flags, 0, resolve)
    };
    match open(parents.len()) {
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
        other => return other,
    }
    // Create missing directories one level at a time, each resolved beneath the root.
    let mut dir = open(0)?;
    for i in 1..=parents.len() {
        match open(i) {
            Ok(fd) => dir = fd,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                let name = CString::new(parents[i - 1].as_bytes()).map_err(io::Error::other)?;
                match sys::mkdirat(dir.as_raw_fd(), &name, 0o755) {
                    Err(e) if e.raw_os_error() != Some(libc::EEXIST) => return Err(e),
                    _ => {}
                }
                dir = open(i)?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(dir)
}

fn cstr(s: &OsStr) -> Result<CString, AgentError> {
    CString::new(s.as_bytes())
        .map_err(|_| AgentError::new(ErrorCode::InvalidPath, "path contains NUL"))
}

fn map_err(e: io::Error, path: &Path) -> AgentError {
    let code = match e.raw_os_error() {
        Some(libc::ENOENT) => ErrorCode::NotFound,
        Some(libc::EACCES | libc::EPERM | libc::EROFS) => ErrorCode::PermissionDenied,
        Some(libc::EXDEV | libc::ELOOP) => ErrorCode::InvalidPath,
        Some(libc::EISDIR | libc::ENOTDIR | libc::EEXIST) => ErrorCode::WrongType,
        Some(libc::EFBIG) => ErrorCode::TooLarge,
        Some(libc::ENOSPC | libc::EDQUOT) => ErrorCode::NoSpace,
        _ => ErrorCode::Io,
    };
    AgentError::new(code, format!("{}: {e}", path.display()))
}
