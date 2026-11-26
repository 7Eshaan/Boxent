//! Namespace creation and mount syscalls.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn cvt(r: libc::c_long) -> io::Result<libc::c_long> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn cpath(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(io::Error::other)
}

/// What the helper child does after `unshare`.
#[derive(Clone, Copy)]
pub enum Setup {
    None,
    /// Bring up the loopback interface of the new network namespace.
    LoopbackUp,
}

/// Creates a namespace and pins it with a bind mount at `pin`, so it outlives every process.
///
/// A short-lived child calls `unshare(flags)`; `between` runs in the parent while the child
/// waits (used to write UID maps); then the child's namespace is bind-mounted onto `pin`.
pub fn create_namespace(
    flags: libc::c_int,
    setup: Setup,
    pin: &Path,
    between: impl FnOnce(libc::pid_t) -> io::Result<()>,
) -> io::Result<()> {
    let mut ready = [0 as RawFd; 2];
    let mut release = [0 as RawFd; 2];
    // SAFETY: pipe2 fills both arrays with new descriptors.
    unsafe {
        cvt(libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC).into())?;
        cvt(libc::pipe2(release.as_mut_ptr(), libc::O_CLOEXEC).into())?;
    }
    let [ready_r, ready_w] = ready.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    let [release_r, release_w] = release.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });

    // SAFETY: the child only makes async-signal-safe syscalls and leaves with _exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // The child must not hold the parent's ends, or it would never see the release EOF.
        // SAFETY: closing descriptors this process owns, before taking any other action.
        unsafe {
            libc::close(ready_r.as_raw_fd());
            libc::close(release_w.as_raw_fd());
            child(flags, setup, ready_w.as_raw_fd(), release_r.as_raw_fd())
        }
    }
    drop(ready_w);
    drop(release_r);

    let result = (|| {
        let mut status = [0u8; 1];
        // SAFETY: reads one byte into a local buffer.
        let n = unsafe { libc::read(ready_r.as_raw_fd(), status.as_mut_ptr().cast(), 1) };
        if n != 1 || status[0] != 0 {
            return Err(io::Error::other(format!(
                "namespace helper failed at step {}",
                if n == 1 { status[0] } else { 255 }
            )));
        }
        between(pid)?;
        let ns = match flags {
            libc::CLONE_NEWUSER => "user",
            libc::CLONE_NEWNET => "net",
            _ => return Err(io::Error::other("unsupported namespace")),
        };
        std::fs::File::create(pin)?;
        bind(Path::new(&format!("/proc/{pid}/ns/{ns}")), pin)
    })();

    drop(release_w); // lets the child exit
    let mut st = 0;
    // SAFETY: waits for our own child.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    result
}

/// Runs in the forked child. Never returns.
unsafe fn child(flags: libc::c_int, setup: Setup, ready: RawFd, release: RawFd) -> ! {
    let report = |step: u8| {
        // SAFETY: writes one byte from a local.
        unsafe { libc::write(ready, (&raw const step).cast(), 1) };
    };
    // SAFETY: plain syscalls in a single-threaded child.
    unsafe {
        if libc::unshare(flags) != 0 {
            report(1);
            libc::_exit(1);
        }
        if let Setup::LoopbackUp = setup
            && !loopback_up()
        {
            report(2);
            libc::_exit(1);
        }
        report(0);
        let mut b = 0u8;
        libc::read(release, (&raw mut b).cast(), 1);
        libc::_exit(0);
    }
}

/// Sets IFF_UP on `lo` with ioctls (no netlink, no allocation).
unsafe fn loopback_up() -> bool {
    // SAFETY: socket/ioctl on a zeroed ifreq naming "lo".
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return false;
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        ifr.ifr_name[0] = b'l' as libc::c_char;
        ifr.ifr_name[1] = b'o' as libc::c_char;
        let ok = libc::ioctl(s, libc::SIOCGIFFLAGS as _, &mut ifr) == 0 && {
            ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            libc::ioctl(s, libc::SIOCSIFFLAGS as _, &ifr) == 0
        };
        libc::close(s);
        ok
    }
}

pub fn bind(src: &Path, dst: &Path) -> io::Result<()> {
    let (s, d) = (cpath(src)?, cpath(dst)?);
    // SAFETY: both paths are NUL-terminated.
    cvt(unsafe {
        libc::mount(
            s.as_ptr(),
            d.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    }
    .into())
    .map(drop)
}

pub fn unmount(p: &Path) {
    if let Ok(c) = cpath(p) {
        // SAFETY: path is NUL-terminated; failure (not mounted) is fine.
        unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
    }
}

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

const OPEN_TREE_CLONE: libc::c_uint = 1;
const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;
const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

/// Bind-mounts `src` at `dst` through the ID mapping of `userns`: files owned by UID n on disk
/// show up as UID n inside that user namespace, whatever host range it maps to.
pub fn idmapped_bind(
    src: &Path,
    dst: &Path,
    userns: BorrowedFd<'_>,
    readonly: bool,
) -> io::Result<()> {
    let (s, d) = (cpath(src)?, cpath(dst)?);
    let empty = c"";
    // SAFETY: new-mount-API syscalls with valid, NUL-terminated paths and a correctly sized attr.
    unsafe {
        let tree = cvt(libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            s.as_ptr(),
            OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint,
        ))?;
        let tree = OwnedFd::from_raw_fd(tree as RawFd);
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_IDMAP
                | MOUNT_ATTR_NOSUID
                | MOUNT_ATTR_NODEV
                | if readonly { MOUNT_ATTR_RDONLY } else { 0 },
            attr_clr: 0,
            propagation: 0,
            userns_fd: userns.as_raw_fd() as u64,
        };
        cvt(libc::syscall(
            libc::SYS_mount_setattr,
            tree.as_raw_fd(),
            empty.as_ptr(),
            libc::AT_EMPTY_PATH,
            &raw const attr,
            std::mem::size_of::<MountAttr>(),
        ))?;
        cvt(libc::syscall(
            libc::SYS_move_mount,
            tree.as_raw_fd(),
            empty.as_ptr(),
            libc::AT_FDCWD,
            d.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        ))?;
    }
    Ok(())
}

pub fn chown(p: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let c = cpath(p)?;
    // SAFETY: path is NUL-terminated.
    cvt(unsafe { libc::chown(c.as_ptr(), uid, gid) }.into()).map(drop)
}

/// 128 random bits as lowercase hex.
pub fn random_hex() -> io::Result<String> {
    let mut b = [0u8; 16];
    // SAFETY: fills the buffer with random bytes.
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    if n != b.len() as isize {
        return Err(io::Error::last_os_error());
    }
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}
