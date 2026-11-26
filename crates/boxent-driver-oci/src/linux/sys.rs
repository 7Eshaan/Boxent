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

    // Release the child with an explicit byte rather than EOF: helper children forked
    // concurrently by other threads inherit copies of this pipe, so EOF may never come.
    // SAFETY: writes one byte from a local.
    unsafe { libc::write(release_w.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
    drop(release_w);
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

/// A detached clone of the mount at `src`, seen through the ID mapping of `userns`: files owned
/// by UID n on disk show up as UID n inside that user namespace, whatever host range it maps to.
pub fn idmapped_tree(src: &Path, userns: BorrowedFd<'_>, readonly: bool) -> io::Result<OwnedFd> {
    let s = cpath(src)?;
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
        Ok(tree)
    }
}

fn move_tree(tree: &OwnedFd, dst: &std::ffi::CStr) -> libc::c_long {
    // SAFETY: attaches a detached mount at a NUL-terminated path.
    unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            tree.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            dst.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    }
}

/// Bind-mounts `src` at `dst` (on the host) through the ID mapping of `userns`.
pub fn idmapped_bind(
    src: &Path,
    dst: &Path,
    userns: BorrowedFd<'_>,
    readonly: bool,
) -> io::Result<()> {
    let tree = idmapped_tree(src, userns, readonly)?;
    cvt(move_tree(&tree, &cpath(dst)?)).map(drop)
}

/// Replaces mounts inside a running sandbox: for each `(tree, path)`, whatever is mounted at
/// `path` in the sandbox is detached and `tree` is attached there instead.
///
/// Joining a mount namespace requires a single-threaded process, so a forked child does it: it
/// enters the namespace of `pid` (the sandbox's PID 1), takes that process's root, and moves the
/// trees, which were prepared in this process. Paths are inside the sandbox.
pub fn inject_mounts(pid: u32, mounts: &[(OwnedFd, &str)]) -> io::Result<()> {
    let mnt_ns = std::fs::File::open(format!("/proc/{pid}/ns/mnt"))?;
    let root = std::fs::File::open(format!("/proc/{pid}/root"))?;
    let targets: Vec<std::ffi::CString> = mounts
        .iter()
        .map(|(_, p)| std::ffi::CString::new(*p).map_err(io::Error::other))
        .collect::<io::Result<_>>()?;
    let mut status = [0 as RawFd; 2];
    // SAFETY: pipe2 fills the array with new descriptors.
    unsafe { cvt(libc::pipe2(status.as_mut_ptr(), libc::O_CLOEXEC).into())? };
    let [status_r, status_w] = status.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });

    // SAFETY: the child makes only async-signal-safe syscalls on prepared data, then _exit.
    let pid_child = unsafe { libc::fork() };
    if pid_child < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid_child == 0 {
        // SAFETY: as above; every value used here was prepared before fork.
        unsafe {
            libc::close(status_r.as_raw_fd());
            let fail = |step: i32| -> ! {
                let report = [step, *libc::__errno_location()];
                libc::write(status_w.as_raw_fd(), report.as_ptr().cast(), 8);
                libc::_exit(1)
            };
            if libc::setns(mnt_ns.as_raw_fd(), libc::CLONE_NEWNS) != 0 {
                fail(1);
            }
            if libc::fchdir(root.as_raw_fd()) != 0 || libc::chroot(c".".as_ptr()) != 0 {
                fail(2);
            }
            for (i, (tree, _)) in mounts.iter().enumerate() {
                let target = &targets[i];
                libc::umount2(target.as_ptr(), libc::MNT_DETACH);
                if move_tree(tree, target) != 0 {
                    fail(10 + i as i32);
                }
            }
            libc::_exit(0)
        }
    }
    drop(status_w);
    let mut report = [0i32; 2];
    // SAFETY: reads up to 8 bytes into a local array.
    let n = unsafe { libc::read(status_r.as_raw_fd(), report.as_mut_ptr().cast(), 8) };
    let mut st = 0;
    // SAFETY: waits for our own child.
    unsafe { libc::waitpid(pid_child, &mut st, 0) };
    if n == 8 {
        return Err(io::Error::other(format!(
            "mount injection failed at step {}: {}",
            report[0],
            io::Error::from_raw_os_error(report[1])
        )));
    }
    if !(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0) {
        return Err(io::Error::other("mount injection helper died"));
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

/// Opens a TCP listener on 127.0.0.1:`port` inside the network namespace pinned at `netns`.
///
/// A socket stays in the namespace it was created in, so the engine can serve it from the host
/// while sandbox processes connect to it on their loopback. A short-lived thread joins the
/// namespace (allowed per thread for network namespaces) and creates the socket.
pub fn listen_in_netns(netns: &Path, port: u16) -> io::Result<std::net::TcpListener> {
    let ns = std::fs::File::open(netns)?;
    std::thread::spawn(move || {
        // SAFETY: setns on a namespace descriptor we own; it affects only this thread.
        if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        std::net::TcpListener::bind(("127.0.0.1", port))
    })
    .join()
    .map_err(|_| io::Error::other("netns listener thread panicked"))?
}
