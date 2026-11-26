//! Thin wrappers over the Linux syscalls the agent needs. Every `unsafe` block is here or in the
//! fork-to-exec hook in `exec.rs`.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

pub fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

/// Blocks `sigs` in the calling thread; threads spawned afterwards inherit the mask.
pub fn block_signals(sigs: &[libc::c_int]) -> io::Result<libc::sigset_t> {
    // SAFETY: sigset_t is plain data; sigemptyset/sigaddset initialise it.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &s in sigs {
            libc::sigaddset(&mut set, s);
        }
        let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        Ok(set)
    }
}

pub fn signalfd(set: &libc::sigset_t) -> io::Result<OwnedFd> {
    // SAFETY: set is initialised; the returned fd is owned by us.
    let fd = cvt(unsafe { libc::signalfd(-1, set, libc::SFD_CLOEXEC) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Reads one signal from a signalfd, blocking.
pub fn read_signal(fd: BorrowedFd<'_>) -> io::Result<libc::c_int> {
    // SAFETY: signalfd_siginfo is plain data and we read exactly its size.
    let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::signalfd_siginfo>();
    loop {
        let n = unsafe { libc::read(fd.as_raw_fd(), (&raw mut info).cast(), size) };
        if n == size as isize {
            return Ok(info.ssi_signo as libc::c_int);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

pub fn eventfd() -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the returned fd is owned by us.
    let fd = cvt(unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn eventfd_signal(fd: BorrowedFd<'_>) {
    let one: u64 = 1;
    // SAFETY: writes 8 bytes from a valid u64. Failure (counter overflow) is harmless here.
    unsafe {
        libc::write(fd.as_raw_fd(), (&raw const one).cast(), 8);
    }
}

pub fn eventfd_clear(fd: BorrowedFd<'_>) {
    let mut v: u64 = 0;
    // SAFETY: reads 8 bytes into a valid u64; EAGAIN when already clear is fine.
    unsafe {
        libc::read(fd.as_raw_fd(), (&raw mut v).cast(), 8);
    }
}

pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on an fd we own.
    unsafe {
        let flags = cvt(libc::fcntl(fd, libc::F_GETFL))?;
        cvt(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK))?;
    }
    Ok(())
}

pub fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on an fd we own.
    unsafe {
        let flags = cvt(libc::fcntl(fd, libc::F_GETFD))?;
        cvt(libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC))?;
    }
    Ok(())
}

/// Marks every inherited descriptor except stdio and `keep` close-on-exec, so nothing the agent
/// was started with leaks into user commands.
pub fn cloexec_inherited(keep: RawFd) {
    let ranges = [(3u32, keep as u32 - 1), (keep as u32 + 1, u32::MAX)];
    for (lo, hi) in ranges {
        if lo <= hi {
            // SAFETY: close_range with CLOSE_RANGE_CLOEXEC only changes flags.
            unsafe {
                libc::syscall(libc::SYS_close_range, lo, hi, libc::CLOSE_RANGE_CLOEXEC);
            }
        }
    }
}

/// poll(2) that retries on EINTR. `None` waits forever.
pub fn poll(fds: &mut [libc::pollfd], timeout: Option<Duration>) -> io::Result<usize> {
    let ms = timeout.map_or(-1, |d| d.as_millis().min(i32::MAX as u128) as libc::c_int);
    loop {
        // SAFETY: fds is a valid slice of pollfd.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        if rc >= 0 {
            return Ok(rc as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Non-blocking read: `Ok(None)` when no data is ready, `Ok(Some(0))` at EOF.
pub fn read_nb(fd: RawFd, buf: &mut [u8]) -> io::Result<Option<usize>> {
    loop {
        // SAFETY: buf is valid for writes of buf.len() bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(Some(n as usize));
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return Ok(None),
            _ => return Err(err),
        }
    }
}

pub fn openat2(
    dirfd: RawFd,
    path: &CStr,
    flags: libc::c_int,
    mode: u32,
    resolve: u64,
) -> io::Result<OwnedFd> {
    // SAFETY: open_how is plain data; zero is a valid starting value for every field.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (flags | libc::O_CLOEXEC) as u64;
    how.mode = u64::from(mode);
    how.resolve = resolve;
    loop {
        // SAFETY: path is NUL-terminated and how is a valid open_how of the size we pass.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                path.as_ptr(),
                &raw const how,
                std::mem::size_of::<libc::open_how>(),
            )
        };
        if fd >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) });
        }
        let err = io::Error::last_os_error();
        // openat2 may return EAGAIN under RESOLVE_* flags when a rename raced the lookup.
        if !matches!(err.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) {
            return Err(err);
        }
    }
}

pub fn mkdirat(dirfd: RawFd, name: &CStr, mode: u32) -> io::Result<()> {
    // SAFETY: name is NUL-terminated.
    cvt(unsafe { libc::mkdirat(dirfd, name.as_ptr(), mode as libc::mode_t) }).map(drop)
}

pub fn renameat(dirfd: RawFd, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: both names are NUL-terminated.
    cvt(unsafe { libc::renameat(dirfd, from.as_ptr(), dirfd, to.as_ptr()) }).map(drop)
}

pub fn unlinkat(dirfd: RawFd, name: &CStr) {
    // SAFETY: name is NUL-terminated; failure only leaves a stray temp file.
    unsafe {
        libc::unlinkat(dirfd, name.as_ptr(), 0);
    }
}

pub fn fchmod(fd: RawFd, mode: u32) -> io::Result<()> {
    // SAFETY: plain syscall on an fd we own.
    cvt(unsafe { libc::fchmod(fd, mode as libc::mode_t) }).map(drop)
}

pub fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: stat is plain data filled in by the kernel.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    cvt(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(st)
}

/// Sets the filesystem UID and GID of the calling thread only.
pub fn set_thread_fs_ids(uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: plain syscalls. setfsuid returns the previous id, so verify by reading it back.
    unsafe {
        libc::syscall(libc::SYS_setfsgid, gid);
        libc::syscall(libc::SYS_setfsuid, uid);
        let now_uid = libc::syscall(libc::SYS_setfsuid, u32::MAX) as u32;
        let now_gid = libc::syscall(libc::SYS_setfsgid, u32::MAX) as u32;
        if now_uid != uid || now_gid != gid {
            return Err(io::Error::other(format!(
                "setfsuid/setfsgid did not take effect (now {now_uid}:{now_gid})"
            )));
        }
    }
    Ok(())
}
