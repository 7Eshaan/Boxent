//! Running one command: spawn in its own cgroup as the sandbox user, capture head and tail of
//! its output, enforce the timeout, and report how it ended.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use boxent_proto::{
    AgentError, Capture, ErrorCode, ExecRequest, ExecResult, MAX_CAPTURE, Response,
};

use super::{Ctx, landlock, sys};

/// After the main process exits, keep reading output this long before returning. Background
/// processes that hold the pipes open would otherwise make every call wait for the timeout.
const GRACE: Duration = Duration::from_millis(50);
const MAX_TIMEOUT_MS: u64 = 60 * 60 * 1000;
const MAX_CONCURRENT: usize = 64;
const MAX_ARGV_ENV_BYTES: usize = 1024 * 1024;
/// If a killed command still has not exited after this long, stop waiting and report it.
const KILL_WAIT: Duration = Duration::from_secs(10);
/// Bytes read from one pipe per poll round, so a fast writer cannot starve the deadline check.
const READ_BUDGET: usize = 1024 * 1024;

pub fn run(ctx: &Ctx, req: ExecRequest) -> Response {
    match run_inner(ctx, &req) {
        Ok(r) => Response::Exec(r),
        Err(e) => Response::Error(e),
    }
}

fn invalid(msg: impl Into<String>) -> AgentError {
    AgentError::new(ErrorCode::InvalidRequest, msg)
}

fn validate(req: &ExecRequest) -> Result<(), AgentError> {
    if req.argv.is_empty() || req.argv[0].is_empty() {
        return Err(invalid("argv is empty"));
    }
    if req.timeout_ms == 0 || req.timeout_ms > MAX_TIMEOUT_MS {
        return Err(invalid(format!("timeout_ms must be 1..={MAX_TIMEOUT_MS}")));
    }
    if req.head_cap > MAX_CAPTURE || req.tail_cap > MAX_CAPTURE {
        return Err(AgentError::new(
            ErrorCode::TooLarge,
            "output cap above the protocol limit",
        ));
    }
    let mut bytes = 0;
    for s in req.argv.iter().chain(std::iter::once(&req.cwd)) {
        if s.contains('\0') {
            return Err(invalid("argv and cwd must not contain NUL"));
        }
        bytes += s.len();
    }
    for (k, v) in &req.env {
        if k.is_empty() || k.contains(['=', '\0']) || v.contains('\0') {
            return Err(invalid(format!(
                "invalid environment variable name or value: {k:?}"
            )));
        }
        bytes += k.len() + v.len();
    }
    if bytes > MAX_ARGV_ENV_BYTES {
        return Err(AgentError::new(
            ErrorCode::TooLarge,
            "argv and env exceed 1 MiB",
        ));
    }
    if !req.cwd.starts_with('/') {
        return Err(invalid("cwd must be absolute"));
    }
    Ok(())
}

struct RunningGuard<'a>(&'a Ctx);

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.0.running.fetch_sub(1, Ordering::Relaxed);
    }
}

fn run_inner(ctx: &Ctx, req: &ExecRequest) -> Result<ExecResult, AgentError> {
    validate(req)?;
    if ctx.running.fetch_add(1, Ordering::Relaxed) >= MAX_CONCURRENT {
        ctx.running.fetch_sub(1, Ordering::Relaxed);
        return Err(invalid(format!(
            "more than {MAX_CONCURRENT} commands running"
        )));
    }
    let _guard = RunningGuard(ctx);

    let cg = ctx
        .cgroups
        .create_exec()
        .map_err(|e| AgentError::new(ErrorCode::Io, format!("creating the command cgroup: {e}")))?;

    let mut cmd = Command::new(&req.argv[0]);
    cmd.args(&req.argv[1..])
        .env_clear()
        .envs(req.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&req.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let ruleset = landlock::ruleset(&ctx.cfg.writable_roots).map_err(|e| {
        AgentError::new(ErrorCode::Io, format!("building the Landlock ruleset: {e}"))
    })?;
    if ruleset.is_none() && ctx.cfg.require_landlock {
        return Err(AgentError::new(
            ErrorCode::SpawnFailed,
            "Landlock is required but unavailable",
        ));
    }
    let setup = ChildSetup {
        landlock_fd: ruleset.as_ref().map_or(-1, AsRawFd::as_raw_fd),
        procs_fd: cg.procs_file().as_raw_fd(),
        uid: ctx.cfg.uid,
        gid: ctx.cfg.gid,
        nofile: ctx.cfg.nofile,
    };
    // SAFETY: child_setup only makes async-signal-safe syscalls and does not allocate.
    unsafe {
        cmd.pre_exec(move || setup.apply());
    }

    let start = Instant::now();
    let spawned = ctx.reaper.spawn_registered(|| {
        let mut child = cmd.spawn()?;
        let pid = child.id() as libc::pid_t;
        let out: OwnedFd = child.stdout.take().expect("stdout is piped").into();
        let err: OwnedFd = child.stderr.take().expect("stderr is piped").into();
        Ok((pid, (out, err)))
    });
    let (slot, (out, err)) = match spawned {
        Ok(v) => v,
        Err(e) => {
            if let Err(cg) = cg.try_remove() {
                ctx.cgroups.linger(cg);
            }
            return Err(AgentError::new(
                ErrorCode::SpawnFailed,
                format!("cannot start {:?}: {e}", req.argv[0]),
            ));
        }
    };

    sys::set_nonblocking(out.as_raw_fd()).map_err(io_err)?;
    sys::set_nonblocking(err.as_raw_fd()).map_err(io_err)?;
    let mut pipes = [Some(out), Some(err)];
    let mut caps = [
        Capture::new(req.head_cap as usize, req.tail_cap as usize),
        Capture::new(req.head_cap as usize, req.tail_cap as usize),
    ];
    let deadline = start + Duration::from_millis(req.timeout_ms);
    let mut exited_at: Option<Instant> = None;
    let mut killed_at: Option<Instant> = None;
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let now = Instant::now();
        if exited_at.is_none() && killed_at.is_none() && now >= deadline {
            cg.kill();
            killed_at = Some(now);
        }
        if let Some(t) = exited_at
            && (pipes.iter().all(Option::is_none) || now >= t + GRACE)
        {
            break;
        }
        if exited_at.is_none() && killed_at.is_some_and(|k| now >= k + KILL_WAIT) {
            break; // unkillable (stuck in the kernel); report what we have
        }
        let wait = match (exited_at, killed_at) {
            (Some(t), _) => (t + GRACE).saturating_duration_since(now),
            (None, Some(_)) => Duration::from_millis(100),
            (None, None) => deadline.saturating_duration_since(now),
        };
        let mut fds = [
            pollfd(pipes[0].as_ref().map_or(-1, AsRawFd::as_raw_fd)),
            pollfd(pipes[1].as_ref().map_or(-1, AsRawFd::as_raw_fd)),
            pollfd(if exited_at.is_none() {
                slot.fd().as_raw_fd()
            } else {
                -1
            }),
        ];
        sys::poll(&mut fds, Some(wait)).map_err(io_err)?;
        for i in 0..2 {
            if fds[i].revents != 0
                && let Some(fd) = &pipes[i]
                && read_some(fd.as_raw_fd(), &mut caps[i], &mut buf)
            {
                pipes[i] = None; // EOF
            }
        }
        if fds[2].revents != 0 {
            exited_at = Some(Instant::now());
        }
    }

    let ended = exited_at.unwrap_or_else(Instant::now);
    let duration_ms = ended.duration_since(start).as_millis() as u64;
    let (exit_code, signal) = match slot.status() {
        Some(st) if libc::WIFEXITED(st) => (libc::WEXITSTATUS(st), None),
        Some(st) if libc::WIFSIGNALED(st) => (128 + libc::WTERMSIG(st), Some(libc::WTERMSIG(st))),
        _ => (-1, None),
    };
    let oom_killed = cg.oom_kills() > 0;

    // Pipes still held open by background processes are drained (and discarded) elsewhere, so
    // those processes do not die of SIGPIPE when they write.
    for fd in pipes.into_iter().flatten() {
        ctx.drainer.adopt(fd);
    }
    if !cg.populated() {
        if let Err(cg) = cg.try_remove() {
            ctx.cgroups.linger(cg);
        }
    } else {
        ctx.cgroups.linger(cg);
    }

    let [out_cap, err_cap] = caps;
    Ok(ExecResult {
        exit_code,
        signal,
        timed_out: killed_at.is_some(),
        oom_killed,
        duration_ms,
        stdout: out_cap.finish(),
        stderr: err_cap.finish(),
    })
}

fn pollfd(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// Reads what is available, up to the budget. Returns true at EOF or on a read error.
fn read_some(fd: RawFd, cap: &mut Capture, buf: &mut [u8]) -> bool {
    let mut read = 0;
    while read < READ_BUDGET {
        match sys::read_nb(fd, buf) {
            Ok(Some(0)) | Err(_) => return true,
            Ok(Some(n)) => {
                cap.push(&buf[..n]);
                read += n;
            }
            Ok(None) => return false,
        }
    }
    false
}

fn io_err(e: io::Error) -> AgentError {
    AgentError::new(ErrorCode::Io, e.to_string())
}

/// What the child does between fork and exec.
#[derive(Clone, Copy)]
struct ChildSetup {
    landlock_fd: RawFd,
    procs_fd: RawFd,
    uid: u32,
    gid: u32,
    nofile: u64,
}

impl ChildSetup {
    /// Runs in the forked child. Only async-signal-safe syscalls, no allocation.
    fn apply(self) -> io::Result<()> {
        fn check(rc: libc::c_int) -> io::Result<()> {
            if rc < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
        // SAFETY: each call is a plain syscall on valid arguments in a single-threaded child.
        unsafe {
            // The agent blocks these signals to receive them on a signalfd; the command must not
            // start with them blocked, and must get default SIGPIPE behaviour.
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);

            check(libc::setsid())?;
            // Join the command's cgroup before dropping privileges: cgroup.procs is root-owned.
            if libc::write(self.procs_fd, b"0".as_ptr().cast(), 1) != 1 {
                return Err(io::Error::last_os_error());
            }
            let nofile = libc::rlimit {
                rlim_cur: self.nofile,
                rlim_max: self.nofile,
            };
            check(libc::setrlimit(libc::RLIMIT_NOFILE, &nofile))?;
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            check(libc::setrlimit(libc::RLIMIT_CORE, &no_core))?;
            if libc::getuid() == 0 {
                // Empty the bounding set so no capability can ever be regained, even by a
                // setuid-root binary (no_new_privs already blocks that; this is belt and braces).
                for cap in 0..64 {
                    libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
                }
                check(libc::setgroups(0, std::ptr::null()))?;
                check(libc::setgid(self.gid))?;
                check(libc::setuid(self.uid))?;
            }
            check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
            if self.landlock_fd >= 0 && landlock::restrict_self(self.landlock_fd) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}
