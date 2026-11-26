//! The agent proper (Linux only).

mod cgroup;
mod drain;
mod exec;
mod files;
mod landlock;
mod reaper;
mod sys;

use std::fs::File;
use std::io::{self, BufReader};
use std::os::fd::{AsFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use boxent_proto::{
    AgentError, Envelope, ErrorCode, FrameError, HelloInfo, MAX_FRAME, PROTOCOL_VERSION, Request,
    Response, read_frame, write_frame,
};

use cgroup::Cgroups;
use drain::Drainer;
use reaper::Reaper;

pub struct Config {
    pub control_fd: RawFd,
    pub cgroup_root: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub workdir: PathBuf,
    pub writable_roots: Vec<PathBuf>,
    pub nofile: u64,
    /// Refuse to run commands when the kernel has no Landlock (set by the driver in sandboxes).
    pub require_landlock: bool,
}

impl Config {
    const USAGE: &str = "usage: boxent-agent [--control-fd N] [--cgroup-root DIR] [--uid N] \
        [--gid N] [--workdir DIR] [--writable-root DIR]... [--nofile N] [--require-landlock]";

    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut cfg = Self {
            control_fd: 3,
            cgroup_root: "/sys/fs/cgroup".into(),
            uid: 1000,
            gid: 1000,
            workdir: "/workspace".into(),
            writable_roots: Vec::new(),
            nofile: 1024,
            require_landlock: false,
        };
        while let Some(flag) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or(format!("{flag} needs a value\n{}", Self::USAGE))
            };
            let num = |v: String| {
                v.parse::<u64>()
                    .map_err(|_| format!("{flag}: not a number: {v}"))
            };
            match flag.as_str() {
                "--control-fd" => cfg.control_fd = num(value()?)? as RawFd,
                "--cgroup-root" => cfg.cgroup_root = value()?.into(),
                "--uid" => cfg.uid = num(value()?)? as u32,
                "--gid" => cfg.gid = num(value()?)? as u32,
                "--workdir" => cfg.workdir = value()?.into(),
                "--writable-root" => cfg.writable_roots.push(value()?.into()),
                "--nofile" => cfg.nofile = num(value()?)?,
                "--require-landlock" => cfg.require_landlock = true,
                _ => return Err(format!("unknown argument {flag}\n{}", Self::USAGE)),
            }
        }
        if cfg.control_fd < 3 {
            return Err("--control-fd must be 3 or higher".into());
        }
        if cfg.writable_roots.is_empty() {
            cfg.writable_roots = vec![cfg.workdir.clone(), "/home/sandbox".into(), "/tmp".into()];
        }
        if cfg
            .writable_roots
            .iter()
            .chain([&cfg.workdir, &cfg.cgroup_root])
            .any(|p| !p.is_absolute())
        {
            return Err("directories must be absolute paths".into());
        }
        Ok(cfg)
    }
}

/// State shared by every thread.
pub struct Ctx {
    pub cfg: Config,
    pub reaper: Reaper,
    pub cgroups: Cgroups,
    pub drainer: Drainer,
    pub running: AtomicUsize,
    conn: Mutex<File>,
}

impl Ctx {
    /// Sends one response. If the engine is gone, the sandbox has no purpose: exit.
    fn send(&self, id: u64, body: Response) {
        let mut w = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = write_frame(&mut *w, &Envelope { id, body }) {
            log("error", &format!("cannot write to the engine: {e}"));
            self.exit(4);
        }
    }

    fn exit(&self, code: i32) -> ! {
        self.cgroups.kill_all();
        std::process::exit(code);
    }
}

pub fn log(level: &str, msg: &str) {
    eprintln!("{{\"level\":\"{level}\",\"component\":\"agent\",\"msg\":{msg:?}}}");
}

pub fn main() {
    let cfg = match Config::parse(std::env::args().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(cfg) {
        log("error", &format!("agent failed to start: {e}"));
        std::process::exit(1);
    }
}

fn run(cfg: Config) -> io::Result<()> {
    // Signals are taken from a signalfd by one thread; block them everywhere else.
    let sigset = sys::block_signals(&[libc::SIGCHLD, libc::SIGTERM, libc::SIGINT, libc::SIGHUP])?;
    // SAFETY: plain syscalls, still single-threaded here.
    unsafe {
        libc::umask(0o022);
        if libc::geteuid() == 0 {
            sys::cvt(libc::setgroups(0, std::ptr::null()))?;
        }
    }
    sys::cloexec_inherited(cfg.control_fd);
    sys::set_cloexec(cfg.control_fd)?;
    // SAFETY: the engine passed this descriptor to us; nothing else owns it.
    let control = unsafe { File::from_raw_fd(cfg.control_fd) };

    let cgroups = Cgroups::init(&cfg.cgroup_root)?;
    let ctx = Arc::new(Ctx {
        conn: Mutex::new(control.try_clone()?),
        cfg,
        reaper: Reaper::default(),
        cgroups,
        drainer: Drainer::new()?,
        running: AtomicUsize::new(0),
    });

    let sigfd = sys::signalfd(&sigset)?;
    let c = Arc::clone(&ctx);
    std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            loop {
                match sys::read_signal(sigfd.as_fd()) {
                    Ok(libc::SIGCHLD) => c.reaper.reap(),
                    Ok(sig) => {
                        log("info", &format!("received signal {sig}, shutting down"));
                        c.exit(0);
                    }
                    Err(e) => {
                        log("error", &format!("signalfd: {e}"));
                        c.exit(5);
                    }
                }
            }
        })?;

    let c = Arc::clone(&ctx);
    std::thread::Builder::new()
        .name("drain".into())
        .spawn(move || c.drainer.run())?;

    let (fs_tx, fs_rx) = mpsc::channel::<Envelope<Request>>();
    let c = Arc::clone(&ctx);
    std::thread::Builder::new()
        .name("files".into())
        .spawn(move || {
            if let Err(e) = sys::set_thread_fs_ids(c.cfg.uid, c.cfg.gid) {
                log(
                    "error",
                    &format!("cannot switch the file thread to the sandbox user: {e}"),
                );
                c.exit(6);
            }
            for env in fs_rx {
                let body = match &env.body {
                    Request::WriteFile(r) => files::write(&c.cfg, r)
                        .map_or_else(Response::Error, |n| Response::WriteFile {
                            bytes_written: n,
                        }),
                    Request::ReadFile(r) => {
                        files::read(&c.cfg, r).map_or_else(Response::Error, Response::ReadFile)
                    }
                    _ => unreachable!("only file requests are sent to the file thread"),
                };
                c.send(env.id, body);
            }
        })?;

    let mut reader = BufReader::new(control);
    loop {
        let env: Envelope<Request> = match read_frame(&mut reader, MAX_FRAME) {
            Ok(env) => env,
            Err(FrameError::Closed) => {
                log("info", "engine closed the connection");
                ctx.exit(0);
            }
            Err(e) => {
                // The stream cannot be trusted or resynchronised after a bad frame.
                log("error", &format!("rejecting control stream: {e}"));
                ctx.exit(3);
            }
        };
        let id = env.id;
        match env.body {
            Request::Hello { protocol } => {
                let body = if protocol == PROTOCOL_VERSION {
                    Response::Hello(HelloInfo {
                        protocol: PROTOCOL_VERSION,
                        agent_version: env!("CARGO_PKG_VERSION").into(),
                        pid: std::process::id(),
                        landlock_abi: landlock::abi() as u32,
                    })
                } else {
                    Response::Error(AgentError::new(
                        ErrorCode::InvalidRequest,
                        format!(
                            "protocol {protocol} not supported (agent speaks {PROTOCOL_VERSION})"
                        ),
                    ))
                };
                ctx.send(id, body);
            }
            Request::Ping => ctx.send(id, Response::Pong),
            Request::Exec(req) => {
                let c = Arc::clone(&ctx);
                std::thread::Builder::new()
                    .name(format!("exec-{id}"))
                    .spawn(move || {
                        let body = exec::run(&c, req);
                        c.send(id, body);
                    })?;
            }
            Request::WriteFile(_) | Request::ReadFile(_) => {
                if fs_tx.send(env).is_err() {
                    ctx.exit(6);
                }
            }
            Request::KillAll => {
                let c = Arc::clone(&ctx);
                std::thread::Builder::new()
                    .name("kill-all".into())
                    .spawn(move || {
                        let n = c.cgroups.kill_all();
                        c.send(
                            id,
                            Response::KillAll {
                                processes_killed: n,
                            },
                        );
                    })?;
            }
            Request::Shutdown => {
                ctx.send(id, Response::ShuttingDown);
                ctx.exit(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    fn parse(args: &[&str]) -> Result<Config, String> {
        Config::parse(args.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn defaults() {
        let c = parse(&[]).unwrap();
        assert_eq!(c.control_fd, 3);
        assert_eq!(c.uid, 1000);
        assert_eq!(c.writable_roots.len(), 3);
        assert_eq!(c.writable_roots[0], c.workdir);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse(&["--control-fd", "1"]).is_err());
        assert!(parse(&["--uid"]).is_err());
        assert!(parse(&["--uid", "x"]).is_err());
        assert!(parse(&["--workdir", "relative"]).is_err());
        assert!(parse(&["--bogus"]).is_err());
    }

    #[test]
    fn explicit_roots_replace_defaults() {
        let c = parse(&[
            "--workdir",
            "/w",
            "--writable-root",
            "/w",
            "--writable-root",
            "/t",
        ])
        .unwrap();
        assert_eq!(
            c.writable_roots,
            vec![std::path::PathBuf::from("/w"), "/t".into()]
        );
    }
}
