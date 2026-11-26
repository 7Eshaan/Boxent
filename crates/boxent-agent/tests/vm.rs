//! Agent tests against a real kernel. They run as root inside the Lima VM (`cargo xtask vm-test`)
//! and are skipped anywhere else.
//!
//! Each test starts the agent as PID 1 of a fresh PID namespace (`unshare --pid --fork`), in its
//! own cgroup, and talks to it over a socketpair passed as fd 3, as the engine will.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use boxent_proto::{
    Caps, Envelope, ErrorCode, ExecRequest, ExecResult, MAX_FRAME, PROTOCOL_VERSION,
    ReadFileRequest, Request, Response, WriteFileRequest, read_frame, write_frame,
};

const UID: u32 = 1000;
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// True when running as root with the opt-in variable set; otherwise the test is skipped.
fn enabled() -> bool {
    let on = std::env::var_os("BOXENT_VM_TESTS").is_some() && unsafe { libc::geteuid() } == 0;
    if !on {
        eprintln!("skipped: set BOXENT_VM_TESTS=1 and run as root (cargo xtask vm-test)");
    }
    on
}

struct Agent {
    child: Child,
    conn: UnixStream,
    next_id: u64,
    cgroup: PathBuf,
    base: PathBuf,
    ws: PathBuf,
}

struct Options {
    memory_max: Option<&'static str>,
}

impl Agent {
    fn start() -> Self {
        Self::start_with(Options { memory_max: None })
    }

    fn start_with(opts: Options) -> Self {
        let n = format!(
            "{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let cgroup = PathBuf::from(format!("/sys/fs/cgroup/boxent-test-{n}"));
        fs::create_dir(&cgroup).expect("create test cgroup");
        if let Some(max) = opts.memory_max {
            fs::write(cgroup.join("memory.max"), max).unwrap();
            fs::write(cgroup.join("memory.swap.max"), "0").unwrap();
        }
        let base = PathBuf::from(format!("/tmp/boxent-test-{n}"));
        let ws = base.join("workspace");
        fs::create_dir_all(&ws).unwrap();
        chown(&ws);

        let agent = std::env::var("BOXENT_AGENT_BIN")
            .unwrap_or_else(|_| "/usr/local/lib/boxent/boxent-agent".into());
        let (ours, theirs) = UnixStream::pair().unwrap();
        let theirs_fd = theirs.as_raw_fd();
        let mut cmd = Command::new("unshare");
        cmd.args(["--pid", "--fork", "--mount-proc", "--kill-child", &agent])
            .args(["--control-fd", "3", "--cgroup-root"])
            .arg(&cgroup)
            .arg("--workdir")
            .arg(&ws)
            .arg("--writable-root")
            .arg(&ws)
            // A secret in the agent's own environment must never reach commands.
            .env("BOXENT_CANARY_SECRET", "canary-7f3a")
            .stdin(Stdio::null());
        unsafe {
            cmd.pre_exec(move || {
                if theirs_fd == 3 {
                    let flags = libc::fcntl(3, libc::F_GETFD);
                    libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                } else if libc::dup2(theirs_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().expect("spawn unshare + agent");
        drop(theirs);
        ours.set_read_timeout(Some(Duration::from_secs(180)))
            .unwrap();
        let mut a = Self {
            child,
            conn: ours,
            next_id: 1,
            cgroup,
            base,
            ws,
        };
        match a.call(Request::Hello {
            protocol: PROTOCOL_VERSION,
        }) {
            Response::Hello(h) => assert_eq!(h.pid, 1, "agent must be PID 1 in its namespace"),
            other => panic!("unexpected hello reply: {other:?}"),
        }
        a
    }

    fn send(&mut self, body: Request) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        write_frame(&mut self.conn, &Envelope { id, body }).unwrap();
        id
    }

    fn recv(&mut self) -> Envelope<Response> {
        read_frame(&mut self.conn, MAX_FRAME).expect("agent reply")
    }

    fn call(&mut self, body: Request) -> Response {
        let id = self.send(body);
        let env = self.recv();
        assert_eq!(env.id, id);
        env.body
    }

    fn exec_req(&self, script: &str, timeout_ms: u64) -> ExecRequest {
        let caps = Caps::default();
        ExecRequest {
            argv: vec![
                "/bin/bash".into(),
                "--noprofile".into(),
                "--norc".into(),
                "-c".into(),
                script.into(),
            ],
            env: vec![
                ("PATH".into(), PATH.into()),
                ("HOME".into(), self.ws.display().to_string()),
            ],
            cwd: self.ws.display().to_string(),
            timeout_ms,
            head_cap: caps.head,
            tail_cap: caps.tail,
        }
    }

    fn exec(&mut self, script: &str, timeout_ms: u64) -> ExecResult {
        let req = self.exec_req(script, timeout_ms);
        let caps = req.caps();
        match self.call(Request::Exec(req)) {
            Response::Exec(r) => {
                r.check(caps).expect("result must respect the caps");
                r
            }
            other => panic!("exec {script:?}: {other:?}"),
        }
    }

    /// Runs a command and returns its trimmed stdout, failing on a non-zero exit.
    fn sh(&mut self, script: &str) -> String {
        let r = self.exec(script, 10_000);
        assert_eq!(r.exit_code, 0, "{script}: stderr={}", r.stderr.render());
        r.stdout.render().trim().to_owned()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = write_frame(
            &mut self.conn,
            &Envelope {
                id: 0,
                body: Request::Shutdown,
            },
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        remove_cgroup_tree(&self.cgroup);
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn remove_cgroup_tree(dir: &Path) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                let _ = fs::write(e.path().join("cgroup.kill"), "1");
                remove_cgroup_tree(&e.path());
            }
        }
    }
    let _ = fs::write(dir.join("cgroup.kill"), "1");
    for _ in 0..200 {
        if fs::remove_dir(dir).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn chown(p: &Path) {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(c.as_ptr(), UID, UID) }, 0);
}

fn exec_cgroups(cg: &Path) -> Vec<String> {
    fs::read_dir(cg)
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("exec-"))
        .collect()
}

#[test]
fn hello_ping_and_basic_exec() {
    if !enabled() {
        return;
    }
    let mut a = Agent::start();
    assert!(matches!(a.call(Request::Ping), Response::Pong));
    let r = a.exec("echo out; echo err >&2; exit 3", 5_000);
    assert_eq!(r.exit_code, 3);
    assert_eq!(r.stdout.render(), "out\n");
    assert_eq!(r.stderr.render(), "err\n");
    assert!(!r.timed_out && !r.oom_killed && r.signal.is_none());
}

#[test]
fn commands_run_as_the_sandbox_user_with_a_clean_environment() {
    if !enabled() {
        return;
    }
    let mut a = Agent::start();
    assert_eq!(a.sh("id -u; id -g; id -G"), "1000\n1000\n1000");
    assert_eq!(
        a.sh("grep ^NoNewPrivs /proc/self/status | awk '{print $2}'"),
        "1"
    );
    assert_eq!(
        a.sh("grep ^CapEff /proc/self/status | awk '{print $2}'"),
        "0000000000000000"
    );
    assert_eq!(a.sh("ulimit -n; ulimit -c"), "1024\n0");
    assert!(a.sh("cat /proc/self/cgroup").contains("/exec-"));
    let env = a.sh("env");
    assert!(
        !env.contains("canary-7f3a"),
        "agent environment leaked: {env}"
    );
    assert!(!env.contains("BOXENT"), "agent environment leaked: {env}");
    // The control socket must not be inherited by commands.
    let fds = a.sh("ls /proc/self/fd | sort -n | tr '\\n' ' '");
    assert_eq!(
        fds, "0 1 2 3",
        "unexpected inherited fds (3 is ls's own dir fd)"
    );
    // The agent's own memory is off limits to the user.
    let r = a.exec("cat /proc/1/environ", 5_000);
    assert_ne!(r.exit_code, 0);
}

#[test]
fn orphans_are_reaped() {
    if !enabled() {
        return;
    }
    let mut a = Agent::start();
    // Each subshell exits at once, so every `sleep` is orphaned and reparented to the agent.
    a.sh("for i in $(seq 50); do (sleep 0.2 &) ; done");
    assert!(
        a.sh("ps -e -o comm= | grep -c '^sleep$' || true")
            .parse::<u32>()
            .unwrap()
            > 0
    );
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(
        a.sh("ps -e -o stat= | grep -c '^Z' || true"),
        "0",
        "zombies left behind"
    );
    assert_eq!(a.sh("ps -e -o comm= | grep -c '^sleep$' || true"), "0");
}

#[test]
fn ten_gigabytes_of_output_is_capped() {
    if !enabled() {
        return;
    }
    let mut a = Agent::start();
    let ten_gib: u64 = 10 * 1024 * 1024 * 1024;
    let t = Instant::now();
    let r = a.exec(&format!("head -c {ten_gib} /dev/zero"), 600_000);
    eprintln!("10 GiB through the agent in {:?}", t.elapsed());
    assert_eq!(r.exit_code, 0);
    assert_eq!(r.stdout.total, ten_gib);
    assert!(r.stdout.truncated);
    assert_eq!(r.stdout.head.len() + r.stdout.tail.len(), 64 * 1024);
    let rss_kib: u64 = a
        .sh("awk '/^VmHWM/ {print $2}' /proc/1/status")
        .parse()
        .unwrap();
    eprintln!("agent peak RSS: {rss_kib} KiB");
    assert!(rss_kib < 32 * 1024, "agent peak RSS {rss_kib} KiB");
}

#[test]
fn timeout_kills_the_whole_tree_including_setsid_escapees() {
    if !enabled() {
        return;
    }
    let mut a = Agent::start();
    let t = Instant::now();
    let r = a.exec(
        "setsid sleep 1000 & nohup sleep 1001 >/dev/null 2>&1 & trap '' TERM; sleep 1002",
        1_000,
    );
    let took = t.elapsed();
    assert!(r.timed_out);
    assert_eq!(r.exit_code, 137);
    assert_eq!(r.signal, Some(9));
    assert!(took < Duration::from_secs(3), "took {took:?}");
    assert!(
        (1000..2000).contains(&r.duration_ms),
        "duration {} ms",
        r.duration_ms
    );
    assert_eq!(
        a.sh("pgrep -c -x sleep || true"),
        "0",
        "processes survived the timeout"
    );
    // The killed command's cgroup is cleaned up (only the probe's own may still exist).
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        exec_cgroups(&a.cgroup).len() <= 1,
        "{:?}",
        exec_cgroups(&a.cgroup)
    );
}

#[test]
fn background_processes_outlive_their_command_and_kill_all_stops_them() {
    if !enabled() {
        return;
    }
    let mut a = Agent::start();
    // Holds the stdout pipe open: the call must still return promptly.
    let r = a.exec("(sleep 30 &); echo started", 10_000);
    assert_eq!(r.stdout.render(), "started\n");
    assert!(r.duration_ms < 500, "took {} ms", r.duration_ms);
    // Redirected background process.
    a.sh("sleep 31 >/dev/null 2>&1 &");
    assert_eq!(a.sh("pgrep -c -x sleep"), "2");
    match a.call(Request::KillAll) {
        Response::KillAll { processes_killed } => assert!(processes_killed >= 2),
        other => panic!("{other:?}"),
    }
    assert_eq!(a.sh("pgrep -c -x sleep || true"), "0");
}

#[test]
fn oom_kill_is_reported_and_the_agent_survives() {
    if !enabled() {
        return;
    }
    let mut a = Agent::start_with(Options {
        memory_max: Some("64M"),
    });
    // tail keeps a newline-free stream in memory until it is killed.
    let r = a.exec("head -c 500M /dev/zero | tail -n 1", 30_000);
    assert!(r.oom_killed, "{r:?}");
    assert!(matches!(a.call(Request::Ping), Response::Pong));
    assert_eq!(a.sh("echo alive"), "alive");
}

#[test]
fn oversized_frame_makes_the_agent_exit() {
    if !enabled() {
        return;
    }
    let mut a = Agent::start();
    a.conn.write_all(&0xFFFF_FFF0u32.to_be_bytes()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(s) = a.child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "agent did not exit");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(!status.success(), "{status:?}");
}

#[test]
fn write_and_read_files() {
    if !enabled() {
        return;
    }
    let mut a = Agent::start();
    let write = |a: &mut Agent, path: &str, content: &[u8]| {
        a.call(Request::WriteFile(WriteFileRequest {
            path: path.into(),
            content: content.to_vec(),
            mode: None,
        }))
    };
    let read = |a: &mut Agent, path: &str, offset: u64, max: u32| {
        a.call(Request::ReadFile(ReadFileRequest {
            path: path.into(),
            offset,
            max_bytes: max,
        }))
    };
    let err_code = |r: Response| match r {
        Response::Error(e) => e.code,
        other => panic!("expected an error, got {other:?}"),
    };

    assert!(matches!(
        write(&mut a, "a/b/c.txt", b"hello\n"),
        Response::WriteFile { bytes_written: 6 }
    ));
    assert_eq!(a.sh("cat a/b/c.txt"), "hello");
    assert_eq!(
        a.sh("stat -c '%u %g %a' a/b/c.txt a/b"),
        "1000 1000 644\n1000 1000 755"
    );
    match read(&mut a, "a/b/c.txt", 1, 3) {
        Response::ReadFile(r) => {
            assert_eq!(r.content, b"ell");
            assert_eq!(r.size, 6);
            assert!(r.truncated);
        }
        other => panic!("{other:?}"),
    }
    // Overwrite is atomic and keeps no temp files around.
    write(&mut a, "a/b/c.txt", b"v2");
    assert_eq!(a.sh("cat a/b/c.txt; ls -A a/b"), "v2c.txt");

    assert_eq!(
        err_code(write(&mut a, "../escape", b"x")),
        ErrorCode::InvalidPath
    );
    assert_eq!(
        err_code(write(&mut a, "/etc/evil", b"x")),
        ErrorCode::InvalidPath
    );
    a.sh("ln -s /etc etclink && ln -s ../.. up");
    assert_eq!(
        err_code(write(&mut a, "etclink/evil", b"x")),
        ErrorCode::InvalidPath
    );
    assert_eq!(
        err_code(write(&mut a, "up/evil", b"x")),
        ErrorCode::InvalidPath
    );
    assert_eq!(err_code(write(&mut a, "a/b", b"x")), ErrorCode::WrongType);
    // Reads run with the user's permissions: the agent's root access does not apply.
    assert_eq!(
        err_code(read(&mut a, "/proc/1/environ", 0, 100)),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        err_code(read(&mut a, "/etc/shadow", 0, 100)),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        err_code(read(&mut a, "/proc/self/root/etc/hostname", 0, 100)),
        ErrorCode::InvalidPath
    );
    assert_eq!(
        err_code(read(&mut a, "missing", 0, 100)),
        ErrorCode::NotFound
    );
    assert_eq!(err_code(read(&mut a, "a", 0, 100)), ErrorCode::WrongType);
    assert!(matches!(
        read(&mut a, "/etc/hostname", 0, 100),
        Response::ReadFile(_)
    ));
}

#[test]
fn concurrent_commands_overlap() {
    if !enabled() {
        return;
    }
    let mut a = Agent::start();
    let t = Instant::now();
    let ids: Vec<u64> = (0..8)
        .map(|i| {
            let req = a.exec_req(&format!("sleep 0.3; echo {i}"), 5_000);
            a.send(Request::Exec(req))
        })
        .collect();
    let mut seen = Vec::new();
    for _ in 0..8 {
        let env = a.recv();
        assert!(ids.contains(&env.id));
        match env.body {
            Response::Exec(r) => seen.push(r.stdout.render().trim().parse::<u32>().unwrap()),
            other => panic!("{other:?}"),
        }
    }
    seen.sort_unstable();
    assert_eq!(seen, (0..8).collect::<Vec<_>>());
    assert!(
        t.elapsed() < Duration::from_millis(1500),
        "took {:?}",
        t.elapsed()
    );
}

#[test]
fn exec_round_trip_latency() {
    if !enabled() {
        return;
    }
    let mut a = Agent::start();
    let mut samples = Vec::new();
    for _ in 0..300 {
        let mut req = a.exec_req("", 5_000);
        req.argv = vec!["/bin/true".into()];
        let t = Instant::now();
        match a.call(Request::Exec(req)) {
            Response::Exec(r) => assert_eq!(r.exit_code, 0),
            other => panic!("{other:?}"),
        }
        samples.push(t.elapsed());
    }
    samples.sort();
    let pct = |p: usize| samples[samples.len() * p / 100];
    eprintln!(
        "exec round trip: p50 {:?}, p95 {:?}, p99 {:?}",
        pct(50),
        pct(95),
        pct(99)
    );
    assert!(pct(99) < Duration::from_millis(50), "p99 {:?}", pct(99));
}
