//! Verification suite B: isolation of real sandboxes. Runs as root inside the Lima VM
//! (`cargo xtask vm-test`) and is skipped anywhere else. Egress (B12) arrives with M6 and the
//! workspace disk budget (second half of B6) with M5.
//!
//! Every test ends with a leak check: no mounts, cgroups, subvolumes, state or UID slots may
//! remain once the sandbox is destroyed.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use boxent_driver_oci::{DriverConfig, Limits, OciDriver, Sandbox};
use boxent_proto::{Caps, ErrorCode, ExecRequest, ExecResult, Request, Response, WriteFileRequest};

/// Tests share the host-wide parent cgroup and state directories; run them one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn enabled() -> bool {
    let on = std::env::var_os("BOXENT_VM_TESTS").is_some() && unsafe { libc::geteuid() } == 0;
    if !on {
        eprintln!("skipped: set BOXENT_VM_TESTS=1 and run as root (cargo xtask vm-test)");
    }
    on
}

fn driver() -> OciDriver {
    let mut cfg = DriverConfig::default();
    if let Ok(agent) = std::env::var("BOXENT_AGENT_BIN") {
        cfg.agent_bin = agent.into();
    }
    OciDriver::new(cfg).expect("driver (is the base image built?)")
}

struct Run {
    code: i32,
    out: String,
    err: String,
    result: ExecResult,
}

fn exec(sb: &mut Sandbox, script: &str, timeout_ms: u64) -> Run {
    let caps = Caps::default();
    let result = sb
        .client()
        .exec(ExecRequest {
            argv: vec![
                "/bin/bash".into(),
                "--noprofile".into(),
                "--norc".into(),
                "-c".into(),
                script.into(),
            ],
            env: vec![
                (
                    "PATH".into(),
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
                ),
                ("HOME".into(), "/home/sandbox".into()),
                ("LANG".into(), "C.UTF-8".into()),
            ],
            cwd: "/workspace".into(),
            timeout_ms,
            head_cap: caps.head,
            tail_cap: caps.tail,
        })
        .unwrap_or_else(|e| panic!("exec {script:?}: {e}"));
    Run {
        code: result.exit_code,
        out: result.stdout.render().trim().to_owned(),
        err: result.stderr.render().trim().to_owned(),
        result,
    }
}

/// Runs a command that must succeed and returns its stdout.
fn ok(sb: &mut Sandbox, script: &str) -> String {
    let r = exec(sb, script, 20_000);
    assert_eq!(r.code, 0, "{script}\nstdout: {}\nstderr: {}", r.out, r.err);
    r.out
}

/// Runs a command that must fail and returns its stderr.
fn fails(sb: &mut Sandbox, script: &str) -> String {
    let r = exec(sb, script, 20_000);
    assert_ne!(r.code, 0, "{script} unexpectedly succeeded: {}", r.out);
    r.err
}

/// Python snippet: calls a raw syscall and prints the errno (0 on success).
fn syscall_errno(nr: u32) -> String {
    format!(
        "python3 -c 'import ctypes,os; l=ctypes.CDLL(None,use_errno=True); \
         r=l.syscall({nr},0,0,0,0,0); print(0 if r>=0 else ctypes.get_errno())'"
    )
}

/// What must be gone after a sandbox is destroyed.
fn assert_clean(d: &OciDriver, id: &str) {
    let cfg = d.config();
    let state = cfg.state_dir.join("sb").join(id);
    assert!(!state.exists(), "state dir left: {}", state.display());
    assert!(
        !cfg.data_dir.join("sb").join(id).exists(),
        "storage left for {id}"
    );
    let cg = Path::new("/sys/fs/cgroup")
        .join(&cfg.cgroup_parent)
        .join(id);
    assert!(!cg.exists(), "cgroup left: {}", cg.display());
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(!mounts.contains(id), "mounts left for {id}");
    let qgroups = std::process::Command::new("btrfs")
        .args(["qgroup", "show", "--raw"])
        .arg(&cfg.data_dir)
        .output()
        .unwrap();
    let live_qgroups = String::from_utf8_lossy(&qgroups.stdout)
        .lines()
        .filter(|l| l.starts_with("1/"))
        .count();
    let retired = fs::read_to_string(cfg.data_dir.join(".retired-qgroups")).unwrap_or_default();
    assert!(
        live_qgroups <= retired.lines().count(),
        "{live_qgroups} sandbox qgroups exist but only {} are retired",
        retired.lines().count()
    );
    let slots = fs::read_dir(cfg.state_dir.join("uid-slots"))
        .unwrap()
        .count();
    assert_eq!(slots, 0, "UID slots still claimed");
}

/// Creates a sandbox, runs `f`, destroys it, and checks nothing leaked.
fn with_sandbox(limits: Limits, f: impl FnOnce(&mut Sandbox)) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let d = driver();
    let mut sb = d.create(&limits).expect("create sandbox");
    let id = sb.id().to_owned();
    f(&mut sb);
    sb.destroy().expect("destroy sandbox");
    assert_clean(&d, &id);
}

fn vm_ipv4() -> String {
    let out = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "scope", "global"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace()
        .skip_while(|w| *w != "inet")
        .nth(1)
        .and_then(|cidr| cidr.split('/').next())
        .expect("VM has a global IPv4 address")
        .to_owned()
}

#[cfg(target_arch = "aarch64")]
mod nr {
    pub const PTRACE: u32 = 117;
    pub const KEYCTL: u32 = 219;
    pub const PERF_EVENT_OPEN: u32 = 241;
    pub const BPF: u32 = 280;
    pub const USERFAULTFD: u32 = 282;
}
#[cfg(target_arch = "x86_64")]
mod nr {
    pub const PTRACE: u32 = 101;
    pub const KEYCTL: u32 = 250;
    pub const PERF_EVENT_OPEN: u32 = 298;
    pub const BPF: u32 = 321;
    pub const USERFAULTFD: u32 = 323;
}
const IO_URING_SETUP: u32 = 425;
const CLONE3: u32 = 435;

#[test]
fn b1_network_is_loopback_only() {
    if !enabled() {
        return;
    }
    with_sandbox(Limits::default(), |sb| {
        let links = ok(sb, "ip -o link");
        assert_eq!(links.lines().count(), 1, "{links}");
        assert!(links.contains(": lo:") && links.contains("UP"), "{links}");
        fails(sb, "curl -sS -m 3 https://example.com");
        fails(sb, "getent hosts example.com");
        let errno = ok(
            sb,
            "python3 -c 'import socket\ntry:\n socket.create_connection((\"1.1.1.1\",53),2)\n print(0)\nexcept OSError as e:\n print(e.errno)'",
        );
        assert_eq!(errno, "101", "expected ENETUNREACH");
    });
}

#[test]
fn b2_no_raw_sockets_vsock_host_or_metadata_access() {
    if !enabled() {
        return;
    }
    let vm_ip = vm_ipv4();
    with_sandbox(Limits::default(), |sb| {
        let probe = |family: &str, kind: &str, proto: &str| {
            format!(
                "python3 -c 'import socket\ntry:\n socket.socket({family},{kind},{proto})\n print(\"opened\")\nexcept OSError as e:\n print(e.errno)'"
            )
        };
        assert_eq!(
            ok(
                sb,
                &probe("socket.AF_INET", "socket.SOCK_RAW", "socket.IPPROTO_ICMP")
            ),
            "1"
        );
        assert_eq!(
            ok(sb, &probe("socket.AF_PACKET", "socket.SOCK_RAW", "0")),
            "1"
        );
        // AF_VSOCK would reach the hypervisor host directly; seccomp refuses it.
        assert_eq!(ok(sb, &probe("40", "socket.SOCK_STREAM", "0")), "1");
        for target in [
            format!("{vm_ip}:22"),
            "169.254.169.254:80".into(),
            "192.168.5.2:22".into(),
        ] {
            let (host, port) = target.split_once(':').unwrap();
            fails(
                sb,
                &format!("timeout 3 bash -c 'exec 3<>/dev/tcp/{host}/{port}'"),
            );
        }
        let run = ok(sb, "ls -A /run");
        assert!(
            !run.contains("boxent") && !run.contains("lima"),
            "/run shows host state: {run}"
        );
        let mounts = ok(sb, "cat /proc/self/mountinfo");
        for leak in ["/Users", "lima", ".ssh", "/run/boxent"] {
            assert!(
                !mounts.contains(leak),
                "mountinfo mentions {leak}:\n{mounts}"
            );
        }
    });
}

#[test]
fn b3_fork_bomb_is_contained() {
    if !enabled() {
        return;
    }
    let limits = Limits {
        pids: 64,
        ..Limits::default()
    };
    let host_procs = || {
        fs::read_dir("/proc")
            .unwrap()
            .filter(|e| {
                e.as_ref().is_ok_and(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .chars()
                        .all(|c| c.is_ascii_digit())
                })
            })
            .count()
    };
    let before = host_procs();
    with_sandbox(limits, |sb| {
        let r = exec(sb, "bomb() { bomb | bomb & }; bomb; sleep 2", 3_000);
        let events = fs::read_to_string(sb.cgroup().join("pids.events")).unwrap();
        let hits: u64 = events.split_whitespace().nth(1).unwrap().parse().unwrap();
        assert!(hits > 0, "pids.max was never reached: {events}");
        let peak: u64 = fs::read_to_string(sb.cgroup().join("pids.peak"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(peak <= 64, "pids.peak {peak}");
        eprintln!(
            "fork bomb: timed_out={} pids.max hits={hits} peak={peak}",
            r.result.timed_out
        );
        // The bomb is gone and the sandbox still works.
        match sb.client().call(Request::KillAll).unwrap() {
            Response::KillAll { .. } => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(ok(sb, "echo alive"), "alive");
    });
    let after = host_procs();
    assert!(after <= before + 5, "host processes {before} -> {after}");
}

#[test]
fn b4_memory_limit_kills_the_command_not_the_sandbox() {
    if !enabled() {
        return;
    }
    let limits = Limits {
        memory_bytes: 256 << 20,
        ..Limits::default()
    };
    with_sandbox(limits, |sb| {
        let r = exec(sb, "python3 -c \"b = b'x' * (512 << 20)\"", 30_000);
        assert!(
            r.result.oom_killed,
            "not OOM-killed: code {} err {}",
            r.code, r.err
        );
        assert_eq!(r.code, 137);
        assert_eq!(
            fs::read_to_string(sb.cgroup().join("memory.swap.max"))
                .unwrap()
                .trim(),
            "0"
        );
        assert!(matches!(
            sb.client().call(Request::Ping).unwrap(),
            Response::Pong
        ));
        assert_eq!(ok(sb, "echo alive"), "alive");
    });
}

#[test]
fn b5_cpu_quota_is_enforced() {
    if !enabled() {
        return;
    }
    with_sandbox(
        Limits {
            cpus: 1.0,
            ..Limits::default()
        },
        |sb| {
            let r = exec(
                sb,
                "TIMEFORMAT='%U %S %R'; time (for i in 1 2 3 4; do timeout 3 bash -c 'while :; do :; done' & done; wait)",
                20_000,
            );
            let nums: Vec<f64> = r
                .err
                .split_whitespace()
                .filter_map(|w| w.parse().ok())
                .collect();
            let [user, sys, real] = nums[..] else {
                panic!("unexpected timing output: {}", r.err)
            };
            let cores = (user + sys) / real;
            eprintln!("4 busy loops under a 1-CPU quota used {cores:.2} cores");
            assert!(cores <= 1.15, "used {cores:.2} cores");
            assert!(cores >= 0.7, "loops barely ran ({cores:.2} cores)");
        },
    );
}

#[test]
fn b6_tmp_and_shm_are_size_capped() {
    if !enabled() {
        return;
    }
    with_sandbox(Limits::default(), |sb| {
        let err = fails(
            sb,
            "dd if=/dev/zero of=/tmp/big bs=1M count=100 status=none",
        );
        assert!(err.contains("No space left"), "{err}");
        let err = fails(
            sb,
            "dd if=/dev/zero of=/dev/shm/big bs=1M count=100 status=none",
        );
        assert!(err.contains("No space left"), "{err}");
    });
}

#[test]
fn b7_rootfs_proc_and_sys_are_read_only() {
    if !enabled() {
        return;
    }
    with_sandbox(Limits::default(), |sb| {
        assert!(fails(sb, "touch /usr/bin/x").contains("Read-only file system"));
        fails(sb, "echo x >> /etc/passwd");
        fails(sb, "echo 1 > /proc/sys/kernel/sysrq");
        fails(sb, "touch /sys/x");
        fails(sb, "mkdir /sys/fs/cgroup/escape");
        assert_eq!(
            ok(sb, "wc -c < /proc/kcore"),
            "0",
            "/proc/kcore is not masked"
        );
        assert_eq!(ok(sb, "cat /proc/keys | wc -l"), "0");
        // The sandbox root user cannot write the rootfs either: it is a read-only mount.
        assert_eq!(ok(sb, "stat -c %U /usr/bin/env"), "root");
    });
}

#[test]
fn b8_privileges_syscalls_and_landlock() {
    if !enabled() {
        return;
    }
    with_sandbox(Limits::default(), |sb| {
        let status = ok(
            sb,
            "grep -E '^(Uid|CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status",
        );
        for want in [
            "Uid:\t1000",
            "CapEff:\t0000000000000000",
            "CapBnd:\t0000000000000000",
            "NoNewPrivs:\t1",
            "Seccomp:\t2",
        ] {
            assert!(status.contains(want), "missing {want:?} in\n{status}");
        }
        fails(sb, "unshare -U true");
        fails(sb, "mkdir -p /tmp/m && mount -t tmpfs none /tmp/m");
        for (name, n) in [
            ("io_uring_setup", IO_URING_SETUP),
            ("bpf", nr::BPF),
            ("keyctl", nr::KEYCTL),
            ("ptrace", nr::PTRACE),
            ("userfaultfd", nr::USERFAULTFD),
            ("perf_event_open", nr::PERF_EVENT_OPEN),
        ] {
            assert_eq!(
                ok(sb, &syscall_errno(n)),
                "1",
                "{name} is not blocked with EPERM"
            );
        }
        assert_eq!(
            ok(sb, &syscall_errno(CLONE3)),
            "38",
            "clone3 should be ENOSYS"
        );
        // Landlock: writable by file permissions, outside the writable roots.
        fails(sb, "echo 500 > /proc/self/oom_score_adj");
        // Root in the sandbox is an unprivileged, sandbox-specific UID on the host.
        let pid = sb.host_pid().unwrap();
        let host_status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let uid: u32 = host_status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|l| l.split_whitespace().next())
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(uid, sb.uid_base(), "agent runs as host UID {uid}");
        assert!(uid >= 1 << 20);
    });
}

#[test]
fn b9_no_host_environment_or_secrets() {
    if !enabled() {
        return;
    }
    // SAFETY: tests holding SERIAL are the only ones touching the environment.
    unsafe { std::env::set_var("BOXENT_CANARY_SECRET", "canary-91c4") };
    with_sandbox(Limits::default(), |sb| {
        let env = ok(sb, "env");
        assert!(
            !env.contains("canary-91c4") && !env.contains("BOXENT"),
            "{env}"
        );
        let pid = sb.host_pid().unwrap();
        let agent_env = fs::read(format!("/proc/{pid}/environ")).unwrap();
        assert!(!String::from_utf8_lossy(&agent_env).contains("canary-91c4"));
        assert_eq!(
            ok(
                sb,
                "grep -rs canary-91c4 /etc /home /workspace /tmp | wc -l"
            ),
            "0"
        );
        assert!(ok(sb, "ls -A /home").lines().eq(["sandbox"]));
    });
    unsafe { std::env::remove_var("BOXENT_CANARY_SECRET") };
}

#[test]
fn b10_sandboxes_are_isolated_from_each_other() {
    if !enabled() {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let d = driver();
    let mut a = d.create(&Limits::default()).unwrap();
    let mut b = d.create(&Limits::default()).unwrap();
    assert_ne!(a.uid_base(), b.uid_base());
    ok(
        &mut a,
        "echo secret > /workspace/a.txt; sleep 30 >/dev/null 2>&1 &",
    );
    assert_eq!(ok(&mut b, "ls -A /workspace | wc -l"), "0");
    assert_eq!(ok(&mut b, "pgrep -c -x sleep || true"), "0");
    assert_eq!(ok(&mut a, "ps -o comm= -p 1"), "agent");
    let procs: usize = ok(&mut a, "ps -e --no-headers | wc -l").parse().unwrap();
    assert!(procs < 10, "sandbox sees {procs} processes");
    let ids = [a.id().to_owned(), b.id().to_owned()];
    a.destroy().unwrap();
    b.destroy().unwrap();
    for id in ids {
        assert_clean(&d, &id);
    }
}

#[test]
fn b11_write_file_cannot_escape_the_writable_tree() {
    if !enabled() {
        return;
    }
    with_sandbox(Limits::default(), |sb| {
        let mut write = |path: &str| {
            sb.client().call(Request::WriteFile(WriteFileRequest {
                path: path.into(),
                content: b"x".to_vec(),
                mode: None,
            }))
        };
        assert!(matches!(
            write("notes/a.txt"),
            Ok(Response::WriteFile { .. })
        ));
        let code = |r: Result<Response, boxent_proto::ClientError>| match r {
            Err(boxent_proto::ClientError::Agent(e)) => e.code,
            other => panic!("expected an agent error, got {other:?}"),
        };
        assert_eq!(code(write("/etc/passwd")), ErrorCode::InvalidPath);
        assert_eq!(code(write("../escape")), ErrorCode::InvalidPath);
        drop(write);
        ok(sb, "ln -s /etc etclink");
        let r = sb.client().call(Request::WriteFile(WriteFileRequest {
            path: "etclink/evil".into(),
            content: b"x".to_vec(),
            mode: None,
        }));
        assert_eq!(code(r), ErrorCode::InvalidPath);
        assert_eq!(ok(sb, "stat -c '%U %a' notes/a.txt"), "sandbox 644");
    });
}

#[test]
fn sandbox_lifecycle_timing() {
    if !enabled() {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let d = driver();
    let (mut create, mut destroy) = (Vec::new(), Vec::new());
    for _ in 0..20 {
        let t = Instant::now();
        let sb = d.create(&Limits::default()).unwrap();
        create.push(t.elapsed());
        let id = sb.id().to_owned();
        let t = Instant::now();
        sb.destroy().unwrap();
        destroy.push(t.elapsed());
        assert_clean(&d, &id);
    }
    create.sort();
    destroy.sort();
    eprintln!(
        "create p50 {:?} max {:?}; destroy p50 {:?} max {:?}",
        create[10], create[19], destroy[10], destroy[19]
    );
    assert!(create[19] < Duration::from_secs(2));
}

#[test]
fn restore_swaps_the_workspace_inside_the_running_sandbox() {
    if !enabled() {
        return;
    }
    with_sandbox(Limits::default(), |sb| {
        ok(
            sb,
            "echo v1 > /workspace/f; mkdir -p /home/sandbox/.cfg; echo h1 > /home/sandbox/.cfg/x",
        );
        sb.snapshot("snap_a1").unwrap();
        ok(
            sb,
            "echo v2 > /workspace/f; rm -r /home/sandbox/.cfg; touch /workspace/new",
        );
        match sb.client().call(Request::KillAll).unwrap() {
            Response::KillAll { .. } => {}
            other => panic!("{other:?}"),
        }
        sb.restore("snap_a1").unwrap();
        assert_eq!(
            ok(sb, "cat /workspace/f /home/sandbox/.cfg/x; ls /workspace"),
            "v1\nh1\nf"
        );
        assert_eq!(ok(sb, "stat -c %U /workspace/f"), "sandbox");
        // The new mounts are writable by the user and covered by Landlock's writable roots.
        assert_eq!(
            ok(
                sb,
                "echo v3 > /workspace/f && cat /workspace/f && touch /home/sandbox/y && echo ok"
            ),
            "v3\nok"
        );
        // The snapshot itself is untouched and can be restored again.
        sb.restore("snap_a1").unwrap();
        assert_eq!(ok(sb, "cat /workspace/f"), "v1");
        assert!(sb.restore("snap_missing").is_err());
        assert!(sb.snapshot("../evil").is_err());
    });
}
