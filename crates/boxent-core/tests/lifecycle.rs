//! Verification suite C (lifecycle and reaping) and the engine-level latency benchmark. Runs as
//! root inside the Lima VM (`cargo xtask vm-test`) and is skipped anywhere else.
//!
//! Every test shuts its engine down and then checks that no sandbox state is left on the host.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::{Duration, Instant};

use boxent_core::{Engine, EngineConfig, ErrorCode, ExecSpec};
use boxent_driver_oci::DriverConfig;

/// Counts live heap bytes, so the soak test can tell a leak from allocator fragmentation
/// (RSS alone cannot: musl's allocator holds on to freed pages).
struct Counting;

static LIVE_BYTES: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
        LIVE_BYTES.fetch_add(l.size() as isize, std::sync::atomic::Ordering::Relaxed);
        unsafe { std::alloc::System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
        LIVE_BYTES.fetch_sub(l.size() as isize, std::sync::atomic::Ordering::Relaxed);
        unsafe { std::alloc::System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: std::alloc::Layout, new: usize) -> *mut u8 {
        LIVE_BYTES.fetch_add(
            new as isize - l.size() as isize,
            std::sync::atomic::Ordering::Relaxed,
        );
        unsafe { std::alloc::System.realloc(p, l, new) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live_kib() -> isize {
    LIVE_BYTES.load(std::sync::atomic::Ordering::Relaxed) / 1024
}

fn enabled() -> bool {
    let on = std::env::var_os("BOXENT_VM_TESTS").is_some() && unsafe { libc::geteuid() } == 0;
    if !on {
        eprintln!("skipped: set BOXENT_VM_TESTS=1 and run as root (cargo xtask vm-test)");
    }
    on
}

fn init_logs() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(std::env::var("BOXENT_LOG").unwrap_or_else(|_| "warn".into()))
            .try_init();
    });
}

fn config() -> EngineConfig {
    let mut driver = DriverConfig::default();
    if let Ok(agent) = std::env::var("BOXENT_AGENT_BIN") {
        driver.agent_bin = agent.into();
    }
    EngineConfig {
        driver,
        ..EngineConfig::default()
    }
}

async fn start(cfg: EngineConfig) -> Engine {
    init_logs();
    Engine::start(cfg).await.expect("engine start")
}

async fn stop(e: Engine) {
    let cfg = e.config().driver.clone();
    e.shutdown().await;
    drop(e);
    assert_no_leftovers(&cfg);
}

fn assert_no_leftovers(cfg: &DriverConfig) {
    let entries = |p: &Path| -> Vec<String> {
        fs::read_dir(p)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default()
    };
    assert!(entries(&cfg.state_dir.join("sb")).is_empty(), "state left");
    assert!(entries(&cfg.data_dir.join("sb")).is_empty(), "storage left");
    assert!(
        entries(&cfg.state_dir.join("uid-slots")).is_empty(),
        "UID slots left"
    );
    let cg = Path::new("/sys/fs/cgroup").join(&cfg.cgroup_parent);
    assert!(
        !entries(&cg).iter().any(|n| n.starts_with("sb-")),
        "cgroups left"
    );
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(!mounts.contains("/run/boxent/sb/"), "mounts left");
    let out = Command::new("crun")
        .arg("--root")
        .arg(cfg.state_dir.join("crun"))
        .args(["list", "-q"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        "crun containers left"
    );
}

async fn bash(e: &Engine, id: &str, cmd: &str) -> String {
    let r = e
        .exec(
            id,
            ExecSpec::Bash(cmd.into()),
            Some(Duration::from_secs(20)),
        )
        .await
        .unwrap_or_else(|err| panic!("{cmd}: {err}"));
    assert_eq!(r.exit_code, 0, "{cmd}: {}", r.stderr);
    r.stdout.trim().to_owned()
}

async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let t = Instant::now();
    while !cond() {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn crun_pid(cfg: &DriverConfig, id: &str) -> i32 {
    let out = Command::new("crun")
        .arg("--root")
        .arg(cfg.state_dir.join("crun"))
        .args(["state", id])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    text.split("\"pid\":")
        .nth(1)
        .and_then(|s| s.trim_start().split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse().ok())
        .expect("crun state pid")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn basic_operations_and_error_codes() {
    if !enabled() {
        return;
    }
    let e = start(config()).await;
    let id = e.claim().await.unwrap();
    assert_eq!(bash(&e, &id, "echo hi; whoami").await, "hi\nsandbox");
    let py = e
        .exec(
            &id,
            ExecSpec::Python("import sys\nprint(2 + 2)\nprint('err', file=sys.stderr)".into()),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        (py.stdout.as_str(), py.stderr.as_str(), py.exit_code),
        ("4\n", "err\n", 0)
    );
    let tb = e
        .exec(&id, ExecSpec::Python("1/0".into()), None)
        .await
        .unwrap();
    assert_eq!(tb.exit_code, 1);
    assert!(
        tb.stderr.contains("ZeroDivisionError") && tb.stderr.contains("run-"),
        "{}",
        tb.stderr
    );
    assert_eq!(
        e.write_file(&id, "src/app.py", b"x = 1\n".to_vec(), None)
            .await
            .unwrap(),
        6
    );
    let r = e.read_file(&id, "src/app.py", 0, 1024).await.unwrap();
    assert_eq!(r.content, b"x = 1\n");
    let err = e
        .write_file(&id, "/etc/passwd", b"x".to_vec(), None)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidPath);
    let err = e.read_file(&id, "missing.txt", 0, 10).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
    let big = e
        .write_file(&id, "big", vec![0; 11 << 20], None)
        .await
        .unwrap_err();
    assert_eq!(big.code, ErrorCode::FileTooLarge);

    e.destroy(&id).await.unwrap();
    let err = e
        .exec(&id, ExecSpec::Bash("true".into()), None)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::SandboxReaped);
    assert!(err.message.contains("destroyed"), "{err}");
    let err = e
        .exec("sb-nope", ExecSpec::Bash("true".into()), None)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::SandboxNotFound);
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c1_timeout_kills_the_whole_tree() {
    if !enabled() {
        return;
    }
    let e = start(config()).await;
    let id = e.claim().await.unwrap();
    let t = Instant::now();
    let r = e
        .exec(
            &id,
            ExecSpec::Bash("setsid sleep 1000 & trap '' TERM; sleep 1001".into()),
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    assert!(r.timed_out && r.exit_code == 137, "{r:?}");
    assert!(
        t.elapsed() < Duration::from_secs(3),
        "took {:?}",
        t.elapsed()
    );
    assert_eq!(bash(&e, &id, "pgrep -c -x sleep || true").await, "0");
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c2_background_server_outlives_its_command() {
    if !enabled() {
        return;
    }
    let e = start(config()).await;
    let id = e.claim().await.unwrap();
    let r = e
        .exec(
            &id,
            ExecSpec::Bash("python3 -m http.server 8000 --bind 127.0.0.1 & echo started".into()),
            None,
        )
        .await
        .unwrap();
    // The server's own banner may land in the 50 ms window after the shell exits.
    assert!(r.stdout.starts_with("started\n"), "{}", r.stdout);
    assert!(r.duration_ms < 500, "took {} ms", r.duration_ms);
    let code = bash(
        &e,
        &id,
        "curl -s -o /dev/null -w '%{http_code}' --retry 20 --retry-connrefused --retry-delay 0 --retry-max-time 5 http://127.0.0.1:8000/",
    )
    .await;
    assert_eq!(code, "200");
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c3_idle_sandboxes_are_reaped_but_busy_ones_are_not() {
    if !enabled() {
        return;
    }
    let e = start(EngineConfig {
        idle_timeout: Duration::from_secs(2),
        reap_interval: Duration::from_millis(200),
        ..config()
    })
    .await;
    let idle = e.claim().await.unwrap();
    let busy = e.claim().await.unwrap();
    bash(&e, &idle, "true").await;
    // A command running longer than the idle timeout keeps its sandbox alive.
    assert_eq!(bash(&e, &busy, "sleep 3; echo done").await, "done");
    let err = e
        .exec(&idle, ExecSpec::Bash("true".into()), None)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::SandboxReaped);
    assert!(err.message.contains("idle"), "{err}");
    assert_eq!(bash(&e, &busy, "echo still-here").await, "still-here");
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c4_ttl_reaps_even_during_a_command() {
    if !enabled() {
        return;
    }
    let e = start(EngineConfig {
        ttl: Duration::from_secs(2),
        reap_interval: Duration::from_millis(200),
        ..config()
    })
    .await;
    let id = e.claim().await.unwrap();
    let t = Instant::now();
    let err = e
        .exec(
            &id,
            ExecSpec::Bash("sleep 30".into()),
            Some(Duration::from_secs(60)),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::SandboxReaped, "{err}");
    assert!(err.message.contains("ttl"), "{err}");
    assert!(
        t.elapsed() < Duration::from_secs(4),
        "took {:?}",
        t.elapsed()
    );
    stop(e).await;
}

/// Helper for c5: run in a child process, killed with SIGKILL by the test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_helper() {
    if std::env::var_os("BOXENT_CRASH_HELPER").is_none() || !enabled() {
        return;
    }
    let e = start(EngineConfig {
        pool_size: 2,
        ..config()
    })
    .await;
    for _ in 0..3 {
        let id = e.claim().await.unwrap();
        bash(
            &e,
            &id,
            "sleep 1000 >/dev/null 2>&1 & echo x > /workspace/f",
        )
        .await;
    }
    wait_for("warm pool", || e.stats().warm == 2).await;
    println!("READY");
    tokio::time::sleep(Duration::from_secs(600)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c5_restart_after_sigkill_reaps_everything() {
    if !enabled() {
        return;
    }
    let cfg = config();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_helper", "--nocapture", "--test-threads=1"])
        .env("BOXENT_CRASH_HELPER", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    assert!(
        lines.any(|l| l.is_ok_and(|l| l.contains("READY"))),
        "helper never got ready"
    );
    // SAFETY: signalling our own child.
    unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
    child.wait().unwrap();

    let left = fs::read_dir(cfg.driver.state_dir.join("sb"))
        .unwrap()
        .count();
    assert_eq!(
        left, 5,
        "expected 3 active + 2 warm sandboxes left by the killed engine"
    );
    let e = start(cfg).await;
    let host_sleeps = Command::new("pgrep")
        .args(["-f", "sleep 1000"])
        .output()
        .unwrap();
    assert!(
        host_sleeps.stdout.is_empty(),
        "sandbox processes survived the restart"
    );
    let id = e.claim().await.unwrap();
    assert_eq!(bash(&e, &id, "ls -A /workspace | wc -l").await, "0");
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_one_engine_at_a_time() {
    if !enabled() {
        return;
    }
    let e = start(config()).await;
    let err = Engine::start(config())
        .await
        .err()
        .expect("second engine must fail");
    assert!(err.message.contains("another Boxent engine"), "{err}");
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_refills_and_claims_come_from_it() {
    if !enabled() {
        return;
    }
    let e = start(EngineConfig {
        pool_size: 4,
        ..config()
    })
    .await;
    wait_for("4 warm sandboxes", || e.stats().warm == 4).await;
    let mut ids = Vec::new();
    for _ in 0..4 {
        ids.push(e.claim().await.unwrap());
    }
    assert_eq!(e.stats().claims_warm, 4);
    assert_eq!(e.stats().claims_cold, 0);
    wait_for("the pool to refill", || e.stats().warm == 4).await;
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claims_wait_then_fail_when_the_engine_is_full() {
    if !enabled() {
        return;
    }
    let e = start(EngineConfig {
        pool_size: 1,
        max_sandboxes: 3,
        claim_timeout: Duration::from_millis(300),
        ..config()
    })
    .await;
    let a = e.claim().await.unwrap();
    e.claim().await.unwrap();
    e.claim().await.unwrap();
    let t = Instant::now();
    let err = e.claim().await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PoolExhausted);
    assert!(t.elapsed() >= Duration::from_millis(300));
    e.destroy(&a).await.unwrap();
    e.claim().await.expect("a slot freed up");
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dead_warm_sandboxes_are_never_handed_out() {
    if !enabled() {
        return;
    }
    let cfg = EngineConfig {
        pool_size: 2,
        reap_interval: Duration::from_secs(60), // the claim path must catch it, not the reaper
        ..config()
    };
    let driver = cfg.driver.clone();
    let e = start(cfg).await;
    wait_for("2 warm sandboxes", || e.stats().warm == 2).await;
    let out = Command::new("crun")
        .arg("--root")
        .arg(driver.state_dir.join("crun"))
        .args(["list", "-q"])
        .output()
        .unwrap();
    for id in String::from_utf8_lossy(&out.stdout).lines() {
        // SAFETY: killing a sandbox agent we own.
        unsafe { libc::kill(crun_pid(&driver, id.trim()), libc::SIGKILL) };
    }
    let id = e.claim().await.unwrap();
    assert_eq!(bash(&e, &id, "echo healthy").await, "healthy");
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hung_agent_is_detected_by_the_engine_deadline() {
    if !enabled() {
        return;
    }
    let cfg = config();
    let driver = cfg.driver.clone();
    let e = start(cfg).await;
    let id = e.claim().await.unwrap();
    // SAFETY: freezing a sandbox agent we own.
    unsafe { libc::kill(crun_pid(&driver, &id), libc::SIGSTOP) };
    let t = Instant::now();
    let err = e
        .exec(
            &id,
            ExecSpec::Bash("echo hi".into()),
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::AgentFailed, "{err}");
    let took = t.elapsed();
    assert!(
        took >= Duration::from_secs(3) && took < Duration::from_secs(5),
        "took {took:?}"
    );
    assert_eq!(
        e.exec(&id, ExecSpec::Bash("true".into()), None)
            .await
            .unwrap_err()
            .code,
        ErrorCode::SandboxReaped
    );
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_commands_in_one_sandbox() {
    if !enabled() {
        return;
    }
    let e = start(config()).await;
    let id = e.claim().await.unwrap();
    let t = Instant::now();
    let runs: Vec<_> = (0..8)
        .map(|i| {
            let (e, id) = (e.clone(), id.clone());
            tokio::spawn(async move {
                e.exec(&id, ExecSpec::Bash(format!("sleep 0.3; echo {i}")), None)
                    .await
                    .unwrap()
                    .stdout
            })
        })
        .collect();
    let mut outs: Vec<u32> = Vec::new();
    for r in runs {
        outs.push(r.await.unwrap().trim().parse().unwrap());
    }
    outs.sort_unstable();
    assert_eq!(outs, (0..8).collect::<Vec<_>>());
    assert!(
        t.elapsed() < Duration::from_millis(1500),
        "took {:?}",
        t.elapsed()
    );
    stop(e).await;
}

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn latency_claim_plus_echo() {
    if !enabled() {
        return;
    }
    let e = start(EngineConfig {
        pool_size: 4,
        ..config()
    })
    .await;
    wait_for("warm pool", || e.stats().warm == 4).await;
    let mut samples = Vec::new();
    for _ in 0..300 {
        let t = Instant::now();
        let id = e.claim().await.unwrap();
        let r = e
            .exec(&id, ExecSpec::Bash("echo ok".into()), None)
            .await
            .unwrap();
        samples.push(t.elapsed());
        assert_eq!(r.stdout, "ok\n");
        e.destroy(&id).await.unwrap();
    }
    samples.sort();
    let stats = e.stats();
    eprintln!(
        "claim + echo over 300 fresh sandboxes: p50 {:?}, p95 {:?}, p99 {:?}, max {:?} ({} warm claims, {} cold)",
        percentile(&samples, 50),
        percentile(&samples, 95),
        percentile(&samples, 99),
        samples[samples.len() - 1],
        stats.claims_warm,
        stats.claims_cold
    );
    assert!(
        percentile(&samples, 99) < Duration::from_millis(50),
        "p99 {:?}",
        percentile(&samples, 99)
    );
    // Commands in an already-claimed sandbox.
    let id = e.claim().await.unwrap();
    let mut warm = Vec::new();
    for _ in 0..300 {
        let t = Instant::now();
        e.exec(&id, ExecSpec::Bash("echo ok".into()), None)
            .await
            .unwrap();
        warm.push(t.elapsed());
    }
    warm.sort();
    eprintln!(
        "echo in an active sandbox: p50 {:?}, p99 {:?}",
        percentile(&warm, 50),
        percentile(&warm, 99)
    );
    assert!(percentile(&warm, 99) < Duration::from_millis(50));
    stop(e).await;
}

fn self_fds() -> usize {
    fs::read_dir("/proc/self/fd").unwrap().count()
}

fn self_rss_kib() -> u64 {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c7_soak_1000_cycles_without_leaks() {
    if !enabled() {
        return;
    }
    let e = start(EngineConfig {
        pool_size: 4,
        ..config()
    })
    .await;
    let cycle = |e: Engine| async move {
        let id = e.claim().await.unwrap();
        e.write_file(&id, "f.txt", b"data".to_vec(), None)
            .await
            .unwrap();
        let r = e
            .exec(&id, ExecSpec::Bash("cat f.txt".into()), None)
            .await
            .unwrap();
        assert_eq!(r.stdout, "data");
        e.destroy(&id).await.unwrap();
    };
    // Warm-up: allocator arenas, Tokio worker caches and the reaped-id memory settle first.
    for _ in 0..300 {
        cycle(e.clone()).await;
    }
    let (fds, rss, live) = (self_fds(), self_rss_kib(), live_kib());
    let t = Instant::now();
    let mut trace = Vec::new();
    for i in 1..=1000 {
        cycle(e.clone()).await;
        if i % 200 == 0 {
            trace.push(live_kib());
        }
    }
    let (fds2, rss2, live2) = (self_fds(), self_rss_kib(), live_kib());
    eprintln!(
        "soak: 1000 cycles in {:?}; fds {fds} -> {fds2}; live heap {live} KiB, then every 200 cycles {trace:?} KiB; RSS {rss} -> {rss2} KiB",
        t.elapsed()
    );
    assert!(fds2 <= fds + 8, "fd leak: {fds} -> {fds2}");
    // The engine remembers the last 4096 reaped ids by design (~200 bytes each), so allow for
    // that plus 10% of the starting heap.
    let allowance = live / 10 + 1000 * 200 / 1024;
    assert!(
        live2 <= live + allowance,
        "live heap grew from {live} to {live2} KiB over 1000 cycles"
    );
    stop(e).await;
}
