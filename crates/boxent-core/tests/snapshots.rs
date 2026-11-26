//! Verification suite D: snapshot -> mutate -> restore correctness, at the engine level. Runs as
//! root inside the Lima VM (`cargo xtask vm-test`) and is skipped anywhere else. The
//! model-based test (D7) runs from the Mac through MCP, in `tests/e2e`.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use boxent_core::{Engine, EngineConfig, ErrorCode, ExecSpec};
use boxent_driver_oci::{DriverConfig, Limits};

fn enabled() -> bool {
    let on = std::env::var_os("BOXENT_VM_TESTS").is_some() && unsafe { libc::geteuid() } == 0;
    if !on {
        eprintln!("skipped: set BOXENT_VM_TESTS=1 and run as root (cargo xtask vm-test)");
    }
    on
}

fn config() -> EngineConfig {
    let mut driver = DriverConfig::default();
    if let Ok(agent) = std::env::var("BOXENT_AGENT_BIN") {
        driver.agent_bin = agent.into();
    }
    EngineConfig {
        driver,
        pool_size: 1,
        ..EngineConfig::default()
    }
}

async fn start(cfg: EngineConfig) -> Engine {
    Engine::start(cfg).await.expect("engine start")
}

/// Shuts the engine down and checks that no sandbox storage, subvolume or budget is left.
async fn stop(e: Engine) {
    let cfg = e.config().driver.clone();
    e.shutdown().await;
    drop(e);
    let sb = cfg.data_dir.join("sb");
    assert_eq!(
        fs::read_dir(&sb).map(|d| d.count()).unwrap_or(0),
        0,
        "sandbox storage left"
    );
    let list = Command::new("btrfs")
        .args(["subvolume", "list", "-o"])
        .arg(&cfg.data_dir)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&list.stdout);
    assert!(
        !text.lines().any(|l| l.contains("sb/sb-")),
        "subvolumes left:\n{text}"
    );
    assert_budgets_retired(&cfg.data_dir);
}

fn assert_budgets_retired(data_dir: &Path) {
    let out = Command::new("btrfs")
        .args(["qgroup", "show", "--raw"])
        .arg(data_dir)
        .output()
        .unwrap();
    let retired = fs::read_to_string(data_dir.join(".retired-qgroups")).unwrap_or_default();
    for q in String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next())
    {
        if q.starts_with("1/") {
            assert!(
                retired.lines().any(|r| r.trim() == q),
                "budget {q} is neither live nor retired"
            );
        }
    }
}

async fn sh(e: &Engine, id: &str, cmd: &str) -> String {
    let r = e
        .exec(
            id,
            ExecSpec::Bash(cmd.into()),
            Some(Duration::from_secs(120)),
        )
        .await
        .unwrap_or_else(|err| panic!("{cmd}: {err}"));
    assert_eq!(r.exit_code, 0, "{cmd}: {}", r.stderr);
    r.stdout
}

/// Everything that makes two trees equal: path, type, mode, owner, size, mtime, link target,
/// and the content hash of every file.
const TREE: &str = "cd / && find workspace home/sandbox -printf '%p %y %m %U %G %s %T@ %l\\n' | LC_ALL=C sort \
    && find workspace home/sandbox -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum";

async fn tree(e: &Engine, id: &str) -> String {
    sh(e, id, TREE).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d1_d2_restore_is_an_exact_rewind_and_repeatable() {
    if !enabled() {
        return;
    }
    let e = start(config()).await;
    let id = e.claim().await.unwrap();
    sh(&e, &id, "mkdir -p src/deep/er docs && echo 'fn main() {}' > src/main.rs && echo deep > src/deep/er/x \
        && printf 'hidden\\n' > .env && ln -s src/main.rs link && chmod 750 src && install -m 755 /dev/null run.sh \
        && head -c 20M /dev/urandom > blob.bin && echo 'alias ll=ls' > ~/.bashrc && mkdir ~/.cache && touch ~/.cache/c").await;
    let before = tree(&e, &id).await;
    let snap = e.snapshot(&id, Some("baseline".into())).await.unwrap();

    sh(&e, &id, "echo changed >> src/main.rs; rm -r src/deep docs; echo new > new.txt; chmod 600 .env; \
        ln -sf /etc/hostname link; head -c 100M /dev/urandom > big.bin; rm ~/.bashrc; echo x > ~/.cache/c").await;
    assert_ne!(tree(&e, &id).await, before);

    e.restore(&id, &snap.snap_id).await.unwrap();
    assert_eq!(
        tree(&e, &id).await,
        before,
        "restore did not reproduce the snapshot exactly"
    );

    // Restoring the same snapshot again works, after more changes.
    sh(&e, &id, "rm -rf ./* ./.env; echo again > again.txt").await;
    e.restore(&id, &snap.snap_id).await.unwrap();
    assert_eq!(tree(&e, &id).await, before);
    // The restored tree is writable by the sandbox user (Landlock and ID mapping still apply).
    assert_eq!(
        sh(
            &e,
            &id,
            "echo w > src/w && stat -c %U src/w && touch ~/h && echo ok"
        )
        .await,
        "sandbox\nok\n"
    );
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d3_snapshot_chains_restore_in_any_order() {
    if !enabled() {
        return;
    }
    let e = start(config()).await;
    let id = e.claim().await.unwrap();
    sh(&e, &id, "echo A > state").await;
    let a = tree(&e, &id).await;
    let s1 = e.snapshot(&id, None).await.unwrap().snap_id;
    sh(&e, &id, "echo B > state; touch b").await;
    let b = tree(&e, &id).await;
    let s2 = e.snapshot(&id, None).await.unwrap().snap_id;
    sh(&e, &id, "echo C > state; rm b").await;
    for (snap, want) in [(&s1, &a), (&s2, &b), (&s1, &a), (&s2, &b)] {
        e.restore(&id, snap).await.unwrap();
        assert_eq!(&tree(&e, &id).await, want);
    }
    let listed: Vec<String> = e
        .list_snapshots(&id)
        .unwrap()
        .into_iter()
        .map(|s| s.snap_id)
        .collect();
    assert_eq!(listed, [s1, s2]);
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d4_restore_kills_background_writers_and_clears_tmp() {
    if !enabled() {
        return;
    }
    let e = start(config()).await;
    let id = e.claim().await.unwrap();
    let snap = e.snapshot(&id, None).await.unwrap().snap_id;
    sh(&e, &id, "echo junk > /tmp/t; (while :; do echo x >> /workspace/log; sleep 0.01; done) >/dev/null 2>&1 &").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let killed = e.restore(&id, &snap).await.unwrap();
    assert!(killed >= 1, "no process was killed");
    assert_eq!(
        sh(&e, &id, "find /workspace /tmp -mindepth 1 | wc -l")
            .await
            .trim(),
        "0"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        sh(
            &e,
            &id,
            "ls -A /workspace | wc -l; pgrep -c -f 'echo [x]' || true"
        )
        .await,
        "0\n0\n"
    );
    stop(e).await;
}

const WRITER: &str = r#"
import os, time
fd = os.open('/workspace/rec', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
i = 0
while True:
    h = i.to_bytes(8, 'big')
    os.write(fd, h + bytes([i % 251]) * (65536 - 16) + h)   # one write per 64 KiB record
    i += 1
    time.sleep(0.001)
"#;

const CHECKER: &str = r#"
d = open('/workspace/rec', 'rb').read()
assert len(d) % 65536 == 0, f'torn record: size {len(d)}'
for i in range(len(d) // 65536):
    r = d[i * 65536:(i + 1) * 65536]
    h = i.to_bytes(8, 'big')
    assert r[:8] == h and r[-8:] == h and r[8:-8] == bytes([i % 251]) * (65536 - 16), f'bad record {i}'
print(len(d) // 65536)
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d5_snapshots_of_a_busy_writer_hold_only_whole_records() {
    if !enabled() {
        return;
    }
    let e = start(config()).await;
    let id = e.claim().await.unwrap();
    e.write_file(&id, "/tmp/writer.py", WRITER.as_bytes().to_vec(), None)
        .await
        .unwrap();
    sh(&e, &id, "python3 /tmp/writer.py >/dev/null 2>&1 &").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut snaps = Vec::new();
    for _ in 0..20 {
        snaps.push(e.snapshot(&id, None).await.unwrap().snap_id);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let mut counts = Vec::new();
    for s in &snaps {
        e.restore(&id, s).await.unwrap();
        let r = e
            .exec(&id, ExecSpec::Python(CHECKER.into()), None)
            .await
            .unwrap();
        assert_eq!(r.exit_code, 0, "snapshot {s}: {}", r.stderr);
        counts.push(r.stdout.trim().parse::<u64>().unwrap());
    }
    eprintln!("records per snapshot: {counts:?}");
    assert!(
        counts.windows(2).all(|w| w[0] <= w[1]),
        "snapshots out of order: {counts:?}"
    );
    assert!(
        counts.last().unwrap() > counts.first().unwrap(),
        "the writer never advanced"
    );
    stop(e).await;
}

fn p95(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() * 95 / 100]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d6_snapshot_time_does_not_grow_with_workspace_size() {
    if !enabled() {
        return;
    }
    let e = start(config()).await;
    let id = e.claim().await.unwrap();
    let measure = |e: Engine, id: String| async move {
        let mut times = Vec::new();
        for _ in 0..20 {
            let t = Instant::now();
            let s = e.snapshot(&id, None).await.unwrap();
            times.push(t.elapsed());
            e.delete_snapshot(&id, &s.snap_id).await.unwrap();
        }
        p95(times)
    };
    sh(&e, &id, "for i in $(seq 10); do echo $i > f$i; done").await;
    let small = measure(e.clone(), id.clone()).await;
    sh(
        &e,
        &id,
        "mkdir many && cd many && seq 10000 | xargs touch && cd .. && head -c 1G /dev/zero > big",
    )
    .await;
    // Data not yet written back is flushed by the first snapshot that follows (Btrfs must put it
    // on disk to share it), so that cost depends on how much was just written, not on the size of
    // the workspace. Measure it separately, then the steady state.
    let t = Instant::now();
    let first = e.snapshot(&id, None).await.unwrap();
    let flush = t.elapsed();
    e.delete_snapshot(&id, &first.snap_id).await.unwrap();
    let large = measure(e.clone(), id.clone()).await;
    eprintln!(
        "snapshot p95: 10 files {small:?}; 10,010 files + 1 GiB {large:?}; first snapshot right after writing 1 GiB (flushes it) {flush:?}"
    );
    assert!(small < Duration::from_millis(50) && large < Duration::from_millis(50));
    let restore_t = {
        let s = e.snapshot(&id, None).await.unwrap().snap_id;
        let t = Instant::now();
        e.restore(&id, &s).await.unwrap();
        t.elapsed()
    };
    eprintln!("restore of 10,010 files + 1 GiB: {restore_t:?}");
    assert!(restore_t < Duration::from_millis(500));
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d8_snapshots_cannot_pin_more_than_the_disk_budget() {
    if !enabled() {
        return;
    }
    let mut cfg = config();
    cfg.limits = Limits {
        disk_bytes: 256 << 20,
        ..Limits::default()
    };
    let e = start(cfg).await;
    let id = e.claim().await.unwrap();
    let mut failed_at = None;
    for i in 1..=6 {
        let r = e
            .exec(
                &id,
                ExecSpec::Bash("dd if=/dev/urandom of=big bs=1M count=100 status=none".into()),
                None,
            )
            .await
            .unwrap();
        if r.exit_code != 0 {
            assert!(r.stderr.contains("Disk quota exceeded"), "{}", r.stderr);
            failed_at = Some(i);
            break;
        }
        e.snapshot(&id, None).await.unwrap();
        sh(&e, &id, "rm big").await;
    }
    let failed_at = failed_at.expect("the budget was never enforced");
    eprintln!("write {failed_at} of 100 MB hit the 256 MB budget");
    assert!(failed_at <= 3);
    let err = e
        .write_file(&id, "more.bin", vec![1; 4 << 20], None)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::QuotaExceeded, "{err}");
    stop(e).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d9_snapshots_are_per_sandbox_limited_and_cleaned_up() {
    if !enabled() {
        return;
    }
    let mut cfg = config();
    cfg.max_snapshots = 3;
    let e = start(cfg).await;
    let a = e.claim().await.unwrap();
    let b = e.claim().await.unwrap();
    let mut snaps = Vec::new();
    for _ in 0..3 {
        snaps.push(e.snapshot(&a, None).await.unwrap().snap_id);
    }
    assert_eq!(
        e.snapshot(&a, None).await.unwrap_err().code,
        ErrorCode::SnapshotLimit
    );
    e.delete_snapshot(&a, &snaps[0]).await.unwrap();
    e.snapshot(&a, None).await.unwrap();
    // Another sandbox cannot use these snapshot ids.
    assert_eq!(
        e.restore(&b, &snaps[1]).await.unwrap_err().code,
        ErrorCode::SnapshotNotFound
    );
    assert_eq!(
        e.restore(&a, &snaps[0]).await.unwrap_err().code,
        ErrorCode::SnapshotNotFound
    );
    assert_eq!(
        e.restore(&a, "../../etc").await.unwrap_err().code,
        ErrorCode::SnapshotNotFound
    );
    // A snapshot taken while a command runs does not disturb it (the freeze only pauses it).
    let (e2, a2) = (e.clone(), a.clone());
    let running = tokio::spawn(async move {
        e2.exec(&a2, ExecSpec::Bash("sleep 1; echo done".into()), None)
            .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    e.delete_snapshot(&a, &snaps[1]).await.unwrap();
    e.snapshot(&a, None).await.unwrap();
    assert_eq!(running.await.unwrap().unwrap().stdout, "done\n");
    // Destroying the sandbox removes its live subvolume, every snapshot and its budget.
    let storage = e.config().driver.data_dir.join("sb").join(&a);
    assert!(storage.join("snaps").read_dir().unwrap().count() == 3);
    e.destroy(&a).await.unwrap();
    assert!(!storage.exists());
    stop(e).await;
}
