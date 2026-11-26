//! The engine (Linux only).

mod agent;

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use boxent_driver_oci::{DriverConfig, Limits, OciDriver, Sandbox};
use boxent_egress::{Profile, ProxyHandle, ProxyOptions};
use boxent_proto::{
    Caps, ExecRequest, MAX_FILE, ReadFileRequest, ReadFileResult, Request, Response,
    WriteFileRequest,
};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use crate::{EngineError, ErrorCode, ReapReason};
use agent::{AgentConn, CallError};

/// Extra time the engine waits beyond a command's own timeout before declaring the agent dead.
const AGENT_GRACE: Duration = Duration::from_secs(2);
/// Deadline for requests that do no user work (ping, file operations).
const CONTROL_DEADLINE: Duration = Duration::from_secs(30);
const PING_DEADLINE: Duration = Duration::from_secs(1);
/// How many reaped sandbox ids are remembered, to answer "reaped" rather than "not found".
const REAPED_MEMORY: usize = 4096;
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The profile used when none is named. Unless the operator redefines it, it allows nothing.
pub const DEFAULT_PROFILE: &str = "default";
const PROXY_URL: &str = "http://127.0.0.1:3128";

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub driver: DriverConfig,
    pub limits: Limits,
    /// Warm sandboxes kept ready.
    pub pool_size: usize,
    /// Upper bound on warm + active + starting sandboxes.
    pub max_sandboxes: usize,
    /// Hard lifetime of a claimed sandbox, counted from the claim.
    pub ttl: Duration,
    /// A claimed sandbox with no call in flight for this long is reaped.
    pub idle_timeout: Duration,
    /// Warm sandboxes older than this are replaced.
    pub warm_max_age: Duration,
    pub reap_interval: Duration,
    /// How long a claim waits for a free slot when the engine is at `max_sandboxes`.
    pub claim_timeout: Duration,
    pub default_timeout: Duration,
    pub max_timeout: Duration,
    pub caps: Caps,
    /// Snapshots one sandbox may hold at a time.
    pub max_snapshots: usize,
    /// Egress profiles agents may choose from. A `default` profile denying everything is added
    /// at start if the operator did not define one.
    pub profiles: Vec<Profile>,
    pub proxy: ProxyOptions,
    /// Sandboxes created in parallel by the refill task.
    pub create_parallelism: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            driver: DriverConfig::default(),
            limits: Limits::default(),
            pool_size: 4,
            max_sandboxes: 32,
            ttl: Duration::from_secs(30 * 60),
            idle_timeout: Duration::from_secs(5 * 60),
            warm_max_age: Duration::from_secs(60 * 60),
            reap_interval: Duration::from_secs(1),
            claim_timeout: Duration::from_secs(5),
            default_timeout: Duration::from_secs(30),
            max_timeout: Duration::from_secs(600),
            caps: Caps::default(),
            max_snapshots: 32,
            profiles: Vec::new(),
            proxy: ProxyOptions::default(),
            create_parallelism: 2,
        }
    }
}

/// What to run.
#[derive(Debug, Clone)]
pub enum ExecSpec {
    /// A fresh `bash -c` in /workspace; shell state does not carry over between calls.
    Bash(String),
    /// Python source, written to a temp file and run with `python3 -u`.
    Python(String),
}

/// Result of a command, ready for the MCP layer.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub sandbox_id: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub oom_killed: bool,
    pub duration_ms: u64,
    pub stdout_truncated: bool,
    pub stdout_total_bytes: u64,
    pub stderr_truncated: bool,
    pub stderr_total_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub snap_id: String,
    pub label: Option<String>,
    pub created_at: std::time::SystemTime,
}

#[derive(Debug, Clone)]
pub struct SandboxInfo {
    pub id: String,
    /// The egress profile the sandbox was claimed with.
    pub profile: Profile,
    pub age: Duration,
    pub expires_in: Duration,
    pub idle_for: Duration,
    pub calls_in_flight: usize,
}

#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    pub warm: usize,
    pub active: usize,
    pub provisioning: usize,
    pub created: u64,
    pub claims_warm: u64,
    pub claims_cold: u64,
    pub reaped: u64,
    pub create_failures: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Warm,
    Cold,
}

struct Warm {
    sb: Sandbox,
    conn: AgentConn,
    /// The sandbox's egress proxy; denies everything until the sandbox is claimed.
    proxy: ProxyHandle,
    born: Instant,
}

struct Active {
    id: String,
    conn: AgentConn,
    proxy: ProxyHandle,
    sb: Arc<Mutex<Option<Sandbox>>>,
    /// Serialises snapshot, restore and snapshot deletion for this sandbox.
    ops: tokio::sync::Mutex<()>,
    snapshots: Mutex<Vec<SnapshotInfo>>,
    claimed: Instant,
    expires: Instant,
    last_used: Mutex<Instant>,
    inflight: AtomicUsize,
    seq: AtomicU64,
}

#[derive(Default)]
struct Reaped {
    order: VecDeque<String>,
    reasons: HashMap<String, ReapReason>,
}

impl Reaped {
    fn insert(&mut self, id: String, reason: ReapReason) {
        if self.order.len() >= REAPED_MEMORY
            && let Some(old) = self.order.pop_front()
        {
            self.reasons.remove(&old);
        }
        self.order.push_back(id.clone());
        self.reasons.insert(id, reason);
    }
}

#[derive(Default)]
struct State {
    warm: VecDeque<Warm>,
    active: HashMap<String, Arc<Active>>,
    provisioning: usize,
    /// Taken from the pool by a claim that is still checking its health.
    claiming: usize,
    /// Out of service but not yet destroyed; still counted against `max_sandboxes`.
    tearing_down: usize,
    reaped: Reaped,
    stopped: bool,
    stats: PoolStats,
    consecutive_failures: u32,
    last_failure: Option<Instant>,
}

impl State {
    fn total(&self) -> usize {
        self.warm.len() + self.active.len() + self.provisioning + self.claiming + self.tearing_down
    }
}

struct Inner {
    cfg: EngineConfig,
    driver: OciDriver,
    state: Mutex<State>,
    refill: Arc<Notify>,
    _lock: File,
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The sandbox engine. Cheap to clone; all clones share one pool.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

impl Engine {
    /// Takes the engine lock, reaps whatever a previous engine left behind, and starts the
    /// refill and reaper tasks. Must be called inside a Tokio runtime.
    pub async fn start(mut cfg: EngineConfig) -> Result<Self, EngineError> {
        for p in &cfg.profiles {
            p.validate()
                .map_err(|e| EngineError::new(ErrorCode::InvalidArgument, e))?;
        }
        let mut names: Vec<&str> = cfg.profiles.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        if names.windows(2).any(|w| w[0] == w[1]) {
            return Err(EngineError::new(
                ErrorCode::InvalidArgument,
                "duplicate profile names",
            ));
        }
        if !cfg.profiles.iter().any(|p| p.name == DEFAULT_PROFILE) {
            cfg.profiles.insert(0, Profile::deny_all(DEFAULT_PROFILE));
        }
        let driver_cfg = cfg.driver.clone();
        let (lock, driver, swept) = tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&driver_cfg.state_dir).map_err(EngineError::internal)?;
            let lock = take_lock(&driver_cfg)?;
            let driver =
                OciDriver::new(driver_cfg).map_err(|e| EngineError::internal(format!("{e:#}")))?;
            let swept = driver
                .sweep_orphans()
                .map_err(|e| EngineError::internal(format!("{e:#}")))?;
            Ok::<_, EngineError>((lock, driver, swept))
        })
        .await
        .map_err(EngineError::internal)??;
        tracing::info!(
            event = "engine_started",
            orphans_reaped = swept,
            pool_size = cfg.pool_size,
            max_sandboxes = cfg.max_sandboxes
        );
        let inner = Arc::new(Inner {
            cfg,
            driver,
            state: Mutex::new(State::default()),
            refill: Arc::new(Notify::new()),
            _lock: lock,
        });
        tokio::spawn(refill_loop(Arc::downgrade(&inner)));
        tokio::spawn(reaper_loop(Arc::downgrade(&inner)));
        Ok(Self { inner })
    }

    pub fn config(&self) -> &EngineConfig {
        &self.inner.cfg
    }

    /// Claims a sandbox: a warm one if available, otherwise a new one. Waits up to
    /// `claim_timeout` when the engine is at `max_sandboxes`.
    pub async fn claim(&self) -> Result<String, EngineError> {
        self.claim_with(DEFAULT_PROFILE).await
    }

    /// The operator-defined egress profiles, by name.
    pub fn profiles(&self) -> &[Profile] {
        &self.inner.cfg.profiles
    }

    /// Claims a sandbox whose egress follows the named profile.
    pub async fn claim_with(&self, profile: &str) -> Result<String, EngineError> {
        let profile = self
            .inner
            .cfg
            .profiles
            .iter()
            .find(|p| p.name == profile)
            .cloned()
            .ok_or_else(|| {
                let names: Vec<&str> = self
                    .inner
                    .cfg
                    .profiles
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect();
                EngineError::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "unknown profile '{profile}' (available: {})",
                        names.join(", ")
                    ),
                )
            })?;
        let start = Instant::now();
        let deadline = start + self.inner.cfg.claim_timeout;
        loop {
            let taken = {
                let mut st = self.inner.state();
                if st.stopped {
                    return Err(EngineError::new(
                        ErrorCode::Internal,
                        "engine is shutting down",
                    ));
                }
                let w = st.warm.pop_front();
                if w.is_some() {
                    st.claiming += 1;
                }
                w
            };
            self.inner.refill.notify_one();
            if let Some(w) = taken {
                match w.conn.call(Request::Ping, PING_DEADLINE).await {
                    Ok(Response::Pong) => {
                        return Ok(self.activate(w, start, Source::Warm, profile));
                    }
                    _ => {
                        tracing::warn!(event = "warm_sandbox_unhealthy", sandbox_id = %w.sb.id());
                        {
                            let mut st = self.inner.state();
                            st.claiming -= 1;
                            st.tearing_down += 1;
                        }
                        retire(&self.inner, w).await;
                        continue;
                    }
                }
            }
            let reserved = {
                let mut st = self.inner.state();
                let ok = st.total() < self.inner.cfg.max_sandboxes;
                if ok {
                    st.provisioning += 1;
                }
                ok
            };
            if reserved {
                let created = create_one(&self.inner).await;
                let stopped = self.inner.state().stopped;
                return match created {
                    Ok(w) if stopped => {
                        {
                            let mut st = self.inner.state();
                            st.provisioning -= 1;
                            st.tearing_down += 1;
                        }
                        retire(&self.inner, w).await;
                        Err(EngineError::new(
                            ErrorCode::Internal,
                            "engine is shutting down",
                        ))
                    }
                    Ok(w) => Ok(self.activate(w, start, Source::Cold, profile)),
                    Err(e) => {
                        let mut st = self.inner.state();
                        st.provisioning -= 1;
                        st.stats.create_failures += 1;
                        Err(e)
                    }
                };
            }
            if Instant::now() >= deadline {
                return Err(EngineError::new(
                    ErrorCode::PoolExhausted,
                    format!(
                        "all {} sandbox slots are in use; destroy a sandbox or try again",
                        self.inner.cfg.max_sandboxes
                    ),
                ));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Moves a sandbox into the active set. The counter it was held under (claiming or
    /// provisioning) is released in the same critical section, so the total never dips.
    fn activate(&self, w: Warm, start: Instant, from: Source, profile: Profile) -> String {
        let cold = from == Source::Cold;
        let now = Instant::now();
        let id = w.sb.id().to_owned();
        let profile_name = profile.name.clone();
        w.proxy.set_profile(profile);
        let active = Arc::new(Active {
            id: id.clone(),
            conn: w.conn,
            proxy: w.proxy,
            sb: Arc::new(Mutex::new(Some(w.sb))),
            ops: tokio::sync::Mutex::new(()),
            snapshots: Mutex::new(Vec::new()),
            claimed: now,
            expires: now + self.inner.cfg.ttl,
            last_used: Mutex::new(now),
            inflight: AtomicUsize::new(0),
            seq: AtomicU64::new(1),
        });
        let mut st = self.inner.state();
        match from {
            Source::Warm => st.claiming -= 1,
            Source::Cold => st.provisioning -= 1,
        }
        st.active.insert(id.clone(), active);
        if cold {
            st.stats.claims_cold += 1;
        } else {
            st.stats.claims_warm += 1;
        }
        tracing::info!(
            event = "sandbox_claimed",
            sandbox_id = %id,
            profile = %profile_name,
            acquire_ms = start.elapsed().as_secs_f64() * 1000.0,
            cold,
            pool_depth = st.warm.len()
        );
        id
    }

    fn lookup(&self, id: &str) -> Result<Arc<Active>, EngineError> {
        let st = self.inner.state();
        if let Some(a) = st.active.get(id) {
            return Ok(Arc::clone(a));
        }
        Err(reaped_or_missing(&st, id))
    }

    pub async fn exec(
        &self,
        id: &str,
        spec: ExecSpec,
        timeout: Option<Duration>,
    ) -> Result<ExecOutcome, EngineError> {
        let a = self.lookup(id)?;
        let _busy = Busy::new(&a);
        let cfg = &self.inner.cfg;
        let timeout = timeout.unwrap_or(cfg.default_timeout).min(cfg.max_timeout);
        if timeout.is_zero() {
            return Err(EngineError::new(
                ErrorCode::InvalidArgument,
                "timeout must be at least 1 second",
            ));
        }
        let (argv, source) = match &spec {
            ExecSpec::Bash(cmd) => (
                vec![
                    "/bin/bash".into(),
                    "--noprofile".into(),
                    "--norc".into(),
                    "-c".into(),
                    cmd.clone(),
                ],
                cmd.as_bytes(),
            ),
            ExecSpec::Python(code) => {
                let path = format!(
                    "/tmp/.boxent/run-{}.py",
                    a.seq.fetch_add(1, Ordering::Relaxed)
                );
                self.agent_call(
                    &a,
                    Request::WriteFile(WriteFileRequest {
                        path: path.clone(),
                        content: code.as_bytes().to_vec(),
                        mode: Some(0o644),
                    }),
                    CONTROL_DEADLINE,
                )
                .await?;
                (
                    vec!["/usr/bin/python3".into(), "-u".into(), path],
                    code.as_bytes(),
                )
            }
        };
        let req = ExecRequest {
            argv,
            env: default_env(),
            cwd: "/workspace".into(),
            timeout_ms: timeout.as_millis() as u64,
            head_cap: cfg.caps.head,
            tail_cap: cfg.caps.tail,
        };
        let started = Instant::now();
        let r = match self
            .agent_call(&a, Request::Exec(req), timeout + AGENT_GRACE)
            .await?
        {
            Response::Exec(r) => r,
            other => {
                return Err(self
                    .agent_violation(&a, format!("unexpected reply {other:?}"))
                    .await);
            }
        };
        if let Err(e) = r.check(cfg.caps) {
            return Err(self.agent_violation(&a, e).await);
        }
        let digest = Sha256::digest(source);
        tracing::info!(
            event = "exec_finished",
            sandbox_id = %a.id,
            kind = match spec { ExecSpec::Bash(_) => "bash", ExecSpec::Python(_) => "python" },
            exec_ms = started.elapsed().as_secs_f64() * 1000.0,
            agent_ms = r.duration_ms,
            exit_code = r.exit_code,
            timed_out = r.timed_out,
            oom_killed = r.oom_killed,
            cmd_sha256 = %hex(&digest[..8]),
            cmd_len = source.len()
        );
        Ok(ExecOutcome {
            sandbox_id: a.id.clone(),
            stdout: r.stdout.render(),
            stderr: r.stderr.render(),
            exit_code: r.exit_code,
            signal: r.signal,
            timed_out: r.timed_out,
            oom_killed: r.oom_killed,
            duration_ms: r.duration_ms,
            stdout_truncated: r.stdout.truncated,
            stdout_total_bytes: r.stdout.total,
            stderr_truncated: r.stderr.truncated,
            stderr_total_bytes: r.stderr.total,
        })
    }

    pub async fn write_file(
        &self,
        id: &str,
        path: &str,
        content: Vec<u8>,
        mode: Option<u32>,
    ) -> Result<u64, EngineError> {
        if content.len() > MAX_FILE as usize {
            return Err(EngineError::new(
                ErrorCode::FileTooLarge,
                format!(
                    "content is {} bytes; the limit is {MAX_FILE}",
                    content.len()
                ),
            ));
        }
        let a = self.lookup(id)?;
        let _busy = Busy::new(&a);
        let req = Request::WriteFile(WriteFileRequest {
            path: path.into(),
            content,
            mode,
        });
        match self.agent_call(&a, req, CONTROL_DEADLINE).await? {
            Response::WriteFile { bytes_written } => Ok(bytes_written),
            other => Err(self
                .agent_violation(&a, format!("unexpected reply {other:?}"))
                .await),
        }
    }

    pub async fn read_file(
        &self,
        id: &str,
        path: &str,
        offset: u64,
        max_bytes: u32,
    ) -> Result<ReadFileResult, EngineError> {
        let a = self.lookup(id)?;
        let _busy = Busy::new(&a);
        let req = Request::ReadFile(ReadFileRequest {
            path: path.into(),
            offset,
            max_bytes: max_bytes.min(MAX_FILE),
        });
        match self.agent_call(&a, req, CONTROL_DEADLINE).await? {
            Response::ReadFile(r) if r.content.len() <= max_bytes as usize => Ok(r),
            other => Err(self
                .agent_violation(&a, format!("unexpected reply {other:?}"))
                .await),
        }
    }

    /// Takes a point-in-time snapshot of the sandbox's workspace and home.
    pub async fn snapshot(
        &self,
        id: &str,
        label: Option<String>,
    ) -> Result<SnapshotInfo, EngineError> {
        let a = self.lookup(id)?;
        let _busy = Busy::new(&a);
        let _op = a.ops.lock().await;
        let max = self.inner.cfg.max_snapshots;
        if lock(&a.snapshots).len() >= max {
            return Err(EngineError::new(
                ErrorCode::SnapshotLimit,
                format!("sandbox {id} already has {max} snapshots; delete one first"),
            ));
        }
        let snap_id = new_snap_id()?;
        let started = Instant::now();
        let sb = Arc::clone(&a.sb);
        let sid = snap_id.clone();
        tokio::task::spawn_blocking(move || match lock(&sb).as_ref() {
            Some(s) => s.snapshot(&sid).map_err(|e| format!("{e:#}")),
            None => Err("the sandbox was reaped".into()),
        })
        .await
        .map_err(EngineError::internal)?
        .map_err(|e| EngineError::internal(format!("snapshot failed: {e}")))?;
        let info = SnapshotInfo {
            snap_id,
            label,
            created_at: std::time::SystemTime::now(),
        };
        lock(&a.snapshots).push(info.clone());
        tracing::info!(
            event = "snapshot_created",
            sandbox_id = %a.id,
            snap_id = %info.snap_id,
            op_ms = started.elapsed().as_secs_f64() * 1000.0
        );
        Ok(info)
    }

    /// Rewinds the workspace and home to a snapshot. Every process in the sandbox is killed
    /// first, and /tmp and /dev/shm are emptied. Returns how many processes were killed.
    pub async fn restore(&self, id: &str, snap_id: &str) -> Result<u32, EngineError> {
        let a = self.lookup(id)?;
        let _busy = Busy::new(&a);
        let _op = a.ops.lock().await;
        if !lock(&a.snapshots).iter().any(|s| s.snap_id == snap_id) {
            return Err(snapshot_not_found(id, snap_id));
        }
        let started = Instant::now();
        let killed = match self
            .agent_call(&a, Request::KillAll, CONTROL_DEADLINE)
            .await?
        {
            Response::KillAll { processes_killed } => processes_killed,
            other => {
                return Err(self
                    .agent_violation(&a, format!("unexpected reply {other:?}"))
                    .await);
            }
        };
        let sb = Arc::clone(&a.sb);
        let sid = snap_id.to_owned();
        let swapped = tokio::task::spawn_blocking(move || match lock(&sb).as_mut() {
            Some(s) => s.restore(&sid).map_err(|e| format!("{e:#}")),
            None => Err("the sandbox was reaped".into()),
        })
        .await
        .map_err(EngineError::internal)?;
        if let Err(e) = swapped {
            tracing::error!(event = "restore_failed", sandbox_id = %a.id, snap_id, error = %e);
            self.reap(&a.id, ReapReason::RestoreFailed).await;
            return Err(EngineError::internal(format!(
                "restore failed ({e}); sandbox {id} was destroyed because its files may be half restored"
            )));
        }
        let wipe = ExecRequest {
            argv: vec![
                "/usr/bin/find".into(),
                "/tmp".into(),
                "/dev/shm".into(),
                "-mindepth".into(),
                "1".into(),
                "-delete".into(),
            ],
            env: default_env(),
            cwd: "/".into(),
            timeout_ms: 10_000,
            head_cap: 1024,
            tail_cap: 1024,
        };
        self.agent_call(&a, Request::Exec(wipe), Duration::from_secs(12))
            .await?;
        tracing::info!(
            event = "snapshot_restored",
            sandbox_id = %a.id,
            snap_id,
            processes_killed = killed,
            op_ms = started.elapsed().as_secs_f64() * 1000.0
        );
        Ok(killed)
    }

    pub fn list_snapshots(&self, id: &str) -> Result<Vec<SnapshotInfo>, EngineError> {
        let a = self.lookup(id)?;
        Ok(lock(&a.snapshots).clone())
    }

    pub async fn delete_snapshot(&self, id: &str, snap_id: &str) -> Result<(), EngineError> {
        let a = self.lookup(id)?;
        let _busy = Busy::new(&a);
        let _op = a.ops.lock().await;
        let pos = lock(&a.snapshots)
            .iter()
            .position(|s| s.snap_id == snap_id)
            .ok_or_else(|| snapshot_not_found(id, snap_id))?;
        let sb = Arc::clone(&a.sb);
        let sid = snap_id.to_owned();
        tokio::task::spawn_blocking(move || match lock(&sb).as_ref() {
            Some(s) => s.delete_snapshot(&sid).map_err(|e| format!("{e:#}")),
            None => Err("the sandbox was reaped".into()),
        })
        .await
        .map_err(EngineError::internal)?
        .map_err(|e| EngineError::internal(format!("deleting the snapshot failed: {e}")))?;
        lock(&a.snapshots).remove(pos);
        Ok(())
    }

    /// Destroys a claimed sandbox and everything it holds.
    pub async fn destroy(&self, id: &str) -> Result<(), EngineError> {
        if self.reap(id, ReapReason::Destroyed).await {
            Ok(())
        } else {
            Err(reaped_or_missing(&self.inner.state(), id))
        }
    }

    pub fn info(&self, id: &str) -> Result<SandboxInfo, EngineError> {
        let a = self.lookup(id)?;
        let now = Instant::now();
        let last = *a.last_used.lock().unwrap_or_else(|e| e.into_inner());
        Ok(SandboxInfo {
            id: a.id.clone(),
            profile: (*a.proxy.profile()).clone(),
            age: now - a.claimed,
            expires_in: a.expires.saturating_duration_since(now),
            idle_for: now - last,
            calls_in_flight: a.inflight.load(Ordering::Relaxed),
        })
    }

    pub fn stats(&self) -> PoolStats {
        let st = self.inner.state();
        PoolStats {
            warm: st.warm.len(),
            active: st.active.len(),
            provisioning: st.provisioning,
            ..st.stats.clone()
        }
    }

    /// Stops refilling and destroys every sandbox.
    pub async fn shutdown(&self) {
        let (warm, active) = {
            let mut st = self.inner.state();
            st.stopped = true;
            let warm: Vec<Warm> = st.warm.drain(..).collect();
            st.tearing_down += warm.len();
            let active: Vec<String> = st.active.keys().cloned().collect();
            (warm, active)
        };
        for w in warm {
            retire(&self.inner, w).await;
        }
        for id in active {
            self.reap(&id, ReapReason::Shutdown).await;
        }
        // Wait for sandboxes still being created; the refill task destroys them on arrival.
        for _ in 0..400 {
            if self.inner.state().provisioning == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let late: Vec<Warm> = {
            let mut st = self.inner.state();
            let late: Vec<Warm> = st.warm.drain(..).collect();
            st.tearing_down += late.len();
            late
        };
        for w in late {
            retire(&self.inner, w).await;
        }
        tracing::info!(event = "engine_stopped");
    }

    /// Removes a claimed sandbox from service and destroys it. False if it was not active.
    async fn reap(&self, id: &str, reason: ReapReason) -> bool {
        reap(&self.inner, id, reason).await
    }

    async fn agent_call(
        &self,
        a: &Arc<Active>,
        req: Request,
        deadline: Duration,
    ) -> Result<Response, EngineError> {
        match a.conn.call(req, deadline).await {
            Ok(Response::Error(e)) => Err(e.into()),
            Ok(resp) => Ok(resp),
            Err(e) => {
                // A sandbox reaped while the call was running (TTL, destroy) reports why.
                if !self.inner.state().active.contains_key(&a.id) {
                    return Err(reaped_or_missing(&self.inner.state(), &a.id));
                }
                let what = match e {
                    CallError::Timeout => "did not answer within the deadline",
                    CallError::Disconnected => "connection was lost",
                };
                self.reap(&a.id, ReapReason::AgentFailed).await;
                Err(EngineError::new(
                    ErrorCode::AgentFailed,
                    format!("the sandbox agent {what}; sandbox {} was reaped", a.id),
                ))
            }
        }
    }

    async fn agent_violation(&self, a: &Arc<Active>, detail: String) -> EngineError {
        tracing::warn!(event = "agent_protocol_violation", sandbox_id = %a.id, detail = %detail);
        self.reap(&a.id, ReapReason::AgentFailed).await;
        EngineError::new(
            ErrorCode::AgentFailed,
            format!(
                "the sandbox agent broke the protocol; sandbox {} was reaped",
                a.id
            ),
        )
    }
}

/// Marks a sandbox busy for the duration of a call, then records the time of last use.
struct Busy<'a>(&'a Active);

impl<'a> Busy<'a> {
    fn new(a: &'a Active) -> Self {
        a.inflight.fetch_add(1, Ordering::AcqRel);
        Self(a)
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        *self.0.last_used.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        self.0.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn snapshot_not_found(id: &str, snap_id: &str) -> EngineError {
    EngineError::new(
        ErrorCode::SnapshotNotFound,
        format!("sandbox {id} has no snapshot {snap_id}"),
    )
}

/// `snap_` followed by 128 random bits in lowercase base32 (26 characters).
fn new_snap_id() -> Result<String, EngineError> {
    let mut b = [0u8; 16];
    // SAFETY: fills the buffer with random bytes.
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    if n != b.len() as isize {
        return Err(EngineError::internal(std::io::Error::last_os_error()));
    }
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bits: u128 = u128::from_be_bytes(b);
    let mut out = String::from("snap_");
    for _ in 0..26 {
        out.push(ALPHABET[(bits & 31) as usize] as char);
        bits >>= 5;
    }
    Ok(out)
}

fn reaped_or_missing(st: &State, id: &str) -> EngineError {
    match st.reaped.reasons.get(id) {
        Some(r) => EngineError::new(
            ErrorCode::SandboxReaped,
            format!("sandbox {id} was reaped ({}); claim a new one", r.as_str()),
        ),
        None => EngineError::new(
            ErrorCode::SandboxNotFound,
            format!("no sandbox with id {id}"),
        ),
    }
}

async fn create_one(inner: &Arc<Inner>) -> Result<Warm, EngineError> {
    let i = Arc::clone(inner);
    let (sb, stream) = tokio::task::spawn_blocking(move || {
        let mut sb = i.driver.create(&i.cfg.limits)?;
        let stream = sb.take_stream().expect("a new sandbox has a connection");
        Ok::<_, anyhow_free::Error>((sb, stream))
    })
    .await
    .map_err(EngineError::internal)?
    .map_err(|e| EngineError::internal(format!("creating a sandbox: {e}")))?;
    let mut sb = sb;
    let listener = sb
        .take_proxy_listener()
        .ok_or_else(|| EngineError::internal("the sandbox has no egress listener"))?;
    let proxy = boxent_egress::serve(
        listener,
        sb.id().to_owned(),
        Profile::deny_all("unclaimed"),
        inner.cfg.proxy.clone(),
    )
    .map_err(EngineError::internal)?;
    let conn = AgentConn::new(stream).map_err(EngineError::internal)?;
    Ok(Warm {
        sb,
        conn,
        proxy,
        born: Instant::now(),
    })
}

/// Avoids a direct anyhow dependency: the driver's errors are only ever formatted.
mod anyhow_free {
    pub struct Error(String);
    impl<E: std::fmt::Debug + std::fmt::Display> From<E> for Error {
        fn from(e: E) -> Self {
            Self(format!("{e:#}"))
        }
    }
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
}

async fn destroy_blocking(sb: Sandbox) {
    let id = sb.id().to_owned();
    match tokio::task::spawn_blocking(move || sb.destroy()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::error!(event = "sandbox_cleanup_failed", sandbox_id = %id, error = %format!("{e:#}"))
        }
        Err(e) => tracing::error!(event = "sandbox_cleanup_failed", sandbox_id = %id, error = %e),
    }
}

async fn reap(inner: &Arc<Inner>, id: &str, reason: ReapReason) -> bool {
    let a = {
        let mut st = inner.state();
        let Some(a) = st.active.remove(id) else {
            return false;
        };
        st.reaped.insert(id.to_owned(), reason);
        st.stats.reaped += 1;
        st.tearing_down += 1;
        a
    };
    let sb = a.sb.lock().unwrap_or_else(|e| e.into_inner()).take();
    tracing::info!(
        event = "sandbox_reaped",
        sandbox_id = %id,
        reason = reason.as_str(),
        lifetime_ms = a.claimed.elapsed().as_millis() as u64,
        calls_in_flight = a.inflight.load(Ordering::Relaxed)
    );
    if let Some(sb) = sb {
        destroy_blocking(sb).await;
    }
    inner.state().tearing_down -= 1;
    inner.refill.notify_one();
    true
}

/// Destroys a sandbox that was never claimed. The caller has already counted it in
/// `tearing_down`; this releases that count once it is gone.
async fn retire(inner: &Arc<Inner>, w: Warm) {
    tracing::info!(event = "sandbox_retired", sandbox_id = %w.sb.id(), age_ms = w.born.elapsed().as_millis() as u64);
    inner.state().stats.reaped += 1;
    destroy_blocking(w.sb).await;
    inner.state().tearing_down -= 1;
    inner.refill.notify_one();
}

async fn refill_loop(weak: Weak<Inner>) {
    loop {
        let Some(inner) = weak.upgrade() else { return };
        let n = {
            let mut st = inner.state();
            if st.stopped {
                return;
            }
            let backoff = Duration::from_secs(u64::from(st.consecutive_failures.min(30)));
            let cooling = st.last_failure.is_some_and(|t| t.elapsed() < backoff);
            let want = inner
                .cfg
                .pool_size
                .saturating_sub(st.warm.len() + st.provisioning);
            let room = inner.cfg.max_sandboxes.saturating_sub(st.total());
            let par = inner.cfg.create_parallelism.saturating_sub(st.provisioning);
            let n = if cooling { 0 } else { want.min(room).min(par) };
            st.provisioning += n;
            n
        };
        for _ in 0..n {
            let i = Arc::clone(&inner);
            tokio::spawn(async move {
                let created = create_one(&i).await;
                let leftover = {
                    let mut st = i.state();
                    match created {
                        // Shutting down: destroy it before releasing the provisioning count, so
                        // shutdown() does not return while it still exists.
                        Ok(w) if st.stopped => Some(w),
                        Ok(w) => {
                            st.provisioning -= 1;
                            st.stats.created += 1;
                            st.consecutive_failures = 0;
                            st.warm.push_back(w);
                            None
                        }
                        Err(e) => {
                            st.provisioning -= 1;
                            st.stats.create_failures += 1;
                            st.consecutive_failures += 1;
                            st.last_failure = Some(Instant::now());
                            tracing::error!(event = "sandbox_create_failed", error = %e);
                            None
                        }
                    }
                };
                if let Some(w) = leftover {
                    destroy_blocking(w.sb).await;
                    i.state().provisioning -= 1;
                }
                i.refill.notify_one();
            });
        }
        // Wait on the Notify alone, so a dropped engine is not kept alive by this task.
        let wake = Arc::clone(&inner.refill);
        drop(inner);
        tokio::select! {
            _ = wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn reaper_loop(weak: Weak<Inner>) {
    loop {
        let Some(inner) = weak.upgrade() else { return };
        let interval = inner.cfg.reap_interval;
        let now = Instant::now();
        let (expired, stale) = {
            let mut st = inner.state();
            if st.stopped {
                return;
            }
            let idle = inner.cfg.idle_timeout;
            let expired: Vec<(String, ReapReason)> = st
                .active
                .values()
                .filter_map(|a| {
                    let last = *a.last_used.lock().unwrap_or_else(|e| e.into_inner());
                    if now >= a.expires {
                        Some((a.id.clone(), ReapReason::Ttl))
                    } else if !a.conn.is_alive() {
                        Some((a.id.clone(), ReapReason::AgentFailed))
                    } else if a.inflight.load(Ordering::Acquire) == 0 && now - last >= idle {
                        Some((a.id.clone(), ReapReason::Idle))
                    } else {
                        None
                    }
                })
                .collect();
            let max_age = inner.cfg.warm_max_age;
            let (keep, stale): (Vec<Warm>, Vec<Warm>) = st
                .warm
                .drain(..)
                .partition(|w| w.conn.is_alive() && w.born.elapsed() < max_age);
            st.warm = keep.into();
            st.tearing_down += stale.len();
            (expired, stale)
        };
        for (id, reason) in expired {
            reap(&inner, &id, reason).await;
        }
        for w in stale {
            retire(&inner, w).await;
        }
        drop(inner);
        tokio::time::sleep(interval).await;
    }
}

fn take_lock(cfg: &DriverConfig) -> Result<File, EngineError> {
    let path = cfg.state_dir.join("engine.lock");
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(EngineError::internal)?;
    // SAFETY: flock on a descriptor we own; released when the file is closed or we die.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(EngineError::internal(format!(
            "another Boxent engine holds {}",
            path.display()
        )));
    }
    Ok(f)
}

fn default_env() -> Vec<(String, String)> {
    [
        ("PATH", PATH),
        ("HOME", "/home/sandbox"),
        ("USER", "sandbox"),
        ("LOGNAME", "sandbox"),
        ("SHELL", "/bin/bash"),
        ("LANG", "C.UTF-8"),
        ("TERM", "dumb"),
        ("PYTHONUNBUFFERED", "1"),
        // The only way out of a sandbox: the egress proxy on its loopback. With the default
        // profile it refuses every destination, with a message that says so.
        ("HTTP_PROXY", PROXY_URL),
        ("HTTPS_PROXY", PROXY_URL),
        ("http_proxy", PROXY_URL),
        ("https_proxy", PROXY_URL),
        ("NO_PROXY", "localhost,127.0.0.1,::1"),
        ("no_proxy", "localhost,127.0.0.1,::1"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
