//! The crun driver (Linux only).

mod btrfs;
pub mod image;
mod sys;

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use boxent_proto::{Client, Request};

use crate::spec::{self, DriverConfig, Limits, SANDBOX_UID, SpecPaths};

/// First host UID handed out; slot n maps container 0-65535 to `UID_BASE + n * 65536`.
const UID_BASE: u32 = 1 << 20;
const UID_RANGE: u32 = 65536;
const UID_SLOTS: u32 = 4096;
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CONTROLLERS: [&str; 4] = ["cpu", "memory", "pids", "io"];

pub struct OciDriver {
    cfg: DriverConfig,
}

impl OciDriver {
    /// Checks the image exists and prepares the shared directories and parent cgroup.
    pub fn new(cfg: DriverConfig) -> Result<Self> {
        if !image::exists(&cfg.data_dir, &cfg.image) {
            bail!(
                "image '{}' not found under {}; run `boxent image build`",
                cfg.image,
                cfg.data_dir.display()
            );
        }
        if !cfg.agent_bin.is_file() {
            bail!("agent binary {} not found", cfg.agent_bin.display());
        }
        for d in ["sb", "uid-slots", "crun"] {
            fs::create_dir_all(cfg.state_dir.join(d))?;
        }
        // Traverse-only: crun opens bundle paths after joining the sandbox's user namespace, as a
        // UID that owns nothing here. It can follow known paths but not list sandboxes.
        for d in [cfg.state_dir.clone(), cfg.state_dir.join("sb")] {
            fs::set_permissions(&d, fs::Permissions::from_mode(0o711))?;
        }
        fs::set_permissions(
            cfg.state_dir.join("uid-slots"),
            fs::Permissions::from_mode(0o700),
        )?;
        fs::create_dir_all(cfg.data_dir.join("sb"))?;

        let parent = Path::new(CGROUP_ROOT).join(&cfg.cgroup_parent);
        fs::create_dir_all(&parent).context("creating the parent cgroup")?;
        for c in CONTROLLERS {
            write(&parent.join("cgroup.subtree_control"), &format!("+{c}"))
                .with_context(|| format!("enabling the {c} controller for sandboxes"))?;
        }
        Ok(Self { cfg })
    }

    pub fn config(&self) -> &DriverConfig {
        &self.cfg
    }

    /// Creates and starts a sandbox, and completes the agent handshake.
    pub fn create(&self, limits: &Limits) -> Result<Sandbox> {
        let id = format!("sb-{}", sys::random_hex()?);
        let slot = self.claim_uid_slot()?;
        let uid_base = UID_BASE + slot * UID_RANGE;
        let state = self.cfg.state_dir.join("sb").join(&id);
        // From here on, dropping `sb` undoes whatever was set up.
        let mut sb = Sandbox {
            id: id.clone(),
            uid_base,
            slot,
            client: None,
            state: state.clone(),
            storage: self.cfg.data_dir.join("sb").join(&id),
            cgroup: Path::new(CGROUP_ROOT)
                .join(&self.cfg.cgroup_parent)
                .join(&id),
            slots_dir: self.cfg.state_dir.join("uid-slots"),
            crun: self.cfg.crun.clone(),
            crun_root: self.cfg.state_dir.join("crun"),
            data_dir: self.cfg.data_dir.clone(),
            qgroup: None,
            agent_pid: 0,
            destroyed: false,
        };
        self.setup(&mut sb, limits)
            .with_context(|| format!("creating sandbox {id}"))?;
        Ok(sb)
    }

    fn setup(&self, sb: &mut Sandbox, limits: &Limits) -> Result<()> {
        let st = &sb.state;
        let (rootfs, ws, home, bundle) = (
            st.join("rootfs"),
            st.join("ws"),
            st.join("home"),
            st.join("bundle"),
        );
        for d in [&rootfs, &ws, &home, &bundle] {
            fs::create_dir_all(d)?;
        }
        fs::set_permissions(st, fs::Permissions::from_mode(0o711))?;

        let (userns, netns) = (st.join("userns"), st.join("netns"));
        let base = sb.uid_base;
        sys::create_namespace(libc::CLONE_NEWUSER, sys::Setup::None, &userns, |pid| {
            let map = format!("0 {base} {UID_RANGE}\n");
            fs::write(format!("/proc/{pid}/uid_map"), &map)?;
            fs::write(format!("/proc/{pid}/gid_map"), &map)
        })
        .context("creating the user namespace")?;
        sys::create_namespace(libc::CLONE_NEWNET, sys::Setup::LoopbackUp, &netns, |_| {
            Ok(())
        })
        .context("creating the network namespace")?;

        fs::create_dir_all(sb.storage.join("snaps"))?;
        let qgroup = btrfs::next_qgroup(&self.cfg.data_dir)?;
        btrfs::create_budget(&self.cfg.data_dir, &qgroup, limits.disk_bytes)
            .context("creating the disk budget")?;
        sb.qgroup = Some(qgroup.clone());
        let live = sb.storage.join("live");
        btrfs::create_subvolume_in(&live, &qgroup)?;
        for d in ["workspace", "home"] {
            let p = live.join(d);
            fs::create_dir(&p)?;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755))?;
            sys::chown(&p, SANDBOX_UID, SANDBOX_UID)?;
        }

        let userns_fd = File::open(&userns)?;
        let image = image::path(&self.cfg.data_dir, &self.cfg.image);
        sys::idmapped_bind(&image, &rootfs, userns_fd.as_fd(), true)
            .context("mounting the root filesystem")?;
        sys::idmapped_bind(&live.join("workspace"), &ws, userns_fd.as_fd(), false)
            .context("mounting the workspace")?;
        sys::idmapped_bind(&live.join("home"), &home, userns_fd.as_fd(), false)
            .context("mounting home")?;

        // Delegate the sandbox cgroup to its root, so the agent can create per-command children.
        fs::create_dir(&sb.cgroup).context("creating the sandbox cgroup")?;
        for f in [
            "",
            "cgroup.procs",
            "cgroup.subtree_control",
            "cgroup.threads",
        ] {
            sys::chown(&sb.cgroup.join(f), base, base)?;
        }

        let config = spec::oci_config(
            &sb.id,
            &self.cfg.cgroup_parent,
            &SpecPaths {
                rootfs: &rootfs,
                workspace: &ws,
                home: &home,
                agent_bin: &self.cfg.agent_bin,
                userns: &userns,
                netns: &netns,
            },
            limits,
        );
        fs::write(
            bundle.join("config.json"),
            serde_json::to_vec_pretty(&config)?,
        )?;

        let (ours, theirs) = UnixStream::pair()?;
        let log = File::create(st.join("agent.log"))?;
        let theirs_fd = theirs.as_raw_fd();
        let mut crun = Command::new(&self.cfg.crun);
        crun.arg("--root")
            .arg(&sb.crun_root)
            .args(["run", "--detach", "--preserve-fds", "1", "--bundle"])
            .arg(&bundle)
            .arg(&sb.id)
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        // SAFETY: dup2/fcntl only, between fork and exec.
        unsafe {
            crun.pre_exec(move || {
                if theirs_fd == 3 {
                    let flags = libc::fcntl(3, libc::F_GETFD);
                    libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                } else if libc::dup2(theirs_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let status = crun.status().context("running crun")?;
        drop(theirs);
        if !status.success() {
            bail!("crun failed with {status}: {}", tail(&st.join("agent.log")));
        }

        ours.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut client = Client::new(ours);
        let hello = client.hello().map_err(|e| {
            anyhow::anyhow!(
                "agent handshake failed: {e}; log: {}",
                tail(&st.join("agent.log"))
            )
        })?;
        if hello.pid != 1 {
            bail!("agent is PID {} inside the sandbox, expected 1", hello.pid);
        }
        if hello.landlock_abi == 0 {
            bail!("the agent reports no Landlock support");
        }
        client.get_ref().set_read_timeout(None)?;
        sb.client = Some(client);
        sb.agent_pid = sb.host_pid()?;
        Ok(())
    }

    /// Removes every sandbox left by a previous engine: crun containers, mounts, storage,
    /// cgroups and UID slots. Only safe while no engine is running (the engine lock ensures it).
    pub fn sweep_orphans(&self) -> Result<usize> {
        let mut ids: Vec<String> = Vec::new();
        let crun = |args: &[&str]| {
            Command::new(&self.cfg.crun)
                .arg("--root")
                .arg(self.cfg.state_dir.join("crun"))
                .args(args)
                .stderr(Stdio::null())
                .output()
        };
        if let Ok(out) = crun(&["list", "-q"]) {
            for id in String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
            {
                let _ = crun(&["delete", "--force", id]);
                ids.push(id.to_owned());
            }
        }
        let names = |dir: &Path| -> Vec<String> {
            fs::read_dir(dir)
                .map(|rd| {
                    rd.flatten()
                        .filter_map(|e| e.file_name().into_string().ok())
                        .filter(|n| n.starts_with("sb-"))
                        .collect()
                })
                .unwrap_or_default()
        };
        let cgroup_parent = Path::new(CGROUP_ROOT).join(&self.cfg.cgroup_parent);
        for dir in [
            self.cfg.state_dir.join("sb"),
            self.cfg.data_dir.join("sb"),
            cgroup_parent.clone(),
        ] {
            ids.extend(names(&dir));
        }
        ids.sort();
        ids.dedup();
        for id in &ids {
            let state = self.cfg.state_dir.join("sb").join(id);
            for m in ["rootfs", "ws", "home", "userns", "netns"] {
                sys::unmount(&state.join(m));
            }
            let _ = fs::remove_dir_all(&state);
            let storage = self.cfg.data_dir.join("sb").join(id);
            let _ = remove_storage(&self.cfg.data_dir, &storage, None);
            let cg = cgroup_parent.join(id);
            if cg.exists() {
                let _ = write(&cg.join("cgroup.kill"), "1");
                remove_cgroup_tree(&cg);
            }
        }
        // Every sandbox budget is ours, and no sandbox is alive: retire them all.
        for q in btrfs::level1_qgroups(&self.cfg.data_dir) {
            let _ = btrfs::retire_budget(&self.cfg.data_dir, &q);
        }
        btrfs::gc_budgets(&self.cfg.data_dir);
        if let Ok(rd) = fs::read_dir(self.cfg.state_dir.join("uid-slots")) {
            for e in rd.flatten() {
                let _ = fs::remove_file(e.path());
            }
        }
        Ok(ids.len())
    }

    fn claim_uid_slot(&self) -> Result<u32> {
        let dir = self.cfg.state_dir.join("uid-slots");
        for n in 0..UID_SLOTS {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(n.to_string()))
            {
                Ok(_) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        bail!("all {UID_SLOTS} UID ranges are in use")
    }
}

pub struct Sandbox {
    id: String,
    uid_base: u32,
    slot: u32,
    client: Option<Client<UnixStream>>,
    state: PathBuf,
    storage: PathBuf,
    cgroup: PathBuf,
    slots_dir: PathBuf,
    crun: PathBuf,
    crun_root: PathBuf,
    data_dir: PathBuf,
    /// This sandbox's level-1 qgroup (disk budget).
    qgroup: Option<String>,
    /// The agent's PID on the host, used to enter the sandbox's mount namespace.
    agent_pid: u32,
    destroyed: bool,
}

/// Snapshot ids reach the filesystem as directory names: only this shape is accepted.
fn valid_snap_id(id: &str) -> bool {
    id.len() <= 64
        && id.starts_with("snap_")
        && id[5..]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && id.len() > 5
}

impl Sandbox {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// First host UID of this sandbox's range (container UID 0).
    pub fn uid_base(&self) -> u32 {
        self.uid_base
    }

    pub fn cgroup(&self) -> &Path {
        &self.cgroup
    }

    pub fn client(&mut self) -> &mut Client<UnixStream> {
        self.client.as_mut().expect("sandbox is running")
    }

    /// Hands the agent connection to the caller (the engine's async client). The handshake has
    /// already been done. Afterwards, `destroy` stops the sandbox with crun alone.
    pub fn take_stream(&mut self) -> Option<UnixStream> {
        self.client.take().map(Client::into_inner)
    }

    /// The agent's PID as the host sees it.
    pub fn host_pid(&self) -> Result<u32> {
        let out = Command::new(&self.crun)
            .arg("--root")
            .arg(&self.crun_root)
            .args(["state", &self.id])
            .output()?;
        let v: serde_json::Value =
            serde_json::from_slice(&out.stdout).context("parsing crun state")?;
        v["pid"]
            .as_u64()
            .map(|p| p as u32)
            .context("crun state has no pid")
    }

    /// Takes a read-only snapshot of the workspace and home as one point in time: the sandbox's
    /// processes are frozen for the few milliseconds it takes, so no write is half done.
    pub fn snapshot(&self, snap_id: &str) -> Result<()> {
        if !valid_snap_id(snap_id) {
            bail!("invalid snapshot id {snap_id:?}");
        }
        let qgroup = self
            .qgroup
            .as_deref()
            .context("sandbox has no disk budget")?;
        let dst = self.storage.join("snaps").join(snap_id);
        if dst.exists() {
            bail!("snapshot {snap_id} already exists");
        }
        self.freeze(true)?;
        let result = btrfs::snapshot(&self.storage.join("live"), &dst, true, qgroup);
        self.freeze(false)?;
        result
    }

    /// Rewinds the workspace and home to a snapshot, inside the running sandbox. The caller must
    /// have killed the sandbox's user processes first: they would keep the old files open.
    ///
    /// A writable copy of the snapshot is mounted over /workspace and /home/sandbox in the
    /// sandbox's own mount namespace; the snapshot itself stays read-only, so it can be restored
    /// again later.
    pub fn restore(&mut self, snap_id: &str) -> Result<()> {
        if !valid_snap_id(snap_id) {
            bail!("invalid snapshot id {snap_id:?}");
        }
        let qgroup = self.qgroup.clone().context("sandbox has no disk budget")?;
        let snap = self.storage.join("snaps").join(snap_id);
        if !snap.is_dir() {
            bail!("snapshot {snap_id} does not exist");
        }
        let next = self.storage.join("live.next");
        if next.exists() {
            btrfs::delete_subvolume(&next)?;
        }
        btrfs::snapshot(&snap, &next, false, &qgroup)?;
        let userns = File::open(self.state.join("userns"))?;
        let mounts = [
            (
                sys::idmapped_tree(&next.join("workspace"), userns.as_fd(), false)?,
                spec::WORKSPACE,
            ),
            (
                sys::idmapped_tree(&next.join("home"), userns.as_fd(), false)?,
                spec::HOME,
            ),
        ];
        sys::inject_mounts(self.agent_pid, &mounts).context("swapping the workspace mounts")?;
        // The old live subvolume is no longer mounted in the sandbox; release the host-side
        // mounts crun bound from, then replace it.
        sys::unmount(&self.state.join("ws"));
        sys::unmount(&self.state.join("home"));
        let live = self.storage.join("live");
        btrfs::delete_subvolume(&live)?;
        fs::rename(&next, &live)?;
        Ok(())
    }

    pub fn delete_snapshot(&self, snap_id: &str) -> Result<()> {
        if !valid_snap_id(snap_id) {
            bail!("invalid snapshot id {snap_id:?}");
        }
        btrfs::delete_subvolume(&self.storage.join("snaps").join(snap_id))
    }

    fn freeze(&self, on: bool) -> Result<()> {
        write(
            &self.cgroup.join("cgroup.freeze"),
            if on { "1" } else { "0" },
        )?;
        let want = if on { "frozen 1" } else { "frozen 0" };
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let events = fs::read_to_string(self.cgroup.join("cgroup.events"))?;
            if events.lines().any(|l| l.trim() == want) {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                let _ = write(&self.cgroup.join("cgroup.freeze"), "0");
                bail!(
                    "the sandbox did not {} within 2 s",
                    if on { "freeze" } else { "thaw" }
                );
            }
            std::thread::sleep(Duration::from_micros(200));
        }
    }

    /// Stops the sandbox and removes everything it used. Also runs on drop.
    pub fn destroy(mut self) -> Result<()> {
        self.teardown()
    }

    fn teardown(&mut self) -> Result<()> {
        if self.destroyed {
            return Ok(());
        }
        self.destroyed = true;
        if let Some(mut c) = self.client.take() {
            let _ = c.get_ref().set_read_timeout(Some(Duration::from_secs(2)));
            let _ = c.call(Request::Shutdown);
        }
        let _ = Command::new(&self.crun)
            .arg("--root")
            .arg(&self.crun_root)
            .args(["delete", "--force", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        for m in ["rootfs", "ws", "home", "userns", "netns"] {
            sys::unmount(&self.state.join(m));
        }
        let mut errors = Vec::new();
        if let Err(e) = remove_storage(&self.data_dir, &self.storage, self.qgroup.as_deref()) {
            errors.push(format!("{e:#}"));
        }
        if self.cgroup.exists() {
            let _ = write(&self.cgroup.join("cgroup.kill"), "1");
            remove_cgroup_tree(&self.cgroup);
        }
        if let Err(e) = fs::remove_dir_all(&self.state) {
            errors.push(format!("removing {}: {e}", self.state.display()));
        }
        let _ = fs::remove_file(self.slots_dir.join(self.slot.to_string()));
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("cleaning up {}: {}", self.id, errors.join("; "))
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if let Err(e) = self.teardown() {
            eprintln!("{e:#}");
        }
    }
}

/// Deletes a sandbox's subvolumes (live, a half-made restore, every snapshot) and retires its
/// disk budget, which is dropped once Btrfs has cleaned the subvolumes up.
fn remove_storage(data_dir: &Path, storage: &Path, qgroup: Option<&str>) -> Result<()> {
    let mut subvolumes: Vec<PathBuf> = ["live", "live.next"]
        .iter()
        .map(|n| storage.join(n))
        .collect();
    if let Ok(rd) = fs::read_dir(storage.join("snaps")) {
        subvolumes.extend(rd.flatten().map(|e| e.path()));
    }
    let mut first_error = None;
    for sv in subvolumes.iter().filter(|p| p.exists()) {
        if let Err(e) = btrfs::delete_subvolume(sv) {
            first_error.get_or_insert(e);
        }
    }
    let _ = fs::remove_dir(storage.join("snaps"));
    let _ = fs::remove_dir(storage);
    if let Some(q) = qgroup {
        btrfs::retire_budget(data_dir, q)?;
    }
    btrfs::gc_budgets(data_dir);
    first_error.map_or(Ok(()), Err)
}

fn remove_cgroup_tree(dir: &Path) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                remove_cgroup_tree(&e.path());
            }
        }
    }
    for _ in 0..200 {
        if fs::remove_dir(dir).is_ok() || !dir.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn write(p: &Path, v: &str) -> std::io::Result<()> {
    OpenOptions::new()
        .write(true)
        .open(p)?
        .write_all(v.as_bytes())
}

fn tail(p: &Path) -> String {
    let s = fs::read_to_string(p).unwrap_or_default();
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(5)..].join(" | ")
}
