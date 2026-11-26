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

        fs::create_dir_all(&sb.storage)?;
        let live = sb.storage.join("live");
        btrfs::create_subvolume(&live)?;
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
            if let Ok(rd) = fs::read_dir(&storage) {
                for e in rd.flatten() {
                    let _ = btrfs::delete_subvolume(&e.path());
                }
            }
            let _ = fs::remove_dir_all(&storage);
            let cg = cgroup_parent.join(id);
            if cg.exists() {
                let _ = write(&cg.join("cgroup.kill"), "1");
                remove_cgroup_tree(&cg);
            }
        }
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
    destroyed: bool,
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
        let live = self.storage.join("live");
        if live.exists()
            && let Err(e) = btrfs::delete_subvolume(&live)
        {
            errors.push(format!("{e:#}"));
        }
        let _ = fs::remove_dir(&self.storage);
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
