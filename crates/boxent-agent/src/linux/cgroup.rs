//! The agent's cgroup subtree.
//!
//! ```text
//! <root>/            the sandbox cgroup; its limits are set by the engine
//!   agent/           the agent itself (cgroup v2 allows processes only in leaves)
//!   exec-<n>/        one per command: OOM kills take the whole group, timeouts use cgroup.kill
//! ```
//!
//! `cgroup.kill` reaches every process in the group, including ones that called `setsid` or
//! double-forked, which a process-group kill would miss.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const CONTROLLERS: [&str; 4] = ["cpu", "memory", "pids", "io"];

pub struct Cgroups {
    root: PathBuf,
    next: AtomicU64,
    /// Exec cgroups whose main process exited while background processes kept running.
    lingering: Mutex<Vec<PathBuf>>,
}

impl Cgroups {
    /// Moves the agent into `<root>/agent` and enables controllers for the children.
    pub fn init(root: &Path) -> io::Result<Self> {
        let agent = root.join("agent");
        mkdir(&agent)?;
        write_file(&agent.join("cgroup.procs"), "0")
            .map_err(|e| annotate(e, "moving the agent into its cgroup"))?;
        let available = fs::read_to_string(root.join("cgroup.controllers")).unwrap_or_default();
        for c in CONTROLLERS {
            if available.split_whitespace().any(|a| a == c) {
                write_file(&root.join("cgroup.subtree_control"), &format!("+{c}"))
                    .map_err(|e| annotate(e, &format!("enabling the {c} controller")))?;
            }
        }
        let cgroups = Self {
            root: root.to_owned(),
            next: AtomicU64::new(1),
            lingering: Mutex::new(Vec::new()),
        };
        // Leftovers from a previous agent in the same cgroup (should not happen) are killed.
        cgroups.kill_all();
        Ok(cgroups)
    }

    /// Creates a fresh cgroup for one command.
    pub fn create_exec(&self) -> io::Result<ExecCgroup> {
        self.sweep();
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        let path = self.root.join(format!("exec-{n}"));
        fs::create_dir(&path)?;
        // Whole-group OOM kills: a command and its children live or die together.
        if path.join("memory.oom.group").exists() {
            let _ = write_file(&path.join("memory.oom.group"), "1");
        }
        let procs = OpenOptions::new()
            .write(true)
            .open(path.join("cgroup.procs"))
            .inspect_err(|_| {
                let _ = fs::remove_dir(&path);
            })?;
        Ok(ExecCgroup { path, procs })
    }

    /// Keeps a cgroup that still has processes, to remove later or kill with [`Self::kill_all`].
    pub fn linger(&self, cg: ExecCgroup) {
        let mut l = self.lingering.lock().unwrap_or_else(|e| e.into_inner());
        l.push(cg.path);
    }

    /// Removes lingering cgroups that have emptied.
    fn sweep(&self) {
        let mut l = self.lingering.lock().unwrap_or_else(|e| e.into_inner());
        l.retain(|p| populated(p) || fs::remove_dir(p).is_err());
    }

    /// Kills every command's processes, waits for the groups to empty and removes them.
    /// Returns how many processes were killed.
    pub fn kill_all(&self) -> u32 {
        let dirs: Vec<PathBuf> = fs::read_dir(&self.root)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with("exec-"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut killed = 0;
        for d in &dirs {
            killed += count_procs(d);
            let _ = write_file(&d.join("cgroup.kill"), "1");
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        for d in &dirs {
            while populated(d) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = fs::remove_dir(d);
        }
        let mut l = self.lingering.lock().unwrap_or_else(|e| e.into_inner());
        l.retain(|p| p.exists());
        killed
    }
}

pub struct ExecCgroup {
    path: PathBuf,
    /// Open handle to `cgroup.procs`; the child writes itself into it between fork and exec.
    procs: File,
}

impl ExecCgroup {
    pub fn procs_file(&self) -> &File {
        &self.procs
    }

    pub fn kill(&self) {
        let _ = write_file(&self.path.join("cgroup.kill"), "1");
    }

    pub fn oom_kills(&self) -> u64 {
        fs::read_to_string(self.path.join("memory.events"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("oom_kill "))
                    .and_then(|v| v.trim().parse().ok())
            })
            .unwrap_or(0)
    }

    pub fn populated(&self) -> bool {
        populated(&self.path)
    }

    /// Removes the cgroup if it is empty; otherwise hands it back.
    pub fn try_remove(self) -> Result<(), Self> {
        if fs::remove_dir(&self.path).is_ok() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

fn populated(dir: &Path) -> bool {
    fs::read_to_string(dir.join("cgroup.events"))
        .map(|s| s.lines().any(|l| l.trim() == "populated 1"))
        .unwrap_or(false)
}

fn count_procs(dir: &Path) -> u32 {
    fs::read_to_string(dir.join("cgroup.procs"))
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count() as u32)
        .unwrap_or(0)
}

fn mkdir(p: &Path) -> io::Result<()> {
    match fs::create_dir(p) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

fn write_file(p: &Path, v: &str) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .open(p)?
        .write_all(v.as_bytes())
}

fn annotate(e: io::Error, what: &str) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}
