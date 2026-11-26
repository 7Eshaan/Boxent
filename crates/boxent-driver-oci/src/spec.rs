//! Driver configuration, per-sandbox limits, and the OCI runtime config generated from them.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::seccomp;

/// Where the driver keeps things and which binaries it uses.
#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// Runtime state: bundles, namespace handles, mount points, crun state. Wiped on reboot.
    pub state_dir: PathBuf,
    /// The Btrfs pool: images and sandbox storage.
    pub data_dir: PathBuf,
    /// Image to use as the root filesystem, under `<data_dir>/images/`.
    pub image: String,
    pub agent_bin: PathBuf,
    pub crun: PathBuf,
    /// Parent cgroup for all sandboxes, relative to `/sys/fs/cgroup`.
    pub cgroup_parent: String,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            state_dir: "/run/boxent".into(),
            data_dir: "/var/lib/boxent".into(),
            image: "base".into(),
            agent_bin: "/usr/local/lib/boxent/boxent-agent".into(),
            crun: "crun".into(),
            cgroup_parent: "boxent".into(),
        }
    }
}

/// Resource limits for one sandbox.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    /// CPU time per wall-clock second, in CPUs (1.0 = one full core).
    pub cpus: f64,
    pub memory_bytes: u64,
    /// Processes and threads, all counted together.
    pub pids: u32,
    pub tmp_bytes: u64,
    pub shm_bytes: u64,
    /// Open files per command.
    pub nofile: u32,
    /// Disk budget for the workspace, home and every snapshot together.
    pub disk_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            cpus: 1.0,
            memory_bytes: 512 << 20,
            pids: 256,
            tmp_bytes: 64 << 20,
            shm_bytes: 64 << 20,
            nofile: 1024,
            disk_bytes: 2 << 30,
        }
    }
}

pub const SANDBOX_UID: u32 = 1000;
/// Port of the egress proxy listener on the sandbox's loopback.
pub const PROXY_PORT: u16 = 3128;
pub const WORKSPACE: &str = "/workspace";
pub const HOME: &str = "/home/sandbox";
/// Where the agent binary is mounted inside the sandbox (a mount point baked into the image).
pub const AGENT_PATH: &str = "/.boxent/agent";
const CPU_PERIOD_US: u64 = 100_000;

/// Host paths the OCI config refers to.
pub struct SpecPaths<'a> {
    pub rootfs: &'a Path,
    pub workspace: &'a Path,
    pub home: &'a Path,
    pub agent_bin: &'a Path,
    pub userns: &'a Path,
    pub netns: &'a Path,
}

/// Builds the OCI `config.json` for a sandbox.
pub fn oci_config(id: &str, cgroup_parent: &str, paths: &SpecPaths<'_>, limits: &Limits) -> Value {
    let p = |path: &Path| path.display().to_string();
    let caps = ["CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"];
    let quota = (limits.cpus * CPU_PERIOD_US as f64).round() as u64;
    json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": [
                AGENT_PATH,
                "--control-fd", "3",
                "--cgroup-root", "/sys/fs/cgroup",
                "--uid", SANDBOX_UID.to_string(),
                "--gid", SANDBOX_UID.to_string(),
                "--workdir", WORKSPACE,
                "--nofile", limits.nofile.to_string(),
                "--require-landlock"
            ],
            // The agent's own environment; commands get the one the engine sends per call.
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "cwd": "/",
            "noNewPrivileges": true,
            // Only what the agent needs to switch to the sandbox user and drop the bounding set.
            "capabilities": {
                "bounding": caps, "effective": caps, "permitted": caps,
                "inheritable": [], "ambient": []
            },
            "rlimits": [
                { "type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096 },
                { "type": "RLIMIT_CORE", "hard": 0, "soft": 0 }
            ]
        },
        "root": { "path": p(paths.rootfs), "readonly": true },
        "hostname": "sandbox",
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"] },
            { "destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=64k"] },
            { "destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"] },
            { "destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid", "noexec", "nodev", "mode=1777", format!("size={}", limits.shm_bytes)] },
            { "destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue", "options": ["nosuid", "noexec", "nodev"] },
            // No host sysfs: an empty tmpfs that only carries the sandbox's own cgroup tree.
            { "destination": "/sys", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "noexec", "nodev", "mode=755", "size=64k"] },
            { "destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup", "options": ["nosuid", "noexec", "nodev", "relatime", "rw"] },
            { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777", format!("size={}", limits.tmp_bytes)] },
            { "destination": WORKSPACE, "type": "bind", "source": p(paths.workspace), "options": ["rbind", "nosuid", "nodev"] },
            { "destination": HOME, "type": "bind", "source": p(paths.home), "options": ["rbind", "nosuid", "nodev"] },
            { "destination": AGENT_PATH, "type": "bind", "source": p(paths.agent_bin), "options": ["bind", "ro", "nosuid", "nodev"] }
        ],
        "linux": {
            "namespaces": [
                { "type": "user", "path": p(paths.userns) },
                { "type": "network", "path": p(paths.netns) },
                { "type": "pid" }, { "type": "mount" }, { "type": "ipc" }, { "type": "uts" }, { "type": "cgroup" }
            ],
            "cgroupsPath": format!("/{cgroup_parent}/{id}"),
            "resources": {
                "memory": { "limit": limits.memory_bytes, "swap": limits.memory_bytes },
                "cpu": { "quota": quota, "period": CPU_PERIOD_US },
                "pids": { "limit": limits.pids }
            },
            "seccomp": seccomp::profile(),
            "maskedPaths": [
                "/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore", "/proc/keys",
                "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi", "/proc/timer_list",
                "/proc/timer_stats"
            ],
            "readonlyPaths": [
                "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"
            ]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Value {
        let paths = SpecPaths {
            rootfs: Path::new("/r"),
            workspace: Path::new("/w"),
            home: Path::new("/h"),
            agent_bin: Path::new("/a"),
            userns: Path::new("/u"),
            netns: Path::new("/n"),
        };
        oci_config("sb-1", "boxent", &paths, &Limits::default())
    }

    #[test]
    fn hardening_invariants() {
        let c = config();
        assert_eq!(c["root"]["readonly"], true);
        assert_eq!(c["process"]["noNewPrivileges"], true);
        assert_eq!(
            c["process"]["capabilities"]["bounding"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            c["process"]["capabilities"]["ambient"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(c["linux"]["cgroupsPath"], "/boxent/sb-1");
        let ns: Vec<&str> = c["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["type"].as_str().unwrap())
            .collect();
        for want in ["user", "network", "pid", "mount", "ipc", "uts", "cgroup"] {
            assert!(ns.contains(&want), "missing {want} namespace");
        }
        // Swap equal to memory means no swap at all.
        let mem = &c["linux"]["resources"]["memory"];
        assert_eq!(mem["limit"], mem["swap"]);
        assert_eq!(c["linux"]["resources"]["cpu"]["quota"], 100_000);
    }

    #[test]
    fn only_sandbox_storage_and_the_agent_come_from_the_host() {
        let c = config();
        let binds: Vec<&str> = c["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["type"] == "bind")
            .map(|m| m["source"].as_str().unwrap())
            .collect();
        assert_eq!(binds, ["/w", "/h", "/a"]);
    }
}
