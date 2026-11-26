//! Checks for a Linux host (or the Lima VM): kernel version, cgroups v2, namespaces, seccomp,
//! Landlock, the Btrfs pool and its quota mode, and the external tools the engine calls.

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;

use super::{Check, format_uuid, missing_controllers, parse_kernel_release};

const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683e;
/// `_IOR(0x94, 31, struct btrfs_ioctl_fs_info_args)`; the struct is 1024 bytes.
const BTRFS_IOC_FS_INFO: u64 = 0x8400_941f;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const REQUIRED_CONTROLLERS: [&str; 4] = ["cpu", "memory", "pids", "io"];
const MIN_FREE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

pub fn checks(data_dir: &Path) -> Vec<Check> {
    vec![
        kernel(),
        root(),
        cgroup2(),
        controllers(),
        cgroup_kill(),
        user_namespaces(),
        seccomp(),
        landlock(),
        btrfs_pool(data_dir),
        btrfs_quota(data_dir),
        free_space(data_dir),
        base_image(data_dir),
        tool("crun", "crun", "apt-get install crun"),
        tool("btrfs-progs", "btrfs", "apt-get install btrfs-progs"),
        tool("mmdebstrap", "mmdebstrap", "apt-get install mmdebstrap"),
        kvm(),
    ]
}

fn kernel() -> Check {
    const NAME: &str = "kernel";
    // SAFETY: uname fills a caller-provided, zero-initialised struct.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return Check::fail(NAME, "uname failed", "run on a Linux kernel 6.8 or newer");
    }
    // c_char is u8 on arm64 and i8 on x86_64, so the cast is needed on one of them.
    #[allow(clippy::unnecessary_cast)]
    let release: String = uts
        .release
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8 as char)
        .collect();
    match parse_kernel_release(&release) {
        Some(v) if v >= (6, 8) => Check::pass(NAME, release),
        Some(v) if v >= (6, 7) => Check::warn(
            NAME,
            format!("{release}: works, but 6.8 or newer is recommended"),
            "upgrade the kernel",
        ),
        _ => Check::fail(
            NAME,
            format!(
                "{release}: Btrfs simple quotas and Landlock networking need 6.7, Boxent tests on 6.8+"
            ),
            "use a distribution kernel 6.8 or newer (Ubuntu 24.04 LTS or later)",
        ),
    }
}

fn root() -> Check {
    const NAME: &str = "privileges";
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        Check::pass(NAME, "running as root")
    } else {
        Check::warn(
            NAME,
            "not root: the daemon needs root, and some checks below may be incomplete",
            "run with sudo",
        )
    }
}

fn fs_magic(path: &Path) -> Option<i64> {
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statfs writes into a zero-initialised struct; the path is NUL-terminated.
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut buf) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)]
    Some(buf.f_type as i64)
}

fn cgroup2() -> Check {
    const NAME: &str = "cgroup v2";
    match fs_magic(Path::new("/sys/fs/cgroup")) {
        Some(CGROUP2_SUPER_MAGIC) => Check::pass(NAME, "unified hierarchy at /sys/fs/cgroup"),
        _ => Check::fail(
            NAME,
            "/sys/fs/cgroup is not a cgroup2 mount (legacy or hybrid mode)",
            "boot with systemd.unified_cgroup_hierarchy=1",
        ),
    }
}

fn controllers() -> Check {
    const NAME: &str = "cgroup controllers";
    match fs::read_to_string("/sys/fs/cgroup/cgroup.controllers") {
        Ok(listing) => {
            let missing = missing_controllers(&listing, &REQUIRED_CONTROLLERS);
            if missing.is_empty() {
                Check::pass(NAME, REQUIRED_CONTROLLERS.join(", "))
            } else {
                Check::fail(
                    NAME,
                    format!("missing: {}", missing.join(", ")),
                    "enable these controllers in the kernel and systemd configuration",
                )
            }
        }
        Err(e) => Check::fail(
            NAME,
            format!("cannot read cgroup.controllers: {e}"),
            "enable cgroup v2",
        ),
    }
}

fn cgroup_kill() -> Check {
    const NAME: &str = "cgroup.kill";
    let own = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let path = own
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .unwrap_or("/")
        .trim();
    // The root cgroup has no cgroup.kill file, so look at our own cgroup or, failing that, any child.
    let candidates = [
        format!("/sys/fs/cgroup{path}/cgroup.kill"),
        "/sys/fs/cgroup/system.slice/cgroup.kill".to_owned(),
        "/sys/fs/cgroup/init.scope/cgroup.kill".to_owned(),
    ];
    if candidates.iter().any(|p| Path::new(p).exists()) {
        Check::pass(NAME, "supported (kills whole process trees on timeout)")
    } else {
        Check::fail(NAME, "not found (needs kernel 5.14+)", "upgrade the kernel")
    }
}

fn user_namespaces() -> Check {
    const NAME: &str = "user namespaces";
    let max: u64 = fs::read_to_string("/proc/sys/user/max_user_namespaces")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    if max > 0 {
        Check::pass(NAME, format!("enabled (max {max})"))
    } else {
        Check::fail(NAME, "disabled", "sysctl -w user.max_user_namespaces=15000")
    }
}

fn seccomp() -> Check {
    const NAME: &str = "seccomp";
    let actions = fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail").unwrap_or_default();
    let needed = ["errno", "kill_process", "user_notif"];
    let missing: Vec<&str> = needed
        .iter()
        .copied()
        .filter(|a| !actions.split_whitespace().any(|x| x == *a))
        .collect();
    if missing.is_empty() {
        Check::pass(
            NAME,
            "filter mode with errno, kill_process and user_notif actions",
        )
    } else {
        Check::fail(
            NAME,
            format!("missing actions: {}", missing.join(", ")),
            "use a kernel built with CONFIG_SECCOMP_FILTER",
        )
    }
}

fn landlock() -> Check {
    const NAME: &str = "landlock";
    // SAFETY: with the VERSION flag the kernel ignores the attr pointer and size and returns the ABI.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi >= 4 {
        Check::pass(NAME, format!("ABI v{abi} (filesystem and TCP rules)"))
    } else if abi >= 1 {
        Check::warn(
            NAME,
            format!("ABI v{abi}: filesystem rules only, no TCP rules"),
            "kernel 6.7 or newer adds TCP rules",
        )
    } else {
        let err = std::io::Error::last_os_error();
        Check::fail(
            NAME,
            format!("unavailable: {err}"),
            "add landlock to the lsm= kernel parameter (Ubuntu enables it by default)",
        )
    }
}

fn btrfs_pool(data_dir: &Path) -> Check {
    const NAME: &str = "btrfs pool";
    let shown = data_dir.display();
    match fs_magic(data_dir) {
        Some(BTRFS_SUPER_MAGIC) => Check::pass(NAME, format!("{shown} is on Btrfs")),
        Some(_) => Check::fail(
            NAME,
            format!("{shown} is not on Btrfs"),
            format!("mount a Btrfs filesystem (a disk or a loop image) at {shown}"),
        ),
        None => Check::fail(
            NAME,
            format!("{shown} does not exist"),
            format!("create and mount a Btrfs filesystem at {shown}; on macOS run `boxent vm up`"),
        ),
    }
}

fn btrfs_fsid(data_dir: &Path) -> std::io::Result<String> {
    let dir = fs::File::open(data_dir)?;
    let mut args = [0u8; 1024];
    // SAFETY: BTRFS_IOC_FS_INFO writes at most 1024 bytes into the buffer we pass.
    let rc = unsafe {
        libc::ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&dir),
            BTRFS_IOC_FS_INFO as _,
            args.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // struct btrfs_ioctl_fs_info_args { u64 max_id; u64 num_devices; u8 fsid[16]; ... }
    let mut fsid = [0u8; 16];
    fsid.copy_from_slice(&args[16..32]);
    Ok(format_uuid(&fsid))
}

fn btrfs_quota(data_dir: &Path) -> Check {
    const NAME: &str = "btrfs quotas";
    let fix = format!("btrfs quota enable --simple {}", data_dir.display());
    if fs_magic(data_dir) != Some(BTRFS_SUPER_MAGIC) {
        return Check::fail(NAME, "skipped: no Btrfs pool", fix);
    }
    let fsid = match btrfs_fsid(data_dir) {
        Ok(id) => id,
        Err(e) => return Check::fail(NAME, format!("cannot read filesystem id: {e}"), fix),
    };
    let mode_path = format!("/sys/fs/btrfs/{fsid}/qgroups/mode");
    match fs::read_to_string(&mode_path).map(|s| s.trim().to_owned()) {
        Ok(mode) if mode == "squota" => Check::pass(NAME, "simple quotas enabled"),
        Ok(mode) => Check::warn(
            NAME,
            format!("quota mode is '{mode}': full qgroups work but slow down snapshots"),
            format!("btrfs quota disable {0} && {fix}", data_dir.display()),
        ),
        Err(_) => Check::fail(NAME, "quotas are not enabled", fix),
    }
}

fn free_space(data_dir: &Path) -> Check {
    const NAME: &str = "free space";
    let Ok(c) = CString::new(data_dir.as_os_str().as_bytes()) else {
        return Check::fail(NAME, "invalid path", "pass a valid --data-dir");
    };
    // SAFETY: statvfs writes into a zero-initialised struct; the path is NUL-terminated.
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut buf) } != 0 {
        return Check::fail(
            NAME,
            "skipped: data directory missing",
            "create the Btrfs pool first",
        );
    }
    #[allow(clippy::unnecessary_cast)]
    let free = buf.f_bavail as u64 * buf.f_frsize as u64;
    let gib = free / (1024 * 1024 * 1024);
    if free >= MIN_FREE_BYTES {
        Check::pass(NAME, format!("{gib} GiB available"))
    } else {
        Check::warn(
            NAME,
            format!("only {gib} GiB available"),
            "give the pool at least 10 GiB",
        )
    }
}

fn tool(name: &str, binary: &str, fix: &str) -> Check {
    match Command::new(binary).arg("--version").output() {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let first = text.lines().next().unwrap_or("").trim();
            Check::pass(name, first.to_owned())
        }
        Ok(out) => Check::fail(
            name,
            format!("`{binary} --version` exited with {}", out.status),
            fix,
        ),
        Err(_) => Check::fail(name, format!("`{binary}` not found on PATH"), fix),
    }
}

fn kvm() -> Check {
    const NAME: &str = "kvm";
    if Path::new("/dev/kvm").exists() {
        Check::pass(
            NAME,
            "/dev/kvm present (needed only for the later microVM tier)",
        )
    } else {
        Check::warn(
            NAME,
            "/dev/kvm missing: fine for now, needed only for the later Firecracker tier",
            "enable nested virtualization (set in the Boxent Lima template on M3 and newer Macs)",
        )
    }
}

fn base_image(data_dir: &Path) -> Check {
    const NAME: &str = "base image";
    let p = data_dir.join("images/base");
    if p.join("usr").is_dir() {
        Check::pass(NAME, format!("{} is built", p.display()))
    } else {
        Check::warn(NAME, "not built yet", "boxent image build")
    }
}
