//! Developer tasks, run as `cargo xtask <task>`.
//!
//! - `build-linux [--debug]`: static arm64 Linux binaries via `cargo zigbuild`.
//! - `vm-deploy [--debug]`: build, then install the binaries into the Lima VM.
//! - `vm-test [FILTER]`: build the agent and its tests for Linux and run them as root in the VM.
//! - `e2e [PYTEST ARGS]`: black-box MCP tests from this machine through `boxent mcp`, using the
//!   official Python MCP SDK (suite E and the client-side latency of suite A).
//! - `ci`: formatting, clippy for the host and for Linux, unit tests.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

const LINUX_TARGET: &str = "aarch64-unknown-linux-musl";
const VM: &str = "boxent";
/// (binary name in target dir, install path inside the VM)
const VM_BINARIES: [(&str, &str); 2] = [
    ("boxent", "/usr/local/bin/boxent"),
    ("boxent-agent", "/usr/local/lib/boxent/boxent-agent"),
];

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let debug = args.iter().any(|a| a == "--debug");
    match args.first().map(String::as_str) {
        Some("build-linux") => build_linux(debug).map(drop),
        Some("vm-deploy") => vm_deploy(debug),
        Some("vm-test") => vm_test(args.get(1).filter(|a| !a.starts_with("--")).cloned()),
        Some("e2e") => e2e(&args[1..]),
        Some("ci") => ci(),
        _ => {
            eprintln!(
                "usage: cargo xtask <build-linux|vm-deploy|vm-test [FILTER]|e2e [ARGS]|ci> [--debug]"
            );
            std::process::exit(2);
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the workspace root")
        .to_path_buf()
}

fn run(cmd: &mut Command) -> Result<()> {
    eprintln!("+ {cmd:?}");
    let status = cmd.status().with_context(|| format!("starting {cmd:?}"))?;
    if !status.success() {
        bail!("{cmd:?} failed with {status}");
    }
    Ok(())
}

fn cargo() -> Command {
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(root());
    cmd
}

/// Builds the Linux binaries and returns the directory they are in.
fn build_linux(debug: bool) -> Result<PathBuf> {
    let mut cmd = cargo();
    cmd.args([
        "zigbuild",
        "--target",
        LINUX_TARGET,
        "-p",
        "boxent-cli",
        "-p",
        "boxent-agent",
    ]);
    if !debug {
        cmd.arg("--release");
    }
    run(&mut cmd).context(
        "cross-build failed; is cargo-zigbuild installed? (cargo install --locked cargo-zigbuild)",
    )?;
    Ok(root()
        .join("target")
        .join(LINUX_TARGET)
        .join(if debug { "debug" } else { "release" }))
}

fn vm_deploy(debug: bool) -> Result<()> {
    let dir = build_linux(debug)?;
    for (name, dest) in VM_BINARIES {
        let src = dir.join(name);
        let staged = format!("/tmp/{name}");
        run(Command::new("limactl")
            .arg("copy")
            .arg(&src)
            .arg(format!("{VM}:{staged}")))?;
        run(Command::new("limactl").args([
            "shell",
            "--workdir",
            "/",
            VM,
            "sudo",
            "install",
            "-D",
            "-m",
            "0755",
            &staged,
            dest,
        ]))?;
        run(Command::new("limactl").args(["shell", "--workdir", "/", VM, "rm", "-f", &staged]))?;
    }
    install_service()?;
    eprintln!("deployed to the '{VM}' VM and restarted boxentd; check it with `boxent doctor`");
    Ok(())
}

const UNIT: &str = include_str!("../../deploy/systemd/boxentd.service");

/// Installs the systemd unit and (re)starts the daemon. The socket is owned by the VM's login
/// user so Lima can forward it to the Mac.
fn install_service() -> Result<()> {
    let out = Command::new("limactl")
        .args(["shell", "--workdir", "/", VM, "id", "-u"])
        .output()
        .context("asking the VM for the login user's UID")?;
    let uid = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if uid.is_empty() || !uid.bytes().all(|b| b.is_ascii_digit()) {
        bail!("unexpected UID from the VM: {uid:?}");
    }
    let script = format!(
        "set -e\n\
         install -d -m 0755 /etc/boxent\n\
         printf 'BOXENT_SOCKET_UID={uid}\\n' > /etc/boxent/daemon.env\n\
         cat > /etc/systemd/system/boxentd.service <<'UNIT'\n{UNIT}UNIT\n\
         systemctl daemon-reload\n\
         systemctl enable --quiet boxentd\n\
         systemctl restart boxentd\n"
    );
    run(Command::new("limactl").args([
        "shell",
        "--workdir",
        "/",
        VM,
        "sudo",
        "bash",
        "-c",
        &script,
    ]))
}

fn systemctl(action: &str) -> Result<()> {
    run(Command::new("limactl").args([
        "shell",
        "--workdir",
        "/",
        VM,
        "sudo",
        "systemctl",
        action,
        "boxentd",
    ]))
}

/// Test binaries that run inside the VM: package, cargo target selector, target name.
const VM_TESTS: [(&str, &str, &str); 8] = [
    ("boxent-agent", "--bin", "boxent-agent"),
    ("boxent-agent", "--test", "vm"),
    ("boxent-driver-oci", "--lib", "boxent_driver_oci"),
    ("boxent-driver-oci", "--test", "isolation"),
    ("boxent-core", "--test", "lifecycle"),
    ("boxent-core", "--test", "snapshots"),
    ("boxent-core", "--test", "egress"),
    ("boxent-mcp", "--test", "sessions"),
];
const VM_TEST_DIR: &str = "/tmp/boxent-vm-test";

fn vm_test(filter: Option<String>) -> Result<()> {
    // Installs the current binaries, then makes sure the base image exists (built once, ~90 s).
    vm_deploy(false)?;
    run(Command::new("limactl").args([
        "shell",
        "--workdir",
        "/",
        VM,
        "sudo",
        "/usr/local/bin/boxent",
        "image",
        "build",
    ]))?;
    // The tests start their own engines; the daemon would hold the engine lock and sandboxes.
    systemctl("stop")?;
    let result = run_vm_tests(filter);
    systemctl("start")?;
    result
}

fn run_vm_tests(filter: Option<String>) -> Result<()> {
    let release = root().join("target").join(LINUX_TARGET).join("release");
    let mut binaries = Vec::new();
    for (package, selector, target) in VM_TESTS {
        let out = cargo()
            .args([
                "zigbuild",
                "--target",
                LINUX_TARGET,
                "--release",
                "--tests",
                "-p",
                package,
            ])
            .arg(selector)
            .args((selector != "--lib").then_some(target))
            .args(["--message-format", "json-render-diagnostics"])
            .stderr(std::process::Stdio::inherit())
            .output()
            .context("building VM tests")?;
        if !out.status.success() {
            bail!("building {package} tests failed");
        }
        let exe = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["reason"] == "compiler-artifact" && v["profile"]["test"] == true)
            .filter(|v| v["target"]["name"] == target)
            .find_map(|v| v["executable"].as_str().map(PathBuf::from))
            .with_context(|| format!("no test executable for {package} {selector} {target}"))?;
        binaries.push((format!("{package}-{}-tests", target), exe));
    }
    let shell = |args: &[&str]| {
        let mut c = Command::new("limactl");
        c.args(["shell", "--workdir", "/", VM]).args(args);
        c
    };
    run(&mut shell(&["mkdir", "-p", VM_TEST_DIR]))?;
    let agent = format!("{VM_TEST_DIR}/boxent-agent");
    run(Command::new("limactl")
        .arg("copy")
        .arg(release.join("boxent-agent"))
        .arg(format!("{VM}:{agent}")))?;
    for (name, exe) in &binaries {
        let dest = format!("{VM_TEST_DIR}/{name}");
        run(Command::new("limactl")
            .arg("copy")
            .arg(exe)
            .arg(format!("{VM}:{dest}")))?;
        let mut args = vec![
            "sudo".to_owned(),
            "env".into(),
            "BOXENT_VM_TESTS=1".into(),
            format!("BOXENT_AGENT_BIN={agent}"),
            dest,
            "--test-threads=1".into(),
            "--nocapture".into(),
        ];
        args.extend(filter.clone());
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run(&mut shell(&args))?;
    }
    Ok(())
}

fn e2e(pytest_args: &[String]) -> Result<()> {
    let venv = root().join(".venv");
    if !venv.join("bin/pytest").exists() {
        run(Command::new("python3").arg("-m").arg("venv").arg(&venv))?;
        run(Command::new(venv.join("bin/pip"))
            .args(["install", "-q", "-r"])
            .arg(root().join("tests/e2e/requirements.txt")))?;
    }
    run(cargo().args(["build", "-q", "-p", "boxent-cli"]))?;
    run(Command::new(venv.join("bin/pytest"))
        .current_dir(root().join("tests/e2e"))
        .arg("-s")
        .args(pytest_args)
        .env("BOXENT_BIN", root().join("target/debug/boxent")))
}

fn ci() -> Result<()> {
    run(cargo().args(["fmt", "--all", "--check"]))?;
    run(cargo().args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]))?;
    // Clippy type-checks without linking, so this covers the Linux-only code paths from macOS.
    run(cargo().args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--target",
        LINUX_TARGET,
        "--",
        "-D",
        "warnings",
    ]))?;
    run(cargo().args(["test", "--workspace"]))?;
    Ok(())
}
