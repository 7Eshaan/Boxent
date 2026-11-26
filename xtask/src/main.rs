//! Developer tasks, run as `cargo xtask <task>`.
//!
//! - `build-linux [--debug]`: static arm64 Linux binaries via `cargo zigbuild`.
//! - `vm-deploy [--debug]`: build, then install the binaries into the Lima VM.
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
        Some("ci") => ci(),
        _ => {
            eprintln!("usage: cargo xtask <build-linux|vm-deploy|ci> [--debug]");
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
    eprintln!("deployed to the '{VM}' VM; check it with `boxent doctor`");
    Ok(())
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
