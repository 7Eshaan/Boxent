//! Linux-only development commands: build images and run one-off sandboxes. The daemon (M3)
//! replaces `sandbox run` for real use.

use std::time::Instant;

use anyhow::Result;
use boxent_driver_oci::{DriverConfig, Limits, OciDriver, image};
use boxent_proto::{Caps, ExecRequest};
use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum ImageCommand {
    /// Build the base image (Ubuntu with bash, coreutils, python3, git, curl).
    Build {
        /// Rebuild even if the image exists.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum SandboxCommand {
    /// Create a sandbox, run one bash command in it, print the result and destroy it.
    Run(RunArgs),
}

#[derive(Args)]
pub struct RunArgs {
    #[arg(long, default_value_t = 1.0)]
    cpus: f64,
    /// Memory limit in MiB.
    #[arg(long, default_value_t = 512)]
    memory: u64,
    #[arg(long, default_value_t = 256)]
    pids: u32,
    #[arg(long, default_value_t = 30)]
    timeout: u64,
    /// The bash command to run.
    command: String,
}

pub fn image(cmd: ImageCommand) -> Result<bool> {
    let cfg = DriverConfig::default();
    match cmd {
        ImageCommand::Build { force } => {
            let t = Instant::now();
            let p = image::build(&cfg.data_dir, &cfg.image, force)?;
            eprintln!("image ready at {} ({:.1?})", p.display(), t.elapsed());
        }
    }
    Ok(true)
}

pub fn sandbox(cmd: SandboxCommand) -> Result<bool> {
    let SandboxCommand::Run(a) = cmd;
    let driver = OciDriver::new(DriverConfig::default())?;
    let limits = Limits {
        cpus: a.cpus,
        memory_bytes: a.memory << 20,
        pids: a.pids,
        ..Limits::default()
    };
    let t = Instant::now();
    let mut sb = driver.create(&limits)?;
    let created = t.elapsed();
    let caps = Caps::default();
    let t = Instant::now();
    let r = sb.client().exec(ExecRequest {
        argv: vec![
            "/bin/bash".into(),
            "--noprofile".into(),
            "--norc".into(),
            "-c".into(),
            a.command,
        ],
        env: vec![
            (
                "PATH".into(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
            ),
            ("HOME".into(), "/home/sandbox".into()),
            ("LANG".into(), "C.UTF-8".into()),
        ],
        cwd: "/workspace".into(),
        timeout_ms: a.timeout * 1000,
        head_cap: caps.head,
        tail_cap: caps.tail,
    })?;
    let ran = t.elapsed();
    let id = sb.id().to_owned();
    let t = Instant::now();
    sb.destroy()?;
    print!("{}", r.stdout.render());
    eprint!("{}", r.stderr.render());
    eprintln!(
        "[{id}] exit {} (signal {:?}, timed out {}, oom {}) | create {:.1?}, exec {:.1?}, destroy {:.1?}",
        r.exit_code,
        r.signal,
        r.timed_out,
        r.oom_killed,
        created,
        ran,
        t.elapsed()
    );
    Ok(r.exit_code == 0)
}
