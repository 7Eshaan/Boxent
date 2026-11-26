//! `boxent mcp`: the stdio MCP server an IDE or agent launches. It relays bytes between its
//! stdio and the daemon's socket (forwarded from the VM by Lima on macOS), so MCP itself is
//! handled by the daemon. Nothing but relayed bytes is ever written to stdout.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

pub fn run(socket: Option<PathBuf>, no_start: bool) -> Result<bool> {
    let path = match socket {
        Some(p) => p,
        None => default_socket(),
    };
    let stream = connect(&path, no_start)?;
    let mut up = stream.try_clone()?;
    let mut down = stream;
    // Unbuffered handles: each relayed chunk is written through immediately.
    let mut stdin = File::from(io::stdin().as_fd().try_clone_to_owned()?);
    let mut stdout = File::from(io::stdout().as_fd().try_clone_to_owned()?);
    std::thread::spawn(move || {
        let _ = copy(&mut stdin, &mut up);
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    copy(&mut down, &mut stdout).context("relaying from the daemon")?;
    Ok(true)
}

fn copy(from: &mut impl Read, to: &mut impl Write) -> io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        to.write_all(&buf[..n])?;
    }
}

#[cfg(target_os = "linux")]
fn default_socket() -> PathBuf {
    "/run/boxent/boxent.sock".into()
}

#[cfg(not(target_os = "linux"))]
fn default_socket() -> PathBuf {
    let dir = crate::vm::instance()
        .ok()
        .flatten()
        .and_then(|i| i.get("dir").and_then(|d| d.as_str()).map(PathBuf::from))
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
                .join(".lima")
                .join(crate::vm::INSTANCE)
        });
    dir.join("sock").join("boxent.sock")
}

fn connect(path: &Path, no_start: bool) -> Result<UnixStream> {
    if let Ok(s) = UnixStream::connect(path) {
        return Ok(s);
    }
    if cfg!(target_os = "linux") || no_start {
        bail!(
            "cannot connect to the Boxent daemon at {} (is boxentd running?)",
            path.display()
        );
    }
    start_vm()?;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match UnixStream::connect(path) {
            Ok(s) => return Ok(s),
            Err(e) if Instant::now() >= deadline => {
                bail!(
                    "the Boxent daemon did not come up at {}: {e}",
                    path.display()
                )
            }
            Err(_) => std::thread::sleep(Duration::from_millis(250)),
        }
    }
}

/// Starts the VM if it exists and is stopped. Output goes to stderr, never stdout.
fn start_vm() -> Result<()> {
    let status = crate::vm::instance()?.map(|i| crate::vm::str_field(&i, "status").to_owned());
    match status.as_deref() {
        None => bail!("the Boxent VM does not exist; run `boxent vm up` first"),
        Some("Running") => Ok(()),
        Some(_) => {
            eprintln!("boxent: starting the Boxent VM...");
            let err = || io::stderr().as_fd().try_clone_to_owned().map(Stdio::from);
            let ok = Command::new("limactl")
                .args(["start", "--tty=false", crate::vm::INSTANCE])
                .stdin(Stdio::null())
                .stdout(err()?)
                .stderr(err()?)
                .status()?
                .success();
            if !ok {
                bail!("limactl start failed");
            }
            Ok(())
        }
    }
}
