//! Requests from the engine and responses from the agent.
//!
//! Every frame is an [`Envelope`]. The engine picks request ids; the agent echoes the id on the
//! matching response. Requests may run concurrently, so responses can arrive out of order.

use serde::{Deserialize, Serialize};

use crate::Captured;

/// Per-stream capture limits the agent may be asked for.
pub const MAX_CAPTURE: u32 = 1024 * 1024;
/// Largest file `WriteFile` and `ReadFile` move in one request.
pub const MAX_FILE: u32 = 10 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub id: u64,
    pub body: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// First message on a connection; the agent answers with [`Response::Hello`].
    Hello {
        protocol: u32,
    },
    Ping,
    Exec(ExecRequest),
    WriteFile(WriteFileRequest),
    ReadFile(ReadFileRequest),
    /// Kill every process started by `Exec` (running or left in the background).
    KillAll,
    /// Kill everything and exit.
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Hello(HelloInfo),
    Pong,
    Exec(ExecResult),
    WriteFile { bytes_written: u64 },
    ReadFile(ReadFileResult),
    KillAll { processes_killed: u32 },
    ShuttingDown,
    Error(AgentError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloInfo {
    pub protocol: u32,
    pub agent_version: String,
    /// The agent's PID as it sees itself (1 inside a sandbox).
    pub pid: u32,
    /// Landlock ABI applied to commands; 0 when the kernel has none.
    #[serde(default)]
    pub landlock_abi: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub head: u32,
    pub tail: u32,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            head: 16 * 1024,
            tail: 48 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    /// Program and arguments; `argv[0]` is looked up on `PATH` from `env`.
    pub argv: Vec<String>,
    /// The complete environment. Nothing is inherited from the agent.
    pub env: Vec<(String, String)>,
    pub cwd: String,
    pub timeout_ms: u64,
    pub head_cap: u32,
    pub tail_cap: u32,
}

impl ExecRequest {
    pub fn caps(&self) -> Caps {
        Caps {
            head: self.head_cap,
            tail: self.tail_cap,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    /// Exit status, or 128 + signal number when the process was killed by a signal.
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub oom_killed: bool,
    /// Wall time from spawn to the main process exiting, measured by the agent.
    pub duration_ms: u64,
    pub stdout: Captured,
    pub stderr: Captured,
}

impl ExecResult {
    /// Rejects results that an honest agent could not have produced for these caps.
    pub fn check(&self, caps: Caps) -> Result<(), String> {
        let (h, t) = (caps.head as usize, caps.tail as usize);
        if !self.stdout.is_consistent(h, t) {
            return Err("stdout capture violates the requested caps".into());
        }
        if !self.stderr.is_consistent(h, t) {
            return Err("stderr capture violates the requested caps".into());
        }
        if self.signal.is_some_and(|s| !(1..=64).contains(&s)) {
            return Err("signal number out of range".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteFileRequest {
    /// Absolute, or relative to the workspace.
    pub path: String,
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
    /// Permission bits; defaults to 0644.
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFileRequest {
    /// Absolute, or relative to the workspace.
    pub path: String,
    pub offset: u64,
    pub max_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFileResult {
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
    /// Size of the whole file.
    pub size: u64,
    /// True when the file continues past what was returned.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// The request was malformed or out of bounds.
    InvalidRequest,
    /// The path escapes the sandbox user's view, uses `..`, or crosses a magic link.
    InvalidPath,
    NotFound,
    PermissionDenied,
    /// Content or a cap exceeds a protocol limit.
    TooLarge,
    /// The path is a directory where a file was expected, or the reverse.
    WrongType,
    /// The program could not be started (not found, not executable).
    SpawnFailed,
    Io,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentError {
    pub code: ErrorCode,
    pub message: String,
}

impl AgentError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Capture;

    #[test]
    fn exec_result_check() {
        let mut out = Capture::new(4, 4);
        out.push(b"0123456789");
        let ok = ExecResult {
            exit_code: 0,
            signal: None,
            timed_out: false,
            oom_killed: false,
            duration_ms: 1,
            stdout: out.finish(),
            stderr: Captured::default(),
        };
        assert!(ok.check(Caps { head: 4, tail: 4 }).is_ok());
        assert!(ok.check(Caps { head: 2, tail: 4 }).is_err());
        let bad_signal = ExecResult {
            signal: Some(999),
            ..ok
        };
        assert!(bad_signal.check(Caps { head: 4, tail: 4 }).is_err());
    }
}
