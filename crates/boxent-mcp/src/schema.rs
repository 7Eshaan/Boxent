//! Tool arguments and results. The JSON schemas MCP clients see are generated from these types,
//! so the doc comments below are what an agent reads about each field.
//!
//! Arguments reject unknown fields (`additionalProperties: false`), so a typo in a field name is
//! an error instead of a silently ignored option.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const DEFAULT_READ_BYTES: u32 = 256 * 1024;
pub const MAX_READ_BYTES: u32 = 1024 * 1024;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunBashArgs {
    /// Bash command line, run in /workspace. Each call starts a fresh shell: files persist between calls, but `cd`, variables and functions do not. Background processes (`server &`) keep running after the call returns.
    pub command: String,
    /// Sandbox to run in. Omit to use this session's default sandbox, created on first use.
    #[serde(default)]
    pub sandbox_id: Option<String>,
    /// Seconds before the command and everything it started are killed. Default 30, max 600.
    #[serde(default)]
    #[schemars(range(min = 1, max = 600))]
    pub timeout_sec: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunPythonArgs {
    /// Python 3 source code, run with `python3 -u` in /workspace.
    pub code: String,
    /// Sandbox to run in. Omit to use this session's default sandbox, created on first use.
    #[serde(default)]
    pub sandbox_id: Option<String>,
    /// Seconds before the program and everything it started are killed. Default 30, max 600.
    #[serde(default)]
    #[schemars(range(min = 1, max = 600))]
    pub timeout_sec: Option<u32>,
}

/// Result of `run_bash` and `run_python`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ExecOutput {
    pub sandbox_id: String,
    /// Standard output. If longer than the cap, the start and the end are kept and a marker shows how many bytes were left out.
    pub stdout: String,
    pub stderr: String,
    /// Exit status; 128 + N when the process was killed by signal N (137 for a timeout).
    pub exit_code: i32,
    /// Signal that killed the process, if any.
    pub signal: Option<i32>,
    pub timed_out: bool,
    /// The command was killed for exceeding the sandbox memory limit.
    pub oom_killed: bool,
    pub duration_ms: u64,
    pub stdout_truncated: bool,
    pub stdout_total_bytes: u64,
    pub stderr_truncated: bool,
    pub stderr_total_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    #[default]
    Utf8,
    Base64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteFileArgs {
    /// Absolute path, or relative to /workspace. Must be inside /workspace, /home/sandbox or /tmp. Parent directories are created. The write is atomic.
    pub path: String,
    /// File content (text, or base64 when `encoding` is `base64`). At most 10 MiB.
    pub content: String,
    #[serde(default)]
    pub sandbox_id: Option<String>,
    /// How `content` is encoded. Default `utf8`.
    #[serde(default)]
    pub encoding: Option<Encoding>,
    /// Octal permission bits such as "644" or "755". Default "644".
    #[serde(default)]
    #[schemars(regex(pattern = r"^[0-7]{3,4}$"))]
    pub mode: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct WriteFileOutput {
    pub sandbox_id: String,
    pub path: String,
    pub bytes_written: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadFileArgs {
    /// Absolute path, or relative to /workspace.
    pub path: String,
    #[serde(default)]
    pub sandbox_id: Option<String>,
    /// Byte offset to start at. Default 0.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Bytes to return at most. Default 262144 (256 KiB), max 1048576 (1 MiB).
    #[serde(default)]
    #[schemars(range(min = 1, max = 1_048_576))]
    pub max_bytes: Option<u32>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ReadFileOutput {
    pub sandbox_id: String,
    pub path: String,
    /// The bytes read: text when they are valid UTF-8, otherwise base64.
    pub content: String,
    pub encoding: Encoding,
    /// Size of the whole file in bytes.
    pub size: u64,
    /// True when the file continues past what was returned; read again with a larger offset.
    pub truncated: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateSandboxArgs {
    /// Sandbox profile set by the operator. Only `default` exists until egress profiles arrive.
    #[serde(default)]
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CreateSandboxOutput {
    /// Pass this as `sandbox_id` to other tools. It is a secret capability: anyone who has it can use the sandbox.
    pub sandbox_id: String,
    pub profile: String,
    /// Seconds until the sandbox is destroyed regardless of use.
    pub expires_in_sec: u64,
    /// Seconds without any call after which the sandbox is destroyed.
    pub idle_timeout_sec: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DestroySandboxArgs {
    /// Sandbox to destroy. Omit to destroy this session's default sandbox.
    #[serde(default)]
    pub sandbox_id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DestroySandboxOutput {
    pub sandbox_id: String,
    pub destroyed: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotArgs {
    /// A note to recognise the snapshot by, such as "before refactor". At most 200 characters.
    #[serde(default)]
    #[schemars(length(max = 200))]
    pub label: Option<String>,
    #[serde(default)]
    pub sandbox_id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SnapshotOutput {
    pub sandbox_id: String,
    /// Pass this to `restore` to rewind /workspace and /home/sandbox to this moment.
    pub snap_id: String,
    pub label: Option<String>,
    /// RFC 3339 time, UTC.
    pub created_at: String,
    pub snapshots_used: u32,
    pub snapshots_max: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RestoreArgs {
    /// A snapshot of this sandbox, as returned by `snapshot` or `list_snapshots`.
    pub snap_id: String,
    #[serde(default)]
    pub sandbox_id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct RestoreOutput {
    pub sandbox_id: String,
    pub snap_id: String,
    pub restored: bool,
    /// Processes that were running in the sandbox and were killed by the restore.
    pub processes_killed: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListSnapshotsArgs {
    #[serde(default)]
    pub sandbox_id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SnapshotEntry {
    pub snap_id: String,
    pub label: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ListSnapshotsOutput {
    pub sandbox_id: String,
    /// Oldest first.
    pub snapshots: Vec<SnapshotEntry>,
    pub snapshots_max: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteSnapshotArgs {
    pub snap_id: String,
    #[serde(default)]
    pub sandbox_id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DeleteSnapshotOutput {
    pub sandbox_id: String,
    pub snap_id: String,
    pub deleted: bool,
}

/// Formats seconds since the Unix epoch as RFC 3339 in UTC, e.g. `2026-11-26T12:06:29Z`.
pub fn rfc3339(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Parses an octal mode string such as "644".
pub fn parse_mode(s: &str) -> Option<u32> {
    if !(3..=4).contains(&s.len()) {
        return None;
    }
    u32::from_str_radix(s, 8).ok().filter(|m| *m <= 0o7777)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn schema<T: JsonSchema>() -> Value {
        serde_json::to_value(schemars::schema_for!(T)).unwrap()
    }

    #[test]
    fn arguments_are_strict() {
        for s in [
            schema::<RunBashArgs>(),
            schema::<RunPythonArgs>(),
            schema::<WriteFileArgs>(),
            schema::<ReadFileArgs>(),
            schema::<CreateSandboxArgs>(),
            schema::<DestroySandboxArgs>(),
            schema::<SnapshotArgs>(),
            schema::<RestoreArgs>(),
            schema::<ListSnapshotsArgs>(),
            schema::<DeleteSnapshotArgs>(),
        ] {
            assert_eq!(s["additionalProperties"], json!(false), "{s}");
        }
        assert_eq!(schema::<RunBashArgs>()["required"], json!(["command"]));
        assert_eq!(
            schema::<WriteFileArgs>()["required"],
            json!(["path", "content"])
        );
        assert!(
            serde_json::from_value::<RunBashArgs>(json!({"command": "x", "comand": 1})).is_err()
        );
        assert!(serde_json::from_value::<RunBashArgs>(json!({"command": "x"})).is_ok());
    }

    #[test]
    fn exec_output_names_the_spec_fields() {
        let s = schema::<ExecOutput>();
        let props = s["properties"].as_object().unwrap();
        for f in [
            "stdout",
            "stderr",
            "exit_code",
            "duration_ms",
            "timed_out",
            "sandbox_id",
        ] {
            assert!(props.contains_key(f), "missing {f}");
        }
    }

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_795_090_589), "2026-11-19T12:16:29Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn modes() {
        assert_eq!(parse_mode("644"), Some(0o644));
        assert_eq!(parse_mode("0755"), Some(0o755));
        assert_eq!(parse_mode("999"), None);
        assert_eq!(parse_mode("7"), None);
    }
}
