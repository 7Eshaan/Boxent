//! The MCP server: one instance per client connection (session), sharing one engine.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use boxent_core::{Engine, EngineError, ErrorCode, ExecOutcome, ExecSpec};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{Json, ServerHandler, tool, tool_handler, tool_router};
use serde_json::json;

use crate::schema::*;

const INSTRUCTIONS: &str = "Boxent runs code in disposable, isolated Linux sandboxes \
(Ubuntu with bash, python3, git and curl; no network access). Every tool takes an optional \
sandbox_id; without one, calls go to this session's default sandbox, created on first use. \
Files persist between calls in /workspace; each run_bash call starts a fresh shell. \
Sandboxes are destroyed when idle for a while, after a maximum lifetime, or when the session \
ends; errors then say `sandbox_reaped` and the next call without a sandbox_id starts a new one.";

/// What one client connection owns.
#[derive(Default)]
pub struct Session {
    /// The sandbox used when a call names none.
    default: tokio::sync::Mutex<Option<String>>,
    /// Sandboxes this session created; destroyed when the session ends (after a grace period).
    owned: Mutex<HashSet<String>>,
}

impl Session {
    pub fn owned(&self) -> Vec<String> {
        self.owned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    fn own(&self, id: &str) {
        self.owned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.to_owned());
    }

    fn disown(&self, id: &str) {
        self.owned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
    }
}

#[derive(Clone)]
pub struct BoxentServer {
    engine: Engine,
    session: Arc<Session>,
    tool_router: ToolRouter<Self>,
}

/// A failed tool call: `isError: true` with `{"error": {"code", "message"}}` as text, so the agent sees a stable code it can act on.
fn tool_error(e: EngineError) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(
        json!({ "error": { "code": e.code.as_str(), "message": e.message } }).to_string(),
    )])
}

fn invalid(msg: impl Into<String>) -> CallToolResult {
    tool_error(EngineError::new(ErrorCode::InvalidArgument, msg))
}

impl BoxentServer {
    pub fn new(engine: Engine, session: Arc<Session>) -> Self {
        Self {
            engine,
            session,
            tool_router: Self::tool_router(),
        }
    }

    /// Picks the sandbox for a call: the named one, or the session default (claimed on first use). If the default was reaped, the error is reported once and the next call starts a fresh default.
    async fn resolve(&self, explicit: Option<String>) -> Result<String, CallToolResult> {
        if let Some(id) = explicit {
            if id.is_empty()
                || id.len() > 64
                || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(invalid("sandbox_id is malformed"));
            }
            return Ok(id);
        }
        let mut default = self.session.default.lock().await;
        if let Some(id) = default.as_ref() {
            match self.engine.info(id) {
                Ok(_) => return Ok(id.clone()),
                Err(e) => {
                    *default = None;
                    return Err(tool_error(e));
                }
            }
        }
        let id = self.engine.claim().await.map_err(tool_error)?;
        self.session.own(&id);
        *default = Some(id.clone());
        Ok(id)
    }

    async fn run(
        &self,
        id: Option<String>,
        spec: ExecSpec,
        timeout_sec: Option<u32>,
    ) -> Result<Json<ExecOutput>, CallToolResult> {
        if let Some(t) = timeout_sec
            && !(1..=600).contains(&t)
        {
            return Err(invalid("timeout_sec must be between 1 and 600"));
        }
        let id = self.resolve(id).await?;
        let o: ExecOutcome = self
            .engine
            .exec(
                &id,
                spec,
                timeout_sec.map(|t| Duration::from_secs(u64::from(t))),
            )
            .await
            .map_err(tool_error)?;
        Ok(Json(ExecOutput {
            sandbox_id: o.sandbox_id,
            stdout: o.stdout,
            stderr: o.stderr,
            exit_code: o.exit_code,
            signal: o.signal,
            timed_out: o.timed_out,
            oom_killed: o.oom_killed,
            duration_ms: o.duration_ms,
            stdout_truncated: o.stdout_truncated,
            stdout_total_bytes: o.stdout_total_bytes,
            stderr_truncated: o.stderr_truncated,
            stderr_total_bytes: o.stderr_total_bytes,
        }))
    }
}

#[tool_router]
impl BoxentServer {
    /// Run a bash command in a sandbox and return its output, exit code and timing.
    #[tool(annotations(
        title = "Run bash",
        read_only_hint = false,
        destructive_hint = false,
        open_world_hint = false
    ))]
    async fn run_bash(
        &self,
        Parameters(a): Parameters<RunBashArgs>,
    ) -> Result<Json<ExecOutput>, CallToolResult> {
        self.run(a.sandbox_id, ExecSpec::Bash(a.command), a.timeout_sec)
            .await
    }

    /// Run Python 3 code in a sandbox and return its output, exit code and timing.
    #[tool(annotations(
        title = "Run Python",
        read_only_hint = false,
        destructive_hint = false,
        open_world_hint = false
    ))]
    async fn run_python(
        &self,
        Parameters(a): Parameters<RunPythonArgs>,
    ) -> Result<Json<ExecOutput>, CallToolResult> {
        self.run(a.sandbox_id, ExecSpec::Python(a.code), a.timeout_sec)
            .await
    }

    /// Write a file in a sandbox, creating parent directories. Replaces an existing file.
    #[tool(annotations(
        title = "Write file",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = true,
        open_world_hint = false
    ))]
    async fn write_file(
        &self,
        Parameters(a): Parameters<WriteFileArgs>,
    ) -> Result<Json<WriteFileOutput>, CallToolResult> {
        let content = match a.encoding.unwrap_or_default() {
            Encoding::Utf8 => a.content.into_bytes(),
            Encoding::Base64 => B64
                .decode(a.content.trim())
                .map_err(|e| invalid(format!("content is not valid base64: {e}")))?,
        };
        let mode = match a.mode.as_deref() {
            None => None,
            Some(m) => Some(
                parse_mode(m).ok_or_else(|| invalid("mode must be octal digits like \"644\""))?,
            ),
        };
        let id = self.resolve(a.sandbox_id).await?;
        let n = self
            .engine
            .write_file(&id, &a.path, content, mode)
            .await
            .map_err(tool_error)?;
        Ok(Json(WriteFileOutput {
            sandbox_id: id,
            path: a.path,
            bytes_written: n,
        }))
    }

    /// Read a file from a sandbox. Text is returned as is; binary content as base64.
    #[tool(annotations(title = "Read file", read_only_hint = true, open_world_hint = false))]
    async fn read_file(
        &self,
        Parameters(a): Parameters<ReadFileArgs>,
    ) -> Result<Json<ReadFileOutput>, CallToolResult> {
        let max = a.max_bytes.unwrap_or(DEFAULT_READ_BYTES);
        if max == 0 || max > MAX_READ_BYTES {
            return Err(invalid(format!(
                "max_bytes must be between 1 and {MAX_READ_BYTES}"
            )));
        }
        let id = self.resolve(a.sandbox_id).await?;
        let r = self
            .engine
            .read_file(&id, &a.path, a.offset.unwrap_or(0), max)
            .await
            .map_err(tool_error)?;
        let (content, encoding) = match String::from_utf8(r.content) {
            Ok(text) => (text, Encoding::Utf8),
            Err(e) => (B64.encode(e.into_bytes()), Encoding::Base64),
        };
        Ok(Json(ReadFileOutput {
            sandbox_id: id,
            path: a.path,
            content,
            encoding,
            size: r.size,
            truncated: r.truncated,
        }))
    }

    /// Create a new, empty sandbox and return its id, for running several sandboxes side by side. Most callers can skip this and rely on the session's default sandbox.
    #[tool(annotations(
        title = "Create sandbox",
        read_only_hint = false,
        destructive_hint = false,
        open_world_hint = false
    ))]
    async fn create_sandbox(
        &self,
        Parameters(a): Parameters<CreateSandboxArgs>,
    ) -> Result<Json<CreateSandboxOutput>, CallToolResult> {
        let profile = a.profile.unwrap_or_else(|| "default".into());
        if profile != "default" {
            return Err(invalid(format!(
                "unknown profile '{profile}' (available: default)"
            )));
        }
        let id = self.engine.claim().await.map_err(tool_error)?;
        self.session.own(&id);
        let cfg = self.engine.config();
        Ok(Json(CreateSandboxOutput {
            sandbox_id: id,
            profile,
            expires_in_sec: cfg.ttl.as_secs(),
            idle_timeout_sec: cfg.idle_timeout.as_secs(),
        }))
    }

    /// Destroy a sandbox and everything in it.
    #[tool(annotations(
        title = "Destroy sandbox",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = false
    ))]
    async fn destroy_sandbox(
        &self,
        Parameters(a): Parameters<DestroySandboxArgs>,
    ) -> Result<Json<DestroySandboxOutput>, CallToolResult> {
        let id =
            match a.sandbox_id {
                Some(id) => id,
                None => self.session.default.lock().await.take().ok_or_else(|| {
                    invalid("this session has no default sandbox; pass sandbox_id")
                })?,
            };
        self.engine.destroy(&id).await.map_err(tool_error)?;
        self.session.disown(&id);
        Ok(Json(DestroySandboxOutput {
            sandbox_id: id,
            destroyed: true,
        }))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for BoxentServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("boxent", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}
