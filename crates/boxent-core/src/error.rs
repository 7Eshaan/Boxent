//! Engine errors with stable codes, which the MCP layer returns to clients as-is.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// No sandbox with this id ever existed (or it was reaped long ago).
    SandboxNotFound,
    /// The sandbox existed but was reaped; the message says why.
    SandboxReaped,
    /// Every sandbox slot is in use and none freed up in time.
    PoolExhausted,
    InvalidArgument,
    InvalidPath,
    NotFound,
    PermissionDenied,
    FileTooLarge,
    /// The command could not be started.
    SpawnFailed,
    /// The agent stopped answering or broke the protocol; the sandbox was reaped.
    AgentFailed,
    /// The sandbox's disk budget (workspace, home and snapshots together) is used up.
    QuotaExceeded,
    SnapshotNotFound,
    /// The sandbox already has the maximum number of snapshots; delete one first.
    SnapshotLimit,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SandboxNotFound => "sandbox_not_found",
            Self::SandboxReaped => "sandbox_reaped",
            Self::PoolExhausted => "pool_exhausted",
            Self::InvalidArgument => "invalid_argument",
            Self::InvalidPath => "invalid_path",
            Self::NotFound => "not_found",
            Self::PermissionDenied => "permission_denied",
            Self::FileTooLarge => "file_too_large",
            Self::SpawnFailed => "spawn_failed",
            Self::AgentFailed => "agent_failed",
            Self::QuotaExceeded => "quota_exceeded",
            Self::SnapshotNotFound => "snapshot_not_found",
            Self::SnapshotLimit => "snapshot_limit",
            Self::Internal => "internal",
        }
    }
}

/// Why a sandbox was reaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapReason {
    Destroyed,
    Idle,
    Ttl,
    AgentFailed,
    /// Warm sandbox past its maximum age, or unhealthy before being claimed.
    Retired,
    Shutdown,
    /// A restore failed halfway; the sandbox's files were in an unknown state.
    RestoreFailed,
}

impl ReapReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Destroyed => "destroyed",
            Self::Idle => "idle",
            Self::Ttl => "ttl",
            Self::AgentFailed => "agent_failed",
            Self::Retired => "retired",
            Self::Shutdown => "shutdown",
            Self::RestoreFailed => "restore_failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EngineError {
    pub code: ErrorCode,
    pub message: String,
}

impl EngineError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn internal(message: impl fmt::Display) -> Self {
        Self::new(ErrorCode::Internal, message.to_string())
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for EngineError {}

impl From<boxent_proto::AgentError> for EngineError {
    fn from(e: boxent_proto::AgentError) -> Self {
        use boxent_proto::ErrorCode as A;
        let code = match e.code {
            A::InvalidRequest => ErrorCode::InvalidArgument,
            A::InvalidPath | A::WrongType => ErrorCode::InvalidPath,
            A::NotFound => ErrorCode::NotFound,
            A::PermissionDenied => ErrorCode::PermissionDenied,
            A::TooLarge => ErrorCode::FileTooLarge,
            A::SpawnFailed => ErrorCode::SpawnFailed,
            A::NoSpace => ErrorCode::QuotaExceeded,
            A::Io => ErrorCode::Internal,
        };
        Self::new(code, e.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_errors_map_to_stable_codes() {
        let e: EngineError =
            boxent_proto::AgentError::new(boxent_proto::ErrorCode::WrongType, "dir").into();
        assert_eq!(e.code, ErrorCode::InvalidPath);
        assert_eq!(e.to_string(), "invalid_path: dir");
        assert_eq!(ReapReason::Ttl.as_str(), "ttl");
    }
}
