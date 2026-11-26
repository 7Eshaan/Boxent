//! Wire protocol between the Boxent engine and the in-sandbox agent.
//!
//! Each message is one frame: a 4-byte big-endian length followed by that many bytes of CBOR.
//! CBOR keeps command output as raw bytes (output is often not valid UTF-8) while staying
//! self-describing, so fields can be added without breaking older peers.
//!
//! The engine treats everything the agent sends as untrusted: frame sizes are capped before any
//! allocation, and [`ExecResult::check`] verifies captured output against the requested caps.

mod capture;
mod client;
mod frame;
mod msg;

pub use capture::{Capture, Captured};
pub use client::{Client, ClientError};
pub use frame::{FrameError, MAX_FRAME, read_frame, write_frame};
pub use msg::*;

/// Bumped on any incompatible change to the messages below.
pub const PROTOCOL_VERSION: u32 = 1;
