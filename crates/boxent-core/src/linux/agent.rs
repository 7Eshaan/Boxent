//! Async connection to one sandbox's agent: many requests in flight, matched to responses by id.
//!
//! Everything the agent sends is untrusted. Frames are size-checked before allocation, replies
//! to unknown ids are dropped, and any malformed frame ends the connection (the engine then reaps
//! the sandbox). Deadlines are enforced here, not by the agent.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boxent_proto::{Envelope, MAX_FRAME, Request, Response, decode_body, encode_frame};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::oneshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    /// The connection is gone (agent exited, sandbox killed, or a bad frame).
    Disconnected,
    /// No answer within the deadline.
    Timeout,
}

#[derive(Default)]
struct Pending {
    waiters: HashMap<u64, oneshot::Sender<Response>>,
    closed: bool,
}

pub struct AgentConn {
    writer: tokio::sync::Mutex<OwnedWriteHalf>,
    pending: Arc<Mutex<Pending>>,
    alive: Arc<AtomicBool>,
    next_id: AtomicU64,
}

impl AgentConn {
    /// Takes over a connected socket. Must be called inside a Tokio runtime.
    pub fn new(stream: std::os::unix::net::UnixStream) -> std::io::Result<Self> {
        stream.set_nonblocking(true)?;
        let stream = tokio::net::UnixStream::from_std(stream)?;
        let (reader, writer) = stream.into_split();
        let pending = Arc::new(Mutex::new(Pending::default()));
        let alive = Arc::new(AtomicBool::new(true));
        tokio::spawn(read_loop(reader, Arc::clone(&pending), Arc::clone(&alive)));
        Ok(Self {
            writer: tokio::sync::Mutex::new(writer),
            pending,
            alive,
            next_id: AtomicU64::new(1),
        })
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    pub async fn call(&self, body: Request, deadline: Duration) -> Result<Response, CallError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut p = lock(&self.pending);
            if p.closed {
                return Err(CallError::Disconnected);
            }
            p.waiters.insert(id, tx);
        }
        let frame = encode_frame(&Envelope { id, body }).map_err(|_| self.forget(id))?;
        let sent = tokio::time::timeout(deadline, async {
            self.writer.lock().await.write_all(&frame).await
        })
        .await;
        match sent {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(self.forget(id)),
            Err(_) => {
                self.forget(id);
                return Err(CallError::Timeout);
            }
        }
        match tokio::time::timeout(deadline, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err(CallError::Disconnected),
            Err(_) => {
                self.forget(id);
                Err(CallError::Timeout)
            }
        }
    }

    fn forget(&self, id: u64) -> CallError {
        lock(&self.pending).waiters.remove(&id);
        CallError::Disconnected
    }
}

fn lock(p: &Mutex<Pending>) -> std::sync::MutexGuard<'_, Pending> {
    p.lock().unwrap_or_else(|e| e.into_inner())
}

async fn read_loop(
    mut reader: OwnedReadHalf,
    pending: Arc<Mutex<Pending>>,
    alive: Arc<AtomicBool>,
) {
    let reason = loop {
        let mut len = [0u8; 4];
        if let Err(e) = reader.read_exact(&mut len).await {
            break format!("read: {e}");
        }
        let len = u32::from_be_bytes(len);
        if len > MAX_FRAME {
            break format!("frame of {len} bytes exceeds the limit");
        }
        let mut body = vec![0u8; len as usize];
        if let Err(e) = reader.read_exact(&mut body).await {
            break format!("read: {e}");
        }
        let env: Envelope<Response> = match decode_body(&body) {
            Ok(env) => env,
            Err(e) => break format!("decode: {e}"),
        };
        if let Some(tx) = lock(&pending).waiters.remove(&env.id) {
            let _ = tx.send(env.body);
        }
    };
    alive.store(false, Ordering::Release);
    let mut p = lock(&pending);
    p.closed = true;
    p.waiters.clear(); // wakes every caller with Disconnected
    tracing::debug!(event = "agent_disconnected", reason = %reason);
}
