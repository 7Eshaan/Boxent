//! A blocking client for the agent protocol, used by the driver for the startup handshake, by the
//! development CLI and by tests. The daemon gets an async client in M3.

use std::io::{Read, Write};

use crate::{
    Caps, Envelope, ExecRequest, ExecResult, FrameError, HelloInfo, MAX_FRAME, PROTOCOL_VERSION,
    Request, Response, read_frame, write_frame,
};

#[derive(Debug)]
pub enum ClientError {
    Frame(FrameError),
    /// The agent answered with an error.
    Agent(crate::AgentError),
    /// The agent broke the protocol (wrong id, wrong response type, impossible values).
    Protocol(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "{e}"),
            Self::Agent(e) => write!(f, "agent error {:?}: {}", e.code, e.message),
            Self::Protocol(e) => write!(f, "agent protocol violation: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<FrameError> for ClientError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

pub struct Client<S> {
    stream: S,
    next_id: u64,
}

impl<S: Read + Write> Client<S> {
    pub fn new(stream: S) -> Self {
        Self { stream, next_id: 1 }
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Sends a request and waits for its response. Only one request may be outstanding.
    pub fn call(&mut self, body: Request) -> Result<Response, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        write_frame(&mut self.stream, &Envelope { id, body })?;
        let env: Envelope<Response> = read_frame(&mut self.stream, MAX_FRAME)?;
        if env.id != id {
            return Err(ClientError::Protocol(format!(
                "expected reply {id}, got {}",
                env.id
            )));
        }
        match env.body {
            Response::Error(e) => Err(ClientError::Agent(e)),
            other => Ok(other),
        }
    }

    pub fn hello(&mut self) -> Result<HelloInfo, ClientError> {
        match self.call(Request::Hello {
            protocol: PROTOCOL_VERSION,
        })? {
            Response::Hello(h) => Ok(h),
            other => Err(unexpected("Hello", &other)),
        }
    }

    pub fn exec(&mut self, req: ExecRequest) -> Result<ExecResult, ClientError> {
        let caps: Caps = req.caps();
        match self.call(Request::Exec(req))? {
            Response::Exec(r) => {
                r.check(caps).map_err(ClientError::Protocol)?;
                Ok(r)
            }
            other => Err(unexpected("Exec", &other)),
        }
    }
}

fn unexpected(want: &str, got: &Response) -> ClientError {
    ClientError::Protocol(format!("expected a {want} response, got {got:?}"))
}
