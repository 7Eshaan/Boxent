//! Length-prefixed CBOR framing.

use std::fmt;
use std::io::{self, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Largest frame either side accepts: room for a 10 MiB file write plus encoding overhead.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum FrameError {
    /// The peer closed the stream cleanly between frames.
    Closed,
    /// The length prefix exceeds the limit. The stream cannot be resynchronised after this.
    TooLarge {
        len: u32,
        max: u32,
    },
    Io(io::Error),
    Decode(String),
    Encode(String),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "peer closed the connection"),
            Self::TooLarge { len, max } => {
                write!(f, "frame of {len} bytes exceeds the {max}-byte limit")
            }
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::Decode(e) => write!(f, "malformed frame: {e}"),
            Self::Encode(e) => write!(f, "cannot encode frame: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Encodes `msg` and writes it as one frame. Refuses messages larger than [`MAX_FRAME`].
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), FrameError> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&[0; 4]);
    ciborium::into_writer(msg, &mut buf).map_err(|e| FrameError::Encode(e.to_string()))?;
    let len = u32::try_from(buf.len() - 4).unwrap_or(u32::MAX);
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge {
            len,
            max: MAX_FRAME,
        });
    }
    buf[..4].copy_from_slice(&len.to_be_bytes());
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

/// Reads one frame and decodes it. The length is checked against `max` before allocating.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R, max: u32) -> Result<T, FrameError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len);
    if len > max {
        return Err(FrameError::TooLarge { len, max });
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    ciborium::from_reader(body.as_slice()).map_err(|e| FrameError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Envelope, Request};

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        let msg = Envelope {
            id: 7,
            body: Request::Ping,
        };
        write_frame(&mut buf, &msg).unwrap();
        let back: Envelope<Request> = read_frame(&mut buf.as_slice(), MAX_FRAME).unwrap();
        assert_eq!(back.id, 7);
        assert!(matches!(back.body, Request::Ping));
    }

    #[test]
    fn oversized_length_is_rejected_before_allocating() {
        let mut buf = u32::MAX.to_be_bytes().to_vec();
        buf.extend_from_slice(b"junk");
        let err = read_frame::<_, Envelope<Request>>(&mut buf.as_slice(), MAX_FRAME).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge { len: u32::MAX, .. }));
    }

    #[test]
    fn clean_eof_is_closed_and_truncated_body_is_io() {
        let err = read_frame::<_, Envelope<Request>>(&mut [].as_slice(), MAX_FRAME).unwrap_err();
        assert!(matches!(err, FrameError::Closed));
        let mut buf = 10u32.to_be_bytes().to_vec();
        buf.extend_from_slice(b"abc");
        let err = read_frame::<_, Envelope<Request>>(&mut buf.as_slice(), MAX_FRAME).unwrap_err();
        assert!(matches!(err, FrameError::Io(_)));
    }

    #[test]
    fn garbage_body_is_a_decode_error() {
        let mut buf = 3u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0xff, 0xff, 0xff]);
        let err = read_frame::<_, Envelope<Request>>(&mut buf.as_slice(), MAX_FRAME).unwrap_err();
        assert!(matches!(err, FrameError::Decode(_)));
    }
}
