//! Head-and-tail output capture.
//!
//! A command may write gigabytes; only the first `head_max` and last `tail_max` bytes are kept,
//! plus the total count. Errors usually sit at the end of the output, so the tail is the larger
//! part by default.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// Accumulates a stream, keeping only its head and tail. Memory use is bounded by the caps.
#[derive(Debug)]
pub struct Capture {
    head: Vec<u8>,
    head_max: usize,
    tail: VecDeque<u8>,
    tail_max: usize,
    total: u64,
}

impl Capture {
    pub fn new(head_max: usize, tail_max: usize) -> Self {
        Self {
            head: Vec::with_capacity(head_max.min(4096)),
            head_max,
            tail: VecDeque::with_capacity(tail_max.min(4096)),
            tail_max,
            total: 0,
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.total += data.len() as u64;
        let take = (self.head_max - self.head.len()).min(data.len());
        self.head.extend_from_slice(&data[..take]);
        let rest = &data[take..];
        if self.tail_max == 0 || rest.is_empty() {
            return;
        }
        if rest.len() >= self.tail_max {
            self.tail.clear();
            self.tail.extend(&rest[rest.len() - self.tail_max..]);
        } else {
            self.tail.extend(rest);
            let excess = self.tail.len().saturating_sub(self.tail_max);
            self.tail.drain(..excess);
        }
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn finish(self) -> Captured {
        let tail: Vec<u8> = self.tail.into();
        let kept = (self.head.len() + tail.len()) as u64;
        Captured {
            truncated: self.total > kept,
            head: self.head,
            tail,
            total: self.total,
        }
    }
}

/// Captured output as sent on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Captured {
    #[serde(with = "serde_bytes")]
    pub head: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub tail: Vec<u8>,
    /// Bytes the stream produced in total.
    pub total: u64,
    /// True when bytes between head and tail were dropped.
    pub truncated: bool,
}

impl Captured {
    /// Bytes dropped between head and tail.
    pub fn omitted(&self) -> u64 {
        self.total
            .saturating_sub((self.head.len() + self.tail.len()) as u64)
    }

    /// Checks the invariants an honest agent upholds; used by the engine on untrusted input.
    pub fn is_consistent(&self, head_max: usize, tail_max: usize) -> bool {
        let kept = (self.head.len() + self.tail.len()) as u64;
        self.head.len() <= head_max
            && self.tail.len() <= tail_max
            && self.total >= kept
            && self.truncated == (self.total > kept)
            && (self.tail.is_empty() || self.head.len() == head_max)
    }

    /// Renders as text. Invalid UTF-8 becomes U+FFFD; when truncated, the cut points are moved
    /// to character boundaries and a marker states how many bytes were left out.
    pub fn render(&self) -> String {
        if !self.truncated {
            let mut all = self.head.clone();
            all.extend_from_slice(&self.tail);
            return String::from_utf8_lossy(&all).into_owned();
        }
        let head = trim_incomplete_end(&self.head);
        let tail = trim_continuation_start(&self.tail);
        format!(
            "{}\n[... {} bytes omitted ...]\n{}",
            String::from_utf8_lossy(head),
            self.omitted(),
            String::from_utf8_lossy(tail)
        )
    }
}

/// Drops a multi-byte UTF-8 sequence cut off at the end of `b`.
fn trim_incomplete_end(b: &[u8]) -> &[u8] {
    // Look back at most 3 bytes for the lead byte of the last sequence.
    for back in 1..=b.len().min(4) {
        let i = b.len() - back;
        let byte = b[i];
        if byte & 0b1100_0000 == 0b1000_0000 {
            continue; // continuation byte, keep looking
        }
        let need = match byte {
            0x00..=0x7f => 1,
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            _ => return b, // not UTF-8 anyway; leave it to lossy decoding
        };
        return if back < need { &b[..i] } else { b };
    }
    b
}

/// Drops continuation bytes at the start of `b` (the rest of a sequence cut at the front).
fn trim_continuation_start(b: &[u8]) -> &[u8] {
    let skip = b
        .iter()
        .take(3)
        .take_while(|&&x| x & 0b1100_0000 == 0b1000_0000)
        .count();
    &b[skip..]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(chunks: &[&[u8]], head: usize, tail: usize) -> Captured {
        let mut c = Capture::new(head, tail);
        for ch in chunks {
            c.push(ch);
        }
        c.finish()
    }

    /// Reference model: the whole stream, then cut.
    fn model(all: &[u8], head: usize, tail: usize) -> (Vec<u8>, Vec<u8>) {
        let h = all[..head.min(all.len())].to_vec();
        let rest = &all[h.len()..];
        let t = rest[rest.len().saturating_sub(tail)..].to_vec();
        (h, t)
    }

    #[test]
    fn short_output_is_kept_whole() {
        let c = capture(&[b"hello ", b"world"], 16, 48);
        assert!(!c.truncated);
        assert_eq!(c.render(), "hello world");
        assert_eq!(c.total, 11);
    }

    #[test]
    fn matches_model_for_many_chunkings() {
        let all: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        for (head, tail) in [
            (0, 0),
            (0, 10),
            (10, 0),
            (16, 48),
            (100, 1000),
            (4999, 1),
            (6000, 6000),
        ] {
            for chunk in [1, 7, 64, 999, 5000] {
                let chunks: Vec<&[u8]> = all.chunks(chunk).collect();
                let c = capture(&chunks, head, tail);
                let (h, t) = model(&all, head, tail);
                assert_eq!(c.head, h, "head={head} tail={tail} chunk={chunk}");
                assert_eq!(c.tail, t, "head={head} tail={tail} chunk={chunk}");
                assert_eq!(c.total, 5000);
                assert!(c.is_consistent(head, tail));
            }
        }
    }

    #[test]
    fn truncated_render_marks_the_gap() {
        let all = vec![b'x'; 1000];
        let c = capture(&[&all], 10, 20);
        assert!(c.truncated);
        assert_eq!(c.omitted(), 970);
        assert!(c.render().contains("[... 970 bytes omitted ...]"));
    }

    #[test]
    fn cuts_land_on_char_boundaries() {
        // "é" is 2 bytes, "€" is 3: cut both in the middle.
        let text = "aé€".repeat(100);
        let c = capture(&[text.as_bytes()], 5, 7);
        let out = c.render();
        assert!(!out.contains('\u{fffd}'), "{out:?}");
    }

    #[test]
    fn invalid_utf8_is_replaced_not_dropped() {
        let c = capture(&[&[0x66, 0xff, 0x6f]], 16, 16);
        assert_eq!(c.render(), "f\u{fffd}o");
    }

    #[test]
    fn inconsistent_results_are_detected() {
        let mut c = capture(&[b"abc"], 16, 16);
        assert!(c.is_consistent(16, 16));
        c.total = 1;
        assert!(!c.is_consistent(16, 16));
        let c = capture(&[&[0u8; 100]], 10, 10);
        assert!(!c.is_consistent(5, 10), "head larger than the cap");
    }
}
