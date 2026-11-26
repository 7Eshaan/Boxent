//! Keeps reading (and discarding) output pipes that background processes still hold after their
//! command returned, until those processes close them.

use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::sync::Mutex;

use super::sys;

pub struct Drainer {
    fds: Mutex<Vec<OwnedFd>>,
    wake: OwnedFd,
}

impl Drainer {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            fds: Mutex::new(Vec::new()),
            wake: sys::eventfd()?,
        })
    }

    pub fn adopt(&self, fd: OwnedFd) {
        self.fds.lock().unwrap_or_else(|e| e.into_inner()).push(fd);
        sys::eventfd_signal(self.wake.as_fd());
    }

    /// Runs forever on its own thread.
    pub fn run(&self) {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let raw: Vec<RawFd> = self
                .fds
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .map(AsRawFd::as_raw_fd)
                .collect();
            let mut pfds: Vec<libc::pollfd> = std::iter::once(self.wake.as_raw_fd())
                .chain(raw.iter().copied())
                .map(|fd| libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            if sys::poll(&mut pfds, None).is_err() {
                continue;
            }
            if pfds[0].revents != 0 {
                sys::eventfd_clear(self.wake.as_fd());
            }
            let mut finished = Vec::new();
            for p in &pfds[1..] {
                if p.revents == 0 {
                    continue;
                }
                for _ in 0..16 {
                    match sys::read_nb(p.fd, &mut buf) {
                        Ok(Some(0)) | Err(_) => {
                            finished.push(p.fd);
                            break;
                        }
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                    }
                }
            }
            if !finished.is_empty() {
                self.fds
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|fd| !finished.contains(&fd.as_raw_fd()));
            }
        }
    }
}
