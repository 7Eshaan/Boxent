//! Child reaping for PID 1.
//!
//! Every exited process in the sandbox ends up as our child: the commands we start and any
//! orphans they leave behind. One thread waits for SIGCHLD and reaps them all with
//! `waitpid(-1)`. Commands we started are registered, and their exit status is handed to the
//! waiting exec thread through an eventfd it can poll alongside its output pipes.

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex};

use super::sys;

/// Where a registered child's exit status is delivered.
pub struct ExitSlot {
    status: Mutex<Option<libc::c_int>>,
    ready: OwnedFd,
}

impl ExitSlot {
    /// Readable once the child has exited.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.ready.as_fd()
    }

    pub fn status(&self) -> Option<libc::c_int> {
        *self.status.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[derive(Default)]
pub struct Reaper {
    children: Mutex<HashMap<libc::pid_t, Arc<ExitSlot>>>,
}

impl Reaper {
    /// Runs `spawn` and registers the child it returns. The registry lock is held throughout, so
    /// the reaper cannot collect the child's status before it is registered.
    pub fn spawn_registered<T>(
        &self,
        spawn: impl FnOnce() -> io::Result<(libc::pid_t, T)>,
    ) -> io::Result<(Arc<ExitSlot>, T)> {
        let slot = Arc::new(ExitSlot {
            status: Mutex::new(None),
            ready: sys::eventfd()?,
        });
        let mut children = self.children.lock().unwrap_or_else(|e| e.into_inner());
        let (pid, extra) = spawn()?;
        children.insert(pid, Arc::clone(&slot));
        Ok((slot, extra))
    }

    /// Reaps every exited child. Called by the signal thread on SIGCHLD; signals coalesce, so
    /// this loops until no exited child remains.
    pub fn reap(&self) {
        let mut children = self.children.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let mut status = 0;
            // SAFETY: plain syscall writing into a local int.
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                break; // 0: children still running; -1/ECHILD: none left
            }
            if let Some(slot) = children.remove(&pid) {
                *slot.status.lock().unwrap_or_else(|e| e.into_inner()) = Some(status);
                sys::eventfd_signal(slot.fd());
            }
        }
    }
}
