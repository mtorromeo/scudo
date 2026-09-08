//! A thread that belongs to one loaded object, and the handle that ends it.
//!
//! Both the ring buffer readers and the per-sandbox DNS resolver are the same
//! shape: a loop that sleeps in `poll` until there is something to do, and
//! wakes on a timer besides so that counters and expiries are picked up even
//! when nothing arrives. Dropping the thing that owns one has to end it and
//! wait, or the maps it holds would outlive the object they came from.
//!
//! **Being told to stop is a thing to wait on, not a flag to notice later.**
//! The obvious shape — set an `AtomicBool` and join — makes every teardown
//! take up to a full poll interval, and these are torn down under the daemon's
//! state lock on the path every command takes to register. Half a second there
//! is half a second added to a command that has not started yet, so the flag is
//! paired with a pipe the body polls alongside its own work.

use core::sync::atomic::{AtomicBool, Ordering};
use std::{
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd},
    sync::Arc,
    thread::JoinHandle,
};

use anyhow::{Context as _, Result};

/// How long a worker sleeps before waking of its own accord.
///
/// This is the *timer*, not the teardown latency: what a worker has to do on a
/// tick regardless of traffic is pick up the counters of what the kernel could
/// not deliver, and let a DNS entry's TTL run out.
pub const POLL_INTERVAL_MS: i32 = 500;

/// What a worker's body waits on, and what tells it to stop.
pub struct Shutdown {
    stopping: Arc<AtomicBool>,
    /// The read end of the pipe [`Worker::stop`] writes to. A body polls this
    /// alongside its own descriptors, so it stops when asked rather than at the
    /// end of the interval it happened to be in.
    wake: OwnedFd,
}

impl Shutdown {
    /// Has the owner asked this thread to finish?
    #[must_use]
    pub fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }

    /// The descriptor to add to a `poll` set, so the wait ends immediately.
    #[must_use]
    pub fn wake_fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }
}

pub struct Worker {
    stopping: Arc<AtomicBool>,
    /// The write end. Dropped with the worker, which is a second way the body
    /// learns to stop: the read end then reports end-of-file.
    wake: Option<OwnedFd>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    /// Start `body` on a named thread, handing it what it waits on.
    pub fn spawn<F>(name: &str, body: F) -> Result<Self>
    where
        F: FnOnce(&Shutdown) + Send + 'static,
    {
        let (read, write) = wakeup_pipe()?;
        let stopping = Arc::new(AtomicBool::new(false));
        let shutdown = Shutdown {
            stopping: Arc::clone(&stopping),
            wake: read,
        };
        let handle = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || body(&shutdown))
            .with_context(|| format!("starting the {name} thread"))?;
        Ok(Worker {
            stopping,
            wake: Some(write),
            handle: Some(handle),
        })
    }

    /// Ask the thread to stop and wait for it.
    ///
    /// The flag is set before the pipe is written, so a body that wakes on the
    /// byte always sees the flag that goes with it.
    pub fn stop(&mut self) {
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(wake) = self.wake.as_ref() {
            let byte = 1u8;
            // SAFETY: writing one byte from a local into a pipe we own. It is
            // non-blocking: a pipe already full has a wakeup pending in it, so
            // a refused write has nothing to report.
            let written = unsafe { libc::write(wake.as_raw_fd(), (&raw const byte).cast(), 1) };
            let _: isize = written;
        }
        if let Some(handle) = self.handle.take() {
            drop(handle.join());
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A pipe whose only message is "stop".
///
/// Non-blocking so that [`Worker::stop`] can never wait on a reader that has
/// already gone, and close-on-exec because nothing we start has any business
/// inheriting it.
fn wakeup_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    // SAFETY: pipe2 writes two descriptors into an array of exactly that size.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if rc != 0i32 {
        return Err(std::io::Error::last_os_error()).context("creating a wakeup pipe");
    }
    let read = *fds.first().context("pipe2 returned no read end")?;
    let write = *fds.get(1).context("pipe2 returned no write end")?;
    // SAFETY: pipe2 has just handed us a descriptor nobody else owns.
    let read = unsafe { OwnedFd::from_raw_fd(read) };
    // SAFETY: as above.
    let write = unsafe { OwnedFd::from_raw_fd(write) };
    Ok((read, write))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };

    /// The point of the pipe: a worker asleep for the whole interval still
    /// stops at once. Half a second here is half a second added to a command
    /// waiting to register.
    #[test]
    fn a_sleeping_worker_stops_without_waiting_out_its_interval() {
        let (tx, rx) = mpsc::channel();
        let mut worker = Worker::spawn("test", move |stop| {
            // Tell the test we are in the loop, then sleep exactly as the ring
            // buffer readers do.
            tx.send(()).expect("the test is still listening");
            while !stop.stopping() {
                let mut fds = [libc::pollfd {
                    fd: stop.wake_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                }];
                // SAFETY: a live, correctly sized array of pollfd.
                unsafe {
                    libc::poll(fds.as_mut_ptr(), 1, POLL_INTERVAL_MS);
                }
            }
        })
        .expect("the thread starts");

        rx.recv().expect("the worker reaches its loop");
        let start = Instant::now();
        worker.stop();
        let took = start.elapsed();
        assert!(
            took < Duration::from_millis(200),
            "stopping took {took:?}, which is most of a poll interval"
        );
    }

    /// Dropping is stopping: a thread holding a map must not outlive the
    /// object the map came from. The drop joins, so the flag is set by the time
    /// it returns or not at all.
    #[test]
    fn dropping_a_worker_ends_its_thread() {
        let finished = Arc::new(AtomicBool::new(false));
        let thread_finished = Arc::clone(&finished);
        let worker = Worker::spawn("test", move |stop| {
            while !stop.stopping() {
                std::thread::sleep(Duration::from_millis(5));
            }
            thread_finished.store(true, Ordering::Relaxed);
        })
        .expect("the thread starts");

        drop(worker);
        assert!(
            finished.load(Ordering::Relaxed),
            "the thread was not joined"
        );
    }
}
