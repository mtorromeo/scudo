//! The shared file monitor: one eBPF object for the whole daemon.
//!
//! Unlike the network programs, which are loaded once per sandbox and attached
//! to its cgroup, these sit on syscall tracepoints and therefore run for every
//! process on the machine. There is no cgroup-scoped hook that sees a path
//! which was never resolved — an LSM hook runs after resolution has already
//! succeeded — so one object per sandbox would mean every `openat()` on the
//! system running one program per live sandbox. Instead this is loaded once,
//! the cgroups being watched go in a map, and each event says which one it
//! belongs to.
//!
//! It is loaded on the first sandbox that asks and unloaded with the last, so a
//! machine that is watching nothing pays nothing.
//!
//! The reader thread must not block, for the same reason the network one must
//! not: a watcher that has stopped reading costs reports, never enforcement.

use std::{
    collections::HashMap,
    os::fd::AsRawFd as _,
    sync::{Arc, Mutex, PoisonError, Weak},
};

use anyhow::{Context as _, Result};
use aya::{
    Ebpf, EbpfLoader,
    maps::{HashMap as BpfHashMap, MapData, PerCpuArray, RingBuf},
    programs::RawTracePoint,
};
use scudo_bpf_common::fs::{
    ERR_EACCES, ERR_ENOENT, ERR_EPERM, ERR_EROFS, FileEvent, OP_ACCESS, OP_CHDIR, OP_EXEC,
    OP_MKDIR, OP_OPEN, OP_READLINK, OP_RENAME, OP_STAT, OP_TRUNCATE, OP_UNLINK,
};

use crate::bpfd::{
    caps,
    events::Bus,
    outside::Checker,
    protocol::{FileError, FileOp, Notification},
    worker::{POLL_INTERVAL_MS, Shutdown, Worker},
};

/// The compiled programs, built by `build.rs` alongside the network ones.
static PROGRAM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/scudo-fs"));

/// The two tracepoints the object sits on, which are also its program names.
///
/// Not one per syscall: attaching a classic tracepoint means reading its id out
/// of `<tracefs>/events/…/id`, and tracefs is root-only on an ordinary system,
/// so no capability would get us there. A raw tracepoint is attached by name
/// through `bpf(2)` and touches no filesystem. Which syscalls are watched is
/// therefore decided inside the programs — see the `arch` module in
/// `ebpf/scudo-bpf-ebpf/src/fs.rs`.
///
/// Both are needed: without the entry there is no path, and without the exit
/// there is no error.
const PROGRAMS: [&str; 2] = ["sys_enter", "sys_exit"];

/// Where each sandbox's events go, by cgroup id.
type Routes = Mutex<HashMap<u64, Arc<Bus>>>;

/// The loaded object, its reader thread, and who each event belongs to.
pub struct Monitor {
    /// Keeping the object alive is what keeps the programs attached. The
    /// `WATCHED` map is taken out of it and lives in `watched` instead.
    _bpf: Ebpf,
    /// The kernel-side filter. Writing a cgroup into it is what starts the
    /// events flowing; taking it out is what stops them, and it happens before
    /// the route is dropped so nothing arrives for a bus that has gone.
    watched: Mutex<BpfHashMap<MapData, u64, u8>>,
    routes: Arc<Routes>,
    /// Held rather than read: dropping it ends the reader thread.
    _reader: Worker,
}

/// One sandbox's place in the monitor. Dropping it stops the reporting.
pub struct Watch {
    /// Weak, because the monitor owns every watch through its routes and the
    /// daemon owns the monitor: a strong reference here would keep the object
    /// loaded for as long as any watch existed, which is the wrong way round.
    monitor: Weak<Monitor>,
    cgroup_id: u64,
}

impl Drop for Watch {
    fn drop(&mut self) {
        if let Some(monitor) = self.monitor.upgrade() {
            monitor.unwatch(self.cgroup_id);
        }
    }
}

impl Monitor {
    /// Load the object and start reading. Fails when the daemon has not been
    /// granted `CAP_PERFMON`, which is the usual reason and worth naming.
    pub fn load() -> Result<Arc<Self>> {
        caps::check_perfmon().context("cannot report refused file accesses")?;

        let mut bpf = EbpfLoader::new()
            .load(PROGRAM)
            .context("loading the file monitor")?;

        // Both or neither: one half on its own reports nothing, and leaving it
        // attached would be a cost paid by every syscall on the machine for no
        // return.
        for name in PROGRAMS {
            attach_one(&mut bpf, name)
                .with_context(|| format!("attaching the {name} tracepoint"))?;
        }

        let watched: BpfHashMap<_, u64, u8> = bpf
            .take_map("WATCHED")
            .context("eBPF object has no WATCHED map")?
            .try_into()
            .context("WATCHED is not a hash map")?;
        let ring: RingBuf<MapData> = bpf
            .take_map("EVENTS")
            .context("eBPF object has no EVENTS map")?
            .try_into()
            .context("EVENTS is not a ring buffer")?;
        let dropped: PerCpuArray<MapData, u64> = bpf
            .take_map("DROPPED")
            .context("eBPF object has no DROPPED map")?
            .try_into()
            .context("DROPPED is not a per-CPU array")?;

        let routes: Arc<Routes> = Arc::new(Mutex::new(HashMap::new()));
        let reader_routes = Arc::clone(&routes);
        let reader = Worker::spawn("fs-events", move |stop| {
            read_events(ring, &dropped, &reader_routes, stop);
        })?;

        Ok(Arc::new(Monitor {
            _bpf: bpf,
            watched: Mutex::new(watched),
            routes,
            _reader: reader,
        }))
    }

    /// Start reporting this cgroup's refused file accesses onto `bus`.
    ///
    /// The route goes in before the kernel-side filter, so there is no moment
    /// in which an event arrives with nowhere to go.
    pub fn watch(self: &Arc<Self>, cgroup_id: u64, bus: Arc<Bus>) -> Result<Watch> {
        lock(&self.routes).insert(cgroup_id, bus);
        if let Err(err) = lock(&self.watched).insert(cgroup_id, 1u8, 0) {
            lock(&self.routes).remove(&cgroup_id);
            return Err(anyhow::Error::from(err).context("watching the sandbox's cgroup"));
        }
        Ok(Watch {
            monitor: Arc::downgrade(self),
            cgroup_id,
        })
    }

    /// Stop the events at the kernel before dropping the route, so the reader
    /// never has to wonder where a late one belongs.
    fn unwatch(&self, cgroup_id: u64) {
        drop(lock(&self.watched).remove(&cgroup_id));
        lock(&self.routes).remove(&cgroup_id);
    }

    /// Is anyone still being watched? The daemon drops the monitor when nobody
    /// is, which detaches the tracepoints.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        lock(&self.routes).is_empty()
    }
}

/// Load and attach one program. Its name is also its tracepoint's.
fn attach_one(bpf: &mut Ebpf, name: &str) -> Result<()> {
    let program: &mut RawTracePoint = bpf
        .program_mut(name)
        .context("no such program in the object")?
        .try_into()
        .context("not a raw tracepoint program")?;
    program.load().context("loading")?;
    program.attach(name).context("attaching")?;
    Ok(())
}

/// A poisoned lock would mean a thread panicked mid-update. Nothing here is
/// worth propagating that: the worst a partly-updated table can do is misroute
/// one report.
fn lock<T>(what: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    what.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Drain the ring buffer onto the buses until the monitor goes away.
fn read_events(
    mut ring: RingBuf<MapData>,
    dropped: &PerCpuArray<MapData, u64>,
    routes: &Routes,
    stop: &Shutdown,
) {
    // The wakeup goes in the same wait as the ring buffer, so a teardown does
    // not have to sit out the rest of the interval.
    let mut fds = [
        libc::pollfd {
            fd: ring.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stop.wake_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // The cache lives here, so it is warm for the whole run and belongs to one
    // thread: a program resolving modules asks the same question repeatedly.
    let mut checker = Checker::new();
    let mut reported = 0u64;

    while !stop.stopping() {
        while let Some(item) = ring.next() {
            let Some((event, path)) = FileEvent::from_bytes(&item) else {
                continue;
            };
            // The route is looked up first: going to the filesystem for a
            // sandbox that has already gone would be work for nothing.
            let Some(bus) = lock(routes).get(&event.cgroup_id).map(Arc::clone) else {
                continue;
            };
            if let Some(notification) = notification(&event, path, &mut checker) {
                bus.publish(notification);
            }
        }
        // Whatever the kernel could not fit in while we were away, reported as
        // a delta because the counters only ever go up. It is shared across
        // sandboxes, so it goes to everyone currently being watched: a loss
        // cannot be attributed, and saying nothing would be worse.
        let total = total_dropped(dropped);
        if total > reported {
            let lost = total.saturating_sub(reported);
            for bus in lock(routes).values() {
                bus.note_lost(lost);
            }
            reported = total;
        }
        // SAFETY: fds is a live, correctly sized array of pollfd.
        unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                fds.len() as libc::nfds_t,
                POLL_INTERVAL_MS,
            );
        }
    }
}

/// The per-CPU tallies of events that did not fit, added up.
fn total_dropped(dropped: &PerCpuArray<MapData, u64>) -> u64 {
    dropped.get(&0, 0).map_or(0, |values| {
        values.iter().copied().fold(0u64, u64::saturating_add)
    })
}

/// Turn one event from the kernel into the message a watcher reads.
///
/// An event whose fields name nothing we know is dropped rather than guessed
/// at: the two ends are built together, so it would mean the object and the
/// daemon had come apart.
fn notification(event: &FileEvent, path: &[u8], checker: &mut Checker) -> Option<Notification> {
    let op = match event.op {
        OP_OPEN => FileOp::Open,
        OP_STAT => FileOp::Stat,
        OP_ACCESS => FileOp::Access,
        OP_EXEC => FileOp::Exec,
        OP_READLINK => FileOp::Readlink,
        OP_UNLINK => FileOp::Unlink,
        OP_MKDIR => FileOp::Mkdir,
        OP_RENAME => FileOp::Rename,
        OP_CHDIR => FileOp::Chdir,
        OP_TRUNCATE => FileOp::Truncate,
        _ => return None,
    };
    let error = match event.errno {
        ERR_ENOENT => FileError::NotFound,
        // Two errnos for one story: both are what an inaccessible path gives,
        // and the difference between them is not the sandbox's.
        ERR_EACCES | ERR_EPERM => FileError::Permission,
        ERR_EROFS => FileError::ReadOnly,
        _ => return None,
    };
    let (path, outside) = checker.check(path, event.dirfd, event.pid, event.truncated());
    Some(Notification::FileBlocked {
        op,
        path,
        error,
        outside,
    })
}

#[cfg(test)]
#[expect(
    clippy::non_ascii_literal,
    reason = "the ellipsis, spelled the way the assertion reads best"
)]
mod tests {
    use super::*;
    use crate::bpfd::protocol::Outside;
    use scudo_bpf_common::fs::{AT_FDCWD, FLAG_TRUNCATED};

    fn event(op: u8, errno: i32, path: &[u8]) -> FileEvent {
        FileEvent {
            cgroup_id: 1,
            pid: std::process::id(),
            errno,
            dirfd: AT_FDCWD,
            op,
            flags: 0,
            len: u16::try_from(path.len()).expect("a short test path"),
        }
    }

    #[test]
    fn an_event_names_the_path_and_what_was_done_to_it() {
        let mut checker = Checker::new();
        let got = notification(&event(OP_OPEN, ERR_ENOENT, b"/"), b"/", &mut checker);
        assert_eq!(
            got,
            Some(Notification::FileBlocked {
                op: FileOp::Open,
                path: "/".to_owned(),
                error: FileError::NotFound,
                // The daemon is outside the sandbox, so it can see that this
                // one is really there.
                outside: Outside::Present,
            })
        );
    }

    /// The two errnos an inaccessible path can give tell one story.
    #[test]
    fn permission_is_one_answer_however_the_kernel_spelled_it() {
        let mut checker = Checker::new();
        for errno in [ERR_EACCES, ERR_EPERM] {
            let got = notification(&event(OP_STAT, errno, b"/etc"), b"/etc", &mut checker);
            assert!(
                matches!(
                    got,
                    Some(Notification::FileBlocked {
                        error: FileError::Permission,
                        ..
                    })
                ),
                "errno {errno} gave {got:?}"
            );
        }
    }

    /// A cut path is reported, marked, and never looked for.
    #[test]
    fn a_cut_path_is_marked_and_left_unanswered() {
        let mut checker = Checker::new();
        let mut cut = event(OP_OPEN, ERR_ENOENT, b"/");
        cut.flags = FLAG_TRUNCATED;
        let got = notification(&cut, b"/", &mut checker);
        assert_eq!(
            got,
            Some(Notification::FileBlocked {
                op: FileOp::Open,
                path: "/…".to_owned(),
                error: FileError::NotFound,
                outside: Outside::Unknown,
            })
        );
    }

    /// A field naming something we do not know means the object and the daemon
    /// have come apart; inventing a plausible event would be worse than none.
    #[test]
    fn an_event_we_cannot_read_is_dropped() {
        let mut checker = Checker::new();
        assert_eq!(
            notification(&event(200, ERR_ENOENT, b"/"), b"/", &mut checker),
            None
        );
        assert_eq!(
            notification(&event(OP_OPEN, 99, b"/"), b"/", &mut checker),
            None
        );
    }

    /// Every operation the programs can report has a name on the wire.
    #[test]
    fn every_operation_is_covered() {
        let mut checker = Checker::new();
        for op in [
            OP_OPEN,
            OP_STAT,
            OP_ACCESS,
            OP_EXEC,
            OP_READLINK,
            OP_UNLINK,
            OP_MKDIR,
            OP_RENAME,
            OP_CHDIR,
            OP_TRUNCATE,
        ] {
            assert!(
                notification(&event(op, ERR_ENOENT, b"/"), b"/", &mut checker).is_some(),
                "op {op} has no notification"
            );
        }
    }

    /// Raw tracepoints, not classic ones — the whole reason the daemon can
    /// attach these at all without being root. A `tracepoint/syscalls/…`
    /// section creeping back in would load fine and then fail to attach on any
    /// ordinary machine, where tracefs is `drwx------ root`.
    #[test]
    fn the_object_carries_two_raw_tracepoints_and_no_classic_ones() {
        let object = String::from_utf8_lossy(PROGRAM);
        for name in PROGRAMS {
            let section = format!("raw_tp/{name}");
            assert!(
                object.contains(&section),
                "the object has no {section} program"
            );
        }
        assert!(
            !object.contains("tracepoint/syscalls/"),
            "a classic tracepoint cannot be attached without root"
        );
    }
}
