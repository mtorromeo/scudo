//! The ABI for reporting file accesses a sandbox turned away.
//!
//! Unlike the network side, nothing here is a verdict: systemd applies the
//! filesystem restrictions by rearranging the unit's mount namespace, and all
//! the eBPF programs do is notice a syscall coming back with an error a sandbox
//! could have caused. The verdict was made before we ever saw it.
//!
//! One event is a fixed header followed by the path, which is why the programs
//! write it with `bpf_ringbuf_output` rather than `reserve::<T>()`: a reserved
//! type has to be one size, and that size would have to be [`MAX_PATH`] for
//! every `/etc/hosts` in the stream.

/// What the sandbox was trying to do with the path.
///
/// Only operations that name a path are here. A syscall working on a file
/// descriptor has already got past the sandbox — the open that produced the
/// descriptor is the one that would have been refused.
pub const OP_OPEN: u8 = 0;
pub const OP_STAT: u8 = 1;
pub const OP_ACCESS: u8 = 2;
pub const OP_EXEC: u8 = 3;
pub const OP_READLINK: u8 = 4;
pub const OP_UNLINK: u8 = 5;
pub const OP_MKDIR: u8 = 6;
pub const OP_RENAME: u8 = 7;
pub const OP_CHDIR: u8 = 8;
pub const OP_TRUNCATE: u8 = 9;

/// The path did not fit in [`MAX_PATH`] and was cut short.
///
/// A truncated path names a different file from the one that was asked for, so
/// whoever reads it must not go and look for it: the answer would be about
/// something else.
pub const FLAG_TRUNCATED: u8 = 1 << 0;

/// The errors a sandbox can be the cause of.
///
/// `ENOENT` is what a path hidden behind `TemporaryFileSystem=` or `PrivateTmp=`
/// looks like, `EACCES`/`EPERM` what `InaccessiblePaths=` produces, and `EROFS`
/// what writing under `ReadOnlyPaths=` or `ProtectSystem=` gets. Everything
/// else the kernel can return says nothing about the sandbox and is left alone.
pub const ERR_EPERM: i32 = 1;
pub const ERR_ENOENT: i32 = 2;
pub const ERR_EACCES: i32 = 13;
pub const ERR_EROFS: i32 = 30;

/// Is this the kind of failure a sandbox could have caused?
#[inline(always)]
#[must_use]
pub const fn is_sandbox_errno(errno: i32) -> bool {
    matches!(errno, ERR_EPERM | ERR_ENOENT | ERR_EACCES | ERR_EROFS)
}

/// `AT_FDCWD`, as it reaches us from a syscall that has no directory argument.
pub const AT_FDCWD: i32 = -100;

/// How many sandboxes the shared monitor can watch at once.
///
/// This is the daemon's own `MAX_SANDBOXES`: one entry per sandbox that asked
/// for file reporting, and the daemon refuses to hold more sandboxes than that
/// in the first place. A test on the daemon side keeps the two in step.
pub const MAX_WATCHED: u32 = 128;

/// How many threads may be inside a traced syscall at once.
///
/// The map is an LRU, so this is a working set and not a limit: past it, the
/// oldest thread in flight loses the path it stashed and its refusal goes
/// unreported. It is global rather than per sandbox, hence the headroom.
pub const MAX_PENDING: u32 = 4096;

/// How much of a path is reported. Beyond this it is cut and flagged.
///
/// This is the size of the per-CPU scratch buffer the programs build an event
/// in, so it is paid for once per CPU and not per event. `PATH_MAX` is 4096,
/// but a path that long is vanishingly rare next to the cost of carrying room
/// for one through every event.
pub const MAX_PATH: usize = 512;

/// How much ring buffer the shared file monitor gets. The kernel wants a
/// power-of-two multiple of the page size.
///
/// Larger than the network one because these events are larger and arrive in
/// bursts: a program resolving modules or searching a library path produces
/// hundreds of refusals in a few milliseconds.
pub const FS_EVENTS_BYTES: u32 = 512 * 1024;

/// The header of one refused file access, followed by `len` bytes of path.
///
/// The `u64` comes first so the alignment stays at 8: `bpf_ringbuf_output`
/// cannot hand out memory aligned to more than that, and aya turns a stricter
/// type into a panic that shows up as a load failure.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileEvent {
    /// Which sandbox this belongs to. The programs are attached system-wide and
    /// one object serves every sandbox, so unlike the network side the event
    /// has to say whose it is.
    pub cgroup_id: u64,
    /// The thread that made the call, so a relative path can be resolved
    /// against `/proc/<pid>/cwd` or `/proc/<pid>/fd/<dirfd>`.
    pub pid: u32,
    /// Positive, one of the `ERR_*` above.
    pub errno: i32,
    /// The directory the path is relative to, or [`AT_FDCWD`]. Meaningless for
    /// an absolute path, which is the usual case.
    pub dirfd: i32,
    /// One of the `OP_*` above.
    pub op: u8,
    /// [`FLAG_TRUNCATED`], or zero.
    pub flags: u8,
    /// Path bytes following this header, the trailing NUL not counted.
    pub len: u16,
}

/// The fixed part of an event, before the path.
pub const FILE_EVENT_HEADER: usize = size_of::<FileEvent>();

impl FileEvent {
    /// Read one event, and the path that came with it, back out of the ring
    /// buffer.
    ///
    /// Both ends are the same machine and the same object, so the integers are
    /// in native order — this is a cast written out longhand, not a decoder.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let header = bytes.get(..FILE_EVENT_HEADER)?;
        let event = FileEvent {
            cgroup_id: u64::from_ne_bytes(header.get(0..8)?.try_into().ok()?),
            pid: u32::from_ne_bytes(header.get(8..12)?.try_into().ok()?),
            errno: i32::from_ne_bytes(header.get(12..16)?.try_into().ok()?),
            dirfd: i32::from_ne_bytes(header.get(16..20)?.try_into().ok()?),
            op: *header.get(20)?,
            flags: *header.get(21)?,
            len: u16::from_ne_bytes(header.get(22..24)?.try_into().ok()?),
        };
        // A record whose header promises more path than arrived is one the two
        // ends disagree about; reading it would mean reading past the event.
        let path = bytes.get(FILE_EVENT_HEADER..FILE_EVENT_HEADER + event.len as usize)?;
        Some((event, path))
    }

    /// Was the path cut short?
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.flags & FLAG_TRUNCATED != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(event: &FileEvent) -> [u8; FILE_EVENT_HEADER] {
        // SAFETY: FileEvent is repr(C), Copy, and every byte of it is written
        // by the caller — the field layout leaves no padding to observe.
        unsafe { core::mem::transmute(*event) }
    }

    fn event(len: u16) -> FileEvent {
        FileEvent {
            cgroup_id: 0xdead_beef,
            pid: 4242,
            errno: ERR_ENOENT,
            dirfd: AT_FDCWD,
            op: OP_OPEN,
            flags: 0,
            len,
        }
    }

    /// The layout both ends agree on. `bpf_ringbuf_output` cannot align a
    /// record to more than 8 bytes, so an alignment that crept above that would
    /// turn into a load failure rather than a compile error.
    #[test]
    fn the_event_layout_is_the_one_both_ends_agree_on() {
        assert_eq!(FILE_EVENT_HEADER, 24);
        assert!(8 % align_of::<FileEvent>() == 0);
    }

    #[test]
    fn an_event_survives_the_round_trip_through_bytes() {
        let path = b"/home/me/.ssh/id_ed25519";
        let expected = event(path.len() as u16);
        let mut bytes = header(&expected).to_vec();
        bytes.extend_from_slice(path);

        let (got, got_path) = FileEvent::from_bytes(&bytes).expect("a whole event");
        assert_eq!(got, expected);
        assert_eq!(got_path, path);
    }

    /// A record that came up short is not an event: the header would be read
    /// out of the next one's bytes.
    #[test]
    fn a_short_record_is_not_an_event() {
        let bytes = header(&event(0));
        assert_eq!(FileEvent::from_bytes(&bytes[..FILE_EVENT_HEADER - 1]), None);
    }

    /// A header promising more path than arrived means the object and the
    /// daemon have come apart. Reading it would read past the event.
    #[test]
    fn a_lying_length_is_refused_rather_than_trusted() {
        let mut bytes = header(&event(64)).to_vec();
        bytes.extend_from_slice(b"/etc/hosts");
        assert_eq!(FileEvent::from_bytes(&bytes), None);
    }

    /// A path with no bytes at all is still a well-formed event.
    #[test]
    fn an_empty_path_is_still_an_event() {
        let bytes = header(&event(0));
        let (got, path) = FileEvent::from_bytes(&bytes).expect("an event");
        assert_eq!(got.len, 0);
        assert!(path.is_empty());
    }

    #[test]
    fn only_the_errors_a_sandbox_can_cause_are_reported() {
        for errno in [ERR_EPERM, ERR_ENOENT, ERR_EACCES, ERR_EROFS] {
            assert!(is_sandbox_errno(errno), "{errno} should be reported");
        }
        // EINTR, EMFILE, ENOTDIR on a genuine file, ELOOP: nothing to do with us.
        for errno in [4, 20, 24, 40] {
            assert!(!is_sandbox_errno(errno), "{errno} should not be reported");
        }
    }

    #[test]
    fn a_cut_path_says_so() {
        let mut cut = event(0);
        cut.flags = FLAG_TRUNCATED;
        assert!(cut.truncated());
        assert!(!event(0).truncated());
    }
}
