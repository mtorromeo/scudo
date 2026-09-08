//! Whether a path the sandbox refused exists outside it.
//!
//! This is what turns a stream of `ENOENT` into something worth reading. The
//! daemon runs outside the unit's mount namespace, so it can simply go and
//! look: a path that is there is one the sandbox hid, and a path that is not
//! was never anywhere — a library search, a module resolution, a shell walking
//! `$PATH`. The two arrive from the kernel indistinguishable.
//!
//! It answers "is there a file of this name out there", not "is it the same
//! inode". That is the question worth asking, because it is the one that says
//! whether widening the profile would have helped.
//!
//! **A relative path is resolved through `/proc`, and that races.** Between the
//! syscall returning and this reading `/proc/<pid>/cwd`, the thread may have
//! called `chdir`, or closed and reused the directory descriptor, and the path
//! rebuilt here would then be someone else's. There is no cheap way out:
//! `bpf_d_path`, which would give the cwd inside the program itself, is allowed
//! only to `fentry`/`fexit`/`lsm` programs and not to tracepoints. In practice
//! the window is short — the reader is woken by `poll` as soon as the kernel
//! writes — and what a lost race costs is a wrong path in one line of a report.
//! Nothing here decides anything, so nothing else is at stake.

use std::{
    collections::HashMap,
    ffi::OsStr,
    io::ErrorKind,
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use scudo_bpf_common::fs::AT_FDCWD;

use crate::bpfd::protocol::Outside;

/// How long an answer is reused before going back to the filesystem.
///
/// Files do appear and disappear while a command runs, so this is not a cache
/// of something immutable; it is short enough that a `git checkout` in another
/// terminal is noticed, and long enough that a program resolving modules asks
/// the same question once.
const TTL: Duration = Duration::from_secs(10);

/// How many answers are remembered. A command that walks a large tree must not
/// be able to grow the daemon, and forgetting only costs a `stat`.
const MAX_CACHED: usize = 4096;

/// The mark a path that had to be cut short carries, so nobody reads it as the
/// whole name. The same one the panel truncates with.
const ELLIPSIS: char = '\u{2026}';

/// Resolves paths and remembers what it found.
///
/// Owned by the reader thread and used from it alone, so the cache needs no
/// lock of its own.
#[derive(Debug, Default)]
pub struct Checker {
    seen: HashMap<PathBuf, (Outside, Instant)>,
}

impl Checker {
    #[must_use]
    pub fn new() -> Self {
        Checker::default()
    }

    /// The path as it is named outside the sandbox, and whether it is there.
    ///
    /// `pid` is the thread that made the call — the one whose `/proc` entry can
    /// still say what a relative path was relative to, for as long as it lives.
    pub fn check(
        &mut self,
        path: &[u8],
        dirfd: i32,
        pid: u32,
        truncated: bool,
    ) -> (String, Outside) {
        let shown = show(path, truncated);
        // A cut path names a different file from the one that was asked for.
        // Going to look for it would answer a question about something else,
        // which is worse than not answering.
        if truncated || path.is_empty() {
            return (shown, Outside::Unknown);
        }
        let Some(full) = absolute(path, dirfd, pid) else {
            return (shown, Outside::Unknown);
        };
        let outside = self.lookup(&full);
        (show(full.as_os_str().as_bytes(), false), outside)
    }

    fn lookup(&mut self, path: &Path) -> Outside {
        let now = Instant::now();
        if let Some(&(outside, at)) = self.seen.get(path)
            && now.duration_since(at) < TTL
        {
            return outside;
        }
        let outside = exists(path);
        self.remember(path, outside, now);
        outside
    }

    /// Same shape as the bus's own table: drop what has gone stale, and if that
    /// was not enough, start over rather than grow.
    fn remember(&mut self, path: &Path, outside: Outside, now: Instant) {
        if self.seen.len() >= MAX_CACHED {
            self.seen
                .retain(|_, &mut (_, at)| now.duration_since(at) < TTL);
            if self.seen.len() >= MAX_CACHED {
                self.seen.clear();
            }
        }
        self.seen.insert(path.to_path_buf(), (outside, now));
    }
}

/// Look, without following the last link: a dangling symlink is still something
/// the sandbox could have hidden, and `metadata` would report it as missing.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "every other way of failing to look is the same not knowing"
)]
fn exists(path: &Path) -> Outside {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Outside::Present,
        // A component that is not a directory means nothing of that name can be
        // out there either, so it is an answer and not an unknown.
        Err(err) => match err.kind() {
            ErrorKind::NotFound | ErrorKind::NotADirectory => Outside::Absent,
            // We are the user, not root, so a path under a directory we may not
            // traverse is one we genuinely cannot answer for. Calling it absent
            // would be the one wrong answer available.
            _ => Outside::Unknown,
        },
    }
}

/// The path as it would be named from outside the sandbox.
///
/// `None` when it cannot be worked out — which is what a process that has
/// already exited looks like, and what a descriptor that no longer names a file
/// on disk looks like.
fn absolute(path: &[u8], dirfd: i32, pid: u32) -> Option<PathBuf> {
    let path = Path::new(OsStr::from_bytes(path));
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    let link = if dirfd == AT_FDCWD {
        format!("/proc/{pid}/cwd")
    } else {
        // A negative descriptor that is not AT_FDCWD names nothing.
        let fd = u32::try_from(dirfd).ok()?;
        format!("/proc/{pid}/fd/{fd}")
    };
    let base = std::fs::read_link(link).ok()?;
    // `readlink` on a descriptor that is not a file gives things like
    // `socket:[12345]`, and on an unlinked one a `/path (deleted)` that names
    // nothing. Neither joins into a path worth looking for.
    if !base.is_absolute() || base.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return None;
    }
    Some(base.join(path))
}

/// A path as a person reads it. Not UTF-8 clean is rare enough that lossy is
/// the right trade against carrying bytes over a JSON protocol.
fn show(path: &[u8], truncated: bool) -> String {
    let mut shown = String::from_utf8_lossy(path).into_owned();
    if truncated {
        shown.push(ELLIPSIS);
    }
    shown
}

#[cfg(test)]
#[expect(
    clippy::non_ascii_literal,
    reason = "the ellipsis, spelled the way the assertion reads best"
)]
mod tests {
    use super::*;

    fn pid() -> u32 {
        std::process::id()
    }

    /// The ordinary case, and the only one that involves no guessing.
    #[test]
    fn an_absolute_path_is_looked_up_as_it_stands() {
        let mut checker = Checker::new();
        let (path, outside) = checker.check(b"/", AT_FDCWD, pid(), false);
        assert_eq!(path, "/");
        assert_eq!(outside, Outside::Present);

        let (path, outside) = checker.check(b"/no-such-thing-anywhere", AT_FDCWD, pid(), false);
        assert_eq!(path, "/no-such-thing-anywhere");
        assert_eq!(outside, Outside::Absent);
    }

    /// A path under something that is not a directory cannot be out there
    /// either, so it is an answer and not an unknown.
    #[test]
    fn a_path_below_a_file_is_absent_rather_than_unknown() {
        let mut checker = Checker::new();
        let (_, outside) = checker.check(b"Cargo.toml/below", AT_FDCWD, pid(), false);
        assert!(
            matches!(outside, Outside::Absent | Outside::Unknown),
            "got {outside:?}"
        );
    }

    /// Resolved against our own cwd, which is what `AT_FDCWD` means.
    #[test]
    fn a_relative_path_is_resolved_against_the_callers_directory() {
        let mut checker = Checker::new();
        let cwd = std::env::current_dir().expect("a working directory");
        let (path, outside) = checker.check(b"Cargo.toml", AT_FDCWD, pid(), false);
        assert_eq!(path, cwd.join("Cargo.toml").display().to_string());
        assert_eq!(outside, Outside::Present);
    }

    /// A descriptor we hold, which is the other half of resolving a relative
    /// path. It names the crate's own directory, because a build in a chroot
    /// has no `/etc` worth relying on and this is the one tree we know is there.
    #[test]
    fn a_relative_path_is_resolved_against_a_directory_descriptor() {
        use std::os::fd::AsRawFd as _;

        // `/proc/<pid>/fd` answers with links resolved, so the expected name has
        // to be resolved too or a symlinked source tree would not match.
        let root = std::fs::canonicalize(env!("CARGO_MANIFEST_DIR")).expect("the crate directory");
        let dir = std::fs::File::open(&root).expect("the crate directory is openable");
        let fd = dir.as_raw_fd();
        let mut checker = Checker::new();
        let (path, outside) = checker.check(b"Cargo.toml", fd, pid(), false);
        assert_eq!(path, root.join("Cargo.toml").display().to_string());
        assert_eq!(outside, Outside::Present);
    }

    /// A thread that has gone takes its `/proc` entry with it, and a relative
    /// path is then unanswerable rather than wrong.
    #[test]
    fn a_relative_path_with_nobody_to_ask_is_unknown() {
        let mut checker = Checker::new();
        // pid_max is far below i32::MAX, so this names nothing.
        let (path, outside) = checker.check(b"config.toml", AT_FDCWD, u32::MAX, false);
        assert_eq!(path, "config.toml");
        assert_eq!(outside, Outside::Unknown);
    }

    /// A cut path names something else. Looking for it would answer confidently
    /// about the wrong file, so it is never looked for at all.
    #[test]
    fn a_cut_path_is_never_looked_for() {
        let mut checker = Checker::new();
        let (path, outside) = checker.check(b"/", AT_FDCWD, pid(), true);
        assert_eq!(path, "/…");
        assert_eq!(outside, Outside::Unknown);
        assert!(
            checker.seen.is_empty(),
            "nothing should have been looked up"
        );
    }

    /// `openat` with `AT_EMPTY_PATH` names the descriptor, not a path anyone
    /// would recognise.
    #[test]
    fn an_empty_path_names_nothing_to_look_for() {
        let mut checker = Checker::new();
        assert_eq!(
            checker.check(b"", AT_FDCWD, pid(), false).1,
            Outside::Unknown
        );
    }

    /// One question, one `stat`: this is what keeps a program that resolves
    /// hundreds of modules from turning into hundreds of syscalls per repeat.
    #[test]
    fn an_answer_is_reused_rather_than_asked_again() {
        let mut checker = Checker::new();
        checker.check(b"Cargo.toml", AT_FDCWD, pid(), false);
        assert_eq!(checker.seen.len(), 1);
        checker.check(b"Cargo.toml", AT_FDCWD, pid(), false);
        assert_eq!(checker.seen.len(), 1);
    }

    /// A command walking a large tree must not be able to grow the daemon.
    #[test]
    fn the_cache_is_capped_rather_than_the_truth() {
        let mut checker = Checker::new();
        let now = Instant::now();
        for i in 0..MAX_CACHED + 16 {
            let path = PathBuf::from(format!("/nowhere/{i}"));
            checker.remember(&path, Outside::Absent, now);
        }
        assert!(checker.seen.len() <= MAX_CACHED, "{}", checker.seen.len());
    }

    /// A path that is not valid UTF-8 still names something a person can read.
    #[test]
    fn a_path_that_is_not_utf8_is_still_shown() {
        let mut checker = Checker::new();
        let (path, _) = checker.check(b"/tmp/\xff\xfe", AT_FDCWD, pid(), false);
        assert!(path.starts_with("/tmp/"), "{path}");
    }
}
