//! Reporting the file accesses a scudo sandbox could not make.
//!
//! Nothing here refuses anything. systemd applies the filesystem restrictions
//! by rearranging the unit's mount namespace, and by the time a syscall comes
//! back with `ENOENT` or `EACCES` the verdict has already been made somewhere
//! we cannot see. All these programs do is notice, and say which path it was —
//! which is the one thing the command itself never gets told.
//!
//! **These are raw tracepoints, and they have to be.** The obvious choice is a
//! classic tracepoint per syscall, but attaching one means reading its numeric
//! id out of `<tracefs>/events/…/id`, and tracefs is `drwx------ root` on an
//! ordinary system. No capability opens it — `scudo-bpfd` would have to be root.
//! `bpf_raw_tracepoint_open` takes the tracepoint's *name* through `bpf(2)` and
//! touches no filesystem at all, so the two global `sys_enter` / `sys_exit`
//! tracepoints are reachable where twenty-eight per-syscall ones are not.
//!
//! It is also the cheaper shape. These two programs run for *every* syscall on
//! the machine, so the first thing each does is look at the syscall number,
//! which costs nothing and rejects everything else before a map is touched.
//!
//! **One object serves every sandbox, unlike the network programs.** There is
//! no cgroup-scoped hook that sees a path which was never resolved, so the
//! daemon loads this once and writes the cgroups it is watching into `WATCHED`.
//! That map is also the privacy boundary: a path belonging to a process outside
//! every watched cgroup never leaves this file. The daemon carries capabilities
//! the caller does not have, so the filtering has to happen here and not in the
//! reader.
//!
//! **There is no loop in this file, and there must not be one.** The path is
//! copied by `bpf_probe_read_user_str`, which is a helper call rather than
//! something the program walks, and its cost is bounded by [`MAX_PATH`].

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::pt_regs,
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, raw_tracepoint},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::RawTracePointContext,
};
use scudo_bpf_common::fs::{
    AT_FDCWD, FILE_EVENT_HEADER, FLAG_TRUNCATED, FS_EVENTS_BYTES, FileEvent, MAX_PATH, MAX_PENDING,
    MAX_WATCHED, is_sandbox_errno,
};

/// The cgroups the daemon is watching, keyed by cgroup id. Written from
/// userspace as sandboxes come and go, which is why it is a map and not a
/// `.rodata` global the way the network object's settings are.
///
/// The match is exact rather than over ancestors: a `systemd-run` transient
/// unit puts its processes directly in one cgroup and `ProtectControlGroups=`
/// keeps them there, and walking ancestors would cost a lookup per level on
/// every syscall the machine makes.
#[map]
static WATCHED: HashMap<u64, u8> = HashMap::with_max_entries(MAX_WATCHED, 0);

/// What a thread asked for, between the syscall's entry and its return.
///
/// The path is a pointer into the caller's memory: it is only meaningful on the
/// way in, and the error only on the way out, so the two have to be joined here.
#[repr(C)]
#[derive(Clone, Copy)]
struct Pending {
    /// Noted on the way in, so the event belongs to the sandbox that was
    /// matched then rather than to whatever the task looks like on the way out.
    cgroup_id: u64,
    /// The caller's `const char *`, read back at exit.
    path: u64,
    dirfd: i32,
    op: u8,
    _pad: [u8; 3],
}

/// LRU rather than a plain hash: a thread killed inside a syscall never reaches
/// the exit tracepoint, and must not hold a slot for ever.
#[map]
static PENDING: LruHashMap<u64, Pending> = LruHashMap::with_max_entries(MAX_PENDING, 0);

/// Refused accesses on their way to `scudo-bpfd`, which routes each one to the
/// sandbox its cgroup id names.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(FS_EVENTS_BYTES, 0);

/// How many events did not fit. Per-CPU, so counting costs no atomic; the
/// daemon adds the counters up.
#[map]
static DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Where an event is built before it is handed to the ring buffer.
///
/// Per-CPU because the eBPF stack is 512 bytes and an event is larger than
/// that on its own.
#[map]
static SCRATCH: PerCpuArray<[u8; FILE_EVENT_HEADER + MAX_PATH]> =
    PerCpuArray::with_max_entries(1, 0);

/// A syscall worth reporting the failures of, and where it keeps its path.
#[derive(Clone, Copy)]
struct Traced {
    /// One of the `OP_*` in the shared ABI.
    op: u8,
    /// `true` when a directory descriptor comes first and the path second, as
    /// every `*at` syscall has it; `false` when the path is the first argument
    /// and resolves against the working directory.
    at: bool,
}

/// Syscall numbers, and the two registers the first two arguments arrive in.
///
/// Both are per-architecture, and only x86-64 is written out: it is the only
/// architecture scudo is packaged for, and a table of numbers guessed for
/// another one would not fail — it would quietly report the wrong syscalls.
#[cfg(bpf_target_arch = "x86_64")]
mod arch {
    use aya_ebpf::{bindings::pt_regs, helpers::bpf_probe_read_kernel};
    use scudo_bpf_common::fs::{
        OP_ACCESS, OP_CHDIR, OP_EXEC, OP_MKDIR, OP_OPEN, OP_READLINK, OP_RENAME, OP_STAT,
        OP_TRUNCATE, OP_UNLINK,
    };

    use super::Traced;

    /// Is this a syscall that names a path, and can a sandbox be why it failed?
    ///
    /// A `match` and nothing more: this is the first question both programs ask
    /// and it runs on every syscall the machine makes, so it must not touch a
    /// map or call a helper. Syscalls working on a file descriptor are absent
    /// on purpose — one has already got past the sandbox, and the open that
    /// produced it is the call that would have been refused.
    ///
    /// The numbers are the 64-bit table. A 32-bit process on the same machine
    /// numbers its syscalls differently and could be read as the wrong one
    /// here; the cost is a stray line in a report, and the alternative is a
    /// second table for something scudo does not sandbox.
    #[inline(always)]
    pub fn traced(nr: i64) -> Option<Traced> {
        let (op, at) = match nr {
            2 => (OP_OPEN, false),      // open
            85 => (OP_OPEN, false),     // creat
            257 => (OP_OPEN, true),     // openat
            437 => (OP_OPEN, true),     // openat2
            4 => (OP_STAT, false),      // stat
            6 => (OP_STAT, false),      // lstat
            262 => (OP_STAT, true),     // newfstatat
            332 => (OP_STAT, true),     // statx
            21 => (OP_ACCESS, false),   // access
            269 => (OP_ACCESS, true),   // faccessat
            439 => (OP_ACCESS, true),   // faccessat2
            89 => (OP_READLINK, false), // readlink
            267 => (OP_READLINK, true), // readlinkat
            59 => (OP_EXEC, false),     // execve
            322 => (OP_EXEC, true),     // execveat
            87 => (OP_UNLINK, false),   // unlink
            84 => (OP_UNLINK, false),   // rmdir
            263 => (OP_UNLINK, true),   // unlinkat
            83 => (OP_MKDIR, false),    // mkdir
            258 => (OP_MKDIR, true),    // mkdirat
            82 => (OP_RENAME, false),   // rename
            264 => (OP_RENAME, true),   // renameat
            316 => (OP_RENAME, true),   // renameat2
            76 => (OP_TRUNCATE, false), // truncate
            80 => (OP_CHDIR, false),    // chdir
            _ => return None,
        };
        Some(Traced { op, at })
    }

    /// Syscall argument `index`, out of the registers the kernel saved.
    ///
    /// Only the first two, which is all the table above needs: every syscall in
    /// it names its path in argument 0 or 1. Those two live in the same
    /// registers under the syscall convention as under the ordinary one, so
    /// there is no second mapping to get wrong here.
    #[inline(always)]
    pub fn syscall_arg(regs: *const pt_regs, index: usize) -> Option<u64> {
        // SAFETY: `&raw const` takes the address of a field without reading
        // through the pointer; the read itself is the helper's, which fails
        // rather than faults on an address it may not have.
        let field = unsafe {
            match index {
                0 => &raw const (*regs).rdi,
                1 => &raw const (*regs).rsi,
                _ => return None,
            }
        };
        // SAFETY: reading kernel memory the tracepoint handed us.
        unsafe { bpf_probe_read_kernel(field) }.ok()
    }

    /// The syscall number on the way out.
    ///
    /// It is not among the exit tracepoint's arguments, and `rax` has been
    /// overwritten with the return value by then — which is exactly what
    /// `orig_rax` is kept for.
    #[inline(always)]
    pub fn syscall_nr(regs: *const pt_regs) -> Option<i64> {
        // SAFETY: as in `syscall_arg`.
        let field = unsafe { &raw const (*regs).orig_rax };
        // SAFETY: reading kernel memory the tracepoint handed us.
        unsafe { bpf_probe_read_kernel(field) }
            .ok()
            .map(|nr| nr as i64)
    }
}

#[cfg(not(bpf_target_arch = "x86_64"))]
compile_error!(
    "the file monitor needs this architecture's syscall numbers; \
     see the `arch` module in ebpf/scudo-bpf-ebpf/src/fs.rs"
);

/// The cgroup id of the running task, if the daemon is watching it.
#[inline(always)]
fn watched_cgroup() -> Option<u64> {
    // SAFETY: the helper reads the current task and touches no memory of ours.
    let cgroup = unsafe { bpf_get_current_cgroup_id() };
    // SAFETY: the value is not kept; only its presence is read.
    if unsafe { WATCHED.get(&cgroup) }.is_some() {
        Some(cgroup)
    } else {
        None
    }
}

/// Add one to this CPU's tally of events that did not fit.
#[inline(always)]
fn note_drop() {
    if let Some(counter) = DROPPED.get_ptr_mut(0) {
        // SAFETY: the map hands back a pointer to this CPU's own slot, which no
        // other instance of the program can be writing at the same time.
        unsafe { *counter = (*counter).wrapping_add(1) };
    }
}

/// Copy the path out of the caller and hand the event to the ring buffer.
#[inline(always)]
fn emit(pending: &Pending, errno: i32) {
    let Some(buf) = SCRATCH.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: this CPU's own slot, and no other instance of this program can be
    // running on it while we are inside here.
    let buf = unsafe { &mut *buf };
    let Some(dest) = buf.get_mut(FILE_EVENT_HEADER..) else {
        return;
    };

    // SAFETY: the pointer is the caller's own argument, and the helper bounds
    // the copy by the length of the buffer we hand it — a bad pointer comes
    // back as an error rather than a fault.
    let Ok(path) = (unsafe { bpf_probe_read_user_str_bytes(pending.path as *const u8, dest) })
    else {
        return;
    };
    let len = path.len();

    // The helper NUL-terminates within the buffer, so a string that filled it
    // came back one byte short of the whole. A path that happens to be exactly
    // that long is flagged too: saying "this may have been cut" about a path
    // that was not costs a report the outside check it would have got, and
    // claiming a cut path is whole would send the daemon looking for the wrong
    // file.
    let flags = if len >= MAX_PATH.saturating_sub(1) {
        FLAG_TRUNCATED
    } else {
        0
    };

    let header = FileEvent {
        cgroup_id: pending.cgroup_id,
        // The low half is the thread id, which is what names a directory under
        // /proc for resolving a relative path.
        pid: bpf_get_current_pid_tgid() as u32,
        errno,
        dirfd: pending.dirfd,
        op: pending.op,
        flags,
        len: len as u16,
    };
    // SAFETY: writing a repr(C) header into the start of a buffer we own.
    // Unaligned because the map's value type is a byte array, so nothing
    // promises the eight bytes the header wants.
    unsafe { core::ptr::write_unaligned(buf.as_mut_ptr().cast::<FileEvent>(), header) };

    // Shown to the verifier as well as to us: the length handed to the ring
    // buffer is not a constant, so the bound has to be visible.
    if len > MAX_PATH {
        return;
    }
    let Some(record) = buf.get(..FILE_EVENT_HEADER.saturating_add(len)) else {
        return;
    };
    if EVENTS.output::<[u8]>(record, 0).is_err() {
        note_drop();
    }
}

/// Note what a thread is about to ask for.
///
/// `sys_enter` fires for every syscall on the machine, so the order here is the
/// order of cost: the syscall number is already in the context and rejects
/// almost everything, and only then is a map touched.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn sys_enter(ctx: RawTracePointContext) -> i32 {
    // `sys_enter` passes the saved registers as arg 0 and the syscall number
    // as arg 1.
    let Some(traced) = arch::traced(ctx.arg::<i64>(1)) else {
        return 0;
    };
    let Some(cgroup_id) = watched_cgroup() else {
        return 0;
    };

    let regs: *const pt_regs = ctx.arg(0);
    let path_arg = if traced.at { 1 } else { 0 };
    let Some(path) = arch::syscall_arg(regs, path_arg) else {
        return 0;
    };
    if path == 0 {
        return 0;
    }
    let dirfd = if traced.at {
        // The slot is eight bytes wide whatever the argument's type, and the
        // register may have been sign-extended, so only the low half is the int.
        match arch::syscall_arg(regs, 0) {
            Some(raw) => raw as u32 as i32,
            None => return 0,
        }
    } else {
        // A syscall that takes no directory resolves against the working
        // directory, which is what AT_FDCWD means to whoever reads this.
        AT_FDCWD
    };

    // Losing the note costs the report, never the syscall.
    _ = PENDING.insert(
        &bpf_get_current_pid_tgid(),
        &Pending {
            cgroup_id,
            path,
            dirfd,
            op: traced.op,
            _pad: [0; 3],
        },
        0,
    );
    0
}

/// Report it, if it came back in a way a sandbox could be the cause of.
#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn sys_exit(ctx: RawTracePointContext) -> i32 {
    // `sys_exit` passes the saved registers as arg 0 and the return value as
    // arg 1, so the syscall number has to come from the registers.
    let regs: *const pt_regs = ctx.arg(0);
    let Some(nr) = arch::syscall_nr(regs) else {
        return 0;
    };
    if arch::traced(nr).is_none() {
        return 0;
    }

    let ret = ctx.arg::<i64>(1);
    let key = bpf_get_current_pid_tgid();

    // A call that succeeded, or failed in a way a sandbox cannot cause, still
    // has to give its note back: leaving it there would make the thread's next
    // refusal report this path instead of its own.
    let errno = ret
        .checked_neg()
        .and_then(|errno| i32::try_from(errno).ok())
        .unwrap_or(0);
    if ret >= 0 || !is_sandbox_errno(errno) {
        _ = PENDING.remove(&key);
        return 0;
    }

    // SAFETY: the value is copied out before anything else can touch the map.
    let Some(pending) = (unsafe { PENDING.get(&key) }).copied() else {
        return 0;
    };
    _ = PENDING.remove(&key);
    emit(&pending, errno);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
