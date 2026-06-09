#![cfg(target_os = "linux")]

use std::{
    ffi::{OsStr, OsString},
    hash::DefaultHasher,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::PathBuf,
};

use core::{
    hash::{Hash as _, Hasher as _},
    time::Duration,
};

use clap::Parser;
use fuser::{
    AccessFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, Request, SessionACL,
};

const TTL: Duration = Duration::from_mins(1);

#[derive(Parser)]
#[command(
    about = "Mount a FUSE shim filesystem that redirects any command lookup to a target binary"
)]
struct Args {
    /// Directory to mount the shim filesystem on.
    mountpoint: PathBuf,
    /// Target binary that all symlinks in the shim directory will point to.
    target: PathBuf,
    /// Colon-separated list of directories to search for executables.
    #[arg(short = 'p', long, env = "PATH")]
    path: String,
    /// Do not enumerate executables in readdir; only respond to explicit lookups.
    #[arg(long)]
    disable_listing: bool,
}

/// Derive a stable inode number from a filename. Avoids 0 (invalid) and 1 (root).
fn name_to_ino(name: &OsStr) -> INodeNo {
    let mut h = DefaultHasher::new();
    name.hash(&mut h);
    #[expect(clippy::integer_division_remainder_used)]
    let n = h.finish() % (u64::MAX - 2);
    INodeNo(n.saturating_add(2))
}

/// Returns true if `name` exists as an executable file in any of `dirs`.
fn find_in_path(name: &OsStr, dirs: &[PathBuf]) -> bool {
    dirs.iter().any(|dir| {
        std::fs::metadata(dir.join(name))
            .is_ok_and(|m| !m.is_dir() && m.permissions().mode() & 0o111u32 != 0u32)
    })
}

fn uid() -> u32 {
    std::fs::metadata("/proc/self").map_or(0, |m| m.uid())
}

fn gid() -> u32 {
    std::fs::metadata("/proc/self").map_or(0, |m| m.gid())
}

fn root_attr() -> FileAttr {
    FileAttr {
        ino: INodeNo(1),
        size: 0,
        blocks: 0,
        atime: std::time::UNIX_EPOCH,
        mtime: std::time::UNIX_EPOCH,
        ctime: std::time::UNIX_EPOCH,
        crtime: std::time::UNIX_EPOCH,
        kind: FileType::Directory,
        perm: 0o555,
        nlink: 2,
        uid: uid(),
        gid: gid(),
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

struct ScudoShimsFS {
    target: String,
    path_dirs: Vec<PathBuf>,
    /// Basenames that are never exposed as shims, regardless of PATH contents.
    excluded: std::collections::HashSet<OsString>,
    disable_listing: bool,
}

impl ScudoShimsFS {
    /// Enumerate all executable files reachable via `path_dirs`, first-entry-wins per name.
    /// Returns tuples of `(filename, inode, kind)` including the `.` and `..` dot entries.
    fn list_entries(&self) -> Vec<(OsString, INodeNo, FileType)> {
        let mut entries = vec![
            (OsString::from("."), INodeNo(1), FileType::Directory),
            (OsString::from(".."), INodeNo(1), FileType::Directory),
        ];
        let mut seen = std::collections::HashSet::new();
        for dir in &self.path_dirs {
            let Ok(read_dir) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in read_dir.flatten() {
                let name = entry.file_name();
                if seen.contains(&name) || self.excluded.contains(&name) {
                    continue;
                }
                if std::fs::metadata(entry.path())
                    .is_ok_and(|m| !m.is_dir() && m.permissions().mode() & 0o111u32 != 0u32)
                {
                    entries.push((name.clone(), name_to_ino(&name), FileType::Symlink));
                    seen.insert(name);
                }
            }
        }
        entries
    }

    fn symlink_attr(&self, ino: INodeNo) -> FileAttr {
        FileAttr {
            ino,
            size: self.target.len() as u64,
            blocks: 0,
            atime: std::time::UNIX_EPOCH,
            mtime: std::time::UNIX_EPOCH,
            ctime: std::time::UNIX_EPOCH,
            crtime: std::time::UNIX_EPOCH,
            kind: FileType::Symlink,
            perm: 0o777,
            nlink: 1,
            uid: uid(),
            gid: gid(),
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }
}

impl Filesystem for ScudoShimsFS {
    /// Resolve a name in the root directory to a symlink only if the binary exists in path.
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent != INodeNo(1)
            || self.excluded.contains(name)
            || !find_in_path(name, &self.path_dirs)
        {
            reply.error(Errno::ENOENT);
            return;
        }
        reply.entry(&TTL, &self.symlink_attr(name_to_ino(name)), Generation(0));
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino == INodeNo(1) {
            reply.attr(&TTL, &root_attr());
        } else {
            reply.attr(&TTL, &self.symlink_attr(ino));
        }
    }

    fn readlink(&self, _req: &Request, _ino: INodeNo, reply: ReplyData) {
        reply.data(self.target.as_bytes());
    }

    fn opendir(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino != INodeNo(1) {
            reply.error(Errno::ENOTDIR);
            return;
        }
        if self.disable_listing {
            reply.ok();
            return;
        }
        let start = usize::try_from(offset).unwrap_or(0);
        for (idx, (name, entry_ino, kind)) in
            self.list_entries().into_iter().enumerate().skip(start)
        {
            let next_offset = u64::try_from(idx.saturating_add(1)).unwrap_or(u64::MAX);
            if reply.add(entry_ino, next_offset, kind, &name) {
                break;
            }
        }
        reply.ok();
    }

    fn access(&self, _req: &Request, _ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        if mask & AccessFlags::W_OK == AccessFlags::F_OK {
            reply.ok();
        } else {
            reply.error(Errno::EACCES);
        }
    }
}

fn main() -> Result<(), i32> {
    let args = Args::parse();

    let target = args
        .target
        .to_str()
        .expect("target path must be valid UTF-8")
        .to_owned();

    if let Err(e) = std::fs::create_dir_all(&args.mountpoint) {
        eprintln!("scudo-fuse: failed to create mountpoint: {e}");
        std::process::exit(1);
    }

    // Canonicalize the mountpoint so we can exclude it from path_dirs, preventing
    // FUSE re-entrancy deadlocks when the shims directory itself is in PATH.
    let mountpoint_real =
        std::fs::canonicalize(&args.mountpoint).unwrap_or_else(|_| args.mountpoint.clone());

    let path_dirs: Vec<PathBuf> = args
        .path
        .split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .filter(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()) != mountpoint_real)
        .collect();

    let mut options = Config::default();
    options.mount_options = vec![
        MountOption::RO,
        MountOption::FSName("scudo-shims".to_owned()),
        MountOption::AutoUnmount,
        MountOption::NoAtime,
        MountOption::NoDev,
        MountOption::NoExec,
    ];
    options.acl = SessionACL::All;

    // Build the set of basenames that must never be shimmed:
    //   - systemd-run: the tool scudo invokes internally
    //   - basename of target (e.g. "scudo"): would create a shim pointing to itself
    //   - basename of current exe (e.g. "scudo-fuse"): the FUSE process itself
    let mut excluded: std::collections::HashSet<OsString> = [OsString::from("systemd-run")].into();
    if let Some(name) = args.target.file_name() {
        excluded.insert(name.to_owned());
    }
    if let Ok(self_exe) = std::env::current_exe()
        && let Some(name) = self_exe.file_name()
    {
        excluded.insert(name.to_owned());
    }

    if let Err(e) = fuser::mount2(
        ScudoShimsFS {
            target,
            path_dirs,
            excluded,
            disable_listing: args.disable_listing,
        },
        &args.mountpoint,
        &options,
    ) {
        eprintln!("scudo-fuse: mount failed: {e}");
        return Err(1);
    }

    Ok(())
}
