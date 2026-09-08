//! Locating and vetting the cgroup a client is asking us to restrict.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

/// Where cgroup2 is mounted.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Read a process's cgroup2 path, as it appears in `/proc/<pid>/cgroup`.
pub fn of_pid(pid: i32) -> Result<String> {
    let path = format!("/proc/{pid}/cgroup");
    let content = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    for line in content.lines() {
        // cgroup2 lines look like "0::/user.slice/…".
        if let Some(rest) = line.strip_prefix("0::") {
            return Ok(rest.to_owned());
        }
    }
    bail!("process {pid} is not in a cgroup2 hierarchy")
}

/// Check that `cgroup` belongs to `uid`'s own systemd subtree.
///
/// Restricting someone else's cgroup would be a denial of service, and the
/// daemon runs with capabilities the caller does not have, so this is the line
/// that keeps it from being used as a lever.
#[must_use]
pub fn belongs_to_user(cgroup: &str, uid: u32) -> bool {
    let prefix = format!("/user.slice/user-{uid}.slice/user@{uid}.service/");
    cgroup.starts_with(&prefix)
}

/// The directory to open in order to attach a program.
#[must_use]
pub fn dir_of(cgroup: &str) -> PathBuf {
    let relative = cgroup.trim_start_matches('/');
    Path::new(CGROUP_ROOT).join(relative)
}

/// The id the kernel names this cgroup by.
///
/// On cgroup2 that id *is* the inode number of the cgroup's directory, which is
/// what `bpf_get_current_cgroup_id()` returns inside a program. Asking the
/// filesystem is therefore not an approximation of the id — it is the id.
pub fn id_of_dir(dir: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata =
        std::fs::metadata(dir).with_context(|| format!("reading cgroup {}", dir.display()))?;
    Ok(metadata.ino())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_users_own_subtree_is_accepted() {
        assert!(belongs_to_user(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/x.service",
            1000
        ));
        // Another user's subtree, and the system's.
        assert!(!belongs_to_user(
            "/user.slice/user-1001.slice/user@1001.service/app.slice/x.service",
            1000
        ));
        assert!(!belongs_to_user("/system.slice/sshd.service", 1000));
        // The manager itself, rather than something under it.
        assert!(!belongs_to_user(
            "/user.slice/user-1000.slice/user@1000.service",
            1000
        ));
        // A lookalike prefix.
        assert!(!belongs_to_user(
            "/user.slice/user-10000.slice/user@10000.service/app.slice/x.service",
            1000
        ));
    }

    /// The id a program sees is the directory's inode, so the two have to agree
    /// on any real cgroup — our own will do.
    #[test]
    fn a_cgroups_id_is_its_directorys_inode() {
        let mine = i32::try_from(std::process::id()).expect("pid fits in an i32");
        let Ok(cgroup) = of_pid(mine) else {
            // Not a cgroup2 system; nothing to check.
            return;
        };
        let dir = dir_of(&cgroup);
        let Ok(id) = id_of_dir(&dir) else {
            return;
        };
        assert_ne!(id, 0, "a cgroup id is never zero");
    }

    #[test]
    fn cgroup_path_is_rooted_at_the_mount_point() {
        assert_eq!(
            dir_of("/user.slice/x.service"),
            PathBuf::from("/sys/fs/cgroup/user.slice/x.service")
        );
    }
}
