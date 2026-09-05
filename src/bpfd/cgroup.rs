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

    #[test]
    fn cgroup_path_is_rooted_at_the_mount_point() {
        assert_eq!(
            dir_of("/user.slice/x.service"),
            PathBuf::from("/sys/fs/cgroup/user.slice/x.service")
        );
    }
}
