//! scudo started from inside one of its own sandboxes.
//!
//! A sandbox that cannot reach `systemd --user` cannot start another one: the
//! inner `systemd-run` has no bus to ask. Rather than fail, the inner scudo runs
//! the command as it is, which leaves it in the sandbox it was started from.
//!
//! **That grants nothing.** The command runs with exactly the restrictions of
//! the process that started it, which could have run the binary directly all
//! along; skipping the inner profile only means not adding to them. So the one
//! thing that has to hold is that an *unsandboxed* scudo can never be talked
//! into the same shortcut, and that is why the signal is the cgroup and nothing
//! else. An environment variable could be set by a `.envrc`, a config file by
//! whoever wrote the project; a cgroup named after a sealed sandbox can only be
//! entered by running `systemd-run` or writing `cgroup.procs`, and a process
//! that can do either is already running whatever it likes, unsandboxed.
//!
//! A profile can hide that name, though: `ProtectControlGroups = "private"`
//! (which rootless podman wants) gives the unit a cgroup namespace of its own,
//! and inside it the unit's cgroup reads as `/`. So a sealed sandbox also gets
//! `/dev/null` mounted on [`marker_path`], and a mount point there counts as
//! much as the cgroup's name. The same argument holds: a file can be put there
//! by anyone, a *mount* only by someone with a mount namespace of their own,
//! who is equally free already.
//!
//! A sandbox whose bus does lead to the manager (`session = "allow"`) is not
//! marked, and a scudo started inside it creates a sandbox of its own as before:
//! there the inner profile can still restrict the inner command.

use std::path::PathBuf;

use crate::bpfd::cgroup;

/// How the unit of a sealed sandbox is named, before its id.
const SEALED_PREFIX: &str = "scudo-sealed-";

/// The unit name for a sealed sandbox with this id.
#[must_use]
pub fn sealed_unit(id: &str) -> String {
    format!("{SEALED_PREFIX}{id}.service")
}

/// Where a sealed sandbox has `/dev/null` mounted, so that it can be told
/// apart even when its cgroup cannot.
///
/// Derived from the uid and not from `$XDG_RUNTIME_DIR`: what the environment
/// says must not be able to point the check at some mount that exists anyway.
#[must_use]
pub fn marker_path(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}/scudo/sealed"))
}

/// Whether this process runs inside a sandbox scudo marked as sealed.
///
/// Anything that cannot be read answers `false`: the worst that does is try to
/// start a sandbox, which is what scudo always did.
#[must_use]
pub fn inside_sealed_sandbox() -> bool {
    let Ok(pid) = i32::try_from(std::process::id()) else {
        return false;
    };
    // SAFETY: getuid always succeeds and touches no memory.
    let uid = unsafe { libc::getuid() };
    cgroup::of_pid(pid).is_ok_and(|path| is_sealed_cgroup(&path, uid))
        || std::fs::read_to_string("/proc/self/mountinfo").is_ok_and(|mountinfo| {
            marker_path(uid)
                .to_str()
                .is_some_and(|marker| has_mount_point(&mountinfo, marker))
        })
}

/// Whether `path` is a mount point in `mountinfo`, as `/proc/self/mountinfo`
/// writes it.
///
/// The mount point is the fifth field; the fourth is the mount's root within
/// its filesystem, which says nothing about where it is. Paths are written
/// with octal escapes, which the marker, made of digits and slashes, never
/// needs.
fn has_mount_point(mountinfo: &str, path: &str) -> bool {
    mountinfo
        .lines()
        .any(|line| line.split(' ').nth(4) == Some(path))
}

/// Whether `path`, a cgroup2 path, lies in a sealed sandbox of `uid`'s own.
///
/// Any component may be the unit: a profile that sets `Delegate=` lets the
/// command make cgroups of its own underneath.
fn is_sealed_cgroup(path: &str, uid: u32) -> bool {
    cgroup::belongs_to_user(path, uid) && path.split('/').any(is_sealed_unit)
}

/// `scudo-sealed-<pid>-<hex>.service`, exactly as [`sealed_unit`] writes it.
fn is_sealed_unit(name: &str) -> bool {
    let Some(id) = name
        .strip_prefix(SEALED_PREFIX)
        .and_then(|rest| rest.strip_suffix(".service"))
    else {
        return false;
    };
    id.split_once('-').is_some_and(|(pid, nanos)| {
        !pid.is_empty()
            && !nanos.is_empty()
            && pid.bytes().all(|b| b.is_ascii_digit())
            && nanos.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "/user.slice/user-1000.slice/user@1000.service/app.slice";

    #[test]
    fn a_sealed_unit_of_ones_own_is_recognised() {
        let unit = sealed_unit("42-1a2b");
        assert!(is_sealed_cgroup(&format!("{BASE}/{unit}"), 1000));
        // Underneath it, with `Delegate=`.
        assert!(is_sealed_cgroup(&format!("{BASE}/{unit}/sub"), 1000));
    }

    #[test]
    fn someone_elses_or_the_systems_is_not() {
        let unit = sealed_unit("42-1a2b");
        assert!(!is_sealed_cgroup(
            &format!("/user.slice/user-1001.slice/user@1001.service/app.slice/{unit}"),
            1000
        ));
        assert!(!is_sealed_cgroup(&format!("/system.slice/{unit}"), 1000));
    }

    const MARKER: &str = "/run/user/1000/scudo/sealed";

    fn mount_at(root: &str, point: &str) -> String {
        format!("1474 1432 0:5 {root} {point} ro,nosuid shared:1 - devtmpfs dev rw\n")
    }

    #[test]
    fn the_marker_is_where_marker_path_says() {
        assert_eq!(marker_path(1000).to_str(), Some(MARKER));
    }

    #[test]
    fn a_mount_on_the_marker_is_recognised() {
        let mountinfo = format!("{}{}", mount_at("/", "/"), mount_at("/null", MARKER));
        assert!(has_mount_point(&mountinfo, MARKER));
    }

    #[test]
    fn anything_but_a_mount_on_the_marker_is_not() {
        assert!(!has_mount_point("", MARKER));
        // The marker as the mount's root, not as where it is mounted.
        assert!(!has_mount_point(&mount_at(MARKER, "/mnt"), MARKER));
        for point in [
            "/run/user/1000/scudo/sealedx",
            "/run/user/1000/scudo/sealed/x",
            "/run/user/1000/scudo",
            "/run/user/1001/scudo/sealed",
        ] {
            assert!(
                !has_mount_point(&mount_at("/null", point), MARKER),
                "{point}"
            );
        }
    }

    #[test]
    fn lookalikes_are_not() {
        for name in [
            "run-u1.service",
            "scudo-dbus@42-1a2b.service",
            "scudo-sealed-.service",
            "scudo-sealed-42.service",
            "scudo-sealed-42-.service",
            "scudo-sealed-42-xyz.service",
            "scudo-sealed-42-1a2b.service.x",
            "scudo-sealed-42-1a2b.scope",
            "xscudo-sealed-42-1a2b.service",
        ] {
            assert!(!is_sealed_cgroup(&format!("{BASE}/{name}"), 1000), "{name}");
        }
    }
}
