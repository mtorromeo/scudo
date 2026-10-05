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
//! A sandbox whose bus does lead to the manager (`session = "allow"`) is not
//! marked, and a scudo started inside it creates a sandbox of its own as before:
//! there the inner profile can still restrict the inner command.

use crate::bpfd::cgroup;

/// How the unit of a sealed sandbox is named, before its id.
const SEALED_PREFIX: &str = "scudo-sealed-";

/// The unit name for a sealed sandbox with this id.
#[must_use]
pub fn sealed_unit(id: &str) -> String {
    format!("{SEALED_PREFIX}{id}.service")
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
