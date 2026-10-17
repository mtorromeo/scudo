//! End-to-end checks that a sandbox which delegates a command gets it run in a
//! sandbox of its own, and that what the request controls cannot widen it.
//!
//! These start units under `systemd --user`, so they are ignored by default:
//!
//! ```sh
//! cargo test --test delegation -- --ignored
//! ```

#![cfg(target_os = "linux")]
// An integration test crate is all test functions; there is no module to put
// them in.
#![expect(clippy::tests_outside_test_module)]

use std::{os::unix::fs::PermissionsExt as _, path::Path, process::Command};

/// A sandbox, `agent`, that delegates every delegable profile: `probe-*` get a
/// profile of their own, `code` does not. The tool may not see `agent-only`,
/// which the agent writes.
const CONFIG: &str = r#"
[agent]
filesystem.read = ["/"]
filesystem.write = ["$PWD"]
delegate = true

# The same sandbox, delegating nothing unless the command line asks.
[plain]
filesystem.read = ["/"]
filesystem.write = ["$PWD"]

[tool]
match = "probe-tool"
delegable = true
filesystem.read = ["/"]
filesystem.write = ["$PWD"]
filesystem.deny = ["$PWD/agent-only"]

[mk]
match = "probe-mk"
delegable = true
args.directory = ["-C"]
filesystem.read = ["/"]
filesystem.write = ["${arg_directory:-$PWD}"]

[code]
match = "probe-code"
filesystem.read = ["/"]
filesystem.write = ["$PWD"]
"#;

/// What the probe prints: the unit it ran in, and whether it saw the agent's
/// own directory. It exits 7, so that the code can be seen to travel.
const PROBE: &str = "#!/bin/sh
echo \"unit=$(grep -o 'scudo-[a-z]*-[0-9a-f-]*\\.service' /proc/self/cgroup)\"
if ls agent-only >/dev/null 2>&1; then echo saw-agent-only; fi
exit 7
";

/// Run `script` with `sh` inside the `agent` sandbox, from a directory holding
/// the probes, and return its standard output and exit code.
fn agent(script: &str) -> (String, i32) {
    sandbox("agent", &[], script)
}

/// Like [`agent`], under `profile` and with `flags` on the command line.
fn sandbox(profile: &str, flags: &[&str], script: &str) -> (String, i32) {
    let dir = tempdir::TempDir::new();
    let config = dir.path().join("config/scudo");
    std::fs::create_dir_all(&config).expect("creating the config directory");
    std::fs::write(config.join("config.toml"), CONFIG).expect("writing the config");
    let work = dir.path().join("work");
    std::fs::create_dir_all(work.join("agent-only")).expect("creating the work directory");
    for probe in ["probe-tool", "probe-mk", "probe-code"] {
        write_executable(&work.join(probe), PROBE);
    }

    // `systemd-run` passes no environment on, so the path is written in.
    let script = script.replace("$SCUDO", env!("CARGO_BIN_EXE_scudo"));
    let output = Command::new(env!("CARGO_BIN_EXE_scudo"))
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        // `$PWD` in a profile is the variable, which `current_dir` leaves alone.
        .env("PWD", &work)
        .current_dir(&work)
        .args(["--no-match", "--profile", profile])
        .args(flags)
        .args(["--", "sh", "-c", &script])
        .output()
        .expect("running scudo");
    // stderr follows, so that a failing assertion shows why.
    let text = format!(
        "{}--- stderr\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (text, output.status.code().unwrap_or(-1i32))
}

fn write_executable(path: &Path, body: &str) {
    std::fs::write(path, body).expect("writing a probe");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("making a probe executable");
}

/// The unit a probe line names.
fn units(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("unit="))
        .collect()
}

#[test]
#[ignore = "starts units under systemd --user"]
fn a_delegated_command_runs_in_a_sandbox_of_its_own() {
    let (stdout, code) = agent(
        "echo \"unit=$(grep -o 'scudo-[a-z]*-[0-9a-f-]*\\.service' /proc/self/cgroup)\"
         \"$SCUDO\" -- ./probe-tool; echo \"code=$?\"",
    );
    assert_eq!(code, 0i32, "{stdout}");
    let units = units(&stdout);
    assert_eq!(units.len(), 2usize, "{stdout}");
    assert_ne!(
        units.first(),
        units.get(1),
        "the tool ran in the agent's unit"
    );
    assert!(!stdout.contains("saw-agent-only"), "{stdout}");
    assert!(stdout.contains("code=7"), "{stdout}");
}

#[test]
#[ignore = "starts units under systemd --user"]
fn a_command_nobody_delegated_runs_where_it_was_started() {
    let (stdout, _) = agent(
        "echo \"unit=$(grep -o 'scudo-[a-z]*-[0-9a-f-]*\\.service' /proc/self/cgroup)\"
         \"$SCUDO\" -- sh -c \"grep -o 'scudo-[a-z]*-[0-9a-f-]*\\.service' /proc/self/cgroup | sed 's/^/unit=/'\"",
    );
    let units = units(&stdout);
    assert_eq!(units.len(), 2usize, "{stdout}");
    assert_eq!(units.first(), units.get(1), "{stdout}");
}

/// `-C /` would have given the delegated profile the whole filesystem to write,
/// far more than the agent itself had.
#[test]
#[ignore = "starts units under systemd --user"]
fn an_argument_cannot_widen_what_the_profile_writes() {
    let (stdout, _) = agent("\"$SCUDO\" -- ./probe-mk -C /; echo \"code=$?\"");
    assert!(stdout.contains("code=1"), "{stdout}");
    assert!(units(&stdout).is_empty(), "{stdout}");

    let (stdout, _) = agent("\"$SCUDO\" -- ./probe-mk -C .; echo \"code=$?\"");
    assert!(stdout.contains("code=7"), "{stdout}");
}

/// `code` has a profile of its own but was never marked `delegable`, so asking
/// for it gets the caller's sandbox and not that profile.
#[test]
#[ignore = "starts units under systemd --user"]
fn a_profile_nobody_made_delegable_is_not_delegated() {
    let (stdout, _) = agent(
        "echo \"unit=$(grep -o 'scudo-[a-z]*-[0-9a-f-]*\\.service' /proc/self/cgroup)\"
         \"$SCUDO\" -- ./probe-code",
    );
    let units = units(&stdout);
    assert_eq!(units.len(), 2usize, "{stdout}");
    assert_eq!(units.first(), units.get(1), "{stdout}");
}

/// Where the agent shell and the tool it starts ran.
const BOTH_UNITS: &str =
    "echo \"unit=$(grep -o 'scudo-[a-z]*-[0-9a-f-]*\\.service' /proc/self/cgroup)\"
     \"$SCUDO\" -- ./probe-tool";

#[test]
#[ignore = "starts units under systemd --user"]
fn no_delegate_keeps_every_command_in_the_sandbox() {
    let (stdout, _) = sandbox("agent", &["--no-delegate"], BOTH_UNITS);
    let units = units(&stdout);
    assert_eq!(units.len(), 2usize, "{stdout}");
    assert_eq!(units.first(), units.get(1), "{stdout}");
}

#[test]
#[ignore = "starts units under systemd --user"]
fn delegate_on_the_command_line_delegates_what_is_delegable() {
    let (stdout, _) = sandbox("plain", &[], BOTH_UNITS);
    let without = units(&stdout);
    assert_eq!(without.len(), 2usize, "{stdout}");
    assert_eq!(without.first(), without.get(1), "{stdout}");

    let (stdout, _) = sandbox("plain", &["--delegate"], BOTH_UNITS);
    let with = units(&stdout);
    assert_eq!(with.len(), 2usize, "{stdout}");
    assert_ne!(with.first(), with.get(1), "{stdout}");
}

/// A temporary directory that cleans up after itself, so the tests need no
/// dependency for one.
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub fn new() -> Self {
            let base = std::env::temp_dir();
            let unique = format!(
                "scudo-delegation-test-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            );
            let path = base.join(unique.replace(['(', ')', ' '], ""));
            drop(std::fs::remove_dir_all(&path));
            std::fs::create_dir_all(&path).expect("creating a temporary directory");
            TempDir { path }
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.path));
        }
    }
}
