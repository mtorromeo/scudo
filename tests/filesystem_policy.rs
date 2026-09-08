//! End-to-end checks that refused file accesses are reported.
//!
//! These need `scudo-bpfd` running with `CAP_PERFMON` on top of the two
//! capabilities the network tests want, and the daemon must be the *installed*
//! binary — `cargo make install` puts it in place and grants all three. Run
//! them with:
//!
//! ```sh
//! cargo make install --profile production
//! systemctl --user restart scudo-bpfd.socket
//! cargo test --test filesystem_policy -- --ignored
//! ```
//!
//! Nothing here is enforced by scudo: systemd hides the paths, and what is
//! under test is whether the daemon notices and says which ones.
//!
//! **A command that only lists a directory produces no events at all.** `ls`
//! inside a `$HOME` replaced by `TemporaryFileSystem=` reads an empty tmpfs and
//! never asks for a file it has not just seen; `find` does the same
//! recursively. What produces events is a command that *names* a path without
//! knowing whether it is there — which is what every real program does on
//! startup, and what the commands below do on purpose.

#![cfg(target_os = "linux")]
// An integration test crate is all test functions; there is no module to put
// them in.
#![expect(clippy::tests_outside_test_module)]

use std::{io::Write as _, path::PathBuf, process::Command};

fn daemon_socket() -> PathBuf {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").expect("XDG_RUNTIME_DIR is not set");
    PathBuf::from(runtime_dir).join("scudo/bpfd.sock")
}

fn require_daemon() {
    let socket = daemon_socket();
    assert!(
        socket.exists(),
        "scudo-bpfd is not running: {} does not exist",
        socket.display()
    );
}

/// Write a config holding a single `probe` profile and return its XDG dir.
fn config_with(body: &str) -> tempdir::TempDir {
    let dir = tempdir::TempDir::new();
    let scudo_dir = dir.path().join("scudo");
    std::fs::create_dir_all(&scudo_dir).expect("creating the config directory");
    let mut file =
        std::fs::File::create(scudo_dir.join("config.toml")).expect("creating the config");
    write!(file, "[probe]\n{body}").expect("writing the config");
    dir
}

/// Run a command under the `probe` profile and return everything scudo said.
///
/// stderr is a pipe, and the watcher process inherits it, so reading to EOF
/// also waits for the watcher to finish — which is what makes the reports
/// observable here at all.
fn run(config: &str, argv: &[&str]) -> String {
    require_daemon();
    let dir = config_with(config);
    let output = Command::new(env!("CARGO_BIN_EXE_scudo"))
        .env("XDG_CONFIG_HOME", dir.path())
        // Run from a directory with no .scudo.toml, so no trust prompt appears.
        .current_dir(dir.path())
        // Everything below the sandbox's own denials is at debug, which is
        // where a path that was missing outside too is deliberately kept.
        .args([
            "--log-level",
            "debug",
            "--no-match",
            "--profile",
            "probe",
            "--",
        ])
        .args(argv)
        .output()
        .expect("running scudo");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn home() -> String {
    std::env::var("HOME").expect("HOME is not set")
}

/// The case the whole feature exists for: a file that is really there, which
/// the sandbox took away, named by a command that has no way to say so itself.
#[test]
#[ignore = "needs scudo-bpfd with CAP_PERFMON"]
fn a_file_the_sandbox_hid_is_reported_as_hidden() {
    let home = home();
    let marker = PathBuf::from(&home).join(".scudo-fs-test-marker");
    std::fs::write(&marker, b"marker").expect("writing the marker file");

    let stderr = run(
        &format!("filesystem.log = \"denied\"\nsystemd.TemporaryFileSystem = \"{home}\"\n"),
        &["cat", marker.to_str().expect("a UTF-8 path")],
    );
    drop(std::fs::remove_file(&marker));

    assert!(
        stderr.contains(".scudo-fs-test-marker"),
        "the hidden path was not named: {stderr}"
    );
    assert!(
        stderr.contains("hidden by the sandbox"),
        "it was not reported as hidden: {stderr}"
    );
}

/// A path that is nowhere is not a refusal, and must not be reported as one —
/// this is what keeps a linker's search out of an ordinary run.
#[test]
#[ignore = "needs scudo-bpfd with CAP_PERFMON"]
fn a_path_that_is_nowhere_is_not_called_blocked() {
    let home = home();
    let missing = PathBuf::from(&home).join(".scudo-fs-test-nowhere");
    assert!(!missing.exists(), "the test's own premise is broken");

    let stderr = run(
        &format!("filesystem.log = \"denied\"\nsystemd.TemporaryFileSystem = \"{home}\"\n"),
        &["cat", missing.to_str().expect("a UTF-8 path")],
    );

    assert!(
        stderr.contains(".scudo-fs-test-nowhere"),
        "the path was not reported at all: {stderr}"
    );
    assert!(
        stderr.contains("not there outside the sandbox either"),
        "it should not read as a refusal: {stderr}"
    );
}

/// The half of the story `ReadOnlyPaths=` tells, which nothing on the read path
/// would ever see.
#[test]
#[ignore = "needs scudo-bpfd with CAP_PERFMON"]
fn a_write_under_a_read_only_path_is_reported_as_read_only() {
    let stderr = run(
        "filesystem.log = \"denied\"\nsystemd.ReadOnlyPaths = [\"/\"]\nsystemd.PrivateTmp = false\n",
        &["mkdir", "/var/tmp/scudo-fs-test-dir"],
    );
    assert!(
        stderr.contains("read-only"),
        "a write under ReadOnlyPaths was not reported: {stderr}"
    );
}

/// Asking for the panel is asking for what fills it: a sandboxed command run
/// verbosely reports its files without the profile having to say so.
#[test]
#[ignore = "needs scudo-bpfd with CAP_PERFMON"]
fn verbose_reports_a_sandboxed_commands_files_without_being_configured() {
    let home = home();
    let marker = PathBuf::from(&home).join(".scudo-fs-test-implicit");
    std::fs::write(&marker, b"marker").expect("writing the marker file");

    let dir = config_with(&format!("systemd.TemporaryFileSystem = \"{home}\"\n"));
    let output = Command::new(env!("CARGO_BIN_EXE_scudo"))
        .env("XDG_CONFIG_HOME", dir.path())
        .current_dir(dir.path())
        .args(["--verbose", "--no-match", "--profile", "probe", "--", "cat"])
        .arg(&marker)
        .output()
        .expect("running scudo");
    drop(std::fs::remove_file(&marker));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(".scudo-fs-test-implicit"),
        "the hidden path was not named: {stderr}"
    );
}

/// Nothing is attached to the machine while nothing is being watched. A
/// tracepoint left on every `openat()` for the next command that might want it
/// would be a cost paid by everything else on the system.
#[test]
#[ignore = "needs scudo-bpfd with CAP_PERFMON and bpftool"]
fn no_tracepoint_is_left_attached_once_the_command_is_gone() {
    let home = home();
    let stderr = run(
        &format!("filesystem.log = \"denied\"\nsystemd.TemporaryFileSystem = \"{home}\"\n"),
        &["cat", &format!("{home}/.scudo-fs-test-gone")],
    );
    assert!(stderr.contains(".scudo-fs-test-gone"), "{stderr}");

    // The daemon reaps on a five second timer, and the object goes with the
    // last watch.
    std::thread::sleep(std::time::Duration::from_secs(8));
    let listed = Command::new("bpftool")
        .args(["prog", "list"])
        .output()
        .expect("running bpftool");
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(
        !listed.contains("sys_enter"),
        "a tracepoint is still attached: {listed}"
    );
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
                "scudo-fs-test-{}-{:?}",
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
