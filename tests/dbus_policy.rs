//! End-to-end checks that a sandboxed command cannot leave its cgroup, and
//! that a filtered session bus lets through what it names and nothing else.
//!
//! These start units under `systemd --user`, so they are ignored by default.
//! The filtered ones also need `xdg-dbus-proxy` and the `scudo-dbus@.service`
//! template, whose `ExecStart=` has to point at the scudo being tested. Run
//! them with:
//!
//! ```sh
//! sed "s#/usr/bin/scudo #$PWD/target/debug/scudo #" scudo-dbus@.service \
//!     > ~/.config/systemd/user/scudo-dbus@.service
//! systemctl --user daemon-reload
//! cargo test --test dbus_policy -- --ignored
//! ```

#![cfg(target_os = "linux")]
// An integration test crate is all test functions; there is no module to put
// them in.
#![expect(clippy::tests_outside_test_module)]

use std::{io::Write as _, process::Command};

/// Write a config holding a single `probe` profile and return its XDG dir.
///
/// The profile always reads `/`, so that it is a sandbox whatever `body` says.
fn config_with(body: &str) -> tempdir::TempDir {
    let dir = tempdir::TempDir::new();
    let scudo_dir = dir.path().join("scudo");
    std::fs::create_dir_all(&scudo_dir).expect("creating the config directory");
    let mut file =
        std::fs::File::create(scudo_dir.join("config.toml")).expect("creating the config");
    write!(file, "[probe]\nfilesystem.read = [\"/\"]\n{body}").expect("writing the config");
    dir
}

/// Run `args` under the `probe` profile and return its exit code.
fn run_under(body: &str, args: &[&str]) -> i32 {
    let dir = config_with(body);
    let mut command_line = vec!["--no-match", "--profile", "probe", "--"];
    command_line.extend_from_slice(args);
    let status = Command::new(env!("CARGO_BIN_EXE_scudo"))
        .env("XDG_CONFIG_HOME", dir.path())
        // Run from a directory with no .scudo.toml, so no trust prompt appears.
        .current_dir(dir.path())
        .args(&command_line)
        .status()
        .expect("running scudo");
    status.code().unwrap_or(-1i32)
}

/// Ask the service manager for a sibling unit: the shortest way out.
const ESCAPE: &[&str] = &["systemd-run", "--user", "--wait", "-q", "true"];

/// Move this shell into the cgroup above its own: the other way out.
const MIGRATE: &[&str] = &[
    "sh",
    "-c",
    "echo $$ > \"/sys/fs/cgroup$(dirname \"$(cut -d: -f3 /proc/self/cgroup)\")/cgroup.procs\"",
];

#[test]
#[ignore = "starts units under systemd --user"]
fn the_bus_is_gone_by_default() {
    assert_ne!(run_under("", &["busctl", "--user", "status"]), 0i32);
}

/// Without a network policy too: what the cgroup carries is not only the
/// network filter.
#[test]
#[ignore = "starts units under systemd --user"]
fn the_service_manager_cannot_be_used_to_escape() {
    assert_ne!(
        run_under("", ESCAPE),
        0i32,
        "the sandbox reached the service manager and left its cgroup"
    );
}

#[test]
#[ignore = "starts units under systemd --user"]
fn the_cgroup_cannot_be_left_by_hand() {
    assert_ne!(
        run_under("", MIGRATE),
        0i32,
        "the sandbox moved itself out of its cgroup"
    );
}

#[test]
#[ignore = "starts units under systemd --user"]
fn allow_gives_the_service_manager_back() {
    assert_eq!(run_under("dbus.session = \"allow\"\n", ESCAPE), 0i32);
}

/// The bus is there, but the service manager is not on it.
#[test]
#[ignore = "needs xdg-dbus-proxy and scudo-dbus@.service"]
fn a_filtered_bus_hides_what_it_does_not_name() {
    let body = "dbus.talk = [\"org.example.Nothing\"]\n";
    assert_eq!(run_under(body, &["busctl", "--user", "status"]), 0i32);
    assert_ne!(
        run_under(body, ESCAPE),
        0i32,
        "the filtered bus let the sandbox reach the service manager"
    );
    assert_ne!(run_under(body, MIGRATE), 0i32);
}

#[test]
#[ignore = "needs xdg-dbus-proxy and scudo-dbus@.service"]
fn a_filtered_bus_lets_through_what_it_names() {
    let body = "dbus.talk = [\"org.freedesktop.systemd1\"]\n";
    let args = [
        "busctl",
        "--user",
        "get-property",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "Version",
    ];
    assert_eq!(run_under(body, &args), 0i32);
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
                "scudo-dbus-test-{}-{:?}",
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
