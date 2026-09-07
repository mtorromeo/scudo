//! End-to-end checks that the logging is configurable, and that the command
//! line and the config file compose the way they are documented to.
//!
//! These drive the real binary, because that is the only place the two sources
//! actually meet: the config is read after the command line has already had a
//! subscriber installed for it.

#![cfg(target_os = "linux")]
// An integration test crate is all test functions; there is no module to put
// them in.
#![expect(clippy::tests_outside_test_module)]

use std::process::Command;

/// The line scudo emits at debug level for a command no profile restricts.
const DEBUG_LINE: &str = "no profile matched or empty systemd-run options";

/// Run `scudo <args> -- true` against `config`, returning its stderr.
///
/// `true` is deliberately unremarkable: no profile gives it any systemd
/// property, so scudo execs it directly and nothing but the logging is under
/// test.
fn run(config: &str, args: &[&str]) -> (String, tempdir::TempDir) {
    let dir = tempdir::TempDir::new();
    let scudo_dir = dir.path().join("scudo");
    std::fs::create_dir_all(&scudo_dir).expect("creating the config directory");
    std::fs::write(scudo_dir.join("config.toml"), config).expect("writing the config");

    let output = Command::new(env!("CARGO_BIN_EXE_scudo"))
        .env("XDG_CONFIG_HOME", dir.path())
        // Somewhere with no .scudo.toml, so no trust prompt appears.
        .current_dir(dir.path())
        .args(args)
        .args(["--", "true"])
        .output()
        .expect("running scudo");
    (String::from_utf8_lossy(&output.stderr).into_owned(), dir)
}

fn stderr_of(config: &str, args: &[&str]) -> String {
    run(config, args).0
}

/// A profile matching everything is how a global default is written: there is
/// no reserved section, only the ordinary precedence of glob < regex < exact.
#[test]
fn a_catch_all_profile_sets_the_default_level() {
    let stderr = stderr_of(
        "[default]\nmatch = { type = \"glob\", pattern = \"*\" }\nlog.level = \"debug\"\n",
        &[],
    );
    assert!(stderr.contains(DEBUG_LINE), "{stderr}");
}

#[test]
fn nothing_configured_says_nothing() {
    let stderr = stderr_of("", &[]);
    assert!(stderr.is_empty(), "{stderr}");
}

/// Precedence, not loudness: the exact match has to be able to quieten the
/// catch-all as well as to make it louder.
#[test]
fn an_exact_profile_can_be_quieter_than_the_catch_all() {
    let config = "[default]\nmatch = { type = \"glob\", pattern = \"*\" }\nlog.level = \"debug\"\n\
                  \n[quiet]\nmatch = \"true\"\nlog.level = \"error\"\n";
    let stderr = stderr_of(config, &[]);
    assert!(!stderr.contains(DEBUG_LINE), "{stderr}");
}

#[test]
fn the_command_line_has_the_last_word() {
    let config = "[default]\nmatch = { type = \"glob\", pattern = \"*\" }\nlog.level = \"debug\"\n";
    let stderr = stderr_of(config, &["--log-level", "error"]);
    assert!(!stderr.contains(DEBUG_LINE), "{stderr}");

    let quiet = "[default]\nmatch = { type = \"glob\", pattern = \"*\" }\nlog.level = \"error\"\n";
    let stderr = stderr_of(quiet, &["--log-level", "debug"]);
    assert!(stderr.contains(DEBUG_LINE), "{stderr}");
}

/// `verbose` predates the log table and has to keep meaning what it meant.
#[test]
fn verbose_in_a_profile_still_buys_debug() {
    let config = "[default]\nmatch = { type = \"glob\", pattern = \"*\" }\nverbose = true\n";
    let stderr = stderr_of(config, &[]);
    assert!(stderr.contains(DEBUG_LINE), "{stderr}");
}

/// `-v` raises the floor, so it cannot quieten a louder level next to it, and a
/// level written out on the command line is not overruled by it either.
#[test]
fn the_verbose_flag_only_ever_raises_the_level() {
    let stderr = stderr_of("", &["-v", "--log-level", "error"]);
    assert!(stderr.contains(DEBUG_LINE), "{stderr}");
}

/// A path and no target: there is nothing else a path could have been for, so
/// naming one is enough to move the output off stderr.
#[test]
fn a_path_takes_the_output_off_stderr() {
    let config = "[default]\nmatch = { type = \"glob\", pattern = \"*\" }\n\
                  log.level = \"debug\"\nlog.path = \"$SCUDO_CONFIG_DIR/only.log\"\n";
    let (stderr, dir) = run(config, &[]);
    assert!(stderr.is_empty(), "{stderr}");

    let written = std::fs::read_to_string(dir.path().join("scudo/only.log")).expect("the log file");
    assert!(written.contains(DEBUG_LINE), "{written}");
    // The file carries the level and a timestamp; stderr carries neither.
    assert!(written.contains("DEBUG"), "{written}");
}

/// Two destinations at once, and `$SCUDO_CONFIG_DIR` resolving to the directory
/// the config was read from.
#[test]
fn the_config_dir_variable_works_in_a_log_path() {
    let config = "[default]\nmatch = { type = \"glob\", pattern = \"*\" }\n\
                  log.level = \"debug\"\nlog.target = [\"stderr\", \"file\"]\n\
                  log.path = \"$SCUDO_CONFIG_DIR/scudo.log\"\n";
    let (stderr, dir) = run(config, &[]);
    assert!(stderr.contains(DEBUG_LINE), "{stderr}");

    let written =
        std::fs::read_to_string(dir.path().join("scudo/scudo.log")).expect("the log file");
    assert!(written.contains(DEBUG_LINE), "{written}");
}

/// The `log` table is parsed, not passed through, so a typo in it is caught
/// when the config is read rather than ignored for ever.
#[test]
fn a_misspelled_key_is_a_config_error() {
    let config = "[default]\nmatch = { type = \"glob\", pattern = \"*\" }\nlog.levl = \"debug\"\n";
    let stderr = stderr_of(config, &[]);
    assert!(stderr.contains("levl"), "{stderr}");
}

/// A config that cannot be read has to be reported at the default level: the
/// level it asked for is exactly what could not be read.
#[test]
fn a_broken_config_is_reported_without_being_asked() {
    let stderr = stderr_of("[default]\nlog.level = \"loud\"\n", &[]);
    assert!(stderr.starts_with("scudo: error:"), "{stderr}");
}

mod tempdir {
    use std::{
        path::{Path, PathBuf},
        sync::atomic::{AtomicUsize, Ordering},
    };

    /// Two directories live at once in some tests, and the thread id alone does
    /// not tell them apart — the second would delete the first on creation.
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    pub struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub fn new() -> Self {
            let base = std::env::temp_dir();
            let unique = format!(
                "scudo-log-test-{}-{:?}-{}",
                std::process::id(),
                std::thread::current().id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
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
