//! Finding the command scudo stands in for, past other shims that stand in for
//! it too.
//!
//! scudo looks the command up in `PATH` and skips the entries that are itself.
//! Another shim installed under the same name (a build cache wrapping `cargo`)
//! does the same, so each finds the other and the real command is never run.
//! What breaks the loop is noticing that a call came straight back: the same
//! name, arguments and directory that scudo just dispatched. Whatever it chose
//! then only handed the call on, and is skipped this time. A program calling
//! itself again with exactly the same command line would loop on its own; one
//! that recurses with other arguments resolves as usual.

use std::{
    ffi::OsStr,
    hash::{Hash as _, Hasher as _},
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// What a dispatched command is told about how it was found, for a scudo it
/// calls back to read.
pub const ENV: &str = "SCUDO_DISPATCH";

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    call: String,
    skip: Vec<PathBuf>,
}

/// One call to look up: what identifies it, and what not to choose for it.
#[derive(Debug)]
pub struct Dispatch {
    call: String,
    skip: Vec<PathBuf>,
}

impl Dispatch {
    /// The call `command args…` made from the current directory, with what the
    /// environment says was already tried for it.
    #[must_use]
    pub fn new(command: &str, args: &[String]) -> Self {
        let cwd = std::env::current_dir().unwrap_or_default();
        Self::from_parts(command, args, &cwd, std::env::var(ENV).ok().as_deref())
    }

    fn from_parts(command: &str, args: &[String], cwd: &Path, inherited: Option<&str>) -> Self {
        let call = fingerprint(command, args, cwd);
        let skip = match inherited.map(serde_json::from_str::<Record>) {
            Some(Ok(record)) if record.call == call => record.skip,
            Some(Err(err)) => {
                debug!("ignoring {ENV}: {err}");
                Vec::new()
            }
            Some(Ok(_)) | None => Vec::new(),
        };
        if !skip.is_empty() {
            debug!(
                "'{command}' came back unchanged: skipping {}",
                listed(&skip)
            );
        }
        Self { call, skip }
    }

    /// Find the command in `PATH`, past scudo itself and what this call
    /// already went through.
    ///
    /// # Errors
    ///
    /// When nothing is left to run.
    pub fn which(&self, command: &str, self_exe: &Path) -> Result<PathBuf> {
        lookup(
            command,
            self_exe,
            &self.skip,
            &std::env::var_os("PATH").unwrap_or_default(),
        )
    }

    /// The value of [`ENV`] for `bin`, chosen for this call.
    #[must_use]
    pub fn record(&self, bin: &Path) -> Option<String> {
        let mut skip = self.skip.clone();
        skip.push(std::fs::canonicalize(bin).unwrap_or_else(|_| bin.to_path_buf()));
        serde_json::to_string(&Record {
            call: self.call.clone(),
            skip,
        })
        .inspect_err(|err| debug!("not recording the dispatch of '{}': {err}", bin.display()))
        .ok()
    }
}

fn fingerprint(command: &str, args: &[String], cwd: &Path) -> String {
    // `DefaultHasher::new` has fixed keys: the same call hashes the same in
    // every process of the same build.
    let mut hasher = std::hash::DefaultHasher::new();
    Path::new(command).file_name().hash(&mut hasher);
    args.hash(&mut hasher);
    cwd.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn listed(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether `candidate` is neither scudo nor something to skip.
fn eligible(candidate: &Path, self_exe: &Path, skip: &[PathBuf]) -> bool {
    matches!(
        std::fs::canonicalize(candidate),
        Ok(canonical) if canonical != self_exe && !skip.contains(&canonical)
    )
}

fn lookup(command: &str, self_exe: &Path, skip: &[PathBuf], path: &OsStr) -> Result<PathBuf> {
    if command.contains('/') && eligible(Path::new(command), self_exe, skip) {
        return Ok(std::path::absolute(command).or_else(|_| std::fs::canonicalize(command))?);
    }

    let name = Path::new(command)
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("invalid command: {command}"))?;

    for dir in std::env::split_paths(path) {
        let candidate = dir.join(name);
        if candidate.is_file() && eligible(&candidate, self_exe, skip) {
            return Ok(candidate);
        }
    }

    if skip.is_empty() {
        anyhow::bail!("command not found: {}", name.display());
    }
    anyhow::bail!(
        "every '{}' in PATH leads back to scudo (already tried: {})",
        name.display(),
        listed(skip)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("scudo-dispatch-{tag}-{}", std::process::id()));
            drop(std::fs::remove_dir_all(&dir));
            std::fs::create_dir_all(&dir).unwrap();
            Self(std::fs::canonicalize(dir).unwrap())
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.0));
        }
    }

    /// `scudo/cargo` → the fake scudo, `shim/cargo` and `real/cargo` files of
    /// their own; returns the fake scudo and the `PATH` in that order.
    fn layout(root: &Path) -> (PathBuf, std::ffi::OsString) {
        let self_exe = root.join("scudo-bin");
        std::fs::write(&self_exe, "").unwrap();
        let dirs = ["scudo", "shim", "real"].map(|dir| root.join(dir));
        for dir in &dirs {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::os::unix::fs::symlink(&self_exe, dirs[0].join("cargo")).unwrap();
        std::fs::write(dirs[1].join("cargo"), "").unwrap();
        std::fs::write(dirs[2].join("cargo"), "").unwrap();
        (self_exe, std::env::join_paths(&dirs).unwrap())
    }

    #[test]
    fn a_call_that_comes_back_unchanged_skips_what_it_went_through() {
        let root = TempDir::new("loop");
        let (self_exe, path) = layout(&root.0);
        let shim = root.0.join("shim/cargo");
        let real = root.0.join("real/cargo");
        let args = vec!["build".to_owned()];

        let first = Dispatch::from_parts("cargo", &args, &root.0, None);
        assert_eq!(
            lookup("cargo", &self_exe, &first.skip, &path).unwrap(),
            shim
        );

        // The shim called `cargo build` again, from the same place.
        let record = first.record(&shim).unwrap();
        let second = Dispatch::from_parts("cargo", &args, &root.0, Some(&record));
        assert_eq!(
            lookup("cargo", &self_exe, &second.skip, &path).unwrap(),
            real
        );

        let record = second.record(&real).unwrap();
        let third = Dispatch::from_parts("cargo", &args, &root.0, Some(&record));
        let err = lookup("cargo", &self_exe, &third.skip, &path).unwrap_err();
        assert!(err.to_string().contains("leads back to scudo"), "{err}");
    }

    #[test]
    fn a_different_call_starts_over() {
        let root = TempDir::new("other");
        let (self_exe, path) = layout(&root.0);
        let shim = root.0.join("shim/cargo");
        let first = Dispatch::from_parts("cargo", &["build".to_owned()], &root.0, None);
        let record = first.record(&shim).unwrap();

        for (args, cwd) in [
            (vec!["check".to_owned()], root.0.clone()),
            (vec!["build".to_owned()], root.0.join("real")),
        ] {
            let next = Dispatch::from_parts("cargo", &args, &cwd, Some(&record));
            assert_eq!(next.skip, Vec::<PathBuf>::new());
            assert_eq!(lookup("cargo", &self_exe, &next.skip, &path).unwrap(), shim);
        }
    }

    #[test]
    fn a_path_to_the_command_is_followed_unless_skipped() {
        let root = TempDir::new("path");
        let (self_exe, path) = layout(&root.0);
        let shim = root.0.join("shim/cargo");
        let real = root.0.join("real/cargo");
        let given = shim.to_str().unwrap();
        assert_eq!(lookup(given, &self_exe, &[], &path).unwrap(), shim);
        assert_eq!(
            lookup(given, &self_exe, std::slice::from_ref(&shim), &path).unwrap(),
            real
        );
    }

    #[test]
    fn an_unreadable_record_is_ignored() {
        let dispatch = Dispatch::from_parts("cargo", &[], Path::new("/"), Some("not json"));
        assert_eq!(dispatch.skip, Vec::<PathBuf>::new());
    }
}
