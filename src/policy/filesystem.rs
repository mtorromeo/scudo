//! The filesystem half of a profile: which paths the command may write, read,
//! not see, or not touch — and reporting what those restrictions turned away.
//!
//! Access is declared as four lists rather than as systemd properties, so that
//! profiles written without knowing about each other can be combined: every
//! path ends up with the most permissive access any of them asked for, and
//! whether that takes `ReadOnlyPaths=` or a bind mount depends on whether some
//! profile hid a directory above it — something no single profile can know.
//! The unit's own properties hide directories too (`PrivateTmp=` replaces
//! `/tmp`), so they are read for the same decision; see [`UnitMounts`].
//!
//! Reporting is the one policy kind that enforces nothing. systemd applies the
//! filesystem restrictions itself, by rearranging the unit's mount namespace,
//! and scudo has no say in the verdict — it only asks the daemon to notice, and
//! to name the path, which is the one thing the command is never told.
//!
//! It is a `Policy` all the same rather than a flag on the profile, because
//! everything the machinery needs is what a policy gets: a registration, a
//! token, a bus, and a shim that claims it from inside the cgroup. There is no
//! other way for the daemon to learn which cgroup to watch.

use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::policy::network::LogLevel;

/// Whether the sandbox says what it could not reach on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    /// Off by default. Reporting means a set of system-wide tracepoints, and
    /// most commands are run with nobody watching; `--verbose` and `--tui` turn
    /// it on for one run, and this is how a profile keeps it on.
    #[serde(default)]
    pub log: LogLevel,
}

impl FilesystemPolicy {
    /// `true` when this sandbox should report refused file accesses.
    #[must_use]
    pub fn reports_denials(&self) -> bool {
        self.log == LogLevel::Denied
    }
}

/// What a `[profile.filesystem]` table may say.
///
/// The paths are kept as written: they may still hold `$VAR` and `$arg_*`
/// references, which are only expanded once the command line is known.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemConfig {
    pub log: Option<LogLevel>,
    /// Paths the command may read and write.
    #[serde(default)]
    pub write: Vec<String>,
    /// Paths the command may read but not write.
    #[serde(default)]
    pub read: Vec<String>,
    /// Directories replaced by an empty, throwaway one.
    #[serde(default)]
    pub hide: Vec<String>,
    /// Paths the command may not access at all.
    #[serde(default)]
    pub deny: Vec<String>,
}

impl FilesystemConfig {
    /// This table over `lower`: the lists accumulate, and `log` is the one
    /// that was said last.
    #[must_use]
    pub fn over(self, lower: Self) -> Self {
        FilesystemConfig {
            log: self.log.or(lower.log),
            write: union(lower.write, self.write),
            read: union(lower.read, self.read),
            hide: union(lower.hide, self.hide),
            deny: union(lower.deny, self.deny),
        }
    }
}

fn union(mut base: Vec<String>, extra: Vec<String>) -> Vec<String> {
    for entry in extra {
        if !base.contains(&entry) {
            base.push(entry);
        }
    }
    base
}

/// Accesses given on the command line, applied on top of whatever the profiles
/// settled on.
///
/// They have the last word on the paths they name: the most permissive access
/// wins among profiles, so hiding something a profile reads would otherwise
/// change nothing. Paths below one keep what the profiles gave them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilesystemOverrides {
    entries: Vec<(Access, PathBuf)>,
}

impl FilesystemOverrides {
    /// Parse the values of `--fs-hide`, `--fs-read` and `--fs-write`. They are
    /// taken as written, the shell having expanded whatever they held, and made
    /// absolute against the current directory.
    pub fn parse(hide: &[String], read: &[String], write: &[String]) -> Result<Self> {
        let mut entries: Vec<(Access, PathBuf)> = Vec::new();
        for (access, list) in [
            (Access::Hide, hide),
            (Access::Read, read),
            (Access::Write, write),
        ] {
            for entry in list {
                let path = normalize(
                    &std::path::absolute(entry)
                        .with_context(|| format!("invalid path '{entry}'"))?,
                );
                match entries.iter().find(|(_, known)| *known == path) {
                    // Two accesses at once have no order to settle them.
                    Some((known, _)) if *known != access => bail!(
                        "{} is given two accesses on the command line",
                        path.display()
                    ),
                    Some(_) => {}
                    None => entries.push((access, path)),
                }
            }
        }
        Ok(FilesystemOverrides { entries })
    }

    /// `true` when no path was given.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The accesses given, for the log.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        for (label, wanted) in [
            ("hide", Access::Hide),
            ("read", Access::Read),
            ("write", Access::Write),
        ] {
            let list: Vec<_> = self
                .entries
                .iter()
                .filter(|(access, _)| *access == wanted)
                .map(|(_, path)| path.to_string_lossy())
                .collect();
            if !list.is_empty() {
                parts.push(format!("{label} {}", list.join(",")));
            }
        }
        parts.join("; ")
    }

    /// Replace what the profiles' `entries` say about each path given here.
    #[must_use]
    pub fn apply(&self, mut entries: Vec<(Access, PathBuf)>) -> Vec<(Access, PathBuf)> {
        entries.retain(|(_, path)| {
            let path = normalize(path);
            !self.entries.iter().any(|(_, given)| *given == path)
        });
        entries.extend(self.entries.iter().cloned());
        entries
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                out.push(component);
            }
        }
    }
    out
}

/// The access a path is given, from least to most permissive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    Deny,
    Hide,
    Read,
    Write,
}

/// What the unit's own properties do to whole directories, as far as the
/// `filesystem` lists care.
///
/// Fed the `systemd` table's properties, already expanded, in order; a
/// single-valued one said twice counts as its last value, as in systemd.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitMounts {
    private_tmp: bool,
    private_devices: bool,
    protect_home: ProtectHome,
    temporary: Vec<PathBuf>,
    inaccessible: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum ProtectHome {
    #[default]
    No,
    ReadOnly,
    Tmpfs,
    Yes,
}

const HOMES: [&str; 3] = ["/home", "/root", "/run/user"];

impl UnitMounts {
    /// Take one value of the unit property `key` into account.
    pub fn add(&mut self, key: &str, value: &str) {
        let on = !matches!(value, "no" | "false" | "0" | "off");
        match key {
            "PrivateTmp" => self.private_tmp = on,
            "PrivateDevices" => self.private_devices = on,
            "ProtectHome" => {
                self.protect_home = match value {
                    "read-only" => ProtectHome::ReadOnly,
                    "tmpfs" => ProtectHome::Tmpfs,
                    _ if on => ProtectHome::Yes,
                    _ => ProtectHome::No,
                };
            }
            // Both take a space-separated list; a temporary file system's
            // options follow its path after a `:`.
            "TemporaryFileSystem" => self.temporary.extend(
                value
                    .split_whitespace()
                    .filter_map(|entry| entry.split(':').next())
                    .map(|path| normalize(Path::new(path))),
            ),
            "InaccessiblePaths" => self.inaccessible.extend(
                value
                    .split_whitespace()
                    .map(|entry| normalize(Path::new(entry.trim_start_matches(['-', '+'])))),
            ),
            _ => {}
        }
    }

    /// Directories the unit replaces with fresh ones: what is granted inside
    /// has to be bind-mounted in.
    fn replaced(&self) -> Vec<PathBuf> {
        let mut dirs = self.temporary.clone();
        if self.private_tmp {
            dirs.extend(["/tmp", "/var/tmp"].map(PathBuf::from));
        }
        if self.private_devices {
            dirs.push(PathBuf::from("/dev"));
        }
        if self.protect_home == ProtectHome::Tmpfs {
            dirs.extend(HOMES.map(PathBuf::from));
        }
        dirs
    }

    /// Directories the unit makes inaccessible, inside which nothing can be
    /// mounted, not even a bind mount.
    fn inaccessible(&self) -> Vec<PathBuf> {
        let mut dirs = self.inaccessible.clone();
        if self.protect_home == ProtectHome::Yes {
            dirs.extend(HOMES.map(PathBuf::from));
        }
        dirs
    }
}

/// The systemd properties that realise the `filesystem` lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mounts {
    pub properties: Vec<(&'static str, String)>,
    /// Paths granted inside an inaccessible directory: systemd cannot give
    /// them back, so the grant has no effect.
    pub unreachable: Vec<PathBuf>,
}

/// Turn the accesses asked for into the systemd properties that realise them.
///
/// A path named more than once gets the most permissive access among them, so
/// a profile that only reads a directory cannot take writing away from one
/// that writes it. A path inside a hidden directory — one of the lists' or one
/// the `unit` replaces — is not there to be made read-only or writable, so it
/// is bind-mounted back in instead. Every path but a hidden one is prefixed
/// with `-`, which tells systemd to skip it when it does not exist: a tool's
/// config directory often does not yet.
///
/// Paths are expected to be absolute already; they are only normalised here,
/// lexically, so that `/a/b/`, `/a/./b` and `/a/c/../b` are the same path.
/// Symlinks are left alone on purpose: binding a link's target in place of the
/// link would put it somewhere the command does not look.
#[must_use]
pub fn mount_properties<I>(entries: I, unit: &UnitMounts) -> Mounts
where
    I: IntoIterator<Item = (Access, PathBuf)>,
{
    let mut paths: BTreeMap<PathBuf, Access> = BTreeMap::new();
    for (access, path) in entries {
        let path = normalize(&path);
        let slot = paths.entry(path).or_insert(access);
        *slot = (*slot).max(access);
    }

    let listed = |wanted: Access| -> Vec<&Path> {
        paths
            .iter()
            .filter(|&(_, access)| *access == wanted)
            .map(|(path, _)| path.as_path())
            .collect()
    };
    let (hidden, denied) = (listed(Access::Hide), listed(Access::Deny));
    let (replaced, inaccessible) = (unit.replaced(), unit.inaccessible());
    // A listed directory is itself what the grant on it overrides; one the
    // unit replaces is gone even when the grant names it.
    let inside = |path: &Path, listed: &[&Path], unit: &[PathBuf]| {
        listed.iter().any(|dir| *dir != path && path.starts_with(dir))
            || unit.iter().any(|dir| path.starts_with(dir))
    };

    let mut unreachable = Vec::new();
    let properties = paths
        .iter()
        .map(|(path, access)| {
            let granted = matches!(access, Access::Read | Access::Write);
            if granted && inside(path, &denied, &inaccessible) {
                unreachable.push(path.clone());
            }
            let under_hidden = inside(path, &hidden, &replaced);
            let shown = path.to_string_lossy();
            let optional = format!("-{shown}");
            match access {
                Access::Deny => ("InaccessiblePaths", optional),
                Access::Hide => ("TemporaryFileSystem", shown.into_owned()),
                Access::Read if under_hidden => ("BindReadOnlyPaths", optional),
                Access::Read => ("ReadOnlyPaths", optional),
                Access::Write if under_hidden => ("BindPaths", optional),
                Access::Write => ("ReadWritePaths", optional),
            }
        })
        .collect();
    Mounts {
        properties,
        unreachable,
    }
}

impl From<FilesystemConfig> for FilesystemPolicy {
    fn from(config: FilesystemConfig) -> Self {
        FilesystemPolicy {
            log: config.log.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_table_that_says_nothing_reports_nothing() {
        let config: FilesystemConfig = toml::from_str("").expect("an empty table parses");
        assert!(!FilesystemPolicy::from(config).reports_denials());
    }

    #[test]
    fn asking_to_be_told_is_what_turns_it_on() {
        let config: FilesystemConfig =
            toml::from_str(r#"log = "denied""#).expect("a log setting parses");
        assert!(FilesystemPolicy::from(config).reports_denials());
    }

    /// A child's setting wins over the profile it extends, and a child that
    /// says nothing keeps the parent's.
    #[test]
    fn a_child_overrides_what_it_mentions_and_inherits_the_rest() {
        let parent = FilesystemConfig {
            log: Some(LogLevel::Denied),
            read: vec!["/a".to_owned()],
            ..FilesystemConfig::default()
        };
        let quiet = FilesystemConfig {
            log: Some(LogLevel::Off),
            read: vec!["/b".to_owned(), "/a".to_owned()],
            ..FilesystemConfig::default()
        };
        let merged = quiet.over(parent.clone());
        assert_eq!(merged.log, Some(LogLevel::Off));
        assert_eq!(merged.read, ["/a", "/b"]);
        assert_eq!(
            FilesystemConfig::default().over(parent).log,
            Some(LogLevel::Denied)
        );
    }

    fn mounts(entries: &[(Access, &str)], unit: &[(&str, &str)]) -> Mounts {
        let mut mounts = UnitMounts::default();
        for (key, value) in unit {
            mounts.add(key, value);
        }
        mount_properties(entries.iter().map(|(a, p)| (*a, PathBuf::from(p))), &mounts)
    }

    fn props(entries: &[(Access, &str)]) -> Vec<(&'static str, String)> {
        mounts(entries, &[]).properties
    }

    fn props_in(entries: &[(Access, &str)], unit: &[(&str, &str)]) -> Vec<(&'static str, String)> {
        mounts(entries, unit).properties
    }

    /// `PrivateTmp=` replaces `/tmp` and `/var/tmp` as `hide` would, so what is
    /// granted there, the directory itself included, has to be bind-mounted.
    #[test]
    fn grants_inside_a_private_tmp_are_bind_mounts() {
        let entries = [
            (Access::Write, "/tmp/claude-1000"),
            (Access::Read, "/var/tmp/x"),
            (Access::Write, "/tmp"),
            (Access::Write, "/tmpfoo"),
        ];
        for value in ["yes", "true", "disconnected"] {
            assert_eq!(
                props_in(&entries, &[("PrivateTmp", value)]),
                [
                    ("BindPaths", "-/tmp".to_owned()),
                    ("BindPaths", "-/tmp/claude-1000".to_owned()),
                    ("ReadWritePaths", "-/tmpfoo".to_owned()),
                    ("BindReadOnlyPaths", "-/var/tmp/x".to_owned()),
                ],
                "{value}"
            );
        }
        // The last value said is the one systemd keeps.
        assert_eq!(
            props_in(&entries[..1], &[("PrivateTmp", "yes"), ("PrivateTmp", "no")]),
            [("ReadWritePaths", "-/tmp/claude-1000".to_owned())]
        );
    }

    #[test]
    fn directories_the_unit_replaces_take_bind_mounts() {
        assert_eq!(
            props_in(&[(Access::Write, "/dev/kvm")], &[("PrivateDevices", "yes")]),
            [("BindPaths", "-/dev/kvm".to_owned())]
        );
        assert_eq!(
            props_in(&[(Access::Read, "/home/u/.gitconfig")], &[("ProtectHome", "tmpfs")]),
            [("BindReadOnlyPaths", "-/home/u/.gitconfig".to_owned())]
        );
        assert_eq!(
            props_in(
                &[(Access::Write, "/srv/a"), (Access::Write, "/opt/b")],
                &[("TemporaryFileSystem", "/srv:ro /opt")]
            ),
            [
                ("BindPaths", "-/opt/b".to_owned()),
                ("BindPaths", "-/srv/a".to_owned()),
            ]
        );
        // Read-only is a restriction a nested grant can lift.
        assert_eq!(
            props_in(&[(Access::Write, "/home/u/p")], &[("ProtectHome", "read-only")]),
            [("ReadWritePaths", "-/home/u/p".to_owned())]
        );
    }

    /// Nothing can be mounted inside an inaccessible directory, so a grant
    /// there is reported rather than silently dropped by systemd.
    #[test]
    fn grants_inside_an_inaccessible_directory_are_unreachable() {
        let found = mounts(
            &[
                (Access::Deny, "/secret"),
                (Access::Read, "/secret/a"),
                (Access::Deny, "/denied"),
                (Access::Write, "/denied"),
                (Access::Write, "/home/u/p"),
                (Access::Write, "/srv/x"),
                (Access::Hide, "/srv/x/y"),
            ],
            &[("ProtectHome", "yes"), ("InaccessiblePaths", "-/srv")],
        );
        assert_eq!(
            found.unreachable,
            ["/home/u/p", "/secret/a", "/srv/x"].map(PathBuf::from)
        );
    }

    #[test]
    fn each_access_has_its_property() {
        assert_eq!(
            props(&[
                (Access::Write, "/w"),
                (Access::Read, "/r"),
                (Access::Hide, "/h"),
                (Access::Deny, "/d"),
            ]),
            [
                ("InaccessiblePaths", "-/d".to_owned()),
                ("TemporaryFileSystem", "/h".to_owned()),
                ("ReadOnlyPaths", "-/r".to_owned()),
                ("ReadWritePaths", "-/w".to_owned()),
            ]
        );
    }

    /// Profiles that disagree about a path end up with the most permissive
    /// access among them, whatever order they come in.
    #[test]
    fn the_most_permissive_access_wins() {
        for entries in [
            [
                (Access::Read, "/p"),
                (Access::Write, "/p/"),
                (Access::Deny, "/p"),
            ],
            [
                (Access::Deny, "/p"),
                (Access::Write, "/p"),
                (Access::Read, "/./p"),
            ],
        ] {
            assert_eq!(props(&entries), [("ReadWritePaths", "-/p".to_owned())]);
        }
        assert_eq!(
            props(&[(Access::Deny, "/p"), (Access::Read, "/p")]),
            [("ReadOnlyPaths", "-/p".to_owned())]
        );
        assert_eq!(
            props(&[(Access::Hide, "/p"), (Access::Deny, "/p")]),
            [("TemporaryFileSystem", "/p".to_owned())]
        );
    }

    /// Inside a hidden directory there is nothing to restrict: what is granted
    /// there has to be mounted back in.
    #[test]
    fn grants_inside_a_hidden_directory_are_bind_mounts() {
        assert_eq!(
            props(&[
                (Access::Hide, "/home/u"),
                (Access::Read, "/home/u/.gitconfig"),
                (Access::Write, "/home/u/proj"),
                (Access::Deny, "/home/u/proj/secret"),
                (Access::Read, "/home/user2"),
            ]),
            [
                ("TemporaryFileSystem", "/home/u".to_owned()),
                ("BindReadOnlyPaths", "-/home/u/.gitconfig".to_owned()),
                ("BindPaths", "-/home/u/proj".to_owned()),
                ("InaccessiblePaths", "-/home/u/proj/secret".to_owned()),
                // A sibling that merely shares a prefix is not inside it.
                ("ReadOnlyPaths", "-/home/user2".to_owned()),
            ]
        );
    }

    fn overrides(hide: &[&str], read: &[&str], write: &[&str]) -> FilesystemOverrides {
        let owned = |list: &[&str]| list.iter().map(ToString::to_string).collect::<Vec<_>>();
        FilesystemOverrides::parse(&owned(hide), &owned(read), &owned(write)).unwrap()
    }

    /// The command line has the last word on the paths it names, even against
    /// a more permissive profile, and leaves what is below them alone.
    #[test]
    fn the_command_line_replaces_what_profiles_say_about_a_path() {
        let entries = overrides(&["/p/"], &[], &[]).apply(vec![
            (Access::Write, PathBuf::from("/p")),
            (Access::Read, PathBuf::from("/./p")),
            (Access::Write, PathBuf::from("/p/sub")),
        ]);
        assert_eq!(
            mount_properties(entries, &UnitMounts::default()).properties,
            [
                ("TemporaryFileSystem", "/p".to_owned()),
                ("BindPaths", "-/p/sub".to_owned()),
            ]
        );
        let entries = overrides(&[], &[], &["/h/u/p"]).apply(vec![(Access::Hide, "/h/u".into())]);
        assert_eq!(
            mount_properties(entries, &UnitMounts::default()).properties,
            [
                ("TemporaryFileSystem", "/h/u".to_owned()),
                ("BindPaths", "-/h/u/p".to_owned()),
            ]
        );
    }

    #[test]
    fn command_line_paths_are_absolute_and_may_not_disagree() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            overrides(&[], &["rel"], &[]).apply(Vec::new()),
            [(Access::Read, cwd.join("rel"))]
        );
        // Saying the same twice is not disagreeing.
        assert_eq!(overrides(&["/a", "/a/"], &[], &[]).entries.len(), 1);
        let err = FilesystemOverrides::parse(&["/a".into()], &[], &["/a/.".into()])
            .expect_err("two accesses for one path");
        assert!(format!("{err}").contains("/a"), "{err}");
        assert_eq!(
            overrides(&["/h"], &["/r"], &["/w", "/x"]).describe(),
            "hide /h; read /r; write /w,/x"
        );
    }

    /// `deny_unknown_fields` is what makes a typo an error rather than a
    /// setting that silently does nothing.
    #[test]
    fn a_misspelt_key_is_an_error_and_not_a_shrug() {
        let err = toml::from_str::<FilesystemConfig>(r#"logg = "denied""#)
            .expect_err("an unknown key is refused");
        assert!(format!("{err}").contains("logg"), "{err}");
    }
}
