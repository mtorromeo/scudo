//! Reporting what the sandbox's filesystem restrictions turned away.
//!
//! This is the one policy kind that enforces nothing. systemd applies the
//! filesystem restrictions itself, by rearranging the unit's mount namespace,
//! and scudo has no say in the verdict — it only asks the daemon to notice, and
//! to name the path, which is the one thing the command is never told.
//!
//! It is a `Policy` all the same rather than a flag on the profile, because
//! everything the machinery needs is what a policy gets: a registration, a
//! token, a bus, and a shim that claims it from inside the cgroup. There is no
//! other way for the daemon to learn which cgroup to watch.

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
/// The same shape as the policy, because there is nothing here to normalise:
/// unlike the network table there are no lists to splice and no addresses to
/// parse. It exists so that the parse error names the table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemConfig {
    pub log: Option<LogLevel>,
}

impl FilesystemConfig {
    /// This table over `lower`, field by field.
    ///
    /// Like `log` and unlike `network`: there is nothing here to splice, so the
    /// table is parsed into its final shape when the config is read and merged
    /// with `.or()` rather than carried around as raw TOML.
    #[must_use]
    pub fn over(self, lower: Self) -> Self {
        FilesystemConfig {
            log: self.log.or(lower.log),
        }
    }

    /// Does this table ask for anything at all?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.log.is_none()
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
        };
        let quiet = FilesystemConfig {
            log: Some(LogLevel::Off),
        };
        assert_eq!(quiet.over(parent).log, Some(LogLevel::Off));
        assert_eq!(
            FilesystemConfig::default().over(parent).log,
            Some(LogLevel::Denied)
        );
        assert!(FilesystemConfig::default().is_empty());
        assert!(!quiet.is_empty());
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
