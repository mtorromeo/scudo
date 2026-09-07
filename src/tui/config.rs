//! What the terminal UI reads from the config.
//!
//! Only what a person writes by hand. The panel's width is not here: it is set
//! from inside the UI and remembered in [`state`](super::state), and having it
//! in both places would only let the two disagree.
//!
//! Compiled whether or not the `tui` feature is on, so that a config written
//! for a full build still parses under one built without it: the settings are
//! then simply never acted on. Every field is optional for the same reason
//! [`LogConfig`](crate::logging::LogConfig) makes them optional — a lower
//! priority source has to be able to fill in what a higher one left out.

use serde::Deserialize;

/// The prefix used when none is configured. Chosen over tmux's own `C-b` so
/// that scudo's UI and a tmux running inside it do not fight over one key.
pub const DEFAULT_PREFIX: &str = "C-a";

/// Lines of terminal scrollback kept behind the visible screen.
pub const DEFAULT_SCROLLBACK: usize = 10_000;

/// The `[scudo.tui]` table: how the terminal UI behaves when `--tui` asks for it.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TuiConfig {
    /// The key that introduces a UI command, as `C-a`, `M-x` or `F12`.
    pub prefix: Option<String>,
    pub scrollback: Option<usize>,
}

impl TuiConfig {
    /// Fields set on `self` win; the rest fall back to `lower`.
    #[must_use]
    pub fn over(self, lower: Self) -> Self {
        TuiConfig {
            prefix: self.prefix.or(lower.prefix),
            scrollback: self.scrollback.or(lower.scrollback),
        }
    }

    #[must_use]
    pub fn prefix(&self) -> &str {
        self.prefix.as_deref().unwrap_or(DEFAULT_PREFIX)
    }

    #[must_use]
    pub fn scrollback(&self) -> usize {
        self.scrollback.unwrap_or(DEFAULT_SCROLLBACK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_field_falls_through_to_the_lower_source() {
        let higher = TuiConfig {
            prefix: Some("C-b".to_owned()),
            ..TuiConfig::default()
        };
        let lower = TuiConfig {
            prefix: Some("C-x".to_owned()),
            scrollback: Some(500),
        };
        let merged = higher.over(lower);
        assert_eq!(merged.prefix(), "C-b");
        assert_eq!(merged.scrollback(), 500);

        // Neither source said anything, so the default stands.
        assert_eq!(TuiConfig::default().scrollback(), DEFAULT_SCROLLBACK);
    }

    #[test]
    fn an_unknown_key_is_a_typo_rather_than_something_to_pass_on() {
        let err = toml::from_str::<TuiConfig>("prefx = \"C-b\"\n")
            .expect_err("an unknown key must be rejected");
        assert!(err.to_string().contains("prefx"), "{err}");
    }

    /// The panel's width is governed from inside the UI and remembered there, so
    /// a config still naming it has to say so rather than be quietly ignored.
    #[test]
    fn a_panel_width_left_in_the_config_is_reported() {
        let err = toml::from_str::<TuiConfig>("panel_width = 40\n")
            .expect_err("the key no longer exists");
        assert!(err.to_string().contains("panel_width"), "{err}");
    }
}
