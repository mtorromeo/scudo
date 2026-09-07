//! What the terminal UI remembers between runs.
//!
//! This is not configuration, and the distinction is the reason it lives in a
//! file of its own: nothing here was written by hand, everything here can be
//! changed from inside the UI, and scudo rewrites it without asking. A config
//! file is the opposite on all three counts, which is why the panel's width was
//! taken out of it — two sources for one value only differ in order to disagree.
//!
//! Nothing here is worth failing a command over. A state file that cannot be
//! read means nothing was remembered; one that cannot be written means nothing
//! will be. Both are a note in the log and no more.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

/// The file, beside the trust database in the same per-user directory.
const STATE_FILE: &str = "state.toml";

/// What the UI remembers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub tui: TuiState,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuiState {
    /// Absent while the width follows the screen. Absent is a value here, not a
    /// missing one: it is how "let it follow the screen again" is recorded, and
    /// writing a number for it would make that choice unrecoverable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub panel_width: Option<u16>,
}

fn path() -> Result<PathBuf> {
    Ok(crate::config::user_path()
        .context("determining the state file path")?
        .join(STATE_FILE))
}

/// Read what was remembered. Never fails: nothing here is worth stopping for.
#[must_use]
pub fn load() -> State {
    path().map_or_else(|_| State::default(), |path| load_from(&path))
}

fn load_from(path: &Path) -> State {
    let Ok(content) = std::fs::read_to_string(path) else {
        // Overwhelmingly: no file yet, which is not worth a word.
        return State::default();
    };
    match toml::from_str(&content) {
        Ok(state) => state,
        Err(err) => {
            debug!("ignoring {}: {err}", path.display());
            State::default()
        }
    }
}

/// Write what to remember, replacing the file as one step.
///
/// The rename is what makes it one step: another scudo may be starting up and
/// reading this file at the same moment, and a half-written one would read as a
/// broken one.
pub fn save(state: &State) -> Result<()> {
    save_to(&path()?, state)
}

fn save_to(path: &Path, state: &State) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let content = toml::to_string(state).context("serialising the UI state")?;

    let temporary = path.with_extension("toml.new");
    std::fs::write(&temporary, content)
        .with_context(|| format!("writing {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file of our own to work on. The public `load`/`save` resolve the path
    /// from the environment, which is why the tests use the two halves below
    /// them instead: a test that had to set `$XDG_CONFIG_HOME` could not run
    /// beside another one, and the whole path is covered end to end in
    /// `tests/tui.rs` anyway.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("scudo-state-{name}-{}", std::process::id()));
            drop(std::fs::remove_dir_all(&dir));
            std::fs::create_dir_all(&dir).expect("a scratch directory");
            Scratch(dir.join(STATE_FILE))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if let Some(dir) = self.0.parent() {
                drop(std::fs::remove_dir_all(dir));
            }
        }
    }

    #[test]
    fn a_width_written_is_a_width_read_back() {
        let scratch = Scratch::new("roundtrip");
        let state = State {
            tui: TuiState {
                panel_width: Some(48),
            },
        };
        save_to(&scratch.0, &state).expect("the state is written");
        assert_eq!(load_from(&scratch.0), state);
    }

    /// The first run of all, and every run before this file existed.
    #[test]
    fn nothing_remembered_yet_is_not_an_error() {
        let scratch = Scratch::new("absent");
        assert_eq!(load_from(&scratch.0), State::default());
        assert_eq!(load_from(&scratch.0).tui.panel_width, None);
    }

    /// A file someone edited by hand, or one truncated by a full disk.
    #[test]
    fn a_file_that_cannot_be_read_means_nothing_was_remembered() {
        let scratch = Scratch::new("broken");
        std::fs::write(&scratch.0, "[tui\npanel_width = ").expect("the file is written");
        assert_eq!(load_from(&scratch.0), State::default());
    }

    /// Going back to automatic has to be recordable, or the first width chosen
    /// would be the last one ever used.
    #[test]
    fn going_back_to_automatic_leaves_no_width_behind() {
        let scratch = Scratch::new("automatic");
        save_to(
            &scratch.0,
            &State {
                tui: TuiState {
                    panel_width: Some(48),
                },
            },
        )
        .expect("the state is written");
        save_to(&scratch.0, &State::default()).expect("the state is written again");
        assert_eq!(load_from(&scratch.0).tui.panel_width, None);
    }
}
