use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use similar::{ChangeTag, TextDiff};

use crate::config;
use crate::runner;

#[derive(Serialize, Deserialize, Default)]
struct TrustDb {
    #[serde(default)]
    entries: Vec<TrustEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct TrustEntry {
    path: String,
    content: String,
}

fn load_trust_db(path: &Path) -> Result<TrustDb> {
    if !path.is_file() {
        return Ok(TrustDb::default());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading trust db {}", path.display()))?;
    toml::from_str(&content).with_context(|| format!("parsing trust db {}", path.display()))
}

fn save_trust_db(db_path: &Path, db: &TrustDb) -> Result<()> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating config dir {}", parent.display()))?;
    }
    let content = toml::to_string(db).context("serializing trust db")?;
    std::fs::write(db_path, content)
        .with_context(|| format!("writing trust db {}", db_path.display()))
}

/// Check whether `file_path` with the given `content` is trusted.
/// If not, show a diff (or full content for new files) and prompt the user.
/// Returns an error if the user declines, and without asking at all when
/// `interactive` is false.
pub fn check_and_confirm(file_path: &Path, content: &str, interactive: bool) -> Result<()> {
    let db_path = config::user_path()
        .with_context(|| "determining trust db file path")?
        .join("trusted.toml");

    let mut db = load_trust_db(&db_path)?;
    let path_str = file_path.to_string_lossy().to_string();

    if let Some(entry) = db.entries.iter().find(|e| e.path == path_str) {
        if entry.content == content {
            return Ok(());
        }
        if !interactive {
            bail!(
                "config file {path_str} changed since it was trusted; run scudo from a \
                 terminal there to review it"
            );
        }
        // Content changed: show diff against the trusted version
        eprintln!("\nModified config file: {path_str}");
        eprintln!("--- trusted version");
        eprintln!("+++ current version\n");
        let diff = TextDiff::from_lines(entry.content.as_str(), content);
        for change in diff.iter_all_changes() {
            let sign = match change.tag() {
                ChangeTag::Delete => "-",
                ChangeTag::Insert => "+",
                ChangeTag::Equal => " ",
            };
            eprint!("{sign}{change}");
        }
    } else if !interactive {
        bail!(
            "config file {path_str} is not trusted; run scudo from a terminal there to \
             review it"
        );
    } else {
        // New path: show full content
        eprintln!("\nNew config file: {path_str}\n");
        for line in content.lines() {
            eprintln!("  {line}");
        }
    }
    eprintln!();

    if !runner::prompt_confirm("Trust this config file?")? {
        bail!("Untrusted config file: {path_str}");
    }

    let content = content.to_owned();

    // Persist the trusted content
    if let Some(entry) = db.entries.iter_mut().find(|e| e.path == path_str) {
        entry.content = content;
    } else {
        db.entries.push(TrustEntry {
            path: path_str,
            content,
        });
    }
    save_trust_db(&db_path, &db)
}
