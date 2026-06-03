use std::{os::unix::process::CommandExt, path::Path};

use anyhow::Result;

pub fn exec(command: &Path, args: &[String], systemd_args: &[String], debug: bool) -> Result<()> {
    if debug {
        let display: Vec<String> = std::iter::once("systemd-run")
            .chain(["--user", "--wait", "-qPdt"].iter().copied())
            .chain(systemd_args.iter().map(String::as_str))
            .chain(["--"].iter().copied())
            .chain(std::iter::once(command.to_string_lossy().as_ref()))
            .chain(args.iter().map(String::as_str))
            .map(shell_quote)
            .collect();
        eprintln!("+ {}", display.join(" "));
    }

    let err = std::process::Command::new("systemd-run")
        .args(["--user", "--wait", "-qPdt"])
        .args(systemd_args)
        .arg("--")
        .arg(command)
        .args(args)
        .exec();

    // exec() only returns on failure
    Err(anyhow::Error::from(err).context("failed to exec systemd-run"))
}

/// Wrap a token in single quotes if it contains characters unsafe in shell.
fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '=' | ':' | '@' | '%' | '+' | ','))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
