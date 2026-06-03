use std::{ffi::OsStr, os::unix::process::CommandExt, path::Path};

use anyhow::Result;

pub fn exec(
    command: &Path,
    args: &[String],
    systemd_args: &[String],
    debug: bool,
    confirm: bool,
) -> Result<()> {
    let mut cmd = std::process::Command::new("systemd-run");
    cmd.args(["--user", "--wait", "-Pdt"]).args(systemd_args);

    if !debug {
        cmd.arg("-q");
    }

    cmd.arg("--").arg(command).args(args);

    if debug || confirm {
        let cmdline = std::iter::once(cmd.get_program())
            .chain(cmd.get_args())
            .map(shell_quote)
            .collect::<Vec<_>>()
            .join(" ");

        if confirm {
            if !prompt_confirm(&cmdline)? {
                anyhow::bail!("aborted");
            }
        } else {
            eprintln!("scudo: running command: {cmdline}");
        }
    }

    let err = cmd.exec();
    Err(anyhow::Error::from(err).context("failed to exec systemd-run"))
}

/// Ask the user for confirmation on stdin. Returns true if confirmed.
fn prompt_confirm(cmdline: &str) -> Result<bool> {
    eprintln!("{cmdline}\nProceed? [y/N] ");

    let mut line = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut line)?;

    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Wrap a token in single quotes if it contains characters unsafe in shell.
fn shell_quote(s: &OsStr) -> String {
    let s = s.to_string_lossy();
    if s.chars().all(|c| {
        c.is_alphanumeric()
            || matches!(c, '-' | '_' | '.' | '/' | '=' | ':' | '@' | '%' | '+' | ',')
    }) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
