use std::{
    ffi::OsStr,
    io::{BufRead, BufWriter, Write},
    os::unix::process::CommandExt,
    path::Path,
};

use anyhow::{Context, Result};

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
            eprintln!("+ {cmdline}");
        }
    }

    let err = cmd.exec();
    Err(anyhow::Error::from(err).context("failed to exec systemd-run"))
}

/// Ask the user for confirmation on /dev/tty. Returns true if confirmed.
fn prompt_confirm(cmdline: &str) -> Result<bool> {
    let tty_out = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .context("cannot open /dev/tty")?;
    let tty_in = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .context("cannot open /dev/tty")?;

    let mut out = BufWriter::new(tty_out);
    writeln!(out, "{cmdline}")?;
    write!(out, "Proceed? [y/N] ")?;
    out.flush()?;

    let mut line = String::new();
    std::io::BufReader::new(tty_in).read_line(&mut line)?;

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
