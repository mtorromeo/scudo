use std::{
    ffi::OsStr, io::IsTerminal as _, os::unix::process::CommandExt as _, path::Path, process::Stdio,
};

use anyhow::{Context as _, Result};

/// How to start the command inside the transient unit.
#[derive(Debug, Default)]
pub struct Options<'a> {
    pub verbose: bool,
    pub confirm: bool,
    /// When set, run the command through scudo's own shim, which claims the
    /// policies registered under this token before it execs the command.
    ///
    /// The shim exists because the cgroup does not exist until the unit starts:
    /// registering earlier is impossible, and attaching later would leave a
    /// window in which the command runs unfiltered.
    pub shim_token: Option<&'a str>,
    /// Report the network accesses the sandbox refuses.
    pub log_denials: bool,
}

pub fn exec(
    command: &Path,
    args: &[String],
    systemd_args: &[String],
    options: &Options<'_>,
) -> Result<()> {
    let Options {
        verbose,
        confirm,
        shim_token,
        log_denials,
    } = *options;

    let mut cmd = std::process::Command::new("/usr/bin/systemd-run");
    cmd.args(["--user", "--wait", "-Pdt"]).args(systemd_args);

    if !verbose {
        cmd.arg("-q");
    }

    cmd.arg("--");
    if let Some(token) = shim_token {
        let self_exe = std::env::current_exe().context("locating the scudo binary")?;
        cmd.arg(self_exe).arg("--bpf-shim").arg(token).arg("--");
    }
    cmd.arg(command).args(args);

    let interactive = std::io::stdin().is_terminal();

    if verbose || (confirm && interactive) {
        let cmdline = core::iter::once(cmd.get_program())
            .chain(cmd.get_args())
            .map(shell_quote)
            .collect::<Vec<_>>()
            .join(" ");

        if confirm && interactive {
            if !prompt_confirm(format!("{cmdline}\nProceed?"))? {
                anyhow::bail!("aborted");
            }
        } else {
            eprintln!("scudo: running command: {cmdline}");
        }
    }

    // After the prompt, so that declining leaves nothing behind, and before the
    // exec, which is the last moment this process gets to start anything.
    if log_denials && let Some(token) = shim_token {
        spawn_watcher(token, command);
    }

    let err = cmd.exec();
    Err(anyhow::Error::from(err).context("failed to exec systemd-run"))
}

/// Start the process that prints what the sandbox turns away.
///
/// It has to be a separate process: this one is about to become `systemd-run`,
/// and the shim inside the unit becomes the command itself, so neither is left
/// to read anything. The watcher keeps our stderr and outlives us both, ending
/// when the daemon closes the stream on it.
fn spawn_watcher(token: &str, command: &Path) {
    let self_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("scudo: warning: cannot report blocked network accesses: {err}");
            return;
        }
    };
    // Only stderr is inherited: the watcher must not hold the command's own
    // input or output open, nor read from a terminal the command is using.
    let spawned = std::process::Command::new(self_exe)
        .arg("--bpf-watch")
        .arg(token)
        .arg("--")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn();
    if let Err(err) = spawned {
        eprintln!("scudo: warning: cannot report blocked network accesses: {err}");
    }
}

/// Ask the user for confirmation on stdin. Returns true if confirmed.
pub fn prompt_confirm<S: AsRef<str>>(question: S) -> Result<bool> {
    eprint!("{} [y/N] ", question.as_ref());

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
    let s = s.display().to_string();
    if s.chars().all(|c| {
        c.is_alphanumeric()
            || matches!(c, '-' | '_' | '.' | '/' | '=' | ':' | '@' | '%' | '+' | ',')
    }) {
        s
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
