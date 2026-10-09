use std::{
    ffi::OsStr, io::IsTerminal as _, os::unix::process::CommandExt as _, path::Path, process::Stdio,
};

use anyhow::{Context as _, Result};
use tracing::{debug, warn};

use crate::logging::{Level, LogConfig, Target};

/// How to start the command inside the transient unit.
#[derive(Debug)]
pub struct Options<'a> {
    pub verbose: bool,
    pub confirm: bool,
    /// Passed on to the watcher, which is spawned too late to read the config
    /// for itself.
    pub log: &'a LogConfig,
    /// When set, run the command through scudo's own shim, which claims the
    /// policies registered under this token before it execs the command.
    ///
    /// The shim exists because the cgroup does not exist until the unit starts:
    /// registering earlier is impossible, and attaching later would leave a
    /// window in which the command runs unfiltered.
    pub shim_token: Option<&'a str>,
    /// Report the network accesses the sandbox refuses.
    pub log_denials: bool,
    /// The filtered session bus the unit pulls in, still waiting for its
    /// arguments.
    pub dbus_proxy: Option<&'a crate::policy::dbus::Proxy>,
    /// The name to give the unit, when it has to be told apart from others:
    /// a sealed sandbox; see [`crate::nested`].
    pub unit: Option<&'a str>,
}

/// Build the `systemd-run` command line, without starting anything.
///
/// Split out from [`exec`] because the terminal UI needs the same command and a
/// different fate for it: it spawns it on a pty of its own rather than becoming
/// it, and there is nothing about how it is put together that should differ.
pub fn build(
    command: &Path,
    args: &[String],
    systemd_args: &[String],
    options: &Options<'_>,
) -> Result<std::process::Command> {
    let flags = if sets_working_directory(systemd_args) {
        "-Pt"
    } else {
        "-Pdt"
    };
    let mut cmd = std::process::Command::new("/usr/bin/systemd-run");
    cmd.args(["--user", "--wait", flags]);
    if let Some(unit) = options.unit {
        cmd.arg(format!("--unit={unit}"));
    }
    cmd.args(systemd_args);

    if !options.verbose {
        cmd.arg("-q");
    }

    cmd.arg("--");
    if let Some(token) = options.shim_token {
        let self_exe = std::env::current_exe().context("locating the scudo binary")?;
        cmd.arg(self_exe).arg("--bpf-shim").arg(token).arg("--");
    }
    cmd.arg(command).args(args);
    Ok(cmd)
}

/// A command line as it would be typed into a shell.
#[must_use]
pub fn render(cmd: &std::process::Command) -> String {
    core::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(shell_quote)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Show the command line and ask, when asking was requested and there is
/// somebody there to answer. Errors when the answer is no.
pub fn confirm(cmdline: &str, wanted: bool) -> Result<()> {
    if !wanted || !std::io::stdin().is_terminal() {
        return Ok(());
    }
    if prompt_confirm(format!("{cmdline}\nProceed?"))? {
        return Ok(());
    }
    anyhow::bail!("aborted")
}

pub fn exec(
    command: &Path,
    args: &[String],
    systemd_args: &[String],
    options: &Options<'_>,
) -> Result<()> {
    let Options {
        verbose,
        confirm: wanted,
        log,
        shim_token,
        log_denials,
        dbus_proxy,
        ..
    } = *options;

    let mut cmd = build(command, args, systemd_args, options)?;
    let interactive = std::io::stdin().is_terminal();

    if verbose || (wanted && interactive) {
        let cmdline = render(&cmd);
        if wanted && interactive {
            confirm(&cmdline, true)?;
        } else {
            debug!("running command: {cmdline}");
        }
    }

    // After the prompt, so that declining leaves nothing behind, and before the
    // exec, which is the last moment this process gets to start anything.
    if log_denials && let Some(token) = shim_token {
        spawn_watcher(token, command, log);
    }
    if let Some(proxy) = dbus_proxy {
        proxy.write_args()?;
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
fn spawn_watcher(token: &str, command: &Path, log: &LogConfig) {
    let self_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            warn!("cannot report blocked network accesses: {err}");
            return;
        }
    };
    // Only stderr is inherited: the watcher must not hold the command's own
    // input or output open, nor read from a terminal the command is using.
    let mut cmd = std::process::Command::new(self_exe);
    cmd.arg("--bpf-watch")
        .arg(token)
        .arg("--")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    for (key, value) in watcher_log_env(log) {
        cmd.env(key, value);
    }
    if let Err(err) = cmd.spawn() {
        warn!("cannot report blocked network accesses: {err}");
    }
}

/// The logging settings the watcher inherits, as environment variables.
///
/// It is a process of its own and never reads a config file, so whatever the
/// profiles decided has to travel to it this way. Its floor is `info`: the
/// watcher exists only because the denials were asked for, and its closing
/// summary must not then be filtered out by a quieter level.
fn watcher_log_env(log: &LogConfig) -> Vec<(&'static str, String)> {
    let mut env = vec![("SCUDO_LOG_LEVEL", log.level().max(Level::Info).to_string())];
    if let Some(targets) = log.targets.as_ref() {
        env.push((
            "SCUDO_LOG_TARGET",
            targets
                .iter()
                .map(Target::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ));
    }
    if let Some(path) = log.path.as_ref() {
        env.push(("SCUDO_LOG_FILE", path.clone()));
    }
    if let Some(facility) = log.syslog_facility {
        env.push(("SCUDO_LOG_SYSLOG_FACILITY", facility.to_string()));
    }
    env
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

/// Whether the unit properties already choose a working directory.
///
/// `-d` would start the command in ours instead, overriding the one that was
/// asked for, so it is left out when this holds.
fn sets_working_directory(systemd_args: &[String]) -> bool {
    sets_property(systemd_args, "WorkingDirectory")
}

/// Whether `systemd_args` set the unit property `key`, in any of the forms
/// `systemd-run` takes: `-p Key=…`, `--property Key=…`, `-pKey=…` or
/// `--property=Key=…`.
#[must_use]
pub fn sets_property(systemd_args: &[String], key: &str) -> bool {
    property_value(systemd_args, key).is_some()
}

/// The value `systemd_args` give the unit property `key`, in any of the forms
/// [`sets_property`] recognises. When it is set more than once this is the last
/// one, which is the one systemd keeps for a single-valued property.
#[must_use]
pub fn property_value<'a>(systemd_args: &'a [String], key: &str) -> Option<&'a str> {
    let value_of = |property: &'a str| property.strip_prefix(key)?.strip_prefix('=');
    let mut flagged = false;
    let mut last = None;
    for arg in systemd_args {
        let value = if flagged {
            value_of(arg)
        } else {
            arg.strip_prefix("--property=")
                .or_else(|| arg.strip_prefix("-p"))
                .and_then(value_of)
        };
        flagged = matches!(arg.as_str(), "-p" | "--property");
        last = value.or(last);
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_of(systemd_args: &[&str]) -> Vec<String> {
        args_with_unit(systemd_args, None)
    }

    fn args_with_unit(systemd_args: &[&str], unit: Option<&str>) -> Vec<String> {
        let systemd_args: Vec<String> = systemd_args.iter().map(ToString::to_string).collect();
        let log = LogConfig::default();
        let options = Options {
            verbose: false,
            confirm: false,
            log: &log,
            shim_token: None,
            log_denials: false,
            dbus_proxy: None,
            unit,
        };
        build(Path::new("/bin/true"), &[], &systemd_args, &options)
            .expect("the command builds")
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn same_dir_by_default() {
        let args = args_of(&["-p", "MemoryMax=1G"]);
        assert!(args.contains(&"-Pdt".to_owned()));
    }

    #[test]
    fn working_directory_from_a_profile_drops_same_dir() {
        let args = args_of(&["-p", "WorkingDirectory=/tmp"]);
        assert!(args.contains(&"-Pt".to_owned()));
        assert!(!args.contains(&"-Pdt".to_owned()));
    }

    #[test]
    fn working_directory_from_the_command_line_drops_same_dir() {
        let args = args_of(&["--property=WorkingDirectory=/tmp"]);
        assert!(args.contains(&"-Pt".to_owned()));
    }

    #[test]
    fn working_directory_in_another_value_keeps_same_dir() {
        let args = args_of(&["-p", "Environment=WorkingDirectory=/tmp"]);
        assert!(args.contains(&"-Pdt".to_owned()));
    }

    #[test]
    fn a_property_is_found_in_every_form() {
        let set = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(ToString::to_string).collect();
            sets_property(&args, "ProtectControlGroups")
        };
        assert!(set(&["-p", "ProtectControlGroups=no"]));
        assert!(set(&["--property", "ProtectControlGroups=no"]));
        assert!(set(&["-pProtectControlGroups=no"]));
        assert!(set(&["--property=ProtectControlGroups=no"]));
        assert!(!set(&["-p", "ProtectControlGroupsX=no"]));
        assert!(!set(&["-p", "Environment=ProtectControlGroups=no"]));
        assert!(!set(&[]));
    }

    #[test]
    fn the_last_value_of_a_property_is_the_one_kept() {
        let args: Vec<String> = [
            "-p",
            "ProtectControlGroups=no",
            "--property=ProtectControlGroups=private",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(
            property_value(&args, "ProtectControlGroups"),
            Some("private")
        );
        assert_eq!(property_value(&args, "MemoryMax"), None);
    }

    #[test]
    fn a_unit_name_is_passed_only_when_given() {
        let args = args_with_unit(&["-p", "MemoryMax=1G"], Some("scudo-sealed-1-a.service"));
        assert!(args.contains(&"--unit=scudo-sealed-1-a.service".to_owned()));
        assert!(
            !args_of(&["-p", "MemoryMax=1G"])
                .iter()
                .any(|a| a.starts_with("--unit"))
        );
    }
}
