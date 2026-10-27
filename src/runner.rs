use std::{
    ffi::{OsStr, OsString},
    io::IsTerminal as _,
    os::unix::process::CommandExt as _,
    path::Path,
    process::Stdio,
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
    /// A descriptor to put in place of stderr just before the command starts,
    /// so that the watcher and the command write to it while everything scudo
    /// said before still went to the stderr it was started with. A delegated
    /// run uses it for the requester's stderr; see [`crate::broker`].
    pub stderr: Option<i32>,
    /// Variables, by name or glob, not to copy from this process's
    /// environment into the unit; see [`EnvRules::unit_changes`].
    pub deny_env: &'a [String],
    /// Variables copied even though `deny_env` matches them.
    pub allow_env: &'a [String],
    /// The service manager's environment, as `NAME=value`, which the unit
    /// starts from; see [`manager_environment`].
    pub manager_env: &'a [String],
    /// How the command was found, for a scudo it calls back; see
    /// [`crate::dispatch`].
    pub dispatch: Option<&'a str>,
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
    // Only the names go on the command line: `systemd-run` reads the values
    // from the environment it inherits, so they are not echoed with it.
    let set_by_unit = environment_names(systemd_args);
    let env = EnvRules {
        deny: &compile(options.deny_env),
        allow: &compile(options.allow_env),
        set_by_unit: &set_by_unit,
    };
    let (copied, unset) = env.unit_changes(std::env::vars_os(), options.manager_env);
    for name in copied {
        cmd.arg(format!("--setenv={name}"));
    }
    if let Some(record) = options.dispatch {
        cmd.env(crate::dispatch::ENV, record);
        cmd.arg(format!("--setenv={}", crate::dispatch::ENV));
    }
    if !unset.is_empty() {
        cmd.arg(format!("--property=UnsetEnvironment={}", unset.join(" ")));
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

/// Variables that never cross into the unit, whatever `allow_env` says: those
/// the service manager sets for the unit it runs scudo in, which would describe
/// that unit instead of the sandbox, scudo's own between broker and run, and
/// the dispatch record, which describes the call that started this scudo.
const NEVER_COPIED: &[&str] = &[
    "NOTIFY_SOCKET",
    "LISTEN_FDS",
    "LISTEN_PID",
    "LISTEN_FDNAMES",
    "INVOCATION_ID",
    "JOURNAL_STREAM",
    "MANAGERPID",
    "MAINPID",
    "SYSTEMD_EXEC_PID",
    "WATCHDOG_PID",
    "WATCHDOG_USEC",
    "MONITOR_*",
    "TRIGGER_*",
    crate::broker::SPEC_ENV,
    crate::broker::FD_ENV,
    crate::broker::DELEGATE_ENV,
    crate::dispatch::ENV,
];

/// Every pattern was checked when it was read.
fn compile(patterns: &[impl AsRef<str>]) -> Vec<glob::Pattern> {
    patterns
        .iter()
        .filter_map(|pattern| glob::Pattern::new(pattern.as_ref()).ok())
        .collect()
}

fn matches_any(patterns: &[glob::Pattern], name: &str) -> bool {
    patterns.iter().any(|pattern| pattern.matches(name))
}

/// What decides which variables the command gets.
struct EnvRules<'a> {
    deny: &'a [glob::Pattern],
    allow: &'a [glob::Pattern],
    /// What the unit sets itself with `Environment=`: a value a profile or
    /// scudo fixed is not for the caller's environment to replace, nor to take
    /// away.
    set_by_unit: &'a [&'a str],
}

impl EnvRules<'_> {
    fn denied(&self, name: &str) -> bool {
        matches_any(self.deny, name) && !matches_any(self.allow, name)
    }

    /// Whether the unit's value of `name` is left to what it would be anyway.
    fn untouchable(&self, name: &str) -> bool {
        thread_local! {
            static NEVER: Vec<glob::Pattern> = compile(NEVER_COPIED);
        }
        // A name no shell could have set, such as bash's exported functions,
        // is no name `systemd-run` takes either.
        !crate::config::is_var_name(name)
            || self.set_by_unit.contains(&name)
            || NEVER.with(|never| matches_any(never, name))
    }

    /// What to change of the environment the unit starts from, the service
    /// manager's (`manager`, as `NAME=value`), so that the command gets
    /// `present` less what is denied: the names to copy with `--setenv`,
    /// sorted, and the names to take away with `UnsetEnvironment=`, sorted.
    ///
    /// A variable the manager already has with the same value is not copied
    /// again; one the manager has and the command should not, because it is
    /// denied or because `present` lacks it, is unset. `UnsetEnvironment=`
    /// is applied last, over every other source, so it is never given what
    /// the unit sets itself.
    fn unit_changes(
        &self,
        present: impl Iterator<Item = (OsString, OsString)>,
        manager: &[String],
    ) -> (Vec<String>, Vec<String>) {
        let manager: std::collections::HashMap<&str, &str> = manager
            .iter()
            .filter_map(|assignment| assignment.split_once('='))
            .collect();
        let present: std::collections::BTreeMap<String, OsString> = present
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value)))
            .filter(|(name, _)| !self.untouchable(name) && !self.denied(name))
            .collect();
        let copied = present
            .iter()
            .filter(|&(name, value)| manager.get(name.as_str()).copied() != value.to_str())
            .map(|(name, _)| name.clone())
            .collect();
        let mut unset: Vec<String> = manager
            .keys()
            .filter(|&&name| !self.untouchable(name) && !present.contains_key(name))
            .map(|&name| name.to_owned())
            .collect();
        unset.sort_unstable();
        (copied, unset)
    }
}

/// Take what `deny_env` keeps out from a command run as it is, outside any
/// sandbox: there is no unit, and no manager's environment, to account for.
pub fn remove_denied_env(
    cmd: &mut std::process::Command,
    deny_env: &[String],
    allow_env: &[String],
) {
    if deny_env.is_empty() {
        return;
    }
    let rules = EnvRules {
        deny: &compile(deny_env),
        allow: &compile(allow_env),
        set_by_unit: &[],
    };
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(|name| rules.denied(name)) {
            cmd.env_remove(name);
        }
    }
}

/// The service manager's environment, as `NAME=value`: what every unit it
/// starts begins with, before `--setenv` and `Environment=`.
///
/// Read with `busctl` rather than `systemctl show-environment`, which quotes
/// the values it prints.
pub fn manager_environment() -> Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Property {
        data: Vec<String>,
    }
    let output = std::process::Command::new("busctl")
        .args([
            "--user",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "Environment",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .context("running busctl")?;
    if !output.status.success() {
        anyhow::bail!("busctl failed: {}", output.status);
    }
    let property: Property =
        serde_json::from_slice(&output.stdout).context("reading busctl's answer")?;
    Ok(property.data)
}

/// The names the unit's `Environment=` assignments set, in any of the forms
/// [`property_value`] recognises. A value holds assignments separated by
/// spaces, each of which may be quoted.
fn environment_names(systemd_args: &[String]) -> Vec<&str> {
    property_values(systemd_args, "Environment")
        .flat_map(str::split_whitespace)
        .filter_map(|assignment| {
            assignment
                .trim_start_matches(['"', '\''])
                .split_once('=')
                .map(|(name, _)| name)
        })
        .collect()
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

    if let Some(fd) = options.stderr {
        // SAFETY: dup2 on descriptors this process owns.
        if unsafe { libc::dup2(fd, 2i32) } < 0i32 {
            return Err(std::io::Error::last_os_error()).context("taking over stderr");
        }
        // SAFETY: the original is not used again.
        if unsafe { libc::close(fd) } != 0i32 {
            debug!(
                "closing the stderr handed over: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // After the prompt, so that declining leaves nothing behind, and before the
    // exec, which is the last moment this process gets to start anything.
    if log_denials && let Some(token) = shim_token {
        // A delegated run's watcher writes to the requester, which wants the
        // refusals, not every path that was never there.
        if options.stderr.is_some() {
            let quieter = LogConfig {
                level: Some(Level::Info),
                ..log.clone()
            };
            spawn_watcher(token, command, &quieter);
        } else {
            spawn_watcher(token, command, log);
        }
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
    log_env(log, Level::Info)
}

/// `log` as the `SCUDO_LOG_*` variables a scudo started by this one reads,
/// never quieter than `floor`.
#[must_use]
pub fn log_env(log: &LogConfig, floor: Level) -> Vec<(&'static str, String)> {
    let mut env = vec![("SCUDO_LOG_LEVEL", log.level().max(floor).to_string())];
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
    property_values(systemd_args, key).last()
}

/// Every value `systemd_args` give the unit property `key`, in order.
fn property_values<'a, 'k>(
    systemd_args: &'a [String],
    key: &'k str,
) -> impl Iterator<Item = &'a str> + use<'a, 'k> {
    let value_of = move |property: &'a str| property.strip_prefix(key)?.strip_prefix('=');
    let mut flagged = false;
    systemd_args.iter().filter_map(move |arg| {
        let value = if flagged {
            value_of(arg)
        } else {
            arg.strip_prefix("--property=")
                .or_else(|| arg.strip_prefix("-p"))
                .and_then(value_of)
        };
        flagged = matches!(arg.as_str(), "-p" | "--property");
        value
    })
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
            stderr: None,
            deny_env: &[],
            allow_env: &[],
            manager_env: &[],
            dispatch: None,
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

    fn vars(vars: &[(&str, &str)]) -> std::vec::IntoIter<(OsString, OsString)> {
        vars.iter()
            .map(|&(name, value)| (OsString::from(name), OsString::from(value)))
            .collect::<Vec<_>>()
            .into_iter()
    }

    fn patterns(patterns: &[&str]) -> Vec<String> {
        patterns.iter().map(ToString::to_string).collect()
    }

    /// What `unit_changes` gives for `present` and `manager`.
    fn changes(
        present: &[(&str, &str)],
        manager: &[&str],
        deny: &[&str],
        allow: &[&str],
        set_by_unit: &[&str],
    ) -> (Vec<String>, Vec<String>) {
        let rules = EnvRules {
            deny: &compile(deny),
            allow: &compile(allow),
            set_by_unit,
        };
        rules.unit_changes(vars(present), &patterns(manager))
    }

    const SHELL: &[(&str, &str)] = &[
        ("PATH", "/bin"),
        ("HOME", "/home/u"),
        ("GH_TOKEN", "t"),
        ("NPM_TOKEN", "n"),
        ("LC_ALL", "C"),
        ("BASH_FUNC_f%%", "() { :; }"),
    ];

    #[test]
    fn every_variable_is_copied_unless_denied() {
        let copied = |deny: &[&str], allow: &[&str]| changes(SHELL, &[], deny, allow, &[]).0;
        assert_eq!(
            copied(&[], &[]),
            ["GH_TOKEN", "HOME", "LC_ALL", "NPM_TOKEN", "PATH"]
        );
        // An allow with nothing denied changes nothing.
        assert_eq!(copied(&[], &["PATH"]).len(), 5);
        assert_eq!(copied(&["*_TOKEN"], &[]), ["HOME", "LC_ALL", "PATH"]);
        assert_eq!(
            copied(&["*"], &["PATH", "LC_*", "NPM_TOKEN"]),
            ["LC_ALL", "NPM_TOKEN", "PATH"]
        );
    }

    #[test]
    fn what_the_manager_has_already_is_not_copied_again() {
        let manager = &["PATH=/bin", "HOME=/elsewhere", "LANG=C"];
        let (copied, unset) = changes(SHELL, manager, &[], &[], &[]);
        assert_eq!(copied, ["GH_TOKEN", "HOME", "LC_ALL", "NPM_TOKEN"]);
        // Unset in the shell, so unset in the unit too.
        assert_eq!(unset, ["LANG"]);
    }

    #[test]
    fn what_is_denied_is_taken_from_the_managers_environment() {
        let manager = &["PATH=/bin", "GH_TOKEN=t", "API_KEY=k", "HOME=/home/u"];
        let shell = &[
            ("PATH", "/bin"),
            ("GH_TOKEN", "t"),
            ("API_KEY", "k"),
            ("HOME", "/home/u"),
        ];
        let (copied, unset) = changes(shell, manager, &["*"], &["PATH", "HOME"], &[]);
        assert_eq!(copied, Vec::<String>::new());
        assert_eq!(unset, ["API_KEY", "GH_TOKEN"]);
    }

    #[test]
    fn what_the_unit_sets_or_the_manager_set_is_left_alone() {
        let shell = &[
            ("NOTIFY_SOCKET", "/x"),
            ("MONITOR_UNIT", "u"),
            ("SCUDO_DELEGATE", "{}"),
            ("FOO", "shell"),
            ("BAR", "b"),
        ];
        let manager = &["FOO=manager", "INVOCATION_ID=1", "QUX=q"];
        let (copied, unset) = changes(shell, manager, &["*"], &["*"], &["FOO"]);
        assert_eq!(copied, ["BAR"]);
        // FOO is the unit's to set, INVOCATION_ID systemd's.
        assert_eq!(unset, ["QUX"]);
        let (_, unset) = changes(shell, manager, &["*"], &[], &["FOO"]);
        assert_eq!(unset, ["QUX"]);
    }

    #[test]
    fn the_names_environment_assignments_set() {
        let args: Vec<String> = [
            "-p",
            "Environment=A=1",
            "--property=Environment=B=2 C=3",
            "-pEnvironment=\"D=x y\"",
            "-p",
            "EnvironmentFile=/x",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(environment_names(&args), ["A", "B", "C", "D"]);
    }

    #[test]
    fn the_changes_go_on_the_command_line_by_name() {
        let log = LogConfig::default();
        let deny = patterns(&["*"]);
        let allow = patterns(&["PATH", "HOME", "SCUDO_TEST_SURELY_UNSET"]);
        let path = std::env::var("PATH").expect("PATH is set");
        let manager = [format!("PATH={path}"), "SCUDO_TEST_SECRET=x".to_owned()];
        let options = Options {
            verbose: false,
            confirm: false,
            log: &log,
            shim_token: None,
            log_denials: false,
            dbus_proxy: None,
            unit: None,
            stderr: None,
            deny_env: &deny,
            allow_env: &allow,
            manager_env: &manager,
            dispatch: None,
        };
        let args: Vec<String> = build(Path::new("/bin/true"), &[], &[], &options)
            .expect("the command builds")
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let env: Vec<&String> = args
            .iter()
            .filter(|a| a.starts_with("--setenv") || a.contains("UnsetEnvironment"))
            .collect();
        let mut expected = vec!["--property=UnsetEnvironment=SCUDO_TEST_SECRET"];
        if std::env::var_os("HOME").is_some() {
            expected.insert(0, "--setenv=HOME");
        }
        assert_eq!(env, expected);
    }

    #[test]
    fn the_dispatch_record_reaches_the_unit_whatever_is_denied() {
        let log = LogConfig::default();
        let deny = patterns(&["*"]);
        let options = Options {
            verbose: false,
            confirm: false,
            log: &log,
            shim_token: None,
            log_denials: false,
            dbus_proxy: None,
            unit: None,
            stderr: None,
            deny_env: &deny,
            allow_env: &[],
            manager_env: &[],
            dispatch: Some("{}"),
        };
        let cmd = build(Path::new("/bin/true"), &[], &[], &options).expect("the command builds");
        let setenv = format!("--setenv={}", crate::dispatch::ENV);
        assert_eq!(cmd.get_args().filter(|a| *a == setenv.as_str()).count(), 1);
        assert!(
            cmd.get_envs().any(
                |(name, value)| name == crate::dispatch::ENV && value == Some(OsStr::new("{}"))
            )
        );
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
