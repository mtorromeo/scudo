#![cfg(target_os = "linux")]

use std::{
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::exit,
};

use anyhow::{Context as _, Result};
use clap::Parser;
use scudo::{
    bpfd::{protocol::Notification, report},
    logging::{Facility, Level, LogConfig, Target},
};
#[cfg(feature = "tui")]
use tracing::info;
use tracing::{debug, error, warn};

#[derive(Debug, Parser)]
#[command(about, version, author)]
#[expect(clippy::struct_field_names, reason = "the log flags share a prefix")]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each is a flag of its own, and they are independent"
)]
struct Args {
    /// Enable verbose output. A shorthand for `--log-level debug`.
    #[arg(short, long)]
    verbose: bool,

    /// How much to report: off, error, warn, info, debug or trace.
    #[arg(long, value_name = "LEVEL", env = "SCUDO_LOG_LEVEL")]
    log_level: Option<Level>,

    /// Where to report it: stderr, file, syslog or journald (repeatable).
    #[arg(
        long,
        value_name = "TARGET",
        value_delimiter = ',',
        env = "SCUDO_LOG_TARGET"
    )]
    log_target: Vec<Target>,

    /// Write the log to this file. Implies `--log-target file`.
    #[arg(long, value_name = "PATH", env = "SCUDO_LOG_FILE")]
    log_file: Option<String>,

    /// The syslog facility to log under. Only used by `--log-target syslog`.
    #[arg(long, value_name = "FACILITY", env = "SCUDO_LOG_SYSLOG_FACILITY")]
    log_syslog_facility: Option<Facility>,

    /// Confirm before running the command.
    #[arg(long)]
    confirm: bool,

    /// Set a property for the systemd-run command.
    #[arg(short = 'P', long, value_name = "PROPERTY=VALUE")]
    property: Vec<String>,

    /// Apply the named profile, ignoring its match rules (repeatable, comma-separated).
    #[arg(short, long, value_name = "NAME", value_delimiter = ',')]
    profile: Vec<String>,

    /// Skip profile matching; apply only the profiles given with --profile.
    #[arg(long)]
    no_match: bool,

    /// Run commands started inside the sandbox under their own profile when it is delegable, as `delegate = true` does.
    #[arg(long, overrides_with = "no_delegate")]
    delegate: bool,

    /// Run every command started inside the sandbox in the sandbox itself, whatever `delegate` says.
    #[arg(long, overrides_with = "delegate")]
    no_delegate: bool,

    /// Allow a destination (address, CIDR, host or glob), even one a profile denies (repeatable, comma-separated).
    #[arg(long, value_name = "DEST", value_delimiter = ',')]
    allow_dest: Vec<String>,

    /// Deny a destination, even one a profile allows (repeatable, comma-separated).
    #[arg(long, value_name = "DEST", value_delimiter = ',')]
    deny_dest: Vec<String>,

    /// Allow a port or range, optionally `/tcp` or `/udp`, even one a profile denies (repeatable, comma-separated).
    #[arg(long, value_name = "PORT[/PROTO]", value_delimiter = ',')]
    allow_port: Vec<String>,

    /// Deny a port or range, optionally `/tcp` or `/udp`, even one a profile allows (repeatable, comma-separated).
    #[arg(long, value_name = "PORT[/PROTO]", value_delimiter = ',')]
    deny_port: Vec<String>,

    /// Hide a directory behind an empty one, even one a profile grants (repeatable).
    #[arg(long, value_name = "PATH")]
    fs_hide: Vec<String>,

    /// Make a path read-only, even one a profile hides or makes writable (repeatable).
    #[arg(long, value_name = "PATH")]
    fs_read: Vec<String>,

    /// Make a path writable, even one a profile hides or makes read-only (repeatable).
    #[arg(long, value_name = "PATH")]
    fs_write: Vec<String>,

    // Reachable only when scudo is invoked by name, and nothing checks: the
    // argv[0] dispatch rewrites a symlinked call into `scudo -- <command> …`,
    // after which every flag belongs to the command.
    /// Run the command in scudo's terminal UI, beside a live list of blocks.
    #[cfg(feature = "tui")]
    #[arg(long)]
    tui: bool,

    /// The UI's prefix key, as `C-a`, `M-x` or `F12`. Overrides `[scudo]`.
    #[cfg(feature = "tui")]
    #[arg(long, value_name = "KEY", requires = "tui")]
    tui_prefix: Option<String>,

    /// Internal: claim the policies registered under TOKEN, then exec the
    /// command. Set by scudo itself when starting a sandboxed unit.
    #[arg(long, value_name = "TOKEN", hide = true)]
    bpf_shim: Option<String>,

    /// Internal: print what the sandbox registered under TOKEN turns away.
    /// Set by scudo itself when the policy asks for its denials to be reported.
    #[arg(long, value_name = "TOKEN", hide = true, conflicts_with = "bpf_shim")]
    bpf_watch: Option<String>,

    /// Internal: run the command as the filtered session bus proxy ID. Set by
    /// the `scudo-dbus@.service` template.
    #[arg(
        long,
        value_name = "ID",
        hide = true,
        conflicts_with_all = ["bpf_shim", "bpf_watch"]
    )]
    dbus_proxy: Option<String>,

    /// Internal: serve the delegation requests of the sandbox that started us.
    /// Set by scudo itself when a profile delegates commands.
    #[arg(
        long,
        hide = true,
        conflicts_with_all = ["bpf_shim", "bpf_watch", "dbus_proxy"]
    )]
    broker: bool,

    /// Internal: run the command for a sandbox's broker, as sandbox ID. Set by
    /// the broker itself.
    #[arg(
        long,
        value_name = "ID",
        hide = true,
        conflicts_with_all = ["bpf_shim", "bpf_watch", "dbus_proxy", "broker"]
    )]
    delegated: Option<String>,

    #[arg()]
    command: String,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command_args: Vec<String>,
}

impl Args {
    /// What the command line asks of the logging, on its own.
    ///
    /// This is the highest-priority source: it is layered over whatever the
    /// profiles said, so a flag left off has to stay `None` rather than become
    /// a default that would silently overrule the config.
    fn log_config(&self) -> LogConfig {
        let mut config = LogConfig {
            level: self.log_level,
            targets: (!self.log_target.is_empty()).then(|| self.log_target.clone()),
            path: self.log_file.clone(),
            syslog_facility: self.log_syslog_facility,
        };
        // `-v` raises the floor rather than setting the level, so it cannot
        // quieten an explicit `--log-level trace` next to it.
        if self.verbose {
            config.raise_to(Level::Debug);
        }
        config
    }
}

fn main() {
    // Before anything else: an error while reading the command line or the
    // config is still an error worth reporting, and there is nothing to report
    // it with until this returns.
    let logging = scudo::logging::init();
    if let Err(e) = run(&logging) {
        error!("{e:#}");
        exit(1);
    }
}

/// Find the canonicalized command searching in PATH, skipping any entries that are the same as the current executable.
fn which(command: &str, self_exe: &PathBuf) -> Result<PathBuf> {
    if command.contains('/')
        && let Ok(candidate) = std::fs::canonicalize(command)
        && candidate != *self_exe
    {
        if let Ok(absolute) = std::path::absolute(Path::new(command)) {
            return Ok(absolute);
        }
        return Ok(candidate);
    }

    let command = Path::new(command);
    let command = command
        .file_name()
        .ok_or(anyhow::anyhow!("invalid command: {}", command.display()))?;

    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let candidate = PathBuf::from(dir).join(command);
        if candidate.is_file()
            && matches!(std::fs::canonicalize(&candidate), Ok(canonical) if canonical != *self_exe)
        {
            return Ok(candidate);
        }
    }

    anyhow::bail!("command not found: {}", command.display())
}

fn run(logging: &scudo::logging::Handle) -> Result<()> {
    let self_exe = std::env::current_exe().and_then(std::fs::canonicalize)?;
    let mut args: Vec<_> = std::env::args().collect();

    if let Some(mut command) = args.first().cloned() {
        if let Some(basename) = PathBuf::from(command.clone()).file_name() {
            basename
                .to_str()
                .ok_or(anyhow::anyhow!("invalid command: {command}"))?
                .clone_into(&mut command);
        }

        if let Some(basename) = self_exe.file_name()
            && matches!(basename.to_str(), Some(basename) if basename != command)
        {
            args.insert(0, "scudo".to_owned());
            args.insert(1, "--".to_owned());
        }
    }

    let args = Args::parse_from(args);

    // The command line is known now; the config is not. Apply what we have, so
    // that reading the config is itself reported at the level asked for.
    let cli_log = args.log_config();
    logging.reconfigure(&cli_log)?;

    if let Some(token) = args.bpf_shim.as_deref() {
        return shim(token, &args);
    }

    if let Some(token) = args.bpf_watch.as_deref() {
        return watch(token, &args);
    }

    if let Some(id) = args.dbus_proxy.as_deref() {
        let code = scudo::policy::dbus::serve(id, Path::new(&args.command))?;
        #[expect(clippy::exit, reason = "the proxy's code has to become the unit's")]
        std::process::exit(code);
    }

    if args.broker {
        return scudo::broker::run_process(&log_broker_event);
    }

    // Before the config, so that no file anyone else wrote has a say in it.
    if scudo::nested::inside_sealed_sandbox() {
        refuse_nested_flags(&args)?;
        // Before looking the command up: the sandbox may not even let us see
        // it, and outside is where it will be found.
        if scudo::nested::broker_mounted() {
            match scudo::broker::delegate(&args.command, &args.command_args)? {
                scudo::broker::Outcome::NotDelegated => {}
                scudo::broker::Outcome::Exited { code, signal } => exit_like(code, signal),
            }
        }
        let bin = which(&args.command, &self_exe)?;
        return run_nested(&bin, &args);
    }

    let delegation = match args.delegated.as_deref() {
        Some(id) => Some(Delegation::from_env(id, &args)?),
        None => None,
    };
    if delegation.is_some() {
        // Whatever goes wrong from here on, the requester has to be told: its
        // stderr is the only place it is looking.
        return run_sandboxed(&args, &self_exe, logging, &cli_log, delegation.as_ref())
            .inspect_err(tell_requester);
    }
    run_sandboxed(&args, &self_exe, logging, &cli_log, None)
}

/// What a run on behalf of a sandbox's broker is held to.
struct Delegation {
    id: String,
    limits: scudo::broker::Limits,
}

impl Delegation {
    fn from_env(id: &str, args: &Args) -> Result<Self> {
        // The command line is the requester's in all but name: nothing on it
        // may choose a profile or loosen one.
        #[cfg(feature = "tui")]
        let tui = args.tui;
        #[cfg(not(feature = "tui"))]
        let tui = false;
        if !args.profile.is_empty()
            || args.no_match
            || !args.property.is_empty()
            || !args.allow_dest.is_empty()
            || !args.deny_dest.is_empty()
            || !args.allow_port.is_empty()
            || !args.deny_port.is_empty()
            || !args.fs_hide.is_empty()
            || !args.fs_read.is_empty()
            || !args.fs_write.is_empty()
            || args.delegate
            || args.no_delegate
            || args.confirm
            || tui
        {
            anyhow::bail!("a delegated run takes no options");
        }
        let limits = serde_json::from_str(
            &std::env::var(scudo::broker::DELEGATE_ENV)
                .with_context(|| format!("{} is not set", scudo::broker::DELEGATE_ENV))?,
        )
        .context("reading the delegation's limits")?;
        Ok(Delegation {
            id: id.to_owned(),
            limits,
        })
    }
}

/// Say what went wrong where the requester of a delegated run will see it.
fn tell_requester(err: &anyhow::Error) {
    use std::{io::Write as _, os::fd::FromRawFd as _};

    // SAFETY: the broker put the requester's stderr there for us to write to;
    // `ManuallyDrop` leaves closing it to the process exit.
    let file = unsafe { std::fs::File::from_raw_fd(scudo::broker::REQUESTER_STDERR) };
    let mut file = core::mem::ManuallyDrop::new(file);
    drop(writeln!(file, "scudo: {err:#}"));
}

/// Exit the way the delegated command did: with its code, or by its signal.
fn exit_like(code: Option<i32>, signal: Option<i32>) -> ! {
    if let Some(signal) = signal {
        // SAFETY: restoring the default disposition, so that the signal
        // raised next is not ignored or handled.
        let restored = unsafe { libc::signal(signal, libc::SIG_DFL) } != libc::SIG_ERR;
        // SAFETY: raising it on ourselves is how a parent learns what killed
        // its child.
        if restored && unsafe { libc::raise(signal) } != 0i32 {
            debug!("cannot end by signal {signal}");
        }
        // Still here: say it the way a shell would.
        #[expect(clippy::exit, reason = "the command's end has to become scudo's")]
        exit(signal.saturating_add(128i32));
    }
    #[expect(clippy::exit, reason = "the command's code has to become scudo's")]
    exit(code.unwrap_or(1i32));
}

/// Report what the broker did: refusals always, the rest when asked for.
#[expect(
    clippy::needless_pass_by_value,
    reason = "a sink is handed each event to keep"
)]
fn log_broker_event(event: scudo::broker::Event) {
    if event.is_refusal() {
        warn!("{event}");
    } else {
        debug!("{event}");
    }
}

/// The run itself, from the config to `systemd-run`: from a terminal, or for a
/// broker when `delegation` is set.
#[expect(
    clippy::too_many_lines,
    reason = "one straight path from the profiles to the exec"
)]
fn run_sandboxed(
    args: &Args,
    self_exe: &Path,
    logging: &scudo::logging::Handle,
    cli_log: &LogConfig,
    delegation: Option<&Delegation>,
) -> Result<()> {
    let bin = which(&args.command, &self_exe.to_path_buf())?;

    // Before the config: a mistyped rule is the command line's fault, and says
    // so without waiting on anything else.
    let network = scudo::policy::NetworkOverrides::parse(
        &args.allow_dest,
        &args.deny_dest,
        &args.allow_port,
        &args.deny_port,
    )?;
    let files =
        scudo::policy::FilesystemOverrides::parse(&args.fs_hide, &args.fs_read, &args.fs_write)?;

    // A delegated run's standard input is the requester's: no question may be
    // put to it.
    let loaded = scudo::config::load_configs_with(delegation.is_none())?;
    let mut resolved = scudo::profile::resolve_with(
        &loaded.profiles,
        &args.command,
        &args.command_args,
        scudo::profile::ResolveOptions {
            profiles: &args.profile,
            no_match: args.no_match,
            network: Some(&network),
            filesystem: Some(&files),
            vars: Some(&loaded.settings.vars),
        },
    )?;

    if let Some(delegation) = delegation {
        if !resolved
            .matched
            .iter()
            .any(|name| delegation.limits.allow.contains(name))
        {
            anyhow::bail!("'{}' is not matched by a delegated profile", args.command);
        }
        if let Some(name) = resolved
            .matched
            .iter()
            .find(|name| loaded.profiles.refuses_delegation(name))
        {
            anyhow::bail!("profile '{name}' matches it and is not delegable");
        }
        if resolved.confirm {
            anyhow::bail!("its profile asks for confirmation, which a delegated run cannot ask");
        }
        scudo::broker::check_derived(&resolved.derived, &delegation.limits.roots)?;
    }

    // The command line has the last word, so it goes on top of what the
    // profiles settled on, which in turn sit on the `[scudo]` defaults.
    let log = cli_log
        .clone()
        .over(resolved.log)
        .over(loaded.settings.log.clone());
    logging.reconfigure(&log)?;

    // Everything `--verbose` used to switch on now hangs off the level, so that
    // `log.level = "debug"` in a profile buys exactly what `-v` does.
    let verbose = log.level() >= Level::Debug;
    #[cfg(feature = "tui")]
    let tui = args.tui;
    #[cfg(not(feature = "tui"))]
    let tui = false;

    if args.confirm {
        resolved.confirm = true;
    }

    for line in &resolved.match_log {
        debug!("{line}");
    }

    let bin = match resolved.exec {
        Some(path) => PathBuf::from(&path),
        None => bin,
    };

    // The level can only make scudo louder, the way it does for everything
    // else, and asking for the panel is asking for what fills it.
    if verbose || tui {
        for policy in &mut resolved.policies {
            policy.report_denials();
        }
        // A profile that hides half of `$HOME` and says nothing about
        // reporting is the ordinary case, and an empty panel beside a command
        // that just died on a missing file is the whole problem this exists to
        // solve. So asking to be told about a sandboxed command is taken as
        // asking about its files too.
        //
        // Only for a command that is actually being restricted: an unsandboxed
        // one has nothing that could have been taken from it, and the
        // registration it would need is not free — it costs the shim, and
        // `ProtectControlGroups=`.
        let restricted = !resolved.systemd_args.is_empty();
        let declared = resolved
            .policies
            .iter()
            .any(|policy| matches!(policy, scudo::policy::Policy::Filesystem(_)));
        if restricted && !declared {
            resolved.policies.push(scudo::policy::Policy::Filesystem(
                scudo::policy::FilesystemPolicy {
                    log: scudo::policy::LogLevel::Denied,
                },
            ));
        }
    }
    let reporting = resolved
        .policies
        .iter()
        .any(scudo::policy::Policy::reports_denials);

    // Independent of what else is watched: a filesystem policy being reported
    // says nothing about the network half, and a `[net]` panel that can only
    // ever be empty is exactly the silence this explains.
    let network_unwatched = unwatched_network(&resolved.policies);
    if network_unwatched {
        debug!(
            "the network is taken away entirely, so there is nothing to report \
             blocked accesses from"
        );
    }

    // What the profile set itself, taken before anything is added to it, so
    // that what scudo adds is weighed against the profile alone.
    let explicit = resolved.systemd_args.clone();
    let applied = scudo::policy::apply(&resolved.policies, &explicit)?;
    #[cfg(feature = "tui")]
    let shim_token_present = applied.token.is_some();
    resolved.systemd_args.extend(applied.systemd_args);
    let shim_token = applied.token;
    // Kept, not just printed: with `--tui` this goes to a stderr the panel is
    // about to draw over, and a policy that quietly lost its enforcement or its
    // reporting is exactly what the panel has to be able to say.
    let mut warnings = applied.warnings;

    resolved
        .systemd_args
        .extend(args.property.iter().map(|p| format!("--property={p}")));

    // A profile that only spoke about the bus still asked for a sandbox.
    let unsandboxed = resolved.systemd_args.is_empty()
        && shim_token.is_none()
        && resolved.dbus == scudo::policy::DbusConfig::default();
    if unsandboxed {
        debug!(
            "no profile matched or empty systemd-run options for '{}'",
            args.command
        );
    }

    // Only a sandbox needs closing: a command run as it is has nothing to
    // escape from. Ahead of the command line's properties, which have the last
    // word.
    let mut dbus_proxy = None;
    let mut unit = None;
    if !unsandboxed {
        let bus = scudo::policy::dbus::prepare(
            &resolved.dbus,
            delegation.map(|delegation| delegation.id.as_str()),
        );
        let properties: Vec<String> = bus
            .properties
            .iter()
            .filter(|(key, _)| {
                let overridden = scudo::policy::overridden(&explicit, key);
                if overridden && !scudo::policy::still_confined(&explicit, key, false) {
                    warnings.push(format!(
                        "{key} is set by the profile, so the command can move itself \
                         out of its cgroup and leave the sandbox"
                    ));
                }
                !overridden
            })
            .map(|(key, value)| format!("{key}={value}"))
            .filter(|property| !resolved.systemd_args.contains(property))
            .flat_map(|property| ["-p".to_owned(), property])
            .collect();
        let first_cli = resolved
            .systemd_args
            .iter()
            .position(|arg| arg.starts_with("--property="))
            .unwrap_or(resolved.systemd_args.len());
        resolved
            .systemd_args
            .splice(first_cli..first_cli, properties);
        warnings.extend(bus.warning);
        dbus_proxy = bus.proxy;
        unit = bus.unit;
    }

    if let Some(delegation) = delegation {
        if unsandboxed {
            // Outside the requester's sandbox and in none of its own: that is
            // no sandbox at all.
            anyhow::bail!("'{}' would run without a sandbox", args.command);
        }
        // Named even when unsealed, so that the broker knows what to stop.
        unit = unit.or_else(|| Some(scudo::broker::plain_unit(&delegation.id)));
    }

    // The command line has the last word here too: `--delegate` adds every
    // delegable profile to what the profiles named, `--no-delegate` takes all
    // of it away.
    if args.no_delegate {
        resolved.delegate.clear();
    } else if args.delegate {
        let all = loaded.profiles.delegates(&scudo::config::Delegate {
            all: true,
            names: Vec::new(),
        });
        for name in all {
            if !resolved.delegate.contains(&name) {
                resolved.delegate.push(name);
            }
        }
    } else {
        // Neither: the profiles decide.
    }

    let broker = if resolved.delegate.is_empty() || unsandboxed {
        None
    } else {
        let Some(sandbox) = unit.as_deref() else {
            anyhow::bail!(
                "delegating commands needs a sealed sandbox, and this profile lets the \
                 command reach the service manager (`dbus.session = \"allow\"`)"
            );
        };
        let private_tmp = scudo::runner::property_value(&resolved.systemd_args, "PrivateTmp")
            .is_some_and(|value| !matches!(value, "no" | "false" | "0" | "off"));
        let broker = prepare_broker(
            &loaded.profiles,
            &resolved.delegate,
            &resolved.writable,
            private_tmp,
            sandbox,
            &log,
        )?;
        let first_cli = resolved
            .systemd_args
            .iter()
            .position(|arg| arg.starts_with("--property="))
            .unwrap_or(resolved.systemd_args.len());
        resolved
            .systemd_args
            .splice(first_cli..first_cli, broker.properties());
        Some(broker)
    };

    for warning in &warnings {
        warn!("{warning}");
    }

    let options = scudo::runner::Options {
        // `systemd-run`'s own chatter would go to the requester of a delegated
        // run, which asked for the command and not for that.
        verbose: verbose && delegation.is_none(),
        confirm: resolved.confirm,
        log: &log,
        shim_token: shim_token.as_deref(),
        log_denials: reporting,
        dbus_proxy: dbus_proxy.as_ref(),
        unit: unit.as_deref(),
        stderr: delegation.map(|_| scudo::broker::REQUESTER_STDERR),
    };

    #[cfg(feature = "tui")]
    if tui {
        let cmd = if unsandboxed {
            let mut cmd = std::process::Command::new(&bin);
            cmd.args(&args.command_args);
            cmd
        } else {
            scudo::runner::build(&bin, &args.command_args, &resolved.systemd_args, &options)?
        };
        return start_ui(
            cmd,
            args,
            logging,
            &log,
            &loaded.settings.tui,
            UiContext {
                match_log: &resolved.match_log,
                warnings: &warnings,
                token: shim_token,
                reporting: reporting_state(reporting, shim_token_present, network_unwatched),
                confirm: resolved.confirm,
                dbus_proxy: dbus_proxy.as_ref(),
                broker,
            },
        );
    }

    if let Some(broker) = broker {
        broker.spawn(self_exe, &args.command)?;
    }

    if unsandboxed {
        let err = std::process::Command::new(&bin)
            .args(&args.command_args)
            .exec();
        return Err(anyhow::Error::from(err).context("exec failed"));
    }

    scudo::runner::exec(&bin, &args.command_args, &resolved.systemd_args, &options)
}

/// Run the command where we already are: inside a sandbox of scudo's that has
/// no way to start another one. See [`scudo::nested`] for why this is safe.
///
/// The restrictions the command line asks for explicitly cannot be had here,
/// and are not quietly dropped: they fail instead. `--no-match` only takes
/// profiles away, which is what happens here anyway.
fn run_nested(bin: &Path, args: &Args) -> Result<()> {
    debug!(
        "already inside a scudo sandbox that cannot start another one: \
         running '{}' in it as it is",
        args.command
    );
    let mut cmd = std::process::Command::new(bin);
    cmd.args(&args.command_args);
    scudo::runner::confirm(&scudo::runner::render(&cmd), args.confirm)?;
    let err = cmd.exec();
    Err(anyhow::Error::from(err).context("exec failed"))
}

/// The restrictions the command line asks for explicitly cannot be had inside
/// a sandbox, whether the command then runs there or is delegated, and are not
/// quietly dropped: they fail instead. `--no-match` only takes profiles away,
/// which is what happens here anyway.
fn refuse_nested_flags(args: &Args) -> Result<()> {
    #[cfg(feature = "tui")]
    let tui = args.tui;
    #[cfg(not(feature = "tui"))]
    let tui = false;
    let asked = [
        ("--profile", !args.profile.is_empty()),
        ("--property", !args.property.is_empty()),
        ("--allow-dest", !args.allow_dest.is_empty()),
        ("--deny-dest", !args.deny_dest.is_empty()),
        ("--allow-port", !args.allow_port.is_empty()),
        ("--deny-port", !args.deny_port.is_empty()),
        ("--fs-hide", !args.fs_hide.is_empty()),
        ("--fs-read", !args.fs_read.is_empty()),
        ("--fs-write", !args.fs_write.is_empty()),
        ("--delegate", args.delegate),
        ("--no-delegate", args.no_delegate),
        ("--tui", tui),
    ];
    let asked: Vec<&str> = asked
        .into_iter()
        .filter_map(|(flag, given)| given.then_some(flag))
        .collect();
    if !asked.is_empty() {
        anyhow::bail!(
            "already inside a scudo sandbox that cannot start another one; \
             cannot apply {}",
            asked.join(", ")
        );
    }
    Ok(())
}

/// Make the socket and the spec for the broker of `sandbox`.
fn prepare_broker(
    profiles: &scudo::config::ValidatedConfigMap,
    delegate: &[String],
    writable: &[PathBuf],
    private_tmp: bool,
    sandbox: &str,
    log: &LogConfig,
) -> Result<scudo::broker::Setup> {
    let (listener, socket) = scudo::broker::listen(sandbox)?;
    // A private `/tmp` is not the `/tmp` outside: nothing in it is the same
    // directory for the broker, and nothing under it may be handed over.
    let roots = writable
        .iter()
        .filter(|root| {
            !private_tmp || !["/tmp", "/var/tmp"].iter().any(|tmp| root.starts_with(tmp))
        })
        .cloned()
        .collect();
    let spec = scudo::broker::Spec {
        delegates: profiles.delegate_patterns(delegate),
        roots,
        unit: sandbox.to_owned(),
        parent: i32::try_from(std::process::id()).context("pid out of range")?,
        log_env: scudo::runner::log_env(log, Level::Off)
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    };
    for (name, _) in &spec.delegates {
        debug!("commands of profile '{name}' are delegated to a sandbox of their own");
    }
    Ok(scudo::broker::Setup {
        listener,
        socket,
        spec,
    })
}

/// What the UI needs that the command line does not carry.
#[cfg(feature = "tui")]
struct UiContext<'a> {
    match_log: &'a [String],
    /// What `apply` had to weaken, which stderr can no longer carry: the panel
    /// is about to own the screen it would have been written to.
    warnings: &'a [String],
    token: Option<String>,
    reporting: scudo::tui::Reporting,
    confirm: bool,
    dbus_proxy: Option<&'a scudo::policy::dbus::Proxy>,
    broker: Option<scudo::broker::Setup>,
}

/// Why the panel would be empty, so it can say so rather than look broken.
#[cfg(feature = "tui")]
fn reporting_state(
    reporting: bool,
    attached: bool,
    unwatched_network: bool,
) -> scudo::tui::Reporting {
    use scudo::tui::Reporting;
    match (reporting, unwatched_network) {
        // Watching was asked for and nothing came back to watch with: the
        // daemon could not be reached, and an observer that cannot attach is
        // dropped rather than allowed to hold the command up.
        (true, _) if !attached => Reporting::Unavailable,
        // Files are watched and the network is not: saying the sandbox is being
        // watched would leave the empty `[net]` half looking like a fault.
        (true, true) => Reporting::FilesOnly,
        (true, false) => Reporting::Watching,
        // Nothing is attached, so nothing observes what the command then fails
        // to reach; an empty panel here is the truth and not a fault.
        (false, true) => Reporting::DenyAll,
        (false, false) if attached => Reporting::Unavailable,
        (false, false) => Reporting::NoPolicy,
    }
}

/// Hand the command to the terminal UI, and give the terminal back afterwards.
/// Never returns: scudo stands in for the command, so the last thing it does is
/// take on its exit code.
#[expect(clippy::exit, reason = "the command's code has to become scudo's")]
#[cfg(feature = "tui")]
fn start_ui(
    cmd: std::process::Command,
    args: &Args,
    logging: &scudo::logging::Handle,
    log: &LogConfig,
    settings: &scudo::tui::TuiConfig,
    context: UiContext<'_>,
) -> Result<()> {
    let cmdline = scudo::runner::render(&cmd);
    // Before the screen is taken over, so declining leaves the terminal exactly
    // as it was found.
    scudo::runner::confirm(&cmdline, context.confirm)?;
    if let Some(proxy) = context.dbus_proxy {
        proxy.write_args()?;
    }

    let command = Path::new(&args.command)
        .file_name()
        .map_or_else(|| args.command.clone(), |name| name.display().to_string());

    // What `--verbose` would have printed goes into the UI's own context area
    // instead: printing it would put it underneath the drawing, where it would
    // be both invisible and in the way.
    let mut lines: Vec<String> = context.match_log.to_vec();
    lines.extend(
        context
            .warnings
            .iter()
            .map(|warning| format!("warning: {warning}")),
    );
    lines.push(format!("running: {cmdline}"));

    let config = match args.tui_prefix.clone() {
        Some(prefix) => scudo::tui::TuiConfig {
            prefix: Some(prefix),
            ..settings.clone()
        },
        None => settings.clone(),
    };

    // The UI owns the screen for as long as it runs, and stderr is that same
    // screen: a warning written to it would land in the middle of the drawing.
    // Anything worth saying is said once the terminal has been handed back.
    let quiet = if log.writes_to_stderr() {
        LogConfig {
            level: Some(Level::Off),
            ..log.clone()
        }
    } else {
        log.clone()
    };
    logging.reconfigure(&quiet)?;

    // Not configuration: what the UI was left set to last time, which it can
    // change again from the inside.
    let remembered = scudo::tui::state::load();
    let outcome = scudo::tui::run(
        cmd,
        &scudo::tui::Options {
            command: &command,
            context: lines,
            token: context.token,
            reporting: context.reporting,
            config,
            panel_width: remembered.tui.panel_width,
        },
        context.broker,
    );

    logging.reconfigure(log)?;
    let outcome = outcome?;

    // Written once, on the way out, and only when it actually changed: the
    // resize keys must not put the disk to work on every press.
    if outcome.panel_width != remembered.tui.panel_width {
        let state = scudo::tui::state::State {
            tui: scudo::tui::state::TuiState {
                panel_width: outcome.panel_width,
            },
        };
        if let Err(err) = scudo::tui::state::save(&state) {
            warn!("cannot remember the panel width: {err:#}");
        }
    }

    if let Some(summary) = outcome.summary {
        info!("{summary}");
    }
    // scudo stands in for the command, so what the command exited with is what
    // whoever ran scudo has to see.
    exit(outcome.code);
}

/// `true` when a policy leaves the command with no network at all and nobody
/// asked to watch it: systemd realises that on its own, so no programs are
/// attached and nothing observes what the command then fails to reach.
///
/// A deny-all policy that *did* ask gets an observer attached beside the empty
/// netns instead, and is watched like any other.
fn unwatched_network(policies: &[scudo::policy::Policy]) -> bool {
    policies.iter().any(|policy| match policy {
        scudo::policy::Policy::Network(network) => {
            network.is_deny_all() && !network.reports_denials()
        }
        // It says nothing about the network either way.
        scudo::policy::Policy::Filesystem(_) => false,
    })
}

/// Run as the watcher: print what the sandbox turns away, until it is gone.
///
/// This process exists because neither of the others survives to do it — scudo
/// becomes `systemd-run` and the shim becomes the command. It holds the stderr
/// they started with, so its output lands where the user is looking.
fn watch(token: &str, args: &Args) -> Result<()> {
    // Ctrl-C goes to the whole foreground group, and dying here would throw
    // away the summary at exactly the moment it is most wanted: the user gave
    // up on a command that could not reach something. The daemon closes the
    // stream a few seconds after the command's cgroup goes away, so nothing is
    // waited on for ever.
    ignore_interrupts();

    let mut reader =
        scudo::bpfd::client::watch(token).context("cannot report blocked network accesses")?;
    let command = Path::new(&args.command)
        .file_name()
        .map_or_else(|| args.command.clone(), |name| name.display().to_string());

    while let Some(event) = reader.read::<Notification>()? {
        report::report(&event, &command);
    }
    Ok(())
}

/// Take ourselves out of the terminal's interrupt handling.
fn ignore_interrupts() {
    for signal in [libc::SIGINT, libc::SIGQUIT] {
        // SAFETY: setting a disposition on the calling process, with a handler
        // the kernel understands and no memory of ours involved.
        unsafe {
            libc::signal(signal, libc::SIG_IGN);
        }
    }
}

/// Run as the in-unit shim: claim the registered policies for this cgroup, then
/// become the real command.
///
/// This runs inside the transient unit, so the cgroup the daemon reads from our
/// connection is the one the command will run in. Nothing is executed until the
/// daemon confirms: a policy that cannot be attached must never end up with the
/// command running unfiltered.
fn shim(token: &str, args: &Args) -> Result<()> {
    scudo::bpfd::client::attach(token).context("claiming the sandbox policies")?;

    let err = std::process::Command::new(&args.command)
        .args(&args.command_args)
        .exec();
    Err(anyhow::Error::from(err).context("exec failed"))
}

#[cfg(test)]
mod tests {
    use scudo::policy::{FilesystemPolicy, LogLevel, Policy, network::NetworkConfig};

    use super::{reporting_state, unwatched_network};

    fn network(src: &str) -> Policy {
        let config: NetworkConfig = toml::from_str(src).unwrap();
        Policy::Network(config.try_into().unwrap())
    }

    /// Nobody asked, so nothing is attached: the empty panel is the truth.
    #[test]
    fn an_unwatched_deny_all_is_owned_up_to() {
        assert!(unwatched_network(&[network("")]));
    }

    /// Asking is what attaches the observer, and an observed deny-all is
    /// watched like any other policy.
    #[test]
    fn a_watched_deny_all_is_not_silent() {
        assert!(!unwatched_network(&[network(r#"log = "denied""#)]));
    }

    /// The filesystem half says nothing about the network half. This is the
    /// case that used to announce "watching" over a `[net]` panel that could
    /// only ever be empty.
    #[test]
    fn watched_files_do_not_speak_for_an_unwatched_network() {
        let policies = [
            network(""),
            Policy::Filesystem(FilesystemPolicy {
                log: LogLevel::Denied,
            }),
        ];
        assert!(unwatched_network(&policies));
        assert_eq!(
            reporting_state(true, true, true),
            scudo::tui::Reporting::FilesOnly
        );
    }

    /// Reporting was asked for and nothing attached to answer with: an observer
    /// that cannot reach the daemon is dropped rather than allowed to hold the
    /// command up, so the panel must not claim to be watching.
    #[test]
    fn asking_to_watch_is_not_being_able_to() {
        assert_eq!(
            reporting_state(true, false, false),
            scudo::tui::Reporting::Unavailable
        );
    }

    #[test]
    fn the_panel_says_why_it_is_empty() {
        use scudo::tui::Reporting;
        assert_eq!(reporting_state(true, true, false), Reporting::Watching);
        assert_eq!(reporting_state(false, true, true), Reporting::DenyAll);
        assert_eq!(reporting_state(false, true, false), Reporting::Unavailable);
        assert_eq!(reporting_state(false, false, false), Reporting::NoPolicy);
    }
}
