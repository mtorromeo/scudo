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
// Only with the UI does the count of flags reach the limit; without it the
// expectation would go unfulfilled, which is itself a warning.
#[cfg_attr(
    feature = "tui",
    expect(
        clippy::struct_excessive_bools,
        reason = "each is a flag the person typed, and they are independent"
    )
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

    let bin = which(&args.command, &self_exe)?;

    let loaded = scudo::config::load_configs()?;
    let mut resolved = scudo::profile::resolve_with(
        &loaded.profiles,
        &args.command,
        &args.command_args,
        scudo::profile::ResolveOptions {
            profiles: &args.profile,
            no_match: args.no_match,
        },
    )?;

    // The command line has the last word, so it goes on top of what the
    // profiles settled on, which in turn sit on the `[scudo]` defaults.
    let log = cli_log.over(resolved.log).over(loaded.settings.log.clone());
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
    }
    let reporting = resolved
        .policies
        .iter()
        .any(scudo::policy::Policy::reports_denials);

    // Only when nothing else is being reported: with a second policy still
    // watched, saying there is nothing to report would be plainly wrong.
    if !reporting && deny_all(&resolved.policies) {
        debug!(
            "the network is taken away entirely, so there is nothing to report \
             blocked accesses from"
        );
    }

    let applied = scudo::policy::apply(&resolved.policies)?;
    #[cfg(feature = "tui")]
    let shim_token_present = applied.token.is_some();
    for warning in &applied.warnings {
        warn!("{warning}");
    }
    resolved.systemd_args.extend(applied.systemd_args);
    let shim_token = applied.token;

    resolved
        .systemd_args
        .extend(args.property.iter().map(|p| format!("--property={p}")));

    let options = scudo::runner::Options {
        verbose,
        confirm: resolved.confirm,
        log: &log,
        shim_token: shim_token.as_deref(),
        log_denials: reporting,
    };

    let unsandboxed = resolved.systemd_args.is_empty() && shim_token.is_none();
    if unsandboxed {
        debug!(
            "no profile matched or empty systemd-run options for '{}'",
            args.command
        );
    }

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
            &args,
            logging,
            &log,
            &loaded.settings.tui,
            UiContext {
                match_log: &resolved.match_log,
                token: shim_token,
                reporting: reporting_state(
                    reporting,
                    shim_token_present,
                    deny_all(&resolved.policies),
                ),
                confirm: resolved.confirm,
            },
        );
    }

    if unsandboxed {
        let err = std::process::Command::new(&bin)
            .args(&args.command_args)
            .exec();
        return Err(anyhow::Error::from(err).context("exec failed"));
    }

    scudo::runner::exec(&bin, &args.command_args, &resolved.systemd_args, &options)
}

/// What the UI needs that the command line does not carry.
#[cfg(feature = "tui")]
struct UiContext<'a> {
    match_log: &'a [String],
    token: Option<String>,
    reporting: scudo::tui::Reporting,
    confirm: bool,
}

/// Why the panel would be empty, so it can say so rather than look broken.
#[cfg(feature = "tui")]
fn reporting_state(reporting: bool, enforced: bool, deny_all: bool) -> scudo::tui::Reporting {
    use scudo::tui::Reporting;
    if reporting {
        Reporting::Watching
    } else if deny_all {
        // Nothing is attached, so nothing observes what the command then fails
        // to reach; an empty panel here is the truth and not a fault.
        Reporting::DenyAll
    } else if enforced {
        Reporting::Unavailable
    } else {
        Reporting::NoPolicy
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

    let command = Path::new(&args.command)
        .file_name()
        .map_or_else(|| args.command.clone(), |name| name.display().to_string());

    // What `--verbose` would have printed goes into the UI's own context area
    // instead: printing it would put it underneath the drawing, where it would
    // be both invisible and in the way.
    let mut lines: Vec<String> = context.match_log.to_vec();
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

/// `true` when a policy leaves the command with no network at all, which
/// systemd realises on its own — no programs are attached, so nothing observes
/// what the command then fails to reach.
fn deny_all(policies: &[scudo::policy::Policy]) -> bool {
    policies.iter().any(|policy| match policy {
        scudo::policy::Policy::Network(network) => network.is_deny_all(),
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
