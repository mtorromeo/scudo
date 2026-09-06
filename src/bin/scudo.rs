#![cfg(target_os = "linux")]

use std::{
    io::IsTerminal as _,
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::exit,
};

use anyhow::{Context as _, Result};
use clap::Parser;
use scudo::bpfd::protocol::{Notification, Stage, Transport};

#[derive(Debug, Parser)]
#[command(about, version, author)]
#[expect(clippy::struct_field_names)]
struct Args {
    /// Enable verbose output.
    #[arg(short, long)]
    verbose: bool,

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

fn main() {
    if let Err(e) = run() {
        eprintln!("scudo: {e:#}");
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

fn run() -> Result<()> {
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

    if let Some(token) = args.bpf_shim.as_deref() {
        return shim(token, &args);
    }

    if let Some(token) = args.bpf_watch.as_deref() {
        return watch(token, &args);
    }

    let bin = which(&args.command, &self_exe)?;

    let configs = scudo::config::load_configs()?;
    let mut resolved = scudo::profile::resolve_with(
        &configs,
        &args.command,
        &args.command_args,
        scudo::profile::ResolveOptions {
            profiles: &args.profile,
            no_match: args.no_match,
        },
    )?;

    if args.verbose {
        resolved.verbose = true;
    }

    if args.confirm {
        resolved.confirm = true;
    }

    if resolved.verbose {
        for line in &resolved.match_log {
            eprintln!("scudo: {line}");
        }
    }

    let bin = match resolved.exec {
        Some(path) => PathBuf::from(&path),
        None => bin,
    };

    // The flag can only make scudo louder, the way it does for everything else.
    if resolved.verbose {
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
    if resolved.verbose && !reporting && deny_all(&resolved.policies) {
        eprintln!(
            "scudo: the network is taken away entirely, so there is nothing to report \
             blocked accesses from"
        );
    }

    let applied = scudo::policy::apply(&resolved.policies)?;
    for warning in &applied.warnings {
        eprintln!("scudo: warning: {warning}");
    }
    resolved.systemd_args.extend(applied.systemd_args);
    let shim_token = applied.token;

    resolved
        .systemd_args
        .extend(args.property.iter().map(|p| format!("--property={p}")));

    if resolved.systemd_args.is_empty() && shim_token.is_none() {
        if resolved.verbose {
            eprintln!(
                "scudo: warning: no profile matched or empty systemd-run options for '{}'",
                args.command
            );
        }
        let err = std::process::Command::new(&bin)
            .args(&args.command_args)
            .exec();
        return Err(anyhow::Error::from(err).context("exec failed"));
    }

    scudo::runner::exec(
        &bin,
        &args.command_args,
        &resolved.systemd_args,
        &scudo::runner::Options {
            verbose: resolved.verbose,
            confirm: resolved.confirm,
            shim_token: shim_token.as_deref(),
            log_denials: reporting,
        },
    )
}

/// `true` when a policy leaves the command with no network at all, which
/// systemd realises on its own — no programs are attached, so nothing observes
/// what the command then fails to reach.
fn deny_all(policies: &[scudo::policy::Policy]) -> bool {
    policies.iter().any(|policy| match policy {
        scudo::policy::Policy::Network(network) => network.is_deny_all(),
    })
}

/// How many refused targets the closing summary names before it gives up.
const SUMMARY_TARGETS: usize = 5;

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
    // systemd-run --pty leaves the terminal in raw mode, where a bare newline
    // moves down without returning to the first column and every line after the
    // first comes out indented further than the last.
    let newline = if std::io::stderr().is_terminal() {
        "\r\n"
    } else {
        "\n"
    };

    while let Some(event) = reader.read::<Notification>()? {
        eprint!("scudo: {}{newline}", describe(&event, &command));
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

/// One line of output for one notification.
fn describe(event: &Notification, command: &str) -> String {
    match event {
        Notification::Blocked {
            stage,
            transport,
            addr,
            ..
        } => {
            let target = format!(
                "{}{}",
                event.target().unwrap_or_else(|| addr.to_string()),
                match transport {
                    Transport::Tcp => "/tcp",
                    Transport::Udp => "/udp",
                    // Nothing with a port, so nothing to qualify.
                    Transport::Other => "",
                }
            );
            match stage {
                Stage::Connect => format!("blocked connect to {target}"),
                Stage::Sendmsg => format!("blocked sendmsg to {target}"),
                Stage::Egress => format!("blocked packet to {target}"),
                Stage::Ingress => format!("blocked packet from {target}"),
            }
        }
        Notification::DnsRefused { name, reason } => {
            format!("blocked DNS lookup of {name} ({reason})")
        }
        Notification::Summary {
            targets,
            suppressed,
            lost,
        } => summarise(command, targets, *suppressed, *lost),
    }
}

/// The closing line: what was refused, how often, and what was not shown.
fn summarise(command: &str, targets: &[(String, u64)], suppressed: u64, lost: u64) -> String {
    if targets.is_empty() {
        return format!("{command}: nothing was blocked");
    }
    let mut named: Vec<String> = targets
        .iter()
        .take(SUMMARY_TARGETS)
        .map(|(target, count)| format!("{target} ({count}x)"))
        .collect();
    if let Some(rest) = targets.len().checked_sub(SUMMARY_TARGETS)
        && rest > 0
    {
        named.push(format!("and {rest} more"));
    }
    // Repeats folded together are worth saying so the counts above add up;
    // events that never arrived are worth saying because they are missing.
    let mut notes = Vec::new();
    if suppressed > 0 {
        notes.push(format!("{suppressed} repeats suppressed"));
    }
    if lost > 0 {
        notes.push(format!("{lost} events lost"));
    }
    let trailer = if notes.is_empty() {
        String::new()
    } else {
        format!(" [{}]", notes.join(", "))
    };
    format!("{command}: blocked {}{trailer}", named.join(", "))
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
    use super::*;

    fn blocked(stage: Stage, transport: Transport, addr: &str, port: u16) -> Notification {
        Notification::Blocked {
            stage,
            transport,
            addr: addr.parse().expect("a valid test address"),
            port,
        }
    }

    #[test]
    fn each_stage_says_what_it_did_and_which_way_round() {
        let line =
            |stage, transport, addr, port| describe(&blocked(stage, transport, addr, port), "curl");
        assert_eq!(
            line(Stage::Connect, Transport::Tcp, "1.1.1.1", 443),
            "blocked connect to 1.1.1.1:443/tcp"
        );
        assert_eq!(
            line(Stage::Sendmsg, Transport::Udp, "8.8.8.8", 53),
            "blocked sendmsg to 8.8.8.8:53/udp"
        );
        // On ingress the address is where it came from, not where it was going.
        assert_eq!(
            line(Stage::Ingress, Transport::Tcp, "10.0.0.5", 80),
            "blocked packet from 10.0.0.5:80/tcp"
        );
        // ICMP has no port and no transport to name.
        assert_eq!(
            line(Stage::Egress, Transport::Other, "10.0.0.5", 0),
            "blocked packet to 10.0.0.5"
        );
    }

    #[test]
    fn a_refused_lookup_says_why() {
        let event = Notification::DnsRefused {
            name: "ads.example".to_owned(),
            reason: "no rule names it".to_owned(),
        };
        assert_eq!(
            describe(&event, "curl"),
            "blocked DNS lookup of ads.example (no rule names it)"
        );
    }

    /// Silence would be ambiguous: it reads the same as the reporting having
    /// failed to start.
    #[test]
    fn a_run_that_was_never_blocked_says_so() {
        assert_eq!(summarise("curl", &[], 0, 0), "curl: nothing was blocked");
    }

    #[test]
    fn the_summary_counts_attempts_and_owns_up_to_what_it_dropped() {
        let targets = vec![
            ("1.1.1.1:443".to_owned(), 42),
            ("ads.example".to_owned(), 4),
        ];
        assert_eq!(
            summarise("curl", &targets, 39, 2),
            "curl: blocked 1.1.1.1:443 (42x), ads.example (4x) [39 repeats suppressed, 2 events lost]"
        );
        // Nothing hidden, nothing to add.
        assert_eq!(
            summarise("curl", &targets, 0, 0),
            "curl: blocked 1.1.1.1:443 (42x), ads.example (4x)"
        );
    }

    /// A command that was refused everywhere must not fill the screen with its
    /// own summary.
    #[test]
    fn a_long_summary_is_cut_short_rather_than_scrolled() {
        let targets: Vec<(String, u64)> = (0..SUMMARY_TARGETS + 3)
            .map(|i| (format!("10.0.0.{i}:443"), 1))
            .collect();
        let line = summarise("curl", &targets, 0, 0);
        assert!(line.ends_with("and 3 more"), "{line}");
        assert_eq!(line.matches("10.0.0.").count(), SUMMARY_TARGETS);
    }
}
