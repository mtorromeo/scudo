#![cfg(target_os = "linux")]

use std::{
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::exit,
};

use anyhow::{Context as _, Result};
use clap::Parser;

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
        },
    )
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
