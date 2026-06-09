#![cfg(target_os = "linux")]

use std::{os::unix::process::CommandExt as _, path::PathBuf};

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(about, version, author)]
#[expect(clippy::struct_field_names)]
struct Args {
    /// Enable debug output.
    #[arg(long)]
    debug: bool,

    /// Confirm before running the command.
    #[arg(long)]
    confirm: bool,

    #[arg()]
    command: String,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command_args: Vec<String>,
}

fn main() -> Result<(), i32> {
    if let Err(e) = run() {
        eprintln!("scudo: {e:#}");
        return Err(1);
    }
    Ok(())
}

/// Find the canonicalized command searching in PATH, skipping any entries that are the same as the current executable.
fn which(command: &str, self_exe: &PathBuf) -> Result<PathBuf> {
    if command.contains('/') {
        if let Ok(candidate) = std::fs::canonicalize(command)
            && candidate != *self_exe
        {
            return Ok(candidate);
        }
    } else {
        for dir in std::env::var("PATH").unwrap_or_default().split(':') {
            let candidate = PathBuf::from(dir).join(command);
            if candidate.is_file()
                && matches!(std::fs::canonicalize(&candidate), Ok(canonical) if canonical != *self_exe)
            {
                return Ok(candidate);
            }
        }
    }
    anyhow::bail!("command not found: {command}")
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
    let bin = which(&args.command, &self_exe)?;

    let configs = scudo::config::load_configs()?;
    let mut resolved = scudo::profile::resolve(&configs, &args.command, &args.command_args)?;

    if args.debug {
        resolved.debug = true;
    }

    if args.confirm {
        resolved.confirm = true;
    }

    if resolved.debug {
        for line in &resolved.match_log {
            eprintln!("scudo: {line}");
        }
    }

    let bin = match resolved.exec {
        Some(path) => PathBuf::from(&path),
        None => bin,
    };

    if resolved.systemd_args.is_empty() {
        if resolved.debug {
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
        resolved.debug,
        resolved.confirm,
    )
}
