#![cfg(target_os = "linux")]

mod config;
mod profile;
mod runner;

use std::path::PathBuf;

use anyhow::Result;

fn main() {
    if let Err(e) = run() {
        eprintln!("scudo: {e:#}");
        std::process::exit(1);
    }
}

fn help() -> ! {
    eprintln!("usage: scudo <command> [args...]");
    std::process::exit(1);
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
            if candidate.is_file() {
                let Ok(candidate) = std::fs::canonicalize(&candidate) else {
                    continue;
                };

                if candidate != *self_exe {
                    return Ok(candidate);
                }
            }
        }
    }
    anyhow::bail!("command not found: {command}")
}

fn run() -> Result<()> {
    let mut args = std::env::args();

    let Some(mut command) = args.next() else {
        help();
    };

    let self_exe = std::env::current_exe().and_then(std::fs::canonicalize)?;
    let bin = which(&command, &self_exe).or_else(|_| {
        let Some(argv1) = args.next() else {
            help();
        };
        let bin = which(&argv1, &self_exe);
        command = argv1;
        bin
    })?;

    let command_args = args.collect::<Vec<_>>();

    let configs = config::load_configs()?;
    let resolved = profile::resolve(&configs, &command)?;

    let bin = match resolved.exec {
        Some(ref path) => PathBuf::from(path),
        None => bin,
    };

    runner::exec(&bin, &command_args, &resolved.systemd_args, resolved.debug, resolved.confirm)
}
