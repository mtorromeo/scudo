use std::{os::unix::process::CommandExt, path::Path};

use anyhow::Result;

pub fn exec(command: &Path, args: &[String], systemd_args: &[String]) -> Result<()> {
    let err = std::process::Command::new("systemd-run")
        .args(["--user", "--wait", "-qPdt"])
        .args(systemd_args)
        .arg("--")
        .arg(command)
        .args(args)
        .exec();

    // exec() only returns on failure
    Err(anyhow::Error::from(err).context("failed to exec systemd-run"))
}
