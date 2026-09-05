//! The wire protocol between `scudo` and `scudo-bpfd`.
//!
//! One JSON object per line, in both directions. Requests carry a list of
//! tagged policies rather than a network policy, so a later policy kind needs no
//! protocol change and no change to the shim.

use std::{
    io::{BufRead as _, BufReader, Write as _},
    os::unix::net::UnixStream,
    path::PathBuf,
};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::policy::Policy;

/// Name of the daemon's socket inside the user's runtime directory.
const SOCKET_NAME: &str = "scudo/bpfd.sock";

/// The socket the daemon listens on.
pub fn socket_path() -> Result<PathBuf> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .context("XDG_RUNTIME_DIR is not set, so the scudo-bpfd socket cannot be located")?;
    Ok(PathBuf::from(runtime_dir).join(SOCKET_NAME))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Compile a set of policies and hold them until someone claims the token.
    Register { policies: Vec<Policy> },
    /// Claim a registration for the calling process's cgroup.
    Attach { token: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Registered { token: String },
    Attached,
    Error { message: String },
}

/// Write one framed message.
pub fn write_message<T: Serialize>(stream: &UnixStream, message: &T) -> Result<()> {
    let mut line = serde_json::to_vec(message).context("serialising message")?;
    line.push(b'\n');
    // UnixStream implements Write for &Self, so a shared reference is enough.
    let mut sink = stream;
    sink.write_all(&line).context("writing to scudo-bpfd")?;
    sink.flush().context("flushing to scudo-bpfd")
}

/// Read one framed message.
pub fn read_message<T: for<'de> Deserialize<'de>>(stream: &UnixStream) -> Result<T> {
    let mut line = String::new();
    let read = BufReader::new(stream)
        .read_line(&mut line)
        .context("reading from scudo-bpfd")?;
    if read == 0 {
        bail!("scudo-bpfd closed the connection");
    }
    serde_json::from_str(&line).context("parsing message")
}
