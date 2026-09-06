//! Client side of the `scudo-bpfd` protocol.

use std::os::unix::net::UnixStream;

use anyhow::{Context as _, Result, bail};

use crate::{
    bpfd::protocol::{MessageReader, Request, Response, read_message, socket_path, write_message},
    policy::Policy,
};

/// Open a connection to the daemon.
fn connect() -> Result<UnixStream> {
    let path = socket_path()?;
    UnixStream::connect(&path)
        .with_context(|| format!("connecting to scudo-bpfd at {}", path.display()))
}

/// Send one request and read the reply.
fn round_trip(request: &Request) -> Result<Response> {
    let stream = connect()?;
    write_message(&stream, request)?;
    read_message(&stream)
}

/// Ask the daemon to hold `policies`, returning the token that claims them.
///
/// The token is claimed later, from inside the sandbox's cgroup: the cgroup does
/// not exist yet at this point, and attaching after the command has started
/// would leave a window in which it runs unfiltered.
pub fn register(policies: &[Policy]) -> Result<String> {
    let request = Request::Register {
        policies: policies.to_vec(),
    };
    match round_trip(&request)? {
        Response::Registered { token } => Ok(token),
        Response::Error { message } => bail!("{message}"),
        Response::Attached | Response::Watching => bail!("unexpected reply from scudo-bpfd"),
    }
}

/// Claim a registration for this process's cgroup. Called by the shim, which
/// runs inside the unit, just before it execs the real command.
pub fn attach(token: &str) -> Result<()> {
    let request = Request::Attach {
        token: token.to_owned(),
    };
    match round_trip(&request)? {
        Response::Attached => Ok(()),
        Response::Error { message } => bail!("{message}"),
        Response::Registered { .. } | Response::Watching => {
            bail!("unexpected reply from scudo-bpfd")
        }
    }
}

/// Follow what the sandbox registered under `token` turns away.
///
/// Returns a reader positioned on the stream of notifications; it ends when the
/// sandbox is torn down, which the daemon marks with a summary and then a close.
pub fn watch(token: &str) -> Result<MessageReader> {
    let stream = connect()?;
    let request = Request::Watch {
        token: token.to_owned(),
    };
    write_message(&stream, &request)?;
    let mut reader = MessageReader::new(stream);
    match reader.read::<Response>()? {
        Some(Response::Watching) => Ok(reader),
        Some(Response::Error { message }) => bail!("{message}"),
        Some(Response::Registered { .. } | Response::Attached) => {
            bail!("unexpected reply from scudo-bpfd")
        }
        None => bail!("scudo-bpfd closed the connection"),
    }
}
