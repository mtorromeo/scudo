//! Client side of the `scudo-bpfd` protocol.

use std::os::unix::net::UnixStream;

use anyhow::{Context as _, Result, bail};

use crate::{
    bpfd::protocol::{Request, Response, read_message, socket_path, write_message},
    policy::Policy,
};

/// Send one request and read the reply.
fn round_trip(request: &Request) -> Result<Response> {
    let path = socket_path()?;
    let stream = UnixStream::connect(&path)
        .with_context(|| format!("connecting to scudo-bpfd at {}", path.display()))?;
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
        Response::Attached => bail!("unexpected reply from scudo-bpfd"),
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
        Response::Registered { .. } => bail!("unexpected reply from scudo-bpfd"),
    }
}
