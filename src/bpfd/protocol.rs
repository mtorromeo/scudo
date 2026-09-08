//! The wire protocol between `scudo` and `scudo-bpfd`.
//!
//! One JSON object per line, in both directions. Requests carry a list of
//! tagged policies rather than a network policy, so a later policy kind needs no
//! protocol change and no change to the shim.
//!
//! Two of the three verbs are a single round trip. `Watch` is not: the reply is
//! followed by a stream of [`Notification`]s that runs for as long as the
//! sandbox does, which is why [`MessageReader`] exists.

use std::{
    io::{BufRead as _, BufReader, Write as _},
    net::IpAddr,
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
    /// Follow what a registration turns away, until its sandbox is gone.
    ///
    /// Answered with `Watching` and then a stream of [`Notification`]s. The
    /// token may still be pending: the caller watches before the command it is
    /// watching has even started, which is the only way not to miss the first
    /// thing it does.
    Watch { token: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Registered { token: String },
    Attached,
    Watching,
    Error { message: String },
}

/// Which hook turned the traffic away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// `connect()` was refused, so the command got a clean `EPERM`.
    Connect,
    /// The same, for a datagram sent on an unconnected socket.
    Sendmsg,
    /// A packet was dropped on its way out. This is the layer that sees raw
    /// sockets and ICMP, and the command is told nothing.
    Egress,
    /// A packet was dropped on its way in.
    Ingress,
}

/// The transport a refused access used, as far as the hook could tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
    /// Neither, so it carries no port of its own: ICMP, or a raw socket.
    Other,
}

/// What the sandbox was trying to do with a path.
///
/// Only operations that name a path are here: a syscall working on a file
/// descriptor has already got past the sandbox, and the open that produced the
/// descriptor is the one that would have been refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOp {
    Open,
    Stat,
    Access,
    Exec,
    Readlink,
    Unlink,
    Mkdir,
    Rename,
    Chdir,
    Truncate,
}

/// How the sandbox got in the way, as the kernel put it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileError {
    /// `ENOENT`: the path is not there. Under `TemporaryFileSystem=` or
    /// `PrivateTmp=` that is what a hidden file looks like — and it is also
    /// what a path that never existed looks like, which is why [`Outside`] has
    /// to be consulted before calling this a refusal.
    NotFound,
    /// `EACCES` or `EPERM`, which is what `InaccessiblePaths=` produces.
    Permission,
    /// `EROFS`: writing under `ReadOnlyPaths=` or `ProtectSystem=`.
    ReadOnly,
}

/// Whether a file of that name exists outside the sandbox.
///
/// The daemon lives outside the unit's mount namespace, so it can simply look.
/// This answers "is there a file by this name out there", not "is it the same
/// inode" — which is the question worth asking, because it is the one that
/// separates a path the sandbox hid from one the command was only guessing at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outside {
    /// It is there. The sandbox is why the command could not have it.
    Present,
    /// It is not there either, so nothing was taken away: the command was
    /// searching a path, resolving a module, or probing for a config file.
    Absent,
    /// Could not be established — a path cut short, or one relative to a
    /// directory the process no longer has.
    Unknown,
}

/// Something the sandbox was not allowed to do.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Notification {
    /// An access the eBPF programs refused. The address is the destination,
    /// except on ingress where it is the source.
    Blocked {
        stage: Stage,
        transport: Transport,
        addr: IpAddr,
        /// Zero when the traffic carries no port.
        port: u16,
    },
    /// A name the sandbox's resolver would not look up. Naming a host in a rule
    /// is also what permits resolving it, so this is what a missing rule looks
    /// like long before any address is ever reached.
    DnsRefused { name: String, reason: String },
    /// A file access that failed inside the sandbox.
    ///
    /// scudo refuses none of these: systemd hid the path, made it inaccessible
    /// or read-only by rearranging the unit's mount namespace, and the command
    /// was simply handed an error with no way to say which path it was about.
    /// Whether this was a refusal at all is `outside`'s to answer.
    FileBlocked {
        op: FileOp,
        /// Absolute wherever it could be resolved, and ending in `…` when the
        /// path was too long to carry whole.
        path: String,
        error: FileError,
        outside: Outside,
    },
    /// The last message on the stream, sent when the sandbox is torn down.
    Summary {
        /// What was refused and how often, most frequent first.
        targets: Vec<(String, u64)>,
        /// Repeats collapsed inside the deduplication window.
        suppressed: u64,
        /// Events that never made it here at all, because the ring buffer or a
        /// watcher's queue was full.
        lost: u64,
    },
}

impl Notification {
    /// What this event is about, whether or not the sandbox is the reason.
    ///
    /// Repeats of one subject add up under this, so it carries neither the hook
    /// nor the transport nor the operation.
    #[must_use]
    pub fn label(&self) -> Option<String> {
        match self {
            // No port at all is not port zero: ICMP and raw sockets carry none.
            Notification::Blocked { addr, port: 0, .. } => Some(addr.to_string()),
            Notification::Blocked { addr, port, .. } => Some(match addr {
                IpAddr::V4(v4) => format!("{v4}:{port}"),
                // Brackets, or the port reads as part of the address.
                IpAddr::V6(v6) => format!("[{v6}]:{port}"),
            }),
            Notification::DnsRefused { name, .. } => Some(name.clone()),
            Notification::FileBlocked { path, .. } => Some(path.clone()),
            Notification::Summary { .. } => None,
        }
    }

    /// Did the sandbox actually take this away?
    ///
    /// Everything the network programs report is a refusal by construction —
    /// they made it. A file access is not: a program resolving modules or
    /// searching `$PATH` asks for dozens of files that were never anywhere, and
    /// they come back with the same `ENOENT` as one the sandbox hid. The only
    /// thing that tells the two apart is whether the path exists outside.
    #[must_use]
    pub fn is_denial(&self) -> bool {
        !matches!(
            self,
            Notification::FileBlocked {
                error: FileError::NotFound,
                outside: Outside::Absent,
                ..
            } | Notification::Summary { .. }
        )
    }

    /// How this reads in a summary: what was refused.
    ///
    /// `None` for anything that was not refused at all — counting a file that
    /// was missing outside the sandbox too under "blocked" would say the
    /// sandbox had done something it did not do.
    #[must_use]
    pub fn target(&self) -> Option<String> {
        if !self.is_denial() {
            return None;
        }
        self.label()
    }
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
///
/// Only good for a connection that carries exactly one message in this
/// direction: the buffer is built here and dropped here, so anything the read
/// pulled in past the newline goes with it. Use [`MessageReader`] to read more
/// than one.
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

/// Reads a whole stream of messages off one connection, keeping the buffer
/// between them.
pub struct MessageReader {
    inner: BufReader<UnixStream>,
}

impl MessageReader {
    #[must_use]
    pub fn new(stream: UnixStream) -> Self {
        MessageReader {
            inner: BufReader::new(stream),
        }
    }

    /// The next message, or `None` once the far end has closed.
    pub fn read<T: for<'de> Deserialize<'de>>(&mut self) -> Result<Option<T>> {
        let mut line = String::new();
        if self
            .inner
            .read_line(&mut line)
            .context("reading from scudo-bpfd")?
            == 0
        {
            return Ok(None);
        }
        serde_json::from_str(&line)
            .map(Some)
            .context("parsing message")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_notification_survives_the_wire() {
        let events = [
            Notification::Blocked {
                stage: Stage::Connect,
                transport: Transport::Tcp,
                addr: "1.1.1.1".parse().unwrap(),
                port: 443,
            },
            Notification::DnsRefused {
                name: "example.com".to_owned(),
                reason: "no rule names it".to_owned(),
            },
            Notification::Summary {
                targets: vec![("1.1.1.1:443".to_owned(), 3)],
                suppressed: 2,
                lost: 0,
            },
        ];
        for event in events {
            let line = serde_json::to_string(&event).unwrap();
            assert_eq!(
                serde_json::from_str::<Notification>(&line).unwrap(),
                event,
                "round trip changed {line}"
            );
        }
    }

    /// A v6 target keeps its port distinguishable from its address.
    #[test]
    fn a_target_names_the_address_and_the_port() {
        let blocked = |addr: &str, port| Notification::Blocked {
            stage: Stage::Egress,
            transport: Transport::Other,
            addr: addr.parse().unwrap(),
            port,
        };
        assert_eq!(blocked("1.1.1.1", 443).target().unwrap(), "1.1.1.1:443");
        assert_eq!(
            blocked("2606:4700::1", 80).target().unwrap(),
            "[2606:4700::1]:80"
        );
        // No port at all is not port zero.
        assert_eq!(blocked("1.1.1.1", 0).target().unwrap(), "1.1.1.1");
    }

    /// The whole reason `MessageReader` exists: `read_message` throws away
    /// whatever the read pulled in past the first newline, so a second call on
    /// the same connection would miss it.
    #[test]
    fn a_reader_keeps_its_place_between_messages() {
        use std::os::unix::net::UnixStream;

        let (tx, rx) = UnixStream::pair().unwrap();
        let first = Notification::DnsRefused {
            name: "one.example".to_owned(),
            reason: "no rule names it".to_owned(),
        };
        let second = Notification::DnsRefused {
            name: "two.example".to_owned(),
            reason: "no rule names it".to_owned(),
        };
        // Both in one write, so they land in the same buffer fill.
        write_message(&tx, &first).unwrap();
        write_message(&tx, &second).unwrap();
        drop(tx);

        let mut reader = MessageReader::new(rx);
        assert_eq!(reader.read::<Notification>().unwrap(), Some(first));
        assert_eq!(reader.read::<Notification>().unwrap(), Some(second));
        assert_eq!(reader.read::<Notification>().unwrap(), None);
    }
}
