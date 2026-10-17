//! Running a command started inside a sandbox in a sandbox of its own.
//!
//! A scudo started inside a sealed sandbox cannot start another one — it has no
//! way to the service manager — so it runs the command as it is, with whatever
//! the sandbox around it allows. For an agent that means a `npm install` it
//! runs has the agent's access rather than npm's, and a supply-chain attack in
//! a postinstall script gets everything the agent was trusted with.
//!
//! A profile that lists other profiles in `delegate` gets a broker: a process
//! outside its sandbox, listening on a socket that is mounted into that one
//! sandbox only. The scudo inside hands it the command and its standard
//! streams; the broker checks the request and starts the scudo binary again,
//! on the host, which resolves and runs the command exactly as it would have
//! been run from a terminal. The result is a *sibling* sandbox, not one nested
//! inside the agent's.
//!
//! **What the broker guards is that the request cannot widen anything.** The
//! command's name has to be matched by a delegated profile, and nothing else
//! of the command line reaches the profile selection. The working directory is
//! read from the kernel rather than taken from the request, and has to be the
//! very same directory outside the sandbox, inside something the sandbox could
//! already write. And the paths a profile works out from the request — `$PWD`,
//! an `$arg_*`, a lookup variable — are held to the same rule by the run
//! itself; see [`check_derived`].
//!
//! Only a peer whose cgroup is the sandbox's own unit is served: the socket
//! being out of everyone else's sight is the first line, and the cgroup the
//! kernel reports for the connection is the one that decides.

use std::{
    io::{BufRead as _, BufReader, Write as _},
    os::{
        fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd},
        unix::{
            fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
            net::{UnixListener, UnixStream},
            process::CommandExt as _,
        },
    },
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicI32, AtomicUsize, Ordering},
    },
};

use anyhow::{Context as _, Result, bail};
use glob::Pattern;
use serde::{Deserialize, Serialize};

use crate::{bpfd::cgroup, nested, policy::dbus};

/// How many delegated commands may run at once for one sandbox.
const MAX_IN_FLIGHT: usize = 16;

/// The environment variable the broker's spec travels in, from the scudo that
/// starts it.
pub const SPEC_ENV: &str = "SCUDO_BROKER_SPEC";
/// The environment variable holding the listening socket's descriptor.
pub const FD_ENV: &str = "SCUDO_BROKER_FD";
/// The environment variable a delegated run reads its limits from.
pub const DELEGATE_ENV: &str = "SCUDO_DELEGATE";
/// Where a delegated run finds the stream that is the requester's stderr.
/// Its own stderr stays the broker's, so that what scudo says about the run
/// lands in scudo's log rather than in the requester's output.
pub const REQUESTER_STDERR: RawFd = 3;

/// What the broker is told when it starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Spec {
    /// Each delegated profile with its `match` patterns, as written.
    pub delegates: Vec<(String, Vec<String>)>,
    /// What the sandbox may write: a request's directory, and every path a
    /// profile derives from it, has to lie under one of these.
    pub roots: Vec<PathBuf>,
    /// The sandbox's unit; only processes in it are served.
    pub unit: String,
    /// The pid the broker belongs to: the scudo that started it, which becomes
    /// `systemd-run`. Its end is the sandbox's end.
    pub parent: i32,
    /// Logging for the runs it starts, as `SCUDO_LOG_*` variables.
    pub log_env: Vec<(String, String)>,
}

/// What a delegated run is held to, handed to it by the broker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    /// The delegated profiles: one of them has to match the command.
    pub allow: Vec<String>,
    /// See [`Spec::roots`].
    pub roots: Vec<PathBuf>,
}

/// From the scudo inside to the broker.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Run this, with the streams passed alongside.
    Run { command: String, args: Vec<String> },
    /// The requester was sent this signal; pass it on.
    Signal { signo: i32 },
}

/// From the broker to the scudo inside.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Reply {
    /// No delegated profile matches: run it where you are.
    NotDelegated,
    /// Matched, but the request may not be served.
    Refused { reason: String },
    /// Running, in this unit.
    Started { unit: String },
    /// Done, with the code or the signal it ended on.
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
}

/// Something the broker did, for the log or the terminal UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    NotDelegated {
        command: String,
    },
    Delegated {
        command: String,
        cwd: PathBuf,
        profiles: Vec<String>,
        unit: String,
    },
    Refused {
        command: String,
        reason: String,
    },
    Exited {
        command: String,
        unit: String,
        status: String,
    },
}

impl Event {
    /// A refusal is a request the sandbox made and was told no: worth seeing
    /// whatever the level, unlike the rest.
    #[must_use]
    pub fn is_refusal(&self) -> bool {
        matches!(self, Event::Refused { .. })
    }
}

impl core::fmt::Display for Event {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Event::NotDelegated { command } => write!(
                f,
                "'{command}' is not delegated: it runs inside the calling sandbox"
            ),
            Event::Delegated {
                command,
                cwd,
                profiles,
                unit,
            } => write!(
                f,
                "delegated '{command}' (in {}) to {} as {unit}",
                cwd.display(),
                profiles.join(", ")
            ),
            Event::Refused { command, reason } => {
                write!(f, "refused to delegate '{command}': {reason}")
            }
            Event::Exited {
                command,
                unit,
                status,
            } => write!(f, "delegated '{command}' ({unit}) {status}"),
        }
    }
}

/// Where the sockets of every broker live, outside any sandbox's sight.
#[must_use]
pub fn socket_dir() -> PathBuf {
    Path::new(&dbus::runtime_dir()).join("scudo/brokers")
}

/// Create the listening socket for the sandbox `id`.
///
/// Done by the scudo that starts the sandbox, before it does: the socket is
/// bind-mounted into the unit, and a bind mount needs its source to exist.
pub fn listen(id: &str) -> Result<(UnixListener, PathBuf)> {
    let dir = socket_dir();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(format!("{id}.sock"));
    // A leftover of a broker that was killed; the id is fresh, so it is never
    // one in use.
    drop(std::fs::remove_file(&path));
    let listener =
        UnixListener::bind(&path).with_context(|| format!("listening on {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))?;
    Ok((listener, path))
}

/// Serve requests until `stop` becomes readable or hangs up.
///
/// `stop` is a pidfd of [`Spec::parent`] when the broker is a process of its
/// own, and the read end of a pipe when it is a thread in the terminal UI. On
/// the way out every delegated run still going is stopped, and the socket is
/// removed.
pub fn serve(
    listener: &UnixListener,
    socket: &Path,
    spec: &Spec,
    stop: &OwnedFd,
    sink: &(dyn Fn(Event) + Sync),
) -> Result<()> {
    let ctx = Context::new(spec)?;
    listener
        .set_nonblocking(true)
        .context("making the broker's socket non-blocking")?;

    let result = std::thread::scope(|scope| -> Result<()> {
        loop {
            let ready = poll(&[listener.as_raw_fd(), stop.as_raw_fd()], -1i32)?;
            if ready.get(1).copied().unwrap_or(false) {
                // Before the scope joins the connections: each waits for its
                // run, and stopping the runs is what lets them finish.
                ctx.stop_all();
                return Ok(());
            }
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(err) => return Err(err).context("accepting a request"),
            };
            drop(stream.set_nonblocking(false));
            let shared = &ctx;
            scope.spawn(move || {
                if let Err(err) = handle(&stream, shared, sink) {
                    sink(Event::Refused {
                        command: String::from("?"),
                        reason: format!("{err:#}"),
                    });
                }
            });
        }
    });

    // Whatever is still running belongs to a sandbox that is gone, or to a UI
    // that is closing; nobody is left to wait for it. Already done when asked
    // to stop; this is for leaving on an error.
    ctx.stop_all();
    drop(std::fs::remove_file(socket));
    result
}

/// What every connection needs, prepared once.
struct Context<'a> {
    spec: &'a Spec,
    patterns: Vec<(String, Vec<Pattern>)>,
    roots: Vec<PathBuf>,
    uid: u32,
    self_exe: PathBuf,
    in_flight: AtomicUsize,
    /// The ids of the runs going on, so that they can be stopped together.
    running: Mutex<Vec<String>>,
}

impl<'a> Context<'a> {
    fn new(spec: &'a Spec) -> Result<Self> {
        let patterns = spec
            .delegates
            .iter()
            .map(|(name, globs)| {
                let compiled = globs
                    .iter()
                    .map(|g| Pattern::new(g).with_context(|| format!("invalid pattern '{g}'")))
                    .collect::<Result<_>>()?;
                Ok((name.clone(), compiled))
            })
            .collect::<Result<_>>()?;
        Ok(Context {
            spec,
            patterns,
            roots: canonical_roots(&spec.roots),
            // SAFETY: getuid always succeeds and touches no memory.
            uid: unsafe { libc::getuid() },
            self_exe: std::env::current_exe().context("locating the scudo binary")?,
            in_flight: AtomicUsize::new(0),
            running: Mutex::new(Vec::new()),
        })
    }

    fn stop_all(&self) {
        let ids = self
            .running
            .lock()
            .map(|running| running.clone())
            .unwrap_or_default();
        for id in ids {
            stop_units(&id);
        }
    }

    fn track(&self, id: &str, running: bool) {
        if let Ok(mut list) = self.running.lock() {
            if running {
                list.push(id.to_owned());
            } else {
                list.retain(|other| other != id);
            }
        }
    }
}

/// The roots, with their symlinks resolved, so that a directory can be
/// compared against them once its own are. A root that does not exist holds
/// nothing and is dropped.
fn canonical_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect()
}

/// Serve one connection, from the first message to the command's end.
fn handle(stream: &UnixStream, ctx: &Context<'_>, sink: &(dyn Fn(Event) + Sync)) -> Result<()> {
    let (pid, uid) = crate::bpfd::protocol::peer_credentials(stream)?;
    let cgroup = cgroup::of_pid(pid)?;
    if uid != ctx.uid || !nested::in_unit(&cgroup, ctx.uid, &ctx.spec.unit) {
        bail!("a request from outside {} (cgroup {cgroup})", ctx.spec.unit);
    }

    // The streams come first, on the first byte, before anything is buffered:
    // a reader that got ahead would swallow the byte they are attached to.
    let streams = recv_fds(stream, 3)?;
    let mut reader = BufReader::new(stream.try_clone().context("cloning the connection")?);
    let Some(Request::Run { command, args }) = read_line::<Request>(&mut reader)? else {
        bail!("the request did not start with a command");
    };

    let name = Path::new(&command)
        .file_name()
        .map_or_else(|| command.clone(), |n| n.to_string_lossy().into_owned());
    let profiles: Vec<String> = ctx
        .patterns
        .iter()
        .filter(|(_, patterns)| patterns.iter().any(|p| p.matches(&name)))
        .map(|(profile, _)| profile.clone())
        .collect();
    if profiles.is_empty() {
        sink(Event::NotDelegated { command: name });
        return reply(stream, &Reply::NotDelegated);
    }

    let refuse = |reason: String| -> Result<()> {
        sink(Event::Refused {
            command: name.clone(),
            reason: reason.clone(),
        });
        reply(stream, &Reply::Refused { reason })
    };

    let cwd = match working_directory(pid, &ctx.roots) {
        Ok(cwd) => cwd,
        Err(err) => return refuse(format!("{err:#}")),
    };
    if ctx.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
        ctx.in_flight.fetch_sub(1, Ordering::SeqCst);
        return refuse(format!(
            "{MAX_IN_FLIGHT} delegated commands are running already"
        ));
    }
    let result = run(
        stream,
        &mut reader,
        ctx,
        sink,
        &command,
        &args,
        &profiles,
        &cwd,
        streams,
    );
    ctx.in_flight.fetch_sub(1, Ordering::SeqCst);
    result
}

/// Start the delegated run and see it through.
#[expect(
    clippy::too_many_arguments,
    reason = "one request's worth of state, passed once"
)]
fn run(
    stream: &UnixStream,
    reader: &mut BufReader<UnixStream>,
    ctx: &Context<'_>,
    sink: &(dyn Fn(Event) + Sync),
    command: &str,
    args: &[String],
    profiles: &[String],
    cwd: &Path,
    streams: Vec<OwnedFd>,
) -> Result<()> {
    let id = dbus::new_id();
    let unit = nested::sealed_unit(&id);
    let name = Path::new(command)
        .file_name()
        .map_or_else(|| command.to_owned(), |n| n.to_string_lossy().into_owned());

    let limits = Limits {
        allow: ctx.spec.delegates.iter().map(|(n, _)| n.clone()).collect(),
        roots: ctx.roots.clone(),
    };
    let mut streams = streams.into_iter();
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (streams.next(), streams.next(), streams.next())
    else {
        bail!("the request did not carry its three standard streams");
    };

    let mut cmd = Command::new(&ctx.self_exe);
    cmd.arg("--delegated")
        .arg(&id)
        .arg("--")
        .arg(command)
        .args(args)
        .current_dir(cwd)
        .env("PWD", cwd)
        .env(DELEGATE_ENV, serde_json::to_string(&limits)?)
        .env_remove(SPEC_ENV)
        .env_remove(FD_ENV)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::inherit());
    for (key, value) in &ctx.spec.log_env {
        cmd.env(key, value);
    }
    let requester_stderr = stderr.as_raw_fd();
    let hook = move || {
        // SAFETY: dup2 is async-signal-safe; it puts the requester's stderr
        // where the run expects it, and the duplicate is not close-on-exec.
        if unsafe { libc::dup2(requester_stderr, REQUESTER_STDERR) } < 0i32 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    ctx.track(&id, true);
    // SAFETY: the hook only makes an async-signal-safe call.
    let mut child = match unsafe { cmd.pre_exec(hook) }.spawn() {
        Ok(child) => child,
        Err(err) => {
            ctx.track(&id, false);
            sink(Event::Refused {
                command: name.clone(),
                reason: format!("cannot start scudo: {err}"),
            });
            return reply(
                stream,
                &Reply::Refused {
                    reason: format!("cannot start scudo: {err}"),
                },
            );
        }
    };
    drop(stderr);
    sink(Event::Delegated {
        command: name.clone(),
        cwd: cwd.to_path_buf(),
        profiles: profiles.to_vec(),
        unit: unit.clone(),
    });
    reply(stream, &Reply::Started { unit: unit.clone() })?;

    let child_pid = i32::try_from(child.id()).context("child pid out of range")?;
    let pidfd = pidfd_open(child_pid)?;
    let status = loop {
        let ready = if reader.buffer().is_empty() {
            poll(&[stream.as_raw_fd(), pidfd.as_raw_fd()], -1i32)?
        } else {
            vec![true, false]
        };
        if ready.get(1).copied().unwrap_or(false) {
            break Some(child.wait().context("waiting for the delegated run")?);
        }
        match read_line::<Request>(reader) {
            Ok(Some(Request::Signal { signo })) => forward_signal(signo, child_pid, &id),
            Ok(Some(Request::Run { .. })) => {}
            // The requester is gone: nobody is left to see the result, and a
            // unit left running would outlive it.
            Ok(None) | Err(_) => {
                stop_units(&id);
                drop(child.kill());
                drop(child.wait());
                break None;
            }
        }
    };
    ctx.track(&id, false);

    let Some(status) = status else {
        sink(Event::Exited {
            command: name,
            unit,
            status: String::from("was stopped: the caller went away"),
        });
        return Ok(());
    };
    sink(Event::Exited {
        command: name,
        unit,
        status: describe(status),
    });
    reply(
        stream,
        &Reply::Exited {
            code: status.code(),
            signal: std::os::unix::process::ExitStatusExt::signal(&status),
        },
    )
}

fn describe(status: ExitStatus) -> String {
    match (
        status.code(),
        std::os::unix::process::ExitStatusExt::signal(&status),
    ) {
        (Some(code), _) => format!("exited {code}"),
        (None, Some(signal)) => format!("was killed by signal {signal}"),
        (None, None) => String::from("ended"),
    }
}

/// Pass a signal the requester received on to the run.
///
/// `SIGWINCH` goes to `systemd-run`, which forwards the new size to the pty it
/// made. Everything else goes to the unit's processes: killing `systemd-run`
/// would only make it stop waiting and leave the unit running.
fn forward_signal(signo: i32, child_pid: i32, id: &str) {
    if signo == libc::SIGWINCH {
        // SAFETY: kill only sends a signal to a process we started.
        if unsafe { libc::kill(child_pid, libc::SIGWINCH) } != 0i32 {
            tracing::debug!(
                "cannot pass a resize on: {}",
                std::io::Error::last_os_error()
            );
        }
        return;
    }
    for unit in [nested::sealed_unit(id), plain_unit(id)] {
        systemctl(&["kill", "--signal", &signo.to_string(), &unit]);
    }
}

/// The unit a delegated run gets when its profile leaves it unsealed.
#[must_use]
pub fn plain_unit(id: &str) -> String {
    format!("scudo-delegated-{id}.service")
}

/// Stop whichever unit the run `id` is in.
fn stop_units(id: &str) {
    for unit in [nested::sealed_unit(id), plain_unit(id)] {
        systemctl(&["stop", &unit]);
    }
}

fn systemctl(args: &[&str]) {
    drop(
        Command::new("systemctl")
            .arg("--user")
            .arg("--quiet")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
}

/// The requester's working directory, if it may be used outside the sandbox.
///
/// The path is read through `/proc`, so the requester does not get to say it;
/// it has to name the same directory outside the sandbox as inside — which a
/// private `/tmp`, or a home replaced by an empty one, does not — and it has to
/// lie under a root the sandbox could write.
fn working_directory(pid: i32, roots: &[PathBuf]) -> Result<PathBuf> {
    let link = format!("/proc/{pid}/cwd");
    let path = std::fs::read_link(&link).context("reading the caller's directory")?;
    let inside = std::fs::metadata(&link).context("reading the caller's directory")?;
    let outside = std::fs::metadata(&path).ok();
    if outside.is_none_or(|meta| meta.dev() != inside.dev() || meta.ino() != inside.ino()) {
        bail!(
            "{} is not the same directory outside the sandbox",
            path.display()
        );
    }
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolving {}", path.display()))?;
    if !under_roots(&canonical, roots) {
        bail!(
            "{} is outside what the sandbox can write",
            canonical.display()
        );
    }
    Ok(canonical)
}

/// Whether `path`, already canonical, is one of `roots` or inside one.
#[must_use]
pub fn under_roots(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

/// Check the paths a delegated run's profiles derived from the request; see
/// [`crate::profile::ResolvedProfile::derived`].
///
/// A path that does not exist yet is judged by its closest ancestor that does,
/// resolved, with the rest put back on: it can only ever be created there.
pub fn check_derived(derived: &[PathBuf], roots: &[PathBuf]) -> Result<()> {
    for path in derived {
        let resolved = resolve_existing(path);
        if !under_roots(&resolved, roots) {
            bail!(
                "{} is outside what the calling sandbox can write",
                path.display()
            );
        }
    }
    Ok(())
}

fn resolve_existing(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut current = path;
    loop {
        if let Ok(resolved) = current.canonicalize() {
            let mut out = resolved;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (current.parent(), current.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_owned());
                current = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// What came of asking the broker.
#[derive(Debug)]
pub enum Outcome {
    NotDelegated,
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
}

/// The write end of the pipe the signal handler reports on.
static SIGNAL_PIPE: AtomicI32 = AtomicI32::new(-1i32);

/// The signals passed on to the run.
const FORWARDED: [i32; 5] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGWINCH,
];

extern "C" fn on_signal(signo: libc::c_int) {
    let bytes = signo.to_be_bytes();
    // SAFETY: write is async-signal-safe, and the buffer is on this stack.
    unsafe {
        libc::write(
            SIGNAL_PIPE.load(Ordering::Relaxed),
            bytes.as_ptr().cast::<libc::c_void>(),
            bytes.len(),
        );
    }
}

/// Ask the broker to run `command`, from inside the sandbox, and wait for it.
///
/// Called by the scudo inside, which hands over its own standard streams. Any
/// failure to reach the broker is an error, never a reason to run the command
/// where it is: whether it should have been delegated is the broker's to say.
pub fn delegate(command: &str, args: &[String]) -> Result<Outcome> {
    // SAFETY: getuid always succeeds and touches no memory.
    let uid = unsafe { libc::getuid() };
    let path = nested::broker_path(uid);
    let stream = UnixStream::connect(&path)
        .with_context(|| format!("scudo's broker at {} is not answering", path.display()))?;
    send_fds(&stream, &[0i32, 1i32, 2i32])?;
    write_line(
        &stream,
        &Request::Run {
            command: command.to_owned(),
            args: args.to_vec(),
        },
    )?;

    let mut reader = BufReader::new(stream.try_clone().context("cloning the connection")?);
    match read_line::<Reply>(&mut reader)? {
        Some(Reply::NotDelegated) => return Ok(Outcome::NotDelegated),
        Some(Reply::Refused { reason }) => bail!("delegation refused: {reason}"),
        Some(Reply::Started { unit }) => tracing::debug!("delegated '{command}' as {unit}"),
        Some(Reply::Exited { code, signal }) => return Ok(Outcome::Exited { code, signal }),
        None => bail!("scudo's broker closed the connection"),
    }

    let (read_end, write_end) = pipe()?;
    SIGNAL_PIPE.store(write_end.as_raw_fd(), Ordering::Relaxed);
    for signo in FORWARDED {
        // SAFETY: installing a handler that only calls write(2).
        unsafe {
            libc::signal(signo, on_signal as *const () as libc::sighandler_t);
        }
    }

    loop {
        let ready = if reader.buffer().is_empty() {
            poll(&[stream.as_raw_fd(), read_end.as_raw_fd()], -1i32)?
        } else {
            vec![true, false]
        };
        if ready.get(1).copied().unwrap_or(false) {
            let mut buf = [0u8; 4];
            // SAFETY: reading into a buffer of the length given.
            let n = unsafe {
                libc::read(
                    read_end.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n == 4isize {
                write_line(
                    &stream,
                    &Request::Signal {
                        signo: i32::from_be_bytes(buf),
                    },
                )?;
            }
        }
        if ready.first().copied().unwrap_or(false) {
            match read_line::<Reply>(&mut reader)? {
                Some(Reply::Exited { code, signal }) => {
                    return Ok(Outcome::Exited { code, signal });
                }
                Some(_) => {}
                None => bail!("scudo's broker went away before the command ended"),
            }
        }
    }
}

fn reply(stream: &UnixStream, message: &Reply) -> Result<()> {
    write_line(stream, message)
}

fn write_line<T: Serialize>(stream: &UnixStream, message: &T) -> Result<()> {
    let mut line = serde_json::to_vec(message).context("serialising message")?;
    line.push(b'\n');
    let mut sink = stream;
    sink.write_all(&line)
        .context("writing to the broker connection")
}

/// Read one message, or `None` at the end of the stream.
fn read_line<T: for<'de> Deserialize<'de>>(
    reader: &mut BufReader<UnixStream>,
) -> Result<Option<T>> {
    let mut line = String::new();
    if reader
        .read_line(&mut line)
        .context("reading from the broker connection")?
        == 0
    {
        return Ok(None);
    }
    Ok(Some(
        serde_json::from_str(&line).context("decoding a broker message")?,
    ))
}

/// Wait until any of `fds` is readable or hung up; `true` for each that is.
fn poll(fds: &[RawFd], timeout: i32) -> Result<Vec<bool>> {
    let mut pollfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let count = libc::nfds_t::try_from(pollfds.len()).context("too many descriptors")?;
    loop {
        // SAFETY: the array and its length agree.
        let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), count, timeout) };
        if rc >= 0i32 {
            break;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err).context("waiting on the broker's descriptors");
        }
    }
    Ok(pollfds
        .iter()
        .map(|p| p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0)
        .collect())
}

fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    // SAFETY: pipe2 fills the two-element array it is given.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0i32 {
        return Err(std::io::Error::last_os_error()).context("creating a pipe");
    }
    let [read, write] = fds;
    // SAFETY: both descriptors were just created and are owned by nobody else.
    let read = unsafe { OwnedFd::from_raw_fd(read) };
    // SAFETY: as above.
    let write = unsafe { OwnedFd::from_raw_fd(write) };
    Ok((read, write))
}

/// A descriptor that becomes readable when `pid` exits.
pub fn pidfd_open(pid: i32) -> Result<OwnedFd> {
    // SAFETY: pidfd_open takes a pid and flags and returns a new descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0i32) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("watching process {pid}"));
    }
    let fd = RawFd::try_from(fd).context("pidfd out of range")?;
    // SAFETY: the descriptor was just created and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Send `fds` along with a single byte.
#[expect(
    clippy::multiple_unsafe_ops_per_block,
    reason = "filling a control message is one operation spelt in several raw steps"
)]
fn send_fds(stream: &UnixStream, fds: &[RawFd]) -> Result<()> {
    let payload = core::mem::size_of_val(fds);
    let payload_u32 = u32::try_from(payload).context("too many descriptors")?;
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE(payload_u32) };
    let space = usize::try_from(space).context("control message too large")?;
    // u64 elements keep the buffer aligned for a cmsghdr.
    let mut control = vec![0u64; space.div_ceil(8)];
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: byte.len(),
    };
    // SAFETY: msghdr is plain data; every field used is set below.
    let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = space;
    // SAFETY: the control buffer is large enough for one header carrying
    // `payload` bytes, which is what CMSG_SPACE was asked for.
    let filled: Result<()> = unsafe {
        let header = libc::CMSG_FIRSTHDR(&raw const msg);
        if header.is_null() {
            bail!("no room for the control message");
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len =
            usize::try_from(libc::CMSG_LEN(payload_u32)).context("control message too large")?;
        core::ptr::copy_nonoverlapping(fds.as_ptr().cast::<u8>(), libc::CMSG_DATA(header), payload);
        Ok(())
    };
    filled?;
    // SAFETY: msg points at buffers that outlive the call.
    if unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const msg, 0i32) } < 0 {
        return Err(std::io::Error::last_os_error()).context("handing over the standard streams");
    }
    Ok(())
}

/// Receive the single byte [`send_fds`] sends, and the descriptors with it.
#[expect(
    clippy::multiple_unsafe_ops_per_block,
    reason = "walking control messages is one operation spelt in several raw steps"
)]
fn recv_fds(stream: &UnixStream, count: usize) -> Result<Vec<OwnedFd>> {
    let payload = count.saturating_mul(core::mem::size_of::<RawFd>());
    let payload_u32 = u32::try_from(payload).context("too many descriptors")?;
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE(payload_u32) };
    let space = usize::try_from(space).context("control message too large")?;
    let mut control = vec![0u64; space.div_ceil(8)];
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: byte.len(),
    };
    // SAFETY: msghdr is plain data; every field used is set below.
    let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = space;
    // SAFETY: msg points at buffers that outlive the call.
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("receiving the standard streams");
    }
    if n == 0 {
        bail!("the connection closed before the request");
    }

    let mut fds = Vec::new();
    // SAFETY: walking the control messages the kernel just wrote, within the
    // length it reported.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&raw const msg);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(header);
                let len = (*header)
                    .cmsg_len
                    .saturating_sub(usize::try_from(libc::CMSG_LEN(0)).unwrap_or(usize::MAX));
                let n = len
                    .checked_div(core::mem::size_of::<RawFd>())
                    .unwrap_or(0usize);
                for i in 0..n {
                    let mut fd = 0i32;
                    core::ptr::copy_nonoverlapping(
                        data.add(i.saturating_mul(core::mem::size_of::<RawFd>())),
                        (&raw mut fd).cast::<u8>(),
                        core::mem::size_of::<RawFd>(),
                    );
                    fds.push(OwnedFd::from_raw_fd(fd));
                }
            }
            header = libc::CMSG_NXTHDR(&raw const msg, header);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0i32 {
        bail!("the request carried more descriptors than expected");
    }
    if fds.len() != count {
        bail!(
            "the request carried {} descriptors instead of {count}",
            fds.len()
        );
    }
    Ok(fds)
}

/// Run as the broker process: take the socket and the spec from the
/// environment, and serve until the sandbox ends.
pub fn run_process(sink: &(dyn Fn(Event) + Sync)) -> Result<()> {
    let spec: Spec = serde_json::from_str(
        &std::env::var(SPEC_ENV).with_context(|| format!("{SPEC_ENV} is not set"))?,
    )
    .context("reading the broker's spec")?;
    let fd: RawFd = std::env::var(FD_ENV)
        .with_context(|| format!("{FD_ENV} is not set"))?
        .parse()
        .context("reading the broker's socket")?;
    // SAFETY: the descriptor was handed down by the scudo that started us, for
    // this process to own.
    let listener = unsafe { UnixListener::from_raw_fd(fd) };
    let socket = listener
        .local_addr()
        .ok()
        .and_then(|addr| addr.as_pathname().map(Path::to_path_buf))
        .unwrap_or_default();
    // The parent becomes `systemd-run`, keeping its pid; when that is gone the
    // sandbox is, and so is everything there was to serve.
    let stop = pidfd_open(spec.parent)?;
    serve(&listener, &socket, &spec, &stop, sink)
}

/// A broker about to be started for a sandbox: its socket, and what it is told.
#[derive(Debug)]
pub struct Setup {
    pub listener: UnixListener,
    pub socket: PathBuf,
    pub spec: Spec,
}

impl Setup {
    /// The unit properties that put the socket where the sandbox looks for it,
    /// and every other broker's out of its sight.
    #[must_use]
    pub fn properties(&self) -> Vec<String> {
        // SAFETY: getuid always succeeds and touches no memory.
        let uid = unsafe { libc::getuid() };
        vec![
            "-p".to_owned(),
            format!(
                "BindPaths={}:{}",
                self.socket.display(),
                nested::broker_path(uid).display()
            ),
            "-p".to_owned(),
            format!("InaccessiblePaths=-{}", socket_dir().display()),
        ]
    }

    /// Start the broker as a process of its own, which outlives this one: the
    /// caller is about to become `systemd-run`.
    pub fn spawn(self, self_exe: &Path, command: &str) -> Result<()> {
        let fd = self.listener.as_raw_fd();
        let mut cmd = Command::new(self_exe);
        cmd.arg("--broker")
            .arg("--")
            .arg(command)
            .env(SPEC_ENV, serde_json::to_string(&self.spec)?)
            .env(FD_ENV, fd.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        for (key, value) in &self.spec.log_env {
            cmd.env(key, value);
        }
        let hook = move || {
            // SAFETY: fcntl is async-signal-safe; clearing close-on-exec on the
            // socket is what lets the broker inherit it.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, 0i32) } < 0i32 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };
        // SAFETY: the hook only makes an async-signal-safe call.
        unsafe { cmd.pre_exec(hook) }
            .spawn()
            .context("starting the broker")?;
        Ok(())
    }

    /// Serve from a thread of this process instead, reporting to `sink`: the
    /// terminal UI stays, and is where the reports go.
    pub fn start_thread(self, sink: Box<dyn Fn(Event) + Send + Sync>) -> Result<Thread> {
        Thread::start(self.listener, self.socket, self.spec, sink)
    }
}

/// A broker running as a thread of this process, for the terminal UI.
#[derive(Debug)]
pub struct Thread {
    stop: Option<OwnedFd>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Thread {
    /// Start serving, reporting to `sink`.
    pub fn start(
        listener: UnixListener,
        socket: PathBuf,
        spec: Spec,
        sink: Box<dyn Fn(Event) + Send + Sync>,
    ) -> Result<Self> {
        let (read_end, write_end) = pipe()?;
        let handle = std::thread::spawn(move || {
            if let Err(err) = serve(&listener, &socket, &spec, &read_end, &*sink) {
                tracing::warn!("the broker stopped: {err:#}");
            }
        });
        Ok(Thread {
            stop: Some(write_end),
            handle: Some(handle),
        })
    }

    /// Stop serving, stopping every delegated run still going.
    pub fn shutdown(mut self) {
        self.stop.take();
        if let Some(handle) = self.handle.take() {
            drop(handle.join());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of its own for one test, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("scudo-broker-test-{}-{tag}", std::process::id()));
            drop(std::fs::remove_dir_all(&path));
            std::fs::create_dir_all(&path).unwrap();
            Scratch(path.canonicalize().unwrap())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.0));
        }
    }

    #[test]
    fn a_root_covers_what_is_inside_it_only() {
        let roots = [PathBuf::from("/home/u/project")];
        assert!(under_roots(Path::new("/home/u/project"), &roots));
        assert!(under_roots(Path::new("/home/u/project/sub"), &roots));
        assert!(!under_roots(Path::new("/home/u/projectx"), &roots));
        assert!(!under_roots(Path::new("/home/u"), &roots));
    }

    #[test]
    fn a_missing_path_is_judged_by_where_it_would_be_created() {
        let root = Scratch::new("missing");
        let roots = [root.0.clone()];
        check_derived(&[root.0.join("not/yet/there")], &roots).unwrap();
        assert!(check_derived(&[PathBuf::from("/definitely/not/here")], &roots).is_err());
    }

    #[test]
    fn a_symlink_out_of_a_root_does_not_count_as_inside_it() {
        let root = Scratch::new("link-root");
        let outside = Scratch::new("link-outside");
        std::os::unix::fs::symlink(&outside.0, root.0.join("link")).unwrap();
        check_derived(&[root.0.join("link/file")], core::slice::from_ref(&root.0)).unwrap_err();
    }

    #[test]
    fn descriptors_travel_with_the_first_byte() {
        let (a, b) = UnixStream::pair().unwrap();
        let (r, w) = pipe().unwrap();
        send_fds(&a, &[r.as_raw_fd(), w.as_raw_fd(), r.as_raw_fd()]).unwrap();
        write_line(&a, &Request::Signal { signo: 2i32 }).unwrap();
        let fds = recv_fds(&b, 3).unwrap();
        assert_eq!(fds.len(), 3);
        let mut reader = BufReader::new(b);
        assert!(matches!(
            read_line::<Request>(&mut reader).unwrap(),
            Some(Request::Signal { signo: 2i32 })
        ));
    }

    #[test]
    fn too_few_descriptors_are_refused() {
        let (a, b) = UnixStream::pair().unwrap();
        let (r, _w) = pipe().unwrap();
        send_fds(&a, &[r.as_raw_fd()]).unwrap();
        recv_fds(&b, 3).unwrap_err();
    }
}
