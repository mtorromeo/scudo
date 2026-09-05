//! The `scudo-bpfd` daemon: hold policies, attach them to the cgroup of the
//! process that claims them, and tear them down when that cgroup goes away.
//!
//! The daemon carries `CAP_BPF` and `CAP_NET_ADMIN`, so anyone on the system can
//! execute it. What keeps that harmless is that it only ever *adds* restrictions
//! to a cgroup the caller already owns, and offers no way to remove them: cgroup
//! programs combine with a logical AND, so an extra one can only narrow what is
//! allowed. Detaching happens only when the cgroup itself disappears.

use core::{fmt::Write as _, time::Duration};
use std::{
    collections::HashMap,
    io::ErrorKind,
    os::{
        fd::{FromRawFd as _, RawFd},
        unix::net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context as _, Result, bail};

use crate::{
    bpfd::{
        caps, cgroup,
        loader::{self, Attached},
        protocol::{Request, Response, read_message, socket_path, write_message},
    },
    policy::Policy,
};

/// How long a registration whose caller is gone waits to be claimed before it is
/// dropped.
const CLAIM_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest a registration lives whatever else is true.
///
/// While the process that registered is still running, the timeout above does
/// not apply — it may be sitting at a `--confirm` prompt, and a user thinking it
/// over must not have the registration reaped from under them. A pid can be
/// recycled, though, so a live-looking owner is not proof of anything for ever.
const PENDING_MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// How often to look for sandboxes whose cgroup has gone.
const REAP_INTERVAL: Duration = Duration::from_secs(5);

/// Upper bound on live sandboxes, so a runaway caller cannot exhaust memory or
/// kernel BPF resources.
const MAX_SANDBOXES: usize = 128;

/// A registration waiting for its shim to claim it.
struct Pending {
    policies: Vec<Policy>,
    registered_at: Instant,
    /// The process that registered. It goes on to become `systemd-run`, so it
    /// stays alive across the whole wait, and while it is there the registration
    /// is still on its way to being claimed.
    owner: i32,
}

/// A sandbox with policies attached. Dropping it detaches them.
struct Sandbox {
    cgroup_dir: PathBuf,
    _attached: Vec<Attached>,
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Pending>,
    sandboxes: Vec<Sandbox>,
}

impl State {
    /// Drop registrations nobody claimed and sandboxes whose cgroup is gone.
    ///
    /// A cgroup outlives its processes only until the last reference goes away,
    /// so its absence is a reliable "the command has finished".
    fn reap(&mut self) {
        let now = Instant::now();
        self.pending.retain(|_, p| {
            let age = now.duration_since(p.registered_at);
            if age >= PENDING_MAX_LIFETIME {
                return false;
            }
            // Whoever registered is still on their way here: scudo asks for the
            // token before it runs the command, and between the two it may stop
            // to ask the user. Only once it is gone does the timeout decide.
            process_alive(p.owner) || age < CLAIM_TIMEOUT
        });
        self.sandboxes.retain(|s| s.cgroup_dir.exists());
    }
}

/// Run the daemon until it is stopped.
pub fn run() -> Result<()> {
    // Report a missing capability now, rather than as an EPERM on the first
    // attach — by which point a command is already waiting on the answer.
    crate::bpfd::caps::check().context("scudo-bpfd cannot load eBPF programs")?;

    let listener = listener()?;
    let state = Arc::new(Mutex::new(State::default()));

    let reaper_state = Arc::clone(&state);
    let _reaper = std::thread::Builder::new()
        .name("reaper".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(REAP_INTERVAL);
                // A poisoned lock means a client thread panicked: stop rather
                // than work with state that can no longer be trusted.
                let Ok(mut state) = reaper_state.lock() else {
                    break;
                };
                state.reap();
            }
        })
        .context("starting the reaper thread")?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                // One thread per connection: each one is a couple of messages
                // long, and a stuck client must not block the others.
                if let Err(err) = std::thread::Builder::new()
                    .name("client".to_owned())
                    .spawn(move || serve(&stream, &state))
                {
                    eprintln!("scudo-bpfd: cannot serve connection: {err}");
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => eprintln!("scudo-bpfd: accept failed: {err}"),
        }
    }

    Ok(())
}

/// Take the listening socket from systemd, or create it ourselves.
fn listener() -> Result<UnixListener> {
    if let Some(listener) = socket_activated()? {
        return Ok(listener);
    }

    let path = socket_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // A stale socket from a previous run would make bind fail.
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => bail!("removing stale socket {}: {err}", path.display()),
    }

    let listener =
        UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    set_socket_permissions(&path)?;
    Ok(listener)
}

/// systemd hands the socket over as fd 3 when the unit is socket-activated.
fn socket_activated() -> Result<Option<UnixListener>> {
    const SD_LISTEN_FDS_START: RawFd = 3;

    let Some(count) = std::env::var_os("LISTEN_FDS") else {
        return Ok(None);
    };
    let count: i32 = count
        .to_string_lossy()
        .parse()
        .context("LISTEN_FDS is not a number")?;
    if count < 1i32 {
        return Ok(None);
    }
    // Only trust the handover if it was meant for us.
    if let Some(pid) = std::env::var_os("LISTEN_PID")
        && pid.to_string_lossy().parse::<u32>().ok() != Some(std::process::id())
    {
        return Ok(None);
    }

    // SAFETY: systemd guarantees fd 3 is a listening socket it passed to us,
    // and nothing else in this process has claimed it.
    Ok(Some(unsafe {
        UnixListener::from_raw_fd(SD_LISTEN_FDS_START)
    }))
}

/// Only the owner may talk to the daemon.
fn set_socket_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting permissions on {}", path.display()))
}

fn serve(stream: &UnixStream, state: &Mutex<State>) {
    let response = match handle(stream, state) {
        Ok(response) => response,
        Err(err) => Response::Error {
            message: format!("{err:#}"),
        },
    };
    if let Err(err) = write_message(stream, &response) {
        eprintln!("scudo-bpfd: cannot reply: {err:#}");
    }
}

fn handle(stream: &UnixStream, state: &Mutex<State>) -> Result<Response> {
    let request: Request = read_message(stream)?;
    match request {
        Request::Register { policies } => register(policies, stream, state),
        Request::Attach { token } => attach(&token, stream, state),
    }
}

fn register(policies: Vec<Policy>, stream: &UnixStream, state: &Mutex<State>) -> Result<Response> {
    if policies.is_empty() {
        bail!("no policies to register");
    }

    let (owner, _) = peer_credentials(stream)?;
    let token = new_token()?;
    let mut state = lock(state)?;
    state.reap();
    if state.pending.len().saturating_add(state.sandboxes.len()) >= MAX_SANDBOXES {
        bail!("too many policies in flight");
    }
    state.pending.insert(
        token.clone(),
        Pending {
            policies,
            registered_at: Instant::now(),
            owner,
        },
    );
    Ok(Response::Registered { token })
}

fn attach(token: &str, stream: &UnixStream, state: &Mutex<State>) -> Result<Response> {
    let (pid, uid) = peer_credentials(stream)?;

    let cgroup = cgroup::of_pid(pid)?;
    if !cgroup::belongs_to_user(&cgroup, uid) {
        bail!("cgroup {cgroup} is not in uid {uid}'s own subtree");
    }
    // Guard against the pid having been recycled between the two reads: the
    // caller is blocked waiting for our reply, so its cgroup cannot legitimately
    // change while we work.
    if cgroup::of_pid(pid)? != cgroup {
        bail!("the calling process moved between cgroups");
    }

    let mut state = lock(state)?;
    let pending = state
        .pending
        .remove(token)
        .context("unknown or already claimed token")?;

    let cgroup_dir = cgroup::dir_of(&cgroup);
    let mut attached = Vec::with_capacity(pending.policies.len());
    for policy in &pending.policies {
        match policy {
            Policy::Network(network) => {
                attached.push(loader::attach(network, &cgroup_dir).with_context(|| {
                    format!(
                        "attaching the network policy; if this is a permission error, check: {}",
                        caps::SETCAP_HINT
                    )
                })?);
            }
        }
    }

    state.sandboxes.push(Sandbox {
        cgroup_dir,
        _attached: attached,
    });
    Ok(Response::Attached)
}

/// Take the state lock, turning a poisoned lock into a plain error.
///
/// The lock is poisoned only if a client thread panicked while holding it, in
/// which case refusing to serve is the safe answer.
fn lock(state: &Mutex<State>) -> Result<std::sync::MutexGuard<'_, State>> {
    state
        .lock()
        .map_err(|err| anyhow::anyhow!("daemon state is poisoned: {err}"))
}

/// Read the connecting process's pid and uid from the kernel.
///
/// `UnixStream::peer_cred` is still unstable, and these are the credentials the
/// whole trust model rests on, so we ask for them directly.
fn peer_credentials(stream: &UnixStream) -> Result<(i32, u32)> {
    use std::os::fd::AsRawFd as _;

    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len =
        libc::socklen_t::try_from(size_of::<libc::ucred>()).context("ucred size does not fit")?;
    // SAFETY: passing a correctly sized, correctly typed buffer for SO_PEERCRED
    // on a socket we own.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0i32 {
        return Err(std::io::Error::last_os_error()).context("reading peer credentials");
    }
    Ok((cred.pid, cred.uid))
}

/// Is that process still running?
///
/// Signal 0 sends nothing and only asks the question. A pid of 0 or less is not
/// a process at all — `kill` would read it as a process group — so it is never
/// alive as far as this is concerned.
fn process_alive(pid: i32) -> bool {
    if pid <= 0i32 {
        return false;
    }
    // SAFETY: kill with signal 0 performs the permission check and returns.
    if unsafe { libc::kill(pid, 0i32) } == 0i32 {
        return true;
    }
    // It exists but belongs to someone else: not something we expect, but it is
    // still there.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// A token is only ever used to *apply* restrictions, so it needs to be
/// unguessable merely to keep two sandboxes from claiming each other's policies.
fn new_token() -> Result<String> {
    let mut bytes = [0u8; 16];
    // SAFETY: writing into a local buffer of exactly the length we pass.
    let read =
        unsafe { libc::getrandom(bytes.as_mut_ptr().cast::<libc::c_void>(), bytes.len(), 0u32) };
    if read != isize::try_from(bytes.len()).unwrap_or(-1isize) {
        bail!("cannot read random bytes for a token");
    }
    let mut token = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        write!(token, "{byte:02x}").context("formatting a token")?;
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(owner: i32, age: Duration) -> Pending {
        Pending {
            policies: Vec::new(),
            registered_at: Instant::now()
                .checked_sub(age)
                .expect("the test clock does not go that far back"),
            owner,
        }
    }

    /// A pid that cannot be running: `pid_max` is far below `i32::MAX`.
    const NO_SUCH_PROCESS: i32 = i32::MAX;

    /// The gap between registering and claiming holds a `--confirm` prompt, and
    /// a user thinking it over is not a reason to throw the policy away: the
    /// shim would then be refused and the command would die for no reason.
    #[test]
    fn a_registration_survives_while_its_caller_does() {
        let mut state = State::default();
        let mine = i32::try_from(std::process::id()).expect("pid fits in an i32");
        state
            .pending
            .insert("waiting".to_owned(), pending(mine, CLAIM_TIMEOUT * 4));
        state.reap();
        assert!(state.pending.contains_key("waiting"));
    }

    /// Once the caller is gone, nobody is coming for it.
    #[test]
    fn a_registration_nobody_is_coming_for_is_dropped() {
        let mut state = State::default();
        state.pending.insert(
            "abandoned".to_owned(),
            pending(NO_SUCH_PROCESS, CLAIM_TIMEOUT * 2),
        );
        state.pending.insert(
            "fresh".to_owned(),
            pending(NO_SUCH_PROCESS, Duration::from_secs(1)),
        );
        state.reap();
        assert!(!state.pending.contains_key("abandoned"));
        // Still inside the timeout: the caller may just have exec'd.
        assert!(state.pending.contains_key("fresh"));
    }

    /// A live-looking owner is not proof for ever: pids are recycled.
    #[test]
    fn nothing_pends_for_ever() {
        let mut state = State::default();
        let mine = i32::try_from(std::process::id()).expect("pid fits in an i32");
        state
            .pending
            .insert("ancient".to_owned(), pending(mine, PENDING_MAX_LIFETIME));
        state.reap();
        assert!(state.pending.is_empty());
    }

    #[test]
    fn a_process_group_is_not_a_process() {
        assert!(!process_alive(0));
        assert!(!process_alive(-1));
        assert!(!process_alive(NO_SUCH_PROCESS));
        let mine = i32::try_from(std::process::id()).expect("pid fits in an i32");
        assert!(process_alive(mine));
    }
}
