//! The session bus: hidden, filtered through `xdg-dbus-proxy`, or left alone.
//!
//! A command that can reach `systemd --user` can ask it to start a process in
//! a sibling cgroup, or to move one of its own there — Chromium does exactly
//! that, to give itself an `app-*.scope`. Out of the sandbox's cgroup nothing
//! bound to it applies any more: not the resource limits, not the eBPF
//! programs, not the IP filters. The manager is reached over its private
//! socket or the session bus, so every sandboxed command loses both unless its
//! profile says otherwise, and `ProtectControlGroups=` closes the third way
//! out, writing to `cgroup.procs` in the subtree the user manager owns.
//!
//! Losing the session bus breaks plenty of programs, so a profile can ask for a
//! filtered one instead. The filter is an allow-list — that is the only kind
//! `xdg-dbus-proxy` has — and the proxy runs as its own unit, an instance of
//! `scudo-dbus@.service`, pulled in by the sandbox and stopped by systemd once
//! nothing needs it. scudo itself is long gone by then: it becomes
//! `systemd-run`.

use std::{
    ffi::OsString,
    io::{Read as _, Write as _},
    os::{
        fd::AsRawFd as _,
        linux::net::SocketAddrExt as _,
        unix::{
            ffi::{OsStrExt as _, OsStringExt as _},
            fs::{DirBuilderExt as _, OpenOptionsExt as _},
            net::{SocketAddr, UnixDatagram},
            process::CommandExt as _,
        },
    },
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use tracing::warn;

/// What the command gets of the session bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Session {
    /// None of it, and no way to the service manager either.
    Deny,
    /// A proxy that only lets through the names it was told about.
    Filter,
    /// All of it, service manager included: the command can leave its cgroup.
    Allow,
}

/// What a `[profile.dbus]` table may say. The lists map one to one onto
/// `xdg-dbus-proxy`'s options of the same name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbusConfig {
    /// Unset means `filter` when any list says something, `deny` otherwise.
    pub session: Option<Session>,
    /// Names the command may see on the bus.
    #[serde(default)]
    pub see: Vec<String>,
    /// Names the command may call and get signals from.
    #[serde(default)]
    pub talk: Vec<String>,
    /// Names the command may own.
    #[serde(default)]
    pub own: Vec<String>,
    /// `NAME=RULE`: calls allowed on a name the command cannot talk to.
    #[serde(default)]
    pub call: Vec<String>,
    /// `NAME=RULE`: broadcasts received from a name the command cannot talk to.
    #[serde(default)]
    pub broadcast: Vec<String>,
    /// Have the proxy log every message it sees, to its unit's journal.
    pub log: Option<bool>,
}

impl DbusConfig {
    /// This table over `lower`: the lists accumulate, and the scalars are the
    /// ones said last.
    #[must_use]
    pub fn over(self, lower: Self) -> Self {
        DbusConfig {
            session: self.session.or(lower.session),
            see: union(lower.see, self.see),
            talk: union(lower.talk, self.talk),
            own: union(lower.own, self.own),
            call: union(lower.call, self.call),
            broadcast: union(lower.broadcast, self.broadcast),
            log: self.log.or(lower.log),
        }
    }

    /// What the command actually gets. Naming something to let through is
    /// asking for a filter: a list nobody could act on would be a silent no.
    #[must_use]
    pub fn session(&self) -> Session {
        self.session.unwrap_or_else(|| {
            if self.lists().any(|(_, list)| !list.is_empty()) {
                Session::Filter
            } else {
                Session::Deny
            }
        })
    }

    /// Reject what `xdg-dbus-proxy` would refuse only once the sandbox is
    /// already starting.
    pub fn validate(&self) -> Result<()> {
        for (option, list) in self.lists() {
            for entry in list {
                let name = if matches!(option, "call" | "broadcast") {
                    let Some((name, rule)) = entry.split_once('=') else {
                        bail!("dbus.{option}: '{entry}' is not NAME=RULE");
                    };
                    if rule.is_empty() {
                        bail!("dbus.{option}: '{entry}' has an empty rule");
                    }
                    name
                } else {
                    entry.as_str()
                };
                if !is_name_pattern(name) {
                    bail!(
                        "dbus.{option}: '{name}' is not a bus name \
                         (a wildcard is only allowed as a trailing '.*')"
                    );
                }
            }
        }
        Ok(())
    }

    /// Whether any rule lets the command reach `systemd --user`, the one name
    /// that can start a process outside the sandbox on its behalf. Seeing it is
    /// counted too: erring this way only means a nested scudo tries to start a
    /// sandbox of its own.
    fn reaches_manager(&self) -> bool {
        self.lists().any(|(option, list)| {
            list.iter().any(|entry| {
                let name = if matches!(option, "call" | "broadcast") {
                    entry
                        .split_once('=')
                        .map_or(entry.as_str(), |(name, _)| name)
                } else {
                    entry.as_str()
                };
                name_matches(name, MANAGER)
            })
        })
    }

    fn lists(&self) -> impl Iterator<Item = (&'static str, &Vec<String>)> {
        [
            ("see", &self.see),
            ("talk", &self.talk),
            ("own", &self.own),
            ("call", &self.call),
            ("broadcast", &self.broadcast),
        ]
        .into_iter()
    }
}

/// The service manager's name on the bus.
const MANAGER: &str = "org.freedesktop.systemd1";

/// Whether `pattern` lets `name` through: itself, or as a prefix ending in
/// `.*`, which also matches the prefix alone.
fn name_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix(".*") {
        Some(prefix) => {
            name == prefix
                || name
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('.'))
        }
        None => pattern == name,
    }
}

/// A well-known bus name, optionally ending in `.*` — the only wildcard
/// `xdg-dbus-proxy` takes, and the only names it takes at all.
fn is_name_pattern(pattern: &str) -> bool {
    let name = pattern.strip_suffix(".*").unwrap_or(pattern);
    let elements: Vec<&str> = name.split('.').collect();
    // A prefix stands for itself and every name under it, so one element is
    // enough there.
    let min = if name.len() < pattern.len() { 1 } else { 2 };
    name.len() <= 255
        && elements.len() >= min
        && elements.iter().all(|element| {
            element.chars().next().is_some_and(|c| !c.is_ascii_digit())
                && element
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
}

fn union(mut base: Vec<String>, extra: Vec<String>) -> Vec<String> {
    for entry in extra {
        if !base.contains(&entry) {
            base.push(entry);
        }
    }
    base
}

/// The template the proxy runs as, one instance per sandbox.
pub const PROXY_TEMPLATE: &str = "scudo-dbus@.service";
/// The binary behind the proxy.
pub const PROXY_BINARY: &str = "xdg-dbus-proxy";

/// What realising the bus policy for one run takes.
#[derive(Debug, Default)]
pub struct Bus {
    /// Unit properties for the sandbox.
    pub properties: Vec<(String, String)>,
    /// The proxy to hand its arguments to, once the run is certain.
    pub proxy: Option<Proxy>,
    /// Set when the bus came out stricter, or looser, than asked.
    pub warning: Option<String>,
    /// The name to give the sandbox's unit when nothing in it can reach the
    /// service manager, so that a scudo started inside knows it cannot start
    /// another sandbox; see [`crate::nested`].
    pub unit: Option<String>,
}

/// One proxy, for one sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    id: String,
    dir: PathBuf,
    args: Vec<String>,
}

impl Proxy {
    /// The unit that runs it.
    #[must_use]
    pub fn unit(&self) -> String {
        format!("scudo-dbus@{}.service", self.id)
    }

    /// The arguments it is started with, before the readiness pipe.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Leave the proxy's arguments where its unit will look for them.
    ///
    /// Only done once the command is certain to run: the unit is started by
    /// systemd as part of the sandbox, and a file left behind by a declined
    /// prompt would be read by nobody.
    pub fn write_args(&self) -> Result<()> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        let path = args_path(&self.dir, &self.id);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        file.write_all(&encode_args(&self.args))
            .with_context(|| format!("writing {}", path.display()))
    }
}

/// Decide what the session bus looks like from inside the sandbox.
///
/// `id` names the sandbox; a fresh one is made up when it is `None`. A broker
/// picks it itself, so that it knows which unit to stop; see
/// [`crate::broker`].
#[must_use]
pub fn prepare(config: &DbusConfig, id: Option<&str>) -> Bus {
    let runtime_dir = runtime_dir();
    let upstream = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
    // SAFETY: getuid always succeeds and touches no memory.
    let uid = unsafe { libc::getuid() };
    prepare_with(
        config,
        &runtime_dir,
        upstream.as_deref(),
        proxy_availability(),
        &id.map_or_else(new_id, str::to_owned),
        uid,
    )
}

/// The body of [`prepare`], with everything it would look up passed in.
fn prepare_with(
    config: &DbusConfig,
    runtime_dir: &str,
    upstream: Option<&str>,
    available: Result<(), String>,
    id: &str,
    uid: u32,
) -> Bus {
    let mut bus = Bus::default();
    let session = config.session();
    if session == Session::Allow {
        return bus;
    }
    // A bus on an abstract socket stays reachable whatever is mounted, and a
    // filter that lets the manager through leads out all the same. Left
    // unmarked, a scudo started inside tries to start a sandbox of its own,
    // which is what it always did.
    let abstract_bus = upstream.is_some_and(|address| address.contains("abstract="));
    let sealed = !abstract_bus && (session == Session::Deny || !config.reaches_manager());
    if sealed {
        bus.unit = Some(crate::nested::sealed_unit(id));
    }

    let mut push = |key: &str, value: String| bus.properties.push((key.to_owned(), value));
    if sealed {
        // The unit's name is out of sight in a cgroup namespace of its own
        // (`ProtectControlGroups = "private"`); a mount is visible either way.
        push(
            "BindReadOnlyPaths",
            format!("-/dev/null:{}", crate::nested::marker_path(uid).display()),
        );
    }
    push("InaccessiblePaths", format!("-{runtime_dir}/systemd"));
    push("ProtectControlGroups", "yes".to_owned());

    if session == Session::Deny {
        push("InaccessiblePaths", format!("-{runtime_dir}/bus"));
        return bus;
    }
    if let Err(reason) = available {
        push("InaccessiblePaths", format!("-{runtime_dir}/bus"));
        bus.warning = Some(format!(
            "cannot filter the session bus ({reason}); the command gets none"
        ));
        return bus;
    }

    let dir = proxy_dir(runtime_dir);
    let socket = dir.join(format!("{id}.sock"));
    let proxy = Proxy {
        id: id.to_owned(),
        dir: dir.clone(),
        args: proxy_args(
            config,
            upstream.unwrap_or(&format!("unix:path={runtime_dir}/bus")),
            &socket,
        ),
    };
    let unit = proxy.unit();
    // Wants, not Requires: a dependency that failed makes systemd-run report
    // success without having run anything. The command is kept from running
    // without its proxy all the same — the bind below has no `-`, so a socket
    // that never appeared fails the unit, and says so.
    push("Wants", unit.clone());
    push("After", unit);
    // Where every client looks, so that nothing has to be told: the proxy's
    // socket takes the bus's place, and the directory holding every sandbox's
    // proxy goes away, so that none of them can borrow another one's filter.
    push(
        "BindPaths",
        format!("{}:{runtime_dir}/bus", socket.display()),
    );
    push("InaccessiblePaths", dir.display().to_string());
    push(
        "Environment",
        format!("DBUS_SESSION_BUS_ADDRESS=unix:path={runtime_dir}/bus"),
    );

    if abstract_bus {
        bus.warning = Some(
            "the session bus is on an abstract socket, which no mount can hide: \
             the command can still reach it unless the network is taken away"
                .to_owned(),
        );
    }
    bus.proxy = Some(proxy);
    bus
}

/// `xdg-dbus-proxy`'s command line, readiness pipe aside.
fn proxy_args(config: &DbusConfig, upstream: &str, socket: &Path) -> Vec<String> {
    let mut args = vec![
        upstream.to_owned(),
        socket.display().to_string(),
        "--filter".to_owned(),
    ];
    if config.log == Some(true) {
        args.push("--log".to_owned());
    }
    for (option, list) in config.lists() {
        args.extend(list.iter().map(|entry| format!("--{option}={entry}")));
    }
    args
}

/// Arguments as the proxy unit reads them back: NUL-terminated, since a bus
/// rule may hold anything else.
fn encode_args(args: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for arg in args {
        out.extend_from_slice(arg.as_bytes());
        out.push(0);
    }
    out
}

fn decode_args(raw: &[u8]) -> Vec<OsString> {
    raw.split(|b| *b == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| OsString::from_vec(arg.to_vec()))
        .collect()
}

/// `XDG_RUNTIME_DIR`, or where systemd puts it when that is not set.
#[must_use]
pub fn runtime_dir() -> String {
    std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| {
        // SAFETY: getuid always succeeds and touches no memory.
        let uid = unsafe { libc::getuid() };
        format!("/run/user/{uid}")
    })
}

fn proxy_dir(runtime_dir: &str) -> PathBuf {
    Path::new(runtime_dir).join("scudo/dbus")
}

fn args_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.args"))
}

/// Unique enough among one user's sandboxes, and a valid unit instance name.
#[must_use]
pub fn new_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{}-{nanos:x}", std::process::id())
}

/// Whether a proxy could be started at all: the binary has to be there, and so
/// does the unit that runs it.
fn proxy_availability() -> Result<(), String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    if !std::env::split_paths(&path).any(|dir| dir.join(PROXY_BINARY).is_file()) {
        return Err(format!("{PROXY_BINARY} is not installed"));
    }
    if !unit_dirs()
        .iter()
        .any(|dir| dir.join(PROXY_TEMPLATE).is_file())
    {
        return Err(format!("{PROXY_TEMPLATE} is not installed"));
    }
    Ok(())
}

/// Where the user's service manager looks for unit files.
fn unit_dirs() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".config")));
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".local/share")));
    let mut dirs: Vec<PathBuf> = config
        .into_iter()
        .chain(data)
        .map(|d| d.join("systemd/user"))
        .collect();
    dirs.extend(
        [
            "/etc/systemd/user",
            "/run/systemd/user",
            "/usr/local/lib/systemd/user",
            "/usr/lib/systemd/user",
        ]
        .map(PathBuf::from),
    );
    dirs
}

/// Run as the proxy unit: start `binary` with the arguments left for `id`, tell
/// systemd once it is listening, and live as long as it does.
///
/// The readiness pipe doubles as the proxy's lifeline: it stops when the other
/// end closes, so it cannot outlive this process however that one ends.
pub fn serve(id: &str, binary: &Path) -> Result<i32> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail!("invalid proxy id '{id}'");
    }
    let path = args_path(&proxy_dir(&runtime_dir()), id);
    let raw = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    // Read once: nothing else is meant to learn the filter from it.
    if let Err(err) = std::fs::remove_file(&path) {
        warn!("cannot remove {}: {err}", path.display());
    }

    let (mut ready, lifeline) = std::io::pipe().context("creating the readiness pipe")?;
    let fd = lifeline.as_raw_fd();
    let mut cmd = Command::new(binary);
    cmd.arg(format!("--fd={fd}")).args(decode_args(&raw));
    // The proxy is handed the write end; it must survive the exec.
    let inherit = move || -> std::io::Result<()> {
        // SAFETY: both calls take the fd and a flag word; nothing of ours is
        // read through a pointer, and fcntl is async-signal-safe.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0i32 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: as above.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0i32 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: the closure only makes async-signal-safe calls, on a descriptor
    // this process owns.
    let cmd = unsafe { cmd.pre_exec(inherit) };
    let mut child = cmd
        .spawn()
        .with_context(|| format!("starting {}", binary.display()))?;
    drop(lifeline);

    let mut byte = [0u8; 1];
    if ready.read(&mut byte).unwrap_or(0) == 0 {
        let status = child.wait()?;
        bail!("{} exited before it was ready ({status})", binary.display());
    }
    notify("READY=1").context("telling systemd the proxy is ready")?;

    let status = child.wait()?;
    drop(ready);
    Ok(status.code().unwrap_or(1))
}

/// `sd_notify`, for the one message this needs.
fn notify(state: &str) -> Result<()> {
    let Some(target) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket = UnixDatagram::unbound()?;
    let bytes = target.as_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        let addr = SocketAddr::from_abstract_name(name)?;
        socket.send_to_addr(state.as_bytes(), &addr)?;
    } else {
        socket.send_to(state.as_bytes(), target)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(src: &str) -> DbusConfig {
        toml::from_str(src).unwrap()
    }

    fn bus(src: &str) -> Bus {
        prepare_with(&config(src), "/run/user/1", None, Ok(()), "7-a", 1)
    }

    fn has(bus: &Bus, key: &str, value: &str) -> bool {
        bus.properties.iter().any(|(k, v)| k == key && v == value)
    }

    #[test]
    fn the_bus_and_the_manager_are_gone_by_default() {
        let b = bus("");
        assert!(has(&b, "InaccessiblePaths", "-/run/user/1/bus"));
        assert!(has(&b, "InaccessiblePaths", "-/run/user/1/systemd"));
        assert!(has(&b, "ProtectControlGroups", "yes"));
        assert!(b.proxy.is_none());
        assert!(b.warning.is_none());
    }

    #[test]
    fn allow_takes_nothing_away() {
        let b = bus(r#"session = "allow""#);
        assert!(b.properties.is_empty());
        assert!(b.proxy.is_none());
    }

    #[test]
    fn naming_something_asks_for_a_filter() {
        assert_eq!(config(r#"talk = ["a.b"]"#).session(), Session::Filter);
        assert_eq!(config("").session(), Session::Deny);
        assert_eq!(
            config(
                r#"session = "deny"
talk = ["a.b"]"#
            )
            .session(),
            Session::Deny
        );
    }

    #[test]
    fn a_filter_puts_the_proxy_in_the_bus_place() {
        let b = bus(r#"talk = ["org.freedesktop.Notifications"]"#);
        let proxy = b.proxy.as_ref().unwrap();
        assert_eq!(proxy.unit(), "scudo-dbus@7-a.service");
        assert!(has(&b, "Wants", "scudo-dbus@7-a.service"));
        assert!(has(&b, "After", "scudo-dbus@7-a.service"));
        assert!(has(
            &b,
            "BindPaths",
            "/run/user/1/scudo/dbus/7-a.sock:/run/user/1/bus"
        ));
        assert!(has(&b, "InaccessiblePaths", "/run/user/1/scudo/dbus"));
        assert!(has(
            &b,
            "Environment",
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1/bus"
        ));
        assert!(has(&b, "InaccessiblePaths", "-/run/user/1/systemd"));
        assert!(!has(&b, "InaccessiblePaths", "-/run/user/1/bus"));
    }

    #[test]
    fn the_proxy_is_told_every_list() {
        let b = bus(r#"talk = ["a.b"]
see = ["c.*"]
own = ["d.e"]
call = ["f.g=*"]
broadcast = ["h.i=@/x/*"]
log = true"#);
        assert_eq!(
            b.proxy.unwrap().args(),
            [
                "unix:path=/run/user/1/bus",
                "/run/user/1/scudo/dbus/7-a.sock",
                "--filter",
                "--log",
                "--see=c.*",
                "--talk=a.b",
                "--own=d.e",
                "--call=f.g=*",
                "--broadcast=h.i=@/x/*",
            ]
        );
    }

    #[test]
    fn the_upstream_address_is_the_one_scudo_was_given() {
        let b = prepare_with(
            &config(r#"talk = ["a.b"]"#),
            "/run/user/1",
            Some("unix:path=/elsewhere"),
            Ok(()),
            "7-a",
            1,
        );
        assert_eq!(
            b.proxy.unwrap().args().first().map(String::as_str),
            Some("unix:path=/elsewhere")
        );
    }

    #[test]
    fn an_abstract_bus_is_warned_about() {
        let b = prepare_with(
            &config(r#"talk = ["a.b"]"#),
            "/run/user/1",
            Some("unix:abstract=/tmp/dbus-x"),
            Ok(()),
            "7-a",
            1,
        );
        assert!(b.warning.unwrap().contains("abstract"));
    }

    #[test]
    fn without_a_proxy_the_bus_is_hidden_instead() {
        let b = prepare_with(
            &config(r#"talk = ["a.b"]"#),
            "/run/user/1",
            None,
            Err("xdg-dbus-proxy is not installed".to_owned()),
            "7-a",
            1,
        );
        assert!(b.proxy.is_none());
        assert!(has(&b, "InaccessiblePaths", "-/run/user/1/bus"));
        assert!(b.warning.unwrap().contains("not installed"));
    }

    #[test]
    fn lists_accumulate_and_scalars_are_said_last() {
        let base = config(
            r#"session = "deny"
talk = ["a.b"]
log = true"#,
        );
        let top = config(
            r#"session = "filter"
talk = ["a.b", "c.d"]"#,
        );
        let merged = top.over(base);
        assert_eq!(merged.session, Some(Session::Filter));
        assert_eq!(merged.talk, ["a.b", "c.d"]);
        assert_eq!(merged.log, Some(true));
    }

    #[test]
    fn rules_must_name_a_rule() {
        assert!(config(r#"call = ["a.b"]"#).validate().is_err());
        assert!(config(r#"call = ["a.b="]"#).validate().is_err());
        assert!(config(r#"talk = ["a b"]"#).validate().is_err());
        assert!(
            config(r#"own = ["org.kde.StatusNotifierItem-*"]"#)
                .validate()
                .is_err()
        );
        assert!(config(r#"talk = ["single"]"#).validate().is_err());
        assert!(config(r#"talk = ["org.9x"]"#).validate().is_err());
        config(r#"talk = ["org.freedesktop.portal.*", "org.a-b_c.d"]"#)
            .validate()
            .unwrap();
        config(r#"call = ["a.b=*"]"#).validate().unwrap();
    }

    #[test]
    fn unknown_keys_are_rejected() {
        toml::from_str::<DbusConfig>(r#"tlak = ["a.b"]"#).unwrap_err();
    }

    #[test]
    fn arguments_survive_the_round_trip() {
        let args = ["a".to_owned(), "--call=x=@/p/*".to_owned()];
        let decoded = decode_args(&encode_args(&args));
        assert_eq!(
            decoded,
            [OsString::from("a"), OsString::from("--call=x=@/p/*")]
        );
    }

    const MARKER: &str = "-/dev/null:/run/user/1/scudo/sealed";

    /// Named after a sealed sandbox, and carrying the mount that says so
    /// inside a cgroup namespace of its own.
    fn sealed(bus: &Bus) -> bool {
        bus.unit.as_deref() == Some("scudo-sealed-7-a.service")
            && has(bus, "BindReadOnlyPaths", MARKER)
    }

    /// Neither of the two.
    fn unmarked(bus: &Bus) -> bool {
        bus.unit.is_none()
            && !bus
                .properties
                .iter()
                .any(|(_, value)| value.contains("scudo/sealed"))
    }

    /// Each shape the bus can take adds a different set of properties, and
    /// every one of them has to be classified for a profile writing the same
    /// key not to lose it.
    #[test]
    fn every_bus_property_is_classified() {
        let buses = [
            bus(""),
            bus(r#"talk = ["a.b"]"#),
            bus(r#"talk = ["org.freedesktop.systemd1"]"#),
            prepare_with(
                &config(r#"talk = ["a.b"]"#),
                "/run/user/1",
                None,
                Err("missing".to_owned()),
                "7-a",
                1,
            ),
        ];
        for (key, _) in buses.iter().flat_map(|b| &b.properties) {
            crate::policy::tests::assert_classified(key);
        }
    }

    #[test]
    fn a_closed_bus_marks_the_sandbox_sealed() {
        assert!(sealed(&bus("")));
        assert!(sealed(&bus(r#"talk = ["org.freedesktop.Notifications"]"#)));
        // Asked for a filter and got no bus at all.
        let b = prepare_with(
            &config(r#"talk = ["org.freedesktop.systemd1"]"#),
            "/run/user/1",
            None,
            Err("missing".to_owned()),
            "7-a",
            1,
        );
        assert!(unmarked(&b), "a rule naming the manager is never sealed");
    }

    #[test]
    fn a_way_to_the_manager_leaves_the_sandbox_unmarked() {
        assert!(unmarked(&bus(r#"session = "allow""#)));
        for src in [
            r#"talk = ["org.freedesktop.systemd1"]"#,
            r#"talk = ["org.freedesktop.*"]"#,
            r#"talk = ["org.*"]"#,
            r#"see = ["org.freedesktop.systemd1.*"]"#,
            r#"own = ["org.freedesktop.systemd1"]"#,
            r#"call = ["org.freedesktop.systemd1=*"]"#,
            r#"broadcast = ["org.freedesktop.*=*"]"#,
        ] {
            assert!(unmarked(&bus(src)), "{src}");
        }
        // A lookalike is not the manager.
        assert!(sealed(&bus(r#"talk = ["org.freedesktop.systemd10"]"#)));
        assert!(sealed(&bus(r#"talk = ["org.freedesktop.systemd1x.*"]"#)));
    }

    #[test]
    fn an_abstract_bus_is_never_sealed() {
        for src in ["", r#"talk = ["a.b"]"#] {
            let b = prepare_with(
                &config(src),
                "/run/user/1",
                Some("unix:abstract=/tmp/dbus-x"),
                Ok(()),
                "7-a",
                1,
            );
            assert!(unmarked(&b), "{src}");
        }
    }
}
