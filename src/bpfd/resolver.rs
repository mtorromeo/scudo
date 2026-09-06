//! A per-sandbox DNS resolver that answers only for the names a policy allows.
//!
//! This is what lets a policy be written in names. The eBPF programs redirect
//! every query to the port this resolver listens on; it refuses names no rule
//! mentions, forwards the rest, and writes the addresses it hands back into the
//! destination tries, so the connection that follows is permitted without anyone
//! having had to guess an address in advance.
//!
//! It also takes them out again. Expiry is enforced by removal and by nothing
//! else — the programs carry no expiry check — for the reason `bpfd::trie`
//! spells out.
//!
//! Answers are matched against the *question*, not the CNAME chain: a rule for
//! `api.github.com` covers whatever addresses that name ends up resolving to.

use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::{
    collections::{HashMap, HashSet},
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream, UdpSocket},
    os::fd::AsRawFd as _,
    sync::{Arc, Mutex},
};

use anyhow::{Context as _, Result, bail};
use aya::Ebpf;
use glob::Pattern;

use crate::{
    bpfd::{
        dns,
        events::Bus,
        protocol::Notification,
        trie::{self, DestKey},
    },
    policy::network::Action,
};

/// Largest DNS message we will handle. Anything bigger is a sign of something
/// we do not want to be parsing anyway.
const MAX_MESSAGE: usize = 4096;

/// How long to wait for the upstream nameserver.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the poll loop checks whether it should stop.
const POLL_INTERVAL_MS: i32 = 500;

/// A record's TTL is clamped into this range before it becomes an expiry.
///
/// The floor matters: a zero TTL would expire the address before the program
/// that asked for it managed to connect.
const MIN_TTL: u32 = 30;
const MAX_TTL: u32 = 3600;

/// Which names a rule covers, and which trie their addresses belong in.
pub struct HostRule {
    pub pattern: Pattern,
    pub action: Action,
}

/// Everything the resolver needs to answer a query.
pub struct Config {
    /// The policy's host rules. Order is not meaningful: a name matched by both
    /// a deny and an allow rule lands in both tries, and the deny wins there.
    pub hosts: Vec<HostRule>,
    /// The prefixes the config declared outright.
    ///
    /// A learnt address that happens to equal one of these shares its key, so
    /// letting a TTL expire it would delete the rule the user wrote — on the
    /// deny side, silently opening a hole. The sweep skips anything in here.
    pub statics: HashSet<(Action, DestKey)>,
    /// Whether to forward names no rule mentions; see
    /// `NetworkPolicy::resolves_unknown_names`.
    pub resolve_unknown: bool,
    /// Nameservers to forward to.
    pub upstreams: Vec<SocketAddr>,
}

impl Config {
    /// Did the config declare this prefix outright?
    ///
    /// A learnt address that lands on a declared key must never be expired: the
    /// removal would delete the rule the user wrote, and on the deny side that
    /// opens a hole nobody asked for.
    fn is_static(&self, action: Action, key: DestKey) -> bool {
        self.statics.contains(&(action, key))
    }

    /// May this name be looked up?
    ///
    /// Naming a host in a rule is what makes it resolvable — allowing the
    /// connection but refusing the lookup would be pointless — and that holds
    /// for a deny rule too: its addresses have to be learnt to be denied.
    fn may_resolve(&self, name: &str) -> bool {
        self.resolve_unknown || self.hosts.iter().any(|h| h.pattern.matches(name))
    }
}

/// The sockets a resolver listens on. Bound before the eBPF programs are loaded,
/// because the port has to be compiled into them.
pub struct Sockets {
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
    /// Port for IPv4 queries, and for IPv6 queries. Either can be 0, meaning
    /// that family has no resolver and its queries are left alone.
    pub port_v4: u16,
    pub port_v6: u16,
}

impl Sockets {
    /// Bind loopback sockets for each family that has one.
    ///
    /// Each family gets its own port so that binding one cannot be held up by
    /// the other; the programs know both. A family that cannot be bound at all —
    /// `::1` on a machine booted with `ipv6.disable=1` — is left at port 0,
    /// which the programs read as "no resolver here" and judge those queries by
    /// the rules like any other traffic. Only losing *both* is fatal: then
    /// nothing would be left to answer a name.
    pub fn bind() -> Result<Self> {
        let mut sockets = Sockets {
            udp: Vec::new(),
            tcp: Vec::new(),
            port_v4: 0,
            port_v6: 0,
        };
        let v4 = sockets.add(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let v6 = sockets.add(IpAddr::V6(Ipv6Addr::LOCALHOST));

        match (v4, v6) {
            (Err(v4_err), Err(v6_err)) => Err(anyhow::anyhow!(
                "no loopback socket left for the resolver: {v4_err:#}; {v6_err:#}"
            )),
            (v4, v6) => {
                for (family, result) in [("127.0.0.1", v4), ("::1", v6)] {
                    if let Err(err) = result {
                        eprintln!(
                            "scudo-bpfd: resolver: no {family} socket ({err:#}); \
                             names will not resolve over that family"
                        );
                    }
                }
                Ok(sockets)
            }
        }
    }

    /// Bind one family and remember the port it landed on.
    fn add(&mut self, addr: IpAddr) -> Result<()> {
        let (udp, tcp) =
            bind_pair(addr).with_context(|| format!("binding the resolver to {addr}"))?;
        let port = udp.local_addr().context("reading the bound port")?.port();
        if addr.is_ipv4() {
            self.port_v4 = port;
        } else {
            self.port_v6 = port;
        }
        self.udp.push(udp);
        self.tcp.push(tcp);
        Ok(())
    }
}

/// Bind a UDP socket and a TCP listener on the same address and port.
///
/// The port is chosen by binding UDP first and asking for it back; on the rare
/// occasion TCP cannot have the same one, try again with another.
fn bind_pair(addr: IpAddr) -> Result<(UdpSocket, TcpListener)> {
    const ATTEMPTS: usize = 16;
    let mut last: Option<anyhow::Error> = None;
    for _ in 0..ATTEMPTS {
        let udp = UdpSocket::bind(SocketAddr::new(addr, 0)).context("binding UDP")?;
        let port = udp.local_addr().context("reading the bound port")?.port();
        match TcpListener::bind(SocketAddr::new(addr, port)) {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(err) => last = Some(anyhow::Error::from(err)),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no free port for the resolver")))
}

/// Remember that a learnt key is good until `expiry`.
///
/// Two names can resolve to one address and so share a single key. The later
/// deadline wins: expiring on the earlier one would take away a grant the other
/// name is still vouching for.
fn remember(learnt: &mut HashMap<(Action, DestKey), u64>, key: (Action, DestKey), expiry: u64) {
    let deadline = learnt.entry(key).or_insert(expiry);
    *deadline = (*deadline).max(expiry);
}

/// A running resolver.
pub struct Resolver {
    sockets: Sockets,
    config: Config,
    bpf: Arc<Mutex<Ebpf>>,
    /// Where refused lookups go. A name the rules do not mention is the first
    /// thing a too-tight policy turns away, and long before any address is
    /// reached — so it belongs on the same stream as the rest.
    bus: Arc<Bus>,
    /// Every address this resolver put in a trie, and when it stops counting.
    learnt: Mutex<HashMap<(Action, DestKey), u64>>,
}

impl Resolver {
    #[must_use]
    pub fn new(sockets: Sockets, config: Config, bpf: Arc<Mutex<Ebpf>>, bus: Arc<Bus>) -> Self {
        Resolver {
            sockets,
            config,
            bpf,
            bus,
            learnt: Mutex::new(HashMap::new()),
        }
    }

    /// Say that a name was not looked up, and why.
    fn refuse(&self, query: &[u8], name: &str, reason: impl Into<String>) -> Vec<u8> {
        self.bus.publish(Notification::DnsRefused {
            name: name.to_owned(),
            reason: reason.into(),
        });
        dns::refuse(query)
    }

    /// Serve queries until `stop` is set.
    pub fn run(&self, stop: &AtomicBool) {
        let mut fds: Vec<libc::pollfd> = Vec::new();
        for socket in &self.sockets.udp {
            fds.push(pollfd(socket.as_raw_fd()));
        }
        for listener in &self.sockets.tcp {
            fds.push(pollfd(listener.as_raw_fd()));
        }

        while !stop.load(Ordering::Relaxed) {
            // Every turn, whether or not anything arrived: this is what makes a
            // TTL run out, so it must not depend on traffic.
            self.sweep();
            // SAFETY: fds is a live, correctly sized array of pollfd.
            let ready = unsafe {
                libc::poll(
                    fds.as_mut_ptr(),
                    fds.len() as libc::nfds_t,
                    POLL_INTERVAL_MS,
                )
            };
            if ready <= 0i32 {
                continue;
            }
            // The poll array is the UDP sockets followed by the TCP listeners.
            let udp_count = self.sockets.udp.len();
            for (index, entry) in fds.iter().enumerate() {
                if entry.revents & libc::POLLIN == 0 {
                    continue;
                }
                match self.sockets.udp.get(index) {
                    Some(socket) => self.serve_udp(socket),
                    None => {
                        if let Some(listener) =
                            self.sockets.tcp.get(index.saturating_sub(udp_count))
                        {
                            self.serve_tcp(listener);
                        }
                    }
                }
            }
        }
    }

    fn serve_udp(&self, socket: &UdpSocket) {
        let mut buf = [0u8; MAX_MESSAGE];
        let Ok((len, peer)) = socket.recv_from(&mut buf) else {
            return;
        };
        let Some(query) = buf.get(..len) else {
            return;
        };
        let response = self.answer(query);
        drop(socket.send_to(&response, peer));
    }

    fn serve_tcp(&self, listener: &TcpListener) {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        drop(stream.set_read_timeout(Some(UPSTREAM_TIMEOUT)));
        drop(stream.set_write_timeout(Some(UPSTREAM_TIMEOUT)));
        if let Err(err) = self.serve_tcp_stream(&mut stream) {
            eprintln!("scudo-bpfd: resolver: {err:#}");
        }
    }

    fn serve_tcp_stream(&self, stream: &mut TcpStream) -> Result<()> {
        let query = read_tcp_message(stream)?;
        let response = self.answer(&query);
        write_tcp_message(stream, &response)
    }

    /// Decide, forward, learn.
    fn answer(&self, query: &[u8]) -> Vec<u8> {
        // A message we cannot parse is one we will not forward. There is no
        // name to report either, which is the one refusal that stays silent.
        let Ok(question) = dns::question(query) else {
            return dns::refuse(query);
        };

        if !self.config.may_resolve(&question.name) {
            return self.refuse(query, &question.name, "no rule names it");
        }

        match self.forward(query) {
            Ok(response) => {
                if let Err(err) = self.learn(&question.name, &response) {
                    // Failing to record the addresses would leave the caller
                    // with an answer it cannot use, which is worse than saying
                    // no: refuse instead of handing out a dead lead.
                    eprintln!("scudo-bpfd: resolver: {err:#}");
                    self.refuse(query, &question.name, format!("{err:#}"))
                } else {
                    response
                }
            }
            Err(err) => {
                eprintln!("scudo-bpfd: resolver: {err:#}");
                self.refuse(query, &question.name, format!("{err:#}"))
            }
        }
    }

    /// Send the query upstream, retrying over TCP if the answer did not fit.
    fn forward(&self, query: &[u8]) -> Result<Vec<u8>> {
        let mut last: Option<anyhow::Error> = None;
        for upstream in &self.config.upstreams {
            match Self::forward_udp(query, *upstream) {
                Ok(response) if dns::is_truncated(&response) => {
                    match Self::forward_tcp(query, *upstream) {
                        Ok(full) => return Ok(full),
                        // The truncated answer is still better than nothing.
                        Err(_) => return Ok(response),
                    }
                }
                Ok(response) => return Ok(response),
                Err(err) => last = Some(err),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("no upstream nameserver is configured")))
    }

    fn forward_udp(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
        let bind: SocketAddr = if upstream.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind).context("binding an upstream socket")?;
        socket
            .set_read_timeout(Some(UPSTREAM_TIMEOUT))
            .context("setting the upstream timeout")?;
        socket
            .send_to(query, upstream)
            .with_context(|| format!("sending to {upstream}"))?;

        let mut buf = [0u8; MAX_MESSAGE];
        loop {
            let (len, from) = socket
                .recv_from(&mut buf)
                .with_context(|| format!("waiting for {upstream}"))?;
            // Ignore anything that did not come from the server we asked.
            if from != upstream {
                continue;
            }
            let response = buf
                .get(..len)
                .context("short read from the upstream nameserver")?;
            // The socket is unconnected, so the address above is only as good as
            // the network's word for it. What the answer says about itself has
            // to match the query too — its addresses are about to become policy.
            if !dns::is_answer_to(query, response) {
                continue;
            }
            return Ok(response.to_vec());
        }
    }

    fn forward_tcp(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
        let mut stream = TcpStream::connect_timeout(&upstream, UPSTREAM_TIMEOUT)
            .with_context(|| format!("connecting to {upstream}"))?;
        stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
        stream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
        write_tcp_message(&mut stream, query)?;
        read_tcp_message(&mut stream)
    }

    /// Write the addresses from `response` into the dynamic map, under every
    /// host rule whose pattern covers `name`.
    fn learn(&self, name: &str, response: &[u8]) -> Result<()> {
        // A reply we cannot parse teaches us nothing, but the caller may still
        // make sense of it.
        let Ok(answers) = dns::answers(response) else {
            return Ok(());
        };
        if answers.is_empty() {
            return Ok(());
        }

        // At most one entry per verdict: which trie an address goes into
        // depends on the verdicts of the rules that named it, not on how many
        // of them there were.
        let mut actions: Vec<Action> = Vec::new();
        for host in &self.config.hosts {
            if host.pattern.matches(name) && !actions.contains(&host.action) {
                actions.push(host.action);
            }
        }
        if actions.is_empty() {
            // The name was resolvable but no rule covers it: the lookup is
            // allowed, reaching the address is not.
            return Ok(());
        }

        let now = monotonic_nanos()?;
        let mut bpf = self
            .bpf
            .lock()
            .map_err(|err| anyhow::anyhow!("eBPF state is poisoned: {err}"))?;
        let mut learnt = self
            .learnt
            .lock()
            .map_err(|err| anyhow::anyhow!("learnt addresses are poisoned: {err}"))?;

        for answer in answers {
            let ttl = u64::from(answer.ttl.clamp(MIN_TTL, MAX_TTL));
            let expiry = now.saturating_add(ttl.saturating_mul(1_000_000_000));
            let key = DestKey::address(answer.addr);
            for &action in &actions {
                if self.config.is_static(action, key) {
                    continue;
                }
                trie::insert(&mut bpf, action, key)
                    .with_context(|| format!("recording {}", answer.addr))?;
                remember(&mut learnt, (action, key), expiry);
            }
        }
        Ok(())
    }

    /// Take out every address whose TTL has run out.
    ///
    ///
    /// A sweep that runs late merely leaves an entry doing what it was already
    /// doing for another moment — permitting in the allow trie, denying in the
    /// deny trie — so lateness errs on the safe side either way.
    fn sweep(&self) {
        let Ok(now) = monotonic_nanos() else {
            return;
        };
        let (Ok(mut bpf), Ok(mut learnt)) = (self.bpf.lock(), self.learnt.lock()) else {
            return;
        };
        learnt.retain(|&(action, key), deadline| {
            if *deadline > now {
                return true;
            }
            // A key that is already gone is not a problem: the point is that it
            // is not there afterwards.
            _ = trie::remove(&mut bpf, action, key);
            false
        });
    }
}

fn pollfd(fd: libc::c_int) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// DNS over TCP prefixes each message with its length.
fn read_tcp_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).context("reading a length")?;
    let len = usize::from(u16::from_be_bytes(len));
    if len > MAX_MESSAGE {
        bail!("DNS message of {len} bytes is too large");
    }
    let mut message = vec![0u8; len];
    stream
        .read_exact(&mut message)
        .context("reading a message")?;
    Ok(message)
}

fn write_tcp_message(stream: &mut TcpStream, message: &[u8]) -> Result<()> {
    let len = u16::try_from(message.len()).context("message is too long for DNS over TCP")?;
    stream
        .write_all(&len.to_be_bytes())
        .context("writing a length")?;
    stream.write_all(message).context("writing a message")?;
    stream.flush().context("flushing")
}

/// The same clock `bpf_ktime_get_ns` reads, so the expiry we store means what
/// the program thinks it means.
fn monotonic_nanos() -> Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: writing into a local timespec.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
    if rc != 0i32 {
        return Err(std::io::Error::last_os_error()).context("reading the monotonic clock");
    }
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(ts.tv_nsec).unwrap_or(0);
    Ok(secs.saturating_mul(1_000_000_000).saturating_add(nanos))
}

/// Read the system's nameservers.
///
/// These are the daemon's own, not the sandbox's: the sandbox never gets to talk
/// to a nameserver directly.
#[must_use]
pub fn system_upstreams() -> Vec<SocketAddr> {
    const RESOLV_CONF: &str = "/etc/resolv.conf";
    let mut servers = Vec::new();
    if let Ok(content) = std::fs::read_to_string(RESOLV_CONF) {
        for line in content.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver")
                && let Ok(addr) = rest.trim().parse::<IpAddr>()
            {
                servers.push(SocketAddr::new(addr, 53));
            }
        }
    }
    if servers.is_empty() {
        // What systemd-resolved listens on; a reasonable guess when
        // resolv.conf says nothing useful.
        servers.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)),
            53,
        ));
    }
    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(resolve_unknown: bool, hosts: &[&str]) -> Config {
        Config {
            resolve_unknown,
            hosts: hosts
                .iter()
                .map(|p| HostRule {
                    pattern: Pattern::new(p).unwrap(),
                    action: Action::Allow,
                })
                .collect(),
            statics: HashSet::new(),
            upstreams: vec![],
        }
    }

    fn key(addr: &str) -> DestKey {
        DestKey::address(addr.parse().unwrap())
    }

    /// A second name vouching for the same address pushes the deadline out; it
    /// must never pull it in, or the first TTL to run out would revoke a grant
    /// the second name is still making.
    #[test]
    fn a_renewal_keeps_the_later_deadline() {
        let mut learnt = HashMap::new();
        let entry = (Action::Allow, key("1.1.1.1"));
        remember(&mut learnt, entry, 100);
        remember(&mut learnt, entry, 500);
        assert_eq!(learnt.get(&entry), Some(&500));
        // An earlier deadline is not allowed to win.
        remember(&mut learnt, entry, 200);
        assert_eq!(learnt.get(&entry), Some(&500));
    }

    /// A learnt address that lands on a prefix the config declared is left
    /// alone: expiring it would delete the user's own rule.
    #[test]
    fn a_declared_prefix_is_never_expired() {
        let mut config = config(false, &["example.com"]);
        let declared = key("1.1.1.1");
        config.statics.insert((Action::Deny, declared));

        assert!(config.is_static(Action::Deny, declared));
        // Only that prefix, and only in the trie it was declared in.
        assert!(!config.is_static(Action::Allow, declared));
        assert!(!config.is_static(Action::Deny, key("1.1.1.2")));
    }

    /// The rules are the allowlist: a name one of them mentions resolves, and
    /// nothing else does.
    #[test]
    fn the_rules_decide() {
        let config = config(false, &["*.crates.io", "github.com"]);
        assert!(config.may_resolve("static.crates.io"));
        assert!(config.may_resolve("github.com"));
        assert!(!config.may_resolve("evil.example"));
        // A glob does not cover the bare domain.
        assert!(!config.may_resolve("crates.io"));
    }

    /// When the policy would let the command reach an unnamed address anyway,
    /// refusing the lookup would only break it.
    #[test]
    fn unknown_names_pass_when_the_policy_says_so() {
        let config = config(true, &["github.com"]);
        assert!(config.may_resolve("evil.example"));
    }

    #[test]
    fn a_ttl_of_zero_still_leaves_time_to_connect() {
        assert_eq!(0u32.clamp(MIN_TTL, MAX_TTL), MIN_TTL);
        assert_eq!(86400u32.clamp(MIN_TTL, MAX_TTL), MAX_TTL);
        assert_eq!(120u32.clamp(MIN_TTL, MAX_TTL), 120);
    }

    #[test]
    fn the_monotonic_clock_moves_forward() {
        let first = monotonic_nanos().unwrap();
        let second = monotonic_nanos().unwrap();
        assert!(second >= first);
        assert!(first > 0);
    }
}
