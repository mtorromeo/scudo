//! End-to-end checks that a network policy is actually enforced.
//!
//! These need `scudo-bpfd` running with `CAP_BPF` and `CAP_NET_ADMIN`, so they
//! are ignored by default. Run them with:
//!
//! ```sh
//! systemctl --user start scudo-bpfd.socket
//! cargo test --test network_policy -- --ignored
//! ```
//!
//! Every destination is a listener on loopback, so nothing here depends on the
//! machine having working internet access.

#![cfg(target_os = "linux")]
// An integration test crate is all test functions; there is no module to put
// them in.
#![expect(clippy::tests_outside_test_module)]

use std::{
    io::Write as _,
    net::{Ipv4Addr, TcpListener},
    path::PathBuf,
    process::Command,
};

/// `curl` exit codes we distinguish.
const CURL_COULD_NOT_CONNECT: i32 = 7;
const CURL_EMPTY_REPLY: i32 = 52;

/// A listener that accepts and immediately closes, so a permitted connection
/// ends in "empty reply" and a blocked one in "could not connect".
struct Sink {
    port: u16,
}

impl Sink {
    fn spawn() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binding a listener");
        let port = listener.local_addr().expect("listener address").port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                drop(stream);
            }
        });
        Sink { port }
    }
}

fn daemon_socket() -> PathBuf {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").expect("XDG_RUNTIME_DIR is not set");
    PathBuf::from(runtime_dir).join("scudo/bpfd.sock")
}

fn require_daemon() {
    let socket = daemon_socket();
    assert!(
        socket.exists(),
        "scudo-bpfd is not running: {} does not exist",
        socket.display()
    );
}

/// Write a config holding a single `probe` profile and return its XDG dir.
fn config_with(network: &str) -> tempdir::TempDir {
    let dir = tempdir::TempDir::new();
    let scudo_dir = dir.path().join("scudo");
    std::fs::create_dir_all(&scudo_dir).expect("creating the config directory");
    let mut file =
        std::fs::File::create(scudo_dir.join("config.toml")).expect("creating the config");
    write!(file, "[probe]\n{network}").expect("writing the config");
    dir
}

/// Run `curl` against `port` under the `probe` profile, returning its exit code.
fn probe(network: &str, port: u16) -> i32 {
    require_daemon();
    let dir = config_with(network);
    let url = format!("http://127.0.0.1:{port}/");
    let status = Command::new(env!("CARGO_BIN_EXE_scudo"))
        .env("XDG_CONFIG_HOME", dir.path())
        // Run from a directory with no .scudo.toml, so no trust prompt appears.
        .current_dir(dir.path())
        .args([
            "--no-match",
            "--profile",
            "probe",
            "--",
            "curl",
            "-s",
            "-m",
            "3",
            "-o",
            "/dev/null",
            &url,
        ])
        .status()
        .expect("running scudo");
    status.code().unwrap_or(-1)
}

#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF"]
fn allowed_destination_is_reachable() {
    let sink = Sink::spawn();
    let network = format!(
        "network.dest.allow = [\"127.0.0.1\"]\nnetwork.ports.allow = [{}]\n",
        sink.port
    );
    assert_eq!(probe(&network, sink.port), CURL_EMPTY_REPLY);
}

#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF"]
fn destination_outside_the_allowlist_is_blocked() {
    let blocked = Sink::spawn();
    let network = "network.dest.allow = [\"10.0.0.0/8\"]\n";
    assert_eq!(probe(network, blocked.port), CURL_COULD_NOT_CONNECT);
}

/// A port grants on its own, at an address no destination rule names. This is
/// the half of the model that is easiest to get wrong, so it is worth seeing
/// happen for real.
#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF"]
fn an_allowed_port_reaches_an_unnamed_destination() {
    let sink = Sink::spawn();
    let network = format!(
        "network.dest.allow = [\"10.0.0.0/8\"]\nnetwork.ports.allow = [{}]\n",
        sink.port
    );
    assert_eq!(probe(&network, sink.port), CURL_EMPTY_REPLY);
}

/// And a denied port revokes at an address the destination list does name.
#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF"]
fn a_denied_port_beats_an_allowed_destination() {
    let sink = Sink::spawn();
    let network = format!(
        "network.dest.allow = [\"localhost\"]\nnetwork.ports.deny = [{}]\n",
        sink.port
    );
    assert_eq!(probe(&network, sink.port), CURL_COULD_NOT_CONNECT);
}

/// A port narrowed to UDP does not open the TCP one.
#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF"]
fn a_udp_port_does_not_open_the_tcp_one() {
    let sink = Sink::spawn();
    let network = format!("network.ports.allow = [\"{}/udp\"]\n", sink.port);
    assert_eq!(probe(&network, sink.port), CURL_COULD_NOT_CONNECT);
}

/// A deny rule beats an allow rule covering the same destination.
#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF"]
fn deny_wins_over_allow() {
    let sink = Sink::spawn();
    let network = "network.dest.allow = [\"localhost\"]\nnetwork.dest.deny = [\"127.0.0.1\"]\n";
    assert_eq!(probe(network, sink.port), CURL_COULD_NOT_CONNECT);
}

/// ICMP has no port, so the destination decides on its own.
///
/// Which layer says no depends on how the system's `ping` opens its socket: with
/// a datagram ICMP socket (`net.ipv4.ping_group_range`) the connect hook gets
/// there first and the error is a clean `EPERM`; with a real raw socket nothing
/// but the packet-level program ever sees it. Both are the policy working.
#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF"]
fn raw_sockets_are_covered() {
    // 127.0.0.1 is deliberately not in the list.
    let network = "network.dest.allow = [\"10.0.0.0/8\"]\n";
    assert_ne!(
        run_under(network, &["ping", "-c", "1", "-W", "2", "127.0.0.1"]),
        0i32,
        "ping should not have got through"
    );
}

/// And it is the destination that decides, not the mere fact of being something
/// other than TCP or UDP: a backstop that drops everything it cannot parse would
/// pass the test above for the wrong reason.
#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF"]
fn an_allowed_destination_answers_a_ping() {
    let network = "network.dest.allow = [\"127.0.0.1\"]\n";
    assert_eq!(
        run_under(network, &["ping", "-c", "1", "-W", "2", "127.0.0.1"]),
        0i32,
        "ping to an allowed destination should have got through"
    );
}

/// A command that can reach `systemd --user` can ask it to start something in a
/// sibling cgroup, where none of our programs are attached. That is a complete
/// escape, so the policy has to close it by default.
#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF"]
fn the_service_manager_cannot_be_used_to_escape() {
    require_daemon();
    let allowed = Sink::spawn();
    let blocked = Sink::spawn();
    let network = format!(
        "network.dest.allow = [\"127.0.0.1\"]\nnetwork.ports.allow = [{}]\n",
        allowed.port
    );
    let dir = config_with(&network);
    let url = format!("http://127.0.0.1:{}/", blocked.port);

    let status = Command::new(env!("CARGO_BIN_EXE_scudo"))
        .env("XDG_CONFIG_HOME", dir.path())
        .current_dir(dir.path())
        .args([
            "--no-match",
            "--profile",
            "probe",
            "--",
            "systemd-run",
            "--user",
            "--wait",
            "-q",
            "--pipe",
            "--",
            "curl",
            "-s",
            "-m",
            "3",
            "-o",
            "/dev/null",
            &url,
        ])
        .status()
        .expect("running scudo");

    assert_ne!(
        status.code(),
        Some(0i32),
        "the sandbox reached the service manager and escaped the policy"
    );
}

/// Run a command under a profile and return its exit code.
fn run_under(network: &str, args: &[&str]) -> i32 {
    require_daemon();
    let dir = config_with(network);
    let mut command_line = vec!["--no-match", "--profile", "probe", "--"];
    command_line.extend_from_slice(args);
    let status = Command::new(env!("CARGO_BIN_EXE_scudo"))
        .env("XDG_CONFIG_HOME", dir.path())
        .current_dir(dir.path())
        .args(&command_line)
        .status()
        .expect("running scudo");
    status.code().unwrap_or(-1)
}

/// The name-based tests need a working internet connection, unlike the rest:
/// the resolver forwards to the system's real nameservers.
const BY_NAME: &str = "network.dest.allow = [\"example.com\"]\n";

#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF and working DNS"]
fn an_allowed_name_resolves_and_connects() {
    assert_eq!(
        run_under(
            BY_NAME,
            &[
                "curl",
                "-s",
                "-m",
                "8",
                "-o",
                "/dev/null",
                "https://example.com/"
            ]
        ),
        0i32
    );
}

#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF and working DNS"]
fn a_name_outside_the_allowlist_does_not_resolve() {
    // getent exits 2 when the name is not found.
    assert_eq!(run_under(BY_NAME, &["getent", "hosts", "crates.io"]), 2i32);
}

/// A name in a `deny` rule resolves — that is how its addresses get learnt — but
/// the addresses it resolves to are the ones the rule then keeps out of reach.
#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF and working DNS"]
fn a_denied_name_resolves_but_stays_out_of_reach() {
    let network = "network.dest.deny = [\"example.com\"]\n\
                   network.dest.allow = [\"any\"]\n";
    assert_eq!(
        run_under(network, &["getent", "hosts", "example.com"]),
        0i32,
        "the name should still resolve"
    );
    assert_eq!(
        run_under(
            network,
            &[
                "curl",
                "-s",
                "-m",
                "8",
                "-o",
                "/dev/null",
                "https://example.com/"
            ]
        ),
        CURL_COULD_NOT_CONNECT,
        "but connecting to it should not be allowed"
    );
}

/// Refusing a name the policy would let the command reach anyway only breaks
/// it, so a wide-open allow rule keeps unnamed lookups working.
#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF and working DNS"]
fn unknown_names_resolve_when_any_address_is_allowed() {
    let network = "network.dest.allow = [\"any\", \"example.com\"]\n";
    assert_eq!(run_under(network, &["getent", "hosts", "crates.io"]), 0i32);
}

/// Truncated answers are retried over TCP, so that path has to work too.
#[test]
#[ignore = "needs scudo-bpfd with CAP_BPF and working DNS"]
fn dns_over_tcp_is_served() {
    assert_eq!(
        run_under(
            BY_NAME,
            &[
                "dig",
                "+tcp",
                "+time=5",
                "+tries=1",
                "example.com",
                "A",
                "+short"
            ]
        ),
        0i32
    );
}

/// A minimal scoped temporary directory; the test suite has no dev-dependencies
/// and this is all that is needed.
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub fn new() -> Self {
            let base = std::env::temp_dir();
            let unique = format!(
                "scudo-test-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            );
            let path = base.join(unique.replace(['(', ')', ' '], ""));
            drop(std::fs::remove_dir_all(&path));
            std::fs::create_dir_all(&path).expect("creating a temporary directory");
            TempDir { path }
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.path));
        }
    }
}
