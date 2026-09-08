//! Checking that the daemon has the capabilities it needs.
//!
//! Cgroup BPF programs cannot be loaded without `CAP_BPF` and `CAP_NET_ADMIN`
//! (and on most systems `kernel.unprivileged_bpf_disabled` closes the door to
//! unprivileged BPF anyway). Finding out at startup gives a clear message
//! instead of an `EPERM` at the first attach, with a command already waiting.
//!
//! `CAP_PERFMON` is deliberately *not* among those: it is needed only to load
//! the tracepoint programs that report refused file accesses, and a daemon
//! without it still does everything else it was installed for. Requiring it at
//! startup would turn an optional report into a reason not to run at all, so it
//! is asked for at the point of use and its absence is a warning.

use anyhow::{Context as _, Result, bail};

/// Capability bit numbers from `linux/capability.h`.
const CAP_NET_ADMIN: u32 = 12;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// The setcap invocation that grants everything the daemon can use.
pub const SETCAP_HINT: &str = "setcap cap_bpf,cap_net_admin,cap_perfmon=ep /usr/bin/scudo-bpfd";

/// Check that the effective set holds the two capabilities without which the
/// daemon can do nothing at all.
pub fn check() -> Result<()> {
    let effective = effective_set()?;
    let missing = missing_from(effective);
    if missing.is_empty() {
        return Ok(());
    }
    bail!(
        "missing {}; grant them with: {SETCAP_HINT}",
        missing.join(" and ")
    )
}

/// Can we load tracepoint programs and read a caller's memory?
///
/// The kernel gates every tracing program type on `perfmon_capable()`, and
/// `bpf_probe_read_user` with it, so this is the one question the file monitor
/// has to ask before it tries.
pub fn check_perfmon() -> Result<()> {
    let effective = effective_set()?;
    if effective & (1u64 << CAP_PERFMON) != 0u64 {
        return Ok(());
    }
    bail!("missing CAP_PERFMON; grant it with: {SETCAP_HINT}")
}

fn missing_from(effective: u64) -> Vec<&'static str> {
    [(CAP_BPF, "CAP_BPF"), (CAP_NET_ADMIN, "CAP_NET_ADMIN")]
        .into_iter()
        .filter(|&(bit, _)| effective & (1u64 << bit) == 0u64)
        .map(|(_, name)| name)
        .collect()
}

/// Read this process's effective capability set.
///
/// `/proc/self/status` rather than `capget`: the kernel prints the same bitmask
/// there, and it needs no unsafe FFI.
fn effective_set() -> Result<u64> {
    let status =
        std::fs::read_to_string("/proc/self/status").context("reading /proc/self/status")?;
    parse_effective(&status).context("no CapEff line in /proc/self/status")
}

fn parse_effective(status: &str) -> Option<u64> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?
        .trim();
    u64::from_str_radix(value, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_effective_set() {
        assert_eq!(
            parse_effective("Name:\tx\nCapEff:\t000001ffffffffff\nSeccomp:\t0\n"),
            Some(0x0000_01ff_ffff_ffff)
        );
        assert_eq!(parse_effective("Name:\tx\n"), None);
    }

    /// The tracing capability is asked for on its own, and is not one of the
    /// two the daemon refuses to start without.
    #[test]
    fn perfmon_is_not_one_of_the_two_that_are_required() {
        let both = (1u64 << CAP_BPF) | (1u64 << CAP_NET_ADMIN);
        assert!(missing_from(both).is_empty());
        assert_eq!(both & (1u64 << CAP_PERFMON), 0u64);
    }

    #[test]
    fn names_only_what_is_missing() {
        assert_eq!(missing_from(0u64), vec!["CAP_BPF", "CAP_NET_ADMIN"]);
        assert_eq!(missing_from(1u64 << CAP_BPF), vec!["CAP_NET_ADMIN"]);
        assert!(missing_from((1u64 << CAP_BPF) | (1u64 << CAP_NET_ADMIN)).is_empty());
    }
}
