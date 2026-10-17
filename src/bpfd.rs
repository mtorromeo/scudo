//! Talking to `scudo-bpfd`, the helper that attaches eBPF programs to a
//! sandbox's cgroup.
//!
//! The daemon is the only privileged part of scudo. It exists because a user
//! service manager may not load BPF programs, so systemd's own `IPAddressAllow=`
//! and friends are silently ignored in user units.

pub mod cgroup;
pub mod client;
// Pure parsing with no aya in it, so it builds without the eBPF toolchain and
// the fuzz targets can reach it.
pub mod dns;
pub mod protocol;
pub mod report;

#[cfg(feature = "bpf")]
pub mod caps;
#[cfg(feature = "bpf")]
pub mod events;
#[cfg(feature = "bpf")]
pub mod fsmon;
#[cfg(feature = "bpf")]
pub mod loader;
#[cfg(feature = "bpf")]
pub mod outside;
#[cfg(feature = "bpf")]
pub mod resolver;
#[cfg(feature = "bpf")]
pub mod server;
#[cfg(feature = "bpf")]
pub mod trie;
#[cfg(feature = "bpf")]
pub mod worker;
