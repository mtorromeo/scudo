//! The destination tries: what a policy's addresses look like once they are in
//! the kernel, and the two ways they get there.
//!
//! A destination is a prefix and nothing else — the LPM trie matches it, so the
//! program needs no loop to find it. Statically declared prefixes are written
//! once at load; addresses learnt from DNS are written as full-length prefixes
//! and taken out again when their TTL runs out.
//!
//! Removal is what enforces expiry, and it is the only thing that does: the
//! programs carry no expiry check. That is deliberate. An entry that has expired
//! but is still present would keep covering the shorter prefixes underneath it,
//! and there is no way to fall back to the next-longest match — so a stale
//! `/32` in the deny trie would read as "no match" and let traffic through. With
//! removal alone, a late sweep merely keeps doing what it was already doing for
//! another moment, which errs on the safe side in both tries.

use core::net::IpAddr;

use anyhow::{Context as _, Result};
use aya::{
    Ebpf,
    maps::lpm_trie::{Key, LpmTrie},
};

use crate::policy::network::{Action, Destination};

/// A prefix as the tries key on it: the address in network order, and how many
/// of its bits count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DestKey {
    V4 { addr: u32, prefix_len: u32 },
    V6 { addr: [u8; 16], prefix_len: u32 },
}

impl DestKey {
    /// The key for a network, with the address kept in network order because
    /// that is the order an LPM trie compares bits in.
    #[must_use]
    pub fn net(addr: IpAddr, prefix_len: u8) -> Self {
        let prefix_len = u32::from(prefix_len);
        match addr {
            IpAddr::V4(v4) => DestKey::V4 {
                addr: u32::from(v4).to_be(),
                prefix_len,
            },
            IpAddr::V6(v6) => DestKey::V6 {
                addr: v6.octets(),
                prefix_len,
            },
        }
    }

    /// The key for a single address, which is a prefix covering only itself.
    #[must_use]
    pub fn address(addr: IpAddr) -> Self {
        let prefix_len = match addr {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };
        Self::net(addr, prefix_len)
    }

    /// The key a destination rule declares, if it declares one at all. A host
    /// rule names no address until the resolver learns one.
    #[must_use]
    pub fn of(dest: &Destination) -> Option<Self> {
        match *dest {
            Destination::Net { addr, prefix_len } => Some(Self::net(addr, prefix_len)),
            Destination::Host(_) => None,
        }
    }

    fn map_name(self, action: Action) -> &'static str {
        match (self, action) {
            (DestKey::V4 { .. }, Action::Deny) => "DEST_DENY_V4",
            (DestKey::V4 { .. }, Action::Allow) => "DEST_ALLOW_V4",
            (DestKey::V6 { .. }, Action::Deny) => "DEST_DENY_V6",
            (DestKey::V6 { .. }, Action::Allow) => "DEST_ALLOW_V6",
        }
    }
}

/// The value is never read: presence in one trie or the other is the verdict.
const PRESENT: u8 = 1;

/// Put a prefix in the trie that carries `action`.
pub fn insert(bpf: &mut Ebpf, action: Action, key: DestKey) -> Result<()> {
    let name = key.map_name(action);
    let map = bpf
        .map_mut(name)
        .with_context(|| format!("eBPF object has no {name} map"))?;
    match key {
        DestKey::V4 { addr, prefix_len } => {
            let mut trie: LpmTrie<_, u32, u8> = map
                .try_into()
                .with_context(|| format!("{name} is not an LPM trie"))?;
            trie.insert(&Key::new(prefix_len, addr), PRESENT, 0)
        }
        DestKey::V6 { addr, prefix_len } => {
            let mut trie: LpmTrie<_, [u8; 16], u8> = map
                .try_into()
                .with_context(|| format!("{name} is not an LPM trie"))?;
            trie.insert(&Key::new(prefix_len, addr), PRESENT, 0)
        }
    }
    .with_context(|| format!("writing a destination into {name}"))
}

/// Take a prefix back out. A key that is not there is not an error: two names
/// can resolve to one address, and only one sweep gets to remove it.
pub fn remove(bpf: &mut Ebpf, action: Action, key: DestKey) -> Result<()> {
    let name = key.map_name(action);
    let map = bpf
        .map_mut(name)
        .with_context(|| format!("eBPF object has no {name} map"))?;
    match key {
        DestKey::V4 { addr, prefix_len } => {
            let mut trie: LpmTrie<_, u32, u8> = map
                .try_into()
                .with_context(|| format!("{name} is not an LPM trie"))?;
            trie.remove(&Key::new(prefix_len, addr))
        }
        DestKey::V6 { addr, prefix_len } => {
            let mut trie: LpmTrie<_, [u8; 16], u8> = map
                .try_into()
                .with_context(|| format!("{name} is not an LPM trie"))?;
            trie.remove(&Key::new(prefix_len, addr))
        }
    }
    .with_context(|| format!("removing a destination from {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[expect(clippy::panic)]
    #[test]
    fn a_v4_key_holds_the_address_in_network_order() {
        let DestKey::V4 { addr, prefix_len } = DestKey::net("10.0.0.0".parse().unwrap(), 8u8)
        else {
            panic!("expected a v4 key");
        };
        // The host-endian bytes are exactly what matters here: the u32 is a
        // container for octets the trie compares in order, not a number.
        #[expect(clippy::host_endian_bytes)]
        let octets = addr.to_ne_bytes();
        assert_eq!(octets, [10, 0, 0, 0]);
        assert_eq!(prefix_len, 8);
    }

    #[test]
    fn a_bare_address_covers_only_itself() {
        assert_eq!(
            DestKey::address("1.1.1.1".parse().unwrap()),
            DestKey::net("1.1.1.1".parse().unwrap(), 32u8)
        );
        assert_eq!(
            DestKey::address("2606:4700::1".parse().unwrap()),
            DestKey::net("2606:4700::1".parse().unwrap(), 128u8)
        );
    }

    #[test]
    fn a_host_rule_declares_no_key() {
        assert!(DestKey::of(&Destination::Host("example.com".into())).is_none());
    }

    /// The four tries are told apart by family and verdict together, so a
    /// prefix can sit in the allow trie and its own deny trie at once.
    #[test]
    fn each_family_and_verdict_gets_its_own_trie() {
        let v4 = DestKey::address("1.1.1.1".parse().unwrap());
        let v6 = DestKey::address("::1".parse().unwrap());
        let names = [
            v4.map_name(Action::Deny),
            v4.map_name(Action::Allow),
            v6.map_name(Action::Deny),
            v6.map_name(Action::Allow),
        ];
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }
}
