//! Types and layout shared between `scudo-bpfd` and the eBPF programs it loads.
//!
//! Everything here is `no_std`: the loader writes the maps that the
//! verifier-checked program reads, so the layout below is the ABI between them.
//!
//! There is no rule struct any more. Destinations live in LPM tries, keyed by
//! the address itself, and ports live in the bitmaps this module lays out — so
//! what used to be a scanned array of rules is now two map lookups with no loop
//! in sight.

#![no_std]

/// The policy default, and the verdict a destination trie stands for.
pub const ACTION_DENY: u8 = 0;
pub const ACTION_ALLOW: u8 = 1;

/// IP protocol numbers, plus the "neither TCP nor UDP" case. These name what a
/// packet *is*; `SLOT_*` below names where its ports are recorded.
pub const PROTO_ANY: u8 = 0;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// The port a DNS query is redirected away from.
pub const DNS_PORT: u16 = 53;

/// How many destinations a single policy's tries may hold. LPM tries are
/// created with `BPF_F_NO_PREALLOC`, so this is a ceiling and not a cost.
pub const MAX_DESTINATIONS: u32 = 16384;

/// How many sockets we remember a redirected DNS destination for. The map is an
/// LRU, so this is a working set and not a limit: a sandbox with more DNS
/// sockets in flight than this loses the *source address* of the odd reply, not
/// the reply itself.
pub const MAX_DNS_ORIGINS: u32 = 1024;

/// The `PORTS` map is four bitmaps over the whole port space, laid out as
/// `(set, protocol slot)` pairs. A rule's protocol picks the slot; a rule
/// written without one sets its bit in both.
pub const SET_DENY: u32 = 0;
pub const SET_ALLOW: u32 = 1;
pub const SLOT_TCP: u32 = 0;
pub const SLOT_UDP: u32 = 1;

const SETS: u32 = 2;
const SLOTS: u32 = 2;
/// 65536 ports, 64 to a `u64` word.
pub const PORT_WORDS: u32 = 1024;
/// Total entries in the `PORTS` array map: 32 KB of bitmap.
pub const PORTS_ENTRIES: u32 = SETS * SLOTS * PORT_WORDS;

/// Which word of `PORTS` holds `port` for this set and protocol slot.
#[inline(always)]
#[must_use]
pub const fn port_word(set: u32, slot: u32, port: u16) -> u32 {
    (set * SLOTS + slot) * PORT_WORDS + (port as u32 >> 6)
}

/// Which bit of that word.
#[inline(always)]
#[must_use]
pub const fn port_bit(port: u16) -> u64 {
    1u64 << (port as u32 & 63)
}

/// The loopback address of each family, in the byte order the tries and the
/// packet fields use.
pub const LOOPBACK_V4: u32 = 0x7f00_0001u32.to_be();
pub const LOOPBACK_V6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every (set, slot, port) triple lands in its own bit, and nothing spills
    /// out of the map.
    #[test]
    fn the_bitmap_layout_is_disjoint_and_in_bounds() {
        for set in [SET_DENY, SET_ALLOW] {
            for slot in [SLOT_TCP, SLOT_UDP] {
                for port in [1u16, 63, 64, 443, 65535] {
                    assert!(port_word(set, slot, port) < PORTS_ENTRIES);
                }
            }
        }
        // Neighbouring ports share a word but not a bit.
        assert_eq!(
            port_word(SET_ALLOW, SLOT_TCP, 64),
            port_word(SET_ALLOW, SLOT_TCP, 127)
        );
        assert_ne!(port_bit(64), port_bit(127));
        // A word boundary moves to the next word.
        assert_ne!(
            port_word(SET_ALLOW, SLOT_TCP, 63),
            port_word(SET_ALLOW, SLOT_TCP, 64)
        );
        // The four bitmaps never overlap.
        assert_ne!(
            port_word(SET_DENY, SLOT_TCP, 443),
            port_word(SET_ALLOW, SLOT_TCP, 443)
        );
        assert_ne!(
            port_word(SET_ALLOW, SLOT_TCP, 443),
            port_word(SET_ALLOW, SLOT_UDP, 443)
        );
    }

    #[test]
    fn loopback_constants_are_in_network_order() {
        // Host-endian on purpose: the constant holds octets, not a number.
        assert_eq!(LOOPBACK_V4.to_ne_bytes(), [127, 0, 0, 1]);
        assert_eq!(LOOPBACK_V6, core::net::Ipv6Addr::LOCALHOST.octets());
    }
}
