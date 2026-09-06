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

/// What a denied access is reported as, when the policy asks for it.
///
/// The programs write this into the `EVENTS` ring buffer and `scudo-bpfd` reads
/// it straight back out, so the layout below is an ABI like everything else
/// here. It is fixed size and 2-byte aligned: `bpf_ringbuf_reserve` hands out
/// 8-byte aligned memory, and a type needing more than that cannot be reserved
/// at all.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenialEvent {
    /// Where the traffic was going, or on ingress where it came from, as the
    /// octets a trie keys on. A v4 address sits in the first four bytes.
    pub addr: [u8; 16],
    /// Host order. Zero when the traffic carries no port at all, which is what
    /// ICMP and the raw sockets look like.
    pub port: u16,
    /// [`FAMILY_V4`] or [`FAMILY_V6`].
    pub family: u8,
    /// One of the `PROTO_*` above.
    pub proto: u8,
    /// One of the `STAGE_*` below.
    pub stage: u8,
    pub _pad: [u8; 3],
}

/// Which hook turned the traffic away. The two syscall-level stages fail the
/// call with `EPERM`; the two packet-level ones drop it silently, and are the
/// only ones that see raw sockets.
pub const STAGE_CONNECT: u8 = 0;
pub const STAGE_SENDMSG: u8 = 1;
pub const STAGE_EGRESS: u8 = 2;
pub const STAGE_INGRESS: u8 = 3;

pub const FAMILY_V4: u8 = 4;
pub const FAMILY_V6: u8 = 6;

/// One event, as it sits in the ring buffer.
pub const EVENT_SIZE: usize = size_of::<DenialEvent>();

/// How much ring buffer a sandbox that reports its denials gets. The kernel
/// wants a power-of-two multiple of the page size.
pub const EVENTS_BYTES: u32 = 256 * 1024;

/// The floor the loader shrinks it to when nothing is being reported. The map
/// is declared in the object, so it is created either way; the kernel wants a
/// power-of-two multiple of the page size, and the loader raises this to the
/// running kernel's page size when that is larger.
pub const EVENTS_BYTES_OFF: u32 = 4096;

impl DenialEvent {
    /// Read one event back out of the ring buffer.
    ///
    /// Both ends are the same machine and the same object, so the integers are
    /// in native order — this is a cast written out longhand, not a decoder.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // The trailing padding is never read, so nothing below would notice a
        // record that came up short — but a reader that accepted one would be
        // reading the next event's bytes as this one's.
        if bytes.len() < EVENT_SIZE {
            return None;
        }
        let addr: [u8; 16] = bytes.get(..16)?.try_into().ok()?;
        let port = u16::from_ne_bytes(bytes.get(16..18)?.try_into().ok()?);
        Some(DenialEvent {
            addr,
            port,
            family: *bytes.get(18)?,
            proto: *bytes.get(19)?,
            stage: *bytes.get(20)?,
            _pad: [0; 3],
        })
    }
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

    /// The layout the programs write and the daemon reads back. `reserve`
    /// cannot hand out memory aligned to more than 8 bytes, so an alignment
    /// that crept above that would turn into a load failure.
    #[test]
    fn the_event_layout_is_the_one_both_ends_agree_on() {
        assert_eq!(EVENT_SIZE, 24);
        assert!(8 % align_of::<DenialEvent>() == 0);
    }

    #[test]
    fn an_event_survives_the_round_trip_through_bytes() {
        let event = DenialEvent {
            addr: [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            port: 443,
            family: FAMILY_V4,
            proto: PROTO_TCP,
            stage: STAGE_CONNECT,
            _pad: [0; 3],
        };
        // SAFETY: DenialEvent is repr(C), Copy, and holds no padding the read
        // could observe as uninitialised — every byte of it is written above.
        let bytes: [u8; EVENT_SIZE] = unsafe { core::mem::transmute(event) };
        assert_eq!(DenialEvent::from_bytes(&bytes), Some(event));
        // A short read is not an event.
        assert_eq!(DenialEvent::from_bytes(&bytes[..EVENT_SIZE - 1]), None);
    }

    #[test]
    fn loopback_constants_are_in_network_order() {
        // Host-endian on purpose: the constant holds octets, not a number.
        assert_eq!(LOOPBACK_V4.to_ne_bytes(), [127, 0, 0, 1]);
        assert_eq!(LOOPBACK_V6, core::net::Ipv6Addr::LOCALHOST.octets());
    }
}
