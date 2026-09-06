//! Network policy enforcement for a single scudo sandbox.
//!
//! One instance of this object is loaded per sandbox, so its maps and its
//! `.rodata` belong to that sandbox alone and no policy id is needed anywhere.
//!
//! Three layers, deliberately overlapping:
//!
//! * `connect4`/`connect6` reject a connection at `connect()` time, so the
//!   command gets a clean `EPERM` rather than a silent black hole.
//! * `sendmsg4`/`sendmsg6` do the same for unconnected UDP.
//! * `cgroup_skb` egress and ingress are the backstop, and the only layer that
//!   covers raw sockets and everything that is neither TCP nor UDP.
//!
//! **There is not a loop anywhere in this file, and there must not be one.**
//! Destinations are longest-prefix matched by the kernel's own LPM tries and a
//! port is a bit test, so what the verifier has to walk does not grow with the
//! size of the policy. That is what lets a policy hold as many rules as it likes.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_sock_addr, sk_action},
    helpers::bpf_get_socket_cookie,
    macros::{cgroup_skb, cgroup_sock_addr, map},
    maps::{Array, LpmTrie, LruHashMap, lpm_trie::Key},
    programs::{SkBuffContext, SockAddrContext},
};
use scudo_bpf_common::{
    ACTION_ALLOW, DNS_PORT, LOOPBACK_V4, LOOPBACK_V6, MAX_DESTINATIONS, MAX_DNS_ORIGINS,
    PORTS_ENTRIES, PROTO_ANY, PROTO_TCP, PROTO_UDP, SET_ALLOW, SET_DENY, SLOT_TCP, SLOT_UDP,
    port_bit, port_word,
};

/// Set by the loader: the verdict when neither dimension has anything to say.
#[unsafe(no_mangle)]
static DEFAULT_ACTION: u8 = 0;

/// Set by the loader: the loopback port scudo-bpfd's resolver listens on, or 0
/// when the policy names no hosts, in which case queries are left alone and
/// judged like any other traffic.
#[unsafe(no_mangle)]
static RESOLVER_PORT_V4: u16 = 0;

/// The same, for queries sent over IPv6 (redirected to `::1`).
#[unsafe(no_mangle)]
static RESOLVER_PORT_V6: u16 = 0;

/// Set by the loader: whether the matching port bitmap holds anything at all.
/// When it does not, the verifier folds that whole stage away.
#[unsafe(no_mangle)]
static PORTS_DENY_SET: u8 = 0;
#[unsafe(no_mangle)]
static PORTS_ALLOW_SET: u8 = 0;

/// Destination prefixes, statically declared or learnt from a DNS answer. An
/// address learnt from DNS is a `/32` or `/128` like any other prefix; taking it
/// out again when its TTL runs out is the resolver's job, and an entry that
/// outlived its TTL would otherwise keep covering the prefixes beneath it.
#[map]
static DEST_DENY_V4: LpmTrie<u32, u8> = LpmTrie::with_max_entries(MAX_DESTINATIONS, 0);
#[map]
static DEST_ALLOW_V4: LpmTrie<u32, u8> = LpmTrie::with_max_entries(MAX_DESTINATIONS, 0);
#[map]
static DEST_DENY_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(MAX_DESTINATIONS, 0);
#[map]
static DEST_ALLOW_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(MAX_DESTINATIONS, 0);

/// Four bitmaps over the port space: {deny, allow} × {TCP, UDP}.
#[map]
static PORTS: Array<u64> = Array::with_max_entries(PORTS_ENTRIES, 0);

/// Where a redirected DNS query was originally headed, keyed by socket cookie.
///
/// The reply comes back from the loopback resolver, and a stub resolver that
/// sent its query on an unconnected socket compares the reply's source against
/// the nameserver it asked — musl's `res_msend` and glibc's `res_ourserver_p`
/// both do — so the source has to be put back before it is handed up. Only the
/// socket that sent the query knows which address that was, hence the cookie.
///
/// LRU rather than a plain hash: the entry outlives the reply it is there for,
/// and a socket that goes away without one must not hold a slot for ever.
#[map]
static DNS_ORIGIN_V4: LruHashMap<u64, u32> = LruHashMap::with_max_entries(MAX_DNS_ORIGINS, 0);
#[map]
static DNS_ORIGIN_V6: LruHashMap<u64, [u8; 16]> = LruHashMap::with_max_entries(MAX_DNS_ORIGINS, 0);

/// Read a `.rodata` global. The loader rewrites these before load, so they must
/// be read volatile or the optimiser folds in the placeholder value.
#[inline(always)]
fn global<T: Copy>(value: &T) -> T {
    unsafe { core::ptr::read_volatile(value) }
}

/// Is this port in one of the policy's port sets?
///
/// Traffic that is neither TCP nor UDP has no port of its own, so it belongs to
/// no set on either side: the port dimension abstains and the destination
/// decides alone. That is why ICMP needs no special case anywhere below.
#[inline(always)]
fn in_port_set(set: u32, port: u16, proto: u8) -> bool {
    let declared = if set == SET_DENY {
        global(&PORTS_DENY_SET)
    } else {
        global(&PORTS_ALLOW_SET)
    };
    if declared == 0 {
        return false;
    }
    let slot = if proto == PROTO_TCP {
        SLOT_TCP
    } else if proto == PROTO_UDP {
        SLOT_UDP
    } else {
        return false;
    };
    match PORTS.get(port_word(set, slot, port)) {
        Some(&word) => word & port_bit(port) != 0,
        None => false,
    }
}

/// Fold the two dimensions into a verdict.
///
/// Destinations and ports are independent sources of permission: either can
/// deny, either can allow, and a deny from one beats an allow from the other.
/// An empty list grants nothing rather than granting everything, which is what
/// lets the two compose without one silently swallowing the other.
#[inline(always)]
fn decide(dest_denied: bool, dest_allowed: bool, port: u16, proto: u8) -> bool {
    if dest_denied || in_port_set(SET_DENY, port, proto) {
        return false;
    }
    if dest_allowed || in_port_set(SET_ALLOW, port, proto) {
        return true;
    }
    global(&DEFAULT_ACTION) == ACTION_ALLOW
}

/// Traffic to and from our own resolver always passes: the packet-level programs
/// see the redirected query too, and no list knows the ephemeral loopback port
/// it was sent to.
#[inline(always)]
fn is_resolver_v4(addr: u32, port: u16) -> bool {
    let resolver = global(&RESOLVER_PORT_V4);
    resolver != 0 && port == resolver && addr == LOOPBACK_V4
}

#[inline(always)]
fn is_resolver_v6(addr: [u8; 16], port: u16) -> bool {
    let resolver = global(&RESOLVER_PORT_V6);
    resolver != 0 && port == resolver && addr == LOOPBACK_V6
}

/// `true` allows. Two map lookups, no iteration.
#[inline(always)]
fn verdict_v4(addr: u32, port: u16, proto: u8) -> bool {
    if is_resolver_v4(addr, port) {
        return true;
    }
    let key = Key::new(32, addr);
    if DEST_DENY_V4.get(&key).is_some() {
        return decide(true, false, port, proto);
    }
    decide(false, DEST_ALLOW_V4.get(&key).is_some(), port, proto)
}

#[inline(always)]
fn verdict_v6(addr: [u8; 16], port: u16, proto: u8) -> bool {
    if is_resolver_v6(addr, port) {
        return true;
    }
    let key = Key::new(128, addr);
    if DEST_DENY_V6.get(&key).is_some() {
        return decide(true, false, port, proto);
    }
    decide(false, DEST_ALLOW_V6.get(&key).is_some(), port, proto)
}

/// `sock_addr` programs report the socket type, not the IP protocol.
/// `SOCK_STREAM` is 1 and `SOCK_DGRAM` is 2.
#[inline(always)]
fn proto_of(sock_type: u32) -> u8 {
    match sock_type {
        1 => PROTO_TCP,
        2 => PROTO_UDP,
        _ => PROTO_ANY,
    }
}

/// The IPv6 address a `sock_addr` context carries, as the bytes a trie key wants.
///
/// `user_ip6` holds the address as four words already in network order, so their
/// native-endian bytes *are* the octets, in order.
#[inline(always)]
fn sock_addr_v6(sock_addr: &bpf_sock_addr) -> [u8; 16] {
    let w0 = sock_addr.user_ip6[0].to_ne_bytes();
    let w1 = sock_addr.user_ip6[1].to_ne_bytes();
    let w2 = sock_addr.user_ip6[2].to_ne_bytes();
    let w3 = sock_addr.user_ip6[3].to_ne_bytes();
    [
        w0[0], w0[1], w0[2], w0[3], w1[0], w1[1], w1[2], w1[3], w2[0], w2[1], w2[2], w2[3], w3[0],
        w3[1], w3[2], w3[3],
    ]
}

/// Put an address back into a `sock_addr` context, undoing [`sock_addr_v6`].
#[inline(always)]
fn set_sock_addr_v6(sock_addr: &mut bpf_sock_addr, addr: [u8; 16]) {
    sock_addr.user_ip6[0] = u32::from_ne_bytes([addr[0], addr[1], addr[2], addr[3]]);
    sock_addr.user_ip6[1] = u32::from_ne_bytes([addr[4], addr[5], addr[6], addr[7]]);
    sock_addr.user_ip6[2] = u32::from_ne_bytes([addr[8], addr[9], addr[10], addr[11]]);
    sock_addr.user_ip6[3] = u32::from_ne_bytes([addr[12], addr[13], addr[14], addr[15]]);
}

/// `user_port` is a network-order 32-bit field holding a 16-bit port.
#[inline(always)]
fn sock_addr_port(sock_addr: &bpf_sock_addr) -> u16 {
    (u32::from_be(sock_addr.user_port) >> 16) as u16
}

#[inline(always)]
fn set_sock_addr_port(sock_addr: &mut bpf_sock_addr, port: u16) {
    sock_addr.user_port = u32::to_be(u32::from(port) << 16);
}

/// Point a DNS query at scudo-bpfd's own resolver.
///
/// Rewriting the destination here is what lets the policy speak in names: the
/// resolver decides which names may be looked up, and puts the addresses it
/// hands back into the destination tries, so the connection that follows is
/// allowed without any list ever having to guess an address.
///
/// It happens before any check, so a policy whose port lists never mention 53
/// still resolves names.
#[inline(always)]
fn redirect_to_resolver(sock_addr: &mut bpf_sock_addr, v4: bool, port: u16) {
    if v4 {
        sock_addr.user_ip4 = LOOPBACK_V4;
    } else {
        sock_addr.user_ip6[0] = 0;
        sock_addr.user_ip6[1] = 0;
        sock_addr.user_ip6[2] = 0;
        sock_addr.user_ip6[3] = u32::to_be(1);
    }
    set_sock_addr_port(sock_addr, port);
}

/// Shared body of the four `sock_addr` hooks. Returns 1 to allow, 0 to fail the
/// syscall with `EPERM`.
#[inline(always)]
fn sock_addr_verdict(ctx: &SockAddrContext, v4: bool) -> i32 {
    // SAFETY: the kernel hands us a valid, writable context for the duration of
    // the call, and rewriting the destination is what these hooks are for.
    let sock_addr = unsafe { &mut *ctx.sock_addr };
    let port = sock_addr_port(sock_addr);
    let proto = proto_of(sock_addr.type_);

    let resolver = if v4 {
        global(&RESOLVER_PORT_V4)
    } else {
        global(&RESOLVER_PORT_V6)
    };
    if resolver != 0 && port == DNS_PORT {
        remember_dns_origin(ctx, sock_addr, v4);
        redirect_to_resolver(sock_addr, v4, resolver);
        return 1;
    }

    let allowed = if v4 {
        verdict_v4(sock_addr.user_ip4, port, proto)
    } else {
        verdict_v6(sock_addr_v6(sock_addr), port, proto)
    };
    i32::from(allowed)
}

/// The socket a `sock_addr` hook is running for, as a cookie that survives from
/// the query to its reply. 0 means the kernel had none to give.
#[inline(always)]
fn socket_cookie(ctx: &SockAddrContext) -> u64 {
    // SAFETY: the helper only reads the context the kernel handed us.
    unsafe { bpf_get_socket_cookie(ctx.sock_addr.cast()) }
}

/// Note where a query was headed before it was redirected, so the reply can be
/// handed back with the source the caller is waiting for.
#[inline(always)]
fn remember_dns_origin(ctx: &SockAddrContext, sock_addr: &bpf_sock_addr, v4: bool) {
    let cookie = socket_cookie(ctx);
    if cookie == 0 {
        return;
    }
    // Failing to record it costs the answer, not the policy: the reply then
    // arrives from 127.0.0.1 and a strict stub resolver ignores it.
    //
    // The address is copied to the stack first. A helper may not be handed a
    // pointer into the context — the verifier rejects the load outright with
    // "dereference of modified ctx ptr" — and `&sock_addr.user_ip4` is one.
    if v4 {
        let addr = sock_addr.user_ip4;
        _ = DNS_ORIGIN_V4.insert(cookie, addr, 0);
    } else {
        let addr = sock_addr_v6(sock_addr);
        _ = DNS_ORIGIN_V6.insert(cookie, addr, 0);
    }
}

/// Put the reply's source back to the address the caller sent the query to.
///
/// Without this, a resolver using an unconnected UDP socket sees an answer from
/// 127.0.0.1 rather than from the nameserver it asked, and throws it away.
#[inline(always)]
fn recvmsg_restore(ctx: &SockAddrContext, v4: bool) -> i32 {
    // SAFETY: as in `sock_addr_verdict`.
    let sock_addr = unsafe { &mut *ctx.sock_addr };
    let port = sock_addr_port(sock_addr);
    let from_resolver = if v4 {
        is_resolver_v4(sock_addr.user_ip4, port)
    } else {
        is_resolver_v6(sock_addr_v6(sock_addr), port)
    };
    if !from_resolver {
        return 1;
    }
    // The address this socket's query was redirected away from, if we still
    // have it; the port is always 53, since that is where it was going.
    let cookie = socket_cookie(ctx);
    // SAFETY: the value is copied out before anything else can touch the map.
    if v4 {
        if let Some(&addr) = unsafe { DNS_ORIGIN_V4.get(cookie) } {
            sock_addr.user_ip4 = addr;
        }
    } else if let Some(&addr) = unsafe { DNS_ORIGIN_V6.get(cookie) } {
        set_sock_addr_v6(sock_addr, addr);
    }
    set_sock_addr_port(sock_addr, DNS_PORT);
    1
}

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    sock_addr_verdict(&ctx, true)
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    sock_addr_verdict(&ctx, false)
}

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    sock_addr_verdict(&ctx, true)
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    sock_addr_verdict(&ctx, false)
}

#[cgroup_sock_addr(recvmsg4)]
pub fn recvmsg4(ctx: SockAddrContext) -> i32 {
    recvmsg_restore(&ctx, true)
}

#[cgroup_sock_addr(recvmsg6)]
pub fn recvmsg6(ctx: SockAddrContext) -> i32 {
    recvmsg_restore(&ctx, false)
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

/// The ethertype of a packet, in host order.
///
/// `skb->protocol` is a `__be16`, and the kernel's context rewrite loads those
/// two bytes exactly as they sit in the socket buffer — no byte swap anywhere.
/// Comparing the raw value against `ETH_P_IP` therefore never matches on a
/// little-endian machine, and every packet would look like something other than
/// IP: the backstop would pass all of them, which is the whole program.
#[inline(always)]
fn skb_protocol(ctx: &SkBuffContext) -> u16 {
    // SAFETY: the kernel hands us a valid context for the duration of the call.
    let protocol = unsafe { (*ctx.skb.skb).protocol };
    u16::from_be(protocol as u16)
}

/// Read the port out of a TCP or UDP header. Anything else has no port, which
/// leaves the verdict to the destination alone.
#[inline(always)]
fn transport_port(ctx: &SkBuffContext, offset: usize, proto: u8, egress: bool) -> u16 {
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return 0;
    }
    let at = if egress { offset + 2 } else { offset };
    match ctx.load::<u16>(at) {
        Ok(port) => u16::from_be(port),
        Err(_) => 0,
    }
}

#[inline(always)]
fn ipv4_verdict(ctx: &SkBuffContext, egress: bool) -> bool {
    // A header we cannot read is one we cannot judge; the connect hooks have
    // already had their say on anything that went through a socket.
    let Ok(version_ihl) = ctx.load::<u8>(0) else {
        return true;
    };
    let Ok(proto) = ctx.load::<u8>(9) else {
        return true;
    };
    let addr_offset = if egress { 16usize } else { 12usize };
    // Loaded as raw bytes, which is the order the tries key on.
    let Ok(addr) = ctx.load::<u32>(addr_offset) else {
        return true;
    };
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    let port = transport_port(ctx, ihl, proto, egress);
    verdict_v4(addr, port, normalise_proto(proto))
}

#[inline(always)]
fn ipv6_verdict(ctx: &SkBuffContext, egress: bool) -> bool {
    let Ok(proto) = ctx.load::<u8>(6) else {
        return true;
    };
    let addr_offset = if egress { 24usize } else { 8usize };
    let Ok(addr) = ctx.load::<[u8; 16]>(addr_offset) else {
        return true;
    };
    let port = transport_port(ctx, 40, proto, egress);
    verdict_v6(addr, port, normalise_proto(proto))
}

#[inline(always)]
fn normalise_proto(proto: u8) -> u8 {
    match proto {
        PROTO_TCP => PROTO_TCP,
        PROTO_UDP => PROTO_UDP,
        _ => PROTO_ANY,
    }
}

/// Packet-level verdict, applied to the destination on egress and to the source
/// on ingress. This is the layer that sees raw sockets and ICMP.
#[inline(always)]
fn skb_verdict(ctx: &SkBuffContext, egress: bool) -> i32 {
    let allowed = match skb_protocol(ctx) {
        ETH_P_IP => ipv4_verdict(ctx, egress),
        ETH_P_IPV6 => ipv6_verdict(ctx, egress),
        // Not IP at all: the policy has nothing to say about it.
        _ => true,
    };
    if allowed {
        sk_action::SK_PASS as i32
    } else {
        sk_action::SK_DROP as i32
    }
}

#[cgroup_skb(egress)]
pub fn egress(ctx: SkBuffContext) -> i32 {
    skb_verdict(&ctx, true)
}

#[cgroup_skb(ingress)]
pub fn ingress(ctx: SkBuffContext) -> i32 {
    skb_verdict(&ctx, false)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
