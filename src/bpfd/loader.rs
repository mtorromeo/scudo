//! Loading the eBPF programs and attaching them to a sandbox's cgroup.
//!
//! One object is loaded per sandbox, so its maps and `.rodata` belong to that
//! sandbox alone: no policy id, no shared state, and cleanup is just a drop.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{
    fs::File,
    os::fd::AsRawFd as _,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context as _, Result};
use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, MapData, PerCpuArray, RingBuf},
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSockAddr},
};
use glob::Pattern;
use scudo_bpf_common::{
    ACTION_ALLOW, ACTION_DENY, DenialEvent, EVENTS_BYTES, EVENTS_BYTES_OFF, FAMILY_V4, FAMILY_V6,
    PORTS_ENTRIES, PROTO_TCP, PROTO_UDP, SET_ALLOW, SET_DENY, SLOT_TCP, SLOT_UDP, STAGE_CONNECT,
    STAGE_EGRESS, STAGE_INGRESS, STAGE_SENDMSG, port_bit, port_word,
};

use crate::{
    bpfd::{
        events::Bus,
        protocol::{Notification, Stage, Transport},
        resolver::{self, Config as ResolverConfig, HostRule, Resolver, Sockets},
        trie::{self, DestKey},
        worker::{POLL_INTERVAL_MS, Shutdown, Worker},
    },
    policy::network::{Action, NetworkPolicy, PortRule, Protocol},
};

/// The compiled programs, built by `build.rs`.
static PROGRAM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/scudo-net"));

/// A loaded, attached policy. Dropping it detaches every program and stops the
/// threads that went with it — each [`Worker`] ends its own thread and waits
/// for it, so the maps a reader holds never outlive the object they came from.
pub struct Attached {
    /// Keeping the object alive is what keeps the programs attached.
    _bpf: Arc<Mutex<Ebpf>>,
    /// Held rather than read: dropping a [`Worker`] is what ends its thread.
    _resolver: Option<Worker>,
    _events: Option<Worker>,
}

fn action_value(action: Action) -> u8 {
    match action {
        Action::Allow => ACTION_ALLOW,
        Action::Deny => ACTION_DENY,
    }
}

/// Every destination the policy declares outright, paired with its verdict.
///
/// Host rules are not here: they name no address until the resolver learns one.
fn static_keys(policy: &NetworkPolicy) -> Vec<(Action, DestKey)> {
    let deny = policy.dest.deny.iter().map(|dest| (Action::Deny, dest));
    let allow = policy.dest.allow.iter().map(|dest| (Action::Allow, dest));
    deny.chain(allow)
        .filter_map(|(action, dest)| DestKey::of(dest).map(|key| (action, key)))
        .collect()
}

/// The host names the resolver has to watch for, with the verdict each carries.
fn host_rules(policy: &NetworkPolicy) -> Result<Vec<HostRule>> {
    policy
        .host_rules()
        .map(|(name, action)| {
            let pattern = Pattern::new(name)
                .with_context(|| format!("host rule '{name}' is not a valid pattern"))?;
            Ok(HostRule { pattern, action })
        })
        .collect()
}

/// Turn a policy's port rules into the four bitmaps the program bit-tests.
///
/// A rule that names no protocol sets its bits in both slots, so the program
/// never has to combine anything at run time.
fn port_bitmaps(policy: &NetworkPolicy) -> Vec<u64> {
    let mut words = vec![0u64; PORTS_ENTRIES as usize];
    for (set, rules) in [
        (SET_DENY, &policy.ports.deny),
        (SET_ALLOW, &policy.ports.allow),
    ] {
        for rule in rules {
            set_bits(&mut words, set, *rule);
        }
    }
    words
}

fn set_bits(words: &mut [u64], set: u32, rule: PortRule) {
    let slots: &[u32] = match rule.proto {
        Protocol::Any => &[SLOT_TCP, SLOT_UDP],
        Protocol::Tcp => &[SLOT_TCP],
        Protocol::Udp => &[SLOT_UDP],
    };
    for &slot in slots {
        for port in rule.ports.start..=rule.ports.end {
            let index = port_word(set, slot, port) as usize;
            if let Some(word) = words.get_mut(index) {
                *word |= port_bit(port);
            }
        }
    }
}

/// Load the programs for `policy` and attach them to `cgroup`.
///
/// Attaching uses BPF links (`CgroupAttachMode::Single`, which means no legacy
/// attach flags — `bpf_link_create` rejects `BPF_F_ALLOW_MULTI`, since links
/// already stack). Several links may sit on the same hook, and the kernel
/// combines their verdicts with a logical AND, so another policy on the same
/// cgroup can only ever narrow what is allowed — never widen it.
pub fn attach(policy: &NetworkPolicy, cgroup: &Path, bus: &Arc<Bus>) -> Result<Attached> {
    let statics = static_keys(policy);
    let hosts = host_rules(policy)?;
    let ports = port_bitmaps(policy);

    // The resolver's ports are compiled into the programs, so its sockets have
    // to exist before they are loaded.
    let sockets = if policy.needs_resolver() {
        Some(Sockets::bind().context("starting the policy's DNS resolver")?)
    } else {
        None
    };
    let (port_v4, port_v6) = sockets
        .as_ref()
        .map_or((0u16, 0u16), |s| (s.port_v4, s.port_v6));

    // A bitmap nobody set a bit in folds the whole port stage out of the
    // verified program, so a policy with no port rules pays nothing for them.
    let deny_set = u8::from(!policy.ports.deny.is_empty());
    let allow_set = u8::from(!policy.ports.allow.is_empty());
    // Reporting is folded out of the programs the same way, so a sandbox nobody
    // is watching carries none of it — and its ring buffer shrinks to a page,
    // which at a hundred-odd live sandboxes is the difference that matters.
    let reporting = policy.reports_denials();
    let mut bpf = EbpfLoader::new()
        .override_global("DEFAULT_ACTION", &action_value(policy.default), true)
        .override_global("RESOLVER_PORT_V4", &port_v4, true)
        .override_global("RESOLVER_PORT_V6", &port_v6, true)
        .override_global("PORTS_DENY_SET", &deny_set, true)
        .override_global("PORTS_ALLOW_SET", &allow_set, true)
        .override_global("LOG_DENIALS", &u8::from(reporting), true)
        .map_max_entries("EVENTS", events_bytes(reporting))
        .load(PROGRAM)
        .context("loading eBPF programs")?;

    for &(action, key) in &statics {
        trie::insert(&mut bpf, action, key)?;
    }

    {
        let mut map: Array<_, u64> = bpf
            .map_mut("PORTS")
            .context("eBPF object has no PORTS map")?
            .try_into()
            .context("PORTS is not an array map")?;
        // Only the words that hold something are worth a syscall; the map is
        // already zeroed.
        for (index, word) in ports.iter().enumerate() {
            if *word == 0 {
                continue;
            }
            let index = u32::try_from(index).context("port bitmap is too large")?;
            map.set(index, word, 0)
                .with_context(|| format!("writing port word {index}"))?;
        }
    }

    let cgroup_file =
        File::open(cgroup).with_context(|| format!("opening cgroup {}", cgroup.display()))?;

    // connect/sendmsg first: they turn a rejected connection into a clean EPERM
    // rather than a packet that silently disappears. recvmsg goes with them: it
    // puts the source address of a redirected DNS reply back to what the caller
    // expects to see.
    for name in [
        "connect4", "connect6", "sendmsg4", "sendmsg6", "recvmsg4", "recvmsg6",
    ] {
        let program: &mut CgroupSockAddr = bpf
            .program_mut(name)
            .with_context(|| format!("eBPF object has no {name} program"))?
            .try_into()
            .with_context(|| format!("{name} is not a cgroup/sock_addr program"))?;
        program.load().with_context(|| format!("loading {name}"))?;
        program
            .attach(&cgroup_file, CgroupAttachMode::Single)
            .with_context(|| format!("attaching {name}"))?;
    }

    // The packet-level backstop, and the only layer that sees raw sockets.
    let egress: &mut CgroupSkb = bpf
        .program_mut("egress")
        .context("eBPF object has no egress program")?
        .try_into()
        .context("egress is not a cgroup_skb program")?;
    egress.load().context("loading egress")?;
    egress
        .attach(
            &cgroup_file,
            CgroupSkbAttachType::Egress,
            CgroupAttachMode::Single,
        )
        .context("attaching egress")?;

    // Inbound filtering matches the source address against the same rules, the
    // way systemd's IPAddressAllow= does, so replies from an allowed peer still
    // get through.
    if policy.inbound == Action::Deny {
        let ingress: &mut CgroupSkb = bpf
            .program_mut("ingress")
            .context("eBPF object has no ingress program")?
            .try_into()
            .context("ingress is not a cgroup_skb program")?;
        ingress.load().context("loading ingress")?;
        ingress
            .attach(
                &cgroup_file,
                CgroupSkbAttachType::Ingress,
                CgroupAttachMode::Single,
            )
            .context("attaching ingress")?;
    }

    // Taken out before the object is shared: the reader owns these two, and
    // nothing else ever looks at them. The programs keep referring to the maps
    // themselves, which live in the kernel either way.
    let events = if reporting {
        Some(start_events(&mut bpf, Arc::clone(bus))?)
    } else {
        None
    };

    let bpf = Arc::new(Mutex::new(bpf));

    let resolver = match sockets {
        Some(sockets) => Some(start_resolver(
            sockets,
            policy,
            hosts,
            statics,
            Arc::clone(&bpf),
            Arc::clone(bus),
        )?),
        None => None,
    };

    Ok(Attached {
        _bpf: bpf,
        _resolver: resolver,
        _events: events,
    })
}

/// How much ring buffer to ask for. The kernel wants a power-of-two multiple of
/// the page size, so the floor is a page and not a fixed 4 KB.
fn events_bytes(reporting: bool) -> u32 {
    if reporting {
        return EVENTS_BYTES;
    }
    // SAFETY: sysconf reads a constant and touches no memory of ours.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u32::try_from(page)
        .unwrap_or(EVENTS_BYTES_OFF)
        .max(EVENTS_BYTES_OFF)
}

/// Start the thread that carries denials from the kernel to the bus.
fn start_events(bpf: &mut Ebpf, bus: Arc<Bus>) -> Result<Worker> {
    let ring: RingBuf<MapData> = bpf
        .take_map("EVENTS")
        .context("eBPF object has no EVENTS map")?
        .try_into()
        .context("EVENTS is not a ring buffer")?;
    let dropped: PerCpuArray<MapData, u64> = bpf
        .take_map("DROPPED")
        .context("eBPF object has no DROPPED map")?
        .try_into()
        .context("DROPPED is not a per-CPU array")?;

    Worker::spawn("events", move |stop| {
        read_events(ring, &dropped, &bus, stop);
    })
}

/// Drain the ring buffer onto the bus until the sandbox goes away.
fn read_events(
    mut ring: RingBuf<MapData>,
    dropped: &PerCpuArray<MapData, u64>,
    bus: &Bus,
    stop: &Shutdown,
) {
    // The wakeup goes in the same wait as the ring buffer, so a teardown does
    // not have to sit out the rest of the interval.
    let mut fds = [
        libc::pollfd {
            fd: ring.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stop.wake_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let mut reported = 0u64;

    while !stop.stopping() {
        while let Some(item) = ring.next() {
            if let Some(event) = DenialEvent::from_bytes(&item)
                && let Some(notification) = notification(&event)
            {
                bus.publish(notification);
            }
        }
        // Whatever the kernel could not fit in while we were away. Reported as
        // a delta, because the counters only ever go up.
        let total = total_dropped(dropped);
        if total > reported {
            bus.note_lost(total.saturating_sub(reported));
            reported = total;
        }
        // SAFETY: fds is a live, correctly sized array of pollfd.
        unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                fds.len() as libc::nfds_t,
                POLL_INTERVAL_MS,
            );
        }
    }
}

/// The per-CPU tallies of events that did not fit, added up.
fn total_dropped(dropped: &PerCpuArray<MapData, u64>) -> u64 {
    dropped.get(&0, 0).map_or(0, |values| {
        values.iter().copied().fold(0u64, u64::saturating_add)
    })
}

/// Turn one event from the kernel into the message a watcher reads.
///
/// An event whose fields name nothing we know is dropped rather than guessed
/// at: the two ends are built together, so it would mean the object and the
/// daemon had come apart.
fn notification(event: &DenialEvent) -> Option<Notification> {
    let addr = match event.family {
        FAMILY_V4 => {
            let octets: [u8; 4] = event.addr.get(..4)?.try_into().ok()?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        FAMILY_V6 => IpAddr::V6(Ipv6Addr::from(event.addr)),
        _ => return None,
    };
    let stage = match event.stage {
        STAGE_CONNECT => Stage::Connect,
        STAGE_SENDMSG => Stage::Sendmsg,
        STAGE_EGRESS => Stage::Egress,
        STAGE_INGRESS => Stage::Ingress,
        _ => return None,
    };
    let transport = match event.proto {
        PROTO_TCP => Transport::Tcp,
        PROTO_UDP => Transport::Udp,
        _ => Transport::Other,
    };
    Some(Notification::Blocked {
        stage,
        transport,
        addr,
        port: event.port,
    })
}

/// Start the resolver thread for a policy that speaks in names.
fn start_resolver(
    sockets: Sockets,
    policy: &NetworkPolicy,
    hosts: Vec<HostRule>,
    statics: Vec<(Action, DestKey)>,
    bpf: Arc<Mutex<Ebpf>>,
    bus: Arc<Bus>,
) -> Result<Worker> {
    let config = ResolverConfig {
        hosts,
        // A learnt address that happens to equal a declared one shares its key,
        // so expiring it would delete the rule the config wrote. The sweep skips
        // anything in here.
        statics: statics.into_iter().collect(),
        resolve_unknown: policy.resolves_unknown_names(),
        upstreams: resolver::system_upstreams(),
    };
    Worker::spawn("resolver", move |stop| {
        Resolver::new(sockets, config, bpf, bus).run(stop);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(family: u8, addr: [u8; 16], stage: u8, proto: u8, port: u16) -> DenialEvent {
        DenialEvent {
            addr,
            port,
            family,
            proto,
            stage,
            _pad: [0; 3],
        }
    }

    #[test]
    fn a_v4_event_names_the_address_it_carries() {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&[1, 1, 1, 1]);
        let got = notification(&event(FAMILY_V4, addr, STAGE_CONNECT, PROTO_TCP, 443));
        assert_eq!(
            got,
            Some(Notification::Blocked {
                stage: Stage::Connect,
                transport: Transport::Tcp,
                addr: "1.1.1.1".parse().unwrap(),
                port: 443,
            })
        );
    }

    /// ICMP and raw sockets carry no port and no transport of their own, and
    /// only the packet-level hooks ever see them.
    #[test]
    fn a_portless_event_is_reported_as_such() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let got = notification(&event(FAMILY_V6, addr, STAGE_EGRESS, 1, 0));
        assert_eq!(
            got,
            Some(Notification::Blocked {
                stage: Stage::Egress,
                transport: Transport::Other,
                addr: "2001:db8::1".parse().unwrap(),
                port: 0,
            })
        );
    }

    /// A field naming something we do not know means the object and the daemon
    /// have come apart; inventing a plausible event would be worse than none.
    #[test]
    fn an_event_we_cannot_read_is_dropped() {
        assert_eq!(
            notification(&event(7, [0; 16], STAGE_CONNECT, PROTO_TCP, 443)),
            None
        );
        assert_eq!(
            notification(&event(FAMILY_V4, [0; 16], 99, PROTO_TCP, 443)),
            None
        );
    }

    /// Every stage the programs can report has a name on the wire.
    #[test]
    fn every_stage_is_covered() {
        for stage in [STAGE_CONNECT, STAGE_SENDMSG, STAGE_EGRESS, STAGE_INGRESS] {
            assert!(
                notification(&event(FAMILY_V4, [0; 16], stage, PROTO_UDP, 53)).is_some(),
                "stage {stage} has no notification"
            );
        }
    }

    /// The ring buffer size the kernel is asked for has to be a power-of-two
    /// multiple of the page size, at both settings.
    #[test]
    fn the_ring_buffer_size_is_one_the_kernel_will_take() {
        for reporting in [true, false] {
            let size = events_bytes(reporting);
            assert!(size.is_power_of_two(), "{size} is not a power of two");
            assert!(size >= EVENTS_BYTES_OFF);
        }
    }
}
