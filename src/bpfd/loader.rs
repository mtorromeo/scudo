//! Loading the eBPF programs and attaching them to a sandbox's cgroup.
//!
//! One object is loaded per sandbox, so its maps and `.rodata` belong to that
//! sandbox alone: no policy id, no shared state, and cleanup is just a drop.

use core::sync::atomic::{AtomicBool, Ordering};
use std::{
    fs::File,
    path::Path,
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

use anyhow::{Context as _, Result};
use aya::{
    Ebpf, EbpfLoader,
    maps::Array,
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSockAddr},
};
use glob::Pattern;
use scudo_bpf_common::{
    ACTION_ALLOW, ACTION_DENY, PORTS_ENTRIES, SET_ALLOW, SET_DENY, SLOT_TCP, SLOT_UDP, port_bit,
    port_word,
};

use crate::{
    bpfd::{
        resolver::{self, Config as ResolverConfig, HostRule, Resolver, Sockets},
        trie::{self, DestKey},
    },
    policy::network::{Action, NetworkPolicy, PortRule, Protocol},
};

/// The compiled programs, built by `build.rs`.
static PROGRAM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/scudo-net"));

/// A loaded, attached policy. Dropping it detaches every program and stops the
/// resolver that went with it.
pub struct Attached {
    /// Keeping the object alive is what keeps the programs attached.
    _bpf: Arc<Mutex<Ebpf>>,
    resolver: Option<ResolverThread>,
}

/// The resolver thread and the flag that ends it.
struct ResolverThread {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for Attached {
    fn drop(&mut self) {
        let Some(resolver) = self.resolver.as_mut() else {
            return;
        };
        resolver.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = resolver.handle.take() {
            // The thread wakes at least twice a second, so this is a short wait.
            drop(handle.join());
        }
    }
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
pub fn attach(policy: &NetworkPolicy, cgroup: &Path) -> Result<Attached> {
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
    let mut bpf = EbpfLoader::new()
        .override_global("DEFAULT_ACTION", &action_value(policy.default), true)
        .override_global("RESOLVER_PORT_V4", &port_v4, true)
        .override_global("RESOLVER_PORT_V6", &port_v6, true)
        .override_global("PORTS_DENY_SET", &deny_set, true)
        .override_global("PORTS_ALLOW_SET", &allow_set, true)
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

    let bpf = Arc::new(Mutex::new(bpf));

    let resolver = match sockets {
        Some(sockets) => Some(start_resolver(
            sockets,
            policy,
            hosts,
            statics,
            Arc::clone(&bpf),
        )?),
        None => None,
    };

    Ok(Attached {
        _bpf: bpf,
        resolver,
    })
}

/// Start the resolver thread for a policy that speaks in names.
fn start_resolver(
    sockets: Sockets,
    policy: &NetworkPolicy,
    hosts: Vec<HostRule>,
    statics: Vec<(Action, DestKey)>,
    bpf: Arc<Mutex<Ebpf>>,
) -> Result<ResolverThread> {
    let config = ResolverConfig {
        hosts,
        // A learnt address that happens to equal a declared one shares its key,
        // so expiring it would delete the rule the config wrote. The sweep skips
        // anything in here.
        statics: statics.into_iter().collect(),
        resolve_unknown: policy.resolves_unknown_names(),
        upstreams: resolver::system_upstreams(),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = std::thread::Builder::new()
        .name("resolver".to_owned())
        .spawn(move || {
            Resolver::new(sockets, config, bpf).run(&thread_stop);
        })
        .context("starting the resolver thread")?;

    Ok(ResolverThread {
        stop,
        handle: Some(handle),
    })
}
