//! Network policy: the rules a profile declares under `[profile.network]`, and
//! their normalised form.
//!
//! Parsing and normalisation live here so that a syntax error surfaces when the
//! config is loaded rather than when the command is about to run.

use core::{fmt, net::IpAddr};

use anyhow::{Context as _, Result, bail};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, Visitor},
};

/// The verdict a rule, or the policy default, produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Deny,
    Allow,
}

/// Transport protocol a port rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    Any,
    Tcp,
    Udp,
}

/// What to do when the policy cannot be enforced.
///
/// Ordered strictest first, so that `min()` over several policies picks the one
/// that gives the most protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnUnavailable {
    /// Refuse to run the command at all (default).
    #[default]
    Fail,
    /// Run it with no network whatsoever.
    NoNetwork,
    /// Warn on stderr and run it unfiltered.
    Warn,
}

/// An inclusive port range. A single port is stored as `start == end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

/// What a destination rule applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Destination {
    /// An IP network. A bare address is stored with a full-length prefix.
    Net { addr: IpAddr, prefix_len: u8 },
    /// A hostname or `*`-glob, resolved at run time by the DNS proxy.
    Host(String),
}

/// A port range, optionally narrowed to one transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRule {
    pub ports: PortRange,
    pub proto: Protocol,
}

/// An allow list and a deny list over the same kind of value.
///
/// Order within a list is not meaningful: every entry of a list carries the same
/// verdict, so which one matches cannot change the outcome. That is what makes
/// merging two profiles' lists a plain union.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet<T> {
    #[serde(default = "Vec::new")]
    pub allow: Vec<T>,
    #[serde(default = "Vec::new")]
    pub deny: Vec<T>,
}

/// Hand-written: the derive would demand `T: Default`, which neither a
/// `Destination` nor a `PortRule` has any business implementing.
impl<T> Default for RuleSet<T> {
    fn default() -> Self {
        RuleSet {
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

impl<T> RuleSet<T> {
    /// `true` when neither list names anything, so the dimension abstains.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

/// A profile's network policy, normalised and ready to be enforced.
///
/// Destinations and ports are two independent sources of permission, not a
/// filter narrowing one another. A packet is judged by:
///
/// ```text
/// if destination denied or port denied    -> deny
/// if destination allowed or port allowed  -> allow
/// otherwise                               -> default
/// ```
///
/// So an empty `allow` list grants nothing rather than granting everything, a
/// port in `ports.allow` is reachable at *any* address, and `ports.deny` revokes
/// even at an address `dest.allow` names. Traffic with no port of its own —
/// ICMP, raw sockets — needs no special case: the port dimension abstains on
/// both sides and the destination decides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub default: Action,
    pub inbound: Action,
    /// Whether the command may talk to the user's service manager.
    ///
    /// It must not, by default: a process that can reach `systemd --user` can
    /// ask it to start a command in a sibling cgroup, which no program attached
    /// to this one can see. That is a complete escape from the policy, and it is
    /// two lines of shell.
    pub service_manager: Action,
    pub on_unavailable: OnUnavailable,
    pub dest: RuleSet<Destination>,
    pub ports: RuleSet<PortRule>,
}

impl NetworkPolicy {
    /// `true` when the policy denies everything, which is realised with
    /// `PrivateNetwork=yes` and needs no enforcer.
    ///
    /// Nothing is reachable when the default denies and neither dimension
    /// grants anything; the deny lists cannot make that any more closed.
    #[must_use]
    pub fn is_deny_all(&self) -> bool {
        self.default == Action::Deny
            && self.inbound == Action::Deny
            && self.dest.allow.is_empty()
            && self.ports.allow.is_empty()
    }

    /// `true` when the policy restricts nothing, so it can be ignored entirely.
    ///
    /// The mirror of `is_deny_all`: with an allowing default the allow lists are
    /// inert, so only a deny list can still take something away.
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.default == Action::Allow
            && self.inbound == Action::Allow
            && self.dest.deny.is_empty()
            && self.ports.deny.is_empty()
    }

    /// `true` when the command must be kept away from the user's service
    /// manager, which it could otherwise use to escape the policy entirely.
    #[must_use]
    pub fn isolates_service_manager(&self) -> bool {
        self.service_manager == Action::Deny
    }

    /// `true` when the policy needs the eBPF enforcer to be applied.
    #[must_use]
    pub fn requires_enforcer(&self) -> bool {
        !self.is_deny_all() && !self.is_unrestricted()
    }

    /// `true` when the policy needs its own DNS resolver.
    ///
    /// Naming a host in a rule is what asks for one: the rule's addresses are
    /// whatever the resolver learns, so a lookup that goes around the resolver
    /// produces an address the rule will never recognise. That holds for a deny
    /// rule too — the addresses it has to recognise are learnt the same way.
    #[must_use]
    pub fn needs_resolver(&self) -> bool {
        self.host_rules().next().is_some()
    }

    /// Every host rule in the policy, paired with the verdict it carries.
    pub fn host_rules(&self) -> impl Iterator<Item = (&str, Action)> {
        let deny = self.dest.deny.iter().map(|dest| (dest, Action::Deny));
        let allow = self.dest.allow.iter().map(|dest| (dest, Action::Allow));
        deny.chain(allow).filter_map(|(dest, action)| match dest {
            Destination::Host(name) => Some((name.as_str(), action)),
            Destination::Net { .. } => None,
        })
    }

    /// `true` when the resolver should forward names no rule mentions.
    ///
    /// Refusing them is what makes the rules the DNS allowlist as well. But
    /// refusing a name whose address would be reachable anyway only breaks the
    /// command: it takes nothing away from an attacker who can already connect
    /// wherever it likes. A non-empty `ports.allow` is exactly that case — it
    /// grants those ports at every address — so it counts too.
    #[must_use]
    pub fn resolves_unknown_names(&self) -> bool {
        self.default == Action::Allow
            || !self.ports.allow.is_empty()
            || self.dest.allow.iter().any(|dest| {
                matches!(
                    dest,
                    Destination::Net {
                        prefix_len: 0u8,
                        ..
                    }
                )
            })
    }
}

/// A network policy exactly as written in TOML, before normalisation.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub default: Option<Action>,
    pub inbound: Option<Action>,
    pub service_manager: Option<Action>,
    pub on_unavailable: Option<OnUnavailable>,
    /// Addresses, networks and host names, as bare strings.
    #[serde(default)]
    pub dest: RuleSet<String>,
    /// Ports, as `443` or `"8000-8100"`, each optionally suffixed `/tcp`
    /// or `/udp`.
    #[serde(default)]
    pub ports: RuleSet<PortSpec>,
}

/// A port entry as written in TOML: `443`, or a string holding a range and an
/// optional protocol.
///
/// The string form is kept unparsed because it may still hold a `$VAR`; an
/// integer cannot, so it is checked as it is read.
#[derive(Debug, Clone)]
pub enum PortSpec {
    Single(u16),
    Spec(String),
}

impl PortSpec {
    fn is_sentinel(&self) -> bool {
        matches!(self, PortSpec::Spec(s) if s == SENTINEL)
    }

    fn has_variables(&self) -> bool {
        matches!(self, PortSpec::Spec(s) if s.contains('$'))
    }

    fn into_rule(self) -> Result<PortRule> {
        match self {
            PortSpec::Single(port) => Ok(PortRule {
                ports: single_port(port)?,
                proto: Protocol::Any,
            }),
            PortSpec::Spec(spec) => {
                parse_port_rule(&spec).with_context(|| format!("invalid port rule '{spec}'"))
            }
        }
    }
}

/// Hand-written so that an out-of-range port says so, which `#[serde(untagged)]`
/// could not: there every failure degrades to "did not match any variant".
impl<'de> Deserialize<'de> for PortSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PortSpecVisitor;

        impl Visitor<'_> for PortSpecVisitor {
            type Value = PortSpec;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a port number, or a string holding a port, a range, or either followed by '/tcp' or '/udp'")
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<PortSpec, E> {
                u16::try_from(v)
                    .map(PortSpec::Single)
                    .map_err(|_ignored| E::custom(format!("invalid port {v}")))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<PortSpec, E> {
                u16::try_from(v)
                    .map(PortSpec::Single)
                    .map_err(|_ignored| E::custom(format!("invalid port {v}")))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<PortSpec, E> {
                Ok(PortSpec::Spec(v.to_owned()))
            }
        }

        deserializer.deserialize_any(PortSpecVisitor)
    }
}

/// The array sentinel that splices in the inherited list; see `profile::merge_into`.
pub const SENTINEL: &str = "...";

impl NetworkConfig {
    /// Check every entry parses, so that a typo is caught when the config is
    /// read rather than when a command is about to run.
    ///
    /// Entries are skipped when they cannot be judged yet: `"..."` is resolved
    /// when profiles merge, and `$VAR` / `$arg_*` when the command line is
    /// known. Both are validated for real once resolved.
    pub fn validate(&self) -> Result<()> {
        for entry in self.dest.deny.iter().chain(self.dest.allow.iter()) {
            if entry == SENTINEL || entry.contains('$') {
                continue;
            }
            parse_dest(entry)?;
        }
        for entry in self.ports.deny.iter().chain(self.ports.allow.iter()) {
            if entry.is_sentinel() || entry.has_variables() {
                continue;
            }
            entry.clone().into_rule()?;
        }
        Ok(())
    }
}

impl TryFrom<NetworkConfig> for NetworkPolicy {
    type Error = anyhow::Error;

    fn try_from(config: NetworkConfig) -> Result<Self> {
        Ok(NetworkPolicy {
            default: config.default.unwrap_or_default(),
            inbound: config.inbound.unwrap_or_default(),
            service_manager: config.service_manager.unwrap_or_default(),
            on_unavailable: config.on_unavailable.unwrap_or_default(),
            dest: RuleSet {
                allow: destinations(config.dest.allow)?,
                deny: destinations(config.dest.deny)?,
            },
            ports: RuleSet {
                allow: port_rules(config.ports.allow)?,
                deny: port_rules(config.ports.deny)?,
            },
        })
    }
}

/// A symbolic name is two networks, so one entry can yield more than one
/// destination.
fn destinations(entries: Vec<String>) -> Result<Vec<Destination>> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        out.extend(parse_dest(&entry)?);
    }
    Ok(out)
}

fn port_rules(entries: Vec<PortSpec>) -> Result<Vec<PortRule>> {
    entries
        .into_iter()
        .map(|entry| {
            if entry.is_sentinel() {
                bail!("'{SENTINEL}' is only meaningful in a profile that extends another");
            }
            entry.into_rule()
        })
        .collect()
}

fn parse_dest(s: &str) -> Result<Vec<Destination>> {
    if s == SENTINEL {
        bail!("'{SENTINEL}' is only meaningful in a profile that extends another");
    }
    parse_net(s.trim()).with_context(|| format!("invalid network destination '{s}'"))
}

fn single_port(port: u16) -> Result<PortRange> {
    if port == 0 {
        bail!("port 0 is not a valid rule target");
    }
    Ok(PortRange {
        start: port,
        end: port,
    })
}

/// Parse the string form of a port entry: `"443"`, `"8000-8100"`, `"53/udp"`,
/// `"8000-8100/tcp"`.
fn parse_port_rule(s: &str) -> Result<PortRule> {
    let (ports, proto) = match s.rsplit_once('/') {
        Some((ports, proto)) => (ports, parse_proto(proto)?),
        None => (s, Protocol::Any),
    };
    Ok(PortRule {
        ports: parse_ports(ports)?,
        proto,
    })
}

fn parse_proto(s: &str) -> Result<Protocol> {
    match s.trim() {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "any" => Ok(Protocol::Any),
        other => bail!("invalid protocol '{other}': expected tcp, udp or any"),
    }
}

fn parse_ports(s: &str) -> Result<PortRange> {
    let (start, end) = if let Some((lo, hi)) = s.split_once('-') {
        (parse_port(lo)?, parse_port(hi)?)
    } else {
        let port = parse_port(s)?;
        (port, port)
    };
    if start > end {
        bail!("port range '{s}' ends before it starts");
    }
    Ok(PortRange { start, end })
}

fn parse_port(s: &str) -> Result<u16> {
    let port: u16 = s
        .trim()
        .parse()
        .with_context(|| format!("invalid port '{s}'"))?;
    if port == 0 {
        bail!("port 0 is not a valid rule target");
    }
    Ok(port)
}

fn max_prefix_len(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32u8,
        IpAddr::V6(_) => 128u8,
    }
}

/// The symbolic network names systemd's `IPAddressAllow=` accepts, so a rule
/// can be written the same way here.
fn symbolic_net(name: &str) -> Option<Vec<Destination>> {
    let nets: &[(&str, u8)] = match name {
        "any" => &[("0.0.0.0", 0u8), ("::", 0u8)],
        "localhost" => &[("127.0.0.0", 8u8), ("::1", 128u8)],
        "link-local" => &[("169.254.0.0", 16u8), ("fe80::", 64u8)],
        "multicast" => &[("224.0.0.0", 4u8), ("ff00::", 8u8)],
        _ => return None,
    };
    nets.iter()
        .map(|&(addr, prefix_len)| {
            addr.parse()
                .ok()
                .map(|addr| Destination::Net { addr, prefix_len })
        })
        .collect()
}

/// Parse an IP address, CIDR or symbolic name. Falls back to a hostname when it
/// is none of those.
fn parse_net(s: &str) -> Result<Vec<Destination>> {
    if let Some(nets) = symbolic_net(s) {
        return Ok(nets);
    }
    if let Some((addr_str, len_str)) = s.split_once('/') {
        let addr: IpAddr = addr_str
            .parse()
            .with_context(|| format!("invalid IP address '{addr_str}'"))?;
        let prefix_len: u8 = len_str
            .parse()
            .with_context(|| format!("invalid prefix length '{len_str}'"))?;
        let max = max_prefix_len(addr);
        if prefix_len > max {
            bail!("prefix length /{prefix_len} is too long for {addr}");
        }
        return Ok(vec![Destination::Net { addr, prefix_len }]);
    }
    if let Ok(addr) = s.parse::<IpAddr>() {
        return Ok(vec![Destination::Net {
            addr,
            prefix_len: max_prefix_len(addr),
        }]);
    }
    Ok(vec![parse_host(s)?])
}

/// Parse a hostname or `*`-glob. Hosts are lowercased so that matching is
/// case-insensitive, as DNS is.
fn parse_host(s: &str) -> Result<Destination> {
    if s.is_empty() {
        bail!("empty host");
    }
    // A host is something the resolver hands us an address for; an address is
    // never resolved, so a rule written that way could never match anything.
    // `parse_net` tries addresses first, so this only guards a direct caller.
    if s.parse::<IpAddr>().is_ok() {
        bail!("'{s}' is an address, not a host name");
    }
    // A colon here is almost always a port someone tried to attach to the
    // destination. Saying so beats "not a valid host name", which is true but
    // unhelpful — an unbracketed IPv6 address would already have parsed above.
    if s.contains(':') {
        bail!("'{s}' carries a port: ports belong in the policy's 'ports' list");
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*' | '?'))
    {
        bail!("'{s}' is neither an IP address nor a valid host name");
    }
    Ok(Destination::Host(s.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a `[profile.network]` body into a normalised policy.
    fn policy(src: &str) -> Result<NetworkPolicy> {
        let config: NetworkConfig = toml::from_str(src)?;
        config.validate()?;
        NetworkPolicy::try_from(config)
    }

    fn error(src: &str) -> String {
        format!("{:#}", policy(src).unwrap_err())
    }

    /// The single destination an allow list of one entry produces.
    fn one_dest(src: &str) -> Destination {
        let mut p = policy(src).unwrap();
        assert_eq!(p.dest.allow.len(), 1);
        p.dest.allow.pop().unwrap()
    }

    fn one_port(src: &str) -> PortRule {
        let mut p = policy(src).unwrap();
        assert_eq!(p.ports.allow.len(), 1);
        p.ports.allow.pop().unwrap()
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::from([a, b, c, d])
    }

    fn net(addr: IpAddr, prefix_len: u8) -> Destination {
        Destination::Net { addr, prefix_len }
    }

    #[test]
    fn bare_cidr() {
        assert_eq!(
            one_dest(r#"dest = { allow = ["10.0.0.0/8"] }"#),
            net(v4(10, 0, 0, 0), 8u8)
        );
    }

    #[test]
    fn bare_address_gets_full_prefix() {
        assert_eq!(
            one_dest(r#"dest = { allow = ["1.1.1.1"] }"#),
            net(v4(1, 1, 1, 1), 32u8)
        );
    }

    #[test]
    fn ipv6_needs_no_brackets() {
        assert_eq!(
            one_dest(r#"dest = { allow = ["2606:4700::1"] }"#),
            net("2606:4700::1".parse().unwrap(), 128u8)
        );
        assert_eq!(
            one_dest(r#"dest = { allow = ["2606:4700::/32"] }"#),
            net("2606:4700::".parse().unwrap(), 32u8)
        );
    }

    #[test]
    fn host_and_glob() {
        let p = policy(r#"dest = { allow = ["api.github.com", "*.crates.io"] }"#).unwrap();
        assert_eq!(
            p.dest.allow,
            vec![
                Destination::Host("api.github.com".into()),
                Destination::Host("*.crates.io".into()),
            ]
        );
    }

    #[test]
    fn host_is_lowercased() {
        assert_eq!(
            one_dest(r#"dest = { allow = ["API.GitHub.COM"] }"#),
            Destination::Host("api.github.com".into())
        );
    }

    #[test]
    fn symbolic_names_expand_to_both_families() {
        let p = policy(r#"dest = { allow = ["localhost"] }"#).unwrap();
        assert_eq!(
            p.dest.allow,
            vec![
                net(v4(127, 0, 0, 0), 8u8),
                net("::1".parse().unwrap(), 128u8),
            ]
        );
    }

    #[test]
    fn any_is_the_whole_address_space() {
        let p = policy(r#"dest = { allow = ["any"] }"#).unwrap();
        assert_eq!(
            p.dest.allow,
            vec![net(v4(0, 0, 0, 0), 0u8), net("::".parse().unwrap(), 0u8),]
        );
    }

    #[test]
    fn dest_tells_addresses_from_names_by_itself() {
        let p = policy(r#"dest = { allow = ["10.0.0.0/8", "example.com", "localhost"] }"#).unwrap();
        assert_eq!(
            p.dest.allow,
            vec![
                net(v4(10, 0, 0, 0), 8u8),
                Destination::Host("example.com".into()),
                net(v4(127, 0, 0, 0), 8u8),
                net("::1".parse().unwrap(), 128u8),
            ]
        );
    }

    #[test]
    fn deny_and_allow_are_kept_apart() {
        let p = policy(
            r#"
            dest = { allow = ["10.0.0.0/8"], deny = ["10.1.2.0/24"] }
            "#,
        )
        .unwrap();
        assert_eq!(p.dest.allow, vec![net(v4(10, 0, 0, 0), 8u8)]);
        assert_eq!(p.dest.deny, vec![net(v4(10, 1, 2, 0), 24u8)]);
    }

    #[test]
    fn a_bare_port_covers_every_protocol() {
        assert_eq!(
            one_port("ports = { allow = [443] }"),
            PortRule {
                ports: PortRange {
                    start: 443,
                    end: 443
                },
                proto: Protocol::Any,
            }
        );
    }

    #[test]
    fn port_range() {
        assert_eq!(
            one_port(r#"ports = { allow = ["8000-8100"] }"#),
            PortRule {
                ports: PortRange {
                    start: 8000,
                    end: 8100
                },
                proto: Protocol::Any,
            }
        );
    }

    #[test]
    fn a_port_can_name_its_protocol() {
        assert_eq!(
            one_port(r#"ports = { allow = ["53/udp"] }"#),
            PortRule {
                ports: PortRange { start: 53, end: 53 },
                proto: Protocol::Udp,
            }
        );
        assert_eq!(
            one_port(r#"ports = { allow = ["8000-8100/tcp"] }"#),
            PortRule {
                ports: PortRange {
                    start: 8000,
                    end: 8100
                },
                proto: Protocol::Tcp,
            }
        );
    }

    /// The protocol narrows the port; it does not spread to the other one.
    #[test]
    fn a_udp_port_does_not_grant_the_tcp_one() {
        let p = policy(r#"ports = { allow = ["53/udp"] }"#).unwrap();
        assert_eq!(
            p.ports.allow,
            vec![PortRule {
                ports: PortRange { start: 53, end: 53 },
                proto: Protocol::Udp,
            }]
        );
    }

    #[test]
    fn ports_take_a_deny_list_of_their_own() {
        let p = policy("ports = { allow = [443], deny = [22] }").unwrap();
        assert_eq!(
            p.ports.allow.first().map(|r| r.ports),
            Some(PortRange {
                start: 443,
                end: 443
            })
        );
        assert_eq!(
            p.ports.deny.first().map(|r| r.ports),
            Some(PortRange { start: 22, end: 22 })
        );
    }

    #[test]
    fn defaults_are_closed() {
        let p = policy("").unwrap();
        assert_eq!(p.default, Action::Deny);
        assert_eq!(p.inbound, Action::Deny);
        assert_eq!(p.service_manager, Action::Deny);
        assert_eq!(p.on_unavailable, OnUnavailable::Fail);
        assert!(p.dest.is_empty());
        assert!(p.ports.is_empty());
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = policy("").unwrap();
        assert!(p.is_deny_all());
        assert!(!p.requires_enforcer());
    }

    #[test]
    fn allow_rules_need_the_enforcer() {
        let p = policy(r#"dest = { allow = ["1.1.1.1"] }"#).unwrap();
        assert!(!p.is_deny_all());
        assert!(!p.is_unrestricted());
        assert!(p.requires_enforcer());
    }

    #[test]
    fn deny_only_policy_still_needs_the_enforcer() {
        let p = policy(
            r#"
            default = "allow"
            inbound = "allow"
            dest = { deny = ["10.0.0.0/8"] }
            "#,
        )
        .unwrap();
        assert!(!p.is_unrestricted());
        assert!(p.requires_enforcer());
    }

    #[test]
    fn open_policy_is_unrestricted() {
        let p = policy(
            r#"
            default = "allow"
            inbound = "allow"
            "#,
        )
        .unwrap();
        assert!(p.is_unrestricted());
        assert!(!p.requires_enforcer());
    }

    /// With an allowing default the allow lists take nothing away, so a policy
    /// made only of them is still nothing at all.
    #[test]
    fn allow_lists_are_inert_under_an_allowing_default() {
        let p = policy(
            r#"
            default = "allow"
            inbound = "allow"
            dest = { allow = ["1.1.1.1"] }
            ports = { allow = [443] }
            "#,
        )
        .unwrap();
        assert!(p.is_unrestricted());
    }

    /// A policy of nothing but port rules is a real restriction, and must not be
    /// mistaken for an empty one — it would be discarded.
    #[test]
    fn a_ports_only_policy_is_not_unrestricted() {
        let p = policy("ports = { allow = [443] }").unwrap();
        assert!(!p.is_unrestricted());
        assert!(!p.is_deny_all());
        assert!(p.requires_enforcer());
    }

    #[test]
    fn host_rules_ask_for_the_resolver() {
        assert!(
            policy(r#"dest = { allow = ["example.com"] }"#)
                .unwrap()
                .needs_resolver()
        );
        // A deny rule too: its addresses have to be learnt to be denied.
        assert!(
            policy(r#"dest = { deny = ["example.com"] }"#)
                .unwrap()
                .needs_resolver()
        );
        assert!(
            !policy(r#"dest = { allow = ["1.1.1.1"] }"#)
                .unwrap()
                .needs_resolver()
        );
    }

    #[test]
    fn host_rules_carry_their_verdict() {
        let p = policy(
            r#"
            dest = { allow = ["a.example.com", "1.1.1.1"], deny = ["b.example.com"] }
            "#,
        )
        .unwrap();
        let hosts: Vec<_> = p.host_rules().collect();
        // Deny first, and the address is not a host rule at all.
        assert_eq!(
            hosts,
            vec![
                ("b.example.com", Action::Deny),
                ("a.example.com", Action::Allow),
            ]
        );
    }

    #[test]
    fn unknown_names_resolve_only_where_refusing_them_buys_nothing() {
        // Nothing reachable that was not named: refuse.
        assert!(
            !policy(r#"dest = { allow = ["example.com"] }"#)
                .unwrap()
                .resolves_unknown_names()
        );
        // The whole address space is open anyway.
        assert!(
            policy(r#"dest = { allow = ["any"] }"#)
                .unwrap()
                .resolves_unknown_names()
        );
        assert!(
            policy(r#"default = "allow""#)
                .unwrap()
                .resolves_unknown_names()
        );
        // A port grant reaches every address on that port, so refusing a lookup
        // takes nothing away either.
        assert!(
            policy("ports = { allow = [443] }")
                .unwrap()
                .resolves_unknown_names()
        );
    }

    #[test]
    fn rejects_bad_syntax() {
        for src in [
            "ports = { allow = [0] }",
            "ports = { allow = [99999] }",
            r#"ports = { allow = ["100-50"] }"#,
            r#"ports = { allow = ["443/sctp"] }"#,
            r#"ports = { allow = ["not-a-port"] }"#,
            r#"dest = { allow = ["10.0.0.0/33"] }"#,
            r#"dest = { allow = ["::1/129"] }"#,
            r#"dest = { allow = ["not a host"] }"#,
            r#"dest = { allow = [""] }"#,
            // The fields the new shape replaced.
            r#"allow = ["1.1.1.1"]"#,
            r#"deny = ["1.1.1.1"]"#,
            r#"dest = { allow = [{ dest = "1.1.1.1", port = 443 }] }"#,
            r#"dest = { alow = ["1.1.1.1"] }"#,
            "port = { allow = [443] }",
        ] {
            assert!(policy(src).is_err(), "expected '{src}' to be rejected");
        }
    }

    /// A destination that carries a port is the one mistake the new shape
    /// invites, so it gets a message that names the fix.
    #[test]
    fn a_destination_with_a_port_says_where_ports_go() {
        let msg = error(r#"dest = { allow = ["api.github.com:443"] }"#);
        assert!(msg.contains("ports"), "{msg}");
        assert!(msg.contains("api.github.com:443"), "{msg}");
    }

    #[test]
    fn errors_name_what_is_wrong() {
        assert!(error("ports = { allow = [99999] }").contains("99999"));
        assert!(error(r#"dest = { allow = ["10.0.0.0/33"] }"#).contains("prefix length"));
        assert!(error(r#"ports = { allow = ["443/sctp"] }"#).contains("sctp"));
        assert!(error(r#"dest = { allow = ["not a host"] }"#).contains("not a host"));
    }

    #[test]
    fn sentinel_passes_validation_but_not_conversion() {
        let config: NetworkConfig =
            toml::from_str(r#"dest = { allow = ["...", "1.1.1.1"] }"#).unwrap();
        config.validate().unwrap();
        drop(NetworkPolicy::try_from(config).unwrap_err());

        let config: NetworkConfig = toml::from_str(r#"ports = { allow = ["..."] }"#).unwrap();
        config.validate().unwrap();
        drop(NetworkPolicy::try_from(config).unwrap_err());
    }

    /// Entries holding a variable are checked once it is expanded, not before.
    #[test]
    fn variables_pass_validation() {
        let config: NetworkConfig = toml::from_str(r#"dest = { allow = ["$HOST"] }"#).unwrap();
        config.validate().unwrap();

        let config: NetworkConfig = toml::from_str(r#"ports = { allow = ["$PORT"] }"#).unwrap();
        config.validate().unwrap();
    }
}
