//! Enforcement policies requested for a sandboxed command.
//!
//! A policy is anything `scudo-bpfd` can enforce on the command's cgroup.
//! Network filtering is the first kind; the tagged union below is what lets
//! later kinds (file access, exec) be added without touching the wire protocol
//! or the shim.

pub mod dbus;
pub mod filesystem;
pub mod network;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

pub use dbus::{DbusConfig, Session};
pub use filesystem::{Access, FilesystemConfig, FilesystemPolicy, mount_properties};
pub use network::{LogLevel, NetworkConfig, NetworkOverrides, NetworkPolicy, OnUnavailable};

/// A single enforcement policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Policy {
    Network(NetworkPolicy),
    /// Reporting only: systemd applies the filesystem restrictions and this
    /// asks the daemon to say which paths they turned away.
    Filesystem(FilesystemPolicy),
}

impl Policy {
    /// `true` when this policy asks for the accesses it refuses to be reported.
    #[must_use]
    pub fn reports_denials(&self) -> bool {
        match self {
            Policy::Network(policy) => policy.reports_denials(),
            Policy::Filesystem(policy) => policy.reports_denials(),
        }
    }

    /// `true` when this policy restricts nothing and is only there to report.
    ///
    /// A filesystem policy is always one — systemd applies the restrictions and
    /// this only watches — and so is a network observer, which sits beside a
    /// sandbox `PrivateNetwork=yes` already closed.
    #[must_use]
    pub fn observes_only(&self) -> bool {
        match self {
            Policy::Network(policy) => policy.observe_only,
            Policy::Filesystem(_) => true,
        }
    }

    /// Turn reporting on, whatever the profile asked for. This is what
    /// `--verbose` does: the flag can only ever make scudo louder.
    pub fn report_denials(&mut self) {
        match self {
            Policy::Network(policy) => policy.log = policy.log.max(LogLevel::Denied),
            Policy::Filesystem(policy) => policy.log = policy.log.max(LogLevel::Denied),
        }
    }

    /// The systemd unit properties this policy requires in order to be
    /// enforceable. They are added on top of whatever the profile itself sets.
    ///
    /// These are not the policy: they are the things without which the policy
    /// could be walked around.
    #[must_use]
    pub fn required_properties(&self) -> Vec<(String, String)> {
        let mut props: Vec<(String, String)> = Vec::new();
        match self {
            Policy::Network(policy) => {
                if policy.requires_enforcer() {
                    // Keep the command from migrating out of the cgroup the eBPF
                    // programs are attached to.
                    props.push(("ProtectControlGroups".to_owned(), "yes".to_owned()));

                    if policy.needs_resolver() {
                        // nss-resolve talks to systemd-resolved over these
                        // varlink sockets, which no network hook can see — so a
                        // lookup made that way neither obeys the rules nor
                        // teaches the policy the address it resolved to. Only
                        // the sockets are taken away, not the directory around
                        // them: /etc/resolv.conf is a symlink into it, and
                        // programs that cannot read it give up rather than fall
                        // back. Where resolved is not running the sockets are
                        // not there to go around, and the `-` keeps systemd
                        // from refusing to start the unit over their absence.
                        for socket in RESOLVED_SOCKETS {
                            props.push(("InaccessiblePaths".to_owned(), format!("-{socket}")));
                        }
                    }
                }
            }
            // Nothing is being enforced, so nothing has to be shut off to keep
            // it enforceable — except the one property that decides whether the
            // programs see the command at all: the events are matched on the
            // cgroup they came from, and a command that can move itself out of
            // that cgroup simply stops being reported.
            Policy::Filesystem(policy) => {
                if policy.reports_denials() {
                    props.push(("ProtectControlGroups".to_owned(), "yes".to_owned()));
                }
            }
        }
        props
    }
}

/// What applying a set of policies produced.
#[derive(Debug, Default)]
pub struct Applied {
    /// Extra `systemd-run` arguments needed to realise the policies.
    pub systemd_args: Vec<String>,
    /// Messages to show the user: a policy was weakened, or dropped entirely.
    pub warnings: Vec<String>,
    /// Set when the daemon is holding policies for us: the command must then be
    /// started through the shim, which claims them from inside the cgroup.
    pub token: Option<String>,
}

/// Realise `policies`, returning the systemd properties they need.
///
/// A policy that only denies is realised by systemd alone. Anything finer needs
/// `scudo-bpfd`; when it cannot be reached the policy's `on_unavailable` decides
/// whether to refuse, drop the network entirely, or run unfiltered.
///
/// `explicit` holds the arguments the profile itself produced: a property it
/// sets outright is its own decision and is not overwritten here (see
/// [`overridden`]).
pub fn apply(policies: &[Policy], explicit: &[String]) -> Result<Applied> {
    apply_with(explicit, policies, crate::bpfd::client::register)
}

/// The body of [`apply`], with the hand-off to the daemon injected so that the
/// decisions around it can be tested without one running.
fn apply_with<F>(explicit: &[String], policies: &[Policy], enforce: F) -> Result<Applied>
where
    F: FnOnce(&[Policy]) -> Result<String>,
{
    let mut applied = Applied::default();
    let mut to_enforce: Vec<Policy> = Vec::new();

    for policy in policies {
        match policy {
            Policy::Network(net) => {
                if net.is_unrestricted() {
                    continue;
                }
                if net.is_deny_all() {
                    // No enforcer needed: systemd can take the network away.
                    push_property(&mut applied, "PrivateNetwork", "yes");
                    // The netns enforces, but it cannot say what it turned away.
                    // An observer attached beside it can, and enforces nothing
                    // the netns was not enforcing already.
                    if let Some(observer) = net.observer() {
                        to_enforce.push(Policy::Network(observer));
                    }
                    continue;
                }
                to_enforce.push(policy.clone());
            }
            Policy::Filesystem(fs) => {
                if !fs.reports_denials() {
                    continue;
                }
                to_enforce.push(policy.clone());
            }
        }
    }

    if to_enforce.is_empty() {
        return Ok(applied);
    }

    match enforce(&to_enforce) {
        Ok(token) => {
            applied.token = Some(token);
            for policy in &to_enforce {
                push_required(&mut applied, policy, explicit);
            }
        }
        Err(err) => degrade(&mut applied, &to_enforce, &format!("{err:#}"))?,
    }

    Ok(applied)
}

/// Add `-p key=value`, unless it is already there.
///
/// Two policies asking for the same property is ordinary — every one of them
/// wants the service manager shut out — and systemd would take the repetition,
/// but a command line nobody can read is its own kind of bug.
fn push_property(applied: &mut Applied, key: &str, value: &str) {
    let arg = format!("{key}={value}");
    if applied.systemd_args.contains(&arg) {
        return;
    }
    applied.systemd_args.push("-p".to_owned());
    applied.systemd_args.push(arg);
}

/// Add what `policy` needs to stay enforceable, short of anything the profile
/// decided for itself — and say what that decision costs.
fn push_required(applied: &mut Applied, policy: &Policy, explicit: &[String]) {
    for (key, value) in policy.required_properties() {
        if !overridden(explicit, &key) {
            push_property(applied, &key, &value);
            continue;
        }
        if still_confined(explicit, &key, policy.observes_only()) {
            continue;
        }
        let warning = if policy.observes_only() {
            format!("{key} is set by the profile; blocked accesses may go unreported")
        } else {
            format!(
                "{key} is set by the profile; the command can leave its cgroup and walk \
                 around the network policy"
            )
        };
        if !applied.warnings.contains(&warning) {
            applied.warnings.push(warning);
        }
    }
}

/// Whether a property scudo would add is one the profile already decided.
///
/// Only single-valued properties are ever overwritten — systemd keeps the last
/// one — so only those are left alone. Lists accumulate: adding to
/// `InaccessiblePaths=` takes nothing away from the entries the profile wrote.
#[must_use]
pub fn overridden(explicit: &[String], key: &str) -> bool {
    !accumulates(key) && crate::runner::sets_property(explicit, key)
}

/// Whether the value the profile chose for `key` keeps the command where scudo
/// wanted it anyway, so overriding scudo's own value costs nothing worth a
/// warning.
///
/// Only `ProtectControlGroups=` has values that qualify. `private` and `strict`
/// put the unit in a cgroup namespace rooted at its own cgroup, and with the
/// hierarchy mounted `nsdelegate` — as systemd mounts it — the kernel refuses
/// every migration across that root: that confines it better than `yes`.
/// `private` does leave the subtree writable, though, and a process moved into a
/// sub-cgroup is still under every program attached above it but no longer in
/// the one cgroup the filesystem monitor matches exactly. So it is enough for an
/// enforced policy and not for one that only reports.
#[must_use]
pub fn still_confined(explicit: &[String], key: &str, observes_only: bool) -> bool {
    if key != "ProtectControlGroups" {
        return false;
    }
    let Some(value) = crate::runner::property_value(explicit, key) else {
        return false;
    };
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" | "strict" => true,
        "private" => !observes_only,
        _ => false,
    }
}

/// The properties scudo adds to that accumulate rather than replace.
fn accumulates(key: &str) -> bool {
    matches!(
        key,
        "InaccessiblePaths" | "BindPaths" | "BindReadOnlyPaths" | "Wants" | "After" | "Environment"
    )
}

/// The varlink sockets `nss-resolve` uses to reach systemd-resolved.
const RESOLVED_SOCKETS: &[&str] = &[
    "/run/systemd/resolve/io.systemd.Resolve",
    "/run/systemd/resolve/io.systemd.Resolve.Monitor",
];

/// Weaken the policies that could not be enforced.
///
/// With several policies in play the strictest `on_unavailable` wins: a profile
/// that asked to fail closed must not be talked out of it by another one that
/// was content to run unfiltered.
fn degrade(applied: &mut Applied, policies: &[Policy], reason: &str) -> Result<()> {
    let strictest = policies
        .iter()
        .map(|policy| match policy {
            Policy::Network(net) => net.on_unavailable,
            // Not being able to watch a command is never a reason not to run
            // it. `min` takes the strictest, so this can only ever lose to a
            // network policy that asked for more.
            Policy::Filesystem(_) => OnUnavailable::Warn,
        })
        .min()
        .unwrap_or_default();
    degrade_to(applied, policies, strictest, reason)
}

fn degrade_to(
    applied: &mut Applied,
    policies: &[Policy],
    on_unavailable: OnUnavailable,
    reason: &str,
) -> Result<()> {
    match on_unavailable {
        OnUnavailable::Fail => {
            bail!("cannot enforce the network policy: {reason}")
        }
        OnUnavailable::NoNetwork => {
            push_property(applied, "PrivateNetwork", "yes");
            applied.warnings.push(format!(
                "network policy not enforced ({reason}); running with no network"
            ));
        }
        OnUnavailable::Warn => {
            // An observer takes nothing away, so losing it costs the reporting
            // and nothing else; saying the command runs unfiltered would be
            // plainly false when the network was taken away by systemd.
            if policies.iter().all(Policy::observes_only) {
                applied.warnings.push(format!(
                    "cannot report blocked accesses ({reason}); the policy is \
                     still enforced"
                ));
            } else {
                applied.warnings.push(format!(
                    "network policy NOT enforced ({reason}); running unfiltered"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::network::{NetworkConfig, symbolic_net};

    fn policy(src: &str) -> Policy {
        let config: NetworkConfig = toml::from_str(src).unwrap();
        Policy::Network(NetworkPolicy::try_from(config).unwrap())
    }

    /// An enforcer that is not there.
    fn unavailable(_: &[Policy]) -> Result<String> {
        anyhow::bail!("scudo-bpfd is not available")
    }

    /// An enforcer that accepts everything. Its signature has to match the real
    /// one, hence the `Result` it never uses.
    #[expect(clippy::unnecessary_wraps)]
    fn available(_: &[Policy]) -> Result<String> {
        Ok("token".to_owned())
    }

    fn has_arg(args: &[String], value: &str) -> bool {
        args.windows(2)
            .any(|w| w.first().is_some_and(|f| f == "-p") && w.get(1).is_some_and(|v| v == value))
    }

    /// Denying everything needs no enforcer: systemd can do it on its own.
    #[test]
    fn deny_all_becomes_private_network() {
        let applied = apply_with(&[], &[policy("")], unavailable).unwrap();
        assert!(has_arg(&applied.systemd_args, "PrivateNetwork=yes"));
        assert!(applied.warnings.is_empty());
        // Nobody asked to be told, so nothing was registered.
        assert!(applied.token.is_none());
    }

    /// A deny-all policy that asked to be told keeps the network namespace and
    /// gains an observer beside it: enforcement is unchanged, and the refusals
    /// now have something to report them.
    #[test]
    fn a_watched_deny_all_keeps_the_namespace_and_gains_an_observer() {
        let mut seen: Vec<Policy> = Vec::new();
        let applied = apply_with(&[], &[policy(r#"log = "denied""#)], |policies| {
            seen = policies.to_vec();
            Ok("token".to_owned())
        })
        .unwrap();

        assert!(has_arg(&applied.systemd_args, "PrivateNetwork=yes"));
        assert_eq!(applied.token.as_deref(), Some("token"));
        assert!(applied.warnings.is_empty());

        assert_eq!(seen.len(), 1);
        let observer = seen
            .iter()
            .find_map(|policy| match policy {
                Policy::Network(net) => Some(net),
                Policy::Filesystem(_) => None,
            })
            .unwrap();
        assert!(observer.observe_only);
        assert!(observer.reports_denials());
        // What the empty netns already permits, and nothing more.
        assert_eq!(observer.dest.allow, symbolic_net("localhost").unwrap());
    }

    /// Losing the observer costs the reporting and nothing else, so even a
    /// policy that asked to fail closed still runs: the network was taken away
    /// by systemd, and it is still gone.
    #[test]
    fn a_watched_deny_all_still_runs_without_the_daemon() {
        let applied = apply_with(
            &[],
            &[policy(
                r#"log = "denied"
on_unavailable = "fail""#,
            )],
            unavailable,
        )
        .unwrap();

        assert!(has_arg(&applied.systemd_args, "PrivateNetwork=yes"));
        assert!(applied.token.is_none());
        assert_eq!(applied.warnings.len(), 1);
        assert!(
            applied
                .warnings
                .iter()
                .any(|warning| warning.contains("cannot report blocked accesses")),
            "unexpected warnings: {:?}",
            applied.warnings
        );
    }

    /// An observer must not talk a real policy out of failing closed: the
    /// strictest `on_unavailable` still wins.
    #[test]
    fn an_observer_does_not_soften_a_policy_that_asked_to_fail() {
        let err = apply_with(
            &[],
            &[
                policy(r#"log = "denied""#),
                policy(
                    r#"on_unavailable = "fail"
dest.allow = ["1.1.1.1"]"#,
                ),
            ],
            unavailable,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot enforce the network policy"),
            "unexpected error: {err}"
        );
    }

    /// Two policies asking for the same property leave one of it on the command
    /// line, not two.
    #[test]
    fn properties_are_not_repeated() {
        let applied = apply_with(&[], &[policy(""), policy("")], unavailable).unwrap();
        let repeats = applied
            .systemd_args
            .iter()
            .filter(|arg| *arg == "PrivateNetwork=yes")
            .count();
        assert_eq!(repeats, 1);
    }

    #[test]
    fn unenforceable_policy_fails_closed_by_default() {
        let err =
            apply_with(&[], &[policy(r#"dest.allow = ["1.1.1.1"]"#)], unavailable).unwrap_err();
        assert!(format!("{err:#}").contains("scudo-bpfd"));
    }

    #[test]
    fn no_network_degradation_drops_the_network() {
        let applied = apply_with(
            &[],
            &[policy(
                r#"on_unavailable = "no-network"
dest.allow = ["1.1.1.1"]"#,
            )],
            unavailable,
        )
        .unwrap();
        assert!(has_arg(&applied.systemd_args, "PrivateNetwork=yes"));
        assert_eq!(applied.warnings.len(), 1);
    }

    #[test]
    fn warn_degradation_runs_unfiltered() {
        let applied = apply_with(
            &[],
            &[policy(
                r#"on_unavailable = "warn"
dest.allow = ["1.1.1.1"]"#,
            )],
            unavailable,
        )
        .unwrap();
        assert!(applied.systemd_args.is_empty());
        assert_eq!(applied.warnings.len(), 1);
    }

    fn has_property(props: &[(String, String)], key: &str, value: &str) -> bool {
        props.iter().any(|(k, v)| k == key && v == value)
    }

    /// Pinning the cgroup is what keeps the command from stepping out of the
    /// one the eBPF programs are attached to.
    #[test]
    fn enforced_policy_requires_the_cgroup_to_be_pinned() {
        let props = policy(r#"dest.allow = ["1.1.1.1"]"#).required_properties();
        assert!(has_property(&props, "ProtectControlGroups", "yes"));
    }

    /// Naming a host is worth nothing while nss-resolve can still reach
    /// resolved over its varlink socket, which no network hook sees: the lookup
    /// would go around the resolver, and the rule would never learn an address.
    #[test]
    fn host_rules_close_the_varlink_path() {
        let props = policy(r#"dest.allow = ["api.github.com"]"#).required_properties();
        assert!(has_property(
            &props,
            "InaccessiblePaths",
            "-/run/systemd/resolve/io.systemd.Resolve"
        ));
    }

    /// A policy written only in addresses needs no resolver, so it has no
    /// reason to take the varlink sockets away.
    #[test]
    fn an_address_only_policy_leaves_the_varlink_path_alone() {
        let props = policy(r#"dest.allow = ["1.1.1.1"]"#).required_properties();
        assert!(!has_property(
            &props,
            "InaccessiblePaths",
            "-/run/systemd/resolve/io.systemd.Resolve"
        ));
    }

    /// When the daemon takes the policy, the command runs through the shim and
    /// gets the properties the policy depends on.
    #[test]
    fn an_enforced_policy_yields_a_token_and_its_properties() {
        let applied = apply_with(&[], &[policy(r#"dest.allow = ["1.1.1.1"]"#)], available).unwrap();
        assert_eq!(applied.token.as_deref(), Some("token"));
        assert!(applied.warnings.is_empty());
        assert!(has_arg(&applied.systemd_args, "ProtectControlGroups=yes"));
    }

    fn explicit(args: &[&str]) -> Vec<String> {
        args.iter().map(ToString::to_string).collect()
    }

    /// A property the profile set itself is its decision, and systemd keeps
    /// the last one: appending ours would quietly take it back.
    #[test]
    fn a_property_the_profile_set_is_not_overwritten() {
        let profile = explicit(&["-p", "ProtectControlGroups=no"]);
        let applied = apply_with(
            &profile,
            &[policy(r#"dest.allow = ["1.1.1.1"]"#)],
            available,
        )
        .unwrap();
        assert!(!has_arg(&applied.systemd_args, "ProtectControlGroups=yes"));
        assert_eq!(applied.warnings.len(), 1);
    }

    /// A cgroup namespace keeps the command in its cgroup as well as `yes`
    /// does, so choosing one costs an enforced policy nothing to warn about —
    /// but `private` lets it into sub-cgroups the file monitor does not see.
    #[test]
    fn a_cgroup_namespace_the_profile_chose_is_not_warned_about() {
        let warnings = |value: &str, policy: Policy| {
            let profile = explicit(&["-p", &format!("ProtectControlGroups={value}")]);
            apply_with(&profile, &[policy], available).unwrap().warnings
        };
        let net = || policy(r#"dest.allow = ["1.1.1.1"]"#);
        let fs = || {
            Policy::Filesystem(FilesystemPolicy {
                log: LogLevel::Denied,
            })
        };
        assert_eq!(warnings("private", net()), Vec::<String>::new());
        assert_eq!(warnings("strict", net()), Vec::<String>::new());
        assert_eq!(warnings("strict", fs()), Vec::<String>::new());
        assert_eq!(warnings("private", fs()).len(), 1);
        assert_eq!(warnings("no", net()).len(), 1);
    }

    /// Lists accumulate, so a profile that hides paths of its own still gets
    /// the ones the policy needs hidden.
    #[test]
    fn a_list_the_profile_set_is_still_added_to() {
        let profile = explicit(&["-p", "InaccessiblePaths=/srv"]);
        let applied = apply_with(
            &profile,
            &[policy(r#"dest.allow = ["api.github.com"]"#)],
            available,
        )
        .unwrap();
        assert!(has_arg(
            &applied.systemd_args,
            "InaccessiblePaths=-/run/systemd/resolve/io.systemd.Resolve"
        ));
        assert!(applied.warnings.is_empty());
    }

    /// `PrivateNetwork=yes` is not something the policy needs: it is the
    /// policy. A profile saying `no` beside `deny all` does not open the network.
    #[test]
    fn deny_all_is_not_overridden_by_the_profile() {
        let profile = explicit(&["-p", "PrivateNetwork=no"]);
        let applied = apply_with(&profile, &[policy("")], unavailable).unwrap();
        assert!(has_arg(&applied.systemd_args, "PrivateNetwork=yes"));
    }

    /// The properties scudo adds that hold a single value: the profile's own
    /// setting replaces scudo's, which is the point of leaving them out of
    /// [`accumulates`].
    const SINGLE_VALUED: &[&str] = &["ProtectControlGroups"];

    /// Every property scudo adds is either a list, which [`accumulates`] has to
    /// name, or one of [`SINGLE_VALUED`]. A list missing from `accumulates` is
    /// dropped whenever the profile writes to it as well, and the warning
    /// that comes with it describes a different property.
    pub(super) fn assert_classified(key: &str) {
        assert!(
            accumulates(key) ^ SINGLE_VALUED.contains(&key),
            "{key} is added by scudo but is in neither accumulates() nor SINGLE_VALUED"
        );
    }

    #[test]
    fn every_required_property_is_classified() {
        let policies = [
            policy(r#"dest.allow = ["1.1.1.1", "example.com"]"#),
            Policy::Filesystem(FilesystemPolicy {
                log: LogLevel::Denied,
            }),
        ];
        let keys: Vec<String> = policies
            .iter()
            .flat_map(Policy::required_properties)
            .map(|(key, _)| key)
            .collect();
        assert_ne!(keys.len(), 0);
        for key in &keys {
            assert_classified(key);
        }
    }

    /// A list the profile writes to is added to, not taken over: the sealed
    /// marker is a `BindReadOnlyPaths=` entry, and a profile binding files of
    /// its own must not lose it.
    #[test]
    fn list_properties_are_never_overridden() {
        let profile = explicit(&["-p", "BindReadOnlyPaths=/etc/hosts"]);
        assert!(!overridden(&profile, "BindReadOnlyPaths"));
        assert!(!overridden(&profile, "InaccessiblePaths"));
    }

    /// The strictest `on_unavailable` wins: a profile that asked to fail closed
    /// must not be talked out of it by one that was content to run unfiltered.
    #[test]
    fn the_strictest_degradation_wins() {
        let lenient = policy(
            r#"on_unavailable = "warn"
dest.allow = ["1.1.1.1"]"#,
        );
        let strict = policy(
            r#"on_unavailable = "no-network"
dest.allow = ["2.2.2.2"]"#,
        );
        let applied = apply_with(&[], &[lenient, strict], unavailable).unwrap();
        assert!(has_arg(&applied.systemd_args, "PrivateNetwork=yes"));
    }

    /// Those properties belong to the enforcement path: a degraded policy must
    /// not restrict the command for nothing.
    #[test]
    fn degraded_policy_adds_no_support_properties() {
        let applied = apply_with(
            &[],
            &[policy(
                r#"on_unavailable = "warn"
dest.allow = ["1.1.1.1", "example.com"]"#,
            )],
            unavailable,
        )
        .unwrap();
        assert!(applied.systemd_args.is_empty());
    }
}
