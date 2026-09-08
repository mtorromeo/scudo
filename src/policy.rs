//! Enforcement policies requested for a sandboxed command.
//!
//! A policy is anything `scudo-bpfd` can enforce on the command's cgroup.
//! Network filtering is the first kind; the tagged union below is what lets
//! later kinds (file access, exec) be added without touching the wire protocol
//! or the shim.

pub mod filesystem;
pub mod network;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

pub use filesystem::{FilesystemConfig, FilesystemPolicy};
pub use network::{LogLevel, NetworkConfig, NetworkPolicy, OnUnavailable};

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
                        // back.
                        for socket in RESOLVED_SOCKETS {
                            props.push(("InaccessiblePaths".to_owned(), (*socket).to_owned()));
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
        props.extend(self.service_manager_properties());
        props
    }

    /// The properties that matter however the policy is realised.
    ///
    /// A command that can reach `systemd --user` can ask it to run something in
    /// a sibling cgroup, where none of our programs are attached and no
    /// `PrivateNetwork=` applies. That escape is two lines of shell, and it is
    /// open just as wide when the policy is realised by taking the network away
    /// as when the enforcer is doing the work — so these are not part of the
    /// enforcement path, and must not be skipped along with it. Both the private
    /// socket and the session bus lead there.
    #[must_use]
    pub fn service_manager_properties(&self) -> Vec<(String, String)> {
        match self {
            Policy::Network(policy) if policy.isolates_service_manager() => service_manager_paths()
                .into_iter()
                .map(|path| ("InaccessiblePaths".to_owned(), path))
                .collect(),
            // Watching a command is no reason to take anything away from it.
            Policy::Network(_) | Policy::Filesystem(_) => Vec::new(),
        }
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
pub fn apply(policies: &[Policy]) -> Result<Applied> {
    apply_with(policies, crate::bpfd::client::register)
}

/// The body of [`apply`], with the hand-off to the daemon injected so that the
/// decisions around it can be tested without one running.
fn apply_with<F>(policies: &[Policy], enforce: F) -> Result<Applied>
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
                    // The policy's own properties still apply — taking the
                    // network away is worth nothing while the command can ask
                    // `systemd --user` to start a sibling unit that has one.
                    push_property(&mut applied, "PrivateNetwork", "yes");
                    push_properties(&mut applied, &policy.service_manager_properties());
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
                push_properties(&mut applied, &policy.required_properties());
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

fn push_properties(applied: &mut Applied, properties: &[(String, String)]) {
    for (key, value) in properties {
        push_property(applied, key, value);
    }
}

/// The varlink sockets `nss-resolve` uses to reach systemd-resolved.
const RESOLVED_SOCKETS: &[&str] = &[
    "/run/systemd/resolve/io.systemd.Resolve",
    "/run/systemd/resolve/io.systemd.Resolve.Monitor",
];

/// The paths through which the user's service manager can be reached.
///
/// systemd puts both under `XDG_RUNTIME_DIR`; falling back to the documented
/// default keeps this working where that variable is not set.
fn service_manager_paths() -> Vec<String> {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| {
        // SAFETY: getuid always succeeds and touches no memory.
        let uid = unsafe { libc::getuid() };
        format!("/run/user/{uid}")
    });
    vec![
        format!("{runtime_dir}/systemd"),
        format!("{runtime_dir}/bus"),
    ]
}

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
            // As in the deny-all case: without the network there is nothing left
            // to filter, but the way out through the service manager is still
            // open, and it leads to a cgroup with a network.
            push_property(applied, "PrivateNetwork", "yes");
            for policy in policies {
                push_properties(applied, &policy.service_manager_properties());
            }
            applied.warnings.push(format!(
                "network policy not enforced ({reason}); running with no network"
            ));
        }
        OnUnavailable::Warn => {
            applied.warnings.push(format!(
                "network policy NOT enforced ({reason}); running unfiltered"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::network::NetworkConfig;

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
        let applied = apply_with(&[policy("")], unavailable).unwrap();
        assert!(has_arg(&applied.systemd_args, "PrivateNetwork=yes"));
        assert!(applied.warnings.is_empty());
    }

    /// Every way the network gets taken away without the enforcer.
    fn without_a_network() -> Vec<Applied> {
        vec![
            // Denied outright.
            apply_with(&[policy("")], unavailable).unwrap(),
            // Degraded to it because the daemon was not there.
            apply_with(
                &[policy(
                    r#"on_unavailable = "no-network"
dest.allow = ["1.1.1.1"]"#,
                )],
                unavailable,
            )
            .unwrap(),
        ]
    }

    /// `PrivateNetwork=yes` is worth nothing on its own: the command can ask
    /// `systemd --user` to start a sibling unit that has a network, and that is
    /// two lines of shell. The service manager has to go with it.
    #[test]
    fn taking_the_network_away_also_shuts_the_service_manager_out() {
        for applied in without_a_network() {
            let blocked: Vec<&String> = applied
                .systemd_args
                .iter()
                .filter(|arg| arg.starts_with("InaccessiblePaths="))
                .collect();
            assert!(
                blocked.iter().any(|p| p.ends_with("/systemd")),
                "no InaccessiblePaths for the private socket in {:?}",
                applied.systemd_args
            );
            assert!(
                blocked.iter().any(|p| p.ends_with("/bus")),
                "no InaccessiblePaths for the session bus in {:?}",
                applied.systemd_args
            );
        }
    }

    /// Opting out still works when there is no network to filter either.
    #[test]
    fn a_networkless_policy_can_still_keep_the_bus() {
        let applied = apply_with(&[policy(r#"service_manager = "allow""#)], unavailable).unwrap();
        assert!(has_arg(&applied.systemd_args, "PrivateNetwork=yes"));
        assert!(
            !applied
                .systemd_args
                .iter()
                .any(|arg| arg.starts_with("InaccessiblePaths="))
        );
    }

    /// Two policies asking for the same property leave one of it on the command
    /// line, not two.
    #[test]
    fn properties_are_not_repeated() {
        let applied = apply_with(&[policy(""), policy("")], unavailable).unwrap();
        let repeats = applied
            .systemd_args
            .iter()
            .filter(|arg| *arg == "PrivateNetwork=yes")
            .count();
        assert_eq!(repeats, 1);
    }

    #[test]
    fn unenforceable_policy_fails_closed_by_default() {
        let err = apply_with(&[policy(r#"dest.allow = ["1.1.1.1"]"#)], unavailable).unwrap_err();
        assert!(format!("{err:#}").contains("scudo-bpfd"));
    }

    #[test]
    fn no_network_degradation_drops_the_network() {
        let applied = apply_with(
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
            "/run/systemd/resolve/io.systemd.Resolve"
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
            "/run/systemd/resolve/io.systemd.Resolve"
        ));
    }

    /// Reaching `systemd --user` is a complete escape: it will happily start a
    /// command in a cgroup none of our programs are attached to.
    #[test]
    fn enforced_policy_shuts_the_service_manager_out() {
        let props = policy(r#"dest.allow = ["1.1.1.1"]"#).required_properties();
        let blocked: Vec<&String> = props
            .iter()
            .filter(|(k, _)| k == "InaccessiblePaths")
            .map(|(_, v)| v)
            .collect();
        assert!(blocked.iter().any(|p| p.ends_with("/systemd")));
        assert!(blocked.iter().any(|p| p.ends_with("/bus")));
    }

    /// When the daemon takes the policy, the command runs through the shim and
    /// gets the properties the policy depends on.
    #[test]
    fn an_enforced_policy_yields_a_token_and_its_properties() {
        let applied = apply_with(&[policy(r#"dest.allow = ["1.1.1.1"]"#)], available).unwrap();
        assert_eq!(applied.token.as_deref(), Some("token"));
        assert!(applied.warnings.is_empty());
        assert!(has_arg(&applied.systemd_args, "ProtectControlGroups=yes"));
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
        let applied = apply_with(&[lenient, strict], unavailable).unwrap();
        assert!(has_arg(&applied.systemd_args, "PrivateNetwork=yes"));
    }

    /// Opting out is possible, because blocking the session bus breaks plenty of
    /// legitimate programs.
    #[test]
    fn service_manager_access_can_be_granted() {
        let props = policy(
            r#"service_manager = "allow"
dest.allow = ["1.1.1.1"]"#,
        )
        .required_properties();
        assert!(!props.iter().any(|(k, _)| k == "InaccessiblePaths"));
    }

    /// Those properties belong to the enforcement path: a degraded policy must
    /// not restrict the command for nothing.
    #[test]
    fn degraded_policy_adds_no_support_properties() {
        let applied = apply_with(
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
