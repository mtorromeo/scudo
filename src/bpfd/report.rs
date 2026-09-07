//! Turning a [`Notification`] into something a person reads.
//!
//! Two consumers need exactly the same words: the watcher process, which logs
//! each refusal as it arrives, and the terminal UI, which lists them in a panel
//! and closes with the same summary. Keeping the wording here is what stops the
//! two from drifting apart.

use tracing::{info, warn};

use crate::bpfd::protocol::{Notification, Stage, Transport};

/// How many refused targets the closing summary names before it gives up.
pub const SUMMARY_TARGETS: usize = 5;

/// Say what the sandbox turned away.
///
/// The human sentence is the message, unchanged, so stderr reads as it always
/// did; the parts it is made of go alongside it as fields, which is what
/// journald and syslog consumers can actually filter on.
pub fn report(event: &Notification, command: &str) {
    let line = describe(event, command);
    match event {
        Notification::Blocked {
            stage,
            transport,
            addr,
            port,
        } => warn!(
            %addr,
            port,
            stage = stage_name(*stage),
            transport = transport_name(*transport),
            "{line}"
        ),
        Notification::DnsRefused { name, .. } => warn!(name, "{line}"),
        // The closing line of a run that was watched: not a problem in itself,
        // and the one thing said even when nothing was blocked at all.
        Notification::Summary {
            suppressed, lost, ..
        } => info!(suppressed, lost, "{line}"),
    }
}

#[must_use]
pub fn stage_name(stage: Stage) -> &'static str {
    match stage {
        Stage::Connect => "connect",
        Stage::Sendmsg => "sendmsg",
        Stage::Egress => "egress",
        Stage::Ingress => "ingress",
    }
}

#[must_use]
pub fn transport_name(transport: Transport) -> &'static str {
    match transport {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
        Transport::Other => "other",
    }
}

/// One line of output for one notification.
#[must_use]
pub fn describe(event: &Notification, command: &str) -> String {
    match event {
        Notification::Blocked {
            stage,
            transport,
            addr,
            ..
        } => {
            let target = format!(
                "{}{}",
                event.target().unwrap_or_else(|| addr.to_string()),
                match transport {
                    Transport::Tcp => "/tcp",
                    Transport::Udp => "/udp",
                    // Nothing with a port, so nothing to qualify.
                    Transport::Other => "",
                }
            );
            match stage {
                Stage::Connect => format!("blocked connect to {target}"),
                Stage::Sendmsg => format!("blocked sendmsg to {target}"),
                Stage::Egress => format!("blocked packet to {target}"),
                Stage::Ingress => format!("blocked packet from {target}"),
            }
        }
        Notification::DnsRefused { name, reason } => {
            format!("blocked DNS lookup of {name} ({reason})")
        }
        Notification::Summary {
            targets,
            suppressed,
            lost,
        } => summarise(command, targets, *suppressed, *lost),
    }
}

/// The closing line: what was refused, how often, and what was not shown.
#[must_use]
pub fn summarise(command: &str, targets: &[(String, u64)], suppressed: u64, lost: u64) -> String {
    if targets.is_empty() {
        return format!("{command}: nothing was blocked");
    }
    let mut named: Vec<String> = targets
        .iter()
        .take(SUMMARY_TARGETS)
        .map(|(target, count)| format!("{target} ({count}x)"))
        .collect();
    if let Some(rest) = targets.len().checked_sub(SUMMARY_TARGETS)
        && rest > 0
    {
        named.push(format!("and {rest} more"));
    }
    // Repeats folded together are worth saying so the counts above add up;
    // events that never arrived are worth saying because they are missing.
    let mut notes = Vec::new();
    if suppressed > 0 {
        notes.push(format!("{suppressed} repeats suppressed"));
    }
    if lost > 0 {
        notes.push(format!("{lost} events lost"));
    }
    let trailer = if notes.is_empty() {
        String::new()
    } else {
        format!(" [{}]", notes.join(", "))
    };
    format!("{command}: blocked {}{trailer}", named.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(stage: Stage, transport: Transport, addr: &str, port: u16) -> Notification {
        Notification::Blocked {
            stage,
            transport,
            addr: addr.parse().expect("a valid test address"),
            port,
        }
    }

    #[test]
    fn each_stage_says_what_it_did_and_which_way_round() {
        let line =
            |stage, transport, addr, port| describe(&blocked(stage, transport, addr, port), "curl");
        assert_eq!(
            line(Stage::Connect, Transport::Tcp, "1.1.1.1", 443),
            "blocked connect to 1.1.1.1:443/tcp"
        );
        assert_eq!(
            line(Stage::Sendmsg, Transport::Udp, "8.8.8.8", 53),
            "blocked sendmsg to 8.8.8.8:53/udp"
        );
        // On ingress the address is where it came from, not where it was going.
        assert_eq!(
            line(Stage::Ingress, Transport::Tcp, "10.0.0.5", 80),
            "blocked packet from 10.0.0.5:80/tcp"
        );
        // ICMP has no port and no transport to name.
        assert_eq!(
            line(Stage::Egress, Transport::Other, "10.0.0.5", 0),
            "blocked packet to 10.0.0.5"
        );
    }

    #[test]
    fn a_refused_lookup_says_why() {
        let event = Notification::DnsRefused {
            name: "ads.example".to_owned(),
            reason: "no rule names it".to_owned(),
        };
        assert_eq!(
            describe(&event, "curl"),
            "blocked DNS lookup of ads.example (no rule names it)"
        );
    }

    /// Silence would be ambiguous: it reads the same as the reporting having
    /// failed to start.
    #[test]
    fn a_run_that_was_never_blocked_says_so() {
        assert_eq!(summarise("curl", &[], 0, 0), "curl: nothing was blocked");
    }

    #[test]
    fn the_summary_counts_attempts_and_owns_up_to_what_it_dropped() {
        let targets = vec![
            ("1.1.1.1:443".to_owned(), 42),
            ("ads.example".to_owned(), 4),
        ];
        assert_eq!(
            summarise("curl", &targets, 39, 2),
            "curl: blocked 1.1.1.1:443 (42x), ads.example (4x) [39 repeats suppressed, 2 events lost]"
        );
        // Nothing hidden, nothing to add.
        assert_eq!(
            summarise("curl", &targets, 0, 0),
            "curl: blocked 1.1.1.1:443 (42x), ads.example (4x)"
        );
    }

    /// A command that was refused everywhere must not fill the screen with its
    /// own summary.
    #[test]
    fn a_long_summary_is_cut_short_rather_than_scrolled() {
        let targets: Vec<(String, u64)> = (0..SUMMARY_TARGETS + 3)
            .map(|i| (format!("10.0.0.{i}:443"), 1))
            .collect();
        let line = summarise("curl", &targets, 0, 0);
        assert!(line.ends_with("and 3 more"), "{line}");
        assert_eq!(line.matches("10.0.0.").count(), SUMMARY_TARGETS);
    }
}
