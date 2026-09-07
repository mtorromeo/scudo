//! What the sandbox turned away, as the side panel shows it.
//!
//! Two views of the same stream, because neither answers the other's question.
//! The tally says *what* a command could not reach, and stays readable when one
//! destination is retried a hundred times; the running list says *when*, which
//! is what tells a failed request apart from the one before it.
//!
//! The counts here are of events received, not of attempts made: the daemon
//! folds repeats of one refusal within a five second window before they ever
//! reach a watcher. Only the closing summary carries the real totals, which is
//! why it is kept and preferred over anything counted here.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use crate::bpfd::{protocol::Notification, report};

/// How many lines of history the running list keeps. Beyond this the oldest go:
/// the panel shows a few dozen at most, and the tally is what remembers.
const RECENT_MAX: usize = 500;

/// One destination, however often it came up.
#[derive(Debug, Clone)]
pub struct Target {
    pub label: String,
    pub count: u64,
    /// What was tried, in a word: `connect`, `sendmsg`, `dns`.
    pub detail: &'static str,
    last: Instant,
}

/// The closing figures, which only the daemon can give.
#[derive(Debug, Clone)]
struct Summary {
    targets: Vec<(String, u64)>,
    suppressed: u64,
    lost: u64,
}

#[derive(Debug, Default)]
pub struct Denials {
    targets: Vec<Target>,
    recent: VecDeque<(Instant, String)>,
    summary: Option<Summary>,
    received: u64,
    /// Set when the daemon closed the stream, which it does once the sandbox is
    /// gone. Nothing further can arrive after it.
    closed: bool,
}

impl Denials {
    /// Take in one notification. The summary ends the stream rather than joining
    /// it: it is a statement about everything above, not another refusal.
    pub fn push(&mut self, event: &Notification, command: &str) {
        if let Notification::Summary {
            targets,
            suppressed,
            lost,
        } = event
        {
            self.summary = Some(Summary {
                targets: targets.clone(),
                suppressed: *suppressed,
                lost: *lost,
            });
            self.closed = true;
            return;
        }

        self.received = self.received.saturating_add(1);
        let now = Instant::now();
        self.recent
            .push_back((now, report::describe(event, command)));
        while self.recent.len() > RECENT_MAX {
            self.recent.pop_front();
        }

        let Some(label) = event.target() else {
            return;
        };
        let detail = detail_of(event);
        if let Some(target) = self.targets.iter_mut().find(|t| t.label == label) {
            target.count = target.count.saturating_add(1);
            target.detail = detail;
            target.last = now;
        } else {
            self.targets.push(Target {
                label,
                count: 1,
                detail,
                last: now,
            });
        }
        // Most recent first: what a command is failing on right now is what the
        // person watching is looking for, and it is the line that would
        // otherwise be pushed off the bottom by an older, busier destination.
        self.targets
            .sort_by_key(|target| core::cmp::Reverse(target.last));
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Destinations, most recently refused first.
    #[must_use]
    pub fn targets(&self) -> &[Target] {
        &self.targets
    }

    /// The running list, oldest first, each with how long ago it arrived.
    pub fn recent(&self) -> impl DoubleEndedIterator<Item = (Duration, &str)> {
        let now = Instant::now();
        self.recent
            .iter()
            .map(move |(at, line)| (now.saturating_duration_since(*at), line.as_str()))
    }

    /// How many refusals reached us. Not how many were made — see the module note.
    #[must_use]
    pub fn received(&self) -> u64 {
        self.received
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty() && self.recent.is_empty()
    }

    /// The line printed on the way out, once the terminal is back.
    ///
    /// The daemon's own summary is used whenever it arrived, because it counted
    /// the attempts that were folded away before anything was sent. When the
    /// person watching pressed a key before it came, what we saw is all there
    /// is, and it says so rather than passing off a partial count as the total.
    #[must_use]
    pub fn summary_line(&self, command: &str) -> String {
        match &self.summary {
            Some(summary) => {
                report::summarise(command, &summary.targets, summary.suppressed, summary.lost)
            }
            None if self.targets.is_empty() => format!("{command}: nothing was blocked so far"),
            None => {
                let mut targets: Vec<(String, u64)> = self
                    .targets
                    .iter()
                    .map(|t| (t.label.clone(), t.count))
                    .collect();
                targets.sort_by_key(|&(_, count)| core::cmp::Reverse(count));
                format!(
                    "{} [counted while watching; the sandbox had not finished being torn down]",
                    report::summarise(command, &targets, 0, 0)
                )
            }
        }
    }
}

fn detail_of(event: &Notification) -> &'static str {
    match event {
        Notification::Blocked { stage, .. } => report::stage_name(*stage),
        Notification::DnsRefused { .. } => "dns",
        Notification::Summary { .. } => "",
    }
}

#[cfg(test)]
#[expect(
    clippy::default_numeric_fallback,
    reason = "counts and ports, spelled the way the assertions read best"
)]
mod tests {
    use crate::bpfd::protocol::{Stage, Transport};

    use super::*;

    fn blocked(addr: &str, port: u16) -> Notification {
        Notification::Blocked {
            stage: Stage::Connect,
            transport: Transport::Tcp,
            addr: addr.parse().expect("a valid test address"),
            port,
        }
    }

    #[test]
    fn repeats_of_one_destination_add_up_instead_of_stacking_up() {
        let mut denials = Denials::default();
        for _ in 0..3 {
            denials.push(&blocked("1.1.1.1", 443), "curl");
        }
        denials.push(&blocked("8.8.8.8", 53), "curl");

        assert_eq!(denials.targets().len(), 2);
        // Most recent first, whatever the counts say.
        let first = denials.targets().first().expect("a target");
        assert_eq!(first.label, "8.8.8.8:53");
        let repeated = denials
            .targets()
            .iter()
            .find(|t| t.label == "1.1.1.1:443")
            .expect("the repeated target");
        assert_eq!(repeated.count, 3);
        // The running list keeps every one of them.
        assert_eq!(denials.recent().count(), 4);
        assert_eq!(denials.received(), 4);
    }

    /// The daemon counted what we never saw, so its figures win.
    #[test]
    fn the_daemons_summary_is_preferred_over_what_was_watched() {
        let mut denials = Denials::default();
        denials.push(&blocked("1.1.1.1", 443), "curl");
        denials.push(
            &Notification::Summary {
                targets: vec![("1.1.1.1:443".to_owned(), 42)],
                suppressed: 41,
                lost: 0,
            },
            "curl",
        );
        assert!(denials.is_closed());
        assert_eq!(
            denials.summary_line("curl"),
            "curl: blocked 1.1.1.1:443 (42x) [41 repeats suppressed]"
        );
    }

    /// Quitting early must not pass off what we happened to see as the total.
    #[test]
    fn a_summary_that_never_arrived_says_that_it_is_partial() {
        let mut denials = Denials::default();
        denials.push(&blocked("1.1.1.1", 443), "curl");
        let line = denials.summary_line("curl");
        assert!(line.starts_with("curl: blocked 1.1.1.1:443 (1x)"), "{line}");
        assert!(line.contains("counted while watching"), "{line}");
    }

    #[test]
    fn a_run_with_nothing_blocked_and_no_summary_yet_does_not_claim_otherwise() {
        let denials = Denials::default();
        assert_eq!(
            denials.summary_line("curl"),
            "curl: nothing was blocked so far"
        );
    }
}
