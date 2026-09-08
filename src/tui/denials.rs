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
//!
//! **Not everything that arrives was blocked.** A file access that failed on a
//! path missing outside the sandbox too is a program searching, not a program
//! being refused, and there are hundreds of those in an ordinary run. They are
//! kept — every one of them — and simply not shown until asked for, because a
//! toggle that only revealed what arrived after it was pressed would answer the
//! wrong question.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use crate::bpfd::{protocol::Notification, report};

/// How many lines of history the running list keeps. Beyond this the oldest go:
/// the panel shows a few dozen at most, and the tally is what remembers.
const RECENT_MAX: usize = 500;

/// How many distinct subjects the tally follows.
///
/// The network side never needed a bound — a command reaches a handful of
/// addresses. Paths are not like that: one `bat` under a sandboxed `$HOME`
/// names hundreds, and a build names thousands. Past this the least recently
/// refused is dropped, which costs the bottom of a list nobody was reading.
const TARGETS_MAX: usize = 200;

/// One destination, however often it came up.
#[derive(Debug, Clone)]
pub struct Target {
    pub label: String,
    pub count: u64,
    /// What was tried, in a word: `connect`, `sendmsg`, `dns`, `open`.
    pub detail: &'static str,
    /// Whether the sandbox is the reason. `false` marks a path that was not
    /// there outside it either, which the panel dims and hides by default.
    pub denial: bool,
    last: Instant,
}

/// One line of the running list.
#[derive(Debug, Clone)]
struct Recent {
    at: Instant,
    line: String,
    denial: bool,
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
    recent: VecDeque<Recent>,
    summary: Option<Summary>,
    blocked: u64,
    /// Whether the panel shows what was never there outside the sandbox. Off by
    /// default: a single `node` or `cc` produces hundreds of those, and they
    /// would bury the handful of lines that are the reason to look.
    show_missing: bool,
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

        let now = Instant::now();
        let denial = event.is_denial();
        if denial {
            self.blocked = self.blocked.saturating_add(1);
        }
        self.recent.push_back(Recent {
            at: now,
            line: report::describe(event, command),
            denial,
        });
        while self.recent.len() > RECENT_MAX {
            evict(&mut self.recent);
        }

        // `label` rather than `target`: the tally lists what the command could
        // not have, and a miss belongs in it too — dimmed, and behind the
        // toggle. `target` is the narrower question the summary asks.
        let Some(label) = event.label() else {
            return;
        };
        let detail = detail_of(event);
        // Most recent first, kept that way by moving the one that was just
        // refused to the front rather than by sorting the list again. Sorting
        // per event is what made a panel watching a program probe a thousand
        // paths cost more than the program did.
        match self.targets.iter().position(|t| t.label == label) {
            Some(index) => {
                let mut target = self.targets.remove(index);
                target.count = target.count.saturating_add(1);
                target.detail = detail;
                target.denial = denial;
                target.last = now;
                self.targets.insert(0, target);
            }
            None => self.targets.insert(
                0,
                Target {
                    label,
                    count: 1,
                    detail,
                    denial,
                    last: now,
                },
            ),
        }
        while self.targets.len() > TARGETS_MAX {
            drop_one(&mut self.targets);
        }
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Show or hide what was missing outside the sandbox too.
    pub fn toggle_missing(&mut self) {
        self.show_missing = !self.show_missing;
    }

    /// How many lines the toggle is currently keeping back. Zero once it is on,
    /// which is what lets the heading stop mentioning it.
    #[must_use]
    pub fn hidden(&self) -> usize {
        if self.show_missing {
            return 0;
        }
        self.targets.iter().filter(|t| !t.denial).count()
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Destinations, most recently refused first.
    pub fn targets(&self) -> impl DoubleEndedIterator<Item = &Target> {
        let show_missing = self.show_missing;
        self.targets
            .iter()
            .filter(move |target| show_missing || target.denial)
    }

    /// How many of them there are to draw.
    #[must_use]
    pub fn shown(&self) -> usize {
        self.targets().count()
    }

    /// The running list, oldest first, each with how long ago it arrived and
    /// whether the sandbox was the reason.
    pub fn recent(&self) -> impl DoubleEndedIterator<Item = (Duration, &str, bool)> {
        let now = Instant::now();
        let show_missing = self.show_missing;
        self.recent
            .iter()
            .filter(move |entry| show_missing || entry.denial)
            .map(move |entry| {
                (
                    now.saturating_duration_since(entry.at),
                    entry.line.as_str(),
                    entry.denial,
                )
            })
    }

    /// How many refusals reached us. Not how many were made — see the module
    /// note — and not how many events arrived: a run where a program probed
    /// three hundred library paths did not have three hundred things taken away
    /// from it, and the status bar saying so would be the panel's least useful
    /// moment.
    #[must_use]
    pub fn blocked(&self) -> u64 {
        self.blocked
    }

    /// Is there nothing to draw? Not the same as nothing having arrived: with
    /// the toggle off, a run that only ever missed looks empty, and the heading
    /// says how many lines are being held back.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shown() == 0 && self.recent().count() == 0
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
            None if !self.targets.iter().any(|t| t.denial) => {
                format!("{command}: nothing was blocked so far")
            }
            None => {
                // Every target, whatever the toggle is showing: the closing
                // line is about the run, not about the view. Misses are left
                // out because they were never blocked.
                let mut targets: Vec<(String, u64)> = self
                    .targets
                    .iter()
                    .filter(|t| t.denial)
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

/// Drop one line of history, preferring one the sandbox was not the reason for.
///
/// A program searching a library path produces hundreds of misses in a moment,
/// and dropping oldest-first would push the one refusal that matters out of the
/// list behind them. The deque stays in time order either way, since removing
/// from the middle keeps what is around it where it was.
fn evict(recent: &mut VecDeque<Recent>) {
    match recent.iter().position(|entry| !entry.denial) {
        Some(index) => drop(recent.remove(index)),
        // All of them matter; the oldest is still the one to lose.
        None => drop(recent.pop_front()),
    }
}

/// The same for the tally: a flood of misses must not push the refusals out.
fn drop_one(targets: &mut Vec<Target>) {
    match targets.iter().rposition(|target| !target.denial) {
        Some(index) => drop(targets.remove(index)),
        None => drop(targets.pop()),
    }
}

fn detail_of(event: &Notification) -> &'static str {
    match event {
        Notification::Blocked { stage, .. } => report::stage_name(*stage),
        Notification::DnsRefused { .. } => "dns",
        Notification::FileBlocked { op, .. } => report::op_name(*op),
        Notification::Summary { .. } => "",
    }
}

#[cfg(test)]
#[expect(
    clippy::default_numeric_fallback,
    reason = "counts and ports, spelled the way the assertions read best"
)]
mod tests {
    use crate::bpfd::protocol::{FileError, FileOp, Outside, Stage, Transport};

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

        assert_eq!(denials.shown(), 2);
        // Most recent first, whatever the counts say.
        let first = denials.targets().next().expect("a target");
        assert_eq!(first.label, "8.8.8.8:53");
        let repeated = denials
            .targets()
            .find(|t| t.label == "1.1.1.1:443")
            .expect("the repeated target");
        assert_eq!(repeated.count, 3);
        // The running list keeps every one of them.
        assert_eq!(denials.recent().count(), 4);
        assert_eq!(denials.blocked(), 4);
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

    fn file(path: &str, outside: Outside) -> Notification {
        Notification::FileBlocked {
            op: FileOp::Open,
            path: path.to_owned(),
            error: FileError::NotFound,
            outside,
        }
    }

    /// The whole reason the toggle exists: a program searching a library path
    /// must not bury the one file the sandbox actually hid.
    #[test]
    fn what_was_missing_outside_is_kept_but_not_shown() {
        let mut denials = Denials::default();
        denials.push(&file("/home/me/.bashrc", Outside::Present), "bash");
        for i in 0..5 {
            denials.push(
                &file(&format!("/usr/lib/lib{i}.so"), Outside::Absent),
                "bash",
            );
        }

        // One line, and a heading that owns up to the other five.
        assert_eq!(denials.shown(), 1);
        assert_eq!(denials.hidden(), 5);
        assert_eq!(denials.recent().count(), 1);
        // The status bar says one, not six: five of them were never blocked.
        assert_eq!(denials.blocked(), 1);
    }

    /// Pressing the key has to reveal what already arrived, not just what comes
    /// next — otherwise it answers a question nobody asked.
    #[test]
    fn the_toggle_reveals_what_had_already_arrived() {
        let mut denials = Denials::default();
        denials.push(&file("/usr/lib/libx.so", Outside::Absent), "bash");
        denials.push(&file("/home/me/.bashrc", Outside::Present), "bash");
        assert_eq!(denials.shown(), 1);

        denials.toggle_missing();
        assert_eq!(denials.shown(), 2);
        assert_eq!(denials.recent().count(), 2);
        // Nothing left to hold back, so the heading stops saying so.
        assert_eq!(denials.hidden(), 0);

        denials.toggle_missing();
        assert_eq!(denials.shown(), 1);
    }

    /// A miss carries the sandbox's name for nothing: it was never blocked, so
    /// the closing line must not count it as one.
    #[test]
    fn the_closing_line_counts_only_what_was_actually_blocked() {
        let mut denials = Denials::default();
        denials.push(&file("/usr/lib/libx.so", Outside::Absent), "bash");
        assert_eq!(
            denials.summary_line("bash"),
            "bash: nothing was blocked so far"
        );

        denials.push(&file("/home/me/.bashrc", Outside::Present), "bash");
        let line = denials.summary_line("bash");
        assert!(line.contains("/home/me/.bashrc (1x)"), "{line}");
        assert!(!line.contains("libx.so"), "{line}");
    }

    /// The panel is empty because of the toggle, not because nothing came: the
    /// heading has to be the one to explain that, so `is_empty` still agrees
    /// with what is drawn.
    #[test]
    fn a_panel_holding_everything_back_reads_as_empty_but_says_how_much() {
        let mut denials = Denials::default();
        denials.push(&file("/usr/lib/libx.so", Outside::Absent), "bash");
        assert!(denials.is_empty());
        assert_eq!(denials.hidden(), 1);
        denials.toggle_missing();
        assert!(!denials.is_empty());
    }

    /// The panel follows a bounded number of subjects. Paths are not addresses:
    /// one program probing a library path names thousands, and an unbounded
    /// tally made the panel cost more than the command it was watching.
    #[test]
    fn the_tally_is_bounded_however_many_paths_a_command_names() {
        let mut denials = Denials::default();
        for i in 0..TARGETS_MAX * 3 {
            denials.push(&file(&format!("/nowhere/{i}"), Outside::Absent), "bat");
        }
        denials.toggle_missing();
        assert_eq!(denials.shown(), TARGETS_MAX);
        assert!(denials.recent().count() <= RECENT_MAX);
    }

    /// And the bound must not cost the one line the panel exists for: a
    /// refusal survives any number of misses arriving after it.
    #[test]
    fn a_flood_of_misses_does_not_push_out_a_real_refusal() {
        let mut denials = Denials::default();
        denials.push(&file("/home/me/.bashrc", Outside::Present), "bat");
        for i in 0..TARGETS_MAX * 3 + RECENT_MAX {
            denials.push(&file(&format!("/nowhere/{i}"), Outside::Absent), "bat");
        }

        assert_eq!(denials.shown(), 1, "the refusal should still be listed");
        let kept = denials.targets().next().expect("the refusal");
        assert_eq!(kept.label, "/home/me/.bashrc");
        // And it is still in the history, however far back it now is.
        assert_eq!(denials.recent().count(), 1);
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
