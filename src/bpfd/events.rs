//! What a sandbox turned away, on its way to whoever asked to be told.
//!
//! One bus per sandbox, created when its policies are registered rather than
//! when they are attached: a watcher connects before the command has started, so
//! by the time there is anything to report there is already somewhere to report
//! it to.
//!
//! Two things feed it — the eBPF programs, by way of the ring buffer reader, and
//! the sandbox's own DNS resolver — and it is deliberately the narrow point
//! between them and the socket. Everything that keeps a flood of refusals from
//! becoming a flood of output happens here, once, rather than in each producer.
//!
//! Nothing published here may block. A watcher that stops reading, or a terminal
//! that stops draining, must cost events and never hold up either the reader
//! thread or the reaper: dropping a report is a nuisance, delaying enforcement
//! or teardown is not.

use std::{
    collections::HashMap,
    sync::{
        Mutex, PoisonError,
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
    time::{Duration, Instant},
};

use crate::bpfd::protocol::Notification;

/// How long a repeat of the same refusal is folded into the first one.
///
/// A denied TCP connect is retried, and a denied UDP flow keeps sending; without
/// this, one `curl` produces a screenful of identical lines.
const DEDUP_WINDOW: Duration = Duration::from_secs(5);

/// How many distinct refusals the deduplication remembers. A port scan must not
/// be able to grow the daemon's memory, and forgetting only costs a repeat.
const MAX_SEEN: usize = 4096;

/// How far behind a watcher may fall before its events start being dropped.
const QUEUE_DEPTH: usize = 1024;

/// How many watchers one sandbox may have. Normally exactly one.
const MAX_WATCHERS: usize = 4;

/// How many targets the closing summary names.
const MAX_TARGETS: usize = 32;

pub struct Bus {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    watchers: Vec<SyncSender<Notification>>,
    /// The last time each distinct refusal was reported.
    seen: HashMap<Notification, Instant>,
    /// What was refused and how often, counting the repeats nobody saw.
    targets: HashMap<String, u64>,
    suppressed: u64,
    lost: u64,
    closed: bool,
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus {
    #[must_use]
    pub fn new() -> Self {
        Bus {
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Follow this sandbox. `None` when it already has as many watchers as it
    /// may have, or when it has already been torn down.
    #[must_use]
    pub fn subscribe(&self) -> Option<Receiver<Notification>> {
        let mut inner = self.lock();
        if inner.closed || inner.watchers.len() >= MAX_WATCHERS {
            return None;
        }
        let (tx, rx) = sync_channel(QUEUE_DEPTH);
        inner.watchers.push(tx);
        Some(rx)
    }

    /// Report a refusal.
    pub fn publish(&self, event: Notification) {
        self.publish_at(event, Instant::now());
    }

    fn publish_at(&self, event: Notification, now: Instant) {
        let mut inner = self.lock();
        if inner.closed {
            return;
        }

        // Counted before the deduplication, so the summary reflects what the
        // sandbox actually did and not merely what was printed.
        if let Some(target) = event.target() {
            let count = inner.targets.entry(target).or_insert(0);
            *count = count.saturating_add(1);
        }

        if inner.is_repeat(&event, now) {
            inner.suppressed = inner.suppressed.saturating_add(1);
            return;
        }
        inner.deliver(&event);
        inner.remember(event, now);
    }

    /// Note events that never reached the bus at all: the ring buffer was full
    /// when the kernel tried to write them.
    pub fn note_lost(&self, count: u64) {
        let mut inner = self.lock();
        inner.lost = inner.lost.saturating_add(count);
    }

    /// Send the summary and let every watcher go.
    ///
    /// This is what ends a watcher: it reads the summary, prints it, and sees
    /// the connection close behind it.
    pub fn close(&self) {
        let mut inner = self.lock();
        if inner.closed {
            return;
        }
        inner.closed = true;
        let summary = inner.summary();
        inner.deliver(&summary);
        inner.watchers.clear();
    }

    /// A poisoned lock would mean a producer panicked mid-publish. Nothing here
    /// is worth propagating that: the worst a partly-updated tally can do is
    /// misreport a count, so take the state as it stands.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Inner {
    /// Have we said this recently enough that saying it again adds nothing?
    fn is_repeat(&self, event: &Notification, now: Instant) -> bool {
        self.seen
            .get(event)
            .is_some_and(|last| now.duration_since(*last) < DEDUP_WINDOW)
    }

    fn remember(&mut self, event: Notification, now: Instant) {
        if self.seen.len() >= MAX_SEEN {
            self.seen
                .retain(|_, last| now.duration_since(*last) < DEDUP_WINDOW);
            // Still full: everything in it is current, and the table is capped
            // rather than the truth. Forgetting costs a duplicate line.
            if self.seen.len() >= MAX_SEEN {
                self.seen.clear();
            }
        }
        self.seen.insert(event, now);
    }

    /// Hand the event to every watcher, dropping the ones that have gone.
    fn deliver(&mut self, event: &Notification) {
        let mut lost = 0u64;
        self.watchers.retain(|tx| match tx.try_send(event.clone()) {
            Ok(()) => true,
            // Behind, but still there: the event is what gives way.
            Err(TrySendError::Full(_)) => {
                lost = lost.saturating_add(1);
                true
            }
            Err(TrySendError::Disconnected(_)) => false,
        });
        self.lost = self.lost.saturating_add(lost);
    }

    fn summary(&self) -> Notification {
        let mut targets: Vec<(String, u64)> = self
            .targets
            .iter()
            .map(|(name, count)| (name.clone(), *count))
            .collect();
        // Most frequent first, and by name within a tie so the output does not
        // reshuffle itself between runs.
        targets.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        targets.truncate(MAX_TARGETS);
        Notification::Summary {
            targets,
            suppressed: self.suppressed,
            lost: self.lost,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpfd::protocol::{Stage, Transport};

    /// Drain what is left on a watcher's channel and hand back the summary the
    /// bus signs off with.
    fn summary_of(rx: &Receiver<Notification>) -> (Vec<(String, u64)>, u64, u64) {
        let mut found = None;
        while let Ok(event) = rx.recv() {
            if let Notification::Summary {
                targets,
                suppressed,
                lost,
            } = event
            {
                found = Some((targets, suppressed, lost));
            }
        }
        found.expect("the bus sends a summary when it closes")
    }

    fn blocked(addr: &str, port: u16) -> Notification {
        Notification::Blocked {
            stage: Stage::Connect,
            transport: Transport::Tcp,
            addr: addr.parse().expect("a valid test address"),
            port,
        }
    }

    /// One denied connect that the command retries is one line, not ten.
    #[test]
    fn a_repeat_inside_the_window_is_folded_into_the_first() {
        let bus = Bus::new();
        let rx = bus.subscribe().expect("the first watcher is accepted");
        let start = Instant::now();

        bus.publish_at(blocked("1.1.1.1", 443), start);
        bus.publish_at(blocked("1.1.1.1", 443), start + Duration::from_millis(10));
        bus.publish_at(blocked("1.1.1.1", 443), start + Duration::from_secs(1));

        assert_eq!(rx.try_recv(), Ok(blocked("1.1.1.1", 443)));
        assert!(
            rx.try_recv().is_err(),
            "the repeats should not be delivered"
        );

        bus.close();
        let (targets, suppressed, lost) = summary_of(&rx);
        // Every attempt is counted, even the ones that were never printed.
        assert_eq!(targets, vec![("1.1.1.1:443".to_owned(), 3)]);
        assert_eq!(suppressed, 2);
        assert_eq!(lost, 0);
    }

    /// Once the window has passed, the refusal is worth saying again: the
    /// command is still trying, and the user is entitled to know.
    #[test]
    fn a_repeat_after_the_window_is_reported_again() {
        let bus = Bus::new();
        let rx = bus.subscribe().expect("the first watcher is accepted");
        let start = Instant::now();

        bus.publish_at(blocked("1.1.1.1", 443), start);
        bus.publish_at(blocked("1.1.1.1", 443), start + DEDUP_WINDOW);

        rx.try_recv().expect("the first report is delivered");
        rx.try_recv()
            .expect("and so is the one after the window closes");
    }

    /// Different destinations are different events, however fast they arrive.
    #[test]
    fn deduplication_does_not_collapse_distinct_refusals() {
        let bus = Bus::new();
        let rx = bus.subscribe().expect("the first watcher is accepted");
        let now = Instant::now();

        bus.publish_at(blocked("1.1.1.1", 443), now);
        bus.publish_at(blocked("1.1.1.1", 80), now);
        bus.publish_at(blocked("8.8.8.8", 443), now);

        assert_eq!(rx.try_recv().unwrap(), blocked("1.1.1.1", 443));
        assert_eq!(rx.try_recv().unwrap(), blocked("1.1.1.1", 80));
        assert_eq!(rx.try_recv().unwrap(), blocked("8.8.8.8", 443));
    }

    /// A watcher that stops reading costs its own events and nothing else. The
    /// publisher here is the ring buffer reader, which must never wait.
    #[test]
    fn a_watcher_that_stops_reading_loses_events_but_blocks_nobody() {
        let bus = Bus::new();
        let _rx = bus.subscribe().expect("the first watcher is accepted");
        let start = Instant::now();

        // Well past the queue depth, each one distinct so nothing is folded.
        let over = u16::try_from(QUEUE_DEPTH).expect("the queue depth fits in a port");
        for port in 1..=over.saturating_add(100) {
            bus.publish_at(blocked("1.1.1.1", port), start);
        }

        bus.close();
        let inner = bus.lock();
        assert!(inner.lost >= 100, "expected losses, got {}", inner.lost);
    }

    /// The summary names the busiest targets first.
    #[test]
    fn the_summary_ranks_targets_by_how_often_they_were_refused() {
        let bus = Bus::new();
        let rx = bus.subscribe().expect("the first watcher is accepted");
        let start = Instant::now();

        for i in 0..3u32 {
            let at = start + DEDUP_WINDOW * i;
            bus.publish_at(blocked("1.1.1.1", 443), at);
        }
        bus.publish_at(blocked("8.8.8.8", 53), start);
        bus.publish_at(
            Notification::DnsRefused {
                name: "ads.example".to_owned(),
                reason: "no rule names it".to_owned(),
            },
            start,
        );
        bus.close();

        let (targets, _, _) = summary_of(&rx);
        assert_eq!(
            targets,
            vec![
                ("1.1.1.1:443".to_owned(), 3),
                ("8.8.8.8:53".to_owned(), 1),
                ("ads.example".to_owned(), 1),
            ]
        );
    }

    /// A caller in a loop must not be able to pile up watcher threads.
    #[test]
    fn a_sandbox_takes_only_so_many_watchers() {
        let bus = Bus::new();
        let held: Vec<_> = (0..MAX_WATCHERS).filter_map(|_| bus.subscribe()).collect();
        assert_eq!(held.len(), MAX_WATCHERS);
        assert!(bus.subscribe().is_none());
    }

    /// Once the sandbox is gone there is nothing left to watch.
    #[test]
    fn a_closed_bus_takes_no_new_watchers_and_no_new_events() {
        let bus = Bus::new();
        bus.close();
        assert!(bus.subscribe().is_none());
        bus.publish(blocked("1.1.1.1", 443));
        let inner = bus.lock();
        assert!(inner.targets.is_empty());
    }

    /// Closing twice must not send a second summary to a watcher that is
    /// already on its way out.
    #[test]
    fn closing_is_idempotent() {
        let bus = Bus::new();
        let rx = bus.subscribe().expect("the first watcher is accepted");
        bus.close();
        bus.close();
        assert!(matches!(rx.recv(), Ok(Notification::Summary { .. })));
        assert!(rx.recv().is_err(), "the stream should have ended");
    }
}
