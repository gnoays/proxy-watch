//! The watcher thread for targets whose change notification, if any, is a bare "something
//! changed": it re-reads [`super::read_config`] every [`WatchOptions::poll_interval`], on
//! [`Watch::poll_now`], and whenever a sender from [`Watch::waker`] fires. With neither an
//! interval nor a notifier nothing would deliver changes, so [`Watch::armed`] refuses rather
//! than hand back a watcher that is frozen from the start.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::ProxyConfig;
use crate::error::Error;
use crate::watch::{BackendHealth, Shared, ThreadGuard, WatchOptions, fatal_watch_error};

static NEXT_ID: AtomicI64 = AtomicI64::new(1);
static SLOTS: Mutex<BTreeMap<i64, SyncSender<()>>> = Mutex::new(BTreeMap::new());

/// A [`Watch::waker`] filed under an id, for an OS callback that carries an integer in
/// place of a pointer. The OS may still run a callback after its registration is removed;
/// a pointer would dangle there, and an id that is no longer filed is ignored by [`wake`].
#[derive(Debug)]
pub(crate) struct WakeSlot(i64);

impl WakeSlot {
    pub(crate) fn new(wake: SyncSender<()>) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        slots().insert(id, wake);
        Self(id)
    }

    pub(crate) fn id(&self) -> i64 {
        self.0
    }
}

impl Drop for WakeSlot {
    fn drop(&mut self) {
        slots().remove(&self.0);
    }
}

/// Wakes the [`Watch`] whose [`WakeSlot`] is filed under `id`, if one still is.
pub(crate) fn wake(id: i64) {
    if let Some(wake) = slots().get(&id) {
        let _ = wake.try_send(());
    }
}

fn slots() -> MutexGuard<'static, BTreeMap<i64, SyncSender<()>>> {
    SLOTS.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug)]
pub(crate) struct Watch {
    // `None`: only a wake-up triggers a read.
    interval: Option<Duration>,
    // Dropping it and every [`Watch::waker`] clone ends the thread; a send is a re-read.
    // The channel holds one wake: a `try_send` refused as full is not a lost change,
    // because the thread consumes the pending wake before the read it leads to.
    wake: Option<SyncSender<()>>,
    woken: Option<Receiver<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Watch {
    /// The watcher for a target with no notification: refuses without a poll interval.
    #[cfg_attr(target_os = "android", allow(dead_code))]
    pub(crate) fn armed(options: &WatchOptions) -> Result<Self, Error> {
        if options.poll_interval.is_none() {
            return Err(fatal_watch_error(
                "registering for proxy change notifications",
                "this platform delivers none to a library",
                Error::Unsupported,
            ));
        }
        Ok(Self::new(options))
    }

    /// The thread's state without the refusal, for a caller that holds a [`Watch::waker`]
    /// and so has something other than the interval to deliver changes.
    pub(crate) fn new(options: &WatchOptions) -> Self {
        // The ceiling keeps `Instant::now() + interval` representable: past it
        // `recv_timeout` waits with a plain `recv`, and the timer never fires.
        const CEILING: Duration = Duration::from_secs(24 * 60 * 60);
        let (wake, woken) = mpsc::sync_channel::<()>(1);
        Self {
            interval: options
                .poll_interval
                .map(|requested| crate::watch::effective_poll_interval(requested).min(CEILING)),
            wake: Some(wake),
            woken: Some(woken),
            thread: None,
        }
    }

    /// A sender whose every `try_send` is a change notification. The thread ends only once
    /// every clone is gone: drop each clone before this `Watch`, or its `Drop` waits for them.
    pub(crate) fn waker(&self) -> SyncSender<()> {
        self.wake
            .clone()
            .expect("a Watch holds its sender until Drop")
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) fn spawn(
        &mut self,
        options: &WatchOptions,
        shared: Arc<Shared>,
    ) -> Result<(), Error> {
        let read_options = options.clone();
        self.spawn_reading(options, shared, move || super::read_config(&read_options))
    }

    // [`Watch::spawn`] with the read passed in, so the loop runs where there is no platform
    // to read from.
    fn spawn_reading(
        &mut self,
        options: &WatchOptions,
        shared: Arc<Shared>,
        mut read: impl FnMut() -> Result<ProxyConfig, Error> + Send + 'static,
    ) -> Result<(), Error> {
        let woken = self
            .woken
            .take()
            .expect("Watch::spawn must be called exactly once");
        let interval = self.interval;
        let debounce = crate::watch::effective_debounce(options.debounce);
        let thread = thread::Builder::new()
            .name("proxy-watch-poll".to_owned())
            .spawn(move || {
                let _guard = ThreadGuard::new(Arc::clone(&shared));
                // The first read closes the window since the constructor's own.
                loop {
                    match read() {
                        Ok(config) => shared.emit(config),
                        // A transient failure must not end the subscription.
                        Err(error) => shared.fail(error),
                    }
                    let waited = match interval {
                        Some(interval) => woken.recv_timeout(interval),
                        None => woken.recv().map_err(|_| RecvTimeoutError::Disconnected),
                    };
                    match waited {
                        // A broadcast storm collapses into the one read after the window.
                        // The deadline is checked before each receive: a zero timeout still
                        // returns a queued wake-up, so senders that never pause would hold
                        // the loop here.
                        Ok(()) => {
                            let until = Instant::now() + debounce;
                            loop {
                                let left = until.saturating_duration_since(Instant::now());
                                if left.is_zero() {
                                    break;
                                }
                                match woken.recv_timeout(left) {
                                    Ok(()) => {}
                                    Err(RecvTimeoutError::Timeout) => break,
                                    Err(RecvTimeoutError::Disconnected) => return,
                                }
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => return,
                    }
                }
            })
            .map_err(|source| Error::io("spawning the proxy-watch polling thread", source))?;
        self.thread = Some(thread);
        Ok(())
    }

    #[cfg_attr(target_os = "android", allow(dead_code))]
    pub(crate) fn health(&self) -> BackendHealth {
        BackendHealth {
            degraded: Vec::new(),
            has_live_notifications: false,
        }
    }

    pub(crate) fn poll_now(&self) {
        if let Some(wake) = &self.wake {
            let _ = wake.try_send(());
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        drop(self.wake.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    fn options(poll_interval: Option<Duration>, debounce: Duration) -> WatchOptions {
        let mut options = WatchOptions::new();
        options.poll_interval = poll_interval;
        options.debounce = debounce;
        options
    }

    // Waits up to five seconds for `reads` to reach `want`, then reports what it holds.
    fn settle(reads: &AtomicUsize, want: usize) -> usize {
        let until = Instant::now() + Duration::from_secs(5);
        while reads.load(Ordering::SeqCst) < want && Instant::now() < until {
            thread::sleep(Duration::from_millis(5));
        }
        reads.load(Ordering::SeqCst)
    }

    // A watcher on no interval whose read counts itself and fails when `fail` says so.
    fn counting(
        debounce: Duration,
        fail: impl Fn(usize) -> bool + Send + 'static,
    ) -> (Watch, Arc<AtomicUsize>) {
        let options = options(None, debounce);
        let mut watch = Watch::new(&options);
        let reads = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reads);
        watch
            .spawn_reading(
                &options,
                Arc::new(Shared::new(ProxyConfig::direct())),
                move || {
                    let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    if fail(n) {
                        Err(Error::Unsupported)
                    } else {
                        Ok(ProxyConfig::direct())
                    }
                },
            )
            .unwrap();
        (watch, reads)
    }

    #[test]
    fn a_storm_of_wake_ups_is_one_read_after_the_window_and_the_next_storm_another() {
        let (watch, reads) = counting(Duration::from_millis(100), |_| false);
        assert_eq!(settle(&reads, 1), 1, "the opening read");

        for _ in 0..20 {
            watch.poll_now();
        }
        assert_eq!(settle(&reads, 2), 2);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "the storm read more than once"
        );

        watch.poll_now();
        assert_eq!(
            settle(&reads, 3),
            3,
            "a wake-up after the window is read again"
        );
        drop(watch);
    }

    // Senders that outpace the thread keep the channel non-empty: the window still has to
    // end at its deadline, or the thread never reads again while they keep sending.
    #[test]
    fn wake_ups_that_never_stop_still_end_each_window_in_a_read() {
        let (watch, reads) = counting(Duration::from_millis(20), |_| false);
        assert_eq!(settle(&reads, 1), 1, "the opening read");

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let senders: Vec<_> = (0..4)
            .map(|_| {
                let wake = watch.waker();
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let _ = wake.try_send(());
                    }
                })
            })
            .collect();
        let seen = settle(&reads, 3);
        stop.store(true, Ordering::Relaxed);
        for sender in senders {
            sender.join().unwrap();
        }
        assert!(
            seen >= 3,
            "only {seen} reads while the wake-ups kept coming"
        );
    }

    #[test]
    fn a_failed_read_leaves_the_loop_waiting_for_the_next_wake_up() {
        let (watch, reads) = counting(Duration::from_millis(10), |n| n == 1);
        assert_eq!(settle(&reads, 1), 1);
        watch.poll_now();
        assert_eq!(settle(&reads, 2), 2);
    }

    #[test]
    fn dropping_the_watch_ends_the_thread_once_no_waker_is_left() {
        let (watch, reads) = counting(Duration::from_millis(10), |_| false);
        assert_eq!(settle(&reads, 1), 1);
        // `Drop` joins the thread: this returns only because the thread ended.
        drop(watch);
        let after = reads.load(Ordering::SeqCst);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(reads.load(Ordering::SeqCst), after);
    }

    #[test]
    fn a_slot_wakes_while_it_is_filed_and_not_after() {
        let (wake_tx, woken) = mpsc::sync_channel(1);
        let slot = WakeSlot::new(wake_tx);
        let id = slot.id();
        wake(id);
        assert!(woken.try_recv().is_ok());
        drop(slot);
        wake(id);
        // The sender went with the slot, so nothing is left to deliver or to wait for.
        assert_eq!(woken.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    }

    #[test]
    fn the_interval_is_clamped_to_the_floor_and_the_ceiling() {
        let interval = |requested| Watch::new(&options(Some(requested), Duration::ZERO)).interval;
        assert_eq!(
            interval(Duration::from_millis(1)),
            Some(crate::watch::MIN_POLL_INTERVAL)
        );
        assert_eq!(
            interval(Duration::from_secs(48 * 60 * 60)),
            Some(Duration::from_secs(24 * 60 * 60))
        );
        assert_eq!(Watch::new(&options(None, Duration::ZERO)).interval, None);
    }

    #[test]
    fn a_watch_with_no_notifier_refuses_to_arm_without_an_interval() {
        let error = Watch::armed(&options(None, Duration::ZERO)).unwrap_err();
        assert!(error.to_string().contains("poll_interval"), "{error}");
        assert!(Watch::armed(&options(Some(Duration::from_secs(1)), Duration::ZERO)).is_ok());
    }
}
