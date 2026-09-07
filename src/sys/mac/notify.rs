//! `SCDynamicStore` watcher thread.
//!
//! <div class="warning">
//!
//! **CI-verified only** — no macOS dev machine. See [`super`], i.e.
//! `src/sys/mac/mod.rs`, for what that leaves unverified and how it would show.
//!
//! </div>
//!
//! Stop: version-0 [`CFRunLoopSource`] + `CFRunLoopWakeUp` (attached before
//! registration), then `join`. Deliberately no `CFRunLoopStop` — see [`Watch`]'s `Drop`.
//! [`WatchOptions::poll_interval`] shortens the run-loop wait; [`Watch::poll_now`] reuses
//! the wake source. Debounce + equality skip on every trigger. Registration retries before
//! `ready_tx`; outcome via `watch_fail_soft` (`poll_interval` → degrade).

use std::ffi::c_void;
use std::io;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use core_foundation::array::CFArray;
use core_foundation::base::{TCFType, kCFAllocatorDefault};
use core_foundation::runloop::{
    CFRunLoop, CFRunLoopRunResult, CFRunLoopSource, CFRunLoopSourceContext, CFRunLoopSourceCreate,
    CFRunLoopSourceSignal, CFRunLoopWakeUp, kCFRunLoopDefaultMode,
};
use core_foundation::string::CFString;
use system_configuration::dynamic_store::{
    SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext,
};

use crate::config::ProxyConfigSource;
use crate::error::Error;
use crate::watch::{
    BackendHealth, Shared, WatchFailSoft, WatchOptions, effective_debounce,
    effective_poll_interval, fatal_watch_error, watch_fail_soft,
};

use super::{SETUP_PROXIES_KEY, STATE_PROXIES_KEY, STORE_NAME, read_config};

// How long a single blocking wait may last when [`WatchOptions::poll_interval`] is off.
//
// This is not a poll interval: every wake-up is delivered by a run loop source, and the
// thread goes straight back to sleep when nothing happened. The bound only exists so that
// a wait can never be literally infinite.
const IDLE_WAIT: Duration = Duration::from_secs(60 * 60);

// The duration [`run`] passes to the outer [`CFRunLoop::run_in_mode`] wait.
fn idle_wait(poll_interval: Option<Duration>) -> Duration {
    match poll_interval {
        Some(interval) => effective_poll_interval(interval).min(IDLE_WAIT),
        None => IDLE_WAIT,
    }
}

// The delay [`Registration::establish_store`] waits before each retry of a
// [`RegistrationFailure::Retryable`] registration failure.
pub(super) const REGISTRATION_RETRY_INTERVAL: Duration = Duration::from_secs(1);

// How many times [`Registration::establish_store`] retries a
// [`RegistrationFailure::Retryable`] registration failure before giving up. Matches
// Chromium's `kMaxRetry`, for the same reason [`REGISTRATION_RETRY_INTERVAL`] does.
pub(super) const REGISTRATION_MAX_RETRIES: u32 = 5;

// Whether a [`RegistrationFailure::Retryable`] failure on the attempt numbered `attempt`
// (`0` = the very first attempt has just failed) should be followed by another one.
pub(super) fn should_retry(attempt: u32) -> bool {
    attempt < REGISTRATION_MAX_RETRIES
}

// A `CFRunLoopSource` that may be signalled from another thread.
struct WakeSource(CFRunLoopSource);

// SAFETY: see the type documentation — the value is only ever cloned, dropped and
// signalled, and all three are thread safe for a Core Foundation object.
unsafe impl Send for WakeSource {}

impl Clone for WakeSource {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl WakeSource {
    // Create a version 0 run loop source with a do-nothing `perform` callback.
    fn new() -> Result<Self, Error> {
        // The callback a signalled source runs. Waking the run loop *is* the whole
        // effect; there is nothing to do here.
        extern "C" fn perform(_info: *const c_void) {}

        let mut context = CFRunLoopSourceContext {
            version: 0,
            info: ptr::null_mut(),
            retain: None,
            release: None,
            copyDescription: None,
            equal: None,
            hash: None,
            schedule: None,
            cancel: None,
            perform,
        };

        // SAFETY: `context` is a fully initialised version 0 `CFRunLoopSourceContext`
        // whose `perform` is a valid `extern "C"` function; its `info` is null and is
        // never dereferenced because `retain`/`release`/`perform` ignore it. Core
        // Foundation copies the context, so the local may die at the end of the call.
        let raw = unsafe { CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &raw mut context) };
        if raw.is_null() {
            return Err(Error::io(
                "creating the proxy-watch wake-up run loop source",
                io::Error::other("CFRunLoopSourceCreate returned NULL"),
            ));
        }
        // SAFETY: `raw` is a non-null, freshly created (+1 retained) reference whose
        // ownership is transferred to the wrapper.
        Ok(Self(unsafe {
            CFRunLoopSource::wrap_under_create_rule(raw)
        }))
    }

    // Ask the run loop this source was added to to return from its current wait.
    fn signal(&self, run_loop: Option<&CFRunLoop>) {
        // SAFETY: the source is kept alive by `self`; `CFRunLoopSourceSignal` merely
        // sets a flag on it, and Apple's Threading Programming Guide says the Core
        // Foundation run loop functions are "generally thread-safe and can be called
        // from any thread".
        unsafe { CFRunLoopSourceSignal(self.0.as_concrete_TypeRef()) };
        if let Some(run_loop) = run_loop {
            // SAFETY: the run loop is kept alive by the caller (`CFRunLoop` is a
            // reference counted Core Foundation object that the crate marks `Send`), and
            // signal-then-wake-up is the pattern that same guide gives for driving
            // another thread's run loop (Listing 3-9, `fireCommandsOnRunLoop:`):
            // https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/Multithreading/RunLoopManagement/RunLoopManagement.html
            unsafe { CFRunLoopWakeUp(run_loop.as_concrete_TypeRef()) };
        }
    }
}

// The macOS watcher: the wake-up source, the run loop the thread is driving, and the
// thread itself.
pub(crate) struct Watch {
    // Set by [`Drop`] to make the thread return.
    stop: Arc<AtomicBool>,
    // Signalled by [`Drop`] to wake the thread up so it can see `stop`, and by
    // [`Watch::poll_now`] so it can see [`Watch::poll_requested`] instead; [`run`] tells
    // the two apart by checking `stop` first, unconditionally.
    wake: WakeSource,
    // Set by [`Watch::poll_now`], cleared by [`run`] once the debounce window it opened
    // closes and *before* the re-read that follows: clearing first is what keeps a second
    // `poll_now()` landing during the read from being swallowed by the window that is
    // already closing.
    poll_requested: Arc<AtomicBool>,
    // The watcher thread's run loop, once it has reported itself ready. Always `Some` once
    // [`Watch::spawn`] returns `Ok`, whether or not the `SCDynamicStore` subscription
    // itself came up.
    run_loop: Option<CFRunLoop>,
    // Set from what the watcher thread reported once [`Watch::spawn`] returns `Ok`: `true`
    // when registration gave up and fell back to poll-only. Giving up is not always the end
    // of a retry budget — a [`RegistrationFailure::Fatal`] ends it wherever it lands, which
    // need not be the first attempt. Never updated afterwards — see [`Watch::health`].
    degraded: bool,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Watch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watch")
            .field("stopped", &self.stop.load(Ordering::SeqCst))
            .field("running", &self.thread.is_some())
            .field("degraded", &self.degraded)
            .finish_non_exhaustive()
    }
}

impl Watch {
    // Prepare the stop machinery. See the type documentation for why nothing is
    // registered with the operating system yet: the window between
    // [`crate::ProxyWatcher::with_options`]'s initial read and this subscription going
    // live is closed from the other side instead, by [`run`]'s unconditional opening
    // `publish`.
    pub(crate) fn armed(_options: &WatchOptions) -> Result<Self, Error> {
        Ok(Self {
            stop: Arc::new(AtomicBool::new(false)),
            wake: WakeSource::new()?,
            poll_requested: Arc::new(AtomicBool::new(false)),
            run_loop: None,
            degraded: false,
            thread: None,
        })
    }

    // Start the watcher thread (a dedicated `std::thread`, no runtime)
    // and wait for it to have finished registering the notification, one way or
    // another (see the type documentation).
    pub(crate) fn spawn(
        &mut self,
        options: &WatchOptions,
        shared: Arc<Shared>,
    ) -> Result<(), Error> {
        assert!(
            self.thread.is_none(),
            "Watch::spawn must be called exactly once"
        );

        let wake = self.wake.clone();
        let stop = Arc::clone(&self.stop);
        let poll_requested = Arc::clone(&self.poll_requested);
        let options = options.clone();
        // Capacity 1 and a single send: the thread never blocks on this channel, even
        // if `spawn` gave up waiting. The `bool` alongside the run loop is
        // [`Watch::degraded`]'s value — see [`Registration::new`].
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(CFRunLoop, bool), Error>>(1);

        let thread = thread::Builder::new()
            .name("proxy-watch-scdynamicstore".to_owned())
            .spawn(move || {
                let _guard = crate::watch::ThreadGuard::new(Arc::clone(&shared));
                crate::trace::debug!("the SCDynamicStore watcher thread started");
                let changed = Arc::new(AtomicBool::new(false));
                match Registration::new(&wake, Arc::clone(&changed), options.poll_interval) {
                    Ok(registration) => {
                        let _ = ready_tx
                            .send(Ok((registration.run_loop.clone(), registration.degraded)));
                        drop(ready_tx);
                        run(&options, &shared, &stop, &changed, &poll_requested);
                        // Held until here on purpose: dropping the registration
                        // unsubscribes and releases the run loop sources.
                        drop(registration);
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                    }
                }
            })
            .map_err(|source| {
                Error::io("spawning the proxy-watch SCDynamicStore thread", source)
            })?;
        self.thread = Some(thread);

        match ready_rx.recv() {
            Ok(Ok((run_loop, degraded))) => {
                self.run_loop = Some(run_loop);
                self.degraded = degraded;
                Ok(())
            }
            Ok(Err(error)) => Err(error),
            // The sender was dropped without a message, i.e. the thread panicked.
            Err(_) => Err(Error::io(
                "starting the proxy-watch SCDynamicStore thread",
                io::Error::other("the watcher thread exited before it became ready"),
            )),
        }
    }

    // Report which documented macOS notification routes were established — established,
    // past tense, and that is the whole of what this answers. The `degraded` field above
    // points here for why it is never updated afterwards, so the reason belongs here: the
    // `SCDynamicStore` subscription is made once and needs no renewal, so there is no
    // recurring call whose failure `Shared::degrade` could carry. Windows has one —
    // `sys::win::notify`'s `rearm` re-registers after every notification and degrades the
    // health when that fails — and the difference is the platform API's, not a choice made
    // here.
    //
    // The cost is that the two answers are not the same answer. A subscription that stops
    // delivering after it came up leaves `has_live_notifications` reading `true`, and this
    // backend has no way to notice. A caller that needs the stronger guarantee has
    // `poll_now`, or a `poll_interval`, whose whole purpose is to not depend on this.
    pub(crate) fn health(&self) -> BackendHealth {
        if self.degraded {
            BackendHealth {
                degraded: vec![
                    ProxyConfigSource::SystemConfigurationSetup,
                    ProxyConfigSource::SystemConfigurationState,
                ],
                has_live_notifications: false,
            }
        } else {
            BackendHealth {
                degraded: Vec::new(),
                has_live_notifications: true,
            }
        }
    }

    // Ask the watcher thread to re-read the configuration right now.
    pub(crate) fn poll_now(&self) {
        self.poll_requested.store(true, Ordering::SeqCst);
        self.wake.signal(self.run_loop.as_ref());
    }
}

impl Drop for Watch {
    // No `CFRunLoopStop` here, and that is deliberate. [`WakeSource::signal`] is enough
    // in both states the thread can be in: inside [`CFRunLoop::run_in_mode`], which is
    // passed `returnAfterSourceHandled = true` and so returns as soon as the wake source
    // is delivered; or outside it, where the signalled bit persists until the next
    // `run_in_mode` picks it up on entry. [`run`] re-reads `stop` after every wait, so
    // either way the next thing the thread does is return.
    //
    // `CFRunLoopStop` would therefore add nothing, and it is the one call of the three
    // that reference implementations keep on the owning thread: it stops whichever run is
    // innermost on the target thread, which the dropping thread cannot know. Chromium
    // marks the signal-and-wake path `// May be called on any thread.` and the
    // `CFRunLoopStop` path `// Must be called on the run loop thread.`
    // (`MessagePumpCFRunLoopBase::ScheduleWork` and `MessagePumpCFRunLoop::DoQuit` in
    // `base/message_loop/message_pump_apple.mm`); libuv signals across threads in
    // `uv__cf_loop_signal` but calls `CFRunLoopStop` from inside the source callback
    // `uv__cf_loop_cb`, which runs on the run loop's own thread (`src/unix/fsevents.c`).
    fn drop(&mut self) {
        // Not "the thread", for the reason the Windows `Drop` gives: an armed-but-never-
        // spawned `Watch` reaches this line with no thread to stop.
        crate::trace::debug!("stopping the SCDynamicStore watcher");
        self.stop.store(true, Ordering::SeqCst);
        // Store `stop` first, signal second: the signalled bit is persistent, so a thread
        // that is about to enter its wait still sees both.
        self.wake.signal(self.run_loop.as_ref());
        if let Some(thread) = self.thread.take() {
            // Join before the store and the run loop sources are released, so that no
            // Core Foundation object outlives this call.
            let _ = thread.join();
        }
    }
}

// Whether a single [`Registration::try_register_once`] failure should be retried, or is
// certain to repeat no matter how many more times it is attempted.
//
// Chromium is where the retry budget comes from, but not this split: its
// `InitNotificationsHelper` is retried whole, so a NULL from
// `SCDynamicStoreCreateRunLoopSource` gets all five attempts there and only one here. That
// is a deliberate narrowing — a NULL run loop source is an allocation failure, not a round
// trip that lost a race — and it only decides anything when `poll_interval` is `None`,
// since otherwise `watch_fail_soft` degrades to polling either way.
enum RegistrationFailure {
    // A round trip to `configd` failed. [`Registration::establish_store`] retries this,
    // up to [`REGISTRATION_MAX_RETRIES`] times, [`REGISTRATION_RETRY_INTERVAL`] apart.
    Retryable(Error),
    // A local, non-IPC step failed. Retrying would not change the outcome, so
    // [`Registration::establish_store`] gives up on the first one of these.
    Fatal(Error),
}

// Everything the watcher thread must keep alive for the notification to stay live, plus
// the run loop it all runs on.
struct Registration {
    // The session the notification keys were set on, once established. Dropping it
    // unregisters them.
    _store: Option<SCDynamicStore>,
    // The store's run loop source, once established. The run loop retains it, but
    // keeping it here makes the ownership obvious.
    _source: Option<CFRunLoopSource>,
    // The thread's own run loop. Always created and given the wake-up source, whether or
    // not the `SCDynamicStore` subscription itself came up: as the module docs' `Stop:`
    // note says, the source is attached *before* registration, precisely so that `Drop`
    // can stop a thread whose registration never succeeded.
    run_loop: CFRunLoop,
    // Whether the subscription could not be established — after exhausting the retries, or
    // at whatever attempt a [`RegistrationFailure::Fatal`] cut them short — and this
    // registration is running in degraded (poll-only) mode.
    degraded: bool,
}

impl Registration {
    // Prepare this thread's run loop, then attempt to create the `SCDynamicStore` session,
    // subscribe to both [`SETUP_PROXIES_KEY`] and [`STATE_PROXIES_KEY`] (either scope
    // changing must be able to change `effective`), and attach both sources to it —
    // retrying a transient failure per [`establish_store`](Self::establish_store), and
    // falling back to a poll-only registration if every attempt fails and `poll_interval`
    // allows it.
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    fn new(
        wake: &WakeSource,
        changed: Arc<AtomicBool>,
        poll_interval: Option<Duration>,
    ) -> Result<Self, Error> {
        let run_loop = CFRunLoop::get_current();
        // SAFETY: reading an `extern` static. `kCFRunLoopDefaultMode` is a constant
        // `CFStringRef` initialised by Core Foundation before any of its API can be
        // called.
        let mode = unsafe { kCFRunLoopDefaultMode };
        // Unconditional: the wake source must be on this run loop regardless of what
        // happens below, so `Drop` always has something to signal.
        run_loop.add_source(&wake.0, mode);

        match watch_fail_soft(
            true,
            poll_interval,
            Self::establish_store(&run_loop, changed),
        ) {
            WatchFailSoft::Live((store, source)) => Ok(Self {
                _store: Some(store),
                _source: Some(source),
                run_loop,
                degraded: false,
            }),
            WatchFailSoft::Degraded(error) => {
                crate::trace::warning!(
                    setup_key = SETUP_PROXIES_KEY,
                    state_key = STATE_PROXIES_KEY,
                    error = %crate::trace::SafeError(&error),
                    "registering the SCDynamicStore proxies notification failed and will \
                     not be retried; continuing on WatchOptions::poll_interval alone"
                );
                Ok(Self {
                    _store: None,
                    _source: None,
                    run_loop,
                    degraded: true,
                })
            }
            WatchFailSoft::Fatal(error) => Err(fatal_watch_error(
                "registering the SCDynamicStore proxies notification",
                "SCDynamicStore is macOS' only proxy change-notification route, with no \
                 other source this backend can fall back to",
                error,
            )),
        }
    }

    // Attempt [`try_register_once`](Self::try_register_once) up to
    // `1 + REGISTRATION_MAX_RETRIES` times total, sleeping
    // [`REGISTRATION_RETRY_INTERVAL`] before each retry, stopping early on a
    // [`RegistrationFailure::Fatal`] failure (see the module docs).
    fn establish_store(
        run_loop: &CFRunLoop,
        changed: Arc<AtomicBool>,
    ) -> Result<(SCDynamicStore, CFRunLoopSource), Error> {
        let mut attempt = 0u32;
        loop {
            match Self::try_register_once(run_loop, Arc::clone(&changed)) {
                Ok(established) => return Ok(established),
                Err(RegistrationFailure::Fatal(error)) => return Err(error),
                Err(RegistrationFailure::Retryable(error)) => {
                    if !should_retry(attempt) {
                        return Err(error);
                    }
                    attempt += 1;
                    crate::trace::warning!(
                        attempt,
                        max_retries = REGISTRATION_MAX_RETRIES,
                        error = %crate::trace::SafeError(&error),
                        "registering the SCDynamicStore proxies notification failed; \
                         retrying after a delay (Chromium's kRetryInterval/kMaxRetry, \
                         network_config_watcher_apple.cc)"
                    );
                    thread::sleep(REGISTRATION_RETRY_INTERVAL);
                }
            }
        }
    }

    // A single, unretried attempt: create the session, subscribe, and create its run loop
    // source, attaching it to `run_loop`. See [`RegistrationFailure`] for why each failure
    // is classified the way it is, and where that parts company with Chromium.
    fn try_register_once(
        run_loop: &CFRunLoop,
        changed: Arc<AtomicBool>,
    ) -> Result<(SCDynamicStore, CFRunLoopSource), RegistrationFailure> {
        let store = SCDynamicStoreBuilder::new(STORE_NAME)
            .callback_context(SCDynamicStoreCallBackContext {
                callout: on_change,
                info: changed,
            })
            .build()
            .ok_or_else(|| {
                RegistrationFailure::Retryable(Error::io(
                    "creating the watching SCDynamicStore session",
                    io::Error::other("SCDynamicStoreCreateWithOptions returned NULL"),
                ))
            })?;

        let keys = CFArray::from_CFTypes(&[
            CFString::from_static_string(SETUP_PROXIES_KEY),
            CFString::from_static_string(STATE_PROXIES_KEY),
        ]);
        let patterns: CFArray<CFString> = CFArray::from_CFTypes(&[]);
        if !store.set_notification_keys(&keys, &patterns) {
            return Err(RegistrationFailure::Retryable(Error::io(
                "subscribing to Setup:/State: Network/Global/Proxies",
                io::Error::other("SCDynamicStoreSetNotificationKeys failed"),
            )));
        }

        crate::trace::debug!(
            setup_key = SETUP_PROXIES_KEY,
            state_key = STATE_PROXIES_KEY,
            "subscribed to the SCDynamicStore proxies keys"
        );

        let source = store.create_run_loop_source().ok_or_else(|| {
            RegistrationFailure::Fatal(Error::io(
                "creating the SCDynamicStore run loop source",
                io::Error::other("SCDynamicStoreCreateRunLoopSource returned NULL"),
            ))
        })?;

        // SAFETY: reading an `extern` static, see `Registration::new`.
        let mode = unsafe { kCFRunLoopDefaultMode };
        run_loop.add_source(&source, mode);

        Ok((store, source))
    }
}

// The `SCDynamicStore` callback, invoked on the watcher thread's run loop.
//
// It does the minimum possible: reading the configuration here would run inside the
// run loop callback and would defeat the debounce window, so it only records that
// *something* changed.
fn on_change(
    _store: SCDynamicStore,
    _changed_keys: CFArray<CFString>,
    changed: &mut Arc<AtomicBool>,
) {
    changed.store(true, Ordering::SeqCst);
}

// The watcher loop. The caller keeps the [`Registration`] alive for its whole duration,
// which is what keeps the subscription (when one was established) and the run loop sources
// in place. Works unchanged whether or not the subscription itself is live: a degraded
// registration still has a run loop and a wake source, and `options.poll_interval` is
// `Some` whenever degraded mode was reached at all.
fn run(
    options: &WatchOptions,
    shared: &Shared,
    stop: &AtomicBool,
    changed: &AtomicBool,
    poll_requested: &AtomicBool,
) {
    // Close the window between the initial read done by `ProxyWatcher::with_options`
    // and the registration above. `Shared::emit` skips equal snapshots, so this
    // costs nothing when nothing changed.
    publish(options, shared);

    // SAFETY: reading an `extern` static, see `Registration::new`.
    let mode = unsafe { kCFRunLoopDefaultMode };
    let wait = idle_wait(options.poll_interval);

    while !stop.load(Ordering::SeqCst) {
        let result = CFRunLoop::run_in_mode(mode, wait, true);
        if stop.load(Ordering::SeqCst) {
            return;
        }
        // A real notification always sets `changed` before waking the loop (`on_change`
        // runs synchronously as part of delivering the source), so a timeout with polling
        // off is a spurious wake and looping again is correct.
        let polled = options.poll_interval.is_some() && result == CFRunLoopRunResult::TimedOut;
        let requested = poll_requested.load(Ordering::SeqCst);
        if !changed.load(Ordering::SeqCst) && !polled && !requested {
            continue;
        }
        if polled {
            crate::trace::debug!("the poll interval elapsed; opening the debounce window");
        }
        if requested {
            crate::trace::debug!("poll_now() opened the debounce window");
        }

        // The fixed window `WatchOptions::debounce` describes; that is what holds the
        // detection-latency SLO under a storm of changes.
        //
        // Held by test elsewhere — `tests/linux_watch.rs` and `tests/windows_watch.rs` both
        // storm their store for seconds and require the snapshot inside the window — and
        // not here, deliberately. The only way to move this machine's proxy setting from a
        // test is `sudo networksetup`, one process per write, which is neither fast enough
        // to outrun a 200 ms window nor cheap enough to run in a loop on a billed runner.
        // What makes that acceptable is the shape rather than the coverage: the sliding
        // mistake is a *branch* reopening the deadline on a wake, and the loop below has no
        // per-wake branch to put it in — `run_in_mode` returns into a body that only
        // recomputes `remaining` from a deadline it never touches. On Linux and on Windows
        // the wake arrives in a `match` arm, which is exactly where that statement fits and
        // where it fits unnoticed.
        let deadline = Instant::now() + effective_debounce(options.debounce);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            CFRunLoop::run_in_mode(mode, remaining, true);
            if stop.load(Ordering::SeqCst) {
                return;
            }
        }

        // Clear *before* reading, so that a change landing during the read is caught by
        // the next round instead of being swallowed.
        changed.store(false, Ordering::SeqCst);
        poll_requested.store(false, Ordering::SeqCst);
        crate::trace::debug!("the debounce window closed; re-reading the dynamic store");
        publish(options, shared);
    }
}

// Read the configuration once and hand the result to the stream side.
fn publish(options: &WatchOptions, shared: &Shared) {
    match read_config(options) {
        // Emit only when the snapshot actually differs from the previous one.
        Ok(config) => shared.emit(config),
        // A transient failure must not end the subscription.
        Err(error) => shared.fail(error),
    }
}

#[cfg(test)]
mod tests {
    //! [`idle_wait`] / [`should_retry`] unit tests; Mac integration in CI (`tests/mac_watch.rs`).

    use super::*;

    #[test]
    fn no_poll_interval_waits_the_full_idle_bound() {
        assert_eq!(idle_wait(None), IDLE_WAIT);
    }

    #[test]
    fn a_shorter_poll_interval_wins() {
        assert_eq!(
            idle_wait(Some(Duration::from_secs(30))),
            Duration::from_secs(30)
        );
    }

    // An unfloored `Duration::ZERO` would make `CFRunLoopRunInMode(mode, 0.0, true)`
    // return immediately every call — a busy loop.
    #[test]
    fn a_too_small_poll_interval_is_clamped_to_the_floor() {
        assert_eq!(
            idle_wait(Some(Duration::ZERO)),
            crate::watch::MIN_POLL_INTERVAL
        );
        assert_eq!(
            idle_wait(Some(Duration::from_millis(1))),
            crate::watch::MIN_POLL_INTERVAL
        );
    }

    #[test]
    fn a_poll_interval_longer_than_the_idle_bound_is_capped() {
        assert_eq!(idle_wait(Some(IDLE_WAIT * 2)), IDLE_WAIT);
        assert_eq!(idle_wait(Some(Duration::MAX)), IDLE_WAIT);
    }

    // Attempts `0..REGISTRATION_MAX_RETRIES` (0-indexed: "this many retries have already
    // happened") should retry again; `REGISTRATION_MAX_RETRIES` itself, or anything past
    // it, should not.
    #[test]
    fn retries_stop_exactly_at_the_chromium_derived_maximum() {
        for attempt in 0..REGISTRATION_MAX_RETRIES {
            assert!(
                should_retry(attempt),
                "attempt {attempt} should still retry"
            );
        }
        assert!(!should_retry(REGISTRATION_MAX_RETRIES));
        assert!(!should_retry(REGISTRATION_MAX_RETRIES + 1));
    }

    // The worst case [`Watch::spawn`] can be blocked by retries, pinned so the two
    // constants cannot silently drift apart from the five seconds `crate::read` now
    // promises on the public surface. That `ProxyWatcher::with_options` pays it twice —
    // it reads through [`super::create_store`]'s own loop over these constants before it
    // spawns — is stated on `with_options`, and is not repeated here.
    #[test]
    fn the_documented_worst_case_retry_delay_is_five_seconds() {
        assert_eq!(
            REGISTRATION_RETRY_INTERVAL * REGISTRATION_MAX_RETRIES,
            Duration::from_secs(5)
        );
    }
}
