//! Linux watcher: notification sources → one debounced reader ([`crate::sys`] contract).
//!
//! ```text
//!  GSettings "changed"  ─┐
//!  kioslaverc inotify   ─┼─→ one pending wake ─→ coordinator ─ debounce ─→ read_config
//!  poll timer           ─┤                                                  │
//!  Watch::poll_now      ─┘                                       Shared::emit ←─┘
//! ```
//!
//! Every wake re-reads everything via [`super::backend::read_config`] (equality skip).
//!
//! This backend runs more than one OS thread: the coordinator always, the GSettings main
//! loop while that subscription is live, the poll timer while
//! [`WatchOptions::poll_interval`] is set, and whatever `notify` spawns for the inotify
//! watch. Only [`Watch::poll_now`] wakes the coordinator from the caller's own thread.
//! [`Drop`] joins the ones this module started.
//!
//! | Route | Notification |
//! |---|---|
//! | GSettings | `changed` on root + children |
//! | `kioslaverc` | inotify on config dir |
//! | Portal | **none** — needs [`WatchOptions::poll_interval`] |
//!
//! Leading store watch failure without poll → fatal. Portal silence alone is never an
//! [`Error`] (no public single-read API). [`Drop`] tears sources down, then the last
//! [`Sender`].

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
// Only named by the feature-gated `*_fail_soft` signatures below.
#[cfg_attr(
    not(any(feature = "linux-gnome", feature = "linux-kde")),
    allow(unused_imports)
)]
use std::time::Duration;
use std::time::Instant;

use crate::error::Error;
// `WatchFailSoft` / `watch_fail_soft` / `fatal_watch_error` are only named inside
// the feature-gated `*_fail_soft` functions below; the rest are also used outside them.
#[cfg_attr(
    not(any(feature = "linux-gnome", feature = "linux-kde")),
    allow(unused_imports)
)]
use crate::watch::{
    BackendHealth, Shared, WatchFailSoft, WatchOptions, effective_debounce, fatal_watch_error,
    watch_fail_soft,
};

use super::backend::read_config;
use super::desktop;
use super::sandbox;

// The Linux watcher. See the module documentation for the design.
pub(crate) struct Watch {
    // Kept so that the coordinator's channel stays open for the watcher's lifetime;
    // dropped by [`Drop`] to stop it. Also the template every source clones.
    trigger: Option<SyncSender<()>>,
    // Handed to the coordinator by [`Watch::spawn`].
    triggers: Option<Receiver<()>>,
    // Whether the sandbox forced the portal route, in which case there is nothing to
    // subscribe to.
    //
    // Decided once, in [`Watch::armed`], and then fixed for this watcher's life —
    // deliberately, and not the same rule the read path follows.
    // [`backend::read_config`](super::backend::read_config) calls `sandbox::detect` on
    // every read and says so. It can afford to, because a read starts from nothing; this
    // field is the route the subscriptions below were wired against, and re-deciding it
    // would describe a wiring that no longer matches what was registered.
    portal_route: bool,
    // Whether GSettings is the store [`is_leading_store`] answers for — decided in
    // [`Watch::armed`], out of the same reading of the environment as the `kioslaverc`
    // half, and fixed for the same reason `portal_route` is. The two answers describe one
    // wiring and are meant to be complementary, but `spawn` runs after the constructor's
    // own `read_config`: asking again there could make both stores answer "leading", or
    // neither — and neither fail-softens the failure of the store that has no fallback.
    #[cfg(feature = "linux-gnome")]
    gsettings_is_leading: bool,
    // `None` until [`Watch::spawn`] runs, and for the portal route, which never attempts
    // a GSettings subscription.
    #[cfg(feature = "linux-gnome")]
    gnome: Option<GnomeWatch>,
    // `None` only for the portal route, which never attempts a `kioslaverc` watch.
    #[cfg(feature = "linux-kde")]
    kde: Option<KdeWatch>,
    poll: Option<Poll>,
    coordinator: Option<JoinHandle<()>>,
}

// The outcome of one attempt to establish the `kioslaverc` watch, kept apart from a bare
// `Option<FileWatch>` so [`Watch::health`] can tell two very different "nothing to watch"
// cases apart: [`KdeWatch::NoDirectory`] means no candidate configuration directory
// exists, which is the not-configured-at-all case [`WatchHealth::degraded`]'s own doc
// excludes rather than a failure; [`KdeWatch::Degraded`] means a genuine inotify failure
// (a hit `fs.inotify.max_user_watches` limit, say) was fail-softened by
// [`kde_watch_fail_soft`], which *is* what [`WatchHealth::degraded`] exists to report.
#[cfg(feature = "linux-kde")]
enum KdeWatch {
    // Established; dropping this stops the inotify registration. The payload is kept both
    // so that [`Drop for Watch`](Watch)'s `self.kde.take()` drops it, and so
    // [`KdeWatch::is_live`] can ask it whether it is *still* established: a watched
    // directory that is removed or renamed is gone for good: removal drops the `notify`
    // watch, and a rename leaves it armed on the moved inode rather than on the path the
    // reader uses. Losing *one* directory is not losing the registration — this is `false` only
    // once every one has gone; the first loss is reported through
    // [`super::kde::FileWatch::any_lost`] instead.
    Live(super::kde::FileWatch),
    // No candidate directory exists; see the type doc.
    NoDirectory,
    // A genuine inotify failure was fail-softened; see the type doc.
    Degraded,
}

#[cfg(feature = "linux-kde")]
impl KdeWatch {
    // Whether this counts as a live change-notification source for
    // [`Watch::has_live_notification_source`].
    //
    // Being [`KdeWatch::Live`] is necessary but not sufficient: the watch can go
    // permanently silent after construction, so the payload is asked too.
    fn is_live(&self) -> bool {
        matches!(self, KdeWatch::Live(watch) if watch.is_live())
    }
}

// The outcome of one attempt to start the GSettings subscription — the GNOME-side twin of
// [`KdeWatch`], drawing the same line: [`GnomeWatch::NoSchema`] means
// `gsettings-desktop-schemas` is not installed, so there is no store here to subscribe to
// and nothing is degraded; [`GnomeWatch::Degraded`] means a genuine start failure was
// fail-softened by [`gnome_start_fail_soft`].
#[cfg(feature = "linux-gnome")]
enum GnomeWatch {
    // Established; dropping this stops the subscription and joins its thread. The payload
    // is never read — it is carried solely so [`Drop for Watch`](Watch)'s
    // `self.gnome.take()` drops it, hence the explicit `allow`.
    Live(#[allow(dead_code)] super::gnome::Handle),
    // The schema is not installed; see the type doc.
    NoSchema,
    // A genuine start failure was fail-softened; see the type doc.
    Degraded,
}

#[cfg(feature = "linux-gnome")]
impl GnomeWatch {
    // Whether this counts as a live change-notification source for
    // [`Watch::has_live_notification_source`].
    //
    // A verdict from start time, and it never changes afterwards: nothing on this side
    // reports a subscription that stops delivering once it has been established. The KDE
    // side does — [`super::kde::LossFlags`] reaches `health().degraded` through
    // [`LossReport`] — so `has_live_notification_source` asks the GNOME arm a weaker
    // question than the KDE arm, and this is the GNOME answer. Whether GIO offers
    // something to build the other half out of has not been established here; what is
    // established is that this answer means "it started", not "it is working".
    fn is_live(&self) -> bool {
        matches!(self, GnomeWatch::Live(_))
    }
}

impl std::fmt::Debug for Watch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watch")
            .field("portal_route", &self.portal_route)
            .field("polling", &self.poll.is_some())
            .field("running", &self.coordinator.is_some())
            .finish_non_exhaustive()
    }
}

// Ask the coordinator for a re-read, reporting whether it is still there to ask.
//
// A refused wake is not a lost change: `try_send` can only fail because a wake is already
// pending, and the coordinator consumes that one *before* opening the read it leads to. So
// the read happens strictly after whatever this call was reporting, and it re-reads
// everything. That is what lets the channel hold one wake rather than a queue of them.
pub(super) fn wake(trigger: &SyncSender<()>) -> bool {
    !matches!(trigger.try_send(()), Err(TrySendError::Disconnected(())))
}

// Ask for a re-read on a send that is not allowed to be refused.
//
// A refused `try_send` costs nothing when a later wake can carry the same news, which is
// the ordinary case — but it publishes nothing. `TrySendError::Full` says only that the
// buffer was full at that instant; it is not a send, so it leaves no happens-before edge,
// and whatever the caller stored beforehand may still be invisible to the coordinator on
// the pass that follows. Blocking here is what turns the store into something the
// coordinator is guaranteed to see. The wait is bounded by one coordinator pass, and the
// one caller uses it at most once in a watcher's life: when the `kioslaverc` route goes
// completely dark there is no later event to try again with.
#[cfg(feature = "linux-kde")]
pub(super) fn wake_delivered(trigger: &SyncSender<()>) {
    // The coordinator being gone is the other reason a wake stops mattering.
    let _ = trigger.send(());
}

impl Watch {
    // Register everything that can be registered without a thread. The `kioslaverc`
    // inotify watch is registered here rather than in [`Watch::spawn`], which is what
    // spares it the re-read `spawn` sends for GSettings: the fd exists before the
    // constructor's own `read_config`, so a change in the window between the two is
    // already queued on it.
    #[cfg_attr(not(feature = "linux-kde"), allow(unused_variables))]
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    pub(crate) fn armed(options: &WatchOptions) -> Result<Self, Error> {
        // One pending wake is the whole state: every sender means "re-read everything",
        // so a second one queued behind the first would buy a second identical read. The
        // capacity is what bounds the memory — an unbounded channel here grows for as long
        // as senders outrun the coordinator, which cannot receive during `read_config`.
        // A sender in a loop — the shape [`Watch::poll_now`] lets a caller write — against a
        // one-second read queues millions of wakes and hundreds of megabytes of resident
        // memory within a few debounce cycles, still climbing; at capacity 1 the backlog
        // stays at one wake and the resident size does not move. Windows and macOS coalesce
        // the same way —
        // an auto-reset event and an `AtomicBool` respectively.
        let (trigger, triggers) = mpsc::sync_channel(1);
        let portal_route = !sandbox::detect().gsettings_is_trustworthy();
        // Read once and answer both stores from it; see `gsettings_is_leading`.
        #[cfg(any(feature = "linux-gnome", feature = "linux-kde"))]
        let desktop = desktop::current();

        // No test holds this guard, and none in this repository can. `armed` runs before the
        // constructor's `read_config` (`ProxyWatcher::with_options`), so a portal-route
        // watcher is armed and then thrown away when that read fails — and the read only
        // succeeds on this route when a real `org.freedesktop.portal.ProxyResolver` answers,
        // which no test environment here provides — `--include-ignored` and every integration
        // suite included.
        //
        // What it costs where the portal does answer is not a spare inotify watch.
        // `kde_watch_fail_soft` is fallible, so on a KDE-flavoured sandbox with no
        // `poll_interval` the `?` below would fail construction outright over a store this
        // route never reads; short of that, `health` would file `Kioslaverc` under `degraded`
        // for the same store. Both describe a wiring that is not there.
        #[cfg(feature = "linux-kde")]
        let kde = if portal_route {
            None
        } else {
            Some(kde_watch_fail_soft(
                trigger.clone(),
                is_leading_store(desktop, desktop::Store::Kioslaverc),
                options.poll_interval,
            )?)
        };
        // The outcome, not the intent: `kde_watch_fail_soft` fails soft, so being compiled
        // in and on this route only says the watch was *attempted*. Reporting that instead
        // would contradict the warning it just logged.
        #[cfg(feature = "linux-kde")]
        let kioslaverc_watch = matches!(&kde, Some(kde) if kde.is_live());
        #[cfg(not(feature = "linux-kde"))]
        let kioslaverc_watch = false;
        crate::trace::debug!(
            portal_route,
            kioslaverc_watch,
            "armed the Linux change notifications"
        );

        Ok(Self {
            trigger: Some(trigger),
            triggers: Some(triggers),
            portal_route,
            #[cfg(feature = "linux-gnome")]
            gsettings_is_leading: is_leading_store(desktop, desktop::Store::GSettings),
            #[cfg(feature = "linux-gnome")]
            gnome: None,
            #[cfg(feature = "linux-kde")]
            kde,
            poll: None,
            coordinator: None,
        })
    }

    // Start the GSettings thread, the polling thread and the coordinator.
    pub(crate) fn spawn(
        &mut self,
        options: &WatchOptions,
        shared: Arc<Shared>,
    ) -> Result<(), Error> {
        let triggers = self
            .triggers
            .take()
            .expect("Watch::spawn must be called exactly once");
        let trigger = self
            .trigger
            .clone()
            .expect("the trigger is only taken by Drop");

        #[cfg(feature = "linux-gnome")]
        if !self.portal_route {
            self.gnome = Some(gnome_start_fail_soft(
                trigger.clone(),
                self.gsettings_is_leading,
                options.poll_interval,
            )?);
            if matches!(&self.gnome, Some(gnome) if gnome.is_live()) {
                // The subscription went live after the constructor's initial read; ask for
                // one re-read so a change in that window is not lost.
                //
                // No test holds this, and none can — `--include-ignored` and every
                // integration suite
                // included. Holding it needs a change the re-read sees and the subscription
                // does not. Under dconf, a change made once the constructor has returned
                // reaches the live subscription as well, so the re-read is never the only
                // route that could have delivered it. Under the keyfile backend — whose
                // `GFileMonitor` sits on a context no watcher thread iterates, see
                // `tests/gsettings_writable_watch.rs` — the read path does not see the
                // change at all, measured for a written value and for a `chmod` on the
                // settings directory alike. And the window itself lies inside
                // [`ProxyWatcher::with_options`](crate::ProxyWatcher), between the read it
                // does and the subscription it starts, so there is nowhere else to write
                // from.
                wake(&trigger);
            }
        }

        if let Some(interval) = options.poll_interval {
            // Clamp before the poll thread ever sees the value; see [`poll_wait`].
            let interval = poll_wait(interval);
            crate::trace::debug!(interval = ?interval, "starting the polling fallback");
            self.poll = Some(Poll::start(trigger.clone(), interval)?);
        } else if !self.has_live_notification_source() {
            // No live source, and nothing left to fall back on: the watcher emits the
            // initial snapshot and then nothing. Without the `tracing` feature every arm
            // below becomes empty, hence the `allow`.
            #[cfg_attr(not(feature = "tracing"), allow(clippy::if_same_then_else))]
            if self.portal_route {
                crate::trace::warning!(
                    "the portal route has no change notification; set \
                     WatchOptions::poll_interval or this watcher will never update"
                );
            } else {
                crate::trace::warning!(
                    "every Linux change notification source is degraded or absent; set \
                     WatchOptions::poll_interval or this watcher will never update"
                );
            }
        }

        // Computed here rather than in `armed` because it needs the GSettings outcome: if
        // that subscription is live, a dead `kioslaverc` watch degrades one source but does
        // not leave the watcher without any native route at all.
        #[cfg(feature = "linux-kde")]
        let kde_loss = match &self.kde {
            Some(KdeWatch::Live(watch)) => Some(watch.loss_flags()),
            _ => None,
        };
        #[cfg(feature = "linux-kde")]
        let kde_is_the_last_live_route = {
            #[cfg(feature = "linux-gnome")]
            {
                !matches!(&self.gnome, Some(gnome) if gnome.is_live())
            }
            #[cfg(not(feature = "linux-gnome"))]
            {
                true
            }
        };

        let options = options.clone();
        self.coordinator = Some(
            thread::Builder::new()
                .name("proxy-watch-linux".to_owned())
                .spawn(move || {
                    let _guard = crate::watch::ThreadGuard::new(Arc::clone(&shared));
                    crate::trace::debug!("the Linux coordinator thread started");
                    coordinate(
                        &options,
                        &shared,
                        &triggers,
                        #[cfg(feature = "linux-kde")]
                        LossReport {
                            flags: kde_loss,
                            last_live_route: kde_is_the_last_live_route,
                            degraded: false,
                        },
                    );
                })
                .map_err(|source| Error::io("spawning the proxy-watch Linux thread", source))?,
        );
        Ok(())
    }

    // Whether at least one change notification source is actually live right now.
    fn has_live_notification_source(&self) -> bool {
        // Redundant today and kept deliberately. `armed` leaves `kde` `None` on this route
        // and `spawn` only builds `gnome` off it, so the `gnome` arm and the `kde` arm
        // below already answer false whenever this one would — deleting it changes no
        // answer this crate can produce, which is why no test holds it. What it holds
        // instead is the direction: the portal route has no notification of its own, and a
        // future source registered without that in mind would otherwise be reported live to
        // a caller the portal cannot wake.
        if self.portal_route {
            return false;
        }
        #[cfg(feature = "linux-gnome")]
        if matches!(&self.gnome, Some(gnome) if gnome.is_live()) {
            return true;
        }
        #[cfg(feature = "linux-kde")]
        if matches!(&self.kde, Some(kde) if kde.is_live()) {
            return true;
        }
        false
    }

    // Report which documented Linux notification routes were not established
    // or have since degraded (e.g. a watched kioslaverc directory was deleted).
    #[cfg_attr(
        not(any(feature = "linux-gnome", feature = "linux-kde")),
        allow(unused_mut)
    )]
    pub(crate) fn health(&self) -> BackendHealth {
        let mut degraded = Vec::new();
        #[cfg(feature = "linux-gnome")]
        if matches!(&self.gnome, Some(GnomeWatch::Degraded)) {
            degraded.push(crate::config::ProxyConfigSource::GSettings);
        }
        #[cfg(feature = "linux-kde")]
        if matches!(&self.kde, Some(KdeWatch::Degraded))
            || matches!(&self.kde, Some(KdeWatch::Live(watch)) if watch.any_lost())
        {
            degraded.push(crate::config::ProxyConfigSource::Kioslaverc);
        }
        BackendHealth {
            degraded,
            has_live_notifications: self.has_live_notification_source(),
        }
    }

    // Ask the coordinator to re-read the configuration right now — the explicit re-check
    // path a caller can invoke directly.
    pub(crate) fn poll_now(&self) {
        if let Some(trigger) = &self.trigger {
            wake(trigger);
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        crate::trace::debug!("stopping the Linux watcher");
        // Sources first: each of them owns a clone of the trigger, and the coordinator
        // only stops once every clone is gone.
        #[cfg(feature = "linux-gnome")]
        drop(self.gnome.take());
        #[cfg(feature = "linux-kde")]
        drop(self.kde.take());
        drop(self.poll.take());
        drop(self.trigger.take());
        if let Some(thread) = self.coordinator.take() {
            let _ = thread.join();
        }
    }
}

// Whether `store` is the one whose failure leaves nothing behind it — what the
// fatal-without-polling rule actually asks. Usually that is the store [`desktop::order`]
// puts first for the desktop this process runs under, but a store that is not in this
// build cannot be anything's fallback, so when the leading one is compiled out the other
// store inherits the position rather than the position going unfilled. `backend`'s
// [`warn_if_the_leading_store_was_compiled_out`](super::backend) draws the same line on
// the read path, and `kde_is_the_last_live_route` in [`Watch::spawn`] on the runtime-loss
// path; this is the same question asked at construction.
//
// The desktop is a parameter rather than something read here because both stores must be
// answered from one reading — see [`Watch::gsettings_is_leading`](Watch).
#[cfg_attr(
    not(any(feature = "linux-gnome", feature = "linux-kde")),
    allow(dead_code)
)]
fn is_leading_store(desktop: desktop::Desktop, store: desktop::Store) -> bool {
    let leading = desktop::order(desktop)[0];
    if desktop::is_compiled_in(leading) {
        leading == store
    } else {
        // Only the two stores exist, and a caller only runs when its own feature is on,
        // so `store` here is necessarily the one that is left.
        leading != store
    }
}

// Why a Linux leading store's failure has no fallback left, for
// [`crate::watch::fatal_watch_error`]'s `why_no_fallback` parameter — shared by both
// [`kde_watch_fail_soft`] and [`gnome_start_fail_soft`] since it does not depend on
// which of the two stores actually failed, only on the fact that it was the leading one.
//
// The disjunction is [`is_leading_store`]'s second branch, and the reader is the one who
// needs it: naming only the desktop's own store puts the wrong desktop in the message
// whenever the position was inherited, which is a build where the leading store's feature
// is off — precisely the build where a reader looking at `XDG_CURRENT_DESKTOP` would
// conclude this error is about some other session's settings and stop reading.
// `backend`'s [`warn_if_the_leading_store_was_compiled_out`](super::backend) says the same
// thing on the read path, which is where this wording is borrowed from.
#[cfg_attr(
    not(any(feature = "linux-gnome", feature = "linux-kde")),
    allow(dead_code)
)]
const LEADING_STORE_HAS_NO_FALLBACK: &str = "this is the leading Linux desktop store — \
     either the store belonging to the desktop XDG_CURRENT_DESKTOP says is actually \
     running, or, when that desktop's store is not compiled into this build, the store \
     that inherits the position — so there is no other source left to notice a later \
     change with";

// Establish the `kioslaverc` inotify watch for [`Watch::armed`].
#[cfg(feature = "linux-kde")]
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn kde_watch_fail_soft(
    trigger: SyncSender<()>,
    leading: bool,
    poll_interval: Option<Duration>,
) -> Result<KdeWatch, Error> {
    match watch_fail_soft(leading, poll_interval, super::kde::watch(trigger)) {
        WatchFailSoft::Live(Some(watch)) => Ok(KdeWatch::Live(watch)),
        WatchFailSoft::Live(None) => Ok(KdeWatch::NoDirectory),
        WatchFailSoft::Degraded(error) => {
            crate::trace::warning!(
                error = %crate::trace::SafeError(&error),
                "failed to watch kioslaverc for changes (for example, a hit \
                 fs.inotify.max_user_watches limit); continuing without kioslaverc \
                 change notifications"
            );
            Ok(KdeWatch::Degraded)
        }
        WatchFailSoft::Fatal(error) => Err(fatal_watch_error(
            "watching kioslaverc for changes",
            LEADING_STORE_HAS_NO_FALLBACK,
            error,
        )),
    }
}

// Start the GSettings change subscription for [`Watch::spawn`].
#[cfg(feature = "linux-gnome")]
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn gnome_start_fail_soft(
    trigger: SyncSender<()>,
    leading: bool,
    poll_interval: Option<Duration>,
) -> Result<GnomeWatch, Error> {
    match watch_fail_soft(leading, poll_interval, super::gnome::Handle::start(trigger)) {
        WatchFailSoft::Live(Some(handle)) => Ok(GnomeWatch::Live(handle)),
        WatchFailSoft::Live(None) => Ok(GnomeWatch::NoSchema),
        WatchFailSoft::Degraded(error) => {
            crate::trace::warning!(
                error = %crate::trace::SafeError(&error),
                "failed to start the GSettings change subscription (for example, a \
                 GMainContext that could not be acquired); continuing without GSettings \
                 change notifications"
            );
            Ok(GnomeWatch::Degraded)
        }
        WatchFailSoft::Fatal(error) => Err(fatal_watch_error(
            "starting the GSettings change subscription",
            LEADING_STORE_HAS_NO_FALLBACK,
            error,
        )),
    }
}

// What the coordinator needs in order to report a `kioslaverc` watch that died after
// construction.
#[cfg(feature = "linux-kde")]
struct LossReport {
    // `None` when there is no live `kioslaverc` watch to lose in the first place, and
    // again once every report this can make has been made.
    flags: Option<super::kde::LossFlags>,
    // Whether losing the `kioslaverc` watch **entirely** leaves the watcher with no
    // native notification route at all, decided in [`Watch::spawn`] once the GSettings
    // outcome is known.
    last_live_route: bool,
    // Whether [`ProxyConfigSource::Kioslaverc`](crate::config::ProxyConfigSource) has
    // already been reported as degraded. The flags stay in place afterwards, because the
    // second report — the route going completely dark — can arrive much later.
    degraded: bool,
}

#[cfg(feature = "linux-kde")]
impl LossReport {
    // Fold a loss into [`Shared`]'s runtime health, each half at most once.
    fn check(&mut self, shared: &Shared) {
        let Some(flags) = &self.flags else {
            return;
        };
        if !flags.any_lost() {
            return;
        }
        if !self.degraded {
            shared.degrade(crate::config::ProxyConfigSource::Kioslaverc);
            self.degraded = true;
        }
        if flags.is_live() {
            // Some watched directory can still deliver; the route is not dark yet.
            return;
        }
        if self.last_live_route {
            shared.mark_no_live_notifications();
        }
        // Both reports made; stop looking.
        self.flags = None;
    }
}

// The coordinator loop: wait, debounce, re-read, emit.
//
// Every source — `GSettings::changed`, `kioslaverc` inotify, the [`Poll`] timer and
// [`Watch::poll_now`] — arrives here as the same content-free `()`, and the answer is
// always a full [`read_config`] rather than a partial update; see the module diagram.
fn coordinate(
    options: &WatchOptions,
    shared: &Shared,
    triggers: &Receiver<()>,
    #[cfg(feature = "linux-kde")] mut kde_loss: LossReport,
) {
    while triggers.recv().is_ok() {
        // The fixed window `WatchOptions::debounce` describes; that is what holds the
        // 1-second detection-latency SLO here, where a storm is the normal case — each
        // GSettings key written fires its own signal.
        let deadline = Instant::now() + effective_debounce(options.debounce);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match triggers.recv_timeout(remaining) {
                Ok(()) => {}
                Err(RecvTimeoutError::Timeout) => break,
                // Every sender is gone, so the watcher is going away: leave without
                // emitting into a queue nobody will read.
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
        // Before the read, so a caller that inspects `health()` on the snapshot this
        // publishes already sees the route as degraded.
        #[cfg(feature = "linux-kde")]
        kde_loss.check(shared);
        crate::trace::debug!("the debounce window closed; re-reading every Linux source");
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

// The wait [`Poll`]'s thread hands to `recv_timeout`, from the caller's requested
// interval.
//
// The floor is what stops a tiny interval spinning that `recv_timeout` into a busy loop.
// The ceiling is what stops a huge one from silencing it: `Receiver::recv_timeout` turns
// `timeout` into `Instant::now() + timeout` and, when that is not representable, waits with
// a plain `recv` instead — indefinitely. A `Duration::MAX` interval would therefore leave
// the timer never firing while [`crate::watch::WatchHealth::is_frozen`] still answered
// `false`, since a `poll_interval` was set. Windows and macOS cap at their own conversion
// points (`poll_wait_millis`, `idle_wait`); this is the Linux one.
fn poll_wait(requested: Duration) -> Duration {
    const CEILING: Duration = Duration::from_secs(24 * 60 * 60);
    crate::watch::effective_poll_interval(requested).min(CEILING)
}

// The polling fallback.
struct Poll {
    // Dropped by [`Drop`]; the thread's `recv_timeout` then fails and it returns.
    stop: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Poll {
    fn start(trigger: SyncSender<()>, interval: std::time::Duration) -> Result<Self, Error> {
        let (stop, stopped) = mpsc::channel::<()>();
        let thread = thread::Builder::new()
            .name("proxy-watch-poll".to_owned())
            .spawn(move || {
                // `recv_timeout` is the wait: it returns early the moment the sender is
                // dropped, so `Drop` never has to wait out a whole interval.
                while matches!(
                    stopped.recv_timeout(interval),
                    Err(RecvTimeoutError::Timeout)
                ) {
                    if !wake(&trigger) {
                        return;
                    }
                }
            })
            .map_err(|source| Error::io("spawning the proxy-watch polling thread", source))?;
        Ok(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Poll {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    //! [`watch_fail_soft`]'s own judgement-table tests live in `src/watch.rs`, where the
    //! function lives and is shared with the Windows backend. What stays local is Linux's
    //! wiring into it: the wording [`LEADING_STORE_HAS_NO_FALLBACK`] contributes to a
    //! fatal error.

    use super::*;

    fn some_error() -> Error {
        Error::Unsupported
    }

    // [`crate::watch::fatal_watch_error`] must say what to do about it, not just that it
    // failed: a caller who only learns "the watch failed" has no way to know that
    // `WatchOptions::poll_interval` turns it back into degrade-and-continue.
    #[test]
    fn the_fatal_error_names_the_fix() {
        let error = fatal_watch_error(
            "watching kioslaverc for changes",
            LEADING_STORE_HAS_NO_FALLBACK,
            some_error(),
        );
        let message = error.to_string();
        assert!(
            message.contains("poll_interval"),
            "the error should point at the fix: {message}"
        );
        assert!(
            message.contains("watching kioslaverc for changes"),
            "the error should still say what failed: {message}"
        );
        assert!(
            message.contains("leading Linux desktop store"),
            "the error should still say why there is no fallback: {message}"
        );
    }

    // The store whose failure has nothing behind it, asked of every desktop this crate
    // classifies: exactly one store answers yes, and it is one this build can actually
    // read. Neither arm of [`is_leading_store`] was held, and what the answer decides is
    // whether a failed watch is fatal or fail-softened. Answer yes for every store and a
    // degraded GSettings subscription kills a watcher that still has `kioslaverc`; keep
    // the position on a store that is compiled out and the one store this build *can*
    // read fails soft with nothing behind it, which is the silent half.
    #[cfg(any(feature = "linux-gnome", feature = "linux-kde"))]
    #[test]
    fn one_store_this_build_can_read_leads_every_desktop() {
        for desktop in [
            desktop::Desktop::Gnome,
            desktop::Desktop::Kde,
            desktop::Desktop::Unknown,
        ] {
            let leading: Vec<_> = [desktop::Store::GSettings, desktop::Store::Kioslaverc]
                .into_iter()
                .filter(|store| is_leading_store(desktop, *store))
                .collect();
            assert_eq!(leading.len(), 1, "{desktop:?}");
            assert!(desktop::is_compiled_in(leading[0]), "{desktop:?}");
            // And it is the store whose feature is on. The line above cannot say that:
            // transposing the `GSettings` and `Kioslaverc` arms of
            // [`desktop::is_compiled_in`] is self-consistent — this function reads the
            // *other* store whenever the answer is no — so the count stays one and the store
            // it names still calls itself compiled in, while the leading position has moved
            // onto the store this build left out. What that costs is the half named above:
            // the store this build *can* read is no longer the leading one, so its failed
            // watch fail-softens with nothing behind it. Only a build with `linux-gnome` or
            // `linux-kde` on but not the other can see the transposition at all, because
            // with both on each `cfg!` is true either way. An `--all-features` run is
            // therefore blind to it; CI's feature matrix has `resolve,linux-gnome` and
            // `resolve,linux-kde`, and each catches it from its own side.
            #[cfg(not(feature = "linux-kde"))]
            assert_eq!(leading[0], desktop::Store::GSettings, "{desktop:?}");
            #[cfg(not(feature = "linux-gnome"))]
            assert_eq!(leading[0], desktop::Store::Kioslaverc, "{desktop:?}");
        }
    }

    // A source that failed and was fail-softened is not a source. These are the arms
    // [`Watch::has_live_notification_source`] — and through it
    // [`WatchHealth::is_frozen`](crate::WatchHealth::is_frozen) — must not count, and this
    // test is the only thing holding that. Read [`GnomeWatch::is_live`] as "anything except
    // `NoSchema`" and a watcher whose subscription never started reports live notifications
    // and never admits to being frozen.
    #[cfg(any(feature = "linux-gnome", feature = "linux-kde"))]
    #[test]
    fn a_fail_softened_source_does_not_count_as_live() {
        #[cfg(feature = "linux-gnome")]
        {
            assert!(!GnomeWatch::Degraded.is_live());
            assert!(!GnomeWatch::NoSchema.is_live());
        }
        #[cfg(feature = "linux-kde")]
        {
            assert!(!KdeWatch::Degraded.is_live());
            assert!(!KdeWatch::NoDirectory.is_live());
        }
    }

    // The other half of [`Watch::health`]'s `kioslaverc` clause: a watch that *was*
    // established and has since lost a directory. The test above works on the enum arms, and
    // a loss does not change the arm — it stays [`KdeWatch::Live`] and says so through the
    // payload — so this test is the only thing that would see a route which can no longer
    // report a change go unnamed in `degraded`.
    //
    // The three rows are the distinction the clause exists for, and only the middle one
    // needs it: one directory of the cascade gone is degraded *and* still live, because the
    // survivors still report. Read the arm alone and that machine is healthy; read
    // `has_live_notifications` alone and it is indistinguishable from an intact one.
    #[cfg(feature = "linux-kde")]
    #[test]
    fn a_kioslaverc_watch_that_lost_a_directory_is_degraded_while_the_rest_still_report() {
        for (lost, live_directories, expect_degraded, expect_live) in [
            (false, 2, false, true),
            (true, 1, true, true),
            (true, 0, true, false),
        ] {
            let watch = Watch {
                trigger: None,
                triggers: None,
                portal_route: false,
                #[cfg(feature = "linux-gnome")]
                gsettings_is_leading: false,
                #[cfg(feature = "linux-gnome")]
                gnome: None,
                kde: Some(KdeWatch::Live(
                    super::super::kde::FileWatch::with_flags_for_test(lost, live_directories),
                )),
                poll: None,
                coordinator: None,
            };
            let health = watch.health();
            let case = format!("lost={lost} live_directories={live_directories}");
            assert_eq!(
                health
                    .degraded
                    .contains(&crate::config::ProxyConfigSource::Kioslaverc),
                expect_degraded,
                "{case}: {:?}",
                health.degraded
            );
            assert_eq!(health.has_live_notifications, expect_live, "{case}");
        }
    }

    // The survivor clause in [`LossReport::check`]: one lost directory out of several is a
    // degrade and nothing more. This test is the only thing holding it, and what it holds off
    // is a lie in the other direction from the usual one — the *first* loss of a cascade
    // marking the route dark, so `is_frozen` answers yes about a watcher that still reports
    // every change made to the directory `read_store` actually reads.
    //
    // The three rows are what the clause distinguishes, run against one report in sequence
    // because the second half is defined to be sayable long after the first: the reports are
    // each made at most once, and only the loss that empties the cascade makes the second.
    #[cfg(feature = "linux-kde")]
    #[test]
    fn a_survivor_of_the_cascade_keeps_the_route_out_of_the_dark() {
        let shared = Shared::new(crate::config::ProxyConfig::direct());
        shared.set_construction_health(crate::WatchHealth {
            degraded: Vec::new(),
            has_live_notifications: true,
            poll_interval: None,
            stopped: false,
        });
        let watch = super::super::kde::FileWatch::with_flags_for_test(false, 2);
        let mut report = LossReport {
            flags: Some(watch.loss_flags()),
            last_live_route: true,
            degraded: false,
        };

        report.check(&shared);
        assert!(shared.health().degraded.is_empty(), "nothing lost yet");
        assert!(shared.health().has_live_notifications);

        // One of the two gone: the survivor still delivers, so the loss is a degrade only.
        watch.loss_flags().lose_one_for_test();
        report.check(&shared);
        assert_eq!(
            shared.health().degraded,
            vec![crate::config::ProxyConfigSource::Kioslaverc]
        );
        assert!(
            shared.health().has_live_notifications,
            "a cascade with a live directory left still reports changes to it"
        );

        // And now the last one.
        watch.loss_flags().lose_one_for_test();
        report.check(&shared);
        assert!(!shared.health().has_live_notifications);
        assert_eq!(
            shared.health().degraded,
            vec![crate::config::ProxyConfigSource::Kioslaverc],
            "the degrade is reported once, not once per loss"
        );
    }

    // [`wake`] answers whether the coordinator is still there to ask, which is not the same
    // question as whether this particular send landed. This test is the only thing holding
    // the difference, and
    // [`Poll::start`] stops its thread on a `false`: read a full buffer as failure and the
    // polling fallback — the one route a machine with no working notification has — ends the
    // first time a wake happens to be already pending, which is exactly when the system is
    // busy. It comes back only if the watcher is rebuilt.
    #[test]
    fn a_wake_nobody_has_drained_yet_is_not_a_dead_coordinator() {
        let (trigger, triggers) = mpsc::sync_channel::<()>(1);
        assert!(wake(&trigger), "an empty buffer takes the wake");
        assert!(
            wake(&trigger),
            "a wake already pending is the coalescing this channel is sized for"
        );
        drop(triggers);
        assert!(!wake(&trigger), "no coordinator left to ask");
    }

    // The property the ceiling in [`poll_wait`] exists for: whatever the caller asks for,
    // `recv_timeout` must still be able to build a deadline out of it. The first assertion
    // is the control — it is what the poll thread would be handed without the clamp, and
    // `recv_timeout` answers an unrepresentable deadline by waiting forever instead.
    #[test]
    fn every_poll_wait_stays_a_deadline_recv_timeout_can_represent() {
        assert!(Instant::now().checked_add(Duration::MAX).is_none());
        for requested in [
            Duration::ZERO,
            Duration::from_secs(30),
            Duration::from_secs(u64::from(u32::MAX)),
            Duration::MAX,
        ] {
            assert!(
                Instant::now().checked_add(poll_wait(requested)).is_some(),
                "requested {requested:?}"
            );
        }
    }
}
