//! Public watcher façade: [`ProxyWatcher`], [`WatchOptions`]. Platform backend on a dedicated thread.

use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use futures_core::Stream;

use crate::config::{ProxyConfig, ProxyConfigSource};
use crate::error::Error;
use crate::sys;

/// The default debounce window (200 ms).
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(200);

// The shortest [`WatchOptions::poll_interval`] any backend will wait for.
pub(crate) const MIN_POLL_INTERVAL: Duration = DEFAULT_DEBOUNCE;

// Cap [`WatchOptions::debounce`] at a day because `Instant::now() + debounce` panics on
// overflow, and a day already exceeds any useful coalescing window.
pub(crate) const MAX_DEBOUNCE: Duration = Duration::from_secs(24 * 60 * 60);

// Cap undelivered items at 1024 each time [`Shared::emit`] trims, oldest first; a failure
// arriving after the trim can hold one more until the next snapshot. Snapshots fold into
// one another, so what this bounds is the number of undelivered failures.
const MAX_QUEUED_CHANGES: usize = 1024;

// Clamp a caller-supplied poll interval to [`MIN_POLL_INTERVAL`] so no backend can spin.
#[cfg_attr(
    not(any(windows, target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) fn effective_poll_interval(requested: Duration) -> Duration {
    if requested < MIN_POLL_INTERVAL {
        crate::trace::warning!(
            requested = ?requested,
            floor = ?MIN_POLL_INTERVAL,
            "poll_interval is below the minimum that avoids a busy loop; using the floor instead"
        );
        MIN_POLL_INTERVAL
    } else {
        requested
    }
}

// Clamp a caller-supplied debounce window to [`MAX_DEBOUNCE`] so no backend can panic
// computing its deadline.
#[cfg_attr(
    not(any(windows, target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) fn effective_debounce(requested: Duration) -> Duration {
    if requested > MAX_DEBOUNCE {
        crate::trace::warning!(
            requested = ?requested,
            ceiling = ?MAX_DEBOUNCE,
            "debounce is above the maximum that keeps the window's deadline representable; \
             using the ceiling instead"
        );
        MAX_DEBOUNCE
    } else {
        requested
    }
}

/// Tuning knobs for [`ProxyWatcher::with_options`] (`#[non_exhaustive]`: use
/// [`WatchOptions::new`] / `with_*`).
///
/// ```
/// use proxy_watch::WatchOptions;
/// use std::time::Duration;
///
/// let opts = WatchOptions::new()
///     .with_debounce(Duration::from_millis(50))
///     .with_group_policy(false);
/// assert_eq!(opts.debounce, Duration::from_millis(50));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WatchOptions {
    /// Debounce before re-read (default [`DEFAULT_DEBOUNCE`]); anything over 24 h is
    /// lowered to it.
    ///
    /// A *fixed* window, not a sliding one: it opens on the first change, and further
    /// changes inside it are folded into the same emission rather than pushing it back.
    /// The wait after a change is therefore bounded by this value however long the storm
    /// of changes behind it lasts.
    pub debounce: Duration,

    /// Also read and watch per-machine group policy (default `true`; Windows only).
    ///
    /// No failure of this source can fail a read (the machine's WinHTTP default is the
    /// other source with that property). Whatever goes wrong here (an HKLM key this process
    /// cannot read, a policy `AutoConfigURL` this crate refuses as malformed) is reported
    /// as no policy, and [`ProxyConfig::fallbacks`] records that something went wrong
    /// without saying what. A [`ProxyConfigSource::GroupPolicy`] entry is never
    /// [`effective`](ProxyConfig::effective) (see that variant for the measurement), so
    /// failing the whole read on its account would refuse a machine whose per-user store
    /// answers well. A value stored under a type the key's own name does not carry is not a
    /// failure at all: a `ProxyEnable` written as a `REG_SZ` rather than the documented
    /// `REG_DWORD` reads like one that was never written, and the policy is reported as
    /// absent.
    ///
    /// The key is watched because it holds one value Windows *does* act on
    /// (`ProxySettingsPerUser`, the only one `inetres.admx` defines there) and switching it
    /// changes what `WinHttpGetIEProxyConfigForCurrentUser` returns, so a change under this
    /// key can change the effective configuration even though nothing under it is ever the
    /// effective configuration.
    pub watch_group_policy: bool,

    /// Timer re-read in addition to notifications. Anything under 200 ms is raised to
    /// 200 ms. A long interval is shortened so that the wait it becomes is finite, by a
    /// ceiling that differs per platform: 24 h on Linux, Android and iOS, an hour on macOS,
    /// and on Windows the longest wait the OS call accepts, `u32::MAX - 1` ms (about 49
    /// days).
    ///
    /// It also decides how a notification route that will not arm reaches the caller. With
    /// no interval set, the platform's primary route failing to arm is fatal:
    /// [`ProxyWatcher::with_options`] returns [`Error::Io`], naming this option as the fix.
    /// With one set, that same failure only reaches [`WatchHealth::degraded`], on a watcher
    /// that starts. Every other route degrades either way.
    pub poll_interval: Option<Duration>,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchOptions {
    /// Default: 200 ms debounce, group policy on, polling off.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            debounce: DEFAULT_DEBOUNCE,
            watch_group_policy: true,
            poll_interval: None,
        }
    }

    /// Set the debounce window (builder style).
    #[must_use]
    pub const fn with_debounce(mut self, debounce: Duration) -> Self {
        self.debounce = debounce;
        self
    }

    /// Enable or disable reading and watching per-machine group policy (builder style).
    #[must_use]
    pub const fn with_group_policy(mut self, watch: bool) -> Self {
        self.watch_group_policy = watch;
        self
    }

    /// Set or clear the polling interval (see [`WatchOptions::poll_interval`]).
    ///
    /// ```
    /// use proxy_watch::WatchOptions;
    /// use std::time::Duration;
    ///
    /// let opts = WatchOptions::new().with_poll_interval(Some(Duration::from_secs(30)));
    /// assert_eq!(opts.poll_interval, Some(Duration::from_secs(30)));
    /// ```
    #[must_use]
    pub const fn with_poll_interval(mut self, interval: Option<Duration>) -> Self {
        self.poll_interval = interval;
        self
    }
}

// Fail-soft outcome for establishing one change-notification route.
#[cfg_attr(
    not(any(
        windows,
        target_os = "macos",
        target_os = "android",
        all(
            target_os = "linux",
            any(feature = "linux-gnome", feature = "linux-kde")
        )
    )),
    allow(dead_code)
)]
pub(crate) enum WatchFailSoft<T> {
    // Route established (may still be "nothing to watch", e.g. missing courtesy path).
    Live(T),
    // Non-fatal: log at `WARN` and continue without it.
    Degraded(Error),
    // Fatal: caller has no other way to learn of later changes.
    Fatal(Error),
}

// Leading + no poll → Fatal; otherwise a failed establish is Degraded.
#[cfg_attr(
    not(any(
        windows,
        target_os = "macos",
        target_os = "android",
        all(
            target_os = "linux",
            any(feature = "linux-gnome", feature = "linux-kde")
        )
    )),
    allow(dead_code)
)]
pub(crate) fn watch_fail_soft<T>(
    leading: bool,
    poll_interval: Option<Duration>,
    established: Result<T, Error>,
) -> WatchFailSoft<T> {
    match established {
        Ok(value) => WatchFailSoft::Live(value),
        Err(error) if leading && poll_interval.is_none() => WatchFailSoft::Fatal(error),
        Err(error) => WatchFailSoft::Degraded(error),
    }
}

// [`watch_fail_soft`] for a route that needs the same platform access every read needs.
// When `reachable` fails the reads fail the same way, so polling would carry nothing: that
// error goes out unchanged, neither softened nor given the `poll_interval` advice
// [`fatal_watch_error`] adds for a route that failed alone. `establish` runs only after
// `reachable` passes.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn watch_fail_soft_reachable<T>(
    reachable: impl FnOnce() -> Result<(), Error>,
    leading: bool,
    poll_interval: Option<Duration>,
    establish: impl FnOnce() -> Result<T, Error>,
) -> Result<WatchFailSoft<T>, Error> {
    reachable()?;
    Ok(watch_fail_soft(leading, poll_interval, establish()))
}

// [`Error::Io`] for a fatal route failure; names the fix (`poll_interval`).
#[cfg_attr(
    not(any(
        windows,
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        all(
            target_os = "linux",
            any(feature = "linux-gnome", feature = "linux-kde")
        )
    )),
    allow(dead_code)
)]
pub(crate) fn fatal_watch_error(what: &str, why_no_fallback: &str, source: Error) -> Error {
    Error::io(
        format!(
            "{what} failed ({source}), and {why_no_fallback}; set WatchOptions::poll_interval \
             to fall back to polling and continue anyway"
        ),
        std::io::Error::other(source),
    )
}

// Backend report of change-notification routes after construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BackendHealth {
    // See [`WatchHealth::degraded`].
    pub(crate) degraded: Vec<ProxyConfigSource>,
    // See [`WatchHealth::has_live_notifications`].
    pub(crate) has_live_notifications: bool,
}

/// Liveness of change-notification routes ([`ProxyWatcher::health`]).
///
/// **`degraded`:** route is not delivering; set [`WatchOptions::poll_interval`].
/// **`is_frozen`:** nothing arrives on its own (no route and no poll, or a stopped
/// thread). [`ProxyWatcher::poll_now`] still delivers until the thread stops.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchHealth {
    /// Routes that could not be established, or that were established and later lost. An
    /// entry names the source a dead route stops reporting on, which is not always the
    /// store the reader opens; a source that is not configured here is nothing to watch
    /// rather than a failed watch, and is not listed. Windows is the exception: a missing
    /// per-user `Internet Settings` key lists
    /// [`Registry`](crate::ProxyConfigSource::Registry), because a key created later has no
    /// notification armed on it. Do not expect every entry to appear in
    /// [`ProxyConfig::sources`](crate::ProxyConfig::sources): notification routes are per
    /// store, so a lost `kioslaverc` watch is reported as
    /// [`Kioslaverc`](crate::ProxyConfigSource::Kioslaverc) even on a machine whose
    /// `ProxyType = 4` makes that store report
    /// [`KioslavercEnv`](crate::ProxyConfigSource::KioslavercEnv). Only ever grows: a
    /// source that degrades stays listed for the life of the watcher, the same one-way
    /// shape as [`has_live_notifications`](Self::has_live_notifications).
    pub degraded: Vec<ProxyConfigSource>,
    /// At least one native notification route is still live. Starts from what was
    /// established at construction and only ever falls to `false`, once every route is
    /// gone. A backend thread that stopped is reported by [`stopped`](Self::stopped)
    /// instead; that is not a statement about the routes.
    pub has_live_notifications: bool,
    /// Poll interval copied from [`WatchOptions::poll_interval`] at construction: what the
    /// caller asked for, not the floor a shorter request is raised to before any backend
    /// uses it. The floor is never reported, because this field says whether polling was
    /// asked for and [`stopped`](Self::stopped) says whether the request is still met.
    pub poll_interval: Option<Duration>,
    /// The backend thread has stopped, so `poll_interval` no longer has any effect: the
    /// polling this type reports happens *on* that thread. The stream ends with `None`
    /// once drained, but a caller that only reads health would otherwise keep waiting.
    pub stopped: bool,
}

impl WatchHealth {
    /// Every route is delivering: nothing degraded, at least one live native
    /// notification, and a backend thread still running to serve them. A
    /// [`stopped`](Self::stopped) thread is never fully live, whatever the routes
    /// reported while it ran.
    #[must_use]
    pub fn is_fully_live(&self) -> bool {
        !self.stopped && self.degraded.is_empty() && self.has_live_notifications
    }

    /// No live native notification and no [`WatchOptions::poll_interval`], or a
    /// [`stopped`](Self::stopped) thread, which takes the polling with it.
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        self.stopped || (!self.has_live_notifications && self.poll_interval.is_none())
    }
}

/// One internally consistent observation of a watcher.
///
/// [`ProxyWatcher::current`] and [`ProxyWatcher::health`] remain convenient independent
/// reads. Use [`ProxyWatcher::state`] when the configuration and liveness must describe
/// the same instant: both halves are copied while holding the watcher's shared mutex once.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchState {
    /// Most recent proxy configuration.
    pub config: ProxyConfig,
    /// Route and backend-thread liveness at the same observation point.
    pub health: WatchHealth,
}

/// Stream item of [`ProxyWatcher`]: a state snapshot or a failed re-read, each stamped
/// with the watcher's [`WatchState`] as it stood at delivery.
///
/// A snapshot arrives when the configuration changed, when the health changed, or both, so
/// a lost notification route reaches a subscriber rather than only
/// [`ProxyWatcher::health`].
#[non_exhaustive]
#[derive(Debug)]
pub enum WatchEvent {
    /// The configuration, the liveness of the routes, or both moved.
    ///
    /// Consecutive undelivered snapshots fold into the newest one, so a subscriber that
    /// stops polling loses the history between snapshots, never the current answer.
    #[non_exhaustive]
    Snapshot {
        /// Configuration and liveness at delivery.
        state: WatchState,
    },
    /// Re-reading the OS settings failed. This does not end the subscription.
    ///
    /// Nothing is guaranteed to follow, and no event reports the recovery. If the next
    /// successful read returns the same configuration and no route changed, the equality
    /// skip publishes nothing, and [`ProxyWatcher::current`] and [`ProxyWatcher::state`]
    /// return what they returned before the failure, `captured_at` included, so there is
    /// nothing to wait for: what they hold is what that read agreed with. A
    /// [`Snapshot`](Self::Snapshot) does follow whenever the configuration or the health
    /// moved.
    #[non_exhaustive]
    Error {
        /// Why the re-read failed.
        error: Error,
        /// Liveness at delivery, and the last configuration that did read cleanly.
        state: WatchState,
    },
}

impl WatchEvent {
    /// The state stamped on this event, whichever variant it is.
    #[must_use]
    pub fn state(&self) -> &WatchState {
        match self {
            Self::Snapshot { state } | Self::Error { state, .. } => state,
        }
    }
}

// Fold runtime additions into construction-time [`WatchHealth`] (dedupe; one-way live→false).
// `poll_interval` stays as requested even once `stopped`, which reports that it is not met.
fn merge_runtime_health(
    construction: &WatchHealth,
    runtime_degraded: Vec<ProxyConfigSource>,
    runtime_no_live_notifications: bool,
    stopped: bool,
) -> WatchHealth {
    let mut degraded = construction.degraded.clone();
    for source in runtime_degraded {
        if !degraded.contains(&source) {
            degraded.push(source);
        }
    }
    WatchHealth {
        degraded,
        has_live_notifications: construction.has_live_notifications
            && !runtime_no_live_notifications,
        poll_interval: construction.poll_interval,
        stopped,
    }
}

/// Read the OS proxy configuration once, without starting a watcher.
///
/// The read [`ProxyWatcher::new`] performs during construction, on its own: no thread is
/// spawned and no change-notification route is registered. A machine where notifications
/// cannot be armed makes `ProxyWatcher::new` fail while its settings are still readable,
/// and this call returns them.
///
/// Nothing here is watched, so nothing reports a later change; call it again.
///
/// Blocking, and not always briefly. The macOS and Linux backends wait on a system service
/// that can be absent: on macOS a `configd` that is still coming up is retried for five
/// seconds before this gives up, and inside a Linux sandbox each portal `Lookup` is
/// bounded at five seconds too. That bound is per call, and a sandboxed read asks five
/// questions: one unanswered `Lookup` ends the read at five seconds, but five answers
/// that each arrive just inside the bound hold it for twenty-five. Neither is the ordinary
/// case, but keep this call off a request path that expects syscall latency.
///
/// A Linux read consults both desktop stores, and an error from the one that is *not*
/// leading this session is softened to "absent" rather than failing the call: a
/// malformed `kioslaverc` should not break a GNOME session. So a success can be missing a
/// source that exists, and without the `tracing` feature nothing says so. The softening
/// holds only while the leading store is itself configured, which is what makes the
/// missing source one that could not have changed the answer. When the leading store is
/// unset, the store that failed *was* the effective one, and the error is returned rather
/// than reported as a `Direct` nothing measured.
///
/// ```no_run
/// let config = proxy_watch::read()?;
/// println!("effective: {:?}", config.effective);
/// # Ok::<(), proxy_watch::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Unsupported`], [`Error::Io`], [`Error::Sandboxed`] (Linux, in a sandbox with
/// no dconf), [`Error::CgiHttpProxy`] (KDE with `ProxyType = 4`, in a CGI environment),
/// or a parse error from malformed OS settings.
pub fn read() -> Result<ProxyConfig, Error> {
    read_with_options(&WatchOptions::default())
}

/// [`read`], with the one option a read can honour:
/// [`WatchOptions::watch_group_policy`]. The debounce and poll-interval fields describe a
/// watcher this call never starts, so they are ignored.
///
/// # Errors
///
/// Same as [`read`].
pub fn read_with_options(options: &WatchOptions) -> Result<ProxyConfig, Error> {
    read_logged(options, &sys::Env::capture())
}

/// The process environment, copied for a [`read_in`] or a
/// [`ProxyWatcher::with_options_in`] on another thread.
///
/// A Linux read takes the desktop, sandbox and `kioslaverc` variables from the environment,
/// and [`read`] copies it on the thread it runs on. A host that writes its environment from
/// one thread (Node's `process.env`, Python's `os.environ` under the GIL) captures on that
/// thread and reads on a worker, and the worker then races no write the host makes: glibc's
/// `getenv` against a concurrent `setenv` is a data race. Elsewhere the read takes nothing
/// from the environment, and this holds nothing.
///
/// GLib, which the GSettings and portal routes load at run time, still reads variables of
/// its own on the reading thread; this crate does not control those reads.
///
/// Hidden, and outside the semver promise: the language bindings use it. A Rust program
/// writes its environment through `std::env`, whose lock [`read`] already takes.
#[doc(hidden)]
#[derive(Clone)]
pub struct CapturedEnv(sys::Env);

impl CapturedEnv {
    /// Copy the environment of this process, on the calling thread.
    #[must_use]
    pub fn capture() -> Self {
        Self(sys::Env::capture())
    }
}

// The whole environment, tokens included: nothing of it is printed.
impl fmt::Debug for CapturedEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedEnv").finish_non_exhaustive()
    }
}

/// [`read`], with the environment taken from `env` instead of copied on this thread.
///
/// ```no_run
/// let env = proxy_watch::CapturedEnv::capture();
/// let config = std::thread::spawn(move || proxy_watch::read_in(&env)).join().unwrap()?;
/// println!("effective: {:?}", config.effective);
/// # Ok::<(), proxy_watch::Error>(())
/// ```
///
/// # Errors
///
/// Same as [`read`].
#[doc(hidden)]
pub fn read_in(env: &CapturedEnv) -> Result<ProxyConfig, Error> {
    read_logged(&WatchOptions::default(), &env.0)
}

fn read_logged(options: &WatchOptions, env: &sys::Env) -> Result<ProxyConfig, Error> {
    crate::trace::debug!(
        group_policy = options.watch_group_policy,
        "reading the system proxy configuration once"
    );
    let config = sys::read_config_in(options, env)?;
    crate::trace::debug!(
        config = %crate::trace::ConfigSummary(&config),
        "read the system proxy configuration"
    );
    Ok(config)
}

/// OS proxy watcher: initial snapshot, then debounced changes (equality ignores
/// `captured_at`).
/// Own OS threads: one, and on Linux one more per live source, plus one for
/// [`WatchOptions::poll_interval`] (elsewhere that interval shortens the single thread's
/// own wait instead of adding one). Drop joins them.
/// [`ProxyWatcher::health`] for route liveness. Windows, macOS, Linux, Android and iOS;
/// elsewhere [`Error::Unsupported`]. Applies no `*_proxy` convention of its own: only KDE's
/// `ProxyType = 4` builds a [`ProxyEnv`](crate::ProxyEnv), from the variables
/// `kioslaverc` names.
///
/// The stream is level-triggered: while a subscriber keeps polling, a finite number of
/// polls always reaches a [`WatchEvent::Snapshot`] matching the current
/// [`state`](Self::state), a [`WatchEvent::Error`], or `None`. An `Error` item does not
/// end the stream; `None` comes only once the backend thread has stopped, and is preceded
/// by a snapshot reporting [`WatchHealth::stopped`]. Undelivered snapshots fold into the
/// newest one, so a subscriber that stops polling loses the history between snapshots,
/// never [`current`](Self::current); failures with no snapshot between them fold into
/// the newest, and undelivered failures are capped at 1024, oldest discarded first. The
/// trim runs when a snapshot is published, so a failure arriving after a full one holds
/// the queue at 1025 until the next snapshot trims it back.
///
/// One subscriber, not a broadcast. Only the most recently registered waker is kept, and
/// `poll_next` takes `&mut`, so the only way to poll a watcher from more than one task is
/// to put it behind a lock; after which the task that polled first is parked with its
/// waker overwritten, and stays parked until something else on this watcher wakes it. To
/// fan a stream out, poll it in one place and forward.
///
/// The waker is woken on the backend thread, which `Drop` joins, so the last owner of the
/// watcher must not live inside the waker: dropping it there makes that thread wait for
/// itself.
///
/// [`Send`] but not [`Sync`], on every platform. So [`current`](Self::current),
/// [`health`](Self::health), [`state`](Self::state) and [`poll_now`](Self::poll_now) take
/// `&self` and do no OS I/O, yet still belong to the thread that owns the watcher, and
/// `Arc<ProxyWatcher>` is not `Send`. Move the watcher into the task that polls it and
/// forward from there what other threads need. Under the `tokio` feature `watch_channel`
/// is that forwarding already written; without it, one owner republishes
/// [`current`](Self::current) into a `Mutex` or a channel after every item. Neither
/// recovers [`poll_now`](Self::poll_now), which stays with the owner: send it a request
/// rather than sharing the watcher.
///
/// On Linux the watcher copies the process environment once, on the constructing thread,
/// and every later re-read takes the desktop, sandbox and `kioslaverc` variables from that
/// copy. A variable changed after construction is therefore not seen (set what you need
/// before constructing one), and the watcher's own threads never race a concurrent
/// [`std::env::set_var`]. GLib, which the GSettings and portal routes load at run time,
/// reads variables of its own on those threads; this crate does not control those reads.
///
/// ```no_run
/// use std::future::poll_fn;
/// use std::pin::Pin;
///
/// use futures_core::Stream;
/// use proxy_watch::{ProxyWatcher, WatchEvent};
///
/// let mut watcher = ProxyWatcher::new()?;
/// println!("current: {:?}", watcher.current().effective);
///
/// let next = futures_executor::block_on(poll_fn(|cx| Pin::new(&mut watcher).poll_next(cx)));
/// match next {
///     Some(WatchEvent::Snapshot { state, .. }) => {
///         println!("now: {:?} (live: {})", state.config.effective, state.health.is_fully_live());
///     }
///     Some(WatchEvent::Error { error, .. }) => eprintln!("re-read failed: {error}"),
///     _ => {}
/// }
/// # Ok::<(), proxy_watch::Error>(())
/// ```
pub struct ProxyWatcher {
    // Declared first so that it is *dropped* first: the platform thread is stopped
    // and joined before anything else this type owns goes away.
    watch: sys::Watch,
    shared: Arc<Shared>,
}

impl fmt::Debug for ProxyWatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state();
        f.debug_struct("ProxyWatcher")
            .field("current", &state.config.effective)
            .field("health", &state.health)
            .finish_non_exhaustive()
    }
}

impl ProxyWatcher {
    /// Start watching with [`WatchOptions::default`].
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`], [`Error::Io`], [`Error::Sandboxed`] (Linux, in a sandbox
    /// with no dconf), [`Error::CgiHttpProxy`] (KDE with `ProxyType = 4`, in a CGI
    /// environment), or a parse error from malformed OS settings.
    pub fn new() -> Result<Self, Error> {
        Self::with_options(WatchOptions::default())
    }

    /// Start watching with explicit options.
    ///
    /// Blocks the way [`read`] does, and can block for twice as long: the notification
    /// route is armed before the configuration is read, so a change landing between the
    /// two is already queued rather than lost. The GSettings subscription on Linux and the
    /// whole of macOS come up after that read instead, and close the same window with one
    /// forced re-read once live: Linux queues it from `spawn`, macOS publishes on entering
    /// its run loop. On macOS that subscription and the read each run the same five-second
    /// retry budget, so a `configd` that is still coming up can hold this call for ten
    /// seconds.
    ///
    /// # Errors
    ///
    /// Same as [`ProxyWatcher::new`].
    pub fn with_options(options: WatchOptions) -> Result<Self, Error> {
        Self::start(options, &sys::Env::capture())
    }

    /// [`ProxyWatcher::with_options`], with the environment taken from `env` instead of
    /// copied on this thread; every re-read uses the same copy.
    ///
    /// # Errors
    ///
    /// Same as [`ProxyWatcher::new`].
    #[doc(hidden)]
    pub fn with_options_in(options: WatchOptions, env: &CapturedEnv) -> Result<Self, Error> {
        Self::start(options, &env.0)
    }

    fn start(options: WatchOptions, env: &sys::Env) -> Result<Self, Error> {
        // By return, the re-read mechanism is in place (delivery may lag a moment).
        crate::trace::debug!(
            debounce = ?options.debounce,
            group_policy = options.watch_group_policy,
            poll_interval = ?options.poll_interval,
            "starting a proxy watcher"
        );
        let mut watch = sys::armed_in(&options, env)?;
        let initial = sys::read_config_in(&options, env)?;
        crate::trace::initial(&initial);
        let shared = Arc::new(Shared::new(initial));
        watch.spawn(&options, Arc::clone(&shared))?;
        // Routes are established by the time `spawn` returns `Ok` (`src/sys/mod.rs`).
        let backend_health = watch.health();
        // Written before this constructor hands out the `ProxyWatcher` that every reader
        // of the health has to go through, so no caller can observe it unset.
        shared.set_construction_health(WatchHealth {
            degraded: backend_health.degraded,
            has_live_notifications: backend_health.has_live_notifications,
            poll_interval: options.poll_interval,
            stopped: false,
        });
        Ok(Self { watch, shared })
    }

    /// The most recent snapshot (no OS I/O; may briefly wait for the internal mutex).
    /// Equals the constructor read right after start.
    #[must_use]
    pub fn current(&self) -> ProxyConfig {
        self.shared.current()
    }

    /// Construction-time routes plus any runtime degradation (see [`WatchHealth`]).
    /// Does no OS I/O; it may briefly wait for the same internal mutex
    /// [`ProxyWatcher::current`] uses.
    #[must_use]
    pub fn health(&self) -> WatchHealth {
        self.shared.health()
    }

    /// Configuration and health copied from one shared-state observation.
    ///
    /// This does no OS I/O, though it may briefly wait for the internal mutex. Prefer it
    /// over separate [`current`](Self::current) and [`health`](Self::health) calls when a
    /// route may degrade or the backend thread may stop concurrently.
    #[must_use]
    pub fn state(&self) -> WatchState {
        self.shared.state()
    }

    /// Request an immediate re-read (same debounce/equality path as a native notify).
    ///
    /// Call it when the caller knows something this crate cannot see: a connection attempt
    /// failed in a way that might be proxy-related, or the caller's own network-change
    /// watch fired. This crate does not watch the network itself; this call is the hook for
    /// that signal.
    ///
    /// Returns immediately, and may deliver nothing. A re-read shares a notification's
    /// equality skip: one that finds the configuration and the health unchanged publishes
    /// no [`WatchEvent`], and asking again does not force one. The [`Stream`] reports
    /// change, not completion, and [`current`](Self::current) and [`state`](Self::state)
    /// answer the same before and after such a re-read, so neither shows that this request
    /// landed. [`WatchEvent::Error`] says the same for the recovery case.
    pub fn poll_now(&self) {
        self.watch.poll_now();
    }
}

impl Stream for ProxyWatcher {
    type Item = WatchEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.shared.poll_next(cx)
    }
}

// The queue shared between the platform watcher thread and the [`Stream`].
#[derive(Debug)]
pub(crate) struct Shared {
    state: Mutex<State>,
    // Construction-time half of [`WatchHealth`]; the runtime half lives in `state`.
    // It sits here, rather than on [`ProxyWatcher`], so that the health can be assembled
    // wherever the shared state is held: including from inside the queue's own lock.
    construction: OnceLock<WatchHealth>,
}

// One undelivered item. A snapshot carries no payload: [`Shared::poll_next`] stamps the
// state at delivery from `current` and the merged health, so an entry only records *that*
// something is owed, not what it said when it was queued.
#[derive(Debug)]
enum Queued {
    Snapshot,
    Error(Error),
}

#[derive(Debug)]
struct State {
    current: ProxyConfig,
    // At most two `Queued::Snapshot`s, the front one and one behind a failure queued after
    // it (folded by [`Shared::emit`]); failures keep their
    // order and count, coalescing only at the tail via [`Shared::fail`], and are trimmed
    // to [`MAX_QUEUED_CHANGES`] on each snapshot.
    queue: VecDeque<Queued>,
    // Discards in the current overflow episode; reset when the consumer drains.
    dropped: u64,
    waker: Option<Waker>,
    closed: bool,
    // A health transition not yet reported to the consumer. Nothing enqueues on a degrade,
    // so without this a lost route would wait for a configuration change that may never
    // come; [`Shared::poll_next`] synthesises a snapshot for it instead.
    dirty: bool,
    // Routes that degraded after construction ([`Shared::degrade`]).
    runtime_degraded: Vec<ProxyConfigSource>,
    // Set once every native route a backend started with has degraded; never clears.
    runtime_no_live_notifications: bool,
}

impl State {
    // Enforce [`MAX_QUEUED_CHANGES`] by discarding from the front.
    fn trim_to_capacity(&mut self) -> Option<u64> {
        if self.queue.len() <= MAX_QUEUED_CHANGES {
            return None;
        }
        while self.queue.len() > MAX_QUEUED_CHANGES {
            self.queue.pop_front();
            self.dropped += 1;
        }
        Some(self.dropped)
    }
}

// Announce what [`State::trim_to_capacity`] discarded, outside the mutex.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn report_discarded(discarded: Option<u64>) {
    match discarded {
        None => {}
        Some(1) => crate::trace::warning!(
            capacity = MAX_QUEUED_CHANGES,
            "the change queue is full, so the oldest undelivered failure was discarded; \
             the subscriber is not draining the stream. `ProxyWatcher::current` stays \
             accurate — what is being lost is the record of individual read failures"
        ),
        Some(total) => crate::trace::debug!(
            discarded = total,
            capacity = MAX_QUEUED_CHANGES,
            "the change queue is still full; discarding the oldest undelivered failure"
        ),
    }
}

impl Shared {
    pub(crate) fn new(initial: ProxyConfig) -> Self {
        let mut queue = VecDeque::new();
        // The current value is delivered once, at subscription time: stamped with the
        // construction-time health, so a watcher that started degraded says so in its
        // very first event.
        queue.push_back(Queued::Snapshot);
        Self {
            state: Mutex::new(State {
                current: initial,
                queue,
                dropped: 0,
                waker: None,
                closed: false,
                dirty: false,
                runtime_degraded: Vec::new(),
                runtime_no_live_notifications: false,
            }),
            construction: OnceLock::new(),
        }
    }

    // Record what the backend established, once `spawn` has returned `Ok`.
    pub(crate) fn set_construction_health(&self, health: WatchHealth) {
        let already_set = self.construction.set(health).is_err();
        debug_assert!(!already_set, "the constructor writes this exactly once");
    }

    // The construction-time half, or (only before the constructor has returned, which is
    // the one window in which it is unset) a health that claims nothing: no route has been
    // established yet, so an unset health cannot falsely report a live route.
    fn construction(&self) -> &WatchHealth {
        static NOT_ESTABLISHED: WatchHealth = WatchHealth {
            degraded: Vec::new(),
            has_live_notifications: false,
            poll_interval: None,
            stopped: false,
        };
        self.construction.get().unwrap_or(&NOT_ESTABLISHED)
    }

    // Record that `source`'s notification route stopped delivering after construction.
    #[cfg_attr(
        not(any(windows, all(target_os = "linux", feature = "linux-kde"))),
        allow(dead_code)
    )]
    pub(crate) fn degrade(&self, source: ProxyConfigSource) {
        let mut state = self.lock();
        // Already in the health construction reported, so the merged health cannot move and
        // there is nothing to republish. Only once that health is established: `spawn` starts
        // the thread that calls this before the constructor records it.
        if state.runtime_degraded.contains(&source)
            || self
                .construction
                .get()
                .is_some_and(|health| health.degraded.contains(&source))
        {
            return;
        }
        state.runtime_degraded.push(source);
        // A degrade queues nothing, and the re-read that follows it may well be equal and
        // skipped. Waking on the transition is what keeps the loss from being silent.
        state.dirty = true;
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    // Record that no native notification route is live any more.
    pub(crate) fn mark_no_live_notifications(&self) {
        let mut state = self.lock();
        // As in `degrade`: nothing to republish when construction already reported no live
        // route, and only once it has reported anything.
        if state.runtime_no_live_notifications
            || self
                .construction
                .get()
                .is_some_and(|health| !health.has_live_notifications)
        {
            return;
        }
        state.runtime_no_live_notifications = true;
        state.dirty = true;
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    // Runtime additions folded into construction-time [`WatchHealth`].
    //
    // `closed` reaches a live [`ProxyWatcher`] only from [`ThreadGuard::drop`], i.e. the
    // thread stopped on its own; the ordinary `Drop` path closes a watcher no caller can
    // still query.
    pub(crate) fn health(&self) -> WatchHealth {
        let state = self.lock();
        self.merged_health(&state)
    }

    // Current config and health from one lock acquisition. This is the atomic
    // observation boundary exposed by [`ProxyWatcher::state`] and stamped on every
    // [`WatchEvent`].
    pub(crate) fn state(&self) -> WatchState {
        let state = self.lock();
        self.stamp(&state)
    }

    fn merged_health(&self, state: &State) -> WatchHealth {
        merge_runtime_health(
            self.construction(),
            state.runtime_degraded.clone(),
            state.runtime_no_live_notifications,
            state.closed,
        )
    }

    fn stamp(&self, state: &State) -> WatchState {
        WatchState {
            config: state.current.clone(),
            health: self.merged_health(state),
        }
    }

    pub(crate) fn current(&self) -> ProxyConfig {
        self.lock().current.clone()
    }

    // Publish `config` unless it is equal to the previous one (the equality skip).
    //
    // Of the publishing methods, only this one has a platform backend as its sole caller,
    // so on a target that has none it is legitimately dead. `fail` and `close` are not, and
    // neither is [`Error::io`]: [`ThreadGuard`]'s `Drop` calls them, which is what the
    // guard is for, and a `Drop` impl is live on every target. This attribute is also the
    // lint root for `trim_to_capacity` and `report_discarded`. `#[expect]` reports when
    // this target no longer needs the suppression.
    //
    // `not(test)` because the platform backend is only the *non-test* sole caller: the
    // tests below drive `emit` directly, and they are compiled on every target. Without
    // it, `cargo clippy --target <unsupported> --all-targets` builds the lib test, finds
    // `emit` live, and reports the expectation itself as unfulfilled, which `-D warnings`
    // turns into a hard error on a target this crate does not even claim to support.
    #[cfg_attr(
        all(
            not(any(
                windows,
                target_os = "macos",
                target_os = "linux",
                target_os = "android",
                target_os = "ios"
            )),
            not(test)
        ),
        expect(dead_code)
    )]
    pub(crate) fn emit(&self, config: ProxyConfig) {
        let mut state = self.lock();
        if state.current == config {
            // Log after unlock: subscriber code must not run under this mutex.
            drop(state);
            crate::trace::debug!(
                config = %crate::trace::ConfigSummary(&config),
                "an unchanged snapshot was skipped (equality skip)"
            );
            return;
        }
        // Rendering the transition asks the subscriber whether `INFO` is enabled, and a
        // level filter is consumer code like the event hook above, so it waits for the
        // unlock too, and the previous value is kept here to make that possible. The clone
        // is the price, paid only when the configuration changed.
        let previous = std::mem::replace(&mut state.current, config.clone());
        // Fold: at most one undelivered snapshot past the front, and it is always the newest
        // one. The entry carries no payload, so the one already queued renders whatever
        // `current` says when it is taken, and `current` was just replaced above. Moving it
        // to the back is what keeps failures queued before it ahead of it.
        //
        // The front entry is the exception: it is the next thing the consumer takes, and on a
        // subscription that has not polled yet it is the subscription-time snapshot every
        // consumer's first item is documented to be (`README.md`, `examples/watch.rs`, the
        // type doc above). Moving it puts a failure that arrived after subscription in front
        // of it, so the first thing the stream ever says is an error on a configuration it
        // has not once reported. It stays, and a failure queued behind it gets a second
        // snapshot after it: `WatchEvent::Error` promises one follows when the
        // configuration moved, and the front one precedes the failure.
        let last = state
            .queue
            .iter()
            .rposition(|i| matches!(i, Queued::Snapshot));
        let folded = match last {
            Some(at) if at + 1 == state.queue.len() => true,
            Some(at) if at > 0 => {
                state.queue.remove(at);
                state.queue.push_back(Queued::Snapshot);
                true
            }
            _ => {
                state.queue.push_back(Queued::Snapshot);
                false
            }
        };
        // The snapshot about to be delivered carries the health as it will stand then,
        // so it answers whatever transition `dirty` was holding.
        state.dirty = false;
        let discarded = state.trim_to_capacity();
        let waker = state.waker.take();
        drop(state);
        crate::trace::changed(&previous, &config);
        if folded {
            crate::trace::debug!(
                "a newer snapshot replaced one the subscriber had not taken yet; \
                 what it will read is the current configuration, not the intermediate one"
            );
        }
        report_discarded(discarded);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub(crate) fn fail(&self, error: Error) {
        // Log before lock: `error` moves into the queue; subscriber must not run under mutex.
        crate::trace::warning!(
            error = %crate::trace::SafeError(&error),
            "reading the proxy configuration failed; the subscription stays open"
        );
        let mut state = self.lock();
        // Non-empty queue ⇒ no waker (`poll_next` only stores one while empty).
        if !state.queue.is_empty() {
            debug_assert!(
                state.waker.is_none(),
                "a waker must not be registered while the queue is non-empty"
            );
        }
        if let Some(Queued::Error(last)) = state.queue.back_mut() {
            *last = error;
            return;
        }
        state.queue.push_back(Queued::Error(error));
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    // Idempotent: only the first call ends the stream, and only it owes a snapshot.
    pub(crate) fn close(&self) {
        let mut state = self.lock();
        if state.closed {
            return;
        }
        state.closed = true;
        // `stopped` is a health transition like any other, so the consumer is owed one
        // last snapshot saying so before the stream ends. That holds for a panic, a fatal
        // return and an ordinary finish alike, without any of them being contracted
        // separately.
        state.dirty = true;
        let waker = state.waker.take();
        drop(state);
        crate::trace::debug!("the watcher thread finished; the stream will end");
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn poll_next(&self, cx: &mut Context<'_>) -> Poll<Option<WatchEvent>> {
        // Cloned before the lock is taken, for the same reason `emit` logs after releasing
        // it: executor code must not run under this mutex. It cannot wait until the park is
        // decided, because unlocking to take the clone would open a gap in which an `emit`
        // could queue an event and find no waker to wake. The ready paths below pay for one
        // unused clone, and drop it after `state`; locals unwind in reverse declaration
        // order, and `state` is declared second.
        let waker = cx.waker().clone();
        let mut state = self.lock();
        if let Some(item) = state.queue.pop_front() {
            if state.queue.is_empty() {
                // The consumer has caught up: the next overflow is a new episode and
                // gets its own `WARN` (see `State::dropped`).
                state.dropped = 0;
            }
            let event = match item {
                Queued::Snapshot => {
                    // Stamped now, not when it was queued, so it reports whatever the
                    // health has become since, which is what `dirty` was for.
                    state.dirty = false;
                    WatchEvent::Snapshot {
                        state: self.stamp(&state),
                    }
                }
                // A failed read says nothing about the routes, so it leaves `dirty`
                // standing and the health transition still gets its own snapshot.
                Queued::Error(error) => WatchEvent::Error {
                    error,
                    state: self.stamp(&state),
                },
            };
            return Poll::Ready(Some(event));
        }
        // Before the `closed` check: closing is itself the last health transition, and
        // an unreported one must not be swallowed by the end of the stream.
        if state.dirty {
            state.dirty = false;
            return Poll::Ready(Some(WatchEvent::Snapshot {
                state: self.stamp(&state),
            }));
        }
        if state.closed {
            return Poll::Ready(None);
        }
        let previous = state.waker.replace(waker);
        drop(state);
        // Not dropped by `replace` under the lock: `Waker::from(Arc<W>)` makes this `W`'s own
        // `Drop`, so it is ordinary consumer code, and one that reads back from the watcher
        // would block on a lock this very thread holds.
        drop(previous);
        Poll::Pending
    }

    // Recover from a poisoned mutex instead of propagating the panic.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// Ensures [`Shared::close`] runs even if the backend thread panics.
pub(crate) struct ThreadGuard {
    shared: Arc<Shared>,
}

// `new` is what a target with no backend never calls; the struct is not, because `allow`
// makes the item it is written on a lint root and this one names `Self`. That is also why
// the attribute has to sit here rather than on the struct; it does not reach out of the
// item it is written on, and the struct is a separate item.
#[cfg_attr(
    not(any(windows, target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]
impl ThreadGuard {
    pub(crate) fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }
}

impl Drop for ThreadGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            crate::trace::error!("the proxy-watch backend thread panicked; closing the stream");
            // Before the failure, not after: `fail` wakes the consumer, and a consumer that
            // reads the health on being woken must not still be told a route is live.
            self.shared.mark_no_live_notifications();
            self.shared.fail(Error::io(
                "running the proxy-watch backend thread",
                std::io::Error::other("the watcher thread panicked"),
            ));
        }
        self.shared.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Wake;

    // `Send` so a spawned task can hold the watcher; `Sync` is *not*
    // required: a single consumer owns the stream.
    const _: fn() = || {
        fn assert_send<T: Send>() {}
        assert_send::<ProxyWatcher>();
        assert_send::<WatchOptions>();
    };

    // Not `Sync`, on every target: the inference below is ambiguous, and fails to compile,
    // exactly when `ProxyWatcher: Sync`.
    const _: fn() = || {
        trait AmbiguousIfSync<A> {
            fn item() {}
        }
        impl<T: ?Sized> AmbiguousIfSync<()> for T {}
        impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
        let _ = <ProxyWatcher as AmbiguousIfSync<_>>::item;
    };

    // Type-checked only, never run: `poll_now` takes `&self` and returns nothing, so
    // nothing here can tell a working one apart from a no-op. That needs a change the
    // native notification does not already deliver by itself, and only one test arranges
    // one:
    // `tests/linux_watch.rs`'s `poll_now_re_reads_a_change_no_watch_can_see`, which writes
    // through a symlink pointing out of the watched directory. Windows and macOS have no
    // equivalent.
    const _: fn(&ProxyWatcher) = |watcher| watcher.poll_now();
    const _: fn(&ProxyWatcher) -> WatchState = ProxyWatcher::state;

    #[test]
    fn the_initial_value_is_queued_once_and_equality_skips_repeats() {
        let initial = ProxyConfig::direct();
        let shared = Shared::new(initial.clone());

        // Exactly one queued item at subscription time.
        assert_eq!(shared.lock().queue.len(), 1);

        // An identical snapshot does not even reach the queue; a different one replaces
        // the entry that is already there rather than adding to it.
        shared.emit(ProxyConfig::direct());
        assert_eq!(shared.lock().queue.len(), 1);
        assert!(!shared.lock().dirty, "an equal read changes nothing");
        shared.emit(ProxyConfig::from_source(
            crate::config::ProxyConfigSource::Registry,
            crate::mode::ProxyMode::WpadAutoDetect,
        ));
        assert_eq!(shared.lock().queue.len(), 1);
        assert_eq!(
            shared.current().effective,
            crate::mode::ProxyMode::WpadAutoDetect
        );
    }

    // Why [`ProxyConfig::fallbacks`] is compared by `PartialEq` rather than left beside
    // `captured_at`. Two reads can agree on every mode and still not be the same answer,
    // because one of them was assembled without a source it could not read. The skip above
    // suppresses the notification and *keeps* `current`, so the second half of this test
    // checks that a healed degradation stops being reported: with the field excluded, it
    // would go on being reported for the rest of the watcher's life.
    #[test]
    fn a_snapshot_that_differs_only_in_fallbacks_is_published_rather_than_skipped() {
        let complete = ProxyConfig::from_source(
            crate::config::ProxyConfigSource::Registry,
            crate::mode::ProxyMode::Direct,
        );
        let degraded = complete
            .clone()
            .with_fallbacks(vec![crate::config::ProxyConfigSource::GroupPolicy]);
        let shared = Shared::new(complete.clone());

        shared.emit(degraded);
        assert_eq!(
            shared.current().fallbacks,
            [crate::config::ProxyConfigSource::GroupPolicy],
            "a read that lost a source is not the snapshot that never had one"
        );

        shared.emit(complete);
        assert!(
            shared.current().fallbacks.is_empty(),
            "and the recovery is a change too"
        );
    }

    // A read that fails between construction and the first poll, then a change: the
    // subscription snapshot comes first, the error next, and a snapshot of the change last
    // (the fold in `Shared::emit` says why). `tests/mac_watch.rs` holds the first item
    // against a live backend.
    #[test]
    fn a_failure_before_the_first_poll_stays_behind_the_subscription_snapshot() {
        let shared = Shared::new(ProxyConfig::direct());
        shared.fail(Error::io(
            "reading the proxy configuration",
            std::io::Error::other("a read that failed before the first poll"),
        ));
        shared.emit(ProxyConfig::from_source(
            ProxyConfigSource::Registry,
            crate::mode::ProxyMode::WpadAutoDetect,
        ));

        // Read it the way a consumer does: the configuration first, the failure after.
        let mut cx = Context::from_waker(Waker::noop());
        match shared.poll_next(&mut cx) {
            Poll::Ready(Some(WatchEvent::Snapshot { state })) => {
                assert_eq!(
                    state.config.effective,
                    crate::mode::ProxyMode::WpadAutoDetect
                );
            }
            other => panic!("the first item must be the subscription snapshot, got {other:?}"),
        }
        assert!(matches!(
            shared.poll_next(&mut cx),
            Poll::Ready(Some(WatchEvent::Error { .. }))
        ));
        assert!(matches!(
            shared.poll_next(&mut cx),
            Poll::Ready(Some(WatchEvent::Snapshot { .. }))
        ));
        assert!(shared.poll_next(&mut cx).is_pending());
    }

    // The same order once the subscription snapshot is taken: a snapshot still queued in
    // front of a failure stays there, and the change gets its own snapshot behind it. A
    // second change folds into that one.
    #[test]
    fn a_change_after_a_queued_failure_gets_a_snapshot_behind_it() {
        let shared = Shared::new(ProxyConfig::direct());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            shared.poll_next(&mut cx),
            Poll::Ready(Some(WatchEvent::Snapshot { .. }))
        ));
        let changed = |mode| ProxyConfig::from_source(ProxyConfigSource::Registry, mode);
        shared.emit(changed(crate::mode::ProxyMode::WpadAutoDetect));
        shared.fail(sandboxed_error("between"));
        shared.emit(changed(crate::mode::ProxyMode::Direct));
        shared.emit(changed(crate::mode::ProxyMode::WpadAutoDetect));

        let kinds: Vec<&str> = std::iter::from_fn(|| match shared.poll_next(&mut cx) {
            Poll::Ready(Some(WatchEvent::Snapshot { .. })) => Some("snapshot"),
            Poll::Ready(Some(WatchEvent::Error { .. })) => Some("error"),
            _ => None,
        })
        .collect();
        assert_eq!(kinds, ["snapshot", "error", "snapshot"]);
    }

    // The construction-time half a live backend would have written, so that the runtime
    // half has something to override rather than agreeing with the unset default.
    fn live_construction_health() -> WatchHealth {
        WatchHealth {
            degraded: Vec::new(),
            has_live_notifications: true,
            poll_interval: None,
            stopped: false,
        }
    }

    #[test]
    fn one_shared_state_read_contains_config_and_runtime_health() {
        let shared = Shared::new(ProxyConfig::direct());
        shared.set_construction_health(live_construction_health());
        shared.emit(ProxyConfig::from_source(
            ProxyConfigSource::Registry,
            crate::mode::ProxyMode::WpadAutoDetect,
        ));
        shared.degrade(ProxyConfigSource::Registry);
        shared.mark_no_live_notifications();
        shared.close();

        let state = shared.state();
        assert_eq!(
            state.config.effective,
            crate::mode::ProxyMode::WpadAutoDetect
        );
        assert_eq!(state.health.degraded, vec![ProxyConfigSource::Registry]);
        assert!(!state.health.has_live_notifications);
        assert!(state.health.stopped);
    }

    // Nothing can reach `Shared` through a `ProxyWatcher` before the constructor writes
    // the construction-time health, so the unset answer is unobservable in practice. It
    // still has to be the conservative one rather than a reassuring default.
    #[test]
    fn an_unwritten_construction_health_claims_no_route() {
        let shared = Shared::new(ProxyConfig::direct());
        let health = shared.health();
        assert!(!health.has_live_notifications);
        assert!(health.degraded.is_empty());
        assert_eq!(health.poll_interval, None);
        assert!(!health.stopped);
        assert!(!health.is_fully_live());
    }

    // Alternating between these clears the equality skip on every `emit`.
    fn two_distinct_configs() -> (ProxyConfig, ProxyConfig) {
        (
            ProxyConfig::direct(),
            ProxyConfig::from_source(
                crate::config::ProxyConfigSource::Registry,
                crate::mode::ProxyMode::WpadAutoDetect,
            ),
        )
    }

    // Alternate a change and a failure so the queue grows: on its own, a run of
    // changes folds into one entry and a run of failures coalesces into one.
    //
    // Take the subscription snapshot first, and fail once with the queue empty. `emit`
    // leaves a snapshot alone while it is the front entry; that entry is the next thing
    // the consumer takes, so what grows the queue is a stall that begins with an
    // undelivered failure in front, not one that begins before the first poll.
    fn fill_past_capacity(shared: &Shared, rounds: usize) {
        let (direct, wpad) = two_distinct_configs();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(shared.poll_next(&mut cx).is_ready());
        shared.fail(sandboxed_error("filler"));
        for index in 0..rounds {
            shared.emit(if index % 2 == 0 {
                wpad.clone()
            } else {
                direct.clone()
            });
            shared.fail(sandboxed_error("filler"));
        }
    }

    // A stalled consumer must not turn an unbounded number of failures into unbounded
    // memory: [`MAX_QUEUED_CHANGES`] is the ceiling. The `+ 1` is not slack; `emit` is
    // where `trim_to_capacity` runs, so a `fail` that lands on a just-trimmed queue sits
    // one past the ceiling until the next snapshot. `ProxyWatcher`'s stream doc says so.
    #[test]
    fn a_stalled_consumer_cannot_grow_the_queue_without_bound() {
        let shared = Shared::new(ProxyConfig::direct());
        fill_past_capacity(&shared, MAX_QUEUED_CHANGES * 2);

        let state = shared.lock();
        assert!(
            state.queue.len() <= MAX_QUEUED_CHANGES + 1,
            "queue grew to {}",
            state.queue.len()
        );
        assert!(state.dropped > 0, "the cap must have discarded something");
    }

    // Snapshots do not queue up behind a stalled consumer at all: the newest replaces the
    // one it has not taken yet, so what it eventually reads is the current answer and not
    // a backlog of history.
    #[test]
    fn undelivered_snapshots_fold_into_the_newest_one() {
        let (direct, wpad) = two_distinct_configs();
        let shared = Shared::new(direct.clone());
        let mut cx = Context::from_waker(Waker::noop());

        for index in 0..64 {
            shared.emit(if index % 2 == 0 {
                wpad.clone()
            } else {
                direct.clone()
            });
        }

        // One entry, not 65: the initial snapshot and every change folded together.
        assert_eq!(shared.lock().queue.len(), 1);
        match shared.poll_next(&mut cx) {
            Poll::Ready(Some(WatchEvent::Snapshot { state })) => {
                assert_eq!(state.config, shared.current());
                assert_eq!(state.config, direct);
            }
            other => panic!("expected the newest snapshot, got {other:?}"),
        }
        assert!(shared.poll_next(&mut cx).is_pending());
    }

    // The counter behind the `WARN`-once rule tracks *episodes*: draining resets it, so
    // a later overflow is announced again instead of being swallowed by the first one.
    #[test]
    fn draining_the_queue_resets_the_discard_counter() {
        let shared = Shared::new(ProxyConfig::direct());
        let mut cx = Context::from_waker(Waker::noop());

        fill_past_capacity(&shared, MAX_QUEUED_CHANGES + 5);
        assert!(shared.lock().dropped > 0);

        // The poll that empties the queue resets the discard count.
        while shared.poll_next(&mut cx).is_ready() {
            if shared.lock().queue.is_empty() {
                break;
            }
        }
        assert_eq!(shared.lock().dropped, 0);
        assert_eq!(shared.lock().queue.len(), 0);
    }

    // A lost route reaches the stream even when an equal re-read skips the configuration.
    #[test]
    fn a_degrade_reaches_the_stream_even_when_every_later_read_is_equal() {
        let shared = Shared::new(ProxyConfig::direct());
        shared.set_construction_health(live_construction_health());
        let mut cx = Context::from_waker(Waker::noop());

        assert!(matches!(
            shared.poll_next(&mut cx),
            Poll::Ready(Some(WatchEvent::Snapshot { .. }))
        ));
        assert!(shared.poll_next(&mut cx).is_pending());

        shared.degrade(ProxyConfigSource::Registry);
        // The re-read the backend does next finds nothing new, so it publishes nothing.
        shared.emit(ProxyConfig::direct());

        match shared.poll_next(&mut cx) {
            Poll::Ready(Some(WatchEvent::Snapshot { state })) => {
                assert_eq!(state.health.degraded, vec![ProxyConfigSource::Registry]);
                assert_eq!(state.config, ProxyConfig::direct());
            }
            other => panic!("the lost route must reach the stream, got {other:?}"),
        }
        // Once told, the subscriber is not told again.
        assert!(shared.poll_next(&mut cx).is_pending());
        // Nor when the same route degrades a second time. A backend retrying an arm it
        // cannot get back calls this on every attempt, and `merge_runtime_health`'s dedupe
        // only keeps the *health* from growing; the wake and the synthesised snapshot are
        // this guard's, and without it one loss repeats for as long as the retries do.
        shared.degrade(ProxyConfigSource::Registry);
        assert!(shared.poll_next(&mut cx).is_pending());
    }

    // A parked consumer has to be *woken* for the synthesised snapshot to be of any use:
    // a level-triggered stream nobody polls again is still silent.
    #[test]
    fn losing_the_last_route_wakes_a_parked_consumer() {
        struct Signal(AtomicBool);
        impl Wake for Signal {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let shared = Shared::new(ProxyConfig::direct());
        shared.set_construction_health(live_construction_health());
        let signal = Arc::new(Signal(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&signal));
        let mut cx = Context::from_waker(&waker);

        assert!(shared.poll_next(&mut cx).is_ready());
        assert!(shared.poll_next(&mut cx).is_pending());
        assert!(!signal.0.load(Ordering::SeqCst));

        shared.mark_no_live_notifications();
        assert!(
            signal.0.load(Ordering::SeqCst),
            "losing the last route must wake the parked consumer"
        );
        match shared.poll_next(&mut cx) {
            Poll::Ready(Some(WatchEvent::Snapshot { state })) => {
                assert!(!state.health.has_live_notifications);
            }
            other => panic!("expected a snapshot reporting the loss, got {other:?}"),
        }
        // The flag never clears, so a second call has nothing left to say. A backend that
        // finds the route still gone on every retry calls this each time; waking again
        // would report a loss the subscriber has already been told about.
        assert!(shared.poll_next(&mut cx).is_pending());
        signal.0.store(false, Ordering::SeqCst);
        shared.mark_no_live_notifications();
        assert!(!signal.0.load(Ordering::SeqCst));
        assert!(shared.poll_next(&mut cx).is_pending());
    }

    // The one waker slot, from the losing side. [`ProxyWatcher`]'s doc says a second poll
    // overwrites the first task's waker and leaves it parked; that is the failure mode a
    // caller who puts the watcher behind a lock and polls it from two tasks hits,
    // so it is worth pinning rather than leaving as prose.
    #[test]
    fn a_second_poll_takes_the_waker_slot_from_the_first_consumer() {
        struct Signal(AtomicBool);
        impl Wake for Signal {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let shared = Shared::new(ProxyConfig::direct());
        shared.set_construction_health(live_construction_health());
        let first = Arc::new(Signal(AtomicBool::new(false)));
        let second = Arc::new(Signal(AtomicBool::new(false)));
        let first_waker = Waker::from(Arc::clone(&first));
        let second_waker = Waker::from(Arc::clone(&second));

        // The construction snapshot, then the first consumer parks.
        assert!(
            shared
                .poll_next(&mut Context::from_waker(&first_waker))
                .is_ready()
        );
        assert!(
            shared
                .poll_next(&mut Context::from_waker(&first_waker))
                .is_pending()
        );
        // A second consumer polls the same watcher and takes the slot.
        assert!(
            shared
                .poll_next(&mut Context::from_waker(&second_waker))
                .is_pending()
        );

        shared.mark_no_live_notifications();
        assert!(
            second.0.load(Ordering::SeqCst),
            "the most recently registered waker is the one that is kept"
        );
        assert!(
            !first.0.load(Ordering::SeqCst),
            "the first consumer stays parked: nothing on this watcher is left to wake it"
        );
    }

    // Closing is the last health transition there is, so it owes a snapshot before the
    // stream ends; otherwise `None` would be the only notice a subscriber ever got that
    // the thread had stopped, and a subscriber reading health would never see `stopped`.
    #[test]
    fn closing_delivers_a_stopped_snapshot_exactly_once_before_the_end() {
        let shared = Shared::new(ProxyConfig::direct());
        shared.set_construction_health(live_construction_health());
        let mut cx = Context::from_waker(Waker::noop());

        assert!(shared.poll_next(&mut cx).is_ready());
        shared.close();
        // Idempotent: a second close owes nothing further.
        shared.close();

        match shared.poll_next(&mut cx) {
            Poll::Ready(Some(WatchEvent::Snapshot { state })) => {
                assert!(state.health.stopped);
                assert!(state.health.is_frozen());
            }
            other => panic!("expected a stopped snapshot before the end, got {other:?}"),
        }
        assert!(matches!(shared.poll_next(&mut cx), Poll::Ready(None)));
        assert!(matches!(shared.poll_next(&mut cx), Poll::Ready(None)));
    }

    // Queued failures come out before the terminal snapshot, and a failure on its own
    // never answers a health transition: the `stopped` snapshot still follows it.
    #[test]
    fn a_failure_does_not_stand_in_for_the_terminal_snapshot() {
        let shared = Shared::new(ProxyConfig::direct());
        shared.set_construction_health(live_construction_health());
        let mut cx = Context::from_waker(Waker::noop());

        assert!(shared.poll_next(&mut cx).is_ready());
        shared.fail(sandboxed_error("dying"));
        shared.close();

        assert!(matches!(
            shared.poll_next(&mut cx),
            Poll::Ready(Some(WatchEvent::Error { .. }))
        ));
        match shared.poll_next(&mut cx) {
            Poll::Ready(Some(WatchEvent::Snapshot { state })) => assert!(state.health.stopped),
            other => panic!("expected the terminal snapshot after the failure, got {other:?}"),
        }
        assert!(matches!(shared.poll_next(&mut cx), Poll::Ready(None)));
    }

    // Whichever variant arrives, it answers the same question, which is what makes an
    // event comparable with a `ProxyWatcher::state()` taken beside it.
    #[test]
    fn every_event_carries_the_state_it_was_delivered_with() {
        let shared = Shared::new(ProxyConfig::direct());
        shared.set_construction_health(live_construction_health());
        let mut cx = Context::from_waker(Waker::noop());

        let Poll::Ready(Some(snapshot)) = shared.poll_next(&mut cx) else {
            panic!("the subscription-time snapshot is always ready");
        };
        assert_eq!(snapshot.state(), &shared.state());

        shared.fail(sandboxed_error("only a read failed"));
        let Poll::Ready(Some(failure)) = shared.poll_next(&mut cx) else {
            panic!("the queued failure is always ready");
        };
        assert!(matches!(failure, WatchEvent::Error { .. }));
        // A failed read is not a lost route: the health it carries still says so.
        assert_eq!(failure.state(), &shared.state());
        assert!(failure.state().health.has_live_notifications);
    }

    // A distinguishable error so coalescing tests can tell which queued failure
    // survived; [`Error::Unsupported`] carries no payload to tell two instances apart.
    fn sandboxed_error(reason: &str) -> Error {
        Error::Sandboxed {
            sandbox: "Flatpak".to_owned(),
            reason: reason.to_owned(),
        }
    }

    // A persistent read failure must not queue one `Err` per tick forever: a run of
    // [`Shared::fail`] calls collapses into the single tail entry, newest surviving.
    #[test]
    fn consecutive_fails_coalesce_into_the_newest_error() {
        let shared = Shared::new(ProxyConfig::direct());
        // Drain the initial snapshot so only the failure sequence is counted.
        assert!(matches!(
            shared.lock().queue.pop_front(),
            Some(Queued::Snapshot)
        ));

        shared.fail(sandboxed_error("first"));
        assert_eq!(shared.lock().queue.len(), 1);
        shared.fail(sandboxed_error("second"));
        assert_eq!(shared.lock().queue.len(), 1);
        shared.fail(sandboxed_error("third"));
        assert_eq!(shared.lock().queue.len(), 1);

        let state = shared.lock();
        match &state.queue[0] {
            Queued::Error(Error::Sandboxed { reason, .. }) => assert_eq!(reason, "third"),
            other => panic!("expected the newest coalesced Sandboxed error, got {other:?}"),
        }
    }

    // Coalescing only applies to a run of failures with nothing successful in between:
    // a success in the middle must not swallow, or be swallowed by, either failure.
    #[test]
    fn fail_after_an_intervening_emit_is_not_coalesced() {
        let shared = Shared::new(ProxyConfig::direct());
        assert!(matches!(
            shared.lock().queue.pop_front(),
            Some(Queued::Snapshot)
        ));

        shared.fail(sandboxed_error("before"));
        shared.emit(ProxyConfig::from_source(
            crate::config::ProxyConfigSource::Registry,
            crate::mode::ProxyMode::WpadAutoDetect,
        ));
        shared.fail(sandboxed_error("after"));

        let state = shared.lock();
        assert_eq!(state.queue.len(), 3);
        match &state.queue[0] {
            Queued::Error(Error::Sandboxed { reason, .. }) => assert_eq!(reason, "before"),
            other => panic!("expected the first Sandboxed error, got {other:?}"),
        }
        assert!(matches!(state.queue[1], Queued::Snapshot));
        match &state.queue[2] {
            Queued::Error(Error::Sandboxed { reason, .. }) => assert_eq!(reason, "after"),
            other => panic!("expected the second Sandboxed error, got {other:?}"),
        }
    }

    // A consumer parked on a registered waker must still be woken by the *first* of a
    // run of failures, and must then see exactly one `Err`: not zero, not two.
    #[test]
    fn a_parked_consumer_is_woken_once_and_sees_one_coalesced_error() {
        struct Signal(AtomicBool);
        impl Wake for Signal {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let shared = Shared::new(ProxyConfig::direct());
        assert!(matches!(
            shared.lock().queue.pop_front(),
            Some(Queued::Snapshot)
        ));

        let signal = Arc::new(Signal(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&signal));
        let mut cx = Context::from_waker(&waker);

        // Queue empty, stream open: registers the waker and returns Pending.
        assert!(shared.poll_next(&mut cx).is_pending());
        assert!(!signal.0.load(Ordering::SeqCst));

        shared.fail(sandboxed_error("first"));
        assert!(
            signal.0.load(Ordering::SeqCst),
            "the first failure must wake the parked consumer"
        );
        // A second failure while the first is undrained coalesces in place rather than
        // needing a second wake.
        shared.fail(sandboxed_error("second"));

        match shared.poll_next(&mut cx) {
            Poll::Ready(Some(WatchEvent::Error {
                error: Error::Sandboxed { reason, .. },
                ..
            })) => {
                assert_eq!(reason, "second");
            }
            other => panic!("expected exactly one coalesced Sandboxed error, got {other:?}"),
        }
        assert!(shared.lock().queue.is_empty());
    }

    // The clamp tests below are written in terms of `MIN_POLL_INTERVAL` and `MAX_DEBOUNCE`
    // rather than the numbers they hold, which is what lets them describe the shape of the
    // clamp without repeating a literal in six places. It also means both bounds can move
    // and those expectations move with them. The numbers are in the rendered documentation:
    // `WatchOptions::poll_interval` says "anything under 200 ms is raised to it" and
    // `WatchOptions::debounce` says "anything over 24 h is lowered to it"; and
    // `xtask/tests/claim_counts.rs` counts nouns, not durations, so the test below is what
    // turns red when a bound moves and the doc does not.
    //
    // `WatchOptions::new()`'s own defaults are here for the same reason and one more:
    // `poll_interval` is not a tuning knob but a fork. Unset, a primary notification route
    // that will not arm is fatal and `with_options` refuses to build a watcher; set, that
    // same failure only reaches `WatchHealth::degraded` on a watcher that starts. A default
    // of `Some` would turn every such refusal into a silent degradation, and `true` for
    // `watch_group_policy` is what makes a machine-wide setting read at all.
    #[test]
    fn the_documented_defaults_and_bounds_are_the_stated_numbers() {
        let options = WatchOptions::new();
        assert_eq!(options.debounce, DEFAULT_DEBOUNCE);
        assert!(options.watch_group_policy);
        assert_eq!(options.poll_interval, None);

        assert_eq!(DEFAULT_DEBOUNCE, Duration::from_millis(200));
        assert_eq!(MIN_POLL_INTERVAL, Duration::from_millis(200));
        assert_eq!(MAX_DEBOUNCE, Duration::from_secs(24 * 60 * 60));
    }

    // The floor: zero, below, exactly at, and above `MIN_POLL_INTERVAL`.
    #[test]
    fn effective_poll_interval_clamps_to_the_floor() {
        let cases = [
            // zero
            (Duration::ZERO, MIN_POLL_INTERVAL),
            // below the floor
            (Duration::from_millis(1), MIN_POLL_INTERVAL),
            (
                MIN_POLL_INTERVAL - Duration::from_millis(1),
                MIN_POLL_INTERVAL,
            ),
            // exactly at the floor
            (MIN_POLL_INTERVAL, MIN_POLL_INTERVAL),
            // above the floor
            (
                MIN_POLL_INTERVAL + Duration::from_secs(1),
                MIN_POLL_INTERVAL + Duration::from_secs(1),
            ),
            (Duration::from_secs(30), Duration::from_secs(30)),
        ];
        for (requested, expected) in cases {
            assert_eq!(
                effective_poll_interval(requested),
                expected,
                "requested {requested:?}"
            );
        }
    }

    // The ceiling: zero, the default, just below, exactly at, and above `MAX_DEBOUNCE`.
    #[test]
    fn effective_debounce_clamps_to_the_ceiling() {
        let cases = [
            // below the ceiling
            (Duration::ZERO, Duration::ZERO),
            (DEFAULT_DEBOUNCE, DEFAULT_DEBOUNCE),
            (
                MAX_DEBOUNCE - Duration::from_millis(1),
                MAX_DEBOUNCE - Duration::from_millis(1),
            ),
            // exactly at the ceiling
            (MAX_DEBOUNCE, MAX_DEBOUNCE),
            // above the ceiling
            (MAX_DEBOUNCE + Duration::from_millis(1), MAX_DEBOUNCE),
            (Duration::MAX, MAX_DEBOUNCE),
        ];
        for (requested, expected) in cases {
            assert_eq!(
                effective_debounce(requested),
                expected,
                "requested {requested:?}"
            );
        }
    }

    // See [`MAX_DEBOUNCE`]: an overflowing deadline would stop the watcher thread.
    #[test]
    fn a_clamped_debounce_keeps_the_deadline_representable() {
        for requested in [Duration::MAX, MAX_DEBOUNCE + Duration::from_secs(1)] {
            let options = WatchOptions::new().with_debounce(requested);
            assert!(
                std::time::Instant::now()
                    .checked_add(effective_debounce(options.debounce))
                    .is_some(),
                "requested {requested:?}"
            );
        }
    }

    #[test]
    fn watch_health_live_and_frozen_flags() {
        let cases = [
            // Healthy: live native route, nothing degraded.
            (Vec::new(), true, None, false, true, false),
            // Degraded secondary source: not fully live, not frozen.
            (
                vec![ProxyConfigSource::GroupPolicy],
                true,
                None,
                false,
                false,
                false,
            ),
            // No native route and no poll: frozen snapshot only.
            (Vec::new(), false, None, false, false, true),
            // Poll interval rescues a watcher with no native notifications.
            (
                Vec::new(),
                false,
                Some(Duration::from_secs(30)),
                false,
                false,
                false,
            ),
            // ...but only while there is a thread left to do the polling.
            (
                Vec::new(),
                false,
                Some(Duration::from_secs(30)),
                true,
                false,
                true,
            ),
            // A stopped thread is not fully live either, however healthy the routes were
            // while it ran. The Windows backend reaches this state: a fatal `run`
            // error closes the stream without ever marking the routes lost, so
            // `has_live_notifications` is still the `true` it was armed with.
            (Vec::new(), true, None, true, false, true),
        ];
        for (degraded, has_live, poll_interval, stopped, fully_live, frozen) in cases {
            let health = WatchHealth {
                degraded,
                has_live_notifications: has_live,
                poll_interval,
                stopped,
            };
            assert_eq!(health.is_fully_live(), fully_live, "{health:?}");
            assert_eq!(health.is_frozen(), frozen, "{health:?}");
        }
    }

    // Runs `body` on a new thread with the panic hook silenced, so an expected panic prints
    // no backtrace, and returns the join. The hook is process-wide and tests run in
    // parallel, so the swap is serialised: tests restoring each other's silent hook
    // would leave every later panic in the run unprinted.
    fn join_silently(body: impl FnOnce() + Send + 'static) -> std::thread::Result<()> {
        static HOOK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _serial = HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::thread::spawn(body).join();
        std::panic::set_hook(previous);
        result
    }

    #[test]
    fn a_panicking_watcher_thread_still_closes_the_stream() {
        let shared = Arc::new(Shared::new(ProxyConfig::direct()));

        let result = {
            let shared = Arc::clone(&shared);
            join_silently(move || {
                let _guard = ThreadGuard::new(Arc::clone(&shared));
                panic!("simulated backend panic");
            })
        };

        assert!(result.is_err());

        let state = shared.lock();
        // The initial snapshot, then exactly one failure pushed by the panicking guard.
        assert_eq!(state.queue.len(), 2);
        assert!(matches!(state.queue[0], Queued::Snapshot));
        assert!(matches!(state.queue[1], Queued::Error(_)));
        assert!(state.closed);
        // `degraded` stays empty because a dead thread has no single route to blame.
        assert!(state.runtime_no_live_notifications);
        assert!(state.runtime_degraded.is_empty());
    }

    // The sibling above panics with no lock held, so the mutex it leaves behind is clean.
    // This one panics *inside* the critical section, which poisons it, and `ThreadGuard`'s
    // `Drop` then takes that same lock again in `mark_no_live_notifications`, in `fail` and
    // in `close`, all while `std::thread::panicking()` is still true.
    // `Shared::lock` recovers from the poison instead of propagating it; a
    // `lock().unwrap()` there would panic during unwinding, and a panic while panicking
    // aborts the process rather than closing the stream, so the loss is the whole program,
    // not one wrong answer.
    //
    // Nothing else in the tree stands here. `Shared::lock` is private, so an integration
    // test cannot hold the guard, and no other test panics with it held; the recovery
    // answers to this test alone.
    #[test]
    fn a_thread_that_panicked_holding_the_lock_still_gets_its_failure_delivered() {
        let shared = Arc::new(Shared::new(ProxyConfig::direct()));

        let result = {
            let shared = Arc::clone(&shared);
            join_silently(move || {
                let _guard = ThreadGuard::new(Arc::clone(&shared));
                // Declared after the guard, so it unwinds first and the guard's `Drop` finds
                // the mutex already poisoned.
                let _held = shared.lock();
                panic!("simulated backend panic inside the critical section");
            })
        };

        assert!(result.is_err());
        // Not vacuous: a fixture that failed to poison would hold nothing below.
        assert!(shared.state.is_poisoned());

        let state = shared.lock();
        assert_eq!(state.queue.len(), 2);
        assert!(matches!(state.queue[0], Queued::Snapshot));
        assert!(matches!(state.queue[1], Queued::Error(_)));
        assert!(state.closed);
        assert!(state.runtime_no_live_notifications);
    }

    // `emit` drops the guard before it logs, with `// Log after unlock: subscriber code
    // must not run under this mutex.` written on the line. A `tracing` subscriber is
    // arbitrary consumer code, and `std::sync::Mutex` is not reentrant, so a subscriber
    // that reaches back for `ProxyWatcher::state` from inside its own event handler would
    // block on a lock its own thread is holding: a hang rather than a wrong answer, which
    // no assertion about the emitted value can see.
    //
    // The witness has to be `try_lock` rather than a real re-entry, or the test would hang
    // instead of failing.
    #[cfg(feature = "tracing")]
    #[test]
    fn no_subscriber_ever_runs_while_the_state_mutex_is_held() {
        use tracing::subscriber::Interest;

        struct Probe {
            shared: Arc<Shared>,
            held: Mutex<Vec<(&'static str, bool)>>,
        }

        impl Probe {
            fn note(&self, hook: &'static str) {
                let held = self.shared.state.try_lock().is_err();
                self.held.lock().unwrap().push((hook, held));
            }
        }

        // Written out rather than borrowed from `tracing-subscriber` so that both hooks are
        // reachable: a `MakeWriter` sees only what an event *wrote*, and the level filter is
        // the other place consumer code runs.
        struct Wired(Arc<Probe>);

        impl tracing::Subscriber for Wired {
            // Without this the default returns `always`/`never` and the answer is cached at
            // the callsite, so `enabled` is asked once and never again.
            fn register_callsite(&self, _: &tracing::Metadata<'_>) -> Interest {
                Interest::sometimes()
            }

            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                self.0.note("enabled");
                true
            }

            fn event(&self, _: &tracing::Event<'_>) {
                self.0.note("event");
            }

            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::Id {
                tracing::Id::from_u64(1)
            }

            fn record(&self, _: &tracing::Id, _: &tracing::span::Record<'_>) {}

            fn record_follows_from(&self, _: &tracing::Id, _: &tracing::Id) {}

            fn enter(&self, _: &tracing::Id) {}

            fn exit(&self, _: &tracing::Id) {}
        }

        let shared = Arc::new(Shared::new(ProxyConfig::direct()));
        let probe = Arc::new(Probe {
            shared: Arc::clone(&shared),
            held: Mutex::new(Vec::new()),
        });
        tracing::subscriber::with_default(Wired(Arc::clone(&probe)), || {
            // Every branch `Shared` logs from: the equality skip, a real change, and the
            // close. Each is reached from inside a method that took the lock on its first
            // line.
            shared.emit(ProxyConfig::direct());
            shared.emit(ProxyConfig::from_source(
                crate::config::ProxyConfigSource::Registry,
                crate::mode::ProxyMode::WpadAutoDetect,
            ));
            shared.close();
        });

        let observed = probe.held.lock().unwrap();
        // Not vacuous, and not half-vacuous: both hooks have to have been reached, or one of
        // the two claims below is about a call that never happened.
        assert!(
            observed.iter().any(|(hook, _)| *hook == "enabled"),
            "the level filter has to have been consulted"
        );
        assert!(
            observed.iter().any(|(hook, _)| *hook == "event"),
            "an event has to have been emitted"
        );
        assert!(observed.iter().all(|(_, held)| !held), "{observed:?}");
    }

    // The guard marks the route lost *before* it queues the failure, and the comment beside
    // it says why: `fail` wakes the consumer, and a consumer that reads the health on being
    // woken must not still be told a route is live. No other test checks the order:
    // swapped, every assertion above still passes, because they all read the state after
    // the thread has been joined, by which point both calls have run either way.
    //
    // What moves is what the woken consumer is told. Only one of the two calls finds a
    // waker (the first one takes it), so the wake happens inside whichever runs first, and
    // that is the one moment at which the two orders disagree. Reading `health()` from
    // inside `wake` is how a test gets to stand there.
    //
    // It is not only a `health()` read that is at stake: the woken task's next act is to
    // poll, and `poll_next` stamps the failure with the health as it stands then. Swapped,
    // a consumer quick enough to poll before the second call lands takes an
    // `Error` reporting a live notification route from a thread that has already died.
    #[test]
    fn a_panicking_guard_marks_the_route_lost_before_it_wakes_anyone() {
        struct Probe {
            shared: Arc<Shared>,
            live_at_wake: Mutex<Vec<bool>>,
        }
        impl Wake for Probe {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                let live = self.shared.health().has_live_notifications;
                self.live_at_wake.lock().unwrap().push(live);
            }
        }

        let shared = Arc::new(Shared::new(ProxyConfig::direct()));
        shared.set_construction_health(live_construction_health());
        let probe = Arc::new(Probe {
            shared: Arc::clone(&shared),
            live_at_wake: Mutex::new(Vec::new()),
        });
        let waker = Waker::from(Arc::clone(&probe));
        let mut cx = Context::from_waker(&waker);

        // Take the subscription snapshot, then park with the waker registered.
        assert!(shared.poll_next(&mut cx).is_ready());
        assert!(shared.poll_next(&mut cx).is_pending());

        let result = {
            let shared = Arc::clone(&shared);
            join_silently(move || {
                let _guard = ThreadGuard::new(shared);
                panic!("simulated backend panic");
            })
        };
        assert!(result.is_err());

        // Exactly one wake, and the route was already lost when it arrived. The count is
        // part of the claim: a second entry would mean the first call did not take the
        // waker, and then the order below is not the one this test stands on.
        assert_eq!(
            *probe.live_at_wake.lock().unwrap(),
            vec![false],
            "the consumer must be woken once, and told the route is gone"
        );
    }

    // The sibling above stands on one half of a rule the crate states at `emit`: foreign code
    // must not run under this mutex. `degrade`, `fail` and `mark_no_live_notifications` all
    // `drop(state)` before `waker.wake()`, and that test holds it by reading `health()` from
    // inside `wake`.
    //
    // The other half is `poll_next`. It parks by storing the waker, and the store runs two
    // pieces of executor code with the lock held: `Waker::clone`, and the drop of whatever
    // waker was parked before. `Waker::from(Arc<W>)` makes the second one `W`'s own `Drop`,
    // so it is not exotic executor internals: it is ordinary user code. One that reaches
    // back for `ProxyWatcher::state` blocks on a lock its own thread holds, and
    // `std::sync::Mutex` is not reentrant: a deadlock, not a wrong answer.
    //
    // The probe has to be `try_lock` rather than a real re-entry, or the test would hang
    // instead of failing. Only the drop is observable from safe code; `Waker::clone` on an
    // `Arc`-backed waker is a refcount bump with no user hook, but the same two lines move
    // both out from under the lock.
    #[test]
    fn parking_never_runs_executor_code_under_the_state_mutex() {
        struct Probe {
            shared: Arc<Shared>,
            held_at_drop: Arc<Mutex<Vec<bool>>>,
        }
        impl Wake for Probe {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {}
        }
        impl Drop for Probe {
            fn drop(&mut self) {
                let held = self.shared.state.try_lock().is_err();
                self.held_at_drop.lock().unwrap().push(held);
            }
        }

        let shared = Arc::new(Shared::new(ProxyConfig::direct()));
        let held_at_drop = Arc::new(Mutex::new(Vec::new()));
        let probe = Arc::new(Probe {
            shared: Arc::clone(&shared),
            held_at_drop: Arc::clone(&held_at_drop),
        });

        let waker = Waker::from(Arc::clone(&probe));
        // Take the subscription snapshot, then park: the second poll is the one that stores
        // a clone of the probe's waker.
        assert!(
            shared
                .poll_next(&mut Context::from_waker(&waker))
                .is_ready()
        );
        assert!(
            shared
                .poll_next(&mut Context::from_waker(&waker))
                .is_pending()
        );
        // Leave the parked clone as the only reference, so replacing it is what runs `Drop`.
        drop(waker);
        drop(probe);

        assert!(
            shared
                .poll_next(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );

        let observed = held_at_drop.lock().unwrap();
        // Not vacuous: a probe that was never dropped asserts nothing below.
        assert_eq!(
            observed.len(),
            1,
            "the parked waker has to have been dropped"
        );
        assert!(observed.iter().all(|held| !held), "{observed:?}");
    }

    // A cheap-to-construct error: its variant does not matter to [`watch_fail_soft`],
    // only whether establishing the route returned `Err` at all.
    fn some_error() -> Error {
        Error::Unsupported
    }

    #[test]
    fn an_unreachable_platform_fails_the_route_as_it_is_whatever_the_interval() {
        let unreachable = || Err(Error::io("attaching", std::io::Error::other("no JavaVM")));
        for poll_interval in [None, Some(Duration::from_secs(1))] {
            let mut established = false;
            let outcome = watch_fail_soft_reachable(unreachable, true, poll_interval, || {
                established = true;
                Ok(())
            });
            let Err(error) = outcome else {
                panic!("an unreachable platform was softened under {poll_interval:?}");
            };
            assert!(
                matches!(&error, Error::Io { context, .. } if context == "attaching"),
                "{error:?}"
            );
            assert!(
                !established,
                "the route was attempted with no platform to reach"
            );
        }

        // Reachable, the route's own failure is `watch_fail_soft`'s to judge.
        let failed = || Err::<(), _>(Error::Unsupported);
        assert!(matches!(
            watch_fail_soft_reachable(|| Ok(()), true, None, failed),
            Ok(WatchFailSoft::Fatal(Error::Unsupported))
        ));
        assert!(matches!(
            watch_fail_soft_reachable(|| Ok(()), true, Some(Duration::from_secs(1)), failed),
            Ok(WatchFailSoft::Degraded(Error::Unsupported))
        ));
    }

    #[test]
    fn watch_fail_soft_outcomes() {
        enum Input {
            Ok,
            Err,
        }
        enum Expect {
            Live,
            Degraded,
            Fatal,
        }

        let cases: &[(bool, Option<Duration>, Input, Expect)] = &[
            (true, None, Input::Ok, Expect::Live),
            (false, None, Input::Ok, Expect::Live),
            (true, Some(Duration::from_secs(1)), Input::Ok, Expect::Live),
            (false, Some(Duration::from_secs(1)), Input::Ok, Expect::Live),
            (false, None, Input::Err, Expect::Degraded),
            (
                false,
                Some(Duration::from_secs(1)),
                Input::Err,
                Expect::Degraded,
            ),
            (
                true,
                Some(Duration::from_secs(30)),
                Input::Err,
                Expect::Degraded,
            ),
            (true, None, Input::Err, Expect::Fatal),
        ];
        for (leading, poll_interval, input, expect) in cases {
            let outcome = watch_fail_soft(
                *leading,
                *poll_interval,
                match input {
                    Input::Ok => Ok(42),
                    Input::Err => Err(some_error()),
                },
            );
            match expect {
                Expect::Live => assert!(
                    matches!(outcome, WatchFailSoft::Live(42)),
                    "leading = {leading}, poll_interval = {poll_interval:?}"
                ),
                Expect::Degraded => assert!(
                    matches!(outcome, WatchFailSoft::Degraded(_)),
                    "leading = {leading}, poll_interval = {poll_interval:?}"
                ),
                Expect::Fatal => assert!(
                    matches!(outcome, WatchFailSoft::Fatal(_)),
                    "leading = {leading}, poll_interval = {poll_interval:?}"
                ),
            }
        }
    }

    // [`fatal_watch_error`] must say what to do about it, not just that it
    // failed, and must not lose either the caller-supplied `why_no_fallback` or `what`.
    #[test]
    fn fatal_watch_error_names_the_fix_and_keeps_the_context() {
        let error = fatal_watch_error(
            "opening or arming the HKCU Internet Settings key",
            "HKCU is Windows' only mandatory proxy source",
            some_error(),
        );
        let message = error.to_string();
        assert!(
            message.contains("poll_interval"),
            "the error should point at the fix: {message}"
        );
        assert!(
            message.contains("opening or arming the HKCU Internet Settings key"),
            "the error should still say what failed: {message}"
        );
        assert!(
            message.contains("HKCU is Windows' only mandatory proxy source"),
            "the error should still say why there is no fallback: {message}"
        );
    }

    // A source reported through [`Shared::degrade`] shows up in [`Shared::health`], and
    // reporting it twice does not duplicate it.
    #[test]
    fn shared_degrade_is_idempotent() {
        let shared = Shared::new(ProxyConfig::direct());
        shared.set_construction_health(live_construction_health());
        let health = shared.health();
        assert!(health.degraded.is_empty());
        assert!(health.has_live_notifications);
        assert!(!health.stopped);

        shared.degrade(ProxyConfigSource::GroupPolicy);
        shared.degrade(ProxyConfigSource::GroupPolicy);
        let health = shared.health();
        assert_eq!(health.degraded, vec![ProxyConfigSource::GroupPolicy]);
        // One route degrading is not every route degrading, and degrading is not
        // closing: the thread reporting the loss is still running.
        assert!(health.has_live_notifications);
        assert!(!health.stopped);
    }

    // [`Shared::mark_no_live_notifications`] is a one-way flag: nothing ever needs
    // to clear it, since no backend re-establishes a route once it has degraded.
    #[test]
    fn shared_mark_no_live_notifications_is_reflected_in_health() {
        let shared = Shared::new(ProxyConfig::direct());
        shared.set_construction_health(live_construction_health());
        assert!(shared.health().has_live_notifications);
        shared.mark_no_live_notifications();
        assert!(!shared.health().has_live_notifications);
    }

    // [`merge_runtime_health`] must fold what [`Shared`] recorded into the
    // construction-time result without disturbing an already-degraded source or ever
    // flipping `has_live_notifications` back to `true`.
    #[test]
    fn merge_runtime_health_folds_in_new_state_without_disturbing_the_old() {
        let construction = WatchHealth {
            degraded: vec![ProxyConfigSource::GroupPolicy],
            has_live_notifications: true,
            poll_interval: None,
            stopped: false,
        };

        // Nothing runtime-side yet: the construction-time value passes through.
        let health = merge_runtime_health(&construction, Vec::new(), false, false);
        assert_eq!(health.degraded, vec![ProxyConfigSource::GroupPolicy]);
        assert!(health.has_live_notifications);

        // A runtime degrade adds an entry; a duplicate is not added twice.
        let health = merge_runtime_health(
            &construction,
            vec![ProxyConfigSource::Registry, ProxyConfigSource::GroupPolicy],
            false,
            false,
        );
        assert_eq!(
            health.degraded,
            vec![ProxyConfigSource::GroupPolicy, ProxyConfigSource::Registry]
        );
        assert!(health.has_live_notifications);

        // Once every native route has degraded, `has_live_notifications` flips to
        // `false`; the construction-time `true` never wins over it.
        let health = merge_runtime_health(&construction, Vec::new(), true, false);
        assert!(!health.has_live_notifications);
    }

    // The polling configured by `poll_interval` runs *on* the backend thread, so a thread
    // that stopped takes it with it. Without `stopped`, a watcher whose thread panicked
    // went on reporting `is_frozen() == false` on the strength of an interval no thread was
    // waiting out any more, falsely reporting that changes could still be detected.
    #[test]
    fn a_poll_interval_stops_counting_once_the_thread_is_gone() {
        let construction = WatchHealth {
            degraded: Vec::new(),
            has_live_notifications: true,
            poll_interval: Some(Duration::from_secs(30)),
            stopped: false,
        };

        let live = merge_runtime_health(&construction, Vec::new(), false, false);
        assert!(!live.is_frozen());

        // What `ThreadGuard::drop` leaves behind after a panic: no live notifications,
        // and the stream closed.
        let panicked = merge_runtime_health(&construction, Vec::new(), true, true);
        assert!(panicked.is_frozen());
        assert_eq!(
            panicked.poll_interval,
            Some(Duration::from_secs(30)),
            "the interval is still what the caller asked for"
        );
    }
}
