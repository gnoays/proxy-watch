//! `RegNotifyChangeKeyValue` watcher thread.
//!
//! One notification per registration — re-arm after *that* key's wake, never before.
//! Filter/subtree fixed per registration; changing either needs the handle reopened.
//! Persistent thread + `REG_NOTIFY_THREAD_AGNOSTIC`.
//! Debounce + equality skip coalesce storms. Stop via manual-reset event in the wait.
//!
//! [`WatchOptions::poll_interval`] → outer [`WaitForMultipleObjects`] timeout;
//! [`Watch::poll_now`] → auto-reset event — same debounce path.
//!
//! HKCU (leading): `watch_fail_soft` — poll set → degrade; unset → fatal. A key *missing at
//! construction* degrades either way; only opening or arming an existing one can be fatal.
//! After construction only [`WatchedKey::arm`] runs, and it has no missing-key arm, so a key
//! deleted under an open handle fails the re-arm and the table decides. A rearm failure the table softens goes to
//! [`Shared::degrade`] / [`Shared::mark_no_live_notifications`]; one it calls fatal skips
//! them and ends the thread through [`Shared::fail`] instead, which leaves
//! `has_live_notifications` as construction left it — after one last read, since the
//! notification that failed to re-arm had already announced a change.
//!
//! Group policy + non-policy HKLM: fail-soft. [`arm_group_policy_key`] watches an ancestor
//! with `bWatchSubtree` (not the leaf — [`group_policy_ancestors`]); `Software` noise OK.

use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET,
    REG_NOTIFY_CHANGE_NAME, REG_NOTIFY_FILTER, REG_NOTIFY_THREAD_AGNOSTIC, RegNotifyChangeKeyValue,
};
use windows::Win32::System::Threading::{INFINITE, SetEvent, WaitForMultipleObjects};

use crate::config::ProxyConfigSource;
use crate::error::Error;
use crate::watch::{
    BackendHealth, Shared, WatchFailSoft, WatchOptions, effective_debounce,
    effective_poll_interval, fatal_watch_error, watch_fail_soft,
};

use super::ffi::{Event, RegKey, SendPtr, hresult_error, win32_error};
use super::{INTERNET_SETTINGS, POLICY_INTERNET_SETTINGS, read_config};

// `LAST_SET` is the value side, and covers adding or deleting a value as well as
// changing one. `NAME` is the *subkey* side — a subkey appearing or disappearing —
// which is worth having because every registration below passes `bWatchSubtree`: a
// settings key created after the watch was armed is still a change to re-read on.
// `REG_NOTIFY_THREAD_AGNOSTIC` (Windows 8+) unties the registration from the thread
// that made it; without it, that thread exiting signals the event by itself.
const NOTIFY_FILTER: REG_NOTIFY_FILTER = REG_NOTIFY_FILTER(
    REG_NOTIFY_CHANGE_LAST_SET.0 | REG_NOTIFY_CHANGE_NAME.0 | REG_NOTIFY_THREAD_AGNOSTIC.0,
);

// Context for the leading key's open and for the synthetic error that stands in for it
// not existing, so the two cannot drift apart.
const OPENING_USER_KEY: &str = "opening HKCU Internet Settings key for notifications";

// A registry watcher: the watched keys, the thread draining them, and the event used
// to stop it.
#[derive(Debug)]
pub(crate) struct Watch {
    // Signalled by [`Drop`] to make the thread return.
    shutdown: Event,
    // Signalled by [`Watch::poll_now`] to wake the thread out of
    // [`WaitForMultipleObjects`] and open a debounce window immediately. Auto-reset,
    // like the registry notification events: the wait consuming the signal is exactly
    // the desired behaviour.
    poll_now: Event,
    // Armed keys, until [`Watch::spawn`] hands them to the thread.
    watched: Option<Vec<WatchedKey>>,
    // Sources [`Watch::armed`] could not establish a live notification route for,
    // captured once at construction time and fed into [`Watch::health`]. A later,
    // *runtime* degrade (a [`rearm`] failure after construction already succeeded) is
    // reported through `crate::watch::Shared::degrade` instead. Not because this `Vec`
    // has gone anywhere — unlike `watched` below, [`Watch::spawn`] leaves it on `self`
    // for [`Watch::health`] to read afterwards — but because [`Watch::armed`] is the only
    // writer, and the thread that would learn of a runtime degrade cannot reach `self`.
    construction_degraded: Vec<ProxyConfigSource>,
    // How many native notification routes were live once construction finished.
    // Captured separately from `watched.len()` because [`Watch::spawn`] `take`s
    // `watched`, after which [`Watch::health`] would have nothing left to count.
    live_at_construction: usize,
    thread: Option<JoinHandle<()>>,
}

impl Watch {
    // Open the watched keys and register their first change notification.
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    pub(crate) fn armed(options: &WatchOptions) -> Result<Self, Error> {
        let shutdown = Event::new(true, "creating the proxy-watch shutdown event")?;
        let poll_now = Event::new(false, "creating the proxy-watch poll_now event")?;

        let mut watched = Vec::with_capacity(3);
        let mut construction_degraded = Vec::new();

        // `leading` is what makes a failure here fatal without a poll interval, and a key
        // that does not exist is not that failure. [`super::read_user_mode`] answers
        // `Direct` for exactly that machine, so refusing to construct would deny a
        // configuration this crate can still read — and no `poll_interval` could have armed
        // a key that is not there, so naming it as the fix would be wrong too. An open or
        // arm *failure* keeps the leading classification.
        //
        // Nor is there an ancestor-walk, unlike [`arm_group_policy_key`]: the nearest HKCU
        // ancestor is `Software\Microsoft\Windows\CurrentVersion`, which Explorer writes to
        // constantly, so a subtree registration there would wake this thread on traffic
        // that has nothing to do with proxies. What that costs is a key created *later*:
        // nothing arms it, so only a `poll_interval` timer or [`Watch::poll_now`] would ever
        // see it. `health()`
        // reports `Registry` degraded meanwhile, but not frozen — the HKLM keys below do
        // arm — so a caller that wants to catch this reads `is_fully_live`, not
        // `is_frozen`.
        //
        // The quiet version of that registration is refused separately, because the
        // paragraph above prices only the subtree. Watching `CurrentVersion` with
        // `bWatchSubtree` false and `REG_NOTIFY_CHANGE_NAME` alone would not see the
        // Explorer traffic at all — "if the parameter is FALSE, the function reports
        // changes only in the specified key", and that filter fires "if a subkey is added
        // or deleted" (`RegNotifyChangeKeyValue`, *Parameters*) — so the cost named above
        // is not what settles it. Two other things do. [`WatchedKey::arm`] passes
        // `bWatchSubtree` for every key it registers, and neither it nor the filter can be
        // changed on an open handle without closing and reopening it, so this asks for a
        // per-key registration shape and another permanently armed handle on every
        // machine. And it asks for them against a key Windows itself creates: on a
        // Windows 11 machine every hive that could be read already carried it — `.DEFAULT`
        // and the three service accounts included, which is the case
        // [`super::read_user_mode`]'s own missing-key arm is written for. That is the
        // reason [`arm_machine_default_key`] needs no ancestor-walk either, and it applies
        // on this side of the registry too.
        let (user_key, leading) = match WatchedKey::open(
            HKEY_CURRENT_USER,
            INTERNET_SETTINGS,
            true,
            ProxyConfigSource::Registry,
            OPENING_USER_KEY,
        ) {
            Ok(Some(key)) => (key.arm().map(|()| key), true),
            Ok(None) => (
                Err(Error::io(
                    OPENING_USER_KEY,
                    std::io::Error::from(std::io::ErrorKind::NotFound),
                )),
                false,
            ),
            Err(error) => (Err(error), true),
        };

        match watch_fail_soft(leading, options.poll_interval, user_key) {
            WatchFailSoft::Live(key) => watched.push(key),
            WatchFailSoft::Degraded(error) => {
                crate::trace::warning!(
                    key = INTERNET_SETTINGS,
                    error = %crate::trace::SafeError(&error),
                    "there is no HKCU Internet Settings notification route, so the watcher \
                     continues without one; WatchOptions::poll_interval still re-reads on a \
                     timer if it is set"
                );
                push_degraded(&mut construction_degraded, ProxyConfigSource::Registry);
            }
            WatchFailSoft::Fatal(error) => {
                return Err(fatal_watch_error(
                    "opening or arming HKCU Internet Settings for notifications",
                    "HKCU is Windows' only mandatory proxy configuration source, with no \
                     fallback route this backend can use instead",
                    error,
                ));
            }
        }

        // Secondary, always fail-soft — see the module docs. Not requesting group policy
        // watching at all is opting out, not degradation, so nothing is recorded then.
        if options.watch_group_policy && !arm_group_policy_key(&mut watched) {
            push_degraded(&mut construction_degraded, ProxyConfigSource::GroupPolicy);
        }

        // Unconditional, unlike group policy: it costs nothing to try and is not itself
        // opt-in machinery an administrator has to set up.
        if !arm_machine_default_key(&mut watched) {
            push_degraded(
                &mut construction_degraded,
                ProxyConfigSource::WinHttpDefault,
            );
        }

        let live_at_construction = watched.len();

        crate::trace::debug!(
            keys = watched.len(),
            user_key = INTERNET_SETTINGS,
            group_policy = options.watch_group_policy,
            "armed RegNotifyChangeKeyValue over the watched registry subtrees"
        );

        Ok(Self {
            shutdown,
            poll_now,
            watched: Some(watched),
            construction_degraded,
            live_at_construction,
            thread: None,
        })
    }

    // Report which documented Windows notification routes were established at
    // construction time.
    pub(crate) fn health(&self) -> BackendHealth {
        BackendHealth {
            degraded: self.construction_degraded.clone(),
            has_live_notifications: self.live_at_construction > 0,
        }
    }

    // Start the watcher thread (a dedicated `std::thread`, no runtime).
    //
    // # Panics
    //
    // If called twice on the same value.
    pub(crate) fn spawn(
        &mut self,
        options: &WatchOptions,
        shared: Arc<Shared>,
    ) -> Result<(), Error> {
        let watched = self
            .watched
            .take()
            .expect("Watch::spawn must be called exactly once");
        let shutdown = SendPtr(self.shutdown.raw().0);
        let poll_now = SendPtr(self.poll_now.raw().0);
        let options = options.clone();

        let thread = thread::Builder::new()
            .name("proxy-watch-registry".to_owned())
            .spawn(move || {
                let _guard = crate::watch::ThreadGuard::new(Arc::clone(&shared));
                crate::trace::debug!("the registry watcher thread started");
                if let Err(error) = run(shutdown, poll_now, watched, &options, &shared) {
                    // The loop only returns an error when it can no longer wait or
                    // re-arm, i.e. when watching cannot continue at all (`ERROR` is
                    // reserved for exactly that).
                    crate::trace::error!(
                        error = %crate::trace::SafeError(&error),
                        "the registry watcher thread cannot continue"
                    );
                    shared.fail(error);
                }
            })
            .map_err(|source| Error::io("spawning the proxy-watch registry thread", source))?;

        self.thread = Some(thread);
        Ok(())
    }

    // Signal the poll_now event, waking [`WaitForMultipleObjects`] so [`run`] opens a
    // debounce window and re-reads immediately, exactly as a [`Wake::Key`] or
    // [`Wake::Timeout`] wake already does.
    pub(crate) fn poll_now(&self) {
        // SAFETY: `self.poll_now` is a live event handle owned by `self` for as long as
        // this `Watch` exists; the thread only ever waits on it, so signalling it here
        // is race free — the same reasoning `Drop`'s `SetEvent` on `shutdown` relies on.
        unsafe {
            let _ = SetEvent(self.poll_now.raw());
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // Not "the thread": a `Watch` that was armed but never spawned is dropped here too
        // ([`crate::watch::ProxyWatcher::with_options`] reads the configuration between the
        // two, and that read can fail), and then there is no thread to stop.
        crate::trace::debug!("stopping the registry watcher");
        // SAFETY: `shutdown` is a live manual-reset event owned by `self`; the thread
        // only ever waits on it, so signalling it here is race free.
        unsafe {
            let _ = SetEvent(self.shutdown.raw());
        }
        if let Some(thread) = self.thread.take() {
            // Join before `self.shutdown` is closed, so the thread can never wait on a
            // dangling handle, and so no registry handle outlives this call.
            let _ = thread.join();
        }
    }
}

// Push `source` onto `degraded` unless it is already there.
fn push_degraded(degraded: &mut Vec<ProxyConfigSource>, source: ProxyConfigSource) {
    if !degraded.contains(&source) {
        degraded.push(source);
    }
}

// A key being watched together with the event its notifications signal.
#[derive(Debug)]
struct WatchedKey {
    key: RegKey,
    event: Event,
    // Whether a failure to re-arm this key (see [`rearm`]) is fatal *unless*
    // [`WatchOptions::poll_interval`] is set, through
    // [`crate::watch::watch_fail_soft`]'s `leading` parameter.
    //
    // `true` only for HKCU, Windows' one mandatory source — it has no fallback route
    // this backend could use instead. `false` for the HKLM keys, whose failures degrade
    // unconditionally: neither was ever the only way to notice a change.
    critical: bool,
    // Which [`ProxyConfigSource`] a failure of this key should be attributed to in
    // [`BackendHealth::degraded`] / [`crate::watch::WatchHealth::degraded`], whose doc
    // says which source a dead route names: [`ProxyConfigSource::Registry`] for HKCU,
    // [`ProxyConfigSource::GroupPolicy`] for the group policy ancestor, and
    // [`ProxyConfigSource::WinHttpDefault`] for the non-policy HKLM key — nothing opens
    // that key, and [`arm_machine_default_key`] says what it does deliver.
    source: ProxyConfigSource,
    // Only used to say *which* key woke the thread, so it has no reader in a build
    // without the `tracing` feature.
    #[cfg_attr(not(feature = "tracing"), allow(dead_code))]
    path: &'static str,
}

impl WatchedKey {
    fn open(
        root: HKEY,
        path: &'static str,
        critical: bool,
        source: ProxyConfigSource,
        context: &str,
    ) -> Result<Option<Self>, Error> {
        let Some(key) = RegKey::open(root, path, KEY_NOTIFY, context)? else {
            return Ok(None);
        };
        let event = Event::new(false, "creating a registry notification event")?;
        Ok(Some(Self {
            key,
            event,
            critical,
            source,
            path,
        }))
    }

    // (Re-)register for the next notification.
    fn arm(&self) -> Result<(), Error> {
        // SAFETY: the key handle and the event handle are both owned by `self` and
        // still open. `fAsynchronous = true` requires a valid event, which is exactly
        // what is passed, and the call is only ever made when no registration for this
        // key is outstanding (see the module docs).
        let status = unsafe {
            RegNotifyChangeKeyValue(
                self.key.raw(),
                true,
                NOTIFY_FILTER,
                Some(self.event.raw()),
                true,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(win32_error(
                "registering a registry change notification",
                status,
            ))
        }
    }
}

// Strict ancestors of [`POLICY_INTERNET_SETTINGS`] to try watching, most specific first.
// The leaf is deliberately not among them, which is the whole reason this walk exists: a
// `gpupdate` that lifts a policy deletes the leaf out from under the handle, the re-arm
// fails, [`Shared::degrade`] retires [`ProxyConfigSource::GroupPolicy`] for the life of
// the process, and a policy re-applied later is never seen again. An ancestor outlives
// the policy it holds, so the route survives the deletion.
fn group_policy_ancestors() -> Vec<&'static str> {
    let mut candidates = Vec::new();
    let mut rest = POLICY_INTERNET_SETTINGS;
    while let Some(index) = rest.rfind('\\') {
        rest = &rest[..index];
        candidates.push(rest);
    }
    candidates
}

// Try candidates under `root`; push first success. Failures WARN rather than
// failing the caller — both call sites ([`arm_group_policy_key`],
// [`arm_machine_default_key`]) watch a secondary, unconditionally fail-soft source (see
// the module docs). Returns `false` if none armed.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn arm_first_available(
    watched: &mut Vec<WatchedKey>,
    root: HKEY,
    candidates: &[&'static str],
    source: ProxyConfigSource,
    what: &str,
) -> bool {
    for &path in candidates {
        let context = format!("opening {what} ({path}) for notifications");
        let key = match WatchedKey::open(root, path, false, source, &context) {
            Ok(Some(key)) => key,
            Ok(None) => {
                crate::trace::warning!(
                    key = path,
                    what,
                    "a secondary registry key does not exist; trying the next candidate"
                );
                continue;
            }
            Err(error) => {
                crate::trace::warning!(
                    key = path,
                    what,
                    error = %crate::trace::SafeError(&error),
                    "opening a secondary registry key failed; trying the next candidate"
                );
                continue;
            }
        };
        if let Err(error) = key.arm() {
            crate::trace::warning!(
                key = path,
                what,
                error = %crate::trace::SafeError(&error),
                "arming a secondary registry key failed; trying the next candidate"
            );
            continue;
        }
        crate::trace::debug!(key = path, what, "armed a secondary registry key");
        watched.push(key);
        return true;
    }
    false
}

// Try to open and arm the closest *ancestor* of the group policy key that exists — see
// [`group_policy_ancestors`] for why the leaf key itself is not among the candidates.
// Returns `false` only if even `Software` could not be opened or armed, which in
// practice does not happen — `Software` always exists under `HKEY_LOCAL_MACHINE`.
fn arm_group_policy_key(watched: &mut Vec<WatchedKey>) -> bool {
    arm_first_available(
        watched,
        HKEY_LOCAL_MACHINE,
        &group_policy_ancestors(),
        ProxyConfigSource::GroupPolicy,
        "an HKLM group policy ancestor key",
    )
}

// Watch `HKLM\...\Internet Settings` — the non-policy, machine-wide counterpart of the
// per-user key this backend already watches. No reader ever opens this key, but the
// WinHTTP machine default lives *under* it: `netsh winhttp set proxy` writes
// `...\Internet Settings\Connections\WinHttpSettings`, which [`read_config`] reads back
// through `WinHttpGetDefaultProxyConfiguration`. The subtree registration is the only
// *notification* route by which such a change reaches a subscriber — a `poll_interval`
// timer and `poll_now` both re-read it — so a
// failure here degrades [`ProxyConfigSource::WinHttpDefault`] and not the HKCU key's
// [`ProxyConfigSource::Registry`], which is still delivering the per-user store this
// backend reads on an ordinary machine. Unlike
// [`arm_group_policy_key`] there is only one candidate: this key is a pre-existing part
// of Windows itself, not something created or deleted on demand, so no ancestor-walk
// fallback is needed.
fn arm_machine_default_key(watched: &mut Vec<WatchedKey>) -> bool {
    arm_first_available(
        watched,
        HKEY_LOCAL_MACHINE,
        &[INTERNET_SETTINGS],
        ProxyConfigSource::WinHttpDefault,
        "the non-policy HKLM Internet Settings key",
    )
}

// What a wait returned.
enum Wake {
    Shutdown,
    // The poll_now event signalled ([`Watch::poll_now`]): a caller explicitly asked for
    // a re-read.
    PollNow,
    // The watched key at this index signalled.
    Key(usize),
    // The timeout passed to [`wait`] elapsed without any handle signalling. In the outer
    // wait of [`run`] this only happens when [`WatchOptions::poll_interval`] is set; in
    // the debounce sub-wait it is the normal way the window closes.
    Timeout,
}

// Convert [`WatchOptions::poll_interval`] into the timeout the outer [`wait`] in
// [`run`] should use, or [`INFINITE`] when polling is off.
fn poll_wait_millis(poll_interval: Option<Duration>) -> u32 {
    match poll_interval {
        None => INFINITE,
        Some(interval) => u32::try_from(effective_poll_interval(interval).as_millis())
            .unwrap_or(u32::MAX)
            .min(u32::MAX - 1),
    }
}

// Convert what is left of the debounce window into the timeout the inner [`wait`] in
// [`run`] should use.
fn debounce_wait_millis(remaining: Duration) -> u32 {
    u32::try_from(remaining.as_millis())
        .unwrap_or(u32::MAX)
        .min(u32::MAX - 1)
}

// The watcher loop. `watched` arrives already armed by [`Watch::armed`].
fn run(
    shutdown: SendPtr,
    poll_now: SendPtr,
    watched: Vec<WatchedKey>,
    options: &WatchOptions,
    shared: &Shared,
) -> Result<(), Error> {
    // The shutdown event first and the poll_now event next, so `WaitForMultipleObjects`
    // (which reports the lowest signalled index) always prefers stopping over another
    // round of work, and prefers an explicit poll_now request over whichever registry key
    // happens to come later in `watched`.
    let mut handles = Vec::with_capacity(watched.len() + 2);
    handles.push(shutdown.handle());
    handles.push(poll_now.handle());
    handles.extend(watched.iter().map(|w| w.event.raw()));

    let poll_millis = poll_wait_millis(options.poll_interval);

    // Every entry starts alive — `watched` only contains keys `Watch::armed` actually
    // established — and `rearm` flips one to `false` the first time it degrades, so
    // `mark_degraded_and_check_all_dead` can tell "just this key died" from "the last
    // live route just died".
    let mut alive = vec![true; watched.len()];

    loop {
        // A re-arm that cannot continue ends the loop, but only after the read below. The
        // notification that woke us announced a change; returning here would drop it and
        // leave `current()` describing the configuration from before it — answering with
        // nothing while holding the information. Fail-soft covers what could not be read,
        // not what was read and then dropped.
        let mut fatal = None;

        match wait(&handles, poll_millis)? {
            Wake::Shutdown => return Ok(()),
            Wake::PollNow => {
                crate::trace::debug!("poll_now() opened the debounce window");
            }
            Wake::Key(index) => {
                if let Err(error) =
                    rearm(&watched, &mut alive, index, options.poll_interval, shared)
                {
                    fatal.get_or_insert(error);
                }
                crate::trace::debug!(
                    key = watched[index].path,
                    "a registry change notification opened the debounce window"
                );
            }
            Wake::Timeout => {
                crate::trace::debug!("the poll interval elapsed; opening the debounce window");
            }
        }

        // The fixed window `WatchOptions::debounce` describes; that is what holds the
        // detection-latency SLO under a storm of writes.
        let deadline = Instant::now() + effective_debounce(options.debounce);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match wait(&handles, debounce_wait_millis(remaining))? {
                Wake::Shutdown => return Ok(()),
                // Coalesced into the window already open, same as another registry
                // notification arriving inside it — nothing more to do.
                Wake::PollNow => {}
                Wake::Key(index) => {
                    if let Err(error) =
                        rearm(&watched, &mut alive, index, options.poll_interval, shared)
                    {
                        fatal.get_or_insert(error);
                    }
                }
                Wake::Timeout => break,
            }
        }

        crate::trace::debug!("the debounce window closed; re-reading the registry");
        match read_config(options) {
            // Emit only when the snapshot actually differs from the previous one.
            Ok(config) => {
                shared.emit(config);
            }
            // A transient failure (a value being rewritten as we read it, say) must not
            // end the subscription.
            Err(error) => shared.fail(error),
        }

        if let Some(error) = fatal {
            return Err(error);
        }
    }
}

// Mark `alive[index]` dead and report whether every tracked route is now dead.
//
// Pure and index-checked only by the caller, so it is unit tested directly below without
// a real registry key, event, or [`Shared`].
fn mark_degraded_and_check_all_dead(alive: &mut [bool], index: usize) -> bool {
    alive[index] = false;
    alive.iter().all(|&is_alive| !is_alive)
}

// Re-arm `watched[index]` after it woke, honouring [`WatchedKey`]'s `critical` flag and
// [`WatchOptions::poll_interval`] through the shared judgement table
// [`crate::watch::watch_fail_soft`] — the same table [`Watch::armed`] runs HKCU through
// at construction time.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn rearm(
    watched: &[WatchedKey],
    alive: &mut [bool],
    index: usize,
    poll_interval: Option<Duration>,
    shared: &Shared,
) -> Result<(), Error> {
    let key = &watched[index];
    match watch_fail_soft(key.critical, poll_interval, key.arm()) {
        WatchFailSoft::Live(()) => Ok(()),
        WatchFailSoft::Degraded(error) => {
            crate::trace::warning!(
                key = key.path,
                error = %crate::trace::SafeError(&error),
                "re-arming a registry watch failed; it will no longer notify for this key"
            );
            shared.degrade(key.source);
            if mark_degraded_and_check_all_dead(alive, index) {
                shared.mark_no_live_notifications();
            }
            Ok(())
        }
        WatchFailSoft::Fatal(error) => Err(fatal_watch_error(
            "re-arming HKCU Internet Settings for notifications",
            "HKCU is Windows' only mandatory proxy configuration source, with no fallback \
             route this backend can use instead",
            error,
        )),
    }
}

// Wait for the shutdown event, the poll_now event, or any notification event.
//
// `handles` is always laid out as `[shutdown, poll_now, ...watched]` by [`run`], so
// index 0 and 1 are fixed and every index from 2 onwards maps back to `watched[i - 2]`.
fn wait(handles: &[HANDLE], millis: u32) -> Result<Wake, Error> {
    // SAFETY: every handle in the slice is owned by the caller and still open for the
    // duration of the call; `bWaitAll = false` makes the return value an index into it.
    let result = unsafe { WaitForMultipleObjects(handles, false, millis) };

    if result == WAIT_TIMEOUT {
        return Ok(Wake::Timeout);
    }
    if result == WAIT_FAILED {
        return Err(hresult_error(
            "waiting for registry change notifications",
            windows::core::Error::from_thread(),
        ));
    }
    let index = result.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
    match index {
        0 => Ok(Wake::Shutdown),
        1 => Ok(Wake::PollNow),
        i if i < handles.len() => Ok(Wake::Key(i - 2)),
        _ => Err(Error::io(
            "waiting for registry change notifications",
            std::io::Error::other(format!("unexpected wait result {result:?}")),
        )),
    }
}

#[cfg(test)]
mod tests {
    //! Pure logic here, plus read-only opens; registry *writes* in
    //! `tests/windows_watch.rs`; `watch_fail_soft` in `src/watch.rs`.

    use super::*;

    #[test]
    fn no_poll_interval_waits_forever() {
        assert_eq!(poll_wait_millis(None), INFINITE);
    }

    #[test]
    fn a_poll_interval_converts_to_milliseconds() {
        assert_eq!(poll_wait_millis(Some(Duration::from_secs(30))), 30_000);
    }

    // A poll interval below `MIN_POLL_INTERVAL` is floored before converting, so
    // `Duration::ZERO` cannot produce a 0 ms `WaitForMultipleObjects` timeout and
    // busy-loop.
    #[test]
    fn a_too_small_poll_interval_is_clamped_before_converting() {
        let floor_millis = u32::try_from(crate::watch::MIN_POLL_INTERVAL.as_millis())
            .expect("the floor fits u32 milliseconds");
        assert_eq!(
            poll_wait_millis(Some(Duration::from_millis(1))),
            floor_millis
        );
        assert_eq!(poll_wait_millis(Some(Duration::ZERO)), floor_millis);
    }

    #[test]
    fn an_overlong_poll_interval_is_clamped_below_infinite() {
        // `Duration::MAX` in milliseconds does not fit `u32` at all; the clamp must
        // still land strictly below `INFINITE`, never at or above it, or the value
        // would be silently reinterpreted as "wait forever".
        let millis = poll_wait_millis(Some(Duration::MAX));
        assert_eq!(millis, u32::MAX - 1);
        assert!(millis < INFINITE);

        // A value that *does* fit `u32` but still lands on `INFINITE`'s own bit
        // pattern must be nudged down too.
        let millis = poll_wait_millis(Some(Duration::from_millis(u64::from(u32::MAX))));
        assert_eq!(millis, u32::MAX - 1);
        assert!(millis < INFINITE);
    }

    // [`INFINITE`] is never a legitimate answer for the debounce sub-wait: a window
    // saturating to `u32::MAX` would stop it ever closing, and the watcher would go
    // silent after its first notification.
    #[test]
    fn an_overlong_debounce_window_is_clamped_below_infinite() {
        for remaining in [
            Duration::MAX,
            Duration::from_millis(u64::from(u32::MAX)),
            Duration::from_millis(u64::from(u32::MAX) + 1),
        ] {
            let millis = debounce_wait_millis(remaining);
            assert_eq!(millis, u32::MAX - 1, "{remaining:?}");
            assert!(millis < INFINITE, "{remaining:?}");
        }
    }

    // The ordinary case is a plain conversion — the clamp must not disturb the windows
    // anyone actually configures, including the default.
    #[test]
    fn an_ordinary_debounce_window_converts_to_milliseconds() {
        assert_eq!(debounce_wait_millis(Duration::from_millis(250)), 250);
        assert_eq!(debounce_wait_millis(Duration::ZERO), 0);
        assert_eq!(
            debounce_wait_millis(crate::watch::WatchOptions::default().debounce),
            u32::try_from(crate::watch::WatchOptions::default().debounce.as_millis())
                .expect("the default debounce fits u32 milliseconds")
        );
    }

    // Watching the leaf directly would let a policy's *deletion* permanently degrade
    // the group policy route — see [`group_policy_ancestors`].
    #[test]
    fn the_leaf_key_itself_is_never_a_candidate() {
        assert!(
            !group_policy_ancestors().contains(&POLICY_INTERNET_SETTINGS),
            "the leaf key is back in the candidate list"
        );
    }

    #[test]
    fn ancestors_go_from_the_specific_leaf_to_the_broad_root() {
        let candidates = group_policy_ancestors();

        assert_eq!(
            candidates.first().copied(),
            POLICY_INTERNET_SETTINGS
                .rsplit_once('\\')
                .map(|(head, _)| head),
            "the most specific candidate is the leaf's immediate parent"
        );
        assert_eq!(candidates.last(), Some(&"Software"));
        assert!(
            candidates
                .iter()
                .all(|candidate| POLICY_INTERNET_SETTINGS.starts_with(candidate)),
            "every candidate must be an ancestor path of the leaf"
        );

        // Strictly decreasing length: every step removes exactly one path segment, so
        // "most specific first" holds for every consecutive pair, not just the ends.
        for pair in candidates.windows(2) {
            assert!(
                pair[0].len() > pair[1].len(),
                "{:?} is not more specific than {:?}",
                pair[0],
                pair[1]
            );
            assert!(
                pair[0].starts_with(pair[1]),
                "{:?} must be an ancestor path of {:?}",
                pair[1],
                pair[0]
            );
        }
    }

    #[test]
    fn push_degraded_does_not_duplicate_a_source() {
        let mut degraded = Vec::new();
        push_degraded(&mut degraded, ProxyConfigSource::Registry);
        push_degraded(&mut degraded, ProxyConfigSource::Registry);
        assert_eq!(degraded, vec![ProxyConfigSource::Registry]);

        push_degraded(&mut degraded, ProxyConfigSource::GroupPolicy);
        assert_eq!(
            degraded,
            vec![ProxyConfigSource::Registry, ProxyConfigSource::GroupPolicy]
        );
    }

    // [`rearm`] must call `shared.mark_no_live_notifications` exactly once — the
    // first time the *last* live route degrades, not on every degrade after that.
    #[test]
    fn only_the_last_alive_key_dying_reports_total_loss() {
        let mut alive = vec![true, true, true];

        assert!(!mark_degraded_and_check_all_dead(&mut alive, 0));
        assert_eq!(alive, vec![false, true, true]);

        assert!(!mark_degraded_and_check_all_dead(&mut alive, 1));
        assert_eq!(alive, vec![false, false, true]);

        // The third and last route dying is the one that flips the result to `true`.
        assert!(mark_degraded_and_check_all_dead(&mut alive, 2));
        assert_eq!(alive, vec![false, false, false]);
    }

    #[test]
    fn a_single_key_dying_is_immediately_total_loss() {
        let mut alive = vec![true];
        assert!(mark_degraded_and_check_all_dead(&mut alive, 0));
    }

    #[test]
    fn marking_an_already_dead_key_dead_again_is_a_harmless_no_op() {
        let mut alive = vec![false, true];
        assert!(!mark_degraded_and_check_all_dead(&mut alive, 0));
        assert_eq!(alive, vec![false, true]);
    }

    // [`run`] lays `handles` out as `[shutdown, poll_now, ...watched]`, and undoing that
    // offset is all [`wait`] does with an index, and this test is the only thing holding it
    // in a default `cargo test`. `i - 1` in place of `i - 2` still opens a debounce window,
    // and the re-read closing it still sees the change. What it loses is the *re-arm* — one
    // notification per registration, so
    // the key that actually signalled goes quiet after its first wake, and the change
    // after that is announced by nothing. `tests/windows_watch.rs`'s
    // `a_registry_change_is_emitted_exactly_once` is what catches that, and it rewrites the
    // real registry, so it runs only under `--include-ignored`. The last watched key is worse
    // still: `watched[handles.len() - 2]` is one past the end, and the thread panics.
    //
    // Real events rather than a hand-supplied index: the offset only means anything
    // against `WaitForMultipleObjects`' own "lowest signalled handle" answer, so a test
    // that named the index itself would be asking a reimplementation.
    #[test]
    fn a_signalled_handle_names_the_watched_key_that_owns_it() {
        use windows::Win32::System::Threading::ResetEvent;

        // Manual-reset throughout, so a wait does not consume the signal and each
        // iteration decides on its own which single handle is up.
        let events: Vec<Event> = (0..5)
            .map(|_| Event::new(true, "creating a wait-mapping test event").expect("event"))
            .collect();
        let handles: Vec<HANDLE> = events.iter().map(|event| event.raw()).collect();

        assert!(
            matches!(wait(&handles, 0), Ok(Wake::Timeout)),
            "with nothing signalled a wait must name no handle at all"
        );

        for (index, event) in events.iter().enumerate() {
            // SAFETY: `event` is a live manual-reset event owned by this frame, and the
            // only waiter is the single-threaded loop below.
            unsafe { SetEvent(event.raw()) }.expect("signalling the test event");
            match wait(&handles, 0) {
                Ok(Wake::Shutdown) => assert_eq!(index, 0, "handle 0 is the shutdown event"),
                Ok(Wake::PollNow) => assert_eq!(index, 1, "handle 1 is the poll_now event"),
                Ok(Wake::Key(key)) => assert_eq!(
                    key + 2,
                    index,
                    "handle {index} belongs to watched[{}], not watched[{key}]",
                    index - 2
                ),
                Ok(Wake::Timeout) => panic!("handle {index} is signalled, so nothing timed out"),
                Err(error) => panic!("handle {index}: {error}"),
            }
            // SAFETY: as above; clearing it puts the next iteration back to one signal.
            unsafe { ResetEvent(event.raw()) }.expect("clearing the test event");
        }
    }

    // Opening and arming is read-only registry I/O — no value is written, so unlike
    // `tests/windows_watch.rs` this needs no guard and no `#[ignore]`.
    //
    // What it holds is the short-circuit in [`Watch::armed`]: with group policy
    // watching off, [`arm_group_policy_key`] is not called, so it cannot fail, so the
    // "opting out is not degradation" comment beside it describes something unreachable
    // rather than something merely avoided. Dropping the
    // `options.watch_group_policy &&` guard leaves every test in
    // `tests/windows_watch.rs` green, including
    // `group_policy_watching_can_be_disabled` — which asks the *reader* whether it
    // consulted group policy, and the reader never does. Arming is a different question,
    // and this is the one place it is asked.
    #[test]
    fn turning_group_policy_off_arms_one_fewer_key() {
        let watched_with = Watch::armed(&WatchOptions::new()).expect("arming with group policy");
        let watched_without = Watch::armed(&WatchOptions::new().with_group_policy(false))
            .expect("arming without group policy");

        assert!(
            !watched_without
                .construction_degraded
                .contains(&ProxyConfigSource::GroupPolicy),
            "opting out is not degradation: {:?}",
            watched_without.construction_degraded
        );
        // `arm_group_policy_key` walks up to `Software`, which always exists under
        // HKLM, so the route it establishes is exactly the difference between the two.
        assert_eq!(
            watched_with.live_at_construction,
            watched_without.live_at_construction + 1,
            "group policy watching must add exactly the one route it names"
        );
    }
}
