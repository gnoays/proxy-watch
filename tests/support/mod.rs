//! Shared helpers for the backend integration tests.
//!
//! This directory is not itself a test target — Cargo only compiles `tests/*.rs` — so the
//! module is pulled in with `mod support;` by the tests that need it.
//!
//! Its whole job is to drive a [`ProxyWatcher`] with a bounded wait **without an async
//! runtime**: the stream must be pollable by a bare `Waker` and a condition variable.

// Each test binary uses a different subset of the helpers.
#![allow(dead_code)]

use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use proxy_watch::{ProxyConfig, ProxyWatcher, Stream, WatchEvent};

/// The outcome of polling the watcher for a bounded amount of time.
///
/// `Item` dwarfs the other two variants, because a [`WatchEvent`] carries a whole
/// configuration. Boxing it would be the usual answer, but the callers below match
/// *through* this enum into the event's own variants, and `Box` patterns are not stable —
/// so the payload stays inline. One of these exists at a time, on a test's stack.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Next {
    /// The stream yielded an item.
    Item(WatchEvent),
    /// The stream finished.
    Ended,
    /// Nothing arrived before the deadline.
    Timeout,
}

/// A [`Waker`] that unparks a condition variable, i.e. the smallest possible executor.
#[derive(Debug, Default)]
struct Signal {
    woken: Mutex<bool>,
    condvar: Condvar,
}

impl Wake for Signal {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        *self.woken.lock().unwrap() = true;
        self.condvar.notify_all();
    }
}

/// Poll `watcher` until it yields something or `timeout` elapses.
pub fn next(watcher: &mut ProxyWatcher, timeout: Duration) -> Next {
    let signal = Arc::new(Signal::default());
    let waker = Waker::from(Arc::clone(&signal));
    let mut cx = Context::from_waker(&waker);
    let deadline = Instant::now() + timeout;

    loop {
        // Clear before polling so a wake that races the poll is never lost.
        *signal.woken.lock().unwrap() = false;
        match Pin::new(&mut *watcher).poll_next(&mut cx) {
            Poll::Ready(Some(item)) => return Next::Item(item),
            Poll::Ready(None) => return Next::Ended,
            Poll::Pending => {}
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Next::Timeout;
        }
        let guard = signal.woken.lock().unwrap();
        if !*guard {
            let _unused = signal.condvar.wait_timeout(guard, remaining).unwrap();
        }
    }
}

/// [`next`], insisting on a successful snapshot.
pub fn expect_config(watcher: &mut ProxyWatcher, timeout: Duration) -> ProxyConfig {
    match next(watcher, timeout) {
        Next::Item(WatchEvent::Snapshot { state, .. }) => state.config,
        other => panic!("expected a proxy configuration, got {other:?}"),
    }
}

/// Whether nothing arrives within `timeout`.
pub fn nothing_within(watcher: &mut ProxyWatcher, timeout: Duration) -> bool {
    matches!(next(watcher, timeout), Next::Timeout)
}

/// Give the host a proxy configuration to be read, on the one platform whose CI runner
/// has none.
///
/// A test that reads the machine and then says something about the answer needs the
/// machine to have an answer. Windows runners have WPAD auto-detect on and macOS runners
/// have a network service, but a headless ubuntu one has an empty dconf, no `kioslaverc`,
/// and — in a build without `linux-gnome` — no store at all, which `read()` reports as
/// [`proxy_watch::Error::Unsupported`]. That is a precondition a test can *build*, so it
/// belongs in neither bucket of the [`skip_or_fail`] policy below: it is not a gap to be
/// declared, it is one to be closed.
///
/// A plain file in a private `XDG_CONFIG_HOME`, the way `tests/linux_watch.rs` keeps its
/// own fixture off the real user's configuration. No dbus and no dconf, so it works in a
/// bare container.
///
/// It is left in place for the run: the readers include a watcher's own thread, and there
/// is no point at which the file is safe to remove.
///
/// Call it as the *first* statement of a test. The process environment is global, so a
/// second test reading it while this writes is a data race — the [`Once`] keeps the write
/// to one, and `--test-threads=1`, which every integration binary here already requires,
/// keeps the read from overlapping it.
#[cfg(target_os = "linux")]
pub fn seed_a_configuration() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let dir = std::env::temp_dir().join(format!("proxy-watch-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a writable temporary directory");
        std::fs::write(
            dir.join("kioslaverc"),
            "[Proxy Settings]\nProxyType=1\nhttpProxy=127.0.0.1:8080\n",
        )
        .expect("a writable kioslaverc");
        // SAFETY: `Once` admits one writer, and `--test-threads=1` means no other test in
        // this binary is running to read the environment while it writes.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", &dir) };
    });
}

/// Report a missing precondition — as a skip on a developer's machine, but as a failure
/// under CI.
///
/// A skipping test still reports `ok`, and `cargo test` hides the output of tests that
/// pass, so a skip is indistinguishable from a run unless something makes noise. That is
/// tolerable where a test is *designed* not to run everywhere (a developer's machine
/// missing some real desktop environment, real hardware, or elevated privileges), and
/// unacceptable in CI, where an unnoticed self-skip means a whole code path goes
/// unexercised while the job stays green — exactly the failure mode that was caught
/// empirically: `gsettings_watch` reported `7 passed` in 0.06s on the ubuntu CI runner
/// while every one of those tests had silently skipped for want of a session bus.
///
/// ## Policy: CI-side skipping is allow-list only
///
/// Do not call this function and then decide, case by case, whether the resulting CI
/// failure is acceptable — by the time that question is being asked in a PR review, the
/// silent-skip problem this function exists to close has already reappeared. Instead:
///
/// * If a precondition can plausibly hold in CI and its absence should turn CI red until
///   fixed, guard it with `skip_or_fail`. This is the default for anything that runs
///   under `--test-threads=1` alongside the rest of an OS's integration suite.
/// * If a precondition can *never* hold in CI by construction (e.g.
///   `tests/linux_watch.rs`'s Flatpak test, which needs `/.flatpak-info` at the
///   filesystem root and therefore a container built to look like a Flatpak sandbox —
///   not something any of this repository's CI jobs set up), do not route it through
///   `skip_or_fail` at all. Leave it as a plain, explicitly commented skip instead, with
///   the comment stating why the gap is permanent and what standing up a real run would
///   require. That comment *is* the allow-list entry — searchable, reviewable, and
///   distinct from an ordinary `skip_or_fail` call, which always means "this should be
///   running here and isn't".
///
/// Every new self-skipping test should end up in exactly one of those two buckets, never
/// in a third, unexamined one.
///
/// GitHub Actions sets `CI`; so does essentially every other runner.
pub fn skip_or_fail(reason: &str) {
    assert!(
        std::env::var_os("CI").is_none(),
        "this test must not skip under CI: {reason}"
    );
    eprintln!("SKIPPED: {reason}");
}
