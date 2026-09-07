//! GNOME watch backend integration tests for the schema-**absent** path.
//!
//! `tests/gsettings_watch.rs` always assumes `org.gnome.system.proxy` is installed — its
//! `gnome_available` fixture self-skips otherwise — so it never exercises what happens
//! when the schema genuinely cannot be found. This file is that missing half, and what it
//! proves is that an uninstalled `gsettings-desktop-schemas` is **not a failure of any
//! kind**: not a fatal one, not a degraded one, on either of the two axes
//! `src/sys/linux/watcher.rs`'s fail-soft judgement table keys on (leading store ×
//! `WatchOptions::poll_interval`). Three of those four combinations are exercised below,
//! not all four, and the missing one is redundant rather than overlooked: an absent
//! schema reaches `watch_fail_soft` as `Ok(None)`, and both axes are read only on that
//! function's `Err` arm, so non-leading-*and*-polling cannot answer differently from the
//! three that are covered.
//!
//! # What is no longer covered end to end
//!
//! Because an absent schema is not a failure, hiding it is no longer a way to make
//! `src/sys/linux/gnome.rs`'s `Handle::start` fail from *outside* the crate — and it was
//! the only one. So the `Degraded` and `Fatal` arms of `gnome_start_fail_soft` no longer
//! have any end-to-end coverage. They keep the unit tests that drive `watch_fail_soft`'s
//! judgement table with an injected `Result`, which is where the table's own logic has
//! always been tested; what is now untested is only the wiring from a real `Handle::start`
//! failure into it. The remaining ways to produce one (a thread that will not spawn, a
//! `GMainContext` that cannot be acquired) are not inducible from a test process.
//!
//! # How the schema is made to disappear
//!
//! No new CI job, apt package removal, or dedicated "schema absent" container is needed
//! for this. `gio::SettingsSchemaSource::default()` (called from
//! `src/sys/linux/gnome.rs`'s `installed_proxy_schema`, which both `read_settings` and
//! `Handle::start` go through) builds its search path from
//! `g_get_system_data_dirs()`, which honours `XDG_DATA_DIRS` — so overriding that
//! variable to an empty, private directory hides the schema from GLib's lookup inside
//! *this* test process alone, regardless of whether `gsettings-desktop-schemas` is
//! actually installed on the machine running the test. This was confirmed directly
//! against the crate's own `gio` binding (not just the `gsettings` CLI) before writing
//! these tests: under an `XDG_DATA_DIRS` pointed at an empty temporary directory,
//! `gio::SettingsSchemaSource::default()` itself returns `None`, which is exactly the
//! first `?` `installed_proxy_schema` turns into its own `None`. The existing
//! `test (ubuntu-latest)` CI job — which already has
//! `gsettings-desktop-schemas` installed for `tests/gsettings_watch.rs` — can therefore
//! run this file as-is; the schema-hiding happens entirely inside the test process.
//!
//! # Serialisation
//!
//! Unlike `tests/gsettings_watch.rs`, the tests in this file do not share one setup: they
//! disagree about which store `XDG_CURRENT_DESKTOP` puts in the lead, about the
//! `WatchOptions` they pass, and about whether a `kioslaverc` exists at all. So a
//! single `Once`-initialised, file-wide fixture does not fit here — each test has to set
//! up its own environment. The process environment is still global,
//! though, so [`ENV_LOCK`] serialises every test in this binary that touches it: each
//! test acquires the lock for the whole "mutate env, construct a watcher, assert, restore
//! env" critical section before touching `std::env`, and releases it (via
//! [`EnvGuard::drop`]) only after the environment has been put back. This makes the file
//! correct both under `cargo test`'s default parallel execution and under
//! `--test-threads=1` (what CI actually uses) — no test here assumes one or the other.
//!
//! No test here needs a D-Bus session bus: they never write to GSettings, only fail to
//! *find* its schema, so `tests/gsettings_watch.rs`'s `gnome_available` write-probe
//! machinery (which exists to check dconf is writable) does not apply and is not used.
//!
//! # Why a `kioslaverc` is seeded even in the GNOME-leading tests
//!
//! `ProxyWatcher::with_options` takes its *initial* snapshot (`sys::read_config`, called
//! before `Watch::spawn` ever runs) independently of the watch-establishment path this
//! file is about, and that read only succeeds when at least one store has something to
//! report — `src/sys/linux/backend.rs`'s `desktop::assemble` returns `None`, and
//! `read_config` therefore `Error::Unsupported`, when GSettings is absent *and*
//! `kioslaverc` is unset. With `XDG_DATA_DIRS` hiding the schema, GSettings is always
//! absent here, so every test seeds a `kioslaverc` explicitly set to `ProxyType=0` (a
//! real, explicit "no proxy"). An unseeded `XDG_CONFIG_HOME` makes every one of them fail
//! with `Error::Unsupported` from the initial read, before ever reaching the
//! watch-fail-soft code path they exist to exercise. This is not the same "nothing to watch" scenario
//! `src/sys/linux/kde.rs`'s `watch_targets` doc talks about — that describes what
//! establishing the `kioslaverc` *watch* does with a missing directory, a different question
//! from what the *initial read* needs to succeed at all.
//!
//! That seed is also why this file needs `linux-kde` as well as `linux-gnome`: without the
//! KDE store compiled in, `src/sys/linux/backend.rs`'s `kde_store` is the stub that answers
//! `Absent` no matter what is on disk, so the seeded `kioslaverc` cannot be read, no store
//! reports anything, and all three tests fail on the initial read with `Error::Unsupported`
//! before reaching the absent-schema path. The premise is unreachable in a GNOME-only build
//! permanently and by construction — hiding the schema *is* the file's subject, so there is
//! nothing to seed instead — which is a compile-time condition, not the runtime skip
//! `tests/linux_watch.rs` uses for its own version of this.
//!
//! The last test in the file is the one that wants that `Error::Unsupported`: it removes
//! the seed again and asserts it. That test is what holds the paragraph above: without it,
//! reading a hidden schema as `Reading::Unset` rather than `Reading::Absent` turns "no
//! store exists here" into "this machine uses no proxy" with every test still green.
#![cfg(all(target_os = "linux", feature = "linux-gnome", feature = "linux-kde"))]

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use proxy_watch::{Error, ProxyConfigSource, ProxyWatcher, WatchOptions};

/// Serialises every test in this file that mutates the process environment. See the
/// module doc's "Serialisation" section for why a single `Once` fixture (as
/// `tests/gsettings_watch.rs` uses) does not fit here.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Distinguishes the private directories two tests running back to back (under
/// `--test-threads=1`, sequentially through the same `ENV_LOCK` critical sections) create,
/// on top of [`std::process::id`] — the same uniqueness `tests/gsettings_watch.rs`'s and
/// `tests/linux_watch.rs`'s fixtures get for free from being created exactly once per
/// process.
static NEXT_ID: AtomicU32 = AtomicU32::new(0);

// --------------------------------------------------------------------------------
// tests
// --------------------------------------------------------------------------------

/// The tests that assert something did **not** happen (no failure, no degraded route) are
/// exactly the shape that passes vacuously if the fixture silently stops working — a
/// `XDG_DATA_DIRS` override that no longer hides the schema would leave all three of them
/// green while testing nothing. The first test asserts a *failure* only an absent schema
/// can produce; this check states that property explicitly rather than leaning on it.
/// It reads the crate's own effective configuration
/// rather than probing GLib a second time, so it is the same lookup the code under test
/// made: with the schema hidden, `read_store` reports `Reading::Absent` and `assemble`
/// never records GSettings as a contributing source.
fn assert_the_schema_is_really_hidden(watcher: &ProxyWatcher) {
    let config = watcher.current();
    assert!(
        config.source(ProxyConfigSource::GSettings).is_none(),
        "fixture precondition: XDG_DATA_DIRS must hide org.gnome.system.proxy from this \
         process, but GSettings still contributed to the reading, so this test would pass \
         without exercising the absent-schema path at all: {:?}",
        config.sources
    );
}

/// The shape `LEADING_STORE_HAS_NO_FALLBACK` makes fatal, and the reason this one falls
/// outside it: GSettings is the *leading* store (`XDG_CURRENT_DESKTOP=GNOME`), the schema is
/// genuinely unreachable, and no `WatchOptions::poll_interval` is set. Construction must
/// succeed, because "the leading store's watch could not be established" is not what has
/// happened — the leading store is not present on this machine at all, so nothing is
/// left unwatched. The seeded `kioslaverc` is then the store actually supplying the
/// effective value (`desktop::assemble` falls through to it), and its own watch is the
/// live one, which is what makes the absent GSettings notification cost nothing.
#[test]
fn an_absent_schema_does_not_fail_construction_even_when_gsettings_leads() {
    let _env = EnvGuard::set_up("leading-succeeds", "GNOME");

    let watcher = ProxyWatcher::with_options(WatchOptions::new()).expect(
        "an uninstalled gsettings-desktop-schemas is not a watch-establishment failure, so \
         construction must succeed even with GSettings nominally leading and no \
         poll_interval configured",
    );
    assert_the_schema_is_really_hidden(&watcher);

    let health = watcher.health();
    assert!(
        !health.degraded.contains(&ProxyConfigSource::GSettings),
        "a store that is not installed at all must not be reported as a degraded route: \
         {health:?}"
    );
    assert!(
        health.has_live_notifications,
        "the seeded kioslaverc is the store actually believed here, and its watch must be \
         the live one that makes the absent GSettings subscription harmless: {health:?}"
    );
}

/// The same absent schema with GSettings *not* leading (`XDG_CURRENT_DESKTOP=KDE`, so
/// `kioslaverc` leads and the private `XDG_CONFIG_HOME`'s seeded file — see the module doc
/// — is what supplies the effective value). Leading is one axis of the judgement that
/// decides between fatal and degraded; with an absent schema being neither, the answer must
/// not depend on it.
#[test]
fn an_absent_schema_is_not_degraded_when_gsettings_does_not_lead() {
    let _env = EnvGuard::set_up("non-leading", "KDE");

    let watcher = ProxyWatcher::with_options(WatchOptions::new())
        .expect("nothing here can fail construction: kioslaverc leads and is present");
    assert_the_schema_is_really_hidden(&watcher);

    let health = watcher.health();
    assert!(
        !health.degraded.contains(&ProxyConfigSource::GSettings),
        "the absent schema must be reported the same way whether or not GSettings leads: \
         {health:?}"
    );
}

/// The second axis: `WatchOptions::poll_interval` set, GSettings leading. Polling is what
/// turns `LEADING_STORE_HAS_NO_FALLBACK`'s fatal branch into a degraded one — a timer is
/// the other source that notices a later change, which is the same reasoning the Windows
/// backend uses — so pinning that the answer is unchanged here proves the absent schema
/// never enters that decision at all.
#[test]
fn an_absent_schema_is_not_degraded_when_polling_is_configured() {
    let _env = EnvGuard::set_up("leading-with-poll", "GNOME");

    let options = WatchOptions::new().with_poll_interval(Some(Duration::from_secs(30)));
    let watcher = ProxyWatcher::with_options(options)
        .expect("a poll_interval cannot make construction fail that already succeeds without it");
    assert_the_schema_is_really_hidden(&watcher);

    let health = watcher.health();
    assert!(
        !health.degraded.contains(&ProxyConfigSource::GSettings),
        "the absent schema must be reported the same way with and without polling: {health:?}"
    );
}

/// The premise the tests above have to defeat, asserted for its own sake: with the schema
/// hidden **and** no `kioslaverc` on any layer, this machine offers no desktop store at
/// all, and the crate must say so rather than answer `Direct`. See the module doc's "Why a
/// `kioslaverc` is seeded" section — and this test is the only thing holding that
/// `Error::Unsupported`: `read_store` reporting a hidden schema as `Reading::Unset`
/// instead of `Reading::Absent` leaves every other test green while turning "there is
/// nothing here to read" into "this machine uses no proxy". A caller acting on the second sends traffic
/// direct off a reading that measured nothing, which is exactly what
/// `src/sys/linux/backend.rs` exists to keep from happening quietly.
#[test]
fn no_store_at_all_is_an_error_rather_than_a_direct_answer() {
    let env = EnvGuard::set_up("no-store", "GNOME");
    // The seed that lets the tests above reach their subject is the one thing this test
    // must not have.
    std::fs::remove_file(env.directory.join("config").join("kioslaverc"))
        .expect("removing the seeded kioslaverc");

    let error = proxy_watch::read()
        .expect_err("a hidden schema and no kioslaverc is no store, which is no reading");
    assert!(matches!(error, Error::Unsupported), "got {error:?}");
}

// --------------------------------------------------------------------------------
// fixture
// --------------------------------------------------------------------------------

/// Holds [`ENV_LOCK`] and every private directory this test created, restoring the
/// process environment and removing the directories on `Drop` — including on panic, which
/// is exactly when the lock must still be released for the next test.
///
/// Callers must declare this guard before the [`ProxyWatcher`] under test: Rust drops
/// local variables in the reverse of declaration order, so the
/// watcher (declared after) is always gone — along with any thread it owns — before this
/// guard restores the environment.
struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    directory: PathBuf,
    saved: Vec<(&'static str, Option<OsString>)>,
}

/// The variables this file's tests mutate.
const MANAGED_VARS: [&str; 4] = [
    "XDG_CONFIG_HOME",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_DIRS",
    "XDG_CURRENT_DESKTOP",
];

impl EnvGuard {
    /// Acquire [`ENV_LOCK`], then point `XDG_CONFIG_HOME` at a private directory holding
    /// nothing but an explicit `ProxyType=0` `kioslaverc` (isolation: never the
    /// developer's real dconf database or `~/.config/kioslaverc`; see the module doc for
    /// why a real `kioslaverc` is seeded even for the GNOME-leading tests),
    /// `XDG_DATA_DIRS` at a second private, empty directory (so GLib's schema lookup finds
    /// nothing — see the module doc), and `XDG_CURRENT_DESKTOP` to `desktop`.
    ///
    /// `XDG_CONFIG_DIRS` goes to that same empty directory. Unset it defaults to
    /// `/etc/xdg`, which is a `kioslaverc` layer like any other, so a machine carrying a
    /// site-wide one would put a store back under the test that removes the seed.
    ///
    /// `label` only distinguishes this call's directories from another test's in a
    /// process running more than one of them, for easier debugging; it plays no role in
    /// the environment itself.
    fn set_up(label: &str, desktop: &str) -> Self {
        // SAFETY: `set_var`/`remove_var` are unsound only when another thread is
        // concurrently reading or writing the environment. `ENV_LOCK` is acquired first
        // and held for this whole struct's lifetime, and every other test in this binary
        // that touches these variables goes through the same lock before touching them —
        // so whether `cargo test` runs this binary's tests in parallel or serialised
        // (`--test-threads=1`, what CI uses), at most one test's environment mutation is
        // ever in flight at a time. The only reader outside this critical section would be
        // the GSettings thread `ProxyWatcher::with_options` starts internally — and in this
        // file that thread is never even spawned, because `Handle::start`'s
        // `installed_proxy_schema` pre-check runs on the calling thread and returns
        // `Ok(None)` before it. Even when it is spawned, that call blocks (via
        // `ready_rx.recv()`) until the thread has reported the result of its subscription,
        // so the variables are never touched again after the read that matters.
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "proxy-watch-gnome-schema-absent-{}-{}-{label}",
            std::process::id(),
            id
        ));
        let config_home = directory.join("config");
        let data_dirs = directory.join("empty-data-dirs");
        std::fs::create_dir_all(&config_home).expect("creating the private XDG_CONFIG_HOME");
        std::fs::create_dir_all(&data_dirs).expect("creating the empty XDG_DATA_DIRS target");
        // See the module doc's "Why a `kioslaverc` is seeded" section: without this, the
        // initial `read_config` fails with `Error::Unsupported` before either test ever
        // reaches the watch-establishment code path under test, regardless of which
        // store leads.
        std::fs::write(
            config_home.join("kioslaverc"),
            "[$Version]\nupdate_info=kioslave.upd:kioslave\n\n[Proxy Settings][$i]\nProxyType=0\n",
        )
        .expect("seeding a private kioslaverc");
        println!(
            "EnvGuard({label}): XDG_CONFIG_HOME={} XDG_DATA_DIRS={} XDG_CURRENT_DESKTOP={desktop}",
            config_home.display(),
            data_dirs.display()
        );

        let saved = MANAGED_VARS
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect();
        // SAFETY: see above.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_home);
            std::env::set_var("XDG_CONFIG_DIRS", &data_dirs);
            std::env::set_var("XDG_DATA_DIRS", &data_dirs);
            std::env::set_var("XDG_CURRENT_DESKTOP", OsStr::new(desktop));
        }

        Self {
            _lock: lock,
            directory,
            saved,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: as in `set_up` — still inside the critical section `ENV_LOCK` guards,
        // since `_lock` is only released once this whole `drop` returns.
        unsafe {
            for (name, value) in &self.saved {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
