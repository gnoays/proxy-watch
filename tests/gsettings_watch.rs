//! GNOME watch backend integration tests.
//!
//! Unlike the `kioslaverc` tests, these need a **session bus** — dconf writes go over
//! D-Bus to `ca.desrt.dconf` — and the `org.gnome.system.proxy` schema. Neither is
//! present on a bare CI container, so every test starts with [`gnome_available`], which
//! self-skips through `support::skip_or_fail` rather than failing when the environment
//! is not there.
//!
//! These tests are expected to run in CI (the CI workflow provisions a session bus and
//! the GNOME schemas for the ubuntu job specifically so they can), so
//! `support::skip_or_fail` is exactly right here: a skip on a developer's machine that
//! never set up dconf is fine, but the same skip under `CI=1` means the fixture the CI
//! job was supposed to provide is missing, and that must turn the job red rather than
//! report `7 passed` for zero seconds of real work — which is precisely the failure this
//! function exists to catch (see its doc in `tests/support/mod.rs`, and the empirical
//! finding that motivated it: this file reporting `7 passed` in 0.06s on a CI runner
//! where every test had silently skipped for want of a session bus).
//!
//! To actually exercise them:
//!
//! ```text
//! dbus-run-session -- cargo test --test gsettings_watch -- --test-threads=1 --nocapture
//! ```
//!
//! `--test-threads=1` is not what keeps these honest, [`DCONF_LOCK`] is: every test writes
//! the same keys of the same tree, and without the lock three of the seven fail on each
//! other's writes. The flag stays in the line above because `--nocapture` is worth having
//! and one thread is what makes the printed latency readable.
//!
//! The fixture writes through the real `gsettings` command line tool — the same path a
//! user or an administration script takes — into a **private** `XDG_CONFIG_HOME`, so the
//! developer's own dconf database is never touched.
#![cfg(all(target_os = "linux", feature = "linux-gnome"))]

mod support;

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, Once, OnceLock};
use std::time::{Duration, Instant};

use proxy_watch::{ProxyConfigSource, ProxyMode, ProxyWatcher, Scheme};

use support::{expect_config, nothing_within, skip_or_fail};

/// The schema everything below writes to.
const SCHEMA: &str = "org.gnome.system.proxy";

/// A proxy address no real machine uses.
const TEST_HOST: &str = "127.0.0.1";
const TEST_PORT: &str = "18080";

/// The four children of [`SCHEMA`], each living at its own dconf path and therefore each
/// needing its own subscription.
const CHILDREN: [(&str, Scheme); 4] = [
    ("http", Scheme::Http),
    ("https", Scheme::Https),
    ("ftp", Scheme::Ftp),
    ("socks", Scheme::Socks),
];

// --------------------------------------------------------------------------------
// tests
// --------------------------------------------------------------------------------

/// A `gsettings set` reaches the stream exactly once: the watcher's basic
/// change-detection guarantee for the GNOME backend.
#[test]
fn a_gsettings_change_is_emitted_exactly_once() {
    let Some(fixture) = fixture() else {
        return;
    };
    fixture.reset();
    // Start from a store the user has already used, i.e. one that is *configured* to go
    // direct. Without this the first `gsettings set` below would flip GSettings from
    // "unconfigured" to "configured, and direct", which changes `sources` and is
    // therefore a snapshot of its own — a second logical change, not the one
    // under test.
    fixture.set(SCHEMA, "mode", "none");

    let mut watcher = ProxyWatcher::new().expect("watcher");
    let initial = expect_config(&mut watcher, Duration::from_secs(2));
    assert_eq!(initial.effective, ProxyMode::Direct);
    assert!(
        initial.source(ProxyConfigSource::GSettings).is_some(),
        "the GNOME store is configured, so it must appear in `sources`: {:?}",
        initial.sources
    );

    // The child schema first, the mode last: while `mode` is still `none` every
    // intermediate state reads back as `Direct`, so this is one *logical* change.
    let started = Instant::now();
    fixture.set(&format!("{SCHEMA}.http"), "host", TEST_HOST);
    fixture.set(&format!("{SCHEMA}.http"), "port", TEST_PORT);
    fixture.set(SCHEMA, "mode", "manual");

    let changed = expect_config(&mut watcher, Duration::from_secs(3));
    let latency = started.elapsed();
    println!("gsettings detection latency (debounce included): {latency:?}");

    let endpoint = changed
        .effective
        .endpoint_for(Scheme::Http)
        .expect("a manual proxy endpoint");
    assert_eq!(endpoint.authority(), format!("{TEST_HOST}:{TEST_PORT}"));
    assert!(
        changed.source(ProxyConfigSource::GSettings).is_some(),
        "now that it is written, GSettings must appear in `sources`: {:?}",
        changed.sources
    );
    assert_eq!(changed, watcher.current());

    assert!(
        nothing_within(&mut watcher, Duration::from_millis(700)),
        "a single logical change emitted more than one snapshot"
    );
}

/// A change to a **child** schema alone must be noticed — for every child.
///
/// This is the regression test for the trap the schema layout sets: the four children of
/// `org.gnome.system.proxy` live at their own dconf paths, so subscribing to the root
/// schema only would leave `org.gnome.system.proxy.http host` completely invisible. All
/// four are exercised because each is a separate subscription: dropping the `ftp` one
/// breaks nothing an `http`-only test can see.
#[test]
fn every_child_schema_change_is_noticed() {
    let Some(fixture) = fixture() else {
        return;
    };
    fixture.reset();
    // `use-same-proxy` defaults to `true`, which makes the `http` child the proxy for
    // every scheme. Leaving it there would let three of the four subscriptions below be
    // deleted with the loop still passing, because a change to those children would not
    // reach the effective mode at all.
    fixture.set(SCHEMA, "use-same-proxy", "false");
    for (child, _) in CHILDREN {
        fixture.set(&format!("{SCHEMA}.{child}"), "host", TEST_HOST);
        fixture.set(&format!("{SCHEMA}.{child}"), "port", TEST_PORT);
    }
    fixture.set(SCHEMA, "mode", "manual");

    let mut watcher = ProxyWatcher::new().expect("watcher");
    let initial = expect_config(&mut watcher, Duration::from_secs(2));
    for (child, scheme) in CHILDREN {
        assert_eq!(
            initial
                .effective
                .endpoint_for(scheme)
                .unwrap_or_else(|| panic!("an endpoint for {child}"))
                .authority(),
            format!("{TEST_HOST}:{TEST_PORT}"),
            "the {child} child is configured, so {scheme} must carry it: {:?}",
            initial.effective
        );
    }

    // One child at a time, and only the child: `mode` stays `manual` throughout, so each
    // iteration's snapshot can only have come from that child's own subscription.
    for (index, (child, scheme)) in CHILDREN.into_iter().enumerate() {
        let port = format!("1809{index}");
        fixture.set(&format!("{SCHEMA}.{child}"), "port", &port);

        let changed = expect_config(&mut watcher, Duration::from_secs(3));
        assert_eq!(
            changed
                .effective
                .endpoint_for(scheme)
                .unwrap_or_else(|| panic!("an endpoint for {child}"))
                .authority(),
            format!("{TEST_HOST}:{port}"),
            "a change to the {child} child must reach the stream"
        );
    }
}

/// `mode = auto` maps onto PAC and WPAD.
#[test]
fn auto_mode_is_pac_or_wpad() {
    let Some(fixture) = fixture() else {
        return;
    };
    fixture.reset();
    fixture.set(
        SCHEMA,
        "autoconfig-url",
        "http://pac.example.test/proxy.pac",
    );
    fixture.set(SCHEMA, "mode", "auto");

    let mut watcher = ProxyWatcher::new().expect("watcher");
    match expect_config(&mut watcher, Duration::from_secs(2)).effective {
        ProxyMode::Pac { url, .. } => assert_eq!(url.as_str(), "http://pac.example.test/proxy.pac"),
        other => panic!("expected a PAC mode, got {other:?}"),
    }

    // An empty `autoconfig-url` in `auto` mode is GNOME's spelling of WPAD.
    fixture.set(SCHEMA, "autoconfig-url", "");
    assert_eq!(
        expect_config(&mut watcher, Duration::from_secs(3)).effective,
        ProxyMode::WpadAutoDetect
    );
}

/// A write that does not change the effective configuration is swallowed.
#[test]
fn rewriting_an_identical_value_does_not_emit() {
    let Some(fixture) = fixture() else {
        return;
    };
    fixture.reset();
    fixture.set(&format!("{SCHEMA}.http"), "host", TEST_HOST);
    fixture.set(SCHEMA, "mode", "manual");

    let mut watcher = ProxyWatcher::new().expect("watcher");
    assert!(
        !expect_config(&mut watcher, Duration::from_secs(2))
            .effective
            .is_direct()
    );

    // A real dconf write that leaves the meaning identical.
    fixture.set(&format!("{SCHEMA}.http"), "host", TEST_HOST);
    assert!(
        nothing_within(&mut watcher, Duration::from_millis(700)),
        "an unchanged write must not be emitted"
    );

    // ... and the watcher is still alive, which is what makes that non-vacuous.
    fixture.set(SCHEMA, "mode", "none");
    assert_eq!(
        expect_config(&mut watcher, Duration::from_secs(3)).effective,
        ProxyMode::Direct
    );
}

/// The regression test for the bug this behaviour fixes: the store belonging to the
/// running desktop must win over any other configured source, not merely the first one
/// found that is not `Direct`.
///
/// A GNOME session in which the user has deliberately switched the proxy **off**, on a
/// machine that still carries a `kioslaverc` from a KDE they no longer run. The old rule
/// — "the first source that is not `Direct`" — reported the stale KDE proxy and sent the
/// traffic through it. The store the running desktop actually uses must win, `Direct` and
/// all.
#[test]
#[cfg(feature = "linux-kde")]
fn an_explicit_gnome_none_is_not_overruled_by_a_stale_kioslaverc() {
    let Some(fixture) = fixture() else {
        return;
    };
    fixture.reset();
    // `gsettings set` writes a *user value*, which is exactly what distinguishes "the
    // user chose Off" from "this machine only ever had the schema default".
    fixture.set(SCHEMA, "mode", "none");
    let _stale = StaleKioslaverc::write(&fixture.directory);

    let watcher = ProxyWatcher::new().expect("watcher");
    let config = watcher.current();

    assert_eq!(
        config.effective,
        ProxyMode::Direct,
        "a proxy switched off in the running desktop must stay off, whatever a KDE that \
         is no longer used left behind: {:?}",
        config.sources
    );
    assert_eq!(
        config.source(ProxyConfigSource::GSettings),
        Some(&ProxyMode::Direct),
        "the GNOME store is configured, so it leads `sources`: {:?}",
        config.sources
    );
    assert!(
        config.source(ProxyConfigSource::Kioslaverc).is_some(),
        "the stale store is still reported — it is simply not believed: {:?}",
        config.sources
    );
    assert_eq!(config.sources[0].0, ProxyConfigSource::GSettings);
}

/// The other half of the same rule: when GNOME was *never* configured, the fallback to
/// `kioslaverc` still happens.
#[test]
#[cfg(feature = "linux-kde")]
fn an_unconfigured_gnome_store_falls_through_to_kioslaverc() {
    let Some(fixture) = fixture() else {
        return;
    };
    // `reset-recursively` removes every user value, which is what "never configured"
    // looks like.
    fixture.reset();
    let _stale = StaleKioslaverc::write(&fixture.directory);

    let watcher = ProxyWatcher::new().expect("watcher");
    let config = watcher.current();

    assert_eq!(
        config
            .effective
            .endpoint_for(Scheme::Http)
            .expect("the kioslaverc proxy")
            .authority(),
        "127.0.0.1:18099",
        "an unconfigured GNOME store must not mask the store that *is* configured: {:?}",
        config.sources
    );
    assert!(
        config.source(ProxyConfigSource::GSettings).is_none(),
        "an unconfigured store contributes no source: {:?}",
        config.sources
    );
}

/// `Drop` stops the GLib thread. A `g_main_loop_quit` that raced the loop's start
/// would hang here rather than fail.
#[test]
fn dropping_watchers_stops_the_glib_thread() {
    let Some(fixture) = fixture() else {
        return;
    };
    fixture.reset();

    drop(ProxyWatcher::new().expect("watcher"));

    let started = Instant::now();
    for _ in 0..20 {
        let watcher = ProxyWatcher::new().expect("watcher");
        let _ = watcher.current();
        drop(watcher);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "20 create/drop cycles took {elapsed:?}; the GSettings thread is not stopping"
    );
}

// --------------------------------------------------------------------------------
// fixture
// --------------------------------------------------------------------------------

/// Serialises every test in this file. They all write the *same* keys of the *same*
/// `org.gnome.system.proxy` tree in the *same* private dconf database, and cargo
/// serialises test *binaries*, not the tests inside one — so without this lock they run
/// concurrently and read each other's writes. What that costs is not a legible harness
/// message: the failures accuse the watcher instead, with `a single logical change emitted
/// more than one snapshot`, or a `WpadAutoDetect` assertion reading back another test's
/// manual proxy. That is why `--test-threads=1` alone is not enough to rely on. Same five
/// lines of `std`, and for the same reason, as `REGISTRY_LOCK` in `tests/windows_watch.rs`.
static DCONF_LOCK: Mutex<()> = Mutex::new(());

/// A private dconf database plus the `gsettings` tool that writes into it.
struct Fixture {
    directory: PathBuf,
    /// Held for this fixture's whole lifetime; see [`DCONF_LOCK`]. Every test binds the
    /// fixture for its whole body, so the lock spans the writes *and* the stream
    /// assertions that read them back.
    _lock: MutexGuard<'static, ()>,
}

impl Fixture {
    /// `gsettings set <schema> <key> <value>`.
    fn set(&self, schema: &str, key: &str, value: &str) {
        assert!(
            self.try_set(schema, key, value),
            "gsettings set {schema} {key} {value:?}"
        );
    }

    /// [`Fixture::set`], reporting failure instead of panicking, and **verifying that
    /// the write actually landed**.
    ///
    /// `gsettings set` exits 0 even when dconf could not commit — it only prints
    /// `dconf-WARNING: failed to commit changes to dconf` on stderr — so the exit status
    /// alone is not evidence of anything. Reading the value back is.
    fn try_set(&self, schema: &str, key: &str, value: &str) -> bool {
        let set = Command::new("gsettings")
            .args(["set", schema, key, value])
            .current_dir(&self.directory)
            .output();
        match &set {
            Ok(output) if output.status.success() => {}
            other => {
                eprintln!("gsettings set {schema} {key} {value:?} did not run: {other:?}");
                return false;
            }
        }
        let Ok(read) = Command::new("gsettings")
            .args(["get", schema, key])
            .current_dir(&self.directory)
            .output()
        else {
            eprintln!("gsettings get {schema} {key} did not run");
            return false;
        };
        // `gsettings get` prints the GVariant form, so a string comes back quoted.
        let got = String::from_utf8_lossy(&read.stdout).trim().to_owned();
        let landed = got == value || got == format!("'{value}'");
        if !landed {
            eprintln!("gsettings set {schema} {key} {value:?} read back as {got:?}");
        }
        landed
    }

    /// Put the whole schema tree back to its defaults.
    fn reset(&self) {
        let status = Command::new("gsettings")
            .args(["reset-recursively", SCHEMA])
            .current_dir(&self.directory)
            .status()
            .expect("running gsettings");
        assert!(status.success(), "gsettings reset-recursively {SCHEMA}");
        // Let the resulting change notifications drain before a watcher is created, so
        // a stale one cannot be mistaken for the change under test.
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// A `kioslaverc` left behind by a KDE this machine no longer runs, removed again when
/// the test that wrote it ends — the other tests in this file rely on the fixture's
/// `XDG_CONFIG_HOME` holding no KDE store at all.
#[cfg(feature = "linux-kde")]
struct StaleKioslaverc {
    path: PathBuf,
}

#[cfg(feature = "linux-kde")]
impl StaleKioslaverc {
    /// `ProxyType = 1` plus a host: an unmistakably configured KDE proxy.
    fn write(directory: &std::path::Path) -> Self {
        let path = directory.join("kioslaverc");
        std::fs::write(
            &path,
            "[Proxy Settings]\nProxyType=1\nhttpProxy=http://127.0.0.1:18099\n",
        )
        .expect("writing the stale kioslaverc");
        Self { path }
    }
}

#[cfg(feature = "linux-kde")]
impl Drop for StaleKioslaverc {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Prepare the environment, or `None` when this machine cannot run these tests.
fn fixture() -> Option<Fixture> {
    static SETUP: Once = Once::new();
    static USABLE: OnceLock<bool> = OnceLock::new();

    // A poisoned lock means an earlier test panicked. It held nothing but the right to
    // write, and every test resets the tree before it writes, so this one may proceed;
    // propagating the poison would turn one real failure into a cascade of six.
    let _lock = DCONF_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let directory =
        std::env::temp_dir().join(format!("proxy-watch-gsettings-{}", std::process::id()));
    SETUP.call_once(|| {
        std::fs::create_dir_all(&directory).expect("creating the fixture directory");
        // SAFETY: `set_var` is unsound only when another thread is concurrently touching
        // the environment. This runs inside `Once::call_once` at the start of the first
        // test, with [`DCONF_LOCK`] held so no other test is running at all, and before any
        // `ProxyWatcher` — and hence any backend thread that reads these variables — has
        // been created.
        unsafe {
            // A private dconf database: `$XDG_CONFIG_HOME/dconf/user`.
            std::env::set_var("XDG_CONFIG_HOME", &directory);
            // GSettings must lead, and `kioslaverc` must not exist in that directory.
            std::env::set_var("XDG_CURRENT_DESKTOP", "GNOME");
        }
        publish_config_home_to_the_bus(&directory);
    });

    let fixture = Fixture { directory, _lock };
    if *USABLE.get_or_init(|| gnome_available(&fixture)) {
        Some(fixture)
    } else {
        None
    }
}

/// Tell the session bus about the private `XDG_CONFIG_HOME` before anything activates
/// `ca.desrt.dconf`.
///
/// Writes do not go to the dconf database directly — they go over D-Bus to the
/// `ca.desrt.dconf` service, which the bus **activates with the environment the bus
/// itself was started with**, not with the caller's. Setting `XDG_CONFIG_HOME` inside
/// this process therefore splits the two halves apart: the test would read the private
/// database while the service wrote the developer's real one, and every write would look
/// like it had silently vanished. `UpdateActivationEnvironment` is the documented way to
/// fix that, and it has to happen before the first write activates the service.
///
/// Failure is not fatal: the write probe in [`gnome_available`] is what actually decides
/// whether these tests can run.
fn publish_config_home_to_the_bus(directory: &std::path::Path) {
    let argument = format!("{{'XDG_CONFIG_HOME': '{}'}}", directory.display());
    let _ = Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.DBus",
            "--object-path",
            "/org/freedesktop/DBus",
            "--method",
            "org.freedesktop.DBus.UpdateActivationEnvironment",
            &argument,
        ])
        .output();
}

/// Whether the schema is installed **and** dconf can actually be written to.
///
/// The write probe is the part that matters. `DBUS_SESSION_BUS_ADDRESS` being set proves
/// nothing — WSL, for one, exports an address whose socket does not exist — and neither
/// `gsettings set` nor `g_settings_set_*` fails when the commit does not reach dconf.
/// Without a real bus these tests would then be testing that unwritable settings never
/// change, which is worse than not running them.
fn gnome_available(fixture: &Fixture) -> bool {
    if !Command::new("gsettings")
        .args(["list-keys", SCHEMA])
        .output()
        .is_ok_and(|output| output.status.success())
    {
        skip_or_fail(&format!(
            "`gsettings list-keys {SCHEMA}` failed. Install gsettings-desktop-schemas and \
             dconf-gsettings-backend."
        ));
        return false;
    }
    if !fixture.try_set(
        SCHEMA,
        "autoconfig-url",
        "http://proxy-watch.invalid/probe.pac",
    ) {
        skip_or_fail(
            "dconf is not writable (no session bus?). Run these under `dbus-run-session -- \
             cargo test --test gsettings_watch -- --test-threads=1`.",
        );
        return false;
    }
    let _ = Command::new("gsettings")
        .args(["reset", SCHEMA, "autoconfig-url"])
        .output();
    true
}
