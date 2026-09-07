//! Linux watch backend integration tests for the KDE (`kioslaverc`) backend.
//!
//! These drive the **real** backend — a real inotify watch, a real GLib main loop when
//! the `linux-gnome` feature is on — but never the real user's configuration: the whole
//! fixture lives under a private `XDG_CONFIG_HOME` in the temporary directory.
//!
//! ```text
//! cargo test -- --test-threads=1
//! ```
//!
//! That flag is worth passing — a watcher is a set of threads whose timing assertions
//! read better when nothing else is running — but it is not what keeps these tests
//! correct. [`ENV_LOCK`] is: the process environment is global, and so is the one
//! `kioslaverc` every test rewrites.
//!
//! The KDE half needs no desktop environment at all — it is a file and a file watch —
//! which is exactly why it is the part that can be tested in CI. The GNOME half needs a
//! session bus, so it is exercised separately in `gsettings_watch.rs`.
#![cfg(all(target_os = "linux", feature = "linux-kde"))]

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, Once};
use std::time::{Duration, Instant};

use proxy_watch::{
    Error, ProxyConfigSource, ProxyMode, ProxyWatcher, Scheme, WatchEvent, WatchOptions,
};

use support::{Next, expect_config, next, nothing_within};

/// A proxy address no real machine uses.
const TEST_PROXY: &str = "http://127.0.0.1:18080";

/// The variable the `ProxyType = 4` test indirects through. Deliberately *not* one of
/// the conventional names: KDE stores the variable's name, and picking an unusual one is
/// what proves the indirection is real.
const INDIRECT_VAR: &str = "PROXY_WATCH_TEST_PROXY";

/// The value that variable holds.
const INDIRECT_VALUE: &str = "http://127.0.0.1:18081";

// --------------------------------------------------------------------------------
// tests
// --------------------------------------------------------------------------------

/// The current configuration is delivered once, at subscription time.
#[test]
fn subscription_emits_the_current_configuration() {
    let (config_file, _lock) = fixture();
    write_kioslaverc(&config_file, "ProxyType=0\n");

    let mut watcher = ProxyWatcher::new().expect("watcher");
    let first = expect_config(&mut watcher, Duration::from_secs(1));

    assert_eq!(first, watcher.current());
    assert_eq!(first.effective, ProxyMode::Direct);
    assert!(
        first.source(ProxyConfigSource::Kioslaverc).is_some(),
        "kioslaverc exists, so it must appear in `sources`: {:?}",
        first.sources
    );
}

/// Rewriting `kioslaverc` reaches the stream — with no desktop environment
/// running — exactly once, and inside the crate's 1 second detection-latency SLO.
#[test]
fn a_kioslaverc_change_is_emitted_exactly_once() {
    let (config_file, _lock) = fixture();
    write_kioslaverc(&config_file, "ProxyType=0\n");

    let mut watcher = ProxyWatcher::new().expect("watcher");
    assert_eq!(
        expect_config(&mut watcher, Duration::from_secs(1)).effective,
        ProxyMode::Direct
    );

    let started = Instant::now();
    write_kioslaverc(
        &config_file,
        &format!(
            "ProxyType=1\nhttpProxy={TEST_PROXY}\nNoProxyFor=localhost,.example.test\n\
             ReversedException=false\n"
        ),
    );

    let changed = expect_config(&mut watcher, Duration::from_secs(2));
    let latency = started.elapsed();
    println!("kioslaverc detection latency (debounce included): {latency:?}");

    let endpoint = changed
        .effective
        .endpoint_for(Scheme::Http)
        .expect("a manual proxy endpoint");
    assert_eq!(endpoint.authority(), "127.0.0.1:18080");
    assert!(
        changed
            .effective
            .bypass()
            .expect("bypass rules")
            .matches_authority("host.example.test")
    );
    assert_eq!(changed, watcher.current());
    assert!(
        latency < Duration::from_secs(1),
        "detection latency SLO violated: {latency:?}"
    );

    // Exactly once: a single logical change must not produce a second snapshot, even
    // though one `fs::write` produces several inotify events.
    assert!(
        nothing_within(&mut watcher, Duration::from_millis(700)),
        "a single logical change emitted more than one snapshot"
    );
}

/// The same SLO under the condition [`WatchOptions::debounce`]'s own documentation makes
/// the promise for: a storm of changes that outlasts the window.
///
/// That documentation says the window is fixed — it "opens on the first change, and further
/// changes inside it are folded into the same emission rather than pushing it back. The
/// wait after a change is therefore bounded by this value however long the storm of changes
/// behind it lasts." This test is the only thing holding that. Reopening the deadline on
/// every wake — the sliding window that sentence exists to deny — leaves the test above
/// green as well, because a single change never reopens anything. What it costs is a
/// machine whose settings are being rewritten in a loop: the watcher reports nothing at all
/// until the rewriting stops.
///
/// That loop is the ordinary case rather than an exotic one. A KDE session writing several
/// proxy keys renames `kioslaverc` into place once per key, and the GNOME side is worse
/// still — every key of `org.gnome.system.proxy` fires its own `changed`, which is the
/// reason the coordinator debounces at all.
#[test]
fn a_storm_that_outlasts_the_window_is_still_reported_inside_it() {
    let (config_file, _lock) = fixture();
    write_kioslaverc(&config_file, "ProxyType=0\n");

    let mut watcher = ProxyWatcher::new().expect("watcher");
    assert_eq!(
        expect_config(&mut watcher, Duration::from_secs(1)).effective,
        ProxyMode::Direct
    );

    // The same new contents written over and over for well past the 200 ms window. Each
    // rename is its own inotify event and so its own wake; the configuration only changes
    // once, at the first of them.
    let storming = config_file.clone();
    let started = Instant::now();
    let storm = std::thread::spawn(move || {
        let body = format!("ProxyType=1\nhttpProxy={TEST_PROXY}\n");
        let until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < until {
            write_kioslaverc(&storming, &body);
            std::thread::sleep(Duration::from_millis(25));
        }
    });

    let arrived = next(&mut watcher, Duration::from_millis(1500));
    let latency = started.elapsed();
    // Joined before anything can panic, so a failure leaves no thread writing into the
    // fixture the rest of this binary shares.
    storm.join().expect("the storm thread");
    println!("kioslaverc detection latency under a storm: {latency:?}");

    let Next::Item(WatchEvent::Snapshot { state, .. }) = arrived else {
        panic!("the storm held the read off past the window: {arrived:?} after {latency:?}");
    };
    assert_eq!(
        state
            .config
            .effective
            .endpoint_for(Scheme::Http)
            .expect("a manual proxy endpoint")
            .authority(),
        "127.0.0.1:18080"
    );
    assert!(
        latency < Duration::from_secs(1),
        "detection latency SLO violated under a storm: {latency:?}"
    );
}

/// A write that leaves the configuration identical is swallowed.
#[test]
fn rewriting_an_identical_file_does_not_emit() {
    let (config_file, _lock) = fixture();
    let manual = format!("ProxyType=1\nhttpProxy={TEST_PROXY}\n");
    write_kioslaverc(&config_file, &manual);

    let mut watcher = ProxyWatcher::new().expect("watcher");
    assert!(
        !expect_config(&mut watcher, Duration::from_secs(1))
            .effective
            .is_direct()
    );

    // A real write — inotify does fire — that leaves the meaning byte for byte identical.
    write_kioslaverc(&config_file, &manual);
    assert!(
        nothing_within(&mut watcher, Duration::from_millis(700)),
        "an unchanged rewrite must not be emitted"
    );

    // ... and the watcher is still alive, which is what makes that assertion non-vacuous.
    write_kioslaverc(&config_file, "ProxyType=0\n");
    assert_eq!(
        expect_config(&mut watcher, Duration::from_secs(2)).effective,
        ProxyMode::Direct
    );
}

/// Deleting the watched *directory* ends the inotify registration for good, and
/// the watcher must say so instead of continuing to report itself as live.
///
/// `notify` 8.2.0 turns the `DELETE_SELF` into an `EventKind::Remove` carrying the
/// directory's own path and then drops the watch without re-arming. Nothing will ever
/// arrive again, so a `health()` that still answered `has_live_notifications = true` would
/// be exactly the "watching and not watching" lie this crate must never tell.
///
/// This is the one assertion in the suite that could not have been made against
/// `sys::linux::watcher::Watch::health` alone: `ProxyWatcher::health` folds a **frozen**
/// construction-time snapshot with `Shared`'s runtime half, and only the latter is re-read.
/// A flag consulted only by the backend's own `health()` would therefore be invisible to
/// the public API — hence the coordinator carrying the loss into `Shared::degrade`, and
/// hence this test going through `ProxyWatcher` rather than any internal type.
///
/// The fixture directory is process-wide (see [`fixture`]), so it is put back before this
/// returns — including on the failure paths, which is what the guard is for.
#[test]
fn losing_the_watched_directory_is_reported_rather_than_hidden() {
    let (config_file, _lock) = fixture();
    write_kioslaverc(&config_file, "ProxyType=0\n");

    let watcher = ProxyWatcher::new().expect("watcher");
    let before = watcher.health();
    assert!(
        before.has_live_notifications,
        "a live kioslaverc watch is the premise of this test: {before:?}"
    );
    assert!(
        !before.degraded.contains(&ProxyConfigSource::Kioslaverc),
        "nothing has gone wrong yet: {before:?}"
    );

    let directory = config_file.parent().expect("the fixture has a parent");
    let _restore = RestoreFixture(directory.to_path_buf());
    std::fs::remove_dir_all(directory).expect("removing the watched directory");

    let deadline = Instant::now() + Duration::from_secs(3);
    let after = loop {
        let health = watcher.health();
        if health.degraded.contains(&ProxyConfigSource::Kioslaverc) {
            break health;
        }
        assert!(
            Instant::now() < deadline,
            "the watch is gone but health() never said so: {health:?}"
        );
        std::thread::sleep(Duration::from_millis(25));
    };

    assert!(
        !after.is_fully_live(),
        "a route that should exist for this platform no longer does: {after:?}"
    );

    // Whether `has_live_notifications` also drops depends on whether a *second* native
    // route survives, so this half is not asserted blind. With `linux-gnome` compiled in
    // and `gsettings-desktop-schemas` installed — the case on the machine this was
    // written on — the GSettings subscription is genuinely still live, and reporting
    // `true` is right rather than a leftover lie. Asserting `false` unconditionally fails
    // on exactly that machine, which is what the `cfg` below is for.
    //
    // Without it, the two halves of the loss report are made by one coordinator pass but
    // in order — `Shared::degrade` first, `mark_no_live_notifications` second — so the
    // loop above can return in the moment between them. Wait for the second half rather
    // than reading it once.
    #[cfg(not(feature = "linux-gnome"))]
    let after = {
        let mut health = after;
        while health.has_live_notifications {
            assert!(
                Instant::now() < deadline,
                "kioslaverc was the only native route this build has, and its only watched \
                 directory is gone: {health:?}"
            );
            std::thread::sleep(Duration::from_millis(25));
            health = watcher.health();
        }
        health
    };

    if !after.has_live_notifications {
        assert!(
            after.is_frozen(),
            "no live route and no poll_interval is exactly what is_frozen reports: {after:?}"
        );
    }
}

/// Puts the process-wide fixture directory back, however the test above ends.
struct RestoreFixture(PathBuf);

impl Drop for RestoreFixture {
    fn drop(&mut self) {
        let _ = std::fs::create_dir_all(&self.0);
    }
}

/// A rename-over-the-target save — how KDE's `KConfig` actually writes — is noticed.
///
/// This is the case a naive file (rather than directory) watch would miss: the rename
/// replaces the inode the watch was attached to.
#[test]
fn a_rename_over_the_file_is_noticed() {
    let (config_file, _lock) = fixture();
    write_kioslaverc(&config_file, "ProxyType=0\n");

    let mut watcher = ProxyWatcher::new().expect("watcher");
    assert_eq!(
        expect_config(&mut watcher, Duration::from_secs(1)).effective,
        ProxyMode::Direct
    );

    let temporary = config_file.with_extension("new");
    std::fs::write(
        &temporary,
        format!("[Proxy Settings]\nProxyType=1\nhttpProxy={TEST_PROXY}\n"),
    )
    .expect("writing the temporary file");
    std::fs::rename(&temporary, &config_file).expect("renaming over kioslaverc");

    let changed = expect_config(&mut watcher, Duration::from_secs(2));
    assert_eq!(
        changed
            .effective
            .endpoint_for(Scheme::Http)
            .expect("endpoint")
            .authority(),
        "127.0.0.1:18080"
    );
}

/// `ProxyType = 4`: the file names a variable, the value comes from the environment.
#[test]
fn env_var_proxy_is_delegated_to_the_environment() {
    let (config_file, _lock) = fixture();
    write_kioslaverc(
        &config_file,
        &format!("ProxyType=4\nhttpProxy={INDIRECT_VAR}\n"),
    );

    let mut watcher = ProxyWatcher::new().expect("watcher");
    let config = expect_config(&mut watcher, Duration::from_secs(1));

    assert!(
        config.source(ProxyConfigSource::KioslavercEnv).is_some(),
        "a ProxyType=4 file contributes a KioslavercEnv source, not a Kioslaverc one: {:?}",
        config.sources
    );
    assert_eq!(
        config
            .effective
            .endpoint_for(Scheme::Http)
            .expect("endpoint")
            .authority(),
        "127.0.0.1:18081",
        "the value must come from {INDIRECT_VAR}, which only the file names"
    );
}

/// A `ProxyType = 2` file is reported as [`ProxyMode::Pac`].
#[test]
fn a_config_script_is_reported_as_pac() {
    let (config_file, _lock) = fixture();
    write_kioslaverc(
        &config_file,
        "ProxyType=2\nProxy Config Script[$e]=http://pac.example.test/proxy.pac\n",
    );

    let mut watcher = ProxyWatcher::new().expect("watcher");
    match expect_config(&mut watcher, Duration::from_secs(1)).effective {
        ProxyMode::Pac { url, .. } => assert_eq!(url.as_str(), "http://pac.example.test/proxy.pac"),
        other => panic!("expected a PAC mode, got {other:?}"),
    }
}

/// Polling is additive. It must not turn an unchanged configuration into a stream of
/// duplicate snapshots — the equality skip still applies to a polled read.
#[test]
fn polling_does_not_emit_duplicates() {
    let (config_file, _lock) = fixture();
    write_kioslaverc(&config_file, "ProxyType=0\n");

    let options = WatchOptions::new()
        .with_debounce(Duration::from_millis(20))
        .with_poll_interval(Some(Duration::from_millis(50)));
    let mut watcher = ProxyWatcher::with_options(options).expect("watcher");
    assert_eq!(
        expect_config(&mut watcher, Duration::from_secs(1)).effective,
        ProxyMode::Direct
    );

    // ~3 poll cycles in which nothing changed: 50 ms is raised to the 200 ms floor.
    assert!(
        nothing_within(&mut watcher, Duration::from_millis(700)),
        "polling an unchanged configuration must not emit"
    );

    // The polling thread is nevertheless alive and still feeding the coordinator.
    write_kioslaverc(
        &config_file,
        &format!("ProxyType=1\nhttpProxy={TEST_PROXY}\n"),
    );
    assert!(
        !expect_config(&mut watcher, Duration::from_secs(2))
            .effective
            .is_direct()
    );
}

/// [`ProxyWatcher::poll_now`] re-reads a change no notification can carry.
///
/// Every other test here rewrites `kioslaverc` inside the watched directory, so inotify
/// carries the change and a `poll_now` that did nothing whatsoever would still look like
/// it had worked. This one puts the file out of the watch's reach: `kioslaverc` is a
/// symlink into a sibling directory — how a dotfile manager usually arranges it — and the
/// write lands on the link's target. [`kde::read_store`](../src/sys/linux/kde.rs) follows
/// the link, because `std::fs::read_to_string` does, while `kde::watch` watches the
/// *directory*; nothing inside it changed, so there is no event to deliver. The second
/// `nothing_within` below is what makes that a measurement rather than an assumption, and
/// it is what leaves `poll_now` as the only thing that can produce the snapshot after it.
///
/// The symlink is removed on the way out rather than by a guard: every test here writes
/// its own `kioslaverc` through [`write_kioslaverc`] before asserting anything, and that
/// renames over whatever is at the path, symlink included — so a panic that skips the
/// cleanup cannot reach another test.
#[test]
fn poll_now_re_reads_a_change_no_watch_can_see() {
    let (config_file, _lock) = fixture();

    let out_of_tree = config_file.with_file_name("out-of-the-watch");
    std::fs::create_dir_all(&out_of_tree).expect("creating the out-of-tree directory");
    let target = out_of_tree.join("kioslaverc");
    write_kioslaverc(&target, "ProxyType=0\n");
    let _ = std::fs::remove_file(&config_file);
    std::os::unix::fs::symlink(&target, &config_file).expect("linking kioslaverc out of tree");

    // No `poll_interval`, so the re-read asked for below is the only one this watcher can
    // ever do beyond the notifications it is about to stop receiving.
    let mut watcher = ProxyWatcher::new().expect("watcher");
    assert_eq!(
        expect_config(&mut watcher, Duration::from_secs(1)).effective,
        ProxyMode::Direct,
        "the link is followed on read, so the first snapshot is the target's"
    );

    // The constructor can queue one re-read of its own — the GSettings subscription goes
    // live after the initial read, and `Watch::spawn` asks for a re-read to cover that
    // window. It has to be spent *before* the write, or it would read the new content and
    // the emission below would be its work rather than `poll_now`'s.
    assert!(
        nothing_within(&mut watcher, Duration::from_millis(600)),
        "nothing has changed yet, so the constructor's own re-read must find the same \
         configuration it started from"
    );

    write_kioslaverc(&target, &format!("ProxyType=1\nhttpProxy={TEST_PROXY}\n"));
    assert!(
        nothing_within(&mut watcher, Duration::from_millis(600)),
        "nothing inside the watched directory changed, so no notification may arrive"
    );

    watcher.poll_now();
    let changed = expect_config(&mut watcher, Duration::from_secs(2));
    assert_eq!(
        changed
            .effective
            .endpoint_for(Scheme::Http)
            .expect("endpoint")
            .authority(),
        "127.0.0.1:18080"
    );

    drop(watcher);
    let _ = std::fs::remove_file(&config_file);
    let _ = std::fs::remove_dir_all(&out_of_tree);
}

/// Inside a Flatpak that cannot reach dconf, the backend must
/// **never** answer `Direct`.
///
/// The test only runs when `/.flatpak-info` actually exists, because that is the only
/// thing the detection looks at. To exercise it deliberately — the file has to be at the
/// filesystem root, so this needs privileges:
///
/// ```text
/// sudo tee /.flatpak-info >/dev/null <<'EOF'
/// [Application]
/// name=org.example.App
///
/// [Session Bus Policy]
/// org.freedesktop.Notifications=talk
/// EOF
/// cargo test --test linux_watch -- --test-threads=1 --nocapture
/// sudo rm /.flatpak-info
/// ```
///
/// With `ca.desrt.dconf=talk` added to that section the same run must instead behave
/// exactly like the unsandboxed case.
///
/// ## This is an allow-listed skip, permanently
///
/// `support::skip_or_fail` exists precisely to stop a self-skip from going unnoticed in
/// CI, but that function is deliberately **not** used here. `/.flatpak-info` living at
/// the filesystem root is not something a process can arrange for itself — it requires
/// either running inside a real Flatpak sandbox (`bwrap`/`flatpak run` writes it as part
/// of setting the sandbox up) or root privileges to plant a fake one, and no job in this
/// repository's CI does either: the Linux CI containers are plain, unsandboxed
/// containers. Routing this test's skip through `skip_or_fail` would therefore make
/// every Linux CI run fail on a precondition CI has no way to satisfy — the opposite of
/// that function's purpose, which is to surface preconditions CI *should* be able to
/// meet but currently doesn't.
///
/// This comment is that skip's allow-list entry (see `skip_or_fail`'s doc in
/// `tests/support/mod.rs` for the two-bucket policy it is part of): the gap is
/// permanent by construction, not an oversight, and this paragraph is where that claim
/// can be checked and, if it ever stops being true, updated.
///
/// To actually run this test in CI it would need a job that builds a container image
/// with a real (or convincingly faked) Flatpak sandbox — e.g. one that installs
/// `flatpak`/`bubblewrap` and invokes the test binary via `flatpak run` (or
/// `bwrap --ro-bind / / --bind <fake-info> /.flatpak-info ...`) so that `/.flatpak-info`
/// is genuinely present at container root before `cargo test` starts, with and without
/// `ca.desrt.dconf=talk` in its `[Session Bus Policy]` section to exercise both branches
/// below. No such job exists today; the manual recipe above is the only way to exercise
/// this test, on a Linux machine where the tester can `sudo`.
#[test]
fn a_flatpak_without_dconf_access_never_reports_direct() {
    let (config_file, _lock) = fixture();
    write_kioslaverc(&config_file, "ProxyType=0\n");

    let Ok(info) = std::fs::read_to_string("/.flatpak-info") else {
        // Allow-listed, not `skip_or_fail`-gated — see the doc above.
        eprintln!("SKIPPED: not running inside a Flatpak (no /.flatpak-info)");
        return;
    };
    let has_dconf_access = flatpak_grants_dconf_talk(&info);

    match ProxyWatcher::new() {
        Ok(watcher) => {
            let config = watcher.current();
            if has_dconf_access {
                // dconf is reachable, so this is the ordinary desktop route.
                assert!(
                    config.source(ProxyConfigSource::GSettings).is_some()
                        || config.source(ProxyConfigSource::Kioslaverc).is_some(),
                    "with a dconf policy the desktop stores must be read: {:?}",
                    config.sources
                );
            } else {
                assert!(
                    config.source(ProxyConfigSource::Portal).is_some(),
                    "without a dconf policy the only admissible source is the portal, \
                     never a GSettings answer that GLib faked from the schema defaults: {:?}",
                    config.sources
                );
            }
        }
        Err(error) => {
            assert!(
                !has_dconf_access,
                "a Flatpak *with* dconf access must not fail: {error}"
            );
            assert!(
                matches!(error, proxy_watch::Error::Sandboxed { .. }),
                "the sandbox must be reported explicitly, got {error:?}"
            );
            println!("sandboxed as expected: {error}");
        }
    }
}

/// Whether `/.flatpak-info` grants dconf the way GLib does — exact `talk` under
/// `[Session Bus Policy]`.
///
/// A deliberate re-implementation of the crate-private
/// `sys::linux::sandbox::has_dconf_access`, which is what makes it an oracle rather than a
/// restatement of the answer under test. Every rule below is one that function attributes
/// to GKeyFile in its own comments, so a divergence here is a bug in *this* file: the test
/// above picks which assertion to make from this answer, and an oracle that is more
/// forgiving than the crate accuses correct code of being wrong.
///
/// Do not widen it to "any `ca.desrt.dconf` line", do not treat `;` as a comment (it opens
/// a key), do not trim a group name, do not accept a key name carrying a bracket, do not
/// return early on the first match (GKeyFile is last-wins for a duplicate key), and do not
/// soften the `return false`s into `continue`: a file GKeyFile refuses to load is a file
/// that denies access. The trimming is ASCII-only throughout, because `g_ascii_isspace` is
/// what GKeyFile asks — trimming a non-breaking space would accept a key GLib does not.
fn flatpak_grants_dconf_talk(flatpak_info: &str) -> bool {
    let mut in_section = false;
    let mut in_group = false;
    let mut granted = false;
    for line in flatpak_info.lines() {
        let line = line.trim_ascii_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let Some((name, after)) = rest.split_once(']') else {
                return false;
            };
            if !after.bytes().all(|byte| byte == b' ' || byte == b'\t')
                || name.is_empty()
                || name
                    .bytes()
                    .any(|byte| byte == b'[' || byte.is_ascii_control())
            {
                return false;
            }
            in_section = name == "Session Bus Policy";
            in_group = true;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        if !in_group {
            return false;
        }
        let key = key.trim_ascii_end();
        if key.is_empty() || key.bytes().any(|byte| byte == b'[' || byte == b']') {
            return false;
        }
        if in_section && key == "ca.desrt.dconf" {
            granted = value.trim_ascii_start() == "talk";
        }
    }
    granted
}

/// `Drop` stops every thread the backend owns.
#[test]
fn dropping_watchers_does_not_leak_threads() {
    let (config_file, _lock) = fixture();
    write_kioslaverc(&config_file, "ProxyType=0\n");

    // Warm up, so that one-off costs (loading the GIO modules, the first inotify
    // instance) are not counted.
    drop(ProxyWatcher::new().expect("watcher"));

    let started = Instant::now();
    for _ in 0..30 {
        let watcher = ProxyWatcher::with_options(
            WatchOptions::new()
                .with_debounce(Duration::from_millis(10))
                .with_poll_interval(Some(Duration::from_secs(30))),
        )
        .expect("watcher");
        // Touch it so the threads have certainly started.
        let _ = watcher.current();
        drop(watcher);
    }
    let elapsed = started.elapsed();

    // `Watch::drop` joins every thread, so one that refused to stop would hang here
    // rather than accumulate. The 30 second polling interval is the point: a polling
    // thread that waited out its interval instead of noticing the closed channel would
    // blow this budget on the very first iteration.
    assert!(
        elapsed < Duration::from_secs(10),
        "30 create/drop cycles took {elapsed:?}; a watcher thread is not stopping promptly"
    );
}

// --------------------------------------------------------------------------------
// `Watch::health` must be able to tell "no `kioslaverc` directory
// exists at all" apart from "a `kioslaverc` watch was attempted and genuinely failed" —
// see `KdeWatch`'s doc comment in `src/sys/linux/watcher.rs` for the type that now keeps
// them apart. These two tests exercise both halves end to end, through the real
// `ProxyWatcher::health()` public API rather than `KdeWatch` directly, since `KdeWatch`
// itself is a private implementation detail deliberately kept out of the public
// `WatchHealth` type.
// --------------------------------------------------------------------------------

/// A daemon started with `HOME` unset and no `/etc/xdg` entry — i.e. no candidate
/// `kioslaverc` directory exists anywhere `kde::config_search_dirs` looks — must not be
/// reported as degraded. [`proxy_watch::WatchHealth::degraded`]'s own doc is explicit that
/// "degraded" means a route that *should* exist could not be established, which excludes
/// "the source was never configured" — the same principle that keeps an absent GNOME proxy
/// schema out of `degraded` as `GnomeWatch::NoSchema` (which is the *same* fix, applied to
/// the GNOME side once it turned out that side had the identical bug: see
/// `tests/gnome_schema_absent.rs`). Before
/// this fix, `Watch::health` folded both of `kde::watch`'s `Ok(None)` outcomes — "no
/// directory at all" and "tried and failed" (fail-softened by `kde_watch_fail_soft`) —
/// into the same `self.kde.is_none()` check, so this exact scenario wrongly showed up as
/// degraded.
#[test]
fn a_missing_configuration_directory_is_not_reported_as_degraded() {
    let base = std::env::temp_dir().join(format!(
        "proxy-watch-tests-{}-no-config-dir",
        std::process::id()
    ));
    // Deliberately never created on disk: that absence is the whole point of the test.
    let missing_config_home = base.join("xdg-config-home");
    let missing_config_dirs_entry = base.join("xdg-config-dirs-entry");

    let _guard = EnvVarGuard::set(&[
        (
            "XDG_CONFIG_HOME",
            missing_config_home.to_str().expect("a UTF-8 temp path"),
        ),
        (
            // Overridden so the platform default (`/etc/xdg`, which does exist on most
            // real Linux systems) cannot accidentally supply a candidate directory this
            // test needs absent.
            "XDG_CONFIG_DIRS",
            missing_config_dirs_entry
                .to_str()
                .expect("a UTF-8 temp path"),
        ),
        // Realistic worst case: this is the platform's leading store, so if the fix ever
        // regressed and this were reported degraded, the leading-store safety valve would
        // have every reason to also fail construction outright — it does not, because
        // there is nothing here that ever counted as a failed *attempt*.
        ("XDG_CURRENT_DESKTOP", "KDE"),
    ]);

    // Allow-listed plain skip, not `skip_or_fail` — see that function's "CI-side skipping
    // is allow-list only" policy. `KdeWatch::NoDirectory` needs *no* candidate directory
    // to exist, and in a build without `linux-gnome` that leaves `desktop_config` with no
    // store at all, which is `Error::Unsupported` by design. The premise is therefore
    // unreachable in a KDE-only build permanently and by construction, not for want of
    // anything CI could install; seeding a `kioslaverc` the way `gnome_schema_absent.rs`
    // does would destroy the very "no candidate directory" condition under test. CI runs
    // this suite with `--all-features`, where the case is exercised for real.
    //
    // This was found by running the suite in the GLib-free configuration the README
    // describes (`default-features = false` plus `linux-kde`), where both this test and
    // `a_genuine_inotify_failure_is_reported_as_degraded` had been failing — a pre-existing
    // gap, unrelated to whatever change is under test today.
    #[cfg(not(feature = "linux-gnome"))]
    if matches!(ProxyWatcher::new(), Err(proxy_watch::Error::Unsupported)) {
        eprintln!(
            "SKIPPED: with no candidate directory and no `linux-gnome`, there is no store \
             at all and construction is `Unsupported` by design"
        );
        return;
    }

    let watcher = ProxyWatcher::new().expect(
        "an absent configuration directory must not fail construction, only report an \
         absent source",
    );
    let health = watcher.health();
    assert!(
        !health.degraded.contains(&ProxyConfigSource::Kioslaverc),
        "an absent kioslaverc directory is not a failed route, only an unconfigured \
         source: {:?}",
        health.degraded
    );
}

/// The other half: a **genuine** inotify establishment failure must still be reported as
/// degraded, proving the fix above narrows what counts as degraded rather than quietly
/// swallowing this case too — which would reintroduce exactly the silent degradation
/// this crate's fail-soft read policy exists to rule out.
///
/// A directory with execute-but-not-read permission forces a real `Err` out of
/// `notify::Watcher::watch` deterministically, rather than exhausting the systemwide
/// `fs.inotify.max_user_watches` limit — and does so *without* also breaking the ordinary
/// config read, which needs to keep succeeding (as "no `kioslaverc` here", `Reading::Absent`)
/// for this to isolate the inotify failure alone:
///
/// * `kde::read_kioslaverc`'s `read_to_string(dir.join("kioslaverc"))` only needs execute
///   (search) permission on `dir` to look up that one named entry — since it does not
///   exist, this resolves to a plain `NotFound`, not `PermissionDenied`, and is treated as
///   "no store here" rather than propagated as an `Error::Io` (a real but *unrelated* gap
///   this test must route around, not the one it exists to exercise).
/// * `kde::watch_targets`'s `Path::is_dir()` only needs execute permission on the *parent*
///   directory to stat `dir` itself, so it still picks `dir` as a watch target.
/// * `inotify_add_watch` (`notify`'s `watch()`), per its own man page, needs *read*
///   access to the target — which `0o100` (execute only) deliberately withholds — and is
///   refused.
///
/// `poll_interval` is set so [`Watch::armed`](../src/sys/linux/watcher.rs)'s leading-store
/// safety valve does not turn this failure into a hard construction
/// error instead — that path is real and intentional, just not what this test is about;
/// see `kde_watch_fail_soft`'s doc for the distinction.
#[test]
fn a_genuine_inotify_failure_is_reported_as_degraded() {
    let config_home = std::env::temp_dir().join(format!(
        "proxy-watch-tests-{}-denied-config-dir",
        std::process::id()
    ));
    std::fs::create_dir_all(&config_home).expect("creating the fixture directory");
    std::fs::set_permissions(&config_home, std::fs::Permissions::from_mode(0o100))
        .expect("denying read access to the fixture directory");

    if std::fs::read_dir(&config_home).is_ok() {
        // Allow-listed, not `skip_or_fail`-gated — same policy as
        // `a_flatpak_without_dconf_access_never_reports_direct` above: running with
        // enough privilege to ignore `0o100`'s missing read bit (root, some CI
        // containers) bypasses the very permission check this test relies on — the same
        // one `inotify_add_watch` itself is expected to enforce below — and there is
        // nothing this process can do about its own privilege level.
        eprintln!("SKIPPED: running with enough privilege to ignore 0o100 (root?)");
        let _ = std::fs::set_permissions(&config_home, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&config_home);
        return;
    }

    // A readable, lower-priority candidate holding a real `kioslaverc`.
    //
    // Do not point this at a path that does not exist. It reads as the safer choice, on the
    // reasoning that a working fallback candidate might mask the failure on the denied
    // directory. It does not, and it cannot: `watch_targets` returns the holder *and every
    // existing directory ahead of it*, the denied directory is ahead of this one, and
    // `kde::watch` registers them in order and fails on the first — so the `EACCES` this
    // test is about is still what comes back.
    //
    // What a nonexistent path does cost is the KDE-only build, which is then left with no
    // store at all: `read_config` answers `Error::Unsupported` and construction fails before
    // this test can assert anything. The seed is the same device `gnome_schema_absent.rs`
    // uses for the same reason, and it makes the case run in the GLib-free configuration the
    // README describes rather than only under `--all-features`.
    let fallback = std::env::temp_dir().join(format!(
        "proxy-watch-tests-{}-readable-fallback",
        std::process::id()
    ));
    std::fs::create_dir_all(&fallback).expect("creating the readable fallback directory");
    std::fs::write(
        fallback.join("kioslaverc"),
        "[$Version]\nupdate_info=kioslave.upd:kioslave\n\n[Proxy Settings][$i]\nProxyType=0\n",
    )
    .expect("seeding the fallback kioslaverc");

    let _guard = EnvVarGuard::set(&[
        (
            "XDG_CONFIG_HOME",
            config_home.to_str().expect("a UTF-8 temp path"),
        ),
        (
            // Overridden so the platform default (`/etc/xdg`) cannot take part; the
            // replacement is the seeded directory above, not a missing one.
            "XDG_CONFIG_DIRS",
            fallback.to_str().expect("a UTF-8 temp path"),
        ),
        ("XDG_CURRENT_DESKTOP", "KDE"),
    ]);

    let options = WatchOptions::new().with_poll_interval(Some(Duration::from_secs(30)));
    let watcher = ProxyWatcher::with_options(options).expect(
        "a poll_interval is set precisely so this failure degrades instead of \
         propagating — see the doc comment above",
    );
    let health = watcher.health();
    assert!(
        health.degraded.contains(&ProxyConfigSource::Kioslaverc),
        "a genuine inotify establishment failure must still be reported as degraded: {:?}",
        health.degraded
    );
    drop(watcher);

    let _ = std::fs::set_permissions(&config_home, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::remove_dir_all(&config_home);
    let _ = std::fs::remove_dir_all(&fallback);
}

/// The third case, between the two above: the *leading* candidate directory does not exist
/// but a lower one does, so a watch is established and yet the layer that would win the
/// cascade cannot be watched. `kde::watch` seeds [`LossFlags::lost`] from `watch_targets`'
/// second return for exactly this, and this test is the only thing holding the seed —
/// replacing it with a plain `false` leaves every other test in the Linux tree green.
///
/// The two tests above cannot reach it and are not near-misses for it.
/// `a_missing_configuration_directory_is_not_reported_as_degraded` deletes *every*
/// candidate, which is the `!kept.is_empty()` half of the same expression and answers
/// `Ok(None)` before any flag is built; `a_genuine_inotify_failure_is_reported_as_degraded`
/// reaches `degraded` through `KdeWatch::Degraded`, a different arm of the same clause in
/// `Watch::health`. Only a machine with both a missing leading directory and a surviving
/// lower one distinguishes the seed from `false`.
///
/// That machine is ordinary rather than contrived: a user who has never opened a KDE
/// settings dialog has no `~/.config` entry for it, and `/etc/xdg/kioslaverc` — shipped and
/// site-editable — is the layer their proxy comes from. Under the mutation `health()` calls
/// that route healthy, so a caller who trusts it skips
/// [`WatchOptions::poll_interval`](proxy_watch::WatchOptions::poll_interval) — and the
/// `~/.config/kioslaverc` KDE writes the first time the user changes anything wins the
/// cascade, is read on the next re-read, and no event ever asks for one.
#[test]
fn a_missing_leading_directory_is_reported_as_degraded() {
    let base = std::env::temp_dir().join(format!(
        "proxy-watch-tests-{}-absent-leading-dir",
        std::process::id()
    ));
    // Never created: this is the leading candidate, and its absence is the test.
    let missing_config_home = base.join("xdg-config-home");
    // The surviving lower layer, seeded so that the KDE-only build has a store to read and
    // so that the directory is watchable — `kept` must not be empty or `watch_targets`
    // withdraws the report by its own `!kept.is_empty()` clause.
    let system = base.join("xdg-config-dirs-entry");
    std::fs::create_dir_all(&system).expect("creating the system layer");
    std::fs::write(
        system.join("kioslaverc"),
        "[Proxy Settings]\nProxyType=1\nhttpProxy=system.corp:8080\n",
    )
    .expect("seeding the system kioslaverc");

    let _guard = EnvVarGuard::set(&[
        (
            "XDG_CONFIG_HOME",
            missing_config_home.to_str().expect("a UTF-8 temp path"),
        ),
        (
            "XDG_CONFIG_DIRS",
            system.to_str().expect("a UTF-8 temp path"),
        ),
        ("XDG_CURRENT_DESKTOP", "KDE"),
    ]);

    let watcher = ProxyWatcher::new().expect("a watchable lower layer exists");
    let health = watcher.health();
    assert!(
        health.degraded.contains(&ProxyConfigSource::Kioslaverc),
        "the layer that would win the cascade cannot be watched: {:?}",
        health.degraded
    );
    // Still live: the lower layer can deliver, so this is a degraded route rather than a
    // dark one — the distinction the seed rides on, and the reason it is not simply
    // `mark_no_live_notifications`.
    assert!(
        health.has_live_notifications,
        "the surviving layer still delivers"
    );
    drop(watcher);

    let _ = std::fs::remove_dir_all(&base);
}

/// A re-read that fails reaches the subscriber as [`WatchEvent::Error`].
///
/// `Shared::fail`'s own unit test proves the stream side turns an error into an event.
/// What it cannot prove is that anything ever hands it one: `watcher::publish` is the only
/// caller, and only when `read_config` fails on a watcher that is already running. So the
/// failure here is a real one — a directory where `kioslaverc` should be, which
/// `kde::read_kioslaverc` reads with `read_to_string` and cannot forgive the way it
/// forgives `NotFound` — arriving through the same inotify watch every other test uses.
///
/// It brings its own `XDG_CONFIG_HOME` rather than taking the shared [`fixture`] one,
/// because what it puts at that path is a directory, and every fixture test seeds the same
/// path with a plain file.
#[test]
fn a_failed_reread_reaches_the_stream_as_an_error() {
    let config_home = std::env::temp_dir().join(format!(
        "proxy-watch-tests-{}-unreadable-kioslaverc",
        std::process::id()
    ));
    std::fs::create_dir_all(&config_home).expect("creating the fixture directory");
    let config_file = config_home.join("kioslaverc");
    std::fs::write(&config_file, "[Proxy Settings][$i]\nProxyType=0\n")
        .expect("seeding the kioslaverc");
    // Pinned to a path that does not exist, for the reason [`fixture`] gives: otherwise a
    // host `/etc/xdg/kioslaverc` is a second candidate, and the read below would have one
    // that still succeeds.
    let absent = config_home.join("absent");

    let _guard = EnvVarGuard::set(&[
        (
            "XDG_CONFIG_HOME",
            config_home.to_str().expect("a UTF-8 temp path"),
        ),
        (
            "XDG_CONFIG_DIRS",
            absent.to_str().expect("a UTF-8 temp path"),
        ),
        // The leading store is the one whose read failure is fatal; this test controls the
        // KDE one.
        ("XDG_CURRENT_DESKTOP", "KDE"),
    ]);

    let mut watcher = ProxyWatcher::new().expect("watcher");
    assert_eq!(
        expect_config(&mut watcher, Duration::from_secs(1)).effective,
        ProxyMode::Direct
    );

    std::fs::remove_file(&config_file).expect("removing kioslaverc");
    std::fs::create_dir(&config_file).expect("putting a directory in its place");

    let event = next(&mut watcher, Duration::from_secs(3));
    let Next::Item(WatchEvent::Error { error, state, .. }) = event else {
        panic!("a leading store that can no longer be read must reach the stream: {event:?}");
    };
    assert!(
        matches!(error, Error::Io { .. }),
        "the failure that stopped the read is the one published: {error:?}"
    );
    assert_eq!(
        state.config.effective,
        ProxyMode::Direct,
        "the event carries the last configuration that did read cleanly"
    );

    drop(watcher);
    let _ = std::fs::remove_dir_all(&config_home);
}

// --------------------------------------------------------------------------------
// fixture
// --------------------------------------------------------------------------------

/// Serialises every test in this file. Two things are shared and neither is per-test: the
/// process environment, which [`fixture`] and [`EnvVarGuard`] both mutate through `unsafe`
/// `set_var`, and the one private `XDG_CONFIG_HOME` every test writes its `kioslaverc`
/// into. Cargo serialises test *binaries*, not the tests inside one, so without this lock
/// the tests here race each other over both, and a majority of the file fails.
///
/// Both [`fixture`] and [`EnvVarGuard::set`] take this, and [`Mutex`] is not reentrant, so
/// every test here uses one or the other, never both. A test that needs both has to take
/// the lock once and pass it down.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// A poisoned lock means an earlier test panicked. It held nothing but the right to write,
/// and every test seeds its own `kioslaverc` before asserting, so this one may proceed;
/// propagating the poison would turn one real failure into a cascade.
fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Temporarily overrides one or more environment variables for the duration of a single
/// serialized test, restoring each to its prior value — present or absent — on drop.
///
/// # Safety invariant this relies on
///
/// Like [`fixture`]'s own `set_var` calls, mutating the process environment is only sound
/// while no other thread can be reading it concurrently. [`ENV_LOCK`], held for this
/// guard's whole lifetime, is what establishes that, and not `--test-threads=1`: a flag
/// nobody has to pass is not an invariant. Every caller sets its overrides before
/// constructing the [`ProxyWatcher`] under test — i.e. before any backend thread that
/// reads these variables exists — and drops that watcher (and therefore every thread it
/// owns) before this guard itself is dropped and restores them, by declaring the guard
/// first: Rust drops local variables in the reverse of declaration order, so the watcher
/// (declared after) is always gone before the environment is put back.
struct EnvVarGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    /// Declared last so `Drop for EnvVarGuard` — which runs before any field is dropped —
    /// completes the restore while the lock is still held.
    _lock: MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    /// Set each `(name, value)` pair, remembering what was there before so [`Drop`] can
    /// restore it exactly — including "was absent" (`XDG_CONFIG_DIRS`, most likely, on an
    /// ordinary developer machine).
    fn set(vars: &[(&'static str, &str)]) -> Self {
        let _lock = env_lock();
        let saved = vars
            .iter()
            .map(|&(name, _)| (name, std::env::var_os(name)))
            .collect();
        for &(name, value) in vars {
            // SAFETY: see the type doc.
            unsafe {
                std::env::set_var(name, value);
            }
        }
        Self { saved, _lock }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (name, value) in self.saved.drain(..) {
            // SAFETY: see the type doc.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

/// Point `XDG_CONFIG_HOME` at a private directory and return the path of the
/// `kioslaverc` inside it, together with the [`ENV_LOCK`] guard the caller must hold for
/// the rest of the test.
///
/// The environment is process global, so the `set_var` half happens exactly once — before
/// any watcher exists and therefore before any other thread can be reading it — and every
/// later call only returns the path. The `kioslaverc` under that path is not once-only,
/// though: every test rewrites it, which is what the returned guard is for.
fn fixture() -> (PathBuf, MutexGuard<'static, ()>) {
    static SETUP: Once = Once::new();

    let lock = env_lock();
    let directory = std::env::temp_dir().join(format!("proxy-watch-tests-{}", std::process::id()));
    SETUP.call_once(|| {
        std::fs::create_dir_all(&directory).expect("creating the fixture directory");
        // SAFETY: `set_var` is unsound only when another thread is concurrently touching
        // the environment. This runs inside `Once::call_once` at the start of the first
        // test, with `ENV_LOCK` held so no other test is running at all, and before any
        // `ProxyWatcher` — and hence any backend thread that reads `XDG_CONFIG_HOME` —
        // has been created.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &directory);
            // Pinned to a path that does not exist so this fixture's directory is the
            // *only* `kioslaverc` candidate, and therefore the only directory the watch
            // registers. Left unset, the platform default `/etc/xdg` supplies a second
            // one on most real Linux systems (it does under WSL Ubuntu), which both lets
            // a host `/etc/xdg/kioslaverc` contribute to every reading here and keeps
            // `LossFlags::is_live` true after this fixture's directory is removed — see
            // `losing_the_watched_directory_is_reported_rather_than_hidden`.
            std::env::set_var("XDG_CONFIG_DIRS", directory.join("absent"));
            std::env::set_var(INDIRECT_VAR, INDIRECT_VALUE);
            // The GNOME half must not be picked as the leading store: this fixture only
            // controls the KDE one.
            std::env::set_var("XDG_CURRENT_DESKTOP", "KDE");
        }
    });
    (directory.join("kioslaverc"), lock)
}

/// Write a `kioslaverc` whose `[Proxy Settings]` section is `body`.
///
/// # Why this writes to a temporary file and renames it, rather than a plain `fs::write`
///
/// Do not reduce this to a single `std::fs::write(path, contents)`. That call is *not* atomic:
/// opening with `O_TRUNC` empties the file in one syscall and the bytes of `contents` land
/// in a second, separate one, so there is a real (if normally microscopic) window in which
/// the file exists, matches the directory watch's filter, and has no `[Proxy Settings]`
/// section at all.
///
/// `a_kioslaverc_change_is_emitted_exactly_once` lands in exactly that window under CI load:
/// the coordinator in [`watcher::coordinate`](../src/sys/linux/watcher.rs) opens a *fixed*
/// 200 ms debounce window on the first inotify event and reads whatever is on disk when
/// that window closes, not when the writer is done.
/// [`kde::watch`](../src/sys/linux/kde.rs) has no debounce of its own — it sends `()` on
/// the shared trigger for every relevant event, and that one coordinator debounces all
/// four sources (GSettings, this inotify watch, the poll timer, `poll_now`) together. A reader unlucky enough to land between the
/// truncate and the write sees an empty `[Proxy Settings]` section, which
/// [`kde::read_store`](../src/sys/linux/kde.rs) short-circuits to
/// [`Reading::Unset`](../src/sys/linux/desktop.rs) before `configured_from_kioslaverc` is
/// reached at all, rather than `Configured(Direct)` — a real difference in
/// `ProxyConfig::sources`, even
/// though both eventually resolve to the same effective mode. That difference is enough to
/// slip past the equality skip and be emitted as a spurious intermediate snapshot: one
/// with no manual proxy endpoint, which is exactly the panic this test reports. A CI runner
/// under enough scheduling pressure to stall a test thread between two syscalls for
/// upwards of 200 ms is unusual but, empirically, not impossible.
///
/// Writing to a same-directory temporary file and renaming it over `path` closes that
/// window: `rename(2)` within one filesystem is atomic, so any reader — the debounced
/// coordinator included — sees either the old, complete `kioslaverc` or the new, complete
/// one, never a half-written one. This mirrors what real `KConfig` does (see
/// `src/sys/linux/kde.rs`'s module doc), so it is not merely a workaround for the test.
///
/// The alternative — leaving the write unatomic and having the test loop past snapshots
/// that do not look like the expected one — is not open here: this test's whole
/// point is to prove a *single* logical change produces exactly one emission, and a loop
/// that swallows "doesn't match yet" snapshots would quietly swallow a real double-emission
/// bug the same way, defeating the assertion it exists to make.
///
/// ## What this narrows
///
/// Every test in this file writes `kioslaverc` through this function, and — with
/// `a_rename_over_the_file_is_noticed` already dedicated to the rename path — no test in
/// this suite rewrites `kioslaverc` in place (same inode, plain truncate-then-write) while
/// a watcher is live. That is judged acceptable rather than overlooked: `kde::watch`
/// watches the *directory* and matches
/// purely on file name (see `is_interesting` in `src/sys/linux/kde.rs`), so it does not
/// distinguish an in-place `Modify` from a `Remove`+`Create` pair produced by a rename —
/// there is no separate code path this loss leaves unexercised. What genuinely goes
/// unexercised is a *KDE-external* writer that truncates `kioslaverc` in place instead of
/// renaming over it; this crate has no such writer of its own to test.
fn write_kioslaverc(path: &PathBuf, body: &str) {
    let contents =
        format!("[$Version]\nupdate_info=kioslave.upd:kioslave\n\n[Proxy Settings][$i]\n{body}");
    // `.tmp` never matches `kioslaverc`, so the directory watch's own file-name filter
    // (`is_interesting`) drops every event this temporary file generates on its own.
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, &contents).expect("writing the temporary kioslaverc");
    std::fs::rename(&temporary, path).expect("renaming the temporary kioslaverc into place");
}
