//! A lock that moves no value must still wake the watcher.
//!
//! `gnome::subscribe` connects two signals to every schema it watches, and the second one
//! carries a case the first cannot: GLib's `g_settings_real_writable_change_event` emits
//! `writable-changed` alone and never `changed`, so an administrator locking a key whose
//! value does not move is a change to what this crate reports and no change at all to
//! `changed`.
//!
//! ```text
//! cargo test --test gsettings_writable_watch
//! ```
//!
//! This file is the only thing holding the `connect_writable_changed` half of `subscribe`.
//! `tests/gsettings_lock.rs` covers the *reading* of a lock, but it builds its fixture
//! before the watcher exists, so the subscription never has to notice one arriving.
//!
//! The lock here is not dconf's. dconf reads `DCONF_PROFILE` once, when its engine is first
//! used, so a profile cannot gain a lock mid-process. GLib's keyfile backend takes
//! writability from the filesystem instead, and from the *directory* rather than the store
//! file — `g_keyfile_settings_backend_keyfile_writable` queries `access::*` on `kfsb->dir`
//! and demands both write and execute, and the backend's own `GFileMonitor` on that
//! directory calls it again on every event (`gio/gkeyfilesettingsbackend.c`, glib 2.72).
//! So `chmod 0555` on the settings directory is a lock this test can apply while a watcher
//! is running, and what reaches the crate is the same `writable-changed` on the same
//! `GSettings` object a dconf lock would raise.
//!
//! No session bus: the keyfile backend writes nothing through `ca.desrt.dconf`. A separate
//! binary from the other GNOME suites because `GSETTINGS_BACKEND` is process-wide and they
//! need dconf.
#![cfg(all(target_os = "linux", feature = "linux-gnome"))]

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use proxy_watch::{ProxyConfigSource, ProxyMode, ProxyWatcher, WatchEvent};

use support::{Next, expect_config, next, nothing_within, skip_or_fail};

const SCHEMA: &str = "org.gnome.system.proxy";

#[test]
fn a_lock_that_moves_no_value_still_wakes_the_watcher() {
    let root = std::env::temp_dir().join(format!("proxy-watch-writable-{}", std::process::id()));
    let store = root.join("glib-2.0/settings");
    fs::create_dir_all(&store).expect("creating the fixture directory");
    // An empty store, i.e. nothing written: every key stands at the schema default, so
    // `was_written`'s first and third questions both answer no and only the second one —
    // the writability this test moves — is left to answer.
    fs::write(store.join("keyfile"), "").expect("writing the empty keyfile store");

    // SAFETY: this is the only test in this binary and the only write to the environment
    // in it, and it runs before any GSettings call — so no backend exists yet to read them.
    unsafe {
        std::env::set_var("GSETTINGS_BACKEND", "keyfile");
        std::env::set_var("XDG_CONFIG_HOME", &root);
        // No `kioslaverc` is written beside it, so GNOME is the only store here.
        std::env::set_var("XDG_CURRENT_DESKTOP", "GNOME");
    }

    if gio::SettingsSchemaSource::default()
        .and_then(|source| source.lookup(SCHEMA, true))
        .is_none()
    {
        skip_or_fail(&format!(
            "the {SCHEMA} schema is not installed. Install gsettings-desktop-schemas."
        ));
        let _ = fs::remove_dir_all(&root);
        return;
    }

    let mut watcher = ProxyWatcher::new().expect("watcher");
    let initial = expect_config(&mut watcher, Duration::from_secs(2));
    assert!(
        initial.source(ProxyConfigSource::GSettings).is_none(),
        "an untouched store contributes no source, or the change below would not be one: \
         {:?}",
        initial.sources
    );

    // Let the constructor's own trailing re-read land before anything moves. `Watch::spawn`
    // queues one wake after the subscription goes live, to cover the window between the
    // constructor's read and it; a change made before the coordinator has drained that wake
    // would be picked up by the re-read it schedules, and the subscription under test would
    // never have to fire. Without this wait the assertion below passes even with the
    // `connect_writable_changed` half of `subscribe` deleted.
    assert!(
        nothing_within(&mut watcher, Duration::from_secs(1)),
        "a store nobody has touched must not produce a second snapshot"
    );

    // The lock. No value moves — the store is still empty and still readable — so `changed`
    // has nothing to say and only `writable-changed` fires.
    fs::set_permissions(&store, fs::Permissions::from_mode(0o555))
        .expect("making the settings directory read-only");

    // Iterating this thread's main context is part of the fixture rather than a workaround
    // for the crate. `ProxyWatcher::with_options` reads before it subscribes, so the first
    // `GSettings` in the process is built here, on the test thread, and the keyfile
    // backend's `GFileMonitor` over the settings directory is attached to *this* thread's
    // default context — which a test that only blocks on the watcher never iterates.
    // Without this loop the wake never arrives. dconf has no such affinity, its
    // change source being a GDBus subscription on GLib's own worker thread, so nothing here
    // stands in for work the crate would otherwise do: the last hop, from the backend to
    // `writable-changed` on the watcher thread's own `GSettings`, is the crate's either way.
    let context = gio::glib::MainContext::default();
    let deadline = Instant::now() + Duration::from_secs(10);
    let locked = loop {
        while context.iteration(false) {}
        match next(&mut watcher, Duration::from_millis(50)) {
            Next::Item(WatchEvent::Snapshot { state, .. }) => break state.config,
            other => assert!(
                matches!(other, Next::Timeout) && Instant::now() < deadline,
                "the lock never reached the watcher: {other:?}"
            ),
        }
    };
    // Writable again first, so a failing assertion still leaves a removable directory.
    let _ = fs::set_permissions(&store, fs::Permissions::from_mode(0o755));
    assert_eq!(
        locked.source(ProxyConfigSource::GSettings),
        Some(&ProxyMode::Direct),
        "a store nobody can write is a decision somebody made, and the watcher has to \
         publish it: {:?}",
        locked.sources
    );

    drop(watcher);
    let _ = fs::remove_dir_all(&root);
}
