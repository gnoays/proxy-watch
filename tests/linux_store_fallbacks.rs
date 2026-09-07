//! The store that failed to read, named in the answer rather than only in a log line.
//!
//! [`ProxyConfig::fallbacks`] is the difference between "this machine is not configured
//! with that source" and "this read did not learn what that source holds", and on Linux
//! the only thing that fills it in is `backend::desktop_config`'s final
//! `.with_fallbacks(...)`. This file is the only thing holding that call. `desktop.rs`'s
//! unit tests do assert that `read_store_fail_soft` pushes the source, but they pass their
//! own `&mut Vec` in and read it back out, so they hold the push and not the hand-off;
//! between that vector and the caller's `ProxyConfig` there is nothing else.
//!
//! ```text
//! cargo test --test linux_store_fallbacks
//! ```
//!
//! What the missing hand-off costs is a silent one. `read()` still succeeds, still reports
//! the GNOME proxy, and reports `fallbacks` empty — which reads as "KDE holds nothing
//! here". A caller that trusts it cannot tell this machine from one where `kioslaverc`
//! genuinely does not exist, and the field is compared by [`PartialEq`], so a watcher
//! would also skip the snapshot where the degradation appears and the one where it clears.
//!
//! A separate binary because `GSETTINGS_BACKEND` and the XDG variables are process-wide,
//! and the keyfile backend rather than dconf because a fixture must not write to the
//! machine's own settings — the same reasoning as `tests/gsettings_use_same_proxy.rs`.
#![cfg(all(target_os = "linux", feature = "linux-gnome", feature = "linux-kde"))]

mod support;

use std::fs;

use proxy_watch::{ProxyConfigSource, ProxyEndpoint, Scheme};

use support::skip_or_fail;

const SCHEMA: &str = "org.gnome.system.proxy";

const STORE: &str = "[system/proxy]\n\
                     mode='manual'\n\
                     \n\
                     [system/proxy/http]\n\
                     host='gnome.example'\n\
                     port=3128\n";

#[test]
fn a_desktop_store_that_could_not_be_read_is_named_in_the_answer() {
    let root = std::env::temp_dir().join(format!("proxy-watch-fallbacks-{}", std::process::id()));
    let settings = root.join("glib-2.0/settings");
    fs::create_dir_all(&settings).expect("creating the fixture directory");
    fs::write(settings.join("keyfile"), STORE).expect("writing the keyfile store");
    // A *directory* where the file goes. `read_to_string` fails on it with something other
    // than `NotFound`, which is the one distinction `read_kioslaverc`'s cascade draws: a
    // missing layer is skipped, a layer that exists and cannot be read fails the read. Any
    // other way of making the file unreadable — a mode-000 file, an unsearchable parent —
    // depends on not being root, and the WSL and container environments this suite runs in
    // often are.
    fs::create_dir_all(root.join("kioslaverc")).expect("creating the unreadable layer");

    // SAFETY: this is the only test in this binary and the only write to the environment
    // in it, and it runs before any GSettings call — so no backend exists yet to read them.
    unsafe {
        std::env::set_var("GSETTINGS_BACKEND", "keyfile");
        std::env::set_var("XDG_CONFIG_HOME", &root);
        // Not the machine's `/etc/xdg`: a site `kioslaverc` there is a readable layer, and
        // the cascade would fail on this one before reaching it either way, but the
        // fixture should not depend on which layers the host happens to ship.
        std::env::set_var("XDG_CONFIG_DIRS", root.join("absent"));
        // GNOME leads, so GSettings is read first and `kioslaverc` is the trailing store —
        // the only position from which a failure is softened at all.
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

    let config = proxy_watch::read().expect("a failed trailing store must not fail the read");
    let gnome = config
        .source(ProxyConfigSource::GSettings)
        .and_then(|mode| mode.endpoint_for(Scheme::Http))
        .map(ProxyEndpoint::authority);
    let kde = config.source(ProxyConfigSource::Kioslaverc).cloned();
    let fallbacks = config.fallbacks.clone();
    let _ = fs::remove_dir_all(&root);

    // The precondition the softening rests on: the leading store answered with a
    // configuration, so leaving the trailing one out costs the caller no effective value.
    // Without this the read would have failed instead, and there would be no snapshot to
    // carry a fallback.
    assert_eq!(
        gnome,
        Some("gnome.example:3128".to_owned()),
        "the leading store is the effective one"
    );
    // And the two halves of the distinction, which only exist together: `sources` cannot
    // hold the KDE store, because nothing was read from it...
    assert!(
        kde.is_none(),
        "a store that could not be read has no mode to report: {kde:?}"
    );
    // ...so this list is the only place the caller can learn that the source was consulted
    // at all rather than simply unconfigured.
    assert_eq!(
        fallbacks,
        vec![ProxyConfigSource::Kioslaverc],
        "the store that was consulted and could not be read"
    );
}
