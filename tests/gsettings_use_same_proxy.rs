//! The catch-all `use-same-proxy` asks for, read from a real store.
//!
//! `manual_mode` gives the HTTP child a [`Scheme::All`] slot when `use-same-proxy` is
//! `true`, which is glib-networking's reading of this schema and the one this crate
//! follows — see the note beside that branch in `gsettings_map` for why Chromium's
//! disagreement does not settle it. The key's schema default is `true`, so the branch it
//! selects is the ordinary GNOME case rather than an unusual one.
//!
//! ```text
//! cargo test --test gsettings_use_same_proxy
//! ```
//!
//! This file is the only thing holding `use-same-proxy` in the keys `gnome::read_settings`
//! asks for. An unread key reads back as absent, absent is not `Some(true)`, and the
//! per-scheme branch
//! runs instead: no `Scheme::All`, so `ftp` and `socks` answer Direct on a machine whose
//! administrator pointed every protocol at one proxy. `gsettings_map`'s own tests cover
//! both branches, but they build the key map by hand and so hold the choice without ever
//! holding the reading that feeds it.
//!
//! A separate binary because `GSETTINGS_BACKEND` is process-wide, and the keyfile backend
//! rather than dconf because a fixture must not write to the machine's own settings. See
//! `tests/gsettings_authentication.rs` for why the group names below are what they are.
#![cfg(all(target_os = "linux", feature = "linux-gnome"))]

mod support;

use std::fs;

use proxy_watch::{ProxyConfigSource, ProxyEndpoint, Scheme};

use support::skip_or_fail;

const SCHEMA: &str = "org.gnome.system.proxy";

// Only the `http` child is named. `use-same-proxy` is written rather than left to its
// default so that the fixture states what it is testing, and so that a distribution that
// ships a different default cannot quietly turn this into a test of the other branch.
const STORE: &str = "[system/proxy]\n\
                     mode='manual'\n\
                     use-same-proxy=true\n\
                     \n\
                     [system/proxy/http]\n\
                     host='proxy.example'\n\
                     port=3128\n";

#[test]
fn the_http_child_covers_every_protocol_when_the_store_says_it_does() {
    let root = std::env::temp_dir().join(format!("proxy-watch-same-{}", std::process::id()));
    let store = root.join("glib-2.0/settings");
    fs::create_dir_all(&store).expect("creating the fixture directory");
    fs::write(store.join("keyfile"), STORE).expect("writing the keyfile store");

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

    let config = proxy_watch::read().expect("reading the configuration");
    let gnome = config
        .source(ProxyConfigSource::GSettings)
        .unwrap_or_else(|| {
            panic!(
                "the fixture store is the GNOME source: {:?}",
                config.sources
            )
        });
    let ftp = gnome
        .endpoint_for(Scheme::Ftp)
        .map(ProxyEndpoint::authority);
    let socks = gnome
        .endpoint_for(Scheme::Socks)
        .map(ProxyEndpoint::authority);
    let _ = fs::remove_dir_all(&root);

    // Neither child is named in the store, so each of these can only be the catch-all the
    // `http` child was given — which is the whole of what the key buys.
    let expected = Some("proxy.example:3128".to_owned());
    assert_eq!(
        ftp, expected,
        "an unnamed `ftp` child falls through to the HTTP proxy"
    );
    assert_eq!(socks, expected, "and so does an unnamed `socks` child");
}
