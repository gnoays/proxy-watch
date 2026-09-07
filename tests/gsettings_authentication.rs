//! The two authentication keys, read from the one child schema that declares them.
//!
//! `org.gnome.system.proxy.http` is the only child carrying `use-authentication` and
//! `authentication-user`, so `gnome::read_settings` asks for them on that child alone and
//! `gsettings_map` turns them into the [`ProxyAuth`](proxy_watch::ProxyAuth) on the HTTP
//! endpoint — the username a caller needs before it can answer a `407`.
//!
//! ```text
//! cargo test --test gsettings_authentication
//! ```
//!
//! Asking for the pair on the `https` child instead — where the schema declares neither, so
//! `read_key`'s `has_key` guard silently drops both and the endpoint comes back with no
//! credentials at all — is a mistake this file alone would catch. `gsettings_map`'s own
//! tests build the key map by hand, so they hold the *mapping* and say nothing about the
//! reading that fills it; nothing else reads these two keys from a real store.
//!
//! A separate binary because `GSETTINGS_BACKEND` is process-wide, and the keyfile backend
//! rather than dconf because a fixture must not write to the machine's own settings. No
//! session bus is needed: the keyfile backend goes nowhere near `ca.desrt.dconf`.
#![cfg(all(target_os = "linux", feature = "linux-gnome"))]

mod support;

use std::fs;

use proxy_watch::{ProxyConfigSource, Scheme};

use support::skip_or_fail;

const SCHEMA: &str = "org.gnome.system.proxy";

// Byte for byte what `gsettings set` writes here with the same two environment variables,
// which is the only way to be sure of the group names: the keyfile backend does not spell
// them out of the schema id, and a group it does not recognise is silently no store at all
// — every key reads back at its schema default and the fixture looks like an empty machine.
// Values are in `GVariant` text form, which is what makes `true` a `b` and `'alice'` an `s`.
const STORE: &str = "[system/proxy]\n\
                     mode='manual'\n\
                     \n\
                     [system/proxy/http]\n\
                     host='proxy.example'\n\
                     port=3128\n\
                     use-authentication=true\n\
                     authentication-user='alice'\n";

#[test]
fn the_http_child_is_where_the_authentication_keys_are_read_from() {
    let root = std::env::temp_dir().join(format!("proxy-watch-auth-{}", std::process::id()));
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
    let http = gnome
        .endpoint_for(Scheme::Http)
        .expect("`mode='manual'` with a host on the `http` child is an endpoint");
    let _ = fs::remove_dir_all(&root);

    assert_eq!(http.authority(), "proxy.example:3128");
    let auth = http
        .auth
        .as_ref()
        .expect("`use-authentication` is set, so the endpoint carries the user");
    assert_eq!(auth.username(), "alice");
    // Not read at all, deliberately: see `gnome::READ_AUTHENTICATION_PASSWORD`.
    assert_eq!(auth.password(), None);
}
