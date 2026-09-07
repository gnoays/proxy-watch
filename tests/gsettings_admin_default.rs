//! An administrator default nobody wrote and nobody locked, built without root.
//!
//! `gnome::was_written` asks three questions, and [`gsettings_lock`](../gsettings_lock.rs)
//! covers the second. This file covers the third — `g_settings_get_default_value` differing
//! from the schema's own compiled default, which is how a site-wide dconf profile speaks
//! when it neither writes into the user's layer nor locks anything.
//!
//! ```text
//! cargo test --test gsettings_admin_default
//! ```
//!
//! Nothing else asks that third question. The only administrator default any other fixture
//! carries is one *equal* to the schema default — which the question is defined not to
//! notice. What the question buys is a store that answers
//! `mode='none'` for a reason: with it, `ProxyConfigSource::GSettings` reports Direct as a
//! decision somebody made; without it the whole GNOME source reads as `Reading::Unset` and
//! falls out of the report, so a caller looking for why its traffic goes direct is told
//! GNOME said nothing at all.
//!
//! The fixture is built the way `gsettings_lock` builds its own — `DCONF_PROFILE`,
//! `file-db:` and `dconf compile`, all as the ordinary user — and it is deliberately the
//! complement of that one: nothing is locked here, so `is_writable` cannot answer, and
//! `ignore-hosts` rather than `mode` carries the administrator default, so the resulting
//! mode stays Direct and `configured_mode`'s `!mode.is_direct()` cannot answer either. Only
//! the third question is left.
//!
//! A separate binary rather than another test in `gsettings_lock`: dconf reads
//! `DCONF_PROFILE` once, when its engine is first used, so two profiles cannot coexist in
//! one process.
#![cfg(all(target_os = "linux", feature = "linux-gnome"))]

mod support;

use std::path::Path;
use std::process::Command;

use gio::prelude::*;

use proxy_watch::{ProxyConfigSource, ProxyMode};

use support::skip_or_fail;

const SCHEMA: &str = "org.gnome.system.proxy";

/// The key the administrator default is put on. Not `mode`: moving that away from `none`
/// would make the store configured through `configured_mode`'s own `!mode.is_direct()`
/// arm, and the question under test would never be reached.
const KEY: &str = "ignore-hosts";

/// The schema's dconf path is the GConf-era `/system/proxy/`, not `/org/gnome/…`.
const DCONF_PATH: &str = "system/proxy";

#[test]
fn an_administrator_default_nobody_wrote_is_a_configured_source() {
    let root = std::env::temp_dir().join(format!("proxy-watch-admin-{}", std::process::id()));
    let Some(profile) = compile_the_administrator_profile(&root) else {
        let _ = std::fs::remove_dir_all(&root);
        return;
    };

    // SAFETY: this is the only test in this binary and the only write to the environment
    // in it, and it runs before any GSettings call — dconf reads `DCONF_PROFILE` once,
    // when its engine is first used, so a later write would not be read at all.
    unsafe {
        std::env::set_var("DCONF_PROFILE", &profile);
        // A private user database, and no `kioslaverc` beside it, so nothing on this
        // machine reaches the answer.
        std::env::set_var("XDG_CONFIG_HOME", root.join("config"));
        std::env::set_var("XDG_CURRENT_DESKTOP", "GNOME");
    }

    let Some(schema) =
        gio::SettingsSchemaSource::default().and_then(|source| source.lookup(SCHEMA, true))
    else {
        skip_or_fail(&format!(
            "the {SCHEMA} schema is not installed. Install gsettings-desktop-schemas."
        ));
        let _ = std::fs::remove_dir_all(&root);
        return;
    };

    // The fixture's own four properties, in the order `was_written` asks its questions
    // plus the one `configured_mode` asks first. If any of these stops holding, the
    // assertion below would be measuring a different question.
    let settings = gio::Settings::new(SCHEMA);
    assert!(
        settings.user_value(KEY).is_none(),
        "nothing may be written to {KEY}, or the first question would answer"
    );
    assert!(
        settings.is_writable(KEY) && settings.is_writable("mode"),
        "nothing may be locked, or the second question would answer"
    );
    assert_eq!(
        settings.string("mode"),
        "none",
        "the mode must stay at the schema default, or configured_mode would not need \
         was_written at all"
    );
    let effective = settings.default_value(KEY);
    assert!(
        effective.is_some() && effective != Some(schema.key(KEY).default_value()),
        "this machine's dconf did not surface the file-db default for {KEY} (got \
         {effective:?}), so there is nothing here to measure"
    );

    let config = proxy_watch::read().expect("reading a GSettings tree with a site default");
    assert_eq!(
        config.source(ProxyConfigSource::GSettings),
        Some(&ProxyMode::Direct),
        "a site default is somebody's decision, not the schema speaking: {:?}",
        config.sources
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Build `root/site` from an administrator default on [`KEY`] and return the profile
/// naming it, or `None` when this machine cannot compile one.
fn compile_the_administrator_profile(root: &Path) -> Option<std::path::PathBuf> {
    let keyfiles = root.join("db.d");
    std::fs::create_dir_all(&keyfiles).expect("creating the fixture directory");
    // No `locks/` directory at all: the lock is the other test's subject, and its presence
    // here would let the second question answer in place of the third.
    std::fs::write(
        keyfiles.join("00-proxy"),
        format!("[{DCONF_PATH}]\n{KEY}=['corp.example']\n"),
    )
    .expect("writing the administrator default");

    let database = root.join("site");
    let output = match Command::new("dconf")
        .arg("compile")
        .args([&database, &keyfiles])
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            skip_or_fail(&format!(
                "`dconf compile` is not available ({error}). Install dconf-cli."
            ));
            return None;
        }
    };
    assert!(
        output.status.success(),
        "dconf compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let profile = root.join("profile");
    // `user-db:` first and writable, so nothing here is locked and the store as a whole
    // stays writable.
    std::fs::write(
        &profile,
        format!("user-db:user\nfile-db:{}\n", database.display()),
    )
    .expect("writing the dconf profile");
    Some(profile)
}
