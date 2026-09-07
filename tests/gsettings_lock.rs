//! An administrator lock on a key whose value never moves, built without root.
//!
//! `gnome::was_written` asks three questions, and the second one — `is_writable` — exists
//! for a single case the other two cannot see: an administrator forcing `mode='none'`, the
//! schema's own default. Nothing is written, no default moves, and only the lock carries
//! the intent. That case reads as untestable without root, because forcing a key looks
//! like it needs a `system-db:` profile under `/etc/dconf/db`. It does not. `DCONF_PROFILE`
//! names a profile file, `file-db:` reads a database anywhere on disk, and `dconf compile`
//! builds one from a directory — all as the ordinary user.
//!
//! ```text
//! cargo test --test gsettings_lock
//! ```
//!
//! No session bus: reads never go through `ca.desrt.dconf`, only writes do, and this file
//! writes nothing through GSettings. `dconf` itself is the one thing that can be missing
//! (Debian ships the compiler in `dconf-cli`, apart from the backend), so that is what the
//! skip is for.
//!
//! The lock is what makes this the *benefit* of the `is_writable` clause rather than its
//! cost. A backend read-only for some other reason makes every key unwritable, which the
//! clause also reads as configured — a case `gnome.rs` documents and accepts. Here
//! `ignore-hosts` stays writable in the same process, so what the crate answers to is one
//! locked key, not a store it cannot write at all.
#![cfg(all(target_os = "linux", feature = "linux-gnome"))]

mod support;

use std::path::Path;
use std::process::Command;

use gio::prelude::*;

use proxy_watch::{ProxyConfigSource, ProxyMode};

use support::skip_or_fail;

const SCHEMA: &str = "org.gnome.system.proxy";

/// The schema's dconf path is the GConf-era `/system/proxy/`, not `/org/gnome/…`.
const LOCKED_PATH: &str = "/system/proxy/mode";

#[test]
fn a_locked_key_at_its_default_value_is_a_configured_source() {
    let root = std::env::temp_dir().join(format!("proxy-watch-lock-{}", std::process::id()));
    let Some(profile) = compile_the_locked_profile(&root) else {
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

    if gio::SettingsSchemaSource::default()
        .and_then(|source| source.lookup(SCHEMA, true))
        .is_none()
    {
        skip_or_fail(&format!(
            "the {SCHEMA} schema is not installed. Install gsettings-desktop-schemas."
        ));
        let _ = std::fs::remove_dir_all(&root);
        return;
    }

    // The fixture's own three properties, in the order `was_written` asks them. If any of
    // these stops holding, the assertion below would be measuring something else.
    let settings = gio::Settings::new(SCHEMA);
    assert!(
        settings.user_value("mode").is_none(),
        "nothing may be written to mode, or the first question would answer"
    );
    assert_eq!(
        settings.default_value("mode"),
        Some("none".to_variant()),
        "the administrator default must equal the schema default, or the third would"
    );
    assert!(
        !settings.is_writable("mode"),
        "the {LOCKED_PATH} lock did not take, so this machine's dconf is not honouring \
         file-db: locks and there is nothing here to measure"
    );
    assert!(
        settings.is_writable("ignore-hosts"),
        "an unrelated key lost writability too, so this is a read-only store rather than \
         one locked key"
    );

    let config = proxy_watch::read().expect("reading a locked GSettings tree");
    assert_eq!(
        config.source(ProxyConfigSource::GSettings),
        Some(&ProxyMode::Direct),
        "a locked mode is a decision an administrator made, not the schema speaking: {:?}",
        config.sources
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Build `root/site` from a lock on [`LOCKED_PATH`] and return the profile naming it, or
/// `None` when this machine cannot compile one.
fn compile_the_locked_profile(root: &Path) -> Option<std::path::PathBuf> {
    let keyfiles = root.join("db.d");
    std::fs::create_dir_all(keyfiles.join("locks")).expect("creating the fixture directory");
    // An administrator default equal to the schema default. Written as well as locked so
    // that the file-db is a store with something in it, which is the shape a site profile
    // really has; the lock is what the crate answers to.
    std::fs::write(keyfiles.join("00-proxy"), "[system/proxy]\nmode='none'\n")
        .expect("writing the administrator default");
    std::fs::write(keyfiles.join("locks/proxy"), format!("{LOCKED_PATH}\n"))
        .expect("writing the lock");

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
    // `user-db:` first and unlocked, so the store as a whole stays writable.
    std::fs::write(
        &profile,
        format!("user-db:user\nfile-db:{}\n", database.display()),
    )
    .expect("writing the dconf profile");
    Some(profile)
}
