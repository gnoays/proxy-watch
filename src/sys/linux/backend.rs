//! Assemble Linux sources into one [`ProxyConfig`].
//!
//! ```text
//!            ┌─ sandbox, no dconf ─→ Portal only
//! read_config┤
//!            └─ else ─────────────→ GSettings + kioslaverc
//! ```
//!
//! Sandbox first (GSettings would silently answer `mode = 'none'`). That branch drops
//! `kioslaverc` too, though the predicate selecting it speaks only for GSettings: inside
//! the sandbox `XDG_CONFIG_HOME` points into the application's own private tree rather
//! than the host's `~/.config` (Flatpak sets it to `~/.var/app/<id>/config` and overrides
//! any host value), so reading `kioslaverc` there would answer about the sandbox instead
//! of about the machine. The portal is what still speaks for the host. Outside sandbox
//! **both** stores are read; `XDG_CURRENT_DESKTOP` orders them. A store this build left
//! out is read here too, by a stub that answers `Absent` — the pair is always consulted,
//! but a missing feature makes one of them unable to find anything, which is what
//! `desktop::note_if_the_leading_store_was_compiled_out` exists to say. Effective = leading
//! *configured* store (including Direct), else Direct. A read failure is fatal unless the
//! leading store already answered `Configured`, in which case the store that failed was
//! not going to be the effective one and its error softens to Absent.

use crate::config::{ProxyConfig, ProxyConfigSource};
use crate::error::Error;
use crate::mode::ProxyMode;
use crate::watch::WatchOptions;

use super::desktop::{self, Reading};
use super::sandbox::{self, Sandbox};

// Read every source this build and this machine can offer.
pub(crate) fn read_config(_options: &WatchOptions) -> Result<ProxyConfig, Error> {
    let sandbox = sandbox::detect();
    // Read here rather than inside `desktop_config`, so the value logged below is the same
    // one the precedence order is taken from. Both come out of the environment, which any
    // thread in the process can rewrite between two reads — and a log that names a
    // different desktop from the one that was used is worse than no log.
    let desktop = desktop::current();
    // Which of the two branches below was taken is the single hardest thing to work out
    // after the fact on this platform — the whole point of `sandbox` is that the wrong
    // route produces a *successful* wrong answer — so it is recorded on every read.
    crate::trace::debug!(
        sandbox = sandbox.name(),
        gsettings_trustworthy = sandbox.gsettings_is_trustworthy(),
        desktop = ?desktop,
        "choosing the Linux configuration route"
    );
    let config = if sandbox.gsettings_is_trustworthy() {
        desktop_config(desktop)?
    } else {
        crate::trace::info!(
            sandbox = sandbox.name(),
            "GSettings would answer from GLib's keyfile backend here, so the settings \
             are read through org.freedesktop.portal.ProxyResolver instead"
        );
        // The portal is not a store to be weighed against another one: it hands back an
        // already resolved answer, so the desktop-precedence rule does not apply to this
        // route at all.
        let mode = portal_mode(sandbox)?;
        ProxyConfig::from_source(ProxyConfigSource::Portal, mode)
    };

    crate::trace::debug!(
        config = %crate::trace::ConfigSummary(&config),
        "read the Linux proxy configuration"
    );
    Ok(config)
}

// Read both desktop stores and let [`desktop::assemble`] apply the precedence rule.
fn desktop_config(desktop: desktop::Desktop) -> Result<ProxyConfig, Error> {
    let mut fallbacks = Vec::new();
    let (gsettings, kioslaverc) =
        desktop::read_in_order(desktop, gnome_store, kde_store, &mut fallbacks)?;
    crate::trace::debug!(
        gsettings = ?gsettings,
        kioslaverc = ?kioslaverc,
        "read both Linux desktop stores"
    );

    desktop::note_if_the_leading_store_was_compiled_out(
        desktop,
        &gsettings,
        &kioslaverc,
        desktop::is_compiled_in,
        &mut fallbacks,
    );

    // `None` is the one case that is not a configuration: no store exists here at all.
    let config = desktop::assemble(desktop, &gsettings, &kioslaverc).ok_or(Error::Unsupported)?;
    Ok(config.with_fallbacks(fallbacks))
}

#[cfg(feature = "linux-gnome")]
fn gnome_store() -> Result<Reading, Error> {
    super::gnome::read_store()
}

// Without the `linux-gnome` feature there is no GSettings store at all.
#[cfg(not(feature = "linux-gnome"))]
fn gnome_store() -> Result<Reading, Error> {
    Ok(Reading::Absent)
}

#[cfg(feature = "linux-kde")]
fn kde_store() -> Result<Reading, Error> {
    super::kde::read_store()
}

// Without the `linux-kde` feature there is no `kioslaverc` store at all.
#[cfg(not(feature = "linux-kde"))]
fn kde_store() -> Result<Reading, Error> {
    Ok(Reading::Absent)
}

#[cfg(feature = "linux-gnome")]
fn portal_mode(sandbox: Sandbox) -> Result<ProxyMode, Error> {
    super::portal::read_mode(sandbox)
}

// Without the `linux-gnome` feature the portal client is not compiled in, and a
// sandbox with no dconf access has no readable source left. Reporting
// [`ProxyMode::Direct`] would be the exact silent misdetection this backend exists to
// prevent, so it is an error instead.
#[cfg(not(feature = "linux-gnome"))]
fn portal_mode(sandbox: Sandbox) -> Result<ProxyMode, Error> {
    Err(Error::Sandboxed {
        sandbox: sandbox.name().to_owned(),
        reason: "GSettings would answer from GLib's keyfile backend with the schema \
                 default mode='none', and the org.freedesktop.portal.ProxyResolver \
                 fallback needs the `linux-gnome` feature"
            .to_owned(),
    })
}

// Everything this file decides beyond which route to take — the precedence order, the
// softening rule, and which store each reading belongs to — lives in `super::desktop`,
// whose tests are compiled on every target rather than on Linux alone.
