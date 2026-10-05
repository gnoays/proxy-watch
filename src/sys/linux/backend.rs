//! Assemble Linux sources into one [`ProxyConfig`].
//!
//! ```text
//!               ┌─ sandbox, no dconf ──────────────→ Portal only
//!               ├─ Flatpak with dconf, KDE desktop ─→ Portal only
//! read_config_in┼─ Flatpak with dconf, otherwise ──→ GSettings only
//!               └─ no sandbox ─────────────────────→ GSettings + kioslaverc
//! ```
//!
//! Sandbox first (GSettings would silently answer `mode = 'none'`). That branch drops
//! `kioslaverc` too, though the predicate selecting it speaks only for GSettings: inside
//! the sandbox `XDG_CONFIG_HOME` points into the application's own private tree rather
//! than the host's `~/.config` (Flatpak sets it to `~/.var/app/<id>/config` and overrides
//! any host value), so reading `kioslaverc` there would answer about the sandbox instead
//! of about the machine. The portal is what still speaks for the host. The same holds in a
//! Flatpak granted dconf access: GSettings reaches the host's dconf there, but `kioslaverc`
//! is still the sandbox's own, so only GSettings is read; and on a KDE desktop, whose
//! settings live in that `kioslaverc`, GSettings would answer for a store KDE does not
//! write, so that case takes the portal too ([`route`]). Outside a sandbox **both** stores
//! are read; `XDG_CURRENT_DESKTOP` orders them. A store this build left
//! out is read here too, by a stub that answers `Absent`; the pair is always consulted,
//! but a missing feature makes one of them unable to find anything, which is what
//! `desktop::note_if_the_leading_store_was_compiled_out` exists to say. Effective = leading
//! *configured* store (including Direct), else Direct. A read failure is fatal unless the
//! leading store already answered `Configured`, in which case the store that failed was
//! not going to be the effective one and its error softens to Absent.

use crate::config::{ProxyConfig, ProxyConfigSource};
use crate::error::Error;
use crate::mode::ProxyMode;

use super::Env;
use super::desktop::{self, Desktop, Reading};
use super::sandbox::{self, Sandbox};

// Where a read and a watch get the configuration from, decided once for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    // `org.freedesktop.portal.ProxyResolver`: the host's resolver, asked about probe URLs.
    Portal,
    // The desktop stores. `kioslaverc` is read only where it is the host's file.
    Stores { kioslaverc: bool },
}

pub(crate) fn route(sandbox: Sandbox, desktop: Desktop) -> Route {
    if sandbox == Sandbox::None {
        Route::Stores { kioslaverc: true }
    } else if sandbox.gsettings_is_trustworthy() && desktop != Desktop::Kde {
        Route::Stores { kioslaverc: false }
    } else {
        Route::Portal
    }
}

// Read every source this build and this machine can offer, with every environment
// variable taken from `env`: a copy the caller took on a thread of its choosing, so no
// thread reads the process environment here.
pub(crate) fn read_config_in(env: &Env) -> Result<ProxyConfig, Error> {
    let sandbox = sandbox::detect(env);
    // Read here rather than inside `desktop_config`, so the value logged below is the same
    // one the precedence order is taken from.
    let desktop = desktop::current(env);
    // Which of the two branches below was taken is the single hardest thing to work out
    // after the fact on this platform: the whole point of `sandbox` is that the wrong
    // route produces a *successful* wrong answer, so it is recorded on every read.
    crate::trace::debug!(
        sandbox = sandbox.name(),
        route = ?route(sandbox, desktop),
        desktop = ?desktop,
        "choosing the Linux configuration route"
    );
    let config = if let Route::Stores { kioslaverc } = route(sandbox, desktop) {
        desktop_config(desktop, env, kioslaverc)?
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

// Read both desktop stores and let [`desktop::assemble`] apply the precedence rule. A
// `kioslaverc` this route may not read answers `Absent`, as a store this build left out does.
fn desktop_config(
    desktop: Desktop,
    env: &Env,
    read_kioslaverc: bool,
) -> Result<ProxyConfig, Error> {
    let mut fallbacks = Vec::new();
    let kde = || {
        if read_kioslaverc {
            kde_store(env)
        } else {
            Ok(Reading::Absent)
        }
    };
    let (gsettings, kioslaverc) =
        desktop::read_in_order(desktop, gnome_store, kde, &mut fallbacks)?;
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
fn kde_store(env: &Env) -> Result<Reading, Error> {
    super::kde::read_store(env)
}

// Without the `linux-kde` feature there is no `kioslaverc` store at all.
#[cfg(not(feature = "linux-kde"))]
fn kde_store(_env: &Env) -> Result<Reading, Error> {
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

// Everything this file decides beyond which route to take (the precedence order, the
// softening rule, and which store each reading belongs to) lives in `super::desktop`,
// whose tests are compiled on every target rather than on Linux alone.

#[cfg(test)]
mod tests {
    use super::*;

    // `kioslaverc` is read only outside a sandbox, where it is the host's own file. A
    // Flatpak with dconf access reads GSettings alone, unless the desktop is KDE, whose
    // settings live in the file the sandbox cannot see: that one asks the portal.
    #[test]
    fn the_route_reads_kioslaverc_only_where_it_is_the_hosts() {
        let dconf = Sandbox::Flatpak { dconf_access: true };
        let no_dconf = Sandbox::Flatpak {
            dconf_access: false,
        };
        for (sandbox, desktop, expected) in [
            (
                Sandbox::None,
                Desktop::Kde,
                Route::Stores { kioslaverc: true },
            ),
            (
                Sandbox::None,
                Desktop::Gnome,
                Route::Stores { kioslaverc: true },
            ),
            (
                Sandbox::None,
                Desktop::Unknown,
                Route::Stores { kioslaverc: true },
            ),
            (dconf, Desktop::Gnome, Route::Stores { kioslaverc: false }),
            (dconf, Desktop::Unknown, Route::Stores { kioslaverc: false }),
            (dconf, Desktop::Kde, Route::Portal),
            (no_dconf, Desktop::Gnome, Route::Portal),
            (Sandbox::Snap, Desktop::Gnome, Route::Portal),
            (Sandbox::Snap, Desktop::Kde, Route::Portal),
        ] {
            assert_eq!(route(sandbox, desktop), expected, "{sandbox:?} {desktop:?}");
        }
    }
}
