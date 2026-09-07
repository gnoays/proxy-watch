//! The backend used on targets that have no proxy watching implementation.
//!
//! Its only job is to keep [`ProxyWatcher`](crate::ProxyWatcher) compiling — and
//! documented — on every target, while making the absence of support explicit through
//! [`Error::Unsupported`]. Not on docs.rs's account: the three targets it builds
//! (Windows, macOS, Linux) each have a real backend, so this module is never the one
//! rendered there. It exists for the targets nobody publishes docs for.
//!
//! This is everything that is neither Windows, macOS nor Linux — the BSDs, illumos,
//! WASI and friends. (Linux with **both** `linux-gnome` and `linux-kde` turned off
//! still uses the real backend, which reports [`Error::Unsupported`] from `read_config`
//! for the same reason — except inside a sandbox, where the route that would have
//! answered is the portal, so the error names it:
//! [`Error::Sandboxed`].)

use std::sync::Arc;

use crate::config::ProxyConfig;
use crate::error::Error;
use crate::watch::{BackendHealth, Shared, WatchOptions};

// Always fails with [`Error::Unsupported`].
pub(crate) fn read_config(_options: &WatchOptions) -> Result<ProxyConfig, Error> {
    Err(Error::Unsupported)
}

// A watcher that can never be constructed on this target.
#[derive(Debug)]
pub(crate) struct Watch {
    _private: (),
}

impl Watch {
    // Always fails with [`Error::Unsupported`], which is what makes
    // [`ProxyWatcher::new`](crate::ProxyWatcher::new) fail on this target.
    pub(crate) fn armed(_options: &WatchOptions) -> Result<Self, Error> {
        Err(Error::Unsupported)
    }

    // Unreachable: [`Watch::armed`] never returns a value to call this on.
    pub(crate) fn spawn(
        &mut self,
        _options: &WatchOptions,
        _shared: Arc<Shared>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    // Unreachable, like [`Watch::spawn`]: [`Watch::armed`] never returns a value to
    // call this on either. Implemented anyway so the five-item backend contract
    // in `src/sys/mod.rs` stays uniform across every target, including this one — an
    // unsupported platform is not exempt from having *a* `Watch::health`, only from
    // ever having a `Watch` value to call it on.
    pub(crate) fn health(&self) -> BackendHealth {
        BackendHealth {
            degraded: Vec::new(),
            has_live_notifications: false,
        }
    }

    // Unreachable, like [`Watch::spawn`] and [`Watch::health`]: [`Watch::armed`] never
    // returns a value to call this on either. Implemented anyway — this is the explicit
    // re-check path a caller can invoke directly.
    pub(crate) fn poll_now(&self) {}
}
