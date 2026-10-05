//! Platform backends.
//!
//! Backend selection is a **target cfg** decision, never a Cargo feature (features are
//! additive). Every backend exposes `read_config` and `Watch` with these obligations:
//!
//! * `read_config(&WatchOptions) -> Result<ProxyConfig, Error>`: sync read;
//! * `Watch::armed(&WatchOptions) -> Result<Watch, Error>`: register notifications before
//!   the thread exists when possible. Windows registers all of it here, and so does Linux's
//!   `kioslaverc` inotify watch; what cannot be registered until `spawn` (the GSettings
//!   subscription, macOS's `SCDynamicStore` run loop) closes the window against the
//!   constructor's own read (the `read_config_in` that
//!   [`crate::watch::ProxyWatcher::with_options`] runs before `spawn`) with a
//!   forced re-read once live. That re-read belongs to the backend, not to the
//!   constructor: Linux sends one extra trigger from `spawn` when the GSettings
//!   subscription came up live, macOS publishes unconditionally on entry to its run loop;
//! * `Watch::spawn(&WatchOptions, Arc<Shared>)`: deliver; `Drop` stops every thread it
//!   started (one on Windows, macOS, Android and iOS, more on Linux).
//!   Always call [`crate::watch::Shared::close`] on exit (panic included) via
//!   [`crate::watch::ThreadGuard`]; on panic also `mark_no_live_notifications` + `fail`,
//!   in that order, so a woken consumer never reads a health that still claims a route;
//! * `Watch::health(&self) -> BackendHealth`: construction-time routes only; runtime
//!   degrade goes through `Shared::degrade` / `mark_no_live_notifications`;
//! * `Watch::poll_now(&self)`: wake into the same notify→debounce→read path.
//!
//! Linux alone reads the process environment, from an `Env` copied on a thread the caller
//! picks: its `Watch::armed` takes one as a second argument, and it has `read_config_in`,
//! which reads from one, in place of `read_config`. `read_config_in` and `armed_in` below
//! give every backend that shape, and elsewhere drop the empty copy.
//!
//! macOS is **CI-verified only** (`src/sys/mac/mod.rs`). Linux reads GNOME + KDE, in a
//! Flatpak with dconf GNOME's store alone, and in any other sandbox the portal (paths no
//! real Flatpak or Snap has run):
//! `src/sys/linux/sandbox.rs` and `src/sys/linux/portal.rs` say what that costs. Android has
//! run on an emulator and iOS on a simulator, neither on a device.

// `pub(crate)` so `crate::pac::winhttp` can reuse `win::ffi`.
#[cfg(windows)]
pub(crate) mod win;

#[cfg(target_os = "macos")]
mod mac;

// Pure Linux conversion layers also compile under `cfg(test)` on every target.
// Plain `//` (not `///`) so this does not steal `linux/mod.rs`'s `//!` scope.
// `pub(crate)` for the same reason as `proxy_dict` below: `crate::debug_masking` has to
// build one of these settings maps to check what its `Debug` prints.
#[cfg(any(target_os = "linux", test))]
pub(crate) mod linux;

// Pure macOS / iOS proxies-dict mapping; also under `cfg(test)` everywhere.
#[cfg(any(target_os = "macos", target_os = "ios", test))]
pub(crate) mod proxy_dict;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod cf_dict;

#[cfg(target_os = "ios")]
mod ios;

// Pure Android `ProxyInfo` mapping; also under `cfg(test)` everywhere.
#[cfg(any(target_os = "android", test))]
pub(crate) mod proxy_info;

#[cfg(target_os = "android")]
pub(crate) mod android;

// The re-reading thread, woken by an interval and by the callbacks each mobile backend registers.
// Also under `cfg(test)` everywhere, where its loop runs on a read the test supplies.
#[cfg(any(target_os = "android", target_os = "ios", test))]
#[cfg_attr(not(any(target_os = "android", target_os = "ios")), allow(dead_code))]
mod poll;

#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    target_os = "ios"
)))]
mod stub;

#[cfg(windows)]
pub(crate) use self::win::{Watch, read_config};

#[cfg(target_os = "macos")]
pub(crate) use self::mac::{Watch, read_config};

#[cfg(target_os = "linux")]
pub(crate) use self::linux::Watch;

#[cfg(target_os = "android")]
pub(crate) use self::android::{Watch, read_config};

#[cfg(target_os = "ios")]
pub(crate) use self::ios::{Watch, read_config};

#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    target_os = "ios"
)))]
pub(crate) use self::stub::{Watch, read_config};

#[cfg(target_os = "linux")]
pub(crate) use self::linux::Env;

// A read with the environment copied beforehand, on whatever thread the caller chose.
#[cfg(target_os = "linux")]
pub(crate) fn read_config_in(
    _options: &crate::watch::WatchOptions,
    env: &Env,
) -> Result<crate::config::ProxyConfig, crate::error::Error> {
    self::linux::read_config_in(env)
}

#[cfg(target_os = "linux")]
pub(crate) fn armed_in(
    options: &crate::watch::WatchOptions,
    env: &Env,
) -> Result<Watch, crate::error::Error> {
    Watch::armed(options, env)
}

// Only the Linux backend reads the environment; elsewhere the copy is empty.
#[cfg(not(target_os = "linux"))]
#[derive(Clone)]
pub(crate) struct Env;

#[cfg(not(target_os = "linux"))]
impl Env {
    pub(crate) fn capture() -> Self {
        Self
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn read_config_in(
    options: &crate::watch::WatchOptions,
    _env: &Env,
) -> Result<crate::config::ProxyConfig, crate::error::Error> {
    read_config(options)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn armed_in(
    options: &crate::watch::WatchOptions,
    _env: &Env,
) -> Result<Watch, crate::error::Error> {
    Watch::armed(options)
}
