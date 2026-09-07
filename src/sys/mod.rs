//! Platform backends.
//!
//! Backend selection is a **target cfg** decision, never a Cargo feature (features are
//! additive). Every backend exposes `read_config` and `Watch` with these obligations:
//!
//! * `read_config(&WatchOptions) -> Result<ProxyConfig, Error>` — sync read;
//! * `Watch::armed(&WatchOptions) -> Result<Watch, Error>` — register notifications before
//!   the thread exists when possible. Windows registers all of it here, and so does Linux's
//!   `kioslaverc` inotify watch; what cannot be registered until `spawn` — the GSettings
//!   subscription, macOS's `SCDynamicStore` run loop — closes the window against the
//!   constructor's own read (the `read_config` in
//!   [`crate::watch::ProxyWatcher::with_options`], which runs before `spawn`) with a
//!   forced re-read once live. That re-read belongs to the backend, not to the
//!   constructor: Linux sends one extra trigger from `spawn` when the GSettings
//!   subscription came up live, macOS publishes unconditionally on entry to its run loop;
//! * `Watch::spawn(&WatchOptions, Arc<Shared>)` — deliver; `Drop` stops every thread it
//!   started (one on Windows and macOS, more on Linux).
//!   Always call [`crate::watch::Shared::close`] on exit (panic included) via
//!   [`crate::watch::ThreadGuard`]; on panic also `mark_no_live_notifications` + `fail`,
//!   in that order, so a woken consumer never reads a health that still claims a route;
//! * `Watch::health(&self) -> BackendHealth` — construction-time routes only; runtime
//!   degrade goes through `Shared::degrade` / `mark_no_live_notifications`;
//! * `Watch::poll_now(&self)` — wake into the same notify→debounce→read path.
//!
//! macOS is **CI-verified only** (`src/sys/mac/mod.rs`). Linux reads GNOME + KDE, and in a
//! no-dconf sandbox the portal — a path no real Flatpak or Snap has run:
//! `src/sys/linux/sandbox.rs` and `src/sys/linux/portal.rs` say what that costs.

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

// Pure macOS proxies-dict mapping; also under `cfg(test)` everywhere.
#[cfg(any(target_os = "macos", test))]
pub(crate) mod proxy_dict;

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod stub;

#[cfg(windows)]
pub(crate) use self::win::{Watch, read_config};

#[cfg(target_os = "macos")]
pub(crate) use self::mac::{Watch, read_config};

#[cfg(target_os = "linux")]
pub(crate) use self::linux::{Watch, read_config};

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub(crate) use self::stub::{Watch, read_config};
