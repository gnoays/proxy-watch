//! The Linux backend.
//!
//! No unified API — route selection in [`backend`]. Pure helpers:
//!
//! | Module | Role |
//! |---|---|
//! | [`desktop`] | `XDG_CURRENT_DESKTOP` → leading store |
//! | [`sandbox`] | Flatpak detection → trust GSettings? |
//! | [`gsettings_map`] / [`kioslaverc`] | → [`ProxyMode`](crate::ProxyMode) |
//! | `gnome` / `portal` / `kde` | GLib / portal / inotify (feature-gated) |
//! | `backend` / `watcher` | assemble + [`Watch`] contract |
//!
//! The four pure modules are compiled on **every** target under `cfg(test)`.
//!
//! Features: `linux-gnome` / `linux-kde` (both default). Both off →
//! [`Error::Unsupported`](crate::Error::Unsupported), except inside a sandbox whose
//! GSettings cannot be trusted: the portal route that answers instead needs `linux-gnome`,
//! so that case reports [`Error::Sandboxed`](crate::Error::Sandboxed). WSL Ubuntu 22.04
//! for watch tests; not a real Flatpak/Snap — see [`portal`] / [`sandbox`].

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub(crate) mod desktop;
pub(crate) mod gsettings_map;
pub(crate) mod kioslaverc;
pub(crate) mod sandbox;

#[cfg(target_os = "linux")]
mod backend;
#[cfg(all(target_os = "linux", feature = "linux-gnome"))]
mod gnome;
#[cfg(all(target_os = "linux", feature = "linux-kde"))]
mod kde;
#[cfg(all(target_os = "linux", feature = "linux-gnome"))]
mod portal;
#[cfg(target_os = "linux")]
mod watcher;

#[cfg(target_os = "linux")]
pub(crate) use self::backend::read_config;
#[cfg(target_os = "linux")]
pub(crate) use self::watcher::Watch;
