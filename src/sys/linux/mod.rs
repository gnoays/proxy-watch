//! The Linux backend.
//!
//! No unified API: route selection in [`backend`]. Pure helpers:
//!
//! | Module | Role |
//! |---|---|
//! | [`desktop`] | `XDG_CURRENT_DESKTOP` → leading store |
//! | [`sandbox`] | Flatpak / Snap detection → trust GSettings? |
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
//! for watch tests; not a real Flatpak/Snap (see [`portal`] / [`sandbox`]).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub(crate) mod desktop;
pub(crate) mod gsettings_map;
pub(crate) mod kioslaverc;
pub(crate) mod sandbox;

#[cfg(target_os = "linux")]
mod backend;
#[cfg(all(target_os = "linux", feature = "linux-gnome"))]
mod gio_dl;
#[cfg(all(target_os = "linux", feature = "linux-gnome"))]
mod gnome;
#[cfg(all(target_os = "linux", feature = "linux-kde"))]
mod kde;
#[cfg(all(target_os = "linux", feature = "linux-gnome"))]
mod portal;
#[cfg(target_os = "linux")]
mod watcher;

#[cfg(target_os = "linux")]
pub(crate) use self::backend::read_config_in;
#[cfg(target_os = "linux")]
pub(crate) use self::watcher::Watch;

// The process environment, copied once.
//
// Every variable this backend reads comes from one of these, never from `std::env` on a
// watcher thread. A host that calls `setenv` while a watcher is alive (Python's
// `os.environ[k] = v`, Node's `process.env.k = v`) then races nothing this crate runs:
// glibc's `getenv` against a concurrent `setenv` is a data race. The copy is the whole
// environment, not a fixed list, because `kioslaverc` names the variables it reads.
#[derive(Clone, Default)]
pub(crate) struct Env(std::collections::HashMap<std::ffi::OsString, std::ffi::OsString>);

impl Env {
    // Copy the environment of this process. A name given twice keeps its first value, as
    // `getenv` answers; `collect()` would keep the last.
    pub(crate) fn capture() -> Self {
        let mut vars = std::collections::HashMap::new();
        for (name, value) in std::env::vars_os() {
            vars.entry(name).or_insert(value);
        }
        Self(vars)
    }

    #[cfg(test)]
    pub(crate) fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self(pairs.iter().map(|&(k, v)| (k.into(), v.into())).collect())
    }

    pub(crate) fn var_os(&self, name: &str) -> Option<std::ffi::OsString> {
        self.0.get(std::ffi::OsStr::new(name)).cloned()
    }
}
