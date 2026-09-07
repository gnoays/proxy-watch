//! Detect — and on Windows, macOS and Linux *watch* — the operating system's proxy
//! settings.
//!
//! [`read`] answers once, starting no watcher and arming no notification route:
//!
//! ```no_run
//! use proxy_watch::{Scheme, read};
//!
//! let config = read()?;
//! match config.effective.endpoint_for(Scheme::Https) {
//!     Some(endpoint) => println!("https goes through {endpoint}"),
//!     None => println!("https is direct"),
//! }
//! # Ok::<(), proxy_watch::Error>(())
//! ```
//!
//! [`ProxyWatcher`] follows the settings instead — a [`Stream`] of [`WatchEvent`] that
//! opens with a snapshot, then publishes changes coalesced over
//! [`WatchOptions::debounce`] (200 ms). It runs its own OS threads, so it needs no async
//! runtime. Where there is no store to read — any other platform, or a Linux host with no
//! desktop — the answer is [`Error::Unsupported`], which means "read `ProxyEnv::from_env()`
//! instead", not "give up".
//!
//! `resolve()` (behind the `resolve` feature, so unlinked here) turns a snapshot and a URL
//! into the ordered endpoints to try, bypass rules applied; a host on PAC or WPAD stops it
//! with [`Error::PacNotSupported`] until `pac` and an engine — `pac-boa`, or
//! `pac-windows-native` on Windows — are on. The remaining flags are `linux-gnome` and
//! `linux-kde` (the Linux stores, on by default), `tokio` for a
//! `tokio::sync::watch::Receiver`, and `tracing` for lifecycle logs.
//!
//! The README carries the feature table, the per-OS map of where these settings live, and a
//! runnable example for each of the above.
//!
//! # Platform coverage
//!
//! Windows, GNOME and KDE are exercised on real machines. Under Flatpak or snap without
//! dconf the Linux backend falls back to the desktop portal, which has no change
//! notification of its own — set [`WatchOptions::poll_interval`] to poll — or reports
//! [`Error::Sandboxed`].
//!
//! **Unverified:** the macOS backend and that sandbox path have only ever run in CI — no
//! Mac, no Flatpak, no Snap.
//! **Risk:** macOS reads a missing or unexpected answer as "nothing is configured" rather
//! than as an error, so a host that does have a proxy is reported as having none. The
//! sandbox path fails loudly instead, so what is open there is whether the detection fires
//! at all, not what it does once it has.
//! **Symptom:** on a machine whose settings plainly show a proxy, the stream yields
//! [`ProxyMode::Direct`] and never publishes an error. `src/sys/mac/mod.rs`,
//! `src/sys/linux/sandbox.rs` and `src/sys/linux/portal.rs` carry the per-backend form.
// Doc examples compile, but rustdoc discards the warnings of the ones that pass — so a
// dead `use` in a snippet a reader is shown survives every command CI runs,
// `RUSTDOCFLAGS=-D warnings` included. Denying it turns that silence into a failing test.
// Narrow on purpose: an unused *binding* can be a legitimate way to show a type in an
// example, and its only escape hatch is an underscore the reader can see. An unused
// import has no legitimate form.
#![doc(test(attr(deny(unused_imports))))]
// Paired with `rustdoc-args = ["--cfg", "docsrs"]` in `Cargo.toml`: neither half does
// anything alone. Together they put an "Available on crate feature `resolve`" banner on
// every gated item, which the docs.rs page — built with all features on — otherwise omits,
// leaving a reader no way to see which items a default dependency line compiles.
#![cfg_attr(docsrs, feature(doc_cfg))]

mod auth;
#[cfg(feature = "tokio")]
mod bridge;
mod bypass;
mod config;
#[cfg(test)]
mod debug_masking; // hand-written Debug gate
mod diagnostic;
mod endpoint;
mod env;
mod error;
mod mode;
#[cfg(feature = "resolve")]
mod resolve;
mod sys;
mod trace;
mod util;
mod watch;

#[cfg(feature = "pac")]
pub mod pac;
pub mod parse;

pub use crate::auth::ProxyAuth;
pub use crate::bypass::{BypassRules, HostPattern, LOCAL_TOKEN, NO_LOOPBACK_TOKEN};
pub use crate::config::{EnvPrecedence, ProxyConfig, ProxyConfigSource};
pub use crate::diagnostic::{RejectedValue, RejectionKind, RejectionSource};
pub use crate::endpoint::{ProxyEndpoint, ProxyEntry, ProxyScheme, Scheme};
pub use crate::env::{CGI_MARKER_VAR, ProxyEnv};
pub use crate::error::Error;
pub use crate::mode::ProxyMode;
pub use crate::watch::{
    DEFAULT_DEBOUNCE, ProxyWatcher, WatchEvent, WatchHealth, WatchOptions, WatchState, read,
    read_with_options,
};

/// Routing decisions, behind the `resolve` feature (on by default).
#[cfg(feature = "resolve")]
pub use crate::resolve::{ProxyStep, resolve};

/// Routing decisions that may need a PAC script, behind the `pac` feature (off by
/// default).
#[cfg(feature = "pac")]
pub use crate::resolve::resolve_with_pac;

/// The tokio bridge, behind the `tokio` feature (off by default).
#[cfg(feature = "tokio")]
pub use crate::bridge::watch_channel;

/// Re-export of [`futures_core::Stream`].
pub use futures_core::Stream;

/// Re-export of [`url::Host`] (IPv6 brackets already resolved).
pub use url::Host;

/// Re-export of [`ipnet::IpNet`] for [`HostPattern::Cidr`].
pub use ipnet::IpNet;

/// Re-export of [`url::Url`] for [`ProxyMode::Pac`].
pub use url::Url;

// Hands the README to rustdoc so that `cargo test` compiles its examples. They are the
// first code a reader runs, and the one place a signature change is invisible to `cargo
// build`. Keep each block whole: rustdoc's `# ` hidden lines render literally on GitHub,
// so a block only compiles here if it also reads as a complete program there.
//
// `resolve` gates the item because one example calls `resolve()`, which the feature-off
// rows of the matrix do not compile.
#[cfg(all(doctest, feature = "resolve"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
