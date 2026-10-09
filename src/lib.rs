//! Detect and *watch* the operating system's proxy settings on Windows, macOS, Linux,
//! Android and iOS.
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
//! [`ProxyWatcher`] follows the settings instead: a [`Stream`] of [`WatchEvent`] that
//! opens with a snapshot, then publishes changes coalesced over
//! [`WatchOptions::debounce`] (200 ms). It runs its own OS threads, so it needs no async
//! runtime. Where there is no store to read (any other platform, or a Linux host with no
//! desktop), the answer is [`Error::Unsupported`]. Treat this as falling back to
//! `ProxyEnv::from_env()`.
//!
//! `resolve()` (behind the `resolve` feature, so unlinked here) turns a snapshot and a URL
//! into the ordered endpoints to try, bypass rules applied; a host on PAC or WPAD stops it
//! with [`Error::PacNotSupported`] until `pac` and an engine (`pac-quickjs`,
//! `pac-windows-native` on Windows, `pac-macos-native` on macOS, `pac-ios-native` on iOS,
//! or `pac-android-native` on Android, all four at once as `pac-native`) are on;
//! `pac-subprocess` runs the QuickJS engine in a worker process instead. The remaining flags are `linux-gnome` and
//! `linux-kde` (the Linux stores, on by default), `tokio` for a
//! `tokio::sync::watch::Receiver`, and `tracing` for lifecycle logs.
//!
//! The README carries a runnable example for each of the above. The sections below are the
//! reference it leaves out: every feature with its limits, what each platform reads and
//! what writes it, and each backend's limits.
//!
//! # Platform coverage
//!
//! Windows, GNOME and KDE are exercised on real machines. Under Flatpak or snap without
//! dconf, and under a KDE Flatpak with it, the Linux backend falls back to the desktop
//! portal (which has no change notification of its own: set
//! [`WatchOptions::poll_interval`] to poll) or reports [`Error::Sandboxed`].
//!
//! **Unverified:** the macOS backend and that sandbox path have run only in CI, the iOS
//! backend only on a simulator, and the Android backend on an emulator and one phone; no
//! device has run the iOS backend. The table below says what each run covered.
//! **Risk:** macOS reads a missing or unexpected answer as "nothing is configured"
//! instead of reporting an error, so a host that does have a proxy is reported as having
//! none. iOS reads the same dictionary the same way. The sandbox path fails loudly, so
//! the open question is whether the detection fires at all, not what it does once it has
//! fired. On Android below API 26 the watcher runs on `poll_interval` alone, and that
//! timer has not re-read on any device.
//! **Symptom:** on a machine whose settings show a proxy, the stream yields
//! [`ProxyMode::Direct`] and never publishes an error; on an Android device below API 26
//! the stream keeps its first snapshot after the settings change. `src/sys/mac/mod.rs`,
//! `src/sys/linux/sandbox.rs` and `src/sys/linux/portal.rs` carry the per-backend form.
//!
//! | Platform | Status |
//! |---|---|
//! | Windows | Implemented, tested in CI (`RegNotifyChangeKeyValue` over `Internet Settings`, read through `WinHttpGetIEProxyConfigForCurrentUser`) |
//! | macOS | Implemented, tested in CI headless (`SCDynamicStore` plus a `CFRunLoop`). GUI changes, network-location switching and MDM `GlobalHTTPProxy` are **unverified** on real hardware |
//! | Linux (GNOME) | Implemented, tested in CI (GSettings `changed` signal), behind `linux-gnome` |
//! | Linux (KDE) | Implemented, tested in CI (`kioslaverc` file watch, no desktop environment needed), behind `linux-kde` |
//! | Linux (Flatpak/Snap) | Sandbox detected from `/.flatpak-info`, or (as GLib's `is_snap` does it) from `$SNAP/meta/snap.yaml` declaring anything but `confinement: classic`; read via the `ProxyResolver` portal (needs `linux-gnome`) or `Error::Sandboxed`. Watch needs `WatchOptions::poll_interval` (portal has no change signal). **Unverified** |
//! | Android | Read through JNI, API 23+; the crate needs the app's `JavaVM` and a `Context`: `android-activity` registers them with `ndk-context`, which the crate reads, and so does `tao` from 0.36 (Tauri 2.12); a host built on an earlier `tao` calls `android::init` instead. The bypass list is read with `java.net.ProxySelector`'s rules, so loopback goes direct only when the list is non-empty. Watch receives the `PROXY_CHANGE_ACTION` broadcast through a small receiver class the crate loads from memory (API 26+); below API 26, or where in-memory code loading is refused, it needs `WatchOptions::poll_interval`. **Partly verified**. `read()` (direct, manual, PAC), `pac-android-native` and the watcher ran on an API 36 x86-64 emulator: a settings change, a switch of the default network between a Wi-Fi with its own proxy and bypass list and mobile data, and unregistering on drop. The host registered through `ndk-context` there, through `android::init` from a Tauri 2.11 app, and through what `tao` registers in a Tauri 2.12 app built for release. On a phone with Android 17, a Tauri app read, resolved and received changes for a Wi-Fi proxy with a bypass list, a PAC URL, and a switch to mobile data. The poll fallback has not run, nor a global, VPN or APN proxy |
//! | iOS | Read through `CFNetworkCopySystemProxySettings()` and interpreted as macOS's dictionary is. Watch needs `WatchOptions::poll_interval`: iOS gives an app no proxy change notification. The app becoming active and a network path change (`nw_path_monitor`, iOS 12+) re-read before the interval is up. **Partly verified**: on an iOS simulator in CI, watchers read, take their first network path update and drop; what they read is not checked against a configured proxy, and no device has run it |
//! | Environment variables | `ProxyEnv::from_env()` on every platform: a snapshot, never a `Stream`. Nothing outside the process can change them, and a process changing its own is signalled nowhere. Re-read to pick that up; `ProxyEnv::captured_at()` says when the snapshot was taken |
//!
//! # Feature flags
//!
//! | Feature | Default | What it adds |
//! |---|---|---|
//! | `resolve` | **on** | `resolve()` and `ProxyStep`. No extra dependency |
//! | `linux-gnome` | **on** | GNOME half of the Linux backend (GSettings, XDG portal fallback). Opens GLib at run time; nothing to install at build time |
//! | `linux-kde` | **on** | KDE half (`kioslaverc` and its file watch). Pure Rust |
//! | `tokio` | off | `watch_channel()`; pulls in `tokio` with only `rt` and `sync` |
//! | `tracing` | off | Log lines giving the effective mode before and after each change, and the sources read. They are written to leave out credentials, PAC bodies and echoed parse inputs |
//! | `pac-native` | off | Every native resolver below; each builds only on its own OS, so one feature list serves every target. `pac::NativePacResolver` names this target's, and `PacResolver::with_system_native()` attaches it with its defaults. Implies `pac` |
//! | `pac-quickjs` | off | An engine for `pac`: QuickJS through `rquickjs`. Stops a script at its timeout and bounds its heap and stack; compiles C, so it needs a C compiler for the target, and is left out of the docs.rs build for that reason: run `cargo doc --features pac-quickjs` to see `QuickJsEvaluator`. Implies `pac` |
//! | `pac-subprocess` | off | `pac::SubprocessEvaluator`: each evaluation runs in a `proxy-watch-pac-worker` process at a path you give, killed at the timeout, with name lookups answered by your process under its `PacPolicy`. Needs no engine itself; the worker binary is built with `pac-subprocess` and `pac-quickjs` (`cargo install proxy-watch --features pac-subprocess,pac-quickjs`). Windows and Linux also cap the worker's memory. On Linux (x86-64, AArch64) the worker runs under a seccomp filter that leaves it no file, socket or process calls; elsewhere it has no sandbox and is refused unless you call `allow_unsandboxed()`. Implies `pac` |
//! | `pac-windows-native` | off | Windows only. `pac::WinHttpPacResolver`: download and evaluation via WinHTTP, and WPAD discovery after `with_wpad(true)`. No `PacInline`; `PacPolicy` does not apply on this path. Implies `pac` |
//! | `pac-macos-native` | off | macOS only: `pac::CfNetworkPacResolver` downloads and evaluates a PAC URL through CFNetwork, and `pac::CfNetworkPacEvaluator` evaluates a body there as a `PacEvaluator`. WPAD after `with_wpad(true)`, through the PAC URL the system settings name; `PacPolicy` does not apply on this path; CFNetwork drops `HTTPS` and `SOCKS5` entries from a script's answer, cuts an IPv6 literal proxy at its first colon (dropped here), and the script sees the target URL cut to its scheme and host. Implies `pac` |
//! | `pac-ios-native` | off | iOS only: the same `pac::CfNetworkPacResolver` and `pac::CfNetworkPacEvaluator` as `pac-macos-native`, with the same limits; WPAD resolves from the `CfNetworkSystemSettings` scope. Not yet run on a device or simulator. Implies `pac` |
//! | `pac-android-native` | off | Android only: `pac::AndroidPacResolver` asks `ProxySelector.getDefault()`, which the system PAC service answers, for a `Pac` configuration `ConnectivityManager` reports, and errors once the system settings name a different PAC URL. No download or WPAD of its own; `PacPolicy` does not apply on this path. Implies `pac` |
//! | `pac` | off | The `pac` module and `resolve_with_pac()`. Parsing and policy only: no JavaScript engine; you supply the script body. Implies `resolve` |
//!
//! Platform backends are **not** feature-selected: they are chosen by target `cfg`, because
//! a feature enabled anywhere in a dependency graph can never be turned off again.
//! `linux-gnome` and `linux-kde` are the exception: they pick between stores *within*
//! Linux. Turning `linux-gnome` off means GLib is never opened; with both off, Linux
//! behaves like an unsupported target, except inside a sandbox, where the portal fallback
//! needs `linux-gnome` to be compiled in at all, so the answer is `Error::Sandboxed` rather
//! than `Error::Unsupported`. Both are errors; a caller matching only on `Unsupported`
//! misses that one.
//!
//! # Where a host's settings live
//!
//! Reproducing a report, or writing a setting to test against, means knowing which store is
//! being read, which is not always the one the GUI writes.
//!
//! | Platform | Store | Where it comes from |
//! |---|---|---|
//! | Windows | Per-user WinINet through `WinHttpGetIEProxyConfigForCurrentUser`, falling back to `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` (`ProxyServer`, `ProxyOverride`, `AutoConfigURL`) | Settings → Network & Internet → Proxy |
//! | Windows | The WinHTTP machine default, `WinHttpGetDefaultProxyConfiguration` | `netsh winhttp set proxy`. Reported, but never `effective`: the per-user store outranks it |
//! | Windows | `HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings` | Group Policy. Also reported, also behind the per-user store |
//! | macOS | The `SCDynamicStore` proxy dictionary (`HTTPProxy`, `ExceptionsList`, `ProxyAutoConfigURLString`, …) | System Settings → Network → *service* → Details → Proxies, or `sudo networksetup -setwebproxy <service> <host> <port>`. Read it back with `scutil --proxy` |
//! | Linux (GNOME) | GSettings `org.gnome.system.proxy` and its `.http` / `.https` / `.ftp` / `.socks` children | Settings → Network → Network Proxy, or `gsettings set org.gnome.system.proxy mode 'manual'` |
//! | Linux (KDE) | `[Proxy Settings]` in `kioslaverc`, merged across the whole XDG cascade | System Settings → Network → Proxy, which writes `~/.config/kioslaverc` |
//! | Android | `ConnectivityManager.getDefaultProxy()` through JNI: host and port for `http` and `https`, the exclusion list, the PAC URL | Wi-Fi → *network* → Proxy, a VPN's proxy, or `adb shell settings put global http_proxy <host>:<port>` |
//! | iOS | `CFNetworkCopySystemProxySettings()`, the same dictionary keys as macOS | Settings → Wi-Fi → *network* → Configure Proxy, a VPN's proxy, or an MDM profile |
//! | Any | `http_proxy`, `https_proxy`, `ftp_proxy`, `all_proxy`, `no_proxy` | The process environment, read by `ProxyEnv::from_env()`. Lowercase beats uppercase; on Windows any other casing is read after both. An `http_proxy` next to a non-empty `REQUEST_METHOD` is refused with `Error::CgiHttpProxy`, because a request header sets that variable |
//!
//! Each of those spells its bypass list differently, and the differences decide which hosts go
//! direct. The [`parse`] module's docs have the table, entry shape by entry shape.
//!
//! # Pitfalls
//!
//! - [`read`] can block for seconds on macOS and inside a Linux sandbox, while a system
//!   service comes up or times out. Keep it off a UI thread.
//! - A PAC or WPAD machine makes `resolve()` fail with [`Error::PacNotSupported`] rather
//!   than answering direct, so a caller that treats an error as "go direct" routes traffic
//!   around the administrator's proxy. Handle it, or pass the snapshot to a PAC resolver
//!   with an engine enabled.
//! - A sandboxed watcher never fires without [`WatchOptions::poll_interval`]: the portal
//!   has no change signal, so the stream stays on its first snapshot.
//! - A `kioslaverc` that is a symlink into another directory is read but not watched: the
//!   watch is on the config directories, and an edit to the link's target fires nothing
//!   there. Set [`WatchOptions::poll_interval`] if a dotfile manager links it.
//! - `ProxyStep::to_url()` carries the password in the clear. It exists to hand
//!   `user:password@` to a client; `endpoint()`'s `Display` masks it, so print that one.
//! - `watch_channel()` (behind `tokio`) publishes configuration only. A failed re-read or a
//!   dead notification route leaves the last good configuration standing with nothing
//!   marking it.
//!
//! # Backend limits
//!
//! Each backend documents its own limits at the top of its module. Those modules are private,
//! so the text is in the source. These are the limits to know before relying on a backend.
//!
//! - Windows 8 / Windows Server 2012 is the floor, and nothing checks it. The registry watch
//!   arms `RegNotifyChangeKeyValue` with `REG_NOTIFY_THREAD_AGNOSTIC`, which Microsoft
//!   documents as "only supported in Windows 8 and later"; the function itself goes back
//!   to Windows 2000, so the flag sets the floor, not the call.
//!   `pac-windows-native` calls `WinHttpCreateProxyResolver` and `WinHttpGetProxyForUrlEx`,
//!   both of which list Windows 8 and Windows Server 2012 as their minimum supported client
//!   and server. Behaviour on an older release has not been measured.
//! - Windows reads the settings of the active connection only. `WinHttpGetIEProxyConfigForCurrentUser`
//!   is documented as returning them for the current active connection (LAN, dial-up or VPN
//!   alike) and this crate never enumerates connectoids to find the others. It also reports
//!   one mode: auto-detect wins over a PAC URL, which wins over static servers.
//! - `kioslaverc` is merged across the whole XDG cascade (`/etc/xdg` through
//!   `$XDG_CONFIG_HOME`), so a system value marked immutable (`[$i]`) is not overridden by
//!   a user file. A `[$e]` flag is not expanded: KDE substitutes `$VAR`/`${VAR}` from the
//!   environment of whichever session read the file. A library that only reports should not
//!   pull process environment in on a config file's say-so. A `[$e]` value that still
//!   contains a `$` is recorded in `ProxyMode::rejected` and not reported as a host, bypass
//!   pattern, or PAC script. The literal text is not the value the desktop is using, and
//!   naming it as a proxy would invent an unconfigured destination. A `[$e]` value with no
//!   `$` in it expands to itself and is read as written.
//! - A `kioslaverc` watch can go silent if a watched directory is deleted. That surfaces as
//!   `WatchHealth::degraded`.
// Doc examples compile, but rustdoc discards the warnings of the ones that pass, so a
// dead `use` in a snippet a reader is shown survives every command CI runs,
// `RUSTDOCFLAGS=-D warnings` included. Denying it turns that silence into a failing test.
// Narrow on purpose: an unused *binding* can be a legitimate way to show a type in an
// example, and its only escape hatch is an underscore the reader can see. An unused
// import has no legitimate form.
#![doc(test(attr(deny(unused_imports))))]
// Paired with `rustdoc-args = ["--cfg", "docsrs"]` in `Cargo.toml`: neither half does
// anything alone. Together they put an "Available on crate feature `resolve`" banner on
// every gated item, which the docs.rs page (built with nearly every feature on) otherwise
// omits, leaving a reader no way to see which items a default dependency line compiles.
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

#[cfg(target_os = "android")]
pub mod android;
#[cfg(feature = "pac")]
pub mod pac;
pub mod parse;

pub use crate::auth::{PasswordState, ProxyAuth};
pub use crate::bypass::{BypassRules, HostPattern, ImplicitBypass, LOCAL_TOKEN, NO_LOOPBACK_TOKEN};
pub use crate::config::{EnvPrecedence, ProxyConfig, ProxyConfigSource};
pub use crate::diagnostic::{RejectedValue, RejectionKind, RejectionSource};
pub use crate::endpoint::{ProxyEndpoint, ProxyEntry, ProxyScheme, Scheme};
pub use crate::env::{CGI_MARKER_VAR, ProxyEnv};
pub use crate::error::Error;
pub use crate::mode::ProxyMode;
pub use crate::watch::{
    CapturedEnv, DEFAULT_DEBOUNCE, ProxyWatcher, WatchEvent, WatchHealth, WatchOptions, WatchState,
    read, read_in, read_with_options,
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
