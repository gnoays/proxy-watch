# proxy-watch

[![CI](https://github.com/gnoays/proxy-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/gnoays/proxy-watch/actions/workflows/ci.yml)

Read the operating system's proxy configuration on Windows, macOS and Linux — and get a
`Stream` item every time it changes.

A one-shot read at process start goes stale: a PAC URL pushed by policy, or a proxy
switched out from under a long-running program, never reaches code that read once and
cached the answer. This crate exists so that change arrives as a `Stream` item — within
what each backend can see. Windows reads whichever connection is currently active, not
every connection configured; **Platform support** below says what else each one leaves out.

Backends prefer the OS notification API: `RegNotifyChangeKeyValue` on Windows,
`SCDynamicStore` on macOS, GSettings signals or a `kioslaverc` file watch on Linux.
Sandboxed Linux (Flatpak/Snap portal) has no change signal — set
`WatchOptions::poll_interval` there, or the stream stays on the first snapshot.

## Install

```sh
cargo add proxy-watch
```

The default features include GNOME support, which on Linux needs GLib's development files
(`libglib2.0-dev`, `glib2-devel`) at build time; Windows and macOS builds never reach for
them. A Linux build with no C dependency turns the defaults off and asks for the KDE half
instead:

```sh
cargo add proxy-watch --no-default-features --features resolve,linux-kde
```

That command is also the answer to the licence question `linux-gnome` raises. The Rust
bindings it pulls in — `gio`, `glib` and their `-sys` crates — are MIT, and this crate
carries none of GLib's own code; GLib itself is LGPL-2.1-or-later, reached at run time as
a shared library through `pkg-config`. Turning the feature off drops the C library from
the picture entirely.

## Usage

[`examples/`](examples/) carries a runnable file per section — `current`, `watch`,
`resolve`, `reqwest_client` — plus `env`, `resolve_os_and_env` and `pac`
(`cargo run --example <name>`). The full API reference is on
[docs.rs](https://docs.rs/proxy-watch).

### Read it once

```rust,no_run
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = proxy_watch::read()?;
    println!("effective: {:?}", config.effective);
    Ok(())
}
```

`read()` starts no watcher: no thread, and no change-notification route to register. That
last part is the reason it exists rather than being `ProxyWatcher::new()?.current()` —
arming notifications can fail on a machine whose settings still read fine, and only the
watcher has to care.

If configuration and watcher liveness must describe the same instant, use the atomic
`ProxyWatcher::state()` observation instead of separate `current()` and `health()` calls.

`read()` reports the OS stores alone. `http_proxy` / `no_proxy` are a second snapshot,
`ProxyEnv::from_env()`, and which one wins is a policy you name rather than one this crate
picks — most command-line tools want the environment first, the way `curl` reads it:

```rust,no_run
use proxy_watch::{read, EnvPrecedence, ProxyEnv};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = read()?.with_env(&ProxyEnv::from_env()?, EnvPrecedence::BeforeSystem);
    println!("effective: {:?}", config.effective);
    Ok(())
}
```

On a Linux host with no desktop store at all — a server, a container, CI — `read()` itself
answers `Error::Unsupported`, and the environment is the only configuration there. Treat
that error as "use `ProxyEnv` alone", not as fatal.

### Watch it

`ProxyWatcher` is a `futures_core::Stream` on OS threads of its own, so it needs no async
runtime. Driving it still needs something that blocks on a future: this uses `poll_fn` with
`futures_executor::block_on`, which is not a dependency of this crate — add
`futures-executor` yourself, or block with whatever your runtime already provides.

```rust,no_run
use std::future::poll_fn;
use std::pin::Pin;

use proxy_watch::{ProxyWatcher, Stream, WatchEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut watcher = ProxyWatcher::new()?;
    loop {
        match futures_executor::block_on(poll_fn(|cx| Pin::new(&mut watcher).poll_next(cx))) {
            Some(WatchEvent::Snapshot { state, .. }) => {
                let live = state.health.is_fully_live();
                println!("-> {:?} (live: {live})", state.config.effective);
            }
            Some(WatchEvent::Error { error, .. }) => eprintln!("-> error: {error}"),
            Some(_) => {}
            None => break,
        }
    }
    Ok(())
}
```

The first item is always a snapshot of the current configuration, emitted at subscription
time. After that a snapshot means the configuration really changed, *or* that a
notification route was lost — the health rides the same stream, so a watcher that has gone
deaf says so instead of only falling quiet. Snapshots equal to the previous one are
dropped, and notifications are coalesced over a 200 ms debounce window
(`WatchOptions::debounce`).

Nothing is promised after a `WatchEvent::Error`. If the next successful read returns the
same configuration and no route changed, there is nothing to publish and the stream stays
silent; confirm recovery with `current()` or `state()` rather than waiting for an item. A
snapshot does follow whenever the configuration or the health actually moved.

With the `tokio` feature, `watch_channel()` moves the watcher into a background task and
publishes to a `tokio::sync::watch::Receiver`, which clones freely — that is how you get
more than one consumer. It has to be called from inside a runtime, and it is **configuration
only**: it drops both the errors and the health, so a failed re-read or a dead route leaves
the last good configuration published with nothing to mark it. Poll the `Stream` yourself,
or read `ProxyWatcher::state()`, if you need either.

### Decide how to reach a URL

`resolve()` turns a snapshot into an ordered list of `ProxyStep`s, applying the bypass
rules, the per-scheme precedence and the `<local>` / CIDR / wildcard patterns:

```rust,no_run
use proxy_watch::{read, resolve, Url};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = read()?;
    for step in resolve(&config, &Url::parse("https://example.com/")?)? {
        match step.endpoint() {
            Some(endpoint) => println!("via {endpoint}"),
            None => println!("DIRECT"),
        }
    }
    Ok(())
}
```

`endpoint()` and not `to_url()`, for two reasons. `ProxyEndpoint`'s `Display` masks
credentials and a `Url`'s does not — `to_url()` exists to hand `user:password@` to a
client, so printing one prints the proxy password. And `to_url()` also answers `None` for
an endpoint whose host cannot be written into a URL, which would print `DIRECT` for a
machine that has a proxy. Use `to_url()` where the URL is *sent*, as the `reqwest` snippet
below does.

On a machine configured with a PAC script or WPAD it **fails**, with
`Error::PacNotSupported`. Falling back to a direct connection would route traffic around a
proxy the administrator configured, so the choice is the caller's.

To evaluate a script instead, enable `pac` — plus `pac-boa` for a pure-Rust engine — and
call `resolve_with_pac()` with a body you already have; that path never downloads. On
Windows, `pac-windows-native` hands discovery, download and evaluation to WinHTTP
instead. `PacPolicy`'s rustdoc covers the safety envelope and the two CVEs behind its
defaults.

### With `reqwest`

`reqwest` fixes its proxy at `Client` build time
([#2674](https://github.com/seanmonstar/reqwest/issues/2674)), but `Proxy::custom` runs a
closure each time a connection is opened, so a config kept fresh by a watcher makes an
existing `Client` follow the OS for every destination it is not already connected to
([`examples/reqwest_client.rs`](examples/reqwest_client.rs)):

```rust,ignore
let client = reqwest::Client::builder()
    .proxy(reqwest::Proxy::custom(move |url| {
        let config = for_proxy.read().ok()?;          // Arc<RwLock<ProxyConfig>>
        resolve(&config, url).ok()?.first().and_then(ProxyStep::to_url)
    }))
    .build()?;
```

A connection already in the pool keeps its old route, because hyper-util keys the pool on
the destination alone: expect the change after `pool_idle_timeout` (90 s by default), or
set `pool_max_idle_per_host(0)`, or rebuild the `Client` on each event.

Turning a `resolve` error into `None` via `.ok()?` is fail-open (direct), and two errors
reach it: `PacNotSupported` on a PAC/WPAD machine, and `ProxyEntryUnusable` where the
configured proxy for that scheme could not be read. Fail the request, or call
`resolve_with_pac()` / WinHTTP for the first — the full example spells that out.

## Pitfalls

- **`read()` blocks, and not always briefly.** Both non-Windows backends wait on a system
  service that can be absent: a `configd` still coming up is retried for five seconds, and
  inside a Linux sandbox each portal `Lookup` is bounded at five seconds — per call, and a
  sandboxed read asks five of them. Keep it off a UI thread.
- **A PAC or WPAD machine makes `resolve()` fail** with `Error::PacNotSupported` rather
  than answering `DIRECT`, so a caller that treats an error as "go direct" routes traffic
  around the administrator's proxy. Handle it, or enable `pac`.
- **Windows reports one connection and one step**: the active connection's settings only,
  and when auto-detect, a PAC URL and static servers are all enabled, only the first.
- **A sandboxed watcher never fires** without `WatchOptions::poll_interval` — the portal
  has no change signal, so the stream stays on its first snapshot.
- **`ProxyStep::to_url()` carries the password in the clear.** It exists to hand
  `user:password@` to a client; `endpoint()`'s `Display` masks it, so print that one.
- **`watch_channel()` publishes configuration only.** A failed re-read or a dead
  notification route leaves the last good configuration standing with nothing marking it.

## Where a host's settings live

Reproducing a report, or writing a setting to test against, means knowing which store is
being read — which is not always the one the GUI writes.

| Platform | Store | Where it comes from |
|---|---|---|
| Windows | Per-user WinINet through `WinHttpGetIEProxyConfigForCurrentUser`, falling back to `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` (`ProxyServer`, `ProxyOverride`, `AutoConfigURL`) | Settings → Network & Internet → Proxy |
| Windows | The WinHTTP machine default, `WinHttpGetDefaultProxyConfiguration` | `netsh winhttp set proxy`. Reported, but never `effective` — the per-user store outranks it |
| Windows | `HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings` | Group Policy. Also reported, also behind the per-user store |
| macOS | The `SCDynamicStore` proxy dictionary (`HTTPProxy`, `ExceptionsList`, `ProxyAutoConfigURLString`, …) | System Settings → Network → *service* → Details → Proxies, or `sudo networksetup -setwebproxy <service> <host> <port>`. Read it back with `scutil --proxy` |
| Linux (GNOME) | GSettings `org.gnome.system.proxy` and its `.http` / `.https` / `.ftp` / `.socks` children | Settings → Network → Network Proxy, or `gsettings set org.gnome.system.proxy mode 'manual'` |
| Linux (KDE) | `[Proxy Settings]` in `kioslaverc`, merged across the whole XDG cascade | System Settings → Network → Proxy, which writes `~/.config/kioslaverc` |
| Any | `http_proxy`, `https_proxy`, `ftp_proxy`, `all_proxy`, `no_proxy` | The process environment, read by `ProxyEnv::from_env()`. Lowercase beats uppercase; on Windows any other casing is read after both. An `http_proxy` next to a non-empty `REQUEST_METHOD` is refused with `Error::CgiHttpProxy`, because a request header sets that variable |

Each of those spells its bypass list differently, and the differences decide which hosts go
direct. The `parse` module's docs have the table, entry shape by entry shape.

## Feature flags

| Feature | Default | What it adds |
|---|---|---|
| `resolve` | **on** | `resolve()` and `ProxyStep`. No extra dependency |
| `linux-gnome` | **on** | GNOME half of the Linux backend (GSettings, XDG portal fallback). Pulls in `gio`/`glib`, so GLib is a build-time C dependency |
| `linux-kde` | **on** | KDE half (`kioslaverc` and its file watch). Pure Rust |
| `tokio` | off | `watch_channel()`; pulls in `tokio` with only `rt` and `sync` |
| `pac` | off | The `pac` module and `resolve_with_pac()`. Parsing and policy only — no JavaScript engine; you supply the script body. Implies `resolve` |
| `pac-boa` | off | The engine for `pac`: pure-Rust `boa_engine`. Opt-in on purpose, since a PAC script is code from a network-controlled location. Implies `pac` |
| `pac-windows-native` | off | Windows only: `pac::WinHttpPacResolver` — WPAD discovery, download, and evaluation via WinHTTP. No `PacInline`; `PacPolicy` does not apply on this path. Implies `pac` |
| `tracing` | off | Log lines naming which source changed the configuration. Credentials, PAC bodies and echoed parse inputs are never logged |

Platform backends are **not** feature-selected — they are chosen by target `cfg`, because
a feature enabled anywhere in a dependency graph can never be turned off again.
`linux-gnome` and `linux-kde` are the deliberate exception: they pick between stores
*within* Linux. Turning `linux-gnome` off drops the C dependency; with both off, Linux
behaves like an unsupported target — except inside a sandbox, where the portal fallback
needs `linux-gnome` to be compiled in at all, so the answer is `Error::Sandboxed` rather
than `Error::Unsupported`. Both are errors; a caller matching only on `Unsupported`
misses that one.

## Platform support

| Platform | Status |
|---|---|
| Windows | Implemented, tested in CI (`RegNotifyChangeKeyValue` over `Internet Settings`, read through `WinHttpGetIEProxyConfigForCurrentUser`) |
| macOS | Implemented, tested in CI headless (`SCDynamicStore` plus a `CFRunLoop`). GUI changes, network-location switching and MDM `GlobalHTTPProxy` are **unverified** on real hardware |
| Linux (GNOME) | Implemented, tested in CI (`gio` `changed` signal), behind `linux-gnome` |
| Linux (KDE) | Implemented, tested in CI (`kioslaverc` file watch, no desktop environment needed), behind `linux-kde` |
| Linux (Flatpak/Snap) | Sandbox detected from `/.flatpak-info`, or — as GLib's `is_snap` does it — from `$SNAP/meta/snap.yaml` declaring anything but `confinement: classic`; read via the `ProxyResolver` portal (needs `linux-gnome`) or `Error::Sandboxed`. Watch needs `WatchOptions::poll_interval` (portal has no change signal). **Unverified** |
| Environment variables | `ProxyEnv::from_env()` on every platform — a snapshot, never a `Stream`: nothing outside the process can change them, and a process changing its own is signalled nowhere. Re-read to pick that up; `ProxyEnv::captured_at()` says when the snapshot was taken |

Everywhere else the constructors compile and return `Error::Unsupported` at runtime, so
downstream code compiles on any target.

Where the table says **unverified**, the failure to expect is the quiet one: the crate
reports no proxy while the host has one, and publishes no error. The crate docs open with
what to look for on each. An issue carrying that output is worth more than any review —
these are the surfaces this crate cannot verify on its own, and
[the form](https://github.com/gnoays/proxy-watch/issues/new?template=unverified-surface.yml)
asks for the pair that settles one: what the host is set to, and what the crate answered.

Each backend documents its own limits at the top of its module. Those modules are private,
so the text is in the source rather than on docs.rs; the limits worth knowing before
relying on a backend are:

- Windows 8 / Windows Server 2012 is the floor, and nothing checks it. The registry watch
  arms `RegNotifyChangeKeyValue` with `REG_NOTIFY_THREAD_AGNOSTIC`, which Microsoft
  documents as "only supported in Windows 8 and later" — the function itself goes back to
  Windows 2000, so it is the flag and not the call that sets the floor — and
  `pac-windows-native` calls `WinHttpCreateProxyResolver` and `WinHttpGetProxyForUrlEx`,
  both of which list Windows 8 and Windows Server 2012 as their minimum supported client
  and server. Behaviour on an older release has not been measured.
- Windows reads the settings of the active connection only. `WinHttpGetIEProxyConfigForCurrentUser`
  is documented as returning them for the current active connection — LAN, dial-up or VPN
  alike — and this crate never enumerates connectoids to find the others. It also reports
  only the first enabled step when auto-detect, a PAC URL and static servers are all on.
- `kioslaverc` is merged across the whole XDG cascade (`/etc/xdg` through
  `$XDG_CONFIG_HOME`), so a system value marked immutable (`[$i]`) is not overridden by a
  user file. But a `[$e]` flag is not expanded: KDE substitutes `$VAR`/`${VAR}` from the
  environment of whichever session read the file, and pulling process environment in on a
  config file's say-so is not something a library that only reports should do. A `[$e]`
  value that still contains a `$` is therefore recorded in `ProxyMode::rejected` rather
  than reported as a host, a bypass pattern, or a PAC script — the literal text is not the
  value the desktop is
  using, and naming it as a proxy would invent a destination nobody configured. A `[$e]`
  value with no `$` in it expands to itself and is read as written.
- A `kioslaverc` watch can go silent if a watched directory is deleted. That surfaces as
  `WatchHealth::degraded`.

## Minimum supported Rust version

**1.88**, and **1.92** with `linux-gnome` (its `gio`/`glib` declare that themselves).
`linux-gnome` is a default feature, so a default build *on Linux* needs 1.92; 1.88 is the
floor everywhere else. Both are checked in CI (`cargo check --all-targets`) rather than
taken on trust.

## Design

- **Async-runtime agnostic:** `futures_core::Stream` on dedicated OS threads (`tokio` optional).
- **`unsafe` is confined to the code that calls the OS directly.** Windows and macOS
  backends and the WinHTTP PAC engine; the OS-independent core and the Linux backend
  contain none of their own.
- **Credentials stay masked** in `Debug`; `ProxyAuth` has no `Display`.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) has the checks CI applies and how to run them, what
`#[ignore]` means here — it marks the tests that rewrite your machine's real proxy settings
— and what the prose gates in `xtask/` require of a comment.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
