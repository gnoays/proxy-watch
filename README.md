# proxy-watch

[![crates.io](https://img.shields.io/crates/v/proxy-watch.svg)](https://crates.io/crates/proxy-watch)
[![docs.rs](https://img.shields.io/docsrs/proxy-watch)](https://docs.rs/proxy-watch)
[![CI](https://github.com/gnoays/proxy-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/gnoays/proxy-watch/actions/workflows/ci.yml)
[![Audit](https://github.com/gnoays/proxy-watch/actions/workflows/audit.yml/badge.svg)](https://github.com/gnoays/proxy-watch/actions/workflows/audit.yml)

Read the operating system's proxy configuration on Windows, macOS, Linux, Android and
iOS, and get a `Stream` item every time it changes. On a host set to PAC, a URL's route
comes from the OS's own PAC engine or a bundled one.

```rust,no_run
use futures_util::StreamExt;
use proxy_watch::{ProxyWatcher, WatchEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut watcher = ProxyWatcher::new()?;
    while let Some(event) = futures_executor::block_on(watcher.next()) {
        if let WatchEvent::Snapshot { state, .. } = event {
            println!("proxy: {:?}", state.config.effective);
        }
    }
    Ok(())
}
```

A one-shot read at process start goes stale: code that read once and cached the answer
never sees a PAC URL pushed by policy, or a proxy switched out from under a long-running
program. This crate delivers that change as a `Stream` item.

## Which part you need

- **The settings once**, for a program that starts, reads and exits: `read()`.
- **The settings as they change**, for a long-running program: `ProxyWatcher`, a `Stream`
  that opens with a snapshot.
- **The route for one URL**, bypass rules applied: `resolve()`, and a PAC engine from the
  feature table below when the host uses PAC or WPAD.
- **An HTTP client that follows the OS**: `reqwest`'s `Proxy::custom` fed by a watcher.
- **Only `http_proxy` / `no_proxy`**: `ProxyEnv::from_env()`, on every platform.

Each has a section under **Usage**.

## Install

```sh
cargo add proxy-watch
```

GNOME support, on by default, opens GLib at run time: a build needs no C library or
headers, and a machine without GLib reads the other stores.

## Other languages

The same library, built from this repository; each package's README has its usage.

| Language | Package | |
|---|---|---|
| Node.js | [`proxy-watch`](bindings/node/README.md) on npm | [![npm](https://img.shields.io/npm/v/proxy-watch.svg)](https://www.npmjs.com/package/proxy-watch) |
| Python | [`proxy-watch`](bindings/python/README.md) on PyPI | [![PyPI](https://img.shields.io/pypi/v/proxy-watch.svg)](https://pypi.org/project/proxy-watch/) |
| C | [header and libraries](bindings/c/README.md) on the GitHub Releases page (`bindings-v*` tags) | |

## Usage

[`examples/`](examples/) has a runnable file per section (`current`, `watch`, `resolve`,
`reqwest_client`), plus `env`, `resolve_os_and_env` and `pac`
(`cargo run --example <name>`; `pac` needs `--features pac-quickjs`). The API reference, every feature's limits and each
platform's details are on [docs.rs](https://docs.rs/proxy-watch).

### Read it once

```rust,no_run
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = proxy_watch::read()?;
    println!("effective: {:?}", config.effective);
    Ok(())
}
```

`read()` reports the OS settings only; layer `http_proxy` / `no_proxy` on top with
`.with_env(&ProxyEnv::from_env()?, EnvPrecedence::BeforeSystem)`, or `AfterSystem`. On a
Linux host with no desktop store (most servers, containers and CI hosts), `read()` answers
`Error::Unsupported`: use `ProxyEnv` alone there.

### Watch it

`ProxyWatcher` runs on OS threads of its own, so it needs no async runtime. This example
drives it with `futures-executor`; add `futures-util` and `futures-executor` yourself, or
`.await` `next()` from the runtime you have.

```rust,no_run
use futures_util::StreamExt;
use proxy_watch::{ProxyWatcher, WatchEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut watcher = ProxyWatcher::new()?;
    while let Some(event) = futures_executor::block_on(watcher.next()) {
        match event {
            WatchEvent::Snapshot { state, .. } => {
                let live = state.health.is_fully_live();
                println!("-> {:?} (live: {live})", state.config.effective);
            }
            WatchEvent::Error { error, .. } => eprintln!("-> error: {error}"),
            _ => {}
        }
    }
    Ok(())
}
```

The first item is the current configuration; each later one is a change, coalesced over
200 ms. With the `tokio` feature, `watch_channel()` publishes to a
`tokio::sync::watch::Receiver` instead.

### Decide how to reach a URL

`resolve()` turns a snapshot into the ordered `ProxyStep`s to try, bypass rules applied:

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

On a machine configured with a PAC script or WPAD it **fails** with
`Error::PacNotSupported` instead of answering direct. `pac::PacResolver` answers there,
with the OS's engine (`pac-native`) or a bundled one (`pac-quickjs`, or `pac-subprocess`
to keep the script out of your process); `examples/pac.rs` shows one.

### With `reqwest`

`reqwest`'s `Proxy::custom` asks on every new connection, so a configuration kept fresh by
a watcher makes one `Client` follow the OS:
[`examples/reqwest_client.rs`](examples/reqwest_client.rs).

## Pitfalls

- **`read()` can block for seconds** on macOS and inside a Linux sandbox. Keep it off a UI
  thread.
- **Do not treat a `resolve()` error as "go direct"**: on a PAC or WPAD machine that routes
  traffic around the administrator's proxy.
- **A sandboxed watcher never fires** without `WatchOptions::poll_interval`.

The rest, with each platform's limits, is on [docs.rs](https://docs.rs/proxy-watch).

## Feature flags

| Feature | Default | What it adds |
|---|---|---|
| `resolve` | **on** | `resolve()`: the proxy, or direct, for one URL |
| `linux-gnome` | **on** | GNOME settings; opens GLib at run time |
| `linux-kde` | **on** | KDE settings (`kioslaverc`) |
| `tokio` | off | `watch_channel()`, a `tokio::sync::watch::Receiver` |
| `tracing` | off | Logs naming which source changed; written to keep credentials out of them |
| `pac-native` | off | PAC through the OS's own resolver on Windows, macOS, iOS and Android |
| `pac-quickjs` | off | A bundled QuickJS engine for a PAC body you supply; needs a C compiler |
| `pac-subprocess` | off | The same engine in a worker process of its own; the worker is built with `pac-quickjs` too |
| `pac-windows-native` | off | The Windows part of `pac-native` (WinHTTP) |
| `pac-macos-native` | off | The macOS part of `pac-native` (CFNetwork) |
| `pac-ios-native` | off | The iOS part of `pac-native` (CFNetwork) |
| `pac-android-native` | off | The Android part of `pac-native` (`ProxySelector`) |
| `pac` | off | PAC parsing and policy with no engine; every `pac-*` feature turns it on |

## Platform support

| Platform | Status |
|---|---|
| Windows | Tested in CI |
| macOS | Tested in CI without a GUI. GUI changes, network-location switches and MDM `GlobalHTTPProxy` are **unverified** on real hardware |
| Linux (GNOME, KDE) | Tested in CI; behind `linux-gnome` and `linux-kde` |
| Linux (Flatpak/Snap) | Read through the desktop portal (needs `linux-gnome`); watching needs `WatchOptions::poll_interval`. **Unverified** |
| Android | API 23+; watching needs API 26+, or else `WatchOptions::poll_interval`. `android-activity` and Tauri 2.12+ hand the crate the app's `JavaVM` and `Context`; any other host calls `proxy_watch::android::init` before the first read, which otherwise fails, or aborts under `panic = "abort"`. **Partly verified** on an emulator and a phone (Android 17) |
| iOS | Watching needs `WatchOptions::poll_interval`: iOS gives an app no proxy change notification. **Partly verified** on a simulator |
| Environment variables | `ProxyEnv::from_env()` on every platform; a snapshot, never a `Stream` |

Everywhere else the constructors compile and return `Error::Unsupported` at runtime.

Where the table says **unverified**, expect this failure mode: no proxy reported while the
host has one, and no error. If you see it,
[the form](https://github.com/gnoays/proxy-watch/issues/new?template=unverified-surface.yml)
asks for what the host is set to and what the crate answered; a report needs both.

## Minimum supported Rust version

**1.88**, with every feature. CI checks it on Linux x86-64
(`cargo check --all-targets --all-features`); the other targets' dependencies are not
checked against it.

## Design

- **Async-runtime agnostic:** `futures_core::Stream` on dedicated OS threads (`tokio` optional).
- **`unsafe` is confined to the code that calls the OS directly.** Windows and macOS
  backends, the iOS backend and the Core Foundation conversion it shares with macOS, the
  Android backend's JNI entry, the WinHTTP and CFNetwork PAC engines, the limits
  `pac-subprocess` puts on its worker (a memory cap through `setrlimit` on Linux and a job
  object on Windows, and the Linux seccomp filter), and the table through which
  `linux-gnome` calls GLib; the OS-independent core and the rest of the Linux backend
  contain none of their own.
- **Credentials stay masked** in `Debug`; `ProxyAuth` has no `Display`. That is the
  `user:password@` of a URL; its query prints as it is, a PAC URL's `?key=` included,
  because nothing about a query parameter says it is a secret and the PAC URL is what
  tells two configurations apart.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) has the checks CI applies and how to run them, what
`#[ignore]` means here (it marks the tests that rewrite your machine's real proxy settings)
and what the prose gates in `xtask/` require of a comment.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
