# Changelog

Notable changes to `proxy-watch`, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the version numbers follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every entry names the minimum
supported Rust version in force for that release.

## [Unreleased]

MSRV unchanged: 1.88, and 1.92 with `linux-gnome`. No change to the library's API.

### Changed

- `examples/reqwest_client.rs` reads `ProxyEnv` once at start-up and merges it into each
  snapshot as it arrives, instead of re-scanning the environment inside the `Proxy::custom`
  closure; `ProxyEnv::from_env()` failing is now a start-up error rather than a silent
  fall-back to the OS snapshot. The watch thread reports `WatchEvent::Error` on stderr
  instead of dropping it, and the module doc says what `reqwest` actually does with the
  closure: called on connection to route, and twice more per plaintext request for
  headers, never to re-route.
- The README's watch example and `examples/watch.rs` drive the stream with
  `StreamExt::next()` and `block_on` instead of a hand-written `poll_fn` over `poll_next`.
  `futures-util` joins the dev-dependencies for that; consumers see no new dependency.

## [0.1.0] - 2026-09-07

Initial release. MSRV 1.88, which the `linux-gnome` feature raises to 1.92.

### Reading

- `read()` returns the operating system's current proxy configuration as a `ProxyConfig`;
  `read_with_options()` takes the same `WatchOptions` the watcher does. Neither starts a
  thread, and neither registers a change notification.
- Windows reads the active connection through WinHTTP and the registry, macOS reads the
  global proxies key out of `SCDynamicStore`, and Linux reads GNOME's GSettings, KDE's
  `kioslaverc` or the XDG desktop portal — whichever the desktop and the sandbox make
  available. None of them reads `http_proxy`: the environment is a second snapshot,
  `ProxyEnv::from_env()`, and `ProxyConfig::with_env` merges the two under an
  `EnvPrecedence` the caller names.
- `ProxyConfig::effective` is the merged answer. `sources` keeps each store that replied
  next to its own `ProxyConfigSource`, and `fallbacks` names a store the machine may well
  be configured with whose value this read did not learn — the case `sources` alone cannot
  express. `ProxyMode::rejected()` carries what was read and refused, with a
  `RejectionKind` saying why.

### Watching

- `ProxyWatcher` delivers each change as a `Stream` item, preferring the operating
  system's own notification API: `RegNotifyChangeKeyValue`, `SCDynamicStore`, GSettings
  signals, a `kioslaverc` file watch. A sandboxed Linux portal offers no signal at all, so
  `WatchOptions::poll_interval` is what makes the stream live there.
- `WatchHealth` and `WatchState` report which sources are still armed. A source whose
  notification route cannot be re-armed is retired and named in `fallbacks`, and the
  watcher goes on delivering the sources that remain.
- `watch_channel()` (feature `tokio`) hands the same stream over as a
  `tokio::sync::watch::Receiver<ProxyConfig>`.

### Routing

- `resolve()` (feature `resolve`, on by default) turns a configuration and a target `Url`
  into the ordered `ProxyStep`s to try, bypass rules applied. `resolve_with_pac()` does
  the same with a PAC evaluator in hand.
- `BypassRules` implements the platform bypass syntaxes: the `<local>` and `<-loopback>`
  tokens Windows spells, and the CIDR, leading-dot and suffix forms the environment
  variables use.
- `pac` adds `PacScript` and the `PacEvaluator` trait. `pac-boa` supplies a portable
  engine, `pac-windows-native` hands evaluation to WinHTTP.
- `parse` exposes the platform parsers on their own — `proxy_server`, `proxy_override`,
  `no_proxy`, `windows_manual` — for code that already holds a raw settings string.

### Known limits at this version

- Windows reports whichever connection is currently active, not every connection
  configured.
- macOS sees the proxies key `configd` derives from the primary network service, so a
  proxy set on a service that is not primary does not appear. That is also the one key
  `SCDynamicStoreCopyProxies` reads, and what every reader built on it sees.
- The macOS backend has run on CI runners only, never on Mac hardware.
- `tracing` is off by default, so the library picks no logging facade on a dependent's
  behalf; a consumer that wants the lifecycle and change logs turns the feature on.

[Unreleased]: https://github.com/gnoays/proxy-watch/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gnoays/proxy-watch/releases/tag/v0.1.0
