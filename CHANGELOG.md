# Changelog

Notable changes to `proxy-watch`, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the version numbers follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every entry names the minimum
supported Rust version in force for that release.

## [Unreleased]

### Routing answers that change

- macOS: an empty `ExceptionsList` array is no bypass key, so `localhost`, `127.0.0.1` and
  `::1` go to the proxy, as the Mac sends them; they were `Direct`. A list cleared in
  System Settings is stored this way.
- KDE: `ReversedException` is read as KConfig reads a bool, so `true`, the value KDE's
  settings dialog writes, inverts the list as KF5's KIO and Chromium do; the list was used
  the ordinary way round. libproxy's `config-kde`, which answers for Qt and KIO 6
  applications, ignores `true`; a warning names the values on which the two part.
- Environment (`no_proxy`, `BypassRules::new()`): link-local destinations (`169.254.0.0/16`,
  `fe80::/10`, `169.254.169.254` among them) go to the proxy unless an entry names them;
  they were `Direct`. Every `no_proxy` reader measured proxies them. Loopback is still
  bypassed.

## [0.2.0] - 2026-10-05

MSRV 1.88 with every feature; `linux-gnome` no longer raises it to 1.92. Additions to the
library's API: `Error::PacSaturated`, `pac::PacResolver` and `pac::QUICKJS_AVAILABLE`
behind `pac`, `pac::QuickJsEvaluator` behind the new `pac-quickjs` feature (not on Android
or iOS), `pac::SubprocessEvaluator` behind the new `pac-subprocess` feature,
`pac::serve_worker` behind both, `pac::CfNetworkPacResolver`, `pac::CfNetworkPacEvaluator`
and `pac::DEFAULT_CFNETWORK_PAC_TIMEOUT` behind `pac-macos-native` and `pac-ios-native`,
`pac::AndroidPacResolver` behind `pac-android-native`, `pac::NativePacResolver` behind
`pac-native` or one `pac-*-native` feature, `PacResolver::with_system_native()`, `with_wpad` / `wpad` on
`pac::WinHttpPacResolver` and `pac::CfNetworkPacResolver`,
`WinHttpPacResolver::reset_auto_proxy()` and `pac::AutoProxyReset`, `PasswordState` and
`ProxyAuth::password_state()`, `android::init` on Android, and the `ProxyConfigSource::ConnectivityManager`,
`ProxyConfigSource::CfNetworkSystemSettings` and `RejectionSource::ProxyInfo` variants,
`ImplicitBypass`, and the `BypassRules::implicit`, `BypassRules::ipv4_mapped_as_ipv4` and
`BypassRules::strip_trailing_dot` fields.

### Routing answers that change

The same machine and destination can route differently from 0.1.1. `### Changed` has the
details for each.

- Windows (`WinHttpPacResolver`): `WpadAutoDetect` is `Error::PacNotSupported` unless
  built `with_wpad(true)`; discovery ran by default.
- Windows and macOS: the rest of `127.0.0.0/8`, `*.localhost`, `localhost.` and
  IPv4-mapped loopback go to the proxy, and on macOS link-local too; they were `Direct`.
- macOS with no bypass key in the dictionary: `localhost`, `127.0.0.1` and `::1` go to the
  proxy too; they were `Direct`.
- GNOME and KDE: loopback and link-local go to the proxy unless an entry names them; they
  were `Direct`.
- Windows, GNOME and KDE: `example.com.` goes to the proxy under a list naming
  `example.com`; it was `Direct`.
- Windows and KDE: a bypass entry `example.com.` no longer bypasses `example.com`, which
  goes to the proxy; it was `Direct`.
- GNOME: an `ignore-hosts` entry GLib never matches no longer bypasses anything; those
  destinations go to the proxy, where they were `Direct`.
- Windows, macOS, GNOME and KDE: `[::ffff:10.0.0.1]` goes to the proxy under
  `10.0.0.0/8`; it was `Direct`. On GNOME and KDE, `10.0.0.1` goes to the proxy under
  `::ffff:10.0.0.0/104` too.
- KDE: a `[Proxy Settings]` header with text after its `]` is read, so the proxy it names
  applies where the read answered `Direct`; `[ Proxy Settings ]` is not read.
- macOS: an HTTPS proxy with no `HTTPSPort`, or `0`, is on port 443; it was 80.
- PAC: `PROXY p:0` from `pac::evaluate` is the keyword's default port; it was port 0.
- Environment: a variable named twice keeps its first value; the last one was kept.

### Added

- `PasswordState` and `ProxyAuth::password_state()`: why a `ProxyAuth` has no password;
  none at the source, one this crate does not read (GNOME's `authentication-password`), or
  one in the macOS keychain.
- `WinHttpPacResolver::reset_auto_proxy()`: flushes the WinHTTP autoproxy service's cached
  scripts and WPAD misses, machine-wide. A call within 30 seconds of the previous one from
  this process is not made and returns `pac::AutoProxyReset::TooSoon`.
- `pac-quickjs`: a PAC engine on QuickJS (`rquickjs`). A script still running at its timeout
  is interrupted, regular expressions included, so its thread ends with the call unless a
  host function such as `dnsResolve` has yet to return; the heap
  (64 MiB) and native stack (256 KiB) are bounded, so nesting deep enough to abort the
  process under `pac-boa` throws a JavaScript exception instead. It compiles C, so it needs
  a C compiler for the target. It is the engine `resolve_with_pac()` and `pac::evaluate` use.
  On Android and iOS the feature builds without the engine, since `rquickjs-sys` ships no
  bindings there: an app keeps one feature list across desktop and mobile, and PAC on those
  targets answers as if no engine were enabled.
- An Android backend. `read()` asks `ConnectivityManager.getDefaultProxy()` through JNI and
  reports it as the new `ProxyConfigSource::ConnectivityManager`; a field it cannot use is
  a `RejectionSource::ProxyInfo`. The crate takes the app's `JavaVM` and `Context` from
  `android::init`, or else from `ndk-context`, which `android-activity` and `tao` 0.36+
  (Tauri 2.12+) fill; a host built on an earlier `tao` calls `android::init`. The bypass list follows
  `java.net.ProxySelector`: an empty list sends even `localhost` through the proxy, and a
  non-empty one gains loopback but never link-local. `ProxyWatcher` receives the
  `PROXY_CHANGE_ACTION` broadcast through a receiver class compiled into the crate and
  loaded with `InMemoryDexClassLoader` (API 26+); below API 26, or where loading it fails,
  it polls on `WatchOptions::poll_interval` and fails to construct without one. `read()`
  has run on an API 36 x86-64 emulator with the proxy direct, manual and PAC. The watcher
  there delivered each settings change and each switch of the default network between a
  Wi-Fi with its own proxy and bypass list and mobile data, and unregistered its receiver on
  drop, registered through `ndk-context` and through `android::init` from a Tauri 2 app;
  the poll fallback has not run, and no device has run the backend.
- `pac-android-native`: `pac::AndroidPacResolver`, which resolves the `Pac` configuration
  `ConnectivityManager` reports by asking `ProxySelector.getDefault().select(uri)`, answered
  by the system PAC service. `PacResolver::with_native` takes it on Android. It errors once
  the system settings name a different PAC URL than the snapshot, and `PacPolicy` does not
  apply. Run on an API 36 x86-64 emulator against a served PAC file: the script sees the URL
  path, and `PROXY; SOCKS; DIRECT` comes back as `Http`, `Socks5`, `Direct`.
- `pac-native`, which turns on every `pac-*-native` feature; `pac::NativePacResolver`, the
  alias for this target's native resolver; and `PacResolver::with_system_native()`, which
  attaches it with its defaults (WPAD off) and returns the resolver unchanged on a target
  without one.
- `pac-ios-native`: `CfNetworkPacResolver` and `CfNetworkPacEvaluator` on iOS, the same
  CFNetwork calls `pac-macos-native` makes on macOS. WPAD resolves from the
  `CfNetworkSystemSettings` scope there. Not yet run on a device or simulator.
- An iOS backend. `read()` asks `CFNetworkCopySystemProxySettings()` and reports it as the new
  `ProxyConfigSource::CfNetworkSystemSettings`; the dictionary carries macOS's keys and is
  read the same way, rejections included (`RejectionSource::SystemConfiguration`).
  `ProxyWatcher` polls, so it needs `WatchOptions::poll_interval`; the app becoming active
  (`UIApplicationDidBecomeActiveNotification`) and a network path change (`nw_path_monitor`)
  re-read before the interval is up. `Network.framework` puts the floor at iOS 12. Run on
  an iOS simulator by a CI workflow started by hand (read, first path update, drop); not yet
  on a device.
- `pac-subprocess`: `pac::SubprocessEvaluator` runs each evaluation in a
  `proxy-watch-pac-worker` process, kills it at the timeout, and answers its name lookups
  under the caller's `PacPolicy`. On Linux (x86-64, AArch64) the worker confines itself with
  a seccomp filter before it reads the script; on other platforms it cannot, and the
  evaluator refuses it unless `allow_unsandboxed()` was called.
- `pac-macos-native`: PAC through CFNetwork on macOS. `pac::CfNetworkPacResolver` downloads
  and evaluates a PAC URL; `pac::CfNetworkPacEvaluator` evaluates a body and plugs into
  `PacResolver::with_evaluator`. Each call pumps a private run-loop mode and gives up with
  `Error::PacTimeout` at its timeout (5 s by default). `PacPolicy` does not apply.
  `CfNetworkPacResolver::with_wpad(true)` resolves `WpadAutoDetect` through the PAC URL the
  live system settings name, for a snapshot whose effective mode came from
  `SystemConfigurationState`; an unresolvable `wpad` host is Direct and every other failure
  an error. Off, WPAD is `Error::PacNotSupported`, where other clients on the same Mac run
  `http://wpad/wpad.dat` as an ordinary PAC URL. `PacResolver::with_native` takes the
  CFNetwork resolver on macOS. CFNetwork cuts the URL the
  script sees to its scheme and host, and drops `HTTPS` and `SOCKS5` entries from its answer,
  so `SOCKS5 s:1080; DIRECT` comes back as `DIRECT`. An IPv6 literal proxy
  (`PROXY [2001:db8::1]:3128`) arrives cut at its first colon and is dropped the same way.

### Changed

- **Breaking:** `WinHttpPacResolver` no longer runs WPAD discovery by default. Build it
  `with_wpad(true)` to keep 0.1's behaviour; without it, `WpadAutoDetect` with a host and an
  explicit `resolve(url, &WinHttpPacSource::AutoDetect)` or `AutoDetectThenUrl` return
  `Error::PacNotSupported { mode: "wpad" }`. Discovery lets whoever answers for `wpad` on
  the local network choose the proxy. `cargo semver-checks` does not report this change.
- `linux-gnome` opens GLib at run time instead of linking it through `gio`/`glib`. A build
  needs no GLib headers and no `pkg-config`, so the default features cross-compile, musl
  included. A binary started where GLib is absent treats GNOME's store as not installed
  and reads the others; inside a sandbox, where the portal was the only route, that is
  `Error::Sandboxed`.
- PAC evaluation runs at most as many threads at once as the machine has cores (at least
  4), process-wide, counting QuickJS evaluations and `pac-subprocess` conversations alike. QuickJS interrupts a script at its deadline, so a thread outlives
  its timed-out call only while a host function such as `dnsResolve` has yet to return; a
  call that finds every slot taken waits within its timeout and then returns the new
  `Error::PacSaturated`. Lookups stuck in slow DNS therefore hold a bounded number of
  threads instead of one more per call, at the price of PAC answering `PacSaturated` for
  everyone once the slots are held.
- An environment that names a variable twice keeps the first value, as `getenv` answers
  (and with it `std::env::var_os`, curl, Python and Node); the last one was kept. The C
  binding's `pw_context_open_with_env` follows the same rule.
- KDE: `kioslaverc` group headers and entry flags are read as KConfig reads them. Text
  after a header's `]` no longer hides `[Proxy Settings]` (the section was lost and the read
  answered `Direct`); padding inside the brackets is part of the name, so `[ Proxy Settings ]`
  is not the section; `[$di]` is a plain deletion and `[$id]` an immutable one; and a
  deletion of a key no layer set still leaves a tombstone.
- GNOME: `ignore-hosts` is sorted the way GLib's `GSimpleProxyResolver` sorts it, and an
  entry GLib never matches is refused (listed in `rejected`) rather than read as a live
  rule: a bracketed address with no port, a mask with bits past its prefix or a leading
  zero, non-ASCII text, a trailing dot, a short or octal IPv4 spelling, trailing non-ASCII
  whitespace, and every name after one that leaves no name (`""`, `.`, `*.`), where GLib's
  matcher stops. An IPv4-mapped mask is no longer folded into its IPv4 block. Each of
  these answered `Direct` for a destination GNOME sends to the proxy. `<local>` and
  `<-loopback>` are refused there too, since GLib reads each as a host name. What still
  differs is a destination with a trailing dot.
- The implicit bypass, what goes direct with no entry naming it, is now the source's
  own, in the new `BypassRules::implicit` (`ImplicitBypass`). Windows carries WinINet's
  set (`localhost`, `loopback`, `127.0.0.1`, `::1`, `169.254/16`, `fe80::/10`), macOS
  and iOS carry CFNetwork's (`localhost`, `127.0.0.1`, `::1`) while the dictionary has a
  bypass key and none without one, as CFNetwork does, and GNOME (GSettings and the portal)
  and KDE carry none, as GLib and KIO have none. One broad set applied to every source answered `Direct`
  for the rest of `127.0.0.0/8`, `*.localhost`, `localhost.` and IPv4-mapped loopback on
  Windows and macOS, link-local on macOS, and all of loopback and link-local on GNOME and
  KDE, each a destination the machine sends to the proxy. The Windows and macOS sets are
  measured against WinINet and CFNetwork. `no_proxy` keeps the broad set.
- A destination's trailing dot (`example.com.`) is kept when it meets a Windows, GNOME,
  KDE or Android list, the way those resolvers compare it, under the new
  `BypassRules::strip_trailing_dot`: WinINet sent `localhost.` to the proxy under a list
  naming `localhost`, and GLib, KIO and Android compare the text. Shedding it answered
  `Direct` for those destinations. `no_proxy` keeps shedding it, and so do macOS and iOS,
  where CFNetwork was measured shedding it on the destination and on the entry.
- A store's bypass entry that ends in a dot (`example.com.`) is refused into `rejected`
  on Windows, KDE and Android, as on GNOME; it was stored as `example.com` and
  bypassed the undotted name, which KIO and Android's selector proxy. KDE's `NoProxyFor`,
  including the variable `ProxyType = 4` names, is read in its own dialect for this.
- `ProxyEndpoint::parse` refuses a value with an `@` after a `/`, `?` or `#`, such as
  `http://bob:123/x@proxy.example:8080`: it resolved to the host `bob` and port 123 from
  the start of an unencoded password, where a password that was not all digits already
  failed.
- PAC: `PROXY p:0` from the in-process engines is the keyword's default port, as the
  WinHTTP and CFNetwork engines read it, and a WinHTTP wait that fails is `Error::Io` and
  not `PacTimeout`.
- GNOME and KDE: an IPv4-mapped destination (`[::ffff:10.0.0.1]`) is compared as the IPv6
  address it is, as GLib and Qt compare it, so `10.0.0.0/8` no longer bypasses it there
  (and on Windows, macOS and Android, whose explicit-entry reading is unmeasured or a
  string compare),
  and a block written `::ffff:10.0.0.0/104` no longer bypasses `10.0.0.1`. The new
  `BypassRules::ipv4_mapped_as_ipv4` holds the switch. `HostPattern::parse` keeps a
  mapped-spelling block as written; matching reads it as the IPv4 block while the switch
  is set.
- GNOME in a sandbox: the portal's `ftp://host:port` answer for the `ftp` setting is read
  as the HTTP proxy it is, as the GSettings path reads it; it failed the whole read.
- macOS: an HTTPS proxy with no `HTTPSPort`, or `0`, is on port 443, the port
  `SCDynamicStoreCopyProxies` fills in and Chromium and libproxy therefore use; it was 80.

### Removed

- **Breaking:** the `pac-boa` feature and `pac::BoaEvaluator`. Boa could not stop a running
  script, and deep nesting in one aborted the process; use `pac-quickjs`, or
  `pac-subprocess` for a script the process does not trust.
- **Breaking:** `PacPolicy::with_max_loop_iterations`, `with_recursion_limit`,
  `with_stack_size_limit`, their getters, and `pac::DEFAULT_PAC_LOOP_LIMIT`,
  `DEFAULT_PAC_RECURSION_LIMIT` and `DEFAULT_PAC_STACK_SIZE_LIMIT`. They configured Boa
  only; QuickJS bounds a script by its timeout, heap and stack.

## [0.1.1] - 2026-09-20

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
  `kioslaverc` or the XDG desktop portal, whichever the desktop and the sandbox make
  available. None of them reads `http_proxy`: the environment is a second snapshot,
  `ProxyEnv::from_env()`, and `ProxyConfig::with_env` merges the two under an
  `EnvPrecedence` the caller names.
- `ProxyConfig::effective` is the merged answer. `sources` keeps each store that replied
  next to its own `ProxyConfigSource`, and `fallbacks` names a store the machine may well
  be configured with whose value this read did not learn, the case `sources` alone cannot
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
- `parse` exposes the platform parsers on their own (`proxy_server`, `proxy_override`,
  `no_proxy`, `windows_manual`) for code that already holds a raw settings string.

### Known limits at this version

- Windows reports whichever connection is currently active, not every connection
  configured.
- macOS sees the proxies key `configd` derives from the primary network service, so a
  proxy set on a service that is not primary does not appear. That is also the one key
  `SCDynamicStoreCopyProxies` reads, and what every reader built on it sees.
- The macOS backend has run on CI runners only, never on Mac hardware.
- `tracing` is off by default, so the library picks no logging facade on a dependent's
  behalf; a consumer that wants the lifecycle and change logs turns the feature on.

[Unreleased]: https://github.com/gnoays/proxy-watch/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/gnoays/proxy-watch/releases/tag/v0.2.0
[0.1.1]: https://github.com/gnoays/proxy-watch/releases/tag/v0.1.1
[0.1.0]: https://github.com/gnoays/proxy-watch/releases/tag/v0.1.0
