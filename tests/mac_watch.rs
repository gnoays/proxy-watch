//! macOS watch backend smoke test.
//!
//! # Why this file has to exist
//!
//! The macOS backend (`src/sys/mac/`) has **no development hardware behind it at
//! all** — see the CI-verified-only warning at the top of `src/sys/mac/mod.rs` and
//! `src/sys/mac/notify.rs` (named, not quoted: a quoted heading here has gone stale
//! twice already). Every claim about its runtime
//! behaviour — that `SCDynamicStoreCreateWithOptions` succeeds, that
//! `SCDynamicStoreSetNotificationKeys` actually registers, that the run loop thread
//! reports itself ready — was derived from Apple's documentation and from reading the
//! `system-configuration` / `core-foundation` crates, never from watching it run. The
//! `macos-latest` GitHub Actions runner is therefore the **only** place this backend is
//! ever executed, which makes it the only place these claims can be falsified.
//!
//! `tests/tracing.rs` builds a `ProxyWatcher` too, but it is written to accept a
//! construction failure — that early return exists so the *same* test also passes on
//! Linux with both `linux-gnome` and `linux-kde` off, where `ProxyWatcher::new()`
//! legitimately returns `Error::Unsupported`. On macOS that same permissiveness would
//! hide exactly the failure this file exists to catch: if `SCDynamicStoreBuilder::build`
//! returned `None`, or `set_notification_keys` failed, `tracing.rs` would quietly treat
//! it as "nothing to watch here" and CI would stay green.
//!
//! So this file's whole job is the opposite: to **insist** that construction, the first
//! snapshot, and `Drop` all succeed, and to fail loudly — turning CI red — the moment any
//! of them does not.
//!
//! # What is deliberately *not* asserted
//!
//! The CI runner's actual proxy configuration is unknown and out of this crate's
//! control — a `macos-latest` image is not guaranteed to be `Direct` any more than the
//! Windows runners were guaranteed to have WPAD auto-detection off. Asserting anything
//! about `ProxyConfig`'s *contents* (`effective`, which `sources` are present, …) would
//! make this file's pass/fail depend on GitHub's fleet configuration rather than on the
//! backend actually working, so the assertions below stop at "a watcher was built", "a
//! snapshot arrived" and "dropping it did not hang".
//!
//! # Proving the notification actually fires
//!
//! Every claim above is static: a watcher can be *built*, and *a* snapshot arrives at
//! subscription time. Nothing in this crate's history had ever shown that a *change* to
//! the real configuration is actually seen — because nothing had tried to mutate the
//! macOS proxy setting and watch for the resulting notification. `networksetup(8)` is
//! the only documented way to write the setting without going through System
//! Preferences by hand, and whether a GitHub Actions runner would even let such a write
//! through was not something any written source could confirm — so the question was
//! settled empirically on a `macos-26-arm64` runner (macOS 26.4), by the same
//! `sudo networksetup` writes the standing test below still performs:
//!
//! * `networksetup -listallnetworkservices` lists a real, non-empty service
//!   (`Ethernet`) — there is something to configure at all;
//! * `sudo networksetup -setwebproxy Ethernet 127.0.0.1 8080` succeeds, and the very
//!   next `scutil --proxy` shows `HTTPEnable : 1` / `HTTPProxy : 127.0.0.1` /
//!   `HTTPPort : 8080` — the write reaches the dynamic store the backend reads;
//! * writing `State:/Network/Global/Proxies` directly through a non-root `scutil`
//!   session is refused with `Permission denied` — so `sudo networksetup` is not merely
//!   *a* way to change the setting for a test, it is the *only* way available to a
//!   process that is not already root, which is exactly this test's situation.
//!
//! The test below (`a_sudo_networksetup_change_is_observed`) turns that finding into a
//! standing assertion: it runs `sudo networksetup -setwebproxy` against whatever real
//! network service the runner has, and requires the already-running [`ProxyWatcher`] to
//! emit a changed [`ProxyConfig`] that mentions the host/port just set. If it passes,
//! that is end-to-end proof — the only kind this backend has ever had — that
//! `SCDynamicStoreSetNotificationKeys` really fires in a headless CI session, not just
//! according to Apple's documentation.
//!
//! ## Safety: this test can also run on a developer's own Mac
//!
//! Unlike the two tests above, this one changes a **real** system setting, so it guards
//! itself the way `tests/windows_watch.rs`'s registry tests and `tests/linux_watch.rs`'s
//! Flatpak test do:
//!
//! * it self-skips unless `CI` is set *and* `sudo -n true` succeeds. Passwordless sudo
//!   alone is not enough of a gate, on the reading that CI has it and a developer
//!   machine does not — that is a habit, not a property: provisioning `NOPASSWD` for
//!   one's own account is a common convenience, and on such a Mac a sudo-only gate lets a
//!   plain `cargo test` write a real proxy into a real network service with only
//!   best-effort restoration behind it. `CI` is what the rest of this suite already treats as authoritative for
//!   where a test belongs (`support::skip_or_fail`), so it decides this too; sudo stays
//!   as the second condition because CI without it cannot do the write either;
//! * it refuses to write at all unless `networksetup -getwebproxy` printed the whole
//!   `Enabled`/`Server`/`Port` trio the restoration is rebuilt from. A missing key used
//!   to fall back to `false` / `""` / `0`, which is exactly what an unconfigured service
//!   looks like — so an output format this no longer parses would have restored an
//!   *enabled* proxy as off, and called that success;
//! * it never assumes which network service exists, or what its web proxy was set to
//!   before the test ran (Windows' WPAD-auto-detect-on runners are the standing
//!   reminder of why guessing a baseline is unsafe — see `tests/windows_watch.rs`'s
//!   `RegistryGuard::force_wpad_auto_detect_off`): the service name comes from
//!   `networksetup -listallnetworkservices`, and the original `-getwebproxy` output for
//!   it is captured and restored by a `Drop` guard that runs even if the test panics;
//! * that `Drop` guard never panics itself, even when a restoration command fails —
//!   panicking during unwind, with the test body's own panic already in flight, would
//!   abort the process before the remaining restoration commands ran, so each step is
//!   attempted independently and a failure is only logged.
//!
//! ## Serialisation
//!
//! Like `tests/windows_watch.rs` and `tests/linux_watch.rs`, this file's tests share
//! state wider than the process — here, the real network service's web proxy setting —
//! so the whole suite must run with `cargo test -- --test-threads=1`, which is already
//! how CI invokes every OS's integration tests (`.github/workflows/ci.yml`).
#![cfg(target_os = "macos")]

mod support;

use std::process::Command;
use std::time::{Duration, Instant};

use proxy_watch::{ProxyConfig, ProxyConfigSource, ProxyMode, ProxyWatcher, Scheme};

use support::{expect_config, skip_or_fail};

// --------------------------------------------------------------------------------
// tests
// --------------------------------------------------------------------------------

/// The core assertion this file exists for: the `SCDynamicStore` backend actually
/// starts, delivers the "current configuration once at subscription time" contract,
/// and `Drop` (`stop` → `wake.signal` → `join`, see `src/sys/mac/notify.rs`) does not
/// hang.
///
/// Every `expect` message below names the specific step it covers, because
/// `ProxyWatcher::new()` folds three very different possible failures — creating the
/// `SCDynamicStore` session, registering the notification keys on it, and the first
/// blocking read — into one `Result`; see `Watch::armed`, `Registration::new` and
/// `read_config` in `src/sys/mac/`.
#[test]
fn the_backend_starts_and_stops_cleanly() {
    let mut watcher = ProxyWatcher::new().expect(
        "ProxyWatcher::new() failed on macOS: either SCDynamicStoreCreateWithOptions \
         returned NULL (Watch::armed / create_store in src/sys/mac/mod.rs and \
         src/sys/mac/notify.rs), SCDynamicStoreSetNotificationKeys failed to register the \
         Setup:/State: Network/Global/Proxies keys (Registration::new in \
         src/sys/mac/notify.rs), or the watcher thread never reported itself ready \
         (Watch::spawn's ready_rx.recv() in src/sys/mac/notify.rs) — see the attached \
         error for which one",
    );

    // On this ordinary, non-degraded path (the only one CI can force — see
    // `tests/mac_configd_denied.rs` module doc, "What it can prove", on why the
    // retry/degrade path itself cannot be exercised from a test), `Watch::health` must report both SCDynamicStore
    // scopes as live: no retry was needed, so `Registration::new` never took the
    // `WatchFailSoft::Degraded` branch that would otherwise mark
    // `SystemConfigurationSetup`/`SystemConfigurationState` as degraded.
    assert!(
        watcher.health().is_fully_live(),
        "a freshly constructed macOS watcher should report every notification route as \
         live when SCDynamicStore registration succeeded on the first attempt: {:?}",
        watcher.health()
    );

    // Subscribing must deliver the current configuration once, and `current()` must
    // then agree with what the stream just handed out. Deliberately nothing is asserted
    // about the snapshot's contents — see the module doc.
    let first = expect_config(&mut watcher, Duration::from_secs(5));
    assert_eq!(
        first,
        watcher.current(),
        "the first item off the stream must match ProxyWatcher::current()"
    );

    // Drop must return promptly. If `Watch::drop`'s stop/signal/join sequence in
    // src/sys/mac/notify.rs does not actually reach the parked run loop
    // thread, this call blocks forever and the test times out instead of failing
    // cleanly — which is still a red CI job, just a slower and less legible one. The
    // bound below turns that into an ordinary, fast assertion failure instead.
    let started = Instant::now();
    drop(watcher);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "dropping the watcher took {elapsed:?}; the SCDynamicStore watcher thread is not \
         stopping promptly (see the `Stop:` note in src/sys/mac/notify.rs's module doc)"
    );

    // The process is still alive and responsive after the drop, which is what makes the
    // elapsed-time assertion above non-vacuous rather than merely unreached.
    println!("watcher dropped cleanly after {elapsed:?}");
}

/// Informational only: which of `Setup:` / `State:` (see the source-priority rule in the
/// module doc of `src/sys/mac/mod.rs`) the CI runner's configuration actually populates.
///
/// This is not something the backend controls — Apple's own IPMonitor is not confirmed
/// to ever populate a *global* `Setup:` proxies key at all (the same module doc says so:
/// "may not exist at all") — so nothing here is
/// asserted. It only exists to leave a record, in the CI log, of what a real
/// `macos-latest` runner's `SCDynamicStore` looks like, which is the only piece of
/// ground truth this backend has ever had. Run with `--nocapture` to see it.
#[test]
fn logs_which_scope_the_configuration_came_from() {
    let watcher = match ProxyWatcher::new() {
        Ok(watcher) => watcher,
        Err(error) => {
            // The other test already turns CI red for this; here it is just noted.
            println!("SKIPPED: ProxyWatcher::new() failed: {error}");
            return;
        }
    };

    let config = watcher.current();
    let has_setup = config
        .source(ProxyConfigSource::SystemConfigurationSetup)
        .is_some();
    let has_state = config
        .source(ProxyConfigSource::SystemConfigurationState)
        .is_some();
    println!(
        "macOS SCDynamicStore scopes on this runner: Setup:={has_setup} State:={has_state} \
         sources={:?}",
        config.sources
    );
}

/// The payoff of this whole file: change the **real** web proxy setting through
/// `sudo networksetup`, and require the already-running watcher to notice.
///
/// See the module doc's "Proving the notification actually fires" section for why
/// `sudo networksetup` is the only available way to do this, and its "Safety" section
/// for the self-skip and restoration guarantees this test relies on — both are load
/// bearing, so read them before changing anything here.
///
/// The sequence is the same shape every other backend's "a change is emitted" test
/// uses (`tests/windows_watch.rs::a_registry_change_is_emitted_exactly_once`,
/// `tests/linux_watch.rs::a_kioslaverc_change_is_emitted_exactly_once`): subscribe, take
/// the first (current-configuration) snapshot, make exactly one change, wait for the
/// next snapshot. What is deliberately *not* done, unlike those two, is asserting
/// anything about `effective`'s exact shape: `networksetup -setwebproxy` is only known
/// (from the empirical CI probe) to update the `State:` scope, and the source-priority
/// rule makes `effective` the `State:` scope whenever it exists at all — which on
/// this runner's real configuration is outside this test's control. So the assertion
/// below only checks that the host/port just set show up *somewhere* in the emitted
/// snapshot (`effective` or any entry of `sources`), which is true under either merge
/// outcome.
#[test]
fn a_sudo_networksetup_change_is_observed() {
    // Asked before the sudo probe, and separately from it: `sudo -n true` answers "could
    // this machine make the change", never "should it". A developer who provisioned
    // passwordless sudo for their own convenience answered yes to the first question and
    // no to the second, and only the first was being read.
    if std::env::var_os("CI").is_none() {
        eprintln!(
            "SKIPPED: not running under CI, so this test will not change a real network \
             service's web proxy; set CI=1 to opt a machine in to that"
        );
        return;
    }
    if !passwordless_sudo_available() {
        skip_or_fail(
            "passwordless sudo is not available (`sudo -n true` failed); this test only \
             runs where `sudo networksetup` needs no password, which in practice means \
             CI, never a developer's own machine — see the module doc's \"Safety\" \
             section",
        );
        return;
    }

    let services = network_services();
    let Some(service) = pick_service(&services) else {
        skip_or_fail(
            "`networksetup -listallnetworkservices` reported no configurable network \
             service on this machine",
        );
        return;
    };
    println!("using network service {service:?} (of {services:?})");

    // Captured, and drop-time restoration armed, before anything else has a chance to
    // fail: even if `ProxyWatcher::new()` or the first `expect_config` below panics,
    // `guard` is already a local and its `Drop` still runs during unwind.
    let guard = WebProxyGuard::capture(service.clone());

    let mut watcher = ProxyWatcher::new().expect("watcher");
    let _initial = expect_config(&mut watcher, Duration::from_secs(5));

    guard.set(TEST_HOST, TEST_PORT);

    let changed = expect_config(&mut watcher, Duration::from_secs(10));
    assert!(
        config_mentions_http_proxy(&changed, TEST_HOST, TEST_PORT),
        "after `sudo networksetup -setwebproxy {service} {TEST_HOST} {TEST_PORT}`, the \
         emitted configuration must show that host/port somewhere — effective or a \
         source — got effective={:?} sources={:?}",
        changed.effective,
        changed.sources
    );

    println!(
        "SCDynamicStore watcher observed the sudo networksetup change: effective={:?} \
         sources={:?}",
        changed.effective, changed.sources
    );
}

// --------------------------------------------------------------------------------
// live web proxy fixture
// --------------------------------------------------------------------------------

/// A host:port pair no real machine proxies through, distinct from the `18080` the
/// Windows and Linux fixtures already use, so a leftover value from either of those
/// suites is never mistaken for this one's.
const TEST_HOST: &str = "127.0.0.1";
const TEST_PORT: u16 = 28080;

/// Whether `sudo` can run a command without prompting for a password.
///
/// `-n` ("non-interactive") makes `sudo` fail immediately, rather than block on a
/// prompt, when it would otherwise have to ask — which is exactly the distinction
/// between a CI runner (passwordless sudo provisioned) and a developer's own Mac (it
/// almost certainly is not) that this test must tell apart before touching anything.
fn passwordless_sudo_available() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .is_ok_and(|status| status.success())
}

/// Every line `networksetup -listallnetworkservices` prints after its leading
/// explanatory header ("An asterisk (*) denotes that a network service is disabled."),
/// trimmed. A service name may itself carry a leading `*` when that service is
/// currently disabled; that marker is preserved here and stripped later, in
/// [`pick_service`], because whether a service is disabled is exactly what
/// [`pick_service`] uses to choose between candidates.
fn network_services() -> Vec<String> {
    let output = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .expect("running networksetup -listallnetworkservices");
    assert!(
        output.status.success(),
        "networksetup -listallnetworkservices failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Choose which service to test against, never hardcoded — whatever real network
/// service the CI runner happens to have must work: an
/// enabled service (no leading `*`) is preferred, since a *disabled* service's proxy
/// settings are not guaranteed to reach the primary-service-derived global `State:`
/// dictionary the backend reads — falling back to the first service at all, `*` stripped,
/// only when every one of them is disabled.
fn pick_service(services: &[String]) -> Option<String> {
    services
        .iter()
        .find(|name| !name.starts_with('*'))
        .or_else(|| services.first())
        .map(|name| name.trim_start_matches('*').trim().to_owned())
}

/// The three fields `networksetup -getwebproxy <service>` prints, parsed from its
/// documented `Key: value` lines (`Enabled`, `Server`, `Port`; a fourth line,
/// `Authenticated Proxy Enabled`, is not needed here and ignored). Confirmed against the
/// empirical CI probe's own use of this command (see the module doc).
#[derive(Debug, Clone, PartialEq, Eq)]
struct WebProxyState {
    enabled: bool,
    server: String,
    port: u16,
}

/// Read the current web proxy setting of `service` through `networksetup -getwebproxy`,
/// which needs no privileges — only `-setwebproxy*` writes do.
fn get_web_proxy(service: &str) -> WebProxyState {
    let output = Command::new("networksetup")
        .args(["-getwebproxy", service])
        .output()
        .expect("running networksetup -getwebproxy");
    assert!(
        output.status.success(),
        "networksetup -getwebproxy {service} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Every field is required rather than defaulted. This state is the whole of what
    // `WebProxyGuard` restores from, and defaulting a missing key — to `false` / `""` / `0`
    // — spells "this service had no web proxy", which sends `Drop` down its
    // `-setwebproxystate off` branch. An output this cannot parse would therefore switch a
    // live proxy off and report nothing. Failing here costs a red run
    // on a machine that is still exactly as it was, because no write has happened yet.
    let text = String::from_utf8_lossy(&output.stdout);
    let mut enabled = None;
    let mut server = None;
    let mut port = None;
    for line in text.lines() {
        // First colon only: a `Server` may be an IPv6 literal and carry more of them.
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Enabled" => enabled = Some(value.eq_ignore_ascii_case("yes")),
            "Server" => server = Some(value.to_owned()),
            "Port" => port = Some(value.parse::<u16>()),
            _ => {}
        }
    }
    match (enabled, server, port) {
        (Some(enabled), Some(server), Some(Ok(port))) => WebProxyState {
            enabled,
            server,
            port,
        },
        _ => panic!(
            "networksetup -getwebproxy {service} did not print the Enabled/Server/Port \
             trio this test restores from, so nothing has been changed. Output was:\n{text}"
        ),
    }
}

/// Run a `sudo networksetup` mutation and panic loudly if it fails. Used only for the
/// change under test — never from [`WebProxyGuard`]'s `Drop`, which must not panic; see
/// [`try_sudo_networksetup`].
fn sudo_networksetup(args: &[&str]) {
    let output = Command::new("sudo")
        .arg("networksetup")
        .args(args)
        .output()
        .expect("running sudo networksetup");
    assert!(
        output.status.success(),
        "sudo networksetup {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// [`sudo_networksetup`], but reporting failure with `eprintln!` instead of panicking.
///
/// Restoration in [`WebProxyGuard`]'s `Drop` must never panic: `Drop` also runs while a
/// test-body panic is already unwinding, and a second panic during an unwind aborts the
/// process before any later restoration step gets a chance to run. Logging instead lets
/// every step in `Drop` still be attempted even if an earlier one failed.
fn try_sudo_networksetup(args: &[&str]) {
    match Command::new("sudo").arg("networksetup").args(args).output() {
        Ok(output) if output.status.success() => {}
        Ok(output) => eprintln!(
            "WARNING: restoring the web proxy setting failed: sudo networksetup {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => eprintln!(
            "WARNING: restoring the web proxy setting failed: could not run sudo \
             networksetup {args:?}: {error}"
        ),
    }
}

/// Snapshots `service`'s web proxy setting on construction and restores it on `Drop`,
/// panic or not.
struct WebProxyGuard {
    service: String,
    original: WebProxyState,
}

impl WebProxyGuard {
    /// Read and remember `service`'s current web proxy setting. `-getwebproxy` needs no
    /// privileges, so no elevated call has happened yet when this returns: the first one
    /// is [`WebProxyGuard::set`], by which point the restoration this captures is armed.
    fn capture(service: String) -> Self {
        let original = get_web_proxy(&service);
        Self { service, original }
    }

    /// The change under test: point `service`'s web proxy at `host:port`, enabling it in
    /// the same call (`networksetup -setwebproxy` always turns the service's web proxy
    /// on, which is why [`WebProxyGuard::drop`] restores the enabled flag separately
    /// when the original setting was off).
    fn set(&self, host: &str, port: u16) {
        sudo_networksetup(&["-setwebproxy", &self.service, host, &port.to_string()]);
    }
}

impl Drop for WebProxyGuard {
    /// Best-effort restoration — see [`try_sudo_networksetup`] for why this never
    /// panics.
    ///
    /// `networksetup` has no "clear the configured host" verb, only a way to turn the
    /// web proxy off while leaving its last host/port in place; when the original
    /// `Server` was already empty (this service's web proxy had never been configured),
    /// the closest reachable approximation is to leave this test's host/port behind but
    /// force the enabled state back off, which is the same externally visible shape
    /// ("web proxy off") the service had before this test touched it.
    fn drop(&mut self) {
        if self.original.server.is_empty() {
            try_sudo_networksetup(&["-setwebproxystate", &self.service, "off"]);
        } else {
            try_sudo_networksetup(&[
                "-setwebproxy",
                &self.service,
                &self.original.server,
                &self.original.port.to_string(),
            ]);
            if !self.original.enabled {
                try_sudo_networksetup(&["-setwebproxystate", &self.service, "off"]);
            }
        }
    }
}

/// Whether `config` — either its `effective` mode or any of its `sources` — shows an
/// HTTP proxy entry pointing at `host:port`. Matches the documented mapping
/// (`src/lib.rs`'s table: macOS `HTTPEnable`/`HTTPProxy`/`HTTPPort` become a `Manual`
/// entry under [`Scheme::Http`]), which is what `networksetup -setwebproxy` sets.
fn config_mentions_http_proxy(config: &ProxyConfig, host: &str, port: u16) -> bool {
    let expected = format!("{host}:{port}");
    let mentions = |mode: &ProxyMode| {
        mode.endpoint_for(Scheme::Http)
            .is_some_and(|endpoint| endpoint.authority() == expected)
    };
    mentions(&config.effective) || config.sources.iter().any(|(_, mode)| mentions(mode))
}
