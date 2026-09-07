//! Regression tests: a static proxy configured underneath auto-detect must never be
//! silently discarded (`pac-windows-native`).
//!
//! ```text
//! cargo test --features pac-windows-native --test pac_winhttp_registry -- --ignored
//! ```
//!
//! The `--ignored` is not optional: every test here is `#[ignore]` so that a developer's
//! plain `cargo test` never rewrites their own `Internet Settings`. CI runs them on a
//! throwaway `windows-latest` runner via `--include-ignored`. The full rationale is in
//! `tests/windows_watch.rs`'s module doc, which makes the same choice for the same
//! reason.
//!
//! # Why these tests are a test binary of their own
//!
//! Like `tests/windows_watch.rs`, they patch the developer's *real*
//! `HKCU\...\Internet Settings`, because that is the only way to exercise
//! [`resolve_config`](proxy_watch::pac::WinHttpPacResolver::resolve_config)'s
//! WPAD-fallback path: it re-reads the machine's own configuration through WinHTTP, so a
//! fixture has to be machine-wide. [`StaticProxyUnderAutoDetect`] restores every value
//! it touches, and [`REGISTRY_LOCK`] keeps the fixtures here from overwriting each
//! other's state — but neither can hide the fixture from *other* code running at the
//! same time, and a machine-wide proxy configuration is visible to every WinHTTP call in
//! the process.
//!
//! That is not hypothetical. A fixture installed here reaches tests that never touch the
//! registry: beside these at the end of `tests/pac_winhttp.rs`,
//! `a_pac_url_with_nothing_listening_fails_promptly` expects a refused connection and
//! instead spends its whole 3-second budget and reports `PacTimeout`.
//!
//! Cargo runs each `tests/*.rs` target's binary one at a time, so giving them their own
//! file is what actually isolates them: nothing else in the suite runs while a fixture
//! from this file is installed. `tests/windows_watch.rs` is a separate binary for the same
//! reason. Do not move either set back in beside the tests it poisons. A plain
//! `cargo test` is green because it skips everything below; for the runs that do execute
//! them, [`REGISTRY_LOCK`] is what keeps them honest rather than `--test-threads=1`, and
//! only for the tests inside *this* binary. CI still passes the flag on every OS, because
//! the Linux integration tests need it for an unrelated reason — process-global
//! environment variables and PID-keyed fixture directories; see `tests/linux_watch.rs`.
//!
//! # These tests must pass on a machine with no proxy at all
//!
//! Every fixture below is written by this file and removed again on the way out, and the
//! addresses it configures are RFC 5737 / RFC 6890 literals that are guaranteed not to
//! be routed anywhere. The live WPAD probe underneath them accepts whatever this
//! machine's network says: whether DHCP option 252 or a `wpad.<domain>` record exists is
//! a property of the network, not of this crate.

#![cfg(all(windows, feature = "pac-windows-native"))]

mod support;

use std::time::Duration;

use proxy_watch::pac::WinHttpPacResolver;
use proxy_watch::{Error, ProxyConfig, ProxyConfigSource, ProxyMode, ProxyStep, Url};

use support::skip_or_fail;

/// Long enough that the WPAD probe underneath each fixture is never mistaken for a hang,
/// short enough that a blackholed address does not stall the suite. Same value as
/// `GIVE_UP_BUDGET` in `tests/pac_winhttp.rs` (not that file's success-path `BUDGET`).
const BUDGET: Duration = Duration::from_secs(3);

/// The URL whose routing is being asked about. Never connected to.
fn target() -> Url {
    Url::parse("http://example.net/some/path").unwrap()
}

fn resolver() -> WinHttpPacResolver {
    WinHttpPacResolver::with_timeout(BUDGET).expect("opening a WinHTTP session")
}

/// One snapshotted registry value: its name, and its `(type, bytes)` if it existed at
/// all. `None` means "was absent", which restore has to reproduce by deleting.
type SavedValue = (&'static str, Option<(u32, Vec<u8>)>);

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn read_raw(key: windows::Win32::System::Registry::HKEY, name: &str) -> Option<(u32, Vec<u8>)> {
    use windows::Win32::System::Registry::{REG_VALUE_TYPE, RegQueryValueExW};
    use windows::core::PCWSTR;

    let name_w = wide(name);
    let mut kind = REG_VALUE_TYPE::default();
    let mut len: u32 = 0;
    // SAFETY: `key` is open for the duration of this call and `name_w` is a
    // NUL terminated UTF-16 buffer alive across it; this first call only asks
    // for the size, so no output buffer is passed.
    let status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut len),
        )
    };
    if status.0 != 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    // SAFETY: as above; `buf` is sized from the length just reported.
    let status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr()),
            Some(&mut len),
        )
    };
    assert_eq!(status.0, 0, "reading {name}");
    Some((kind.0, buf))
}

fn write_dword(key: windows::Win32::System::Registry::HKEY, name: &str, value: u32) {
    use windows::Win32::System::Registry::{REG_DWORD, RegSetValueExW};
    use windows::core::PCWSTR;

    let name_w = wide(name);
    let bytes = value.to_le_bytes();
    // SAFETY: `key` is open for `KEY_SET_VALUE`; both buffers are alive for
    // the call.
    let status =
        unsafe { RegSetValueExW(key, PCWSTR(name_w.as_ptr()), None, REG_DWORD, Some(&bytes)) };
    assert_eq!(status.0, 0, "writing {name}");
}

fn write_sz(key: windows::Win32::System::Registry::HKEY, name: &str, value: &str) {
    use windows::Win32::System::Registry::{REG_SZ, RegSetValueExW};
    use windows::core::PCWSTR;

    let name_w = wide(name);
    let data_w = wide(value);
    // SAFETY: `data_w` is a NUL terminated UTF-16 buffer; reinterpreting it as
    // its own byte length is exactly what `REG_SZ` expects.
    let bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(data_w.as_ptr().cast(), data_w.len() * 2) };
    let status = unsafe { RegSetValueExW(key, PCWSTR(name_w.as_ptr()), None, REG_SZ, Some(bytes)) };
    assert_eq!(status.0, 0, "writing {name}");
}

/// Open an `HKCU` subkey for read and write, or `None` when it does not exist.
fn open_key(path: &str) -> Option<windows::Win32::System::Registry::HKEY> {
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, RegOpenKeyExW,
    };
    use windows::core::PCWSTR;

    let path_w = wide(path);
    let mut key = HKEY::default();
    // SAFETY: `path_w` is a NUL terminated UTF-16 buffer alive across the call and `key`
    // is a valid out-parameter.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path_w.as_ptr()),
            None,
            KEY_READ | KEY_SET_VALUE,
            &raw mut key,
        )
    };
    (status.0 == 0).then_some(key)
}

/// Put every snapshotted value back, reproducing "was absent" by deleting.
fn restore(key: windows::Win32::System::Registry::HKEY, saved: &[SavedValue]) {
    use windows::Win32::System::Registry::{REG_VALUE_TYPE, RegDeleteValueW, RegSetValueExW};
    use windows::core::PCWSTR;

    for (name, value) in saved {
        let name_w = wide(name);
        match value {
            Some((kind, bytes)) => {
                // SAFETY: `key` is still open and `name_w`/`bytes` are valid for the
                // call; `bytes` was itself read from this same value by `read_raw`.
                let _ = unsafe {
                    RegSetValueExW(
                        key,
                        PCWSTR(name_w.as_ptr()),
                        None,
                        REG_VALUE_TYPE(*kind),
                        Some(bytes),
                    )
                };
            }
            // SAFETY: `key` is still open and `name_w` is a NUL terminated buffer alive
            // across the call; deleting an absent value is a reported failure, not UB.
            None => unsafe {
                let _ = RegDeleteValueW(key, PCWSTR(name_w.as_ptr()));
            },
        }
    }
}

/// Serialises every test in this file that installs a [`StaticProxyUnderAutoDetect`].
/// They all patch the *same* real `HKCU\...\Internet Settings` values, and cargo
/// serialises test *binaries*, not the tests inside one — so by default they run
/// concurrently and overwrite each other's fixtures. See `src/sys/win/mod.rs`'s
/// `registry_guard::REGISTRY_LOCK` for the measurement that made this concrete, and for
/// why this is five lines of `std` rather than a `serial_test` dependency.
static REGISTRY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The four registry values the WPAD-fallback path can read, snapshotted and restored
/// around a test — a smaller, single-purpose cousin of `tests/windows_watch.rs`'s
/// `RegistryGuard`. That fixture lives in a different test binary (Cargo gives every
/// `tests/*.rs` file its own), so it cannot be reused here; duplicating four values'
/// worth of read/write/restore is proportionate to what these tests need.
struct StaticProxyUnderAutoDetect {
    key: windows::Win32::System::Registry::HKEY,
    saved: Vec<SavedValue>,
    /// `None` when this machine has no [`StaticProxyUnderAutoDetect::CONNECTIONS`] key.
    /// Nothing here writes those blobs deliberately; see [`Self::snapshot`].
    connections: Option<windows::Win32::System::Registry::HKEY>,
    connections_saved: Vec<SavedValue>,
    /// Held for this fixture's whole lifetime; see [`REGISTRY_LOCK`]. `Drop` runs before
    /// any field is dropped, so the restore completes while the lock is still held.
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl StaticProxyUnderAutoDetect {
    const VALUES: [&'static str; 4] = [
        "ProxyEnable",
        "ProxyServer",
        "ProxyOverride",
        "AutoConfigURL",
    ];
    const INTERNET_SETTINGS: &'static str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    /// `HKCU\...\Internet Settings\Connections`, which holds the same configuration a
    /// second time as two binary blobs; see [`Self::snapshot`].
    const CONNECTIONS: &'static str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

    /// The two values under [`Self::CONNECTIONS`] that receive Windows' copy of the
    /// plain values. Both are restored so neither can reseed the other.
    const CONNECTION_VALUES: [&'static str; 2] =
        ["DefaultConnectionSettings", "SavedLegacySettings"];

    /// Open the real `HKCU\...\Internet Settings` key with read/write access and
    /// snapshot [`Self::VALUES`], shared by every constructor below so each only has to
    /// write the specific values its scenario needs.
    ///
    /// [`Self::CONNECTION_VALUES`] are snapshotted here too, and restored on drop, even
    /// though nothing in this file ever writes them. Windows copies the plain
    /// values into those blobs asynchronously and on its own, and deleting a plain value
    /// does not clear the copy — so without this, a run of these tests leaves its fixture
    /// strings where the Settings app shows them to the developer as their own
    /// configuration, and advances the blob's own counter along with them.
    /// `src/sys/win/mod.rs`'s `mod registry_guard` describes the same copy from the side
    /// that reads it.
    fn snapshot() -> Self {
        // A poisoned lock means an earlier test panicked. Its fixture still ran `Drop`
        // on the way out, so the registry is restored and this test may proceed;
        // propagating the poison would turn one real failure into a cascade.
        let _lock = REGISTRY_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let key =
            open_key(Self::INTERNET_SETTINGS).expect("opening HKCU Internet Settings for the test");
        let saved = Self::VALUES
            .iter()
            .map(|name| (*name, read_raw(key, name)))
            .collect();

        let connections = open_key(Self::CONNECTIONS);
        let connections_saved = connections
            .map(|key| {
                Self::CONNECTION_VALUES
                    .iter()
                    .map(|name| (*name, read_raw(key, name)))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            key,
            saved,
            connections,
            connections_saved,
            _lock,
        }
    }

    /// Configures a static proxy in the real `HKCU\...\Internet Settings` key — the
    /// same store [`ProxyConfigSource::Registry`] names — without touching the real
    /// `AutoDetect` switch either way: `wpad_fallback` (`src/sys/win/mod.rs`) always
    /// derives the fallback with auto-detect forced off, so what that switch is
    /// currently set to must not matter to this test either.
    fn set() -> Self {
        use windows::Win32::System::Registry::RegDeleteValueW;
        use windows::core::PCWSTR;

        let guard = Self::snapshot();

        write_dword(guard.key, "ProxyEnable", 1);
        write_sz(guard.key, "ProxyServer", "127.0.0.1:18080");
        write_sz(guard.key, "ProxyOverride", "<local>");
        // No `AutoConfigURL` here, so the fallback below auto-detect is the static
        // proxy above, not a PAC URL.
        unsafe {
            let name_w = wide("AutoConfigURL");
            let _ = RegDeleteValueW(guard.key, PCWSTR(name_w.as_ptr()));
        }

        guard
    }

    /// A fixture for an `AutoConfigURL` beneath auto-detect that `url::Url::parse` cannot
    /// parse, with no static proxy configured either. Before this was fixed, this exact
    /// registry state made `wpad_fallback` (`src/sys/win/mod.rs`) return `Err`, which
    /// `resolve_wpad_with_fallback` (`src/pac/winhttp.rs`) propagated straight out of
    /// `resolve_config` — aborting the live WPAD probe below before it ever ran, on a
    /// machine where WPAD itself might have been perfectly healthy.
    fn set_broken_auto_config_url() -> Self {
        use windows::Win32::System::Registry::RegDeleteValueW;
        use windows::core::PCWSTR;

        let guard = Self::snapshot();

        write_sz(guard.key, "AutoConfigURL", "not a url");
        // No static proxy either, so a `wpad_fallback` that fails soft here can only
        // ever recover `Direct` — the assertion below only needs `resolve_config` to
        // not error out before probing WPAD, not any particular fallback mode.
        for name in ["ProxyEnable", "ProxyServer", "ProxyOverride"] {
            unsafe {
                let name_w = wide(name);
                let _ = RegDeleteValueW(guard.key, PCWSTR(name_w.as_ptr()));
            }
        }

        guard
    }

    /// A fixture for the combined case: an `AutoConfigURL` beneath auto-detect that
    /// `url::Url::parse` cannot parse, combined with a working static proxy configured
    /// beneath it as well — the combination [`Self::set`] (static proxy, no
    /// `AutoConfigURL`) and [`Self::set_broken_auto_config_url`] (broken
    /// `AutoConfigURL`, no static proxy) each leave uncovered on their own. Before the
    /// fix accompanying this fixture, `wpad_fallback_beneath` (`src/sys/win/mod.rs`)
    /// `return`ed `ProxyMode::Direct` straight from its unparsable-`AutoConfigURL` arm,
    /// never even looking at `ProxyServer` — so on exactly this registry state,
    /// `resolve_config` would probe WPAD alone, and an ordinary WPAD miss (routine — see
    /// this file's module doc) would silently confirm `Direct`, bypassing this static
    /// proxy.
    fn set_broken_auto_config_url_with_static_proxy() -> Self {
        let guard = Self::snapshot();

        write_dword(guard.key, "ProxyEnable", 1);
        write_sz(guard.key, "ProxyServer", "127.0.0.1:18080");
        write_sz(guard.key, "ProxyOverride", "<local>");
        write_sz(guard.key, "AutoConfigURL", "not a url");

        guard
    }

    /// A fixture for a well-formed but unroutable `AutoConfigURL` (RFC 5737
    /// TEST-NET-1) beneath auto-detect, with a working static proxy also configured.
    /// Unlike [`Self::set_broken_auto_config_url_with_static_proxy`], this URL parses
    /// fine, so `wpad_fallback_beneath` (`src/sys/win/mod.rs`) reports it as the PAC URL
    /// to try, and reports the static proxy alongside it rather than dropping it. The
    /// static proxy reaches an answer only via
    /// `resolve_wpad_with_fallback`'s own fallthrough, when WinHTTP's combined
    /// `AutoDetectThenUrl` call reports a genuine `WpadOutcome::AutoDetectionFailed`;
    /// see `auto_detect_with_an_unreachable_auto_config_url_and_a_static_proxy_underneath_it_never_silently_resolves_to_direct`
    /// below for what was actually observed on real hardware — which is *not* that arm,
    /// so this fixture does not discriminate the fix. The unit test that does is
    /// `a_static_server_survives_the_auto_config_url_configured_above_it`.
    fn set_unreachable_auto_config_url_with_static_proxy() -> Self {
        let guard = Self::snapshot();

        write_dword(guard.key, "ProxyEnable", 1);
        write_sz(guard.key, "ProxyServer", "127.0.0.1:18080");
        write_sz(guard.key, "ProxyOverride", "<local>");
        // TEST-NET-1 (RFC 5737): syntactically valid, never routed.
        write_sz(guard.key, "AutoConfigURL", "http://192.0.2.1/proxy.pac");

        guard
    }
}

impl Drop for StaticProxyUnderAutoDetect {
    fn drop(&mut self) {
        use windows::Win32::System::Registry::RegCloseKey;

        // Plain values first, blobs second: Windows' copy runs plain-to-blob, so once
        // the plain values are the developer's own again, a copy that fires after this
        // point reproduces the correct blob rather than fighting the restore.
        restore(self.key, &self.saved);
        if let Some(connections) = self.connections {
            restore(connections, &self.connections_saved);
            // SAFETY: opened by `snapshot` and closed exactly once, here.
            unsafe {
                let _ = RegCloseKey(connections);
            }
        }
        // SAFETY: `self.key` was opened by `snapshot` and is closed exactly once, here.
        unsafe {
            let _ = RegCloseKey(self.key);
        }
    }
}

/// The failure the WPAD fallback exists to prevent: `ProxyMode` is single valued, so a
/// machine with "automatically detect settings" on *and* a static proxy configured
/// underneath it reports the effective mode as bare `ProxyMode::WpadAutoDetect` — the
/// static proxy is real, it is simply not reachable through `effective` any more. So
/// `resolve_config` must not map a WPAD probe failure straight onto
/// `Ok(vec![ProxyStep::Direct])`: on a network with no real WPAD infrastructure (the
/// common case — see this file's module doc) that silently bypasses a proxy the
/// administrator did configure.
///
/// Real WinHTTP cannot be forced to fail its WPAD probe deterministically — whether it
/// finds anything depends on this machine's own network, not on this crate — so, like
/// `tests/pac_winhttp.rs`'s `wpad_auto_detect_terminates_and_never_returns_an_empty_chain`,
/// this test cannot fully control that half of the outcome. What it *can* guarantee, and
/// does: a bare, unconditional `Direct` — the exact signature of the bug — must never come
/// back while a real static proxy sits configured right underneath auto-detect. On the
/// rare machine that does have working WPAD infrastructure whose script itself
/// legitimately answers `DIRECT` for this URL, that would be a false failure here. It is
/// accepted deliberately: the alternative is not asserting the bug's signature at all.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn auto_detect_with_a_static_proxy_underneath_it_never_silently_resolves_to_direct() {
    let guard = StaticProxyUnderAutoDetect::set();

    let snapshot = ProxyConfig::new(
        ProxyMode::WpadAutoDetect,
        vec![(ProxyConfigSource::Registry, ProxyMode::WpadAutoDetect)],
    );

    let steps = resolver()
        .resolve_config(&snapshot, &target())
        .expect("resolving auto-detect with a static-proxy fallback underneath it");

    assert_ne!(
        steps,
        vec![ProxyStep::Direct],
        "auto-detect ON with a static proxy configured underneath it must not silently \
         resolve to Direct: {steps:?}"
    );

    drop(guard);
}

/// Regression test: an unparsable `AutoConfigURL` sitting underneath auto-detect must not
/// abort `resolve_config` before it ever probes WPAD.
///
/// Before the fix, `wpad_fallback` (`src/sys/win/mod.rs`) propagated the
/// `url::Url::parse` failure straight out as `Err(Error::InvalidProxyUrl { .. })`, and
/// `resolve_wpad_with_fallback` (`src/pac/winhttp.rs`) evaluated that fallback with `?`
/// *before* ever calling `resolve_raw` to probe WPAD — so a machine with a broken,
/// unrelated PAC URL configured beneath "automatically detect settings" would fail here
/// even if WPAD itself was perfectly reachable. This test cannot force real WPAD
/// detection to succeed or fail deterministically (see this file's module doc), so, like
/// `auto_detect_with_a_static_proxy_underneath_it_never_silently_resolves_to_direct`
/// above, it only asserts the one thing under this crate's control: `resolve_config` must
/// return `Ok` — never `Err(Error::InvalidProxyUrl { .. })` — regardless of what WPAD
/// itself answers.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn auto_detect_with_an_unparsable_auto_config_url_underneath_it_still_probes_wpad() {
    let guard = StaticProxyUnderAutoDetect::set_broken_auto_config_url();

    let snapshot = ProxyConfig::new(
        ProxyMode::WpadAutoDetect,
        vec![(ProxyConfigSource::Registry, ProxyMode::WpadAutoDetect)],
    );

    let result = resolver().resolve_config(&snapshot, &target());

    assert!(
        !matches!(result, Err(Error::InvalidProxyUrl { .. })),
        "an unparsable AutoConfigURL beneath auto-detect must degrade to Direct, \
         not abort the WPAD probe with an error: {result:?}"
    );
    result.expect("resolving auto-detect with a broken AutoConfigURL fallback underneath it");

    drop(guard);
}

/// Regression guard: a broken `AutoConfigURL` sitting *above* a working
/// static proxy in the same registry key must not make `resolve_config` discard that
/// proxy as `Direct`. Companion to
/// `auto_detect_with_a_static_proxy_underneath_it_never_silently_resolves_to_direct`
/// (no `AutoConfigURL` at all) and
/// `auto_detect_with_an_unparsable_auto_config_url_underneath_it_still_probes_wpad` (no
/// static proxy) above — neither of those two registry states could have caught this:
/// this is the combination that falls through the gap between
/// them, and the one an earlier version of `wpad_fallback_beneath`
/// (`src/sys/win/mod.rs`) got wrong by returning `Direct` before ever consulting
/// `ProxyServer`.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn auto_detect_with_a_broken_auto_config_url_and_a_static_proxy_underneath_it_never_silently_resolves_to_direct()
 {
    let guard = StaticProxyUnderAutoDetect::set_broken_auto_config_url_with_static_proxy();

    let snapshot = ProxyConfig::new(
        ProxyMode::WpadAutoDetect,
        vec![(ProxyConfigSource::Registry, ProxyMode::WpadAutoDetect)],
    );

    let steps = resolver().resolve_config(&snapshot, &target()).expect(
        "resolving auto-detect with a broken AutoConfigURL and a static-proxy fallback \
         underneath it",
    );

    assert_ne!(
        steps,
        vec![ProxyStep::Direct],
        "a broken AutoConfigURL beneath auto-detect must not discard the static proxy \
         configured beneath it in turn: {steps:?}"
    );

    drop(guard);
}

/// A regression test: an `AutoConfigURL` beneath auto-detect that is
/// syntactically valid but unreachable (RFC 5737 TEST-NET-1, never routed), with a
/// static proxy also configured, must never let the `_` arm in
/// `resolve_wpad_with_fallback` (`src/pac/winhttp.rs`) turn a genuine
/// `WpadOutcome::AutoDetectionFailed` into a bare, silently-confirmed `Direct` — that
/// arm's own comment assumes WinHTTP always tries the URL half of the combined
/// `AutoDetectThenUrl` call before it can report the aggregate
/// `ERROR_WINHTTP_AUTODETECTION_FAILED`, which this crate has not been able to confirm
/// from the documentation alone.
///
/// Live investigation on real hardware found the assumption holds:
/// `WinHttpGetProxyForUrlEx` with this exact registry state never once returned
/// `ERROR_WINHTTP_AUTODETECTION_FAILED` — every attempt, on the
/// first call in a fresh session and on repeated calls in one reused session (the
/// specific pattern `resolve_raw`'s own "Not an error, synchronously either" doc
/// comment flags as able to complete *synchronously* off WinHTTP's per-session
/// negative-WPAD cache), instead surfaced a distinguishable, specific error —
/// `ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT` (0x2f87) on the machine this was verified
/// on — proving the URL was genuinely attempted rather than skipped. This test cannot
/// pin that exact status code down: which one WinHTTP reports is a property of this
/// machine's network stack, not of this crate (same caveat the other real-WPAD tests in
/// this file document). What it does assert, repeatedly and against one shared session,
/// is the one thing under this crate's control and the one that matters here:
/// `resolve_config` must never answer with a bare `Direct` here. An `Err` is an
/// honest, by-design answer — it is exactly how a bare `ProxyMode::Pac` resolution
/// already treats an unreachable URL, see `tests/pac_winhttp.rs`'s
/// `an_unroutable_pac_url_gives_up_inside_the_budget` — silently discarding the
/// static proxy underneath as `Direct` is not.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn auto_detect_with_an_unreachable_auto_config_url_and_a_static_proxy_underneath_it_never_silently_resolves_to_direct()
 {
    let guard = StaticProxyUnderAutoDetect::set_unreachable_auto_config_url_with_static_proxy();

    let snapshot = ProxyConfig::new(
        ProxyMode::WpadAutoDetect,
        vec![(ProxyConfigSource::Registry, ProxyMode::WpadAutoDetect)],
    );

    // One shared resolver (one WinHTTP session) across repeated calls: the case to
    // cover is calls after the first, where WinHTTP's per-session
    // negative-WPAD cache can make the underlying call complete synchronously.
    let shared = resolver();
    for attempt in 1..=3 {
        let result = shared.resolve_config(&snapshot, &target());
        assert!(
            !matches!(&result, Ok(steps) if steps == &[ProxyStep::Direct]),
            "attempt {attempt}: an unreachable AutoConfigURL beneath auto-detect must \
             not silently resolve to Direct, discarding the static proxy configured \
             beneath it: {result:?}"
        );
    }

    drop(guard);
}

/// Regression test for the fallback's *provenance*: the store re-read beneath auto-detect
/// must be the one that produced the effective mode, not whatever sits at the head of
/// [`ProxyConfig::sources`].
///
/// The tests above all pass a config whose single source *is* the effective mode, so the
/// two coincide and none of them can tell the question apart.
/// [`ProxyConfig::new`] is public so a caller can resolve precedence itself, and such a
/// caller may list a source it discarded first — here a group-policy PAC URL it decided
/// not to honour, above the per-user auto-detect it kept.
/// `resolve_wpad_with_fallback` (`src/pac/winhttp.rs`) must not hand
/// `config.sources.first()` to a `wpad_fallback` (`src/sys/win/mod.rs`) that takes the store
/// to read: for [`ProxyConfigSource::GroupPolicy`] that store is
/// `HKLM\...\Policies\...\Internet Settings` — the one underneath the *losing* entry. With
/// no proxy policy on this machine it answers `Direct`, and the static proxy the user
/// really does have configured beneath auto-detect is discarded: the same
/// silently-bypassed-proxy signature the tests above guard against, reached through a
/// different door. Neither the parameter nor that arm survives, so what this now holds is
/// the rule that replaced them — the per-user store is read on the strength of its *own*
/// entry, and a head entry that is not it neither supplies the fallback nor suppresses it.
/// The two tests below hold the other two halves of that rule.
///
/// The fixture is [`StaticProxyUnderAutoDetect::set`] unchanged; only the config differs.
/// What makes it discriminate is that the two stores disagree — `HKCU` has the static
/// proxy and the policy key has no proxy configuration — so that is checked rather than
/// assumed. The `assert_ne!` carries the same real-WPAD caveat as its siblings above.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn the_wpad_fallback_reads_the_store_that_produced_the_effective_mode() {
    let guard = StaticProxyUnderAutoDetect::set();

    let live = proxy_watch::read().expect("reading this machine's own proxy configuration");
    if live.source(ProxyConfigSource::GroupPolicy).is_some() {
        drop(guard);
        skip_or_fail(
            "this machine has a group-policy proxy configuration, so the discarded head \
             entry's store would answer with a proxy of its own and the two stores could \
             not be told apart",
        );
        return;
    }

    let snapshot = ProxyConfig::new(
        ProxyMode::WpadAutoDetect,
        vec![
            (
                ProxyConfigSource::GroupPolicy,
                // TEST-NET-1 (RFC 5737), never routed — and never fetched either: this
                // entry exists to be passed over.
                ProxyMode::pac(Url::parse("http://192.0.2.1/policy.pac").unwrap()),
            ),
            (ProxyConfigSource::Registry, ProxyMode::WpadAutoDetect),
        ],
    );

    let steps = resolver()
        .resolve_config(&snapshot, &target())
        .expect("resolving auto-detect that is not the head of sources");

    assert_ne!(
        steps,
        vec![ProxyStep::Direct],
        "the fallback must be re-read from the Registry entry that produced the effective \
         WpadAutoDetect, not from the discarded GroupPolicy entry ahead of it: {steps:?}"
    );

    drop(guard);
}

/// The other half of provenance, and the one the test above cannot see: a source that is not
/// this machine's registry at all must not be answered *from* this machine's registry.
///
/// `wpad_fallback` must not take the effective source and read the per-user store for every
/// value of it but [`ProxyConfigSource::GroupPolicy`], on the grounds that everything else
/// able to produce [`ProxyMode::WpadAutoDetect`] is that store. Four sources falsify that:
/// [`ProxyConfigSource::GSettings`], [`ProxyConfigSource::Kioslaverc`] and both macOS scopes
/// all produce that mode, and none of them is a Windows registry. `resolve_config` is public
/// and takes a caller-built [`ProxyConfig`], so a snapshot captured on a GNOME machine — or
/// replayed from a log, or synthesised by a test — reaches such a wildcard and comes back
/// with *this* machine's proxy attached to it.
///
/// The fixture is [`StaticProxyUnderAutoDetect::set`] unchanged, so the answer a wildcard
/// invents is a known string: `127.0.0.1:18080`, which no GNOME snapshot ever mentions.
/// Asserting on that string rather than on `Direct` keeps a machine with a live WPAD server
/// from failing this test for the wrong reason — whatever WPAD answers there, it is not the
/// value written two lines above.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn auto_detect_from_a_source_that_is_not_this_registry_is_not_answered_from_this_registry() {
    let guard = StaticProxyUnderAutoDetect::set();

    let snapshot =
        ProxyConfig::from_source(ProxyConfigSource::GSettings, ProxyMode::WpadAutoDetect);

    let steps = resolver()
        .resolve_config(&snapshot, &target())
        .expect("resolving auto-detect that no Windows store produced");

    let leaked: Vec<_> = steps
        .iter()
        .filter_map(|step| step.endpoint())
        .filter(|endpoint| endpoint.authority() == "127.0.0.1:18080")
        .collect();
    assert!(
        leaked.is_empty(),
        "a snapshot whose effective WpadAutoDetect came from GSettings must not be given \
         this machine's HKCU proxy as its fallback: {steps:?}"
    );

    drop(guard);
}

/// A policy entry carrying the *same* mode as the per-user one must not cost the fallback.
///
/// `read_group_policy_mode` (`src/sys/win/mod.rs`) parses the policy key with the same
/// `mode_from_registry` as the per-user key, so `WpadAutoDetect` under both is a shape
/// [`proxy_watch::read`] itself produces on a machine with a hand-written policy key — not a
/// synthetic one. Selecting the fallback's store by mode alone finds `GroupPolicy` first here
/// and reads `HKLM\...\Policies\...\Internet Settings`, which on a machine with no proxy
/// policy answers `Direct` and discards the static proxy underneath: the bug the whole file
/// guards against, re-entered through the fix for the test above.
///
/// The `GroupPolicy` entry is deliberately first, because `Registry` first is the order
/// `in_precedence_order` already guarantees and would prove nothing.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn a_policy_entry_sharing_the_effective_mode_does_not_cost_the_per_user_fallback() {
    let guard = StaticProxyUnderAutoDetect::set();

    let live = proxy_watch::read().expect("reading this machine's own proxy configuration");
    if live.source(ProxyConfigSource::GroupPolicy).is_some() {
        drop(guard);
        skip_or_fail(
            "this machine has a group-policy proxy configuration, so reading the policy key \
             instead of the per-user one would answer with a proxy of its own and the two \
             stores could not be told apart",
        );
        return;
    }

    let snapshot = ProxyConfig::new(
        ProxyMode::WpadAutoDetect,
        vec![
            (ProxyConfigSource::GroupPolicy, ProxyMode::WpadAutoDetect),
            (ProxyConfigSource::Registry, ProxyMode::WpadAutoDetect),
        ],
    );

    let steps = resolver()
        .resolve_config(&snapshot, &target())
        .expect("resolving auto-detect that two sources agree on");

    assert_ne!(
        steps,
        vec![ProxyStep::Direct],
        "a policy entry that agrees with the per-user one must not divert the fallback to \
         the policy key and lose the static proxy configured beneath auto-detect: {steps:?}"
    );

    drop(guard);
}
