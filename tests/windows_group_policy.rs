//! What the crate does with an `HKEY_LOCAL_MACHINE` it has been given rather than found.
//!
//! Every other test that populates the group policy key needs an elevated process
//! (`tests/windows_watch.rs`'s `PolicyKeyGuard`), so on an ordinary developer machine and
//! on any unelevated CI runner they skip and nothing exercises the policy read against a
//! key with values in it. These arrange the same thing with `RegOverridePredefKey`, which
//! redirects `HKEY_LOCAL_MACHINE` for the calling process only and needs no privilege at
//! all: the shadow lives under `HKEY_CURRENT_USER`, which this process may always write.
//!
//! The three states that buys are a policy key holding a proxy, one holding a value the
//! reader cannot use, and no HKLM at all — the last of which is the only way to fail an
//! HKLM notification route without editing an ACL, and so the only way to reach the
//! degraded half of `WatchHealth` on this platform.
//!
//! Its own test binary, deliberately, and nothing in it that is not about the shadow. The
//! redirection is process-wide, so any test running beside it — on another thread of the
//! same binary — would read the shadow too, including tests that have nothing to do with
//! proxies. The tests below are all about it and none holds it across a yield point, so
//! under the `--test-threads=1` every integration binary here already requires they cannot
//! overlap; each also asserts the *unshadowed* machine first, which is what would catch a
//! redirection another one leaked.

#![cfg(windows)]

use proxy_watch::{ProxyConfigSource, ProxyWatcher, Scheme};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_CREATE_SUB_KEY, KEY_QUERY_VALUE,
    KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW,
    RegDeleteKeyExW, RegDeleteTreeW, RegOverridePredefKey, RegSetValueExW,
};
use windows::core::PCWSTR;

/// Where the shadow `HKEY_LOCAL_MACHINE` lives while the override is installed. Under
/// `Software` rather than at the root of `HKEY_CURRENT_USER` so a leaked key is somewhere
/// a person would think to look, and one level deep so that removing it leaves nothing:
/// creating `a\b` creates `a` as well, and deleting `a\b` does not take `a` with it.
const SHADOW_ROOT: &str = r"Software\proxy-watch-test-shadow-hklm";

/// The key the backend reads, relative to `HKEY_LOCAL_MACHINE` — the same string
/// `POLICY_INTERNET_SETTINGS` holds in `src/sys/win/mod.rs`. Spelled out here rather than
/// imported because it is private, which is also what makes this test worth having: it
/// reaches the backend only through the public read.
const POLICY_INTERNET_SETTINGS: &str =
    r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Not routable and not resolvable: `.invalid` is reserved for exactly this
/// (<https://www.rfc-editor.org/rfc/rfc6761#section-6.4>). Nothing in this test connects
/// anywhere, but a value that leaked past a failed cleanup should not be one that could.
const POLICY_PROXY: &str = "policy.invalid:9999";

/// A `AutoConfigURL` `url::Url::parse` refuses, which is the one way to make
/// `read_group_policy_mode` fail without taking away this process's right to read a key it
/// owns. `group_policy_source`'s own comment names this case — "a mistyped policy
/// `AutoConfigURL`" — as the reason every failure of that read softens.
const MALFORMED_PAC_URL: &str = "not a url";

/// A policy proxy is read, reported, and does not answer.
///
/// The premise of the whole arrangement is checked first, because the interesting assertion
/// is a negative one: if the override did not reach the backend, the policy entry would be
/// missing and "the policy did not answer" would be true for the wrong reason. So the entry
/// has to be present and carry [`POLICY_PROXY`] before its absence from `effective` says
/// anything.
///
/// Ignored: it redirects `HKEY_LOCAL_MACHINE` for this process and writes under
/// `HKEY_CURRENT_USER`. Both are undone before it returns, and CI runs it with
/// `--include-ignored`.
#[test]
#[ignore = "redirects this process's HKEY_LOCAL_MACHINE; CI runs it with --include-ignored"]
fn a_policy_proxy_is_reported_and_the_per_user_store_still_answers() {
    let unshadowed = proxy_watch::read().expect("reading this machine's own configuration");
    assert!(
        unshadowed.source(ProxyConfigSource::GroupPolicy).is_none(),
        "this machine has a real proxy group policy, so the shadow below would not be the \
         only thing this test measures: {:?}",
        unshadowed.sources
    );

    let shadow = Shadow::install(&[
        ("ProxyEnable", Value::Dword(1)),
        ("ProxyServer", Value::Sz(POLICY_PROXY)),
    ]);

    let config = proxy_watch::read().expect("reading through the shadowed HKLM");
    let policy = config
        .source(ProxyConfigSource::GroupPolicy)
        .unwrap_or_else(|| {
            panic!(
                "the shadowed policy key must be read at all, or nothing below is measured: \
                 {:?}",
                config.sources
            )
        });
    assert_eq!(
        policy
            .endpoint_for(Scheme::Http)
            .map(ToString::to_string)
            .as_deref(),
        Some(POLICY_PROXY),
        "the entry must carry the value written to the shadow, or the read reached some \
         other key: {policy:?}"
    );

    assert_ne!(
        config.effective, *policy,
        "a proxy under HKLM group policy must not become the effective configuration: \
         Windows does not read those values itself, so routing through one would send this \
         process somewhere nothing else on the machine goes ({:?})",
        config.sources
    );
    assert_eq!(
        config.effective, unshadowed.effective,
        "and what answers instead is the per-user store, unchanged by the policy: {:?}",
        config.sources
    );

    drop(shadow);

    let restored = proxy_watch::read().expect("reading after the override was lifted");
    assert!(
        restored.source(ProxyConfigSource::GroupPolicy).is_none(),
        "the override must be gone by the end of the test: {:?}",
        restored.sources
    );
}

/// A policy key this process cannot make sense of is named in the answer, not passed over
/// in silence.
///
/// [`proxy_watch::ProxyConfig::fallbacks`] is the difference between "this machine has no
/// proxy group policy" and "this read did not learn what its policy holds", and on Windows
/// the only thing that fills it in is the `.with_fallbacks(...)` at the end of
/// `sys::win::read_config`. This test is the only thing holding that call.
/// `sys::win::tests::every_policy_read_that_failed_is_reported_as_no_policy_and_recorded`
/// does assert that `group_policy_source` pushes the source, but it passes its own
/// `&mut Vec` in and reads it back out, so it holds the push and not the hand-off; between
/// that vector and the caller's `ProxyConfig` there is nothing else.
///
/// What the missing hand-off costs is silent. `read()` still succeeds, still answers from
/// HKCU, and still reports no `GroupPolicy` source — which it also does on a machine that
/// has no policy. The field is compared by [`PartialEq`], so a watcher would additionally
/// skip the snapshot where the degradation appears and the one where it clears.
///
/// Ignored for the same reason as the test above, and undone the same way.
#[test]
#[ignore = "redirects this process's HKEY_LOCAL_MACHINE; CI runs it with --include-ignored"]
fn a_policy_key_that_could_not_be_read_is_named_in_the_answer() {
    let unshadowed = proxy_watch::read().expect("reading this machine's own configuration");
    // Both preconditions in one place: a real policy would make the shadow not the only
    // thing measured, and a host that already records a fallback — a WinHTTP default that
    // failed to read, say — would leave the assertion below matching a list this test did
    // not build.
    assert!(
        unshadowed.source(ProxyConfigSource::GroupPolicy).is_none(),
        "this machine has a real proxy group policy: {:?}",
        unshadowed.sources
    );
    assert!(
        unshadowed.fallbacks.is_empty(),
        "this machine already fails to read one of its own sources, so the list below \
         would not be this test's doing: {:?}",
        unshadowed.fallbacks
    );

    let shadow = Shadow::install(&[("AutoConfigURL", Value::Sz(MALFORMED_PAC_URL))]);
    let config = proxy_watch::read().expect("a policy that cannot be read must not fail the read");
    drop(shadow);

    // The two halves of the distinction, which only exist together. The policy key says
    // something — `AutoConfigURL` is one of the three values `decides_whether_to_proxy`
    // asks for — and yet no mode can be built from it, so `sources` cannot carry it...
    assert!(
        config.source(ProxyConfigSource::GroupPolicy).is_none(),
        "a policy whose value will not parse has no mode to report: {:?}",
        config.sources
    );
    // ...and this list is the only place the caller can learn that the source was consulted
    // at all rather than simply absent.
    assert_eq!(
        config.fallbacks,
        vec![ProxyConfigSource::GroupPolicy],
        "the source that was consulted and could not be read"
    );
    // Still an answer, and the same one as without the policy: softening the failure is
    // only defensible because this entry could never have been `effective` anyway.
    assert_eq!(
        config.effective, unshadowed.effective,
        "the per-user store answers exactly as it did before: {:?}",
        config.sources
    );
}

/// A watcher whose HKLM notification routes could not be armed says so.
///
/// `Watch::health` hands `construction_degraded` to `merge_runtime_health`, and this test is
/// the only thing holding that hand-off: replacing the field with an empty `Vec` leaves the
/// rest of the Windows tree green.
/// `push_degraded_does_not_duplicate_a_source` holds the pushes and
/// `merge_runtime_health_folds_in_new_state_without_disturbing_the_old` holds the merge,
/// each against a vector it builds itself; between the backend's list and the caller's
/// `WatchHealth` there is nothing else. Without the hand-off a watcher with two of its
/// three routes dead answers [`proxy_watch::WatchHealth::is_fully_live`] `true`, and a
/// caller that reads it to decide whether to set a `poll_interval` decides not to.
///
/// `tests/windows_watch.rs`'s `health_reports_every_route_live_on_a_normal_machine` says
/// this cannot be tested without an ACL edit — "none of which this test file can redirect
/// to a disposable scratch key". That is true of *that* file and false of this one: the
/// two secondary routes are both under `HKEY_LOCAL_MACHINE`, and an empty shadow makes
/// both fail with no privilege and nothing written outside `HKEY_CURRENT_USER`. The HKCU
/// route, which really would need an ACL edit, is left alone — and has to be, because it
/// is the one route whose loss is fatal rather than degrading.
///
/// Ignored for the same reason as the tests above, and undone the same way.
#[test]
#[ignore = "redirects this process's HKEY_LOCAL_MACHINE; CI runs it with --include-ignored"]
fn a_watcher_whose_secondary_routes_could_not_be_armed_reports_them_degraded() {
    // The premise, on the real machine: both secondary routes arm here, so what the shadow
    // takes away below is a route that existed rather than one this host never had.
    let healthy = ProxyWatcher::new().expect("watching this machine");
    assert!(
        healthy.health().is_fully_live(),
        "this machine cannot arm one of its own routes, so the shadow is not what the \
         assertion below would be measuring: {:?}",
        healthy.health()
    );
    drop(healthy);

    let shadow = Shadow::install(&[]);
    let watcher = ProxyWatcher::new().expect("HKCU is untouched, so the watcher still builds");
    let health = watcher.health();
    drop(watcher);
    drop(shadow);

    // Both secondary sources, and only those: the group policy ancestor walk runs out of
    // candidates in an empty shadow, and the machine-default key has no ancestor walk at
    // all. `Registry` is the HKCU route, which the shadow does not touch.
    assert_eq!(
        health.degraded,
        vec![
            ProxyConfigSource::GroupPolicy,
            ProxyConfigSource::WinHttpDefault
        ],
        "the routes that could not be armed: {health:?}"
    );
    // Degraded rather than dark, and that distinction is the reason `has_live_notifications`
    // is not simply `degraded.is_empty()`: HKCU still delivers, so a change to the settings
    // that actually answer is still announced.
    assert!(
        health.has_live_notifications,
        "the HKCU route is untouched and still delivers: {health:?}"
    );
    assert!(
        !health.is_fully_live(),
        "a caller reading this to decide whether it needs a poll interval must be told \
         that it does: {health:?}"
    );
}

/// What a [`Shadow`] writes under the policy key.
enum Value<'a> {
    Dword(u32),
    Sz(&'a str),
}

/// The installed redirection, and the key it points at.
///
/// `Drop` lifts the redirection before deleting the shadow, because deleting it first would
/// leave `HKEY_LOCAL_MACHINE` pointing at a key that no longer exists for as long as the
/// gap lasts. It runs on a panic — Rust unwinds through it — but not if the binary is
/// killed outright, in which case the process ends with the redirection still installed;
/// the redirection dies with the process, and what survives is the `HKEY_CURRENT_USER`
/// subtree named by [`SHADOW_ROOT`], which affects nothing and can be deleted by hand.
struct Shadow(HKEY);

impl Shadow {
    /// An empty `values` leaves the shadow *empty*, policy key and all — creating that key
    /// would create `Software` along with it, which is the one thing
    /// `arm_group_policy_key`'s ancestor walk needs to succeed.
    fn install(values: &[(&str, Value<'_>)]) -> Self {
        let root = create_key(HKEY_CURRENT_USER, SHADOW_ROOT);
        if !values.is_empty() {
            let policy = create_key(
                HKEY_CURRENT_USER,
                &format!(r"{SHADOW_ROOT}\{POLICY_INTERNET_SETTINGS}"),
            );
            for (name, value) in values {
                match value {
                    Value::Dword(number) => write_dword(policy, name, *number),
                    Value::Sz(text) => write_sz(policy, name, text),
                }
            }
            // SAFETY: `policy` came from `create_key` and is not used again.
            unsafe {
                let _ = RegCloseKey(policy);
            }
        }

        // SAFETY: `root` is a live key handle for the lifetime of the returned guard.
        let status = unsafe { RegOverridePredefKey(HKEY_LOCAL_MACHINE, Some(root)) };
        assert_eq!(
            status.0, 0,
            "redirecting HKEY_LOCAL_MACHINE failed: error {}",
            status.0
        );
        Self(root)
    }
}

impl Drop for Shadow {
    fn drop(&mut self) {
        // SAFETY: `None` restores the predefined key; the handle is this guard's own.
        unsafe {
            let _ = RegOverridePredefKey(HKEY_LOCAL_MACHINE, None);
            let _ = RegCloseKey(self.0);
        }
        let path = wide(SHADOW_ROOT);
        // SAFETY: `path` is a NUL terminated UTF-16 buffer alive across both calls, and
        // `RegDeleteTree`'s reference page does not say whether a non-NULL `lpSubKey` is
        // itself removed, so both readings are covered.
        unsafe {
            let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
            let _ = RegDeleteKeyExW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()), 0, None);
        }
    }
}

fn create_key(parent: HKEY, path: &str) -> HKEY {
    let path_w = wide(path);
    let mut key = HKEY::default();
    // SAFETY: `path_w` outlives the call and `key` is a live out-parameter.
    let status = unsafe {
        RegCreateKeyExW(
            parent,
            PCWSTR(path_w.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
            None,
            &raw mut key,
            None,
        )
    };
    assert_eq!(status.0, 0, "creating {path}: error {}", status.0);
    key
}

fn write_dword(key: HKEY, name: &str, value: u32) {
    let name_w = wide(name);
    // SAFETY: `name_w` outlives the call and the byte slice is a live `u32`.
    let status = unsafe {
        RegSetValueExW(
            key,
            PCWSTR(name_w.as_ptr()),
            None,
            REG_DWORD,
            Some(&value.to_ne_bytes()),
        )
    };
    assert_eq!(status.0, 0, "writing {name}: error {}", status.0);
}

fn write_sz(key: HKEY, name: &str, value: &str) {
    let name_w = wide(name);
    let value_w = wide(value);
    let bytes: &[u8] = unsafe {
        // SAFETY: reinterpreting the UTF-16 buffer as the bytes the registry stores.
        std::slice::from_raw_parts(value_w.as_ptr().cast::<u8>(), value_w.len() * 2)
    };
    // SAFETY: both buffers outlive the call.
    let status = unsafe { RegSetValueExW(key, PCWSTR(name_w.as_ptr()), None, REG_SZ, Some(bytes)) };
    assert_eq!(status.0, 0, "writing {name}: error {}", status.0);
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
