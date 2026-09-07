//! Windows watch backend integration tests.
//!
//! These tests write to the **real** `HKCU\Software\Microsoft\Windows\CurrentVersion\
//! Internet Settings` key, so they must not run concurrently. A bare `cargo test` is safe
//! because it does not run them at all — they are `#[ignore]`, for the reason below. For
//! the runs that *do* execute them, [`REGISTRY_LOCK`] enforces the serialisation from
//! inside [`RegistryGuard::acquire`]; `--test-threads=1` (which CI still passes for every
//! integration-test job) is belt-and-braces rather than the mechanism.
//!
//! Every test that writes `HKCU\...\Internet Settings` takes a [`RegistryGuard`] first,
//! which snapshots the five documented proxy values and restores them from `Drop` —
//! including on panic, and including deleting values that did not exist before. The one
//! exception, `a_group_policy_key_created_after_the_watcher_starts_is_detected`, writes
//! only under `HKEY_LOCAL_MACHINE` and uses [`PolicyKeyGuard`] instead. Acquiring the guard also forces real
//! WPAD auto-detect off for its lifetime (see
//! [`RegistryGuard::force_wpad_auto_detect_off`]) — a freshly provisioned machine
//! (such as a CI runner) otherwise has it on by default, which this file's tests
//! cannot see through the five plain values alone.
//!
//! # Why every test here is `#[ignore]`
//!
//! The guard restores what it changed, but restoring is a *recovery*, not a *promise*:
//! it runs on the developer's own machine, against the key their browser and every
//! other program on it reads, and only a `Drop` that actually runs puts it back. A
//! killed process, a debugger stop, a power loss — any of those leaves fixture values
//! behind, and a defect in this very fixture has, on at least one real occasion,
//! destroyed this machine's real `ProxyOverride`. Nothing about the crate requires a
//! developer to accept that risk on every `cargo test`.
//!
//! So these tests do not run by default. They are not broken and not deferred: **CI is
//! where they belong**, on a throwaway `windows-latest` runner that is discarded
//! afterwards, and `.github/workflows/ci.yml` passes `--include-ignored` to its unit-test
//! step and to its three integration-test steps, so they run there on every push. (The
//! separate feature-matrix job deliberately does not: it exists for build shapes nothing
//! else runs, not for the machine's real settings.) To run them here
//! deliberately:
//!
//! ```text
//! cargo test --test windows_watch --all-features -- --ignored --test-threads=1
//! ```
//!
//! The same applies to `tests/pac_winhttp_registry.rs` and to the three
//! `wpad_fallback*` unit tests in `src/sys/win/mod.rs`.
#![cfg(windows)]

mod support;

use std::time::{Duration, Instant};

use proxy_watch::{ProxyMode, ProxyWatcher, Scheme, WatchEvent, WatchOptions, read_with_options};

use support::{Next, expect_config, next};

use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_BINARY,
    REG_CREATE_KEY_DISPOSITION, REG_CREATED_NEW_KEY, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
    REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW, RegDeleteKeyExW, RegDeleteTreeW, RegDeleteValueW,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
use windows::core::PCWSTR;

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// The group-policy Internet Settings leaf and its strict ancestors, leaf first.
/// The leaf duplicates the private `POLICY_INTERNET_SETTINGS` string in
/// `src/sys/win/mod.rs`; the remaining five match the ancestor walk
/// `group_policy_ancestors()` in `src/sys/win/notify.rs` (which deliberately
/// omits the leaf). Used by [`PolicyKeyGuard`] to create/tear down the path.
const GROUP_POLICY_ANCESTORS: [&str; 6] = [
    r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
    r"Software\Policies\Microsoft\Windows\CurrentVersion",
    r"Software\Policies\Microsoft\Windows",
    r"Software\Policies\Microsoft",
    r"Software\Policies",
    "Software",
];

/// The values the guard snapshots and restores.
const MANAGED_VALUES: [&str; 5] = [
    "ProxyEnable",
    "ProxyServer",
    "ProxyOverride",
    "AutoConfigURL",
    "AutoDetect",
];

/// A proxy address no real machine uses, so a leftover value cannot be mistaken for a
/// genuine configuration.
const TEST_PROXY: &str = "127.0.0.1:18080";

/// A second such address, for the change that has to arrive *after* one already has. It
/// differs from [`TEST_PROXY`] because a `RegSetValueExW` writing back the value a key
/// already holds signals nothing — the measurement
/// `rewriting_an_identical_value_does_not_emit` is built on that.
const TEST_PROXY_MOVED: &str = "127.0.0.1:18081";

/// `HKCU\...\Internet Settings\Connections`, which stores the per-connection LAN
/// settings a second time, as two binary blobs. See
/// [`RegistryGuard::force_wpad_auto_detect_off`] for why this fixture has to reach
/// into it at all.
const CONNECTIONS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

/// The two values under [`CONNECTIONS`] that mirror each other and carry
/// `INTERNET_PER_CONN_FLAGS` — see [`RegistryGuard::force_wpad_auto_detect_off`].
const CONNECTION_SETTINGS_VALUES: [&str; 2] = ["DefaultConnectionSettings", "SavedLegacySettings"];

/// Byte offset of the `INTERNET_PER_CONN_FLAGS` `DWORD` inside each blob named in
/// [`CONNECTION_SETTINGS_VALUES`]: `u32 version; u32 counter; u32 flags; u32
/// proxy_len; u32 bypass_len; u32 pac_len;` followed by that many bytes of string
/// data. Undocumented by Microsoft ([Setting and Retrieving Internet Options][ms-ie-opts]
/// instead warns: *"Client applications should not use registry functions to change the
/// default values of the Internet options..."*), but this offset has been stable since
/// Windows 7 and holds against a real blob on Windows 11: the bytes at this offset flip in
/// lockstep with the real "Automatically detect settings" checkbox, toggled through the
/// documented `InternetSetOption` per-connection API, while every other byte (including
/// the stale proxy/bypass/PAC strings) stays untouched. That is also what shows that
/// `WinHttpGetIEProxyConfigForCurrentUser` ignores those strings in the blob and reads the
/// plain `ProxyServer`/`ProxyOverride`/`AutoConfigURL` values instead. Only the
/// auto-detect *flag* comes from here.
///
/// [ms-ie-opts]: https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options
const CONNECTION_FLAGS_OFFSET: usize = 8;

/// The `PROXY_TYPE_AUTO_DETECT` bit of `INTERNET_PER_CONN_FLAGS` (`wininet.h`).
const PROXY_TYPE_AUTO_DETECT: u32 = 0x08;

/// The `PROXY_TYPE_DIRECT` bit of `INTERNET_PER_CONN_FLAGS` (`wininet.h`), used for the
/// flags word of a freshly minted blob in
/// [`RegistryGuard::force_wpad_auto_detect_off`].
const PROXY_TYPE_DIRECT: u32 = 0x01;

/// Every bit `INTERNET_PER_CONN_FLAGS` defines (`wininet.h`): `PROXY_TYPE_DIRECT`,
/// `PROXY_TYPE_PROXY`, `PROXY_TYPE_AUTO_PROXY_URL` and `PROXY_TYPE_AUTO_DETECT`.
///
/// Used to recognise the flags word rather than trust its offset — a DWORD carrying bits
/// outside this mask is not `INTERNET_PER_CONN_FLAGS`, whatever else it may be.
const PROXY_TYPE_KNOWN_BITS: u32 = 0x0f;

// --------------------------------------------------------------------------------
// tests
// --------------------------------------------------------------------------------

/// The current configuration is delivered once, at subscription time.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn subscription_emits_the_current_configuration() {
    let guard = RegistryGuard::acquire();
    guard.write_direct_baseline();

    let mut watcher = ProxyWatcher::new().expect("watcher");
    let first = expect_config(&mut watcher, Duration::from_secs(1));

    assert_eq!(first, watcher.current());
    assert_eq!(first.effective, ProxyMode::Direct);
    assert!(
        first
            .source(proxy_watch::ProxyConfigSource::Registry)
            .is_some(),
        "the per-user registry must always appear in `sources`: {:?}",
        first.sources
    );
}

/// One logical change produces exactly one emission, within the 1 second
/// detection-latency SLO — and the per-user key is still armed afterwards, so a second
/// change arrives too.
///
/// The second half is what holds `crate::sys::win::notify::rearm` on the route every
/// watcher has. `RegNotifyChangeKeyValue` is single-shot, so a watcher that stopped
/// re-arming would deliver its first change and then nothing, for the rest of its life,
/// with `health()` still reporting every route live. The only other test in this file that
/// asks for a second notification through one registration is
/// `lifting_a_group_policy_is_detected_and_leaves_the_route_alive`, which arms an HKLM
/// policy key and self-skips without an elevated process.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn a_registry_change_is_emitted_exactly_once() {
    let guard = RegistryGuard::acquire();
    guard.write_direct_baseline();

    let mut watcher = ProxyWatcher::new().expect("watcher");
    let initial = expect_config(&mut watcher, Duration::from_secs(1));
    assert_eq!(initial.effective, ProxyMode::Direct);

    // `ProxyEnable` is written last: while it is still 0 the intermediate states all
    // read back as `Direct`, so this is genuinely one *logical* change even if the
    // three writes end up in different debounce windows.
    let started = Instant::now();
    guard
        .settings
        .write("ProxyServer", &Value::Sz(TEST_PROXY.to_owned()));
    guard.settings.write(
        "ProxyOverride",
        &Value::Sz("<local>;*.example.test".to_owned()),
    );
    guard.settings.write("ProxyEnable", &Value::Dword(1));

    let changed = expect_config(&mut watcher, Duration::from_secs(2));
    let latency = started.elapsed();
    println!("detection latency (debounce included): {latency:?}");

    let endpoint = changed
        .effective
        .endpoint_for(Scheme::Http)
        .expect("a manual proxy endpoint");
    assert_eq!(endpoint.authority(), TEST_PROXY);
    let bypass = changed.effective.bypass().expect("bypass rules");
    assert!(bypass.excludes_simple_hostnames());
    assert!(bypass.matches_authority("host.example.test"));

    assert!(
        latency < Duration::from_secs(1),
        "detection latency SLO violated: {latency:?}"
    );
    assert_eq!(changed, watcher.current());

    // Exactly once: nothing else may arrive for the same change.
    assert!(
        matches!(
            next(&mut watcher, Duration::from_millis(800)),
            Next::Timeout
        ),
        "a single logical change emitted more than one snapshot"
    );

    // Then move the proxy again. This snapshot can only reach the caller through a
    // registration renewed after the first wake.
    guard
        .settings
        .write("ProxyServer", &Value::Sz(TEST_PROXY_MOVED.to_owned()));
    let moved = expect_config(&mut watcher, Duration::from_secs(2));
    assert_eq!(
        moved
            .effective
            .endpoint_for(Scheme::Http)
            .expect("a manual proxy endpoint")
            .authority(),
        TEST_PROXY_MOVED,
        "the watcher stopped listening after the change it already reported"
    );
}

/// The same SLO under the condition [`proxy_watch::WatchOptions::debounce`]'s own
/// documentation makes the promise for: a storm of writes that outlasts the window.
///
/// That documentation calls the window *fixed* — it "opens on the first change, and further
/// changes inside it are folded into the same emission rather than pushing it back. The wait
/// after a change is therefore bounded by this value however long the storm of changes behind
/// it lasts." It is a promise the public API makes on every platform, and on this one this
/// test is the only thing holding it: reopening the deadline on each `Wake::Key` — the
/// sliding window that sentence exists to deny — leaves every other test in this file green,
/// the one above included, because a single logical change never reopens anything.
///
/// What it costs is a machine whose Internet Settings are being rewritten in a loop: the
/// watcher reports nothing at all until the rewriting stops. That is not exotic. A single
/// trip through the Windows proxy settings UI writes several of these values, and each one
/// whose bytes actually move fires `RegNotifyChangeKeyValue` — enough of them, close enough
/// together, to be the storm. Only the ones that move: a `RegSetValueExW` writing back what
/// the value already holds signals nothing, which is why the loop below rotates its data
/// rather than repeating it, and is the measurement
/// `rewriting_an_identical_value_does_not_emit` at the bottom of this file is built on.
///
/// The storm runs on this thread rather than a second one because [`RegistryGuard`]'s `HKEY`
/// is not `Send`, and polling between writes is the truer shape anyway: the writes go on
/// while the watcher is being waited on.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn a_storm_that_outlasts_the_window_is_still_reported_inside_it() {
    let guard = RegistryGuard::acquire();
    guard.write_direct_baseline();

    let mut watcher = ProxyWatcher::new().expect("watcher");
    assert_eq!(
        expect_config(&mut watcher, Duration::from_secs(1)).effective,
        ProxyMode::Direct
    );

    // Writes for well past the 200 ms default window, each one moving bytes that are
    // really there. Measured, and the reason this loop does not simply rewrite the same
    // value: a `RegSetValueExW` whose data equals what the value already holds does not
    // signal `RegNotifyChangeKeyValue` at all. Sixteen such writes across eight passes
    // produced two wakes on this machine — one for each of the two values that actually
    // moved — so a storm built out of them is not a storm, and this test would have gone
    // green under the very mutation it exists to catch.
    //
    // `ProxyServer` and `ProxyEnable` are therefore set once, and the storm runs on
    // `ProxyOverride`, whose two values differ from each other and leave the proxy this
    // test reads about untouched.
    let started = Instant::now();
    let storm_until = started + Duration::from_secs(2);
    let mut arrived = None;
    let mut passes = 0usize;
    guard
        .settings
        .write("ProxyServer", &Value::Sz(TEST_PROXY.to_owned()));
    guard.settings.write("ProxyEnable", &Value::Dword(1));
    while Instant::now() < storm_until {
        let bypass = if passes.is_multiple_of(2) {
            "*.storm-a.example.test"
        } else {
            "*.storm-b.example.test"
        };
        guard
            .settings
            .write("ProxyOverride", &Value::Sz(bypass.to_owned()));
        passes += 1;
        if let Next::Item(WatchEvent::Snapshot { state, .. }) =
            next(&mut watcher, Duration::from_millis(25))
        {
            arrived = Some((state.config, started.elapsed()));
            break;
        }
    }
    println!("storm passes before the snapshot arrived: {passes}");

    let Some((config, latency)) = arrived else {
        panic!(
            "the storm held the read off past the window: nothing in {:?}",
            started.elapsed()
        );
    };
    println!("registry detection latency under a storm: {latency:?}");
    assert_eq!(
        config
            .effective
            .endpoint_for(Scheme::Http)
            .expect("a manual proxy endpoint")
            .authority(),
        TEST_PROXY
    );
    assert!(
        latency < Duration::from_secs(1),
        "detection latency SLO violated under a storm: {latency:?}"
    );
}

/// A write that does not change the effective configuration is swallowed — and on Windows
/// it is swallowed one layer lower than this test can see.
///
/// The reading to resist is that the write fires `RegNotifyChangeKeyValue` and the crate's
/// equality check is what stops it. Measured while building
/// `a_storm_that_outlasts_the_window_is_still_reported_inside_it`: it does not fire.
/// Fourteen `RegSetValueExW` calls whose data equalled what the value already held produced
/// **zero** wakes, against two wakes for the two writes that moved bytes. So the watcher is
/// never woken here at all, and this test cannot be evidence for
/// [`proxy_watch::ProxyWatcher`]'s equality skip. That skip is held directly, at the layer
/// it lives in, by `the_initial_value_is_queued_once_and_equality_skips_repeats` in
/// `src/watch.rs`.
///
/// What is left is still worth holding, and is the same promise from the caller's side:
/// touching a value without changing it produces no event, whichever of the two layers
/// declines to produce it. The second half is what keeps that from being vacuous.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn rewriting_an_identical_value_does_not_emit() {
    let guard = RegistryGuard::acquire();
    guard.write_manual_baseline();

    let mut watcher = ProxyWatcher::new().expect("watcher");
    let initial = expect_config(&mut watcher, Duration::from_secs(1));
    assert!(!initial.effective.is_direct());

    // A real registry write that leaves the configuration byte for byte identical; see the
    // doc comment for which layer actually declines to report it.
    let unchanged = guard.settings.read("ProxyOverride");
    guard.settings.write("ProxyOverride", &unchanged);
    guard
        .settings
        .write("ProxyServer", &guard.settings.read("ProxyServer"));

    assert!(
        matches!(
            next(&mut watcher, Duration::from_millis(800)),
            Next::Timeout
        ),
        "an unchanged touch must not be emitted"
    );

    // ... and the watcher is still alive afterwards, which is what makes the assertion
    // above meaningful rather than vacuous.
    guard.settings.write("ProxyEnable", &Value::Dword(0));
    let after = expect_config(&mut watcher, Duration::from_secs(2));
    assert_eq!(after.effective, ProxyMode::Direct);
}

/// `Drop` stops the thread and releases every handle.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn dropping_watchers_leaks_neither_threads_nor_handles() {
    let guard = RegistryGuard::acquire();
    guard.write_direct_baseline();

    // Warm up: the first watcher makes the process load winhttp.dll and friends, whose
    // handles must not be counted as a leak.
    drop(ProxyWatcher::new().expect("watcher"));

    let before = process_handle_count();
    let started = Instant::now();
    for _ in 0..30 {
        let watcher = ProxyWatcher::new().expect("watcher");
        // Touch the watcher so the thread has certainly started.
        let _ = watcher.current();
        drop(watcher);
    }
    let elapsed = started.elapsed();
    let after = process_handle_count();

    // `Watch::drop` joins the thread, so a thread that refused to stop would hang here
    // rather than accumulate; the elapsed time is the actual thread-leak assertion.
    assert!(
        elapsed < Duration::from_secs(10),
        "30 create/drop cycles took {elapsed:?}; the watcher thread is not stopping promptly"
    );
    assert!(
        after <= before + 4,
        "handle count grew from {before} to {after} over 30 create/drop cycles"
    );
}

/// The group policy source is opt-out, and turning it off keeps the per-user view.
///
/// `with_group_policy(false)` only gates [`proxy_watch::ProxyConfigSource::GroupPolicy`];
/// it does not gate the always-on, purely informational
/// [`proxy_watch::ProxyConfigSource::WinHttpDefault`] source (`src/sys/win/mod.rs`'s
/// module docs), which every `read_config` call attempts regardless of `WatchOptions` and
/// which never drives `effective`. So this test checks for `GroupPolicy`'s absence and
/// `Registry`'s presence directly, rather than asserting a total source count.
///
/// The absence half is vacuous on a host with no proxy GPO, which is most hosts and the
/// usual CI runner: `write_direct_baseline` writes per-user keys, and this test does not
/// take the `PolicyKeyGuard` that installs a real policy — which needs elevation anyway.
/// What is not vacuous anywhere is the *relation* between the two source lists,
/// and `read_once.rs`'s `turning_group_policy_off_removes_that_source_and_disturbs_no_other`
/// pins that without `--ignored`. This test's own value is the live watcher: that the
/// option survives construction and a shorter debounce window still delivers.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn group_policy_watching_can_be_disabled() {
    let guard = RegistryGuard::acquire();
    guard.write_direct_baseline();

    let options = WatchOptions::new()
        .with_group_policy(false)
        .with_debounce(Duration::from_millis(20));
    let mut watcher = ProxyWatcher::with_options(options).expect("watcher");

    let initial = expect_config(&mut watcher, Duration::from_secs(1));
    assert!(
        initial
            .source(proxy_watch::ProxyConfigSource::GroupPolicy)
            .is_none(),
        "group policy must not be consulted when disabled: {:?}",
        initial.sources
    );
    assert!(
        initial
            .source(proxy_watch::ProxyConfigSource::Registry)
            .is_some(),
        "the per-user registry must still be consulted: {:?}",
        initial.sources
    );

    // A shorter debounce window must still deliver the change.
    guard
        .settings
        .write("ProxyServer", &Value::Sz(TEST_PROXY.to_owned()));
    guard.settings.write("ProxyEnable", &Value::Dword(1));
    let changed = expect_config(&mut watcher, Duration::from_secs(2));
    assert_eq!(
        changed
            .effective
            .endpoint_for(Scheme::All)
            .expect("endpoint")
            .authority(),
        TEST_PROXY
    );
}

/// Turning group policy off must suppress a policy that is **actually there**.
///
/// That is the option's whole purpose, and this test is the only thing measuring it: every
/// other place it is asserted runs on a machine with no proxy GPO and so asserts the absence
/// of something absent anyway. `group_policy_watching_can_be_disabled` above installs no
/// policy; `tests/read_once.rs`'s
/// `turning_group_policy_off_removes_that_source_and_disturbs_no_other` says in its own
/// comment that its first half is vacuous without one. The two tests that *do* install a
/// policy both read with the option left on. Dropping the `options.watch_group_policy &&`
/// guard in `read_config` therefore leaves the rest of the tree green, on this machine and
/// on the CI runner alike.
///
/// A watcher is not needed and would only add a debounce window to wait on — the option is
/// read on the way into `read_config`, and [`read_with_options`] takes the same path. The
/// read with the option *on* is not decoration: it is what makes the assertion below a
/// suppression rather than a machine that had no policy to suppress.
///
/// Needs an elevated process to write under `HKLM`, and self-skips through
/// `PolicyKeyGuard::prepare` exactly like the two tests below it.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn turning_group_policy_off_suppresses_a_policy_that_is_really_there() {
    let registry = RegistryGuard::acquire();
    registry.write_direct_baseline();

    let Some(policy) = PolicyKeyGuard::prepare() else {
        return;
    };
    policy.write_manual_baseline();

    let seen = read_with_options(&WatchOptions::new()).expect("read with group policy on");
    assert!(
        seen.source(proxy_watch::ProxyConfigSource::GroupPolicy)
            .is_some(),
        "the policy just written must be visible, or the suppression below proves nothing: {:?}",
        seen.sources
    );
    assert!(
        !seen.effective.is_direct(),
        "and it must be the effective answer, over the direct HKCU baseline: {:?}",
        seen.effective
    );

    let suppressed = read_with_options(&WatchOptions::new().with_group_policy(false))
        .expect("read with group policy off");
    assert!(
        suppressed
            .source(proxy_watch::ProxyConfigSource::GroupPolicy)
            .is_none(),
        "an existing policy must not be consulted when the option is off: {:?}",
        suppressed.sources
    );
    assert_eq!(
        suppressed.effective,
        ProxyMode::Direct,
        "with the policy out of the way the direct HKCU baseline answers: {:?}",
        suppressed.sources
    );
}

/// A PAC URL is reported as [`ProxyMode::Pac`], and beats the static servers.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn an_auto_config_url_is_reported_as_pac() {
    let guard = RegistryGuard::acquire();
    guard.write_manual_baseline();

    let mut watcher = ProxyWatcher::new().expect("watcher");
    let _ = expect_config(&mut watcher, Duration::from_secs(1));

    guard.settings.write(
        "AutoConfigURL",
        &Value::Sz("http://pac.example.test/proxy.pac".to_owned()),
    );

    let changed = expect_config(&mut watcher, Duration::from_secs(2));
    match &changed.effective {
        ProxyMode::Pac { url, .. } => assert_eq!(url.as_str(), "http://pac.example.test/proxy.pac"),
        other => panic!("expected a PAC mode, got {other:?}"),
    }
}

/// A group policy key created **after** the watcher has
/// already started must still be detected. `Watch::armed` cannot watch the leaf key
/// directly for this (a key that does not exist yet cannot be opened at all), so
/// `arm_group_policy_key` instead watches the nearest existing ancestor with
/// `bWatchSubtree = TRUE` — this test is the end-to-end proof that the ancestor
/// actually catches the leaf's creation.
///
/// Writing under `HKEY_LOCAL_MACHINE\Software\Policies` needs administrator privileges,
/// which a plain `cargo test` run does not have. Rather than fail there, this test
/// probes for write access first and skips when it is missing — through
/// `support::skip_or_fail`, so the skip stays quiet locally but turns the job red under
/// CI. That is deliberately *not* the always-quiet, allow-listed skip
/// `tests/linux_watch.rs` uses for its Flatpak-only test; `PolicyKeyGuard::prepare`'s own
/// doc has the reason. To exercise it for real, open an elevated ("Run as administrator")
/// shell and run:
///
/// ```text
/// cargo test --test windows_watch -- --test-threads=1 --nocapture group_policy_key_created_after
/// ```
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn a_group_policy_key_created_after_the_watcher_starts_is_detected() {
    // `PolicyKeyGuard::prepare` reports why, distinguishing an allow-listed developer-
    // machine skip from a `support::skip_or_fail`-gated one — see its doc.
    let Some(guard) = PolicyKeyGuard::prepare() else {
        return;
    };

    let mut watcher = ProxyWatcher::new().expect("watcher");
    let initial = expect_config(&mut watcher, Duration::from_secs(1));
    assert!(
        initial
            .source(proxy_watch::ProxyConfigSource::GroupPolicy)
            .is_none(),
        "the group policy key must not exist yet, or this test would prove nothing: {:?}",
        initial.sources
    );

    // The change under test: the leaf key (and any still-missing ancestors above it,
    // down to `guard`'s `created_root`) is created here, strictly after the watcher
    // armed itself over whichever ancestor already existed at that time.
    guard.write_manual_baseline();

    let changed = expect_config(&mut watcher, Duration::from_secs(2));
    assert!(
        changed
            .source(proxy_watch::ProxyConfigSource::GroupPolicy)
            .is_some(),
        "creating the group policy key after the watcher started must still be detected \
         via the watched ancestor: {:?}",
        changed.sources
    );
}

/// A group policy key **deleted** while the watcher runs must be detected too, and must
/// leave the route able to see the next policy.
///
/// This is the scenario `group_policy_ancestors()` exists for, and it says so: watching the
/// leaf directly would let a `gpupdate` that lifts a policy delete the key out from under
/// the handle, fail the re-arm, and retire
/// [`proxy_watch::ProxyConfigSource::GroupPolicy`] for the life of the process — after
/// which a policy re-applied later is never seen again. This test is the only thing that
/// measures that consequence; `the_leaf_key_itself_is_never_a_candidate` measures the
/// candidate *list* alone.
///
/// So the policy is installed **before** the watcher arms — that is what puts the armed key
/// on the leaf's parent rather than further up — and the test then removes it, observes the
/// removal, and re-applies it. The second detection is the whole point: it can only happen
/// through a registration that outlived the deletion.
///
/// Needs an elevated process for the same reason
/// `a_group_policy_key_created_after_the_watcher_starts_is_detected` does, and self-skips
/// the same way through `PolicyKeyGuard::prepare`.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn lifting_a_group_policy_is_detected_and_leaves_the_route_alive() {
    let registry = RegistryGuard::acquire();
    registry.write_direct_baseline();

    let Some(policy) = PolicyKeyGuard::prepare() else {
        return;
    };
    // Before the watcher, unlike the creation test above: the leaf exists when
    // `arm_group_policy_key` runs, so the ancestor it settles on is the leaf's parent —
    // the key the deletion below has to leave standing.
    policy.write_manual_baseline();

    let mut watcher = ProxyWatcher::new().expect("watcher");
    let initial = expect_config(&mut watcher, Duration::from_secs(1));
    assert!(
        initial
            .source(proxy_watch::ProxyConfigSource::GroupPolicy)
            .is_some(),
        "the policy was applied before the watcher started: {:?}",
        initial.sources
    );
    // Not `effective` — a group policy entry never is, see
    // [`proxy_watch::ProxyConfigSource::GroupPolicy`]. What its removal has to change is
    // the source list, and the entry has to be the policy's own value for that to mean
    // anything: `write_manual_baseline` wrote a static proxy under HKLM while
    // `write_direct_baseline` wrote `Direct` under HKCU, so the two disagree here and the
    // answer is the per-user one.
    assert!(
        !initial
            .source(proxy_watch::ProxyConfigSource::GroupPolicy)
            .expect("just asserted")
            .is_direct(),
        "the policy entry must carry the static proxy that was written to it: {:?}",
        initial.sources
    );
    assert_eq!(
        initial.effective,
        ProxyMode::Direct,
        "a policy proxy Windows itself does not read must not answer over the per-user \
         Direct baseline: {:?}",
        initial.sources
    );

    // The lift itself: the leaf and everything in it, and nothing above it.
    delete_hklm_key_tree(GROUP_POLICY_ANCESTORS.first().expect("non-empty"));

    let lifted = expect_config(&mut watcher, Duration::from_secs(2));
    assert!(
        lifted
            .source(proxy_watch::ProxyConfigSource::GroupPolicy)
            .is_none(),
        "the policy is gone: {:?}",
        lifted.sources
    );
    assert_eq!(
        lifted.effective,
        ProxyMode::Direct,
        "the per-user Direct baseline answered before the lift and still answers after it \
         — unchanged by design, and asserted so a lift that broke the read is not read as \
         a lift that worked"
    );
    assert!(
        !watcher
            .health()
            .degraded
            .contains(&proxy_watch::ProxyConfigSource::GroupPolicy),
        "the deletion must not retire the group policy route: {:?}",
        watcher.health()
    );

    // And the route still works: a policy applied after the lift is seen.
    policy.write_manual_baseline();
    let reapplied = expect_config(&mut watcher, Duration::from_secs(2));
    assert!(
        reapplied
            .source(proxy_watch::ProxyConfigSource::GroupPolicy)
            .is_some(),
        "a policy re-applied after a lift must still be detected: {:?}",
        reapplied.sources
    );
}

/// `health()` merges construction-time [`BackendHealth`] with
/// whatever the backend has learned since — end to end, this is
/// `crate::sys::win::notify::Watch::health` handed to `crate::watch::merge_runtime_health`
/// along with the (empty, on a healthy watcher) runtime state `crate::watch::Shared` holds.
///
/// This test does **not** attempt to trigger a genuine *runtime* degrade (a [`rearm`]
/// failure after construction already succeeded): every route [`ProxyWatcher::new`]
/// establishes is a fixed, hardcoded path — `HKCU\...\Internet Settings`,
/// `HKLM\...\Internet Settings`, the group policy ancestor under
/// `HKEY_LOCAL_MACHINE\Software\Policies` — none of which this test file can redirect to
/// a disposable scratch key, so making one fail for real means denying this very
/// process's own access to a live per-user or per-machine registry key (an ACL edit).
/// That is invasive on a machine this fixture does not own outright, and risky to leave
/// behind if the test panicked mid-way before restoring the ACL — unlike every value
/// [`RegistryGuard`] touches, which is a plain value write/delete safely undone from
/// `Drop`. It is not attempted here for the same reason `PolicyKeyGuard` refuses to touch
/// a *real* pre-existing group policy key rather than a synthetic one: safety of the host
/// machine over completeness of the test.
///
/// What this test does check is that `health()` actually threads a real value through
/// that whole chain on a normal, healthy machine — the same baseline assumption every
/// other test in this file already makes (full access, no group policy applied) — rather
/// than silently returning a stale or default-constructed [`WatchHealth`].
///
/// Two corrections to the paragraphs above, both measured rather than argued.
///
/// The claim that no route can be redirected to a disposable key is true of this file and
/// false of the crate: `RegOverridePredefKey` redirects `HKEY_LOCAL_MACHINE` for the
/// calling process alone, needs no privilege, and writes nothing outside
/// `HKEY_CURRENT_USER`. Two of the three routes are under HKLM, so an *empty* shadow fails
/// both with none of the invasiveness this paragraph weighed. Only the HKCU route would
/// still need an ACL edit — and that one is fatal rather than degrading, so it is not the
/// case the reasoning was reaching for anyway. `tests/windows_group_policy.rs` holds it
/// now; the redirection is process-wide, which is why it is over there and not here.
///
/// And "rather than silently returning a stale or default-constructed [`WatchHealth`]"
/// claims more than the assertions below reach. A wholly default value is caught, because
/// `has_live_notifications` would be `false`. A value that kept that field and dropped
/// only `degraded` is not: on this machine `degraded` is empty either way, so replacing
/// `Watch::health`'s copy of it with `Vec::new()` left this test green.
#[test]
#[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
fn health_reports_every_route_live_on_a_normal_machine() {
    let guard = RegistryGuard::acquire();
    guard.write_direct_baseline();

    let watcher = ProxyWatcher::new().expect("watcher");
    let health = watcher.health();

    assert!(
        health.is_fully_live(),
        "a freshly constructed watcher on a machine with no group policy applied and \
         full registry access must report every route live: {health:?}"
    );
    assert_eq!(
        health.poll_interval, None,
        "no poll interval was configured: {health:?}"
    );

    // A live watcher is the only thing that can print one, and this is the only test that
    // holds one, so this assertion is the whole of what answers for the hand-written `Debug`.
    // Dropping the `health` field and closing the `..` each leave the rest of the tree green
    // — the first
    // leaves a dump that answers "what is this watcher doing" with the configuration alone,
    // which is the half a caller could already get from `current()`; the second claims the
    // dump is complete while the thread and the queue stay unprinted. The values defer to
    // their own renderings, which this impl does not own.
    let state = watcher.state();
    assert_eq!(
        format!("{watcher:?}"),
        format!(
            "ProxyWatcher {{ current: {:?}, health: {:?}, .. }}",
            state.config.effective, state.health
        )
    );
}

// --------------------------------------------------------------------------------
// process handle counting (used by `dropping_watchers_leaks_neither_threads_nor_handles`)
// --------------------------------------------------------------------------------
//
// Stream driving (`Next`, `next`, `expect_config`) now lives in `tests/support/mod.rs`,
// shared with `tests/linux_watch.rs` and `tests/mac_watch.rs` — see the `use support::`
// import above.

fn process_handle_count() -> u32 {
    let mut count = 0u32;
    // SAFETY: `GetCurrentProcess` returns a pseudo handle that is always valid, and
    // `count` is a valid out-parameter.
    unsafe {
        GetProcessHandleCount(GetCurrentProcess(), &raw mut count).expect("GetProcessHandleCount");
    }
    count
}

// --------------------------------------------------------------------------------
// registry fixture
// --------------------------------------------------------------------------------

/// A registry value in one of the three states the proxy settings use.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Absent,
    Dword(u32),
    Sz(String),
}

/// An open handle to `HKCU\...\Internet Settings` with read and write access.
#[derive(Debug)]
struct Settings(HKEY);

impl Settings {
    fn open() -> Self {
        let path = wide(INTERNET_SETTINGS);
        let mut key = HKEY::default();
        // SAFETY: `path` is a NUL terminated UTF-16 buffer alive across the call and
        // `key` is a valid out-parameter.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(path.as_ptr()),
                None,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                &raw mut key,
            )
        };
        assert_eq!(status.0, 0, "opening {INTERNET_SETTINGS} for writing");
        Self(key)
    }

    fn read(&self, name: &str) -> Value {
        let name_w = wide(name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut len = 0u32;
        // SAFETY: a null data pointer asks for the required size; all other pointers
        // are valid out-parameters.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(name_w.as_ptr()),
                None,
                Some(&raw mut kind),
                None,
                Some(&raw mut len),
            )
        };
        if status.0 != 0 {
            return Value::Absent;
        }

        let mut data = vec![0u8; len as usize];
        // SAFETY: `data` has `len` writable bytes.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(name_w.as_ptr()),
                None,
                Some(&raw mut kind),
                Some(data.as_mut_ptr()),
                Some(&raw mut len),
            )
        };
        assert_eq!(status.0, 0, "reading {name}");
        data.truncate(len as usize);

        if kind == REG_DWORD && data.len() >= 4 {
            Value::Dword(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        } else if kind == REG_SZ {
            let units: Vec<u16> = data
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .take_while(|unit| *unit != 0)
                .collect();
            Value::Sz(String::from_utf16_lossy(&units))
        } else {
            Value::Absent
        }
    }

    fn write(&self, name: &str, value: &Value) {
        let name_w = wide(name);
        let status = match value {
            Value::Absent => {
                // SAFETY: `name_w` is a NUL terminated UTF-16 buffer alive across the
                // call; deleting an absent value is reported, not undefined.
                unsafe { RegDeleteValueW(self.0, PCWSTR(name_w.as_ptr())) }
            }
            Value::Dword(number) => {
                let bytes = number.to_le_bytes();
                // SAFETY: as above; `bytes` is a live 4 byte buffer.
                unsafe {
                    RegSetValueExW(
                        self.0,
                        PCWSTR(name_w.as_ptr()),
                        None,
                        REG_DWORD,
                        Some(&bytes),
                    )
                }
            }
            Value::Sz(text) => {
                let text_w = wide(text);
                // SAFETY: `text_w` is a live UTF-16 buffer; the byte slice below covers
                // exactly its bytes, including the NUL terminator.
                let bytes = unsafe {
                    std::slice::from_raw_parts(text_w.as_ptr().cast::<u8>(), text_w.len() * 2)
                };
                // SAFETY: as above.
                unsafe {
                    RegSetValueExW(self.0, PCWSTR(name_w.as_ptr()), None, REG_SZ, Some(bytes))
                }
            }
        };
        // ERROR_FILE_NOT_FOUND when deleting an already absent value is fine.
        assert!(
            status.0 == 0 || (matches!(value, Value::Absent) && status.0 == 2),
            "writing {name}: error {}",
            status.0
        );
    }
}

impl Drop for Settings {
    fn drop(&mut self) {
        // SAFETY: the handle came from `RegOpenKeyExW` and is owned by `self`.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

/// An open handle to [`CONNECTIONS`], created if it did not already exist — see
/// [`RegistryGuard::force_wpad_auto_detect_off`] for why this fixture needs it at all.
#[derive(Debug)]
struct Connections {
    key: HKEY,
    /// Whether `open` had to create [`CONNECTIONS`]: [`RegistryGuard`]'s cue to delete
    /// the whole key again on `Drop` rather than leave behind a key this machine never
    /// had.
    created: bool,
}

impl Connections {
    fn open() -> Self {
        let path = wide(CONNECTIONS);
        let mut key = HKEY::default();
        let mut disposition = REG_CREATE_KEY_DISPOSITION::default();
        // SAFETY: `path` is a NUL terminated UTF-16 buffer alive across the call;
        // `key` and `disposition` are valid out-parameters. `Connections` is an
        // ordinary HKCU subkey, so creating it needs no special access or attributes.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(path.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                None,
                &raw mut key,
                Some(&raw mut disposition),
            )
        };
        assert_eq!(status.0, 0, "opening/creating {CONNECTIONS}");
        Self {
            key,
            created: disposition == REG_CREATED_NEW_KEY,
        }
    }

    /// Read a `REG_BINARY` value, or `None` when it is absent or a different type.
    fn read_binary(&self, name: &str) -> Option<Vec<u8>> {
        let name_w = wide(name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut len = 0u32;
        // SAFETY: a null data pointer asks for the required size; all other pointers
        // are valid out-parameters.
        let status = unsafe {
            RegQueryValueExW(
                self.key,
                PCWSTR(name_w.as_ptr()),
                None,
                Some(&raw mut kind),
                None,
                Some(&raw mut len),
            )
        };
        if status.0 != 0 {
            return None;
        }

        let mut data = vec![0u8; len as usize];
        // SAFETY: `data` has `len` writable bytes.
        let status = unsafe {
            RegQueryValueExW(
                self.key,
                PCWSTR(name_w.as_ptr()),
                None,
                Some(&raw mut kind),
                Some(data.as_mut_ptr()),
                Some(&raw mut len),
            )
        };
        assert_eq!(status.0, 0, "reading {name}");
        data.truncate(len as usize);
        (kind == REG_BINARY).then_some(data)
    }

    /// Write (`Some`) or delete (`None`) a `REG_BINARY` value.
    fn write_binary(&self, name: &str, value: Option<&[u8]>) {
        let name_w = wide(name);
        let status = match value {
            None => {
                // SAFETY: `name_w` is a NUL terminated UTF-16 buffer alive across the
                // call; deleting an absent value is reported, not undefined.
                unsafe { RegDeleteValueW(self.key, PCWSTR(name_w.as_ptr())) }
            }
            Some(bytes) => {
                // SAFETY: `name_w` and `bytes` are both alive across the call.
                unsafe {
                    RegSetValueExW(
                        self.key,
                        PCWSTR(name_w.as_ptr()),
                        None,
                        REG_BINARY,
                        Some(bytes),
                    )
                }
            }
        };
        // ERROR_FILE_NOT_FOUND when deleting an already absent value is fine.
        assert!(
            status.0 == 0 || (value.is_none() && status.0 == 2),
            "writing {name}: error {}",
            status.0
        );
    }
}

impl Drop for Connections {
    fn drop(&mut self) {
        // SAFETY: the handle came from `RegCreateKeyExW` and is owned by `self`.
        unsafe {
            let _ = RegCloseKey(self.key);
        }
    }
}

/// A minimal, valid `DefaultConnectionSettings`/`SavedLegacySettings` blob: no proxy,
/// no PAC, `PROXY_TYPE_DIRECT` only (`CONNECTION_FLAGS_OFFSET`'s doc comment explains
/// the layout). Used by [`RegistryGuard::force_wpad_auto_detect_off`] when the blob is
/// missing outright, which is itself enough to make
/// `WinHttpGetIEProxyConfigForCurrentUser` report auto-detect as on — a freshly
/// provisioned profile, such as a CI runner's, has never had "Automatically detect
/// settings" saved through the LAN settings dialog, so there is no flags byte to clear
/// and a whole blob has to be minted instead.
fn minimal_direct_connection_settings() -> Vec<u8> {
    let mut blob = Vec::with_capacity(24);
    blob.extend_from_slice(&70u32.to_le_bytes()); // version, observed constant
    blob.extend_from_slice(&1u32.to_le_bytes()); // counter
    blob.extend_from_slice(&PROXY_TYPE_DIRECT.to_le_bytes()); // flags
    blob.extend_from_slice(&0u32.to_le_bytes()); // proxy_len
    blob.extend_from_slice(&0u32.to_le_bytes()); // bypass_len
    blob.extend_from_slice(&0u32.to_le_bytes()); // pac_len
    blob
}

/// Serialises every test in this file that takes a [`RegistryGuard`]. They all patch the
/// *same* real `HKCU\...\Internet Settings` values, and cargo serialises test *binaries*,
/// not the tests inside one — so by default they run concurrently and overwrite each
/// other's fixtures. That race was measured, and it silently destroyed a real
/// `ProxyOverride` value on the machine it was measured on. Five lines of `std` rather
/// than a `serial_test` dependency, because one `Mutex` is the whole requirement.
static REGISTRY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Snapshots the proxy values (and the WPAD auto-detect baseline) on construction and
/// restores them on drop, panic or not.
#[derive(Debug)]
struct RegistryGuard {
    settings: Settings,
    saved: Vec<(&'static str, Value)>,
    connections: Connections,
    /// The original bytes of each value in [`CONNECTION_SETTINGS_VALUES`], `None`
    /// meaning it did not exist before this guard forced auto-detect off.
    connections_saved: Vec<(&'static str, Option<Vec<u8>>)>,
    /// Held for this guard's whole lifetime; see [`REGISTRY_LOCK`]. `Drop for
    /// RegistryGuard` runs before any field is dropped, so the restore completes while
    /// the lock is still held.
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl RegistryGuard {
    fn acquire() -> Self {
        // A poisoned lock means an earlier test panicked. Its guard still ran `Drop` on
        // the way out, so the registry is restored and this test may proceed;
        // propagating the poison would turn one real failure into a cascade.
        let _lock = REGISTRY_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let settings = Settings::open();
        let saved = MANAGED_VALUES
            .iter()
            .map(|name| (*name, settings.read(name)))
            .collect();

        let connections = Connections::open();
        let connections_saved = CONNECTION_SETTINGS_VALUES
            .iter()
            .map(|name| (*name, connections.read_binary(name)))
            .collect();

        let guard = Self {
            settings,
            saved,
            connections,
            connections_saved,
            _lock,
        };
        guard.force_wpad_auto_detect_off();
        guard
    }

    /// Force Windows' real "Automatically detect settings" (WPAD) off for the lifetime
    /// of this guard, independently of [`write_direct_baseline`](Self::write_direct_baseline)
    /// / [`write_manual_baseline`](Self::write_manual_baseline).
    ///
    /// Why this exists: `src/sys/win/mod.rs`'s `resolve_mode` checks auto-detect
    /// *first* and returns [`ProxyMode::WpadAutoDetect`] immediately when it is on,
    /// before even looking at `ProxyServer`/`AutoConfigURL`. On a developer's machine
    /// that switch has usually been off for a long time, so every test here appeared
    /// to control the effective configuration through the plain values alone. But
    /// `src/sys/win/mod.rs`'s primary read path, `WinHttpGetIEProxyConfigForCurrentUser`,
    /// does **not** derive `fAutoDetect` from the plain `AutoDetect` value this guard
    /// already snapshots in [`MANAGED_VALUES`] — confirmed by reproducing the exact CI
    /// failure locally — it derives it from
    /// `INTERNET_PER_CONN_FLAGS` in the `DefaultConnectionSettings` /
    /// `SavedLegacySettings` blobs under [`CONNECTIONS`], and defaults to "on" when
    /// that blob does not exist at all. GitHub's Windows runners are freshly
    /// provisioned, so both are true there: auto-detect defaults on, and no test in
    /// this file ever forced it off. Once that is the case, `resolve_mode`'s early
    /// return means every subsequent write to `ProxyServer`, `AutoConfigURL` and the
    /// rest never changes the *effective* mode away from `WpadAutoDetect` — which is
    /// exactly the CI failure this fixture was built to close: two tests see
    /// `WpadAutoDetect` where they expect `Direct`, and three more time out because the
    /// watcher correctly refuses to emit a config whose effective value never actually
    /// changed.
    /// Forcing this baseline once, here, makes every test's `write_direct_baseline` /
    /// `write_manual_baseline` call meaningful on both kinds of machine.
    ///
    /// ## Why not the documented `InternetSetOptionW` API instead
    ///
    /// WinINet has an official, documented way to flip this same bit:
    /// `InternetSetOptionW(INTERNET_OPTION_PER_CONNECTION_OPTION)` with an
    /// `INTERNET_PER_CONN_OPTION_LIST` carrying an `INTERNET_PER_CONN_FLAGS` option, and
    /// it does propagate cross-process — it writes through to the same
    /// `Connections` blobs this fixture patches directly, then broadcasts
    /// `INTERNET_OPTION_SETTINGS_CHANGED`/`INTERNET_OPTION_REFRESH` so other processes'
    /// WinINet/WinHTTP caches (including `WinHttpGetIEProxyConfigForCurrentUser`'s) pick
    /// it up; this was in fact how the CI failure described above was reproduced
    /// locally.
    ///
    /// This fixture stays with the blob approach, for two reasons:
    ///
    /// * `InternetSetOptionW(INTERNET_OPTION_PER_CONNECTION_OPTION)` takes a pointer to
    ///   an `INTERNET_PER_CONN_OPTION_LIST` whose `pOptions` field is an array of
    ///   `INTERNET_PER_CONN_OPTION` — a struct built around a C `union` selected by an
    ///   adjacent `dwOption` tag. Calling it correctly means constructing that layout by
    ///   hand and handing WinINet a raw pointer into it: non-trivial `unsafe` FFI, in a
    ///   fixture whose whole job is to be a trustworthy foundation for the tests above.
    ///   What this fixture does instead — read a blob's bytes, check a DWORD's bit
    ///   pattern, write the bytes back — needs no `unsafe` beyond the plain byte-slice
    ///   reads/writes [`Connections`] already does.
    /// * Cargo's feature unification applies across the whole build, not just to this
    ///   test binary: enabling `Win32_Networking_WinInet` even only as a dev-dependency
    ///   means a `cargo test` invocation compiles this crate's own **library** with that
    ///   feature turned on too, since `src/` and `tests/` share one build graph for that
    ///   command. If production code in `src/sys/win/` ever came to call a WinINet API
    ///   by mistake, a `cargo test` run would not catch it;
    ///   only `cargo build` or `cargo check --no-default-features` (neither of which
    ///   pulls in dev-dependencies) would notice the feature being reachable from `src/`
    ///   at all. Keeping `Win32_Networking_WinInet` out of the dependency tree entirely,
    ///   as this fixture does, avoids trading the (non-)issue of shipped dependency
    ///   weight for this quieter blind spot.
    ///
    /// This does mean depending on an undocumented format, which is mitigated by: (1)
    /// every byte this fixture ever writes back on `Drop` is a byte it read from this
    /// exact machine at [`acquire`](Self::acquire) time, never reconstructed from
    /// documentation — a misunderstood layout can at worst corrupt the *test* run, not
    /// the restore; (2) the one fact this fixture *does* assume about the layout, the
    /// flags offset in [`CONNECTION_FLAGS_OFFSET`], was confirmed empirically against a
    /// real blob by toggling the real "Automatically detect settings" checkbox through
    /// the very same official `InternetSetOptionW` API described above and observing
    /// which byte moved, not guessed from third-party writeups; (3) production code
    /// never parses this blob at all — `src/sys/win/mod.rs`'s `read_user_mode` falls
    /// back to the plain registry values if `WinHttpGetIEProxyConfigForCurrentUser`
    /// ever errors, so a malformed blob has a safety net there even though this test
    /// fixture doesn't need it; and (4) the blast radius is this test file alone —
    /// `src/` is untouched, so a layout surprise here cannot ship.
    fn force_wpad_auto_detect_off(&self) {
        for name in CONNECTION_SETTINGS_VALUES {
            let flags_range = CONNECTION_FLAGS_OFFSET..CONNECTION_FLAGS_OFFSET + 4;
            let patched = match self.connections.read_binary(name) {
                Some(mut bytes) if bytes.len() >= flags_range.end => {
                    let flags = u32::from_le_bytes(
                        bytes[flags_range.clone()].try_into().expect("4 byte slice"),
                    );
                    // The offset is the one assumption this guard makes about an
                    // undocumented layout, so it is checked rather than trusted. A real
                    // `INTERNET_PER_CONN_FLAGS` always has `PROXY_TYPE_DIRECT` and never
                    // has a bit outside the four this API defines; a DWORD that fails
                    // both is not the flags word, and clearing bit 3 of whatever it
                    // actually is would corrupt an unrelated setting quietly. Failing
                    // here instead says which assumption broke.
                    assert!(
                        flags & PROXY_TYPE_DIRECT != 0 && flags & !PROXY_TYPE_KNOWN_BITS == 0,
                        "{name} does not look like INTERNET_PER_CONN_FLAGS at offset \
                         {CONNECTION_FLAGS_OFFSET}: got {flags:#010x}, which has bits \
                         outside {PROXY_TYPE_KNOWN_BITS:#x} or lacks PROXY_TYPE_DIRECT. \
                         The blob layout this fixture patches may have changed; see the \
                         doc on `force_wpad_auto_detect_off`"
                    );
                    bytes[flags_range]
                        .copy_from_slice(&(flags & !PROXY_TYPE_AUTO_DETECT).to_le_bytes());
                    bytes
                }
                // Absent, or too short to contain a flags DWORD at all: neither can be
                // patched in place, so mint a fresh, definitely-auto-detect-off blob.
                _ => minimal_direct_connection_settings(),
            };
            self.connections.write_binary(name, Some(&patched));
        }
        settle();
    }

    /// A known "no proxy" starting point.
    fn write_direct_baseline(&self) {
        self.settings.write("AutoDetect", &Value::Absent);
        self.settings.write("AutoConfigURL", &Value::Absent);
        self.settings.write("ProxyServer", &Value::Absent);
        self.settings.write("ProxyOverride", &Value::Absent);
        self.settings.write("ProxyEnable", &Value::Dword(0));
        settle();
    }

    /// A known "static proxy" starting point.
    fn write_manual_baseline(&self) {
        self.settings.write("AutoDetect", &Value::Absent);
        self.settings.write("AutoConfigURL", &Value::Absent);
        self.settings
            .write("ProxyServer", &Value::Sz(TEST_PROXY.to_owned()));
        self.settings
            .write("ProxyOverride", &Value::Sz("<local>".to_owned()));
        self.settings.write("ProxyEnable", &Value::Dword(1));
        settle();
    }
}

/// Restores the five plain values and the `Connections` blobs this guard patched,
/// including the WPAD auto-detect bit
/// [`force_wpad_auto_detect_off`](RegistryGuard::force_wpad_auto_detect_off) cleared.
///
/// `Drop` runs on a panic (Rust unwinds through it) but **not** if this test binary is
/// killed outright — `SIGKILL`, a CI job timeout, or a developer's Ctrl+C-that-doesn't-
/// stop escalating to Task Manager. In that case the process ends mid-test with WPAD
/// auto-detect still forced off on the real machine that ran it, and nothing left to
/// restore it. This is a real residual risk, not a hypothetical one — every test
/// in this file runs against `HKCU`, a developer's or CI runner's actual registry — but
/// it has no code-level mitigation: there is no way to hook process termination signals
/// this reliably from a test binary, and reaching for one (a watchdog process, a
/// pre-test snapshot-and-diff step) would be a disproportionate amount of machinery for
/// a low-probability, low-blast-radius failure (a CI runner is thrown away after the
/// job; a developer machine left with auto-detect off is one settings-app toggle away
/// from fixed, and would surface immediately the next time the developer actually looks
/// at their proxy settings). Documenting it here, rather than attempting to close it, is
/// the deliberate choice.
///
/// `netsh winhttp reset proxy` is not the one-line fix it looks like:
/// `netsh winhttp` administers WinHTTP's *own* proxy store — a third store, separate
/// from both the plain `HKCU\...\Internet Settings` values and the `Connections` blobs
/// this guard patches — so resetting it would not restore the auto-detect bit this guard
/// cleared. Only the settings app (or Internet Options) writes the store that matters
/// here.
impl Drop for RegistryGuard {
    fn drop(&mut self) {
        for (name, value) in &self.saved {
            self.settings.write(name, value);
        }
        for (name, bytes) in &self.connections_saved {
            self.connections.write_binary(name, bytes.as_deref());
        }
        if self.connections.created {
            let path = wide(CONNECTIONS);
            // SAFETY: `path` is a NUL terminated UTF-16 buffer alive across the call.
            // `Connections` holds no subkeys of its own, only the values restored
            // above, so a plain delete (not `RegDeleteTreeW`) is enough; deleting a key
            // this guard itself just created cannot race a real policy the way the
            // HKLM group policy cleanup below has to guard against.
            unsafe {
                let _ = RegDeleteKeyExW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()), 0, None);
            }
        }
    }
}

// --------------------------------------------------------------------------------
// group policy fixture — `HKEY_LOCAL_MACHINE`, so this is the one part of this
// file that needs administrator privileges; see `PolicyKeyGuard::prepare`.
// --------------------------------------------------------------------------------

/// Prepares, and on `Drop` cleans up, a test that creates the HKLM group policy leaf
/// key while a watcher is already running.
///
/// `prepare` returns `None` — the caller's cue to self-skip — both when the process
/// cannot write under `HKEY_LOCAL_MACHINE` (not elevated) and when a *real* group
/// policy key already exists on this machine: overwriting or deleting that would be
/// destructive to the machine running the test, not a disposable test fixture.
///
/// The two cases are deliberately handled differently: a real GPO key already
/// present is legitimate on a developer's own machine — some of them are joined to a
/// domain, or have local policy configured by hand — and a freshly provisioned CI
/// runner should simply never hit that branch at all, so it is left as a plain,
/// explicitly commented skip rather than routed through `support::skip_or_fail`
/// (consistent with that function's allow-list policy — see its doc). Lacking write
/// access under `HKEY_LOCAL_MACHINE`, on the other hand, is a precondition no one can
/// read off the workflow file; routing it through `support::skip_or_fail` makes it
/// observable — either CI already runs this job elevated and the test executes for
/// real, or it does not and the job goes red, which is itself the information needed
/// to fix it, rather than a silent, misleadingly green `ok`.
///
/// Cleanup deletes exactly the subtree this guard created and nothing above it: since
/// opening a registry key requires every ancestor in its path to exist, the first
/// missing ancestor found by `prepare` proves every path *below* it was absent too, so
/// deleting that one subtree can never remove a sibling key some other, real policy
/// put under `Software\Policies`.
struct PolicyKeyGuard {
    /// The highest ancestor this guard actually created.
    created_root: &'static str,
}

impl PolicyKeyGuard {
    fn prepare() -> Option<Self> {
        let leaf = *GROUP_POLICY_ANCESTORS.first().expect("non-empty");
        if hklm_key_exists(leaf) {
            // Legitimate on a developer's own machine (see this struct's doc); a CI
            // runner is freshly provisioned and should never reach this branch, so it
            // deliberately does *not* go through `support::skip_or_fail` — it is an
            // allow-listed skip, not an unexplained one.
            eprintln!(
                "SKIPPED: a group policy Internet Settings key already exists on this \
                 machine; refusing to touch a real policy"
            );
            return None;
        }

        // `GROUP_POLICY_ANCESTORS` is ordered leaf-first; walk it in reverse (broad to
        // specific) to find the first, topmost segment that does not exist yet.
        let created_root = GROUP_POLICY_ANCESTORS
            .iter()
            .rev()
            .copied()
            .find(|path| !hklm_key_exists(path))
            .expect("the leaf is confirmed absent above, so at least it is missing");

        if !try_create_hklm_key(created_root) {
            // This call is what makes "CI runs this job elevated" observable instead
            // of silently green — see this struct's doc.
            support::skip_or_fail(
                "cannot write HKLM\\Software\\Policies\\... (requires an elevated \
                 process; see this test's doc comment to run it for real)",
            );
            return None;
        }
        Some(Self { created_root })
    }

    /// Create the leaf key (any remaining intermediate ancestors are created
    /// automatically, same as `mkdir -p`) and write a manual-proxy configuration —
    /// this is the change the test asserts gets detected.
    fn write_manual_baseline(&self) {
        let leaf = *GROUP_POLICY_ANCESTORS.first().expect("non-empty");
        let handle = create_hklm_key(leaf);
        let settings = Settings(handle);
        settings.write("AutoDetect", &Value::Absent);
        settings.write("AutoConfigURL", &Value::Absent);
        settings.write("ProxyServer", &Value::Sz(TEST_PROXY.to_owned()));
        settings.write("ProxyOverride", &Value::Sz("<local>".to_owned()));
        settings.write("ProxyEnable", &Value::Dword(1));
        settle();
    }
}

impl Drop for PolicyKeyGuard {
    fn drop(&mut self) {
        delete_hklm_key_tree(self.created_root);
    }
}

/// Whether `HKEY_LOCAL_MACHINE\path` can currently be opened for reading.
fn hklm_key_exists(path: &str) -> bool {
    let path_w = wide(path);
    let mut key = HKEY::default();
    // SAFETY: `path_w` is a NUL terminated UTF-16 buffer alive across the call and
    // `key` is a valid out-parameter.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path_w.as_ptr()),
            None,
            KEY_QUERY_VALUE,
            &raw mut key,
        )
    };
    if status.0 != 0 {
        return false;
    }
    // SAFETY: `key` was just opened above and is closed exactly once here.
    unsafe {
        let _ = RegCloseKey(key);
    }
    true
}

/// Create `HKEY_LOCAL_MACHINE\path` (any missing intermediate ancestors along the way
/// too), closing the handle immediately. Returns `false` on `ERROR_ACCESS_DENIED` —
/// the caller's cue to self-skip — and panics on any other, unexpected failure.
fn try_create_hklm_key(path: &str) -> bool {
    let path_w = wide(path);
    let mut key = HKEY::default();
    // SAFETY: `path_w` is a NUL terminated UTF-16 buffer alive across the call,
    // `key` is a valid out-parameter, and every other argument is `None`/default.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path_w.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            None,
            &raw mut key,
            None,
        )
    };
    if status == ERROR_ACCESS_DENIED {
        return false;
    }
    assert_eq!(status.0, 0, "creating HKLM\\{path}: error {}", status.0);
    // SAFETY: `key` was just created/opened above and is closed exactly once here.
    unsafe {
        let _ = RegCloseKey(key);
    }
    true
}

/// Create (or open, if somehow already present) `HKEY_LOCAL_MACHINE\path` for
/// reading and writing values, handing the open handle to the caller.
fn create_hklm_key(path: &str) -> HKEY {
    let path_w = wide(path);
    let mut key = HKEY::default();
    // SAFETY: as `try_create_hklm_key` above.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path_w.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            None,
            &raw mut key,
            None,
        )
    };
    assert_eq!(status.0, 0, "creating HKLM\\{path}: error {}", status.0);
    key
}

/// Delete `HKEY_LOCAL_MACHINE\path`, including every value and subkey under it.
///
/// The second call is belt-and-braces, not a documented recipe: `RegDeleteTree`'s
/// reference page says only "deletes the subkeys and values of the specified key
/// recursively" and spells out just the `lpSubKey == NULL` case, so whether a non-NULL
/// `lpSubKey` is itself removed is not stated there. Calling `RegDeleteKeyEx` afterwards
/// covers both readings; if the key is already gone it fails harmlessly, and the result
/// is discarded.
fn delete_hklm_key_tree(path: &str) {
    let path_w = wide(path);
    // SAFETY: `path_w` is a NUL terminated UTF-16 buffer alive across both calls.
    unsafe {
        let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(path_w.as_ptr()));
        let _ = RegDeleteKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(path_w.as_ptr()), 0, None);
    }
}

/// Give the previous batch of writes time to drain before a watcher is created, so a
/// stale notification from the fixture cannot be mistaken for the change under test.
fn settle() {
    std::thread::sleep(Duration::from_millis(150));
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
