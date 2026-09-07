//! The one-shot read: `read()` and `read_with_options()`.
//!
//! These run wherever a backend exists, and they write nothing — a read touches no
//! registry key, no `kioslaverc`, no `SCDynamicStore` value — so unlike
//! `tests/windows_watch.rs` they need no `--ignored`. The inverse configuration, where no
//! backend exists at all, is covered by `tests/unsupported_platform.rs`.
//!
//! What is worth pinning here is not that a read succeeds — that depends on the host —
//! but that it agrees with the watcher. `read()` is documented as performing the read
//! `ProxyWatcher::new()` performs during construction and nothing else, which is a claim
//! about two code paths staying in step. A second `read_config` call added to one and not
//! the other, or a `WatchOptions` field that quietly changes what is read, breaks it.
#![cfg(any(
    windows,
    target_os = "macos",
    all(
        target_os = "linux",
        any(feature = "linux-gnome", feature = "linux-kde")
    )
))]

use std::time::Duration;

use proxy_watch::{
    ProxyConfig, ProxyConfigSource, ProxyWatcher, WatchOptions, read, read_with_options,
};

mod support;

#[cfg(target_os = "linux")]
use support::seed_a_configuration;
use support::skip_or_fail;

/// The sources a snapshot consulted, in precedence order.
///
/// Compared instead of the whole [`ProxyConfig`] because a proxy setting changed by
/// someone else between the two reads below would make a value comparison fail for a
/// reason that is not a defect. Which sources were consulted does not move that way, and
/// it is what actually separates the two paths: a `read()` that skipped a source, or
/// answered a bare [`ProxyConfig::direct`] without reading anything, differs here.
fn labels(config: &ProxyConfig) -> Vec<ProxyConfigSource> {
    config.sources.iter().map(|(source, _)| *source).collect()
}

#[test]
fn read_consults_the_same_sources_the_watcher_reads_at_construction() {
    #[cfg(target_os = "linux")]
    seed_a_configuration();

    // Through `skip_or_fail`, not a bare skip: the `#![cfg]` above already narrowed this
    // file to targets that compile a backend in, so a construction failure is not the
    // permanent, by-construction gap that earns a plain allow-listed skip. It is the other
    // bucket — quiet on a developer's machine, red under CI.
    let Ok(watcher) = ProxyWatcher::new() else {
        skip_or_fail("no watcher on this host, so there is nothing to agree with");
        return;
    };
    let from_watcher = watcher.current();
    drop(watcher);

    // Not a skip: `read()` performs a strict subset of what construction just did, so a
    // failure here is a divergence between the two paths, not a difference in host.
    let from_read = read().expect("read() failed where ProxyWatcher::new() had succeeded");

    assert_eq!(labels(&from_read), labels(&from_watcher));
}

#[test]
fn read_with_options_ignores_the_fields_that_only_describe_a_watcher() {
    #[cfg(target_os = "linux")]
    seed_a_configuration();

    let Ok(baseline) = read() else {
        skip_or_fail("nothing readable on this host");
        return;
    };

    // Both fields configure a watcher this call never starts. Values far from the
    // defaults, so a field that did reach the read would have to show it.
    let options = WatchOptions::new()
        .with_debounce(Duration::from_secs(600))
        .with_poll_interval(Some(Duration::from_millis(1)));
    let answered = read_with_options(&options).expect("read_with_options() after read() succeeded");

    assert_eq!(labels(&answered), labels(&baseline));
}

#[test]
fn turning_group_policy_off_removes_that_source_and_disturbs_no_other() {
    #[cfg(target_os = "linux")]
    seed_a_configuration();

    // Stated as a relation between the two source lists rather than as "`GroupPolicy` is
    // absent", because the absent form is vacuous on a host with no proxy GPO set — which
    // is most hosts, including the usual CI runner. The relation is not:
    //
    // * an option that never reaches the read leaves `GroupPolicy` in the second list on a
    //   GPO-configured host, and
    // * an option that reaches too far — skipping the per-user registry read along with the
    //   policy one, say — shortens the list somewhere else, on *every* host.
    //
    // Only the first half needs a GPO to bite. The second half is what makes this test
    // worth running on a bare machine.
    let Ok(with_policy) = read_with_options(&WatchOptions::new()) else {
        skip_or_fail("nothing readable on this host");
        return;
    };
    let without =
        read_with_options(&WatchOptions::new().with_group_policy(false)).expect("the same read");

    let expected: Vec<ProxyConfigSource> = labels(&with_policy)
        .into_iter()
        .filter(|source| *source != ProxyConfigSource::GroupPolicy)
        .collect();
    assert_eq!(labels(&without), expected);
    assert!(!labels(&without).contains(&ProxyConfigSource::GroupPolicy));
}

/// The WinHTTP per-machine default never outranks the per-user registry.
///
/// The order of this list is not presentation. `effective` is `sources.first()`, so it is
/// which store answers. `in_precedence_order` in `src/sys/win/mod.rs` puts the per-user
/// `Registry` entry ahead of the WinHTTP one, because Windows's own precedence puts a
/// per-machine `netsh winhttp set proxy` below HKCU. What the swap changes is that a
/// machine default recorded once — by an installer, or by an administrator years ago —
/// outranks every per-user proxy setting made since, and [`proxy_watch::resolve`] then
/// routes through it.
///
/// This one holds the *real* machine, so what it can compare is whatever that machine
/// reports. `winhttp_default_source` withholds the entry when WinHTTP answers
/// `ERROR_FILE_NOT_FOUND`, which is how it says nobody ever ran `netsh winhttp set proxy` —
/// so on a host that never did, the comparison below is guarded out and the swap stays
/// green here. A host that has one records direct access just as readably as a proxy, so
/// this is not a test that only fires on a configured machine; it is one that needs the
/// value to exist. `in_precedence_order` in `src/sys/win/mod.rs` is where the ordering is
/// written down, and it holds on every machine because it takes no reading to state.
///
/// The `Registry` half is unconditional — only a `?` return can skip it.
#[cfg(windows)]
#[test]
fn the_winhttp_machine_default_never_outranks_the_per_user_registry() {
    let Ok(config) = read() else {
        skip_or_fail("nothing readable on this host");
        return;
    };
    let consulted = labels(&config);

    let registry = consulted
        .iter()
        .position(|source| *source == ProxyConfigSource::Registry)
        .expect("the per-user registry read is unconditional");
    if let Some(winhttp) = consulted
        .iter()
        .position(|source| *source == ProxyConfigSource::WinHttpDefault)
    {
        assert!(
            registry < winhttp,
            "the informational per-machine default must sit below HKCU: {consulted:?}"
        );
    }
}
