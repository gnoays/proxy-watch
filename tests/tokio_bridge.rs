//! The `tokio` feature's public entry point: `watch_channel()`.
//!
//! `src/bridge.rs` tests the machinery behind it — fan-out, the equality filter, the
//! shutdown on last-receiver-drop — against a canned stream, deliberately, so that those
//! tests need no platform backend. What that leaves untested is the one line
//! `watch_channel` adds on top: which configuration the channel *starts* at.
//!
//! It is one line, and it is the line a caller reads first. `tokio::sync::watch` hands
//! every receiver a value immediately, before the bridge task has run and before any
//! `changed().await`, and `watch_channel`'s own doc example reads exactly that value from
//! a second task. Seeding it with a bare `ProxyConfig::direct()` — which reads as a
//! harmless simplification, since the watcher re-emits its current value at subscription
//! anyway — makes that first read say "no proxy" on a machine that has one. That is the
//! fail-open direction: traffic goes out unproxied for as long as it takes the first real
//! snapshot to arrive, which on an idle machine is never.
//!
//! The test below is the only thing in this tree that would go red for that seed.
#![cfg(all(
    feature = "tokio",
    any(
        windows,
        target_os = "macos",
        all(
            target_os = "linux",
            any(feature = "linux-gnome", feature = "linux-kde")
        )
    )
))]

use proxy_watch::{ProxyConfig, ProxyConfigSource, ProxyWatcher, watch_channel};

mod support;

#[cfg(target_os = "linux")]
use support::seed_a_configuration;
use support::skip_or_fail;

/// Provenance rather than values, for the reason `tests/read_once.rs` gives at its own
/// copy of this: someone else changing a proxy setting mid-test moves the values but not
/// the source list. It is also what separates a real read from a manufactured
/// [`ProxyConfig::direct`], which consulted nothing.
fn labels(config: &ProxyConfig) -> Vec<ProxyConfigSource> {
    config.sources.iter().map(|(source, _)| *source).collect()
}

#[test]
fn the_channel_starts_at_the_watchers_configuration_not_at_direct() {
    // This test needs more than a host that reads: it needs one whose read is non-empty,
    // because a real read of a machine with no proxy and a manufactured
    // `ProxyConfig::direct` are the same value, down to the empty source list. Windows and
    // macOS runners have something; a headless ubuntu one has nothing until this writes it.
    #[cfg(target_os = "linux")]
    seed_a_configuration();

    // Through `skip_or_fail`, not a bare skip: the `#![cfg]` above already narrowed this
    // file to targets that compile a backend in, so a construction failure is quiet on a
    // developer's machine and red under CI.
    let Ok(watcher) = ProxyWatcher::new() else {
        skip_or_fail("no watcher on this host, so there is no configuration to start at");
        return;
    };
    let expected = labels(&watcher.current());
    // Without this the assertion below could hold by both sides consulting nothing, which
    // is the state the seed being tested for would also produce.
    assert!(
        !expected.is_empty(),
        "a watcher that consulted no source cannot tell the two seeds apart"
    );

    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
        .block_on(async {
            let receiver = watch_channel(watcher);
            // Read before awaiting anything. On a current-thread runtime the spawned
            // bridge task has not been polled yet, so this is the seed and nothing else —
            // which is also the state the doc example's second task observes.
            assert_eq!(labels(&receiver.borrow()), expected);
        });
}
