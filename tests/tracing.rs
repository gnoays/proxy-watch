//! The `tracing` feature seen from outside the crate.
//!
//! The renderers and the secrecy invariant are unit tested in
//! `src/trace.rs`, where a snapshot can be *constructed* with a password in it. What can
//! only be checked from here is the wiring: that a real [`ProxyWatcher`] on this machine
//! actually produces the events, and that the ones written **from the watcher thread**
//! reach a subscriber too — which needs the global default rather than the thread-local
//! one, and is therefore easy to get wrong.
//!
//! `tracing::subscriber::set_global_default` can only succeed once per process, so this
//! file deliberately contains a single test.

#![cfg(feature = "tracing")]

use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use proxy_watch::{ProxyWatcher, WatchOptions};
use tracing_subscriber::fmt::MakeWriter;

mod support;

/// A `MakeWriter` that appends to a shared buffer.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.lock().clone()).expect("the fmt layer writes UTF-8")
    }

    fn lock(&self) -> MutexGuard<'_, Vec<u8>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.lock().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn a_real_watcher_reports_its_lifecycle_and_its_first_snapshot() {
    let sink = Capture::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(sink.clone())
            .finish(),
    )
    .expect("no other test in this binary installs a subscriber");

    let mut watcher = match ProxyWatcher::with_options(WatchOptions::new()) {
        Ok(watcher) => watcher,
        // Linux with both desktop features off, or any unsupported target: there is
        // nothing to watch, and the constructor says so rather than logging.
        Err(error) => {
            assert!(
                sink.text().contains("starting a proxy watcher"),
                "even a failed start is announced: {error}"
            );
            return;
        }
    };

    // The first item is always the current configuration, and it is the one the
    // `INFO` line above described.
    let _ = support::expect_config(&mut watcher, Duration::from_secs(2));
    drop(watcher);

    let text = sink.text();
    assert!(text.contains("starting a proxy watcher"), "{text}");
    assert!(
        text.contains("watching the system proxy configuration"),
        "{text}"
    );
    // Written from inside the watcher thread — the point of the global subscriber.
    assert!(text.contains("the watcher thread finished"), "{text}");

    // Whatever this machine is configured with, a rendered summary is one of the five
    // shapes `ModeSummary` produces (`direct` / `manual(` / `pac(` / `pac-inline(` /
    // `wpad`) and never a `ProxyConfig` debug dump. The trailing `(` is what keeps the
    // two PAC shapes apart — `current=pac(` is not a substring of `current=pac-inline(`
    // — so the order of the list below does not matter.
    assert!(!text.contains("ProxyConfig {"), "{text}");
    assert!(!text.contains("ProxyAuth {"), "{text}");
    assert!(
        [
            "current=direct",
            "current=manual(",
            "current=pac-inline(",
            "current=pac(",
            "current=wpad"
        ]
        .iter()
        .any(|shape| text.contains(shape)),
        "{text}"
    );
}
