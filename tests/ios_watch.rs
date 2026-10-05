//! iOS watch backend smoke test, run on the simulator by `.github/workflows/ios-sim.yml`.
//!
//! The watcher hands `nw_path_monitor` a block laid out by hand in the Blocks ABI, which
//! the monitor copies and then calls once right after it starts. A layout the runtime
//! disagrees with crashes the process at the copy, the call or the release, so the
//! assertion is that watchers can be built, left long enough for that first call, and
//! dropped, many times over. The runner's proxy settings are unknown, so the contents of
//! the snapshot are not asserted.
#![cfg(target_os = "ios")]

mod support;

use std::time::Duration;

use proxy_watch::{ProxyWatcher, WatchOptions};
use support::expect_config;

#[test]
fn watchers_start_take_their_first_path_update_and_drop() {
    // An hour, so every re-read in this test is one a hint asked for.
    let options = WatchOptions::new().with_poll_interval(Some(Duration::from_secs(3600)));
    for _ in 0..20 {
        let mut watcher = ProxyWatcher::with_options(options.clone()).expect("watcher");
        expect_config(&mut watcher, Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(200));
    }
}
