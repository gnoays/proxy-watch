//! Monitor OS proxy settings and print each update — a tiny CLI-shaped demo.
//!
//! This is an **example**, not a shipped binary. A standalone `proxy-watch` CLI would
//! mostly duplicate `read` / `ProxyWatcher` for a niche that already has VPN-oriented
//! tools; the library is the product. Run this when you want to *see* what the crate
//! sees while you flip Settings / `gsettings` / the registry.
//!
//! Each stream item prints effective mode, every source, any rejected values, fallbacks,
//! and health (live / degraded / frozen). The first item is the subscription snapshot;
//! later ones arrive on a real config or route-liveness change (200 ms debounce by
//! default). Ctrl+C to stop.
//!
//! ```text
//! cargo run --example watch
//! ```

use std::future::poll_fn;
use std::pin::Pin;

use proxy_watch::{ProxyConfig, ProxyWatcher, Stream, WatchEvent, WatchHealth, WatchState};

fn main() -> Result<(), proxy_watch::Error> {
    let mut watcher = ProxyWatcher::new()?;
    println!("watching OS proxy settings (Ctrl+C to stop)");
    println!("change a proxy setting to see the next block\n");

    let mut n = 0u64;
    loop {
        let next = futures_executor::block_on(poll_fn(|cx| Pin::new(&mut watcher).poll_next(cx)));
        match next {
            Some(WatchEvent::Snapshot { state, .. }) => {
                n += 1;
                print_snapshot(n, &state);
            }
            Some(WatchEvent::Error { error, state, .. }) => {
                n += 1;
                eprintln!("--- #{n} error ---");
                eprintln!("error: {error}");
                // Last good state at delivery — recovery is not promised as the next item.
                print_health(&state.health);
                println!();
            }
            // `WatchEvent` is `#[non_exhaustive]`: a future variant lands here.
            Some(_) => {}
            None => {
                println!("stream ended");
                break;
            }
        }
    }

    Ok(())
}

fn print_snapshot(n: u64, state: &WatchState) {
    println!("--- #{n} ---");
    print_config(&state.config);
    print_health(&state.health);
    println!();
}

fn print_config(config: &ProxyConfig) {
    println!("effective: {:?}", config.effective);
    if config.sources.is_empty() {
        println!("sources:   (none)");
    } else {
        println!("sources:");
        for (source, mode) in &config.sources {
            println!("  {source:?} -> {mode:?}");
            if let Some(rejected) = mode.rejected().filter(|r| !r.is_empty()) {
                for drop in rejected {
                    println!("    rejected: {drop:?}");
                }
            }
        }
    }
    if !config.fallbacks.is_empty() {
        println!("fallbacks: {:?}", config.fallbacks);
    }
}

fn print_health(health: &WatchHealth) {
    let status = if health.is_fully_live() {
        "fully live"
    } else if health.is_frozen() {
        "frozen (no live route, no poll_interval)"
    } else {
        "degraded or partial"
    };
    println!(
        "health:    {status}; live_notifications={}; degraded={:?}; poll={:?}; stopped={}",
        health.has_live_notifications, health.degraded, health.poll_interval, health.stopped,
    );
}
