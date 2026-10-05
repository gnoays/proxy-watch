//! Keep a `reqwest` client on the OS proxy through `Proxy::custom`.
//!
//! `reqwest` reads its proxy settings once, when the `Client` is built. `Proxy::custom`
//! is the exception: `reqwest` calls its closure each time it opens a connection
//! (`ConnectorService::call` in `reqwest` 0.13's `src/connect.rs`). So the closure reads
//! the latest `ProxyConfig` from an `Arc<RwLock<_>>`, and a watcher thread keeps that fresh.
//! `*_proxy` is read once at start-up and merged into each snapshot, environment first.
//!
//! A connection already open keeps its route: the pool files it under the destination
//! alone. It goes after `pool_idle_timeout` (90 s by default); `pool_max_idle_per_host(0)`
//! applies a change at once, at the cost of pooling.
//!
//! On a plain `http://` request `reqwest` also calls the closure to look for proxy headers.
//! Those calls do not route, so keep side effects out of the closure.
//!
//! ```text
//! cargo run --example reqwest_client
//! http_proxy=http://127.0.0.1:8080 cargo run --example reqwest_client
//! ```
//!
//! It builds the client and prints what the closure would answer for a few URLs. It sends
//! no request, so it needs no network and no async runtime.
//!
//! **Unverified:** nothing here makes `reqwest` call the closure.
//! **Risk:** a `reqwest` that resolved the closure once, at build time, would still compile
//! and print the same lines, and the client would stop following the OS.
//! **Symptom:** a proxy changed after the `Client` was built is never used. To check, count
//! calls in `pick_proxy` while sending a request to a local port nothing listens on.

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use proxy_watch::{
    EnvPrecedence, ProxyConfig, ProxyEnv, ProxyStep, ProxyWatcher, Stream, Url, WatchEvent, resolve,
};

/// The proxy URL for `url`, credentials included, or `None` for direct.
///
/// `None` also comes back when `resolve` fails: `Error::PacNotSupported` on a PAC or WPAD
/// host, `Error::ProxyEntryUnusable` for an entry that could not be read. The request then
/// goes direct, around the proxy, and `Proxy::custom` offers no way to refuse it. The
/// `eprintln!` leaves a trace. A real integration decides PAC hosts before the closure runs,
/// with `resolve_with_pac()` (see the `pac` example).
fn pick_proxy(config: &ProxyConfig, url: &Url) -> Option<Url> {
    match resolve(config, url) {
        Ok(steps) => steps.first().and_then(ProxyStep::to_url),
        Err(error) => {
            // `url` is every URL the application requests, and it can carry a token.
            eprintln!(
                "cannot resolve a proxy for {}: {error}",
                without_credentials(url)
            );
            None
        }
    }
}

/// `url` without `user:password@`, for printing.
///
/// `set_username` fails for a URL that cannot carry one (no host, or `file:`), and leaves
/// the credentials in place when it does, so that case prints a marker instead.
fn without_credentials(url: &Url) -> String {
    let mut safe = url.clone();
    if safe.set_username("").is_err() || safe.set_password(None).is_err() {
        return format!("<{} URL withheld: credentials not maskable>", url.scheme());
    }
    safe.into()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read once: `std::env::set_var` is off limits while a watcher is alive.
    let env = ProxyEnv::from_env()?;
    let mut watcher = ProxyWatcher::new()?;
    let merge = move |os: ProxyConfig| os.with_env(&env, EnvPrecedence::BeforeSystem);
    let shared = Arc::new(RwLock::new(merge(watcher.current())));

    // `ProxyWatcher` needs no async runtime; a thread and `block_on` are enough.
    let updates = Arc::clone(&shared);
    std::thread::spawn(move || {
        while let Some(item) =
            futures_executor::block_on(poll_fn(|cx| Pin::new(&mut watcher).poll_next(cx)))
        {
            match item {
                WatchEvent::Snapshot { state, .. } => {
                    *updates.write().expect("lock is never poisoned") = merge(state.config);
                }
                // The client keeps routing on the last good configuration.
                WatchEvent::Error { error, .. } => {
                    eprintln!("proxy watch error; routing on the last good snapshot: {error}");
                }
                _ => {}
            }
        }
    });

    let for_proxy = Arc::clone(&shared);
    let proxy = reqwest::Proxy::custom(move |url| {
        // No `expect`: this runs inside the client, on whichever thread makes a request.
        let Ok(config) = for_proxy.read() else {
            eprintln!(
                "the proxy snapshot lock is poisoned; {} goes direct",
                without_credentials(url)
            );
            return None;
        };
        pick_proxy(&config, url)
    });
    let _client = reqwest::Client::builder().proxy(proxy).build()?;

    let config = shared.read().expect("lock is never poisoned");
    println!("effective: {:?}", config.effective);
    println!("sources:");
    for (source, mode) in &config.sources {
        println!("  {source:?} -> {mode:?}");
    }
    println!();
    for input in [
        "http://example.com/",
        "https://example.com/",
        "http://localhost:8080/",
    ] {
        let url = Url::parse(input)?;
        match pick_proxy(&config, &url).as_ref().map(without_credentials) {
            Some(proxy) => println!("{input} -> {proxy}"),
            None => println!("{input} -> DIRECT"),
        }
    }

    Ok(())
}
