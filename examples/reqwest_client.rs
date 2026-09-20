//! Wire `proxy-watch` into `reqwest` through `Proxy::custom`, and keep it live.
//!
//! `reqwest` resolves its proxy configuration when the `Client` is built and never
//! looks again (seanmonstar/reqwest#2674), so a `Client` created before the machine's
//! proxy is changed keeps using the old settings for the rest of the process.
//! `Proxy::custom` takes a closure that `reqwest` calls again afterwards, which is the
//! hook needed: keep the latest `ProxyConfig` in an `Arc<RwLock<_>>` and refresh it from
//! the `ProxyWatcher` stream. Env vars are not on the watcher stream, so
//! [`ProxyEnv`] is read once at start-up and merged into every
//! snapshot as it arrives (env-first, curl-like); see `examples/resolve_os_and_env.rs`
//! for the assembly and the `--os-first` alternative.
//!
//! **Called when a connection is opened, not per request.** The routing decision is made
//! in `ConnectorService::call` — `reqwest-0.12.28` `src/connect.rs:928-954`, whose own log
//! line is `"starting new connection"` — which reaches the closure through
//! `Matcher::intercept` (`src/proxy.rs:528-538`). The pool key hyper-util files the
//! resulting connection under is the *destination's* `(scheme, authority)` and nothing else
//! (`hyper-util-0.1.20` `src/client/legacy/client.rs:92`), so a proxy change does not
//! invalidate a connection that already exists. It takes effect immediately for every
//! destination the client has no live connection to, and for the rest once that connection
//! goes — `pool_idle_timeout` defaults to 90 s, and an HTTP/2 origin is one connection
//! serving everything. `pool_max_idle_per_host(0)` trades pooling for immediacy; rebuilding
//! the `Client` on each `WatchEvent` is the other answer.
//!
//! It is easy to read the closure as per-request because `reqwest` does also call it that
//! way — but only to fill in headers, never to route. `Proxy::custom` sets both
//! `maybe_has_http_auth = true; // never know` and `maybe_has_http_custom_headers = true`
//! (`src/proxy.rs:410-412`), so every request to a plaintext `http://` destination runs it
//! twice more — once looking for `Proxy-Authorization`, once for custom proxy headers
//! (`src/async_impl/client.rs:2605-2606`, which calls `proxy_auth` and then
//! `proxy_custom_headers`). A closure with a side effect will see those calls; a route will
//! not follow from them.
//!
//! `reqwest` is only a dev-dependency of this crate — nothing here is part of the
//! library. Run with:
//!
//! ```text
//! cargo run --example reqwest_client
//! http_proxy=http://127.0.0.1:8080 cargo run --example reqwest_client
//! ```
//!
//! The example builds the client and prints the decision the closure *would* make for a
//! few URLs, by calling `pick_proxy` directly; it sends no request, so it needs no network
//! and no async runtime.
//!
//! **Unverified:** `reqwest` never calls the closure here. Every path that reaches it needs
//! a connection or a request, and this example makes neither, so the wiring above is
//! type-checked and never run.
//! **Risk:** should `reqwest` stop consulting the closure per connection — resolve it once
//! at build time, say — this file would still compile and print the same lines, and the
//! live-update claim at the top would be false with nothing here to say so.
//! **Symptom:** a proxy changed after the `Client` was built is never used by a new
//! connection. To check, count calls in `pick_proxy` while sending one request to a local
//! port nothing listens on: the connect fails, but the closure runs first.

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use proxy_watch::{
    EnvPrecedence, ProxyConfig, ProxyEnv, ProxyStep, ProxyWatcher, Stream, Url, WatchEvent, resolve,
};

/// Pick a proxy URL for `reqwest` from the merged OS + env configuration.
///
/// `None` means "no proxy", which is what `reqwest` expects for a direct connection —
/// but not only that. [`ProxyStep::to_url`] also answers `None` for an endpoint whose
/// host cannot be written into a URL, and this function passes that through unchanged,
/// so a `None` here can mean "there is a proxy and it could not be rendered". `reqwest`
/// reads it as direct either way. [`ProxyStep::endpoint`] is what distinguishes them.
///
/// The URL that comes back carries any `user:password@` the machine had, because that
/// is what `reqwest` has to send. Do not print it — see [`without_credentials`].
///
/// Two different things land in the `Err` arm, and this function treats them alike. A PAC
/// or WPAD configuration lands there not because this version is missing something, but
/// because [`resolve`] is defined never to evaluate a script (`Error::PacNotSupported`).
/// `Error::ProxyEntryUnusable` lands there because the only entry that would have covered
/// the URL was configured and could not be read — the case the crate added that error to
/// stop answering `Direct` for. Note what this function then does with both: it prints,
/// and returns `None`, so the request goes **direct anyway**. That is a fail-open, and it
/// is deliberate only in the sense that a fail-open like this must still leave a trace
/// rather than pass in silence — the `eprintln!` is that trace. It is not a good default
/// for a corporate network, where PAC is common and going direct means leaving the proxy
/// the administrator configured. `Proxy::custom` gives the closure no way to fail a
/// request — `None` is the only other answer it takes — so a real integration decides this
/// outside the closure: enable the `pac` feature with an engine and call
/// `resolve_with_pac()` (see the `pac` example), and let a `ProxyEntryUnusable` stop the
/// caller rather than route it around the proxy. This example keeps the direct fallback so
/// that it stays runnable with `resolve` alone.
fn pick_proxy(config: &ProxyConfig, url: &Url) -> Option<Url> {
    match resolve(config, url) {
        Ok(steps) => steps.first().and_then(ProxyStep::to_url),
        Err(error) => {
            // Masked, and not because a destination is a secret: this function is written
            // to be copied into the per-request closure below, where `url` is every URL
            // the application asks for rather than one someone typed. An API called with
            // `https://user:token@host/` would write that token to the log on every
            // failure, and the failures here are the ones a corporate network produces
            // constantly (`PacNotSupported`).
            eprintln!(
                "cannot resolve a proxy for {}: {error}",
                without_credentials(url)
            );
            None
        }
    }
}

/// Drop any `user:password@` before printing a URL — a proxy's or a destination's.
///
/// [`ProxyStep::to_url`] says "do not log" in as many words, and it means the rendered
/// URL, not just the raw password: it percent-encodes, and `p%40ss` is an encoding of
/// `p@ss`, not a mask of it. The crate hides credentials in everything it renders itself
/// — `ProxyMode`'s `Debug`, every `Error`'s `Display` — but `to_url` exists precisely to
/// hand them to a client, so past that point the masking is the caller's.
///
/// A `String` and not a `Url`, so that the failing path cannot be ignored by accident:
/// `Url::set_username` answers `Err` for a URL that cannot carry a username (`url` 2.5.8
/// refuses an absent or empty host, and the `file` scheme outright), and on `Err` the
/// clone is still the original — credentials and all. Print the marker instead. A mask
/// whose failure mode is "silently returns the input" is worse than no mask, because the
/// call site reads as if it were covered.
fn without_credentials(url: &Url) -> String {
    let mut safe = url.clone();
    if safe.set_username("").is_err() || safe.set_password(None).is_err() {
        return format!("<{} URL withheld: credentials not maskable>", url.scheme());
    }
    safe.into()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `*_proxy` is read once, here, and never again. `ProxyWatcher` documents that
    // `std::env::set_var` is off limits for as long as a watcher is alive, so a later
    // read could only return this same value — and the read is a scan of the whole
    // environment, the wrong price per routing decision for a value that cannot move.
    let env = ProxyEnv::from_env()?;
    let mut watcher = ProxyWatcher::new()?;
    // The lock holds the merged configuration: the watched OS snapshot with the
    // environment already ranked above it. `with_env` also carries the snapshot's
    // `fallbacks` and stamps the result with the older of the two reads, which is why the
    // merge happens where the snapshot arrives and not in the closure.
    let merge = move |os: ProxyConfig| os.with_env(&env, EnvPrecedence::BeforeSystem);
    let shared = Arc::new(RwLock::new(merge(watcher.current())));

    // Keep the merged configuration fresh. `ProxyWatcher` needs no async runtime, so a
    // plain thread and `futures_executor::block_on` are enough.
    let updates = Arc::clone(&shared);
    std::thread::spawn(move || {
        while let Some(item) =
            futures_executor::block_on(poll_fn(|cx| Pin::new(&mut watcher).poll_next(cx)))
        {
            match item {
                // A snapshot also arrives when only the health moved; the configuration
                // it carries is then the same one already stored, so this stays a plain
                // write.
                WatchEvent::Snapshot { state, .. } => {
                    *updates.write().expect("lock is never poisoned") = merge(state.config);
                }
                // The lock keeps the last good configuration and the client keeps routing
                // on it. That is a fail-open like the ones in `pick_proxy`, and it owes the
                // same trace: nothing on the stream promises a recovery notice, so without
                // this line a stale route would have no witness.
                WatchEvent::Error { error, .. } => {
                    eprintln!("proxy watch error; routing on the last good snapshot: {error}");
                }
                // `WatchEvent` is `#[non_exhaustive]`: a future variant lands here.
                _ => {}
            }
        }
    });

    // The closure runs on every new connection, so an OS change is picked up by the
    // *next* connection through this very client.
    let for_proxy = Arc::clone(&shared);
    let proxy = reqwest::Proxy::custom(move |url| {
        // The other two sites take this same lock with `expect`, and this one must not:
        // they run on `main`, where a panic is the program ending with a message, while
        // this closure runs inside the client on whichever thread is making a request.
        // So this one falls open — and `pick_proxy`'s own documentation says what that
        // then owes the reader. `None` here is read as "go direct", the same answer a
        // working lock could have given, so without this line the request would leave the
        // proxy behind and nothing would say why.
        let config = match for_proxy.read() {
            Ok(config) => config,
            Err(_) => {
                eprintln!(
                    "the proxy snapshot lock is poisoned; {} goes direct",
                    without_credentials(url)
                );
                return None;
            }
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
        // `reqwest` gets the credentialed URL; the terminal gets the masked one.
        match pick_proxy(&config, &url).as_ref().map(without_credentials) {
            Some(proxy) => println!("{input} -> {proxy}"),
            None => println!("{input} -> DIRECT"),
        }
    }

    Ok(())
}
