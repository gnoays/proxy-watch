//! Route URLs through a PAC script, including the part this crate refuses to do for you.
//!
//! ```text
//! cargo run --features pac-boa --example pac
//! cargo run --features pac-boa --example pac -- http://intranet/ https://example.net/
//! ```
//!
//! Two things are worth watching here.
//!
//! **The script body is an input.** `ProxyMode::Pac` carries a *URL*, and the crate will
//! not download it — that would mean an HTTP client in the dependency
//! graph of a crate whose point is that it has almost none. `pac::requirement()` tells
//! you what to fetch before you commit to a request, and `resolve_with_pac()` says the
//! same thing as `Error::PacFetchRequired` if you skip the check. This example fetches
//! nothing: it uses a built-in script, and shows where your own HTTP client would go.
//!
//! **The default policy is the paranoid one.** `dnsResolve` returns `null`,
//! `myIpAddress()` answers `127.0.0.1`, and evaluation is abandoned after five seconds.
//! Run with `PAC_ALLOW_DNS=1` to see what the same script does once name resolution is
//! turned on.

use proxy_watch::pac::{PacPolicy, PacRequirement, PacScript, requirement};
use proxy_watch::{Error, ProxyConfig, ProxyConfigSource, ProxyMode, ProxyWatcher, Url};

/// Stands in for the file your HTTP client would have fetched from `AutoConfigURL`.
const SCRIPT: &str = "
    function FindProxyForURL(url, host) {
        // Unqualified names and the intranet never go through the proxy.
        if (isPlainHostName(host)) { return 'DIRECT'; }
        if (dnsDomainIs(host, '.corp.example')) { return 'DIRECT'; }

        // Anything that resolves inside the corporate network is local too. With the
        // default policy `dnsResolve` returns null and this test simply never fires.
        var ip = dnsResolve(host);
        if (ip != null && isInNet(ip, '10.0.0.0', '255.0.0.0')) { return 'DIRECT'; }

        if (shExpMatch(url, 'ftp:*')) { return 'PROXY ftp-gw.corp.example:2121'; }
        return 'PROXY edge.corp.example:8080; PROXY backup.corp.example:8080; DIRECT';
    }";

const DEFAULT_URLS: &[&str] = &[
    "http://intranet/",
    "https://wiki.corp.example/start",
    "ftp://files.example.net/pub",
    "https://example.net/index.html",
];

/// Drop any `user:password@` before printing a PAC URL.
///
/// The crate masks credentials in everything it renders itself — `ProxyMode`'s `Debug`,
/// every `Error`'s `Display`. Reach past those into a `Url` field, as the two call sites
/// below do, and the masking is yours to redo: a `PacRequirement::Fetch` or a
/// `PacFetchRequired` carries the URL exactly as the machine had it, credentials and all,
/// because that is what the caller has to fetch.
///
/// A `String` and not a `Url`, so that the failing path cannot be ignored by accident.
/// `Url::set_username` answers `Err` rather than doing nothing quietly, and `url` 2.5.8
/// refuses three cases: no host, an empty host, and the `file` scheme. That last one is
/// reachable here — a PAC URL is whatever the machine has configured, and `file:` is a
/// legal thing to configure. On `Err` the clone is still the original, so returning it
/// would print exactly what this function exists to hide.
fn without_credentials(url: &Url) -> String {
    let mut safe = url.clone();
    if safe.set_username("").is_err() || safe.set_password(None).is_err() {
        return format!("<{} URL withheld: credentials not maskable>", url.scheme());
    }
    safe.into()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // What the machine is actually configured with, if anything is readable here.
    match ProxyWatcher::new() {
        Ok(watcher) => {
            let current = watcher.current();
            println!("system effective mode: {:?}", current.effective);
            match requirement(&current.effective) {
                PacRequirement::Fetch(url) => {
                    let url = without_credentials(url);
                    println!("  this machine needs the script at {url} fetched by you");
                }
                PacRequirement::Inline(script) => {
                    println!(
                        "  this machine carries the script inline ({} bytes)",
                        script.len()
                    );
                }
                PacRequirement::Discover => println!("  WPAD is on; locating the script is yours"),
                other => println!("  no PAC needed here ({other:?})"),
            }
        }
        Err(error) => println!("system configuration unavailable: {error}"),
    }

    // Pretend the script above came back from `AutoConfigURL`.
    let pac_url = Url::parse("http://wpad.corp.example/proxy.pac")?;
    let config =
        ProxyConfig::from_source(ProxyConfigSource::Registry, ProxyMode::pac(pac_url.clone()));
    let script = PacScript::new(SCRIPT);

    let policy = if std::env::var_os("PAC_ALLOW_DNS").is_some() {
        println!("\npolicy: DNS resolution ON, internal addresses allowed");
        PacPolicy::new()
            .with_dns_resolution(true)
            .with_internal_addresses(true)
    } else {
        println!("\npolicy: default (no DNS, myIpAddress() = 127.0.0.1, 5 s budget)");
        PacPolicy::new()
    };

    // Forgetting to pass the script is not a silent "direct": it names what to fetch.
    if let Err(Error::PacFetchRequired { url }) =
        proxy_watch::resolve_with_pac(&config, &Url::parse("http://example.net/")?, None, &policy)
    {
        let url = without_credentials(&url);
        println!("without a script body the crate asks for: {url}\n");
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let urls: Vec<&str> = if args.is_empty() {
        DEFAULT_URLS.to_vec()
    } else {
        args.iter().map(String::as_str).collect()
    };

    for input in urls {
        let url = Url::parse(input)?;
        match proxy_watch::resolve_with_pac(&config, &url, Some(&script), &policy) {
            Ok(steps) => {
                // The same shape as `examples/resolve.rs`, and for the same two reasons
                // `to_url()`'s own doc gives. It answers `None` for a host no URL can hold
                // as well as for `Direct`, so reading its `None` as "direct" teaches a
                // misreading that would tell the reader to bypass the proxy the
                // administrator configured. And the URL it builds carries the proxy's
                // credentials verbatim: a PAC script is free to return
                // `PROXY alice:hunter2@p:8080`, and printing that puts a password in the
                // terminal and in whatever collects it. `Display` on the endpoint never
                // does.
                let decision: Vec<String> = steps
                    .iter()
                    .map(|step| match step.endpoint() {
                        // `endpoint()` is `None` for `Direct` and for nothing else.
                        None => "DIRECT".to_owned(),
                        Some(endpoint) => match endpoint.scheme_hint {
                            // The hint is the scheme worth printing: `socks5h` vs `socks5`
                            // says who resolves the host name.
                            Some(_) => endpoint.to_string(),
                            // Without a hint it prints a bare `host:port`, so name the
                            // protocol from the step. (`scheme()` is `None` only for
                            // `Direct`, which the arm above already took.)
                            None => format!("{}://{endpoint}", step.scheme().unwrap_or("?")),
                        },
                    })
                    .collect();
                println!("{input} -> {}", decision.join(", "));
            }
            Err(error) => println!("{input} -> error: {error}"),
        }
    }

    Ok(())
}
