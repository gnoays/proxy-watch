//! Ask the *current* system configuration how it would reach a set of URLs.
//!
//! `resolve()` is the last step of the crate: it turns a `ProxyConfig` snapshot plus a
//! destination URL into an ordered list of `ProxyStep`s (`Direct`, or a proxy endpoint
//! to talk to). Run with:
//!
//! ```text
//! cargo run --example resolve
//! cargo run --example resolve -- https://example.com http://intranet/
//! ```
//!
//! A machine configured with a PAC script or WPAD auto-detection makes this print an
//! `Error::PacNotSupported` instead of a decision. That is not a gap: `resolve()` is
//! *defined* never to evaluate a script, and refuses to guess "direct" on its behalf,
//! because a wrong guess bypasses the proxy the administrator configured. Evaluation
//! lives in `resolve_with_pac()` behind the `pac` feature and an engine
//! (`pac-boa` or `pac-windows-native`) — see `cargo run --features pac-boa --example
//! pac`.

use proxy_watch::{ProxyStep, Url, read, resolve};

const DEFAULT_URLS: &[&str] = &[
    "http://example.com/",
    "https://example.com/",
    "http://localhost:8080/",
    "http://intranet/",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = read()?;
    println!("effective: {:?}\n", config.effective);

    let args: Vec<String> = std::env::args().skip(1).collect();
    let urls: Vec<&str> = if args.is_empty() {
        DEFAULT_URLS.to_vec()
    } else {
        args.iter().map(String::as_str).collect()
    };

    for input in urls {
        let url = Url::parse(input)?;
        match resolve(&config, &url) {
            Ok(steps) => {
                let decision: Vec<String> = steps
                    .iter()
                    // Deliberately not `to_url()`, for the two reasons its own doc gives.
                    // It answers `None` for a host no URL can hold as well as for
                    // `Direct`, and printing "DIRECT" for the first is the failure this
                    // crate exists to avoid: telling the reader to bypass the proxy the
                    // administrator configured. And the URL it builds carries the proxy's
                    // credentials, which must not be written to a terminal or a log.
                    .map(|step| match step.endpoint() {
                        // `endpoint()` is `None` for `Direct` and for nothing else.
                        None => "DIRECT".to_owned(),
                        Some(endpoint) => match endpoint.scheme_hint {
                            // `Display` prints the hint's own scheme and never the
                            // credentials. The hint is the scheme worth printing:
                            // `socks5h` vs `socks5` says who resolves the host name.
                            Some(_) => endpoint.to_string(),
                            // Without a hint it prints a bare `host:port`, so name the
                            // protocol from the step. (`scheme()` is `None` only for
                            // `Direct`, which the arm above already took.)
                            None => format!("{}://{endpoint}", step.scheme().unwrap_or("?")),
                        },
                    })
                    .collect();
                println!("{input} -> {}", decision.join(", "));
                if let Some(ProxyStep::Socks5(endpoint)) = steps.first() {
                    println!("  (a SOCKS5 proxy: {endpoint})");
                }
            }
            Err(error) => println!("{input} -> error: {error}"),
        }
    }

    Ok(())
}
