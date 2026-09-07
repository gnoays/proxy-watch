//! Combine OS settings and `*_proxy` env, then `resolve()` URLs.
//!
//! The library keeps these apart on purpose: env vars do not change from outside the
//! process, so they are not on `ProxyWatcher`'s stream (`examples/env.rs`). There is also
//! no single "load everything" API — precedence is a policy choice, which is why the caller
//! names it: read both, then
//! [`ProxyConfig::with_env`](proxy_watch::ProxyConfig::with_env) with the
//! [`EnvPrecedence`](proxy_watch::EnvPrecedence) this program wants, then resolve.
//!
//! Default order is **env first** (curl-like). Pass `--os-first` to rank env below the OS
//! sources — which is a rank, not a veto: on a machine whose OS settings read cleanly and
//! configured nothing, the environment still answers. A systemd unit on a desktop host is
//! usually in that case, and it is why `--os-first` is not spelled "ignore the environment".
//! A container with no desktop store at all is a different case: `read()` fails there with
//! `Error::Unsupported` before either rank gets a say.
//!
//! ```text
//! cargo run --example resolve_os_and_env
//! cargo run --example resolve_os_and_env -- https://example.com/
//! http_proxy=http://127.0.0.1:8080 cargo run --example resolve_os_and_env -- https://example.com/
//! cargo run --example resolve_os_and_env -- --os-first https://example.com/
//! ```
//!
//! PAC / WPAD still surface as `Error::PacNotSupported` from `resolve()` — same as
//! `examples/resolve.rs`. Script evaluation is `examples/pac.rs`.

use proxy_watch::{EnvPrecedence, ProxyConfigSource, ProxyEnv, ProxyStep, Url, read, resolve};

const DEFAULT_URLS: &[&str] = &[
    "http://example.com/",
    "https://example.com/",
    "http://localhost:8080/",
    "http://intranet/",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let os_first = args.iter().any(|a| a == "--os-first");
    let urls: Vec<&str> = {
        let rest: Vec<&str> = args
            .iter()
            .map(String::as_str)
            .filter(|a| *a != "--os-first")
            .collect();
        if rest.is_empty() {
            DEFAULT_URLS.to_vec()
        } else {
            rest
        }
    };

    let precedence = if os_first {
        EnvPrecedence::AfterSystem
    } else {
        EnvPrecedence::BeforeSystem
    };
    // `with_env` carries the OS snapshot's `fallbacks` and stamps the result with the older
    // of the two reads, which is why this is one call and not an assembled source list.
    let config = read()?.with_env(&ProxyEnv::from_env()?, precedence);

    println!(
        "policy:    {}",
        if os_first {
            "OS first, then env (if set)"
        } else {
            "env first (if set), then OS"
        }
    );
    println!("effective: {:?}", config.effective);
    println!("sources:");
    for (source, mode) in &config.sources {
        println!("  {source:?} -> {mode:?}");
    }
    if !config.fallbacks.is_empty() {
        println!("fallbacks: {:?}", config.fallbacks);
    }
    // Not the same as "no `*_proxy` variables are set". What is folded in as nothing at all is
    // an environment that specified nothing *and* dropped nothing, and an empty value is a
    // specification: `http_proxy=` means "no proxy for http", so it leaves an `Env` source and,
    // under the default policy here, outranks the OS. A value that could not be parsed leaves
    // one too — behind the OS sources rather than in front of them.
    if config.source(ProxyConfigSource::Env).is_none() {
        println!("(the process environment contributed nothing to this snapshot)\n");
    } else {
        println!();
    }

    for input in urls {
        let url = Url::parse(input)?;
        match resolve(&config, &url) {
            Ok(steps) => {
                let decision: Vec<String> = steps
                    .iter()
                    .map(|step| match step.endpoint() {
                        None => "DIRECT".to_owned(),
                        Some(endpoint) => match endpoint.scheme_hint {
                            Some(_) => endpoint.to_string(),
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
