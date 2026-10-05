//! PAC evaluation and download delegated to CFNetwork (`pac-macos-native`).
//!
//! ```text
//! cargo test --features pac-macos-native --test pac_cfnetwork
//! ```
//!
//! Nothing here depends on the machine's proxy configuration or on internet access: bodies
//! are strings, and the PAC URLs are served by a [`PacServer`] on `127.0.0.1`. The target URL
//! is never connected to.
//!
//! Every call runs under [`within`], a watchdog on another thread. CFNetwork's behaviour on a
//! script that never returns is not documented; if it blocks the pumping thread instead of
//! honouring the deadline, the test fails at the watchdog rather than holding the runner.

#![cfg(all(target_os = "macos", feature = "pac-macos-native"))]

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use proxy_watch::pac::{
    CfNetworkPacEvaluator, CfNetworkPacResolver, PacEvaluator, PacResolver, PacScript,
    parse_find_proxy_result,
};
use proxy_watch::{Error, ProxyConfig, ProxyConfigSource, ProxyMode, ProxyStep, Url};

#[path = "support/pac_server.rs"]
mod pac_server;
use pac_server::PacServer;

/// The budget the success paths run under. Generous: nothing here measures it.
const BUDGET: Duration = Duration::from_secs(30);

/// The budget the give-up paths measure against.
const GIVE_UP_BUDGET: Duration = Duration::from_secs(2);

/// How long [`within`] waits before calling the call hung.
const WATCHDOG: Duration = Duration::from_secs(60);

fn target() -> Url {
    Url::parse("http://example.net/some/path").unwrap()
}

/// Run `f` on its own thread and fail the test if it has not returned inside [`WATCHDOG`].
fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(WATCHDOG)
        .expect("the CFNetwork call did not return inside the watchdog")
}

fn evaluate(body: &'static str) -> Result<Vec<ProxyStep>, Error> {
    within(move || {
        CfNetworkPacEvaluator::with_timeout(BUDGET)
            .unwrap()
            .evaluate(&PacScript::new(body.to_owned()), &target(), "example.net")
    })
}

/// CFNetwork's answer for a script that returns `result` is what the JS engines make of the
/// same string, for the keywords CFNetwork keeps.
#[test]
fn a_script_answer_reads_as_the_js_engines_read_it() {
    for result in [
        "DIRECT",
        "PROXY proxy.corp.example:8080",
        "PROXY a.example:1; PROXY b.example:2; DIRECT",
        "SOCKS socks.example:1080",
        "PROXY 203.0.113.7:3128",
    ] {
        let body: &'static str = Box::leak(
            format!("function FindProxyForURL(url, host) {{ return '{result}'; }}")
                .into_boxed_str(),
        );
        let steps = evaluate(body).unwrap_or_else(|e| panic!("{result}: {e:?}"));
        println!("{result} -> {steps:?}");
        assert_eq!(steps, parse_find_proxy_result(result).unwrap(), "{result}");
    }
}

/// CFNetwork drops `HTTPS` and `SOCKS5` entries from a script's answer. Alone they leave
/// nothing, which is an error; ahead of `DIRECT` they leave `DIRECT`, where the JS engines
/// would try the proxy first.
#[test]
fn https_and_socks5_answers_are_dropped_by_cfnetwork() {
    for keyword in ["HTTPS", "SOCKS5"] {
        let alone: &'static str = Box::leak(
            format!("function FindProxyForURL(u, h) {{ return '{keyword} p.example:1080'; }}")
                .into_boxed_str(),
        );
        let error = evaluate(alone).expect_err(keyword);
        println!("{keyword} alone -> {error:?}");
        assert!(
            matches!(error, Error::PacInvalidResult { .. }),
            "{keyword}: {error:?}"
        );

        let before_direct: &'static str = Box::leak(
            format!(
                "function FindProxyForURL(u, h) {{ return '{keyword} p.example:1080; DIRECT'; }}"
            )
            .into_boxed_str(),
        );
        let steps = evaluate(before_direct);
        println!("{keyword}; DIRECT -> {steps:?}");
        assert!(
            matches!(steps.as_deref(), Ok([ProxyStep::Direct]) | Err(_)),
            "{keyword}: {steps:?}"
        );
    }
}

/// CFNetwork splits a bracketed IPv6 proxy at its first colon: `PROXY [2001:db8::1]:3128`
/// comes back as host `[2001`, port 0. That entry is unusable and is dropped, so the answer is
/// an error that names what CFNetwork returned. Measured on macOS 26.6.2 (25G83, arm64); a
/// macOS that parses the literal fails here, and the README and CHANGELOG notes go with it.
#[test]
fn an_ipv6_proxy_comes_back_broken_and_is_dropped() {
    let error = evaluate("function FindProxyForURL(u, h) { return 'PROXY [2001:db8::1]:3128'; }")
        .expect_err("a broken entry must not resolve");
    let macos = std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .unwrap_or_default();
    println!("macOS {macos}: {error:?}");
    match error {
        Error::PacInvalidResult { result } => {
            assert!(result.contains("[2001"), "macOS {macos}: {result}")
        }
        other => panic!("macOS {macos}: {other:?}"),
    }
}

/// What CFNetwork hands the script as `url` and `host`, read back through the answer: the
/// host as the proxy name, the URL's length as the port. CFNetwork cuts the URL to its
/// scheme and host; the path and the query never reach the script.
#[test]
fn the_script_sees_the_scheme_and_host_only() {
    let steps = within(|| {
        CfNetworkPacEvaluator::with_timeout(BUDGET).unwrap().evaluate(
            &PacScript::new(
                "function FindProxyForURL(url, host) { return 'PROXY ' + host + ':' + url.length; }"
                    .to_owned(),
            ),
            &Url::parse("http://user:secret@example.net/some/path?q=1#frag").unwrap(),
            "ignored",
        )
    });
    println!("{steps:?}");
    let expected = format!("PROXY example.net:{}", "http://example.net/".len());
    assert_eq!(steps.unwrap(), parse_find_proxy_result(&expected).unwrap());
}

#[test]
fn a_script_that_does_not_parse_is_an_error() {
    let error = evaluate("this is not JavaScript at all {{{").expect_err("must not resolve");
    println!("{error:?}");
    assert!(
        matches!(
            error,
            Error::PacEvaluation { .. } | Error::PacInvalidResult { .. }
        ),
        "{error:?}"
    );
}

#[test]
fn a_script_that_names_nothing_routable_is_an_error() {
    let error = evaluate("function FindProxyForURL(url, host) { return 'BOGUS'; }")
        .expect_err("must not resolve");
    println!("{error:?}");
    assert!(
        matches!(
            error,
            Error::PacEvaluation { .. } | Error::PacInvalidResult { .. }
        ),
        "{error:?}"
    );
}

/// A script that never returns ends at the budget, and the evaluator still works after.
#[test]
fn a_script_that_never_returns_is_abandoned_at_the_budget() {
    let evaluator = CfNetworkPacEvaluator::with_timeout(GIVE_UP_BUDGET).unwrap();
    let (error, elapsed) = within(move || {
        let started = Instant::now();
        let result = evaluator.evaluate(
            &PacScript::new("function FindProxyForURL(url, host) { while (true) {} }".to_owned()),
            &target(),
            "example.net",
        );
        (result, started.elapsed())
    });
    println!("{error:?} after {elapsed:?}");
    // CFNetwork may abandon the script itself and report an error before the budget.
    assert!(
        matches!(
            error,
            Err(Error::PacTimeout { .. } | Error::PacEvaluation { .. })
        ),
        "{error:?}"
    );
    assert!(
        elapsed < GIVE_UP_BUDGET + Duration::from_secs(5),
        "{elapsed:?}"
    );

    let after = evaluate("function FindProxyForURL(url, host) { return 'DIRECT'; }").unwrap();
    assert_eq!(after, vec![ProxyStep::Direct]);
}

#[test]
fn a_zero_budget_is_refused_at_construction() {
    assert!(matches!(
        CfNetworkPacEvaluator::with_timeout(Duration::ZERO),
        Err(Error::PacTimeout { .. })
    ));
    assert!(matches!(
        CfNetworkPacResolver::with_timeout(Duration::ZERO),
        Err(Error::PacTimeout { .. })
    ));
}

#[test]
fn a_served_script_is_downloaded_and_its_chain_comes_back_in_order() {
    let server = PacServer::start(
        "function FindProxyForURL(url, host) { return 'PROXY a.example:1; PROXY b.example:2; DIRECT'; }",
    );
    let pac_url = server.url();
    let steps = within(move || {
        CfNetworkPacResolver::with_timeout(BUDGET)
            .unwrap()
            .resolve(&target(), &pac_url)
    })
    .unwrap();
    assert_eq!(
        steps,
        parse_find_proxy_result("PROXY a.example:1; PROXY b.example:2; DIRECT").unwrap()
    );
}

#[test]
fn a_pac_url_with_nothing_listening_is_an_error() {
    let port = {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    let pac_url = Url::parse(&format!("http://127.0.0.1:{port}/missing.pac")).unwrap();
    let error = within(move || {
        CfNetworkPacResolver::with_timeout(GIVE_UP_BUDGET)
            .unwrap()
            .resolve(&target(), &pac_url)
    })
    .expect_err("an undownloadable script must not resolve");
    println!("{error:?}");
    assert!(
        matches!(error, Error::Io { .. } | Error::PacTimeout { .. }),
        "{error:?}"
    );
}

#[test]
fn a_server_that_never_answers_is_abandoned_at_the_budget() {
    let server = PacServer::stalling();
    let pac_url = server.url();
    let (result, elapsed) = within(move || {
        let started = Instant::now();
        let result = CfNetworkPacResolver::with_timeout(GIVE_UP_BUDGET)
            .unwrap()
            .resolve(&target(), &pac_url);
        (result, started.elapsed())
    });
    println!("{result:?} after {elapsed:?}");
    assert!(
        matches!(result, Err(Error::PacTimeout { .. } | Error::Io { .. })),
        "{result:?}"
    );
    assert!(
        elapsed < GIVE_UP_BUDGET + Duration::from_secs(5),
        "{elapsed:?}"
    );
}

#[test]
fn resolve_config_routes_each_mode() {
    let server = PacServer::start(
        "function FindProxyForURL(url, host) { return 'PROXY served.example:1'; }",
    );
    let pac_url = server.url();
    within(move || {
        let resolver = CfNetworkPacResolver::with_timeout(BUDGET).unwrap();
        let config =
            |mode| ProxyConfig::from_source(ProxyConfigSource::SystemConfigurationState, mode);

        assert_eq!(
            resolver
                .resolve_config(&config(ProxyMode::pac(pac_url)), &target())
                .unwrap(),
            parse_find_proxy_result("PROXY served.example:1").unwrap()
        );
        assert_eq!(
            resolver
                .resolve_config(
                    &config(ProxyMode::pac_inline(
                        "function FindProxyForURL(u, h) { return 'PROXY inline.example:1'; }"
                            .to_owned()
                    )),
                    &target()
                )
                .unwrap(),
            parse_find_proxy_result("PROXY inline.example:1").unwrap()
        );
        assert!(matches!(
            resolver.resolve_config(&config(ProxyMode::WpadAutoDetect), &target()),
            Err(Error::PacNotSupported { mode: "wpad" })
        ));
        assert_eq!(
            resolver
                .resolve_config(
                    &config(ProxyMode::WpadAutoDetect),
                    &Url::parse("mailto:someone@example.net").unwrap()
                )
                .unwrap(),
            vec![ProxyStep::Direct]
        );
        // On, but the snapshot's discovery came from a scope the live settings are not.
        assert!(matches!(
            resolver.clone().with_wpad(true).resolve_config(
                &ProxyConfig::from_source(
                    ProxyConfigSource::SystemConfigurationSetup,
                    ProxyMode::WpadAutoDetect
                ),
                &target()
            ),
            Err(Error::PacNotSupported { mode: "wpad" })
        ));
        assert_eq!(
            resolver
                .resolve_config(&config(ProxyMode::Direct), &target())
                .unwrap(),
            vec![ProxyStep::Direct]
        );
    });
}

/// The evaluator drops into `PacResolver` like any other.
#[test]
fn pac_resolver_runs_inline_bodies_on_cfnetwork() {
    let steps = within(|| {
        let config = ProxyConfig::from_source(
            ProxyConfigSource::SystemConfigurationState,
            ProxyMode::pac_inline(
                "function FindProxyForURL(u, h) { return 'PROXY via-resolver.example:1'; }"
                    .to_owned(),
            ),
        );
        PacResolver::new(Default::default())
            .with_evaluator(CfNetworkPacEvaluator::with_timeout(BUDGET).unwrap())
            .resolve_config(&config, &target(), None)
    })
    .unwrap();
    assert_eq!(
        steps,
        parse_find_proxy_result("PROXY via-resolver.example:1").unwrap()
    );
}

/// A PAC URL that answers 401 with NTLM, Negotiate and Basic challenges gets no credentials
/// back: every request that reaches the server carries no `Authorization` header. This is the
/// WPAD + 401 hash-capture path, and `WinHttpPacResolver` closes it with
/// `fAutoLogonIfChallenged: FALSE`; CFNetwork's execute call has no such switch. A runner has
/// no domain account and no keychain entry for this host, so a pass here bounds only what
/// CFNetwork offers without stored credentials.
#[test]
fn a_challenged_pac_download_sends_no_credentials() {
    use std::io::{BufRead, BufReader, Write};
    use std::sync::{Arc, Mutex};

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let pac_url = Url::parse(&format!(
        "http://{}/challenged.pac",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let requests: Arc<Mutex<Vec<Vec<String>>>> = Arc::default();
    {
        let requests = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut headers = Vec::new();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 && line.trim_end() != "" {
                    headers.push(line.trim_end().to_owned());
                    line.clear();
                }
                requests.lock().unwrap().push(headers);
                let _ = stream.write_all(
                    b"HTTP/1.1 401 Unauthorized\r\n\
                      WWW-Authenticate: NTLM\r\n\
                      WWW-Authenticate: Negotiate\r\n\
                      WWW-Authenticate: Basic realm=\"pac\"\r\n\
                      Content-Length: 0\r\n\
                      Connection: close\r\n\r\n",
                );
            }
        });
    }

    let result = within(move || {
        CfNetworkPacResolver::with_timeout(Duration::from_secs(5))
            .unwrap()
            .resolve(&target(), &pac_url)
    });
    let requests = requests.lock().unwrap().clone();
    println!("{result:?}");
    for (i, headers) in requests.iter().enumerate() {
        println!("request {i}: {headers:?}");
    }
    assert!(!requests.is_empty(), "the PAC URL was never requested");
    let sent: Vec<&String> = requests
        .iter()
        .flatten()
        .filter(|h| h.to_ascii_lowercase().starts_with("authorization:"))
        .collect();
    assert!(sent.is_empty(), "{sent:?}");
    assert!(result.is_err(), "{result:?}");
}
