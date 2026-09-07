//! PAC evaluation through the public API.
//!
//! The whole file is behind the `pac` feature; the engine-specific half is behind
//! `pac-boa` on top of that, so `cargo test` with default features compiles this to
//! nothing.

#![cfg(feature = "pac")]

use proxy_watch::pac::{PacPolicy, PacRequirement, PacScript, requirement};
use proxy_watch::{
    Error, ProxyConfig, ProxyConfigSource, ProxyMode, Url, resolve, resolve_with_pac,
};

fn config(mode: ProxyMode) -> ProxyConfig {
    ProxyConfig::from_source(ProxyConfigSource::Registry, mode)
}

fn pac_url() -> Url {
    Url::parse("http://wpad.corp.example/proxy.pac").unwrap()
}

// `parse_find_proxy_result` has no tests of its own here, deliberately. Every case worth
// writing at this point — the chain, bare `SOCKS`, a junk candidate among good ones, the
// unusable results — is a strict subset of `src/pac/result.rs`'s unit tests, down to the
// input strings, observed through the same public accessors (`authorities` there is a
// `scheme()` + `endpoint().authority()` map). Its rustdoc example runs the chain case
// through `proxy_watch::pac::` as well, so "reachable from outside the crate" is covered
// three times over already. What belongs in this file is what only the public API can
// show: which of `resolve` / `resolve_with_pac` answers, and with which error.

// ---------------------------------------------------------------------------
// Engine-independent: who is supposed to fetch the script.
// ---------------------------------------------------------------------------

#[test]
fn a_url_mode_asks_the_caller_to_fetch() {
    let mode = ProxyMode::pac(pac_url());
    assert_eq!(requirement(&mode), PacRequirement::Fetch(&pac_url()));

    let error = resolve_with_pac(
        &config(mode),
        &Url::parse("http://example.net/").unwrap(),
        None,
        &PacPolicy::new(),
    )
    .unwrap_err();
    match error {
        Error::PacFetchRequired { url } => assert_eq!(url, pac_url()),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn wpad_is_still_refused_without_a_script() {
    let error = resolve_with_pac(
        &config(ProxyMode::WpadAutoDetect),
        &Url::parse("http://example.net/").unwrap(),
        None,
        &PacPolicy::new(),
    )
    .unwrap_err();
    assert!(
        matches!(error, Error::PacNotSupported { mode: "wpad" }),
        "{error:?}"
    );
    assert_eq!(
        requirement(&ProxyMode::WpadAutoDetect),
        PacRequirement::Discover
    );
}

// "Needs no fetch" is a claim about the body, so both assertions look at the body. The
// earlier pair only looked at the shape — an `Inline(_)` that discarded its payload and an
// `is_some()` — and a `from_mode` returning an empty script passed both. That mutation was
// caught, but by the unit test on the same function, not here; from outside the crate the
// caller's guarantee is that the script it put in is the script it can run.
#[test]
fn an_inline_script_needs_no_fetch() {
    let script = "function FindProxyForURL(u, h) { return 'DIRECT'; }";
    let mode = ProxyMode::pac_inline(script.to_owned());
    assert_eq!(requirement(&mode), PacRequirement::Inline(script));
    assert_eq!(
        PacScript::from_mode(&mode).as_ref().map(PacScript::source),
        Some(script)
    );
}

// ---------------------------------------------------------------------------
// The existing `resolve()` contract must not move.
// ---------------------------------------------------------------------------

#[test]
fn resolve_still_refuses_every_auto_config_mode() {
    let url = Url::parse("http://example.net/").unwrap();
    for (mode, expected) in [
        (ProxyMode::pac(pac_url()), "pac"),
        (ProxyMode::pac_inline("x".to_owned()), "pac-inline"),
        (ProxyMode::WpadAutoDetect, "wpad"),
    ] {
        let error = resolve(&config(mode), &url).unwrap_err();
        match error {
            Error::PacNotSupported { mode } => assert_eq!(mode, expected),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
fn resolve_with_pac_agrees_with_resolve_on_non_pac_modes() {
    let script = PacScript::new("function FindProxyForURL(u, h) { return 'PROXY never:1'; }");
    let policy = PacPolicy::new();
    let manual = proxy_watch::parse::windows_manual("http=proxy.corp:8080", "<local>");

    for mode in [ProxyMode::Direct, manual] {
        let config = config(mode);
        for target in [
            "http://example.net/",
            "http://intranet/",
            "https://example.net/",
        ] {
            let url = Url::parse(target).unwrap();
            assert_eq!(
                resolve_with_pac(&config, &url, Some(&script), &policy).unwrap(),
                resolve(&config, &url).unwrap(),
                "{target}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The rest needs a JavaScript engine.
// ---------------------------------------------------------------------------

#[cfg(feature = "pac-boa")]
mod with_engine {
    use super::*;

    use std::time::Duration;

    use proxy_watch::ProxyStep;
    use proxy_watch::pac::{BoaEvaluator, PacEvaluator, evaluate};

    const CORPORATE: &str = "
        function FindProxyForURL(url, host) {
            if (isPlainHostName(host)) { return 'DIRECT'; }
            if (dnsDomainIs(host, '.corp.example')) { return 'DIRECT'; }
            if (shExpMatch(host, '*.cdn.*')) { return 'DIRECT'; }
            return 'PROXY edge.corp.example:8080; DIRECT';
        }";

    // What every test here that actually runs a script asks for. The default budget is 5 s
    // of *wall clock*, and a loaded machine can spend that on scheduling alone — enough for
    // `a_caller_supplied_script_overrides_an_inline_one`, a one-line script, to fail with
    // `PacTimeout { timeout: 5s }` during a full `--all-features` run. None of these tests is
    // about the budget (`an_endless_script_is_stopped` below is, with its own 250 ms), so
    // they ask for a margin load cannot close. It stays a `Some`, which is what keeps the
    // evaluation on the threaded path a real caller takes; `None` would select the other.
    // Nothing else moves, which is what lets the test named for *the default policy* keep
    // that name: the budget is not one of the defaults it is about.
    fn policy() -> PacPolicy {
        PacPolicy::new().with_timeout(Some(Duration::from_secs(60)))
    }

    fn steps(mode: ProxyMode, target: &str) -> Vec<ProxyStep> {
        resolve_with_pac(&config(mode), &Url::parse(target).unwrap(), None, &policy()).unwrap()
    }

    #[test]
    fn an_inline_script_routes_a_real_request() {
        let mode = ProxyMode::pac_inline(CORPORATE.to_owned());
        assert_eq!(steps(mode.clone(), "http://intranet/"), [ProxyStep::Direct]);
        assert_eq!(
            steps(mode.clone(), "http://wiki.corp.example/"),
            [ProxyStep::Direct]
        );
        assert_eq!(
            steps(mode.clone(), "https://images.cdn.example/logo.png"),
            [ProxyStep::Direct]
        );

        // An IPv6 destination carries no dot, so a naive `isPlainHostName` would call it a
        // bare intranet name and take the first line out — sending every IPv6 request direct
        // past a script that never said so. This opening is the common one, which is why the
        // fixture leads with it.
        let chain = steps(mode.clone(), "https://[2001:db8::1]/index.html");
        assert_ne!(chain[0], ProxyStep::Direct, "{chain:?}");
        assert_eq!(
            chain[0].endpoint().unwrap().authority(),
            "edge.corp.example:8080"
        );

        let chain = steps(mode, "https://example.net/index.html");
        assert_eq!(chain.len(), 2);
        assert_eq!(
            chain[0].endpoint().unwrap().authority(),
            "edge.corp.example:8080"
        );
        assert_eq!(chain[1], ProxyStep::Direct);
    }

    #[test]
    fn a_fetched_script_answers_a_url_mode() {
        let script = PacScript::new(CORPORATE);
        let chain = resolve_with_pac(
            &config(ProxyMode::pac(pac_url())),
            &Url::parse("https://example.net/").unwrap(),
            Some(&script),
            &policy(),
        )
        .unwrap();
        assert_eq!(
            chain[0].endpoint().unwrap().authority(),
            "edge.corp.example:8080"
        );
    }

    #[test]
    fn a_caller_supplied_script_overrides_an_inline_one() {
        let mode = ProxyMode::pac_inline(
            "function FindProxyForURL(u, h) { return 'PROXY stale:1'; }".to_owned(),
        );
        let fresh = PacScript::new("function FindProxyForURL(u, h) { return 'PROXY fresh:1'; }");
        let chain = resolve_with_pac(
            &config(mode),
            &Url::parse("http://example.net/").unwrap(),
            Some(&fresh),
            &policy(),
        )
        .unwrap();
        assert_eq!(chain[0].endpoint().unwrap().authority(), "fresh:1");
    }

    #[test]
    fn a_hostless_url_never_reaches_the_script() {
        // The script would panic the assertion by returning a proxy; a `data:` URL has
        // no destination, so it must short-circuit to Direct.
        let mode = ProxyMode::pac_inline(
            "function FindProxyForURL(u, h) { return 'PROXY nope:1'; }".to_owned(),
        );
        assert_eq!(steps(mode, "data:text/plain,hello"), [ProxyStep::Direct]);
    }

    #[test]
    fn bypass_rules_do_not_apply_to_a_pac_result() {
        // The snapshot's *effective* mode is PAC, so the exception list of a manual
        // configuration is irrelevant: only the script decides. `intranet` would be
        // bypassed by `<local>` under a manual mode, and the script proxies it.
        let mode = ProxyMode::pac_inline(
            "function FindProxyForURL(u, h) { return 'PROXY always:8080'; }".to_owned(),
        );
        let chain = steps(mode, "http://intranet/");
        assert_eq!(chain[0].endpoint().unwrap().authority(), "always:8080");
    }

    #[test]
    fn the_default_policy_blocks_dns_and_hides_the_local_address() {
        let script = PacScript::new(
            "function FindProxyForURL(url, host) {
                 var ip = dnsResolve(host);
                 if (ip != null) { return 'PROXY dns-leak:1'; }
                 if (isResolvable(host)) { return 'PROXY resolvable-leak:1'; }
                 if (isInNet(host, '0.0.0.0', '0.0.0.0')) { return 'PROXY innet-leak:1'; }
                 return 'PROXY ' + myIpAddress() + ':1';
             }",
        );
        let chain = evaluate(
            &script,
            &Url::parse("http://localhost/").unwrap(),
            &policy(),
        )
        .unwrap();
        assert_eq!(chain[0].endpoint().unwrap().authority(), "127.0.0.1:1");
    }

    #[test]
    fn a_syntax_error_is_reported_not_panicked() {
        let script = PacScript::new("function FindProxyForURL(url, host) { return 'DIRECT'");
        let error = evaluate(
            &script,
            &Url::parse("http://example.net/").unwrap(),
            &policy(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
    }

    #[test]
    fn an_endless_script_is_stopped() {
        let script = PacScript::new("function FindProxyForURL(url, host) { for (;;) {} }");
        // High enough that the wall clock is what stops this. The abandoned evaluation
        // thread does not end shortly after — it runs until this binary exits. Why the
        // cap is this high anyway, and why no setting avoids the trade, is measured out
        // in `an_infinite_loop_hits_the_wall_clock_timeout` in `src/pac/boa.rs`.
        let policy = PacPolicy::new()
            .with_max_loop_iterations(20_000_000)
            .with_timeout(Some(Duration::from_millis(250)));
        let started = std::time::Instant::now();
        let error = evaluate(
            &script,
            &Url::parse("http://example.net/").unwrap(),
            &policy,
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacTimeout { .. }), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn the_evaluator_trait_is_usable_through_a_trait_object() {
        let evaluator: Box<dyn PacEvaluator> = Box::new(BoaEvaluator::new(policy()));
        let script = PacScript::new("function FindProxyForURL(url, host) { return 'DIRECT'; }");
        let steps = evaluator
            .evaluate(
                &script,
                &Url::parse("http://example.net/").unwrap(),
                "example.net",
            )
            .unwrap();
        assert_eq!(steps, [ProxyStep::Direct]);
    }
}

// ---------------------------------------------------------------------------
// Without an engine, `pac` alone must say so rather than pretend.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "pac-boa"))]
#[test]
fn without_an_engine_the_error_names_the_missing_feature() {
    let mode =
        ProxyMode::pac_inline("function FindProxyForURL(u, h) { return 'DIRECT'; }".to_owned());
    let error = resolve_with_pac(
        &config(mode),
        &Url::parse("http://example.net/").unwrap(),
        None,
        &PacPolicy::new(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::PacEngineUnavailable), "{error:?}");
    assert!(error.to_string().contains("pac-boa"));
}
