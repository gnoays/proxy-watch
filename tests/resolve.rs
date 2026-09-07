//! Table-driven tests for [`resolve`]: scheme routing, the `All` fallback, bypass
//! matching and the auto-config error.
//!
//! The whole file is compiled away without the `resolve` feature.
#![cfg(feature = "resolve")]

use proxy_watch::{
    Error, ProxyConfig, ProxyConfigSource, ProxyEndpoint, ProxyEntry, ProxyMode, ProxyStep, Scheme,
    Url, parse, resolve,
};
use std::collections::HashMap;

/// Per-scheme entries plus one explicitly disabled scheme.
const SERVERS: &str = "http=http-proxy:8080;https=https-proxy:8443;\
                       socks=socks5://socks-proxy;ftp=";

/// One of every pattern kind a Windows list can carry: `<local>`, a name wildcard, the
/// address wildcard that is Windows' spelling of a range, an IPv6 literal and two
/// port-restricted rules. `HostPattern::Cidr` is the kind that cannot appear here, and
/// [`a_cidr_bypass_reaches_resolve_from_the_environment_list`] carries it instead.
const OVERRIDE: &str = "<local>;*.corp.example;10.*;[2001:db8::1];\
                        fixed.example:8080;tls.example:443";

fn manual() -> ProxyConfig {
    let mode = parse::windows_manual(SERVERS, OVERRIDE);
    ProxyConfig::from_source(ProxyConfigSource::Registry, mode)
}

/// A catch-all entry plus a scheme that is explicitly switched off (`Disabled`
/// suppresses the `All` fallback).
fn catch_all() -> ProxyConfig {
    let mode = parse::windows_manual("proxy-all:3128;ftp=", "");
    ProxyConfig::from_source(ProxyConfigSource::Registry, mode)
}

/// The single step `resolve` returns, as `host:port`, or `None` for direct.
///
/// "Exactly one" is not a property of this version but of this function: `resolve`
/// rejects all three auto-config modes outright, and only a PAC script's
/// `FindProxyForURL` can produce a longer chain (see `resolve`'s own header doc, and
/// `resolve_with_pac()` behind the `pac` feature, which is where such a chain surfaces).
#[track_caller]
fn authority_for(config: &ProxyConfig, url: &str) -> Option<String> {
    let url = Url::parse(url).expect("valid test URL");
    let steps = resolve(config, &url).expect("no auto-config involved");
    assert_eq!(steps.len(), 1, "{url}: resolve() always returns one step");
    let step = &steps[0];
    assert_eq!(step.is_direct(), step.endpoint().is_none());
    step.endpoint().map(ProxyEndpoint::authority)
}

/// `(url, expected proxy authority or None for a direct connection)`
const MANUAL_CASES: &[(&str, Option<&str>)] = &[
    // Per-scheme routing.
    ("http://example.net/a?b=c", Some("http-proxy:8080")),
    ("https://example.net/", Some("https-proxy:8443")),
    ("socks5://example.net/", Some("socks-proxy:1080")),
    // WebSocket URLs follow the Chromium socks= -> https= -> http= chain,
    // not their same-name HTTP/HTTPS counterpart: `SERVERS` sets a
    // `socks=`, so both `ws` and `wss` land on it ahead of https= and http=.
    ("ws://example.net/", Some("socks-proxy:1080")),
    ("wss://example.net/", Some("socks-proxy:1080")),
    // `ftp=` with an empty value is `ProxyEntry::Disabled`.
    ("ftp://example.net/", None),
    // An unmodelled scheme can only match a catch-all entry — and `SERVERS` has one,
    // because its `socks=` is exactly that. This case used to expect `None`,
    // on the since-corrected premise that only a bare token can produce a catch-all.
    ("gopher://example.net/", Some("socks-proxy:1080")),
    // A URL with no host at all.
    ("mailto:someone@example.net", None),
    ("data:text/plain,hello", None),
    // `<local>`: a host name without a dot.
    ("http://intranet/", None),
    ("http://intranet.example/", Some("http-proxy:8080")),
    // Wildcard: `*.corp.example` covers subdomains only, not the bare domain.
    ("http://api.corp.example/", None),
    ("http://deep.api.corp.example/", None),
    ("http://corp.example/", Some("http-proxy:8080")),
    ("http://notcorp.example/", Some("http-proxy:8080")),
    // The address wildcard, which covers the same hosts `10.0.0.0/8` would.
    ("http://10.1.2.3/", None),
    ("http://11.1.2.3/", Some("http-proxy:8080")),
    // IPv6 literals, bypassed and not.
    ("http://[2001:db8::1]/", None),
    ("http://[2001:db8::2]/", Some("http-proxy:8080")),
    ("https://[2001:db8::1]:8443/", None),
    // Loopback is bypassed by default, by name and by address.
    ("http://localhost/", None),
    ("http://127.0.0.1:9000/", None),
    ("http://[::1]/", None),
    // A port-restricted rule only applies to that port.
    ("http://fixed.example:8080/", None),
    ("http://fixed.example/", Some("http-proxy:8080")),
    // ... and the port is the scheme's default when the URL omits it.
    ("https://tls.example/", None),
    ("http://tls.example/", Some("http-proxy:8080")),
];

#[test]
fn manual_settings_route_and_bypass() {
    let config = manual();
    for (url, expected) in MANUAL_CASES {
        assert_eq!(authority_for(&config, url).as_deref(), *expected, "{url}");
    }
}

/// The one pattern kind [`MANUAL_CASES`] cannot carry. `parse::proxy_override` refuses an
/// entry holding a `/` — the reason is `a_slash_ends_a_windows_bypass_list` in
/// `tests/bypass.rs` — so a mask reaches `resolve` from the list that does read one.
#[test]
fn a_cidr_bypass_reaches_resolve_from_the_environment_list() {
    let endpoint = ProxyEndpoint::parse("http-proxy:8080", 80).expect("valid endpoint");
    let mode = ProxyMode::manual(
        HashMap::from([(Scheme::Http, ProxyEntry::Use(endpoint))]),
        parse::no_proxy("10.0.0.0/8"),
    );
    let config = ProxyConfig::from_source(ProxyConfigSource::Env, mode);
    assert_eq!(authority_for(&config, "http://10.1.2.3/"), None);
    assert_eq!(
        authority_for(&config, "http://11.1.2.3/").as_deref(),
        Some("http-proxy:8080")
    );
}

/// The third spelling of "no host", and the only one no URL literal can write: `Url::host`
/// answers `Some(Host::Domain(""))` for a URL whose host was emptied, not `None`, so the
/// `mailto:` and `data:` rows in [`MANUAL_CASES`] do not reach it.
/// `endpoint::request_host` is what folds the two spellings into one, and until now its
/// empty-domain arm was held by a single test in `tests/pac_winhttp.rs` — Windows-only, and
/// only with the `pac-windows-native` engine. Every other runner, and every feature set
/// without that engine, could drop the arm and stay green while `resolve` routed a URL with
/// nothing to connect to through `SERVERS`' `socks=` catch-all.
#[test]
fn a_url_whose_host_was_emptied_is_hostless_here_too() {
    // A non-special scheme, because the special ones refuse `set_host(None)` with
    // `EmptyHost` (measured on url 2.5.8) — and `socks5`, so that the entry this would
    // wrongly reach is a live one rather than an empty slot.
    let mut url = Url::parse("socks5://host:1080/path").unwrap();
    url.set_host(None)
        .expect("a non-special scheme may drop its host");
    assert!(
        url.host().is_some(),
        "the premise: this URL is hostless only by `request_host`'s reading, not by \
         `Url::host`'s — if url ever answers `None` here, this test stops being about the \
         arm it was written for"
    );

    assert_eq!(resolve(&manual(), &url).unwrap(), vec![ProxyStep::Direct]);
}

#[test]
fn the_all_entry_is_only_a_fallback() {
    let config = catch_all();
    // No `http=` entry: the catch-all applies.
    assert_eq!(
        authority_for(&config, "http://example.net/").as_deref(),
        Some("proxy-all:3128")
    );
    // Unmodelled schemes reach it too.
    assert_eq!(
        authority_for(&config, "gopher://example.net/").as_deref(),
        Some("proxy-all:3128")
    );
    // `Disabled` beats the catch-all instead of falling through to it.
    assert_eq!(authority_for(&config, "ftp://example.net/"), None);
}

/// `socks=` means "for everything else", and an unmodelled scheme is the most
/// "everything else" a request can be — but the fallback used to fill only
/// `http`/`https`/`ftp`, so `gopher://` went direct on a machine
/// whose one configured proxy was a SOCKS one. Chromium's `MapUrlSchemeToProxyList`
/// hands exactly these schemes to `fallback_proxies`, which is what `socks=` populates
/// there.
///
/// The counterpart to `the_all_entry_is_only_a_fallback` above: same question, asked of
/// the catch-all `socks=` synthesises rather than the one a bare token writes.
#[test]
fn a_lone_socks_entry_also_covers_unmodelled_schemes() {
    let mode = parse::windows_manual("socks=socks-proxy:1080", "");
    let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);

    assert_eq!(
        authority_for(&config, "http://example.net/").as_deref(),
        Some("socks-proxy:1080"),
        "the modelled schemes were already covered"
    );
    assert_eq!(
        authority_for(&config, "gopher://example.net/").as_deref(),
        Some("socks-proxy:1080"),
        "an unmodelled scheme must reach the socks= fallback, not go direct"
    );
}

/// The other half of the fallback-widening behaviour above: widening the fill must not
/// resurrect a scheme that was explicitly switched off. `Disabled` suppresses the
/// `Scheme::All` fallback, and the synthesised catch-all is still a `Scheme::All` entry.
#[test]
fn an_explicitly_disabled_scheme_still_beats_the_socks_catch_all() {
    let mode = parse::windows_manual("socks=socks-proxy:1080;ftp=", "");
    let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);

    assert_eq!(authority_for(&config, "ftp://example.net/"), None);
    assert_eq!(
        authority_for(&config, "gopher://example.net/").as_deref(),
        Some("socks-proxy:1080"),
        "one disabled scheme must not take the catch-all down with it"
    );

    // Written the other way round, an empty entry must still mean the same thing.
    // Chromium is where this is worth pinning rather than copying: its
    // `ProxyRules::ParseFromString` tokenises on `=` with empty tokens off, so `ftp=`
    // yields the single token `ftp`. Reached second it is skipped and `ftp` quietly
    // falls through to the SOCKS `fallback_proxies`; reached *first* the same token is
    // taken for a bare proxy host, so the whole string collapses to "everything through
    // a proxy named ftp" and `socks=` is never read. An empty entry deserves one
    // meaning, and it is this file's, not an artifact of where it was written.
    let reversed = parse::windows_manual("ftp=;socks=socks-proxy:1080", "");
    let reversed = ProxyConfig::from_source(ProxyConfigSource::Registry, reversed);

    assert_eq!(authority_for(&reversed, "ftp://example.net/"), None);
    assert_eq!(
        authority_for(&reversed, "gopher://example.net/").as_deref(),
        Some("socks-proxy:1080")
    );
    assert_eq!(
        authority_for(&reversed, "http://example.net/").as_deref(),
        Some("socks-proxy:1080")
    );
}

/// A malformed `socks=` token does not just lose `socks://` requests — it loses the
/// implied catch-all `apply_socks_catch_all` would have synthesised for every scheme with
/// no token of its own, the same fallback `a_lone_socks_entry_also_covers_unmodelled_schemes`
/// above pins for a *valid* entry. The rejection is attributed as widely as what it took
/// away — `Scheme::All`, not `Scheme::Socks` — so both a modelled and an unmodelled scheme
/// reach the record `ProxyMode::with_rejected` files in the `Scheme::All` slot, and are
/// reported rather than quietly resolved Direct.
#[test]
fn a_malformed_socks_entry_loses_the_catch_all_it_would_have_synthesised() {
    let mode = parse::windows_manual("socks=h:99999", "");
    let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);

    for scheme in ["http", "gopher"] {
        let url = Url::parse(&format!("{scheme}://example.net/")).unwrap();
        let err = resolve(&config, &url).unwrap_err();
        assert!(
            matches!(&err, Error::ProxyEntryUnusable { scheme, .. } if *scheme == Scheme::All),
            "{url}: {err:?}"
        );
    }
}

/// `ws`/`wss` must resolve through the Chromium order
/// `socks=` -> `https=` -> `http=` -> a bare catch-all, not simply reuse
/// `http=`/`https=` the way plain HTTP/HTTPS requests do. `manual_settings_route_and_bypass`
/// above already covers the "a `socks=` entry wins outright" case via `SERVERS`; this
/// test walks the rest of the chain one tier at a time.
#[test]
fn websocket_urls_follow_the_socks_then_https_then_http_order() {
    let cases: &[(&str, &str)] = &[
        // https= and http= both present, no socks=: wss/ws prefer https=.
        (
            "https=https-proxy:8443;http=http-proxy:8080",
            "https-proxy:8443",
        ),
        // Only http= present: falls all the way through to it.
        ("http=http-proxy:8080", "http-proxy:8080"),
        // A bare catch-all is the last resort, reached only once every per-scheme
        // tier is entirely unconfigured.
        ("bare-proxy:3128", "bare-proxy:3128"),
    ];
    for (servers, expected) in cases {
        let mode = parse::windows_manual(servers, "");
        let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);
        for scheme in ["ws", "wss"] {
            let url = format!("{scheme}://example.net/");
            assert_eq!(
                authority_for(&config, &url).as_deref(),
                Some(*expected),
                "{url} with ProxyServer={servers:?}"
            );
        }
    }

    // An explicitly disabled https= is skipped, not treated as a stop signal: the
    // chain still reaches http= behind it (unlike `entry_for`'s behavior, where a
    // `Disabled` entry for the *requested* scheme itself wins outright).
    let mode = parse::windows_manual("https=;http=http-proxy:8080", "");
    let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);
    assert_eq!(
        authority_for(&config, "wss://example.net/").as_deref(),
        Some("http-proxy:8080")
    );
    // The plain HTTPS request, by contrast, is genuinely disabled.
    assert_eq!(authority_for(&config, "https://example.net/"), None);

    // Nothing configured at all: ws/wss go direct, same as everything else.
    let mode = parse::windows_manual("", "");
    let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);
    assert_eq!(authority_for(&config, "ws://example.net/"), None);
    assert_eq!(authority_for(&config, "wss://example.net/"), None);
}

#[test]
fn the_step_variant_comes_from_the_scheme_hint() {
    let config = manual();
    let url = Url::parse("socks5://example.net/").unwrap();
    let steps = resolve(&config, &url).unwrap();
    assert!(
        matches!(steps[0], ProxyStep::Socks5(_)),
        "a socks5:// hint must produce ProxyStep::Socks5, got {:?}",
        steps[0]
    );
    assert_eq!(
        steps[0].to_url().map(|u| u.to_string()).as_deref(),
        Some("socks5://socks-proxy:1080")
    );

    // A bare `host:port` from the registry has no hint and is treated as HTTP.
    let url = Url::parse("http://example.net/").unwrap();
    let steps = resolve(&config, &url).unwrap();
    assert!(matches!(steps[0], ProxyStep::Http(_)), "{:?}", steps[0]);
    assert_eq!(
        steps[0].to_url().map(|u| u.to_string()).as_deref(),
        Some("http://http-proxy:8080/")
    );
    assert!(ProxyStep::Direct.to_url().is_none());
}

/// `to_url()` must not round `socks5h://`/`socks4a://` down to `socks5://`/`socks4://`:
/// the `h`/`a` means the proxy resolves the destination host name, and dropping it would
/// make a caller that trusts `to_url()`'s output resolve DNS locally instead — a leak.
#[test]
fn to_url_keeps_the_socks_remote_dns_hint_end_to_end() {
    let mode = crate::parse::windows_manual("socks=socks5h://socks-proxy:1080", "");
    let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);
    let url = Url::parse("socks5://example.net/").unwrap();
    let steps = resolve(&config, &url).unwrap();
    assert!(matches!(steps[0], ProxyStep::Socks5(_)));
    assert_eq!(
        steps[0].to_url().unwrap().as_str(),
        "socks5h://socks-proxy:1080"
    );

    let mode = crate::parse::windows_manual("socks=socks4a://socks-proxy:1080", "");
    let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);
    let steps = resolve(&config, &url).unwrap();
    assert!(matches!(steps[0], ProxyStep::Socks4(_)));
    assert_eq!(
        steps[0].to_url().unwrap().as_str(),
        "socks4a://socks-proxy:1080"
    );
}

#[test]
fn direct_configurations_need_no_proxy() {
    let config = ProxyConfig::direct();
    assert_eq!(authority_for(&config, "http://example.net/"), None);
    assert_eq!(authority_for(&config, "https://10.0.0.1/"), None);
}

#[test]
fn auto_config_modes_are_an_error_rather_than_a_silent_bypass() {
    let cases = [
        (
            ProxyMode::pac(Url::parse("http://wpad.corp/proxy.pac").unwrap()),
            "pac",
        ),
        (
            ProxyMode::pac_inline("function FindProxyForURL(u, h) { return 'DIRECT'; }".to_owned()),
            "pac-inline",
        ),
        (ProxyMode::WpadAutoDetect, "wpad"),
    ];

    let url = Url::parse("http://example.net/").unwrap();
    for (mode, expected) in cases {
        let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);
        match resolve(&config, &url) {
            Err(Error::PacNotSupported { mode }) => assert_eq!(mode, expected),
            other => panic!("expected PacNotSupported({expected}), got {other:?}"),
        }
    }
}

/// `resolve` is handed a whole [`ProxyConfig`], which carries every source that was
/// consulted, and takes its mode from exactly one of them: `effective`. This test is the
/// only thing pinning that choice. Every other config in this file has a single source, so
/// `effective` and the losing sources are the same value and any of them answers alike —
/// reading the *last* source instead leaves the rest of the tree green.
///
/// The order below is the fixture's own: `effective` is whatever built the list put first,
/// and no backend in this crate produces this particular pair. Resolving against a losing
/// source is the failure the test names, whichever source that happens to be.
#[test]
fn resolve_reads_the_effective_mode_and_not_a_losing_source() {
    let config = ProxyConfig::from_ordered_sources(vec![
        (
            ProxyConfigSource::GroupPolicy,
            parse::windows_manual("policy-proxy:8080", ""),
        ),
        (
            ProxyConfigSource::Registry,
            parse::windows_manual("user-proxy:3128", ""),
        ),
    ]);
    // The sources have to disagree, or the assertion below passes whichever one is read.
    assert_ne!(
        config.source(ProxyConfigSource::GroupPolicy),
        config.source(ProxyConfigSource::Registry)
    );
    assert_eq!(
        authority_for(&config, "http://example.net/"),
        Some("policy-proxy:8080".to_owned())
    );
}

/// Even a destination that would obviously be bypassed does not turn an auto-config
/// mode into a direct connection: PAC scripts decide that themselves, and `resolve()`
/// does not run them. (Evaluating one is what `resolve_with_pac()` and the `pac` feature
/// are for — see `tests/pac.rs`.)
#[test]
fn auto_config_fails_before_bypass_matching() {
    let config = ProxyConfig::from_source(ProxyConfigSource::Registry, ProxyMode::WpadAutoDetect);
    let url = Url::parse("http://localhost:1234/").unwrap();
    assert!(matches!(
        resolve(&config, &url),
        Err(Error::PacNotSupported { .. })
    ));
}
