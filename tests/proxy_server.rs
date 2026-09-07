//! Table-driven tests for the Windows `ProxyServer` parser.

use proxy_watch::{
    Error, ProxyEndpoint, ProxyEntry, ProxyScheme, RejectedValue, RejectionKind, RejectionSource,
    Scheme, parse,
};

fn rejected_texts(values: &[RejectedValue]) -> Vec<&str> {
    values.iter().map(RejectedValue::redacted_input).collect()
}

/// `(input, expected entries as (scheme, rendered))`
///
/// `rendered` is `"-"` for [`ProxyEntry::Disabled`], otherwise `host:port`.
#[rustfmt::skip]
const OK_CASES: &[(&str, &[(Scheme, &str)])] = &[
    // Empty / blank input yields no entries at all.
    ("", &[]),
    ("   ", &[]),
    (";;", &[]),
    // Single address form: applies to every scheme.
    ("proxy.example.com:8080", &[(Scheme::All, "proxy.example.com:8080")]),
    // Port omitted -> 80.
    ("proxy.example.com", &[(Scheme::All, "proxy.example.com:80")]),
    ("1.2.3.4", &[(Scheme::All, "1.2.3.4:80")]),
    // Per-scheme form. The `Scheme::All` entry is `socks=`'s: even with all three
    // modelled schemes spoken for, `socks=` still means "for everything else", and
    // `Scheme::All` is how an unmodelled scheme reaches it. Chromium keeps
    // `fallback_proxies` alongside a fully populated per-scheme set for the same reason.
    (
        "http=h1:8080;https=h2:8443;ftp=h3:21;socks=h4:1080",
        &[
            (Scheme::Http, "h1:8080"),
            (Scheme::Https, "h2:8443"),
            (Scheme::Ftp, "h3:21"),
            (Scheme::Socks, "h4:1080"),
            (Scheme::All, "h4:1080"),
        ],
    ),
    // Per-scheme form with the port omitted.
    ("http=h1;https=h2:8443", &[(Scheme::Http, "h1:80"), (Scheme::Https, "h2:8443")]),
    // Scheme keys are case-insensitive.
    ("HTTP=h:1;HtTpS=h:2", &[(Scheme::Http, "h:1"), (Scheme::Https, "h:2")]),
    // Entries may be separated by whitespace as well as `;`.
    ("http=h1:8080 https=h2:8443", &[(Scheme::Http, "h1:8080"), (Scheme::Https, "h2:8443")]),
    // Surrounding whitespace is ignored.
    (" http=h1:8080 ; https=h2:8443 ", &[(Scheme::Http, "h1:8080"), (Scheme::Https, "h2:8443")]),
    // IPv6 bracket notation, with and without a port.
    ("[::1]:3128", &[(Scheme::All, "[::1]:3128")]),
    ("[2001:db8::1]", &[(Scheme::All, "[2001:db8::1]:80")]),
    ("http=[fe80::1]:8080", &[(Scheme::Http, "[fe80::1]:8080")]),
    // Unmodelled scheme keys are skipped, not fatal.
    ("gopher=g:70;http=h:80", &[(Scheme::Http, "h:80")]),
    ("gopher=g:70", &[]),
    // An empty value is an explicit "no proxy for this scheme".
    ("http=;https=h:8443", &[(Scheme::Http, "-"), (Scheme::Https, "h:8443")]),
    // A full URL is accepted too (some tools write one into the registry).
    ("http://proxy:3128", &[(Scheme::All, "proxy:3128")]),
    ("http=http://proxy:3128", &[(Scheme::Http, "proxy:3128")]),
    // Later entries win over earlier ones for the same scheme.
    ("http=a:1;http=b:2", &[(Scheme::Http, "b:2")]),
    // Unless the later one is skipped. "Last wins" runs over the tokens that survive the
    // fail-soft rule, so a bad last spelling leaves the earlier proxy standing rather than
    // taking the scheme down with it — the drop is still recorded, and `resolve` never
    // reaches the record because this entry covers the scheme.
    ("http=a:1;http=b:99999", &[(Scheme::Http, "a:1")]),
];

/// Each of these, taken on its own, used to make [`parse::proxy_server`] return
/// `Err` for the whole value. Under the fail-soft policy, extended from the bypass-list
/// parser to `ProxyServer` as well, a malformed token is skipped instead — see
/// `rejects_only_the_malformed_token_and_keeps_the_rest` below for the case that
/// actually matters, a bad token *alongside* good ones. Standing alone, a malformed
/// token simply leaves the map empty, the same result `""` produces.
const DROPPED_CASES: &[&str] = &[
    ":8080",         // no host
    "http=:8080",    // no host in a per-scheme entry
    "h:99999",       // port out of range
    "h:abc",         // non-numeric port
    "[::1:8080",     // unbalanced bracket
    "[::zz]:80",     // malformed IPv6 literal
    "http=h:-1",     // negative port
    "gopher://h:70", // unsupported proxy scheme in a URL
    "h:",            // a written port that is empty
    "[::1]:",        // the same, after a bracketed literal
];

fn render(entry: &ProxyEntry) -> String {
    match entry.endpoint() {
        Some(endpoint) => endpoint.authority(),
        None => "-".to_owned(),
    }
}

#[test]
fn parses_valid_proxy_server_values() {
    for (input, expected) in OK_CASES {
        let map = parse::proxy_server(input);
        assert_eq!(
            map.len(),
            expected.len(),
            "entry count for {input:?}: {map:?}"
        );
        for (scheme, rendered) in *expected {
            let entry = map
                .get(scheme)
                .unwrap_or_else(|| panic!("{input:?} is missing an entry for {scheme}"));
            assert_eq!(&render(entry), rendered, "entry for {scheme} of {input:?}");
        }
    }
}

#[test]
fn drops_a_malformed_proxy_server_value_instead_of_failing() {
    for input in DROPPED_CASES {
        assert!(
            parse::proxy_server(input).is_empty(),
            "{input:?} should have parsed to no entries"
        );
    }
}

/// One bad token in an otherwise valid `ProxyServer` value must not take
/// the other, well formed schemes down with it (mirrors how a bare `gopher=` scheme key
/// is already skipped, just for a token whose *scheme* is recognised but whose address
/// is not).
#[test]
fn rejects_only_the_malformed_token_and_keeps_the_rest() {
    for bad in DROPPED_CASES {
        // Skip cases that already contain a `key=` of their own (`"http=:8080"`):
        // nesting one inside `https={bad}` changes what is being tested — the outer
        // `=` splitting sees a *different* token boundary — rather than exercising a
        // malformed https address, which is the point of this test.
        if bad.contains('=') {
            continue;
        }
        let spec = format!("http=h1:8080;https={bad};ftp=h3:21");
        let map = parse::proxy_server(&spec);
        assert_eq!(
            map.get(&Scheme::Http).map(render).as_deref(),
            Some("h1:8080"),
            "http survives alongside bad https={bad:?}"
        );
        assert_eq!(
            map.get(&Scheme::Ftp).map(render).as_deref(),
            Some("h3:21"),
            "ftp survives alongside bad https={bad:?}"
        );
        assert!(
            !map.contains_key(&Scheme::Https),
            "the malformed https token itself must not produce an entry ({bad:?})"
        );
    }
}

#[test]
fn keeps_the_scheme_hint_of_url_shaped_values() {
    let map = parse::proxy_server("socks5://h");
    let endpoint = map[&Scheme::All].endpoint().unwrap();
    assert_eq!(endpoint.scheme_hint, Some(ProxyScheme::Socks5));
    // The scheme's default port beats the Windows default of 80.
    assert_eq!(endpoint.port, 1080);
}

/// `socks` means one thing as a URI scheme and another as a `ProxyServer` bucket key, and
/// the reference says so in as many words: "here 'socks' is understood to be SOCKS4, even
/// though 'socks' maps to SOCKS5 in ProxyServer::GetSchemeFromURIInternal"
/// (`proxy_config.cc`). Both readings live in this crate, so both are pinned here — the
/// bug this replaces read the URI scheme with the bucket key's meaning.
#[test]
fn socks_as_a_uri_scheme_is_socks5_but_as_a_bucket_key_is_socks4() {
    let uri = parse::proxy_server("socks://h")[&Scheme::All]
        .endpoint()
        .unwrap()
        .scheme_hint;
    assert_eq!(uri, Some(ProxyScheme::Socks5));

    let key = parse::proxy_server("socks=h")[&Scheme::Socks]
        .endpoint()
        .unwrap()
        .scheme_hint;
    assert_eq!(key, Some(ProxyScheme::Socks4));

    // A `socks4://` URI still says SOCKS4: the split is about the bare word, not about
    // SOCKS versions being unreachable from a URL.
    let explicit = parse::proxy_server("socks4://h")[&Scheme::All]
        .endpoint()
        .unwrap()
        .scheme_hint;
    assert_eq!(explicit, Some(ProxyScheme::Socks4));
}

/// `socks=` alone used to leave HTTP (and HTTPS, and FTP) going direct, because it was
/// stored as an ordinary per-scheme entry nothing else ever looked at. It must instead
/// act as the catch-all Chromium's `proxy_config.cc` documents it as.
///
/// `Scheme::All` is deliberately one of the filled slots. The opposite pin — "socks=
/// alone must not manufacture a Scheme::All entry" — would be incidental rather than a
/// decision: enumerating `http`/`https`/`ftp` and stopping there records no reason for
/// stopping there. It is the wrong place to stop, because `resolve` sends every
/// *unmodelled* scheme to `Scheme::All`, so leaving that slot empty sent `gopher://`
/// direct while `http://` went through SOCKS. Chromium's `MapUrlSchemeToProxyList`
/// reaches `fallback_proxies` for exactly those schemes — `apply_socks_catch_all` in
/// `src/parse.rs` names the four slots and why `Scheme::All` is one of them. The same
/// hole and the same fix apply to macOS' `SOCKSEnable`.
#[test]
fn socks_alone_becomes_the_catch_all_for_every_other_scheme() {
    let map = parse::proxy_server("socks=127.0.0.1:1080");
    for scheme in [
        Scheme::Http,
        Scheme::Https,
        Scheme::Ftp,
        Scheme::Socks,
        Scheme::All,
    ] {
        assert_eq!(
            map.get(&scheme).map(render).as_deref(),
            Some("127.0.0.1:1080"),
            "entry for {scheme}"
        );
        // Chromium: a scheme-less `socks=` value is read as SOCKS4, not SOCKS5 or HTTP.
        assert_eq!(
            map[&scheme].endpoint().unwrap().scheme_hint,
            Some(ProxyScheme::Socks4),
            "scheme hint for {scheme}"
        );
    }
}

/// The rule that a concrete scheme always wins must survive the new `socks=` fallback: an
/// explicit `http=` is left alone, while the schemes that were never mentioned still
/// pick up the `socks=` catch-all.
#[test]
fn an_explicit_scheme_entry_still_wins_over_the_socks_catch_all() {
    let map = parse::proxy_server("http=h1:8080;socks=127.0.0.1:1080");
    assert_eq!(
        map.get(&Scheme::Http).map(render).as_deref(),
        Some("h1:8080")
    );
    assert_eq!(
        map.get(&Scheme::Https).map(render).as_deref(),
        Some("127.0.0.1:1080")
    );
    assert_eq!(
        map.get(&Scheme::Ftp).map(render).as_deref(),
        Some("127.0.0.1:1080")
    );
}

/// The coexistence rule for the two kinds of catch-all a `ProxyServer` value can carry:
/// a bare, scheme-less token already means "every scheme, no exceptions", which
/// subsumes `socks=`'s narrower "whatever nothing else claims" — so the bare token wins
/// outright rather than the two merging entry by entry. `socks=` itself is untouched
/// (a `socks5://` request still gets it directly, since that concrete scheme still
/// wins).
#[test]
fn a_bare_catch_all_wins_over_the_socks_catch_all_when_both_are_present() {
    let map = parse::proxy_server("bare:9000;socks=127.0.0.1:1080");
    assert_eq!(
        map.get(&Scheme::All).map(render).as_deref(),
        Some("bare:9000")
    );
    assert!(
        !map.contains_key(&Scheme::Http),
        "the socks= fallback must not fire once Scheme::All is present"
    );
    assert!(!map.contains_key(&Scheme::Https));
    assert!(!map.contains_key(&Scheme::Ftp));
    assert_eq!(
        map.get(&Scheme::Socks).map(render).as_deref(),
        Some("127.0.0.1:1080")
    );
}

/// An explicit `scheme://` prefix inside the `socks=` value is always honoured as-is —
/// only a bare, scheme-less value falls back to the SOCKS4 default.
#[test]
fn an_explicit_scheme_inside_socks_is_not_overridden_to_socks4() {
    let map = parse::proxy_server("socks=socks5://h");
    let endpoint = map[&Scheme::Socks].endpoint().unwrap();
    assert_eq!(endpoint.scheme_hint, Some(ProxyScheme::Socks5));
    assert_eq!(endpoint.port, 1080);
}

/// An explicitly disabled `socks=` (empty value) is not a catch-all: it contributes
/// nothing, the same as `socks=` never having been written at all.
#[test]
fn a_disabled_socks_entry_is_not_a_catch_all() {
    let map = parse::proxy_server("socks=;http=h:80");
    assert!(map[&Scheme::Socks].is_disabled());
    assert!(!map.contains_key(&Scheme::Https));
    assert!(!map.contains_key(&Scheme::Ftp));
}

/// `all=` is a key this parser answers to and WinINET does not: `Scheme::from_name`
/// maps it to [`Scheme::All`], so `all=h:8080` reaches the catch-all slot and `all=` empties
/// it — the second of which `ProxyMode::websocket_entry`'s doc used to call unreachable from
/// Windows. The divergence is deliberate (honouring a hand-written `all=` errs toward
/// proxying rather than toward a silent, untraceable `Direct`), so it is pinned here rather
/// than left to be rediscovered as a surprise.
#[test]
fn all_is_accepted_as_a_scheme_key_even_though_windows_has_no_such_key() {
    let map = parse::proxy_server("all=h:8080");
    assert_eq!(map.get(&Scheme::All).map(render).as_deref(), Some("h:8080"));

    // The empty form reaches `Scheme::All` as `Disabled`, and — like any present
    // `Scheme::All` — suppresses the `socks=` fill.
    let map = parse::proxy_server("all=;socks=s:1080");
    assert!(map[&Scheme::All].is_disabled());
    assert!(
        !map.contains_key(&Scheme::Http),
        "a present Scheme::All suppresses the socks= fill whether or not it is disabled"
    );
}

/// Naming `all` is not by itself what suppresses the `socks=` fill — reaching the map is.
/// An `all=` whose address cannot be parsed leaves a `rejected` record and no entry, so
/// the catch-all fills the slot from `socks=` exactly as if `all=` had never been written.
/// That is the module's fail-open-with-a-record rule rather than an exception to it, but
/// it is the one shape where a user who *did* write `all=` still gets SOCKS everywhere, so
/// it is pinned here.
#[test]
fn an_all_entry_that_failed_to_parse_does_not_suppress_the_socks_fill() {
    let mode = parse::windows_manual("all=h:99999;socks=s:1080", "");
    assert_eq!(
        mode.entry_for(Scheme::All).map(render).as_deref(),
        Some("s:1080"),
        "the unparseable all= left no entry, so socks= filled the slot"
    );
    assert_eq!(rejected_texts(mode.rejected().unwrap()), ["all=h:99999"]);
}

/// The SOCKS4 default port (1080), not [`parse::WINDOWS_DEFAULT_PORT`] (80), applies
/// when `socks=` omits a port and gives no `scheme://` of its own.
#[test]
fn socks_without_a_port_defaults_to_1080_not_the_windows_default() {
    let map = parse::proxy_server("socks=127.0.0.1");
    assert_eq!(map[&Scheme::Socks].endpoint().unwrap().port, 1080);
}

/// Security regression test: `ProxyEndpoint::parse` cuts the authority off at the
/// first `/`/`?`/`#` *before* it ever looks for `@` (deliberately unchanged — this cutting
/// order is what has to leave a bare `#note@2` fragment alone). A password
/// containing `/` therefore strands the `@`: `"bob:secr3t"` is all that is left to split
/// into host/port, so `"secr3t"` reaches the port parser looking like one. This used to
/// come back out in the error's `reason` verbatim — this crate's own `SafeError`
/// (`src/trace.rs`), which is the only thing a default `tracing` `WARN` line prints an
/// `Error` through, renders `reason` in full on the assumption that it is already safe.
/// `input` was already masked before this fix (`Error::proxy_server`); this asserts
/// `reason` no longer needs luck to stay clean either, across every rendering path a
/// caller might use.
#[test]
fn a_slash_in_the_password_does_not_leak_it_via_display_debug_or_reason() {
    const SECRET: &str = "secr3t";
    let input = format!("http://bob:{SECRET}/x@proxy.example:8080");
    let error = ProxyEndpoint::parse(&input, 80)
        .expect_err("the '/' strands the '@', so this must fail rather than silently misparse");

    let display = error.to_string();
    let debug = format!("{error:?}");
    assert!(!display.contains(SECRET), "{display}");
    assert!(!debug.contains(SECRET), "{debug}");
    // Not vacuous: the surrounding address is still visible.
    assert!(display.contains("proxy.example"), "{display}");
    assert!(debug.contains("proxy.example"), "{debug}");

    match &error {
        Error::InvalidProxyServer { input, reason } => {
            assert!(!input.contains(SECRET), "input: {input}");
            assert!(!reason.contains(SECRET), "reason: {reason}");
        }
        other => panic!("expected InvalidProxyServer, got {other:?}"),
    }
}

/// The cut above is spelled with three characters, and this test is what holds the other two.
/// A `?` and a `#` are there for the same reason as the `/` and reach the same place: both end
/// an authority, so an `@` behind either is inside a query or a fragment and not a userinfo
/// delimiter. Narrow the cut to `/` alone and the rest of the tree stays green while the two
/// inputs below parse — to `proxy.example:8080`, a destination the writer never named, reached
/// because a `?` or a `#` came first. What the writer did name is a password, which is why
/// these fail rather than resolve.
#[test]
fn a_query_or_a_fragment_ends_the_authority_just_as_a_slash_does() {
    const SECRET: &str = "secr3t";
    for input in [
        format!("http://bob:{SECRET}?x@proxy.example:8080"),
        format!("http://bob:{SECRET}#x@proxy.example:8080"),
    ] {
        match ProxyEndpoint::parse(&input, 80) {
            Err(error) => assert!(!format!("{error:?}").contains(SECRET), "{error:?}"),
            Ok(endpoint) => panic!("{input} resolved to {}", endpoint.authority()),
        }
    }
}

/// Security regression test: a value that reached this crate through a lossy conversion
/// carries U+FFFD where bytes it could not decode used to be, and four readers convert that
/// way *because* the mangled value is then refused here rather than reading as unset. Only
/// the host half ever made that true — `parse_host` refuses the character, `parse_userinfo`
/// cannot fail — so the credential row below used to parse clean, and the crate offered the
/// proxy a secret nobody set: an authentication failure with no record naming the value that
/// changed, and one `ProxyAuth`'s `Debug` masks out of any snapshot.
///
/// The last row is the limit of the rule. A path or query is dropped whole, so mangling
/// there changes nothing the answer is built from and refusing would cost a usable endpoint.
#[test]
fn a_replacement_character_is_refused_across_the_whole_authority() {
    for input in [
        // New: the half `parse_userinfo` cannot refuse.
        "http://alice:hun\u{FFFD}ter2@proxy.example:8080",
        // Already refused, by `parse_host` — here so the two halves are held together.
        "http://pro\u{FFFD}xy.example:8080",
    ] {
        let error = ProxyEndpoint::parse(input, 80)
            .expect_err("a value the reader had to invent is not one to send traffic with");
        assert!(
            matches!(&error, Error::InvalidProxyServer { .. }),
            "{input}: {error:?}"
        );
    }

    assert_eq!(
        ProxyEndpoint::parse("http://proxy.example:8080/pa\u{FFFD}th?q=\u{FFFD}", 80)
            .expect("the authority is intact")
            .authority(),
        "proxy.example:8080"
    );
}

/// RFC 3986 section 3.2.1 puts the password after the *first* colon, so a password may
/// contain one and a user name may not. Splitting at the last colon instead left the tree
/// green, and handed the caller `alice:pa` as a user name and `ss` as a password — neither
/// of which was written anywhere, and both wrong in a way that only shows as an
/// authentication failure at the proxy. `url`, this crate's own dependency, splits the same
/// way.
#[test]
fn a_password_may_hold_a_colon_and_the_user_name_may_not() {
    let endpoint = ProxyEndpoint::parse("http://alice:pa:ss@proxy.example:8080", 80).unwrap();
    let auth = endpoint
        .auth
        .as_ref()
        .expect("the userinfo carries credentials");
    assert_eq!(auth.username(), "alice");
    assert_eq!(auth.password(), Some("pa:ss"));
}

/// RFC 3986 section 3.1: "scheme names are case-insensitive". Dropping the case fold left
/// the tree green — every other test writes its scheme in lowercase — and turned a
/// capitalised prefix into [`Error::UnsupportedProxyScheme`], which is the error for a
/// scheme this crate does not model rather than for one it does.
#[test]
fn a_scheme_written_in_capitals_is_the_same_scheme() {
    let endpoint = ProxyEndpoint::parse("SOCKS5://proxy.example", 80).unwrap();
    assert_eq!(endpoint.scheme_hint, Some(ProxyScheme::Socks5));
    assert_eq!(endpoint.port, 1080);
}

/// `split_scheme_key` reads an `=` as a key separator only when it comes before the first
/// `:` or `/`, and the two do not share the work evenly. The `:` covers both cases the
/// function's doc names — a password holding an `=`, and the query of a URL, which always
/// has a colon in front of its path because it names a scheme or a port. What the `/` covers
/// alone is a token with no colon anywhere. Drop it and the rest of the tree stays green
/// while `proxy.corp/path?a=b` stops being an address: it is recorded as an unknown scheme
/// key named `proxy.corp/path?a`, which is the drop for a token that named a scheme.
#[test]
fn a_path_before_any_colon_is_not_a_scheme_key() {
    let map = parse::proxy_server("proxy.corp/path?a=b");
    assert_eq!(
        map[&Scheme::All].endpoint().unwrap().authority(),
        "proxy.corp:80"
    );
}

/// The `/` in the token above is not what makes it an address, and it used to be the only one
/// of the three authority delimiters the boundary knew. `ProxyEndpoint::parse` cuts the
/// authority at `/`, `?` and `#` alike, so all three of these reach it as the same host — but
/// `split_scheme_key` claimed the token first, splitting `proxy.corp?a=b` into an unknown
/// scheme key named `proxy.corp?a`. The token was then dropped whole and the map came back
/// empty: fail-open Direct for a registry value that names a proxy, the outcome the recorded
/// drop exists to keep from being silent, and here it names a scheme the token never had.
#[test]
fn a_query_or_fragment_before_any_colon_is_not_a_scheme_key_either() {
    for token in ["proxy.corp?a=b", "proxy.corp#a=b"] {
        let map = parse::proxy_server(token);
        assert_eq!(
            map[&Scheme::All].endpoint().unwrap().authority(),
            "proxy.corp:80",
            "{token}"
        );
    }
}

/// The comma is the one character where the server list and a bypass list disagree, and
/// `WINDOWS_SERVER_SEPARATORS` carries a paragraph explaining why: `WINHTTP_PROXY_INFO` gives
/// the server list "one or more of the following strings separated by semicolons or
/// whitespace", while `no_proxy` takes a comma because Go's `httpproxy` splits on that alone.
/// `both_separators_are_accepted` holds the bypass half. This is the other one, and adding `,`
/// to the server separators passed every other test in the crate — nothing else hands this
/// parser a comma.
///
/// It is not a harmless widening. Split on the comma, `http=a,b:80` stops being one token that
/// keeps the comma inside a host name and becomes two that both parse, so a registry value
/// nobody configured a proxy with starts sending http to `a:80` and everything else to `b:80`.
#[test]
fn a_comma_separates_a_bypass_list_and_not_a_server_list() {
    let map = parse::proxy_server("http=a,b:80");
    assert_eq!(map[&Scheme::Http].endpoint().unwrap().authority(), "a,b:80");
    assert!(!map.contains_key(&Scheme::All), "{map:?}");
}

/// The trim here is for callers outside the crate, and this test is the only thing that can
/// hold it: the one call site inside is `parse::proxy_server`, which cannot reach it, because
/// whitespace separates `ProxyServer` tokens before a key is ever cut out of one — `http =
/// h:8080` arrives as three tokens and never as a spaced key. So dropping the trim left the
/// whole tree green while changing what a published function answers. A caller who splits a
/// registry string on `;` alone, without trimming, hands over exactly ` http`, and the
/// function is documented to read the key in `http=proxy:8080` rather than a pre-cleaned one.
#[test]
fn a_scheme_key_is_named_whatever_space_surrounds_it() {
    assert_eq!(Scheme::from_name(" http\t"), Some(Scheme::Http));
    assert_eq!(Scheme::from_name(" HTTPS "), Some(Scheme::Https));
}

#[test]
fn windows_manual_builds_a_mode() {
    let mode = parse::windows_manual("http=h:8080", "<local>");
    assert_eq!(
        mode.endpoint_for(Scheme::Http).unwrap().authority(),
        "h:8080"
    );
    assert!(mode.bypass().unwrap().excludes_simple_hostnames());

    // ProxyEnable=0 is modelled by an empty ProxyServer string.
    assert!(parse::windows_manual("", "<local>").is_direct());
}

/// A dropped `ProxyServer` token is fail-**open** (that scheme
/// silently goes direct), and that fail-open must still leave a trace rather than pass
/// unnoticed, so — unlike [`parse::proxy_server`]'s own return value, which
/// has no room for the record — [`parse::windows_manual`] must not lose it. The well
/// formed tokens survive alongside the dropped one, exactly like a bad bypass-list entry
/// does not take the rest of the list down with it.
#[test]
fn windows_manual_records_a_rejected_token_alongside_the_surviving_ones() {
    let mode = parse::windows_manual("http=h1:8080;https=h2:99999;ftp=h3:21", "");
    assert_eq!(
        mode.endpoint_for(Scheme::Http).unwrap().authority(),
        "h1:8080"
    );
    assert_eq!(mode.endpoint_for(Scheme::Ftp).unwrap().authority(), "h3:21");
    assert!(mode.endpoint_for(Scheme::Https).is_none());
    assert_eq!(rejected_texts(mode.rejected().unwrap()), ["https=h2:99999"]);
}

/// A `ProxyServer` value that is *only* unparseable garbage must still produce a
/// [`ProxyMode::Manual`](proxy_watch::ProxyMode::Manual) carrying the record, rather than
/// collapsing to [`proxy_watch::ProxyStep`]-equivalent `Direct` and silently losing it —
/// the same "have the information, return nothing" trap, the worst failure mode a
/// fail-soft parser can fall into.
#[test]
fn windows_manual_keeps_the_record_even_when_nothing_else_parses() {
    let mode = parse::windows_manual("h:99999", "");
    assert!(!mode.is_direct());
    assert_eq!(rejected_texts(mode.rejected().unwrap()), ["h:99999"]);
}

/// An unrecognised scheme key is the same fail-open as an unparseable value and used to be
/// the one drop with no record at all: `gopher=` (a real WinINet key this crate does not
/// model) or a typo such as `htttp=` left `windows_manual` returning `Direct`, saying
/// nowhere that a proxy had been configured.
#[test]
fn windows_manual_records_an_unrecognised_scheme_key() {
    let mode = parse::windows_manual("http=h1:8080;gopher=h2:70", "");
    assert_eq!(
        mode.endpoint_for(Scheme::Http).unwrap().authority(),
        "h1:8080"
    );
    assert_eq!(rejected_texts(mode.rejected().unwrap()), ["gopher=h2:70"]);
    assert_eq!(
        mode.rejected().unwrap()[0].kind(),
        RejectionKind::UnknownProxyScheme
    );
    assert_eq!(
        mode.rejected().unwrap()[0].source(),
        &RejectionSource::ProxyServer
    );

    let alone = parse::windows_manual("htttp=h:8080", "");
    assert!(!alone.is_direct());
    assert_eq!(rejected_texts(alone.rejected().unwrap()), ["htttp=h:8080"]);
}

/// [`parse::windows_manual`]'s rejected list carries the redacted original text of the
/// token, the same masking [`proxy_watch::BypassRules::rejected`] applies.
#[test]
fn windows_manual_masks_credentials_in_the_rejected_token() {
    let mode = parse::windows_manual("http=alice:hunter2@h:99999", "");
    let rejected = mode.rejected().unwrap();
    assert_eq!(rejected_texts(rejected), ["http=alice:***@h:99999"]);
    assert!(!rejected[0].redacted_input().contains("hunter2"));
}

/// Two [`parse::windows_manual`] modes built from identical registry
/// strings — including identical malformed tokens — must remain equal, so
/// [`proxy_watch::ProxyConfig`]'s duplicate-notification suppression is not defeated by
/// the new `rejected` field.
#[test]
fn windows_manual_is_equal_for_equal_input_including_the_rejected_token() {
    let a = parse::windows_manual("http=h1:8080;https=h2:99999", "<local>");
    let b = parse::windows_manual("http=h1:8080;https=h2:99999", "<local>");
    assert_eq!(a, b);

    let c = parse::windows_manual("http=h1:8080;https=h2:abc", "<local>");
    assert_ne!(a, c, "different rejected text must compare unequal");
}

/// [`ProxyEndpoint`]'s `Display` writes `scheme://` only when the input carried one. That
/// is the whole reason [`ProxyScheme`] is a hint, and it is what makes the `scheme=` key in
/// the tracing summary carry information rather than repeat it — nothing else pinned it.
#[test]
fn display_prefixes_a_scheme_only_when_the_input_named_one() {
    let bare = ProxyEndpoint::parse("proxy.corp:8080", 80).unwrap();
    assert_eq!(bare.to_string(), "proxy.corp:8080");

    let with_scheme = ProxyEndpoint::parse("socks5://proxy.corp:1080", 80).unwrap();
    assert_eq!(with_scheme.to_string(), "socks5://proxy.corp:1080");

    // The registry form this crate reads most is the bare one, so that is not a corner.
    let from_registry = parse::proxy_server("http=proxy.corp:8080");
    let endpoint = from_registry[&Scheme::Http].endpoint().unwrap();
    assert_eq!(endpoint.to_string(), "proxy.corp:8080");

    // A default port that was never written is still rendered — `Display` shows the
    // endpoint as resolved, not as typed.
    let defaulted = ProxyEndpoint::parse("proxy.corp", 80).unwrap();
    assert_eq!(defaulted.to_string(), "proxy.corp:80");

    // Credentials never appear, whichever branch runs.
    for input in ["alice:hunter2@proxy.corp:8080", "http://alice:hunter2@p:1"] {
        let rendered = ProxyEndpoint::parse(input, 80).unwrap().to_string();
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("alice"), "{rendered}");
    }
}

/// A dropped `socks=` is attributed to [`Scheme::All`], because of the schemes its
/// catch-all would have filled. It would not have filled this one: `apply_socks_catch_all`
/// fills with `or_insert_with`, so a readable `socks=` leaves an explicit `http=` off
/// switch exactly where it is. The slot therefore has to survive the attribution — filing
/// the record into the map must not clear it, or a scheme the user switched off answers
/// [`Error::ProxyEntryUnusable`] instead of going direct.
///
/// macOS is the backend where the same two facts come out the other way, and
/// `sys::proxy_dict` clears the slots itself for that reason.
#[test]
fn a_dropped_socks_token_leaves_an_explicit_off_switch_standing() {
    let mode = parse::windows_manual("http=;socks=s:99999", "");
    assert_eq!(
        mode.rejected().unwrap()[0].affected_scheme(),
        Some(Scheme::All)
    );
    assert!(
        matches!(mode.entry_for(Scheme::Http), Some(ProxyEntry::Disabled)),
        "{mode:?}"
    );
}

/// A written-but-empty port is refused, and the test of "written" is a length: `split_host_port`
/// hands an unbracketed IPv6 literal back whole, colons and all, so asking whether the input
/// ends in a colon would read `2001:db8::` as a host that named a port and left it blank.
/// Nothing else pinned that distinction, and the bare form is one this crate accepts on
/// purpose — the backends that read a host out of a settings value get no brackets from the
/// desktop.
#[test]
fn a_bare_ipv6_literal_ending_in_a_colon_is_a_host_not_an_empty_port() {
    let endpoint = ProxyEndpoint::parse("2001:db8::", 8080).unwrap();
    assert_eq!(endpoint.authority(), "[2001:db8::]:8080");

    // The refusal itself still stands, in both spellings that do write a port.
    for input in ["proxy.corp:", "[2001:db8::]:"] {
        let reason = ProxyEndpoint::parse(input, 80).unwrap_err().to_string();
        assert!(reason.contains("empty port after ':'"), "{input}: {reason}");
    }
}

/// Surrounding whitespace is not part of an address. Every backend in this crate trims before
/// it gets here, so the guard exists for the callers outside it — and without it the padding
/// travels into the authority, where `split_host_port` reads `8080 ` as a port and refuses a
/// value that is otherwise perfectly ordinary.
#[test]
fn whitespace_around_an_address_is_not_part_of_it() {
    let padded = ProxyEndpoint::parse("  proxy.corp:8080\t", 80).unwrap();
    assert_eq!(padded.authority(), "proxy.corp:8080");

    // Whitespace alone is an absent address, not a host named by spaces.
    let reason = ProxyEndpoint::parse("   ", 80).unwrap_err().to_string();
    assert!(reason.contains("empty address"), "{reason}");
}
