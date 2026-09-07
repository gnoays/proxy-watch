//! Tests for the core type invariants: secret masking, timestamp-insensitive
//! equality and the scheme resolution rule.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use proxy_watch::{
    BypassRules, Host, ProxyAuth, ProxyConfig, ProxyConfigSource, ProxyEndpoint, ProxyEntry,
    ProxyMode, Scheme, parse,
};

const PASSWORD: &str = "sup3r-s3cret-p4ssw0rd";

#[test]
fn debug_output_never_contains_the_password() {
    let auth = ProxyAuth::new("alice", Some(PASSWORD));
    let endpoint =
        ProxyEndpoint::parse("http://alice:sup3r-s3cret-p4ssw0rd@proxy:8080", 80).unwrap();
    let mut per_scheme = HashMap::new();
    per_scheme.insert(Scheme::Http, ProxyEntry::Use(endpoint.clone()));
    let mode = ProxyMode::manual(per_scheme, BypassRules::new());
    let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode.clone());

    // Every level of nesting must stay clean.
    for rendered in [
        format!("{auth:?}"),
        format!("{endpoint:?}"),
        format!("{mode:?}"),
        format!("{config:?}"),
        format!("{:?}", Some(auth.clone())),
        format!("{config:#?}"),
    ] {
        assert!(
            !rendered.contains(PASSWORD),
            "password leaked into Debug output: {rendered}"
        );
        assert!(rendered.contains("***"), "mask missing from: {rendered}");
    }

    // The user name is not a secret, and the password is still reachable on purpose.
    assert!(format!("{auth:?}").contains("alice"));
    assert_eq!(auth.password(), Some(PASSWORD));
    assert_eq!(endpoint.auth.as_ref().unwrap().password(), Some(PASSWORD));
    // The presence question — the accessor a caller reaches for when it wants that answer
    // without holding the secret to get it. Every other assertion the crate makes about it
    // is a negative one, read off a store that had no password in it, so a body that
    // answered `false` unconditionally keeps the whole tree green while telling every such
    // caller there is nothing to send.
    assert!(auth.has_password());
}

// Percent-encoding a reserved character is how RFC 3986 section 2.2 says "this is data,
// not the delimiter", so `alice%3Ahunter2` is one user name that contains a colon — not a
// user and a password. Pinned against `url`, which this crate already depends on, so the
// rule is anchored to a reference implementation rather than to a reading of the spec.
#[test]
fn a_percent_encoded_colon_in_userinfo_is_not_the_credential_delimiter() {
    let address = format!("http://alice%3A{PASSWORD}@proxy:8080");

    let reference = url::Url::parse(&address).unwrap();
    assert_eq!(reference.username(), format!("alice%3A{PASSWORD}"));
    assert_eq!(reference.password(), None);

    let auth = ProxyEndpoint::parse(&address, 80).unwrap().auth.unwrap();
    assert_eq!(auth.username(), format!("alice:{PASSWORD}"));
    assert_eq!(auth.password(), None);

    // Nothing downstream can tell that colon from a credential delimiter, so `Debug` masks
    // past it regardless. That masking, and not a split, is what keeps the tail unprinted.
    let rendered = format!("{auth:?}");
    assert!(!rendered.contains(PASSWORD), "{rendered}");
    assert!(rendered.contains("alice"), "{rendered}");
    assert!(rendered.contains("***"), "{rendered}");
}

// The other delimiter, and the same question asked of it: with two `@` in the authority,
// which one separates the userinfo from the host? `ProxyEndpoint::parse` takes the *last*,
// and this test is the only thing holding that — taking the first leaves the rest of the
// tree green.
//
// It is not an exotic input. `user@domain.com:password@proxy:8080` is how a corporate proxy
// spells a user name that is an email address, and taking the first `@` reads that as user
// `user` with a host of `domain.com:password@proxy:8080` — which then fails to parse, so the
// setting is dropped and the machine goes direct with a `rejected` record naming a value the
// writer wrote correctly. Pinned against `url` for the same reason as the test above: the
// rule is WHATWG's authority state, not a reading of RFC 3986, which forbids a raw `@` in
// userinfo and so has no opinion on the second one.
#[test]
fn the_last_at_sign_is_the_userinfo_delimiter_so_an_email_user_name_survives() {
    let address = format!("http://alice@corp.example:{PASSWORD}@proxy:8080");

    let reference = url::Url::parse(&address).unwrap();
    assert_eq!(reference.host_str(), Some("proxy"));
    assert_eq!(reference.username(), "alice%40corp.example");
    assert_eq!(reference.password(), Some(PASSWORD));

    let endpoint = ProxyEndpoint::parse(&address, 80).unwrap();
    assert_eq!(endpoint.authority(), "proxy:8080");
    let auth = endpoint.auth.unwrap();
    // Decoded rather than `%40`-encoded, unlike `url` above: this is what gets sent in a
    // `Proxy-Authorization` header, not what gets written back into a URL.
    assert_eq!(auth.username(), "alice@corp.example");
    assert_eq!(auth.password(), Some(PASSWORD));
}

#[test]
fn display_of_an_endpoint_never_contains_credentials() {
    let endpoint =
        ProxyEndpoint::parse("http://alice:sup3r-s3cret-p4ssw0rd@proxy:8080", 80).unwrap();
    let rendered = endpoint.to_string();
    assert_eq!(rendered, "http://proxy:8080");
    assert!(!rendered.contains(PASSWORD));
    assert!(!rendered.contains("alice"));
}

#[test]
fn proxy_config_equality_ignores_captured_at() {
    let mode = parse::windows_manual("http=h:8080", "<local>");
    let a = ProxyConfig::from_source(ProxyConfigSource::Registry, mode.clone());
    let mut b = a.clone();
    b.captured_at = SystemTime::UNIX_EPOCH;
    assert_ne!(a.captured_at, b.captured_at);
    assert_eq!(a, b);

    let mut c = a.clone();
    c.captured_at = a.captured_at + Duration::from_secs(3600);
    assert_eq!(a, c);

    // A real difference is still detected — this is what drives the watcher's
    // duplicate suppression.
    let other = ProxyConfig::from_source(ProxyConfigSource::Registry, ProxyMode::Direct);
    assert_ne!(a, other);

    // So is a difference that only shows up in the provenance list.
    let same_effective =
        ProxyConfig::from_source(ProxyConfigSource::GroupPolicy, a.effective.clone());
    assert_eq!(same_effective.effective, a.effective);
    assert_ne!(same_effective, a);

    // And so is the mirror of it: the resolved mode is the field callers route by, and
    // both `ProxyConfig::new` and the public field let one be stated that the provenance
    // list does not derive. Ignore it and a watcher suppressing duplicates by equality
    // never delivers the change.
    let mut rerouted = a.clone();
    rerouted.effective = ProxyMode::Direct;
    assert_eq!(rerouted.sources, a.sources);
    assert_ne!(rerouted, a);
}

#[test]
fn concrete_scheme_beats_the_catch_all_entry() {
    let mode = parse::windows_manual("http=specific:1;proxy-for-everything:2", "");
    assert_eq!(
        mode.endpoint_for(Scheme::Http).unwrap().authority(),
        "specific:1"
    );
    assert_eq!(
        mode.endpoint_for(Scheme::Https).unwrap().authority(),
        "proxy-for-everything:2"
    );
    assert_eq!(
        mode.endpoint_for(Scheme::All).unwrap().authority(),
        "proxy-for-everything:2"
    );
}

#[test]
fn disabled_entry_suppresses_the_catch_all_fallback() {
    let mode = parse::windows_manual("http=;everything:2", "");
    assert_eq!(mode.entry_for(Scheme::Http), Some(&ProxyEntry::Disabled));
    assert!(mode.endpoint_for(Scheme::Http).is_none());
    // Other schemes still fall back.
    assert_eq!(
        mode.endpoint_for(Scheme::Ftp).unwrap().authority(),
        "everything:2"
    );
}

#[test]
fn non_manual_modes_resolve_to_nothing() {
    for mode in [
        ProxyMode::Direct,
        ProxyMode::pac("http://wpad.corp/proxy.pac".parse().unwrap()),
        ProxyMode::pac_inline("function FindProxyForURL(u, h) { return 'DIRECT'; }".to_owned()),
        ProxyMode::WpadAutoDetect,
    ] {
        for scheme in Scheme::ALL {
            assert!(mode.endpoint_for(scheme).is_none(), "{mode:?} / {scheme}");
        }
        assert!(mode.bypass().is_none());
    }
}

#[test]
fn ipv6_brackets_are_resolved_at_parse_time() {
    let endpoint = ProxyEndpoint::parse("[2001:db8::1]:8080", 80).unwrap();
    assert!(matches!(endpoint.host, Host::Ipv6(_)));
    assert_eq!(endpoint.authority(), "[2001:db8::1]:8080");
}

#[test]
fn default_values_are_the_conservative_ones() {
    assert!(ProxyMode::default().is_direct());
    assert!(ProxyConfig::default().effective.is_direct());
    assert!(ProxyConfig::default().sources.is_empty());

    let rules = BypassRules::default();
    assert!(rules.is_empty());
    assert!(rules.bypass_loopback());
    assert!(!rules.excludes_simple_hostnames());
}

#[test]
fn config_sources_are_queryable() {
    let registry = parse::windows_manual("h:1", "");
    let policy = parse::windows_manual("h:2", "");
    let config = ProxyConfig::new(
        policy.clone(),
        vec![
            (ProxyConfigSource::GroupPolicy, policy.clone()),
            (ProxyConfigSource::Registry, registry.clone()),
        ],
    );
    assert_eq!(config.effective, policy);
    assert_eq!(config.source(ProxyConfigSource::Registry), Some(&registry));
    assert_eq!(config.source(ProxyConfigSource::Env), None);
}

/// Every scheme name this crate writes is one it reads back as the same scheme. Two pairs
/// carry that promise, and this test is the only thing holding either: [`Scheme::as_str`] / [`Scheme::from_name`]
/// (the `http=`/`socks=` bucket keys of the Windows `ProxyServer` grammar), and
/// `ProxyScheme::as_str` / its `FromStr` (the URL scheme [`ProxyEndpoint`]'s `Display`
/// writes and [`ProxyEndpoint::parse`] reads).
///
/// Neither gap is assumed. Spelling `Scheme::Socks` as `"socks5"` — a
/// name `from_name` rejects — leaves the whole tree green, and so does spelling
/// `ProxyScheme::Socks4` as `"socks-4"`, which makes `ProxyEndpoint`'s `Display` emit a
/// string its own `parse` refuses. The nearest existing test,
/// `proxy_server.rs::display_prefixes_a_scheme_only_when_the_input_named_one`, pins
/// `socks5` as a literal and says nothing about the other eight names.
///
/// The rendered form is what a caller logs, pastes back into a `ProxyServer` value, or
/// hands to a client, so a name that does not read back loses a scheme silently:
/// `from_name` answering `None` drops the bucket, and `ProxyScheme`'s `FromStr` turns the
/// whole endpoint into an error.
#[test]
fn every_scheme_name_reads_back_as_the_scheme_that_wrote_it() {
    let mut bucket_keys = Vec::new();
    for scheme in Scheme::ALL {
        let name = scheme.as_str();
        assert_eq!(Scheme::from_name(name), Some(scheme), "{name:?}");
        // `from_name` is only ever reached through a `key=value` bucket, so the round trip
        // that matters is the one through the grammar, not the one through the accessor.
        let map = parse::proxy_server(&format!("{name}=proxy.corp:8080"));
        assert!(
            map.contains_key(&scheme),
            "{name}= did not land in {scheme:?}"
        );
        bucket_keys.push(name);
    }
    // Coverage on purpose rather than by accident: a variant added to `Scheme::ALL` without
    // a name would otherwise widen this test in silence.
    assert_eq!(bucket_keys, ["http", "https", "ftp", "socks", "all"]);

    // `ProxyScheme` has no `ALL`, so the list is written out and checked for completeness
    // below. `socks` is deliberately absent: `FromStr` accepts it, but no `as_str` writes
    // it, and this test walks the writing direction.
    const URL_SCHEMES: &[&str] = &["http", "https", "socks4", "socks4a", "socks5", "socks5h"];
    let mut kinds = Vec::new();
    for name in URL_SCHEMES {
        let endpoint = ProxyEndpoint::parse(&format!("{name}://proxy.corp:8080"), 80).unwrap();
        let hint = endpoint.scheme_hint.expect("the input named a scheme");
        assert_eq!(hint.as_str(), *name, "{name} did not survive parse");
        // `Display` writes the hint back out; `parse` must recover the same endpoint from it.
        let shown = endpoint.to_string();
        assert_eq!(shown, format!("{name}://proxy.corp:8080"));
        assert_eq!(
            ProxyEndpoint::parse(&shown, 80).unwrap(),
            endpoint,
            "{shown}"
        );
        kinds.push(format!("{hint:?}"));
    }
    assert_eq!(
        kinds,
        ["Http", "Https", "Socks4", "Socks4a", "Socks5", "Socks5h"]
    );
}
