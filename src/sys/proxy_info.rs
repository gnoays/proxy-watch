//! Android's `ProxyInfo`, reduced to a pure Rust value.
//!
//! `ConnectivityManager.getDefaultProxy()` answers with a `ProxyInfo` or `null`, and the
//! framework's `Proxy.setHttpProxyConfiguration` turns that into the `http.*` / `https.*`
//! system properties `java.net.ProxySelector.getDefault()` routes by.
//! [`mode_from_proxy_info`] reads host, port, exclusion list and PAC URL the way that
//! selector does, so the whole mapping is a total function of its input and runs under
//! `cfg(test)` on every target.
//!
//! * A PAC URL wins over the host: with one set, `ProxyInfo`'s host is the `localhost` port
//!   of the framework's own PAC service, not a proxy anyone configured.
//! * The host serves `http` and `https`, nothing else; `ftp` and `socks` are never set.
//!   Port 0 is each scheme's default (80 and 443), and any other port outside `1..=65535`
//!   makes the selector throw, so both schemes are recorded as unusable.
//! * The exclusion list is matched against the lower-cased destination host: `*x` is any
//!   host ending in `x`, `x*` any host starting with it, anything else the host itself. Loopback
//!   is bypassed only through `localhost|127.*|[::1]|0.0.0.0|[::0]`, which the selector adds
//!   to a non-empty list; an empty list bypasses nothing, `localhost` included, and no list
//!   ever bypasses link-local.

use std::collections::HashMap;

use url::Url;

use crate::bypass::{BypassDialect, BypassRules, HostPattern};
use crate::diagnostic::{RejectedValue, RejectionKind, RejectionSource};
use crate::endpoint::{ProxyEndpoint, ProxyEntry, Scheme, parse_host};
use crate::error::Error;
use crate::mode::ProxyMode;
#[cfg(feature = "pac-android-native")]
use crate::resolve::ProxyStep;

/// The exclusions `DefaultProxySelector` appends to every non-empty list.
const DEFAULT_EXCLUSIONS: [&str; 5] = ["localhost", "127.*", "[::1]", "0.0.0.0", "[::0]"];

/// The fields of one `ProxyInfo`, as its getters return them.
pub(crate) struct ProxyInfo {
    pub(crate) host: Option<String>,
    pub(crate) port: i32,
    pub(crate) exclusions: Vec<String>,
    /// `getPacFileUrl().toString()`; `Uri.EMPTY` arrives as the empty string.
    pub(crate) pac_url: Option<String>,
}

/// Map `getDefaultProxy()`'s answer, `None` for `null`, onto a [`ProxyMode`].
pub(crate) fn mode_from_proxy_info(info: Option<&ProxyInfo>) -> Result<ProxyMode, Error> {
    let Some(info) = info else {
        return Ok(ProxyMode::Direct);
    };
    if let Some(url) = info.pac_url.as_deref().filter(|url| !url.is_empty()) {
        let parsed = Url::parse(url).map_err(|source| Error::invalid_proxy_url(url, source))?;
        return Ok(ProxyMode::pac(parsed));
    }
    let Some(host) = info.host.as_deref().filter(|host| !host.is_empty()) else {
        return Ok(ProxyMode::Direct);
    };

    let mut per_scheme = HashMap::new();
    let mut rejected = Vec::new();
    for (scheme, default_port) in [(Scheme::Http, 80), (Scheme::Https, 443)] {
        match endpoint(host, info.port, default_port) {
            Ok(endpoint) => {
                per_scheme.insert(scheme, ProxyEntry::Use(endpoint));
            }
            Err((field, input)) => rejected.push(
                RejectedValue::new(
                    RejectionKind::InvalidProxyEndpoint,
                    RejectionSource::ProxyInfo(field.to_owned()),
                    input,
                )
                .for_scheme(Some(scheme)),
            ),
        }
    }
    Ok(ProxyMode::manual(per_scheme, bypass(&info.exclusions)).with_rejected(rejected))
}

// The field that failed and its text, for the rejection record.
fn endpoint(host: &str, port: i32, default_port: u16) -> Result<ProxyEndpoint, (&str, String)> {
    let port = match port {
        0 => default_port,
        port => u16::try_from(port).map_err(|_| ("port", port.to_string()))?,
    };
    let host = parse_host(host).map_err(|_| ("host", host.to_owned()))?;
    Ok(ProxyEndpoint::new(host, port))
}

fn bypass(exclusions: &[String]) -> BypassRules {
    let mut rules = BypassRules::new();
    rules.push_pattern(HostPattern::SubtractImplicit);
    // The selector compares the host string, so `localhost.` misses a `localhost` entry
    // and `[::ffff:10.0.0.1]` misses a `10.0.0.1` one.
    rules.strip_trailing_dot = false;
    rules.ipv4_mapped_as_ipv4 = false;
    // The framework hands the selector the list joined with `,`, and `"".split(",")` in
    // `ProxyInfo` yields `[""]`: the selector sees an empty string and adds no defaults.
    let defaults = if exclusions.join(",").is_empty() {
        &[][..]
    } else {
        &DEFAULT_EXCLUSIONS[..]
    };
    // The same join feeds the selector, which then turns each `,` into `|` and splits on
    // `|`, so an element holding either is several hosts there. Split it the same way here,
    // or `a.example,b.example` becomes one rule no host matches. An empty piece needs no
    // filter: it parses to no rule, as the empty alternative there matches no host.
    let entries = exclusions
        .iter()
        .flat_map(|element| element.split([',', '|']))
        .chain(defaults.iter().copied());
    for entry in entries {
        let source = || RejectionSource::ProxyInfo("exclusionList".to_owned());
        if matches_no_host(entry) {
            rules.rejected.push(RejectedValue::new(
                RejectionKind::InvalidBypassPattern,
                source(),
                entry,
            ));
        } else {
            // Limitation: the rule compares host values where the selector compares strings,
            // so `127.000.000.001` or `LOCALHOST` meet a rule here that they miss there.
            // Exact only if the destination is spelled the way the selector sees it.
            rules.push_entry_from(entry, BypassDialect::Windows, source());
        }
    }
    rules.dedup_patterns();
    rules
}

// The selector reads a `*` only at one end and a `:` nowhere outside an address in
// brackets, so an entry with either anywhere else is a literal no host can equal. The
// Windows dialect would read `*a*` as a glob and `host:80` as a port restriction, a live
// rule the selector does not have. A leading `<` is the same: the selector quotes
// `<local>` and `<-loopback>` as literals, where the Windows dialect would read the first
// as "every name without a dot" and bypass hosts the selector sends to the proxy. So is
// whitespace: the selector trims nothing, so ` a.example` equals no host, where the Windows
// dialect trims it into a live rule for `a.example`.
fn matches_no_host(entry: &str) -> bool {
    if entry.starts_with('<') || entry.contains(char::is_whitespace) {
        return true;
    }
    let inner = entry.strip_prefix('*').unwrap_or(entry);
    let inner = if inner.len() == entry.len() {
        inner.strip_suffix('*').unwrap_or(inner)
    } else {
        inner
    };
    let bracketed = entry.starts_with('[') && entry.ends_with(']');
    inner.contains('*') || (entry.contains(':') && !bracketed)
}

/// One `java.net.Proxy` from `ProxySelector.select(uri)`: its `type().name()`, and the
/// `InetSocketAddress` it carries (`null` for `DIRECT`).
#[cfg(feature = "pac-android-native")]
pub(crate) struct SelectedProxy {
    pub(crate) kind: String,
    pub(crate) host: Option<String>,
    pub(crate) port: i32,
}

/// `url` as text `java.net.URI.create` accepts. `Url` leaves `|`, `^`, `[` and `]` raw in
/// a path, and those and `{`, `}`, `` ` `` and `\` raw in a query; `URI` rejects them there,
/// so they are percent-encoded. So is a `%` that does not start an escape (`100%`, `%zz`):
/// `Url` keeps one as written, and `URI` throws on it. The authority keeps an IPv6 host's
/// brackets.
#[cfg(feature = "pac-android-native")]
pub(crate) fn java_uri_text(url: &Url) -> String {
    let (authority, rest) = url
        .as_str()
        .split_at(url[..url::Position::BeforePath].len());
    let mut text = String::with_capacity(url.as_str().len());
    text.push_str(authority);
    for (at, c) in rest.char_indices() {
        let escape = |b: Option<&u8>| b.is_some_and(u8::is_ascii_hexdigit);
        let bytes = rest.as_bytes();
        match c {
            '|' | '^' | '[' | ']' | '{' | '}' | '`' | '\\' => {
                text.push_str(&format!("%{:02X}", u32::from(c)));
            }
            '%' if !(escape(bytes.get(at + 1)) && escape(bytes.get(at + 2))) => {
                text.push_str("%25");
            }
            _ => text.push(c),
        }
    }
    text
}

/// Map `ProxySelector.select`'s list, in order, onto [`ProxyStep`]s.
///
/// `SOCKS` becomes [`ProxyStep::Socks5`]: the `Proxy` does not say which version, and the
/// `java.net` SOCKS client opens with version 5.
#[cfg(feature = "pac-android-native")]
pub(crate) fn steps_from_selected(selected: &[SelectedProxy]) -> Result<Vec<ProxyStep>, Error> {
    if selected.is_empty() {
        return Err(Error::pac_invalid_result(
            "ProxySelector.select returned no proxy",
        ));
    }
    // An element no client could use is skipped and the rest kept, as the in-process and
    // WinHTTP parsers do with a chain; only an answer with nothing usable in it fails.
    let mut steps = Vec::with_capacity(selected.len());
    let mut first_error = None;
    for result in selected.iter().map(|proxy| {
        let endpoint = || {
            let host = proxy.host.as_deref().and_then(|host| parse_host(host).ok());
            let port = u16::try_from(proxy.port).ok().filter(|&port| port != 0);
            match (host, port) {
                (Some(host), Some(port)) => Ok(ProxyEndpoint::new(host, port)),
                _ => Err(Error::pac_invalid_result(format!(
                    "{} {}:{}",
                    proxy.kind,
                    proxy.host.as_deref().unwrap_or("null"),
                    proxy.port
                ))),
            }
        };
        match proxy.kind.as_str() {
            "DIRECT" => Ok(ProxyStep::Direct),
            "HTTP" => endpoint().map(ProxyStep::Http),
            "SOCKS" => endpoint().map(ProxyStep::Socks5),
            other => Err(Error::pac_invalid_result(other)),
        }
    }) {
        match result {
            Ok(step) => steps.push(step),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) if steps.is_empty() => Err(error),
        _ => Ok(steps),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "pac-android-native")]
    #[test]
    fn a_url_is_encoded_where_java_uri_rejects_it() {
        let text = |url: &str| java_uri_text(&Url::parse(url).unwrap());
        assert_eq!(
            text("http://h.corp/a|b^c[d]"),
            "http://h.corp/a%7Cb%5Ec%5Bd%5D"
        );
        assert_eq!(
            text("http://h.corp/?a={b}&c=`d|e^f\\g"),
            "http://h.corp/?a=%7Bb%7D&c=%60d%7Ce%5Ef%5Cg"
        );
        assert_eq!(text("http://[::1]:8080/p%7C?q"), "http://[::1]:8080/p%7C?q");
        // A `%` that starts no escape is one `URI` throws on; an escape is left alone.
        assert_eq!(text("http://h.corp/100%"), "http://h.corp/100%25");
        assert_eq!(text("http://h.corp/%zz?q=%4"), "http://h.corp/%25zz?q=%254");
        assert_eq!(text("http://h.corp/%41%2f"), "http://h.corp/%41%2f");
    }

    #[cfg(feature = "pac-android-native")]
    #[test]
    fn a_selector_answer_maps_in_order_and_rejects_what_no_client_could_use() {
        let proxy = |kind: &str, host: Option<&str>, port| SelectedProxy {
            kind: kind.to_owned(),
            host: host.map(str::to_owned),
            port,
        };
        let endpoint = |host| ProxyEndpoint::new(parse_host(host).unwrap(), 1080);
        assert_eq!(
            steps_from_selected(&[
                proxy("HTTP", Some("proxy.example"), 1080),
                proxy("SOCKS", Some("2001:db8::1"), 1080),
                proxy("DIRECT", None, 0),
            ])
            .unwrap(),
            [
                ProxyStep::Http(endpoint("proxy.example")),
                ProxyStep::Socks5(endpoint("2001:db8::1")),
                ProxyStep::Direct,
            ]
        );
        for bad in [
            vec![],
            vec![proxy("HTTP", None, 1080)],
            vec![proxy("HTTP", Some("proxy.example"), 0)],
            vec![proxy("HTTP", Some("proxy.example"), 65536)],
            vec![proxy("FTP", Some("proxy.example"), 21)],
        ] {
            assert!(matches!(
                steps_from_selected(&bad),
                Err(Error::PacInvalidResult { .. })
            ));
        }
        // An unusable element beside a usable one is skipped, not the whole answer.
        assert_eq!(
            steps_from_selected(&[proxy("HTTP", None, 1080), proxy("DIRECT", None, 0)]).unwrap(),
            [ProxyStep::Direct]
        );
    }

    fn info(host: &str, port: i32, exclusions: &[&str]) -> ProxyInfo {
        ProxyInfo {
            host: Some(host.to_owned()),
            port,
            exclusions: exclusions.iter().map(|&e| e.to_owned()).collect(),
            pac_url: None,
        }
    }

    fn manual(info: &ProxyInfo) -> (HashMap<Scheme, ProxyEntry>, BypassRules) {
        match mode_from_proxy_info(Some(info)).unwrap() {
            ProxyMode::Manual {
                per_scheme, bypass, ..
            } => (per_scheme, bypass),
            other => panic!("expected Manual, got {other:?}"),
        }
    }

    fn bypassed(rules: &BypassRules, host: &str) -> bool {
        rules.matches(&parse_host(host).unwrap(), Some(443))
    }

    #[test]
    fn null_and_hostless_are_direct() {
        assert_eq!(mode_from_proxy_info(None).unwrap(), ProxyMode::Direct);
        assert_eq!(
            mode_from_proxy_info(Some(&info("", 8080, &[]))).unwrap(),
            ProxyMode::Direct
        );
    }

    #[test]
    fn a_pac_url_wins_over_the_local_host_it_comes_with() {
        let mut pac = info("localhost", 34567, &[]);
        pac.pac_url = Some("http://wpad.example/proxy.pac".to_owned());
        assert_eq!(
            mode_from_proxy_info(Some(&pac)).unwrap(),
            ProxyMode::pac(Url::parse("http://wpad.example/proxy.pac").unwrap())
        );
        pac.pac_url = Some(String::new());
        assert!(matches!(
            mode_from_proxy_info(Some(&pac)).unwrap(),
            ProxyMode::Manual { .. }
        ));
        pac.pac_url = Some("not a url".to_owned());
        assert!(matches!(
            mode_from_proxy_info(Some(&pac)),
            Err(Error::InvalidProxyUrl { .. })
        ));
    }

    #[test]
    fn the_host_serves_http_and_https_only_with_port_zero_as_each_default() {
        let (per_scheme, _) = manual(&info("proxy.example", 0, &[]));
        let port_of = |scheme| match &per_scheme[&scheme] {
            ProxyEntry::Use(endpoint) => endpoint.port,
            other => panic!("{other:?}"),
        };
        assert_eq!((port_of(Scheme::Http), port_of(Scheme::Https)), (80, 443));
        assert_eq!(per_scheme.len(), 2);

        let (per_scheme, _) = manual(&info("2001:db8::1", 3128, &[]));
        assert!(matches!(
            &per_scheme[&Scheme::Http],
            ProxyEntry::Use(e) if e.host == parse_host("2001:db8::1").unwrap() && e.port == 3128
        ));
    }

    #[test]
    fn an_out_of_range_port_makes_both_schemes_unusable() {
        let mode = mode_from_proxy_info(Some(&info("proxy.example", -1, &[]))).unwrap();
        let rejected = mode.rejected().unwrap();
        assert_eq!(rejected.len(), 2);
        assert!(rejected.iter().all(|r| r.redacted_input() == "-1"
            && r.source() == &RejectionSource::ProxyInfo("port".to_owned())));
        let ProxyMode::Manual { per_scheme, .. } = mode else {
            unreachable!()
        };
        assert!(matches!(
            per_scheme[&Scheme::Https],
            ProxyEntry::Unusable(_)
        ));
    }

    #[test]
    fn an_empty_list_bypasses_nothing_not_even_localhost() {
        // `[""]` is what `new ProxyInfo(host, port, "")` returns from `getExclusionList()`.
        for list in [&[][..], &[""][..]] {
            let (_, rules) = manual(&info("proxy.example", 8080, list));
            assert!(!bypassed(&rules, "localhost"), "{list:?}");
            assert!(!bypassed(&rules, "127.0.0.1"), "{list:?}");
            assert!(!bypassed(&rules, "169.254.1.1"), "{list:?}");
            assert!(rules.rejected.is_empty(), "{list:?}");
        }
    }
    // The selector compares host strings, so neither a trailing dot nor the IPv4-mapped
    // spelling reaches an entry written without it.
    #[test]
    fn the_selector_compares_the_host_as_written() {
        let (_, rules) = manual(&info("proxy.example", 8080, &["intra.example", "10.0.0.1"]));
        assert!(bypassed(&rules, "intra.example"));
        assert!(!bypassed(&rules, "intra.example."));
        assert!(bypassed(&rules, "localhost"));
        assert!(!bypassed(&rules, "localhost."));
        assert!(bypassed(&rules, "10.0.0.1"));
        assert!(!bypassed(&rules, "[::ffff:10.0.0.1]"));
    }

    #[test]
    fn a_non_empty_list_adds_loopback_but_not_link_local() {
        let (_, rules) = manual(&info("proxy.example", 8080, &["intra.example"]));
        for host in [
            "intra.example",
            "localhost",
            "127.0.0.1",
            "127.9.9.9",
            "[::1]",
            "0.0.0.0",
            "[::]",
        ] {
            assert!(bypassed(&rules, host), "{host}");
        }
        assert!(!bypassed(&rules, "169.254.1.1"));
        assert!(!bypassed(&rules, "a.intra.example"));
        assert!(rules.rejected.is_empty());
    }

    #[test]
    fn a_star_is_read_at_either_end_and_nowhere_else() {
        let (_, rules) = manual(&info(
            "proxy.example",
            8080,
            &[
                "*.corp.example",
                "10.*",
                "a*b.example",
                "*mid*",
                "host.example:443",
            ],
        ));
        assert!(bypassed(&rules, "a.corp.example"));
        assert!(!bypassed(&rules, "corp.example"));
        assert!(bypassed(&rules, "10.1.2.3"));
        let rejected: Vec<_> = rules.rejected.iter().map(|r| r.redacted_input()).collect();
        assert_eq!(rejected, ["a*b.example", "*mid*", "host.example:443"]);
        let (_, every) = manual(&info("proxy.example", 8080, &["*"]));
        assert!(bypassed(&every, "anything.example"));
    }

    #[test]
    fn a_host_no_client_can_use_is_rejected_for_both_schemes() {
        let mode = mode_from_proxy_info(Some(&info("bad host", 8080, &[]))).unwrap();
        let rejected = mode.rejected().unwrap();
        let mut schemes: Vec<_> = rejected.iter().map(|r| r.affected_scheme()).collect();
        schemes.sort_by_key(|scheme| format!("{scheme:?}"));
        assert_eq!(schemes, [Some(Scheme::Http), Some(Scheme::Https)]);
        for r in rejected {
            assert_eq!(r.kind(), RejectionKind::InvalidProxyEndpoint);
            assert_eq!(r.source(), &RejectionSource::ProxyInfo("host".to_owned()));
            assert_eq!(r.redacted_input(), "bad host");
        }
    }

    // Refused by this module's own check or by the Windows dialect's, an entry names the same
    // source, and it is quoted as it came, spaces included.
    #[test]
    fn every_refused_entry_names_the_exclusion_list() {
        let (_, rules) = manual(&info(
            "proxy.example",
            8080,
            &["<local>", ".corp.example", " a.example", "b.example "],
        ));
        assert!(!bypassed(&rules, "a.example"));
        assert!(!bypassed(&rules, "b.example"));
        let rejected: Vec<_> = rules.rejected.iter().map(|r| r.redacted_input()).collect();
        assert_eq!(
            rejected,
            ["<local>", ".corp.example", " a.example", "b.example "]
        );
        for r in &rules.rejected {
            assert_eq!(
                r.source(),
                &RejectionSource::ProxyInfo("exclusionList".to_owned()),
                "{}",
                r.redacted_input()
            );
        }
    }

    #[test]
    fn an_element_holding_a_comma_or_a_bar_is_several_hosts_as_the_selector_reads_it() {
        let (_, rules) = manual(&info(
            "proxy.example",
            8080,
            &["a.example,b.example", "c.example|d.example", ",,"],
        ));
        for host in ["a.example", "b.example", "c.example", "d.example"] {
            assert!(bypassed(&rules, host), "{host}");
        }
        assert!(!bypassed(&rules, "e.example"));
        assert!(rules.rejected.is_empty(), "{:?}", rules.rejected);
    }

    #[test]
    fn a_windows_token_is_a_literal_the_selector_never_matches() {
        let (_, rules) = manual(&info(
            "proxy.example",
            8080,
            &["<local>", "<-loopback>", "*.corp.example"],
        ));
        assert!(!bypassed(&rules, "intranet"));
        assert!(!bypassed(&rules, "corp.example"));
        assert!(bypassed(&rules, "a.corp.example"));
        let rejected: Vec<_> = rules.rejected.iter().map(|r| r.redacted_input()).collect();
        assert_eq!(rejected, ["<local>", "<-loopback>"]);
    }
}
