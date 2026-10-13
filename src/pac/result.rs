//! Parsing what `FindProxyForURL` returns.

use crate::endpoint::{ProxyEndpoint, ProxyScheme};
use crate::error::Error;
use crate::resolve::ProxyStep;
use std::collections::HashSet;

// The most steps a PAC result keeps. The script's heap limit bounds only the string the
// chain is read from, not the chain.
pub(crate) const MAX_CHAIN: usize = 64;

// The chain every PAC engine's answer goes into: this parse, `winhttp.rs` and
// `sys/proxy_info.rs`. Repeats collapse against the whole chain, since a proxy that failed
// is no better the second time; Chromium keeps them. WinHTTP drops everything past the
// first `DIRECT` before its answer gets here.
pub(crate) struct Chain {
    steps: Vec<ProxyStep>,
    seen: HashSet<ProxyStep>,
}

impl Chain {
    pub(crate) fn new() -> Self {
        Self {
            steps: Vec::new(),
            seen: HashSet::new(),
        }
    }

    pub(crate) fn push(&mut self, step: ProxyStep) {
        if !self.is_full() && self.seen.insert(step.clone()) {
            self.steps.push(step);
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.steps.len() == MAX_CHAIN
    }

    // `None` when nothing usable was pushed; each caller builds its own error, and an empty
    // chain never becomes `DIRECT`.
    pub(crate) fn finish(self) -> Option<Vec<ProxyStep>> {
        (!self.steps.is_empty()).then_some(self.steps)
    }
}

/// Parse a `FindProxyForURL` return string into an ordered fallback chain.
///
/// Tokens are separated by `;` or newlines; newline separation is specific to this crate
/// and differs from Chromium. Keywords are case-insensitive: `DIRECT`;
/// `PROXY`/`HTTP`→[`ProxyStep::Http`]; `HTTPS`→HTTPS; `SOCKS`/`SOCKS4`→SOCKS4;
/// `SOCKS5`→[`ProxyScheme::Socks5h`] (remote DNS). An address without a port uses
/// [`ProxyScheme::default_port`] for the keyword's scheme. Addresses must be bare
/// authorities: `/`, `?` or `#`, including in `scheme://`, invalidates the whole candidate.
/// Bad tokens are skipped, repeats collapse, and embedded credentials are dropped. An empty
/// usable chain returns [`Error::PacInvalidResult`]. Words are split at ASCII whitespace
/// only, so a no-break space or a vertical tab stays inside a word and spoils it. An IPv6
/// address without a port can go without brackets (`PROXY ::1`). The chain keeps its first
/// 64 steps and drops the rest, an explicit `DIRECT` among them.
///
/// ```
/// # use proxy_watch::pac::parse_find_proxy_result;
/// let steps = parse_find_proxy_result("PROXY a:1; SOCKS5 b:2; DIRECT")?;
/// assert_eq!(steps.len(), 3);
/// assert_eq!(steps[0].endpoint().unwrap().authority(), "a:1");
/// assert_eq!(steps[1].scheme(), Some("socks5"));
/// assert_eq!(steps[1].to_url().unwrap().as_str(), "socks5h://b:2");
/// assert!(steps[2].is_direct());
/// # Ok::<(), proxy_watch::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::PacInvalidResult`] when no candidate in the string could be understood,
/// including the empty string.
pub fn parse_find_proxy_result(result: &str) -> Result<Vec<ProxyStep>, Error> {
    let mut chain = Chain::new();
    // A newline separates candidates here and not in Chromium, whose
    // `ProxyList::SetFromPacString` splits on `;` alone.
    // Without it a script that separates its candidates by line loses the whole chain:
    // `PROXY a:1\nDIRECT` would be one candidate of three words. This accepts what Chromium
    // rejects, never the reverse.
    for candidate in result.split([';', '\n', '\r']) {
        if let Some(step) = parse_candidate(candidate) {
            chain.push(step);
            if chain.is_full() {
                break;
            }
        }
    }
    // An error, not `DIRECT` as in Chromium's `PacResult::ToProxyList`: a script that said
    // something unreadable has not said "go direct". The caller can still choose `DIRECT`.
    chain
        .finish()
        .ok_or_else(|| Error::pac_invalid_result(result))
}

// One `;`-separated candidate, or `None` when it is not usable.
fn parse_candidate(candidate: &str) -> Option<ProxyStep> {
    // ASCII whitespace only: a Unicode space is a character of the word it sits in.
    let mut words = candidate.split_ascii_whitespace();
    let keyword = words.next()?;
    let address = words.next();
    // `PROXY a:1 b:2` is not a thing; refuse rather than guess.
    if words.next().is_some() {
        return None;
    }

    let scheme = match keyword.to_ascii_uppercase().as_str() {
        "DIRECT" => return address.is_none().then_some(ProxyStep::Direct),
        "PROXY" | "HTTP" => ProxyScheme::Http,
        "HTTPS" => ProxyScheme::Https,
        "SOCKS" | "SOCKS4" => ProxyScheme::Socks4,
        // Chromium's `ProxyServer::SCHEME_SOCKS5` resolves names on the proxy side, which
        // curl spells with the `h` suffix (https://curl.se/docs/url-syntax.html).
        "SOCKS5" => ProxyScheme::Socks5h,
        _ => return None,
    };

    let address = address?;
    // A PAC candidate is a bare authority, so a `/`, `?` or `#` in it (the `/`s of a
    // `scheme://` included) makes the candidate malformed rather than something to trim, as
    // Chromium reads it. `ProxyEndpoint::parse` does trim them, and is right to: the values
    // operating systems *store* are written as URLs. A script's return value is not, and the
    // same trim here would answer with an address the script did not write. For a scheme it
    // would also override the keyword: `PROXY https://p:8443` read as plain HTTP is
    // cleartext to a port that expects TLS. The tests that hold this are
    // `junk_candidates_are_skipped_but_do_not_poison_the_chain` and
    // `a_candidate_that_is_not_a_bare_authority_is_skipped_whole`.
    if address.contains(['/', '?', '#']) {
        return None;
    }
    // A Unicode space left at either end of the address is part of the word, and
    // `ProxyEndpoint::parse` would trim it off: refuse it here, as one inside the word is.
    if address.contains(char::is_whitespace) {
        return None;
    }
    let mut endpoint = ProxyEndpoint::parse(address, scheme.default_port())
        .ok()?
        .with_scheme_hint(scheme);
    // `p:0` names no port anything listens on. The native engines answer it with the
    // keyword's default port (`winhttp.rs` and `cfnetwork.rs` say why), and the same script
    // gets the same port whichever engine ran it.
    if endpoint.port == 0 {
        endpoint.port = scheme.default_port();
    }
    // A PAC script is remote code (under WPAD, from whoever answered discovery), so
    // credentials in its result are attacker-chosen, and `ProxyStep::to_url` would write
    // them into the URL a caller feeds its HTTP client. Drop them but keep the candidate, as
    // Firefox does (Chromium drops the candidate), and warn: a silent drop looks like a
    // working authenticated proxy until the 407.
    if endpoint.auth.take().is_some() {
        crate::trace::warning!(
            keyword,
            "dropping the credentials embedded in a PAC result candidate"
        );
    }
    // The hint comes from `scheme`, so use `ProxyStep::from_endpoint`'s exhaustive table.
    // Do not duplicate it with a SOCKS5 `_` arm for currently unreachable `ProxyScheme`
    // variants: adding `SOCKS4A` to the keyword list would then produce a SOCKS5 step.
    Some(ProxyStep::from_endpoint(endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorities(result: &str) -> Vec<String> {
        parse_find_proxy_result(result)
            .unwrap()
            .iter()
            .map(|step| match step.endpoint() {
                Some(endpoint) => format!("{}/{}", step.scheme().unwrap(), endpoint.authority()),
                None => "direct".to_owned(),
            })
            .collect()
    }

    #[test]
    fn every_keyword_maps_onto_a_step() {
        assert_eq!(authorities("DIRECT"), ["direct"]);
        assert_eq!(authorities("PROXY p:8080"), ["http/p:8080"]);
        assert_eq!(authorities("HTTP p:8080"), ["http/p:8080"]);
        assert_eq!(authorities("HTTPS p:8443"), ["https/p:8443"]);
        assert_eq!(authorities("SOCKS p:1080"), ["socks4/p:1080"]);
        assert_eq!(authorities("SOCKS4 p:1080"), ["socks4/p:1080"]);
        assert_eq!(authorities("SOCKS5 p:1080"), ["socks5/p:1080"]);
    }

    #[test]
    fn socks5_uses_remote_dns_in_to_url() {
        let step = &parse_find_proxy_result("SOCKS5 proxy.corp:1080").unwrap()[0];
        assert_eq!(step.scheme(), Some("socks5"));
        assert_eq!(
            step.endpoint().unwrap().scheme_hint,
            Some(ProxyScheme::Socks5h)
        );
        assert_eq!(step.to_url().unwrap().as_str(), "socks5h://proxy.corp:1080");
    }

    // `scheme()` says `socks4` for SOCKS4a too, so only `to_url` tells the two apart: a plain
    // SOCKS4 proxy may not speak 4a, and the name is resolved on this side.
    #[test]
    fn socks_and_socks4_resolve_locally_in_to_url() {
        for keyword in ["SOCKS", "SOCKS4"] {
            let step = &parse_find_proxy_result(&format!("{keyword} proxy.corp")).unwrap()[0];
            assert_eq!(
                step.to_url().unwrap().as_str(),
                "socks4://proxy.corp:1080",
                "{keyword}"
            );
        }
    }

    #[test]
    fn keywords_are_case_insensitive_and_ports_default() {
        assert_eq!(authorities("proxy p"), ["http/p:80"]);
        assert_eq!(authorities("Https p"), ["https/p:443"]);
        assert_eq!(authorities("socks5 p"), ["socks5/p:1080"]);
        assert_eq!(authorities("direct"), ["direct"]);
        // Port 0 is the keyword's default too, as the WinHTTP and CFNetwork engines read it.
        assert_eq!(authorities("PROXY p:0"), ["http/p:80"]);
        assert_eq!(authorities("SOCKS5 p:0"), ["socks5/p:1080"]);
    }

    #[test]
    fn a_chain_keeps_its_order() {
        assert_eq!(
            authorities("PROXY a:1; SOCKS5 b:2; DIRECT"),
            ["http/a:1", "socks5/b:2", "direct"]
        );
    }

    #[test]
    fn whitespace_around_a_candidate_is_ignored() {
        assert_eq!(
            authorities("  PROXY   a:1  ;\n\tPROXY b:2 ;;  "),
            ["http/a:1", "http/b:2"]
        );
    }

    // Every `\n` in the row above follows a `;`, so the word split would absorb it anyway.
    // These rows have no `;`, the only shape that tells the two apart.
    #[test]
    fn a_newline_separates_candidates_where_no_semicolon_does() {
        assert_eq!(
            authorities("PROXY a:1\nPROXY b:2\r\nDIRECT"),
            ["http/a:1", "http/b:2", "direct"]
        );

        // A lone `\r` is a line ending too; above, it sits before a `\n` that already cut.
        assert_eq!(authorities("PROXY a:1\rDIRECT"), ["http/a:1", "direct"]);
    }

    #[test]
    fn ipv6_literals_survive() {
        assert_eq!(authorities("PROXY [::1]:8080"), ["http/[::1]:8080"]);
        assert_eq!(authorities("PROXY ::1"), ["http/[::1]:80"]);
    }

    #[test]
    fn duplicates_collapse() {
        assert_eq!(
            authorities("PROXY a:1; PROXY a:1; DIRECT; DIRECT"),
            ["http/a:1", "direct"]
        );
        // Not just adjacent ones: the check is against the whole chain, and the first
        // occurrence is the one that keeps its position.
        assert_eq!(
            authorities("PROXY a:1; PROXY b:2; PROXY a:1"),
            ["http/a:1", "http/b:2"]
        );
        // A repeat is the same protocol to the same address. One address under another
        // protocol is another thing to try.
        assert_eq!(
            authorities("PROXY a:1; HTTPS a:1; SOCKS5 a:1; HTTP a:1"),
            ["http/a:1", "https/a:1", "socks5/a:1"]
        );
    }

    #[test]
    fn junk_candidates_are_skipped_but_do_not_poison_the_chain() {
        assert_eq!(
            authorities("GOPHER g:70; PROXY a:1; PROXY ; DIRECT x; SOCKS9 b:2"),
            ["http/a:1"]
        );
        assert_eq!(authorities("PROXY a:99999; PROXY a:1"), ["http/a:1"]);
        assert_eq!(authorities("PROXY http://a:1; PROXY a:1"), ["http/a:1"]);
        // That row cannot show the scheme is what is being *refused*: the one the address
        // carries agrees with the keyword, so accepting it would build the step the next
        // candidate already contributes and the collapse above hides the difference. Where
        // they disagree the keyword wins: `with_scheme_hint` overwrites what the address
        // said, and reading `https://` as plain HTTP is cleartext to a port that expects
        // TLS. So the candidate goes, and the chain moves on to what the script named next.
        assert_eq!(authorities("PROXY https://p:8443; DIRECT"), ["direct"]);
        assert_eq!(authorities("PROXY a:1 b:2; DIRECT"), ["direct"]);
    }

    /// A candidate carrying a path, query or fragment is malformed, not an address with
    /// something on the end to cut off. `ProxyEndpoint::parse` cuts it off: that is right
    /// for the values operating systems store, which are written as URLs, and running the
    /// same cut here answered with `corp:8080` for a string no script wrote, and put it
    /// ahead of the `DIRECT` the reference falls back to.
    ///
    /// Chromium's `ProxySchemeHostAndPortToProxyServer` gives `url::ParseAuthority` the
    /// whole string, so the port component of `corp:8080/path` is `8080/path` and
    /// `url::ParsePort` refuses it; `corp/path` has no colon, so the path lands in the host
    /// and `CanonicalizeHost` refuses that. `InvalidProxyUriToProxyServer` lists the three
    /// spellings under the comment "Paths disallowed."
    /// (`net/base/proxy_string_util_unittest.cc`), though the three rows there are missing
    /// their commas and so concatenate into one literal, which is why they are separate
    /// rows here.
    #[test]
    fn a_candidate_that_is_not_a_bare_authority_is_skipped_whole() {
        for spec in [
            "PROXY corp:8080/path",
            "PROXY corp:8080/",
            "PROXY corp/path",
            "PROXY corp:8080?q=1",
            "PROXY corp:8080#f",
            "SOCKS5 corp:1080/path",
        ] {
            assert_eq!(
                authorities(&format!("{spec}; DIRECT")),
                ["direct"],
                "{spec}"
            );
        }

        // The candidate goes, and only it: the chain moves on to what the script named next
        // rather than reporting the address a cut would have left.
        assert_eq!(
            authorities("PROXY corp:8080/path; PROXY other:3128"),
            ["http/other:3128"]
        );

        // Nothing else in the chain, and there is no answer to give: the same refusal the
        // parse makes for any string it cannot read.
        assert!(matches!(
            parse_find_proxy_result("PROXY corp:8080/path").unwrap_err(),
            Error::PacInvalidResult { .. }
        ));
    }

    #[test]
    fn credentials_in_a_candidate_are_dropped_but_the_proxy_survives() {
        let steps = parse_find_proxy_result("PROXY alice:hunter2@p:8080").unwrap();
        let endpoint = steps[0].endpoint().unwrap();
        assert_eq!(endpoint.authority(), "p:8080");
        assert_eq!(endpoint.auth, None);
        // Dropped rather than rejected because `to_url` is what a caller hands its HTTP
        // client, and it must not carry userinfo a remote script chose.
        assert_eq!(steps[0].to_url().unwrap().as_str(), "http://p:8080/");
        // A bare user name has no `:` to split on and must go the same way.
        assert_eq!(authorities("SOCKS5 bob@s:1080"), ["socks5/s:1080"]);
    }

    #[test]
    fn a_result_with_nothing_usable_is_an_error() {
        for junk in [
            "",
            "   ",
            ";;;",
            "null",
            "undefined",
            "GOPHER g:70",
            "PROXY",
        ] {
            let error = parse_find_proxy_result(junk).unwrap_err();
            assert!(
                matches!(error, Error::PacInvalidResult { .. }),
                "{junk:?} gave {error:?}"
            );
        }
    }

    // A remote script's string has no length cap, and this parse runs after the PAC timeout
    // has stopped waiting. Repeats and junk never fill the chain, so every candidate is read.
    #[test]
    fn a_long_result_of_repeats_and_junk_parses_in_linear_time() {
        let result = (0..200_000)
            .map(|i| match i % 3 {
                0 => format!("PROXY h0.example.com:{}", 8080 + i % 2),
                1 => format!("PROXY h{i}.example.com/"),
                _ => format!("JUNK{i}"),
            })
            .collect::<Vec<_>>()
            .join(";");
        let start = std::time::Instant::now();
        let chain = authorities(&result);
        let elapsed = start.elapsed();
        assert_eq!(
            chain,
            ["http/h0.example.com:8080", "http/h0.example.com:8081"]
        );
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "parsing 200,000 candidates took {elapsed:?}"
        );
    }

    #[test]
    fn the_chain_keeps_its_first_steps_and_drops_the_rest() {
        // The doc of `parse_find_proxy_result` names the number.
        assert_eq!(MAX_CHAIN, 64);
        // Junk and repeats are not steps and do not count; a `DIRECT` past the limit is
        // dropped with the rest, so the chain never widens to direct by being long.
        let mut result = String::from("junk; PROXY h0:1; PROXY h0:1;");
        for i in 1..=MAX_CHAIN {
            result.push_str(&format!(" PROXY h{i}:1;"));
        }
        result.push_str(" DIRECT");
        let chain = authorities(&result);
        assert_eq!(chain.len(), MAX_CHAIN);
        assert_eq!(chain[0], "http/h0:1");
        assert_eq!(chain[MAX_CHAIN - 1], format!("http/h{}:1", MAX_CHAIN - 1));
        assert!(!chain.contains(&"direct".to_owned()));
    }

    #[test]
    fn words_are_split_at_ascii_whitespace_only() {
        assert_eq!(authorities("PROXY\ta:1"), ["http/a:1"]);
        // A no-break space, an ideographic space and a vertical tab are part of the word
        // they sit in, at either end of a candidate as well as inside it.
        for space in ['\u{a0}', '\u{3000}', '\u{b}'] {
            for result in [
                format!("PROXY{space}a:1; DIRECT"),
                format!("{space}PROXY a:1; DIRECT"),
                format!("PROXY a:1{space}; DIRECT"),
            ] {
                assert_eq!(authorities(&result), ["direct"], "{result:?}");
            }
            let result = format!("DIRECT{space}; PROXY a:1");
            assert_eq!(authorities(&result), ["http/a:1"], "{result:?}");
        }
    }
}
