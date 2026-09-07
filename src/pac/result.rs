//! Parsing what `FindProxyForURL` returns.

use crate::endpoint::{ProxyEndpoint, ProxyScheme};
use crate::error::Error;
use crate::resolve::ProxyStep;
use std::collections::HashSet;

/// Parse a `FindProxyForURL` return string into an ordered fallback chain.
///
/// `;`-separated tokens, and newlines too — that part is this crate's, not Chromium's.
/// Keywords case-insensitive:
/// `DIRECT`; `PROXY`/`HTTP`→[`ProxyStep::Http`]; `HTTPS`→HTTPS; `SOCKS`/`SOCKS4`→SOCKS4;
/// `SOCKS5`→[`ProxyScheme::Socks5h`] (remote DNS). An address with no port of its own gets
/// [`ProxyScheme::default_port`] for the scheme the keyword named, rather than a second
/// table of ports here. The address is a bare authority, so a `/`, `?` or `#` in it — a
/// `scheme://` included — makes the candidate one of the bad ones rather than something to
/// trim. Bad tokens skipped; repeats collapse; embedded credentials dropped; empty usable
/// chain → [`Error::PacInvalidResult`].
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
    let mut steps = Vec::new();
    let mut seen = HashSet::new();
    // A newline is a separator here, and in Chromium it is not: `ProxyList::SetFromPacString`
    // builds a `base::StringTokenizer(pac_string, ";")`. A script that separated its
    // candidates with newlines instead therefore loses all of them at once — with `;` alone,
    // `PROXY a:1\nDIRECT` is a single candidate of three words, one more than the grammar
    // allows, so the chain comes back empty. Refusing an entire chain over punctuation is
    // the same silent-`DIRECT` outcome the block below declines to inherit, reached by a
    // different road. The divergence runs one way only: this accepts what the reference
    // rejects, never the other way round.
    for candidate in result.split([';', '\n', '\r']) {
        // Chromium's `ProxyList::SetFromPacString` keeps repeats — it `emplace_back`s
        // every valid element with no membership check. A chain is a list of things to
        // try in order, and a proxy that just failed is no more alive the second time
        // the script names it. The test is against the whole chain rather than the
        // previous element, so `a; b; a` collapses as well as `a; a`: by the time the
        // second `a` is reached, `a` has already been tried and failed within this same
        // chain. Dropping them is visible in `len()`, hence the doc line above.
        //
        // Keeping repeats is also what let Chromium ask the question with no index. This
        // crate answers it for every candidate, so the structure it asks has to be the
        // cheap one: `steps.contains` walked a vector that grows with the script's own
        // output, which is how a remote string became quadratic work on a thread the
        // timeout has already stopped waiting for
        // (`a_long_chain_of_distinct_candidates_does_not_stall_the_parse`).
        if let Some(step) = parse_candidate(candidate)
            && seen.insert(step.clone())
        {
            steps.push(step);
        }
    }
    if steps.is_empty() {
        // Chromium's `PacResult::ToProxyList` pushes `DIRECT` here instead, under the
        // comment "this basically means an error in the PAC script". Same diagnosis,
        // opposite handling: a script that said something unreadable has not said "go
        // direct", and silently going direct is how traffic leaves a network the script
        // was written to keep it inside. The caller gets the error and can choose
        // `DIRECT` itself.
        return Err(Error::pac_invalid_result(result));
    }
    Ok(steps)
}

// One `;`-separated candidate, or `None` when it is not usable.
fn parse_candidate(candidate: &str) -> Option<ProxyStep> {
    let mut words = candidate.split_whitespace();
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
        // Remote DNS: Chromium's `ProxyServer::SCHEME_SOCKS5` always resolves names on
        // the proxy side; curl's URI vocabulary uses the `h` suffix for that
        // (https://curl.se/docs/url-syntax.html).
        "SOCKS5" => ProxyScheme::Socks5h,
        _ => return None,
    };

    let address = address?;
    // A PAC candidate is a bare authority, so a `/`, `?` or `#` in it — the `/`s of a
    // `scheme://` included — makes the candidate malformed rather than something to trim.
    // `ProxyEndpoint::parse` does trim them, and is right to: the values operating systems
    // *store* are written as URLs, where `http://proxy:8080/` is an ordinary spelling of an
    // endpoint. A script's return value is not written that way, and letting the same trim
    // run here would answer with an address the script did not write — and, for a scheme,
    // silently override the keyword, where reading `https://p:8443` as plain HTTP is
    // cleartext to a port that expects TLS.
    //
    // Chromium refuses the candidate: `ProxySchemeHostAndPortToProxyServer` hands the whole
    // string to `url::ParseAuthority`, so `p:8080/x` yields a port component of `8080/x`
    // that `url::ParsePort` rejects, and `p/x` reaches `CanonicalizeHost` carrying a
    // forbidden host code point ("Paths disallowed.",
    // `net/base/proxy_string_util_unittest.cc`). libproxy takes the other road and keeps the
    // path whole, building `http://<server>` and handing `g_uri_to_string` back unshortened
    // (`px_manager_run_pac`). Neither answers with an address the script did not write, and
    // trimming is the one reading that would; between the two, Chromium's is what this
    // module already follows for the rest of the grammar. Firefox is a third reading again —
    // `ProcessPACString` tries `NS_NewURI` on the address and only prepends `http://` when
    // that yields no host, which is why a `scheme://` is accepted there and then ignored —
    // and it is the one measured for the scheme only, not for a path.
    if address.contains(['/', '?', '#']) {
        return None;
    }
    let mut endpoint = ProxyEndpoint::parse(address, scheme.default_port())
        .ok()?
        .with_scheme_hint(scheme);
    // A PAC script is remote code — under WPAD, code from whoever answered the discovery
    // query — so credentials it hands back are attacker-chosen, and `ProxyStep::to_url`
    // would write them straight into the URL a caller feeds its HTTP client. Neither
    // reference propagates them: Chromium rejects the candidate outright (`ParseAuthority`
    // then `if (username_component.is_valid() || password_component.is_valid()) return
    // ProxyServer()`), Firefox keeps only `GetAsciiHost` and drops them silently. Take
    // Firefox's outcome — a proxy the script named is still worth trying, so this does not
    // fail closed on a chain — but say so, because a silent drop looks like a working
    // authenticated proxy right up until the 407.
    if endpoint.auth.take().is_some() {
        crate::trace::warning!(
            keyword,
            "dropping the credentials embedded in a PAC result candidate"
        );
    }
    // The hint was just set from `scheme`, so `ProxyStep::from_endpoint` — the exhaustive
    // table — answers this. Repeating it here cost a `_` arm over `ProxyScheme` variants
    // no keyword above produces, and a `SOCKS4A` keyword added to that list would have
    // come out of it as a *SOCKS5* step.
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

    #[test]
    fn keywords_are_case_insensitive_and_ports_default() {
        assert_eq!(authorities("proxy p"), ["http/p:80"]);
        assert_eq!(authorities("Https p"), ["https/p:443"]);
        assert_eq!(authorities("socks5 p"), ["socks5/p:1080"]);
        assert_eq!(authorities("direct"), ["direct"]);
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

    // A newline is a separator here and in neither reference — see the note on the split.
    // The row above cannot show it: every `\n` there follows a `;` that has already cut the
    // string, so `split_whitespace` inside the candidate would absorb it either way. These
    // rows have no `;` at all, which is the only shape that tells the two apart: without the
    // newline in the separator set the whole string is one candidate, `PROXY a:1 PROXY b:2`
    // is three words where two are allowed, and the chain comes back empty.
    #[test]
    fn a_newline_separates_candidates_where_no_semicolon_does() {
        assert_eq!(
            authorities("PROXY a:1\nPROXY b:2\r\nDIRECT"),
            ["http/a:1", "http/b:2", "direct"]
        );

        // The carriage return earns its place in that set on its own, and this is the only
        // shape that shows it: in the row above it sits in front of a `\n` that has already
        // cut the string, and inside a candidate `split_whitespace` would absorb it. Alone
        // it is a line ending a script may still be written with, and without it here the
        // whole return value is again one candidate of too many words.
        assert_eq!(authorities("PROXY a:1\rDIRECT"), ["http/a:1", "direct"]);
    }

    #[test]
    fn ipv6_literals_survive() {
        assert_eq!(authorities("PROXY [::1]:8080"), ["http/[::1]:8080"]);
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
        // they disagree the keyword wins — `with_scheme_hint` overwrites what the address
        // said — and reading `https://` as plain HTTP is cleartext to a port that expects
        // TLS. So the candidate goes, and the chain moves on to what the script named next.
        assert_eq!(authorities("PROXY https://p:8443; DIRECT"), ["direct"]);
        assert_eq!(authorities("PROXY a:1 b:2; DIRECT"), ["direct"]);
    }

    /// A candidate carrying a path, query or fragment is malformed, not an address with
    /// something on the end to cut off. `ProxyEndpoint::parse` cuts it off — that is right
    /// for the values operating systems store, which are written as URLs — and running the
    /// same cut here answered with `corp:8080` for a string no script wrote, and put it
    /// ahead of the `DIRECT` the reference falls back to.
    ///
    /// Chromium's `ProxySchemeHostAndPortToProxyServer` gives `url::ParseAuthority` the
    /// whole string, so the port component of `corp:8080/path` is `8080/path` and
    /// `url::ParsePort` refuses it; `corp/path` has no colon, so the path lands in the host
    /// and `CanonicalizeHost` refuses that. `InvalidProxyUriToProxyServer` lists the three
    /// spellings under the comment "Paths disallowed."
    /// (`net/base/proxy_string_util_unittest.cc`) — though the three rows there are missing
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

        // Nothing else in the chain, and there is no answer to give — the same refusal the
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
        // The whole point of dropping rather than rejecting: `to_url` is what a caller
        // hands its HTTP client, and it must not carry userinfo a remote script chose.
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

    // The string parsed here is whatever a remote script returned, and nothing caps its
    // length: `boa::run` hands `to_std_string_escaped()` straight over. Worse, this parse
    // runs *after* `FindProxyForURL` returns, so `run_with_timeout` has already given its
    // caller `PacTimeout` and walked away — the thread still finishing this loop is one
    // nobody is waiting for and nothing will stop. Collapsing repeats with `Vec::contains`
    // makes that quadratic — hence the `HashSet`. Without it, 16,000 distinct candidates
    // take 48.7 s in a debug build and 2.9 s in release, quadrupling on every doubling from
    // 288 ms at 1,000. That 288 ms is the per-candidate cost with the quadratic term still
    // small, so the linear parse this does instead costs about 4.6 s for 16,000 — 3.0 s to
    // 6.6 s here, load included. The bound is placed between
    // that and the 48.7 s, near enough to the quadratic figure to still fail on it and far
    // enough from the linear one that a loaded machine does not.
    #[test]
    fn a_long_chain_of_distinct_candidates_does_not_stall_the_parse() {
        let result = (0..16_000)
            .map(|i| format!("PROXY h{i}.example.com:8080"))
            .collect::<Vec<_>>()
            .join(";");
        let start = std::time::Instant::now();
        let steps = parse_find_proxy_result(&result).expect("every candidate is usable");
        let elapsed = start.elapsed();
        assert_eq!(
            steps.len(),
            16_000,
            "the chain came back a different length"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "parsing {} candidates took {elapsed:?}",
            steps.len()
        );
    }
}
