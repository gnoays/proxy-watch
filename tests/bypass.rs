// The `GO_LIST` constant below is the rule list from the `useProxy` test in Go's
// `golang.org/x/net/http/httpproxy`. That constant alone is Go's; everything else in this
// file is this crate's own and carries the crate's licence. The notice, conditions and
// disclaimer that Go's licence asks a source redistribution to retain follow verbatim.
//
// Copyright 2017 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google LLC nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Table-driven tests for bypass (`no_proxy` / `ProxyOverride`) matching.
//!
//! The first table mirrors the semantics of Go's
//! `golang.org/x/net/http/httpproxy` `useProxy` test: the same rule list, and hosts
//! chosen to exercise each rule kind. `true` here means "bypass the proxy", which is
//! the negation of Go's `match` column.
//!
//! The case table below is this crate's own: it carries ports the Go table cannot express,
//! because Go tests bare hosts and appends the port itself.

use proxy_watch::{
    BypassRules, Error, Host, HostPattern, RejectedValue, RejectionKind, RejectionSource, Url,
    parse,
};

fn rejected_texts(values: &[RejectedValue]) -> Vec<&str> {
    values.iter().map(RejectedValue::redacted_input).collect()
}

/// The rule list used by the Go test suite.
const GO_LIST: &str = "foobar.com, .barbaz.net, *.blobbar.org, 192.168.1.1, \
                       192.168.1.2:81, 192.168.1.3:80, 10.0.0.0/30, 2001:db8::52:0:1, \
                       [2001:db8::52:0:2]:81, [2001:db8::52:0:3]:80, 2002:db8:a::45/64";

/// `(authority, bypass?)`
const GO_CASES: &[(&str, bool)] = &[
    // Loopback is always bypassed, regardless of the list.
    ("localhost", true),
    ("localhost:80", true),
    ("127.0.0.1", true),
    ("127.0.0.2", true), // the whole 127.0.0.0/8 is loopback
    ("[::1]", true),
    ("[::2]", false), // not a loopback address
    // Exact IPv4, no port restriction.
    ("192.168.1.1", true),
    ("192.168.1.1:8080", true),
    // Exact IPv4 restricted to port 81.
    ("192.168.1.2", false),
    ("192.168.1.2:80", false),
    ("192.168.1.2:81", true),
    // Exact IPv4 restricted to port 80.
    ("192.168.1.3:80", true),
    ("192.168.1.3:81", false),
    // Not in the list at all.
    ("192.168.1.4", false),
    // IPv4 CIDR 10.0.0.0/30 covers .0 - .3.
    ("10.0.0.2", true),
    ("10.0.0.3:443", true),
    ("10.0.0.4", false),
    // Bare IPv6 entry.
    ("[2001:db8::52:0:1]", true),
    ("[2001:db8::52:0:1]:8080", true),
    // Bracketed IPv6 with a port restriction.
    ("[2001:db8::52:0:2]", false),
    ("[2001:db8::52:0:2]:81", true),
    ("[2001:db8::52:0:3]:80", true),
    ("[2001:db8::52:0:3]:81", false),
    // IPv6 CIDR.
    ("[2002:db8:a::123]", true),
    // Link-local joins loopback in the implicit bypass set (`is_link_local` in `bypass.rs`),
    // so it bypasses whatever the patterns say; only `<-loopback>`, absent from this list,
    // takes that away. Go proxies this address instead — do not copy its `match` column into
    // this row. It is the one row the two tables share where they disagree on the answer and
    // not merely on how the column is spelled.
    ("[fe80::424b:c8be:1643:a1b6]", true),
    // `foobar.com` matches itself and every subdomain.
    ("foobar.com", true),
    ("foobar.com:8080", true),
    ("www.foobar.com", true),
    ("deep.www.foobar.com", true),
    ("foofoobar.com", false), // not a label boundary
    ("barfoobar.com", false),
    // `.barbaz.net` matches subdomains only.
    ("barbaz.net", false),
    ("www.barbaz.net", true),
    // `*.blobbar.org` behaves exactly like `.blobbar.org`.
    ("blobbar.org", false),
    ("www.blobbar.org", true),
    // Nothing else matches.
    ("google.com", false),
    ("", false),
];

#[test]
fn go_httpproxy_semantics() {
    let rules = parse::no_proxy(GO_LIST);
    for (authority, expected) in GO_CASES {
        assert_eq!(
            rules.matches_authority(authority),
            *expected,
            "bypass({authority:?}) with list {GO_LIST:?}"
        );
    }
}

#[test]
fn matching_is_case_insensitive() {
    let rules = parse::no_proxy("FooBar.COM, .BarBaz.net");
    assert!(rules.matches_authority("WWW.FOOBAR.COM"));
    assert!(rules.matches_authority("www.barbaz.NET"));
}

// The test above only reaches one side of the comparison: `parse` lowercases every entry,
// so by the time a rule is matched its own text is already folded. The other side is a
// rule built by hand — `HostPattern`'s variant fields are public and `BypassRules::new`
// exists to be filled in, which is the very premise `HostPattern::matches` states when it
// refuses to slice a byte off a suffix. Such a rule must name the host it spells.
//
// `Exact` was the only arm that did, and by accident: it renders its `Host` through
// `host_key`, the same helper that lowercases the destination.
#[test]
fn a_hand_built_rule_matches_whatever_case_it_was_written_in() {
    let mut rules = BypassRules::new();
    rules.patterns.push(HostPattern::Domain {
        suffix: ".Example.COM".to_owned(),
        match_self: true,
        port: None,
    });
    rules.patterns.push(HostPattern::Wildcard {
        pattern: "*.BlobBar.org".to_owned(),
        port: None,
    });
    rules.patterns.push(HostPattern::Exact {
        host: Host::Domain("FooBar.com".to_owned()),
        port: None,
    });

    assert!(rules.matches_authority("www.example.com"), "{rules:?}");
    assert!(rules.matches_authority("example.com"), "{rules:?}");
    assert!(rules.matches_authority("www.blobbar.org"), "{rules:?}");
    assert!(rules.matches_authority("foobar.com"), "{rules:?}");

    // Folding the rule must not widen it: neither the label boundary nor the glob's own
    // shape is relaxed by comparing case-insensitively.
    assert!(!rules.matches_authority("notexample.com"), "{rules:?}");
    assert!(!rules.matches_authority("blobbar.org"), "{rules:?}");
    assert!(!rules.matches_authority("foofoobar.com"), "{rules:?}");
}

// Go runs each entry through `idnaASCII`; the destination side here is converted the same
// way, by `Host::parse` when it is parsed from text and by the matcher itself when the
// caller assembled the `Host`. Without the matching step on the entry side a Unicode rule
// matched nothing at all — not the Unicode spelling, not the punycode one.
#[test]
fn an_internationalised_entry_is_stored_as_punycode() {
    let rules = parse::no_proxy("日本.example, .Ünïcode.test, *.日本.example");
    assert!(rules.rejected.is_empty(), "{rules:?}");
    assert!(rules.matches_authority("日本.example"));
    assert!(rules.matches_authority("xn--wgv71a.example"));
    assert!(rules.matches_authority("www.日本.example"));
    assert!(rules.matches_authority("host.ünïcode.test"));
    assert!(!rules.matches_authority("ünïcode.test"), "leading dot");
    assert!(!rules.matches_authority("example.org"));

    // `matches` takes the `Host` rather than parsing one, so nothing has punycoded it on
    // the way in. Both public entry points have to answer alike or an exclusion the caller
    // spelled out goes to the proxy anyway, depending only on which one they reached for.
    for host in ["日本.example", "xn--wgv71a.example", "www.日本.example"] {
        assert!(
            rules.matches(&Host::Domain(host.to_owned()), None),
            "{host} via matches"
        );
    }
    assert!(!rules.matches(&Host::Domain("example.org".to_owned()), None));

    // A glob and non-ASCII text in one label have no punycode spelling between them, so
    // the entry is rejected rather than silently encoded into something else.
    let mixed = parse::no_proxy("*日本*.example");
    assert!(mixed.patterns.is_empty(), "{mixed:?}");
    assert_eq!(mixed.rejected.len(), 1, "{mixed:?}");
}

// The conversion has to spell a label, not judge it. Labels reach `Host::parse` one at a
// time, so every one of them looks like the last to it, and a last label of digits is an
// address: `１２３` normalises to `123` and came back `Ipv4`, sinking the whole entry. The
// destination side never reads it that way — there the digits are followed by `example` —
// so the refused rule was one for a name a caller can actually reach.
#[test]
fn an_internationalised_label_of_digits_is_still_a_name() {
    let rules = parse::no_proxy("１２３.example");
    assert!(rules.rejected.is_empty(), "{rules:?}");
    assert!(rules.matches_authority("１２３.example"));
    assert!(rules.matches_authority("123.example"));
    assert!(!rules.matches_authority("124.example"));
    // The other entry point, where the caller assembled the `Host` and `host_key` runs the
    // same conversion. It failed the same way, and fails open, so the rule matched nothing.
    assert!(rules.matches(&Host::Domain("１２３.example".to_owned()), None));

    // Judging still happens, afterwards and over the whole host part: a bare all-digit name
    // is the address a destination spelled that way becomes, in either script.
    let bare = parse::no_proxy("１２３");
    assert!(bare.rejected.is_empty(), "{bare:?}");
    assert!(bare.matches_authority("１２３"));
    assert!(bare.matches_authority("0.0.0.123"), "{bare:?}");
}

// The punycode step's counterpart: an address entry is stored the way the destination
// side will spell it. `IpAddr` reads dotted decimal and nothing else, so an entry
// carrying the zero padding administrators write into these lists, or written in the
// short form, used to be filed as a domain suffix no destination could ever equal — and
// `rejected` stayed empty, so nothing said so.
#[test]
fn an_address_entry_is_stored_the_way_the_destination_side_spells_it() {
    let rules = parse::no_proxy("192.168.001.001, 010.0.0.1, 192.168.1");
    assert!(rules.rejected.is_empty(), "{rules:?}");
    // Either spelling of the entry matches, on either side of the comparison.
    assert!(rules.matches_authority("192.168.001.001"));
    assert!(rules.matches_authority("192.168.1.1"));
    // A leading zero is octal in the URL parser the destination goes through, so `010`
    // is 8 there and has to be 8 here.
    assert!(rules.matches_authority("8.0.0.1"));
    assert!(!rules.matches_authority("10.0.0.1"));
    // A short form fills from the right.
    assert!(rules.matches_authority("192.168.0.1"));
    assert!(!rules.matches_authority("192.168.1.0"));

    // A name is still a name: only text the destination side reads as an address moves.
    let names = parse::no_proxy("corp.example");
    assert!(names.matches_authority("a.corp.example"));
    assert!(!names.matches_authority("corp.example.org"));

    // The all-digit name is where that reading bites: `123` is an address on the
    // destination side whatever it was meant to be, so the entry is the same address and
    // no longer a suffix that swept up every host ending in `.123`.
    let digits = parse::no_proxy("123");
    assert!(digits.matches_authority("123"));
    assert!(digits.matches_authority("0.0.0.123"));
    assert!(!digits.matches_authority("1.2.3.123"));
}

#[test]
fn star_disables_proxying_entirely() {
    let rules = parse::no_proxy("*");
    for authority in ["example.com", "1.2.3.4:80", "[2001:db8::1]:443", "intranet"] {
        assert!(rules.matches_authority(authority), "{authority}");
    }
}

#[test]
fn empty_list_reports_empty_and_bypasses_loopback() {
    let rules = parse::no_proxy("");
    assert!(rules.is_empty());
    assert!(rules.matches_authority("localhost"));
    assert!(rules.matches_authority("127.0.0.1"));
    assert!(!rules.matches_authority("example.com"));
}

/// `<-loopback>` is an entry like any other — it has to be, because what it subtracts
/// depends on where in the list it sits — so a list holding only that one is not empty and
/// `is_empty()` reporting `true` would invite a caller to drop it and silently put the
/// implicit bypass back.
#[test]
fn a_lone_no_loopback_token_is_not_an_empty_rule_set() {
    let rules = parse::proxy_override("<-loopback>");
    assert_eq!(rules.patterns, [HostPattern::SubtractImplicit]);
    assert!(!rules.bypass_loopback());
    assert!(!rules.is_empty());
    // Not vacuous: the instruction is the whole difference from an empty list, which
    // does bypass loopback.
    assert!(!rules.matches_authority("localhost"));
    assert!(parse::no_proxy("").matches_authority("localhost"));
}

/// Every shape `HostPattern::parse` rejects, each of which its `# Errors` section names —
/// the `/`-that-is-not-a-CIDR case was once missing from it.
#[test]
fn every_documented_rejection_reason_is_reachable() {
    // The last two are here so that the loop covers the `# Errors` list in full; what
    // each of them is refused *for* is the subject of its own test below.
    for entry in [
        "user:pw@proxy.example",
        "a.example b.example",
        "10.0.0/8",
        "example.com:99999",
        "[::1",
        "*日本*.example",
        "https://bad.example.com",
        "a#b.example.com",
        "example.com..",
        ".10.0.0.1",
        "example.123",
    ] {
        assert!(
            HostPattern::parse(entry).is_err(),
            "{entry} should not parse"
        );
    }
    // And the `Ok(None)` list: entries with nothing left to match on are dropped
    // without being recorded as errors.
    for entry in ["", ":8080", "*.", "."] {
        // `Error` is not `PartialEq`, so the `Ok(None)` shape is matched rather than
        // compared.
        assert!(matches!(HostPattern::parse(entry), Ok(None)), "{entry}");
    }
}

#[test]
fn windows_local_token() {
    let rules = parse::proxy_override("<local>");
    assert!(rules.excludes_simple_hostnames());
    // Dot-less (intranet) names are bypassed ...
    assert!(rules.matches_authority("intranet"));
    assert!(rules.matches_authority("build-server:8080"));
    // ... but fully qualified names and IP literals are not.
    assert!(!rules.matches_authority("intranet.corp.example"));
    assert!(!rules.matches_authority("10.0.0.1"));
}

#[test]
fn windows_no_loopback_token() {
    let default = parse::proxy_override("*.contoso.com");
    assert!(default.bypass_loopback());
    assert!(default.matches_authority("localhost"));
    assert!(default.matches_authority("127.0.0.1"));
    assert!(default.matches_authority("[::1]"));

    let disabled = parse::proxy_override("*.contoso.com;<-loopback>");
    assert!(!disabled.bypass_loopback());
    assert!(!disabled.matches_authority("localhost"));
    assert!(!disabled.matches_authority("127.0.0.1"));
    assert!(!disabled.matches_authority("[::1]"));
    // The rest of the list still applies.
    assert!(disabled.matches_authority("www.contoso.com"));

    // Both tokens, and the order between them decides `localhost`: it is a dot-less name
    // and so `<local>`'s, and it is in the implicit set and so `<-loopback>`'s, and the
    // later entry wins. `127.0.0.1` is only ever the second one's.
    let subtract_last = parse::proxy_override("<local>;<-loopback>");
    assert!(!subtract_last.matches_authority("localhost"));
    assert!(!subtract_last.matches_authority("127.0.0.1"));

    let subtract_first = parse::proxy_override("<-loopback>;<local>");
    assert!(subtract_first.matches_authority("localhost"));
    assert!(!subtract_first.matches_authority("127.0.0.1"));
    // Neither order touches what `<local>` is actually for.
    assert!(subtract_last.matches_authority("intranet"));
    assert!(subtract_first.matches_authority("intranet"));

    // WinINet tokens are case-insensitive.
    let rules = parse::proxy_override("<LOCAL>;<-LoopBack>");
    assert!(rules.excludes_simple_hostnames());
    assert!(!rules.bypass_loopback());
}

#[test]
fn windows_style_wildcards() {
    let rules = parse::proxy_override("192.168.*;www.*.com;*.corp");
    assert!(rules.matches_authority("192.168.0.1"));
    assert!(!rules.matches_authority("192.169.0.1"));
    assert!(rules.matches_authority("www.example.com"));
    assert!(!rules.matches_authority("www.example.org"));
    assert!(rules.matches_authority("host.corp"));
    assert!(!rules.matches_authority("corp"));
}

/// The trailing dot is the DNS root marker, and the two "a subdomain of" spellings have to
/// shed it alike. The dotted one does so where every entry does, on the way past the address
/// check; the glob one leaves that path early and strips its own, and only there. Without
/// that second strip, `*.example.com.` is stored as `.example.com.` — a suffix no
/// destination carries, since the root dot is gone by the time a host key is built — and
/// nothing is recorded either, so the entry reads as live and matches nothing.
#[test]
fn a_root_dot_on_a_glob_entry_is_shed_like_any_other() {
    let rules = parse::no_proxy("*.example.com.");
    assert!(rules.matches_authority("a.example.com"));
    assert!(rules.rejected.is_empty());
    assert_eq!(rules, parse::no_proxy("*.example.com"));
}

/// A leading dot is remapped by prepending a `*` — "we remap `.google.com` -->
/// `*.google.com`" (`SchemeHostPortMatcherRule::FromUntrimmedRawString`) — and the
/// reference applies that to *every* rule starting with one, including a rule that also
/// carries a glob. Without the remap a glob entry keeps its leading dot, is matched
/// literally, and no host name begins with a dot: `.*.example.com` used to be a rule that
/// matched nothing and recorded nothing.
#[test]
fn a_leading_dot_on_a_glob_entry_is_a_rule_and_not_a_dead_one() {
    let rules = parse::no_proxy(".*.example.com");
    assert!(rules.matches_authority("a.b.example.com"));
    // The dot still means "under something": the remapped `*.*.example.com` wants two
    // labels in front, so the one-label host is the same non-match it is in the reference.
    assert!(!rules.matches_authority("b.example.com"));
    assert!(rules.rejected.is_empty());

    // The dot-less spelling is untouched, and a port restriction still rides along.
    assert!(parse::no_proxy("*.*.example.com").matches_authority("a.b.example.com"));
    let ported = parse::no_proxy(".*.example.com:8080");
    assert!(ported.matches_authority("a.b.example.com:8080"));
    assert!(!ported.matches_authority("a.b.example.com:80"));
}

/// A semicolon is a separator in the Windows dialect and in no other. Go splits `no_proxy`
/// on `,` alone; every reader of KDE's `NoProxyFor` does too — `g_strsplit (value->str,
/// ",", -1)` in libproxy's `config-kde.c`, and a tokenizer over `", "` in Chromium's
/// `proxy_config_service_linux.cc`. So `a.example;b.example` is one entry to all of them,
/// and one entry that matches nothing: both hosts keep using the proxy.
///
/// Splitting it here made them two live rules and sent both direct instead — a bypass the
/// supplier does not have, on the two hosts the author of the list singled out. The entry
/// is kept whole now, which leaves the same single rule matching nothing that every
/// supplier's reader is left holding — including the part where nobody records it.
#[test]
fn a_semicolon_separates_only_in_the_windows_dialect() {
    let semi = parse::no_proxy("a.example;b.example");
    assert_eq!(semi.patterns.len(), 1);
    assert!(!semi.matches_authority("a.example"));
    assert!(!semi.matches_authority("b.example"));
    assert!(semi.rejected.is_empty());

    let comma = parse::no_proxy("a.example,b.example");
    assert!(comma.matches_authority("a.example"));
    assert!(comma.matches_authority("b.example"));
    assert!(comma.rejected.is_empty());

    // The dialect that does have it is unchanged.
    let windows = parse::proxy_override("a.example;b.example");
    assert!(windows.matches_authority("a.example"));
    assert!(windows.matches_authority("b.example"));
}

/// A malformed entry used to fail the whole
/// list via `Err`. It is now dropped and its (redacted) original text recorded in
/// [`proxy_watch::BypassRules::rejected`] instead — see that field's doc comment.
/// Redaction is why only the out-of-range port is echoed back: the other two leave a
/// `:` that cannot be told apart from a stranded `user:password`, so the entry is
/// recorded but withheld.
#[test]
fn malformed_entries_are_dropped_and_recorded_instead_of_failing_the_list() {
    for (input, echoed) in [
        ("example.com:abc", false),
        ("example.com:99999", true),
        ("[::1:80", false),
    ] {
        let rules = parse::no_proxy(input);
        assert!(rules.patterns.is_empty(), "{input:?}: {rules:?}");
        assert_eq!(rules.rejected.len(), 1, "{input:?}: {rules:?}");
        if echoed {
            assert_eq!(rules.rejected[0].redacted_input(), input, "{input:?}");
        } else {
            assert!(
                rules.rejected[0].redacted_input().contains("withheld"),
                "{input:?}: {rules:?}"
            );
        }
    }
}

/// Brackets are the address-literal spelling, so a bracketed entry that is not one is a
/// dead rule: `[2001:db8::zz]` used to become `Domain { suffix: ".2001:db8::zz" }`, which
/// matches no host and records nothing — and under a reversed (exception-list) semantic a
/// dead rule sends out direct the very traffic the entry meant to keep on the proxy.
/// `[10.0.0.1]` is on the accepting side: brackets belong to IPv6, but an address inside
/// them is plainly the address it says it is, and rejecting that would be a spelling
/// opinion rather than the fail-closed valve this guard exists to be. Which spellings
/// count is the destination side's question, so the brackets accept every spelling the
/// unbracketed entry does — `[010.0.0.1]` is the live rule `010.0.0.1` is, not a dead one.
#[test]
fn a_bracketed_entry_must_be_an_address_literal() {
    for accepted in [
        "[::1]",
        "[::1]:8080",
        "[2001:db8::1]",
        "[10.0.0.1]",
        "[010.0.0.1]",
        "[0x7f.0.0.1]",
        "[0xc0.0.2.1]",
    ] {
        let rules = parse::no_proxy(accepted);
        assert_eq!(rules.patterns.len(), 1, "{accepted:?}: {rules:?}");
        assert!(rules.rejected.is_empty(), "{accepted:?}: {rules:?}");
    }
    // Every destination below is outside the implicit bypass set, which is the whole reason
    // these are not the addresses the accepting list opens with: `[::1]` covering `[::1]`
    // and `[0x7f.0.0.1]` covering `127.0.0.1` both passed on the loopback rule alone, so
    // neither said anything about whether the entry had become a rule. The two loopback
    // spellings stay above, where `patterns.len() == 1` still holds them.
    assert!(parse::no_proxy("[10.0.0.1]").matches_authority("10.0.0.1"));
    assert!(parse::no_proxy("[2001:db8::1]").matches_authority("[2001:db8::1]"));
    // The same address the unbracketed entry names, by the same grammar.
    assert!(parse::no_proxy("[010.0.0.1]").matches_authority("8.0.0.1"));
    assert!(!parse::no_proxy("[010.0.0.1]").matches_authority("10.0.0.1"));
    assert!(parse::no_proxy("[0xc0.0.2.1]").matches_authority("192.0.2.1"));

    for rejected in [
        "[2001:db8::zz]",
        "[not-ip]",
        "[]",
        "[fe80::1%25eth0]",
        "[1.2.3.4.5]",
        "[256.0.0.1]",
    ] {
        let rules = parse::no_proxy(rejected);
        assert!(rules.patterns.is_empty(), "{rejected:?}: {rules:?}");
        assert_eq!(rules.rejected.len(), 1, "{rejected:?}: {rules:?}");
    }
}

/// WinHTTP documents `lpszProxyBypass` as "one or more server names separated by
/// semicolons or whitespace" (`WINHTTP_PROXY_INFO`), and Chromium tokenises the string
/// `WinHttpGetIEProxyConfigForCurrentUser` hands back on `";, \t\n\r"`
/// (`ProxyConfigServiceWin::SetFromIEConfig`). Splitting on `;` and `,` alone made
/// `"*.contoso.com intranet"` a single `Domain` pattern that no host can match, recorded
/// nowhere — the dead-rule shape the bracket and `/` guards above exist to stop.
///
/// `no_proxy` keeps the narrow set on purpose: Go's `httpproxy` splits on `,` alone, so
/// the same text is one entry there too. It is rejected rather than silently dead.
#[test]
fn the_windows_bypass_list_separates_on_whitespace_as_well() {
    let rules = parse::proxy_override("*.contoso.com intranet\t10.1.2.3\r\n<local>");
    assert!(rules.matches_authority("www.contoso.com"));
    assert!(rules.matches_authority("intranet"));
    assert!(rules.matches_authority("10.1.2.3"));
    assert!(rules.excludes_simple_hostnames());
    assert!(rules.rejected.is_empty(), "{rules:?}");
    // Not vacuous: a mixed list still splits on the documented `;` too.
    assert!(parse::proxy_override("a.example b.example;c.example").matches_authority("c.example"));

    // The env variable follows Go instead — one entry, and a recorded one.
    let env = parse::no_proxy("a.example b.example");
    assert!(!env.matches_authority("a.example"));
    assert!(env.patterns.is_empty(), "{env:?}");
    assert_eq!(rejected_texts(&env.rejected), ["a.example b.example"]);
    assert_eq!(env.rejected[0].kind(), RejectionKind::InvalidBypassPattern);
    assert_eq!(env.rejected[0].source(), &RejectionSource::BypassList);
}

/// Windows answers a `/` with the whole list, so an entry holding one is recorded rather
/// than read as a mask. Microsoft bounds the damage at the list — "don't enter subwebs or
/// trailing slashes ... as they are invalidating the whole list otherwise" (KB 4551930) —
/// and both readers land past that bound: handed `other.invalid;10.0.0.0/8`, WinINet fails
/// `InternetOpenW` with `ERROR_INVALID_PARAMETER` and WinHTTP fails `Open` with the same
/// code, while the same text in `ProxyOverride` sends every destination direct, including
/// the ones no entry names. That last reading is measured; no document states it.
///
/// What this crate does *not* do is answer that list-wide consequence: a good entry beside
/// the bad one stays live. Rejecting the one entry stops the crate reporting a bypass no
/// reader grants; discarding its neighbours too would be a claim about the whole
/// configuration, and only the registry reading supports that one.
#[test]
fn a_slash_ends_a_windows_bypass_list() {
    let rules = parse::proxy_override("10.0.0.0/8");
    assert!(!rules.matches_authority("10.1.2.3"), "{rules:?}");
    assert!(rules.patterns.is_empty(), "{rules:?}");
    assert_eq!(rejected_texts(&rules.rejected), ["10.0.0.0/8"]);
    assert_eq!(
        rules.rejected[0].kind(),
        RejectionKind::InvalidBypassPattern
    );
    assert_eq!(rules.rejected[0].source(), &RejectionSource::BypassList);

    // The character, not the CIDR spelling. A scheme meets the `://` guard and the rest
    // meet the slash guard; every one of them lands in `rejected` either way.
    for entry in [
        "10.0.0/8",
        "some/thing",
        "https://contoso.com",
        "contoso.com/",
    ] {
        let one = parse::proxy_override(entry);
        assert!(one.patterns.is_empty(), "{entry:?}: {one:?}");
        assert_eq!(one.rejected.len(), 1, "{entry:?}: {one:?}");
    }

    // The range Windows does read, and the one the rejection reason recommends.
    assert!(parse::proxy_override("10.*").matches_authority("10.1.2.3"));

    // This dialect alone. `no_proxy` follows Go, which reads the same text as a mask.
    assert!(parse::no_proxy("10.0.0.0/8").matches_authority("10.1.2.3"));

    // A rejected entry takes no neighbour with it.
    let mixed = parse::proxy_override("contoso.com;10.0.0.0/8");
    assert!(mixed.matches_authority("contoso.com"), "{mixed:?}");
    assert_eq!(mixed.rejected.len(), 1, "{mixed:?}");
}

/// The other spelling a Windows list has no reading for. Microsoft documents the wildcard
/// in its place — "Enter a wildcard at the beginning of an Internet address, IP address, or
/// domain name that has a common ending" (KB 4551930) — and all three readings agree, asked
/// for `http://sub.pw-probe.invalid/`: `.pw-probe.invalid` makes `InternetOpenW` fail with
/// `ERROR_INVALID_NAME` and takes the whole list with it, while WinHTTP and the reading of
/// `ProxyOverride` under `INTERNET_OPEN_TYPE_PRECONFIG` keep the list and reach the proxy
/// anyway. `*.pw-probe.invalid` bypasses on all three, and the bare parent
/// `pw-probe.invalid` bypasses on none, which is the same row
/// [`a_bare_name_in_a_windows_list_is_the_one_host`] measures.
///
/// Windows will not store the spelling either: typed into the Settings app's exception box,
/// a list holding one is discarded whole and without a warning, where the same list without
/// the dot saves. The spelling reaches `ProxyOverride` through Group Policy or a direct
/// registry write, not through the UI.
///
/// Refusing therefore loses no bypass any reading grants, where a live rule would report
/// direct the traffic all three hand to the proxy. Unlike a `/`, the dot leaves the
/// configuration in use: the registry reading still sends this destination to the proxy
/// rather than turning every destination direct.
#[test]
fn a_leading_dot_is_not_a_windows_suffix() {
    let rules = parse::proxy_override(".contoso.com");
    assert!(!rules.matches_authority("api.contoso.com"), "{rules:?}");
    assert!(rules.patterns.is_empty(), "{rules:?}");
    assert_eq!(rejected_texts(&rules.rejected), [".contoso.com"]);
    assert_eq!(
        rules.rejected[0].kind(),
        RejectionKind::InvalidBypassPattern
    );
    assert_eq!(rules.rejected[0].source(), &RejectionSource::BypassList);

    // The spelling Windows does read, and the one the rejection reason recommends.
    assert!(parse::proxy_override("*.contoso.com").matches_authority("api.contoso.com"));

    // Nothing follows the dot, so no rule is built and there is nothing to refuse: these
    // stay dropped rather than joining `rejected`.
    for entry in [".", ".."] {
        let one = parse::proxy_override(entry);
        assert!(one.patterns.is_empty(), "{entry:?}: {one:?}");
        assert!(one.rejected.is_empty(), "{entry:?}: {one:?}");
    }

    // This dialect alone. The other three read a leading dot as the subdomains.
    assert!(parse::no_proxy(".contoso.com").matches_authority("api.contoso.com"));

    // A rejected entry takes no neighbour with it.
    let mixed = parse::proxy_override("contoso.com;.fabrikam.com");
    assert!(mixed.matches_authority("contoso.com"), "{mixed:?}");
    assert_eq!(mixed.rejected.len(), 1, "{mixed:?}");
}

/// The exact scenario the fix targets: one bad element must not wipe out every other,
/// valid element in the same list. `https://bad.example.com` is what stripping a
/// scheme prefix leaves behind (`//bad.example.com` fails port parsing); `[fe80::]/10`
/// is the bracketed-CIDR mistake Chromium's own `net/docs/proxy.md` calls out as
/// "`[fefe::]/40` -- WRONG! IPv6 literals must not be bracketed" — brackets are for a
/// literal address plus a port, not a network prefix.
#[test]
fn a_bad_element_leaves_the_rest_of_the_list_active() {
    let list = "good.example.com,https://bad.example.com,[fe80::]/10,also-good.example.com";
    let rules = parse::no_proxy(list);

    assert!(rules.matches_authority("good.example.com"));
    assert!(rules.matches_authority("also-good.example.com"));
    assert_eq!(
        rules.patterns.len(),
        2,
        "only the two good entries should have parsed: {:?}",
        rules.patterns
    );
    assert_eq!(
        rejected_texts(&rules.rejected),
        ["https://bad.example.com", "[fe80::]/10"]
    );
}

/// Security regression test: `HostPattern::parse` never processes `@` — a bypass
/// entry is not supposed to be a URL — so a `user:password@host` entry used to fall
/// straight through to `split_host_port`/`parse_port` with `"password@host"` sitting
/// where a port was expected. The resulting port-parse failure used to embed that whole
/// fragment, credential included, in the error's `reason`, which survives even though
/// [`Error`]'s `input` field has always been masked. This is also a realistic operator
/// mistake, not just a contrived input: pasting a full proxy URL into the
/// bypass/exception field instead of just its host.
#[test]
fn a_credential_bearing_entry_is_rejected_without_leaking_the_password() {
    const SECRET: &str = "hunter2";
    let entry = format!("alice:{SECRET}@proxy.example");

    let error = HostPattern::parse(&entry)
        .expect_err("an '@'-bearing entry must be rejected, not silently misparsed");

    let display = error.to_string();
    let debug = format!("{error:?}");
    assert!(!display.contains(SECRET), "{display}");
    assert!(!debug.contains(SECRET), "{debug}");

    match &error {
        Error::InvalidBypassPattern { input, reason } => {
            assert!(!input.contains(SECRET), "input: {input}");
            assert!(!reason.contains(SECRET), "reason: {reason}");
            // Not vacuous, and points the caller at the actual mistake.
            assert!(
                reason.contains('@'),
                "reason should still name the shape: {reason}"
            );
        }
        other => panic!("expected InvalidBypassPattern, got {other:?}"),
    }
}

/// The same shape reaching `HostPattern::parse` through the fail-soft
/// [`parse::no_proxy`] boundary: the password must not leak into
/// [`proxy_watch::BypassRules::rejected`] either, and the rest of the list must survive
/// exactly as it does for any other malformed entry.
#[test]
fn no_proxy_drops_a_credential_bearing_entry_without_leaking_the_password() {
    const SECRET: &str = "hunter2";
    let list = format!("good.example.com,alice:{SECRET}@proxy.example,also-good.example.com");
    let rules = parse::no_proxy(&list);

    assert!(rules.matches_authority("good.example.com"));
    assert!(rules.matches_authority("also-good.example.com"));
    assert_eq!(rules.patterns.len(), 2, "{:?}", rules.patterns);
    assert_eq!(rules.rejected.len(), 1, "{:?}", rules.rejected);
    assert!(
        !rules.rejected[0].redacted_input().contains(SECRET),
        "{}",
        rules.rejected[0].redacted_input()
    );
}

/// An entry with a `/` and no `scheme://` in it can only be meant as a CIDR block, so one
/// that fails to parse as a network must be rejected outright. `10.0.0/8` — an octet
/// short of `10.0.0.0/8` — used to slip past the `IpNet` parse and be reinterpreted as a
/// domain suffix `.10.0.0/8`, a pattern nothing can ever match: no `rejected` record, no
/// warning, and (before the fix to `matches` below) a reversed list would then have
/// bypassed the whole network the entry was written to protect. Go's `httpproxy` skips
/// the same shape explicitly.
#[test]
fn a_slash_entry_that_is_not_a_valid_cidr_is_rejected_rather_than_read_as_a_domain() {
    for input in ["10.0.0/8", "10.0.0.0/33", "not-a-network/8"] {
        let rules = parse::no_proxy(input);
        assert!(
            rules.patterns.is_empty(),
            "{input:?} must not become a pattern: {:?}",
            rules.patterns
        );
        assert_eq!(rejected_texts(&rules.rejected), [input], "{input:?}");
    }

    // The pattern it used to be turned into really was dead, which is why this went
    // unnoticed: neither the network it names nor the literal text ever matched.
    let rules = parse::no_proxy("10.0.0/8");
    assert!(!rules.matches_authority("10.1.2.3"));
    assert!(!rules.matches_authority("10.0.0/8"));
}

/// The destination side is `Host::parse`, which refuses WHATWG's forbidden domain code
/// points, so a rule holding one names a host that can never arrive. Fed the *identical*
/// spelling — the most favourable destination a rule can have — such a rule still did not
/// match: dead, with nothing in `rejected` to say so, and fail-open under
/// `reversed_exceptions`. The `@`, whitespace and `/` guards were the same test spelled
/// three characters at a time; this is the rest of the set.
#[test]
fn a_character_no_host_can_hold_is_refused_rather_than_left_as_a_dead_rule() {
    for bad in [
        '#', '%', '<', '>', '?', '[', '\\', ']', '^', '|', '\u{1}', '\u{7f}',
    ] {
        let entry = format!("a{bad}b.example.com");
        assert!(
            HostPattern::parse(&entry).is_err(),
            "{entry:?} must be refused"
        );

        let rules = parse::no_proxy(&format!("good.example.com,{entry}"));
        assert!(rules.matches_authority("good.example.com"), "{entry:?}");
        assert_eq!(rules.rejected.len(), 1, "{entry:?}: {:?}", rules.rejected);
    }

    // `*` is not one of them, which is what leaves room for the glob spelling.
    let rules = parse::no_proxy("192.168.*");
    assert!(rules.matches_authority("192.168.0.1"));
    assert!(rules.rejected.is_empty());
}

/// The empty label has one place in a host name — the root, at the end — and that is the
/// single trailing dot `HostPattern::parse` strips. A second one made `example.com..` into
/// `Domain { suffix: ".example.com." }`, which the domain the entry names never matched,
/// while the pattern's own `Display` read back as `example.com.`, a rule that does. Dead,
/// with nothing in `rejected` to say so, and fail-open under `reversed_exceptions`.
#[test]
fn an_empty_label_is_refused_rather_than_left_as_a_dead_rule() {
    for entry in [
        "example.com..",
        "..example.com",
        "a..b.example.com",
        "*.example.com..",
        ".example.com..",
        "example.com..:8080",
    ] {
        assert!(
            HostPattern::parse(entry).is_err(),
            "{entry:?} must be refused"
        );
    }

    // The root dot on its own is untouched, and an entry left with no host part at all is
    // still dropped rather than recorded.
    for entry in ["example.com.", ".example.com", "*.example.com"] {
        assert!(
            matches!(HostPattern::parse(entry), Ok(Some(_))),
            "{entry:?}"
        );
    }
    for entry in [".", "..", "*."] {
        assert!(matches!(HostPattern::parse(entry), Ok(None)), "{entry:?}");
    }

    let rules = parse::no_proxy("good.example.com,example.com..");
    assert!(rules.matches_authority("good.example.com"));
    assert_eq!(rejected_texts(&rules.rejected), ["example.com.."]);
}

/// The same dead-rule shape from the other direction: a pattern whose destination cannot
/// exist. An address has no subdomains, so `.10.0.0.1` waited for an `a.10.0.0.1` that
/// `Host::parse` refuses; and a name whose last label reads as a number is an address
/// attempt on the destination side, so nothing is ever spelled `example.123` either. Both
/// used to be stored as domain suffixes with `rejected` left empty.
#[test]
fn a_pattern_no_destination_could_match_is_refused() {
    for entry in [
        // A suffix rule on an address, in every spelling of the suffix and of the address.
        ".10.0.0.1",
        "*.10.0.0.1",
        ".192.168.001.001",
        ".0x0a.0.0.1",
        ".2001:db8::1",
        "*.2001:db8::1",
        ".10.0.0.1:8080",
        // A last label that reads as a number.
        "example.123",
        "example.0x1",
        ".example.123",
        "*.example.123",
        // The same shapes with a glob inside the body, which used to be exempted from the
        // check on the grounds that `*` also stands for the empty string. It does, but not
        // here: the dot survives, so `.*.10.0.0.1` was stored as `Wildcard("*.*.10.0.0.1")`
        // and waited for an `a.b.10.0.0.1` — a name whose last label reads as a number,
        // which is the address reading and so not a host any URL carries. The exemption
        // bought a dead rule with nothing in `rejected` to say so. Not every glob body is
        // dead, though, and taking the exemption away from all of them was its own bug —
        // `a_glob_body_the_leading_octets_can_satisfy_is_kept` below holds the ones that
        // stay, and each entry here is refused by a clause that test also pins from the
        // other side.
        ".*.10.0.0.1",
        "*.*.10.0.0.1",
        ".*.0x0a.0.0.1",
        ".*.example.123",
    ] {
        assert!(
            HostPattern::parse(entry).is_err(),
            "{entry:?} must be refused"
        );
    }

    // The address on its own is the live rule the suffix spelling was reaching for. The
    // glob spelling of it is live too — `*` stands for the empty string, so `*10.0.0.1`
    // does meet `10.0.0.1` — and it is live for a reason that has nothing to do with the
    // check above, which it never reaches: it opens with neither `.` nor `*.`, so it has no
    // subdomain body at all.
    for entry in ["10.0.0.1", "192.168.001.001", "*10.0.0.1", "123"] {
        assert!(
            matches!(HostPattern::parse(entry), Ok(Some(_))),
            "{entry:?}"
        );
    }
    assert!(parse::no_proxy("*10.0.0.1").matches_authority("10.0.0.1"));

    // And a glob body that names a name is untouched by the refusal above: these reach the
    // check, parse as domains, and stay the rules they were.
    for entry in [".*.example", ".a*b.example", ".*"] {
        assert!(
            matches!(HostPattern::parse(entry), Ok(Some(_))),
            "{entry:?}"
        );
    }
    assert!(parse::no_proxy(".*.example").matches_authority("www.corp.example"));

    let rules = parse::no_proxy("good.example.com,.10.0.0.1,example.123");
    assert!(rules.matches_authority("good.example.com"));
    assert_eq!(
        rejected_texts(&rules.rejected),
        [".10.0.0.1", "example.123"]
    );
}

/// The other side of that refusal, and the reason it is not simply "a numeric tail". A glob
/// is matched against the destination's *text*, where a star stands for the leading octets
/// of an address as readily as for whole labels, so `*.*.*.1` is met by `10.0.0.1` itself.
/// Refusing it threw away a live rule with the message that no destination could match it.
#[test]
fn a_glob_body_the_leading_octets_can_satisfy_is_kept() {
    for entry in [".*.1", "*.*.1", ".*.0.1", ".*.*.1", "*.*.*.1"] {
        assert!(
            matches!(HostPattern::parse(entry), Ok(Some(_))),
            "{entry:?} must be kept"
        );
    }
    assert!(parse::no_proxy("*.*.*.1").matches_authority("10.0.0.1"));
    assert!(parse::no_proxy(".*.1").matches_authority("10.0.0.1"));
    assert!(parse::no_proxy(".*.0.1").matches_authority("192.168.0.1"));
    // A rule, not a blanket: the tail is still a tail.
    assert!(!parse::no_proxy(".*.1").matches_authority("10.0.0.2"));

    // Each half of what still refuses the entries in the test above, from the side where
    // only that half is doing the work. `.*.0.0.1` is all digits and dots and dies on the
    // count alone — laid over a quad it leaves the leading star nothing but an empty first
    // label, and a destination with a label to spare is no longer an address. `.*.f.1` is
    // short enough and dies on the byte alone, because no quad carries an `f`.
    for entry in [".*.0.0.1", ".*.f.1"] {
        assert!(
            HostPattern::parse(entry).is_err(),
            "{entry:?} must be refused"
        );
    }

    // And the exemption is the glob's, not the numeric tail's: `.256.1` reaches the refusal
    // by the same route — no octet is 256, so the address reading fails — and, with no star
    // to stand for what comes before it, waits for an `a.256.1` that is no host either.
    assert!(HostPattern::parse(".256.1").is_err());
}

/// How far "no destination could ever match it" reaches. The refusal above rests on
/// `Host::parse`, which is the *special*-scheme host parser: a last label that reads as a
/// number is taken for an address, so `http://a.example.123/` has no spelling. WHATWG sends a
/// non-special scheme to the opaque-host parser before it ever reaches that check, and this
/// crate's public entry points take any `Url`. So the entry is unreachable for the
/// destinations these lists are written about and reachable for one they are not, and the
/// message is absolute where the test behind it is not.
///
/// Kept as a refusal rather than widened: the shape is a typo far more often than it is a
/// `custom://` bypass, and dropping the rule sends the request to the proxy rather than
/// around it. This holds the boundary so nothing downstream reads the gate as more than it
/// measures — and it is the only thing that does: narrow `request_host` to the hosts
/// `Host::parse` accepts, so that every non-special destination is hostless, and this test
/// is the one that fails.
#[test]
fn a_refused_numeric_tail_is_only_unreachable_for_a_special_scheme() {
    let rules = parse::no_proxy(".example.123");
    assert_eq!(rejected_texts(&rules.rejected), [".example.123"]);
    assert!(rules.patterns.is_empty());

    // The reading the refusal is built on, and the one that is not.
    assert!(Url::parse("http://a.example.123/").is_err());
    let url = Url::parse("custom://a.example.123/").expect("an opaque host is not IPv4-parsed");
    assert_eq!(url.host_str(), Some("a.example.123"));

    // So the rule that was thrown away was not dead. Built by hand, because parsing it is
    // exactly what the crate refuses to do.
    let mut kept = BypassRules::default();
    kept.patterns.push(HostPattern::Domain {
        suffix: ".example.123".to_owned(),
        match_self: true,
        port: None,
    });
    assert!(kept.matches_url(&url));

    // The other public entry point is not wider: it parses the authority as a host, so the
    // same name is refused on the destination side too and the gate is exact there.
    assert!(!kept.matches_authority("a.example.123"));
}

/// The refusal above is not only for a numeric last label. A colon is let through as an
/// attempt at an unbracketed IPv6, so a broken one lands on the same reason — and because
/// the colon also makes the input withheld, that reason is the only thing the reader gets.
#[test]
fn a_broken_unbracketed_ipv6_is_refused_with_a_reason_that_covers_it() {
    for entry in ["2001:db8:1", ".2001:db8:1", "*.2001:db8:1"] {
        let Err(error) = HostPattern::parse(entry) else {
            panic!("{entry:?} must be refused");
        };
        let Error::InvalidBypassPattern { input, reason } = &error else {
            panic!("{entry:?}: {error:?}");
        };
        assert!(
            !input.contains("db8"),
            "a colon-bearing entry is withheld: {input}"
        );
        assert!(reason.contains("2001:db8:1"), "{entry:?}: {reason}");
    }
}

/// Windows splits its list on the ASCII spellings it writes itself, so an entry holding
/// any other space reaches `HostPattern::parse` whole. It has to be *refused* there —
/// silently keeping `a.example<U+3000>b.example` would leave a rule matching nothing with
/// nothing in `rejected` to say so, which under `reversed_exceptions` fails open.
#[test]
fn a_unicode_space_inside_a_windows_entry_is_recorded_not_dropped() {
    for space in ['\u{00A0}', '\u{3000}', '\u{000B}'] {
        let spec = format!("a.example{space}b.example;ok.example");
        let rules = parse::proxy_override(&spec);
        assert_eq!(
            rejected_texts(&rules.rejected),
            [format!("a.example{space}b.example")],
            "for {space:?}"
        );
        assert!(rules.matches_authority("ok.example"), "for {space:?}");
    }

    // The ASCII spellings really are separators, so they must not reach the guard at all.
    let rules = parse::proxy_override("a.example b.example\tc.example");
    assert!(rules.rejected.is_empty(), "{:?}", rules.rejected);
    assert!(rules.matches_authority("c.example"));
}

/// A scheme-prefixed entry is a rule in Chromium, not a broken CIDR block: the `://` is
/// split off before the `/` is looked at (`SchemeHostPortMatcherRule::FromUntrimmedRawString`).
/// A [`HostPattern`] cannot carry the restriction, so the entry is refused rather than
/// widened to every scheme — and the reason names the scheme instead of asserting a
/// grammar the reference does not have.
#[test]
fn a_scheme_prefixed_entry_is_refused_as_one_and_not_as_a_broken_cidr() {
    for input in [
        "https://bad.example.com",
        "http://intranet",
        "https://10.0.0.0/8",
    ] {
        let Err(Error::InvalidBypassPattern { reason, .. }) = HostPattern::parse(input) else {
            panic!("{input:?} must be refused");
        };
        assert!(reason.contains("scheme"), "{input:?}: {reason}");
        assert!(!reason.contains("CIDR"), "{input:?}: {reason}");
    }

    // Refused, not fatal: the rest of the list still stands and the entry is on the record.
    let rules = parse::no_proxy("good.example.com,https://bad.example.com");
    assert!(rules.matches_authority("good.example.com"));
    assert!(!rules.matches_authority("bad.example.com"));
    assert_eq!(rejected_texts(&rules.rejected), ["https://bad.example.com"]);
}

/// Under [`proxy_watch::BypassRules::reversed_exceptions`] the list says
/// which destinations *do* use the proxy, which inverts the safety argument that a
/// malformed entry should be dropped in the direction of narrowing bypass, not widening
/// it: a dropped entry no longer widens bypass — it deletes a destination the
/// administrator named as one that must go through the proxy, and that destination then
/// silently goes direct instead. `matches` therefore stops trusting the "not
/// listed means direct" default while anything sits in `rejected`.
#[test]
fn a_rejected_entry_in_a_reversed_list_stops_unlisted_destinations_going_direct() {
    let mut rules = parse::no_proxy(".corp.example, 10.0.0/8");
    rules.reversed_exceptions = true;
    assert_eq!(rejected_texts(&rules.rejected), ["10.0.0/8"]);

    // The destinations the dropped entry was written for: direct before the fix.
    assert!(!rules.matches_authority("10.1.2.3"));
    // Anything else unlisted is treated the same way — which of the two the lost entry
    // covered is unknowable, since it did not parse.
    assert!(!rules.matches_authority("example.net"));
    // What the list does say still holds: listed means "use the proxy", so no bypass.
    assert!(!rules.matches_authority("api.corp.example"));
    // The implicit bypasses are untouched; they are not gated on the pattern verdict.
    assert!(rules.matches_authority("localhost"));
    assert!(rules.matches_authority("169.254.1.1"));
}

/// The other side of the same rule: with nothing rejected, a reversed list keeps its
/// original meaning exactly, and a non-reversed list is unaffected either way.
#[test]
fn a_clean_reversed_list_still_sends_unlisted_destinations_direct() {
    let mut rules = parse::no_proxy(".corp.example");
    rules.reversed_exceptions = true;
    assert!(rules.rejected.is_empty());
    assert!(rules.matches_authority("example.net"));
    assert!(!rules.matches_authority("api.corp.example"));

    // Non-reversed: a rejected entry narrows what is bypassed and nothing more, which is
    // the safe direction for a malformed entry to fail in.
    let rules = parse::no_proxy(".corp.example, 10.0.0/8");
    assert!(!rules.rejected.is_empty());
    assert!(rules.matches_authority("api.corp.example"));
    assert!(!rules.matches_authority("example.net"));
}

/// The end point of the same reasoning: a reversed list whose *only* entry was rejected
/// has no patterns left at all. Before the fix that bypassed everything — one typo
/// disabling the proxy configuration wholesale — where now everything but the implicit
/// bypasses goes through the proxy, which is what the administrator asked for.
#[test]
fn a_reversed_list_of_nothing_but_a_rejected_entry_proxies_everything_reachable() {
    let mut rules = parse::no_proxy("10.0.0/8");
    rules.reversed_exceptions = true;
    assert!(rules.patterns.is_empty());
    assert!(!rules.rejected.is_empty());

    assert!(!rules.matches_authority("example.net"));
    assert!(!rules.matches_authority("10.1.2.3"));
    assert!(rules.matches_authority("localhost"));
}

/// [`proxy_watch::BypassRules::matches_authority`]'s documented answer for an authority
/// it cannot read: "does not bypass". Two returns carry that promise — one for a
/// `host[:port]` that will not split, one for a host part that is not a host — and
/// before this test only the second was reached, incidentally, by tests asserting
/// something else with `""` and `"10.0.0/8"`. The first was reached by nothing.
///
/// Each malformed case is paired with the well-formed twin that *does* bypass, so the
/// assertion cannot pass merely because the rule list would have said `false` anyway.
/// Both rule sets are exercised because the promise is about *where* the answer comes
/// from: these returns are taken before the pattern verdict, and under
/// [`proxy_watch::BypassRules::reversed_exceptions`] that verdict is inverted, so
/// reading an unreadable authority as merely "not listed" would turn the proxy off for
/// it — while still passing every other test in this file.
#[test]
fn an_authority_that_does_not_parse_never_bypasses() {
    // `(malformed, the twin it would have been)`.
    const PAIRS: &[(&str, &str)] = &[
        ("[::1", "[::1]"),                     // unbalanced '['
        ("[::1]x", "[::1]"),                   // trailing text after the literal
        ("[127.0.0.1]", "127.0.0.1"),          // brackets around something not IPv6
        ("127.0.0.1:99999", "127.0.0.1:9999"), // port out of range
        ("127.0.0.1:abc", "127.0.0.1:80"),     // port that is not digits
        ("127.0.0.1:+80", "127.0.0.1:80"),     // signed port
        ("127.0.0.1:-80", "127.0.0.1:80"),     // signed port
        ("", "localhost"),                     // no host at all
    ];

    let plain = parse::no_proxy("localhost");
    let mut reversed = parse::no_proxy(".corp.example");
    reversed.reversed_exceptions = true;
    // With anything in `rejected` a reversed list stops answering `true` for unlisted
    // destinations, which would make every twin below bypass for the wrong reason.
    assert!(reversed.rejected.is_empty());

    for (malformed, twin) in PAIRS {
        for (mode, rules) in [("plain", &plain), ("reversed", &reversed)] {
            assert!(
                rules.matches_authority(twin),
                "{mode}: {twin:?} must bypass, or the case it is paired with proves nothing"
            );
            assert!(
                !rules.matches_authority(malformed),
                "{mode}: {malformed:?} cannot be read and so must not be reported as bypassed"
            );
        }
    }
}

/// [`proxy_watch::BypassRules::rejected`] is a pure function of the source string, so
/// carrying it in `BypassRules` cannot break the derived [`PartialEq`] that the watcher
/// relies on to skip emitting duplicate snapshots. Nothing states that in a doc comment,
/// which is why it is asserted here — at both the `BypassRules` level and (since that is
/// what the watcher actually compares) the `ProxyConfig` level built on top of it.
#[test]
fn rejected_entries_do_not_break_partialeq_between_equal_inputs() {
    let list = "good.example.com,https://bad.example.com,also-good.example.com";

    let a = parse::no_proxy(list);
    let b = parse::no_proxy(list);
    assert!(!a.rejected.is_empty());
    assert_eq!(a, b, "identical input must still compare equal");

    // Different rejected content is a real difference and must still be detected.
    let c = parse::no_proxy("good.example.com,https://other.example.com,also-good.example.com");
    assert_ne!(a, c);

    // The same, one level up: two ProxyConfigs built from the same (partly malformed)
    // input must compare equal, or the watcher's duplicate-emission skip would
    // never trigger for a config carrying rejected entries.
    let server = "http=h:8080";
    let x = proxy_watch::ProxyConfig::from_source(
        proxy_watch::ProxyConfigSource::Registry,
        parse::windows_manual(server, list),
    );
    let y = proxy_watch::ProxyConfig::from_source(
        proxy_watch::ProxyConfigSource::Registry,
        parse::windows_manual(server, list),
    );
    assert!(!x.effective.bypass().unwrap().rejected.is_empty());
    assert_eq!(x, y);
}

#[test]
fn ignores_entries_without_a_host() {
    // Go drops these rather than failing.
    let rules = parse::no_proxy(":80, ., example.com");
    assert_eq!(rules.patterns.len(), 1);
    assert!(rules.matches_authority("example.com"));
    // These are genuinely empty entries (Go's own semantics), not malformed ones — they
    // must not show up as rejections.
    assert!(rules.rejected.is_empty());
}

/// Chromium's *implicit* bypass set, which it connects directly without the list saying
/// so: the link-local ranges, plus what its own `IsLocalHostname` treats as the loopback
/// name (`*.localhost`, a trailing dot) and what `IsIPv4MappedLoopback` does (the
/// IPv4-mapped form). An empty list must bypass every one of them. Implicit, not
/// unconditional — `<-loopback>` subtracts the set, which is
/// [`no_loopback_token_clears_the_whole_implicit_bypass_set`]'s subject.
#[test]
fn implicit_bypass_covers_the_chromium_set_even_with_an_empty_list() {
    let rules = parse::no_proxy("");
    for authority in [
        "169.254.1.1",          // IPv4 link-local (APIPA)
        "[fe80::1]",            // IPv6 link-local
        "app.localhost",        // `*.localhost` subdomain
        "localhost.",           // trailing dot
        "[::ffff:127.0.0.1]",   // IPv4-mapped loopback
        "[::ffff:169.254.1.1]", // IPv4-mapped link-local
    ] {
        assert!(rules.matches_authority(authority), "{authority}");
    }
}

/// The mapped spelling is the address it maps, wherever this file compares addresses.
/// Go reads it that way throughout (`net.IP.Equal` for `ipMatch`, `IPNet.Contains` for
/// `cidrMatch`), and Chromium's `IPAddressMatchesPrefix` does for its CIDR rule.
#[test]
fn an_ipv4_mapped_destination_matches_the_address_it_maps() {
    let rules = parse::no_proxy("10.0.0.0/8, 192.0.2.7");
    assert!(rules.matches_authority("[::ffff:10.1.2.3]"), "cidr");
    assert!(rules.matches_authority("[::ffff:192.0.2.7]"), "exact");
    assert!(!rules.matches_authority("[::ffff:192.0.2.8]"), "over-match");
    // And the rule may be the one carrying the mapped spelling.
    let mapped_rule = parse::no_proxy("[::ffff:192.0.2.7]");
    assert!(mapped_rule.matches_authority("192.0.2.7"));
    assert!(!mapped_rule.matches_authority("192.0.2.8"));
}

/// The half of the test above that was missing: a *CIDR* rule written in the mapped
/// spelling. It parses as an `IpNet::V6`, every destination reaches the matcher already
/// reduced to `IpAddr::V4`, and `IpNet`'s `contains` is false across families — so the rule
/// matched nothing at all, including the two spellings of the very address it names, with
/// `rejected` empty because the entry parsed. Under `ReversedException` that sends a whole
/// subnet direct.
#[test]
fn an_ipv4_mapped_cidr_rule_matches_the_block_it_maps() {
    let rules = parse::no_proxy("::ffff:10.0.0.0/104");
    assert!(rules.matches_authority("10.0.0.1"), "plain destination");
    assert!(
        rules.matches_authority("[::ffff:10.0.0.1]"),
        "mapped destination"
    );
    assert!(!rules.matches_authority("11.0.0.1"), "over-match");
    assert!(rules.rejected.is_empty(), "{:?}", rules.rejected);

    // The boundary itself, which neither row above stands on: /104 is eight bits inside it
    // and /80 sixteen outside, so narrowing the conversion to prefixes strictly wider than
    // /96 leaves every row above green while `::ffff:0.0.0.0/96` — the whole of IPv4 written
    // in the mapped spelling — matches nothing.
    let whole = parse::no_proxy("::ffff:0.0.0.0/96");
    assert!(whole.matches_authority("10.0.0.1"), "boundary, plain");
    assert!(
        whole.matches_authority("[::ffff:203.0.113.9]"),
        "boundary, mapped"
    );

    // A prefix shorter than /96 covers unmapped IPv6 as well, so it stays an IPv6 rule and
    // says nothing about IPv4 destinations.
    let wide = parse::no_proxy("::ffff:10.0.0.0/80");
    assert!(!wide.matches_authority("10.0.0.1"));
    // One bit short of the boundary is already outside it: /95 reaches `::fffe:0:0/96` too.
    let one_short = parse::no_proxy("::ffff:0.0.0.0/95");
    assert!(!one_short.matches_authority("10.0.0.1"));
}

/// The implicit set must not over-match: destinations that merely look similar to one
/// of the cases listed above must keep going through the proxy.
#[test]
fn implicit_bypass_does_not_over_match() {
    let rules = parse::no_proxy("");
    for authority in [
        "169.255.1.1",          // outside 169.254.0.0/16
        "[::ffff:169.255.1.1]", // the mapped spelling of the same near miss
        "notlocalhost",         // not a `.localhost` label boundary
        "localhost.evil.com",   // trailing label is `.com`, not a trailing dot
    ] {
        assert!(!rules.matches_authority(authority), "{authority}");
    }
}

/// The outer edge of the implicit set, which the near-miss test above does not reach: whole
/// categories that another definition of "local" does include and this one must not.
///
/// The rows are not a sample. This crate holds two range predicates over addresses, they
/// answer different questions, and the wider one is `pac::hostfn::is_internal` — the ranges
/// a PAC script must not be allowed to probe. One row here per arm of it that the implicit
/// bypass set does not share, plus `printer.local` for the mDNS name nothing resolves.
/// Widening the bypass set toward that one would be a fail-open on every row; narrowing the
/// PAC filter toward this one would be the SSRF hole it exists to close. Nothing asserted
/// the boundary between them, so a change in either direction was green.
#[test]
fn the_implicit_set_stops_short_of_every_other_kind_of_internal_address() {
    let rules = parse::no_proxy("");
    for authority in [
        "10.0.0.1",        // RFC 1918
        "100.64.0.1",      // carrier-grade NAT
        "0.0.0.0",         // "this network"
        "192.0.0.1",       // IETF protocol assignments
        "192.0.2.1",       // documentation, TEST-NET-1
        "198.51.100.1",    // documentation, TEST-NET-2
        "203.0.113.1",     // documentation, TEST-NET-3
        "192.88.99.1",     // deprecated 6to4 relay anycast
        "198.18.0.1",      // benchmarking
        "240.0.0.1",       // reserved
        "255.255.255.255", // limited broadcast, the last address of the reserved block
        "224.0.0.1",       // multicast
        "[fd00::1]",       // IPv6 unique local
        "printer.local",   // mDNS, and a name rather than an address
    ] {
        assert!(!rules.matches_authority(authority), "{authority}");
    }
}

/// A trailing dot on the *destination* is the DNS root marker and must not defeat an
/// otherwise-matching bypass pattern — `HostPattern::matches` strips it for
/// `Exact`/`Domain`/`Wildcard` the same way `HostPattern::parse` strips it from the
/// pattern itself. `Local` is deliberately not exercised here: a trailing dot still
/// counts as "has a period" for the `<local>` / `ExcludeSimpleHostnames` rule.
#[test]
fn trailing_dots_on_the_destination_do_not_defeat_a_match() {
    // A subdomain-only pattern still matches a subdomain spelled with a trailing dot.
    let subdomain_only = parse::no_proxy(".corp.example");
    assert!(subdomain_only.matches_authority("www.corp.example."));
    // `match_self = false`, so the bare domain must still not match, trailing dot or not.
    assert!(!subdomain_only.matches_authority("corp.example"));
    assert!(!subdomain_only.matches_authority("corp.example."));

    // A bare-domain pattern (`match_self = true`) matches the same domain spelled with a
    // trailing dot.
    let bare_domain = parse::no_proxy("corp.example");
    assert!(bare_domain.matches_authority("corp.example."));
    assert!(bare_domain.matches_authority("corp.example"));

    // A glob that `parse` cannot fold into `Domain` — the `*` is inside a label rather
    // than the whole first one — so this is the `Wildcard` arm and nothing else. The
    // pattern carries no trailing dot, so a destination that does can only match once the
    // arm has stripped it.
    let wildcard = parse::no_proxy("w*.corp.example");
    assert!(wildcard.matches_authority("www.corp.example."));
    assert!(wildcard.matches_authority("www.corp.example"));
    assert!(!wildcard.matches_authority("api.corp.example."));

    // The `Exact` arm, which the doc above named first and nothing below it reached: the
    // same bare name read from a Windows list, where a bare name is `Exact` and not
    // `Domain`. Its strip is a second one — the arm reaches the text comparison only when
    // one of the two sides is not an address, which is exactly the bare-name shape.
    let windows_bare = parse::proxy_override("corp.example");
    assert_eq!(
        windows_bare.patterns,
        vec![HostPattern::Exact {
            host: Host::Domain("corp.example".to_owned()),
            port: None,
        }]
    );
    assert!(windows_bare.matches_authority("corp.example."));
    assert!(windows_bare.matches_authority("corp.example"));
    // Still exact: the root dot is shed, not treated as a suffix boundary.
    assert!(!windows_bare.matches_authority("www.corp.example."));
}

/// `<-loopback>` subtracts the *whole* implicit bypass set, not the loopback half of it.
/// Chromium's `net/docs/proxy.md` lists that set as "localhost, `*.localhost`, `[::1]`,
/// 127.0.0.1/8, 169.254/16, `[FE80::]/10`" and says the token "Subtracts the implicit proxy
/// bypass rules (localhost and link local addresses)" — one rule, both families.
///
/// The opposite reading — one rule for loopback, link-local left alone — justifies itself
/// by saying a proxy cannot reach an address that exists only on the client's own link.
/// `169.254.169.254` is the counterexample that makes that a defect rather than a
/// divergence: the cloud instance-metadata endpoint is link-local, a proxy on the same host
/// reaches it, and routing it through an inspecting proxy is a common reason to set
/// `<-loopback>` in the first place. Answering Direct for it sent the one destination the
/// setting exists to catch past the proxy.
#[test]
fn no_loopback_token_clears_the_whole_implicit_bypass_set() {
    let rules = parse::proxy_override("<-loopback>");
    assert!(!rules.bypass_loopback());

    for authority in [
        // Loopback family.
        "localhost",
        "127.0.0.1",
        "[::1]",
        "app.localhost",
        "localhost.",
        "[::ffff:127.0.0.1]",
        // Link-local, including the address the old rule mattered most for.
        "169.254.1.1",
        "169.254.169.254",
        "[fe80::1]",
        "[::ffff:169.254.169.254]",
    ] {
        assert!(!rules.matches_authority(authority), "{authority}");
    }

    // Without the token the whole set is still bypassed, so the rows above are the
    // token's doing and not a list that matches nothing.
    let default = parse::proxy_override("");
    for authority in ["localhost", "169.254.169.254", "[fe80::1]"] {
        assert!(default.matches_authority(authority), "{authority}");
    }
}

/// `<-loopback>` subtracts the implicit set from the entries written *before* it and from
/// none written after it, because a bypass list is evaluated left to right with the later
/// entry winning: "Later rules override earlier rules … when mixing positive and negative
/// rules, evaluation order makes a difference"
/// (Chromium, `net/base/scheme_host_port_matcher.cc`). The expectation is not Chromium's
/// own invention — its two ordering tests both say it "comes from WinInet (which is where
/// `<-loopback>` comes from)" (`proxy_host_matching_rules_unittest.cc`,
/// `RemoveImplicitAndAddLocalhost` / `AddLocalhostThenRemoveImplicit`) — and Microsoft
/// documents the same for the dialect Edge inherits: "Ordering may matter when using a
/// subtractive rule, as rules will be evaluated in a left-to-right order.
/// `<-loopback>;127.0.0.1` has a subtly different effect than `127.0.0.1;<-loopback>`"
/// (<https://learn.microsoft.com/en-us/deployedge/configure-microsoft-edge-proxy-support>).
///
/// Reading the token as a switch beside an unordered pattern set answered Direct for both
/// spellings, so `127.0.0.1;<-loopback>` — a list whose author asked for loopback to go
/// through the proxy — reported a bypass the stack does not have.
#[test]
fn no_loopback_only_subtracts_from_the_entries_written_before_it() {
    // Microsoft's own pair, verbatim.
    let subtract_last = parse::proxy_override("127.0.0.1;<-loopback>");
    assert!(!subtract_last.matches_authority("127.0.0.1"));

    let subtract_first = parse::proxy_override("<-loopback>;127.0.0.1");
    assert!(subtract_first.matches_authority("127.0.0.1"));
    // Only the entry that names it comes back; the rest of the implicit set stays gone.
    assert!(!subtract_first.matches_authority("localhost"));
    assert!(!subtract_first.matches_authority("169.254.169.254"));

    // Chromium's `AddLocalhostThenRemoveImplicit` and `RemoveImplicitAndAddLocalhost`, by
    // name rather than by address.
    assert!(!parse::no_proxy("localhost,<-loopback>").matches_authority("localhost"));
    assert!(parse::no_proxy("<-loopback>,localhost").matches_authority("localhost"));

    // A destination outside the implicit set never meets the negative entry, so its
    // position cannot matter there.
    for spec in ["www.example.com,<-loopback>", "<-loopback>,www.example.com"] {
        assert!(
            parse::no_proxy(spec).matches_authority("www.example.com"),
            "{spec}"
        );
    }

    // The repeat is not a repeat: collapsing the second `localhost` into the first would
    // hand the verdict to the token between them.
    let readded = parse::no_proxy("localhost,<-loopback>,localhost");
    assert_eq!(readded.patterns.len(), 3);
    assert!(readded.matches_authority("localhost"));
    assert!(!readded.matches_authority("127.0.0.1"));
}

/// `matches` opens with the rule that a host with no text answers `false` before anything
/// else is consulted, "in both modes", and its doc says who that is for: a caller who
/// assembled the `Host` themselves. Nothing in this crate asks — `resolve` sends a hostless
/// URL direct long before the bypass list is reached, and `matches_url` and
/// `matches_authority` both turn one away at the door — so the early return is the whole of
/// the rule and there is nothing under it.
///
/// Dropping it leaves every suite green while three separate readings flip to "bypasses":
/// `HostPattern::All` matches an empty host the way it matches every other one, and under
/// `reversed_exceptions` an empty host is absent from the inclusion list and so reads as
/// unnamed — which is the bypass — whether the list is empty or full.
#[test]
fn a_host_with_no_text_never_bypasses() {
    let nothing = Host::Domain(String::new());

    for spec in ["*", "", "localhost", ".example.com"] {
        assert!(!parse::no_proxy(spec).matches(&nothing, None), "{spec}");

        let mut reversed = parse::no_proxy(spec);
        reversed.reversed_exceptions = true;
        assert!(!reversed.matches(&nothing, None), "{spec} reversed");
    }

    // The controls, one for each shape that flipped: both of these lists do bypass a host
    // that has text, so the rows above are the empty host and not rule sets that match
    // nothing.
    assert!(parse::no_proxy("*").matches_authority("example.org"));
    let mut reversed_empty = parse::no_proxy("");
    reversed_empty.reversed_exceptions = true;
    assert!(reversed_empty.matches_authority("example.org"));
}

/// `HostPattern::Domain`'s field doc promises that a suffix naming no domain matches no
/// destination — "an empty one names none and so matches nothing" — and the fields are
/// public, so that is a contract rather than a description of what `parse` builds. `parse`
/// never builds one: it answers `Ok(None)` for `.` and `..`.
///
/// One `!bare.is_empty()` in `matches` keeps the promise, and this test is the only thing
/// holding it. What it lets through needs a hand-built pattern but *not* a hand-built
/// destination, which is the half
/// that makes it worth a test: `url` reads `http://example.com../` as
/// `Host::Domain("example.com..")`, `matches` sheds one trailing dot, and a suffix that
/// strips nothing leaves the whole of the rest still ending in one — which is the
/// `ends_with('.')` half of the same predicate. A rule naming no domain then bypasses a URL.
#[test]
fn a_domain_suffix_that_names_nothing_matches_nothing() {
    // The destination side, asserted as a premise: this is an ordinary URL, and the double
    // dot survives into the host rather than being an error or normalised away.
    let doubled = url::Url::parse("http://example.com../").unwrap();
    assert_eq!(doubled.host_str(), Some("example.com.."));

    // Both spellings of "names nothing": the empty suffix, and the lone dot that the
    // leading-dot convention reduces to it.
    for suffix in ["", "."] {
        for match_self in [false, true] {
            let mut rules = BypassRules::new();
            rules.patterns.push(HostPattern::Domain {
                suffix: suffix.to_owned(),
                match_self,
                port: None,
            });
            let label = format!("{suffix:?} match_self={match_self}");

            assert!(!rules.matches_url(&doubled), "{label}");
            assert!(
                !rules.matches(&Host::Domain("a..".to_owned()), None),
                "{label}"
            );
            // The destinations that never reached the predicate either way.
            assert!(!rules.matches_authority("example.com"), "{label}");
            assert!(!rules.matches_authority("intranet"), "{label}");
        }
    }

    // The control for the whole test: a suffix that does name a domain still matches the
    // doubled-dot destination, so the rows above are the empty name and not a `Domain` arm
    // that has stopped working.
    let mut named = BypassRules::new();
    named.patterns.push(HostPattern::Domain {
        suffix: ".example.com.".to_owned(),
        match_self: true,
        port: None,
    });
    assert!(named.matches_url(&doubled));
}

/// `exclude_simple_hostnames` is a switch and `<-loopback>` is an entry, and `matches`
/// consults the switch first — so on the one destination both can speak about, the entry
/// still has to win. Chromium is why: it models the switch as a rule *prepended* to the
/// list (`PrependRuleToBypassSimpleHostnames`, `proxy_config_service_mac.cc`), which puts
/// every written entry after it, and back-to-front evaluation gives the last word to the
/// entry.
///
/// Only a dot-less name that is also in the implicit set — `localhost`, `loopback` — is
/// reachable both ways, and nothing else in this file happens to build that pair, so one
/// clause in `matches` carried the whole rule with no test on it. Deleting the clause left
/// every suite green while `localhost` flipped to direct on a list whose author wrote the
/// one token that exists to stop exactly that.
#[test]
fn no_loopback_still_wins_against_the_simple_hostname_switch() {
    let mut rules = parse::proxy_override("<-loopback>");
    rules.exclude_simple_hostnames = true;

    // Dot-less and in the implicit set: the entry decides, and it subtracts.
    assert!(!rules.matches_authority("localhost"));
    assert!(!rules.matches_authority("loopback"));

    // Dot-less and outside it: no entry has anything to say about it, so the switch stands.
    assert!(rules.matches_authority("intranet"));

    // The two controls. Without the token the switch bypasses the same name, and without
    // the switch the token still proxies it — so the rows above are the two of them
    // meeting, not either one of them alone.
    let mut switch_only = BypassRules::new();
    switch_only.exclude_simple_hostnames = true;
    assert!(switch_only.matches_authority("localhost"));
    assert!(!parse::proxy_override("<-loopback>").matches_authority("localhost"));
}

/// Under `reversed_exceptions` the list is the set that *uses* the proxy, so a destination
/// no entry names bypasses — and the implicit set is not inverted, because an inclusion list
/// that never mentioned loopback has not asked for loopback to be proxied. `matches` closes
/// on `implicit || unnamed`; `<-loopback>` is what removes the first term, leaving the
/// destination to the ordinary reading for one the list does not name, which under a
/// reversed list is still direct.
///
/// Reachable from KDE, the one source that reverses (`sys/linux/kioslaverc.rs`): a
/// `ReversedException=true` beside a `NoProxyFor` carrying the token. The value returned
/// there was pinned from neither side — a flat `false` proxies a destination the inclusion
/// list never named, a flat `true` sends one direct out of a list too broken to say — so
/// both are held below.
#[test]
fn no_loopback_in_a_reversed_list_leaves_loopback_to_the_unnamed_reading() {
    let mut rules = parse::no_proxy("<-loopback>,intranet.corp");
    rules.reversed_exceptions = true;

    // Named by the inclusion list, so it keeps the proxy.
    assert!(!rules.matches_authority("intranet.corp"));
    // Unnamed, which under a reversed list is the bypass.
    assert!(rules.matches_authority("www.example.com"));
    // Implicit *and* unnamed: the token took the implicit bypass away, and what is left
    // sends it direct all the same. This is the row that separates the answer from `false`.
    assert!(rules.matches_authority("127.0.0.1"));

    // And this is the row that separates it from `true`: an entry that would not parse
    // leaves the inclusion list incomplete, and an incomplete one may not send anything
    // direct — the token in front of it does not exempt it from that.
    let mut with_rejected = parse::no_proxy("<-loopback>,intranet.corp,a..b");
    with_rejected.reversed_exceptions = true;
    assert!(!with_rejected.rejected.is_empty());
    assert!(!with_rejected.matches_authority("127.0.0.1"));
}

/// `excludes_simple_hostnames` answers `true` for either spelling of the dot-less host
/// rule, and until a list is reversed the two agree. They cannot agree after that,
/// because one is a switch and the other is a list entry: macOS `ExcludeSimpleHostnames`
/// bypasses dot-less hosts the way the implicit set does, before the list is read, while
/// `<local>` inside a KDE inclusion list names dot-less hosts as the ones that must
/// *keep* using the proxy. Both readings follow from what the two things are, so the
/// defect this pins is the tempting refactor — normalising one representation into the
/// other, which the accessor's old wording invited and which silently flips the verdict.
#[test]
fn the_switch_and_the_pattern_spelling_of_local_diverge_once_a_list_is_reversed() {
    let mut as_pattern = parse::no_proxy("<local>");
    as_pattern.reversed_exceptions = true;

    let mut as_switch = proxy_watch::BypassRules::new();
    as_switch.exclude_simple_hostnames = true;
    as_switch.reversed_exceptions = true;

    // The accessor reports both, and says nothing about the verdict.
    assert!(as_pattern.excludes_simple_hostnames());
    assert!(as_switch.excludes_simple_hostnames());

    // The verdict for a dot-less host is the opposite one.
    assert!(!as_pattern.matches_authority("intranet"));
    assert!(as_switch.matches_authority("intranet"));

    // A dotted host is unlisted under both, so both send it direct.
    assert!(as_pattern.matches_authority("www.example.com"));
    assert!(as_switch.matches_authority("www.example.com"));

    // Unreversed, the two spellings do agree — which is why the divergence hides.
    let mut unreversed_switch = proxy_watch::BypassRules::new();
    unreversed_switch.exclude_simple_hostnames = true;
    assert!(parse::no_proxy("<local>").matches_authority("intranet"));
    assert!(unreversed_switch.matches_authority("intranet"));
}

/// `<local>` and `<-loopback>` are WinInet syntax, but Chromium "allow[s] it on all
/// platforms and interpret[s] it the same way" (`proxy_host_matching_rules.cc:113`) and runs the
/// `no_proxy` environment variable through the same parser, so `parse::no_proxy` and
/// `parse::proxy_override` read them alike. Go, the declared reference for `no_proxy`,
/// does not know the tokens, so this is one place the environment dialect follows Chromium
/// and not its own reference. What the two dialects *do* split on is
/// the separator set below and the bare name, which is
/// [`a_bare_name_in_a_windows_list_is_the_one_host`].
#[test]
fn both_bypass_list_dialects_read_the_wininet_tokens() {
    for spec in ["<local>,<-loopback>", "<LOCAL>,<-LoopBack>"] {
        let from_env = parse::no_proxy(spec);
        let from_registry = parse::proxy_override(spec);
        assert_eq!(from_env, from_registry, "{spec}");
        assert!(from_env.excludes_simple_hostnames(), "{spec}");
        assert!(!from_env.bypass_loopback(), "{spec}");
        assert!(from_env.matches_authority("intranet"), "{spec}");
        assert!(!from_env.matches_authority("www.example.com"), "{spec}");
        // `localhost` answers to both tokens — dot-less, and in the implicit set — so it
        // is the row where the order decides, and `<-loopback>` is written last here.
        // Do not read the pair as order-free switches — that sends `localhost` direct, a
        // bypass neither reader of this dialect grants; the case is
        // [`no_loopback_only_subtracts_from_the_entries_written_before_it`].
        assert!(!from_env.matches_authority("localhost"), "{spec}");
        assert!(!from_env.matches_authority("127.0.0.1"), "{spec}");
    }

    // Whitespace is the difference, and it is the registry dialect's alone. In the
    // environment dialect the same string is a single entry with a space inside it, which
    // is not a host name — rejected rather than silently kept as a rule matching nothing.
    assert_eq!(
        parse::proxy_override("a.example b.example").patterns.len(),
        2
    );
    let as_env = parse::no_proxy("a.example b.example");
    assert!(as_env.patterns.is_empty());
    assert_eq!(as_env.rejected.len(), 1);
}

/// A bare name is the whole of the difference between the two dialects' *matching*, and
/// nothing here held it: the Windows readers went through the suffix rule with every test
/// in this file green, so `ProxyOverride=contoso.com` bypassed `api.contoso.com` — a
/// destination the machine sends through the proxy, reported as direct.
///
/// Measured rather than inherited. Chromium matches exactly and libproxy matches the
/// subdomains, from the same registry value, so neither settles it; WinINet and WinHTTP
/// were each handed the list and asked where they connected, and both bypass the name
/// alone. The rows below are the readings from that run, minus the ones about separators
/// and case.
#[test]
fn a_bare_name_in_a_windows_list_is_the_one_host() {
    let windows = parse::proxy_override("contoso.com");
    assert!(windows.matches_authority("contoso.com"));
    assert!(!windows.matches_authority("api.contoso.com"));
    // Not a string suffix either, which is the row that says the one above is the
    // subdomain rule going away and not some narrower quirk.
    assert!(!windows.matches_authority("xcontoso.com"));
    assert!(!windows.matches_authority("other.example"));

    // Same text, other dialect, other rule. Go's `httpproxy`, GLib and libproxy all
    // suffix-match, so this is the majority reading and Windows is the exception.
    let env = parse::no_proxy("contoso.com");
    assert!(env.matches_authority("contoso.com"));
    assert!(env.matches_authority("api.contoso.com"));

    // The glob spellings are unchanged, and they are how a Windows list reaches the
    // subdomains at all. `*` spans dots and does not reach the bare name.
    let glob = parse::proxy_override("*.contoso.com");
    assert!(glob.matches_authority("api.contoso.com"));
    assert!(glob.matches_authority("a.b.contoso.com"));
    assert!(!glob.matches_authority("contoso.com"));

    // Ports still restrict, and an address is one host under either dialect.
    let ported = parse::proxy_override("contoso.com:80");
    assert!(ported.matches_authority("contoso.com:80"));
    assert!(!ported.matches_authority("contoso.com:81"));
    assert!(parse::proxy_override("10.0.0.1").matches_authority("10.0.0.1"));
}

/// `HostPattern::Domain`'s fields are public and `BypassRules::new` returns an empty list
/// to be filled in, so "stored with a leading dot" is `parse`'s convention rather than an
/// invariant the type can hold. Reading a hand-built pattern therefore has to be total:
/// an empty suffix used to match every host — and to panic in `Display` — while a
/// non-ASCII first character panicked on a byte index that is not a char boundary.
#[test]
fn a_hand_built_domain_pattern_is_read_as_the_domain_it_names() {
    let built = |suffix: &str, match_self: bool| {
        let mut rules = proxy_watch::BypassRules::new();
        rules.patterns.push(HostPattern::Domain {
            suffix: suffix.to_owned(),
            match_self,
            port: None,
        });
        rules
    };

    // Naming no domain bypasses nothing. The other direction is the dangerous one: in a
    // list whose entries turn the proxy off, a catch-all is how traffic leaves unproxied.
    let empty = built("", true);
    assert!(!empty.matches_authority("example.com"));
    assert!(!empty.matches_authority(""));
    assert_eq!(empty.patterns[0].to_string(), "");

    // A missing leading dot is the same rule, not a byte to throw away.
    for suffix in [".example.com", "example.com"] {
        let rules = built(suffix, true);
        assert!(rules.matches_authority("example.com"), "{suffix}");
        assert!(rules.matches_authority("www.example.com"), "{suffix}");
        assert!(!rules.matches_authority("myexample.com"), "{suffix}");
        assert_eq!(rules.patterns[0].to_string(), "example.com", "{suffix}");
    }

    // `match_self = false` still excludes the bare domain, whichever way it is spelled —
    // and so does its display, read back. The dotless spelling the field doc blesses used
    // to print `example.com`, which `parse` reads as `match_self = true`: a caller who
    // logged a hand-built rule set and fed it back got the bare domain bypassed too,
    // widening the exclusion list every time it made the trip.
    for suffix in [".example.com", "example.com"] {
        let rules = built(suffix, false);
        assert!(!rules.matches_authority("example.com"), "{suffix}");
        assert!(rules.matches_authority("www.example.com"), "{suffix}");

        let shown = rules.patterns[0].to_string();
        assert_eq!(shown, ".example.com", "{suffix}");
        let reread = parse::no_proxy(&shown);
        assert!(!reread.matches_authority("example.com"), "{suffix}");
        assert!(reread.matches_authority("www.example.com"), "{suffix}");
    }

    // Total on the empty suffix in this direction too: `.` names no domain, and reading it
    // back drops the entry rather than widening it.
    assert_eq!(built("", false).patterns[0].to_string(), ".");
    assert!(parse::no_proxy(".").patterns.is_empty());

    assert!(!built("。example.com", true).matches_authority("example.com"));
}

/// The same byte index from the other side. Above, the non-ASCII text is the rule's and
/// is longer than the destination, so the subtraction that picks the split point fails
/// before any slicing happens. A *destination* longer than the rule reaches the slice,
/// and lands inside a character whenever the excess bytes are part of one —
/// `strip_suffix_ascii_case` answers `false` there, because a suffix cannot begin on a
/// continuation byte.
///
/// `BypassRules::matches` is the way in: it takes a `Host` the caller built rather than
/// one this crate parsed, and `host_key` hands a name with no punycode spelling through
/// as written rather than dropping it.
#[test]
fn a_non_ascii_destination_does_not_panic_against_a_shorter_domain_rule() {
    // A `*` in a non-ASCII label has no punycode spelling, so this text survives
    // `host_key` unchanged: twelve bytes, the middle character spanning bytes 1..4.
    let destination = Host::Domain("*\u{30a2}.example".to_owned());
    // Ten bytes of rule against twelve of destination splits at byte 2, inside that
    // character.
    let rules = parse::no_proxy(".xx.example");
    assert!(!rules.matches(&destination, None));
    // The rule that does name it still matches, so the guard above is not answering
    // `false` for every non-ASCII destination.
    assert!(parse::no_proxy(".example").matches(&destination, None));
}

/// [`HostPattern`]'s `Display` mirrors the grammar [`HostPattern::parse`] reads, down to
/// the leading dot that encodes `match_self`, so rendering a rule and reading it back is
/// the same rule, and this test is the only thing holding it. Dropping the `match_self`
/// arm of the `Display` —
/// which reads like a simplification, since the other arm strips the same dot — turns
/// `.example.com` ("subdomains only") into `example.com` ("and the bare domain too") and
/// leaves every other test in this tree passing.
///
/// The consequence is the one this file keeps naming: under a `no_proxy` list the bare
/// domain starts bypassing the proxy the administrator excluded it from, and under
/// [`proxy_watch::BypassRules::reversed_exceptions`] the same widening runs the other way.
///
/// The list level is checked too, because that is the shape a caller actually uses —
/// render the effective rules, paste them back — and it is where a `Display` that emitted
/// a separator would show up.
#[test]
fn rendering_a_pattern_and_reading_it_back_gives_the_same_rule() {
    const ENTRIES: &[&str] = &[
        "*",
        "<local>",
        "10.0.0.0/30",
        "2002:db8:a::45/64",
        "::ffff:10.0.0.0/104",
        "192.168.1.1",
        "192.168.1.2:81",
        "[2001:db8::1]",
        "[2001:db8::2]:81",
        "example.com",
        ".example.com",
        "*.example.com",
        "example.com:8080",
        ".example.com:8080",
        "*.foo*.example.com",
        ".*.example.com",
        "10.0.0.1:80",
        "EXAMPLE.COM",
        "example.com.",
        "*10.0.0.1",
        "日本.example",
        "[::ffff:10.0.0.1]",
        "0.0.0.0/0",
        "10.0.0.1/32",
        "*.example.com:8080",
        "010.0.0.1",
        "192.168.1",
        "*.*",
        "a.b.c.d.e.f",
        ".co.uk:443",
        "*x*",
    ];
    let mut bad = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for entry in ENTRIES {
        let once = HostPattern::parse(entry).unwrap().unwrap();
        seen.insert(match &once {
            HostPattern::All => "All",
            HostPattern::Cidr(_) => "Cidr",
            HostPattern::Exact { .. } => "Exact",
            HostPattern::Domain {
                match_self: true, ..
            } => "Domain/self",
            HostPattern::Domain { .. } => "Domain/subdomains",
            HostPattern::Wildcard { .. } => "Wildcard",
            HostPattern::Local => "Local",
            _ => "other",
        });
        let shown = once.to_string();
        match HostPattern::parse(&shown) {
            Ok(Some(twice)) if twice == once => {}
            other => bad.push(format!(
                "{entry:?} -> {shown:?} -> {other:?}  (was {once:?})"
            )),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    // Coverage on purpose rather than by accident: an edit to the table above that stopped
    // producing one of the shapes would otherwise narrow this test in silence.
    assert_eq!(
        seen.iter().copied().collect::<Vec<_>>(),
        [
            "All",
            "Cidr",
            "Domain/self",
            "Domain/subdomains",
            "Exact",
            "Local",
            "Wildcard",
        ]
    );

    // List level: what a user would actually do — log the effective rules, paste them back.
    let spec = ENTRIES.join(",");
    let first = parse::no_proxy(&spec);
    let shown = first
        .patterns
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let second = parse::no_proxy(&shown);
    assert_eq!(
        second.patterns, first.patterns,
        "\nfirst : {:?}\nshown : {shown}\nsecond: {:?}",
        first.patterns, second.patterns
    );
    assert!(second.rejected.is_empty(), "{:?}", second.rejected);
}

// A bypass list is OS-sourced, not caller-sourced: `no_proxy` from the environment,
// `ProxyOverride` from a registry key group policy writes, `ExceptionsList` from `configd`.
// None of the three caps its length, and asking `Vec::contains` in `push_pattern` before
// every push makes a list of distinct entries quadratic: 16,000 entries (293 KB, well
// inside what a Linux environment block holds) take 37.1 s in a debug build and 2.9 s in
// release, quadrupling on every doubling from 184 ms at 1,000. The repeated-entry case is
// never the slow one — duplicates keep the vector at one entry, so the scan it walks never
// grows.
//
// That 184 ms is the per-entry cost with the quadratic term still small, so the linear
// parse this does instead costs about 2.9 s for 16,000 — 2.9 s to 5.1 s here, load
// included. The bound is placed between that and the 37.1 s, near enough to the quadratic
// figure to still fail on it and far enough from the linear one that a loaded machine
// does not.
#[test]
fn a_long_list_of_distinct_entries_does_not_stall_the_parse() {
    let spec = (0..16_000)
        .map(|i| format!("h{i}.example.com"))
        .collect::<Vec<_>>()
        .join(",");
    let start = std::time::Instant::now();
    let rules = parse::no_proxy(&spec);
    let elapsed = start.elapsed();
    assert_eq!(rules.patterns.len(), 16_000, "entries were lost");
    assert!(
        rules.rejected.is_empty(),
        "{:?}",
        rejected_texts(&rules.rejected)
    );
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "parsing {} entries took {elapsed:?}",
        rules.patterns.len()
    );
}

/// The text after a wildcard's last `*` is a *suffix* of the name, not something the name
/// merely contains — and the text before its first `*` is a prefix the same way. `glob_match`
/// decides that for every [`HostPattern::Wildcard`] in the crate, and reading either anchor as
/// containment widens the rule past what its author controls: `w*.corp` would then exclude
/// `wx.corp.evil` from the proxy, sending traffic direct to a host somebody else named.
#[test]
fn a_wildcards_literal_text_anchors_at_both_ends() {
    let rules = parse::no_proxy("w*.corp");
    assert!(rules.matches_authority("wx.corp"));
    assert!(!rules.matches_authority("wx.corp.evil"));
    assert!(!rules.matches_authority("evil-wx.corp"));
}

// The collapse itself still has to happen, whichever way the membership test is written.
#[test]
fn repeated_entries_still_collapse_to_one_pattern() {
    let rules = parse::no_proxy("a.example.com,b.example.com,a.example.com");
    assert_eq!(rules.patterns.len(), 2);
    assert_eq!(rules.patterns[0].to_string(), "a.example.com");
    assert_eq!(rules.patterns[1].to_string(), "b.example.com");
}
