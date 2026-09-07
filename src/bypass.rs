//! Bypass ("no proxy") rules.
//!
//! What an entry may look like comes from Go
//! [`httpproxy`](https://github.com/golang/net/blob/master/http/httpproxy/proxy.go); what one
//! *matches* follows Chromium wherever the readers disagree, which is what makes an embedded
//! `*` a glob here. So the `Suffix` dialect is their union rather than a port of either —
//! [`BypassDialect`] carries the measurement. Windows `<local>` / `<-loopback>` on top.
//!
//! One rule is not shared: a bare name covers the subdomains everywhere except in a
//! Windows list, where it matches that name alone. See
//! [`parse::proxy_override`](crate::parse::proxy_override).

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net};
use url::{Host, Url};

use crate::diagnostic::{RejectedValue, RejectionKind, RejectionSource};
use crate::error::Error;
use crate::util::{glob_match, redact_offending_token, split_host_port, strip_brackets};

/// A single entry of a bypass list.
///
/// | Source | Variant |
/// |---|---|
/// | `*` | [`HostPattern::All`] (not from a macOS or GNOME list, where it names nothing) |
/// | CIDR | [`HostPattern::Cidr`] |
/// | IP / `host:port` | [`HostPattern::Exact`] |
/// | `example.com` / `.example.com` / `*.example.com` | [`HostPattern::Domain`] |
/// | `192.168.*` | [`HostPattern::Wildcard`] |
/// | `<local>` | [`HostPattern::Local`] |
/// | `<-loopback>` | [`HostPattern::SubtractImplicit`] |
///
/// The bare-name row is the one that depends on where the list came from: a Windows
/// list reads `example.com` as [`HostPattern::Exact`], because that is what Windows
/// matches. [`parse::proxy_override`](crate::parse::proxy_override) has the readings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HostPattern {
    /// Matches every host: a bare `*` in the list disables proxying entirely.
    All,
    /// Matches any address inside an IP network.
    Cidr(IpNet),
    /// Literal host, optionally port-restricted.
    ///
    /// [`parse`](Self::parse) reaches it only for an address literal, but
    /// [`parse::proxy_override`](crate::parse::proxy_override) reaches it for every bare
    /// name: a bare entry in a Windows list matches that name and nothing under it.
    ///
    /// Its [`Display`](std::fmt::Display) is the name alone, which is also how a suffix
    /// rule for the same domain is written. Reading that text back therefore gives this
    /// variant through `proxy_override` and a [`Domain`](Self::Domain) covering the
    /// subdomains through [`parse::no_proxy`](crate::parse::no_proxy) — the same text,
    /// two rules — so a pattern displayed and re-read through the *other* dialect widens.
    /// Hold the value instead of its text if that matters.
    Exact {
        /// Host to match.
        host: Host,
        /// Optional port restriction.
        port: Option<u16>,
    },
    /// Domain suffix (stored with a leading dot).
    Domain {
        /// Suffix (e.g. `.example.com`). A hand-built one without the dot names the
        /// same domain; an empty one names none and so matches nothing. Case is folded
        /// at match time, so [`parse`](Self::parse)'s lowercasing is a normalisation and
        /// not a precondition.
        suffix: String,
        /// Whether the bare domain matches too.
        match_self: bool,
        /// Optional port restriction.
        port: Option<u16>,
    },
    /// Windows-style glob with `*`.
    ///
    /// A plain `*.example.com` is not one: it is the same rule as `.example.com` and parses
    /// to [`Domain`](Self::Domain). A leading `*.` does reach this variant when the rest
    /// still holds a glob (`*.a*b.com`), and so does the `*` this parse writes in front of a
    /// leading-dot glob (`.*.example.com` is stored as `*.*.example.com`).
    ///
    /// Matched as text against the destination's canonical spelling, so a glob written
    /// around a non-canonical address (`*192.168.001.001`, which arrives as `192.168.1.1`)
    /// matches nothing. Unlike the other variants, such a glob is not refused during
    /// parsing and so does not reach [`BypassRules::rejected`]: `*` stands for the empty
    /// string as well as for text, which leaves `*10.0.0.1` live and every test that
    /// separates the two cases open to a counterexample.
    Wildcard {
        /// Glob pattern. [`parse`](Self::parse) lowercases it, and a hand-built one that
        /// is not lowercased matches the same hosts anyway: case is folded at match time.
        pattern: String,
        /// Optional port restriction.
        port: Option<u16>,
    },
    /// Windows `<local>` / macOS `ExcludeSimpleHostnames`: any host name without a dot.
    Local,
    /// Windows `<-loopback>`: the one entry that takes a bypass away instead of adding
    /// one. It subtracts the implicit set — loopback *and* link-local, see
    /// [`NO_LOOPBACK_TOKEN`] — from every entry written before it, and from none written
    /// after it, which is why it is an entry in [`BypassRules::patterns`] and not a
    /// switch beside them. [`BypassRules::matches`] has the evaluation order.
    SubtractImplicit,
}

// Which list an entry came from, for the places the lists disagree about what an entry
// means. Named after the source rather than after a behaviour, because no two of them
// differ from `Suffix` on the same set of axes: `Windows` on three, `MacOs` and `Gnome` on
// four each and not the same four — and `MacOs` shares one of the three `Windows` axes
// while disagreeing with it everywhere else.
//
// `Suffix` reads a bare name as the name and everything under it, and a leading `*.` or `.`
// as the subdomains alone. That much is Go's `httpproxy` with `no_proxy` and libproxy's with
// KDE's `NoProxyFor` (`px-manager.c:736,752`, reached from `config-kde.c`), and it is why a
// bare name here is not the name alone the way it is under `Windows` and `MacOs`.
//
// A `*` anywhere else is a glob, and that half is *not* those two. `config.init` in
// `http/httpproxy/proxy.go` special-cases a bare `*` and strips one character off a leading
// `*.`; what is left goes to a `domainMatcher` that compares with `strings.HasSuffix`, so no
// star past the first is syntax. libproxy's `ignore_domain` (`px-manager.c`) reads four
// shapes and no more — the bare `*`, an exact name, and the two suffix spellings `.name`
// and `*.name`. Under both, `192.168.*` and `*.*.*.1` are literal text no host carries,
// so they match nothing. Neither refuses a CIDR entry, though — it leaves the name rules
// before it reaches them. `config.init` tries `net.ParseCIDR` first, and libproxy tries
// `ignore_ip` after `ignore_domain` (`px-manager.c:848`), which masks an entry holding a
// `/` with `g_inet_address_mask_new_from_string` against an address literal only.
//
// The star is read as a glob because the third reader of these same two lists reads it that
// way. Chromium hands `no_proxy` and KDE's `NoProxyFor` to the same
// `ProxyHostMatchingRules::ParseFromString` (`proxy_config_service_linux.cc:230`), which builds a
// `SchemeHostPortMatcherHostnamePatternRule` for everything that is not a CIDR or an address
// literal and evaluates it with `base::MatchPattern`
// (`scheme_host_port_matcher_rule.cc:99,139`) — a glob, and the source of the leading-dot
// rewrite the `Wildcard` arm in `parse_in` already quotes.
//
// So this dialect is the union of the two readings rather than either one, and the union is
// the wider answer — the one that reaches `Direct` more often. `*.*.*.1` is met by
// `10.0.0.1` here and by `base::MatchPattern`; the two suffix readers send that request to
// the proxy. The union is kept because narrowing it would leave a rule someone typed a `*`
// into matching nothing while still reading back as live, which is the shape `Gnome` below
// refuses outright rather than store.
//
// `Windows` differs in three places. A bare name is the name alone, measured on this
// crate's own terms rather than read off a reimplementation, because the two
// reimplementations disagree and neither is the OS; the readings are the rows of
// `a_bare_name_in_a_windows_list_is_the_one_host` in `tests/bypass.rs`. And the two
// spellings a Windows list has no reading for — an entry holding a `/`, and an entry
// starting with `.` — are refused rather than stored as rules the machine does not honour.
// Each has a guard in `parse_in` carrying its readings and the vendor sentence.
//
// `MacOs` is CFNetwork's `ExceptionsList`, measured the same way and by the same argument —
// `tests/mac_exceptions_list.rs` hands `CFNetworkCopyProxiesForURL` a settings dictionary
// and reads the verdict off the matcher itself, so Chromium's macOS reader is not consulted:
// it is a reimplementation and not the OS. It agrees with `Windows` that a bare name is the
// name alone, and differs from every other dialect here on three more:
//
//   * a `*` is syntax only as a leading `*.` or a trailing `.*`, and a character everywhere
//     else — so `*probe*`, `*invalid`, `pw-*.invalid` and a bare `*` match nothing. The
//     bare `*` is the one that matters: read as `HostPattern::All` it turns the proxy off
//     for every destination on a Mac that proxies all of them.
//   * a `:port` does not constrain an entry, it kills it. `example.com:80` matched no
//     destination on port 80, and `example.com` matched one that carried a port, so the
//     port is not part of the comparison at all.
//   * neither end is trimmed, which is `trim` below rather than an arm here: a space in
//     front of a name or behind it kills the entry the same way a `*` in the middle does.
//
// Two things it does *not* differ on are left alone deliberately. `<local>` and
// `<-loopback>` bypass nothing there, but they are recognised here anyway, for the reason
// `sys/linux/gsettings_map.rs` gives for GLib: the tokens are read before the dialect so
// every source shares one vocabulary, and no macOS writer types a WinINet token. And
// `name.*` covers the host plus anything whose leading labels are the host — the mirror of
// `*.name`, not a suffix rule — which the glob this arm already builds gets right except
// when the star stands for no labels at all (`example.com.*` against `example.com`). That
// one row is fail-*closed*, so it is recorded rather than answered with a new variant.
//
// `Gnome` is GLib's `GSimpleProxyResolver`, which is the code that resolves on GNOME —
// `gsettings_map.rs` reads the same keys GLib's `GProxyResolverGnome` does. It agrees on
// the bare name, and on CIDR: `reparse_ignore_hosts` tries
// `g_inet_address_mask_new_from_string` on the whole entry before it strips anything
// (`gsimpleproxyresolver.c:186`), so a mask never reaches the name rules. It differs on
// four more axes, all from the same file:
//
//   * `reparse_ignore_hosts` strips a leading `*.` or `.` and stores the rest as a plain
//     name, which `ignore_host` then matches with `offset == 0` allowed — so `*.example.com`,
//     `.example.com` and `example.com` are one rule there, covering the domain *and* its
//     subdomains.
//   * no other `*` is syntax: what is left is `g_ascii_strcasecmp`d whole, and no
//     host contains a `*`, so `foo*.example.com` matches nothing at all. A bare `*` is that
//     rule's worst case and reads the same way — `reparse_ignore_hosts` strips neither a
//     `*.` nor a leading `.` from it, so it is stored whole and `ignore_host` then wants a
//     destination whose last character is a `*` behind a dot. None arrives. It shares this
//     with `MacOs`, and shares the reason with nothing else here: on Windows and in
//     `no_proxy` a bare `*` really does switch the proxy off.
//   * that same parse chomps with `g_strchomp`, trailing whitespace only, so a leading
//     space survives into the name and kills the rule the same way.
//   * `g_simple_proxy_resolver_lookup` resolves the destination with `G_URI_FLAGS_NONE`, and
//     `g_uri_split_internal` fills a scheme's default port only in its scheme-based
//     normalization, under `G_URI_FLAGS_SCHEME_NORMALIZE` — so a portless
//     `http://example.com/` is asked about with port 0, and an `example.com:80` rule does
//     not fire on it. That last one is not a pattern shape and lives in
//     [`BypassRules::require_explicit_port`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BypassDialect {
    Suffix,
    Windows,
    MacOs,
    Gnome,
}

impl BypassDialect {
    // Cut the whitespace the source itself would cut, and no more. `g_strchomp` is the
    // trailing end only, so a GNOME entry written with a leading space keeps it; CFNetwork
    // cuts neither end, so a macOS entry keeps both. In each case the space that survives
    // is part of a name no destination can carry: it meets the whitespace guard in
    // `HostPattern::parse_in` and the entry is refused, which is the verdict the source
    // itself reaches (the rule matches nothing) with the entry visible in
    // `BypassRules::rejected` rather than sitting in the list looking live.
    //
    // The macOS row is measured, not inherited: ` pw-probe.invalid` and `pw-probe.invalid `
    // both proxied a destination the unpadded entry bypasses
    // (`tests/mac_exceptions_list.rs` holds that on a macOS runner). Trimming either would
    // make it a live rule here, and the crate would answer `ProxyStep::Direct` for traffic
    // the Mac hands the proxy.
    //
    // Called from both ends because both need it and for different reasons — `parse_in` so
    // the pattern it builds is the trimmed one, `parse::bypass_entries_in` so an entry it
    // hands to `rejected` is quoted back without the separator's padding.
    pub(crate) fn trim(self, entry: &str) -> &str {
        match self {
            BypassDialect::Gnome => entry.trim_end(),
            BypassDialect::MacOs => entry,
            BypassDialect::Suffix | BypassDialect::Windows => entry.trim(),
        }
    }
}

impl HostPattern {
    /// Parse one bypass entry. `Ok(None)` for empty and for anything with no host left to
    /// match on — `:8080`, `.`, `..`, `*.`.
    ///
    /// ```
    /// # use proxy_watch::HostPattern;
    /// let p = HostPattern::parse("*.example.com").unwrap().unwrap();
    /// assert!(matches!(p, HostPattern::Domain { match_self: false, .. }));
    /// ```
    ///
    /// A bare address entry is stored the way the destination side reads it, not the way it
    /// was written: `010.0.0.1` is octal (`8.0.0.1`) and `192.168.1` is short-form
    /// (`192.168.0.1`), because that is how the [`Host`] the destination carries would parse
    /// the same text.
    ///
    /// A CIDR entry does not follow that grammar, because it is not a host: `ipnet` reads
    /// four decimal octets, so `010.0.0.0/8` is `10.0.0.0/8` — the block the writer meant,
    /// but not the block the same text would denote as a destination — and `192.168.1/24`
    /// and `0x0a.0.0.0/8` are errors rather than addresses. What is shared is the mapped
    /// reduction: `::ffff:10.0.0.0/104` is stored as `10.0.0.0/8`, matching what
    /// destinations `10.0.0.1` and `[::ffff:10.0.0.1]` both become.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidBypassPattern`] for `@`, internal whitespace, a `scheme://` prefix,
    /// a character that cannot appear in a host name (WHATWG forbidden domain code points
    /// not already rejected above), an empty label (`a..b`), a subdomain of an address
    /// (`.10.0.0.1`), a name no destination could carry (`example.123`), bad CIDR `/`, bad
    /// port, bad IPv6 brackets, or non-ASCII text with no punycode spelling.
    pub fn parse(entry: &str) -> Result<Option<Self>, Error> {
        Self::parse_in(entry, BypassDialect::Suffix)
    }

    pub(crate) fn parse_in(entry: &str, dialect: BypassDialect) -> Result<Option<Self>, Error> {
        let entry = dialect.trim(entry);
        if entry.is_empty() {
            return Ok(None);
        }
        let lowered = entry.to_ascii_lowercase();

        match lowered.as_str() {
            // Not on macOS, and not on GNOME: a lone `*` is compared to the destination as
            // a name on both, and meets none, so reading it as `All` would report every
            // destination direct on a machine that proxies every one of them. It falls
            // through to the star arm below, which refuses it by the same rule that refuses
            // `*probe*` — dead entries belong in `rejected`, where the writer can see the
            // rule did nothing, and not in the list looking live.
            "*" if !matches!(dialect, BypassDialect::MacOs | BypassDialect::Gnome) => {
                return Ok(Some(HostPattern::All));
            }
            LOCAL_TOKEN => return Ok(Some(HostPattern::Local)),
            NO_LOOPBACK_TOKEN => return Ok(Some(HostPattern::SubtractImplicit)),
            _ => {}
        }

        // Most of the guards below share one reason, written here rather than at each of
        // them: an entry this crate cannot read as a host still reaches the `Domain` arm at
        // the end, where it is stored as a suffix of whatever was written — a rule that
        // then matches no destination and says so nowhere. Under
        // `BypassRules::reversed_exceptions` that dead rule sends the traffic it names out
        // direct, which is fail-open, and refusing instead is affordable only because the
        // entry survives in `BypassRules::rejected`. Each guard adds the shape it catches
        // and the dead rule that shape would have become; the two that refuse for a
        // *different* reason — the `@` and `://` guards — say so themselves.

        // `@` marks a pasted proxy URL, not a bypass host — reject before port parse
        // would embed the password in the error reason ([`SafeError`] prints it in full).
        if entry.contains('@') {
            return Err(Error::bypass(
                entry,
                format!(
                    "entry looks like a proxy URL with credentials ({}), not a bare \
                     host[:port] or CIDR; bypass/no-proxy lists cannot carry a \
                     username or password",
                    redact_offending_token(entry)
                ),
            ));
        }

        // Whitespace cannot occur inside a host name any more than a `/` can, so an entry
        // that still holds some is stored as `suffix = ".a.example b.example"`.
        // It reaches here from a list whose separators do not include whitespace at all:
        // [`parse::no_proxy`](crate::parse::no_proxy), which splits on `,` alone — Go's
        // `httpproxy`, its reference, does the same, and `;` was removed from
        // `LIST_SEPARATORS` for the reason written there — and the GNOME and KDE readers
        // that go through it with lists `,`-separated already.
        // [`parse::proxy_override`](crate::parse::proxy_override) does split on whitespace,
        // but only on the ASCII spellings Windows itself writes, so a Windows list still
        // reaches this arm when one entry holds something `char::is_whitespace` calls space
        // and `WINDOWS_BYPASS_SEPARATORS` does not — `U+00A0` or `U+3000` pasted into the
        // settings dialog. `src/parse.rs` says the same from the splitting side.
        if entry.chars().any(char::is_whitespace) {
            return Err(Error::bypass(
                entry,
                // Not "',' or ';'": `;` separates nothing outside the Windows list, so
                // advising it told a `no_proxy`, GNOME or KDE writer to reach for the one
                // character that leaves their two entries a single dead rule.
                "entry contains whitespace, so it is not a single host[:port] or CIDR \
                 (separate entries with ',', or on Windows with ';' or a space)",
            ));
        }

        // A rule may name a scheme: Chromium's grammar is
        // `[<scheme>"://"]<host-pattern>[":"<port>]`, and
        // `SchemeHostPortMatcherRule::FromUntrimmedRawString` splits on `://` *before* it
        // reads a `/` as a CIDR mask, so `https://example.com` and `https://10.0.0.0/8` are
        // both rules there. A [`HostPattern`] has nowhere to put the scheme, and dropping
        // the one written would turn an https-only rule into one that bypasses plain HTTP
        // too — a wider bypass than the entry asks for. Refused instead, and the reason
        // says which grammar was not met rather than the CIDR guard's claim below.
        if lowered.contains("://") {
            return Err(Error::bypass(
                entry,
                "entry names a scheme, and a bypass pattern here applies to every scheme, \
                 so the restriction cannot be honoured (write the host on its own, for \
                 example example.com)",
            ));
        }

        // Not on Windows: an entry holding a `/` invalidates the whole list there, so a
        // `Cidr` rule built from one reports a bypass no reader of that list grants.
        // Microsoft bounds the damage at the list — "don't enter subwebs or trailing
        // slashes ... as they are invalidating the whole list otherwise" (KB 4551930) — and
        // both readers land past that bound: `InternetOpenW` fails with
        // `ERROR_INVALID_PARAMETER`, and a `ProxyOverride` holding one sends every
        // destination direct, which is measured rather than documented. The range Windows
        // does read is a wildcard, `10.*`. The rows are
        // `a_slash_ends_a_windows_bypass_list` in `tests/bypass.rs`.
        if dialect == BypassDialect::Windows && lowered.contains('/') {
            return Err(Error::bypass(
                entry,
                "entry contains a '/', which Windows does not read as a CIDR block — it \
                 invalidates the whole bypass list (write the range with wildcards, for \
                 example 10.* rather than 10.0.0.0/8)",
            ));
        }

        // Not on Windows: a leading `.` is a spelling no reader of that list grants, so a
        // `Domain` rule built from one sends traffic direct that the machine proxies.
        // Microsoft documents the wildcard in its place — "Enter a wildcard at the beginning
        // of an Internet address, IP address, or domain name that has a common ending"
        // (KB 4551930) — and the three readings agree, asked for `sub.name`: `InternetOpenW`
        // fails with `ERROR_INVALID_NAME` and takes the whole list with it, while WinHTTP and
        // the registry reading keep the list and reach the proxy anyway. `*.name` bypasses on
        // all three. `.` and `..` are left to the arms below, which build no rule from either
        // and so have nothing to refuse. The rows are
        // `a_leading_dot_is_not_a_windows_suffix` in `tests/bypass.rs`.
        if dialect == BypassDialect::Windows
            && lowered.starts_with('.')
            && !lowered.trim_start_matches('.').is_empty()
        {
            return Err(Error::bypass(
                entry,
                "entry starts with a '.', which Windows does not read as a subdomain rule — \
                 WinINet refuses the whole bypass list over one (write the subdomains as \
                 *.example.com rather than .example.com)",
            ));
        }

        if let Ok(net) = lowered.parse::<IpNet>() {
            return Ok(Some(HostPattern::Cidr(reduce_mapped_net(net))));
        }

        // With the scheme form taken above, a `/` that survives the CIDR parse cannot be
        // anything else: host names do not contain one, and neither does the `host[:port]`
        // form. Without this check `10.0.0/8` falls through to the `Domain` arm and becomes
        // `suffix = "./10.0.0/8"`. Go is where that dead rule was observed, not where the
        // guard comes from: `httpproxy`'s `config.init` tries `net.ParseCIDR` on every
        // entry and, on failure, falls straight through to the domain arm, so `10.0.0/8`
        // becomes a `domainMatch` on `.10.0.0/8` there too. Erroring instead is this
        // crate's own choice.
        if lowered.contains('/') {
            return Err(Error::bypass(
                entry,
                "entry contains a '/', so it can only be a CIDR block, but it is not a \
                 valid one (an address, a '/', and a prefix length — for example \
                 10.0.0.0/8 or fe80::/10)",
            ));
        }

        let (bracketed_text, port) =
            split_host_port(&lowered).map_err(|reason| Error::bypass(entry, reason))?;
        let host_text = strip_brackets(bracketed_text);

        // CFNetwork does not read a port in an entry as a restriction on the entry; it reads
        // the entry as not matching. Stored with a port here it would be the narrower rule
        // the writer appears to have asked for, which is the one shape of divergence this
        // file never lets stand: on macOS the entry is dead, so the port is what killed it
        // and `BypassRules::rejected` is where that has to be visible.
        if dialect == BypassDialect::MacOs && port.is_some() {
            return Err(Error::bypass(
                entry,
                "entry carries a port, which macOS does not read as a restriction — it \
                 compares the whole entry to the destination's host name, so no destination \
                 could ever match it (write the host on its own)",
            ));
        }

        // Brackets are the address-literal spelling and nothing else, so a bracketed entry
        // that is not one reaches the `Domain` arm as `suffix = ".2001:db8::zz"` for
        // `[2001:db8::zz]`. Not a spelling ruling: `parse_host` and not
        // `IpAddr`, because that is the grammar the destination side reads, and the address
        // arm at the end of this function accepts the same padded and hex spellings.
        if host_text.len() != bracketed_text.len()
            && !matches!(
                crate::endpoint::parse_host(host_text),
                Ok(Host::Ipv4(_) | Host::Ipv6(_))
            )
        {
            return Err(Error::bypass(
                entry,
                "entry is bracketed, so it can only be an address literal, but it is not a \
                 valid one (for example [::1] or [2001:db8::1])",
            ));
        }

        // The destination side is `Host::parse`, which refuses WHATWG's "forbidden domain
        // code point" — the C0 controls, DEL, `#`, `%`, `<`, `>`, `?`, `[`, `\`, `]`, `^`
        // and `|`. A rule holding one names a host that can never arrive:
        // `a?b.example.com` becomes `suffix = ".a?b.example.com"`. The `@`, whitespace and
        // `/` guards above are this same test spelled one character at a time; they stay
        // separate because each has a better reason to give than "not a host character",
        // and because `/` and `[` are read as syntax before they get here.
        if let Some(bad) = host_text.chars().find(|c| is_forbidden_host_char(*c)) {
            return Err(Error::bypass(
                entry,
                format!(
                    "entry contains {bad:?}, which cannot appear in a host name, so no \
                     destination could ever match it"
                ),
            ));
        }

        // Go runs every domain entry through `idnaASCII`, and this crate's destination side
        // is converted the same way — by `Host::parse` when the host is parsed from text,
        // and by `host_key` when a caller built the `Host` itself. Without the step here a Unicode
        // entry is a dead rule: `日本.example` is stored verbatim while the destination arrives
        // as `xn--wgv71a.example`, so it matches nothing — in *either* spelling, because the
        // destination is always converted and the pattern never is. Only non-ASCII text
        // reaches the converter, so no entry that works today changes shape.
        let encoded;
        let host_text = if host_text.is_ascii() {
            host_text
        } else {
            encoded = idna_ascii(host_text).map_err(|reason| Error::bypass(entry, reason))?;
            &encoded
        };

        // RFC 1035 section 2.3.1 gives the empty label one place, the root at the end —
        // which is the single trailing dot the arms below strip. A second one is not a
        // host name: `example.com..` is stored as `.example.com.` and meets only a
        // destination spelled the same way. Its own `Display` is `example.com.`, which
        // reads back as the live rule it is not. The `*.` and `.` suffix spellings and the
        // root dot are this grammar's own syntax, so they come off before the labels are
        // counted; what is left of `.` or `..` is no host part at all, which the arms below
        // already answer with `Ok(None)`. Recognising those two spellings of "a subdomain
        // of" once, here, is also what keeps the label check just below and the address
        // check after it from disagreeing about where the body starts.
        let subdomain_body = host_text
            .strip_prefix("*.")
            .or_else(|| host_text.strip_prefix('.'));
        let labelled = subdomain_body.unwrap_or(host_text);
        let labelled = labelled.strip_suffix('.').unwrap_or(labelled);
        if !labelled.is_empty() && labelled.split('.').any(str::is_empty) {
            return Err(Error::bypass(
                entry,
                "entry has an empty label (two dots in a row), so no destination could \
                 ever match it (write example.com, .example.com or *.example.com)",
            ));
        }

        // `.example.com` and `*.example.com` say "a subdomain of this", so what follows the
        // dot has to be something that *has* subdomains — a domain name. An address does
        // not: `.10.0.0.1` waits for an `a.10.0.0.1` that `Host::parse` refuses, in every
        // spelling the address side accepts (`.192.168.001.001`, `.0x0a.0.0.1`) and for an
        // unbracketed IPv6 too. Neither is a name that could never arrive on its own
        // (`.example.123`).
        //
        // "Could never match" is said of a destination a *special* scheme can carry, which is
        // what these lists are written about and what `matches_authority` admits — it goes
        // through `parse_host`, so `a.example.123` is refused there too. `matches_url` is
        // wider: WHATWG sends a non-special scheme to the opaque-host parser *before* the
        // "ends in a number" check, so `custom://a.example.123/` parses and its host is
        // `Domain("a.example.123")` while `http://a.example.123/` fails with
        // `InvalidIpv4Address`. A rule this arm refuses would have met that host. The refusal
        // stays — it catches the typo the shape almost always is, and dropping the rule sends
        // the request to the proxy rather than around it — but the reachability it tests is
        // the special-scheme one, and nothing further down may read it as more than that.
        // `a_refused_numeric_tail_is_only_unreachable_for_a_special_scheme` in `tests/bypass.rs`
        // is the measurement.
        //
        // A glob in the body buys the entry a narrow exemption, covering the spellings that
        // reach here, which keep the dot: `.*.10.0.0.1` becomes `Wildcard("*.*.10.0.0.1")`,
        // which needs a destination of the form `a.b.10.0.0.1` — a name whose last label
        // reads as a number, which is the address reading and not a host any URL can carry.
        // A star standing for the empty string does not widen that: `*10.0.0.1` would meet
        // `10.0.0.1`, but it opens with neither `.` nor `*.`, so it has no subdomain body and
        // never reaches this arm.
        // That holds for a whole address in the tail and does not survive being generalised
        // to any numeric one: a star is matched against the destination's *text*, where it
        // stands for the leading octets of an address as readily as for whole labels, so
        // `Wildcard("*.*.*.1")` is met by `10.0.0.1` itself and `.*.1` is a live rule.
        //
        // The destination such a rule meets can only be an address, because reaching this
        // arm at all means the address reading was tried on the body and failed, which the
        // name reading only does for a last label that is all digits. So the entry is dead
        // unless the pattern could be laid over a dotted quad, and two things settle that.
        // Every literal byte has to be one a quad carries: a digit, a dot, or the star
        // itself — which is what still refuses `.*.0x0a.0.0.1`, `.*.example.123` and the
        // colon of a broken IPv6. And the literal dots have to fit, counting the one in the
        // `*.` this entry gets in front of its body: a quad has four labels and so three
        // dots, which is why `.*.1` and `.*.0.1` live while `.*.0.0.1` and `.*.10.0.0.1` do
        // not. The test is permissive in the direction that costs nothing — no octet is 999,
        // so `.*.999` is kept and matches nothing — and strict in the one that costs a rule.
        // Entries whose body is a name never reach it: `.*.example` and `.a*b.example` parse
        // as domains and pass here as they always did.
        let suffix_body = subdomain_body
            .map(|rest| rest.strip_suffix('.').unwrap_or(rest))
            .filter(|body| !body.is_empty());
        if let Some(body) = suffix_body {
            let fits_a_dotted_quad = body.contains('*')
                && body.matches('.').count() < 3
                && body
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b'.' || b == b'*');
            match crate::endpoint::parse_host(body) {
                Ok(Host::Domain(_)) => {}
                Ok(_) => {
                    return Err(Error::bypass(
                        entry,
                        "entry names a subdomain of an address literal, which has none, so \
                         no destination could ever match it (write the address on its own, \
                         or a CIDR range such as 10.0.0.0/8)",
                    ));
                }
                Err(_) if fits_a_dotted_quad => {}
                Err(_) => return Err(Error::bypass(entry, UNREACHABLE_NAME)),
            }
        }

        // `*.example.com` is the same rule as `.example.com` (Go strips the `*`).
        // Handle this *before* stripping a trailing root dot, otherwise `*.` collapses
        // to `*` and becomes a match-everything wildcard.
        if let Some(rest) = host_text.strip_prefix("*.") {
            let rest = rest.strip_suffix('.').unwrap_or(rest);
            if rest.is_empty() {
                return Ok(None);
            }
            if !rest.contains('*') {
                return Ok(Some(HostPattern::Domain {
                    suffix: format!(".{rest}"),
                    // GNOME stores what is left after the `*.` as a plain name and then
                    // allows the whole-string match, so there the prefix widens the rule
                    // instead of excluding the domain itself.
                    match_self: dialect == BypassDialect::Gnome,
                    port,
                }));
            }
            if dialect == BypassDialect::Gnome {
                return Err(Error::bypass(entry, GNOME_LITERAL_STAR));
            }
            // A second star, past the one that opened the entry, is a character again.
            if dialect == BypassDialect::MacOs {
                return Err(Error::bypass(entry, MACOS_LITERAL_STAR));
            }
            return Ok(Some(HostPattern::Wildcard {
                pattern: format!("*.{rest}"),
                port,
            }));
        }

        // A trailing dot on a pattern is the DNS root marker.
        let host_text = host_text.strip_suffix('.').unwrap_or(host_text);
        if host_text.is_empty() {
            // Go ignores entries with no host part instead of failing — `config.init`
            // in `http/httpproxy/proxy.go` answers that shape with `continue`.
            return Ok(None);
        }

        if let Ok(ip) = host_text.parse::<IpAddr>() {
            let host = match ip {
                IpAddr::V4(v4) => Host::Ipv4(v4),
                IpAddr::V6(v6) => Host::Ipv6(v6),
            };
            return Ok(Some(HostPattern::Exact { host, port }));
        }

        if host_text.contains('*') {
            if dialect == BypassDialect::Gnome {
                return Err(Error::bypass(entry, GNOME_LITERAL_STAR));
            }
            // The `*.` spelling was taken above, so the only star macOS still reads as
            // syntax is a trailing `.*`, and only when it is the sole one. What is left of
            // the entry has to be a name a destination could carry — a leading dot is not,
            // and the glob would be as dead as the entry it came from.
            if dialect == BypassDialect::MacOs {
                let head = host_text.strip_suffix(".*").filter(|head| {
                    !head.is_empty() && !head.contains('*') && !head.starts_with('.')
                });
                return match head {
                    Some(head) => Ok(Some(HostPattern::Wildcard {
                        pattern: format!("{head}.*"),
                        port,
                    })),
                    None => Err(Error::bypass(entry, MACOS_LITERAL_STAR)),
                };
            }
            // The leading dot is the reference's own rewrite — "we remap `.google.com` -->
            // `*.google.com`" — and it is applied to every rule that starts with one, glob
            // or not (`SchemeHostPortMatcherRule::FromUntrimmedRawString`). The `Domain` arm
            // below is that rewrite spelled as a suffix; this arm needs it written out,
            // because a pattern is matched literally and no host key begins with a dot —
            // left alone, `.*.example.com` is the dead rule the guards above refuse.
            let pattern = if host_text.starts_with('.') {
                format!("*{host_text}")
            } else {
                host_text.to_owned()
            };
            return Ok(Some(HostPattern::Wildcard { pattern, port }));
        }

        if let Some(rest) = host_text.strip_prefix('.') {
            if rest.is_empty() {
                return Ok(None);
            }
            return Ok(Some(HostPattern::Domain {
                suffix: host_text.to_owned(),
                // The `*.` spelling above, for the same reason.
                match_self: dialect == BypassDialect::Gnome,
                port,
            }));
        }

        // Store the address the way the destination side spells it, for the same reason the
        // punycode step above exists: `Host::parse` reads a leading zero as octal, `0x` as
        // hex and a short form as filling from the right, so `192.168.001.001` kept verbatim
        // would never meet the `192.168.1.1` that arrives. Reached only once `IpAddr` has
        // said no, so the entry whose meaning this changes is the all-digit name `123`, now
        // the address `0.0.0.123` — which is what a destination spelled `123` already
        // becomes. Hence
        // `idna_ascii` keeps `Host::parse` away from an all-digit *label*, where the address
        // reading is the wrong one.
        // The suffix spellings were answered above; this is the bare one.
        let Ok(host) = crate::endpoint::parse_host(host_text) else {
            return Err(Error::bypass(entry, UNREACHABLE_NAME));
        };

        // An address is one host under every dialect — there is nothing "under"
        // `10.0.0.1` for a suffix rule to reach.
        if matches!(host, Host::Ipv4(_))
            || matches!(dialect, BypassDialect::Windows | BypassDialect::MacOs)
        {
            return Ok(Some(HostPattern::Exact { host, port }));
        }

        Ok(Some(HostPattern::Domain {
            suffix: format!(".{host_text}"),
            match_self: true,
            port,
        }))
    }

    // Test the pattern against a destination.
    //
    // `host_text` must already be lowercased; `ip` is `Some` when the host is a
    // literal address. Prefer [`BypassRules::matches`], which also applies the
    // loopback and simple-hostname rules.
    fn matches(&self, host_text: &str, ip: Option<IpAddr>, port: Option<u16>) -> bool {
        match self {
            HostPattern::All => true,
            HostPattern::Cidr(net) => ip.is_some_and(|ip| net.contains(&ip)),
            HostPattern::Exact {
                host,
                port: rule_port,
            } => {
                // Addresses compare as addresses, so `10.0.0.1` and `[::ffff:10.0.0.1]`
                // are the one host they denote — `host_ip` has reduced both sides. This
                // is Go's `ipMatch`, which compares with `net.IP.Equal`. The references
                // split here: Chromium's `SchemeHostPortMatcherIPHostRule::Evaluate` is
                // `base::MatchPattern(url.GetHost(), ip_host_)`, plain text. Go is the
                // one to follow because the rest of this file already reads the mapped
                // spelling as the address it maps — the CIDR arm below, `is_loopback`,
                // `is_link_local` — and a rule that agreed with none of them would be
                // the asymmetry those exist to avoid. The text fallback carries the
                // `Exact { host: Host::Domain(_) }` that a Windows list produces for every
                // bare name, and the hand-built one.
                let hit = match (host_ip(host), ip) {
                    (Some(rule_ip), Some(destination_ip)) => rule_ip == destination_ip,
                    _ => host_text.strip_suffix('.').unwrap_or(host_text) == host_key(host),
                };
                hit && port_matches(*rule_port, port)
            }
            HostPattern::Domain {
                suffix,
                match_self,
                port: rule_port,
            } => {
                // No `ip.is_none()` guard, so `.1` also matches `10.0.0.1` — text matching,
                // which is what the Windows `ProxyOverride` lists this crate also reads have
                // always done. (Go excludes addresses here, Chromium does not.)
                //
                // The leading dot is `parse`'s convention, not something the type can
                // enforce: the fields are public and `BypassRules::new` exists to be filled
                // in by hand. So name the domain rather than slicing a byte off it — a
                // non-ASCII first character is not a char boundary — and refuse the empty
                // name outright, which is what the field doc promises matches nothing. It
                // would not: an empty `bare` strips nothing, so the whole host comes back as
                // `rest`, and any host still ending in a dot once one is shed then satisfies
                // the `ends_with('.')` test below. The destination side of that is an
                // ordinary URL and not a hand-built value — `url` reads `http://example.com../`
                // as `Host::Domain("example.com..")`. (Not "matches every host": that is what
                // an `ends_with(bare)` shape would do, and this one strips instead.)
                //
                // The case of the suffix is `parse`'s convention for the same reason, and
                // gets the same treatment: fold it here instead of trusting it. The `Exact`
                // arm above has always folded — not by design, but because `host_key` is
                // also what lowercases the destination — and a rule set that answered one
                // way for `Exact { "FooBar.com" }` and another for `Domain { ".FooBar.com" }`
                // would be the asymmetry this file keeps saying it avoids.
                let host_text = host_text.strip_suffix('.').unwrap_or(host_text);
                let bare = suffix.strip_prefix('.').unwrap_or(suffix);
                let hit = !bare.is_empty()
                    && strip_suffix_ascii_case(host_text, bare).is_some_and(|rest| {
                        rest.ends_with('.') || (*match_self && rest.is_empty())
                    });
                hit && port_matches(*rule_port, port)
            }
            HostPattern::Wildcard {
                pattern,
                port: rule_port,
            } => {
                let host_text = host_text.strip_suffix('.').unwrap_or(host_text);
                // Folded on the rule side like `Domain` above, and folded *here* rather
                // than inside `glob_match`: that helper is shared with `sh_exp_match`, the
                // PAC `shExpMatch`, where case sensitivity is the reference behaviour —
                // Mozilla's `ascii_pac_utils.js` builds a `RegExp` with no `i` flag. The
                // allocation is skipped for the shape `parse` produces, which is all of them.
                let hit = if pattern.bytes().any(|byte| byte.is_ascii_uppercase()) {
                    glob_match(&pattern.to_ascii_lowercase(), host_text)
                } else {
                    glob_match(pattern, host_text)
                };
                hit && port_matches(*rule_port, port)
            }
            HostPattern::Local => is_simple_host_name(host_text, ip),
            // Not a bypass this entry adds, and the only entry that can take one away.
            // [`BypassRules::matches`] answers for it before it reaches here, because the
            // answer depends on the destination's membership in the implicit set rather
            // than on this pattern.
            HostPattern::SubtractImplicit => false,
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostPattern::All => f.write_str("*"),
            HostPattern::Cidr(net) => write!(f, "{net}"),
            HostPattern::Exact { host, port } => write_with_port(f, &host_display(host), *port),
            HostPattern::Domain {
                suffix,
                match_self,
                port,
            } => {
                // The dot is added rather than passed through, because the field doc says a
                // hand-built suffix may be written without one and mean the same domain.
                // That is true of matching and was not true of this: `Domain { suffix:
                // "example.com", match_self: false }` printed `example.com`, which
                // [`Self::parse`] reads back as `match_self: true` — a rule for the
                // subdomains alone, displayed and re-read as one that takes the bare domain
                // with them. Anyone logging a rule set and feeding it back gets a wider
                // bypass than the one they built.
                let base = match (*match_self, suffix.strip_prefix('.')) {
                    (true, Some(bare)) => bare.to_owned(),
                    (false, None) => format!(".{suffix}"),
                    _ => suffix.clone(),
                };
                write_with_port(f, &base, *port)
            }
            HostPattern::Wildcard { pattern, port } => write_with_port(f, pattern, *port),
            HostPattern::Local => f.write_str(LOCAL_TOKEN),
            HostPattern::SubtractImplicit => f.write_str(NO_LOOPBACK_TOKEN),
        }
    }
}

/// The Windows `ProxyOverride` token that bypasses dot-less (intranet) host names.
pub const LOCAL_TOKEN: &str = "<local>";

/// Windows `<-loopback>`: subtracts the whole implicit bypass set — loopback *and*
/// link-local — from the entries written before it. Parsed to
/// [`HostPattern::SubtractImplicit`]; see [`BypassRules::bypass_loopback`].
pub const NO_LOOPBACK_TOKEN: &str = "<-loopback>";

// Given twice by `HostPattern::parse`: once for a bare entry, once for a suffix one.
//
// The parenthetical names both shapes that arrive here, because the reason has to hold for
// every entry `parse_host` refused and not just the one that motivated it. `2001:db8:1`
// reaches this too — the guards above let a colon through as an attempt at an unbracketed
// IPv6 — and a colon also makes `Error::bypass` withhold the input, so a message that only
// described `example.123` would leave the reader with neither the entry nor its reason.
const UNREACHABLE_NAME: &str = "entry is not a name any destination could carry, so no \
                                destination could ever match it (a last label that reads as \
                                a number, as in example.123, is taken for an address and \
                                refused as one; so is an unbracketed IPv6 that is not a \
                                valid address, as in 2001:db8:1)";

// GNOME's only wildcard is the leading `*.`, and it is stripped rather than matched
// (`gsimpleproxyresolver.c:227`); anything else holding a `*` is compared whole against a
// host name, which cannot contain one. Refused rather than stored, because storing it is
// the dead rule the guards above exist to keep out of the list — and refusing it here is
// what keeps this crate from reporting a bypass GNOME does not have.
//
// The bare `*` is the one that carries the whole arm, the same way it does for macOS below:
// it is not the leading `*.` the strip looks for, so GLib stores it whole and matches it
// against nothing, while `HostPattern::All` is every destination on the machine reported
// direct at once. It reaches this constant through the guard further down rather than the
// `All` arm at the top of `parse_in`, which is why that arm names this dialect.
const GNOME_LITERAL_STAR: &str = "entry contains a '*' that GNOME does not read as a \
                                  wildcard — only a leading '*.' is one there — so no \
                                  destination could ever match it (write *.example.com for \
                                  a domain, or the host on its own)";

// macOS reads a star at either end of an entry and nowhere in between:
// `tests/mac_exceptions_list.rs` has `*.pw-probe.invalid` and `pw-probe.invalid.*` matching
// and `*probe*`, `*invalid`, `pw-*.invalid` and a bare `*` matching nothing. Refused for
// the reason above it, and the bare `*` is why the refusal is worth the arm: kept as a
// wildcard it is the whole proxy switched off.
const MACOS_LITERAL_STAR: &str = "entry contains a '*' that macOS does not read as a \
                                  wildcard — only a leading '*.' or a trailing '.*' is one \
                                  there — so no destination could ever match it (write \
                                  *.example.com for a domain, or the host on its own)";

/// Destinations that must not go through a proxy
/// ([`parse::no_proxy`](crate::parse::no_proxy) / [`parse::proxy_override`](crate::parse::proxy_override)).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BypassRules {
    /// Parsed list entries.
    pub patterns: Vec<HostPattern>,
    /// Dot-less host bypass, as a switch (macOS `ExcludeSimpleHostnames`). The list
    /// spelling [`HostPattern::Local`] says the same thing until
    /// [`reversed_exceptions`](Self::reversed_exceptions) is set, where a switch and a
    /// list entry mean opposite things — see
    /// [`excludes_simple_hostnames`](Self::excludes_simple_hostnames).
    pub exclude_simple_hostnames: bool,
    /// KDE/`config-kde` inclusion list — the implicit set still applies; see [`matches`](Self::matches).
    pub reversed_exceptions: bool,
    /// Redacted unparseable originals; affects verdict under
    /// [`reversed_exceptions`](Self::reversed_exceptions). Not a complete ledger of the
    /// entries that match nothing — see [`HostPattern::Wildcard`].
    pub rejected: Vec<RejectedValue>,
    /// Whether a destination's port counts only when the destination wrote one, so that a
    /// ported entry such as `example.com:80` does not meet a portless `http://example.com/`.
    ///
    /// Set for GNOME `ignore-hosts` and nowhere else. GLib resolves the destination with
    /// `G_URI_FLAGS_NONE` (`gsimpleproxyresolver.c:341`) and fills a scheme's default port
    /// only under `G_URI_FLAGS_SCHEME_NORMALIZE` (`guri.c:1006`), so the port it compares
    /// against is 0 unless the URL carried one. Windows fills it — a `ProxyOverride` entry
    /// of `host:80` was measured bypassing a portless `http://host/`.
    ///
    /// [`matches`](Self::matches) does not read this: it is told a port and answers about
    /// that port. [`matches_url`](Self::matches_url) is where it is read, and is the reason
    /// to prefer that method whenever the destination is a `Url` — it passes
    /// [`Url::port`](https://docs.rs/url/latest/url/struct.Url.html#method.port) rather than
    /// `port_or_known_default` when this is set. Reading the field by hand is supported, not
    /// recommended.
    ///
    /// One case is approximate, and in the safe direction. `Url` drops a port equal to the
    /// scheme's default while parsing, so `http://host:80/` and `http://host/` are the same
    /// value and `port` answers `None` for both. A rule on that port — `host:80` for
    /// `http`, `host:443` for `https` — therefore stops firing entirely here, where GLib
    /// still fires it on the spelling that wrote the port out. The destination goes to the
    /// proxy instead of direct; the distinction was gone before this crate saw the URL.
    pub require_explicit_port: bool,
}

impl Default for BypassRules {
    fn default() -> Self {
        Self::new()
    }
}

impl BypassRules {
    /// An empty rule set with the default loopback behaviour (loopback is bypassed).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
            exclude_simple_hostnames: false,
            reversed_exceptions: false,
            rejected: Vec::new(),
            require_explicit_port: false,
        }
    }

    /// Whether the implicit bypass set — loopback *and* link-local — is still in force,
    /// which it is unless the list carries [`HostPattern::SubtractImplicit`]
    /// (`<-loopback>`).
    ///
    /// A rough answer, and the reason it is not a field: `<-loopback>` subtracts the
    /// implicit set only from the entries written before it, so a list that carries the
    /// token can still bypass a loopback destination named after it. Ask
    /// [`matches`](Self::matches) about a destination; ask this about the list.
    ///
    /// ```
    /// # use proxy_watch::parse;
    /// assert!(parse::no_proxy("localhost").bypass_loopback());
    /// assert!(!parse::proxy_override("<-loopback>").bypass_loopback());
    /// // The token is in the list, so this is `false` — but `localhost` is written
    /// // after it and wins on the destination it names.
    /// let readded = parse::proxy_override("<-loopback>;localhost");
    /// assert!(!readded.bypass_loopback());
    /// assert!(readded.matches_authority("localhost"));
    /// assert!(!readded.matches_authority("127.0.0.1"));
    /// ```
    #[must_use]
    pub fn bypass_loopback(&self) -> bool {
        !self
            .patterns
            .iter()
            .any(|p| matches!(p, HostPattern::SubtractImplicit))
    }

    // Add `pattern` to [`BypassRules::patterns`]. Repeats are collapsed by
    // [`dedup_patterns`](Self::dedup_patterns) once the list is complete, not here.
    pub(crate) fn push_pattern(&mut self, pattern: HostPattern) {
        self.patterns.push(pattern);
    }

    // Collapse repeats in [`BypassRules::patterns`], keeping the first of each.
    //
    // Do not move this into `push_pattern` as one `Vec::contains` per entry: the vector it
    // would scan is the one being built, so a list of distinct entries costs time in the
    // square of its length — 16,000 entries take 41.4 s in a debug build
    // (`a_long_list_of_distinct_entries_does_not_stall_the_parse`). No source of a bypass
    // list caps it, and all five are open-ended — `no_proxy` is an environment variable,
    // `ProxyOverride` a registry value group policy writes, `ExceptionsList` a `configd`
    // array, `ignore-hosts` a GSettings `as`, `NoProxyFor` one line of a text file.
    //
    // Moving it here rather than handing every caller a set keeps the rule in one place at
    // the cost of a transiently duplicated vector, which nothing reads: every loop that
    // fills a list from one of those sources ends with this call, and there are no others
    // (`parse::bypass_entries_in`, `sys::proxy_dict::bypass_from_dict`).
    //
    // The rule is per run, not per list, because [`HostPattern::SubtractImplicit`] changes
    // what a repeat means: in `localhost, <-loopback>, localhost` the second spelling is
    // the one that decides, so dropping it as a duplicate of the first would hand the
    // verdict to the token between them.
    pub(crate) fn dedup_patterns(&mut self) {
        let mut seen = HashSet::with_capacity(self.patterns.len());
        self.patterns.retain(|pattern| {
            if matches!(pattern, HostPattern::SubtractImplicit) {
                seen.clear();
                return true;
            }
            seen.insert(pattern.clone())
        });
    }

    // Parse one bypass list entry and fold the result into `self` — the fail-soft
    // boundary this crate settled on.
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    pub(crate) fn push_entry_in(&mut self, entry: &str, dialect: BypassDialect) {
        match HostPattern::parse_in(entry, dialect) {
            Ok(Some(pattern)) => self.push_pattern(pattern),
            Ok(None) => {}
            Err(err) => {
                crate::trace::warning!(
                    error = %crate::trace::SafeError(&err),
                    "skipping an unparseable bypass list entry"
                );
                self.rejected.push(RejectedValue::new(
                    RejectionKind::InvalidBypassPattern,
                    RejectionSource::BypassList,
                    entry,
                ));
            }
        }
    }

    /// Whether either representation of the dot-less host rule is present — the
    /// [`exclude_simple_hostnames`](Self::exclude_simple_hostnames) switch or a
    /// [`HostPattern::Local`] entry.
    ///
    /// Present, not equivalent. Under
    /// [`reversed_exceptions`](Self::reversed_exceptions) the two part company, because
    /// one is a switch and the other is a list entry: the switch bypasses dot-less hosts
    /// before the list is consulted at all, the way the implicit set does, while a
    /// `Local` *entry* is inside the inclusion list and so means the opposite — dot-less
    /// hosts are exactly the ones that keep using the proxy. So this answering `true`
    /// does not by itself tell you [`matches`](Self::matches) will bypass a dot-less
    /// host; ask `matches`. Folding one representation into the other silently flips
    /// that verdict.
    #[must_use]
    pub fn excludes_simple_hostnames(&self) -> bool {
        self.exclude_simple_hostnames
            || self
                .patterns
                .iter()
                .any(|p| matches!(p, HostPattern::Local))
    }

    /// Empty patterns and default flags ([`BypassRules::new`]). `<-loopback>` is an entry
    /// in [`patterns`](Self::patterns), so a list holding only that is not empty — it
    /// carries an instruction, and reporting it empty would invite a caller to drop it and
    /// put the implicit bypass back. Omits [`rejected`](Self::rejected) (only matters under
    /// [`reversed_exceptions`](Self::reversed_exceptions), which already answers `false`).
    ///
    /// ```
    /// # use proxy_watch::{parse, BypassRules};
    /// assert!(BypassRules::new().is_empty());
    /// assert!(parse::no_proxy("").is_empty());
    /// // `<-loopback>` is an instruction, not an absence of one.
    /// assert!(!parse::proxy_override("<-loopback>").is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
            && !self.exclude_simple_hostnames
            // Reversed empty list bypasses everything — not trivial.
            && !self.reversed_exceptions
    }

    /// Whether `host` bypasses the proxy.
    ///
    /// A host with no text answers `false` before any of the below, in both modes. Nothing
    /// in this crate asks — a URL with no host is Direct long before the bypass list is
    /// reached — so that answer is for a caller who assembled the `Host` itself. Such a
    /// caller owns the other end of this too: a `Host::Domain` is taken as text and never
    /// re-read as an address, so `Domain("0177.0.0.1")` misses the loopback switch that
    /// [`matches_authority`](Self::matches_authority) hits for the same characters. Neither
    /// `Url::host` nor `url::Host::parse` can hand over that value — both fold every numeric
    /// spelling to `Host::Ipv4` — and re-parsing here would cost every call for a shape only
    /// a literal `Host::Domain(_)` can make.
    ///
    /// No name is resolved here, ever. A host that `/etc/hosts` or DNS points at
    /// `127.0.0.1` is still read as the characters it was written with, so it misses the
    /// implicit set and goes through the proxy unless an entry names it. Chromium reads the
    /// same way — `ProxyHostMatchingRules::Matches` takes a `GURL` and every rule under it
    /// asks `url.host()` — and a lookup inside a predicate that runs per request would put
    /// its latency and its failures there too.
    ///
    /// Ported `:port` rules never match `port = None` (Go). Under
    /// [`reversed_exceptions`](Self::reversed_exceptions), patterns are inclusion-only
    /// while [`rejected`](Self::rejected) is empty.
    ///
    /// Entries are read **back to front**, and the first one that has something to say
    /// answers: "Later rules override earlier rules … when mixing positive and negative
    /// rules, evaluation order makes a difference"
    /// (Chromium, `net/base/scheme_host_port_matcher.cc`; the expectation "comes from
    /// WinInet (which is where `<-loopback>` comes from)",
    /// `proxy_host_matching_rules_unittest.cc`). Order only ever matters because of
    /// [`HostPattern::SubtractImplicit`], the one entry that takes a bypass away — so
    /// `127.0.0.1;<-loopback>` proxies `127.0.0.1` and `<-loopback>;127.0.0.1` sends it
    /// direct. With no entry deciding, the implicit set does: loopback and link-local
    /// alike, and not inverted by `reversed_exceptions`, because an inclusion list that
    /// never named loopback has not asked for loopback to be proxied.
    ///
    /// [`exclude_simple_hostnames`](Self::exclude_simple_hostnames) is a switch and not an
    /// entry, so it is not inverted either — unlike a [`HostPattern::Local`] entry, which
    /// is; see [`excludes_simple_hostnames`](Self::excludes_simple_hostnames) for why that
    /// changes the answer here. An IPv4-mapped IPv6 destination
    /// (`::ffff:a.b.c.d`) is compared as the IPv4 address it maps, against CIDR and exact
    /// patterns alike, and against the loopback/link-local switches.
    ///
    /// ```
    /// # use proxy_watch::parse;
    /// let rules = parse::no_proxy("localhost, .example.com, 10.0.0.0/8");
    /// assert!(rules.matches_authority("www.example.com"));
    /// assert!(rules.matches_authority("10.1.2.3:443"));
    /// assert!(!rules.matches_authority("example.org"));
    /// // Link-local destinations bypass even though the list above never mentions them.
    /// assert!(rules.matches_authority("169.254.1.1"));
    /// assert!(rules.matches_authority("[fe80::1]"));
    /// ```
    #[must_use]
    pub fn matches(&self, host: &Host, port: Option<u16>) -> bool {
        let text = host_key(host);
        if text.is_empty() {
            return false;
        }
        let ip = host_ip(host);
        let implicit = is_loopback(&text, ip) || is_link_local(ip);
        // What a destination no entry names answers under `reversed_exceptions`: the list
        // is then the set that *uses* the proxy, so being absent from it is the bypass. A
        // rejected entry makes that set incomplete, and an incomplete inclusion list may
        // not send anything direct.
        let unnamed = self.reversed_exceptions && self.rejected.is_empty();

        // Before the entries, and so before `reversed_exceptions` can invert it: this is a
        // switch, not a list entry. macOS is where it comes from and macOS has no reversed
        // mode, so the combination has no reference to copy — but the shape does, and the
        // list spelling `<local>` is a `HostPattern::Local` among the entries, is inverted,
        // and therefore answers the opposite. Both readings are right for what they are;
        // what would be wrong is treating them as one flag.
        //
        // The one entry that still overrides it is `<-loopback>`, because Chromium models
        // this switch as a rule *prepended* to the list
        // (`PrependRuleToBypassSimpleHostnames`, `proxy_config_service_mac.cc`) and so puts
        // every entry after it. Only a dot-less name that is also in the implicit set —
        // `localhost`, `loopback` — is reachable both ways; the rest of what the switch
        // covers no negative entry can name.
        if self.exclude_simple_hostnames
            && is_simple_host_name(&text, ip)
            && (self.bypass_loopback() || !implicit)
        {
            return true;
        }

        for pattern in self.patterns.iter().rev() {
            if matches!(pattern, HostPattern::SubtractImplicit) {
                if implicit {
                    return unnamed;
                }
            } else if pattern.matches(&text, ip, port) {
                return !self.reversed_exceptions;
            }
        }
        implicit || unnamed
    }

    /// Whether a destination URL bypasses the proxy.
    ///
    /// Prefer this over [`matches`](Self::matches) whenever the destination is a `Url`: it is
    /// the only entry point that reads [`require_explicit_port`](Self::require_explicit_port),
    /// and getting that wrong by hand is silent — a GNOME `ignore-hosts` of `example.com:80`
    /// asked about with `port_or_known_default` reports a bypass GNOME does not have. This
    /// crate's own `resolve` goes through here.
    ///
    /// A URL with no host to compare — `data:`, `mailto:`, or one whose host was emptied —
    /// is reported as "does not bypass", the same reading as an unparseable authority in
    /// [`matches_authority`](Self::matches_authority). It is not a statement that such a URL
    /// needs a proxy; a caller that routes hostless URLs direct should say so before asking.
    ///
    /// ```
    /// # use proxy_watch::parse;
    /// # use url::Url;
    /// let rules = parse::no_proxy(".example.com");
    /// assert!(rules.matches_url(&Url::parse("https://www.example.com/x").unwrap()));
    /// assert!(!rules.matches_url(&Url::parse("https://example.org/").unwrap()));
    /// assert!(!rules.matches_url(&Url::parse("data:,hello").unwrap()));
    /// ```
    #[must_use]
    pub fn matches_url(&self, url: &Url) -> bool {
        let Some(host) = crate::endpoint::request_host(url) else {
            return false;
        };
        // The one place the flag is read. `port_or_known_default` is the majority reading —
        // a rule written `example.com:80` is meant for the HTTP port whether or not the URL
        // spelled it out, and Windows was measured agreeing: a `ProxyOverride` of `host:80`
        // bypasses a portless `http://host/`.
        let port = if self.require_explicit_port {
            url.port()
        } else {
            url.port_or_known_default()
        };
        self.matches(&host, port)
    }

    /// Convenience wrapper around [`BypassRules::matches`] taking a `host[:port]`
    /// string such as `example.com:8080` or `[::1]:443`.
    ///
    /// Unparseable input is reported as "does not bypass": an authority this cannot
    /// split is one it cannot prove is exempt, so it goes through the proxy, which can
    /// still refuse it. (Other stacks disagree on this edge; this crate does not claim
    /// their spelling.)
    ///
    /// Supplies no default port: an authority written without one is asked with none, so
    /// a rule spelled `example.com:80` does not match `example.com`.
    /// [`matches_url`](Self::matches_url) is the entry point that fills one in.
    #[must_use]
    pub fn matches_authority(&self, authority: &str) -> bool {
        let Ok((host_text, port)) = split_host_port(authority.trim()) else {
            return false;
        };
        let Ok(host) = crate::endpoint::parse_host(host_text) else {
            return false;
        };
        self.matches(&host, port)
    }
}

// WHATWG's forbidden domain code points, less `/`, `@`, and ASCII space (earlier
// guards) and `:` when it splits a single-colon `host:port`. Several colons without
// brackets are treated as an IPv6 literal attempt, not rejected here. `*` is not
// forbidden, which is what leaves room for the glob spelling.
//
// One widening, deliberate rather than overlooked: `char::is_control` is Unicode's `Cc`,
// so it also refuses U+0080..=U+009F, which that list does not name. What it buys is the
// reason and not the verdict: `is_ascii_control` here leaves `a\u{86}b.example`
// to the punycode step below, which refuses it too, as text "that is not a valid
// internationalised domain name". Naming the character instead is the difference between a
// writer who can find the byte they pasted and one who cannot. (U+0085 and U+00A0 reach
// neither test: `char::is_whitespace` counts them, and the whitespace guard is first.)
fn is_forbidden_host_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '#' | '%' | '<' | '>' | '?' | '[' | '\\' | ']' | '^' | '|'
        )
}

// The punycode spelling of a bypass entry's host part.
//
// Label by label, because the whole string is not a host: it may carry a leading dot, a
// `*.` prefix, or an embedded glob, none of which `Host::parse` accepts as written. A
// label that is already ASCII is left untouched, which is most of them.
fn idna_ascii(host_text: &str) -> Result<String, String> {
    // `Host::parse` reads a name it can also read as an address as the address, and the
    // labels here arrive one at a time, so every one of them looks final to it. Lend the
    // label a last label that cannot be part of an address, and take the loan back off.
    const LOAN: &str = ".a";

    let mut out = String::with_capacity(host_text.len());
    for (index, label) in host_text.split('.').enumerate() {
        if index > 0 {
            out.push('.');
        }
        if label.is_ascii() {
            out.push_str(label);
            continue;
        }
        // Punycode would swallow the `*` into the encoded label and the glob would stop
        // being one. A rule that quietly stops meaning what it says is the thing this
        // conversion exists to prevent, so say so instead.
        if label.contains('*') {
            return Err(
                "entry mixes a '*' glob with non-ASCII text in one label, which has no \
                 punycode spelling; write the label as punycode (xn--…) instead"
                    .to_owned(),
            );
        }
        // Without the loan `１２３` normalises to `123` and comes back `Ipv4`, and the entry
        // dies — while the destination side reads `１２３.example` as the name it is, because
        // there the digits are not the last label. Converting is not judging: whether the
        // ASCII text denotes a name or an address is settled afterwards by `parse_host`,
        // over the whole host part, where the address reading is the right one.
        match Host::parse(&format!("{label}{LOAN}")) {
            // The loan is ASCII and lowercase, so it survives the round trip unchanged.
            Ok(Host::Domain(ascii)) if ascii.ends_with(LOAN) => {
                out.push_str(&ascii[..ascii.len() - LOAN.len()]);
            }
            _ => {
                return Err(
                    "entry contains non-ASCII text that is not a valid internationalised \
                     domain name"
                        .to_owned(),
                );
            }
        }
    }
    Ok(out)
}

fn port_matches(rule_port: Option<u16>, port: Option<u16>) -> bool {
    match rule_port {
        None => true,
        Some(expected) => port == Some(expected),
    }
}

fn is_loopback(host_text: &str, ip: Option<IpAddr>) -> bool {
    if let Some(ip) = ip {
        // `127.0.0.0/8` and `::1`. `::ffff:127.0.0.1` arrives as `127.0.0.1` because
        // `host_ip` reduced it — see there for why every numeric rule gets it that way.
        return ip.is_loopback();
    }
    // WinINet bypasses `localhost` and `loopback` by name; Go bypasses `localhost`.
    // Chromium additionally treats any `*.localhost` subdomain and a single trailing
    // dot as local (`net/base/url_util.cc`, `IsLocalHostname`); a trailing dot
    // is stripped before comparing so `localhost.` and `app.localhost.` match too, the
    // same way DNS treats a trailing dot as denoting the root and not a distinct name.
    let name = host_text.strip_suffix('.').unwrap_or(host_text);
    name == "localhost" || name == "loopback" || name.ends_with(".localhost")
}

// Whether `ip` is link-local: IPv4 `169.254.0.0/16` (APIPA) or IPv6 `fe80::/10`.
// `::ffff:169.254.0.0/112` is the first of those, already reduced by `host_ip`.
//
// Read as one implicit set together with [`is_loopback`], so
// [`NO_LOOPBACK_TOKEN`] clears both at once. That is what the token means upstream:
// Chromium's `MatchesImplicitRules` is `IsLocalhost || IsIPv4MappedLoopback ||
// IsLinkLocalIP` in one expression, and `<-loopback>` is the rule that subtracts the whole
// of it — "The name <-loopback> is not a very precise name (as the implicit rules cover
// more than strictly loopback addresses), however this is the name that is used on Windows
// so re-used here" (`net/proxy_resolution/proxy_host_matching_rules.cc`, the file
// `proxy_bypass_rules.cc` became). The same file records Windows' own implicit set as
// "localhost, loopback, 127.0.0.1, [::1], 169.254/16, [FE80::]/10". The flag here is named
// for the token that clears it, not for half of what the token covers.
//
// Holding the two apart, and calling that a deliberate divergence, is the tempting reading:
// a proxy cannot reach an address that exists only on the client's own link. `169.254.169.254`
// refutes it: the cloud instance-metadata endpoint is link-local, a proxy on the same host
// reaches it, and routing it through an inspecting proxy is one of the reasons `<-loopback>`
// gets set at all. Answering Direct for it is fail-open on the one destination the setting
// most often exists to catch.
fn is_link_local(ip: Option<IpAddr>) -> bool {
    match ip {
        Some(IpAddr::V4(v4)) => v4.is_link_local(),
        Some(IpAddr::V6(v6)) => v6.is_unicast_link_local(),
        None => false,
    }
}

// Chromium's `BypassSimpleHostnamesRule` (`proxy_host_matching_rules.cc:80`): a name with no
// period, and never an IP literal. A trailing dot counts as "has a period", so it is not stripped
// first — unlike the `Domain` arm, which strips one from the same `host_text`.
//
// One function for the two spellings of the rule, the `exclude_simple_hostnames` switch
// and a `HostPattern::Local` list entry, because they answer the same question about a
// host even though `matches` consults them at different points and under different
// inversion. Written twice they could only drift.
fn is_simple_host_name(host_text: &str, ip: Option<IpAddr>) -> bool {
    ip.is_none() && !host_text.contains('.')
}

// The lowercase textual key used for matching. IPv6 hosts are *not* bracketed here,
// matching Go's `config.init` (`http/httpproxy/proxy.go`), which strips the brackets
// before `net.ParseIP` so `ipMatch` compares an unbracketed address.
fn host_key(host: &Host) -> String {
    match host {
        // `Host::parse` punycodes a Unicode name, and every `Host` this crate builds itself
        // came from it — but `matches` is public and takes the `Host`, so a caller can hand
        // over a `Host::Domain` that never went through it. Converting here rather than
        // trusting the caller is what keeps `matches` and `matches_authority` answering
        // alike; the rule side is converted at parse time by `idna_ascii`, so an unconverted
        // destination would silently match nothing. A name with no punycode spelling keeps
        // its own text and matches nothing, which is `matches_authority`'s own direction for
        // input it cannot make sense of.
        Host::Domain(domain) if !domain.is_ascii() => idna_ascii(domain)
            .unwrap_or_else(|_| domain.clone())
            .to_ascii_lowercase(),
        Host::Domain(domain) => domain.to_ascii_lowercase(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    }
}

// `str::strip_suffix`, comparing ASCII case-insensitively.
//
// Allocation-free, which is the reason it exists rather than a `to_ascii_lowercase` on
// either side: this runs once per rule per destination. The boundary check is what keeps
// the slicing sound — a split point inside a multi-byte character would panic, and `false`
// is the right answer there anyway, because a `str`'s first byte is never a continuation
// byte and so no suffix can start there.
fn strip_suffix_ascii_case<'a>(text: &'a str, suffix: &str) -> Option<&'a str> {
    let split = text.len().checked_sub(suffix.len())?;
    if !text.is_char_boundary(split) {
        return None;
    }
    text[split..]
        .eq_ignore_ascii_case(suffix)
        .then(|| &text[..split])
}

fn host_display(host: &Host) -> String {
    match host {
        Host::Ipv6(ip) => format!("[{ip}]"),
        other => other.to_string(),
    }
}

// The address a host denotes, with `::ffff:a.b.c.d` reduced to the IPv4 address it maps.
//
// Every numeric comparison in this file goes through here, so the reduction happens once
// instead of at each of them — including `is_loopback` and `is_link_local`, which is why
// neither needs a mapped-spelling arm of its own. Both references reduce too, in their own
// idiom.
fn host_ip(host: &Host) -> Option<IpAddr> {
    match host {
        Host::Domain(_) => None,
        Host::Ipv4(ip) => Some(IpAddr::V4(*ip)),
        Host::Ipv6(ip) => Some(ip.to_ipv4_mapped().map_or(IpAddr::V6(*ip), IpAddr::V4)),
    }
}

// The rule-side half of [`host_ip`]: `::ffff:10.0.0.0/104` is the IPv4 block `10.0.0.0/8`.
//
// Without this the rule is dead and says so nowhere. Every destination reaches
// [`HostPattern::matches`] already reduced by [`host_ip`], so it arrives as an
// `IpAddr::V4`, and `IpNet`'s `contains` is false across families — `10.0.0.1` and
// `[::ffff:10.0.0.1]` both miss a mapped-spelling rule that names exactly them. Nothing
// records the miss, because the entry parsed; under
// [`BypassRules::reversed_exceptions`] that is the fail-open direction this file rejects
// for `10.0.0/8` and `[2001:db8::zz]` a few lines apart.
//
// Only a net that lies wholly inside `::ffff:0:0/96` converts. A shorter prefix covers
// unmapped IPv6 as well, so it is an IPv6 rule about IPv6 destinations — and mapped
// destinations are not those, by the same reduction.
fn reduce_mapped_net(net: IpNet) -> IpNet {
    let IpNet::V6(v6) = net else {
        return net;
    };
    let (Some(addr), true) = (v6.addr().to_ipv4_mapped(), v6.prefix_len() >= 96) else {
        return net;
    };
    Ipv4Net::new(addr, v6.prefix_len() - 96).map_or(net, IpNet::V4)
}

fn write_with_port(f: &mut fmt::Formatter<'_>, base: &str, port: Option<u16>) -> fmt::Result {
    match port {
        Some(port) => write!(f, "{base}:{port}"),
        None => f.write_str(base),
    }
}
