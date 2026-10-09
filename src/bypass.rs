//! Bypass ("no proxy") rules.
//!
//! What an entry may look like comes from Go
//! [`httpproxy`](https://github.com/golang/net/blob/master/http/httpproxy/proxy.go); what one
//! *matches* follows Chromium wherever the readers disagree, so an embedded `*` is a glob
//! here. The `Suffix` dialect is therefore their union rather than a port of either:
//! [`BypassDialect`] carries the measurement. Windows `<local>` / `<-loopback>` on top.
//!
//! One rule is not shared: a bare name covers the subdomains everywhere except in a
//! Windows or macOS list, where it matches that name alone. See
//! [`parse::proxy_override`](crate::parse::proxy_override).

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
/// The bare-name row is the one that depends on where the list came from: a Windows or
/// macOS list reads `example.com` as [`HostPattern::Exact`], because that is what both
/// match. [`parse::proxy_override`](crate::parse::proxy_override) has the readings.
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
    /// name: a bare entry in a Windows or macOS list matches that name and nothing under it.
    ///
    /// Its [`Display`](std::fmt::Display) is the name alone, also used for a suffix rule
    /// for the same domain. Parsing that text with `proxy_override` returns this variant,
    /// while [`parse::no_proxy`](crate::parse::no_proxy) returns a [`Domain`](Self::Domain)
    /// that also covers subdomains. Retaining the value avoids widening the rule by
    /// displaying it and re-parsing it with the other dialect.
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
    /// parsing and does not reach [`BypassRules::rejected`]: `*` can match an empty string,
    /// so `*10.0.0.1` remains valid, and tests that distinguish these cases admit
    /// counterexamples.
    Wildcard {
        /// Glob pattern. [`parse`](Self::parse) lowercases it, and a hand-built one that
        /// is not lowercased matches the same hosts anyway: case is folded at match time.
        pattern: String,
        /// Optional port restriction.
        port: Option<u16>,
    },
    /// Windows `<local>`: any host name without a dot, and no IP literal. The macOS
    /// switch is [`BypassRules::exclude_simple_hostnames`], which also takes a dot-less
    /// IPv6 literal.
    Local,
    /// Windows `<-loopback>`: the one entry that takes a bypass away instead of adding
    /// one. It subtracts the implicit set in force (loopback, and under
    /// [`ImplicitBypass::WinInet`] link-local too, see [`NO_LOOPBACK_TOKEN`]) from every
    /// entry written before it, and from none written
    /// after it, which is why it is an entry in [`BypassRules::patterns`] and not a
    /// switch beside them. [`BypassRules::matches`] has the evaluation order.
    SubtractImplicit,
}

// Which list an entry came from, for the places the lists disagree about what an entry
// means. Named after the source rather than after a behaviour, because no two of them
// differ from `Suffix` on the same set of axes: `Windows` on four, `MacOs` on five, `Gnome`
// on four and `Kde` on two, no two the same set, and `MacOs` shares two of the `Windows`
// axes while disagreeing with it everywhere else.
//
// `Suffix` reads a bare name as the name and everything under it, and a leading `*.` or `.`
// as the subdomains alone. That much is Go's `httpproxy` with `no_proxy` and libproxy's with
// KDE's `NoProxyFor` (`ignore_domain` in `px-manager.c`, reached from `config-kde.c`), and it is why a
// bare name here is not the name alone the way it is under `Windows` and `MacOs`.
//
// A `*` anywhere else is a glob, and that half is *not* those two. `config.init` in
// `http/httpproxy/proxy.go` special-cases a bare `*` and strips one character off a leading
// `*.`; what is left goes to a `domainMatcher` that compares with `strings.HasSuffix`, so no
// star past the first is syntax. libproxy's `ignore_domain` (`px-manager.c`) reads four
// shapes and no more: the bare `*`, an exact name, and the two suffix spellings `.name`
// and `*.name`. Under both, `192.168.*` and `*.*.*.1` are literal text no host carries,
// so they match nothing. Neither refuses a CIDR entry, though, it leaves the name rules
// before it reaches them. `config.init` tries `net.ParseCIDR` first, and libproxy tries
// `ignore_ip` after `ignore_domain` (`px_manager_is_ignore`), which masks an entry holding a
// `/` with `g_inet_address_mask_new_from_string` against an address literal only.
//
// The star is read as a glob because the third reader of these same two lists reads it that
// way. Chromium hands `no_proxy` and KDE's `NoProxyFor` to the same
// `ProxyHostMatchingRules::ParseFromString` (`proxy_config_service_linux.cc:230`), which builds a
// `SchemeHostPortMatcherHostnamePatternRule` for everything that is not a CIDR or an address
// literal and evaluates it with `base::MatchPattern`
// (`scheme_host_port_matcher_rule.cc:99,139`), a glob, and the source of the leading-dot
// rewrite the `Wildcard` arm in `parse_in` already quotes.
//
// So this dialect is the union of the two readings rather than either one, and the union is
// the wider answer, the one that reaches `Direct` more often. `*.*.*.1` is met by
// `10.0.0.1` here and by `base::MatchPattern`; the two suffix readers send that request to
// the proxy. The union is kept because narrowing it would leave a rule someone typed a `*`
// into matching nothing while still reading back as live, which is the shape `Gnome` below
// refuses outright rather than store.
//
// `Windows` differs in four places. A bare name is the name alone, measured on this
// crate's own terms rather than read off a reimplementation, because the two
// reimplementations disagree and neither is the OS; the readings are the rows of
// `a_bare_name_in_a_windows_list_is_the_one_host` in `tests/bypass.rs`. And the three
// spellings a Windows list has no reading this crate can follow (an entry holding a `/`,
// an entry starting with `.`, and an IPv4 address written other than as four decimal
// octets) are refused rather than stored as rules the machine does not honour. Each has
// a guard in `parse_in` carrying its readings.
//
// `MacOs` is CFNetwork's `ExceptionsList`, measured the same way and by the same argument:
// `tests/mac_exceptions_list.rs` hands `CFNetworkCopyProxiesForURL` a settings dictionary
// and reads the verdict off the matcher itself, so Chromium's macOS reader is not consulted:
// it is a reimplementation and not the OS. It agrees with `Windows` that a bare name is the
// name alone, and that an IPv4 address written other than as four decimal octets is
// compared as text (`012.1.2.3` met only a destination written `012.1.2.3`, the same
// diagonal WinINet gives), so it is refused by the same guard. It differs from every other
// dialect here on three more:
//
//   * a `*` is syntax only as a leading `*.` or a trailing `.*`, and a character everywhere
//     else, so `*probe*`, `*invalid`, `pw-*.invalid` and a bare `*` match nothing. Reading
//     the bare `*` as `HostPattern::All` turns the proxy off for every destination on a Mac
//     that proxies all of them.
//   * a `:port` does not constrain an entry, it kills it. `example.com:80` matched no
//     destination on port 80, and `example.com` matched one that carried a port, so the
//     port is not part of the comparison at all.
//   * neither end is trimmed, which is `trim` below rather than an arm here: a space in
//     front of a name or behind it kills the entry the same way a `*` in the middle does.
//
// Two things it does *not* differ on are left alone. `<local>` and
// `<-loopback>` bypass nothing there, but they are recognised here anyway, for the reason
// `sys/linux/gsettings_map.rs` gives for GLib: the tokens are read before the dialect so
// every source shares one vocabulary, and no macOS writer types a WinINet token. And
// `name.*` covers the host plus anything whose leading labels are the host (the mirror of
// `*.name`, not a suffix rule), which the glob this arm already builds gets right except
// when the star stands for no labels at all (`example.com.*` against `example.com`). That
// one row is fail-*closed*, so it is recorded rather than answered with a new variant.
//
// `Gnome` is GLib's `GSimpleProxyResolver`, which is the code that resolves on GNOME:
// `gsettings_map.rs` reads the same keys GLib's `GProxyResolverGnome` does. It agrees on
// the bare name, and on CIDR: `reparse_ignore_hosts` tries
// `g_inet_address_mask_new_from_string` on the whole entry before it strips anything
// (`gsimpleproxyresolver.c:186`), so a mask never reaches the name rules. It differs on
// four more axes, all from the same file:
//
//   * `reparse_ignore_hosts` strips a leading `*.` or `.` and stores the rest as a plain
//     name, which `ignore_host` then matches with `offset == 0` allowed, so
//     `*.example.com`, `.example.com` and `example.com` are one rule there, covering the
//     domain *and* its subdomains.
//   * no other `*` is syntax: what is left is `g_ascii_strcasecmp`d whole, and no
//     host contains a `*`, so `foo*.example.com` matches nothing at all. A bare `*` is that
//     rule's worst case and reads the same way: `reparse_ignore_hosts` strips neither a
//     `*.` nor a leading `.` from it, so it is stored whole and `ignore_host` then wants a
//     destination whose last character is a `*` behind a dot. None arrives. It shares this
//     with `MacOs`, and shares the reason with nothing else here: on Windows and in
//     `no_proxy` a bare `*` does switch the proxy off.
//   * that same parse chomps with `g_strchomp`, trailing whitespace only, so a leading
//     space survives into the name and kills the rule the same way.
//   * `g_simple_proxy_resolver_lookup` resolves the destination with `G_URI_FLAGS_NONE`, and
//     `g_uri_split_internal` fills a scheme's default port only in its scheme-based
//     normalization, under `G_URI_FLAGS_SCHEME_NORMALIZE`, so a portless
//     `http://example.com/` is asked about with port 0, and an `example.com:80` rule does
//     not fire on it. That last one is not a pattern shape and lives in
//     [`BypassRules::require_explicit_port`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BypassDialect {
    Suffix,
    Windows,
    MacOs,
    Gnome,
    // KDE's `NoProxyFor`: `Suffix` in every shape but two. KIO's `revmatch` compares the
    // text from its end, so an entry's trailing dot is part of the name, where the
    // environment variable's readers shed it as the DNS root. And an IPv4 address written
    // other than as four decimal octets is refused, as under `Windows`, because KIO reads
    // each part as decimal where the URL grammar reads `012` as octal.
    #[cfg_attr(not(all(target_os = "linux", feature = "linux-kde")), allow(dead_code))]
    Kde,
}

impl BypassDialect {
    // Match each source's trimming: GLib's `g_strchomp` cuts trailing whitespace, while
    // CFNetwork cuts neither end. Surviving whitespace makes the entry unmatchable, so
    // `HostPattern::parse_in` records it in `BypassRules::rejected`.
    //
    // Trimming a macOS entry would make a dead rule live and bypass traffic CFNetwork
    // proxies. `parse_in` uses the trimmed pattern; `parse::bypass_entries_in` quotes
    // rejected entries without separator padding.
    pub(crate) fn trim(self, entry: &str) -> &str {
        match self {
            // `g_strchomp` cuts ASCII space, tab, LF, FF and CR, but leaves vertical tab
            // and non-ASCII whitespace; a trailing U+00A0 therefore kills the rule.
            BypassDialect::Gnome => entry.trim_end_matches(|c: char| c.is_ascii_whitespace()),
            BypassDialect::MacOs => entry,
            // ASCII only. An edge U+00A0 or U+3000 stays in the name, as it does when WinINet
            // reads `ProxyOverride` and in WinHTTP and Chromium (`TrimWhitespaceASCII`), so
            // the rule matches nothing and the entry goes to `rejected`.
            BypassDialect::Windows => {
                entry.trim_matches(|c| matches!(c, '\t' | '\n' | '\x0B' | '\x0C' | '\r' | ' '))
            }
            BypassDialect::Suffix | BypassDialect::Kde => entry.trim(),
        }
    }
}

impl HostPattern {
    /// Parse one bypass entry. `Ok(None)` for empty and for anything with no host left to
    /// match on: `:8080`, `.`, `..`, `*.`.
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
    /// A CIDR entry's IPv4 address follows the same grammar when it has four parts, as
    /// Chromium's does: `010.0.0.0/8` is `8.0.0.0/8` and `0x0a.0.0.0/8` is `10.0.0.0/8`.
    /// curl and Go read neither as a block. A short form (`192.168.1/24`) is an error
    /// rather than an address. A mapped-spelling block
    /// (`::ffff:10.0.0.0/104`) is stored as written; [`BypassRules::matches`] reads it as
    /// `10.0.0.0/8` while [`BypassRules::ipv4_mapped_as_ipv4`] is set.
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
            // macOS and GNOME compare a bare `*` as a name, so `All` would bypass traffic
            // they proxy. The star arm records the dead entry in `rejected`.
            "*" if !matches!(dialect, BypassDialect::MacOs | BypassDialect::Gnome) => {
                return Ok(Some(HostPattern::All));
            }
            LOCAL_TOKEN => return Ok(Some(HostPattern::Local)),
            NO_LOOPBACK_TOKEN => return Ok(Some(HostPattern::SubtractImplicit)),
            _ => {}
        }

        // Invalid host text would reach `Domain` as a dead suffix rule. Under
        // `BypassRules::reversed_exceptions`, that silently sends traffic direct, so these
        // guards record it in `BypassRules::rejected`. The `@` and `://` guards differ.

        // `@` marks a pasted proxy URL, not a bypass host; reject before port parse
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
        // [`parse::no_proxy`](crate::parse::no_proxy), which splits on `,` alone (Go's
        // `httpproxy`, its reference, does the same, and `;` was removed from
        // `LIST_SEPARATORS` for the reason written there) and the KDE reader, which goes
        // through it with a list `,`-separated already. GNOME's `ignore-hosts` is an array
        // and has no separator to split on.
        // [`parse::proxy_override`](crate::parse::proxy_override) does split on whitespace,
        // but only on the ASCII spellings Windows itself writes, so a Windows list still
        // reaches this arm when one entry holds something `char::is_whitespace` calls space
        // and `WINDOWS_BYPASS_SEPARATORS` does not: `U+00A0` or `U+3000` pasted into the
        // settings dialog. `src/parse.rs` says the same from the splitting side.
        if entry.chars().any(char::is_whitespace) {
            return Err(Error::bypass(
                entry,
                // `;` separates entries only in the Windows list. Advising it for
                // `no_proxy`, GNOME or KDE leaves two entries as a single dead rule.
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
        // too: a wider bypass than the entry asks for. Refused instead, and the reason
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
        // Microsoft bounds the damage at the list ("don't enter subwebs or trailing
        // slashes ... as they are invalidating the whole list otherwise" (KB 4551930)) and
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
        // Microsoft documents the wildcard in its place, "Enter a wildcard at the beginning
        // of an Internet address, IP address, or domain name that has a common ending"
        // (KB 4551930), and the three readings agree, asked for `sub.name`: `InternetOpenW`
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

        // A CIDR block whose IPv4 address is four parts but not four decimal octets
        // (`012.1.2.0/24`, `0xa.1.2.0/24`) has no reading its readers share. Chromium's
        // `ParseCIDRBlock` folds the address the URL way, so `012.1.2.0/24` is
        // `10.1.2.0/24` there, and `Suffix` stores that. CFNetwork and KIO's subnet reader
        // take each part as decimal, `12.1.2.0/24`, while Chromium reading the same macOS
        // or KDE list folds it, so `MacOs` and `Kde` refuse it. curl and Go reject such an
        // address outright. A short form (`192.168.1/24`) is left to `ipnet` below, which
        // refuses it; so is one with a trailing dot (`1.2.3./24`), which splits into four
        // parts but which the URL way reads as the short form `1.2.3`. A percent escape is
        // left there too, as the forbidden-character guard refuses it in an address entry.
        // The rows are `a_non_decimal_cidr_address_is_folded_in_no_proxy` in
        // `tests/bypass.rs` and `cidr_addresses_are_read_as_decimal` in
        // `tests/mac_exceptions_list.rs`.
        if let Some((address, prefix)) = lowered.split_once('/')
            && address.parse::<IpAddr>().is_err()
            && address.split('.').count() == 4
            && address.split('.').all(|part| !part.is_empty())
            && !address.chars().any(is_forbidden_host_char)
            && let Ok(Host::Ipv4(v4)) = crate::endpoint::parse_host(address)
        {
            if matches!(dialect, BypassDialect::MacOs | BypassDialect::Kde) {
                return Err(Error::bypass(
                    entry,
                    "entry is a CIDR block whose IPv4 address is written other than as four \
                     decimal octets, which the system reads as decimal and Chromium as a URL \
                     host (write the four decimal octets, for example 10.1.2.0/24)",
                ));
            }
            if let Ok(net) = format!("{v4}/{prefix}").parse::<IpNet>() {
                return Ok(Some(HostPattern::Cidr(net)));
            }
        }

        if let Ok(net) = lowered.parse::<IpNet>() {
            return Ok(Some(HostPattern::Cidr(net)));
        }

        // After scheme and CIDR parsing, a remaining `/` cannot name a host. Go's
        // `httpproxy` keeps an invalid CIDR such as `10.0.0/8` as a dead domain rule;
        // this crate rejects it so `reversed_exceptions` cannot bypass traffic silently.
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

        // These stores' resolvers compare an entry's name as written (KIO's `revmatch` and
        // Android's string match by their source, WinINet by the fail-closed reading until
        // measured), so `example.com.` there matches only a destination spelled with the
        // same dot, and stored as `example.com` it would bypass the destination the store
        // proxies. GNOME refuses the same shape in `BypassRules::push_gnome_entries`.
        // CFNetwork is not among them: it sheds the dot on both sides, so a macOS entry
        // keeps the root-marker reading (`cfnetwork_sheds_a_trailing_dot`). What is left
        // after `*.`, `.` and the dot is a name; `.` and `*.` alone carry none and fall
        // through to the arms below.
        if matches!(dialect, BypassDialect::Windows | BypassDialect::Kde)
            && host_text.ends_with('.')
            && !host_text.trim_matches(['*', '.']).is_empty()
        {
            return Err(Error::bypass(
                entry,
                "entry ends in a '.', which this store compares as written, so it matches \
                 only a destination spelled with the same trailing dot (write the name \
                 without it)",
            ));
        }

        // CFNetwork matches no entry with a port; storing it as a port-restricted rule
        // would bypass traffic CFNetwork proxies, so record it in `BypassRules::rejected`.
        if dialect == BypassDialect::MacOs && port.is_some() {
            return Err(Error::bypass(
                entry,
                "entry carries a port, which macOS does not read as a restriction — it \
                 compares the whole entry to the destination's host name, so no destination \
                 could ever match it (write the host on its own)",
            ));
        }

        // An invalid bracketed address would become a dead `Domain` suffix rule. Use
        // `parse_host` because the destination side accepts the same address grammar.
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
        // code point": the C0 controls, DEL, `#`, `%`, `<`, `>`, `?`, `[`, `\`, `]`, `^`
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
        // is converted the same way: by `Host::parse` when the host is parsed from text,
        // and by `host_key` when a caller built the `Host` itself. Without the step here a
        // Unicode entry is a dead rule: `日本.example` is stored verbatim while the
        // destination arrives as `xn--wgv71a.example`, so it matches nothing, in *either*
        // spelling, because the destination is always converted and the pattern never is.
        // Only non-ASCII text reaches the converter, preserving existing ASCII rules.
        let encoded;
        let host_text = if host_text.is_ascii() {
            host_text
        } else {
            encoded = idna_ascii(host_text).map_err(|reason| Error::bypass(entry, reason))?;
            &encoded
        };

        // RFC 1035 section 2.3.1 gives the empty label one place, the root at the end:
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
        // dot has to be something that *has* subdomains: a domain name. An address does
        // not: `.10.0.0.1` waits for an `a.10.0.0.1` that `Host::parse` refuses, in every
        // spelling the address side accepts (`.192.168.001.001`, `.0x0a.0.0.1`) and for an
        // unbracketed IPv6 too. Neither is a name that could never arrive on its own
        // (`.example.123`).
        //
        // "Could never match" is said of a destination a *special* scheme can carry, which
        // is what these lists are written about and what `matches_authority` admits: it
        // goes through `parse_host`, so `a.example.123` is refused there too. `matches_url`
        // is wider: WHATWG sends a non-special scheme to the opaque-host parser *before*
        // the "ends in a number" check, so `custom://a.example.123/` parses and its host is
        // `Domain("a.example.123")` while `http://a.example.123/` fails with
        // `InvalidIpv4Address`. A rule this arm refuses would have met that host. The
        // refusal stays (it catches the typo the shape almost always is, and dropping the
        // rule sends the request to the proxy rather than around it), but the reachability
        // it tests is the special-scheme one, and nothing further down may read it as more
        // than that. `a_refused_numeric_tail_is_only_unreachable_for_a_special_scheme` in
        // `tests/bypass.rs` is the measurement.
        //
        // A glob in the body gives the entry a narrow exemption, covering the spellings
        // that reach here, which keep the dot: `.*.10.0.0.1` becomes
        // `Wildcard("*.*.10.0.0.1")`, which needs `a.b.10.0.0.1`: its numeric last label
        // reads as an address, so no URL can carry that name. A star standing for the
        // empty string does not widen that: `*10.0.0.1` would meet `10.0.0.1`, but it opens
        // with neither `.` nor `*.`, so it has no subdomain body and never reaches this
        // arm. That holds for a whole address in the tail and does not survive being
        // generalised to any numeric one: a star is matched against the destination's
        // *text*, where it stands for the leading octets of an address as readily as for
        // whole labels, so `Wildcard("*.*.*.1")` is met by `10.0.0.1` itself and `.*.1` is
        // a live rule.
        //
        // The destination such a rule meets can only be an address, because reaching this
        // arm at all means the address reading was tried on the body and failed, which the
        // name reading only does for a last label that is all digits. So the entry is dead
        // unless the pattern could be laid over a dotted quad, and two things settle that.
        // Every literal byte has to be one a quad carries: a digit, a dot, or the star
        // itself, so `.*.0x0a.0.0.1`, `.*.example.123` and the colon of a broken IPv6 are
        // still refused. And the literal dots have to fit, counting the one in the `*.`
        // this entry gets in front of its body: a quad has four labels and so three dots,
        // which is why `.*.1` and `.*.0.1` live while `.*.0.0.1` and `.*.10.0.0.1` do not.
        // The test is permissive in the direction that costs nothing (no octet is 999, so
        // `.*.999` is kept and matches nothing) and strict in the one that costs a rule.
        // Entries whose body is a name never reach it: `.*.example` and `.a*b.example`
        // parse as domains and pass here as they always did.
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
            // Go ignores entries with no host part instead of failing: `config.init`
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
            // the entry has to be a name a destination could carry: a leading dot is not,
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
            // The leading dot is the reference's own rewrite ("we remap `.google.com` -->
            // `*.google.com`"), and it is applied to every rule that starts with one, glob
            // or not (`SchemeHostPortMatcherRule::FromUntrimmedRawString`). The `Domain`
            // arm below is that rewrite spelled as a suffix; this arm needs it written out,
            // because a pattern is matched literally and no host key begins with a dot:
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
        // the address `0.0.0.123`, which is what a destination spelled `123` already
        // becomes. Hence
        // `idna_ascii` keeps `Host::parse` away from an all-digit *label*, where the address
        // reading is the wrong one.
        // The suffix spellings were answered above; this is the bare one.
        let Ok(host) = crate::endpoint::parse_host(host_text) else {
            return Err(Error::bypass(entry, UNREACHABLE_NAME));
        };

        // `IpAddr` said no above, so an `Ipv4` here is a spelling other than four decimal
        // octets, and no store behind `Windows`, `MacOs` or `Kde` reads it as the address
        // folded here. WinINet, WinHTTP, CFNetwork and Android's `ProxySelector` compare it
        // with the destination as text, so `012.1.2.3` meets only a destination written
        // `012.1.2.3`. KIO's subnet reader takes each part as decimal, so `012.1.2.3` is
        // `12.1.2.3` and `10.66051` is no address; libproxy compares text against a host
        // Qt has already folded. Stored folded, the entry would bypass `10.1.2.3`, which
        // all of them hand to the proxy; stored as text, it would meet nothing, because
        // every destination reaches the rules already folded. The rows are
        // `a_non_decimal_ipv4_entry_is_refused_in_a_windows_list` in `tests/bypass.rs` and
        // `non_decimal_ipv4_spellings_are_compared_as_text` in `tests/mac_exceptions_list.rs`.
        if matches!(
            dialect,
            BypassDialect::Windows | BypassDialect::MacOs | BypassDialect::Kde
        ) && matches!(host, Host::Ipv4(_))
        {
            return Err(Error::bypass(
                entry,
                "entry is an IPv4 address written other than as four decimal octets, which \
                 this list's reader does not read as the address a URL parser does — Windows, \
                 macOS and Android compare it as text, KIO reads each part as decimal \
                 (write the four decimal octets, for example 10.1.2.3)",
            ));
        }

        // An address is one host under every dialect: there is nothing "under"
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
    // `host_text` must already be lowercased, and has had a trailing dot shed when
    // [`BypassRules::strip_trailing_dot`] says to; `ip` is `Some` when the host is a
    // literal address, already reduced by `reduce_mapped` when `reduce` is set, which is
    // [`BypassRules::ipv4_mapped_as_ipv4`]. Prefer [`BypassRules::matches`], which also
    // applies the implicit set and the simple-hostname switch.
    fn matches(
        &self,
        host_text: &str,
        ip: Option<IpAddr>,
        port: Option<u16>,
        reduce: bool,
    ) -> bool {
        match self {
            HostPattern::All => true,
            HostPattern::Cidr(net) => {
                let net = if reduce {
                    reduce_mapped_net(*net)
                } else {
                    *net
                };
                ip.is_some_and(|ip| net.contains(&ip))
            }
            HostPattern::Exact {
                host,
                port: rule_port,
            } => {
                // Addresses compare as addresses, so `10.0.0.1` and `[::ffff:10.0.0.1]` are
                // the one host they denote: `reduce_mapped` reduces both sides. This is
                // Go's `ipMatch`, which compares with `net.IP.Equal`. The references split
                // here: Chromium's `SchemeHostPortMatcherIPHostRule::Evaluate` is
                // `base::MatchPattern(url.GetHost(), ip_host_)`, plain text. Go is the one
                // to follow because the CIDR arm above reads the mapped spelling under the
                // same switch, and a rule that agreed with it on one shape and not the
                // other would make the matching inconsistent. The text fallback carries the
                // `Exact { host: Host::Domain(_) }` that a Windows list produces for every
                // bare name, and the hand-built one.
                let rule_ip = host_ip(host).map(|rule_ip| {
                    if reduce {
                        reduce_mapped(rule_ip)
                    } else {
                        rule_ip
                    }
                });
                let hit = match (rule_ip, ip) {
                    (Some(rule_ip), Some(destination_ip)) => rule_ip == destination_ip,
                    _ => host_text == host_key(host),
                };
                hit && port_matches(*rule_port, port)
            }
            HostPattern::Domain {
                suffix,
                match_self,
                port: rule_port,
            } => {
                // No `ip.is_none()` guard, so `.1` also matches `10.0.0.1` through text
                // matching, as in the Windows `ProxyOverride` lists this crate reads. Go
                // excludes addresses here; Chromium does not.
                //
                // The leading dot is `parse`'s convention, not something the type can
                // enforce: the fields are public and `BypassRules::new` exists to be filled
                // in by hand. So name the domain rather than slicing a byte off it (a
                // non-ASCII first character is not a char boundary) and refuse the empty
                // name outright, which is what the field doc promises matches nothing. It
                // would not: an empty `bare` strips nothing, so the whole host comes back
                // as `rest`, and any host still ending in a dot once one is shed then
                // satisfies the `ends_with('.')` test below. The destination side of that
                // is an ordinary URL and not a hand-built value: `url` reads
                // `http://example.com../` as `Host::Domain("example.com..")`. (Not "matches
                // every host": that is what an `ends_with(bare)` shape would do, and
                // this one strips instead.)
                //
                // The suffix's case is also a `parse` convention, so fold it here. The
                // `Exact` arm folds through `host_key`, which also lowercases the
                // destination. `Exact { "FooBar.com" }` and `Domain { ".FooBar.com" }` must
                // use the same case-insensitive comparison.
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
                // Folded on the rule side like `Domain` above, and folded *here* rather
                // than inside `glob_match`: that helper is shared with `sh_exp_match`, the
                // PAC `shExpMatch`, where case sensitivity is the reference behaviour:
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
                // Add the dot because a hand-built suffix without one matches the same
                // domain. Printing a subdomain-only rule as `example.com` makes
                // [`Self::parse`] read it back with `match_self: true`, widening the bypass
                // when a logged rule is parsed again.
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

/// Windows `<-loopback>`: subtracts the whole implicit bypass set
/// ([`BypassRules::implicit`]) from the entries written before it. Parsed to
/// [`HostPattern::SubtractImplicit`]; see [`BypassRules::bypass_loopback`].
pub const NO_LOOPBACK_TOKEN: &str = "<-loopback>";

/// The destinations a resolver sends direct with no list entry naming them: the implicit
/// bypass set, held in [`BypassRules::implicit`].
///
/// Each store's own resolver has its own set, so a rule set read from a store carries that
/// store's: an implicit bypass the resolver does not have is a destination this crate
/// reports direct while the machine sends it to the proxy. The `WinInet` and `CfNetwork`
/// columns are the machine's answer, measured by handing the resolver a proxy and an
/// otherwise empty list and asking where each destination went; `Empty` is read off
/// GLib's and KIO's matchers, which consult the list and nothing else.
///
/// | Destination | `Broad` | `WinInet` | `CfNetwork` | `Empty` |
/// |---|---|---|---|---|
/// | `localhost` (any case) | ✓ | ✓ | ✓ | |
/// | `loopback` | ✓ | ✓ | | |
/// | `127.0.0.1`, `[::1]` | ✓ | ✓ | ✓ | |
/// | the rest of `127.0.0.0/8` | ✓ | | | |
/// | `*.localhost`, a trailing dot | ✓ | | | |
/// | `169.254.0.0/16`, `[fe80::]/10` | | ✓ | | |
/// | an IPv4-mapped spelling of a loopback address | ✓ | | | |
///
/// [`HostPattern::SubtractImplicit`] (`<-loopback>`) subtracts whichever set is in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ImplicitBypass {
    /// The loopback half of Chromium's implicit rules (`IsLocalhost`, IPv4-mapped
    /// loopback) and WinINet's `loopback` name. The default, and what [`parse::no_proxy`]
    /// carries: the environment variable has no single resolver to measure, and loopback
    /// is the part of Chromium's set a local proxy has no use for. Chromium's link-local
    /// ranges are left out: every `no_proxy` reader measured (Go, Python's `urllib`, curl,
    /// .NET, hyper-util) sends `169.254.0.0/16` and `fe80::/10` to the proxy, and
    /// `169.254.169.254` is the cloud instance-metadata endpoint, which an inspecting proxy
    /// is often there to see.
    ///
    /// [`parse::no_proxy`]: crate::parse::no_proxy
    #[default]
    Broad,
    /// WinINet's, which [`parse::proxy_override`](crate::parse::proxy_override) and the
    /// Windows store carry: the names `localhost` and `loopback`, the addresses
    /// `127.0.0.1` and `::1`, and the link-local ranges. The same six Chromium records as
    /// Windows' own set.
    WinInet,
    /// CFNetwork's: the name `localhost` and the addresses `127.0.0.1` and `::1`.
    /// CFNetwork applies it only while the settings carry a bypass key, so the macOS and
    /// iOS stores carry this set when the dictionary has an `ExceptionsList` array with at
    /// least one element or `ExcludeSimpleHostnames` switched on, and
    /// [`Empty`](Self::Empty) otherwise, `ExcludeSimpleHostnames` set to 0 and an empty
    /// array included. A Mac configured through System Settings has the array while its
    /// list holds an entry; clearing the list leaves an empty one, which the system
    /// settings call drops.
    CfNetwork,
    /// No implicit bypass: every destination is decided by the entries. GNOME's
    /// `GSimpleProxyResolver` and KDE's KIO have none.
    Empty,
}

impl ImplicitBypass {
    // Whether the destination is in this set. `ip` is the address as written, before
    // `reduce_mapped`: only `Broad` reads an IPv4-mapped spelling as the address it maps.
    fn covers(self, host_text: &str, ip: Option<IpAddr>) -> bool {
        match self {
            Self::Broad => is_loopback(host_text, ip.map(reduce_mapped)),
            Self::WinInet => match ip {
                Some(ip) => is_loopback_address(ip) || is_link_local(Some(ip)),
                None => host_text == "localhost" || host_text == "loopback",
            },
            Self::CfNetwork => match ip {
                Some(ip) => is_loopback_address(ip),
                None => host_text == "localhost",
            },
            Self::Empty => false,
        }
    }
}

// Covers bare and suffix entries, including malformed IPv6 such as `2001:db8:1`.
// `Error::bypass` withholds colon-containing input, so the reason must identify its shape.
const UNREACHABLE_NAME: &str = "entry is not a name any destination could carry, so no \
                                destination could ever match it (a last label that reads as \
                                a number, as in example.123, is taken for an address and \
                                refused as one; so is an unbracketed IPv6 that is not a \
                                valid address, as in 2001:db8:1)";

// GNOME strips only leading `*.` (`gsimpleproxyresolver.c:227`); every other `*`, including
// a bare one, is literal and matches no host. Reject the dead rule so it cannot become a
// bypass GNOME does not grant; see the `All` guard in `parse_in`.
const GNOME_LITERAL_STAR: &str = "entry contains a '*' that GNOME does not read as a \
                                  wildcard — only a leading '*.' is one there — so no \
                                  destination could ever match it (write *.example.com for \
                                  a domain, or the host on its own)";

// macOS reads only leading `*.` and trailing `.*` as wildcards. A bare `*` matches nothing;
// treating it as `All` would switch off the proxy.
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
    /// Dot-less host bypass, as a switch (macOS `ExcludeSimpleHostnames`). It takes any
    /// destination without a dot, a dot-less IPv6 literal included, where the list
    /// spelling [`HostPattern::Local`] takes no IP literal; and under
    /// [`reversed_exceptions`](Self::reversed_exceptions) the two mean opposite things (see
    /// [`excludes_simple_hostnames`](Self::excludes_simple_hostnames)).
    pub exclude_simple_hostnames: bool,
    /// KDE/`config-kde` inclusion list; the implicit set, where there is one, still
    /// applies; see [`matches`](Self::matches).
    pub reversed_exceptions: bool,
    /// Redacted unparseable originals; affects verdict under
    /// [`reversed_exceptions`](Self::reversed_exceptions). Not a complete ledger of the
    /// entries that match nothing: see [`HostPattern::Wildcard`].
    pub rejected: Vec<RejectedValue>,
    /// Whether a destination's port counts only when the destination wrote one, so that a
    /// ported entry such as `example.com:80` does not meet a portless `http://example.com/`.
    ///
    /// Set for GNOME `ignore-hosts` and nowhere else. GLib resolves the destination with
    /// `G_URI_FLAGS_NONE` (`gsimpleproxyresolver.c:341`) and fills a scheme's default port
    /// only under `G_URI_FLAGS_SCHEME_NORMALIZE` (`guri.c:1006`), so the port it compares
    /// against is 0 unless the URL carried one. Windows fills it: a `ProxyOverride` entry
    /// of `host:80` was measured bypassing a portless `http://host/`.
    ///
    /// [`matches`](Self::matches) does not read this: it is told a port and answers about
    /// that port. [`matches_url`](Self::matches_url) is where it is read, and is the reason
    /// to prefer that method whenever the destination is a `Url`: it passes
    /// [`Url::port`](https://docs.rs/url/latest/url/struct.Url.html#method.port) rather than
    /// `port_or_known_default` when this is set. Reading the field by hand is supported, not
    /// recommended.
    ///
    /// `Url` drops a port equal to the scheme's default while parsing, so `http://host:80/`
    /// and `http://host/` become the same value and `port` returns `None` for both. A rule
    /// on that port (`host:80` for `http`, `host:443` for `https`) therefore never matches
    /// here, while GLib still matches the spelling with an explicit port. The error is in
    /// the safe direction: the destination uses the proxy instead of connecting directly.
    /// URL parsing removes the distinction before this crate receives the URL.
    pub require_explicit_port: bool,
    /// The destinations bypassed with no entry naming them. [`ImplicitBypass::Broad`]
    /// unless the source says otherwise; each store sets its own resolver's set.
    pub implicit: ImplicitBypass,
    /// Whether an IPv4-mapped IPv6 destination (`[::ffff:10.0.0.1]`) meets the entries as
    /// the IPv4 address it maps. Set by default and for
    /// [`parse::no_proxy`](crate::parse::no_proxy), which is Chromium's and Go's reading.
    ///
    /// Cleared for every store's list. Android's selector compares the host string, and
    /// WinINet and CFNetwork are unmeasured for an explicit entry and take the reading that
    /// cannot send a proxied destination direct. GNOME `ignore-hosts` and KDE `NoProxyFor`
    /// are read off their resolvers, which compare the address in the family it was
    /// written in: GLib's `g_inet_address_mask_matches`
    /// and Qt's `QHostAddress::isInSubnet`, which KIO calls, both answer no across
    /// families, so `10.0.0.0/8` does not bypass `[::ffff:10.0.0.1]` there.
    /// [`implicit`](Self::implicit) does not read this; which spellings an implicit set
    /// covers is part of the set.
    pub ipv4_mapped_as_ipv4: bool,
    /// Whether a destination's trailing dot is shed before it meets the entries, so that
    /// `example.com` and `*.example.com` also match `example.com.` and `www.example.com.`.
    /// Set by default and for [`parse::no_proxy`](crate::parse::no_proxy), which read the
    /// dot as the DNS root it denotes.
    ///
    /// Set for macOS and iOS too: CFNetwork was measured shedding the dot on the
    /// destination and on the entry (`cfnetwork_sheds_a_trailing_dot` in
    /// `tests/mac_exceptions_list.rs`).
    ///
    /// Cleared for every other store, because each of those resolvers compares the name as
    /// written (and a store entry that itself ends in a dot is refused into
    /// [`rejected`](Self::rejected) there for the same reason): WinINet sent `localhost.`
    /// to the proxy under a `ProxyOverride` naming `localhost`, GLib's `ignore_host` and
    /// KIO's `revmatch` compare text, and Android's `ProxySelector` compares strings. The
    /// implicit set and the simple-hostname switch do not read this; each set says which
    /// spellings it covers, and a trailing dot is a dot.
    pub strip_trailing_dot: bool,
}

impl Default for BypassRules {
    fn default() -> Self {
        Self::new()
    }
}

impl BypassRules {
    /// An empty rule set with the [`ImplicitBypass::Broad`] implicit set, so loopback
    /// destinations are bypassed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
            exclude_simple_hostnames: false,
            reversed_exceptions: false,
            rejected: Vec::new(),
            require_explicit_port: false,
            implicit: ImplicitBypass::Broad,
            ipv4_mapped_as_ipv4: true,
            strip_trailing_dot: true,
        }
    }

    /// Whether the list leaves the implicit bypass set ([`implicit`](Self::implicit)) in
    /// force, which it does unless it carries [`HostPattern::SubtractImplicit`]
    /// (`<-loopback>`). Under [`ImplicitBypass::Empty`] there is no set to leave in force,
    /// and the answer is about the list alone.
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
    /// // The token is in the list, so this is `false`, but `localhost` is written
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

    // Repeats are collapsed by [`dedup_patterns`](Self::dedup_patterns) after parsing.
    pub(crate) fn push_pattern(&mut self, pattern: HostPattern) {
        self.patterns.push(pattern);
    }

    // Collapse repeats once the list is complete; a `Vec::contains` per push is quadratic
    // on a long list. A repeat is dropped only within a run between `<-loopback>` tokens,
    // because [`HostPattern::SubtractImplicit`] changes what a repeat means: in
    // `localhost, <-loopback>, localhost` the second `localhost` is the one that decides.
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

    // GNOME's `ignore-hosts`, sorted the way GLib's `reparse_ignore_hosts`
    // (`gsimpleproxyresolver.c`) sorts it before anything is matched. An entry GLib reads
    // as an address or a mask is a `Cidr` here, unreduced, because `GInetAddressMask`
    // compares addresses of one family only. Everything else is a name, and a name GLib
    // either refuses or can never match is refused here rather than handed to `parse_in`,
    // which would normalise it into a live rule: a bracketed address with no port, a mask
    // GLib rejects (bits past the prefix, a leading zero), `<local>` and `<-loopback>`,
    // non-ASCII text, a trailing dot, and an IPv4 spelling `inet_pton` does not read.
    // GLib's matcher also stops at the
    // first name of length zero (`for (...; priv->ignore_domains[i].length; ...)`), so
    // `["", "example.com"]` bypasses nothing there; every name after such an entry is
    // refused for that reason.
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    pub(crate) fn push_gnome_entries<'a>(&mut self, entries: impl Iterator<Item = &'a str>) {
        let mut names_ended = false;
        for entry in entries {
            let entry = BypassDialect::Gnome.trim(entry);
            if let Some(net) = glib_mask(entry) {
                self.push_pattern(HostPattern::Cidr(net));
                continue;
            }
            let refusal = match glib_name(entry) {
                Err(reason) => Some(reason),
                Ok("") => {
                    names_ended = true;
                    None
                }
                Ok(_) if names_ended => Some(
                    "entry follows one that leaves no name (empty, '.', '*.' or a bare \
                     port), and GLib stops reading names there, so it never matches",
                ),
                Ok(name)
                    if name.eq_ignore_ascii_case(LOCAL_TOKEN)
                        || name.eq_ignore_ascii_case(NO_LOOPBACK_TOKEN) =>
                {
                    Some(
                        "entry is a WinINet token, which GLib does not read: it compares the \
                         entry to a host so named, and no host is",
                    )
                }
                Ok(name) if !name.is_ascii() => Some(
                    "entry is not ASCII, and GLib compares it unconverted with the ASCII \
                     form of the destination, so it never matches (write the xn-- form)",
                ),
                Ok(name) if name.ends_with('.') => Some(
                    "entry ends in a '.', which GLib compares as written, so it matches \
                     only a destination spelled with the same trailing dot",
                ),
                Ok(name) if name.contains('/') => Some(
                    "entry is not a mask GLib accepts (an address with bits set past the \
                     prefix, or with a leading zero), so GLib reads it as a name that \
                     matches nothing",
                ),
                Ok(name)
                    if name.parse::<IpAddr>().is_err()
                        && matches!(crate::endpoint::parse_host(name), Ok(Host::Ipv4(_))) =>
                {
                    Some(
                        "entry is an IPv4 spelling inet_pton does not read (short, octal or \
                         hex), so GLib compares it as text and it never matches",
                    )
                }
                Ok(_) => None,
            };
            match refusal {
                Some(reason) => {
                    crate::trace::warning!(
                        error = %crate::trace::SafeError(&Error::bypass(entry, reason)),
                        "skipping an ignore-hosts entry GLib would not match"
                    );
                    self.rejected.push(RejectedValue::new(
                        RejectionKind::InvalidBypassPattern,
                        RejectionSource::BypassList,
                        entry,
                    ));
                }
                None if names_ended && entry.is_empty() => {}
                None => self.push_entry_in(entry, BypassDialect::Gnome),
            }
        }
    }

    pub(crate) fn push_entry_in(&mut self, entry: &str, dialect: BypassDialect) {
        self.push_entry_from(entry, dialect, RejectionSource::BypassList);
    }

    // [`Self::push_entry_in`] for a source that records its own refusals under a name of
    // its own, so a refused entry carries one source whichever check refused it.
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    pub(crate) fn push_entry_from(
        &mut self,
        entry: &str,
        dialect: BypassDialect,
        source: RejectionSource,
    ) {
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
                    source,
                    entry,
                ));
            }
        }
    }

    /// Whether either representation of the dot-less host rule is present: the
    /// [`exclude_simple_hostnames`](Self::exclude_simple_hostnames) switch or a
    /// [`HostPattern::Local`] entry.
    ///
    /// The switch also bypasses dot-less IPv6 literals, which a `Local` entry does not.
    /// Under [`reversed_exceptions`](Self::reversed_exceptions), the switch bypasses
    /// dot-less hosts before the list is consulted, as the implicit set does. A `Local`
    /// entry is part of the inclusion list, so it keeps dot-less hosts using the proxy. A
    /// `true` result therefore does not guarantee that [`matches`](Self::matches) bypasses
    /// a dot-less host; use `matches` to check a destination. Converting between these
    /// representations silently reverses that verdict.
    #[must_use]
    pub fn excludes_simple_hostnames(&self) -> bool {
        self.exclude_simple_hostnames
            || self
                .patterns
                .iter()
                .any(|p| matches!(p, HostPattern::Local))
    }

    /// No entries and neither switch: [`patterns`](Self::patterns) empty,
    /// [`exclude_simple_hostnames`](Self::exclude_simple_hostnames) and
    /// [`reversed_exceptions`](Self::reversed_exceptions) off. `<-loopback>` is an entry
    /// in [`patterns`](Self::patterns), so a list holding only that is not empty; it
    /// carries an instruction, and reporting it empty would invite a caller to drop it and
    /// put the implicit bypass back. Omits [`rejected`](Self::rejected) (only matters under
    /// [`reversed_exceptions`](Self::reversed_exceptions), which already answers `false`).
    ///
    /// Omits [`implicit`](Self::implicit) too: an empty list is "no entries", not "bypasses
    /// nothing". Under [`ImplicitBypass::WinInet`] it still sends WinINet's six destinations
    /// direct, and only under [`ImplicitBypass::Empty`] does it send nothing direct.
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
            // Reversed empty list bypasses everything, not trivial.
            && !self.reversed_exceptions
    }

    /// Whether `host` bypasses the proxy.
    ///
    /// An empty host returns `false` in either mode before any other checks. The crate's
    /// routing functions handle hostless URLs as Direct before consulting the bypass list,
    /// so this applies to caller-constructed `Host` values. A `Host::Domain` is treated as
    /// text without re-parsing it as an address: `Domain("0177.0.0.1")` misses the loopback
    /// switch that [`matches_authority`](Self::matches_authority) matches for the same
    /// text. `Url::host` and `url::Host::parse` normalize numeric spellings to `Host::Ipv4`
    /// and cannot produce this domain value. Re-parsing here would add work to every call
    /// for a value that requires explicit construction with `Host::Domain(_)`.
    ///
    /// No name resolution is performed. A host that `/etc/hosts` or DNS maps to `127.0.0.1`
    /// is matched as text, so it misses the implicit set and uses the proxy unless an entry
    /// matches it. Chromium matches the same way:`ProxyHostMatchingRules::Matches` takes
    /// a `GURL` and its rules check `url.host()`. Resolving names in this per-request
    /// predicate would add lookup latency and failures to each request.
    ///
    /// Ported `:port` rules never match `port = None` (Go). Under
    /// [`reversed_exceptions`](Self::reversed_exceptions), patterns are inclusion-only
    /// while [`rejected`](Self::rejected) is empty.
    ///
    /// Entries are evaluated **back to front**, and the first matching rule determines the
    /// result: "Later rules override earlier rules … when mixing positive and negative
    /// rules, evaluation order makes a difference" (Chromium,
    /// `net/base/scheme_host_port_matcher.cc`; the expectation "comes from WinInet (which
    /// is where `<-loopback>` comes from)", `proxy_host_matching_rules_unittest.cc`). Order
    /// matters only with [`HostPattern::SubtractImplicit`], which removes a bypass:
    /// `127.0.0.1;<-loopback>` proxies `127.0.0.1`, while `<-loopback>;127.0.0.1` sends it
    /// direct. If no entry matches, the implicit set ([`implicit`](Self::implicit))
    /// determines the result. It is not inverted by `reversed_exceptions`, because an
    /// inclusion list that does not name loopback does not request proxying for loopback.
    ///
    /// [`exclude_simple_hostnames`](Self::exclude_simple_hostnames) is a switch and not an
    /// entry, so it is not inverted either, unlike a [`HostPattern::Local`] entry, which
    /// is; see [`excludes_simple_hostnames`](Self::excludes_simple_hostnames) for why that
    /// changes the answer here. An IPv4-mapped IPv6 destination (`::ffff:a.b.c.d`) is
    /// compared with the entries as the IPv4 address it maps while
    /// [`ipv4_mapped_as_ipv4`](Self::ipv4_mapped_as_ipv4) is set, against CIDR and exact
    /// patterns alike.
    ///
    /// ```
    /// # use proxy_watch::parse;
    /// let rules = parse::no_proxy("localhost, .example.com, 10.0.0.0/8");
    /// assert!(rules.matches_authority("www.example.com"));
    /// assert!(rules.matches_authority("10.1.2.3:443"));
    /// assert!(!rules.matches_authority("example.org"));
    /// // Loopback bypasses even though the list above names only `localhost`; link-local
    /// // does not, in `no_proxy`.
    /// assert!(rules.matches_authority("127.0.0.2"));
    /// assert!(!rules.matches_authority("169.254.1.1"));
    /// // A Windows list carries WinINet's implicit set, which stops at `127.0.0.1` and
    /// // takes in link-local.
    /// assert!(parse::proxy_override("").matches_authority("169.254.1.1"));
    /// assert!(parse::proxy_override("").matches_authority("127.0.0.1"));
    /// assert!(!parse::proxy_override("").matches_authority("127.0.0.2"));
    /// ```
    #[must_use]
    pub fn matches(&self, host: &Host, port: Option<u16>) -> bool {
        let text = host_key(host);
        if text.is_empty() {
            return false;
        }
        let written = host_ip(host);
        let reduce = self.ipv4_mapped_as_ipv4;
        let ip = if reduce {
            written.map(reduce_mapped)
        } else {
            written
        };
        let implicit = self.implicit.covers(&text, written);
        let entry_text = if self.strip_trailing_dot {
            text.strip_suffix('.').unwrap_or(&text)
        } else {
            &text
        };
        // What a destination no entry names answers under `reversed_exceptions`: the list
        // is then the set that *uses* the proxy, so being absent from it is the bypass. A
        // rejected entry makes that set incomplete, and an incomplete inclusion list may
        // not send anything direct.
        let unnamed = self.reversed_exceptions && self.rejected.is_empty();

        // Before the entries, and so before `reversed_exceptions` can invert it: this is a
        // switch, not a list entry. macOS is where it comes from and macOS has no reversed
        // mode, so the combination has no reference to copy, but the shape does, and the
        // list spelling `<local>` is a `HostPattern::Local` among the entries, is inverted,
        // and therefore answers the opposite. Both readings are right for what they are;
        // what would be wrong is treating them as one flag.
        //
        // The one entry that still overrides it is `<-loopback>`, because Chromium models
        // this switch as a rule *prepended* to the list
        // (`PrependRuleToBypassSimpleHostnames`, `proxy_config_service_mac.cc`) and so puts
        // every entry after it. Only a dot-less host that is also in the implicit set
        // (`localhost`, `[::1]`) is reachable both ways; the rest of what the switch
        // covers no negative entry can name.
        //
        // The test is the dot alone, so an IPv6 literal is simple here and an IPv4 one is
        // not: CFNetwork was measured to bypass `[fe80::1]` and `[fec0::1]` under this
        // switch and to proxy them under `<local>`, which keeps Chromium's rule of no IP
        // literals at all.
        if self.exclude_simple_hostnames
            && !text.contains('.')
            && (self.bypass_loopback() || !implicit)
        {
            return true;
        }

        for pattern in self.patterns.iter().rev() {
            if matches!(pattern, HostPattern::SubtractImplicit) {
                if implicit {
                    return unnamed;
                }
            } else if pattern.matches(
                // `<local>` asks whether the name has a dot, and a trailing one counts.
                if matches!(pattern, HostPattern::Local) {
                    &text
                } else {
                    entry_text
                },
                ip,
                port,
                reduce,
            ) {
                return !self.reversed_exceptions;
            }
        }
        implicit || unnamed
    }

    /// Whether a destination URL bypasses the proxy.
    ///
    /// Prefer this over [`matches`](Self::matches) whenever the destination is a `Url`: it is
    /// the only entry point that reads [`require_explicit_port`](Self::require_explicit_port),
    /// and getting that wrong by hand is silent: a GNOME `ignore-hosts` of `example.com:80`
    /// asked about with `port_or_known_default` reports a bypass GNOME does not have. This
    /// crate's own `resolve` goes through here.
    ///
    /// A URL with no host to compare (`data:`, `mailto:`, or one whose host was emptied)
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
        // The flag is read only here. `port_or_known_default` is the majority reading: a
        // rule written `example.com:80` is meant for the HTTP port whether or not the URL
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
// `char::is_control` also catches U+0080..=U+009F. These inputs fail punycode anyway, but
// naming the control character in the error helps identify it. Whitespace is checked first.
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
        // Reject `*` here because punycode would encode it and change the glob's meaning.
        if label.contains('*') {
            return Err(
                "entry mixes a '*' glob with non-ASCII text in one label, which has no \
                 punycode spelling; write the label as punycode (xn--…) instead"
                    .to_owned(),
            );
        }
        // The loan keeps `１２３` a label rather than the IPv4 address `123`; `parse_host`
        // decides afterwards, over the whole host, whether it is a name or an address.
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

// `g_inet_address_mask_new_from_string`: an address `inet_pton` reads, optionally `/` and
// a decimal prefix no longer than the family's, with no bit set past the prefix.
fn glib_mask(entry: &str) -> Option<IpNet> {
    let (address, prefix) = match entry.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (entry, None),
    };
    let address: IpAddr = address.parse().ok()?;
    let full = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
            text.parse::<u8>().ok()?
        }
        Some(_) => return None,
        None => full,
    };
    let net = IpNet::new(address, prefix).ok()?;
    (net.trunc().addr() == address).then_some(net)
}

// The name `reparse_ignore_hosts` stores for an entry that is not a mask: a bracketed
// address needs a port after it, a single `:` splits off a decimal port, and a leading `*.`
// or `.` comes off unless the rest is an address.
fn glib_name(entry: &str) -> Result<&str, &'static str> {
    let (name, port) = if let Some(inner) = entry.strip_prefix('[') {
        let (address, rest) = inner
            .split_once(']')
            .ok_or("entry opens a bracket it does not close")?;
        let port = rest.strip_prefix(':').ok_or(
            "entry is a bracketed address with no port, which GLib refuses (write it \
             without brackets, or as [address]:port)",
        )?;
        (address, Some(port))
    } else {
        match entry.split_once(':') {
            Some((name, port)) if !port.contains(':') => (name, Some(port)),
            _ => (entry, None),
        }
    };
    if port.is_some_and(|port| !port.bytes().all(|b| b.is_ascii_digit())) {
        return Err("entry's port is not a number");
    }
    if name.parse::<IpAddr>().is_ok() {
        return Ok(name);
    }
    Ok(name
        .strip_prefix("*.")
        .or_else(|| name.strip_prefix('.'))
        .unwrap_or(name))
}

// The loopback half of `ImplicitBypass::Broad`; the other sets name their members outright.
fn is_loopback(host_text: &str, ip: Option<IpAddr>) -> bool {
    if let Some(ip) = ip {
        // `127.0.0.0/8` and `::1`. `::ffff:127.0.0.1` arrives as `127.0.0.1`, reduced by
        // `ImplicitBypass::covers`.
        return ip.is_loopback();
    }
    // WinINet bypasses `localhost` and `loopback` by name; Go bypasses `localhost`.
    // Chromium additionally treats any `*.localhost` subdomain and a single trailing
    // dot as local (`net/base/url_util.cc`, `IsLocalHostname`); a trailing dot
    // is stripped before comparing so `localhost.` and `app.localhost.` match too, the
    // same way DNS treats a trailing dot as denoting the root and not a distinct name.
    // Neither WinINet nor CFNetwork does either, which is why their sets are their own.
    let name = host_text.strip_suffix('.').unwrap_or(host_text);
    name == "localhost" || name == "loopback" || name.ends_with(".localhost")
}

// Whether `ip` is link-local: IPv4 `169.254.0.0/16` (APIPA) or IPv6 `fe80::/10`. Only
// `ImplicitBypass::WinInet` holds these, compared as written: `::ffff:169.254.0.0/112`
// is another address there.
//
// Read as one implicit set together with the loopback members, so
// [`NO_LOOPBACK_TOKEN`] clears both at once. That is what the token means upstream:
// Chromium's `MatchesImplicitRules` is `IsLocalhost || IsIPv4MappedLoopback ||
// IsLinkLocalIP` in one expression, and `<-loopback>` is the rule that subtracts the whole
// of it: "The name <-loopback> is not a very precise name (as the implicit rules cover
// more than strictly loopback addresses), however this is the name that is used on Windows
// so re-used here" (`net/proxy_resolution/proxy_host_matching_rules.cc`, the file
// `proxy_bypass_rules.cc` became). The same file records Windows' own implicit set as
// "localhost, loopback, 127.0.0.1, [::1], 169.254/16, [FE80::]/10", which is
// `ImplicitBypass::WinInet` member for member, measured against WinINet itself. The flag
// here is named for the token that clears it, not for half of what the token covers.
//
// A proxy on the same host can reach link-local `169.254.169.254`; ignoring `<-loopback>`
// for link-local addresses can send instance-metadata traffic direct.
fn is_link_local(ip: Option<IpAddr>) -> bool {
    match ip {
        Some(IpAddr::V4(v4)) => v4.is_link_local(),
        Some(IpAddr::V6(v6)) => v6.is_unicast_link_local(),
        None => false,
    }
}

// Chromium's `BypassSimpleHostnamesRule` (`proxy_host_matching_rules.cc:80`): a name with no
// period, and never an IP literal. A trailing dot counts as "has a period", so it is not stripped
// first, unlike the `Domain` arm, which strips one from the same `host_text`.
//
// This is `HostPattern::Local`'s test. The `exclude_simple_hostnames` switch tests the dot
// alone, because CFNetwork counts a dot-less IPv6 literal as simple; see `matches`.
fn is_simple_host_name(host_text: &str, ip: Option<IpAddr>) -> bool {
    ip.is_none() && !host_text.contains('.')
}

// The lowercase textual key used for matching. IPv6 hosts are *not* bracketed here,
// matching Go's `config.init` (`http/httpproxy/proxy.go`), which strips the brackets
// before `net.ParseIP` so `ipMatch` compares an unbracketed address.
fn host_key(host: &Host) -> String {
    match host {
        // Public `matches` accepts caller-built `Host::Domain` values. Convert them like
        // `matches_authority` does so Unicode names meet punycoded rules; an unconvertible
        // name retains its text and matches nothing.
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
// Allocation-free because it runs once per rule per destination. A split inside a
// multi-byte character would panic, so the boundary check returns `false` before slicing.
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

// The address a host denotes, in the family it was written in.
fn host_ip(host: &Host) -> Option<IpAddr> {
    match host {
        Host::Domain(_) => None,
        Host::Ipv4(ip) => Some(IpAddr::V4(*ip)),
        Host::Ipv6(ip) => Some(IpAddr::V6(*ip)),
    }
}

// `::ffff:a.b.c.d` reduced to the IPv4 address it maps; every other address unchanged.
//
// Applied once in `BypassRules::matches` rather than at each comparison, so `is_loopback`
// needs no mapped-spelling arm of its own. Chromium and Go both
// reduce, in their own idiom; GLib and Qt do not, which is what
// `BypassRules::ipv4_mapped_as_ipv4` switches.
fn reduce_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

// `127.0.0.1` or `::1` as written: the two loopback addresses WinINet and CFNetwork bypass,
// where `Ipv4Addr::is_loopback` would take the whole `127.0.0.0/8`.
fn is_loopback_address(ip: IpAddr) -> bool {
    ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || ip == IpAddr::V6(Ipv6Addr::LOCALHOST)
}

// The rule-side half of [`reduce_mapped`]: `::ffff:10.0.0.0/104` is the IPv4 block
// `10.0.0.0/8`. Applied at match time under the same switch, so a source whose resolver
// compares one family only keeps the block it wrote.
//
// With the switch set, destinations reach `contains` as IPv4; a mapped rule must also be
// reduced or it matches neither spelling. Under `reversed_exceptions`, this silent miss
// sends traffic direct around the proxy.
//
// Only a net that lies wholly inside `::ffff:0:0/96` converts. A shorter prefix covers
// unmapped IPv6 as well, so it is an IPv6 rule about IPv6 destinations, and mapped
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
