//! Pure parsers for OS proxy string formats.
//!
//! List parsers drop malformed *elements* and keep the rest. Dropping a scheme endpoint
//! without recording it would be fail-open; bypass drops are fail-closed → `rejected`.
//!
//! # Writing a bypass list
//!
//! Every store has one, no two of them read it the same way, and the differences decide
//! which hosts go direct. What an entry means to this crate, by the list it is written in
//! — the store's own reading, except where a cell says the two part company:
//!
//! | Entry | `no_proxy`, KDE `NoProxyFor` | Windows `ProxyOverride` | macOS `ExceptionsList` | GNOME `ignore-hosts` |
//! |---|---|---|---|---|
//! | separator between entries | `,` alone — a `;` leaves the two names one dead rule, and an entry still holding a space is rejected | `;`, `,` or whitespace | the array is the separator | the array is the separator |
//! | `example.com` | that host **and everything under it** | that host alone | that host alone | that host **and everything under it** |
//! | `.example.com`, `*.example.com` | the subdomains, not `example.com` itself | `*.example.com` is the subdomains; `.example.com` is **rejected** — Windows has no reading for a leading `.` (below) | the subdomains | the same rule as the bare name: the domain *and* its subdomains |
//! | a `*` anywhere else (`192.168.*`) | a glob here, which is Chromium's reading; Go and libproxy take it as literal text no host carries | a glob | syntax only as a trailing `.*`, which misses the bare host a Mac's own `name.*` still reaches; anything else is rejected | never syntax; rejected |
//! | a bare `*` | every destination direct | every destination direct | rejected — it matches no host on a Mac | rejected, same reason |
//! | `10.0.0.0/8` | the network | **rejected** — Windows has no `/` in this grammar, and one entry holding it turns the proxy off for every destination (below); write the range as `10.*` | the network | the network |
//! | `example.com:8080` | holds the entry to that port | holds it | **rejected** — macOS compares the whole entry to the host name, so a port kills it | holds it, but a portless `http://` URL is asked about with port 0 and will not meet it |
//! | `<local>`, `<-loopback>` | read | read | read | read |
//! | a space at either end | trimmed | trimmed | **kept**, and no host carries it, so the entry is rejected | trailing trimmed, leading kept and rejected |
//!
//! A rejected entry is not dropped in silence: it lands in
//! [`BypassRules::rejected`](crate::BypassRules::rejected) with the reason, so a rule that
//! does nothing reads as doing nothing rather than as live.
//!
//! Two spellings cost a Windows list more than themselves, and both are refused here rather
//! than read. An entry starting with `.` is granted nothing by any reader measured: WinINet
//! refuses the whole list over one, while WinHTTP and the registry reading keep the list and
//! send the subdomains to the proxy regardless — `*.name` is the spelling to write. An entry
//! holding a `/`, a CIDR block included, goes further still: the registry reading stops
//! using the proxy at all and every destination goes direct. Both land in `rejected` with
//! the reason while the entries beside them stay live — which is narrower than what the
//! machine does with the same list, and as wide a claim as the readings support.
//!
//! Two rows are worth stating flat. A bare name changes meaning between the first column
//! and the next two, so `contoso.com` in `no_proxy` covers `api.contoso.com` and the same
//! text in `ProxyOverride` does not. And `<local>` / `<-loopback>` are read out of every
//! list here so the sources share one vocabulary, while only Windows' own resolver acts on
//! them: a macOS or GNOME store spelling one gets a bypass from this crate and none from
//! the machine. `the_local_token_bypasses_nothing_here` in `tests/mac_exceptions_list.rs`
//! measures the macOS half; GNOME's is read off GLib, in `src/sys/linux/gsettings_map.rs`.

use std::collections::HashMap;

use crate::bypass::{BypassDialect, BypassRules};
use crate::diagnostic::{RejectedValue, RejectionKind, RejectionSource};
use crate::endpoint::{ProxyEndpoint, ProxyEntry, ProxyScheme, Scheme};
use crate::error::Error;
use crate::mode::ProxyMode;

/// The port assumed when a Windows `ProxyServer` entry omits one.
pub const WINDOWS_DEFAULT_PORT: u16 = 80;

// Characters that separate entries in a bypass list.
//
// [`no_proxy`] is the only splitter that takes these, so its sources are the ones that
// matter: the environment variable, where Go's `httpproxy` splits on `,` alone, and KDE's
// `NoProxyFor`, where every implementation that reads the file does the same —
// `g_strsplit (value->str, ",", -1)` in libproxy's `config-kde.c`, and a tokenizer over
// `", "` in Chromium's `proxy_config_service_linux.cc`. Windows takes the wider
// [`WINDOWS_BYPASS_SEPARATORS`], and GNOME's array never reaches here at all
// (`sys::linux::gsettings_map::bypass_from_settings`).
//
// `;` is not here, though neither character can occur inside a host name and taking both
// would be the safe-looking superset. That reading is beside the point: a `;`-separated
// list is not two rules anywhere else, it is one rule that matches nothing. Splitting it
// sends a pair of hosts direct that every supplier's own reader puts through the proxy,
// which is the one direction this crate must not invent. Kept whole it is the same dead rule
// everyone else is holding — no record, because `;` is a character
// [`crate::endpoint::parse_host`] takes and the entry is only unmatchable, not malformed.
const LIST_SEPARATORS: [char; 1] = [','];

// The same, plus whitespace, for the Windows bypass list only.
//
// WinHTTP documents `lpszProxyBypass` as "one or more server names separated by
// semicolons or whitespace" (`WINHTTP_PROXY_INFO`), and Chromium reads the string
// `WinHttpGetIEProxyConfigForCurrentUser` returns with
// `base::StringTokenizer(proxy_bypass, ";, \t\n\r")`
// (`ProxyConfigServiceWin::SetFromIEConfig`). Splitting on `;` and `,` alone turned
// `ProxyOverride = "*.corp.example intranet"` into one `Domain` pattern that no host can
// match, with nothing in [`BypassRules::rejected`] to say so.
//
// [`no_proxy`] keeps the narrower set: Go's `httpproxy`, its reference, splits on `,`
// alone. An entry that still contains whitespace there is caught by
// `HostPattern::parse`, so it is recorded rather than dead.
const WINDOWS_BYPASS_SEPARATORS: [char; 6] = [';', ',', ' ', '\t', '\r', '\n'];

// Characters that separate entries in the Windows `ProxyServer` string.
//
// The same `WINHTTP_PROXY_INFO` page: "The proxy server list contains one or more of the
// following strings separated by semicolons or whitespace." No `,` — that character is in
// [`LIST_SEPARATORS`] because environment variables and GNOME put it there, and neither
// writes this key. Named rather than spelled inline at the split so that the reason a
// server list and a bypass list disagree about one character sits next to both.
const WINDOWS_SERVER_SEPARATORS: [char; 5] = [';', ' ', '\t', '\r', '\n'];

/// Parse Windows `ProxyServer` ([`WINHTTP_CURRENT_USER_IE_PROXY_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_current_user_ie_proxy_config)).
///
/// Bare `host:port` → [`Scheme::All`]; or `http=`/`https=`/`ftp=`/`socks=`/`all=`.
/// Missing port → [`WINDOWS_DEFAULT_PORT`] (1080 for bare `socks=`). Empty scheme →
/// [`ProxyEntry::Disabled`]. Bad tokens skipped; recorded on [`windows_manual`]. A scheme
/// named twice keeps the last token that was not skipped, so a bad last spelling leaves the
/// earlier one standing. A `socks=` entry also fills every scheme the string left
/// unset — the last two examples below are that rule and its limit.
///
/// ```
/// # use proxy_watch::{parse, ProxyScheme, Scheme};
/// let map = parse::proxy_server("http=h:8080;https=h");
/// assert_eq!(map[&Scheme::Http].endpoint().unwrap().port, 8080);
/// assert_eq!(map[&Scheme::Https].endpoint().unwrap().port, 80);
///
/// let map = parse::proxy_server("socks=127.0.0.1:1080");
/// assert_eq!(map[&Scheme::Http].endpoint().unwrap().authority(), "127.0.0.1:1080");
/// assert_eq!(
///     map[&Scheme::Http].endpoint().unwrap().scheme_hint,
///     Some(ProxyScheme::Socks4)
/// );
/// let map = parse::proxy_server("http=h1:8080;socks=127.0.0.1:1080");
/// assert_eq!(map[&Scheme::Http].endpoint().unwrap().authority(), "h1:8080");
/// ```
pub fn proxy_server(spec: &str) -> HashMap<Scheme, ProxyEntry> {
    proxy_server_with_rejected(spec).0
}

// [`proxy_server`] plus the redacted original text of every token it silently drops.
//
// This is what [`windows_manual`] calls instead of [`proxy_server`], so that the dropped
// tokens end up recorded on the [`ProxyMode::Manual`](crate::ProxyMode::Manual) it
// returns.
fn proxy_server_with_rejected(spec: &str) -> (HashMap<Scheme, ProxyEntry>, Vec<RejectedValue>) {
    let mut map = HashMap::new();
    let mut rejected = Vec::new();
    for token in spec.split(WINDOWS_SERVER_SEPARATORS) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        match split_scheme_key(token) {
            Some((key, value)) => {
                let Some(scheme) = Scheme::from_name(key) else {
                    // The module doc's rule, applied to a drop that is easy to miss: a
                    // scheme endpoint that goes missing without a record is fail-open.
                    // `gopher=proxy:80` on an old machine, or a plain typo like `htttp=`,
                    // otherwise leaves `windows_manual` returning `ProxyMode::Direct` with
                    // nothing anywhere to say a proxy had been configured at all.
                    crate::trace::warning!(
                        "skipping a ProxyServer token with an unrecognised scheme key"
                    );
                    rejected.push(RejectedValue::new(
                        RejectionKind::UnknownProxyScheme,
                        RejectionSource::ProxyServer,
                        token,
                    ));
                    continue;
                };
                if value.trim().is_empty() {
                    map.insert(scheme, ProxyEntry::Disabled);
                } else {
                    let default_port = if scheme == Scheme::Socks {
                        ProxyScheme::Socks4.default_port()
                    } else {
                        WINDOWS_DEFAULT_PORT
                    };
                    match ProxyEndpoint::parse(value, default_port) {
                        Ok(mut endpoint) => {
                            // `socks=h:1080`, with no `scheme://` of its own, is read as
                            // SOCKS4 and not SOCKS4a; [`ProxyScheme`]'s own doc carries the
                            // Microsoft table that says so. Set here, not in
                            // `ProxyScheme::from_str`, which reads a *URI* scheme — where
                            // the same word means SOCKS5 instead.
                            if scheme == Scheme::Socks && endpoint.scheme_hint.is_none() {
                                endpoint.scheme_hint = Some(ProxyScheme::Socks4);
                            }
                            map.insert(scheme, ProxyEntry::Use(endpoint));
                        }
                        Err(err) => {
                            warn_dropped_proxy_server_token(&err);
                            // `socks=` losing its own scheme also loses the fallback
                            // `apply_socks_catch_all` would have run below: a valid SOCKS
                            // entry fills every scheme with no token of its own, so a
                            // malformed one drops exactly what that fallback would have
                            // covered, not just `socks://` itself.
                            let affected = if scheme == Scheme::Socks {
                                Scheme::All
                            } else {
                                scheme
                            };
                            rejected.push(
                                RejectedValue::new(
                                    RejectionKind::InvalidProxyEndpoint,
                                    RejectionSource::ProxyServer,
                                    token,
                                )
                                .for_scheme(Some(affected)),
                            );
                        }
                    }
                }
            }
            None => match ProxyEndpoint::parse(token, WINDOWS_DEFAULT_PORT) {
                Ok(endpoint) => {
                    map.insert(Scheme::All, ProxyEntry::Use(endpoint));
                }
                Err(err) => {
                    warn_dropped_proxy_server_token(&err);
                    rejected.push(
                        RejectedValue::new(
                            RejectionKind::InvalidProxyEndpoint,
                            RejectionSource::ProxyServer,
                            token,
                        )
                        .for_scheme(Some(Scheme::All)),
                    );
                }
            },
        }
    }
    apply_socks_catch_all(&mut map);
    (map, rejected)
}

// The `socks=` → "everything else" fallback described on [`proxy_server`]'s doc comment:
// fills [`Scheme::Http`]/[`Scheme::Https`]/[`Scheme::Ftp`] gaps, and [`Scheme::All`],
// from [`Scheme::Socks`] once every token has been read — unless the string already
// answered for [`Scheme::All`] itself, in either of the writings that reach the map: an
// address (a bare `host:port`, or an `all=host:port`) or an `all=` that disabled it. The
// second covers nothing, so the guard is not "already covered" but "already answered".
// It reads the map rather than the string, so naming `all` is not by itself the answer:
// an `all=` whose address failed to parse left a `rejected` record and no entry, and the
// gap it leaves is filled from `socks=` like any other — the fail-open drop the module
// doc sets out for every scheme key, not a special case for this one.
fn apply_socks_catch_all(map: &mut HashMap<Scheme, ProxyEntry>) {
    if map.contains_key(&Scheme::All) {
        return;
    }
    let Some(ProxyEntry::Use(endpoint)) = map.get(&Scheme::Socks) else {
        return;
    };
    let endpoint = endpoint.clone();
    // `Scheme::All` is known absent by the early return above, so its `or_insert_with`
    // always fires; the other three fill only where nothing explicit was written.
    for scheme in [Scheme::Http, Scheme::Https, Scheme::Ftp, Scheme::All] {
        map.entry(scheme)
            .or_insert_with(|| ProxyEntry::Use(endpoint.clone()));
    }
}

// Log-only sink for a `ProxyServer` token [`proxy_server`] could not parse.
//
// `err` is only read inside the `WARN` line below, so without the `tracing` feature it
// would otherwise be flagged unused.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn warn_dropped_proxy_server_token(err: &Error) {
    crate::trace::warning!(
        error = %crate::trace::SafeError(err),
        "skipping an unparseable ProxyServer token"
    );
}

// Split `http=host:port` into `("http", "host:port")`.
//
// Returns `None` when the token has no scheme key: only an `=` that appears before the first
// `:`, `/`, `?` or `#` counts. The `:` is what keeps a percent-free password's `=` and a URL
// query's from being read as a key separator — a URL names a scheme or a port, so it carries
// a colon ahead of its path either way. The other three cover the shape that has no colon at
// all: `proxy.corp/path?a=b` and `proxy.corp?a=b` are neither a URL nor a `host:port`, and
// without them the token is recorded as an unknown scheme key named `proxy.corp/path?a` or
// `proxy.corp?a`, a drop naming a scheme the token never had. With them the token reaches
// `ProxyEndpoint::parse`, which cuts the authority at those same three characters — the
// boundary set is that one, not a shorter guess at it.
fn split_scheme_key(token: &str) -> Option<(&str, &str)> {
    let eq = token.find('=')?;
    let boundary = token.find([':', '/', '?', '#']).unwrap_or(token.len());
    if eq < boundary {
        Some((&token[..eq], &token[eq + 1..]))
    } else {
        None
    }
}

/// Parse a Windows `ProxyOverride` registry value into [`BypassRules`].
///
/// Like [`no_proxy`], but entries are separated by `;`, `,` or whitespace, as WinHTTP
/// documents, and **a bare name matches that name alone** rather than the domain under
/// it: `contoso.com` here does not bypass `api.contoso.com`. Write `*.contoso.com` for
/// the subdomains, which is also what Windows asks for — `.contoso.com` is rejected rather
/// than read, because no measured reader grants it. A CIDR entry is rejected too, because
/// Windows answers a `/` with the whole list: write the range as the wildcard Windows does
/// read, `10.*`. `<local>` →
/// [`HostPattern::Local`](crate::HostPattern::Local) and `<-loopback>` (IE9+) →
/// [`HostPattern::SubtractImplicit`](crate::HostPattern::SubtractImplicit) are read by
/// [`no_proxy`] as well as by this one, the
/// way Chromium reads them ("we allow it on all platforms and interpret it the same way",
/// `proxy_host_matching_rules.cc:113`). Malformed entries skipped into
/// [`BypassRules::rejected`].
///
/// The bare-name rule is measured, not inherited: WinINet and WinHTTP were each handed a
/// bypass list and a destination and asked where they connected. Both reimplementations
/// this crate reads alongside — Chromium and libproxy — answer the question, and they
/// answer it differently, so neither could settle it. The readings are the rows of
/// `a_bare_name_in_a_windows_list_is_the_one_host` in `tests/bypass.rs`.
///
/// ```
/// # use proxy_watch::parse;
/// let rules = parse::proxy_override("<local>;*.contoso.com;<-loopback>");
/// assert!(rules.excludes_simple_hostnames());
/// assert!(!rules.bypass_loopback());
/// assert!(rules.matches_authority("www.contoso.com"));
///
/// // Whitespace separates too, so this is two rules and not one dead one.
/// let rules = parse::proxy_override("*.contoso.com intranet");
/// assert!(rules.matches_authority("www.contoso.com"));
/// assert!(rules.matches_authority("intranet"));
///
/// // A bare name is the host itself. The same text in `no_proxy` takes the subdomains.
/// let rules = parse::proxy_override("contoso.com");
/// assert!(rules.matches_authority("contoso.com"));
/// assert!(!rules.matches_authority("api.contoso.com"));
/// assert!(parse::no_proxy("contoso.com").matches_authority("api.contoso.com"));
///
/// // A `/` is recorded, not read. `no_proxy` takes the same text as a mask.
/// let rules = parse::proxy_override("10.0.0.0/8");
/// assert!(!rules.matches_authority("10.1.2.3"));
/// assert_eq!(rules.rejected.len(), 1);
/// assert!(parse::no_proxy("10.0.0.0/8").matches_authority("10.1.2.3"));
/// ```
pub fn proxy_override(spec: &str) -> BypassRules {
    bypass_entries_in(
        spec.split(WINDOWS_BYPASS_SEPARATORS.as_slice()),
        BypassDialect::Windows,
    )
}

/// Parse `no_proxy` into [`BypassRules`]: `*`, CIDR, domains, `:port`, and a localhost
/// bypass that stays on unless an entry clears it. Entries are separated by `,` alone — not
/// whitespace and not `;`, which is what Go's `httpproxy` does and what KDE's readers do
/// with `NoProxyFor`. Malformed → [`BypassRules::rejected`]. An entry
/// that repeats one already in [`BypassRules::patterns`] is dropped, first spelling kept,
/// so the list can be shorter than the string had entries.
///
/// Go's `httpproxy` is the nearest relative and the separator above is its rule, but this
/// does not implement it: what an entry *matches* follows Chromium's
/// `ProxyHostMatchingRules` wherever the readers answer differently, and the rest of this
/// doc is where they do. None of it is a corner case.
///
/// The Windows tokens `<local>` and `<-loopback>` are read here too, which Go does not
/// do — Chromium feeds the `no_proxy` environment variable through the same
/// `ProxyHostMatchingRules::ParseFromString` as any other bypass list, and that is where the
/// tokens are recognised. See [`proxy_override`], which differs in its separators and in
/// reading a bare name as the one host rather than as the domain under it.
///
/// Two further departures from Go, both downstream of reading `*` as Chromium's glob
/// rather than as Go's optional prefix. A star is matched against the destination's text,
/// so `*.*.*.1` bypasses `10.0.0.1`, where Go answers no domain entry at all against an
/// address destination (`httpproxy/proxy.go:367-369`). And an entry whose body ends in a
/// label that reads as a number — `.example.123` — goes to [`BypassRules::rejected`]
/// rather than being kept: unreachable for the *special* schemes these lists are written
/// about, but a `custom://a.example.123/` it would have matched is proxied instead — and
/// that URL is one this crate answers about, since `resolve` (the `resolve` feature's entry
/// point) sends an unknown scheme to the catch-all entry rather than declining it.
///
/// ```
/// # use proxy_watch::parse;
/// let rules = parse::no_proxy("<local>,<-loopback>");
/// assert!(rules.excludes_simple_hostnames());
/// assert!(!rules.bypass_loopback());
/// ```
pub fn no_proxy(spec: &str) -> BypassRules {
    bypass_entries_in(
        spec.split(LIST_SEPARATORS.as_slice()),
        BypassDialect::Suffix,
    )
}

// Fold a list's entries into one rule set, each read in its own dialect.
//
// Takes an iterator rather than a string because not every source is one: GNOME's
// `ignore-hosts` arrives as a GSettings `as`, where the array *is* the delimiter and no
// character in an element is one.
pub(crate) fn bypass_entries_in<'a>(
    entries: impl Iterator<Item = &'a str>,
    dialect: BypassDialect,
) -> BypassRules {
    let mut rules = BypassRules::new();
    for entry in entries {
        // Trimmed here and not left to `HostPattern::parse_in`, which trims only what it
        // parses: `push_entry_in` puts the string it was given into `BypassRules::rejected`,
        // and an entry quoted back with the separator's whitespace still on it is not the
        // entry anyone wrote.
        rules.push_entry_in(dialect.trim(entry), dialect);
    }
    rules.dedup_patterns();
    rules
}

/// Assemble a [`ProxyMode::Manual`] from the two Windows registry strings.
///
/// [`proxy_server`] + [`proxy_override`]; the returned manual mode records dropped server
/// tokens. Empty server, no rejects →
/// [`ProxyMode::Direct`]; reject-only stays `Manual` so rejects are not lost.
///
/// ```
/// # use proxy_watch::parse;
/// let mode = parse::windows_manual("http=h:8080;https=h:-1", "");
/// assert_eq!(mode.rejected().unwrap()[0].redacted_input(), "https=h:-1");
/// // The well formed `http=` entry survives alongside the dropped `https=` one.
/// assert!(mode.endpoint_for(proxy_watch::Scheme::Http).is_some());
/// ```
pub fn windows_manual(server: &str, override_list: &str) -> ProxyMode {
    let (per_scheme, rejected) = proxy_server_with_rejected(server);
    if per_scheme.is_empty() && rejected.is_empty() {
        return ProxyMode::Direct;
    }
    ProxyMode::manual(per_scheme, proxy_override(override_list)).with_rejected(rejected)
}
