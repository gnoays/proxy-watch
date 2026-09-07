//! The unified proxy mode.

use std::collections::HashMap;
use std::fmt;

use url::Url;

use crate::bypass::BypassRules;
use crate::diagnostic::RejectedValue;
use crate::endpoint::{ProxyEndpoint, ProxyEntry, Scheme};

/// What a single configuration source says about proxying.
///
/// Hand-written [`Debug`], because [`ProxyConfig`](crate::ProxyConfig)'s is derived and would
/// otherwise print whatever this one does. What each variant withholds is not the same thing:
/// a [`Pac`](ProxyMode::Pac) URL is printed, minus its userinfo — the location is what makes a
/// report actionable, and only the credentials are the secret — while a
/// [`PacInline`](ProxyMode::PacInline) body is withheld whole and stands in as length plus
/// hash, because a script is not a locator and any part of it may be one.
/// [`Manual`](ProxyMode::Manual) delegates — [`ProxyEntry`] masks auth.
#[derive(Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyMode {
    /// No proxy at all (Windows `ProxyEnable=0`, GNOME `mode=none`, macOS all
    /// `*Enable` keys zero). This is the [`Default`].
    #[default]
    Direct,
    /// Static per-scheme proxies plus bypass rules.
    ///
    /// Sealed, like the other variants that carry fields: build it with
    /// [`ProxyMode::manual`], which is what keeps the [`rejected`](ProxyMode::Manual) list
    /// and the `per_scheme` entries mirroring it in step — the constructor reads the list
    /// back out of the map, so the two cannot be handed in disagreeing. The enum's own
    /// `#[non_exhaustive]` does not seal a variant — it only forces a `_` arm in a match —
    /// so without this a caller could assemble a `Manual` whose two halves disagree, and
    /// `resolve` answers from the mirror. (Not linked: `resolve` is behind its own feature,
    /// and this variant is not.)
    #[non_exhaustive]
    Manual {
        /// Per-scheme proxy entries.
        per_scheme: HashMap<Scheme, ProxyEntry>,
        /// Bypass rules.
        bypass: BypassRules,
        /// Fail-open drops (redacted); opposite of [`BypassRules::rejected`].
        rejected: Vec<RejectedValue>,
    },
    /// PAC script at a URL (fetch/evaluate via `pac` / `resolve_with_pac`).
    ///
    /// Sealed; build it with [`ProxyMode::pac`].
    #[non_exhaustive]
    Pac {
        /// Script URL.
        url: Url,
        /// Fail-open drops (redacted), as in [`Manual`](ProxyMode::Manual) — a source can
        /// reach a PAC answer having already lost an unrelated key on the way to it. There
        /// is no `per_scheme` to mirror them into here, so they are reachable only through
        /// [`ProxyMode::rejected`].
        rejected: Vec<RejectedValue>,
    },
    /// Inline PAC script body.
    ///
    /// Sealed; build it with [`ProxyMode::pac_inline`].
    #[non_exhaustive]
    PacInline {
        /// JavaScript source.
        script: String,
        /// Fail-open drops (redacted); see [`Pac`](ProxyMode::Pac)'s field of the same name.
        rejected: Vec<RejectedValue>,
    },
    /// WPAD enabled (no DHCP/DNS probe in this crate).
    ///
    /// Not sealed, and neither is [`Direct`](ProxyMode::Direct): a sealed unit variant
    /// cannot be *named* by another crate, not merely constructed by one, so sealing these
    /// two would cost every caller `mode == ProxyMode::Direct`. `Direct` could not be
    /// sealed in any case — it is this enum's [`Default`], and a default variant must be
    /// exhaustive. Neither carries fields, and neither ever will: a backend that dropped a
    /// setting answers [`Manual`](ProxyMode::Manual) so the record has somewhere to go
    /// (`proxy_dict.rs`' "reject-only stays `Manual`"), which is why the pair that cannot
    /// be sealed is also the pair with nothing to add.
    WpadAutoDetect,
}

// Both lookups' precedence rule, in the one place, so that adding a step to either cannot
// put them out of step: the first entry that is an *answer* wins, and a drop is not one.
// A later step that answers is a proxy the platform did configure — macOS' SOCKS fallback
// and Windows' `socks=` fill are exactly that — so preferring the record over it would turn
// a resolvable request into an error. With nothing to answer anywhere the earliest record
// is returned, because that is the slot whose loss took the answer away; walking the chain
// is what keeps that order the *lookup's* order rather than a second one maintained by hand.
fn first_answer<'a>(chain: impl IntoIterator<Item = &'a ProxyEntry>) -> Option<&'a ProxyEntry> {
    let mut dropped = None;
    for entry in chain {
        match entry {
            ProxyEntry::Unusable(_) => dropped = dropped.or(Some(entry)),
            _ => return Some(entry),
        }
    }
    dropped
}

impl ProxyMode {
    /// Build a [`ProxyMode::Manual`] value, taking the
    /// [`rejected`](ProxyMode::Manual) list from whatever drops `per_scheme` already holds.
    ///
    /// Empty for the map a backend builds, which records its drops separately and attaches
    /// them with `with_rejected` (private) once the map is complete. It is a caller filtering
    /// or merging a *parsed* `Manual` that hands one back already carrying
    /// [`ProxyEntry::Unusable`] entries, because that is where `with_rejected` put them, and
    /// the list has to be recovered from there rather than left empty — an empty list beside
    /// a lookup that answers `Unusable` says nothing was lost about a request that cannot be
    /// routed. Read in [`Scheme::ALL`]'s order, not the map's, which is seeded per instance.
    /// A record that named no scheme was never in the map and cannot come back this way.
    #[must_use]
    pub fn manual(per_scheme: HashMap<Scheme, ProxyEntry>, bypass: BypassRules) -> Self {
        let rejected = Scheme::ALL
            .iter()
            .filter_map(|scheme| match per_scheme.get(scheme) {
                Some(ProxyEntry::Unusable(value)) => Some(value.clone()),
                _ => None,
            })
            .collect();
        ProxyMode::Manual {
            per_scheme,
            bypass,
            rejected,
        }
    }

    /// Build a [`ProxyMode::Pac`] value with an empty `rejected` list.
    #[must_use]
    pub fn pac(url: Url) -> Self {
        ProxyMode::Pac {
            url,
            rejected: Vec::new(),
        }
    }

    /// Build a [`ProxyMode::PacInline`] value with an empty `rejected` list.
    #[must_use]
    pub fn pac_inline(script: String) -> Self {
        ProxyMode::PacInline {
            script,
            rejected: Vec::new(),
        }
    }

    /// Set the [`rejected`](ProxyMode::Manual) list of a [`ProxyMode::Manual`] value,
    /// *replacing* whatever it held. Every caller builds the list first and hands it over
    /// once; a second call replaces the list but leaves behind the `per_scheme` entries the
    /// first one derived (below), so a lookup could still reach a record that
    /// [`ProxyMode::rejected`] no longer lists. That is why the `kioslaverc`
    /// `ProxyType = 4` path merges the environment's list and its own skipped slots into
    /// one vector before calling, rather than calling twice.
    ///
    /// A no-op on [`ProxyMode::Direct`] and [`ProxyMode::WpadAutoDetect`], which have
    /// nowhere to put the list. No backend needs one there: a reader that dropped a setting
    /// answers [`Manual`](ProxyMode::Manual) rather than `Direct` precisely so the record
    /// has somewhere to go, and the two WPAD returns are reached only from a flag that read
    /// cleanly, so nothing can have been recorded by the time either is taken.
    ///
    /// Only [`Manual`](ProxyMode::Manual) mirrors the list into `per_scheme`; the PAC
    /// variants have no map, and a lookup against them answers `None` for every scheme
    /// anyway. The rest of this describes that mirror.
    ///
    /// Every record that names a scheme is also written into `per_scheme` as
    /// [`ProxyEntry::Unusable`], which is what makes a drop reachable from a lookup instead
    /// of only from a second list the lookup would have to be kept in step with. Doing it
    /// here rather than in each backend is the point: spread across the backends, five
    /// readers express "keep this scheme out of the map so the record answers instead" in
    /// five dialects, and the two orderings — the lookup's and the record walk's — have to
    /// agree by hand.
    ///
    /// Two rules:
    ///
    /// - An occupied slot stands, including one holding [`ProxyEntry::Disabled`] — that is
    ///   an answer the platform gave, and a backend that recorded a drop and wrote the slot
    ///   anyway (macOS' SOCKS fallback, GNOME's `use-same-proxy`) meant the write. A backend
    ///   that wants the record to answer leaves the slot empty. A record naming
    ///   [`Scheme::All`] is no exception here: a *live* catch-all does not reach past a
    ///   `Disabled` either ([`entry_for`](Self::entry_for)'s first rule), so losing one took
    ///   nothing from that scheme — clearing it would turn `http_proxy=` beside an
    ///   unparseable `all_proxy=` into an error. The one reader whose catch-all *overwrites*
    ///   `Disabled` rather than filling around it is macOS', and it empties those slots
    ///   itself before calling this.
    /// - The first record for a slot wins, which is what
    ///   [`Error::ProxyEntryUnusable`](crate::Error::ProxyEntryUnusable) promises.
    ///
    /// A record naming no scheme stays in the list alone: there is no slot to put it in, and
    /// it never took any one request's answer away.
    #[must_use]
    pub(crate) fn with_rejected(mut self, rejected: Vec<RejectedValue>) -> Self {
        match &mut self {
            ProxyMode::Manual {
                per_scheme,
                rejected: slot,
                ..
            } => {
                for value in &rejected {
                    let Some(scheme) = value.affected_scheme() else {
                        continue;
                    };
                    per_scheme
                        .entry(scheme)
                        .or_insert_with(|| ProxyEntry::Unusable(value.clone()));
                }
                *slot = rejected;
            }
            ProxyMode::Pac { rejected: slot, .. } | ProxyMode::PacInline { rejected: slot, .. } => {
                *slot = rejected
            }
            ProxyMode::Direct | ProxyMode::WpadAutoDetect => {}
        }
        self
    }

    /// Whether the mode means "connect directly".
    #[must_use]
    pub fn is_direct(&self) -> bool {
        matches!(self, ProxyMode::Direct)
    }

    /// The bypass rules, when the mode has any.
    #[must_use]
    pub fn bypass(&self) -> Option<&BypassRules> {
        match self {
            ProxyMode::Manual { bypass, .. } => Some(bypass),
            _ => None,
        }
    }

    /// The redacted text of every scheme-endpoint entry the source dropped, when the
    /// mode has any. See [`ProxyMode::Manual`]'s `rejected` field for what this
    /// records and why.
    #[must_use]
    pub fn rejected(&self) -> Option<&[RejectedValue]> {
        match self {
            ProxyMode::Manual { rejected, .. }
            | ProxyMode::Pac { rejected, .. }
            | ProxyMode::PacInline { rejected, .. } => Some(rejected),
            ProxyMode::Direct | ProxyMode::WpadAutoDetect => None,
        }
    }

    /// Entry for `scheme`. Concrete schemes beat [`Scheme::All`]; `All` has no fallback.
    /// `None` outside Manual or with no entry; `Some(Disabled)` suppresses `All`.
    /// [`Unusable`](ProxyEntry::Unusable) does not: a drop is the last resort, so a live
    /// `All` still answers and the record surfaces only when nothing else covers `scheme`.
    /// Backends may substitute before the map is built (macOS SOCKS fallback, Windows
    /// `socks=` fill) — this applies to the finished map.
    #[must_use]
    pub fn entry_for(&self, scheme: Scheme) -> Option<&ProxyEntry> {
        let ProxyMode::Manual { per_scheme, .. } = self else {
            return None;
        };
        // No `scheme == Scheme::All` guard: reaching the fallback means the first lookup
        // missed, and for `All` the fallback *is* that same lookup, so it can only miss
        // again. A guard would be a branch no input can tell apart from its absence.
        first_answer(
            [scheme, Scheme::All]
                .into_iter()
                .filter_map(|scheme| per_scheme.get(&scheme)),
        )
    }

    /// The proxy endpoint that applies to `scheme`, or `None`.
    ///
    /// `None` is "no endpoint to hand out". Inside [`Manual`](ProxyMode::Manual) that is
    /// direct access when nothing covers the scheme and when what does is
    /// [`Disabled`](ProxyEntry::Disabled) — but not when it is
    /// [`Unusable`](ProxyEntry::Unusable), a setting that was lost rather than an answer,
    /// which `resolve` reports as
    /// [`Error::ProxyEntryUnusable`](crate::Error::ProxyEntryUnusable). A caller that has to
    /// tell those two apart asks [`entry_for`](Self::entry_for), which is the same lookup
    /// with the entry left intact. Every other mode returns `None` for every scheme,
    /// including the PAC and WPAD ones that keep their answer in a script this method cannot
    /// run; that is [`Error::PacNotSupported`](crate::Error::PacNotSupported), not direct.
    ///
    /// ```
    /// # use proxy_watch::{parse, ProxyMode, Scheme, BypassRules};
    /// let per_scheme = parse::proxy_server("http=a:8080;https=b:8443");
    /// let mode = ProxyMode::manual(per_scheme, BypassRules::new());
    /// assert_eq!(mode.endpoint_for(Scheme::Http).unwrap().port, 8080);
    /// // No `ftp=` and no catch-all entry: nothing applies.
    /// assert!(mode.endpoint_for(Scheme::Ftp).is_none());
    /// ```
    #[must_use]
    pub fn endpoint_for(&self, scheme: Scheme) -> Option<&ProxyEndpoint> {
        self.entry_for(scheme).and_then(ProxyEntry::endpoint)
    }

    // Only the first three steps come from the references (Chromium's
    // `GetProxyListForWebSocketScheme`). `all` is a fourth that neither has and Chromium
    // structurally cannot reach — there a catch-all and a per-scheme entry never coexist —
    // so it goes last, for the reason it does everywhere else here: a named entry beats
    // [`Scheme::All`]. `§4.1.3` is Chromium's way of citing it; in the RFC the note is item 3
    // of the numbered list in §4.1, not a section of that number.
    /// Entry for `ws`/`wss`: socks → https → http (RFC 6455 §4.1.3, as Chromium reads it),
    /// then `all` — a step this crate adds.
    ///
    /// Unlike [`entry_for`](Self::entry_for), intermediate `Disabled` entries do not stop
    /// the chain — only terminal [`Scheme::All`] is returned as-is (e.g. empty `all_proxy=`).
    /// An intermediate [`Unusable`](ProxyEntry::Unusable) does not stop it either, but is
    /// remembered, and the earliest one is the answer when no step has a real one.
    ///
    /// ```
    /// # use proxy_watch::{parse, ProxyMode, BypassRules};
    /// // Only `socks=` and `http=`: the WebSocket chain prefers the SOCKS proxy.
    /// let per_scheme = parse::proxy_server("http=h:80;socks=s:1080");
    /// let mode = ProxyMode::manual(per_scheme, BypassRules::new());
    /// assert_eq!(mode.websocket_endpoint().unwrap().authority(), "s:1080");
    ///
    /// // `https=` explicitly disabled: the chain keeps going to `http=` rather than
    /// // stopping the way `entry_for(Scheme::Https)` would for an actual `https`
    /// // request.
    /// let per_scheme = parse::proxy_server("https=;http=h:80");
    /// let mode = ProxyMode::manual(per_scheme, BypassRules::new());
    /// assert_eq!(mode.websocket_endpoint().unwrap().authority(), "h:80");
    /// ```
    #[must_use]
    pub fn websocket_entry(&self) -> Option<&ProxyEntry> {
        let ProxyMode::Manual { per_scheme, .. } = self else {
            return None;
        };
        let configured = |scheme: Scheme| match per_scheme.get(&scheme) {
            entry @ Some(ProxyEntry::Use(_) | ProxyEntry::Unusable(_)) => entry,
            _ => None,
        };
        first_answer(
            [Scheme::Socks, Scheme::Https, Scheme::Http]
                .into_iter()
                .filter_map(configured)
                .chain(per_scheme.get(&Scheme::All)),
        )
    }

    /// The proxy endpoint for a `ws://`/`wss://` request; see
    /// [`websocket_entry`](Self::websocket_entry) for the resolution order.
    #[must_use]
    pub fn websocket_endpoint(&self) -> Option<&ProxyEndpoint> {
        self.websocket_entry().and_then(ProxyEntry::endpoint)
    }
}

impl fmt::Debug for ProxyMode {
    // Not a derive, for the reason [`ProxyMode`]'s own doc gives.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyMode::Direct => write!(f, "Direct"),
            ProxyMode::Manual {
                per_scheme,
                bypass,
                rejected,
            } => f
                .debug_struct("Manual")
                // Sorted, which a `HashMap` is not: its iteration order is seeded per
                // instance, so the same configuration would print differently on each
                // run and a diff between two logged configurations would report changes
                // nobody made. `Scheme`'s `Ord` is the declaration order, which is
                // [`Scheme::ALL`]'s documented one. Every map this crate's `Debug` prints
                // is ordered for that reason — `ProxyEnv`'s is the other public one.
                .field(
                    "per_scheme",
                    &per_scheme
                        .iter()
                        .collect::<std::collections::BTreeMap<_, _>>(),
                )
                .field("bypass", bypass)
                .field("rejected", rejected)
                .finish(),
            ProxyMode::Pac { url, rejected } => f
                .debug_struct("Pac")
                .field(
                    "url",
                    &format_args!("{}", crate::util::redact_userinfo(url.as_str())),
                )
                .field("rejected", rejected)
                .finish(),
            ProxyMode::PacInline { script, rejected } => f
                .debug_struct("PacInline")
                .field("len", &script.len())
                .field(
                    "fnv1a",
                    &format_args!("{:016x}", crate::util::fnv1a(script.as_bytes())),
                )
                .field("rejected", rejected)
                .finish(),
            ProxyMode::WpadAutoDetect => write!(f, "WpadAutoDetect"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejection(input: &str) -> RejectedValue {
        RejectedValue::new(
            crate::RejectionKind::InvalidProxyEndpoint,
            crate::RejectionSource::ProxyServer,
            input,
        )
    }

    const SECRET: &str = "hunter2";

    #[test]
    fn manual_debug_delegates_to_proxy_entrys_own_masking() {
        use crate::auth::ProxyAuth;
        use crate::endpoint::ProxyEndpoint;

        let mut per_scheme = HashMap::new();
        per_scheme.insert(
            Scheme::Http,
            ProxyEntry::Use(
                ProxyEndpoint::new(url::Host::Domain("proxy.corp".to_owned()), 8080)
                    .with_auth(ProxyAuth::new("alice", Some(SECRET))),
            ),
        );
        let mode = ProxyMode::manual(per_scheme, BypassRules::new());
        let debug = format!("{mode:?}");
        assert!(!debug.contains(SECRET), "{debug}");
        assert!(debug.contains("Manual"), "{debug}");
        assert!(debug.contains("proxy.corp"), "{debug}");
    }

    // Two `Debug` renderings of the same configuration must be the same text. A
    // `HashMap` gives no such promise: its iteration order is seeded per instance, so
    // the field would come out in a different order on each run and a diff between two
    // logged configurations would report changes nobody made.
    #[test]
    fn manual_debug_prints_the_schemes_in_a_fixed_order() {
        use crate::parse;

        let mode = ProxyMode::manual(
            parse::proxy_server("all=e:5;socks=d:4;ftp=c:3;https=b:2;http=a:1"),
            BypassRules::new(),
        );
        let debug = format!("{mode:?}");

        let mut at = 0;
        for scheme in Scheme::ALL {
            // With the `:` the map's separator prints, so `Http` does not match inside
            // `Https`.
            let name = format!("{scheme:?}:");
            let found = debug[at..]
                .find(&name)
                .unwrap_or_else(|| panic!("{name} out of order or missing in {debug}"));
            at += found + name.len();
        }
    }

    // The impl is hand-written for the whole enum, and this test is the only thing holding
    // four of its renderings. `WpadAutoDetect` printed as `Direct` makes "discovery is
    // running" and "no proxy at all" the same line in a log — and `is_direct` is false for
    // one of them, so a reader comparing the two would be told the line is wrong. `Pac`'s
    // `rejected` is where a PAC configuration parks what it could not read, and
    // `PacInline`'s `len` is named here for the same reason.
    //
    // Exact strings, so that a label, a field order or a variant name cannot change unseen.
    // The `RejectedValue` and the hash keep their own renderings, which this impl does not
    // own, so the expectations defer to them rather than copying them out.
    #[test]
    fn every_mode_debug_names_itself_and_keeps_its_fields() {
        const SCRIPT: &str = "function FindProxyForURL(){}";
        let dropped = rejection("h:99999");
        for (mode, expected) in [
            (ProxyMode::Direct, "Direct".to_owned()),
            (ProxyMode::WpadAutoDetect, "WpadAutoDetect".to_owned()),
            (
                // No credentials, so the row pins the framing and not the masking, which
                // `debug_masking`'s registry owns for this variant.
                ProxyMode::pac(url::Url::parse("https://wpad.corp/proxy.pac").unwrap())
                    .with_rejected(vec![dropped.clone()]),
                format!("Pac {{ url: https://wpad.corp/proxy.pac, rejected: [{dropped:?}] }}"),
            ),
            (
                ProxyMode::pac_inline(SCRIPT.to_owned()),
                format!(
                    "PacInline {{ len: {}, fnv1a: {:016x}, rejected: [] }}",
                    SCRIPT.len(),
                    crate::util::fnv1a(SCRIPT.as_bytes())
                ),
            ),
        ] {
            assert_eq!(format!("{mode:?}"), expected);
        }
    }

    fn authority(mode: &ProxyMode, want: Option<&str>) {
        assert_eq!(
            mode.websocket_endpoint()
                .map(ProxyEndpoint::authority)
                .as_deref(),
            want
        );
    }

    #[test]
    fn websocket_entry_prefers_socks_then_https_then_http() {
        use crate::parse;

        let mode = ProxyMode::manual(
            parse::proxy_server("http=h:80;https=s:443;socks=k:1080"),
            BypassRules::new(),
        );
        authority(&mode, Some("k:1080"));

        let mode = ProxyMode::manual(
            parse::proxy_server("http=h:80;https=s:443"),
            BypassRules::new(),
        );
        authority(&mode, Some("s:443"));

        let mode = ProxyMode::manual(parse::proxy_server("http=h:80"), BypassRules::new());
        authority(&mode, Some("h:80"));
    }

    #[test]
    fn websocket_entry_falls_back_to_the_bare_catch_all_last() {
        use crate::parse;

        let mode = ProxyMode::manual(parse::proxy_server("bare:9000"), BypassRules::new());
        authority(&mode, Some("bare:9000"));

        // "Last" means after `http=`, not merely "used when it is the only entry". This is
        // the step the references do not have: in `net/proxy_resolution/proxy_config.h`,
        // Chromium's `ProxyConfig::ProxyRules::type` is `PROXY_LIST` (the catch-all, in
        // `single_proxies`) or `PROXY_LIST_PER_SCHEME` (`proxies_for_http` and its
        // siblings) and never both at once, so the input above is not a shape it can hold.
        let mode = ProxyMode::manual(parse::proxy_server("all=a:1;http=h:80"), BypassRules::new());
        authority(&mode, Some("h:80"));

        // Nothing configured at all: no entry, same as a direct connection.
        let mode = ProxyMode::manual(HashMap::new(), BypassRules::new());
        authority(&mode, None);
    }

    // Unlike [`ProxyMode::entry_for`], a disabled entry along the chain does not stop
    // it — [`ProxyMode::websocket_entry`]'s doc states that difference, and it is why
    // the chain cannot be three `entry_for` calls.
    #[test]
    fn websocket_entry_treats_a_disabled_tier_as_absent_not_as_a_stop_signal() {
        use crate::parse;

        // `https=` explicitly off: the chain still reaches `http=` instead of jumping
        // straight to "no entry".
        let mode = ProxyMode::manual(parse::proxy_server("https=;http=h:80"), BypassRules::new());
        authority(&mode, Some("h:80"));

        // Confirm the asymmetry: `entry_for(Https)` itself *does* stop at `Disabled`
        // for an actual `https` request.
        assert_eq!(mode.entry_for(Scheme::Https), Some(&ProxyEntry::Disabled));

        // The same at the head of the chain rather than in its middle. Without this the
        // claim is "a `Disabled` at the `https` tier is skipped", which is one position,
        // not the rule the doc states.
        let mode = ProxyMode::manual(
            parse::proxy_server("socks=;https=s:443"),
            BypassRules::new(),
        );
        authority(&mode, Some("s:443"));
    }

    // The other half of the same doc sentence: the three tiers above drop a `Disabled`,
    // but the terminal [`Scheme::All`] is returned as-is. [`authority`] cannot see the
    // difference — it reads through [`ProxyMode::websocket_endpoint`], which turns both
    // `Some(Disabled)` and `None` into no endpoint — so the entry is asserted directly.
    #[test]
    fn a_disabled_terminal_catch_all_is_returned_rather_than_dropped() {
        use crate::parse;

        let mode = ProxyMode::manual(parse::proxy_server("all="), BypassRules::new());
        assert_eq!(mode.websocket_entry(), Some(&ProxyEntry::Disabled));
        authority(&mode, None);
    }

    #[test]
    fn websocket_entry_is_none_for_non_manual_modes() {
        assert!(ProxyMode::Direct.websocket_entry().is_none());
        assert!(ProxyMode::WpadAutoDetect.websocket_entry().is_none());
    }

    #[test]
    fn manual_defaults_to_an_empty_rejected_list() {
        let mode = ProxyMode::manual(HashMap::new(), BypassRules::new());
        assert_eq!(mode.rejected(), Some(&[][..]));
    }

    // Empty is the answer for a map with nothing lost in it, and the row above is the whole
    // of that case. A caller filtering or merging a parsed `Manual` reaches for its map, and
    // the map is where `with_rejected` put the drops — so handing one back to the only public
    // constructor there is must not turn them into a list that says nothing was lost while a
    // lookup still answers `Unusable`. That is the shape of a drop nobody can name: `resolve`
    // errors, and the report written from `rejected()` has no line for it.
    #[test]
    fn manual_recovers_the_drops_the_map_it_was_handed_already_carries() {
        let lost = rejection("http=not a host").for_scheme(Some(Scheme::Http));
        let inherited = lost.clone().for_scheme(Some(Scheme::Https));
        let mode = ProxyMode::manual(
            HashMap::from([
                (Scheme::Http, ProxyEntry::Unusable(lost.clone())),
                (Scheme::Https, ProxyEntry::Unusable(inherited.clone())),
                (Scheme::Ftp, ProxyEntry::Disabled),
            ]),
            BypassRules::new(),
        );
        // In `Scheme::ALL`'s order, not the map's, which is seeded per instance — the same
        // reason the `Debug` above sorts.
        assert_eq!(mode.rejected(), Some(&[lost, inherited][..]));
    }

    #[test]
    fn with_rejected_attaches_the_list_to_a_manual_mode() {
        let mode = ProxyMode::manual(HashMap::new(), BypassRules::new())
            .with_rejected(vec![rejection("http=not a host")]);
        assert_eq!(
            mode.rejected().unwrap()[0].redacted_input(),
            "http=not a host"
        );
        let debug = format!("{mode:?}");
        assert!(debug.contains("not a host"), "{debug}");
    }

    #[test]
    fn with_rejected_attaches_the_list_to_the_pac_modes_too() {
        let url = Url::parse("http://wpad.corp/proxy.pac").expect("the fixture URL parses");
        for mode in [
            ProxyMode::pac(url),
            ProxyMode::pac_inline("function FindProxyForURL(u, h) {}".to_owned()),
        ] {
            let mode = mode.with_rejected(vec![rejection("ProxyAutoDiscoveryEnable=yes")]);
            assert_eq!(
                mode.rejected().unwrap()[0].redacted_input(),
                "ProxyAutoDiscoveryEnable=yes",
                "{mode:?}"
            );
        }
    }

    // `Direct` and `WpadAutoDetect` have nowhere to put a list, which is also why no backend
    // hands them one: a reader that dropped something answers `Manual` instead of `Direct`,
    // and every WPAD return is reached only from a flag that read cleanly.
    #[test]
    fn the_field_less_modes_have_no_list_and_swallow_one() {
        for mode in [ProxyMode::Direct, ProxyMode::WpadAutoDetect] {
            assert!(mode.rejected().is_none(), "{mode:?}");
            let after = mode.clone().with_rejected(vec![rejection("ignored")]);
            assert_eq!(after, mode);
            assert!(after.rejected().is_none(), "{after:?}");
        }
    }

    // Two [`ProxyMode::Manual`] values built from identical input —
    // including identical `rejected` text — must compare equal so
    // [`ProxyConfig`](crate::ProxyConfig)'s duplicate-notification suppression keeps
    // working now that `rejected` is part of the derived [`PartialEq`].
    #[test]
    fn manual_modes_with_equal_rejected_lists_are_equal() {
        let a = ProxyMode::manual(HashMap::new(), BypassRules::new())
            .with_rejected(vec![rejection("http=garbage")]);
        let b = ProxyMode::manual(HashMap::new(), BypassRules::new())
            .with_rejected(vec![rejection("http=garbage")]);
        assert_eq!(a, b);

        let c = ProxyMode::manual(HashMap::new(), BypassRules::new())
            .with_rejected(vec![rejection("http=other-garbage")]);
        assert_ne!(a, c);
    }
}
