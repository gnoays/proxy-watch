//! Turning a snapshot into a routing decision: [`resolve`] and [`ProxyStep`].
//!
//! Everything in this module lives behind the `resolve` feature (enabled by default).

use url::Url;

use crate::config::ProxyConfig;
use crate::endpoint::{ProxyEndpoint, ProxyEntry, ProxyScheme, Scheme, has_request_host};
use crate::error::Error;
use crate::mode::ProxyMode;

/// One way to reach a destination ([`resolve`]).
///
/// Names the protocol **to the proxy**; bare `host:port` → [`ProxyStep::Http`].
/// `Socks4a`/`Socks5h` collapse to [`Socks4`](ProxyStep::Socks4)/[`Socks5`](ProxyStep::Socks5);
/// [`to_url`](Self::to_url) keeps `socks4a`/`socks5h`, [`scheme`](Self::scheme) does not.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProxyStep {
    /// Connect directly.
    Direct,
    /// Plain HTTP proxy (absolute-form requests, `CONNECT` for TLS).
    Http(ProxyEndpoint),
    /// HTTP proxy over TLS.
    Https(ProxyEndpoint),
    /// SOCKS4 proxy.
    Socks4(ProxyEndpoint),
    /// SOCKS5 proxy.
    Socks5(ProxyEndpoint),
}

impl ProxyStep {
    /// Whether the step means "no proxy".
    #[must_use]
    pub fn is_direct(&self) -> bool {
        matches!(self, ProxyStep::Direct)
    }

    /// The proxy endpoint, or `None` for [`ProxyStep::Direct`].
    #[must_use]
    pub fn endpoint(&self) -> Option<&ProxyEndpoint> {
        match self {
            ProxyStep::Direct => None,
            ProxyStep::Http(endpoint)
            | ProxyStep::Https(endpoint)
            | ProxyStep::Socks4(endpoint)
            | ProxyStep::Socks5(endpoint) => Some(endpoint),
        }
    }

    /// `"http"` / `"https"` / `"socks4"` / `"socks5"`, or `None` for [`Direct`](Self::Direct).
    /// Never `socks4a`/`socks5h` — use [`to_url`](Self::to_url) / `endpoint().scheme_hint`.
    #[must_use]
    pub fn scheme(&self) -> Option<&'static str> {
        match self {
            ProxyStep::Direct => None,
            ProxyStep::Http(_) => Some("http"),
            ProxyStep::Https(_) => Some("https"),
            ProxyStep::Socks4(_) => Some("socks4"),
            ProxyStep::Socks5(_) => Some("socks5"),
        }
    }

    /// Proxy URL for HTTP clients, or `None` for [`Direct`](Self::Direct).
    ///
    /// `None` also when the endpoint's host cannot be written into a URL. `Host::Domain`
    /// wraps a `String` without validating it and `Host` is re-exported from the crate
    /// root, so a hand-built endpoint can hold characters no URL host may carry; one from
    /// [`ProxyEndpoint::parse`] cannot. Do not read `None` as "connect directly" —
    /// [`endpoint`](Self::endpoint) is what answers that question.
    ///
    /// Percent-encodes credentials (do not log). Keeps `socks4a`/`socks5h` from
    /// [`ProxyEndpoint::scheme_hint`] — unlike [`scheme`](Self::scheme). HTTP 407: client job.
    ///
    /// ```
    /// # use proxy_watch::{ProxyEndpoint, ProxyStep};
    /// let e = ProxyEndpoint::parse("socks5h://proxy.example:1080", 80).unwrap();
    /// assert_eq!(ProxyStep::Socks5(e).to_url().unwrap().scheme(), "socks5h");
    /// assert!(ProxyStep::Direct.to_url().is_none());
    /// ```
    #[must_use]
    pub fn to_url(&self) -> Option<Url> {
        let endpoint = self.endpoint()?;
        let scheme = self.url_scheme(endpoint);
        // The host has to be readable back as one host. `Url::parse` alone refuses only
        // text no URL can hold; a hand-built `Host::Domain` carrying `@`, `/`, `?` or `#`
        // parses successfully into a *different* URL — `user@evil` splits at the `@` and
        // leaves `evil` as the host. Naming another machine is worse than naming none.
        crate::endpoint::parse_host(&endpoint.host.to_string()).ok()?;
        let mut url = Url::parse(&format!("{scheme}://{}", endpoint.authority())).ok()?;
        if let Some(auth) = &endpoint.auth {
            url.set_username(auth.username()).ok()?;
            if let Some(password) = auth.password() {
                url.set_password(Some(password)).ok()?;
            }
        }
        Some(url)
    }

    // The refinement only, over [`scheme`](Self::scheme) — which is the same table without
    // `socks4a`/`socks5h`, as that method's doc says. The hint refines the step rather than
    // replacing it: a caller can build `ProxyStep::Socks5(e)` around an endpoint carrying
    // any hint at all, and the variant is what the step means. `None` is `Direct`, which
    // `to_url` returned on before calling this.
    fn url_scheme(&self, endpoint: &ProxyEndpoint) -> &'static str {
        match (self, endpoint.scheme_hint) {
            (ProxyStep::Socks4(_), Some(ProxyScheme::Socks4a)) => "socks4a",
            (ProxyStep::Socks5(_), Some(ProxyScheme::Socks5h)) => "socks5h",
            _ => self.scheme().unwrap_or(""),
        }
    }

    // The crate's one table from a scheme hint to a step. `pac::result` and
    // `pac::winhttp` build their endpoint's hint from the keyword they just read and then
    // come here, so the mapping is written once and stays exhaustive.
    pub(crate) fn from_endpoint(endpoint: ProxyEndpoint) -> Self {
        match endpoint.scheme_hint {
            None | Some(ProxyScheme::Http) => ProxyStep::Http(endpoint),
            Some(ProxyScheme::Https) => ProxyStep::Https(endpoint),
            Some(ProxyScheme::Socks4 | ProxyScheme::Socks4a) => ProxyStep::Socks4(endpoint),
            Some(ProxyScheme::Socks5 | ProxyScheme::Socks5h) => ProxyStep::Socks5(endpoint),
        }
    }
}

/// Decide how to reach `url` under `config`.
///
/// Never empty, and decided in this order. Pac/WPAD → [`Error::PacNotSupported`], hostless
/// URLs included: under an auto-config mode this entry point can answer no URL at all, so
/// singling out `mailto:` for Direct while erroring on every other URL would be the stranger
/// contract. `resolve_with_pac` and `WinHttpPacResolver::resolve_config` do take hostless
/// first — they can answer the rest. Then, under a manual mode, hostless or bypass → Direct;
/// else [`entry_for`](ProxyMode::entry_for) /
/// [`websocket_entry`](ProxyMode::websocket_entry) for `ws`/`wss`.
///
/// The list transcribes what the configuration says; it never invents alternatives. A single
/// manual entry yields a single step, and a versionless `socks` host is one step at this
/// crate's assumed version rather than one step per version a caller might try.
///
/// The transcription is only ever as strong as the source that produced the mode, and one
/// source is weaker than it looks: a [`ProxyMode::Direct`] carrying
/// [`ProxyConfigSource::Portal`](crate::ProxyConfigSource::Portal) says the portal had no
/// proxy for a fixed probe host, not for `url` — that variant's doc has the reason. Nothing
/// here can narrow the gap, because the snapshot no longer knows what was asked.
///
/// # Errors
///
/// [`Error::PacNotSupported`] for auto-config modes, and
/// [`Error::ProxyEntryUnusable`] where the only entry that would have covered `url` was
/// dropped — reporting that is not the same as answering Direct.
///
/// ```
/// # use proxy_watch::{parse, resolve, ProxyConfig, ProxyConfigSource, ProxyStep, Url};
/// let mode = parse::windows_manual("http=proxy.corp:8080", "<local>;*.corp.example");
/// let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);
///
/// let steps = resolve(&config, &Url::parse("http://example.net/x").unwrap())?;
/// assert_eq!(steps[0].endpoint().unwrap().authority(), "proxy.corp:8080");
///
/// let steps = resolve(&config, &Url::parse("http://api.corp.example/x").unwrap())?;
/// assert_eq!(steps, vec![ProxyStep::Direct]);
/// # Ok::<(), proxy_watch::Error>(())
/// ```
pub fn resolve(config: &ProxyConfig, url: &Url) -> Result<Vec<ProxyStep>, Error> {
    resolve_mode(&config.effective, url)
}

// Mode-only body of [`resolve`] (tests / future single-source callers).
fn resolve_mode(mode: &ProxyMode, url: &Url) -> Result<Vec<ProxyStep>, Error> {
    match mode {
        ProxyMode::Direct => return Ok(vec![ProxyStep::Direct]),
        ProxyMode::Pac { .. } => return Err(Error::PacNotSupported { mode: "pac" }),
        ProxyMode::PacInline { .. } => {
            return Err(Error::PacNotSupported { mode: "pac-inline" });
        }
        ProxyMode::WpadAutoDetect => return Err(Error::PacNotSupported { mode: "wpad" }),
        ProxyMode::Manual { .. } => {}
    }

    // No host → Direct (`data:`, `mailto:`, `file:///…`). Asked before the bypass list and
    // not left to it: `matches_url` answers "does not bypass" for a hostless URL, which is
    // the right answer to *that* question and the wrong routing decision here — there is no
    // destination for a proxy to reach.
    if !has_request_host(url) {
        return Ok(vec![ProxyStep::Direct]);
    }

    // Through `matches_url` rather than `matches`, because which port a portless URL is
    // compared with is the source's business and `BypassRules` is what knows the source.
    if let Some(bypass) = mode.bypass()
        && bypass.matches_url(url)
    {
        return Ok(vec![ProxyStep::Direct]);
    }

    let entry = if matches!(url.scheme(), "ws" | "wss") {
        mode.websocket_entry()
    } else {
        mode.entry_for(request_scheme(url))
    };
    match entry {
        Some(ProxyEntry::Use(endpoint)) => Ok(vec![ProxyStep::from_endpoint(endpoint.clone())]),
        // `Disabled` is an answer: the platform named this scheme and left it unproxied.
        Some(ProxyEntry::Disabled) => Ok(vec![ProxyStep::Direct]),
        // A drop *is* why nothing covers the scheme. The lookups above are what found it, so
        // the record reported is the one whose loss took this request's answer away — for
        // `ws` that is not the request's own scheme, and there is no second walk to keep in
        // step with them. Naming it by the slot it came from is what
        // `Error::ProxyEntryUnusable::scheme` promises, and the slot is the key
        // `ProxyMode::with_rejected` filed the record under: its own `affected_scheme`, which
        // for a mode this crate built is never `None`, since a record naming no scheme is
        // never filed at all. A caller assembling a `Manual` by hand can put one there —
        // every piece of that is public — and the `unwrap_or` is what answers then; it says
        // the catch-all rather than a concrete scheme nobody named.
        Some(ProxyEntry::Unusable(rejected)) => Err(Error::ProxyEntryUnusable {
            scheme: rejected.affected_scheme().unwrap_or(Scheme::All),
            rejected: rejected.clone(),
        }),
        None => Ok(vec![ProxyStep::Direct]),
    }
}

/// Like [`resolve`], but evaluates PAC when the mode requires it.
///
/// For [`ProxyMode::Direct`] and [`ProxyMode::Manual`], this agrees with [`resolve`] exactly
/// and `script` is ignored. `PacInline`: body from `script` or mode. `Pac`: `Some(script)`
/// or [`Error::PacFetchRequired`]. `WpadAutoDetect`: `Some(script)` or
/// [`Error::PacNotSupported`]. Never downloads; hostless → Direct; no bypass in PAC modes.
///
/// # Errors
///
/// [`Error::PacFetchRequired`], [`Error::PacNotSupported`], [`pac::evaluate`](crate::pac::evaluate),
/// and — because `Direct` and `Manual` are handed straight to [`resolve`] —
/// [`Error::ProxyEntryUnusable`].
///
/// ```
/// # #[cfg(feature = "pac-boa")] {
/// use proxy_watch::pac::PacPolicy;
/// use proxy_watch::{Error, ProxyConfig, ProxyConfigSource, ProxyMode, Url, resolve_with_pac};
///
/// let mode = ProxyMode::pac(Url::parse("http://wpad.corp/proxy.pac").unwrap());
/// let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);
/// let url = Url::parse("http://example.net/").unwrap();
///
/// let Error::PacFetchRequired { url: wanted } =
///     resolve_with_pac(&config, &url, None, &PacPolicy::new()).unwrap_err()
/// else { panic!() };
/// assert_eq!(wanted.as_str(), "http://wpad.corp/proxy.pac");
/// # }
/// # Ok::<(), proxy_watch::Error>(())
/// ```
#[cfg(feature = "pac")]
pub fn resolve_with_pac(
    config: &ProxyConfig,
    url: &Url,
    script: Option<&crate::pac::PacScript>,
    policy: &crate::pac::PacPolicy,
) -> Result<Vec<ProxyStep>, Error> {
    use crate::pac::{self, PacScript};

    let mode = &config.effective;
    if matches!(mode, ProxyMode::Direct | ProxyMode::Manual { .. }) {
        return resolve_mode(mode, url);
    }

    // Hostless → Direct before mode checks (unlike WinHTTP's PacInline refusal).
    if !has_request_host(url) {
        return Ok(vec![ProxyStep::Direct]);
    }

    let from_mode;
    let script = match script {
        Some(script) => script,
        None => match mode {
            ProxyMode::PacInline { script, .. } => {
                from_mode = PacScript::new(script.clone());
                &from_mode
            }
            ProxyMode::Pac { url, .. } => return Err(Error::PacFetchRequired { url: url.clone() }),
            // WPAD discovery is a non-goal (DHCP/DNS MITM); caller must supply the script.
            _ => return Err(Error::PacNotSupported { mode: "wpad" }),
        },
    };

    pac::evaluate(script, url, policy)
}

// The `per_scheme` key a request URL is looked up under.
fn request_scheme(url: &Url) -> Scheme {
    match url.scheme() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        "ftp" => Scheme::Ftp,
        "socks" | "socks4" | "socks4a" | "socks5" | "socks5h" => Scheme::Socks,
        // Unknown scheme: only a catch-all entry can apply.
        _ => Scheme::All,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use url::Host;

    use crate::auth::ProxyAuth;
    use crate::config::ProxyConfigSource;
    use crate::diagnostic::RejectedValue;

    /// A ported bypass entry meets a portless URL everywhere except GNOME. Do not fill the
    /// scheme's default port at the call site for every source: that makes an `ignore-hosts`
    /// of `intranet.corp:80` report `http://intranet.corp/` direct while GNOME sends it to
    /// the proxy.
    ///
    /// GLib resolves the destination with `G_URI_FLAGS_NONE`
    /// (`gsimpleproxyresolver.c`, `g_simple_proxy_resolver_lookup`) and fills a scheme's
    /// default port only under `G_URI_FLAGS_SCHEME_NORMALIZE` (`guri.c`), so it compares
    /// against port 0 and `ignore_host`'s `domain->port == port` fails. Windows does the
    /// opposite — a
    /// `ProxyOverride` of `host:80` bypasses a portless `http://host/` — so the default
    /// stays the default and GNOME asks for the other reading through the flag.
    #[test]
    fn a_bypass_list_that_wants_an_explicit_port_does_not_get_a_default_one() {
        let manual = |bypass| ProxyMode::Manual {
            per_scheme: std::collections::HashMap::from([(
                Scheme::All,
                ProxyEntry::Use(ProxyEndpoint::new(
                    Host::Domain("proxy.corp".to_owned()),
                    8080,
                )),
            )]),
            bypass,
            rejected: Vec::new(),
        };
        let bare = Url::parse("http://intranet.corp/").unwrap();
        let ported = Url::parse("http://intranet.corp:8081/").unwrap();
        let proxied = |mode: &ProxyMode, url: &Url| {
            resolve_mode(mode, url).unwrap()[0]
                .endpoint()
                .map(ProxyEndpoint::authority)
        };

        // The usual reading: a rule written `:80` is the HTTP port whether or not the URL
        // spelled it out.
        let usual = manual(crate::parse::no_proxy("intranet.corp:80"));
        assert_eq!(
            resolve_mode(&usual, &bare).unwrap(),
            vec![ProxyStep::Direct]
        );

        // GNOME's: the port the URL did not write is not one the rule may match on.
        let mut rules = crate::parse::no_proxy("intranet.corp:80");
        rules.require_explicit_port = true;
        assert_eq!(
            proxied(&manual(rules), &bare).as_deref(),
            Some("proxy.corp:8080")
        );

        // Written out, it is — the flag is about inference, not about ports.
        let mut rules = crate::parse::no_proxy("intranet.corp:8081");
        rules.require_explicit_port = true;
        let gnome = manual(rules);
        assert_eq!(
            resolve_mode(&gnome, &ported).unwrap(),
            vec![ProxyStep::Direct]
        );
        assert_eq!(proxied(&gnome, &bare).as_deref(), Some("proxy.corp:8080"));

        // The limit, held here rather than left to be discovered: a rule on a scheme's own
        // default port can no longer fire at all, because `Url` normalises that port out of
        // the URL at parse time — `http://intranet.corp:80/` and `http://intranet.corp/`
        // are the same value by the time `resolve` is handed one, so the destination GLib
        // would bypass cannot be told from the one it would not. Reporting the proxy is the
        // safe half of a distinction this crate's input type has already lost.
        let mut default_port = crate::parse::no_proxy("intranet.corp:80");
        default_port.require_explicit_port = true;
        assert_eq!(
            proxied(
                &manual(default_port),
                &Url::parse("http://intranet.corp:80/").unwrap()
            )
            .as_deref(),
            Some("proxy.corp:8080")
        );

        // An entry with no port of its own is unaffected either way, which is what keeps
        // the flag from reading as "GNOME bypasses less".
        let mut portless = crate::parse::no_proxy("intranet.corp");
        portless.require_explicit_port = true;
        assert_eq!(
            resolve_mode(&manual(portless), &bare).unwrap(),
            vec![ProxyStep::Direct]
        );
    }

    #[test]
    fn scheme_hints_pick_the_step_variant() {
        let base = ProxyEndpoint::new(Host::Domain("p".to_owned()), 1080);
        let with = |hint| ProxyStep::from_endpoint(base.clone().with_scheme_hint(hint));

        assert!(matches!(
            ProxyStep::from_endpoint(base.clone()),
            ProxyStep::Http(_)
        ));
        assert!(matches!(with(ProxyScheme::Http), ProxyStep::Http(_)));
        assert!(matches!(with(ProxyScheme::Https), ProxyStep::Https(_)));
        assert!(matches!(with(ProxyScheme::Socks4), ProxyStep::Socks4(_)));
        assert!(matches!(with(ProxyScheme::Socks4a), ProxyStep::Socks4(_)));
        assert!(matches!(with(ProxyScheme::Socks5), ProxyStep::Socks5(_)));
        assert!(matches!(with(ProxyScheme::Socks5h), ProxyStep::Socks5(_)));
    }

    #[test]
    fn to_url_preserves_the_socks_remote_dns_hint() {
        // `socks5h://` must come back as `socks5h://`, not rounded down to
        // `socks5://` — the `h` means the proxy resolves the name; dropping it would
        // make the client resolve instead (a DNS leak), not just lose a spelling.
        let endpoint = ProxyEndpoint::parse("socks5h://proxy.example:1080", 80).unwrap();
        let url = ProxyStep::Socks5(endpoint).to_url().unwrap();
        assert_eq!(url.scheme(), "socks5h");
        assert_eq!(url.as_str(), "socks5h://proxy.example:1080");

        // Same rule for the SOCKS4 side.
        let endpoint = ProxyEndpoint::parse("socks4a://proxy.example:1080", 80).unwrap();
        let url = ProxyStep::Socks4(endpoint).to_url().unwrap();
        assert_eq!(url.scheme(), "socks4a");
        assert_eq!(url.as_str(), "socks4a://proxy.example:1080");

        // The non-`a`/`h` forms still round-trip as themselves.
        let endpoint = ProxyEndpoint::parse("socks5://proxy.example:1080", 80).unwrap();
        let url = ProxyStep::Socks5(endpoint).to_url().unwrap();
        assert_eq!(url.scheme(), "socks5");

        let endpoint = ProxyEndpoint::parse("socks4://proxy.example:1080", 80).unwrap();
        let url = ProxyStep::Socks4(endpoint).to_url().unwrap();
        assert_eq!(url.scheme(), "socks4");

        // No hint at all (the usual case from a bare `host:port` source): the variant's
        // plain scheme, same as before this behavior existed.
        let endpoint = ProxyEndpoint::new(Host::Domain("proxy".to_owned()), 1080);
        let url = ProxyStep::Socks5(endpoint).to_url().unwrap();
        assert_eq!(url.scheme(), "socks5");

        // `scheme()` itself is unchanged: it still only ever names the variant, never
        // the `a`/`h` hint.
        let endpoint = ProxyEndpoint::parse("socks5h://proxy.example:1080", 80).unwrap();
        assert_eq!(ProxyStep::Socks5(endpoint).scheme(), Some("socks5"));
    }

    #[test]
    fn to_url_answers_none_for_a_host_no_url_can_hold() {
        // The documented meaning of `None` was Direct, so a caller reading it that way
        // would take this step for "connect directly" — the one reading the step itself
        // contradicts. Nothing beyond the public surface is needed to reach it:
        // `Host::Domain` does not validate its `String` and `Host` is re-exported from
        // the crate root.
        let step = ProxyStep::Http(ProxyEndpoint::new(
            Host::Domain("bad host".to_owned()),
            8080,
        ));
        assert!(step.to_url().is_none());
        assert!(step.endpoint().is_some(), "and yet the step is not Direct");
        assert_eq!(step.scheme(), Some("http"));

        // The other half, and the one a caller cannot see coming: a host the URL parser
        // accepts by reading part of it as something else. `user@evil` splits at the `@`
        // into userinfo and the host `evil`; `evil/x` keeps `evil` and takes the port with
        // it into the path. Both are `None` for the same reason "bad host" is.
        for host in ["user@evil", "evil/x", "evil?x", "evil#x"] {
            let step = ProxyStep::Http(ProxyEndpoint::new(Host::Domain(host.to_owned()), 8080));
            assert!(step.to_url().is_none(), "{host} produced a URL");
        }

        // And the tightening stops there: a name only IDNA can spell still resolves, and
        // the case it was written in is not what makes a host unusable.
        for host in ["例え.jp", "Proxy.Example"] {
            let step = ProxyStep::Http(ProxyEndpoint::new(Host::Domain(host.to_owned()), 8080));
            assert!(step.to_url().is_some(), "{host} lost its URL");
        }
    }

    #[test]
    fn to_url_percent_encodes_credentials() {
        let endpoint = ProxyEndpoint::new(Host::Domain("proxy".to_owned()), 8080)
            .with_auth(ProxyAuth::new("al ice", Some("p@ss")));
        let url = ProxyStep::Http(endpoint).to_url().unwrap();
        assert_eq!(url.as_str(), "http://al%20ice:p%40ss@proxy:8080/");
        assert_eq!(url.password(), Some("p%40ss"));
    }

    #[test]
    fn a_snapshot_resolves_through_its_effective_mode() {
        let mode = crate::parse::windows_manual("proxy:8080", "");
        let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);
        let url = Url::parse("http://example.com/").unwrap();
        assert_eq!(
            resolve(&config, &url).unwrap()[0].endpoint().unwrap().port,
            8080
        );
    }

    #[test]
    fn request_schemes_map_onto_entry_keys() {
        // `ws`/`wss` are deliberately absent here: `resolve_mode` never calls
        // `request_scheme` for them (see its doc comment) — they go through
        // `ProxyMode::websocket_entry` instead, exercised below.
        // Every SOCKS spelling `request_scheme`'s `or` pattern lists, not one of them,
        // because a row is the only thing holding a spelling: one that falls out of that
        // pattern quietly lands on `Scheme::All` and is routed by a catch-all entry instead
        // of the SOCKS one.
        let cases = [
            ("http://h/", Scheme::Http),
            ("https://h/", Scheme::Https),
            ("ftp://h/", Scheme::Ftp),
            ("socks://h/", Scheme::Socks),
            ("socks4://h/", Scheme::Socks),
            ("socks4a://h/", Scheme::Socks),
            ("socks5://h/", Scheme::Socks),
            ("socks5h://h/", Scheme::Socks),
            ("gopher://h/", Scheme::All),
        ];
        for (input, expected) in cases {
            let url = Url::parse(input).unwrap();
            assert_eq!(request_scheme(&url), expected, "{input}");
        }
    }

    // Whether a drop names the scheme being asked about is the whole trigger, so the cases
    // below vary exactly that against modes that would otherwise all answer `Direct`.
    fn dropped(scheme: Option<Scheme>) -> RejectedValue {
        RejectedValue::new(
            crate::RejectionKind::UnsupportedMapping,
            crate::RejectionSource::Kioslaverc("ftpProxy".to_owned()),
            "$ftp_proxy",
        )
        .for_scheme(scheme)
    }

    fn mode_with(entries: Vec<(Scheme, ProxyEntry)>, rejected: Vec<RejectedValue>) -> ProxyMode {
        ProxyMode::manual(entries.into_iter().collect(), crate::BypassRules::new())
            .with_rejected(rejected)
    }

    #[test]
    fn a_drop_that_covered_the_requested_scheme_is_reported_not_called_direct() {
        let mode = mode_with(Vec::new(), vec![dropped(Some(Scheme::Ftp))]);
        let url = Url::parse("ftp://files.example/x").unwrap();
        let err = resolve_mode(&mode, &url).unwrap_err();
        assert!(
            matches!(&err, Error::ProxyEntryUnusable { scheme, rejected }
                if *scheme == Scheme::Ftp && rejected.affected_scheme() == Some(Scheme::Ftp)),
            "{err:?}"
        );
    }

    // Which of several drops the error names. Only a mode whose drops sit in two different
    // tiers can tell the search order apart, and the record order is deliberately the reverse
    // of the lookup order in both halves below.
    #[test]
    fn the_drop_reported_is_the_one_the_lookup_would_have_used_first() {
        // The ordinary path, where the order is "the request's own scheme, then the catch-all".
        let mode = mode_with(
            Vec::new(),
            vec![dropped(Some(Scheme::All)), dropped(Some(Scheme::Http))],
        );
        let url = Url::parse("http://intranet.corp/x").unwrap();
        let err = resolve_mode(&mode, &url).unwrap_err();
        assert!(
            matches!(&err, Error::ProxyEntryUnusable { scheme, .. } if *scheme == Scheme::Http),
            "{err:?}"
        );

        // The websocket chain, which has four tiers rather than two: it tries SOCKS before
        // HTTP, so losing the SOCKS slot is what took this request's answer away — even
        // though the HTTP drop was recorded first.
        let mode = mode_with(
            Vec::new(),
            vec![dropped(Some(Scheme::Http)), dropped(Some(Scheme::Socks))],
        );
        let url = Url::parse("wss://chat.example/x").unwrap();
        let err = resolve_mode(&mode, &url).unwrap_err();
        assert!(
            matches!(&err, Error::ProxyEntryUnusable { scheme, .. } if *scheme == Scheme::Socks),
            "{err:?}"
        );
    }

    // The tier is only half of "which drop". Two records can name the *same* tier, and
    // [`Error::ProxyEntryUnusable`]'s `rejected` field promises the first of them — a
    // promise the whole suite kept passing with the last one instead, because every case
    // above puts its two drops in different tiers.
    //
    // Reachable from one registry value: `proxy_server_with_rejected` files a record per
    // malformed token, and a `ProxyServer` string may repeat a scheme key. Built through it
    // rather than by hand, since which of two same-tier records the caller sees is only
    // interesting if a source can produce two.
    #[test]
    fn the_first_of_two_drops_naming_one_tier_is_the_one_reported() {
        // Out-of-range ports rather than anything with a space in it: the separator set
        // includes whitespace, so a two-word token is two tokens and neither is malformed.
        let mode = crate::parse::windows_manual("http=h:99999;http=h:88888", "");
        let Some([first, second]) = mode
            .rejected()
            .and_then(|all| <&[_; 2]>::try_from(all).ok())
        else {
            panic!("both tokens must be refused, or this holds nothing: {mode:?}");
        };
        assert_eq!(first.redacted_input(), "http=h:99999");
        assert_eq!(second.redacted_input(), "http=h:88888");

        let url = Url::parse("http://intranet.corp/x").unwrap();
        let err = resolve_mode(&mode, &url).unwrap_err();
        assert!(
            matches!(&err, Error::ProxyEntryUnusable { rejected, .. }
                if rejected.redacted_input() == "http=h:99999"),
            "{err:?}"
        );
    }

    // What keeps the change off the path Chromium also takes: a live catch-all answers, so the
    // drop took nothing away and nothing is reported. Chromium's `MapUrlSchemeToProxyList`
    // reaches for `fallback_proxies` in the same case.
    #[test]
    fn a_live_catch_all_still_covers_a_dropped_scheme() {
        let socks = ProxyEndpoint::new(Host::Domain("s".to_owned()), 1080);
        let mode = mode_with(
            vec![(Scheme::All, ProxyEntry::Use(socks))],
            vec![dropped(Some(Scheme::Ftp))],
        );
        let url = Url::parse("ftp://files.example/x").unwrap();
        let steps = resolve_mode(&mode, &url).unwrap();
        assert!(!steps.contains(&ProxyStep::Direct), "{steps:?}");
    }

    #[test]
    fn a_drop_naming_another_scheme_leaves_this_one_direct() {
        let mode = mode_with(Vec::new(), vec![dropped(Some(Scheme::Ftp))]);
        let url = Url::parse("https://a.example/x").unwrap();
        assert_eq!(resolve_mode(&mode, &url).unwrap(), vec![ProxyStep::Direct]);
    }

    // An unrecognised key names no scheme, so it cannot say which requests it would have
    // covered — and must not turn every uncovered request into an error.
    #[test]
    fn a_drop_naming_no_scheme_never_turns_direct_into_an_error() {
        let mode = mode_with(Vec::new(), vec![dropped(None)]);
        for input in [
            "ftp://f.example/x",
            "https://a.example/x",
            "ws://a.example/x",
        ] {
            let url = Url::parse(input).unwrap();
            assert_eq!(
                resolve_mode(&mode, &url).unwrap(),
                vec![ProxyStep::Direct],
                "{input}"
            );
        }
    }

    // The `unwrap_or` behind that error's `scheme`. Inside the crate it is unreachable, and
    // the comment at the call site says so: `ProxyMode::with_rejected` skips a record naming
    // no scheme, so nothing it files under `per_scheme` can hold one. But `ProxyMode::manual`,
    // `ProxyEntry::Unusable` and `RejectedValue::new` are all public, so a caller assembling a
    // mode by hand puts one exactly there, and then the default is what the error reports.
    // This test is the only thing holding the default. The message is built from that field,
    // so with a concrete scheme there instead, a caller who never named http would read "the
    // configured http proxy could not be used" about an ftp request. `Scheme::All` is what
    // the field is documented to say wherever the slot is not a concrete one.
    #[test]
    fn a_hand_built_drop_naming_no_scheme_is_reported_against_the_catch_all() {
        let mode = mode_with(
            vec![(Scheme::Ftp, ProxyEntry::Unusable(dropped(None)))],
            Vec::new(),
        );
        let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);
        let url = Url::parse("ftp://files.example/x").unwrap();
        let err = resolve(&config, &url).unwrap_err();
        assert!(
            matches!(&err, Error::ProxyEntryUnusable { scheme, .. } if *scheme == Scheme::All),
            "{err:?}"
        );
    }

    // `Disabled` is an answer the platform gave, not an answer this crate lost.
    #[test]
    fn an_explicitly_disabled_scheme_stays_direct_beside_a_drop() {
        let mode = mode_with(
            vec![(Scheme::Ftp, ProxyEntry::Disabled)],
            vec![dropped(Some(Scheme::Ftp))],
        );
        let url = Url::parse("ftp://files.example/x").unwrap();
        assert_eq!(resolve_mode(&mode, &url).unwrap(), vec![ProxyStep::Direct]);
    }

    // The same, with the drop moved to `Scheme::All`. A *live* catch-all does not reach a
    // scheme holding `Disabled` — that is `entry_for`'s first rule — so losing one cannot
    // have taken that scheme's answer away either. `http_proxy=` beside an unparseable
    // `all_proxy=` is the reachable spelling: direct for HTTP, the drop for everything else.
    #[test]
    fn an_all_drop_does_not_reach_past_an_explicitly_disabled_scheme() {
        let mode = mode_with(
            vec![(Scheme::Http, ProxyEntry::Disabled)],
            vec![dropped(Some(Scheme::All))],
        );
        let url = Url::parse("http://a.example/x").unwrap();
        assert_eq!(resolve_mode(&mode, &url).unwrap(), vec![ProxyStep::Direct]);

        let url = Url::parse("ftp://files.example/x").unwrap();
        let err = resolve_mode(&mode, &url).unwrap_err();
        assert!(
            matches!(&err, Error::ProxyEntryUnusable { rejected, .. }
                if rejected.affected_scheme() == Some(Scheme::All)),
            "{err:?}"
        );
    }

    // `a_live_catch_all_still_covers_a_dropped_scheme` with the answer moved out of the
    // drop's own reach, which is what the record now sitting *in* `per_scheme` can get wrong:
    // it is passed over on the way to a later slot rather than never looked at at all. Both
    // rows below therefore need a step the lookup takes after
    // the lost one — a `Disabled` catch-all is still an answer, and the `ws` chain still
    // walks on — so neither can be satisfied by a drop that simply stops the walk.
    #[test]
    fn a_drop_never_pre_empts_an_answer_the_chain_reaches_later() {
        let proxy = ProxyEndpoint::parse("p.example:3128", 80).unwrap();
        let cases = [
            (
                "http://a.example/x",
                vec![(Scheme::All, ProxyEntry::Disabled)],
                Scheme::Http,
                vec![ProxyStep::Direct],
            ),
            (
                "ws://a.example/x",
                vec![(Scheme::Http, ProxyEntry::Use(proxy.clone()))],
                Scheme::Socks,
                vec![ProxyStep::from_endpoint(proxy)],
            ),
        ];
        for (input, entries, lost, expected) in cases {
            let mode = mode_with(entries, vec![dropped(Some(lost))]);
            let url = Url::parse(input).unwrap();
            assert_eq!(
                resolve_mode(&mode, &url).unwrap(),
                expected,
                "{input} without {lost:?}"
            );
        }
    }

    // `ws` never asks `entry_for`, so the drop is matched against the chain
    // `websocket_entry` walks rather than against `request_scheme`'s single key.
    #[test]
    fn a_websocket_request_is_covered_by_the_chain_it_would_have_walked() {
        let mode = mode_with(Vec::new(), vec![dropped(Some(Scheme::Https))]);
        let url = Url::parse("ws://a.example/x").unwrap();
        let err = resolve_mode(&mode, &url).unwrap_err();
        assert!(
            matches!(&err, Error::ProxyEntryUnusable { scheme, .. } if *scheme == Scheme::Https),
            "{err:?}"
        );
    }
}
