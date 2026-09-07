//! PAC evaluation (`pac` feature, off by default): script → `Vec<ProxyStep>` like
//! [`resolve`](crate::resolve()).
//!
//! No in-crate fetch — pass body to [`evaluate`]. Untrusted code: [`PacPolicy`] defaults
//! block DNS, fake local IP, 5 s budget. `pac-boa` to run. Bypass lists do not apply.

#[cfg_attr(not(feature = "pac-boa"), allow(dead_code))]
mod hostfn;
mod policy;
mod result;
#[cfg_attr(not(feature = "pac-boa"), allow(dead_code))]
mod time;

#[cfg(feature = "pac-boa")]
mod boa;

// WinHTTP path: target+feature gated so the flag stays additive/portable.
#[cfg(all(windows, feature = "pac-windows-native"))]
mod winhttp;

use std::fmt;

use url::Url;

use crate::error::Error;
use crate::mode::ProxyMode;
use crate::resolve::ProxyStep;

pub use self::policy::{
    DEFAULT_PAC_LOOP_LIMIT, DEFAULT_PAC_RECURSION_LIMIT, DEFAULT_PAC_STACK_SIZE_LIMIT,
    DEFAULT_PAC_TIMEOUT, PacPolicy,
};
pub use self::result::parse_find_proxy_result;

#[cfg(feature = "pac-boa")]
pub use self::boa::BoaEvaluator;

#[cfg(all(windows, feature = "pac-windows-native"))]
pub use self::winhttp::{DEFAULT_WINHTTP_PAC_TIMEOUT, WinHttpPacResolver, WinHttpPacSource};

/// PAC script body (newtype so "this is JS that will run" stays visible in signatures).
#[derive(Clone, PartialEq, Eq)]
pub struct PacScript {
    source: String,
}

// Same masking as [`ProxyMode::PacInline`]: length + FNV-1a, never the source.
impl fmt::Debug for PacScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacScript")
            .field("len", &self.source.len())
            .field(
                "fnv1a",
                &format_args!("{:016x}", crate::util::fnv1a(self.source.as_bytes())),
            )
            .finish()
    }
}

impl PacScript {
    /// Wrap a script body.
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
        }
    }

    /// The JavaScript source.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// [`ProxyMode::PacInline`]'s body, or `None` (including for [`ProxyMode::Pac`]).
    #[must_use]
    pub fn from_mode(mode: &ProxyMode) -> Option<Self> {
        match mode {
            ProxyMode::PacInline { script, .. } => Some(Self::new(script.clone())),
            _ => None,
        }
    }
}

impl From<String> for PacScript {
    fn from(source: String) -> Self {
        Self::new(source)
    }
}

impl From<&str> for PacScript {
    fn from(source: &str) -> Self {
        Self::new(source)
    }
}

/// What [`requirement`] says a [`ProxyMode`] needs before routing.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacRequirement<'a> {
    /// No auto-config; [`resolve`](crate::resolve()) already answers.
    NotNeeded,
    /// Body already in the snapshot ([`ProxyMode::PacInline`]).
    Inline(&'a str),
    /// Fetch this URL and pass the body ([`ProxyMode::Pac`]).
    Fetch(&'a Url),
    /// WPAD on; no DHCP 252 / DNS `wpad.` discovery (collision risk). Windows:
    /// `pac-windows-native`. Else: inline or fetched script.
    Discover,
}

// Mirror [`ProxyMode`]'s Debug: `Inline` → len+digest, `Fetch` → redacted URL.
impl fmt::Debug for PacRequirement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNeeded => f.write_str("NotNeeded"),
            Self::Discover => f.write_str("Discover"),
            Self::Inline(script) => f
                .debug_struct("Inline")
                .field("len", &script.len())
                .field(
                    "fnv1a",
                    &format_args!("{:016x}", crate::util::fnv1a(script.as_bytes())),
                )
                .finish(),
            Self::Fetch(url) => f
                .debug_tuple("Fetch")
                .field(&format_args!(
                    "{}",
                    crate::util::redact_userinfo(url.as_str())
                ))
                .finish(),
        }
    }
}

/// What `mode` needs before [`evaluate`] can be called for it.
///
/// ```
/// # use proxy_watch::pac::{requirement, PacRequirement};
/// # use proxy_watch::ProxyMode;
/// assert_eq!(requirement(&ProxyMode::Direct), PacRequirement::NotNeeded);
/// let inline = ProxyMode::pac_inline("…".to_owned());
/// assert_eq!(requirement(&inline), PacRequirement::Inline("…"));
/// ```
#[must_use]
pub fn requirement(mode: &ProxyMode) -> PacRequirement<'_> {
    match mode {
        ProxyMode::Pac { url, .. } => PacRequirement::Fetch(url),
        ProxyMode::PacInline { script, .. } => PacRequirement::Inline(script),
        ProxyMode::WpadAutoDetect => PacRequirement::Discover,
        _ => PacRequirement::NotNeeded,
    }
}

// Replaceable JS engine: `pac-boa` ships [`BoaEvaluator`]; WinHTTP uses `WinHttpPacResolver`.
/// macOS may wrap `CFNetworkCopyProxiesForAutoConfigurationScript`. [`PacPolicy`] on the impl.
pub trait PacEvaluator {
    /// Run `FindProxyForURL(url, host)` and parse the result.
    ///
    /// Call [`sanitize_url`] if you bypass [`evaluate_with_host`].
    ///
    /// # Errors
    ///
    /// [`Error::PacEvaluation`], [`Error::PacTimeout`], [`Error::PacInvalidResult`], and
    /// [`Error::Io`] for an OS resource the evaluator needs but cannot get — with a
    /// [`PacPolicy::timeout`] set, `BoaEvaluator` spawns the thread it enforces the
    /// budget on, and that spawn can fail.
    fn evaluate(&self, script: &PacScript, url: &Url, host: &str) -> Result<Vec<ProxyStep>, Error>;
}

/// Chromium `SanitizeUrl`: strip userinfo+fragment; path+query only for `https`/`wss`.
/// Not a [`PacPolicy`] knob. Custom [`PacEvaluator`] impls should still sanitize.
///
/// ```
/// use proxy_watch::Url;
/// use proxy_watch::pac::sanitize_url;
///
/// let url = Url::parse("http://user:secret@example.net/a/b?q=1#frag").unwrap();
/// assert_eq!(sanitize_url(&url).as_str(), "http://example.net/a/b?q=1");
///
/// let url = Url::parse("https://user:secret@example.net/a/b?q=1#frag").unwrap();
/// assert_eq!(sanitize_url(&url).as_str(), "https://example.net/");
/// ```
#[must_use]
pub fn sanitize_url(url: &Url) -> Url {
    let mut sanitized = url.clone();
    // Both setters refuse a URL `has_host()` calls hostless. A cannot-be-a-base URL reaches
    // that refusal with no userinfo to lose — but a non-special scheme whose host was emptied
    // is hostless *and* still holds `user:pass@`, because `set_host(Some(""))` accepts on
    // `socks5:` what it rejects on `http:` with `EmptyHost`. Lend such a URL a host so the
    // setters engage, then put the empty host back. All or nothing: a half-applied round trip
    // would move the host instead of the credentials. The authority is what separates the two
    // refusals — `Url::password` is not, because it panics on exactly these URLs
    // (`trace::render::MaskedUrl` has the same note).
    let refused = sanitized.set_username("").is_err();
    let _ = sanitized.set_password(None);
    if refused && sanitized.has_authority() {
        let mut lent = sanitized.clone();
        if lent.set_host(Some("x")).is_ok()
            && lent.set_username("").is_ok()
            && lent.set_password(None).is_ok()
            && lent.set_host(Some("")).is_ok()
        {
            sanitized = lent;
        }
    }
    sanitized.set_fragment(None);
    if matches!(sanitized.scheme(), "https" | "wss") {
        sanitized.set_path("/");
        sanitized.set_query(None);
    }
    sanitized
}

/// Evaluate `script` for `url` under `policy` (`sanitize_url` first).
///
/// `pac-boa` is the only engine this reaches, whatever else is enabled — turning on
/// `pac-windows-native` as well adds `WinHttpPacResolver` for the caller to drive, not a
/// second engine for this function to choose between.
///
/// A URL with no host (`data:`, `mailto:`) is still evaluated, with `host` empty —
/// `resolve_with_pac` and `WinHttpPacResolver::resolve_config` answer Direct for those
/// without running anything. This is the engine door, not a routing entry point.
///
/// # Errors
///
/// [`Error::PacEngineUnavailable`] with no engine, else [`PacEvaluator::evaluate`].
pub fn evaluate(
    script: &PacScript,
    url: &Url,
    policy: &PacPolicy,
) -> Result<Vec<ProxyStep>, Error> {
    // `host_str` keeps the brackets on an IPv6 literal, so the script sees `[::1]`. The two
    // references disagree here — Gecko passes `nsIURI::GetAsciiHost`, whose IPv6 segment is
    // bracketed, while Chromium passes `GURL::HostNoBrackets()` — so neither spelling can be
    // called the right one. Following Gecko keeps the string the URL itself carries; the host
    // functions accept both spellings (`unbracket_ipv6` in `dns_resolve` / `is_resolvable`,
    // the colon test in `is_plain_host_name`), and `evaluate_with_host` is the way out for a
    // caller who wants Chromium's.
    evaluate_with_host(script, url, url.host_str().unwrap_or_default(), policy)
}

/// Like [`evaluate`], but the caller chooses `host` (`url` is still sanitized).
///
/// # Errors
///
/// Same as [`evaluate`].
pub fn evaluate_with_host(
    script: &PacScript,
    url: &Url,
    host: &str,
    policy: &PacPolicy,
) -> Result<Vec<ProxyStep>, Error> {
    let url = &sanitize_url(url);
    // `pac-boa` is the only engine this function can reach, whatever else is enabled:
    // `pac-windows-native` exports [`WinHttpPacResolver`] for the caller to drive itself
    // rather than entering a selection here. There is no engine ordering to describe.
    #[cfg(feature = "pac-boa")]
    {
        BoaEvaluator::new(*policy).evaluate(script, url, host)
    }
    #[cfg(not(feature = "pac-boa"))]
    {
        let _ = (script, url, host, policy);
        Err(Error::PacEngineUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::BypassRules;

    // The answer this type carries is the whole point of asking for it, and the arms with no
    // field print as a bare word from a hand-written impl, so this test is the only thing
    // comparing the word to the variant. `Discover` rendered as `NotNeeded` reads as its own
    // opposite — "WPAD is on and the discovery cannot be run here" against
    // "routing is already answered". Deciding whether a machine needs a PAC engine is read
    // off exactly this line.
    //
    // `PacScript` shares the digest rendering with `Inline`, so it is held here too. Its
    // `len` label is in `debug_masking`'s registry, which asks the rendering to *contain*
    // the word; the exact string is what also refuses `length`.
    #[test]
    fn every_requirement_debug_names_itself_and_keeps_its_fields() {
        const SCRIPT: &str = "function FindProxyForURL(){}";
        let url = Url::parse("https://wpad.corp/proxy.pac").unwrap();
        let digest = format!(
            "len: {}, fnv1a: {:016x}",
            SCRIPT.len(),
            crate::util::fnv1a(SCRIPT.as_bytes())
        );
        for (rendered, expected) in [
            (
                format!("{:?}", PacRequirement::NotNeeded),
                "NotNeeded".to_owned(),
            ),
            (
                format!("{:?}", PacRequirement::Discover),
                "Discover".to_owned(),
            ),
            (
                format!("{:?}", PacRequirement::Inline(SCRIPT)),
                format!("Inline {{ {digest} }}"),
            ),
            (
                // No credentials, so the row pins the framing and not the masking, which
                // `debug_masking`'s registry owns for this arm.
                format!("{:?}", PacRequirement::Fetch(&url)),
                "Fetch(https://wpad.corp/proxy.pac)".to_owned(),
            ),
            (
                format!("{:?}", PacScript::new(SCRIPT)),
                format!("PacScript {{ {digest} }}"),
            ),
        ] {
            assert_eq!(rendered, expected);
        }
    }

    // Every example `net/docs/proxy.md` gives for `FindProxyForURL`'s first argument.
    #[test]
    fn the_documented_chromium_examples_come_out_the_same_way() {
        for (actual, expected) in [
            ("https://www.google.com/Foo", "https://www.google.com/"),
            ("https://[dead::beef]/foo?bar", "https://[dead::beef]/"),
            (
                "https://www.example.com:8080#search",
                "https://www.example.com:8080/",
            ),
            (
                "https://username:password@www.example.com",
                "https://www.example.com/",
            ),
        ] {
            let url = Url::parse(actual).expect("valid url");
            assert_eq!(sanitize_url(&url).as_str(), expected, "for {actual}");
        }
    }

    // The asymmetry is the part most likely to be "tidied up" by a later reader, so it
    // is pinned: plain HTTP keeps its path and query on purpose.
    #[test]
    fn only_cryptographic_schemes_lose_their_path_and_query() {
        let http = Url::parse("http://user:pw@example.net/deep/path?q=1#frag").unwrap();
        assert_eq!(
            sanitize_url(&http).as_str(),
            "http://example.net/deep/path?q=1"
        );

        let wss = Url::parse("wss://user:pw@example.net/socket?q=1#frag").unwrap();
        assert_eq!(sanitize_url(&wss).as_str(), "wss://example.net/");

        let ws = Url::parse("ws://user:pw@example.net/socket?q=1#frag").unwrap();
        assert_eq!(sanitize_url(&ws).as_str(), "ws://example.net/socket?q=1");
    }

    #[test]
    fn sanitizing_is_idempotent_and_leaves_the_host_alone() {
        for raw in [
            "https://user:pw@example.net:8443/a?b#c",
            "http://example.net/",
            "ftp://user@files.corp/pub",
        ] {
            let url = Url::parse(raw).unwrap();
            let once = sanitize_url(&url);
            assert_eq!(sanitize_url(&once), once, "not idempotent for {raw}");
            assert_eq!(once.host_str(), url.host_str(), "host changed for {raw}");
            assert_eq!(once.port(), url.port(), "port changed for {raw}");
        }
    }

    // A URL with no authority has no userinfo to strip; the setters refuse, and that
    // must not be mistaken for a failure to sanitize.
    #[test]
    fn cannot_be_a_base_urls_survive_untouched_except_for_the_fragment() {
        let url = Url::parse("mailto:someone@example.net?subject=hi#frag").unwrap();
        assert_eq!(
            sanitize_url(&url).as_str(),
            "mailto:someone@example.net?subject=hi"
        );
    }

    // ...and the refusal above is not the only one. `set_host(Some(""))` is accepted on a
    // non-special scheme and rejected on a special one, so this is the one shape that reaches
    // the same refusal with credentials still attached. `Url::parse` cannot build it; a caller
    // holding a `Url` can, and both engines hand `as_str()` straight to the script.
    #[test]
    fn an_emptied_host_does_not_carry_the_credentials_through() {
        for (input, expected) in [
            (
                "socks5://user:secret@example.net/p?q=1#frag",
                "socks5:///p?q=1",
            ),
            (
                "socks5://user:secret@example.net:8080/p",
                "socks5://:8080/p",
            ),
            ("socks5://:secret@example.net/p", "socks5:///p"),
            // Nothing to strip, and the shape `Url::password` cannot be asked about.
            ("socks5://example.net:8080/p", "socks5://:8080/p"),
        ] {
            let mut url = Url::parse(input).unwrap();
            url.set_host(Some(""))
                .expect("a non-special scheme accepts an empty host");
            let sanitized = sanitize_url(&url);
            assert_eq!(sanitized.as_str(), expected, "for {input}");
            assert_eq!(
                sanitize_url(&sanitized),
                sanitized,
                "not idempotent for {input}"
            );
        }
    }

    // The other half of the guard on the lend-a-host branch, and the half `mailto:` above
    // cannot show. That one is refused twice over — no authority *and* cannot-be-a-base, so
    // `set_host` refuses too and the round trip collapses on its own. A non-special scheme
    // with a rootless path is refused only once: `unix:/run/foo.socket` has no authority to
    // hold userinfo, but it *can* be a base, so every setter in the chain succeeds and the
    // URL comes back with an empty authority it never had.
    //
    // This test is the only thing holding `has_authority()` in the guard. Without it,
    // `unix:/run/foo.socket` comes back as `unix:///run/foo.socket`, and nothing else in the
    // tree objects. Both engines hand `as_str()` to the script, so that is a
    // different string in `FindProxyForURL`'s first argument.
    #[test]
    fn a_path_only_url_is_not_lent_an_authority_it_never_had() {
        for (input, expected) in [
            ("unix:/run/foo.socket", "unix:/run/foo.socket"),
            // The fragment still goes, so this is not "the function declined to run".
            ("git:/a/b?q=1#frag", "git:/a/b?q=1"),
        ] {
            let url = Url::parse(input).unwrap();
            assert!(!url.has_authority(), "premise for {input}: {url:?}");
            assert!(!url.cannot_be_a_base(), "premise for {input}: {url:?}");
            assert_eq!(sanitize_url(&url).as_str(), expected, "for {input}");
        }
    }

    #[cfg(feature = "pac-boa")]
    #[test]
    fn the_script_is_handed_the_sanitized_url_end_to_end() {
        let script = PacScript::new(
            "function FindProxyForURL(url, host) { return 'PROXY ' + url.replace(/[^a-zA-Z0-9.]/g, '-') + ':8080'; }",
        );
        let url = Url::parse("https://user:secret@example.net/private/doc?token=abc#x").unwrap();
        let steps = evaluate(&script, &url, &PacPolicy::new()).expect("evaluated");
        let seen = steps[0].endpoint().expect("a proxy step").authority();
        assert_eq!(
            seen, "https---example.net-:8080",
            "the script must not see the credentials, path, query or fragment"
        );
    }

    // `evaluate` is the engine door, not a routing entry point: unlike `resolve_with_pac`
    // and `WinHttpPacResolver::resolve_config` it does not answer Direct for a hostless
    // URL, it runs the script with the host empty. Adopting the routing convention here
    // would change what a caller who reached the engine directly gets back, and no other
    // test looks at a URL without a host.
    #[cfg(feature = "pac-boa")]
    #[test]
    fn a_hostless_url_reaches_the_script_with_an_empty_host() {
        let script = PacScript::new(
            "function FindProxyForURL(url, host) {
                 return host === '' ? 'PROXY empty.example:1' : 'PROXY host.example:2';
             }",
        );
        let url = Url::parse("mailto:someone@example.net").unwrap();

        let steps = evaluate(&script, &url, &PacPolicy::new()).expect("evaluated");
        assert_eq!(
            steps[0].endpoint().expect("a proxy step").authority(),
            "empty.example:1",
            "a hostless URL must reach the engine, with the host empty"
        );
    }

    // The escape hatch `evaluate`'s comment points at. `evaluate` passes `host_str`, so a
    // script sees Gecko's bracketed IPv6 spelling; `evaluate_with_host` exists so a caller
    // who wants Chromium's `HostNoBrackets()` can have it. Nothing inside this crate ever
    // passes a host other than the URL's own, so without this the override could stop
    // reaching the engine and no other test would notice.
    #[cfg(feature = "pac-boa")]
    #[test]
    fn the_host_override_is_what_the_script_sees() {
        let script = PacScript::new(
            "function FindProxyForURL(url, host) {
                 if (host === '[dead::beef]') { return 'PROXY bracketed.example:1'; }
                 if (host === 'dead::beef') { return 'PROXY unbracketed.example:2'; }
                 return 'PROXY neither.example:3';
             }",
        );
        let url = Url::parse("https://[dead::beef]/foo").unwrap();

        let steps = evaluate(&script, &url, &PacPolicy::new()).expect("evaluated");
        assert_eq!(
            steps[0].endpoint().expect("a proxy step").authority(),
            "bracketed.example:1",
            "`evaluate` must pass the spelling the URL itself carries"
        );

        let steps =
            evaluate_with_host(&script, &url, "dead::beef", &PacPolicy::new()).expect("evaluated");
        assert_eq!(
            steps[0].endpoint().expect("a proxy step").authority(),
            "unbracketed.example:2",
            "the chosen host must reach the script instead of the URL's own"
        );
    }

    #[test]
    fn scripts_come_from_inline_modes_only() {
        let inline = ProxyMode::pac_inline("body".to_owned());
        assert_eq!(PacScript::from_mode(&inline), Some(PacScript::new("body")));
        assert_eq!(PacScript::from_mode(&ProxyMode::Direct), None);
        // `Manual` for the same reason it appears in `requirements_cover_every_mode`: it is
        // the fifth variant, and `Direct` alone leaves the `_` arm free to grow a case for it.
        assert_eq!(
            PacScript::from_mode(&ProxyMode::manual(HashMap::new(), BypassRules::new())),
            None
        );

        let url = Url::parse("http://wpad.corp/proxy.pac").unwrap();
        assert_eq!(PacScript::from_mode(&ProxyMode::pac(url)), None);
    }

    #[test]
    fn requirements_cover_every_mode() {
        let url = Url::parse("http://wpad.corp/proxy.pac").unwrap();
        assert_eq!(
            requirement(&ProxyMode::pac(url.clone())),
            PacRequirement::Fetch(&url)
        );
        assert_eq!(
            requirement(&ProxyMode::pac_inline("b".to_owned())),
            PacRequirement::Inline("b")
        );
        assert_eq!(
            requirement(&ProxyMode::WpadAutoDetect),
            PacRequirement::Discover
        );
        assert_eq!(requirement(&ProxyMode::Direct), PacRequirement::NotNeeded);
        // The name says *every* mode, and `Direct` alone does not make that true: `Manual`
        // is the other variant the `_` arm answers for, and it is the one with something to
        // lose. A case growing in front of that arm sends a machine with static proxies off
        // to do WPAD discovery, and with only `Direct` here nothing goes red.
        assert_eq!(
            requirement(&ProxyMode::manual(HashMap::new(), BypassRules::new())),
            PacRequirement::NotNeeded
        );
    }

    #[test]
    #[cfg(not(feature = "pac-boa"))]
    fn without_an_engine_evaluation_reports_why() {
        let script = PacScript::new("function FindProxyForURL(u, h) { return 'DIRECT'; }");
        let url = Url::parse("http://example.com/").unwrap();
        let error = evaluate(&script, &url, &PacPolicy::new()).unwrap_err();
        assert!(matches!(error, Error::PacEngineUnavailable), "{error:?}");
    }
}
