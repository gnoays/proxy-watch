//! Proxy endpoints: which host/port to talk to, for which request scheme.

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use url::{Host, Url};

use crate::auth::ProxyAuth;
use crate::error::Error;
use crate::util::{percent_decode, quote_if_not_credential_shaped, split_host_port};

/// Request scheme a proxy setting applies to ([`ProxyMode::Manual`](crate::ProxyMode::Manual)
/// `per_scheme` key). Not [`ProxyScheme`] (how to talk to the proxy).
///
/// Concrete schemes always beat [`Scheme::All`]. On Windows/`socks=`, GNOME (only SOCKS
/// configured → All), and macOS (`SOCKSEnable` fallback), readers may already have copied
/// SOCKS into other slots before a `ProxyMode` exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Scheme {
    /// `http://` requests.
    Http,
    /// `https://` requests.
    Https,
    /// `ftp://` requests.
    Ftp,
    /// SOCKS / catch-all on some platforms.
    Socks,
    /// Bare `ProxyServer` / `all_proxy` catch-all.
    All,
}

impl Scheme {
    /// All schemes this crate models, in a stable order.
    pub const ALL: [Scheme; 5] = [
        Scheme::Http,
        Scheme::Https,
        Scheme::Ftp,
        Scheme::Socks,
        Scheme::All,
    ];

    /// The canonical lowercase name, as used by Windows `ProxyServer` keys.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Ftp => "ftp",
            Scheme::Socks => "socks",
            Scheme::All => "all",
        }
    }

    /// Parse a scheme key such as `http` in `http=proxy:8080`.
    ///
    /// `None` for unmodelled keys (`gopher`, …). `all` is accepted (see
    /// [`parse::proxy_server`](crate::parse::proxy_server)).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Scheme> {
        match name.trim().to_ascii_lowercase().as_str() {
            "http" => Some(Scheme::Http),
            "https" => Some(Scheme::Https),
            "ftp" => Some(Scheme::Ftp),
            "socks" => Some(Scheme::Socks),
            "all" => Some(Scheme::All),
            _ => None,
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The wire protocol used to reach the proxy itself.
///
/// Only ever a *hint*: most operating system sources (the Windows registry in
/// particular) store a bare `host:port` and leave the protocol implicit.
///
/// Where a source names SOCKS without a version — GNOME's `socks` child, KDE's `socksProxy`
/// and macOS's `SOCKSProxy` — this crate reports [`ProxyScheme::Socks5`]. That is a
/// compatibility choice and not something read out of the setting: Chromium makes the same
/// one and calls it a "policy decision" where it makes it, in
/// `proxy_config_service_linux.cc`. GIO chose otherwise, treating such a setting as standing
/// for SOCKS5, SOCKS4a and SOCKS4 alike, so a proxy that speaks only SOCKS4 is reachable from
/// a GIO application and not from a caller that takes this hint literally.
///
/// A version written into the value is kept: `socks4://proxy.example.com` in GNOME's `host`
/// child or KDE's `socksProxy` reads as [`Socks4`](ProxyScheme::Socks4), because both readers
/// here apply their default only where the value named nothing. Chromium reads it the same way
/// — "we default to socks 5, but if the user specifically set it to `socks4://`, then use
/// that", in `FixupProxyHostScheme`. The native stacks do not: glib-networking formats
/// `socks://%s:%u` out of the host key verbatim, and KF5-era KIO re-glues a bare `socks://`
/// over whatever scheme it finds. So the spelling is an escape hatch out of *this crate's*
/// default, not out of the setting — the platform's own resolver still sees SOCKS5, or nonsense.
///
/// The same word can mean different versions in different sources: a `socks://` URI is SOCKS5,
/// while the Windows registry's `socks=host:port` is read as SOCKS4. Microsoft gives that token
/// no version of its own, but WinINet owns the key, and the feature table in
/// [WinINet vs. WinHTTP](https://learn.microsoft.com/en-us/windows/win32/wininet/wininet-vs-winhttp)
/// grants it SOCKS4 alone: "**SOCKS4 (SOCKS version 4) support**. Doesn't include v4a" is `yes`
/// for WinINet, and "**SOCKS5 (SOCKS version 5) support**" is `no`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ProxyScheme {
    /// Plain HTTP proxy (`CONNECT` for TLS). Default port 80.
    Http,
    /// TLS-wrapped HTTP proxy. Default port 443.
    Https,
    /// SOCKS4, names resolved locally. Default port 1080.
    Socks4,
    /// SOCKS4a, names resolved by the proxy. Default port 1080.
    Socks4a,
    /// SOCKS5, names resolved locally. Default port 1080.
    Socks5,
    /// SOCKS5, names resolved by the proxy. Default port 1080.
    Socks5h,
}

impl ProxyScheme {
    /// The canonical lowercase URL scheme.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyScheme::Http => "http",
            ProxyScheme::Https => "https",
            ProxyScheme::Socks4 => "socks4",
            ProxyScheme::Socks4a => "socks4a",
            ProxyScheme::Socks5 => "socks5",
            ProxyScheme::Socks5h => "socks5h",
        }
    }

    /// The port assumed when the source omitted one.
    #[must_use]
    pub fn default_port(self) -> u16 {
        match self {
            ProxyScheme::Http => 80,
            ProxyScheme::Https => 443,
            ProxyScheme::Socks4
            | ProxyScheme::Socks4a
            | ProxyScheme::Socks5
            | ProxyScheme::Socks5h => 1080,
        }
    }
}

impl fmt::Display for ProxyScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProxyScheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "http" => Ok(ProxyScheme::Http),
            "https" => Ok(ProxyScheme::Https),
            "socks4" => Ok(ProxyScheme::Socks4),
            // A `socks://` URI scheme is SOCKS5, and only here. The same word means
            // SOCKS4 as the Windows `socks=` bucket key and as the PAC `SOCKS` keyword, which
            // is why those two set their hint themselves instead of asking this function --
            // the reference draws the same line, and says so out loud.
            "socks" | "socks5" => Ok(ProxyScheme::Socks5),
            "socks4a" => Ok(ProxyScheme::Socks4a),
            "socks5h" => Ok(ProxyScheme::Socks5h),
            // Redact: `ProxyEndpoint::parse` can hand `alice:pass@http` here — or
            // `bob:pw`, from `bob:pw://host`, where no `@` marks the userinfo.
            other => Err(Error::UnsupportedProxyScheme(
                crate::util::redact_offending_token(other),
            )),
        }
    }
}

/// Concrete proxy address. IPv6 brackets resolved at parse; use [`authority`](Self::authority).
/// `#[non_exhaustive]` — construct via [`new`](Self::new) / [`parse`](Self::parse).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ProxyEndpoint {
    /// Wire protocol hint when the source named one.
    pub scheme_hint: Option<ProxyScheme>,
    /// Proxy host.
    pub host: Host,
    /// Proxy port.
    pub port: u16,
    /// Embedded credentials, if any.
    pub auth: Option<ProxyAuth>,
}

impl ProxyEndpoint {
    /// Build an endpoint from an already-parsed host and port.
    #[must_use]
    pub fn new(host: Host, port: u16) -> Self {
        Self {
            scheme_hint: None,
            host,
            port,
            auth: None,
        }
    }

    /// Set the scheme hint (builder style).
    #[must_use]
    pub fn with_scheme_hint(mut self, scheme: ProxyScheme) -> Self {
        self.scheme_hint = Some(scheme);
        self
    }

    /// Set the credentials (builder style).
    #[must_use]
    pub fn with_auth(mut self, auth: ProxyAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Parse a proxy address in any of the shapes operating systems store.
    ///
    /// `host`, `host:port`, `[::1]:8080`, `user:pass@host[:port]`, or any of those behind
    /// a `scheme://`. Credentials do not need the scheme: the userinfo split happens after
    /// the optional prefix, so a bare `user:pass@host` carries a secret just as a
    /// `scheme://` one does. The *last* `@` is the delimiter, as in WHATWG's authority
    /// state, so `user@corp.example:pw@proxy:8080` keeps an email address as the user name.
    /// Port: explicit, else scheme default, else `default_port`.
    /// A path, query or fragment is accepted and dropped, so `http://proxy:8080/` and
    /// `http://proxy:8080` are the same endpoint; nothing after the authority survives.
    ///
    /// ```
    /// # use proxy_watch::{ProxyEndpoint, ProxyScheme};
    /// let ep = ProxyEndpoint::parse("socks5://[::1]", 80).unwrap();
    /// assert_eq!(ep.scheme_hint, Some(ProxyScheme::Socks5));
    /// assert_eq!(ep.port, 1080);
    /// assert_eq!(ep.authority(), "[::1]:1080");
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidProxyServer`] if the input is not a usable address, or
    /// [`Error::UnsupportedProxyScheme`] for a `scheme://` prefix this crate does not
    /// model. Never [`Error::InvalidProxyUrl`]: that one belongs to the callers that
    /// parse an `AutoConfigURL`-style value, not to an address.
    ///
    /// U+FFFD anywhere in the authority — credentials included — is one of the
    /// unusable addresses. It is what a lossy byte-to-text conversion leaves behind, and
    /// this crate's platform readers convert that way so that a value they could not decode
    /// is refused here instead of reading as unset. A path or query is dropped before the
    /// check, so the character is only refused where the answer is built from it.
    pub fn parse(input: &str, default_port: u16) -> Result<Self, Error> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(Error::proxy_server(input, "empty address"));
        }

        let (scheme_hint, rest) = match trimmed.split_once("://") {
            Some((scheme, rest)) => (Some(scheme.parse::<ProxyScheme>()?), rest),
            None => (None, trimmed),
        };
        // Cut the path, query and fragment — and do it *before* the userinfo split below,
        // not after. `@` is an ordinary path character, so `http://bob:pw/x@proxy.corp:8080`
        // would otherwise `rsplit_once` into userinfo `bob:pw/x` and a host taken from the
        // path: a destination the writer never named, reached because a `/` came first.
        // `trace::tests::safe_error_does_not_leak_credentials_from_real_parsers` is what
        // fails if these two lines change places.
        let rest = rest.split(['/', '?', '#']).next().unwrap_or(rest);

        // Four readers convert their bytes the *lossy* way on purpose — `env::readable_var`,
        // `sys::linux::desktop::text_if_set`, `kioslaverc`'s `ProxyType = 4` lookup and
        // `sys::win::ffi::string_value` — and every one of them says the same thing about why:
        // `into_string().ok()` cannot tell "unset" from "set to bytes that are not text", so
        // the value is kept, mangled, and refused *here* instead of vanishing. Only the host
        // half ever made that true. `parse_host` does refuse U+FFFD, but `parse_userinfo`
        // cannot fail, so a `0xFF` in a password parsed clean: the crate then offered the proxy
        // a secret nobody set, an authentication failure with no `rejected` entry anywhere to
        // name the value that changed, and one `ProxyAuth`'s `Debug` masks out of the snapshot
        // that might have shown it. `util::percent_decode` refuses to manufacture the same
        // character for the same reason, and this is the other end of that rule.
        //
        // On the authority, not on `input`: a path, query or fragment is dropped whole, so
        // mangling there costs nothing the answer is built from.
        if rest.contains(char::REPLACEMENT_CHARACTER) {
            return Err(Error::proxy_server(input, "value is not valid text"));
        }

        let (auth, host_port) = match rest.rsplit_once('@') {
            Some((userinfo, host_port)) => (Some(parse_userinfo(userinfo)), host_port),
            None => (None, rest),
        };

        if host_port.is_empty() {
            return Err(Error::proxy_server(input, "missing host"));
        }
        let (host_text, port) =
            split_host_port(host_port).map_err(|reason| Error::proxy_server(input, reason))?;
        let host = parse_host(host_text).map_err(|reason| Error::proxy_server(input, reason))?;

        // `host:` is a *written* port that is empty, which is not the same thing as a source
        // that omitted the port: the writer meant to name one and did not. Chromium draws the
        // same line: `ProxyUriToProxyServer` in `net/base/proxy_string_util.cc` splits the
        // authority and answers with an invalid `ProxyServer()` when the port component
        // `is_valid() && is_empty()`, while `url::ParsePort` -- the canonicaliser the same
        // build uses for ordinary URLs -- reads that empty component as `PORT_UNSPECIFIED`,
        // i.e. as no port at all. Only the proxy side refuses it.
        // Length, not `ends_with(':')`, is what separates the two: `h:` and `[::1]:` leave a
        // host shorter than what was split, while a bare host and an unbracketed `2001:db8::`
        // -- which `split_host_port` hands back whole, colons and all -- do not.
        if port.is_none() && host_port.len() > host_text.len() {
            return Err(Error::proxy_server(input, "empty port after ':'"));
        }

        let port = port
            .or_else(|| scheme_hint.map(ProxyScheme::default_port))
            .unwrap_or(default_port);

        Ok(Self {
            scheme_hint,
            host,
            port,
            auth,
        })
    }

    /// The `host:port` form, with IPv6 hosts re-bracketed.
    #[must_use]
    pub fn authority(&self) -> String {
        match &self.host {
            Host::Ipv6(ip) => format!("[{ip}]:{}", self.port),
            other => format!("{other}:{}", self.port),
        }
    }
}

impl fmt::Display for ProxyEndpoint {
    // Renders `host:port`, and prefixes `scheme://` only when a hint was parsed out. The
    // prefix is the exception, not the shape: most sources store a bare authority, which
    // is why [`ProxyScheme`] is a hint in the first place. Never the credentials — see
    // [`ProxyAuth`]'s own documentation for why.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(scheme) = self.scheme_hint {
            write!(f, "{scheme}://")?;
        }
        f.write_str(&self.authority())
    }
}

/// Whether a given [`Scheme`] uses a proxy at all.
///
/// Three answers, not two. `Disabled` exists so that "this scheme explicitly does *not*
/// use a proxy" can be distinguished from "this scheme was not configured" — the former
/// suppresses the [`Scheme::All`] fallback, the latter does not. [`Unusable`](Self::Unusable)
/// is the third: the scheme *was* configured, and what it was configured with could not be
/// read. Absence therefore means only "the platform said nothing about this scheme".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyEntry {
    /// Route this scheme through the given proxy.
    Use(ProxyEndpoint),
    /// The platform named this scheme and gave it no proxy — an off switch, or a slot
    /// left blank.
    Disabled,
    /// The platform named this scheme and gave it a proxy that could not be read.
    ///
    /// This is the record of the drop, not an answer: routing the request would need an
    /// endpoint there is none of, and answering [`Disabled`](Self::Disabled) would claim the
    /// platform wanted a direct connection when it wanted a proxy nobody can now name. Under
    /// the `resolve` feature it becomes
    /// [`Error::ProxyEntryUnusable`](crate::Error::ProxyEntryUnusable).
    ///
    /// Every lookup treats it as the last resort — see
    /// [`ProxyMode::entry_for`](crate::ProxyMode::entry_for). A live [`Scheme::All`] is an
    /// answer the platform did configure, so it still wins; only when nothing else covers
    /// the scheme does the record answer.
    Unusable(crate::diagnostic::RejectedValue),
}

impl ProxyEntry {
    /// The endpoint, or `None` for [`Disabled`](Self::Disabled) and
    /// [`Unusable`](Self::Unusable) alike — neither has one, which is why a caller that
    /// needs to tell "go direct" from "the setting was lost" asks
    /// [`rejected`](Self::rejected) rather than this.
    #[must_use]
    pub fn endpoint(&self) -> Option<&ProxyEndpoint> {
        match self {
            ProxyEntry::Use(endpoint) => Some(endpoint),
            ProxyEntry::Disabled | ProxyEntry::Unusable(_) => None,
        }
    }

    /// Whether the entry is [`ProxyEntry::Disabled`]. `false` for
    /// [`Unusable`](Self::Unusable): a lost setting is not an off switch.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        matches!(self, ProxyEntry::Disabled)
    }

    /// The drop record, for [`ProxyEntry::Unusable`] only.
    #[must_use]
    pub fn rejected(&self) -> Option<&crate::diagnostic::RejectedValue> {
        match self {
            ProxyEntry::Unusable(rejected) => Some(rejected),
            ProxyEntry::Use(_) | ProxyEntry::Disabled => None,
        }
    }
}

// Parse a URL host, accepting bracketed and bare IPv6 literals.
//
// Both failure messages go into an [`Error`] `reason`, which `crate::trace::SafeError`
// prints in full, so neither echoes `text` unconditionally — see
// [`quote_if_not_credential_shaped`] for what arrives here that is not a host at all.
pub(crate) fn parse_host(text: &str) -> Result<Host, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("missing host".to_owned());
    }
    if let Some(inner) = text.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return inner.parse::<Ipv6Addr>().map(Host::Ipv6).map_err(|_| {
            format!(
                "invalid IPv6 literal {}",
                quote_if_not_credential_shaped(inner)
            )
        });
    }
    if let Ok(ip) = text.parse::<Ipv6Addr>() {
        return Ok(Host::Ipv6(ip));
    }
    Host::parse(text)
        .map_err(|e| format!("invalid host {}: {e}", quote_if_not_credential_shaped(text)))
}

// The host a request URL names, or `None` if it names none. Every "does this URL have a
// host?" question in the crate comes through here rather than to [`Url::host`], which answers
// `Some(Host::Domain(""))` for a URL whose host was emptied — `set_host(None)` on a
// non-special scheme produces exactly that (url 2.5.8; special schemes refuse it with
// `EmptyHost`). Such a URL has nothing to connect to, so it is hostless here.
//
// Lives here rather than beside its first caller in `resolve` because `BypassRules` asks it
// too, and `resolve` is behind a feature while `BypassRules` is not.
fn request_host_ref(url: &Url) -> Option<Host<&str>> {
    match url.host()? {
        Host::Domain("") => None,
        other => Some(other),
    }
}

// Whether the URL names a host at all. Borrows, so a caller that asks only this does not pay
// for the `String` the owned form builds and it would drop. Every caller is under `resolve`,
// which `pac` and the engine flags all pull in.
#[cfg(feature = "resolve")]
pub(crate) fn has_request_host(url: &Url) -> bool {
    request_host_ref(url).is_some()
}

pub(crate) fn request_host(url: &Url) -> Option<Host> {
    match request_host_ref(url)? {
        Host::Domain(domain) => Some(Host::Domain(domain.to_owned())),
        Host::Ipv4(ip) => Some(Host::Ipv4(ip)),
        Host::Ipv6(ip) => Some(Host::Ipv6(ip)),
    }
}

fn parse_userinfo(userinfo: &str) -> ProxyAuth {
    // A literal `:` and nothing else. Percent-encoding a reserved character is how RFC 3986
    // section 2.2 spells "this is data, not the delimiter", so `alice%3Ahunter2` is one user
    // name that happens to contain a colon — `url` (this crate's own dependency) and Python's
    // `urllib` both read it that way. Splitting it here handed the caller a user name that was
    // never one and a password that never existed. The colon then surviving into `username` is
    // masked by [`ProxyAuth`]'s `Debug`, which is what keeps it out of a snapshot.
    match userinfo.split_once(':') {
        Some((user, password)) => {
            ProxyAuth::new(percent_decode(user), Some(percent_decode(password)))
        }
        None => ProxyAuth::from_username(percent_decode(userinfo)),
    }
}
