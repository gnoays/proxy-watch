//! Crate-wide error type.

use thiserror::Error;

use crate::util::{redact_offending_token, redact_userinfo};
use crate::{RejectedValue, Scheme};

/// Errors from reading OS proxy configuration, and from routing a URL through what was read.
///
/// `#[non_exhaustive]`. No `#[from] io::Error` — I/O is always wrapped with context.
/// Hand-written [`Debug`]: [`PacFetchRequired`](Error::PacFetchRequired)'s [`url::Url`]
/// would print credentials; other payloads are masked at construction or safe.
#[derive(Error)]
#[non_exhaustive]
pub enum Error {
    /// A Windows `ProxyServer` style specification could not be parsed.
    #[error("invalid proxy server specification {input:?}: {reason}")]
    InvalidProxyServer {
        /// Offending token, masked — and withheld outright when it may be a credential.
        input: String,
        /// Why parsing failed.
        reason: String,
    },

    /// A single bypass / `no_proxy` / `ProxyOverride` entry could not be parsed.
    #[error("invalid bypass pattern {input:?}: {reason}")]
    InvalidBypassPattern {
        /// Offending entry, masked like [`InvalidProxyServer`](Error::InvalidProxyServer)'s.
        input: String,
        /// Why parsing failed.
        reason: String,
    },

    /// An `AutoConfigURL`-style setting read from the OS is malformed.
    ///
    /// Not the environment: `*_proxy` values go through
    /// [`ProxyEndpoint::parse`](crate::ProxyEndpoint::parse), which answers with
    /// [`InvalidProxyServer`](Error::InvalidProxyServer) instead.
    #[error("invalid proxy URL {input:?}: {source}")]
    InvalidProxyUrl {
        /// Offending input, masked like [`InvalidProxyServer`](Error::InvalidProxyServer)'s.
        input: String,
        /// Underlying parse error.
        #[source]
        source: url::ParseError,
    },

    /// The proxy URL carried a scheme this crate does not understand.
    ///
    /// Recognised schemes are listed on [`ProxyScheme`](crate::ProxyScheme).
    #[error("unsupported proxy scheme {0:?}")]
    UnsupportedProxyScheme(String),

    /// `http_proxy` under CGI: a non-empty `REQUEST_METHOD` ⇒ forged `Proxy:` header
    /// (httpoxy, CVE-2016-5385). Refused like Go's httpproxy; not applied to
    /// `https_proxy`/`no_proxy`, whose names no request header can produce.
    ///
    /// KDE's `ProxyType = 4` raises the same error on a wider rule, because there the
    /// *file* names the variable each slot reads: any name a request header could have set
    /// — RFC 3875 §4.1.18's `HTTP_` prefix — is refused whichever slot named it, including
    /// the one holding the bypass list. `variable` is that name as written.
    #[error("refusing to use {variable} value in CGI environment")]
    CgiHttpProxy {
        /// Variable name as set in the environment.
        variable: String,
    },

    /// An I/O failure, annotated with the operation that caused it.
    ///
    /// OS error codes are carried as [`std::io::Error`], built by `from_raw_os_error`.
    #[error("{context}")]
    Io {
        /// Operation in progress when the failure occurred.
        context: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Linux sandbox: desktop settings unreadable (Flatpak without dconf → keyfile
    /// defaults). Portal fallback when possible; else this error — not a false Direct.
    #[error("running inside a {sandbox} sandbox: {reason}")]
    Sandboxed {
        /// Detected sandbox name.
        sandbox: String,
        /// Why no source could be read.
        reason: String,
    },

    /// No store to read. Off Windows/macOS/Linux there is no backend at all; on Linux it is
    /// a reading and not a property of the build — *neither* desktop store answered, which
    /// both desktop features being off guarantees and which a build with one of them on also
    /// reaches whenever the schema and `kioslaverc` are both missing from the machine.
    ///
    /// Not the answer inside a sandbox: that route is chosen before either store is
    /// consulted and reports [`Sandboxed`](Self::Sandboxed), including when the feature that
    /// would carry the portal fallback is off.
    #[error("watching the system proxy configuration is not supported on this platform")]
    Unsupported,

    /// `resolve()` needs PAC/WPAD evaluation (`resolve_with_pac` / `pac` feature).
    /// Deliberately an error, not silent Direct.
    ///
    /// `resolve_with_pac` answers with it too, for
    /// [`WpadAutoDetect`](crate::ProxyMode::WpadAutoDetect) handed no script body:
    /// discovery is a non-goal, so the fix there is to supply the script rather than to
    /// change entry point. `mode` is `"wpad"` either way and does not tell the two apart.
    #[error("resolving this URL requires evaluating a proxy auto-config script ({mode})")]
    PacNotSupported {
        /// Auto-config mode in effect.
        mode: &'static str,
    },

    /// The system configured a proxy for this scheme, the value could not be used, and no
    /// other entry covers it.
    ///
    /// Returning `ProxyStep::Direct` here would assert something
    /// the platform does not do: KDE expands a `[$e]` value from the session environment and
    /// proxies the request, and this crate deliberately does not expand it. Only a scheme
    /// with no catch-all reaches this — a live `socksProxy` covers the drop first, exactly as
    /// Chromium's `fallback_proxies` does. Where this reports, Chromium goes direct instead:
    /// its `ProxyList::AddProxyChain` drops a malformed entry with "Silently discard
    /// malformed inputs", leaving `MapUrlSchemeToProxyList` to answer `nullptr`.
    // `{scheme}` names the slot, so the second half says "this request" rather than repeating
    // it: for a `ws`/`wss` URL the slot is `Https` or `Socks`, and "nothing else covers https"
    // would describe a request nobody made.
    #[error("the configured {scheme} proxy could not be used and nothing else covers this request")]
    ProxyEntryUnusable {
        /// Which requests lost an answer — read off the drop's own attribution, not off the
        /// slot it was found under. In every mode this crate builds the two are the same
        /// value, because each backend files its record against the slot it dropped, so this
        /// is the slot, and the slot is what decides coverage rather than the request's own
        /// scheme: a lost catch-all reports [`Scheme::All`] whatever was asked for, and a
        /// `ws`/`wss` request reports whichever of the chain it lost. A caller who hands
        /// [`ProxyMode::manual`](crate::ProxyMode::manual) a record attributed to one scheme
        /// under the key of another gets the attribution back rather than the key. Nothing
        /// normalises the pair: the record is the caller's, and the same value is what
        /// [`ProxyMode::rejected`](crate::ProxyMode::rejected) hands back.
        scheme: Scheme,
        /// First drop naming that scheme; masked at construction. The rest stay reachable
        /// through [`ProxyMode::rejected`](crate::ProxyMode::rejected) *on the mode this
        /// error was resolved against*, which is the caller's own `config.effective`
        /// wherever the caller supplied it. Where a resolver builds a mode of its own it is
        /// not: `WinHttpPacResolver::resolve_config` answers a WPAD miss by re-reading the
        /// registry into a `Manual` and resolving against that, and the mode goes out of
        /// scope with the call while the caller still holds `WpadAutoDetect`, which has no
        /// list. This field is what survives that.
        rejected: RejectedValue,
    },

    /// `resolve_with_pac` + [`ProxyMode::Pac`](crate::ProxyMode::Pac) without script body.
    /// Fetch is caller's job; `url` stored verbatim, masked only in `{}`/`{:?}`.
    #[error(
        "the PAC script at {} must be fetched by the caller before it can be evaluated",
        redact_userinfo(.url.as_str())
    )]
    PacFetchRequired {
        /// Script URL.
        url: url::Url,
    },

    /// PAC run failed (syntax, throw, limits). `reason` masked/sanitized at construction.
    #[error("PAC evaluation failed: {reason}")]
    PacEvaluation {
        /// Engine message (sanitized).
        reason: String,
    },

    /// Evaluating a PAC script overran `PacPolicy::timeout`.
    #[error("PAC evaluation exceeded its {timeout:?} budget")]
    PacTimeout {
        /// Budget that was exceeded.
        timeout: std::time::Duration,
    },

    /// `FindProxyForURL` returned nothing usable (malformed candidates skipped first).
    /// `result` masked at construction.
    #[error("PAC script returned no usable proxy candidate: {result:?}")]
    PacInvalidResult {
        /// Raw return string (masked).
        result: String,
    },

    /// `pac` on but no engine (`pac-boa` or a custom `pac::PacEvaluator`).
    ///
    /// Not linked: the item exists only with the `pac` feature on, and this variant does not.
    #[error("no PAC JavaScript engine is enabled; build with the `pac-boa` feature")]
    PacEngineUnavailable,
}

impl Error {
    // Mask `user:password` in `input` once so Display/Debug stay safe downstream — with
    // or without the `@` that would make it recognisable, since `input` is by definition
    // a token that failed to parse.
    pub(crate) fn proxy_server(input: impl AsRef<str>, reason: impl Into<String>) -> Self {
        Error::InvalidProxyServer {
            input: redact_offending_token(input.as_ref()),
            reason: reason.into(),
        }
    }

    // Same masking as [`Self::proxy_server`] (malformed bypasses can still look like userinfo).
    pub(crate) fn bypass(input: impl AsRef<str>, reason: impl Into<String>) -> Self {
        Error::InvalidBypassPattern {
            input: redact_offending_token(input.as_ref()),
            reason: reason.into(),
        }
    }

    // Mask raw text that failed `Url::parse` (cannot re-parse to strip userinfo).
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "macos", windows)),
        allow(dead_code)
    )]
    pub(crate) fn invalid_proxy_url(input: impl AsRef<str>, source: url::ParseError) -> Self {
        Error::InvalidProxyUrl {
            input: redact_offending_token(input.as_ref()),
            source,
        }
    }

    // No `allow(dead_code)` for a target with no backend, unlike its neighbour above:
    // `watch::ThreadGuard`'s `Drop` builds this error when a backend thread panics, and a
    // `Drop` impl is live everywhere.
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }

    // Mask + sanitize, in that order — see
    // [`crate::util::redact_and_sanitize_untrusted`] (PAC return is attacker-chosen).
    #[cfg_attr(not(feature = "pac"), allow(dead_code))]
    pub(crate) fn pac_invalid_result(result: impl AsRef<str>) -> Self {
        Error::PacInvalidResult {
            result: crate::util::redact_and_sanitize_untrusted(result.as_ref()),
        }
    }

    // Mask + sanitize engine/`throw` text. `pac/boa.rs` hands over what the engine said;
    // `pac/winhttp.rs` hands over a sentence it wrote itself and still comes through here,
    // so the variant is never built any other way.
    #[cfg_attr(
        not(any(feature = "pac-boa", all(windows, feature = "pac-windows-native"))),
        allow(dead_code)
    )]
    pub(crate) fn pac_evaluation(reason: impl AsRef<str>) -> Self {
        Error::PacEvaluation {
            reason: crate::util::redact_and_sanitize_untrusted(reason.as_ref()),
        }
    }
}

impl std::fmt::Debug for Error {
    // See enum docs: only [`Error::PacFetchRequired`]'s URL needs special casing.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidProxyServer { input, reason } => f
                .debug_struct("InvalidProxyServer")
                .field("input", input)
                .field("reason", reason)
                .finish(),
            Error::InvalidBypassPattern { input, reason } => f
                .debug_struct("InvalidBypassPattern")
                .field("input", input)
                .field("reason", reason)
                .finish(),
            Error::InvalidProxyUrl { input, source } => f
                .debug_struct("InvalidProxyUrl")
                .field("input", input)
                .field("source", source)
                .finish(),
            Error::UnsupportedProxyScheme(scheme) => f
                .debug_tuple("UnsupportedProxyScheme")
                .field(scheme)
                .finish(),
            Error::CgiHttpProxy { variable } => f
                .debug_struct("CgiHttpProxy")
                .field("variable", variable)
                .finish(),
            Error::Io { context, source } => f
                .debug_struct("Io")
                .field("context", context)
                .field("source", source)
                .finish(),
            Error::Sandboxed { sandbox, reason } => f
                .debug_struct("Sandboxed")
                .field("sandbox", sandbox)
                .field("reason", reason)
                .finish(),
            Error::Unsupported => write!(f, "Unsupported"),
            Error::PacNotSupported { mode } => f
                .debug_struct("PacNotSupported")
                .field("mode", mode)
                .finish(),
            Error::ProxyEntryUnusable { scheme, rejected } => f
                .debug_struct("ProxyEntryUnusable")
                .field("scheme", scheme)
                .field("rejected", rejected)
                .finish(),
            Error::PacFetchRequired { url } => f
                .debug_struct("PacFetchRequired")
                .field("url", &format_args!("{}", redact_userinfo(url.as_str())))
                .finish(),
            Error::PacEvaluation { reason } => f
                .debug_struct("PacEvaluation")
                .field("reason", reason)
                .finish(),
            Error::PacTimeout { timeout } => f
                .debug_struct("PacTimeout")
                .field("timeout", timeout)
                .finish(),
            Error::PacInvalidResult { result } => f
                .debug_struct("PacInvalidResult")
                .field("result", result)
                .finish(),
            Error::PacEngineUnavailable => write!(f, "PacEngineUnavailable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "hunter2";

    #[test]
    fn proxy_server_masks_the_password_in_display_and_debug() {
        let input = format!("http://alice:{SECRET}@proxy.corp:99999");
        let error = Error::proxy_server(&input, "port out of range");

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(SECRET), "{display}");
        assert!(!debug.contains(SECRET), "{debug}");
        // Not vacuous: the rest of the input is still there.
        assert!(display.contains("proxy.corp"), "{display}");
        assert!(debug.contains("proxy.corp"), "{debug}");
    }

    #[test]
    fn invalid_proxy_url_masks_the_password_in_display_and_debug() {
        let input = format!("http://alice:{SECRET}@proxy.corp:99999");
        let error = Error::invalid_proxy_url(&input, url::ParseError::EmptyHost);

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(SECRET), "{display}");
        assert!(!debug.contains(SECRET), "{debug}");
        assert!(display.contains("proxy.corp"), "{display}");
        assert!(debug.contains("proxy.corp"), "{debug}");
    }

    // The payload looks like a bare scheme name, but
    // [`ProxyEndpoint::parse`](crate::ProxyEndpoint::parse) splits on the first `"://"`
    // *before* it looks for userinfo, so credentials written ahead of the scheme end up
    // inside it.
    #[test]
    fn an_unsupported_scheme_masks_credentials_written_ahead_of_it() {
        let input = format!("alice:{SECRET}@http://proxy.corp:8080");
        let error = crate::ProxyEndpoint::parse(&input, 80).unwrap_err();

        assert!(
            matches!(error, Error::UnsupportedProxyScheme(_)),
            "fixture precondition: expected an unsupported-scheme error, got {error:?}"
        );
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(SECRET), "{display}");
        assert!(!debug.contains(SECRET), "{debug}");
        // `SafeError` only exists with the `tracing` feature, so this rendering is checked
        // conditionally: an unconditional reference stops `cargo test
        // --no-default-features` from compiling at all.
        #[cfg(feature = "tracing")]
        {
            let traced = crate::trace::SafeError(&error).to_string();
            assert!(!traced.contains(SECRET), "{traced}");
        }
        // Not vacuous: the user name and the mangled scheme still identify the mistake.
        assert!(display.contains("alice"), "{display}");
    }

    // The `url` field stays a genuine, fetchable `url::Url`, so this variant masks at
    // *display* time rather than at construction. Both rendering paths must still come
    // out clean.
    #[test]
    fn pac_fetch_required_masks_the_password_in_display_and_debug() {
        let url = url::Url::parse(&format!("https://alice:{SECRET}@wpad.corp/proxy.pac")).unwrap();
        let error = Error::PacFetchRequired { url: url.clone() };

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(SECRET), "{display}");
        assert!(!debug.contains(SECRET), "{debug}");
        assert!(display.contains("wpad.corp"), "{display}");
        assert!(debug.contains("wpad.corp"), "{debug}");

        // The field itself is untouched: the caller still needs the real URL to fetch.
        if let Error::PacFetchRequired { url: preserved } = &error {
            assert_eq!(preserved, &url);
            assert_eq!(preserved.password(), Some(SECRET));
        } else {
            unreachable!();
        }
    }

    #[test]
    fn pac_invalid_result_masks_the_password_in_display_and_debug() {
        let error = Error::pac_invalid_result(format!("PROXY alice:{SECRET}@proxy.corp:8080"));

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(SECRET), "{display}");
        assert!(!debug.contains(SECRET), "{debug}");
        assert!(display.contains("proxy.corp"), "{display}");
        assert!(debug.contains("proxy.corp"), "{debug}");
    }

    // A `FindProxyForURL` that returns an unusable string chooses that string outright,
    // so it is at least as attacker-controlled as an engine message quoting a `throw`.
    #[test]
    fn pac_invalid_result_strips_control_characters_and_truncates() {
        let error = Error::pac_invalid_result("BOGUS\nWARN a fake second log line\r\nthird");

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains('\n'), "{display}");
        assert!(!display.contains('\r'), "{display}");
        assert!(!debug.contains('\n'), "{debug}");
        assert!(!debug.contains('\r'), "{debug}");
        assert!(
            display.contains("BOGUS.WARN a fake second log line..third"),
            "{display}"
        );

        let long = Error::pac_invalid_result("y".repeat(4096));
        assert!(long.to_string().len() < 512, "{}", long.to_string().len());
        assert!(long.to_string().contains('…'), "{long}");
    }

    // `Error::proxy_server`/`Error::bypass` mask only their `input` field; `reason` is
    // trusted. `crate::util::split_host_port`'s `Err` tests that trust: on malformed
    // input it hands back the tail of the string it was splitting, which — because
    // `ProxyEndpoint::parse` cuts the authority off at the first `/`/`?`/`#` *before* it
    // looks for `@` — can be a stranded password fragment rather than a port. This drives
    // the real helper the way `endpoint.rs` does, not a made-up reason string.
    #[test]
    fn proxy_server_reason_does_not_leak_a_password_stranded_past_a_slash() {
        let reason = crate::util::split_host_port(&format!("bob:{SECRET}"))
            .expect_err("a non-numeric \"port\" must fail to parse");
        let error = Error::proxy_server(format!("http://bob:{SECRET}/x@proxy.corp:8080"), reason);

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(SECRET), "{display}");
        assert!(!debug.contains(SECRET), "{debug}");
        // Not vacuous: the rest of the address is still there, in both `input` (already
        // masked) and `reason` (now safe by construction rather than by luck).
        assert!(display.contains("proxy.corp"), "{display}");
        assert!(debug.contains("proxy.corp"), "{debug}");
    }

    // `HostPattern::parse` never processes `@` — a bypass entry is not supposed to be a
    // URL — so `bypass.rs` rejects any `@`-bearing entry outright, with a reason that
    // names the mistake instead of repeating it.
    #[test]
    fn bypass_reason_does_not_leak_a_password_before_an_at_sign() {
        let error = crate::bypass::HostPattern::parse(&format!("alice:{SECRET}@proxy.corp"))
            .expect_err("an '@'-bearing entry must be rejected, not silently misparsed");

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(SECRET), "{display}");
        assert!(!debug.contains(SECRET), "{debug}");
        assert!(display.contains("proxy.corp"), "{display}");
        assert!(debug.contains("proxy.corp"), "{debug}");
    }

    // A syntax error repeats the malformed PAC URL literal the script embedded, so the
    // engine's message can quote a `user:password@` fragment.
    #[test]
    fn pac_evaluation_masks_the_password_in_display_and_debug() {
        let error = Error::pac_evaluation(format!(
            "the PAC script failed to load: unexpected token in string literal \
             \"http://alice:{SECRET}@proxy.corp/x.pac\""
        ));

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(SECRET), "{display}");
        assert!(!debug.contains(SECRET), "{debug}");
        assert!(display.contains("proxy.corp"), "{display}");
        assert!(debug.contains("proxy.corp"), "{debug}");
    }

    // A PAC script's own `throw` reaches `reason` verbatim via the engine's message, so a
    // script author chooses its bytes. Newlines must not survive into `Display`/`Debug`,
    // or a script could forge extra log lines wherever a caller prints the error.
    #[test]
    fn pac_evaluation_strips_control_characters_in_display_and_debug() {
        let error = Error::pac_evaluation(
            "FindProxyForURL failed: Error: forged\nWARN a fake second log line\r\nthird",
        );

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains('\n'), "{display}");
        assert!(!display.contains('\r'), "{display}");
        assert!(!debug.contains('\n'), "{debug}");
        assert!(!debug.contains('\r'), "{debug}");
        // Not vacuous: the message survives, control characters swapped for `.`.
        assert!(
            display.contains("forged.WARN a fake second log line..third"),
            "{display}"
        );
    }

    // A pathological script (or engine) message must not make this error unbounded, even
    // without the `tracing` feature.
    #[test]
    fn pac_evaluation_truncates_a_long_reason_in_display_and_debug() {
        let error = Error::pac_evaluation(format!("FindProxyForURL failed: {}", "y".repeat(4096)));

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(display.len() < 512, "{}", display.len());
        assert!(debug.len() < 512, "{}", debug.len());
        assert!(display.contains('…'), "{display}");
        assert!(debug.contains('…'), "{debug}");
    }

    // One row per variant. Only [`Error::PacFetchRequired`] needs the hand-written impl at
    // all; the other arms are what `derive(Debug)` would have written, copied out by hand
    // because a hand-written impl cannot delegate to a derive for the rest. This test is the
    // only thing that notices a copy drifting: `Sandboxed` printed without its `reason` — the
    // field that says *why* the sandbox left nothing readable, and the whole content of that
    // error — and `Unsupported` printed as `PacEngineUnavailable`, which leaves two distinct
    // failures indistinguishable wherever a caller logs `{:?}`.
    //
    // Exact strings, so that a label, an order or a name cannot change unseen. Where a field
    // has a `Debug` of its own the expectation defers to it rather than copying it out,
    // which is the one thing this impl does not own.
    #[test]
    fn every_variant_debug_names_itself_and_keeps_its_fields() {
        let rejected = RejectedValue::new(
            crate::RejectionKind::UnsupportedMapping,
            crate::RejectionSource::ProxyServer,
            "socks",
        );
        for (error, expected) in [
            (
                Error::proxy_server("proxy.corp", "no port"),
                r#"InvalidProxyServer { input: "proxy.corp", reason: "no port" }"#.to_owned(),
            ),
            (
                Error::bypass("*.corp", "empty label"),
                r#"InvalidBypassPattern { input: "*.corp", reason: "empty label" }"#.to_owned(),
            ),
            (
                Error::invalid_proxy_url("not-a-url", url::ParseError::RelativeUrlWithoutBase),
                format!(
                    r#"InvalidProxyUrl {{ input: "not-a-url", source: {:?} }}"#,
                    url::ParseError::RelativeUrlWithoutBase
                ),
            ),
            (
                Error::UnsupportedProxyScheme("gopher".to_owned()),
                r#"UnsupportedProxyScheme("gopher")"#.to_owned(),
            ),
            (
                Error::CgiHttpProxy {
                    variable: "http_proxy".to_owned(),
                },
                r#"CgiHttpProxy { variable: "http_proxy" }"#.to_owned(),
            ),
            (
                Error::io(
                    "reading dconf",
                    std::io::Error::other("dconf exited nonzero"),
                ),
                format!(
                    r#"Io {{ context: "reading dconf", source: {:?} }}"#,
                    std::io::Error::other("dconf exited nonzero")
                ),
            ),
            (
                Error::Sandboxed {
                    sandbox: "flatpak".to_owned(),
                    reason: "dconf is not on the bus".to_owned(),
                },
                r#"Sandboxed { sandbox: "flatpak", reason: "dconf is not on the bus" }"#.to_owned(),
            ),
            (Error::Unsupported, "Unsupported".to_owned()),
            (
                Error::PacNotSupported { mode: "wpad" },
                r#"PacNotSupported { mode: "wpad" }"#.to_owned(),
            ),
            (
                Error::ProxyEntryUnusable {
                    scheme: Scheme::Https,
                    rejected: rejected.clone(),
                },
                format!(
                    "ProxyEntryUnusable {{ scheme: {:?}, rejected: {rejected:?} }}",
                    Scheme::Https
                ),
            ),
            (
                // No credentials, so that the row pins the rendering and not the masking —
                // which `pac_fetch_required_masks_the_password_in_display_and_debug` owns.
                Error::PacFetchRequired {
                    url: url::Url::parse("https://wpad.corp/proxy.pac").unwrap(),
                },
                "PacFetchRequired { url: https://wpad.corp/proxy.pac }".to_owned(),
            ),
            (
                Error::pac_evaluation("the engine refused the script"),
                r#"PacEvaluation { reason: "the engine refused the script" }"#.to_owned(),
            ),
            (
                Error::PacTimeout {
                    timeout: std::time::Duration::from_millis(1500),
                },
                "PacTimeout { timeout: 1.5s }".to_owned(),
            ),
            (
                Error::pac_invalid_result("BOGUS"),
                r#"PacInvalidResult { result: "BOGUS" }"#.to_owned(),
            ),
            (
                Error::PacEngineUnavailable,
                "PacEngineUnavailable".to_owned(),
            ),
        ] {
            assert_eq!(format!("{error:?}"), expected);
        }
    }
}
