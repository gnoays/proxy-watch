//! Observability behind the `tracing` feature. Call sites use the wrappers here so
//! unlogged builds expand to `()` with no `#[cfg]` at each backend.
//!
//! | Level | What |
//! |---|---|
//! | `INFO` | initial snapshot, emitted changes, portal-fallback notice |
//! | `DEBUG` | lifecycle, read outcomes, watch targets, debounce, queue decisions, PAC `alert()` |
//! | `WARN` | recoverable failures the caller is not already handling |
//! | `ERROR` | watch cannot continue; the backend thread panicked |
//!
//! Configurations are only logged via the secret-free summary renderers below — never
//! `{:?}`. Documented recoveries (e.g. WinHTTP IE → plain registry) use `DEBUG`, not
//! `WARN`. Passwords: `MaskedUrl` / PacInline len+hash / `SafeError` — never `{:?}` a
//! whole [`ProxyConfig`].

#![allow(unused_macros)]

#[cfg(feature = "tracing")]
macro_rules! debug {
    ($($arg:tt)*) => { ::tracing::debug!($($arg)*) };
}
#[cfg(not(feature = "tracing"))]
macro_rules! debug {
    ($($arg:tt)*) => {
        ()
    };
}
#[allow(unused_imports)]
pub(crate) use debug;

#[cfg(feature = "tracing")]
macro_rules! info {
    ($($arg:tt)*) => { ::tracing::info!($($arg)*) };
}
#[cfg(not(feature = "tracing"))]
macro_rules! info {
    ($($arg:tt)*) => {
        ()
    };
}
#[allow(unused_imports)]
pub(crate) use info;

#[cfg(feature = "tracing")]
macro_rules! warning {
    ($($arg:tt)*) => { ::tracing::warn!($($arg)*) };
}
#[cfg(not(feature = "tracing"))]
macro_rules! warning {
    ($($arg:tt)*) => {
        ()
    };
}
#[allow(unused_imports)]
pub(crate) use warning;

#[cfg(feature = "tracing")]
macro_rules! error {
    ($($arg:tt)*) => { ::tracing::error!($($arg)*) };
}
#[cfg(not(feature = "tracing"))]
macro_rules! error {
    ($($arg:tt)*) => {
        ()
    };
}
#[allow(unused_imports)]
pub(crate) use error;

use crate::config::ProxyConfig;

// The `INFO` line for a transition [`Shared::emit`](crate::watch::Shared::emit) publishes.
//
// Do not split this into two steps — render under the queue mutex, log after releasing it.
// The split buys nothing that `info!` does not already do — `%` formats lazily and the
// macro asks the subscriber itself — and it puts the level filter, which is consumer code,
// under the lock. Both halves run after the unlock, so there is nothing to carry across it.
#[cfg(feature = "tracing")]
pub(crate) fn changed(previous: &ProxyConfig, current: &ProxyConfig) {
    ::tracing::info!(
        previous = %ModeSummary(&previous.effective),
        current = %ModeSummary(&current.effective),
        sources = %SourceSummary(&current.sources),
        "the system proxy configuration changed"
    );
}

#[cfg(not(feature = "tracing"))]
pub(crate) fn changed(_previous: &ProxyConfig, _current: &ProxyConfig) {}

// The `INFO` line for the snapshot a watcher starts with: the current value is always
// delivered once, at subscription time.
#[cfg(feature = "tracing")]
pub(crate) fn initial(config: &ProxyConfig) {
    ::tracing::info!(
        current = %ModeSummary(&config.effective),
        sources = %SourceSummary(&config.sources),
        "watching the system proxy configuration"
    );
}

#[cfg(not(feature = "tracing"))]
pub(crate) fn initial(_config: &ProxyConfig) {}

// `DEBUG`: an operation failed and the caller is about to work around it.
#[cfg(feature = "tracing")]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn fallback(what: &str, error: &crate::error::Error) {
    ::tracing::debug!(error = %SafeError(error), "{what}");
}

#[cfg(not(feature = "tracing"))]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn fallback(_what: &str, _error: &crate::error::Error) {}

// `alert(message)` from a PAC script.
#[cfg(feature = "tracing")]
#[cfg_attr(not(feature = "pac"), allow(dead_code))]
pub(crate) fn pac_alert(message: &str) {
    // The field is `alert`, not `message`: `message` is the name `tracing` reserves for
    // an event's own text, so a script could otherwise overwrite it.
    ::tracing::debug!(alert = %self::render::Sanitized(message), "PAC script called alert()");
}

#[cfg(not(feature = "tracing"))]
#[cfg_attr(not(feature = "pac"), allow(dead_code))]
pub(crate) fn pac_alert(_message: &str) {}

// ---------------------------------------------------------------------------
// The renderers. None of them is compiled without the feature, so a build without it
// cannot keep a formatting cost — or a leak — around by accident.
// ---------------------------------------------------------------------------

#[cfg(feature = "tracing")]
mod render {
    use std::fmt::{self, Write as _};

    use url::Url;

    use crate::config::{ProxyConfig, ProxyConfigSource};
    use crate::endpoint::{ProxyEntry, Scheme};
    use crate::error::Error;
    use crate::mode::ProxyMode;
    use crate::util::MASK;

    pub(crate) struct MaskedUrl<'a>(pub(crate) &'a Url);

    impl fmt::Display for MaskedUrl<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let url = self.0;
            // Asking first whether there is a host, because `Url::password` slices from the
            // userinfo delimiter to the host and an empty host puts those two the wrong way
            // round. `socks5://:8080/p` — a shape `Url::parse` refuses but
            // `set_host(Some(""))` builds on a non-special scheme, and `ProxyMode::Pac`
            // carries whatever `Url` a caller hands it — panics inside that method, in
            // release as much as in debug. The rebuild below has nothing to do for those
            // anyway: it writes an authority out of parts that are not there.
            if url.host_str().is_none_or(str::is_empty) || url.password().is_none() {
                // Not `url.as_str()`: `password()` is `None` for a percent-encoded
                // delimiter (`alice%3Ahunter2@`), because WHATWG only splits userinfo on
                // a literal `:` — so printing verbatim here would log the secret
                // (`a_percent_encoded_password_is_still_masked`).
                // `redact_userinfo` borrows unchanged when there is nothing shaped like
                // credentials in the string at all, which is the overwhelmingly common
                // case, so the normal path still allocates nothing.
                return f.write_str(&crate::util::redact_userinfo(url.as_str()));
            }
            // Rebuilt rather than run through `Url::set_password`: that needs an owned
            // clone and *fails* on a cannot-be-a-base URL, and a failure here would mean
            // either printing the password or losing the whole field.
            let username = url.username();
            // A user name can hide a second secret behind a `%3A` even when a real
            // password was parsed out after a later literal `:`. Keep the delimiter,
            // drop everything after it; the `:{MASK}` below covers both.
            let username = match crate::util::userinfo_delimiter_end(username) {
                Some(end) => &username[..end],
                None => username,
            };
            write!(f, "{}://{username}:{MASK}@", url.scheme())?;
            if let Some(host) = url.host_str() {
                f.write_str(host)?;
            }
            if let Some(port) = url.port() {
                write!(f, ":{port}")?;
            }
            f.write_str(url.path())?;
            if let Some(query) = url.query() {
                write!(f, "?{query}")?;
            }
            // Rebuilding by hand means every component has to be named, and the fragment
            // is the one with no reason to be dropped: the branch above prints the URL
            // verbatim and keeps it, so leaving it out here would make what `MaskedUrl`
            // renders depend on whether a password happened to be present.
            match url.fragment() {
                Some(fragment) => write!(f, "#{fragment}"),
                None => Ok(()),
            }
        }
    }

    pub(crate) struct ModeSummary<'a>(pub(crate) &'a ProxyMode);

    impl fmt::Display for ModeSummary<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.0 {
                ProxyMode::Direct => f.write_str("direct"),
                // `rejected` is intentionally left out of `..`: it is already
                // `redact_userinfo`-masked, so including it would widen what
                // `ModeSummary` renders rather than make anything safer.
                ProxyMode::Manual {
                    per_scheme, bypass, ..
                } => {
                    f.write_str("manual(")?;
                    // `Scheme::ALL` rather than the map's own iteration order, so two
                    // equal configurations always render identically.
                    for scheme in Scheme::ALL {
                        let Some(entry) = per_scheme.get(&scheme) else {
                            continue;
                        };
                        match entry {
                            // `ProxyEndpoint`'s `Display` prints host and port, and a
                            // `scheme://` prefix only when the source carried one — so
                            // the key written here is what names the scheme for the
                            // bare authorities most sources store, not a duplicate of
                            // it. Credentials never print; that they *exist* is still
                            // worth knowing, hence the flag.
                            ProxyEntry::Use(endpoint) => {
                                write!(f, "{scheme}={endpoint}")?;
                                if endpoint.auth.is_some() {
                                    f.write_str("+auth")?;
                                }
                            }
                            ProxyEntry::Disabled => write!(f, "{scheme}=disabled")?,
                            // The marker, not the record: `RejectedValue`'s text is masked
                            // but wider than anything else here, and leaving `rejected` out
                            // of `..` above would buy nothing if the same values came back
                            // through the map. Which schemes lost their answer is the part
                            // a summary is for.
                            ProxyEntry::Unusable(_) => write!(f, "{scheme}=unusable")?,
                        }
                        f.write_str(" ")?;
                    }
                    write!(f, "bypass={})", bypass.patterns.len())
                }
                ProxyMode::Pac { url, .. } => write!(f, "pac({})", MaskedUrl(url)),
                // The body is never logged: it is large, it is internal, and on macOS it
                // comes from `ProxyAutoConfigJavaScript`, which an MDM profile writes.
                // The hash still makes "the script changed" visible, which is the point.
                ProxyMode::PacInline { script, .. } => write!(
                    f,
                    "pac-inline(len={} fnv1a={:016x})",
                    script.len(),
                    crate::util::fnv1a(script.as_bytes())
                ),
                ProxyMode::WpadAutoDetect => f.write_str("wpad"),
            }
        }
    }

    pub(crate) struct SourceSummary<'a>(pub(crate) &'a [(ProxyConfigSource, ProxyMode)]);

    impl fmt::Display for SourceSummary<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("[")?;
            for (index, (source, mode)) in self.0.iter().enumerate() {
                if index > 0 {
                    f.write_str(" ")?;
                }
                // `ProxyConfigSource` is a field-less enum, so its `Debug` is the variant
                // name and carries nothing that could leak.
                write!(f, "{source:?}={}", ModeSummary(mode))?;
            }
            f.write_str("]")
        }
    }

    pub(crate) struct ConfigSummary<'a>(pub(crate) &'a ProxyConfig);

    impl fmt::Display for ConfigSummary<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{} sources={}",
                ModeSummary(&self.0.effective),
                SourceSummary(&self.0.sources)
            )
        }
    }

    pub(crate) struct SafeError<'a>(pub(crate) &'a Error);

    impl fmt::Display for SafeError<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.0 {
                // `reason` is this crate's own words around a quotation of the offending
                // text — `parse_host` builds `invalid host {…:?}: {e}` — and the source
                // decides how long that text is. The `{:?}` already escapes the line
                // breaks, so only the bound is missing, and `Sanitized` is where the bound
                // lives.
                Error::InvalidProxyServer { reason, .. } => {
                    write!(
                        f,
                        "invalid proxy server specification: {}",
                        Sanitized(reason)
                    )
                }
                Error::InvalidBypassPattern { reason, .. } => {
                    write!(f, "invalid bypass pattern: {reason}")
                }
                Error::InvalidProxyUrl { source, .. } => write!(f, "invalid proxy URL: {source}"),
                Error::UnsupportedProxyScheme(scheme) => {
                    write!(f, "unsupported proxy scheme \"{}\"", Sanitized(scheme))
                }
                Error::CgiHttpProxy { variable } => {
                    write!(f, "refusing to use {variable} in a CGI environment")
                }
                Error::Io { context, source } => write!(f, "{context}: {source}"),
                Error::Sandboxed { sandbox, reason } => {
                    write!(f, "running inside a {sandbox} sandbox: {reason}")
                }
                Error::Unsupported => f.write_str("unsupported platform"),
                Error::PacNotSupported { mode } => write!(f, "routing needs a PAC script ({mode})"),
                // The scheme is a fixed word. The value is not: it was *masked* at
                // construction, and masking is not sanitising. `redact_offending_token`
                // takes out credentials and touches nothing else, so a newline in the
                // configured value is still a newline and its length is still whatever the
                // source wrote. This is the only place a `RejectedValue`'s text is rendered
                // into a log line — every other reader gets it through a derived `Debug`,
                // which escapes — so `http_proxy` or a bypass list holding a line break
                // forged log lines here, which is the half of the rule
                // `untrusted_error_payloads_are_sanitized` states that a mask cannot cover.
                Error::ProxyEntryUnusable { scheme, rejected } => write!(
                    f,
                    "the configured {scheme} proxy could not be used ({})",
                    Sanitized(rejected.redacted_input())
                ),
                Error::PacFetchRequired { url } => {
                    write!(f, "the PAC script at {} must be fetched", MaskedUrl(url))
                }
                // Not a secret of the system's, but attacker-influenced all the same: the
                // engine quotes the script in its message.
                Error::PacEvaluation { reason } => {
                    write!(f, "PAC evaluation failed: {}", Sanitized(reason))
                }
                Error::PacTimeout { timeout } => {
                    write!(f, "PAC evaluation exceeded its {timeout:?} budget")
                }
                Error::PacInvalidResult { result } => {
                    write!(f, "PAC returned no usable candidate: {}", Sanitized(result))
                }
                Error::PacEngineUnavailable => f.write_str("no PAC JavaScript engine is enabled"),
            }
        }
    }

    pub(crate) struct Sanitized<'a>(pub(crate) &'a str);

    impl fmt::Display for Sanitized<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            for character in self.0.chars().take(crate::util::MAX_UNTRUSTED) {
                f.write_char(crate::util::sanitized_char(character))?;
            }
            if self.0.chars().nth(crate::util::MAX_UNTRUSTED).is_some() {
                f.write_str("…")?;
            }
            Ok(())
        }
    }
}

#[cfg(feature = "tracing")]
pub(crate) use self::render::{ConfigSummary, ModeSummary, SafeError, SourceSummary};

#[cfg(all(test, feature = "tracing"))]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::sync::{Arc, Mutex, MutexGuard};

    use tracing_subscriber::fmt::MakeWriter;
    use url::{Host, ParseError, Url};

    use super::render::{MaskedUrl, Sanitized};
    use super::*;
    use crate::auth::ProxyAuth;
    use crate::bypass::BypassRules;
    use crate::config::ProxyConfigSource;
    use crate::endpoint::{ProxyEndpoint, ProxyEntry, Scheme};
    use crate::error::Error;
    use crate::mode::ProxyMode;
    use crate::watch::Shared;

    // The password every secrecy test plants. Distinctive enough that a substring search
    // for it cannot produce a false negative.
    const SECRET: &str = "hunter2-s3cr3t-must-never-appear";

    // A `MakeWriter` that appends to a shared buffer, i.e. the smallest possible sink.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Capture {
        fn text(&self) -> String {
            String::from_utf8(self.lock().clone()).expect("the fmt layer writes UTF-8")
        }

        fn lock(&self) -> MutexGuard<'_, Vec<u8>> {
            self.0.lock().unwrap_or_else(|e| e.into_inner())
        }
    }

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.lock().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    // Run `body` with everything it logs captured, and return the captured text.
    fn capture(body: impl FnOnce()) -> String {
        let sink = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, body);
        sink.text()
    }

    fn endpoint_with_password() -> ProxyEndpoint {
        ProxyEndpoint::parse(&format!("http://alice:{SECRET}@proxy.corp:8080"), 80)
            .expect("a userinfo proxy address parses")
    }

    // A snapshot carrying a secret in every place this crate is able to hold one.
    fn config_full_of_secrets() -> ProxyConfig {
        let mut per_scheme = HashMap::new();
        per_scheme.insert(Scheme::Http, ProxyEntry::Use(endpoint_with_password()));
        per_scheme.insert(
            Scheme::Https,
            ProxyEntry::Use(
                ProxyEndpoint::new(Host::Domain("secure.corp".to_owned()), 8443)
                    .with_auth(ProxyAuth::new("bob", Some(SECRET))),
            ),
        );
        per_scheme.insert(Scheme::Ftp, ProxyEntry::Disabled);
        let manual = ProxyMode::manual(per_scheme, BypassRules::new());

        let pac = ProxyMode::pac(
            Url::parse(&format!("https://alice:{SECRET}@wpad.corp/proxy.pac"))
                .expect("a userinfo URL parses"),
        );
        let inline = ProxyMode::pac_inline(format!(
            "function FindProxyForURL(u, h) {{ return 'PROXY {SECRET}:8080'; }}"
        ));

        ProxyConfig::new(
            manual.clone(),
            vec![
                (ProxyConfigSource::GroupPolicy, manual),
                (ProxyConfigSource::Registry, pac),
                (ProxyConfigSource::SystemConfigurationSetup, inline),
            ],
        )
    }

    #[test]
    fn no_password_survives_any_renderer() {
        let config = config_full_of_secrets();
        let rendered = format!(
            "{} | {} | {}",
            ConfigSummary(&config),
            ModeSummary(&config.effective),
            SourceSummary(&config.sources)
        );
        assert!(!rendered.contains(SECRET), "{rendered}");
        // The user name is deliberately kept — it is not the secret, and "which account
        // is this proxy configured for" is exactly the kind of thing this crate's logging
        // is designed to surface —
        // but it must never be followed by anything except the mask.
        assert!(rendered.contains("alice:***@"), "{rendered}");

        // …and the redaction is not vacuous: everything that is *not* a secret is still
        // there, which is what makes the log worth writing in the first place.
        assert!(
            rendered.contains("http://proxy.corp:8080+auth"),
            "{rendered}"
        );
        assert!(rendered.contains("secure.corp:8443+auth"), "{rendered}");
        assert!(rendered.contains("ftp=disabled"), "{rendered}");
        assert!(rendered.contains("wpad.corp/proxy.pac"), "{rendered}");
        assert!(rendered.contains("***"), "{rendered}");
        assert!(rendered.contains("pac-inline(len="), "{rendered}");
        assert!(rendered.contains("GroupPolicy=manual"), "{rendered}");

        // The two things a list of sources is besides its contents: where each entry starts
        // and where the list does. Every `contains` above passes just as well with the
        // separator gone and the three sources run together, or with a stray one in front of
        // the first — and a summary a reader cannot split back into sources is the one thing
        // this renderer exists to avoid.
        let sources = SourceSummary(&config.sources).to_string();
        assert!(sources.starts_with("[GroupPolicy=manual"), "{sources}");
        assert!(sources.contains(" Registry=pac("), "{sources}");
        assert!(sources.ends_with(")]"), "{sources}");
    }

    #[test]
    fn the_inline_script_body_is_never_rendered() {
        let script = format!("// {SECRET}\nfunction FindProxyForURL(u, h) {{ return 'DIRECT'; }}");
        let mode = ProxyMode::pac_inline(script.clone());
        let rendered = ModeSummary(&mode).to_string();
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(!rendered.contains("FindProxyForURL"), "{rendered}");
        assert!(
            rendered.contains(&format!("len={}", script.len())),
            "{rendered}"
        );

        // The hash still tells two different scripts apart.
        let other = ProxyMode::pac_inline(format!("{script} "));
        assert_ne!(rendered, ModeSummary(&other).to_string());
    }

    // The summary walks `Scheme::ALL` rather than the map it is summarising, so the same
    // configuration always renders as the same line — which is what makes two of them
    // comparable at all. Every other test here asks whether some fragment is present, and a
    // fragment cannot tell one ordering from another, nor notice a field going missing; this
    // one owns the whole line.
    #[test]
    fn a_manual_summary_names_its_schemes_in_the_order_scheme_fixes() {
        fn at(host: &str, port: u16) -> ProxyEntry {
            ProxyEntry::Use(ProxyEndpoint::new(Host::Domain(host.to_owned()), port))
        }

        // Inserted back to front, so a summary reading the map would have to be lucky to
        // agree with the one below.
        let mut per_scheme = HashMap::new();
        // The third state, and the one a fragment test would never have reached: a scheme
        // whose configured value could not be read is not the same as one turned off, and
        // the difference is the whole of what a reader is looking for when a scheme stops
        // working. Its `RejectedValue` is deliberately not rendered — the marker is.
        per_scheme.insert(
            Scheme::All,
            ProxyEntry::Unusable(crate::diagnostic::RejectedValue::new(
                crate::diagnostic::RejectionKind::InvalidProxyEndpoint,
                crate::diagnostic::RejectionSource::EnvironmentVariable("all_proxy".to_owned()),
                "pw-probe-should-not-appear",
            )),
        );
        per_scheme.insert(Scheme::Socks, ProxyEntry::Disabled);
        per_scheme.insert(Scheme::Ftp, at("ftp.corp", 2121));
        per_scheme.insert(Scheme::Https, at("secure.corp", 8443));
        per_scheme.insert(Scheme::Http, at("proxy.corp", 8080));

        let mode = ProxyMode::manual(per_scheme, crate::parse::no_proxy("example.com,.corp"));
        assert_eq!(
            ModeSummary(&mode).to_string(),
            "manual(http=proxy.corp:8080 https=secure.corp:8443 ftp=ftp.corp:2121 \
             socks=disabled all=unusable bypass=2)"
        );
    }

    #[test]
    fn a_watcher_never_logs_a_password() {
        let config = config_full_of_secrets();
        let text = capture(|| {
            let shared = Shared::new(ProxyConfig::direct());
            initial(&shared.current());
            shared.emit(config.clone());
            // The same value again: the equality check that skips a duplicate
            // notification has to stay just as quiet about
            // the secrets it has just compared.
            shared.emit(config.clone());
            shared.fail(Error::InvalidProxyUrl {
                input: format!("http://alice:{SECRET}@proxy.corp:8080"),
                source: ParseError::EmptyHost,
            });
            shared.fail(Error::proxy_server(
                format!("http://alice:{SECRET}@proxy.corp:99999"),
                "port out of range",
            ));
            shared.fail(Error::PacFetchRequired {
                url: Url::parse(&format!("https://alice:{SECRET}@wpad.corp/x.pac")).unwrap(),
            });
            // A PAC `alert()` carries the script's own words, not a system secret, so it
            // is logged verbatim (after sanitising) — see the dedicated test below.
            pac_alert("routing decision taken");
            shared.close();
        });

        assert!(!text.contains(SECRET), "a secret reached the log:\n{text}");
        assert!(
            !text.contains("hunter2"),
            "a secret reached the log:\n{text}"
        );
        // Not vacuous: those events really were emitted.
        assert!(
            text.contains("the system proxy configuration changed"),
            "{text}"
        );
        assert!(
            text.contains("watching the system proxy configuration"),
            "{text}"
        );
        assert!(text.contains("PAC script called alert()"), "{text}");
        assert!(text.contains("proxy.corp:8080"), "{text}");
    }

    #[test]
    fn a_change_is_info_and_an_equal_snapshot_is_a_debug_skip() {
        let text = capture(|| {
            let shared = Shared::new(ProxyConfig::direct());
            shared.emit(ProxyConfig::from_source(
                ProxyConfigSource::Registry,
                ProxyMode::WpadAutoDetect,
            ));
            shared.emit(ProxyConfig::from_source(
                ProxyConfigSource::Registry,
                ProxyMode::WpadAutoDetect,
            ));
        });

        let change = text
            .lines()
            .find(|line| line.contains("the system proxy configuration changed"))
            .unwrap_or_else(|| panic!("no change event in:\n{text}"));
        assert!(change.contains("INFO"), "{change}");
        assert!(change.contains("previous=direct"), "{change}");
        assert!(change.contains("current=wpad"), "{change}");
        assert!(change.contains("Registry=wpad"), "{change}");

        let skip = text
            .lines()
            .find(|line| line.contains("unchanged"))
            .unwrap_or_else(|| panic!("no equality skip event in:\n{text}"));
        assert!(skip.contains("DEBUG"), "{skip}");
    }

    #[test]
    fn an_alert_cannot_forge_log_lines_or_flood_them() {
        let text = capture(|| pac_alert("first\nWARN forged second line\r\nthird"));
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(
            text.contains("first.WARN forged second line..third"),
            "{text}"
        );

        let text = capture(|| pac_alert(&"x".repeat(4096)));
        assert!(text.len() < 1024, "an alert must not flood the log: {text}");
        assert!(text.contains('…'), "{text}");
    }

    #[test]
    fn a_url_without_a_password_is_left_alone() {
        for input in [
            "http://wpad.corp/proxy.pac?a=b",
            "http://alice@wpad.corp/proxy.pac",
            "file:///etc/proxy.pac",
        ] {
            let url = Url::parse(input).unwrap();
            assert_eq!(MaskedUrl(&url).to_string(), url.as_str());
        }
    }

    // `Url::password()` is `None` here — WHATWG only splits on a literal `:` —
    // so a `password().is_none() => print verbatim` shortcut hands the secret
    // straight to the log.
    #[test]
    fn a_percent_encoded_password_is_still_masked() {
        for input in [
            "http://alice%3Ahunter2@wpad.corp/proxy.pac",
            "http://alice%3ahunter2@wpad.corp/proxy.pac",
        ] {
            let url = Url::parse(input).unwrap();
            assert!(url.password().is_none(), "premise of this test: {input}");
            let masked = MaskedUrl(&url).to_string();
            assert!(!masked.contains("hunter2"), "{masked}");
            assert!(masked.contains("***"), "{masked}");
            assert!(masked.contains("wpad.corp"), "{masked}");
        }
    }

    // The password branch rebuilds the URL component by component, so anything it forgets
    // to name is dropped. What it renders must not depend on whether a password was there:
    // the branch above prints the URL verbatim, fragment included.
    #[test]
    fn the_password_branch_drops_the_password_and_nothing_else() {
        let plain = Url::parse("http://alice@wpad.corp:8443/proxy.pac?a=b#section").unwrap();
        let with_password =
            Url::parse("http://alice:hunter2@wpad.corp:8443/proxy.pac?a=b#section").unwrap();
        assert!(with_password.password().is_some(), "premise of this test");

        assert_eq!(
            MaskedUrl(&with_password).to_string(),
            MaskedUrl(&plain)
                .to_string()
                .replace("alice@", "alice:***@"),
        );
    }

    // The password branch has the same hole in its *user name*: a real password after a
    // literal `:` does not stop an earlier `%3A` from hiding a second one.
    #[test]
    fn a_percent_encoded_delimiter_in_the_user_name_is_masked_too() {
        let url = Url::parse("http://alice%3Afirst:second@wpad.corp/proxy.pac").unwrap();
        assert_eq!(url.password(), Some("second"));
        let masked = MaskedUrl(&url).to_string();
        assert!(!masked.contains("first"), "{masked}");
        assert!(!masked.contains("second"), "{masked}");
        assert!(masked.contains("wpad.corp"), "{masked}");
    }

    // An emptied host reaches here through `ProxyMode::Pac { url }`, whose field takes any
    // `Url` a caller holds. The last row is the one that can abort the process: with no
    // userinfo in front of it, the port's `:` is read as the userinfo delimiter and
    // `Url::password` slices backwards past the start of the host.
    #[test]
    fn an_emptied_host_is_masked_rather_than_rebuilt() {
        for (input, expected) in [
            (
                "socks5://alice:hunter2@wpad.corp/proxy.pac",
                "socks5://alice:***@/proxy.pac",
            ),
            (
                "socks5://:hunter2@wpad.corp:8443/p",
                "socks5://:***@:8443/p",
            ),
            ("socks5://alice@wpad.corp:8443/p", "socks5://alice@:8443/p"),
            ("socks5://wpad.corp:8443/p", "socks5://:8443/p"),
        ] {
            let mut url = Url::parse(input).unwrap();
            url.set_host(Some(""))
                .expect("a non-special scheme accepts an empty host");
            let masked = MaskedUrl(&url).to_string();
            assert_eq!(masked, expected, "for {input}");
            assert!(!masked.contains("hunter2"), "{masked}");
        }
    }

    #[test]
    fn no_error_variant_echoes_the_input_it_failed_on() {
        let cases = [
            Error::InvalidProxyServer {
                input: SECRET.to_owned(),
                reason: "bad".to_owned(),
            },
            Error::InvalidBypassPattern {
                input: SECRET.to_owned(),
                reason: "bad".to_owned(),
            },
            Error::InvalidProxyUrl {
                input: SECRET.to_owned(),
                source: ParseError::EmptyHost,
            },
            Error::PacFetchRequired {
                url: Url::parse(&format!("http://a:{SECRET}@wpad/x.pac")).unwrap(),
            },
        ];
        for error in cases {
            let rendered = SafeError(&error).to_string();
            assert!(
                !rendered.contains(SECRET),
                "{error:?} rendered as {rendered}"
            );
        }
    }

    // Regression test (security fix): `SafeError` is the *only* thing a default
    // `tracing` `WARN` line ever prints an `Error` through (every `warning!` that
    // carries one routes it this way; see e.g. `src/env.rs`,
    // `src/sys/linux/gsettings_map.rs`, `src/sys/proxy_dict.rs`), and it renders
    // `reason` verbatim on the assumption that `reason` is already safe — dropping only
    // `input`. That assumption used to be false for several real parser entry points;
    // each row here is a distinct leak vector through the real parsers, end to end
    // through `SafeError`, not through a hand-built `Error`.
    #[test]
    fn safe_error_does_not_leak_credentials_from_real_parsers() {
        struct Case {
            error: Error,
            must_contain: &'static str,
        }

        let cases = [
            Case {
                error: crate::endpoint::ProxyEndpoint::parse(
                    &format!("http://bob:{SECRET}/x@proxy.corp:8080"),
                    80,
                )
                .expect_err("a '/' in the password must strand the '@' and fail to parse"),
                must_contain: "invalid port",
            },
            Case {
                error: crate::bypass::HostPattern::parse(&format!("alice:{SECRET}@proxy.corp"))
                    .expect_err("an '@'-bearing bypass entry must be rejected"),
                must_contain: "proxy.corp",
            },
            Case {
                error: crate::endpoint::ProxyEndpoint::parse(
                    &format!("http://bob:sec:{SECRET}/x@proxy.corp:8080"),
                    80,
                )
                .expect_err("a stranded user:password fragment must not parse as a host"),
                must_contain: "invalid host",
            },
            Case {
                error: crate::endpoint::ProxyEndpoint::parse(
                    &format!("http://[bob:{SECRET}]:8080"),
                    80,
                )
                .expect_err("a bracketed non-IPv6 literal must not parse as a host"),
                // The bracketed spelling is also where `reason` and `input` visibly diverge.
                must_contain: "invalid IPv6 literal",
            },
        ];

        for case in cases {
            let safe = SafeError(&case.error).to_string();
            assert!(!safe.contains(SECRET), "{safe}");
            assert!(
                !format!("{:?}", case.error).contains(SECRET),
                "{:?}",
                case.error
            );
            assert!(safe.contains(case.must_contain), "{safe}");
        }
    }

    // The other half of that trade, so the fix cannot quietly degenerate into "never
    // name a host": an ordinary bad host with no `:` anywhere — nothing the crate's own
    // userinfo test could mistake for a credential — is still reported in full.
    #[test]
    fn an_ordinary_invalid_host_is_still_named() {
        let error = crate::endpoint::ProxyEndpoint::parse("http://pro\\xy", 80)
            .expect_err("a backslash is a forbidden host code point");
        let safe = SafeError(&error).to_string();
        assert!(safe.contains("pro"), "{safe}");
    }

    // `Error` is not the only thing a rejected token reaches: every backend keeps the
    // originals it dropped, and those lists are `Debug`-printed as part of a snapshot.
    // The two types below derive their `Debug`, so `debug_masking`'s registry cannot
    // see them; the `ProxyMode` they feed is covered by a case there instead.
    #[test]
    fn rejected_lists_do_not_leak_credentials_from_real_parsers() {
        let env = crate::env::ProxyEnv::from_vars([("http_proxy", format!("http://bob:{SECRET}"))])
            .expect("a malformed value is a rejected entry, not a snapshot failure");
        assert_eq!(env.rejected().len(), 1);
        assert!(!format!("{env:?}").contains(SECRET), "{env:?}");

        let bypass = crate::parse::no_proxy(&format!("[bob:{SECRET}],example.com"));
        assert_eq!(bypass.rejected.len(), 1);
        assert!(!format!("{bypass:?}").contains(SECRET), "{bypass:?}");
    }

    #[test]
    fn untrusted_error_payloads_are_sanitized() {
        // A script's own output is not a system secret, but it *is* attacker controlled,
        // so it may neither break the line nor be unbounded.
        let error = Error::PacEvaluation {
            reason: format!("Uncaught SyntaxError\n{}", "y".repeat(4096)),
        };
        let rendered = SafeError(&error).to_string();
        assert!(!rendered.contains('\n'), "{rendered}");
        assert!(rendered.len() < 512, "{}", rendered.len());
        assert_eq!(Sanitized("a\tb").to_string(), "a.b");

        // A parser's `reason` is the same kind of payload from the other direction: this
        // crate's own words, wrapped around a quotation of text the source chose the length
        // of. `{:?}` keeps the line whole; nothing kept it short.
        let error =
            crate::endpoint::ProxyEndpoint::parse(&format!("pro\\xy{}", "y".repeat(4096)), 80)
                .expect_err("a backslash is a forbidden host code point");
        let rendered = SafeError(&error).to_string();
        assert!(rendered.len() < 512, "{}", rendered.len());
        assert!(rendered.contains("invalid host"), "{rendered}");

        // Where the cut actually falls. The bound above is satisfied by anything near the
        // limit, so it holds the shape and not the boundary; these rows are the only thing
        // that would notice `Sanitized` taking one character more. The ellipsis is
        // the reason the last row is not longer than the one before it — it stands in for
        // everything dropped, however much that is, so a script cannot make a log line
        // grow by writing a longer `alert()`.
        //
        // Rendered together and compared once, so a failure names every length that moved.
        use crate::util::MAX_UNTRUSTED;
        let lengths: Vec<usize> = [
            MAX_UNTRUSTED - 1,
            MAX_UNTRUSTED,
            MAX_UNTRUSTED + 1,
            MAX_UNTRUSTED + 100,
        ]
        .into_iter()
        .map(|count| Sanitized(&"y".repeat(count)).to_string().chars().count())
        .collect();
        assert_eq!(
            lengths,
            [
                MAX_UNTRUSTED - 1,
                MAX_UNTRUSTED,
                MAX_UNTRUSTED + 1,
                MAX_UNTRUSTED + 1
            ]
        );
    }

    // The same rule for the one payload that arrives already masked, which is the reason it
    // looks like it needs nothing further.
    // `redact_offending_token` removes credentials; it does not replace control characters
    // and it does not truncate, so "masked" leaves both halves of the rule above open.
    //
    // Built through a real backend rather than by hand, because what makes this reachable
    // is that `RejectedValue` is handed the *variable's own text*: `env.rs` trims it and
    // passes it whole. No `:` anywhere in the value, so it is named rather than withheld —
    // withholding would answer the question by accident and the test would hold nothing.
    #[test]
    fn a_dropped_value_cannot_forge_a_log_line_or_run_past_the_bound() {
        let forged = format!("pw-probe\nERROR forged line {}", "y".repeat(4096));
        let env = crate::env::ProxyEnv::from_vars([("http_proxy", forged)])
            .expect("a malformed value is a rejected entry, not a snapshot failure");
        let rejected = env.rejected()[0].clone();
        // The premise: the record really is holding the break and the length.
        assert!(rejected.redacted_input().contains('\n'), "{rejected:?}");
        assert!(rejected.redacted_input().len() > 4096, "{rejected:?}");

        let error = Error::ProxyEntryUnusable {
            scheme: Scheme::Http,
            rejected,
        };
        let rendered = SafeError(&error).to_string();
        assert!(!rendered.contains('\n'), "{rendered}");
        assert!(rendered.len() < 512, "{}", rendered.len());
        // Not vacuous: the value is still named, which is the whole reason this renderer
        // prints more than `Error`'s own `Display` does.
        assert!(rendered.contains("pw-probe"), "{rendered}");
    }
}
