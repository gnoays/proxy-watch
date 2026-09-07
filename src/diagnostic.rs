//! Structured, redaction-safe records for fail-soft configuration drops.

use crate::Scheme;
use crate::util::redact_offending_token;

/// Why one configuration value was ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RejectionKind {
    /// A proxy endpoint or URL could not be parsed.
    InvalidProxyEndpoint,
    /// A bypass-list entry could not be parsed.
    InvalidBypassPattern,
    /// A named proxy scheme was not recognised.
    UnknownProxyScheme,
    /// The source expressed a setting this crate cannot model.
    UnsupportedMapping,
}

/// Where a rejected value was read from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RejectionSource {
    /// A Windows `ProxyServer`-style token.
    ProxyServer,
    /// A bypass / `no_proxy` / `ProxyOverride` token.
    BypassList,
    /// A process environment variable.
    EnvironmentVariable(String),
    /// A KDE `kioslaverc` key.
    Kioslaverc(String),
    /// A GNOME GSettings key.
    GSettings(String),
    /// A macOS SystemConfiguration key.
    SystemConfiguration(String),
}

/// One fail-soft drop with a typed reason and origin.
///
/// Construction masks URL-shaped `user:password` in `input`, or withholds the token when a
/// credential fragment may remain (for example a password that contains whitespace). Derived
/// [`Debug`] and the text accessors therefore cannot expose a password even when the caller
/// supplies an unparseable credential-bearing URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RejectedValue {
    kind: RejectionKind,
    source: RejectionSource,
    redacted_input: String,
    scheme: Option<Scheme>,
}

impl RejectedValue {
    /// Record a rejected raw value, redacting credentials immediately.
    #[must_use]
    pub(crate) fn new(
        kind: RejectionKind,
        source: RejectionSource,
        input: impl AsRef<str>,
    ) -> Self {
        Self {
            kind,
            source,
            redacted_input: redact_offending_token(input.as_ref()),
            scheme: None,
        }
    }

    /// Name the request scheme this drop took an answer away from.
    ///
    /// The question is *which requests lost an answer*, not which key was read. A slot the
    /// parser recognised names its own scheme (`socksProxy` → [`Scheme::Socks`]); a key that
    /// decides every request — a PAC or WPAD switch — names [`Scheme::All`]; only a token
    /// whose key was not recognised at all names nothing, because the crate cannot say which
    /// requests it would have covered.
    ///
    /// `None` is not a safe default. `resolve` cannot find an unattributed record, so it
    /// answers as if the value had never been configured — which is right for the
    /// unrecognised token and wrong for everything else. The widest drops are the ones that
    /// look most like "no single scheme" and least deserve it.
    ///
    /// It takes the [`Option`] rather than the [`Scheme`] because several callers hold one:
    /// a helper shared between a per-scheme loop and a whole-configuration key knows which
    /// it was called for, and would otherwise have to say so with a `match` around the
    /// construction — which is also what hides the masking from `debug_masking`'s scanner.
    #[must_use]
    pub(crate) const fn for_scheme(mut self, scheme: Option<Scheme>) -> Self {
        self.scheme = scheme;
        self
    }

    /// Request scheme this drop took an answer away from, when one is known.
    ///
    /// Under the `resolve` feature, `resolve` reports
    /// [`Error::ProxyEntryUnusable`](crate::Error::ProxyEntryUnusable) rather than
    /// `ProxyStep::Direct` for such a scheme, so a caller is not told "no proxy" about a
    /// request the platform would have proxied. Those two names are left unlinked because
    /// the feature they live behind can be off while this type is still documented.
    #[must_use]
    pub const fn affected_scheme(&self) -> Option<Scheme> {
        self.scheme
    }

    /// Typed reason the value was dropped.
    #[must_use]
    pub const fn kind(&self) -> RejectionKind {
        self.kind
    }

    /// Configuration origin of the dropped value.
    #[must_use]
    pub const fn source(&self) -> &RejectionSource {
        &self.source
    }

    /// Redacted original input.
    #[must_use]
    pub fn redacted_input(&self) -> &str {
        &self.redacted_input
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_redacts_before_debug_or_accessors_can_observe_the_value() {
        let rejected = RejectedValue::new(
            RejectionKind::InvalidProxyEndpoint,
            RejectionSource::EnvironmentVariable("http_proxy".to_owned()),
            "http://alice:hunter2@bad host:8080",
        );
        assert_eq!(rejected.redacted_input(), "http://alice:***@bad host:8080");
        assert!(!format!("{rejected:?}").contains("hunter2"));
    }

    // The two inputs leave [`redact_offending_token`] by different doors — the `//` one
    // masks in place and keeps naming the proxy, the space one is withheld outright — and
    // this test deliberately does not say which is which. What it owns is the layer: that
    // whichever door a value leaves by, `new` has already been through it before any
    // accessor or `Debug` can observe the field. Which door each input takes is pinned one
    // layer down, in `util`'s `redact_offending_token_masks_a_double_slash_inside_a_password`
    // and `redact_offending_token_withholds_when_a_password_holds_a_boundary`.
    #[test]
    fn construction_hides_a_password_that_contains_whitespace_or_double_slash() {
        for (input, secret) in [
            ("http://alice:aa//bb@proxy.corp:8080", "aa//bb"),
            ("http://alice:my pass@proxy.corp:8080", "my pass"),
        ] {
            let rejected = RejectedValue::new(
                RejectionKind::InvalidProxyEndpoint,
                RejectionSource::ProxyServer,
                input,
            );
            assert!(!rejected.redacted_input().contains(secret), "{rejected:?}");
            assert!(!format!("{rejected:?}").contains(secret), "{rejected:?}");
        }
    }
}
