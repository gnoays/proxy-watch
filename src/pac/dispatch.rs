//! [`PacResolver`]: one entry point that hands each mode to the engine that can answer it.

use url::Url;

use super::{PacEvaluator, PacPolicy, PacScript};
use crate::config::ProxyConfig;
use crate::error::Error;
use crate::resolve::ProxyStep;

// The native engine this target has. The Windows and Apple ones download, and discover
// after `with_wpad`; the Android one asks the system PAC service, which does both itself.
#[cfg(pac_native)]
use super::NativePacResolver as Native;

/// Routes a whole [`ProxyConfig`] to whichever PAC engine answers its mode.
///
/// The order, first match wins:
///
/// 1. [`Direct`](crate::ProxyMode::Direct) / [`Manual`](crate::ProxyMode::Manual):
///    [`resolve`](crate::resolve()), bypass list included. A `script` is ignored.
/// 2. A URL with no host (`mailto:`, `data:`): Direct, and no engine runs.
/// 3. A `script` the caller passed: the JS engine, whichever PAC mode is effective. A
///    caller who fetched the body has already answered the question the mode asks.
/// 4. [`PacInline`](crate::ProxyMode::PacInline): the JS engine, with the body the mode
///    carries.
///
/// "The JS engine" is the evaluator attached with [`with_evaluator`](Self::with_evaluator)
/// when there is one, else [`evaluate`](super::evaluate) under this resolver's [`PacPolicy`].
/// 5. [`Pac`](crate::ProxyMode::Pac) / [`WpadAutoDetect`](crate::ProxyMode::WpadAutoDetect)
///    with a native resolver attached (`with_native`): `WinHttpPacResolver::resolve_config`
///    (Windows + `pac-windows-native`) or `CfNetworkPacResolver::resolve_config` (macOS +
///    `pac-macos-native`, iOS + `pac-ios-native`), which downloads, and discovers once the resolver was built
///    `with_wpad(true)`; `AndroidPacResolver::resolve_config` (Android +
///    `pac-android-native`), which asks the system PAC service through `ProxySelector`.
/// 6. Otherwise what [`resolve_with_pac`](crate::resolve_with_pac) says: `Pac` →
///    [`Error::PacFetchRequired`], `WpadAutoDetect` → [`Error::PacNotSupported`].
///
/// A failure is reported, never retried on the other engine: a native error does not fall
/// back to JS, and a JS error does not fall back to the native one. The two engines
/// disagree about what a script is allowed to see: [`PacPolicy`] governs the JS engine
/// only, and the native one uses real DNS and the real local address, so a silent retry
/// would change which policy produced the answer.
///
/// The two budgets are independent: [`PacPolicy::timeout`] bounds a JS evaluation, and the
/// WinHTTP and CFNetwork resolvers' `timeout` bounds a native resolution, download and
/// discovery included. The Android resolver has no timeout of its own.
///
/// With no evaluator attached and no QuickJS engine compiled in (`pac-quickjs` off, or on
/// Android or iOS, where the feature builds without one), the JS arms are
/// [`Error::PacEngineUnavailable`].
///
/// ```
/// # #[cfg(pac_quickjs)] {
/// use proxy_watch::pac::{PacPolicy, PacResolver};
/// use proxy_watch::{ProxyConfig, ProxyConfigSource, ProxyMode, ProxyStep, Url};
///
/// let mode = ProxyMode::pac_inline(
///     "function FindProxyForURL(u, h) { return 'DIRECT'; }".to_owned(),
/// );
/// let config = ProxyConfig::from_source(ProxyConfigSource::Registry, mode);
/// let url = Url::parse("http://example.net/").unwrap();
///
/// let resolver = PacResolver::new(PacPolicy::new());
/// assert_eq!(resolver.resolve_config(&config, &url, None)?, vec![ProxyStep::Direct]);
/// # }
/// # Ok::<(), proxy_watch::Error>(())
/// ```
pub struct PacResolver {
    policy: PacPolicy,
    evaluator: Option<Box<dyn PacEvaluator + Send + Sync>>,
    #[cfg(pac_native)]
    native: Option<Native>,
}

impl PacResolver {
    /// A resolver that runs PAC scripts under `policy` and has no native engine attached.
    #[must_use]
    pub fn new(policy: PacPolicy) -> Self {
        Self {
            policy,
            evaluator: None,
            #[cfg(pac_native)]
            native: None,
        }
    }

    /// Attach the native resolver (`WinHttpPacResolver` on Windows, `CfNetworkPacResolver`
    /// on macOS and iOS, `AndroidPacResolver` on Android) for
    /// [`Pac`](crate::ProxyMode::Pac) and
    /// [`WpadAutoDetect`](crate::ProxyMode::WpadAutoDetect) with no caller-supplied script.
    ///
    /// Takes a built resolver rather than building one, so that a failure to open a
    /// session is the caller's to see, not a silent fall back to "fetch it yourself", and
    /// so that its `with_wpad` choice is the caller's.
    #[cfg(pac_native)]
    #[must_use]
    pub fn with_native(mut self, native: Native) -> Self {
        self.native = Some(native);
        self
    }

    /// Attach this target's native resolver, built with its defaults (WPAD off), when a
    /// `pac-*-native` feature enables one; otherwise return `self` unchanged. Available
    /// without `cfg` guards in cross-platform applications.
    ///
    /// # Errors
    ///
    /// What building the native resolver returns: on Windows, a WinHTTP session that
    /// fails to open.
    pub fn with_system_native(self) -> Result<Self, Error> {
        #[cfg(pac_native)]
        let resolver = self.with_native(open_native()?);
        #[cfg(not(pac_native))]
        let resolver = self;
        Ok(resolver)
    }

    /// The attached native resolver, if any.
    #[cfg(pac_native)]
    #[must_use]
    pub fn native(&self) -> Option<&Native> {
        self.native.as_ref()
    }

    /// Run the JS arms on `evaluator` instead of [`evaluate`](super::evaluate), for example
    /// a `SubprocessEvaluator` (feature `pac-subprocess`), so that a script from the
    /// configuration runs in a worker process.
    ///
    /// The evaluator runs under the policy it was built with; this resolver's
    /// [`policy`](Self::policy) then governs nothing. The native arm is unchanged: a native
    /// resolver still answers URL and WPAD modes when no script is passed.
    #[must_use]
    pub fn with_evaluator(mut self, evaluator: impl PacEvaluator + Send + Sync + 'static) -> Self {
        self.evaluator = Some(Box::new(evaluator));
        self
    }

    /// The policy [`evaluate`](super::evaluate) runs under when no evaluator is attached.
    #[must_use]
    pub fn policy(&self) -> &PacPolicy {
        &self.policy
    }

    /// Resolve `url` under `config`, routing as the type documentation lists.
    ///
    /// # Errors
    ///
    /// Whatever the engine the mode routed to returns: [`resolve_with_pac`]'s errors for the
    /// JS arms and the fall-through (an attached evaluator's own errors in place of
    /// [`evaluate`](super::evaluate)'s), and the native resolver's `resolve_config`'s for the
    /// native arm.
    ///
    /// [`resolve_with_pac`]: crate::resolve_with_pac
    pub fn resolve_config(
        &self,
        config: &ProxyConfig,
        url: &Url,
        script: Option<&PacScript>,
    ) -> Result<Vec<ProxyStep>, Error> {
        #[cfg(pac_native)]
        if let Some(native) = &self.native
            && script.is_none()
            && matches!(
                config.effective,
                crate::ProxyMode::Pac { .. } | crate::ProxyMode::WpadAutoDetect
            )
        {
            return native.resolve_config(config, url);
        }
        crate::resolve::resolve_with_pac_using(config, url, script, |script| {
            match &self.evaluator {
                Some(evaluator) => evaluator.evaluate(
                    script,
                    &super::sanitize_url(url),
                    url.host_str().unwrap_or_default(),
                ),
                None => super::evaluate(script, url, &self.policy),
            }
        })
    }
}

#[cfg(all(windows, feature = "pac-windows-native"))]
fn open_native() -> Result<Native, Error> {
    Native::new()
}

#[cfg(all(pac_native, not(windows)))]
fn open_native() -> Result<Native, Error> {
    Ok(Native::new())
}

impl std::fmt::Debug for PacResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("PacResolver");
        debug
            .field("policy", &self.policy)
            .field("evaluator", &self.evaluator.as_ref().map(|_| "attached"));
        #[cfg(pac_native)]
        debug.field("native", &self.native);
        debug.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProxyConfigSource, ProxyMode};

    // Whether or not this build has a native resolver, attaching it leaves the other arms
    // answering as before.
    #[test]
    fn attaching_the_system_native_keeps_direct_direct() {
        let resolver = PacResolver::new(PacPolicy::new())
            .with_system_native()
            .unwrap();
        #[cfg(pac_native)]
        assert!(resolver.native().is_some());
        let config = ProxyConfig::from_source(ProxyConfigSource::Env, ProxyMode::Direct);
        let url = Url::parse("http://example.net/").unwrap();
        assert_eq!(
            resolver.resolve_config(&config, &url, None).unwrap(),
            vec![ProxyStep::Direct]
        );
    }
}
