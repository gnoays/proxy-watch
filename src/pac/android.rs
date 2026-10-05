//! `pac-android-native`: PAC through the framework's `java.net.ProxySelector` (Android only).
//!
//! Android evaluates PAC in a system service, and the selector the framework installs for a
//! PAC configuration asks that service for each URL. So this resolver runs no script and
//! downloads nothing: it asks the question `java.net` clients in the same process ask.

use url::Url;

use crate::config::{ProxyConfig, ProxyConfigSource};
use crate::error::Error;
use crate::mode::ProxyMode;
use crate::resolve::ProxyStep;

/// Resolves the [`Pac`](ProxyMode::Pac) configuration `ConnectivityManager` reports by
/// asking `ProxySelector.getDefault().select(uri)`.
///
/// The selector answers from the system settings as they are at the call, not from the
/// [`ProxyConfig`] passed in, so only a `Pac` mode that came from
/// [`ConnectivityManager`](ProxyConfigSource::ConnectivityManager) is resolved, and only
/// while the system still names the same PAC URL. The framework is reached the way reading the
/// settings reaches it: through the `JavaVM` and `Context` the host gave `android::init`,
/// or else the ones it registered with `ndk-context`.
///
/// [`PacPolicy`](crate::pac::PacPolicy) does not apply: the system service runs the script
/// with real DNS.
///
/// The selector answers `DIRECT` when the PAC service is unreachable or fails, and when the
/// script answers only with entries it cannot parse (it takes `DIRECT`, `PROXY` and `SOCKS`,
/// not `HTTPS` or `SOCKS5`), so a [`Direct`](ProxyStep::Direct) from this resolver can stand
/// for any of those.
#[derive(Debug, Clone, Default)]
pub struct AndroidPacResolver {
    _private: (),
}

impl AndroidPacResolver {
    /// A resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Like [`resolve_with_pac`](crate::resolve_with_pac), with the system PAC service
    /// evaluating the script. A URL with no host is Direct in every PAC mode.
    ///
    /// Blocks on the framework's call into the PAC service.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the framework cannot be reached, the system settings no longer
    /// name the PAC URL `config` holds, or the process's default `ProxySelector` is not the
    /// system's PAC selector (it is installed a moment after a switch to PAC, and an app
    /// can replace it), [`Error::PacInvalidResult`] for an answer with no element a client
    /// could use (an unusable element beside a usable one is skipped), and
    /// [`resolve`](crate::resolve())'s errors for every other mode.
    pub fn resolve_config(&self, config: &ProxyConfig, url: &Url) -> Result<Vec<ProxyStep>, Error> {
        let mode = &config.effective;
        match mode {
            ProxyMode::Pac { .. } | ProxyMode::PacInline { .. } | ProxyMode::WpadAutoDetect
                if !crate::endpoint::has_request_host(url) =>
            {
                Ok(vec![ProxyStep::Direct])
            }
            ProxyMode::Pac { url: pac_url, .. }
                if config.source(ProxyConfigSource::ConnectivityManager) == Some(mode) =>
            {
                resolve(url, pac_url)
            }
            _ => crate::resolve::resolve(config, url),
        }
    }
}

// Limitation: no timeout of its own; the framework's binder call is the only bound. Run
// it on a thread that may wait, and add a deadline if a PAC service is seen to hang.
fn resolve(url: &Url, pac_url: &Url) -> Result<Vec<ProxyStep>, Error> {
    let target = crate::pac::sanitize_url(url);
    let (live, selected) =
        crate::sys::android::select(&crate::sys::proxy_info::java_uri_text(&target))?;
    // A selector answering for other settings would answer for a later snapshot.
    let live = live.and_then(|live| Url::parse(&live).ok());
    if live.as_ref() != Some(pac_url) {
        return Err(Error::io(
            "resolving PAC through ProxySelector",
            std::io::Error::other("the system proxy settings no longer name this PAC script"),
        ));
    }
    let Some(selected) = selected else {
        return Err(Error::io(
            "resolving PAC through ProxySelector",
            std::io::Error::other(
                "the default ProxySelector is not the system's PacProxySelector: the process \
                 has not installed it yet, or the app replaced it",
            ),
        ));
    };
    crate::sys::proxy_info::steps_from_selected(&selected)
}
