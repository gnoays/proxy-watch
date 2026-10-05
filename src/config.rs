//! Snapshot type: [`ProxyConfig`] and provenance labels.

use std::time::SystemTime;

use crate::env::ProxyEnv;
use crate::mode::ProxyMode;

/// Where a [`ProxyMode`] came from. [`ProxyConfig`] keeps all of them for explanation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ProxyConfigSource {
    /// The per-user WinINet settings, read through
    /// `WinHttpGetIEProxyConfigForCurrentUser`, which answers for the *active* connection,
    /// so a VPN or dial-up connectoid carrying its own proxy is what this reports while it
    /// is up. When that call fails the backend falls back to the plain
    /// `HKCU\…\Internet Settings` values, which are the LAN connection's: the label is
    /// unchanged, the store behind it is not, and the two disagree exactly when a
    /// connectoid was in charge. This label alone does not say which of them answered.
    ///
    /// [`ProxyConfig::fallbacks`] says it for the failures where it is a loss. When the
    /// call reports that no Internet Explorer proxy settings exist (the documented
    /// `ERROR_FILE_NOT_FOUND`), the plain values are read from the same account's own hive.
    /// They are the answer itself, from a store documented to hold the same settings, and
    /// nothing is recorded, except under `ProxySettingsPerUser = 0`. Under that setting,
    /// Windows answers from the per-machine `Connections` blob instead and these per-user
    /// values are a store it is not reading. When it fails any other way, settings may have
    /// existed and gone unread, so this source appears in that list: the read did not learn
    /// the value it came for.
    Registry,
    /// Group policy `HKLM\Software\Policies\…\Internet Settings`. Recorded but never
    /// [`effective`](ProxyConfig::effective), because Windows does not read the values this
    /// crate reads from that key: no administrative template shipped with Windows writes
    /// `ProxyServer`, `ProxyEnable`, `AutoConfigURL` or `ProxyOverride` there
    /// (`C:\Windows\PolicyDefinitions\inetres.admx` defines `ProxySettingsPerUser` and
    /// nothing else under it), and `WinHttpGetIEProxyConfigForCurrentUser` answers the same
    /// with those values present as with the key empty. An administrator who wrote one by
    /// hand may have meant it, so it is reported from
    /// [`sources`](ProxyConfig::sources); acting on it would route through a proxy no other
    /// component on the machine uses.
    GroupPolicy,
    /// WinHTTP machine defaults (`netsh winhttp set proxy`). Recorded but never
    /// [`effective`](ProxyConfig::effective): Microsoft scopes this store to service and
    /// middle-tier processes rather than ranking it against the per-user settings, so the
    /// crate does not rank it either. A consumer that *is* a service reads it from
    /// [`sources`](ProxyConfig::sources).
    WinHttpDefault,
    /// macOS `Setup:/Network/Global/Proxies` (configured; loses to `State:`, but is the
    /// effective mode when there is no `State:` scope to lose to).
    SystemConfigurationSetup,
    /// macOS `State:/Network/Global/Proxies` (in effect; wins when both exist).
    SystemConfigurationState,
    /// GNOME `org.gnome.system.proxy`.
    GSettings,
    /// KDE `kioslaverc`.
    Kioslaverc,
    /// The process environment, read under the variable names a `kioslaverc` with
    /// `ProxyType = 4` chose: `httpProxy=MY_HTTP_VAR` names the *variable*, not the proxy.
    ///
    /// Separate from [`Env`](Self::Env) because only the store is shared: the naming rule
    /// is the file's, so the two can be read on one machine and disagree. Merged under a
    /// single label they would both land in [`sources`](ProxyConfig::sources) and
    /// [`ProxyConfig::source`] would answer with whichever came first, silently.
    ///
    /// The precedence slot is still `kioslaverc`'s: a `ProxyType = 4` file occupies the
    /// position any other `ProxyType` would, because the rule keys off the store that was
    /// read and not off the label it hands back.
    KioslavercEnv,
    /// XDG portal resolver. It answers already-resolved lookups, so a
    /// [`ProxyMode::Manual`] from this source always carries
    /// [`BypassRules`](crate::BypassRules) with no entries and no implicit set
    /// ([`ImplicitBypass::Empty`](crate::ImplicitBypass::Empty)): the portal applied the
    /// bypass itself and never discloses it.
    ///
    /// The lookup names a fixed reserved probe host and not the destination you are asking
    /// about, because the portal resolves per destination and a snapshot has none to give
    /// it. A host-side PAC that branches on the host name therefore answers about the probe:
    /// a [`ProxyMode::Direct`] from this source says the portal had no proxy *for the
    /// probe*, which is a weaker claim than the same value read out of a settings store.
    Portal,
    /// Process environment, under the `*_proxy` convention this crate reads directly
    /// ([`ProxyEnv`](crate::ProxyEnv)). A `kioslaverc` that names its own variables
    /// reports [`KioslavercEnv`](Self::KioslavercEnv) instead.
    Env,
    /// Android's `ConnectivityManager.getDefaultProxy()`: the proxy of the default network,
    /// or the global one when set, as the Java framework hands it to every app. It is what
    /// `java.net.ProxySelector.getDefault()` routes by, so a bypass list is read with that
    /// selector's rules rather than Chromium's.
    ConnectivityManager,
    /// iOS's `CFNetworkCopySystemProxySettings()`: the proxy of the active network, keyed
    /// like macOS's [`SystemConfigurationState`](Self::SystemConfigurationState).
    CfNetworkSystemSettings,
}

/// Point-in-time system proxy snapshot.
///
/// Backend-built: `sources` descending precedence, `effective` = first (or Direct).
/// [`ProxyConfig::from_ordered_sources`] enforces that invariant; [`ProxyConfig::new`]
/// remains available for caller-defined resolved configurations. [`PartialEq`] ignores
/// `captured_at`.
///
/// ```
/// # use proxy_watch::{ProxyConfig, ProxyConfigSource, ProxyMode};
/// # use std::time::SystemTime;
/// let a = ProxyConfig::from_source(ProxyConfigSource::Registry, ProxyMode::Direct);
/// let mut b = a.clone();
/// b.captured_at = SystemTime::UNIX_EPOCH;
/// assert_eq!(a, b);
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProxyConfig {
    /// Resolved mode after platform precedence.
    pub effective: ProxyMode,
    /// Descending precedence; backend snapshots: first wins (or Direct if empty).
    pub sources: Vec<(ProxyConfigSource, ProxyMode)>,
    /// Sources that were consulted, could not be read, and were left out of `sources`
    /// rather than failing the whole read.
    ///
    /// A source absent from both lists was not configured; a source listed here is one
    /// the machine may well be configured with, whose value this read did not learn.
    /// [`sources`](Self::sources) alone cannot express that. The log line that also records
    /// it reaches only a consumer built with the `tracing` feature.
    ///
    /// Backend snapshots only: nothing here is derived from the modes, so
    /// [`ProxyConfig::new`] and the constructors below leave it empty and
    /// [`ProxyConfig::with_fallbacks`] is what fills it in.
    ///
    /// Unlike `captured_at` this **is** compared by [`PartialEq`], so a watcher delivers
    /// the snapshot where a degradation appears or clears. Excluded, it would leave the
    /// watcher's equality skip holding the snapshot it already has, so a degradation that
    /// healed would be reported for the rest of the watcher's life.
    pub fallbacks: Vec<ProxyConfigSource>,
    /// Capture time; excluded from equality.
    pub captured_at: SystemTime,
}

impl ProxyConfig {
    /// Build a snapshot stamped with now.
    #[must_use]
    pub fn new(effective: ProxyMode, sources: Vec<(ProxyConfigSource, ProxyMode)>) -> Self {
        Self {
            effective,
            sources,
            fallbacks: Vec::new(),
            captured_at: SystemTime::now(),
        }
    }

    /// Record the sources this read could not learn the value of.
    ///
    /// See [`fallbacks`](Self::fallbacks). Takes the whole list rather than appending, so
    /// a backend that assembles one alongside its `sources` hands it over in one place.
    #[must_use]
    pub fn with_fallbacks(mut self, fallbacks: Vec<ProxyConfigSource>) -> Self {
        self.fallbacks = fallbacks;
        self
    }

    /// Build a snapshot from sources already ordered by descending precedence.
    ///
    /// The first mode becomes [`effective`](Self::effective); an empty list becomes
    /// [`ProxyMode::Direct`]. The source order and every losing source are preserved.
    #[must_use]
    pub fn from_ordered_sources(sources: Vec<(ProxyConfigSource, ProxyMode)>) -> Self {
        let effective = sources
            .first()
            .map_or(ProxyMode::Direct, |(_, mode)| mode.clone());
        Self::new(effective, sources)
    }

    /// Snapshot whose effective value comes from exactly one source.
    #[must_use]
    pub fn from_source(source: ProxyConfigSource, mode: ProxyMode) -> Self {
        Self::from_ordered_sources(vec![(source, mode)])
    }

    /// "No proxy" with no sources.
    #[must_use]
    pub fn direct() -> Self {
        Self::from_ordered_sources(Vec::new())
    }

    /// Mode for a specific source, if consulted.
    #[must_use]
    pub fn source(&self, source: ProxyConfigSource) -> Option<&ProxyMode> {
        self.sources
            .iter()
            .find(|(s, _)| *s == source)
            .map(|(_, mode)| mode)
    }

    /// Fold the process environment into this snapshot as one more source.
    ///
    /// The environment enters *whole*: one entry in [`sources`](Self::sources), ranked
    /// against the OS sources rather than merged into them slot by slot. Setting only
    /// `http_proxy` therefore does not leave the OS's https proxy in place; the winning
    /// source answers for every scheme, and an environment with no https entry resolves
    /// https to direct. `all_proxy` is how the environment covers the schemes it did not
    /// name.
    ///
    /// The fold depends on the environment's shape. [`ProxyEnv::is_configured`] separates
    /// the first shape from the other two; whether anything was *dropped* separates those,
    /// and [`ProxyEnv::rejected`] and [`ProxyEnv::bypass`]'s own rejections answer that.
    ///
    /// - **Configured**: it takes the rank `precedence` asks for. A `no_proxy` with no
    ///   proxy variable beside it is this shape, and [`ProxyEnv::to_mode`] turns it into
    ///   [`Direct`](ProxyMode::Direct): under [`BeforeSystem`](EnvPrecedence::BeforeSystem) it
    ///   does not *add* a bypass to the OS proxy, it outranks that proxy and every host
    ///   resolves direct. The result errs toward bypassing more than the caller listed,
    ///   never toward proxying a host they asked to exclude.
    /// - **Present but specifying nothing**: appended to `sources` and never made
    ///   [`effective`](Self::effective), so a typo cannot mask the OS. Where every `*_proxy`
    ///   value was malformed, [`ProxyEnv::to_mode`] answers `Manual` and the drops come back
    ///   out of [`source`](Self::source). Where instead a `no_proxy` lost every entry it held,
    ///   `to_mode` answers [`Direct`](ProxyMode::Direct), which has nowhere to hold an
    ///   exclusion list: the entry records only *that* the environment was there and lost
    ///   something, and the text of the drop stays on [`ProxyEnv::bypass`]`().rejected`.
    /// - **Specifying nothing and dropping nothing**: `self` is returned untouched. Usually
    ///   that means the variables are unset, but a `no_proxy` that parses to no rules and no
    ///   rejections (`no_proxy=`, `no_proxy=","`) lands here too: it was set, and the
    ///   snapshot keeps no evidence that it was.
    ///
    /// Being configured and having dropped something are not exclusive. `no_proxy=.corp`
    /// beside an `http_proxy` that does not parse is configured (the bypass list is the
    /// configuration), so it takes the rank, and the dropped scheme rides in with it:
    /// `http` then answers [`Error::ProxyEntryUnusable`](crate::Error::ProxyEntryUnusable)
    /// instead of falling through to the OS proxy or to direct.
    ///
    /// Fold an environment in once. A second `with_env` can leave a second
    /// [`Env`](ProxyConfigSource::Env) entry in `sources`, and [`source`](Self::source)
    /// answers with whichever is first, which the second environment's shape decides as
    /// much as the precedence does.
    ///
    /// [`captured_at`](Self::captured_at) becomes the older of the two reads, except in the
    /// third shape, where nothing is folded in. `effective` is otherwise left alone,
    /// including where that leaves it disagreeing with `sources[0]`.
    ///
    /// ```
    /// # use proxy_watch::{EnvPrecedence, ProxyConfig, ProxyConfigSource, ProxyEnv, ProxyMode};
    /// let env = ProxyEnv::from_vars([("http_proxy", "http://env.corp:3128")]).unwrap();
    /// let os = ProxyConfig::from_source(ProxyConfigSource::Registry, ProxyMode::Direct);
    ///
    /// let merged = os.with_env(&env, EnvPrecedence::BeforeSystem);
    /// assert!(matches!(merged.effective, ProxyMode::Manual { .. }));
    /// assert_eq!(merged.sources.len(), 2);
    /// assert!(merged.source(ProxyConfigSource::Registry).is_some());
    /// ```
    #[must_use]
    pub fn with_env(mut self, env: &ProxyEnv, precedence: EnvPrecedence) -> Self {
        // Left out only when the environment specifies nothing and dropped nothing, so a
        // drop still leaves an `Env` record. `no_proxy=` parses to neither and is left out.
        if !env.is_configured() && env.rejected().is_empty() && env.bypass().rejected.is_empty() {
            return self;
        }
        // `AfterSystem` takes over only when no OS source came back and `effective` is
        // still `Direct`. An earlier `Env` record is not an OS source (KDE's
        // environment-backed mode is labelled `KioslavercEnv`, so it is one), and the
        // `is_direct` test keeps an `effective` that a caller of [`ProxyConfig::new`]
        // supplied without sources.
        let wins = env.is_configured()
            && match precedence {
                EnvPrecedence::BeforeSystem => true,
                EnvPrecedence::AfterSystem => {
                    self.effective.is_direct()
                        && self
                            .sources
                            .iter()
                            .all(|(source, _)| *source == ProxyConfigSource::Env)
                }
            };
        let mode = env.to_mode();
        if wins {
            self.effective = mode.clone();
            self.sources.insert(0, (ProxyConfigSource::Env, mode));
        } else {
            // Malformed-only environment entries remain visible without replacing the
            // effective mode chosen by the OS or by `ProxyConfig::new`.
            self.sources.push((ProxyConfigSource::Env, mode));
        }
        // The same correction [`ProxyEnv::to_config`] makes, for the same reason.
        self.captured_at = self.captured_at.min(env.captured_at());
        self
    }
}

/// Where the process environment ranks against the OS settings in
/// [`ProxyConfig::with_env`].
///
/// A third ranking, "ignore the environment", is not a variant: a caller who wants the
/// environment ignored does not call `with_env`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum EnvPrecedence {
    /// The environment outranks every OS source. What a consumer layering a `*_proxy`
    /// reader over the system settings gets by default: Go's `golang.org/x/net/http/
    /// httpproxy` reads the variables and nothing else, so a caller who consults it first
    /// has already chosen this.
    BeforeSystem,
    /// The OS settings outrank the environment, which answers only when they produced no
    /// configuration at all. Not per scheme: one OS source is enough to settle every
    /// scheme, including the ones it says nothing about; [`ProxyConfig::with_env`] ranks
    /// sources, it does not fill slots. Chromium's
    /// `net/proxy_resolution/proxy_config_service_linux.cc` does this in the strong form:
    /// once the desktop settings have produced a configuration it never looks at the
    /// variables, a desktop mode of "none" counts as one, and reading `mode` always finds a
    /// value, so a stock desktop with no proxy configured still counts.
    ///
    /// This crate is a shade weaker on GNOME: it asks who wrote that `mode`, and only one
    /// that was set (in the user's dconf layer, or an administrator's profile) becomes a
    /// source. A machine whose proxy settings were never touched therefore reaches this
    /// rank with an empty `sources`, and the environment answers. An unset `mode` and a
    /// `mode` set to direct are different answers, and only the second should outrank a
    /// `*_proxy` an operator set.
    ///
    /// On Windows that leaves this a rank the environment never takes: `read` always
    /// reports a `Registry` source, `ProxyEnable = 0` included, so there is never a
    /// snapshot for the environment to answer for. macOS is nearly as closed: a scope the
    /// reader could interpret becomes a source whatever it says,
    /// [`Direct`](ProxyMode::Direct) included, so the environment answers only where
    /// *neither* `State:` nor `Setup:` came back (a missing key, a NULL, or a value that is
    /// not a dictionary); scopes that name no proxy do not qualify. Linux is where this
    /// rank applies: desktop stores that exist and are unset produce a snapshot with no
    /// source at all. So does the degraded case beside it (the store this session's desktop
    /// would normally use compiled out of the build while the other one is unset), where
    /// the empty `sources` means "never consulted" rather than "found nothing", which only
    /// [`fallbacks`](ProxyConfig::fallbacks) records.
    /// A machine with no desktop store *at all* is not this case: `read` fails with
    /// [`Error::Unsupported`](crate::Error::Unsupported), so there is no snapshot to fold an
    /// environment into.
    ///
    /// Even a rank the environment never takes differs from the "ignore" this enum leaves
    /// out, which is a caller not folding at all: a rank settles only `effective`, and the
    /// rest of the fold happens either way, so the environment lands in
    /// [`sources`](ProxyConfig::sources) and [`captured_at`](ProxyConfig::captured_at) drops
    /// to the older of the two reads even where this one can never win.
    AfterSystem,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self::direct()
    }
}

impl PartialEq for ProxyConfig {
    // Everything but `captured_at`; see type docs, and `fallbacks` for why that field is
    // on this side of the line rather than beside the timestamp.
    fn eq(&self, other: &Self) -> bool {
        self.effective == other.effective
            && self.sources == other.sources
            && self.fallbacks == other.fallbacks
    }
}

impl Eq for ProxyConfig {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_sources_derive_the_effective_mode_without_dropping_provenance() {
        let sources = vec![
            (ProxyConfigSource::GroupPolicy, ProxyMode::Direct),
            (ProxyConfigSource::Registry, ProxyMode::WpadAutoDetect),
        ];
        let config = ProxyConfig::from_ordered_sources(sources.clone());
        assert_eq!(config.effective, ProxyMode::Direct);
        assert_eq!(config.sources, sources);
    }

    // Snapshots that agree on every mode still differ when one lost a source. Without
    // `fallbacks` in `PartialEq`, the watcher never reports that a degradation cleared.
    #[test]
    fn a_source_that_could_not_be_read_is_not_the_same_snapshot_as_one_that_was_absent() {
        let complete = ProxyConfig::from_source(ProxyConfigSource::Registry, ProxyMode::Direct);
        let degraded = complete
            .clone()
            .with_fallbacks(vec![ProxyConfigSource::GroupPolicy]);
        assert_eq!(complete.effective, degraded.effective);
        assert_eq!(complete.sources, degraded.sources);
        assert_ne!(complete, degraded);
    }

    #[test]
    fn no_ordered_sources_means_direct() {
        let config = ProxyConfig::from_ordered_sources(Vec::new());
        assert_eq!(config.effective, ProxyMode::Direct);
        assert!(config.sources.is_empty());
    }
}
