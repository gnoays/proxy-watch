//! Windows backend.
//!
//! # Reading
//!
//! Per-user via [`WinHttpGetIEProxyConfigForCurrentUser`] (not undocumented
//! `DefaultConnectionSettings` binary). [`IeProxyConfig`] `GlobalFree`s the `PWSTR`s.
//! On *any* failure (typically `ERROR_FILE_NOT_FOUND`: no user profile), falls back to
//! registry `ProxyEnable` / `ProxyServer` / `ProxyOverride` / `AutoConfigURL` /
//! `AutoDetect`. A failure that was not `ERROR_FILE_NOT_FOUND` also lands in
//! [`ProxyConfig::fallbacks`](crate::ProxyConfig::fallbacks), because then the fallback is
//! standing in for settings that may have existed — see [`read_user_mode`].
//!
//! # Precedence
//!
//! [`ProxyConfigSource::Registry`] → informational [`ProxyConfigSource::GroupPolicy`] (if
//! [`WatchOptions::watch_group_policy`](crate::WatchOptions::watch_group_policy) and
//! [`decides_whether_to_proxy`]) → informational [`ProxyConfigSource::WinHttpDefault`]
//! (`netsh winhttp` / [`WinHttpGetDefaultProxyConfiguration`]). `effective` = first entry,
//! so only the per-user store is ever it — see [`in_precedence_order`] for why neither of
//! the other two leads. Per-connection: the IE call above is documented as returning "the proxy settings
//! for the current active connection" — LAN, dial-up and VPN alike — so an active
//! connectoid's settings are what this backend reads. What it never does is enumerate
//! connectoids or read an inactive one, and the registry fallback reads the per-user LAN
//! values rather than the `Connections` blobs those settings are stored in.

// `pub(crate)` rather than private: the `pac-windows-native` evaluator
// (`crate::pac::winhttp`) reuses the `Event` RAII wrapper, the UTF-16 helpers and the
// error mapping from here rather than growing a second copy of them.
pub(crate) mod ffi;
mod notify;

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, GlobalFree, HGLOBAL};
use windows::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE, WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_ACCESS_TYPE_NO_PROXY,
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO, WinHttpGetDefaultProxyConfiguration,
    WinHttpGetIEProxyConfigForCurrentUser,
};
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
use windows::core::HRESULT;

use crate::config::{ProxyConfig, ProxyConfigSource};
use crate::error::Error;
use crate::mode::ProxyMode;
use crate::parse;
use crate::watch::WatchOptions;

pub(crate) use self::notify::Watch;

use self::ffi::{RegKey, hresult_error, wide_ptr_to_string};

// The per-user WinINet settings key.
const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

// The per-machine group policy key (see the module docs above for how this crate orders it
// against HKCU).
//
// Not the "Make proxy settings per-machine rather than per-user" GPO's doing, whatever the
// name suggests: `inetres.admx` gives that policy one value here, `ProxySettingsPerUser`,
// which selects between the per-user and per-machine stores rather than holding a proxy —
// and this crate never reads it. No administrative template shipped with Windows writes any
// of the values `mode_from_registry` looks for under this key, so what is read here was put
// there directly. One of those names does ship: `inetres.admx` writes `AutoDetect` under
// `…\Internet Settings\ZoneMap`, which is "automatically detect intranet network", a zone
// setting — and nothing here opens a subkey, so a search by value name alone misreads it.
//
// Windows does not read them either. Under a process-local `RegOverridePredefKey` that puts
// `ProxyEnable`, `ProxyServer` and `AutoConfigURL` under this key,
// `WinHttpGetIEProxyConfigForCurrentUser` answers exactly as it does with the key empty. The
// override does reach WinINet — adding `ProxySettingsPerUser = 0` to the same key flips the
// `fAutoDetect` it returns, because that value *is* honoured and switches it to the
// per-machine store — so the silence about the proxy values is a measurement and not a call
// that never looked.
//
// So an entry from this key is reported and never `effective`: it says a value is present
// that nothing on the machine acts on, which is worth reporting and is not an answer.
const POLICY_INTERNET_SETTINGS: &str =
    r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";

// Read the current configuration: the registry and the WinHTTP default unconditionally,
// group policy only when the options ask for it. `# Precedence` above has the order.
pub(crate) fn read_config(options: &WatchOptions) -> Result<ProxyConfig, Error> {
    let mut fallbacks = Vec::new();

    // Group policy is reported and never `effective`, so no failure of it fails the read.
    let policy = if options.watch_group_policy {
        group_policy_source(read_group_policy_mode, &mut fallbacks)
    } else {
        None
    };
    // The one read on the critical path, and the one that answers.
    let user = read_user_mode(IeProxyConfig::query, &mut fallbacks)?;
    // Read after the `?` above on purpose: a per-user read that failed takes the whole call
    // down, and the machine default is then never asked for.
    let machine = winhttp_default_source(WinHttpDefaultConfig::query, &mut fallbacks);

    let config = ProxyConfig::from_ordered_sources(in_precedence_order(policy, user, machine))
        .with_fallbacks(fallbacks);
    crate::trace::debug!(
        config = %crate::trace::ConfigSummary(&config),
        "read the Windows proxy configuration"
    );
    Ok(config)
}

// The sources [`read_config`] gathered, in descending precedence.
//
// The WinHTTP machine default goes *after* the per-user entry, and is therefore never
// `effective`. Not because Windows ranks the two below one another — it does not rank them
// at all. Microsoft's guidance splits them by *environment*: a WinHTTP application in a
// middle-tier server environment "should rely on a server administrator setting a default
// proxy configuration in the registry", read back with `WinHttpGetDefaultProxyConfiguration`
// or `WINHTTP_ACCESS_TYPE_PRECONFIG`, while "a WinHTTP application running on a client
// desktop machine can attempt to examine Internet Explorer's proxy settings" (*Discovery
// Without an Auto-Config File*, WinHTTP). Neither is offered as the other's fallback, and
// the per-user call's own page says it "is only useful when called within a process that is
// running under an interactive user account identity".
//
// So the order is this crate's choice, and what settles it is that no shipping reader of the
// per-user path makes the other one a fallback either. Chromium answers a failed
// `WinHttpGetIEProxyConfigForCurrentUser` with `CreateDirect()` and never asks for the
// machine default (`proxy_config_service_win.cc`); .NET's `WinInetProxyHelper` ignores the
// error and carries an empty configuration. [`read_user_mode`] is already the more generous
// of the three — it falls back to the plain HKCU values — and promoting the machine default
// above even that would leave this crate alone in answering a desktop machine with a setting
// its administrator wrote for services. A consumer that *is* a service is not left without
// it: the entry is in `sources`, which is the whole reason it is read.
//
// The group policy entry goes *after* the per-user one for a different reason, measured
// rather than chosen: nothing on Windows reads the values this crate reads from that key.
// See [`POLICY_INTERNET_SETTINGS`] for the run. Ranking it first meant `effective` could be
// a proxy no other program on the machine would route through, which is the one way a
// precedence order can be wrong rather than merely unlike someone else's.
//
// It stays in `sources` because a value sitting under the policy key is still worth
// reporting — an administrator put it there, and a consumer that wants to say so can.
//
// Here rather than inline in its one caller because the order *is* the answer —
// [`ProxyConfig::from_ordered_sources`] makes the first entry `effective` — and the only
// test that pinned it, `tests/read_once.rs`'s
// `the_winhttp_machine_default_never_outranks_the_per_user_registry`, can compare no two
// positions the host does not report. A machine that never ran `netsh winhttp set proxy`
// reports no `WinHttpDefault` entry at all, so on that host the comparison is skipped and
// swapping the two lines below stays green. Taking the entries as values puts every
// combination in reach of every host, which is what the test beside this one uses.
fn in_precedence_order(
    policy: Option<(ProxyConfigSource, ProxyMode)>,
    user: ProxyMode,
    machine: Option<(ProxyConfigSource, ProxyMode)>,
) -> Vec<(ProxyConfigSource, ProxyMode)> {
    let mut sources = vec![(ProxyConfigSource::Registry, user)];
    sources.extend(policy);
    sources.extend(machine);
    sources
}

// The group policy entry for [`read_config`], or `None` when there is none to report.
//
// `read` is [`read_group_policy_mode`], taken as a parameter so the rule below can be
// exercised without an HKLM key to arrange. *Every* failure softens, and the reason is
// [`in_precedence_order`]: this entry is never `effective`, so a read of it that failed
// costs the caller a line in `sources` and changes no answer. Propagating would fail a call
// that was going to route through HKCU either way — a spurious error on a machine that is
// correctly configured for its user, thrown because a store nothing consults was
// unreadable or held a malformed URL.
//
// That is a change of rule and not of taste. While the policy key led the order, refusing a
// value it handed over was the only way to stop a mistyped policy `AutoConfigURL` from
// silently reinstating the per-user proxy it was written to replace, and `ERROR_MORE_DATA`
// had to propagate on top of that so a policy being edited mid-read did not hand the answer
// to HKCU for as long as the editing lasted. Neither holds once HKCU is the answer.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn group_policy_source(
    read: impl FnOnce() -> Result<Option<ProxyMode>, Error>,
    fallbacks: &mut Vec<ProxyConfigSource>,
) -> Option<(ProxyConfigSource, ProxyMode)> {
    match read() {
        Ok(Some(mode)) => Some((ProxyConfigSource::GroupPolicy, mode)),
        Ok(None) => None,
        Err(error) => {
            crate::trace::warning!(
                error = %crate::trace::SafeError(&error),
                "reading the HKLM group policy Internet Settings key failed; \
                 continuing with the per-user configuration alone"
            );
            // The `None` above and this one are the same value to the caller and not the
            // same fact: that one is a machine with no policy, this one is a machine whose
            // policy this process could not read. Only the second is recorded, which is
            // what keeps [`ProxyConfig::fallbacks`](crate::ProxyConfig::fallbacks) a list
            // of things that went wrong rather than a list of stores that exist.
            fallbacks.push(ProxyConfigSource::GroupPolicy);
            None
        }
    }
}

// Open the HKLM group policy key and read its mode, `Ok(None)` when the key is absent
// or carries nothing that decides whether to proxy ([`decides_whether_to_proxy`]).
//
// This is the fallible core [`group_policy_source`] wraps and softens; kept separate so
// the `?`-propagating logic reads exactly like [`read_user_mode`]'s.
fn read_group_policy_mode() -> Result<Option<ProxyMode>, Error> {
    let Some(key) = RegKey::open(
        HKEY_LOCAL_MACHINE,
        POLICY_INTERNET_SETTINGS,
        KEY_READ,
        "opening HKLM group policy Internet Settings key",
    )?
    else {
        return Ok(None);
    };
    mode_from_registry(&key)
}

// The per-user mode: WinHTTP first, plain registry values as the fallback.
//
// `query` is injected for the same reason [`group_policy_source`] and
// [`winhttp_default_source`] inject theirs: which of the two stores answered is decided by
// how the call failed, and no machine can be made to fail it both ways.
//
// Every failure still softens, and only some of them are recorded. The split is the one
// Microsoft's own page draws: `ERROR_FILE_NOT_FOUND` is "No Internet Explorer proxy settings
// can be found", and for the account that call ran under, the plain HKCU values read below
// are then not a substitute for the answer — they *are* it, from the store that holds the
// same settings. Under `ProxySettingsPerUser = 0` they are not: Windows answers from the
// per-machine `Connections` blob, which this backend does not read, so what is read below is
// a per-user store nothing consults. Any other code is a call that failed while
// settings may well have existed, and what is read instead comes from a different
// connection: the API answers for the *active* connectoid, these values are the LAN one's.
// That is the case [`ProxyConfigSource::Registry`]'s "still answered, from a store that is
// documented to hold the same settings" does not cover, and the one this records.
//
// It records rather than propagates because the page's list is open — "Among the error codes
// returned are the following" — so refusing every unlisted code would fail reads on machines
// Microsoft never enumerated, and because no shipping reader of this API propagates either
// (Chromium answers a failed call with `CreateDirect()`, .NET's `WinInetProxyHelper` carries
// an empty configuration). Recording keeps the answer those two also give while letting a
// caller that cares see that the connectoid's view was lost, which is what neither of them
// offers and what tracing alone did not: `fallbacks` is compared by
// [`PartialEq`](ProxyConfig), so a watcher delivers the snapshot where this appears.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn read_user_mode(
    query: impl FnOnce() -> Result<IeProxyConfig, windows::core::Error>,
    fallbacks: &mut Vec<ProxyConfigSource>,
) -> Result<ProxyMode, Error> {
    match query() {
        Ok(config) => config.to_mode(),
        Err(error) => {
            let lost_the_active_connection =
                error.code() != HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
            let error = hresult_error("WinHttpGetIEProxyConfigForCurrentUser", error);
            if lost_the_active_connection {
                crate::trace::warning!(
                    error = %crate::trace::SafeError(&error),
                    "WinHttpGetIEProxyConfigForCurrentUser failed for a reason other than \
                     having no settings to report; reading the plain HKCU registry values \
                     instead, which are the LAN connection's and not the active one's"
                );
                fallbacks.push(ProxyConfigSource::Registry);
            } else {
                // The account has no Internet Explorer settings to report. A service is
                // not automatically that account: LocalSystem gets `Ok` from this call
                // on Windows 11, per-machine policy or not.
                crate::trace::fallback(
                    "WinHttpGetIEProxyConfigForCurrentUser reports no Internet Explorer \
                     proxy settings; reading the documented plain HKCU registry values \
                     instead",
                    &error,
                );
            }
            let key = RegKey::open(
                HKEY_CURRENT_USER,
                INTERNET_SETTINGS,
                KEY_READ,
                "opening HKCU Internet Settings key",
            )?;
            match key {
                Some(key) => Ok(mode_from_registry(&key)?.unwrap_or(ProxyMode::Direct)),
                None => Ok(ProxyMode::Direct),
            }
        }
    }
}

// Turn the documented plain registry values into a [`ProxyMode`].
//
// Each read folds a value stored under a type that name does not carry into "absent"
// ([`RegKey::dword_value`], [`RegKey::string_value`]). For `ProxyEnable` that costs more
// than the one value: with no `AutoConfigURL` or `AutoDetect` beside it,
// [`decides_whether_to_proxy`] sees a key that said nothing about *whether* to proxy, so the `ProxyServer` beside it is
// never reached however well formed it is, and this returns `Ok(None)` — `Direct` under
// HKCU, *no policy at all* under group policy. `ProxyEnable` is stored as a `REG_SZ` on
// some real machines (psf/requests#4373, "no idea why, but it happens"); what Windows
// itself makes of one is not settled here, and this crate guesses at neither reading.
fn mode_from_registry(key: &RegKey) -> Result<Option<ProxyMode>, Error> {
    let enable = key.dword_value("ProxyEnable")?;
    let server = key.string_value("ProxyServer")?;
    let overrides = key.string_value("ProxyOverride")?;
    let auto_config_url = key.string_value("AutoConfigURL")?;
    let auto_detect = key.dword_value("AutoDetect")?;

    if !decides_whether_to_proxy(enable, auto_config_url.as_deref(), auto_detect) {
        return Ok(None);
    }

    let server = server.filter(|_| static_server_is_enabled(enable));
    Ok(Some(resolve_mode(
        auto_detect == Some(1),
        auto_config_url.as_deref(),
        server.as_deref(),
        overrides.as_deref(),
    )?))
}

// Whether the values read from an `Internet Settings` key are enough to decide a
// [`ProxyMode`] at all. `ProxyServer` and `ProxyOverride` deliberately do not count: they
// say *which* proxy, not whether to use one, and a key carrying only those would otherwise
// resolve to [`ProxyMode::Direct`].
//
// Only the group policy path can observe the difference. Under HKCU a `false` here becomes
// `Direct` anyway ([`read_user_mode`]), so what this decides is whether a
// [`ProxyConfigSource::GroupPolicy`] entry appears in `sources` at all — and since
// [`in_precedence_order`] keeps that entry out of `effective`, the stake is a reported
// source and not a masked answer. Whether `AutoDetect = 0` alone should count is open only
// while the stake is the answer; as a matter of what to report, a key that named the
// mechanism even to switch it off has said something, and it stays.
fn decides_whether_to_proxy(
    enable: Option<u32>,
    auto_config_url: Option<&str>,
    auto_detect: Option<u32>,
) -> bool {
    let has_pac_url = auto_config_url.is_some_and(|url| !url.trim().is_empty());
    enable.is_some() || has_pac_url || auto_detect.is_some()
}

// Whether `ProxyEnable` switches the static `ProxyServer` beside it on. Exactly `1`; what
// any other non-zero value would mean is not settled here. WinINet does read these plain
// per-user values — writing `ProxyEnable = 1` and a `ProxyServer` to the real HKCU key
// routes traffic through it — so the question is a real one, and a process-local
// `RegOverridePredefKey` cannot answer it: an HKCU shadow is invisible to WinINet, which
// keeps answering from the live key, so every shadowed value reports the same nothing. Read
// a shadow back with `RegGetValueW` and all that is established is that the *calling
// process* sees it. Chromium does not interpret the value either — it calls
// `WinHttpGetIEProxyConfigForCurrentUser` and watches these keys only for change
// notification. So `1` is the only reading with something behind it, and a value this crate
// cannot read stays off rather than being promoted to a proxy nobody asked for. Both registry readers
// ([`mode_from_registry`] and [`wpad_fallback_from_key`]) ask this one question, and an
// answer settled in one copy alone leaves the other reading it differently. Whether the
// server value is usable at all is a different question, asked by [`resolve_mode`] and
// [`wpad_fallback_beneath`] because the WinHTTP path reaches them without a switch to
// consult.
fn static_server_is_enabled(enable: Option<u32>) -> bool {
    enable == Some(1)
}

// Collapse the WinINet values below into one [`ProxyMode`].
fn resolve_mode(
    auto_detect: bool,
    auto_config_url: Option<&str>,
    server: Option<&str>,
    overrides: Option<&str>,
) -> Result<ProxyMode, Error> {
    if auto_detect {
        return Ok(ProxyMode::WpadAutoDetect);
    }
    if let Some(url) = auto_config_url.map(str::trim).filter(|u| !u.is_empty()) {
        let url = url::Url::parse(url).map_err(|source| Error::invalid_proxy_url(url, source))?;
        return Ok(ProxyMode::pac(url));
    }
    match server.map(str::trim).filter(|s| !s.is_empty()) {
        Some(server) => Ok(parse::windows_manual(server, overrides.unwrap_or_default())),
        None => Ok(ProxyMode::Direct),
    }
}

// Re-derive what WinINet would fall through to below auto-detect, in the per-user store —
// [`read_user_mode`]'s own precedence, WinHTTP's view of it first and the plain registry
// values as its fallback.
//
// Both remaining steps come back, not the first of them: see [`wpad_fallback_beneath`] for
// why collapsing them into one [`ProxyMode`] lost a configured static proxy.
//
// It names the store instead of taking a [`ProxyConfigSource`] to pick one. Do not
// re-parameterise it. A wildcard arm reading this store for *every* source
// but `GroupPolicy` assumes every other one able to produce
// `ProxyMode::WpadAutoDetect` is this store. That holds for what [`read_config`] builds and
// not for what a caller can hand [`resolve_config`](crate::pac::WinHttpPacResolver): both
// macOS scopes, `GSettings` and `Kioslaverc` all produce that mode in production, and none of
// them is a Windows registry, so a snapshot read on one of those machines would answer with
// this machine's proxy. A `GroupPolicy` arm reading `HKLM\…\Policies\…\Internet Settings` and
// turning it into a route is what `effective` refuses, for the
// reason [`ProxyConfigSource::GroupPolicy`] gives: no administrative template writes
// proxy values under that key, `WinHttpGetIEProxyConfigForCurrentUser` answers the same with
// them present as with the key empty, and routing on them would use a proxy nothing else on
// the machine uses. `resolve_wpad_with_fallback` asks here only when the per-user entry is
// the one carrying `effective`.
#[cfg(feature = "pac-windows-native")]
pub(crate) fn wpad_fallback() -> Result<(Option<url::Url>, ProxyMode), Error> {
    match IeProxyConfig::query() {
        Ok(config) => Ok(config.to_fallback_beneath()),
        Err(error) => {
            // Traced and not recorded, however it failed, because this runs only after
            // [`read_config`] already answered `WpadAutoDetect` from this same store —
            // so a failure worth recording was recorded there, against the snapshot the
            // caller holds. There is no second snapshot here to put it in.
            crate::trace::fallback(
                "WinHttpGetIEProxyConfigForCurrentUser failed while re-reading the \
                 WPAD fallback; reading the documented plain HKCU registry values \
                 instead",
                &hresult_error("WinHttpGetIEProxyConfigForCurrentUser", error),
            );
            let Some(key) = RegKey::open(
                HKEY_CURRENT_USER,
                INTERNET_SETTINGS,
                KEY_READ,
                "opening HKCU Internet Settings key for the WPAD fallback",
            )?
            else {
                return Ok((None, ProxyMode::Direct));
            };
            wpad_fallback_from_key(&key)
        }
    }
}

// The shared core of [`wpad_fallback`]'s registry-backed branches: read the values
// [`resolve_mode`] falls through to and re-derive them through [`wpad_fallback_beneath`],
// fail-soft on an unparsable `AutoConfigURL` (see its doc comment) rather than
// [`resolve_mode`]'s own fail-hard behaviour. Registry I/O failures still propagate.
#[cfg(feature = "pac-windows-native")]
fn wpad_fallback_from_key(key: &RegKey) -> Result<(Option<url::Url>, ProxyMode), Error> {
    let enable = key.dword_value("ProxyEnable")?;
    let server = key.string_value("ProxyServer")?;
    let overrides = key.string_value("ProxyOverride")?;
    let auto_config_url = key.string_value("AutoConfigURL")?;
    let server = server.filter(|_| static_server_is_enabled(enable));
    Ok(wpad_fallback_beneath(
        auto_config_url.as_deref(),
        server.as_deref(),
        overrides.as_deref(),
    ))
}

// The two steps configured *beneath* WPAD auto-detect: the `AutoConfigURL` WinHTTP can be
// asked to try in the same call, and the mode left to answer with once neither WPAD nor
// that URL has produced a usable script. Used only by [`wpad_fallback_from_key`] and
// [`IeProxyConfig::to_fallback_beneath`] — both reach here with `auto_detect` already
// forced to `false` by construction, which is why this takes no such parameter.
//
// A pair rather than one [`ProxyMode`], because collapsing to the first step lost the
// second. A key carrying both an `AutoConfigURL` and a `ProxyServer` came back as
// `ProxyMode::Pac`, and `resolve_wpad_with_fallback` then answered a WPAD-plus-PAC miss
// with `Direct` — sending a request out unproxied past a static proxy that was configured,
// enabled and perfectly usable. Both references continue to that proxy instead:
// Chromium's `ConfiguredProxyResolutionService::OnInitProxyResolverComplete` clears the
// automatic settings and logs "Failed configuring with PAC script, falling-back to manual
// proxy servers" when the script cannot be fetched or parsed, and Microsoft documents that
// "If a PAC file is not available, then the WinHttpGetProxyForUrl function fails. The
// WinHttpGetIEProxyConfigForCurrentUser function can be used as a fall-back mechanism to
// discover a workable proxy configuration" (*WinHttpGetIEProxyConfigForCurrentUser*).
//
// What neither reference licenses is continuing after a script that *ran*: Chromium's
// `DidFinishResolvingProxy` answers a non-mandatory resolver failure with `UseDirect()`,
// and the outcome this pair serves is the other one — `ERROR_WINHTTP_AUTODETECTION_FAILED`,
// which is a script that was never obtained.
//
// An `AutoConfigURL` this crate cannot parse comes back as `None` rather than an error: it
// is a URL nothing was going to fetch, and failing over it would cost the live WPAD probe
// that was about to run. [`resolve_mode`], on [`read_config`]'s main path, still fails hard
// on the same value.
#[cfg(feature = "pac-windows-native")]
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn wpad_fallback_beneath(
    auto_config_url: Option<&str>,
    server: Option<&str>,
    overrides: Option<&str>,
) -> (Option<url::Url>, ProxyMode) {
    let pac = auto_config_url
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .and_then(|raw_url| match url::Url::parse(raw_url) {
            Ok(url) => Some(url),
            Err(source) => {
                crate::trace::warning!(
                    error = %crate::trace::SafeError(&Error::invalid_proxy_url(raw_url, source)),
                    "AutoConfigURL configured beneath WPAD auto-detect could not be \
                     parsed while recovering the WPAD fallback; continuing with any \
                     static proxy configured beneath it instead of discarding it as \
                     Direct"
                );
                None
            }
        });
    let beneath = match server.map(str::trim).filter(|s| !s.is_empty()) {
        Some(server) => parse::windows_manual(server, overrides.unwrap_or_default()),
        None => ProxyMode::Direct,
    };
    (pac, beneath)
}

// The [`ProxyConfigSource::WinHttpDefault`] source for [`read_config`], or `None` when
// it does not apply.
//
// `query` is injected for the same reason [`group_policy_source`] injects its read: the two
// `None`s below are the whole point of the function and no machine can be made to produce
// both of them.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn winhttp_default_source(
    query: impl FnOnce() -> Result<WinHttpDefaultConfig, windows::core::Error>,
    fallbacks: &mut Vec<ProxyConfigSource>,
) -> Option<(ProxyConfigSource, ProxyMode)> {
    match query() {
        Ok(config) => Some((ProxyConfigSource::WinHttpDefault, config.to_mode())),
        Err(error) if error.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => {
            crate::trace::fallback(
                "WinHttpGetDefaultProxyConfiguration reports no WinHTTP machine default \
                 has ever been recorded on this machine (netsh winhttp); the \
                 WinHttpDefault source contributes nothing",
                &hresult_error("WinHttpGetDefaultProxyConfiguration", error),
            );
            None
        }
        Err(error) => {
            crate::trace::warning!(
                error = %crate::trace::SafeError(&hresult_error(
                    "WinHttpGetDefaultProxyConfiguration",
                    error,
                )),
                "reading the WinHTTP per-machine default proxy configuration failed; \
                 continuing without the WinHttpDefault source"
            );
            // The arm above is a machine where nobody ever ran `netsh winhttp`, which is
            // not a failure and is not recorded. This one is, and the difference matters
            // most to exactly the consumer this source is read for: a service reading
            // `sources` for the machine default cannot otherwise tell an administrator who
            // set none from a call that did not answer.
            fallbacks.push(ProxyConfigSource::WinHttpDefault);
            None
        }
    }
}

// Turn a `WINHTTP_PROXY_INFO` access type and its strings into a [`ProxyMode`].
fn winhttp_default_mode(
    access_type: WINHTTP_ACCESS_TYPE,
    server: Option<&str>,
    overrides: Option<&str>,
) -> ProxyMode {
    match access_type {
        WINHTTP_ACCESS_TYPE_NO_PROXY => ProxyMode::Direct,
        WINHTTP_ACCESS_TYPE_NAMED_PROXY => match server.map(str::trim).filter(|s| !s.is_empty()) {
            Some(server) => parse::windows_manual(server, overrides.unwrap_or_default()),
            None => ProxyMode::Direct,
        },
        _ => ProxyMode::Direct,
    }
}

// RAII wrapper around `WINHTTP_CURRENT_USER_IE_PROXY_CONFIG`.
//
// Its `PWSTR` members are allocated by WinHTTP and must be released with `GlobalFree` by
// the caller; `Drop` guarantees that even if converting the strings fails.
struct IeProxyConfig(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG);

impl IeProxyConfig {
    // The raw `windows::core::Error` rather than this crate's, for the same reason
    // [`WinHttpDefaultConfig::query`] keeps it: [`read_user_mode`] classifies the failure by
    // its Win32 code before deciding what to say about it, and [`hresult_error`] does not
    // carry one back out. [`wpad_fallback`] wraps it on the spot instead, having nothing to
    // classify for.
    fn query() -> Result<Self, windows::core::Error> {
        let mut raw = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
        // SAFETY: `raw` is a valid, writable, correctly sized out-parameter. On
        // success WinHTTP fills it in and transfers ownership of the string members to
        // us, which `Drop` releases.
        unsafe { WinHttpGetIEProxyConfigForCurrentUser(&raw mut raw) }?;
        Ok(Self(raw))
    }

    // The three string members as owned Rust strings, in the order the two `to_*_mode`
    // methods below take them. One function for both so that the pointers are read under
    // `unsafe` in one place rather than two identical ones.
    fn strings(&self) -> (Option<String>, Option<String>, Option<String>) {
        // SAFETY: the pointers are either null or NUL terminated UTF-16 strings owned
        // by `self`, so they are valid for the duration of the call.
        unsafe {
            (
                wide_ptr_to_string(self.0.lpszAutoConfigUrl.0),
                wide_ptr_to_string(self.0.lpszProxy.0),
                wide_ptr_to_string(self.0.lpszProxyBypass.0),
            )
        }
    }

    fn to_mode(&self) -> Result<ProxyMode, Error> {
        let (auto_config_url, server, overrides) = self.strings();
        resolve_mode(
            self.0.fAutoDetect.as_bool(),
            auto_config_url.as_deref(),
            server.as_deref(),
            overrides.as_deref(),
        )
    }

    // [`wpad_fallback`]'s per-user branch: the same values [`to_mode`](Self::to_mode)
    // reads, run back through [`wpad_fallback_beneath`] so the steps *below* auto-detect
    // come back instead. Cannot fail — there is no registry I/O left to do once the fields
    // are in hand.
    #[cfg(feature = "pac-windows-native")]
    fn to_fallback_beneath(&self) -> (Option<url::Url>, ProxyMode) {
        let (auto_config_url, server, overrides) = self.strings();
        wpad_fallback_beneath(
            auto_config_url.as_deref(),
            server.as_deref(),
            overrides.as_deref(),
        )
    }
}

impl Drop for IeProxyConfig {
    fn drop(&mut self) {
        for ptr in [
            self.0.lpszAutoConfigUrl.0,
            self.0.lpszProxy.0,
            self.0.lpszProxyBypass.0,
        ] {
            if !ptr.is_null() {
                // SAFETY: each non-null member was allocated by WinHTTP with
                // `GlobalAlloc`, is owned by `self`, and is freed exactly once because
                // `IeProxyConfig` is neither `Clone` nor otherwise duplicated.
                unsafe {
                    let _ = GlobalFree(Some(HGLOBAL(ptr.cast())));
                }
            }
        }
    }
}

// RAII wrapper around `WINHTTP_PROXY_INFO`, the WinHTTP per-machine default (module
// docs).
struct WinHttpDefaultConfig(WINHTTP_PROXY_INFO);

impl WinHttpDefaultConfig {
    fn query() -> Result<Self, windows::core::Error> {
        let mut raw = WINHTTP_PROXY_INFO::default();
        // SAFETY: `raw` is a valid, writable, correctly sized out-parameter. On
        // success WinHTTP fills it in and transfers ownership of the string members to
        // us, which `Drop` releases.
        unsafe { WinHttpGetDefaultProxyConfiguration(&raw mut raw) }?;
        Ok(Self(raw))
    }

    fn to_mode(&self) -> ProxyMode {
        // SAFETY: the pointers are either null or NUL terminated UTF-16 strings owned
        // by `self`, so they are valid for the duration of the call.
        let (server, overrides) = unsafe {
            (
                wide_ptr_to_string(self.0.lpszProxy.0),
                wide_ptr_to_string(self.0.lpszProxyBypass.0),
            )
        };
        winhttp_default_mode(self.0.dwAccessType, server.as_deref(), overrides.as_deref())
    }
}

impl Drop for WinHttpDefaultConfig {
    fn drop(&mut self) {
        for ptr in [self.0.lpszProxy.0, self.0.lpszProxyBypass.0] {
            if !ptr.is_null() {
                // SAFETY: each non-null member was allocated by WinHTTP with
                // `GlobalAlloc`, is owned by `self`, and is freed exactly once because
                // `WinHttpDefaultConfig` is neither `Clone` nor otherwise duplicated.
                unsafe {
                    let _ = GlobalFree(Some(HGLOBAL(ptr.cast())));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only the tests reach for it now that no read softens on it selectively.
    use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NOT_ENOUGH_MEMORY};
    // Named by `WinHttpGetIEProxyConfigForCurrentUser`'s page and by nothing this crate
    // reads, so it lives here rather than beside the classification it is a witness for.
    use windows::Win32::Networking::WinHttp::ERROR_WINHTTP_INTERNAL_ERROR;

    #[test]
    fn auto_detect_wins_over_everything() {
        let mode = resolve_mode(true, Some("http://wpad/x.pac"), Some("h:8080"), None).unwrap();
        assert_eq!(mode, ProxyMode::WpadAutoDetect);
    }

    #[test]
    fn pac_url_wins_over_static_servers() {
        let mode = resolve_mode(false, Some("http://wpad/x.pac"), Some("h:8080"), None).unwrap();
        assert!(matches!(mode, ProxyMode::Pac { .. }));
    }

    #[test]
    fn blank_values_are_ignored() {
        let mode = resolve_mode(false, Some("   "), Some(""), Some("<local>")).unwrap();
        assert_eq!(mode, ProxyMode::Direct);
    }

    #[test]
    fn manual_uses_the_shared_parsers() {
        let mode = resolve_mode(false, None, Some("h:8080"), Some("<local>;*.corp")).unwrap();
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        assert!(bypass.excludes_simple_hostnames());
        assert!(bypass.matches_authority("api.corp"));
    }

    // The two answers `group_policy_source` passes through and the three failures it
    // absorbs. None of the failures can reach the caller as an error any more — the entry
    // they would have carried is never `effective`, so failing the whole read on their
    // account would refuse a machine whose per-user store answers perfectly well. The three
    // are still every distinct failure this backend can produce here: a refused open
    // (`ERROR_ACCESS_DENIED`), a value read successfully and then rejected as malformed,
    // and a value that was being rewritten under the read (`ERROR_MORE_DATA`).
    //
    // What has to part company is therefore not the return value but the fallback list: a
    // machine with no policy at all is not degraded, a machine whose policy could not be
    // read is, and `read_config` cannot tell them apart by any other means.
    #[test]
    fn every_policy_read_that_failed_is_reported_as_no_policy_and_recorded() {
        let mut fallbacks = Vec::new();
        let entries = [
            group_policy_source(|| Ok(None), &mut fallbacks),
            group_policy_source(|| Ok(Some(ProxyMode::Direct)), &mut fallbacks),
            group_policy_source(
                || {
                    Err(Error::io(
                        "opening HKLM group policy Internet Settings key",
                        std::io::Error::from_raw_os_error(5),
                    ))
                },
                &mut fallbacks,
            ),
            group_policy_source(
                || {
                    Err(Error::invalid_proxy_url(
                        "proxy.corp/wpad.dat",
                        url::ParseError::RelativeUrlWithoutBase,
                    ))
                },
                &mut fallbacks,
            ),
            group_policy_source(
                || {
                    Err(ffi::win32_error(
                        "reading HKLM group policy Internet Settings value AutoConfigURL",
                        ERROR_MORE_DATA,
                    ))
                },
                &mut fallbacks,
            ),
        ];
        // One assert over all five rather than one per row: an assert inside a loop stops
        // at the first mismatch, so a change that hardened one error back into a `?` would
        // still be reported against a row that answers correctly.
        let named: Vec<bool> = entries
            .iter()
            .map(|entry| match entry {
                None => false,
                Some((ProxyConfigSource::GroupPolicy, _)) => true,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            named,
            [false, true, false, false, false],
            "only a policy key that was read and understood contributes an entry: {entries:?}"
        );
        // The row that found no policy must not be in here; the three that failed must all
        // be. Length alone is the assertion that a change softening one more thing into
        // silence, or recording a machine that simply has no policy as degraded, fails.
        assert_eq!(
            fallbacks,
            [ProxyConfigSource::GroupPolicy; 3],
            "a policy key this process could not read is degraded; one that is absent is not"
        );
    }

    // The same distinction one source over, where the two indistinguishable answers are
    // both `None` rather than both `Ok(None)`. `ERROR_FILE_NOT_FOUND` is the documented way
    // WinHTTP says nobody ever ran `netsh winhttp set proxy`, which is a machine with no
    // machine default and not a failure; anything else is a call that did not answer, and
    // only that one is recorded. A service reading `sources` for the machine default has no
    // other way to tell the two apart, because the entry is missing either way.
    #[test]
    fn only_a_winhttp_default_that_did_not_answer_is_recorded_as_degraded() {
        let mut fallbacks = Vec::new();
        let contributed: Vec<bool> = [
            // A null `WINHTTP_PROXY_INFO` is what `Drop` is written to accept, so this row
            // allocates nothing and frees nothing.
            winhttp_default_source(
                || Ok(WinHttpDefaultConfig(WINHTTP_PROXY_INFO::default())),
                &mut fallbacks,
            ),
            winhttp_default_source(
                || {
                    Err(windows::core::Error::from_hresult(HRESULT::from_win32(
                        ERROR_FILE_NOT_FOUND.0,
                    )))
                },
                &mut fallbacks,
            ),
            winhttp_default_source(
                || {
                    Err(windows::core::Error::from_hresult(HRESULT::from_win32(
                        ERROR_MORE_DATA.0,
                    )))
                },
                &mut fallbacks,
            ),
        ]
        .iter()
        .map(Option::is_some)
        .collect();
        assert_eq!(contributed, [true, false, false]);
        assert_eq!(fallbacks, [ProxyConfigSource::WinHttpDefault]);
    }

    // The same distinction on the source that answers, where softening can cost something.
    // `ERROR_FILE_NOT_FOUND` is Microsoft's code for a machine with no Internet Explorer
    // proxy settings to report, so the plain HKCU values read next are the answer rather
    // than a stand-in for one, and nothing is recorded. `ERROR_WINHTTP_INTERNAL_ERROR` and
    // `ERROR_NOT_ENOUGH_MEMORY` are the other codes that page names, and each is a call that
    // failed while an active connectoid may have been carrying a proxy of its own;
    // `ERROR_MORE_DATA` stands in for the codes it does not name, since the list arrives as
    // "Among the error codes returned are the following". Each of those reads the LAN
    // connection's values instead, from a store the API was not asked about, and a caller
    // reading a snapshot has no other way to learn that happened.
    //
    // The mode is deliberately unasserted on the failing rows: the fallback reads this
    // host's own HKCU, so what comes back is whatever the machine is configured with, and a
    // host carrying an unparsable `AutoConfigURL` answers `Err`. What the rows are being
    // asked about is settled before any of that runs.
    #[test]
    fn only_a_per_user_query_that_lost_the_active_connection_is_recorded_as_degraded() {
        let mut fallbacks = Vec::new();
        for code in [
            ERROR_FILE_NOT_FOUND.0,
            ERROR_WINHTTP_INTERNAL_ERROR,
            ERROR_NOT_ENOUGH_MEMORY.0,
            ERROR_MORE_DATA.0,
        ] {
            let _ = read_user_mode(
                || {
                    Err(windows::core::Error::from_hresult(HRESULT::from_win32(
                        code,
                    )))
                },
                &mut fallbacks,
            );
        }
        assert_eq!(
            fallbacks,
            [ProxyConfigSource::Registry; 3],
            "a per-user call that had no settings to report is not a degraded read; one that \
             failed some other way answered from the LAN store instead and is"
        );

        // And the call that succeeded records nothing at all. A null
        // `WINHTTP_CURRENT_USER_IE_PROXY_CONFIG` is what `Drop` is written to accept, so
        // this row allocates nothing and frees nothing.
        let mut fallbacks = Vec::new();
        let mode = read_user_mode(
            || {
                Ok(IeProxyConfig(
                    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default(),
                ))
            },
            &mut fallbacks,
        )
        .unwrap();
        assert_eq!(mode, ProxyMode::Direct);
        assert!(fallbacks.is_empty(), "{fallbacks:?}");
    }

    // Which store the caller ends up routing through, on a host that need not hold any of
    // them. The order is the answer and not presentation — `effective` is `sources.first()`
    // — and both of the other two stores are reported without ever being it: the WinHTTP
    // default because it was written for services, the policy key because Windows itself
    // does not read the values this crate reads from it (`POLICY_INTERNET_SETTINGS`).
    //
    // `tests/read_once.rs` asks the same question of the real machine and cannot finish it:
    // its comparison is guarded on the host actually reporting a `WinHttpDefault` entry,
    // which a machine that never ran `netsh winhttp set proxy` does not, and no host this
    // suite may write to reports a policy entry at all. The three modes here are distinct so
    // that `effective` alone says which one won.
    #[test]
    fn the_per_user_store_answers_and_the_other_two_are_only_reported() {
        let policy = ProxyMode::WpadAutoDetect;
        let user = resolve_mode(false, None, Some("user.example:8080"), None).unwrap();
        let machine = ProxyMode::Direct;
        let effective =
            |sources: Vec<_>| ProxyConfig::from_ordered_sources(sources).effective.clone();
        let sources = |sources: Vec<(ProxyConfigSource, ProxyMode)>| {
            sources
                .iter()
                .map(|(source, _)| *source)
                .collect::<Vec<_>>()
        };

        // Every store answering at once, which is the row that says the policy key does not
        // lead: a `WpadAutoDetect` written under HKLM policy would send every request
        // through whatever WPAD hands back, and no other program on the machine reads it.
        let all_three = in_precedence_order(
            Some((ProxyConfigSource::GroupPolicy, policy)),
            user.clone(),
            Some((ProxyConfigSource::WinHttpDefault, machine.clone())),
        );
        assert_eq!(
            sources(all_three.clone()),
            [
                ProxyConfigSource::Registry,
                ProxyConfigSource::GroupPolicy,
                ProxyConfigSource::WinHttpDefault
            ],
            "both reported-only stores follow the one that answers, in a fixed order"
        );
        assert_eq!(
            effective(all_three),
            user,
            "the per-user store answers even when a policy value is present"
        );

        // The pair the integration test cannot reach on a bare host: with no policy, the
        // machine default is still reported below the user rather than dropped.
        let without_policy = in_precedence_order(
            None,
            user.clone(),
            Some((ProxyConfigSource::WinHttpDefault, machine)),
        );
        assert_eq!(
            sources(without_policy.clone()),
            [
                ProxyConfigSource::Registry,
                ProxyConfigSource::WinHttpDefault
            ]
        );
        assert_eq!(
            effective(without_policy),
            user,
            "a per-machine default must not answer for an interactive user"
        );

        // And a machine that never ran `netsh winhttp set proxy` is the host the integration
        // test runs on, where the per-user store is alone.
        assert_eq!(
            effective(in_precedence_order(None, user.clone(), None)),
            user
        );
    }

    // A group policy key that carries only *descriptive* values must not resolve to a mode
    // at all, because `group_policy_source` would then report a `Direct` group policy that
    // nobody configured. The switches stay decisive, `ProxyEnable = 0` included.
    #[test]
    fn a_policy_key_with_no_switch_in_it_decides_nothing() {
        assert!(!decides_whether_to_proxy(None, None, None));

        assert!(decides_whether_to_proxy(Some(0), None, None));
        assert!(decides_whether_to_proxy(Some(1), None, None));
        assert!(decides_whether_to_proxy(
            None,
            Some("http://wpad/x.pac"),
            None
        ));
        assert!(decides_whether_to_proxy(None, None, Some(0)));
        assert!(decides_whether_to_proxy(None, None, Some(1)));

        // A blank AutoConfigURL is a present registry value that resolve_mode would
        // throw away — it must not make the GP key decisive on its own.
        assert!(!decides_whether_to_proxy(None, Some(""), None));
        assert!(!decides_whether_to_proxy(None, Some("   "), None));
    }

    // The other switch, and the one these rows alone hold against a reading of "any non-zero
    // value". `ProxyEnable = 2` is not a value WinINet documents, and this crate
    // guesses at no meaning for it, so a `ProxyServer` beside it stays off rather than
    // routing traffic on a switch nobody can read. `mode_from_registry` and
    // `wpad_fallback_from_key` both come here, which is the whole reason the question lives
    // in a function, so the stance cannot end up differing between them.
    //
    // Read together and compared once, so a failure names every value that moved rather than
    // stopping at the first.
    #[test]
    fn the_static_server_switch_is_exactly_one() {
        let readings: Vec<bool> = [None, Some(0), Some(1), Some(2), Some(u32::MAX)]
            .into_iter()
            .map(static_server_is_enabled)
            .collect();
        assert_eq!(readings, [false, false, true, false, false]);
    }

    // Regression guard: [`resolve_mode`] is on [`read_config`]'s main path and must stay
    // fail-hard on an unparsable `AutoConfigURL` — only [`wpad_fallback_beneath`], on the
    // secondary path, may soften this into [`ProxyMode::Direct`].
    #[test]
    fn resolve_mode_still_fails_hard_on_an_unparsable_auto_config_url() {
        let error = resolve_mode(false, Some("not a url"), None, None).unwrap_err();
        assert!(matches!(error, Error::InvalidProxyUrl { .. }), "{error:?}");
    }

    // An unparsable `AutoConfigURL` must degrade instead of propagating an `Err` that
    // would abort the live WPAD probe before it even runs — over a PAC URL nothing was
    // going to use anyway.
    #[cfg(feature = "pac-windows-native")]
    #[test]
    fn wpad_fallback_degrades_an_unparsable_auto_config_url_to_direct() {
        assert_eq!(
            wpad_fallback_beneath(Some("not a url"), None, None),
            (None, ProxyMode::Direct)
        );
    }

    // `AutoConfigURL` is the next thing WinHTTP is asked to try, and asking for it does not
    // cost the step below it.
    #[cfg(feature = "pac-windows-native")]
    #[test]
    fn wpad_fallback_keeps_a_valid_auto_config_url() {
        let (pac, _) = wpad_fallback_beneath(Some("http://wpad/proxy.pac"), Some("h:8080"), None);
        assert_eq!(pac.map(String::from), Some("http://wpad/proxy.pac".into()));
    }

    // The defect this pair exists for: a machine with WPAD ticked, an `AutoConfigURL`, and
    // an enabled static `ProxyServer` beneath both. While these two were one `ProxyMode`,
    // the URL won and the server was gone by the time anyone could ask for it — so a PAC
    // server that was down turned every request into a direct one, past a proxy that was
    // configured, enabled and reachable. Chromium and Microsoft's own `WinHttp` guidance
    // both continue to the static proxy for a script that could not be *obtained*; the
    // quotations are with `resolve_wpad_with_fallback`.
    //
    // Asserted on the second element and not on `matches!`, because the failure this must
    // catch is the server going missing, not its shape being wrong.
    #[cfg(feature = "pac-windows-native")]
    #[test]
    fn a_static_server_survives_the_auto_config_url_configured_above_it() {
        let (pac, beneath) = wpad_fallback_beneath(
            Some("http://wpad/proxy.pac"),
            Some("h:8080"),
            Some("<local>"),
        );
        assert!(pac.is_some());
        let bypass = beneath.bypass().unwrap_or_else(|| {
            panic!(
                "the static server beneath the PAC URL was dropped as \
                                       {beneath:?}"
            )
        });
        assert!(bypass.excludes_simple_hostnames());
    }

    // Regression guard for the older half of the same rule: an unparsable `AutoConfigURL`
    // must not take the static server with it either.
    #[cfg(feature = "pac-windows-native")]
    #[test]
    fn wpad_fallback_keeps_a_static_server_when_the_auto_config_url_is_unparsable() {
        let (pac, beneath) =
            wpad_fallback_beneath(Some("not a url"), Some("h:8080"), Some("<local>"));
        assert_eq!(pac, None);
        assert!(
            matches!(beneath, ProxyMode::Manual { .. }),
            "a broken AutoConfigURL must not discard the static server sitting beneath \
             it — got {beneath:?}"
        );
    }

    #[test]
    fn winhttp_no_proxy_is_direct() {
        let mode = winhttp_default_mode(WINHTTP_ACCESS_TYPE_NO_PROXY, Some("h:8080"), None);
        assert_eq!(mode, ProxyMode::Direct);
    }

    #[test]
    fn winhttp_named_proxy_uses_the_shared_parser() {
        let mode = winhttp_default_mode(
            WINHTTP_ACCESS_TYPE_NAMED_PROXY,
            Some("h:8080"),
            Some("<local>;*.corp"),
        );
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        assert!(bypass.excludes_simple_hostnames());
        assert!(bypass.matches_authority("api.corp"));
    }

    #[test]
    fn winhttp_named_proxy_with_a_blank_server_is_direct() {
        let mode = winhttp_default_mode(WINHTTP_ACCESS_TYPE_NAMED_PROXY, Some("   "), None);
        assert_eq!(mode, ProxyMode::Direct);
    }

    #[test]
    fn winhttp_named_proxy_with_no_server_is_direct() {
        let mode = winhttp_default_mode(WINHTTP_ACCESS_TYPE_NAMED_PROXY, None, None);
        assert_eq!(mode, ProxyMode::Direct);
    }

    // The wildcard arm stands for more than one thing, and a single value here covers only
    // the first of them: `4` is `WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY`, a
    // value the SDK names and this match declines — not an unknown one. `2` is the unknown
    // case; the SDK assigns it no name. Neither parses the server string it is handed.
    #[test]
    fn the_access_types_this_match_declines_are_direct() {
        // Imported here rather than beside the arms this module does handle: production
        // code never names it, and an unused import is a warning this tree denies.
        use windows::Win32::Networking::WinHttp::WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;

        for access_type in [WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_ACCESS_TYPE(2)] {
            let mode = winhttp_default_mode(access_type, Some("h:8080"), None);
            assert_eq!(mode, ProxyMode::Direct, "access type {access_type:?}");
        }
    }

    // Shared real-registry fixture for the tests below: snapshots the
    // `HKCU\...\Internet Settings` values the registry readers here look at and restores
    // them on drop.
    #[cfg(feature = "pac-windows-native")]
    mod registry_guard {
        use windows::Win32::System::Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
            REG_VALUE_TYPE, RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
            RegSetValueExW,
        };
        use windows::core::PCWSTR;

        use crate::sys::win::ffi::wide;

        use super::super::INTERNET_SETTINGS;

        // The values [`super::super::wpad_fallback`] reads, plus the `AutoDetect` that
        // only [`super::super::mode_from_registry`] reads. A value a test writes but this
        // list omits is a value the developer never gets back.
        const VALUES: [&str; 5] = [
            "ProxyEnable",
            "ProxyServer",
            "ProxyOverride",
            "AutoConfigURL",
            "AutoDetect",
        ];

        // `HKCU\...\Internet Settings\Connections`, which holds the same configuration a
        // second time as binary blobs. Nothing here writes it deliberately — Windows
        // copies the plain values into it on its own — but it has to be restored anyway;
        // see this module's doc comment.
        const CONNECTIONS: &str =
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

        // The values under [`CONNECTIONS`] that receive the copy. They mirror each
        // other; both are restored so neither can reseed the other.
        const CONNECTION_VALUES: [&str; 2] = ["DefaultConnectionSettings", "SavedLegacySettings"];

        // Serialises the tests that use [`Guard`].
        //
        // Without it the race does not merely fail tests, it corrupts the developer's
        // own settings: two guards that snapshot while the other's fixture is installed
        // each restore the *other's* fixture as if it were the original. CI passes
        // `--test-threads=1`, but a flag only fixes the runs that remember to pass it.
        static REGISTRY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

        fn read_raw(key: HKEY, name: &str) -> Option<(u32, Vec<u8>)> {
            let name_w = wide(name);
            let mut kind = REG_VALUE_TYPE::default();
            let mut len: u32 = 0;
            // SAFETY: `key` is a valid, currently open handle for the duration of this
            // call and `name_w` is a NUL terminated UTF-16 buffer alive across it; the
            // first call only discovers the size, so no output buffer is passed.
            let status = unsafe {
                RegQueryValueExW(
                    key,
                    PCWSTR(name_w.as_ptr()),
                    None,
                    Some(&mut kind),
                    None,
                    Some(&mut len),
                )
            };
            if status.0 != 0 {
                return None;
            }
            let mut buf = vec![0u8; len as usize];
            // SAFETY: as above; `buf` is sized from the length the previous call
            // reported and stays valid for the duration of this call.
            let status = unsafe {
                RegQueryValueExW(
                    key,
                    PCWSTR(name_w.as_ptr()),
                    None,
                    Some(&mut kind),
                    Some(buf.as_mut_ptr()),
                    Some(&mut len),
                )
            };
            assert_eq!(status.0, 0, "reading {name}");
            Some((kind.0, buf))
        }

        // One snapshotted registry value: its name, and its `(type, bytes)` if it
        // existed. `None` means "was absent", which restore reproduces by deleting.
        type SavedValue = (&'static str, Option<(u32, Vec<u8>)>);

        // Open an `HKCU` subkey for read and write, or `None` when it does not exist.
        fn open_key(path: &str) -> Option<HKEY> {
            let path_w = wide(path);
            let mut key = HKEY::default();
            // SAFETY: `path_w` is a NUL terminated UTF-16 buffer alive across the call
            // and `key` is a valid out-parameter.
            let status = unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(path_w.as_ptr()),
                    None,
                    KEY_READ | KEY_SET_VALUE,
                    &raw mut key,
                )
            };
            (status.0 == 0).then_some(key)
        }

        // Put every snapshotted value back, reproducing "was absent" by deleting.
        fn restore(key: HKEY, saved: &[SavedValue]) {
            for (name, value) in saved {
                let name_w = wide(name);
                match value {
                    Some((kind, bytes)) => {
                        // SAFETY: `key` is open for `KEY_SET_VALUE` and `name_w`/`bytes`
                        // are valid buffers alive across the call; `bytes` was itself
                        // read from this same value by `read_raw` at `open` time.
                        let _ = unsafe {
                            RegSetValueExW(
                                key,
                                PCWSTR(name_w.as_ptr()),
                                None,
                                REG_VALUE_TYPE(*kind),
                                Some(bytes),
                            )
                        };
                    }
                    // SAFETY: as above; deleting an already absent value is a documented
                    // failure return, harmless here.
                    None => unsafe {
                        let _ = RegDeleteValueW(key, PCWSTR(name_w.as_ptr()));
                    },
                }
            }
        }

        pub(super) struct Guard {
            key: HKEY,
            saved: Vec<SavedValue>,
            // `None` when this machine has no [`CONNECTIONS`] key at all. There is then
            // nothing to restore, and this guard deliberately does not create one — it
            // never writes the blobs itself, it only undoes Windows' copy into them.
            connections: Option<HKEY>,
            connections_saved: Vec<SavedValue>,
            // Held for this guard's whole lifetime; see [`REGISTRY_LOCK`]. `Drop for
            // Guard` runs before any field is dropped, so the restore below completes
            // while the lock is still held.
            _lock: std::sync::MutexGuard<'static, ()>,
        }

        impl Guard {
            pub(super) fn open() -> Self {
                // A poisoned lock means some earlier test panicked. Its `Guard` still ran
                // `Drop` on the way out (Rust unwinds through it), so the registry is
                // restored and this one may proceed; propagating the poison would only
                // turn one real failure into a cascade of unrelated ones.
                let _lock = REGISTRY_LOCK
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());

                let key = open_key(INTERNET_SETTINGS)
                    .expect("opening HKCU Internet Settings for the test");
                let saved = VALUES
                    .iter()
                    .map(|name| (*name, read_raw(key, name)))
                    .collect();

                let connections = open_key(CONNECTIONS);
                let connections_saved = connections
                    .map(|key| {
                        CONNECTION_VALUES
                            .iter()
                            .map(|name| (*name, read_raw(key, name)))
                            .collect()
                    })
                    .unwrap_or_default();

                Self {
                    key,
                    saved,
                    connections,
                    connections_saved,
                    _lock,
                }
            }

            pub(super) fn write_dword(&self, name: &str, value: u32) {
                self.write_dword_bytes(name, &value.to_le_bytes());
            }

            // A `REG_DWORD` whose data need not be four bytes long. `RegSetValueExW` puts no
            // length rule on this type, so an over-long one is something another writer can
            // leave behind and not only something a test can make.
            pub(super) fn write_dword_bytes(&self, name: &str, bytes: &[u8]) {
                let name_w = wide(name);
                // SAFETY: `self.key` is open for `KEY_SET_VALUE` and `name_w`/`bytes`
                // are valid buffers alive across the call.
                let status = unsafe {
                    RegSetValueExW(
                        self.key,
                        PCWSTR(name_w.as_ptr()),
                        None,
                        REG_DWORD,
                        Some(bytes),
                    )
                };
                assert_eq!(status.0, 0, "writing {name}");
            }

            pub(super) fn write_sz(&self, name: &str, value: &str) {
                self.write_string(name, REG_SZ, value);
            }

            // The type Windows uses for a value holding `%VAR%` references. Only the type
            // differs; this fixture never expands anything, and neither does the reader.
            pub(super) fn write_expand_sz(&self, name: &str, value: &str) {
                self.write_string(name, REG_EXPAND_SZ, value);
            }

            fn write_string(&self, name: &str, kind: REG_VALUE_TYPE, value: &str) {
                let name_w = wide(name);
                let data_w = wide(value);
                // SAFETY: `data_w` is a NUL terminated UTF-16 buffer; reinterpreting it
                // as its own byte length is exactly what both string types expect.
                let bytes: &[u8] =
                    unsafe { std::slice::from_raw_parts(data_w.as_ptr().cast(), data_w.len() * 2) };
                // SAFETY: as `write_dword` above.
                let status = unsafe {
                    RegSetValueExW(self.key, PCWSTR(name_w.as_ptr()), None, kind, Some(bytes))
                };
                assert_eq!(status.0, 0, "writing {name}");
            }

            pub(super) fn delete(&self, name: &str) {
                let name_w = wide(name);
                // SAFETY: `self.key` is open for `KEY_SET_VALUE` and `name_w` is a NUL
                // terminated UTF-16 buffer alive across the call. Deleting a value that
                // is already absent is a documented no-op failure, harmless here.
                unsafe {
                    let _ = RegDeleteValueW(self.key, PCWSTR(name_w.as_ptr()));
                }
            }
        }

        impl Drop for Guard {
            fn drop(&mut self) {
                // Plain values first, blobs second. Windows' copy runs plain-to-blob, so
                // once the plain values are the developer's own again, a copy that fires
                // after this point reproduces the correct blob rather than fighting it.
                restore(self.key, &self.saved);
                if let Some(connections) = self.connections {
                    restore(connections, &self.connections_saved);
                    // SAFETY: opened by `Self::open` and closed exactly once, here.
                    unsafe {
                        let _ = RegCloseKey(connections);
                    }
                }
                // SAFETY: `self.key` was opened by `Self::open` and is closed exactly
                // once, here.
                unsafe {
                    let _ = RegCloseKey(self.key);
                }
            }
        }
    }

    // On a machine with "automatically detect settings" on *and* a static proxy
    // configured underneath it, [`resolve_mode`]'s early return for `auto_detect`
    // discards that static proxy entirely; a WPAD probe failure would then map to
    // `Direct`, silently bypassing a proxy the administrator did configure. This proves
    // [`wpad_fallback`] recovers it instead.
    #[cfg(feature = "pac-windows-native")]
    #[test]
    #[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
    fn wpad_fallback_recovers_the_static_proxy_auto_detect_would_otherwise_discard() {
        use crate::Scheme;

        let guard = registry_guard::Guard::open();
        guard.write_dword("ProxyEnable", 1);
        guard.write_sz("ProxyServer", "127.0.0.1:18080");
        guard.write_sz("ProxyOverride", "<local>");
        guard.delete("AutoConfigURL");

        // `wpad_fallback` always forces `auto_detect = false` itself (that is the
        // entire point), so the real `AutoDetect` value is deliberately left alone —
        // the fallback it recovers must not depend on it either way.
        let (pac, beneath) =
            wpad_fallback().expect("recovering the WPAD fallback from HKCU must succeed");

        assert_eq!(pac, None, "no `AutoConfigURL` is configured above it");
        assert!(
            matches!(beneath, ProxyMode::Manual { .. }),
            "a static proxy configured underneath auto-detect (which `effective` \
             discards) must still be recoverable as the WPAD fallback, not silently \
             lost as `Direct` — got {beneath:?}"
        );
        assert_eq!(
            beneath.endpoint_for(Scheme::Http).map(|e| e.authority()),
            Some("127.0.0.1:18080".to_owned()),
            "{beneath:?}"
        );

        drop(guard);
    }

    // End-to-end proof that [`wpad_fallback`] itself — not just [`wpad_fallback_beneath`]
    // in isolation — survives a broken `AutoConfigURL` instead of returning `Err`. Such an
    // error at the `resolve_wpad_with_fallback` call site aborts the WPAD probe before it
    // ever runs, on a machine where WPAD itself might be perfectly healthy.
    //
    // The assertion is deliberately weaker than the unit test's `assert_eq!(…, None)` on
    // the same shape, and the difference is the layer, not carelessness: this path reads
    // the registry back through WinHTTP's own view of it, so what reaches
    // `wpad_fallback_beneath` is what WinHTTP reports rather than the string written above.
    // Predicting that is not this test's job. What is its job holds either way — a URL
    // that does not parse never comes back as one a caller would fetch.
    #[cfg(feature = "pac-windows-native")]
    #[test]
    #[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
    fn wpad_fallback_survives_an_unparsable_auto_config_url_instead_of_erroring() {
        let guard = registry_guard::Guard::open();
        guard.delete("ProxyEnable");
        guard.delete("ProxyServer");
        guard.delete("ProxyOverride");
        guard.write_sz("AutoConfigURL", "not a url");

        let (pac, _) =
            wpad_fallback().expect("an unparsable AutoConfigURL must degrade rather than error");

        assert_eq!(
            pac, None,
            "a broken AutoConfigURL must not be mistaken for a usable PAC URL"
        );

        drop(guard);
    }

    // End-to-end proof, through the real registry, that [`wpad_fallback`] falls through
    // to a static proxy configured beneath auto-detect even when the `AutoConfigURL`
    // sitting above it is unparsable. Returning `Direct` from the unparsable-URL arm
    // without consulting `ProxyServer` would make `resolve_wpad_with_fallback` probe WPAD
    // alone, miss, and confirm `Direct` — silently bypassing the administrator's static
    // proxy. The companion test above covers only the *no static server* half of this
    // registry state.
    #[cfg(feature = "pac-windows-native")]
    #[test]
    #[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
    fn wpad_fallback_falls_through_to_a_static_server_when_the_auto_config_url_is_unparsable() {
        use crate::Scheme;

        let guard = registry_guard::Guard::open();
        guard.write_dword("ProxyEnable", 1);
        guard.write_sz("ProxyServer", "127.0.0.1:18080");
        guard.write_sz("ProxyOverride", "<local>");
        guard.write_sz("AutoConfigURL", "not a url");

        let (pac, beneath) =
            wpad_fallback().expect("a malformed AutoConfigURL must degrade rather than error");

        assert_eq!(pac, None, "the AutoConfigURL written above does not parse");
        assert!(
            matches!(beneath, ProxyMode::Manual { .. }),
            "a static proxy configured beneath auto-detect must survive a broken \
             AutoConfigURL sitting above it in the same registry key, not be silently \
             bypassed as Direct — got {beneath:?}"
        );
        assert_eq!(
            beneath.endpoint_for(Scheme::Http).map(|e| e.authority()),
            Some("127.0.0.1:18080".to_owned()),
            "{beneath:?}"
        );

        drop(guard);
    }

    // `ProxyEnable = 0` with a `ProxyServer` still sitting beside it is an ordinary
    // machine, not a corrupt one: turning the proxy off clears the switch and leaves the
    // address where it was, ready for the next time it goes on. Both readers must drop
    // that address, and no unit test can reach the question — [`resolve_mode`] and
    // [`wpad_fallback_beneath`] are handed a server their caller has already filtered,
    // because the WinHTTP path reaches them with no switch to consult. So the filter is
    // only observable through a real key, and unfiltered it routes every request on that
    // machine through the proxy its user just switched off.
    #[cfg(feature = "pac-windows-native")]
    #[test]
    #[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
    fn a_disabled_switch_drops_the_static_server_left_beside_it() {
        let guard = registry_guard::Guard::open();
        guard.write_dword("ProxyEnable", 0);
        guard.write_sz("ProxyServer", "127.0.0.1:18080");
        guard.write_sz("ProxyOverride", "<local>");
        guard.delete("AutoConfigURL");
        // Left in place, `AutoDetect = 1` would answer `WpadAutoDetect` before the switch
        // below is ever consulted, and this developer's own machine would decide whether
        // the test means anything.
        guard.delete("AutoDetect");

        let key = RegKey::open(
            HKEY_CURRENT_USER,
            INTERNET_SETTINGS,
            KEY_READ,
            "opening HKCU Internet Settings for the test",
        )
        .expect("opening the key the guard just wrote to must succeed")
        .expect("the guard could not have written to a key that is absent");

        assert_eq!(
            mode_from_registry(&key).expect("reading back what the guard wrote must succeed"),
            Some(ProxyMode::Direct),
            "a `ProxyServer` beside `ProxyEnable = 0` is switched off, not in force"
        );
        assert_eq!(
            wpad_fallback_from_key(&key).expect("the same read must succeed for the fallback"),
            (None, ProxyMode::Direct),
            "the WPAD fallback reads the same switch and must reach the same answer"
        );

        drop(guard);
    }

    // Nothing else in this suite reads a string out of the registry. The per-user path takes
    // WinHTTP's own view on a machine with a profile, so
    // [`RegKey::string_value`](ffi::RegKey) reaches the per-user values only where
    // `IeProxyConfig::query` failed — but the group policy read goes through
    // [`mode_from_registry`] on every call that asks for it, so this is a live path.
    // Both halves of what it promises are read back here through a real key instead.
    //
    // The stored terminator is not part of the value: `write_sz` stores one because that is
    // how Windows stores a string, and a reader that keeps it hands every parser downstream
    // a host ending in NUL. `REG_EXPAND_SZ` is an ordinary type for these values, read as
    // configuration and returned exactly as stored — call it absent and a machine that
    // stores its proxy that way reports having none; expand it and a library asked to
    // report someone's settings starts substituting its own process environment into them.
    #[cfg(feature = "pac-windows-native")]
    #[test]
    #[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
    fn registry_strings_arrive_without_their_terminator_and_unexpanded() {
        let guard = registry_guard::Guard::open();
        guard.write_sz("ProxyServer", "127.0.0.1:18080");
        // `%COMPUTERNAME%` is set on every Windows machine, so an expansion creeping in
        // here would change the string rather than leave it alone for want of a variable.
        guard.write_expand_sz("AutoConfigURL", "http://%COMPUTERNAME%.corp/proxy.pac");

        let key = RegKey::open(
            HKEY_CURRENT_USER,
            INTERNET_SETTINGS,
            KEY_READ,
            "opening HKCU Internet Settings for the test",
        )
        .expect("opening the key the guard just wrote to must succeed")
        .expect("the guard could not have written to a key that is absent");

        assert_eq!(
            key.string_value("ProxyServer")
                .expect("reading back a REG_SZ must succeed")
                .as_deref(),
            Some("127.0.0.1:18080")
        );
        assert_eq!(
            key.string_value("AutoConfigURL")
                .expect("reading back a REG_EXPAND_SZ must succeed")
                .as_deref(),
            Some("http://%COMPUTERNAME%.corp/proxy.pac")
        );

        drop(guard);
    }

    // The other half of what [`RegKey::dword_value`](ffi::RegKey) promises, and the half this
    // test alone holds: a `REG_DWORD` carrying more data than the type can hold keeps its low
    // word rather than being refused. Nothing else here would notice the stricter reading —
    // an exactly four-byte value only, which is what `base::win::RegKey::ReadValueDW` does.
    //
    // What that stricter reading costs is a machine whose `ProxyEnable` some other writer
    // left over-long: refused, it reads as unset, and a configured proxy silently becomes
    // Direct with nothing anywhere saying why. The padding below is a recognisable pattern
    // rather than more zeroes, so a reader that took the wrong end of the value comes back
    // with a number this assertion names instead of one that looks plausible.
    #[cfg(feature = "pac-windows-native")]
    #[test]
    #[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
    fn an_over_long_dword_keeps_its_low_word_rather_than_being_refused() {
        let guard = registry_guard::Guard::open();
        guard.write_dword_bytes("ProxyEnable", &[1, 0, 0, 0, 0xEF, 0xBE, 0xAD, 0xDE]);

        let key = RegKey::open(
            HKEY_CURRENT_USER,
            INTERNET_SETTINGS,
            KEY_READ,
            "opening HKCU Internet Settings for the test",
        )
        .expect("opening the key the guard just wrote to must succeed")
        .expect("the guard could not have written to a key that is absent");

        assert_eq!(
            key.dword_value("ProxyEnable")
                .expect("reading back an over-long REG_DWORD must succeed"),
            Some(1)
        );

        drop(guard);
    }

    // The other direction of the same promise, and the one with teeth: a value stored under
    // a type its name does not carry reads as absent, and with `AutoConfigURL` and
    // `AutoDetect` cleared below, an absent `ProxyEnable` silences the whole key rather than
    // losing one value — [`decides_whether_to_proxy`] then sees a
    // key that said nothing about *whether* to proxy, so the `ProxyServer` beside it is
    // never reached and [`mode_from_registry`] answers `None`.
    //
    // This test is the only thing holding the `kind != REG_DWORD` half of the guard in
    // [`RegKey::dword_value`](ffi::RegKey). `write_sz` stores
    // `"1"` as exactly four bytes, so the length half of that guard does not catch it
    // either — the value comes back as `Some(0x31)`, the UTF-16 code unit for `1` read as a
    // number. Under a *policy* key that is the damaging shape: a junk-typed `ProxyEnable`
    // there becomes a `GroupPolicy` entry resolving to `Direct`, reporting an administrator
    // who wrote a proxy as having written none. [`in_precedence_order`] keeps that entry out
    // of `effective`, so the stake is the reported source and not the answer.
    #[cfg(feature = "pac-windows-native")]
    #[test]
    #[ignore = "rewrites this machine's real Internet Settings; CI runs it with --include-ignored"]
    fn a_dword_stored_under_a_string_type_silences_the_key_it_sits_in() {
        let guard = registry_guard::Guard::open();
        guard.write_sz("ProxyEnable", "1");
        // Beside it, so that a reader which took the switch anyway has something to switch
        // on and the difference shows as a proxy rather than as two spellings of Direct.
        guard.write_sz("ProxyServer", "127.0.0.1:18080");
        guard.write_sz("ProxyOverride", "<local>");
        // For the reason `a_disabled_switch_drops_the_static_server_left_beside_it` gives:
        // either of these left in place would decide the answer before the switch is read.
        guard.delete("AutoConfigURL");
        guard.delete("AutoDetect");

        let key = RegKey::open(
            HKEY_CURRENT_USER,
            INTERNET_SETTINGS,
            KEY_READ,
            "opening HKCU Internet Settings for the test",
        )
        .expect("opening the key the guard just wrote to must succeed")
        .expect("the guard could not have written to a key that is absent");

        assert_eq!(
            key.dword_value("ProxyEnable")
                .expect("a wrongly typed value is absent, not a read failure"),
            None
        );
        assert_eq!(
            mode_from_registry(&key).expect("reading back what the guard wrote must succeed"),
            None,
            "a key whose switch is unreadable has said nothing, so it decides nothing"
        );

        drop(guard);
    }
}
