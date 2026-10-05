//! `pac-macos-native` / `pac-ios-native`: PAC through CFNetwork (`cfg(pac_cfnetwork)`, which
//! `build.rs` sets for either feature on its own OS; no-op elsewhere).
//!
//! Two entry points, both CFNetwork's asynchronous `Execute` calls pumped on the
//! caller's thread:
//!
//! * [`CfNetworkPacEvaluator`]: a [`PacEvaluator`](super::PacEvaluator) for a body you
//!   already have (`CFNetworkExecuteProxyAutoConfigurationScript`). Unlike WinHTTP, CFNetwork
//!   takes a body, so [`ProxyMode::PacInline`](crate::ProxyMode::PacInline) has a native
//!   answer here.
//! * [`CfNetworkPacResolver`]: downloads and evaluates a PAC URL
//!   (`CFNetworkExecuteProxyAutoConfigurationURL`), and, after `with_wpad(true)`, resolves
//!   [`ProxyMode::WpadAutoDetect`](crate::ProxyMode::WpadAutoDetect) through the PAC URL the
//!   system settings name (`CFNetworkCopyProxiesForURL`).
//!
//! Every script execution runs in a private run loop mode under one process-wide lock:
//! CFNetwork's PAC calls are not safe to run concurrently, and Chromium's `ProxyResolverApple`
//! serialises them the same way. Once the lock is held the execution is bounded by the
//! timeout, and when the timeout expires the run loop source is invalidated, which stops the
//! callback from ever being delivered, and the result is [`Error::PacTimeout`]. Only the run
//! loop wait is cut short. The synchronous calls count against the timeout but always run to
//! completion: the wait for the lock, the empty-dictionary `CFNetworkCopyProxiesForURL` made
//! under the lock before every execution, and, for WPAD, the system-settings read and the
//! `CFNetworkCopyProxiesForURL` that picks the PAC URL, both made before the lock.
//!
//! The mapping from CFNetwork's proxy dictionaries to [`ProxyStep`]s is compiled on every OS
//! under `cfg(test)` so that it is tested where it is written.

use crate::error::Error;
use crate::resolve::ProxyStep;

// One entry of the array CFNetwork hands back, read out of its dictionary.
#[derive(Clone, PartialEq, Eq)]
struct Entry {
    kind: EntryKind,
    host: Option<String>,
    port: Option<i64>,
    // The script's address, for an `AutoConfigUrl` entry.
    pac_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    None,
    Http,
    Https,
    Socks,
    // Only the answer for the system settings carries one; a script's answer never does.
    // `walk_system_entries` runs it, and `entries_to_steps` skips it like `Other`.
    AutoConfigUrl,
    // FTP, `AutoConfigurationJavaScript`, or a type a later macOS adds. Skipped, as Chromium
    // skips them.
    Other,
}

// Convert CFNetwork's entries into a fallback chain.
//
// Each entry is written back as the `FindProxyForURL` candidate it came from and the whole
// chain goes through [`parse_find_proxy_result`](super::parse_find_proxy_result), so this
// engine collapses repeats, reads a bare `SOCKS` as SOCKS4 and fills default ports exactly
// as the JS engines do. CFNetwork has one SOCKS type, so a script's `SOCKS` arrives here as
// SOCKS4; its `HTTPS` and `SOCKS5` entries never arrive, because CFNetwork drops them. The
// HTTPS arm serves a dictionary that carries that type from elsewhere. CFNetwork splits a
// bracketed IPv6 proxy at its first colon (`[2001:db8::1]:3128` arrives as host `[2001`,
// port 0); the bracket check below drops that entry.
//
// A host that could split a candidate (`;`, whitespace) or that carries a bracket is dropped
// rather than written back: CFNetwork has parsed it once, and a second parse must
// not see more candidates than CFNetwork returned.
fn entries_to_steps(entries: &[Entry]) -> Result<Vec<ProxyStep>, Error> {
    let mut candidates = Vec::with_capacity(entries.len());
    for entry in entries {
        let keyword = match entry.kind {
            EntryKind::None => {
                candidates.push("DIRECT".to_owned());
                continue;
            }
            EntryKind::Http => "PROXY",
            EntryKind::Https => "HTTPS",
            EntryKind::Socks => "SOCKS",
            EntryKind::AutoConfigUrl | EntryKind::Other => continue,
        };
        let Some(host) = entry.host.as_deref().map(str::trim) else {
            continue;
        };
        if host.is_empty()
            || host.contains(|c: char| c == ';' || c == '[' || c == ']' || c.is_whitespace())
        {
            continue;
        }
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        candidates.push(match entry.port {
            Some(port @ 1..=65535) => format!("{keyword} {host}:{port}"),
            _ => format!("{keyword} {host}"),
        });
    }
    if candidates.is_empty() {
        // The entries are named so an answer CFNetwork reshaped can be told from an empty one.
        let seen: Vec<String> = entries
            .iter()
            .map(|entry| format!("{:?} {:?}:{:?}", entry.kind, entry.host, entry.port))
            .collect();
        return Err(Error::pac_invalid_result(format!(
            "CFNetwork returned {} proxy entries, none of them usable: [{}]",
            entries.len(),
            seen.join(", ")
        )));
    }
    super::parse_find_proxy_result(&candidates.join("; "))
}

// Walk the answer `CFNetworkCopyProxiesForURL` gives for the system settings, in its
// failover order.
//
// A PAC entry runs through `run`, which answers `Ok(None)` for a WPAD miss and nothing
// else; the walk then moves to the next entry, and misses to the end of the array are
// Direct, as a WPAD miss is on Windows. The first entry that is not a PAC ends the walk: it
// and the entries after it are converted as CFNetwork gave them, which is also how a target
// the `ExceptionsList` covers comes back. An empty array is an error, not Direct.
fn walk_system_entries(
    entries: &[Entry],
    mut run: impl FnMut(&str) -> Result<Option<Vec<ProxyStep>>, Error>,
) -> Result<Vec<ProxyStep>, Error> {
    if entries.is_empty() {
        return entries_to_steps(entries);
    }
    for (i, entry) in entries.iter().enumerate() {
        match (entry.kind, entry.pac_url.as_deref()) {
            (EntryKind::AutoConfigUrl, Some(pac_url)) => {
                if let Some(steps) = run(pac_url)? {
                    return Ok(steps);
                }
            }
            _ => return entries_to_steps(&entries[i..]),
        }
    }
    Ok(vec![ProxyStep::Direct])
}

// Whether a failed PAC download is a WPAD miss: the script's host is the single label
// `wpad` and CFNetwork could not resolve it (`NSURLErrorDomain` -1003,
// `NSURLErrorCannotFindHost`), which is what discovery-only settings give on a network with
// no WPAD, in about a millisecond. A refused connection (-1004) means something answers for
// `wpad`, and a URL from DHCP names the server the network chose; both stay errors, so that
// a configured proxy that fails is never read as no proxy.
fn is_wpad_miss(pac_url: &str, domain: &str, code: isize) -> bool {
    domain == "NSURLErrorDomain"
        && code == -1003
        && url::Url::parse(pac_url).is_ok_and(|url| url.host_str() == Some("wpad"))
}

#[cfg(pac_cfnetwork)]
pub use self::native::{
    CfNetworkPacEvaluator, CfNetworkPacResolver, DEFAULT_CFNETWORK_PAC_TIMEOUT,
};

#[cfg(pac_cfnetwork)]
mod native {
    use std::ffi::c_void;
    use std::io;
    use std::ptr;
    use std::sync::{Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use core_foundation::array::{CFArray, CFArrayRef};
    use core_foundation::base::{CFIndex, CFType, TCFType, kCFAllocatorDefault};
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::error::{CFError, CFErrorRef};
    use core_foundation::number::CFNumber;
    use core_foundation::runloop::{
        CFRunLoop, CFRunLoopSource, CFRunLoopSourceInvalidate, CFRunLoopSourceRef,
    };
    use core_foundation::string::{CFString, CFStringRef, kCFStringEncodingUTF8};
    use core_foundation::url::{CFURL, CFURLCreateWithBytes, CFURLRef};
    use url::Url;

    use super::{Entry, EntryKind, entries_to_steps, is_wpad_miss, walk_system_entries};
    use crate::config::{ProxyConfig, ProxyConfigSource};
    use crate::error::Error;
    use crate::mode::ProxyMode;
    use crate::pac::{PacEvaluator, PacScript};
    use crate::resolve::ProxyStep;

    /// Default budget (5 s) for one CFNetwork resolution, same as
    /// [`DEFAULT_PAC_TIMEOUT`](crate::pac::DEFAULT_PAC_TIMEOUT); for
    /// [`CfNetworkPacResolver`] it also covers the download.
    pub const DEFAULT_CFNETWORK_PAC_TIMEOUT: Duration = Duration::from_secs(5);

    // The run loop mode the calls are pumped in. Private, so that nothing else scheduled on
    // the caller's run loop runs while this one waits, and nothing here runs in theirs.
    const RUN_LOOP_MODE: &str = "proxy-watch.cfnetwork-pac";

    // `CFStreamClientContext`, spelled out: `core-foundation` 0.9 keeps its `stream` module
    // private, and its `-sys` twin declares the three callbacks non-nullable where CFNetwork
    // takes NULL.
    #[repr(C)]
    struct ClientContext {
        version: CFIndex,
        info: *mut c_void,
        retain: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
        release: Option<unsafe extern "C" fn(*const c_void)>,
        copy_description: Option<unsafe extern "C" fn(*const c_void) -> CFStringRef>,
    }

    type ResultCallback = unsafe extern "C" fn(*mut c_void, CFArrayRef, CFErrorRef);

    // Hand-written for the reason `SCError` is in `src/sys/mac/mod.rs`: a small surface, and
    // the crates that bind it would bring a second copy of the CF types.
    #[link(name = "CFNetwork", kind = "framework")]
    unsafe extern "C" {
        static kCFProxyTypeKey: CFStringRef;
        static kCFProxyHostNameKey: CFStringRef;
        static kCFProxyPortNumberKey: CFStringRef;
        static kCFProxyTypeNone: CFStringRef;
        static kCFProxyTypeHTTP: CFStringRef;
        static kCFProxyTypeHTTPS: CFStringRef;
        static kCFProxyTypeSOCKS: CFStringRef;
        static kCFProxyTypeAutoConfigurationURL: CFStringRef;
        static kCFProxyAutoConfigurationURLKey: CFStringRef;

        fn CFNetworkCopySystemProxySettings() -> CFDictionaryRef;
        fn CFNetworkCopyProxiesForURL(url: CFURLRef, settings: CFDictionaryRef) -> CFArrayRef;
        fn CFNetworkExecuteProxyAutoConfigurationScript(
            script: CFStringRef,
            target: CFURLRef,
            callback: ResultCallback,
            context: *mut ClientContext,
        ) -> CFRunLoopSourceRef;
        fn CFNetworkExecuteProxyAutoConfigurationURL(
            pac_url: CFURLRef,
            target: CFURLRef,
            callback: ResultCallback,
            context: *mut ClientContext,
        ) -> CFRunLoopSourceRef;
    }

    // The scope the live system settings are reported under, which WPAD resolves from.
    #[cfg(target_os = "macos")]
    const SYSTEM_SOURCE: ProxyConfigSource = ProxyConfigSource::SystemConfigurationState;
    #[cfg(target_os = "ios")]
    const SYSTEM_SOURCE: ProxyConfigSource = ProxyConfigSource::CfNetworkSystemSettings;

    // Serialises every CFNetwork PAC call in the process.
    static LOCK: Mutex<()> = Mutex::new(());

    // `CFString`'s `Display` panics on content it cannot reencode as UTF-8, such as an
    // unpaired UTF-16 surrogate; `cf_string_to_string` in `src/sys/cf_dict.rs` has the
    // `core-foundation` internals. What a script answers, or a download fails with, is not
    // this crate's to vouch for, so text that cannot be read is absent rather than a panic.
    fn text(value: &CFString) -> Option<String> {
        std::panic::catch_unwind(|| value.to_string()).ok()
    }

    // What the callback delivered: the proxy array, or the error CFNetwork reported.
    type Answer = Result<Option<CFArray<CFType>>, CFError>;

    /// Evaluates a PAC body through `CFNetworkExecuteProxyAutoConfigurationScript`.
    ///
    /// **[`PacPolicy`](crate::pac::PacPolicy) does not apply**: `dnsResolve` and
    /// `myIpAddress` answer from the real network. The `host` argument of
    /// [`evaluate`](PacEvaluator::evaluate) is not used (CFNetwork takes the target URL and
    /// derives the host itself), and the URL is passed through
    /// [`sanitize_url`](crate::pac::sanitize_url) first.
    ///
    /// CFNetwork hands the script the target's scheme and host only (`url` is
    /// `http://example.net/` for `http://example.net/some/path`) and drops the `HTTPS` and
    /// `SOCKS5` entries of its answer (measured on macOS with an `http:` target). An answer
    /// made only of those is [`Error::PacInvalidResult`]; one that falls back to `DIRECT`
    /// after them comes back as `DIRECT` alone, where the JS engines would try the proxy
    /// first. `SOCKS` comes back as [`ProxyStep::Socks4`]. An IPv6 literal proxy
    /// (`PROXY [2001:db8::1]:3128`) comes back from CFNetwork cut at its first colon and is
    /// dropped the same way.
    #[derive(Debug, Clone)]
    pub struct CfNetworkPacEvaluator {
        timeout: Duration,
    }

    impl CfNetworkPacEvaluator {
        /// An evaluator with the [`DEFAULT_CFNETWORK_PAC_TIMEOUT`] budget.
        #[must_use]
        pub fn new() -> Self {
            Self {
                timeout: DEFAULT_CFNETWORK_PAC_TIMEOUT,
            }
        }

        /// An evaluator with `timeout`; zero → [`Error::PacTimeout`] (not "unlimited").
        ///
        /// # Errors
        ///
        /// [`Error::PacTimeout`] when `timeout` is zero.
        pub fn with_timeout(timeout: Duration) -> Result<Self, Error> {
            check_timeout(timeout)?;
            Ok(Self { timeout })
        }

        /// The per-evaluation budget.
        #[must_use]
        pub fn timeout(&self) -> Duration {
            self.timeout
        }
    }

    impl Default for CfNetworkPacEvaluator {
        fn default() -> Self {
            Self::new()
        }
    }

    impl PacEvaluator for CfNetworkPacEvaluator {
        fn evaluate(
            &self,
            script: &PacScript,
            url: &Url,
            _host: &str,
        ) -> Result<Vec<ProxyStep>, Error> {
            evaluate_script(script.source(), url, self.timeout)
        }
    }

    /// Downloads and evaluates a PAC URL through `CFNetworkExecuteProxyAutoConfigurationURL`.
    ///
    /// [`Pac`](ProxyMode::Pac): CFNetwork fetches and runs the script.
    /// [`PacInline`](ProxyMode::PacInline): the body runs through CFNetwork as
    /// [`CfNetworkPacEvaluator`] does. Direct/Manual: [`resolve`](crate::resolve()).
    /// [`WpadAutoDetect`](ProxyMode::WpadAutoDetect): [`Error::PacNotSupported`] unless
    /// [`with_wpad(true)`](Self::with_wpad) and the snapshot's system-settings scope
    /// ([`resolve_config`](Self::resolve_config)). **[`PacPolicy`](crate::pac::PacPolicy) does not
    /// apply.**
    #[derive(Debug, Clone)]
    pub struct CfNetworkPacResolver {
        timeout: Duration,
        wpad: bool,
    }

    impl CfNetworkPacResolver {
        /// A resolver with the [`DEFAULT_CFNETWORK_PAC_TIMEOUT`] budget.
        #[must_use]
        pub fn new() -> Self {
            Self {
                timeout: DEFAULT_CFNETWORK_PAC_TIMEOUT,
                wpad: false,
            }
        }

        /// A resolver with `timeout`, download included; zero → [`Error::PacTimeout`].
        ///
        /// # Errors
        ///
        /// [`Error::PacTimeout`] when `timeout` is zero.
        pub fn with_timeout(timeout: Duration) -> Result<Self, Error> {
            check_timeout(timeout)?;
            Ok(Self {
                timeout,
                wpad: false,
            })
        }

        /// The per-resolution budget, counted from the call: waiting for another CFNetwork
        /// PAC call in the process spends it too, and runs to that call's end even past it.
        #[must_use]
        pub fn timeout(&self) -> Duration {
            self.timeout
        }

        /// Allow [`WpadAutoDetect`](ProxyMode::WpadAutoDetect). Off by default: discovery
        /// asks the local network where the PAC script is, and whoever answers for `wpad`
        /// there chooses the proxy.
        ///
        /// On, [`resolve_config`](Self::resolve_config) asks CFNetwork for the system
        /// settings' answer (`CFNetworkCopyProxiesForURL` with
        /// `CFNetworkCopySystemProxySettings`) and runs the PAC URL it names: with
        /// discovery alone, `http://wpad/wpad.dat`, or the URL DHCP option 252 handed the
        /// system. Which of DNS and DHCP CFNetwork asks first is its own choice.
        ///
        /// An unresolvable `wpad` host (`NSURLErrorDomain` -1003) is a miss: the next
        /// entry in CFNetwork's answer is tried, and misses to the end of it resolve Direct.
        /// Every other failure is an error, where a client that takes a failed
        /// script for no proxy answers Direct. That rule is this crate's own (.NET, Envoy,
        /// Chromium and libproxy branch on no error code) and it rests on measuring what
        /// discovery-only settings give on a network with no WPAD.
        ///
        /// Off, a Mac with discovery on is [`Error::PacNotSupported`] here, while clients
        /// that ignore the discovery flag (Firefox, .NET) run `http://wpad/wpad.dat` as an
        /// ordinary PAC URL on the same machine.
        ///
        /// CFNetwork may answer from a PAC result another process cached.
        #[must_use]
        pub fn with_wpad(mut self, wpad: bool) -> Self {
            self.wpad = wpad;
            self
        }

        /// Whether [`WpadAutoDetect`](ProxyMode::WpadAutoDetect) is resolved.
        #[must_use]
        pub fn wpad(&self) -> bool {
            self.wpad
        }

        /// Download the script at `pac_url` and run `FindProxyForURL` for `url`.
        ///
        /// A download failure and a script failure both come back as [`Error::Io`] carrying
        /// CFNetwork's error domain and code; the PAC URL is not repeated in it, because it
        /// can carry `user:password@`.
        ///
        /// # Errors
        ///
        /// [`Error::PacTimeout`], [`Error::PacInvalidResult`], [`Error::Io`].
        pub fn resolve(&self, url: &Url, pac_url: &Url) -> Result<Vec<ProxyStep>, Error> {
            let deadline = Instant::now().checked_add(self.timeout);
            let pac = cf_url(pac_url.as_str())?;
            let target = cf_url(crate::pac::sanitize_url(url).as_str())?;
            match self.execute_url(deadline, &pac, &target)? {
                Ok(array) => array_to_steps(array.as_ref()),
                Err(error) => Err(url_error(&error)),
            }
        }

        fn execute_url(
            &self,
            deadline: Option<Instant>,
            pac: &CFURL,
            target: &CFURL,
        ) -> Result<Answer, Error> {
            pump(self.timeout, deadline, target, |target, context| {
                // SAFETY: both URLs are live CF objects for the duration of the call, the
                // callback has the signature CFNetwork requires, and `context` points at a
                // `ClientContext` that `pump` keeps alive until the source is invalidated.
                unsafe {
                    CFNetworkExecuteProxyAutoConfigurationURL(
                        pac.as_concrete_TypeRef(),
                        target,
                        on_result,
                        context,
                    )
                }
            })
        }

        // [`ProxyMode::WpadAutoDetect`], from the settings the system holds now.
        fn resolve_wpad(&self, url: &Url) -> Result<Vec<ProxyStep>, Error> {
            let deadline = Instant::now().checked_add(self.timeout);
            let target = cf_url(crate::pac::sanitize_url(url).as_str())?;
            // SAFETY: no arguments; the result follows the Copy rule.
            let raw = unsafe { CFNetworkCopySystemProxySettings() };
            if raw.is_null() {
                return Err(Error::io(
                    "CFNetwork resolving WPAD",
                    io::Error::other("CFNetworkCopySystemProxySettings returned NULL"),
                ));
            }
            // SAFETY: a non-NULL result of a `Copy` function, owned by the caller.
            let settings: CFDictionary = unsafe { CFDictionary::wrap_under_create_rule(raw) };
            self.resolve_with_settings(deadline, &target, &settings)
        }

        // The walk over CFNetwork's answer for `settings`, which the system hands
        // `resolve_wpad` and a test can build.
        fn resolve_with_settings(
            &self,
            deadline: Option<Instant>,
            target: &CFURL,
            settings: &CFDictionary,
        ) -> Result<Vec<ProxyStep>, Error> {
            // The snapshot said discovery; settings that no longer run a script belong to a
            // later snapshot, and answering from them would answer for that one.
            if !runs_a_script(settings) {
                return Err(Error::io(
                    "CFNetwork resolving WPAD",
                    io::Error::other("the system proxy settings no longer name a PAC script"),
                ));
            }
            // SAFETY: both arguments are live CF objects; the result follows the Copy rule.
            let raw = unsafe {
                CFNetworkCopyProxiesForURL(
                    target.as_concrete_TypeRef(),
                    settings.as_concrete_TypeRef(),
                )
            };
            // SAFETY: a non-NULL result of a `Copy` function, owned by the caller.
            let array =
                (!raw.is_null()).then(|| unsafe { CFArray::<CFType>::wrap_under_create_rule(raw) });
            walk_system_entries(&read_entries(array.as_ref()), |pac_url| {
                let pac = cf_url(pac_url)?;
                match self.execute_url(deadline, &pac, target)? {
                    Ok(array) => array_to_steps(array.as_ref()).map(Some),
                    Err(error)
                        if is_wpad_miss(
                            pac_url,
                            &text(&error.domain()).unwrap_or_default(),
                            error.code(),
                        ) =>
                    {
                        Ok(None)
                    }
                    Err(error) => Err(url_error(&error)),
                }
            })
        }

        /// Like [`resolve_with_pac`](crate::resolve_with_pac) but CFNetwork fetches and runs
        /// the script. A URL with no host is Direct in every PAC mode.
        ///
        /// `WpadAutoDetect` reads the live system settings, so it is resolved only for a
        /// `config` whose effective mode is its
        /// [`SystemConfigurationState`](ProxyConfigSource::SystemConfigurationState) entry
        /// (on iOS, its `CfNetworkSystemSettings` one), the scope those settings are. Where
        /// a snapshot has the discovery switch and a PAC URL both on, that scope carries
        /// the URL alone and the mode is `Pac`.
        ///
        /// # Errors
        ///
        /// [`Error::PacNotSupported`] for `WpadAutoDetect` without
        /// [`with_wpad(true)`](Self::with_wpad) or from another scope, plus
        /// [`resolve`](Self::resolve)'s errors and [`CfNetworkPacEvaluator`]'s for
        /// `PacInline`, and, for the Direct/Manual arm, [`resolve`](crate::resolve())'s.
        pub fn resolve_config(
            &self,
            config: &ProxyConfig,
            url: &Url,
        ) -> Result<Vec<ProxyStep>, Error> {
            let mode = &config.effective;
            let has_host = crate::endpoint::has_request_host(url);
            match mode {
                ProxyMode::Direct | ProxyMode::Manual { .. } => {
                    crate::resolve::resolve(config, url)
                }
                ProxyMode::Pac { .. } | ProxyMode::PacInline { .. } | ProxyMode::WpadAutoDetect
                    if !has_host =>
                {
                    Ok(vec![ProxyStep::Direct])
                }
                ProxyMode::WpadAutoDetect
                    if self.wpad && config.source(SYSTEM_SOURCE) == Some(mode) =>
                {
                    self.resolve_wpad(url)
                }
                ProxyMode::WpadAutoDetect => Err(Error::PacNotSupported { mode: "wpad" }),
                ProxyMode::Pac { url: pac_url, .. } => self.resolve(url, pac_url),
                ProxyMode::PacInline { script, .. } => evaluate_script(script, url, self.timeout),
            }
        }
    }

    impl Default for CfNetworkPacResolver {
        fn default() -> Self {
            Self::new()
        }
    }

    fn check_timeout(timeout: Duration) -> Result<(), Error> {
        if timeout.is_zero() {
            return Err(Error::PacTimeout { timeout });
        }
        Ok(())
    }

    // Carries CFNetwork's error domain and code only: the PAC URL can carry
    // `user:password@`.
    fn url_error(error: &CFError) -> Error {
        Error::io(
            "CFNetwork resolving a PAC URL",
            io::Error::other(format!(
                "{} error {}",
                text(&error.domain())
                    .as_deref()
                    .unwrap_or("<unreadable domain>"),
                error.code()
            )),
        )
    }

    // Whether the system settings run a script, from a URL or by discovery.
    fn runs_a_script(settings: &CFDictionary) -> bool {
        ["ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"]
            .into_iter()
            .any(|key| {
                let key = CFString::from_static_string(key);
                settings
                    .find(key.as_concrete_TypeRef().cast::<c_void>())
                    // SAFETY: a value borrowed from `settings`, retained by the wrapper.
                    .map(|value| unsafe { CFType::wrap_under_get_rule(*value) })
                    .and_then(|value| value.downcast::<CFNumber>())
                    .and_then(|value| value.to_i64())
                    == Some(1)
            })
    }

    fn evaluate_script(
        script: &str,
        url: &Url,
        timeout: Duration,
    ) -> Result<Vec<ProxyStep>, Error> {
        let deadline = Instant::now().checked_add(timeout);
        let script = CFString::new(script);
        let target = cf_url(crate::pac::sanitize_url(url).as_str())?;
        let answer = pump(timeout, deadline, &target, |target, context| {
            // SAFETY: as in `CfNetworkPacResolver::resolve`.
            unsafe {
                CFNetworkExecuteProxyAutoConfigurationScript(
                    script.as_concrete_TypeRef(),
                    target,
                    on_result,
                    context,
                )
            }
        })?;
        match answer {
            Ok(array) => array_to_steps(array.as_ref()),
            // Through the masking constructor: the description can quote the script.
            Err(error) => Err(Error::pac_evaluation(format!(
                "CFNetwork: {} (error {} {})",
                text(&error.description())
                    .as_deref()
                    .unwrap_or("<unreadable description>"),
                text(&error.domain())
                    .as_deref()
                    .unwrap_or("<unreadable domain>"),
                error.code()
            ))),
        }
    }

    fn cf_url(text: &str) -> Result<CFURL, Error> {
        let length = CFIndex::try_from(text.len())
            .map_err(|_| Error::io("building a CFURL", io::Error::other("URL too long")))?;
        // SAFETY: `text` is valid for `length` bytes for the duration of the call; the base
        // URL is NULL, which CFNetwork documents as "no base".
        let raw = unsafe {
            CFURLCreateWithBytes(
                kCFAllocatorDefault,
                text.as_ptr(),
                length,
                kCFStringEncodingUTF8,
                ptr::null(),
            )
        };
        if raw.is_null() {
            return Err(Error::io(
                "building a CFURL",
                io::Error::other("CFURLCreateWithBytes returned NULL"),
            ));
        }
        // SAFETY: a non-NULL result of a `Create` function, owned by the caller.
        Ok(unsafe { CFURL::wrap_under_create_rule(raw) })
    }

    // Start one `Execute` call through `start` and run the private mode until its callback
    // has answered or `deadline` has passed; `None` when the budget is too large to add to
    // the start, and then only the answer ends it. `timeout` is what the error reports.
    fn pump(
        timeout: Duration,
        deadline: Option<Instant>,
        target: &CFURL,
        start: impl FnOnce(CFURLRef, *mut ClientContext) -> CFRunLoopSourceRef,
    ) -> Result<Answer, Error> {
        let _serial = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        warm_up(target);

        let mut answer: Option<Answer> = None;
        let mut context = ClientContext {
            version: 0,
            info: (&raw mut answer).cast(),
            retain: None,
            release: None,
            copy_description: None,
        };
        let raw = start(target.as_concrete_TypeRef(), &raw mut context);
        if raw.is_null() {
            return Err(Error::io(
                "starting a CFNetwork PAC call",
                io::Error::other("CFNetwork returned no run loop source"),
            ));
        }
        // SAFETY: the `Execute` functions follow the Create rule for the source they return.
        let source = unsafe { CFRunLoopSource::wrap_under_create_rule(raw) };
        let mode = CFString::from_static_string(RUN_LOOP_MODE);
        let run_loop = CFRunLoop::get_current();
        run_loop.add_source(&source, mode.as_concrete_TypeRef());

        while answer.is_none() {
            let left = match deadline {
                Some(deadline) => deadline.saturating_duration_since(Instant::now()),
                None => Duration::from_secs(3600),
            };
            if left.is_zero() {
                break;
            }
            CFRunLoop::run_in_mode(mode.as_concrete_TypeRef(), left, false);
        }

        // SAFETY: `source` is a live run loop source. Invalidating it before `answer` and
        // `context` go out of scope is what guarantees the callback, which writes through
        // `context.info`, never runs after this function has returned.
        unsafe { CFRunLoopSourceInvalidate(source.as_concrete_TypeRef()) };
        run_loop.remove_source(&source, mode.as_concrete_TypeRef());

        answer.ok_or(Error::PacTimeout { timeout })
    }

    // rdar://5530166: CFNetwork's `Execute` calls need state that a `CFNetworkCopyProxiesForURL`
    // call sets up. Apple's CFProxySupportTool and Chromium both make this call with an empty
    // dictionary before every execution, and so does this.
    fn warm_up(target: &CFURL) {
        let empty: CFDictionary<CFType, CFType> = CFDictionary::from_CFType_pairs(&[]);
        // SAFETY: both arguments are live CF objects; the result follows the Copy rule and is
        // released by the wrapper.
        let raw = unsafe {
            CFNetworkCopyProxiesForURL(target.as_concrete_TypeRef(), empty.as_concrete_TypeRef())
        };
        if !raw.is_null() {
            // SAFETY: a non-NULL result of a `Copy` function, owned by the caller.
            drop(unsafe { CFArray::<CFType>::wrap_under_create_rule(raw) });
        }
    }

    // The result callback, delivered on the pumping thread while `pump` runs its mode.
    unsafe extern "C" fn on_result(client: *mut c_void, proxies: CFArrayRef, error: CFErrorRef) {
        let answer = if error.is_null() {
            // SAFETY: CFNetwork owns `proxies` for the duration of the callback (Get rule);
            // the wrapper retains it.
            Ok((!proxies.is_null())
                .then(|| unsafe { CFArray::<CFType>::wrap_under_get_rule(proxies) }))
        } else {
            // SAFETY: as above, for the error.
            Err(unsafe { CFError::wrap_under_get_rule(error) })
        };
        // SAFETY: `client` is `context.info` from `pump`, which points at an
        // `Option<Answer>` that outlives the source this callback is attached to.
        unsafe { *client.cast::<Option<Answer>>() = Some(answer) };
        CFRunLoop::get_current().stop();
    }

    fn array_to_steps(array: Option<&CFArray<CFType>>) -> Result<Vec<ProxyStep>, Error> {
        entries_to_steps(&read_entries(array))
    }

    fn read_entries(array: Option<&CFArray<CFType>>) -> Vec<Entry> {
        array
            .map(|array| array.iter().filter_map(|item| read_entry(&item)).collect())
            .unwrap_or_default()
    }

    fn read_entry(item: &CFType) -> Option<Entry> {
        let dict = item.downcast::<CFDictionary>()?;
        let get = |key: CFStringRef| {
            dict.find(key.cast::<c_void>())
                // SAFETY: a value borrowed from `dict`, retained by the wrapper.
                .map(|value| unsafe { CFType::wrap_under_get_rule(*value) })
        };
        // SAFETY: reading `extern` statics that CFNetwork initialises at load time.
        let (type_key, host_key, port_key, pac_key) = unsafe {
            (
                kCFProxyTypeKey,
                kCFProxyHostNameKey,
                kCFProxyPortNumberKey,
                kCFProxyAutoConfigurationURLKey,
            )
        };
        let kind = get(type_key)?.downcast::<CFString>()?;
        // SAFETY: as above.
        let kind = unsafe {
            if kind == CFString::wrap_under_get_rule(kCFProxyTypeNone) {
                EntryKind::None
            } else if kind == CFString::wrap_under_get_rule(kCFProxyTypeHTTP) {
                EntryKind::Http
            } else if kind == CFString::wrap_under_get_rule(kCFProxyTypeHTTPS) {
                EntryKind::Https
            } else if kind == CFString::wrap_under_get_rule(kCFProxyTypeSOCKS) {
                EntryKind::Socks
            } else if kind == CFString::wrap_under_get_rule(kCFProxyTypeAutoConfigurationURL) {
                EntryKind::AutoConfigUrl
            } else {
                EntryKind::Other
            }
        };
        Some(Entry {
            kind,
            host: get(host_key)
                .and_then(|host| host.downcast::<CFString>())
                .and_then(|host| text(&host)),
            port: get(port_key)
                .and_then(|port| port.downcast::<CFNumber>())
                .and_then(|port| port.to_i64()),
            // The header types this value `CFURLRef`.
            pac_url: get(pac_key)
                .and_then(|pac| pac.downcast::<CFURL>())
                .and_then(|pac| text(&pac.absolute().get_string())),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn settings(pairs: &[(&str, CFType)]) -> CFDictionary {
            let pairs: Vec<(CFString, CFType)> = pairs
                .iter()
                .map(|(key, value)| (CFString::new(key), value.clone()))
                .collect();
            CFDictionary::from_CFType_pairs(&pairs).into_untyped()
        }

        // A host CFNetwork hands back holding an unpaired UTF-16 surrogate reads as absent:
        // the entry is dropped and the answer is the invalid-result error, not a panic on
        // the caller's thread.
        #[test]
        fn an_unreadable_host_drops_the_entry_instead_of_panicking() {
            let chars: [core_foundation::string::UniChar; 1] = [0xD800];
            // SAFETY: `chars` is valid for one `UniChar`; the result is owned (`Create`).
            let malformed = unsafe {
                CFString::wrap_under_create_rule(
                    core_foundation::string::CFStringCreateWithCharacters(
                        kCFAllocatorDefault,
                        chars.as_ptr(),
                        1,
                    ),
                )
            };
            // SAFETY: reading `extern` statics that CFNetwork initialises at load time.
            let (type_key, http, host_key) = unsafe {
                (
                    CFString::wrap_under_get_rule(kCFProxyTypeKey),
                    CFString::wrap_under_get_rule(kCFProxyTypeHTTP),
                    CFString::wrap_under_get_rule(kCFProxyHostNameKey),
                )
            };
            let entry = CFDictionary::from_CFType_pairs(&[
                (type_key, http.as_CFType()),
                (host_key, malformed.as_CFType()),
            ])
            .into_untyped();

            let read = read_entry(&entry.as_CFType()).expect("the type key is readable");
            assert_eq!((read.kind, read.host), (EntryKind::Http, None));
            assert!(matches!(
                array_to_steps(Some(&CFArray::from_CFTypes(&[entry.as_CFType()]))),
                Err(Error::PacInvalidResult { .. })
            ));
        }

        // The whole WPAD path through CFNetwork, with settings built here instead of read
        // from the machine: the shape of the array CFNetwork returns for them is what the
        // pure tests of `walk_system_entries` assume and cannot check.
        #[test]
        #[ignore = "asks the network for `wpad` and connects to 127.0.0.1:1"]
        fn system_settings_resolve_through_cfnetwork() {
            let resolver = CfNetworkPacResolver::new();
            let target = cf_url("http://example.com/").unwrap();
            let run = |pairs: &[(&str, CFType)]| {
                let deadline = Instant::now().checked_add(resolver.timeout());
                resolver.resolve_with_settings(deadline, &target, &settings(pairs))
            };
            let on = CFNumber::from(1).as_CFType();
            let pac = |url: &str| {
                [
                    ("ProxyAutoConfigEnable", on.clone()),
                    ("ProxyAutoConfigURLString", CFString::new(url).as_CFType()),
                ]
            };

            // Discovery as configd publishes it, on a network with no `wpad`: a miss, with
            // nothing beneath it.
            let [enable, url] = pac("http://wpad/wpad.dat");
            let discovery = [enable, url, ("ProxyAutoDiscoveryEnable", on.clone())];
            assert_eq!(run(&discovery).unwrap(), vec![ProxyStep::Direct]);

            // A script nothing serves is a failure, not a miss.
            assert!(matches!(
                run(&pac("http://127.0.0.1:1/p.pac")),
                Err(Error::Io { .. })
            ));

            // Settings that run no script are refused before CFNetwork is asked.
            assert!(matches!(run(&[]), Err(Error::Io { .. })));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: EntryKind, host: &str, port: i64) -> Entry {
        Entry {
            kind,
            host: Some(host.to_owned()),
            port: Some(port),
            pac_url: None,
        }
    }

    fn direct() -> Entry {
        Entry {
            kind: EntryKind::None,
            host: None,
            port: None,
            pac_url: None,
        }
    }

    fn pac(url: &str) -> Entry {
        Entry {
            kind: EntryKind::AutoConfigUrl,
            host: None,
            port: None,
            pac_url: Some(url.to_owned()),
        }
    }

    // The mapping is the JS engines' reading of the same candidates, so the oracle is
    // `parse_find_proxy_result` on the string a script would have returned.
    fn same_as(result: &str, entries: &[Entry]) {
        assert_eq!(
            entries_to_steps(entries).unwrap(),
            crate::pac::parse_find_proxy_result(result).unwrap(),
            "{result}"
        );
    }

    #[test]
    fn each_type_maps_as_the_js_engines_read_it() {
        same_as(
            "PROXY a.example:8080; HTTPS b.example:443; SOCKS c.example:1080; DIRECT",
            &[
                entry(EntryKind::Http, "a.example", 8080),
                entry(EntryKind::Https, "b.example", 443),
                entry(EntryKind::Socks, "c.example", 1080),
                direct(),
            ],
        );
    }

    #[test]
    fn a_bare_ipv6_host_is_bracketed() {
        same_as(
            "PROXY [2001:db8::1]:3128",
            &[entry(EntryKind::Http, "2001:db8::1", 3128)],
        );
    }

    #[test]
    fn a_missing_or_impossible_port_takes_the_default() {
        let mut no_port = entry(EntryKind::Http, "a.example", 0);
        no_port.port = None;
        same_as("PROXY a.example", &[no_port]);
        same_as(
            "PROXY a.example",
            &[entry(EntryKind::Http, "a.example", 70000)],
        );
    }

    #[test]
    fn other_types_and_unusable_hosts_are_skipped() {
        same_as(
            "PROXY ok.example:1",
            &[
                entry(EntryKind::Other, "pac.example", 80),
                entry(EntryKind::Http, "x.example; PROXY evil.example", 1),
                entry(EntryKind::Http, "", 1),
                // What CFNetwork makes of a script's `PROXY [2001:db8::1]:3128`.
                entry(EntryKind::Http, "[2001", 0),
                entry(EntryKind::Http, "ok.example", 1),
            ],
        );
    }

    #[test]
    fn nothing_usable_is_an_error() {
        assert!(matches!(
            entries_to_steps(&[]),
            Err(Error::PacInvalidResult { .. })
        ));
        assert!(matches!(
            entries_to_steps(&[entry(EntryKind::Other, "pac.example", 80)]),
            Err(Error::PacInvalidResult { .. })
        ));
    }

    fn steps(result: &str) -> Vec<ProxyStep> {
        crate::pac::parse_find_proxy_result(result).unwrap()
    }

    #[test]
    fn the_first_pac_that_answers_is_the_answer() {
        let mut ran = Vec::new();
        let answer = walk_system_entries(
            &[
                pac("http://wpad/wpad.dat"),
                pac("http://second/p.pac"),
                direct(),
            ],
            |url| {
                ran.push(url.to_owned());
                Ok((url != "http://wpad/wpad.dat").then(|| steps("PROXY p.example:1")))
            },
        );
        assert_eq!(answer.unwrap(), steps("PROXY p.example:1"));
        assert_eq!(ran, ["http://wpad/wpad.dat", "http://second/p.pac"]);
    }

    #[test]
    fn misses_to_the_end_are_direct() {
        let answer = walk_system_entries(&[pac("http://wpad/wpad.dat")], |_| Ok(None));
        assert_eq!(answer.unwrap(), vec![ProxyStep::Direct]);
    }

    #[test]
    fn a_miss_falls_to_the_entries_beneath_as_given() {
        let answer = walk_system_entries(
            &[
                pac("http://wpad/wpad.dat"),
                entry(EntryKind::Http, "beneath.example", 3128),
                direct(),
            ],
            |_| Ok(None),
        );
        assert_eq!(answer.unwrap(), steps("PROXY beneath.example:3128; DIRECT"));
    }

    #[test]
    fn an_array_without_a_pac_is_taken_as_given() {
        let answer = walk_system_entries(&[direct()], |_| panic!("no PAC to run"));
        assert_eq!(answer.unwrap(), vec![ProxyStep::Direct]);
    }

    #[test]
    fn a_failure_is_not_a_miss_and_stops_the_walk() {
        let answer = walk_system_entries(&[pac("http://wpad/wpad.dat"), direct()], |_| {
            Err(Error::PacTimeout {
                timeout: std::time::Duration::from_secs(1),
            })
        });
        assert!(
            matches!(answer, Err(Error::PacTimeout { .. })),
            "{answer:?}"
        );
    }

    #[test]
    fn an_empty_array_is_an_error() {
        assert!(matches!(
            walk_system_entries(&[], |_| Ok(None)),
            Err(Error::PacInvalidResult { .. })
        ));
    }

    #[test]
    fn only_an_unresolvable_wpad_host_is_a_miss() {
        assert!(is_wpad_miss(
            "http://wpad/wpad.dat",
            "NSURLErrorDomain",
            -1003
        ));
        assert!(is_wpad_miss(
            "http://WPAD/wpad.dat",
            "NSURLErrorDomain",
            -1003
        ));
        // Refused: something answers for `wpad`.
        assert!(!is_wpad_miss(
            "http://wpad/wpad.dat",
            "NSURLErrorDomain",
            -1004
        ));
        // A URL DHCP handed over names a server the network chose.
        assert!(!is_wpad_miss(
            "http://pac.corp/wpad.dat",
            "NSURLErrorDomain",
            -1003
        ));
        assert!(!is_wpad_miss(
            "http://wpad.corp/wpad.dat",
            "NSURLErrorDomain",
            -1003
        ));
        assert!(!is_wpad_miss(
            "http://wpad/wpad.dat",
            "kCFErrorDomainCFNetwork",
            -1003
        ));
    }
}
