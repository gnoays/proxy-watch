//! `pac-windows-native`: PAC/WPAD via WinHTTP (`cfg(windows)` + feature; no-op elsewhere).
//!
//! Not a [`PacEvaluator`](super::PacEvaluator): WinHTTP takes *where* the script lives
//! (`WINHTTP_AUTOPROXY_OPTIONS`), not a JS body — separate API. Sole route that
//! downloads/discovers for you (`winhttp.dll`); [`ProxyMode::PacInline`] stays `pac-boa`.
//!
//! Async `WinHttpGetProxyForUrlEx` is blocked on a manual-reset [`Event`] with a
//! **bounded timeout** (cancel by closing the resolver; callback keeps its `Arc` alive).

use std::collections::HashSet;
use std::ffi::c_void;
use std::fmt;
use std::net::Ipv6Addr;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use url::{Host, Url};

use windows::Win32::Foundation::{ERROR_IO_PENDING, ERROR_SUCCESS, WAIT_OBJECT_0};
use windows::Win32::Networking::WinHttp::{
    ERROR_WINHTTP_AUTODETECTION_FAILED, ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT,
    ERROR_WINHTTP_INTERNAL_ERROR, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_ASYNC_RESULT,
    WINHTTP_AUTO_DETECT_TYPE_DHCP, WINHTTP_AUTO_DETECT_TYPE_DNS_A, WINHTTP_AUTOPROXY_AUTO_DETECT,
    WINHTTP_AUTOPROXY_CONFIG_URL, WINHTTP_AUTOPROXY_OPTIONS,
    WINHTTP_CALLBACK_FLAG_GETPROXYFORURL_COMPLETE, WINHTTP_CALLBACK_FLAG_REQUEST_ERROR,
    WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE, WINHTTP_CALLBACK_STATUS_REQUEST_ERROR,
    WINHTTP_FLAG_ASYNC, WINHTTP_INTERNET_SCHEME_HTTP, WINHTTP_INTERNET_SCHEME_HTTPS,
    WINHTTP_INTERNET_SCHEME_SOCKS, WINHTTP_PROXY_RESULT, WINHTTP_PROXY_RESULT_ENTRY,
    WinHttpCloseHandle, WinHttpCreateProxyResolver, WinHttpFreeProxyResult,
    WinHttpGetProxyForUrlEx, WinHttpGetProxyResult, WinHttpOpen, WinHttpSetStatusCallback,
    WinHttpSetTimeouts,
};
use windows::Win32::System::Threading::{SetEvent, WaitForSingleObject};
use windows::core::PCWSTR;

use crate::config::{ProxyConfig, ProxyConfigSource};
use crate::endpoint::{ProxyEndpoint, ProxyScheme};
use crate::error::Error;
use crate::mode::ProxyMode;
use crate::resolve::ProxyStep;
use crate::sys::win::ffi::{Event, wide, wide_ptr_to_string};

/// Default native resolution budget (5 s) — same as [`DEFAULT_PAC_TIMEOUT`](super::DEFAULT_PAC_TIMEOUT),
/// but also covers WPAD discovery and script download.
pub const DEFAULT_WINHTTP_PAC_TIMEOUT: Duration = Duration::from_secs(5);

// The user agent WinHTTP reports while downloading a PAC script.
const USER_AGENT: &str = "proxy-watch";

/// Where WinHTTP looks for the PAC script (`WINHTTP_AUTOPROXY_OPTIONS` — not a body).
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WinHttpPacSource {
    /// WPAD: DHCP option 252, then `wpad.<domain>`. Miss → not an error
    /// ([`WinHttpPacResolver::resolve`]).
    AutoDetect,
    /// Explicit PAC URL ([`ProxyMode::Pac`]).
    Url(Url),
    /// WPAD first, then URL — Windows "auto-detect + script" both ticked.
    /// [`ProxyMode`] is single-valued; [`WinHttpPacResolver::resolve_config`] rebuilds
    /// this for [`ProxyMode::WpadAutoDetect`] by re-reading the registry.
    AutoDetectThenUrl(Url),
}

// Masked like [`ProxyMode::Pac`]'s `Debug`: an `AutoConfigURL` read off a real machine
// can carry `user:password@`, and this type is where that URL lands on its way into
// WinHTTP. Deriving `Debug` would print what [`ProxyMode`] took care not to.
impl fmt::Debug for WinHttpPacSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AutoDetect => f.write_str("AutoDetect"),
            Self::Url(url) => f
                .debug_tuple("Url")
                .field(&format_args!(
                    "{}",
                    crate::util::redact_userinfo(url.as_str())
                ))
                .finish(),
            Self::AutoDetectThenUrl(url) => f
                .debug_tuple("AutoDetectThenUrl")
                .field(&format_args!(
                    "{}",
                    crate::util::redact_userinfo(url.as_str())
                ))
                .finish(),
        }
    }
}

impl WinHttpPacSource {
    /// [`ProxyMode::Pac`] → [`Url`](Self::Url), [`WpadAutoDetect`](ProxyMode::WpadAutoDetect)
    /// → [`AutoDetect`](Self::AutoDetect); [`PacInline`](ProxyMode::PacInline) → `None`.
    ///
    /// ```
    /// # #[cfg(all(windows, feature = "pac-windows-native"))] {
    /// use proxy_watch::pac::WinHttpPacSource;
    /// use proxy_watch::{ProxyMode, Url};
    ///
    /// let mode = ProxyMode::pac(Url::parse("http://wpad.corp/proxy.pac").unwrap());
    /// assert!(matches!(WinHttpPacSource::from_mode(&mode), Some(WinHttpPacSource::Url(_))));
    /// assert_eq!(
    ///     WinHttpPacSource::from_mode(&ProxyMode::WpadAutoDetect),
    ///     Some(WinHttpPacSource::AutoDetect)
    /// );
    /// assert_eq!(WinHttpPacSource::from_mode(&ProxyMode::Direct), None);
    /// # }
    /// ```
    #[must_use]
    pub fn from_mode(mode: &ProxyMode) -> Option<Self> {
        match mode {
            ProxyMode::Pac { url, .. } => Some(Self::Url(url.clone())),
            ProxyMode::WpadAutoDetect => Some(Self::AutoDetect),
            _ => None,
        }
    }

    // The `dwFlags` value for `WINHTTP_AUTOPROXY_OPTIONS`.
    fn flags(&self) -> u32 {
        match self {
            Self::AutoDetect => WINHTTP_AUTOPROXY_AUTO_DETECT,
            Self::Url(_) => WINHTTP_AUTOPROXY_CONFIG_URL,
            Self::AutoDetectThenUrl(_) => {
                WINHTTP_AUTOPROXY_AUTO_DETECT | WINHTTP_AUTOPROXY_CONFIG_URL
            }
        }
    }

    fn url(&self) -> Option<&Url> {
        match self {
            Self::AutoDetect => None,
            Self::Url(url) | Self::AutoDetectThenUrl(url) => Some(url),
        }
    }
}

// Whether a status code is the "WPAD found nothing" answer *for this request*.
//
// `ERROR_WINHTTP_AUTODETECTION_FAILED` can only mean a discovery miss when discovery was
// asked for. A [`WinHttpPacSource::Url`] request names one place to look and has nothing
// to discover, so the same code has to stay an error there: degrading it to `[Direct]`
// would turn a failed PAC fetch into "no proxy" and silently bypass the proxy an
// administrator configured. Measured Windows runs put a URL-side failure on
// `ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT` instead, so no call has ever been seen to
// take this path — the guard makes the contract stated on `resolve_raw` load-bearing
// rather than repairing an observed answer.
fn is_wpad_miss(flags: u32, status: u32) -> bool {
    status == ERROR_WINHTTP_AUTODETECTION_FAILED && flags & WINHTTP_AUTOPROXY_AUTO_DETECT != 0
}

// Convert the configured resolution budget into the timeout for the
// `WaitForSingleObject` in [`WinHttpPacResolver::resolve_raw`].
//
// The clamp lands at `u32::MAX - 1`, not `u32::MAX`: the latter *is* `INFINITE`, so
// saturating there would turn the bounded wait `resolve_raw` promises into an unbounded
// one and [`Error::PacTimeout`] could never come from it. Only a `timeout` past roughly
// fifty days reaches the saturation at all. Same shape as `poll_wait_millis` and
// `debounce_wait_millis` in `src/sys/win/notify.rs`, for the same reason.
fn wait_millis(timeout: Duration) -> u32 {
    u32::try_from(timeout.as_millis())
        .unwrap_or(u32::MAX)
        .min(u32::MAX - 1)
}

// Convert the same budget into the four timeouts the WinHTTP session itself is given.
//
// Floored at 1, not 0, for the mirror of the reason [`wait_millis`] clamps below
// `INFINITE`: `WinHttpSetTimeouts` documents "A value of 0 or -1 sets a time-out to wait
// infinitely", so a budget shorter than a millisecond would truncate onto exactly the
// meaning [`WinHttpPacResolver::with_timeout`] refuses to let a caller ask for, and would
// leave the session's name resolution, connect, send and receive unbounded for the life of
// the resolver. Saturating at `i32::MAX` is safe at the other end: only a negative other
// than -1 is rejected by the API.
fn session_timeout_millis(timeout: Duration) -> i32 {
    i32::try_from(timeout.as_millis())
        .unwrap_or(i32::MAX)
        .max(1)
}

/// PAC/WPAD via `WinHttpGetProxyForUrlEx`. Reuse one session; the cache it does *not*
/// bound is described on [`resolve`](Self::resolve).
///
/// [`Pac`](ProxyMode::Pac) / [`WpadAutoDetect`](ProxyMode::WpadAutoDetect): native fetch.
/// [`PacInline`](ProxyMode::PacInline): `pac-boa`. Direct/Manual: [`resolve_config`](Self::resolve_config).
/// [`resolve_config`](Self::resolve_config) answers a hostless URL Direct, except
/// [`PacInline`](ProxyMode::PacInline): that one is [`Error::PacNotSupported`] whether or not
/// the URL has a host. [`resolve`](Self::resolve) does not short-circuit it — see its doc.
/// **[`PacPolicy`](super::PacPolicy) does not apply** — real DNS/local IP.
#[derive(Debug)]
pub struct WinHttpPacResolver {
    session: Session,
    timeout: Duration,
}

impl WinHttpPacResolver {
    /// Open a session with the default [`DEFAULT_WINHTTP_PAC_TIMEOUT`] budget.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when `WinHttpOpen`, `WinHttpSetTimeouts` or
    /// `WinHttpSetStatusCallback` fails.
    pub fn new() -> Result<Self, Error> {
        Self::with_timeout(DEFAULT_WINHTTP_PAC_TIMEOUT)
    }

    /// Open a session; zero `timeout` → [`Error::PacTimeout`] (not "unlimited").
    ///
    /// # Errors
    ///
    /// [`Error::Io`] (`WinHttpOpen` / `SetTimeouts` / `SetStatusCallback`) or
    /// [`Error::PacTimeout`] when `timeout` is zero.
    pub fn with_timeout(timeout: Duration) -> Result<Self, Error> {
        if timeout.is_zero() {
            return Err(Error::PacTimeout { timeout });
        }
        let session = Session::open(timeout)?;
        Ok(Self { session, timeout })
    }

    /// The per-resolution budget.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Resolve `url` via `source`. Full `FindProxyForURL` chain → [`ProxyStep`]s
    /// (HTTP/HTTPS/SOCKS**4**; `fProxy == FALSE` → Direct; FTP skipped; repeats collapse,
    /// as in [`parse_find_proxy_result`](super::parse_find_proxy_result), so the chain can
    /// be shorter than the entry count WinHTTP reported).
    ///
    /// `ERROR_WINHTTP_AUTODETECTION_FAILED` → `[Direct]`, but only from a `source` that
    /// asked for auto-detect. Download / script failure — and that same code from a
    /// URL-only source, where there was nothing to discover — stays an error.
    ///
    /// A hostless URL (`mailto:`, `data:`) is resolved rather than short-circuited: this is
    /// the engine door, the native counterpart of [`pac::evaluate`](super::evaluate), and
    /// `FindProxyForURL` sees it with an empty host. Answering Direct without asking belongs
    /// to [`resolve_config`](Self::resolve_config), which was handed a whole configuration to
    /// decide from rather than a `source` the caller had already chosen.
    ///
    /// Asking twice can be answered once. What WinHTTP caches is the autoproxy URL and the
    /// script — a repeat resolution re-runs that script rather than fetching it again, and
    /// a WPAD miss is remembered for as long as the session lives. The call that would
    /// bypass the cache is deliberately not made: it hands the user's credentials to
    /// whatever WPAD found. Nothing here flushes it, and neither does dropping the
    /// resolver: `WinHttpGetProxyForUrlEx` "always executes out-of-process", and with that
    /// service active Microsoft's AutoProxy Cache topic puts the cached URL and script
    /// "available to the whole computer" — typically until the machine's IP address
    /// changes, which no caller controls. Unlike [`ProxyConfig`] the result carries no
    /// capture time to say which fetch it came from.
    ///
    /// A [`PacTimeout`](Error::PacTimeout) cancels the resolution without finishing it: the
    /// abandoned operation goes on draining behind this session, and a retry issued at once
    /// can spend its own budget waiting behind that rather than on the script. Widen the
    /// timeout or wait before retrying.
    ///
    /// # Errors
    ///
    /// [`Error::PacTimeout`], [`Error::PacEvaluation`]
    /// (`ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT`), [`Error::PacInvalidResult`],
    /// [`Error::Io`] (incl. undownloadable PAC URL).
    pub fn resolve(&self, url: &Url, source: &WinHttpPacSource) -> Result<Vec<ProxyStep>, Error> {
        match self.resolve_raw(url, source)? {
            WpadOutcome::Resolved(steps) => Ok(steps),
            // See this method's own doc: a genuine WPAD miss is not an error.
            WpadOutcome::AutoDetectionFailed => Ok(vec![ProxyStep::Direct]),
        }
    }

    // Distinguishes genuine AUTODETECTION_FAILED from a script's own DIRECT (fallback needs that).
    //
    // Not an error, synchronously either: `WinHttpGetProxyForUrlEx` need not go asynchronous
    // to fail detection. WinHTTP remembers a WPAD miss for the life of the session, so a
    // second call on one session can hand back `ERROR_WINHTTP_AUTODETECTION_FAILED` from the
    // call itself, with no callback. The status means the same thing on both paths and is
    // mapped the same way; only the callback context reference is reclaimed differently.
    fn resolve_raw(&self, url: &Url, source: &WinHttpPacSource) -> Result<WpadOutcome, Error> {
        let resolver = Resolver::create(&self.session)?;

        // Both buffers must outlive the call; `options` only borrows them.
        //
        // The *config* URL is not touched — that is the address this crate asks WinHTTP to
        // fetch, not something a script gets to read.
        let url_w = wide(&query_url(url));
        let config_url_w = source.url().map(|url| wide(url.as_str()));

        let options = WINHTTP_AUTOPROXY_OPTIONS {
            dwFlags: source.flags(),
            dwAutoDetectFlags: if source.flags() & WINHTTP_AUTOPROXY_AUTO_DETECT == 0 {
                0
            } else {
                WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
            },
            lpszAutoConfigUrl: PCWSTR(config_url_w.as_ref().map_or(ptr::null(), Vec::as_ptr)),
            lpvReserved: ptr::null_mut(),
            dwReserved: 0,
            // WinHTTP's "AutoProxy Cache" topic gives two steps: call with FALSE, and on
            // `ERROR_WINHTTP_LOGIN_FAILURE` call again with TRUE. Only step 1 is taken
            // here. TRUE is also what stops WinHTTP caching the autoproxy URL and script
            // at all under the out-of-process service the `Ex` form always uses, but
            // performance is not why step 2 is skipped: it hands the user's domain
            // credentials to whatever WPAD pointed at, so a PAC file behind an
            // NTLM/Negotiate challenge is left unfetched in a proxy *detection* library.
            fAutoLogonIfChallenged: false.into(),
        };

        let pending = Arc::new(Pending::new()?);
        // One strong reference is handed to WinHTTP as the callback context. It is
        // reclaimed by the callback, or here when no callback will run.
        let context = Arc::into_raw(Arc::clone(&pending));

        // SAFETY: `resolver` is a live proxy resolver handle, `url_w` and `config_url_w`
        // are NUL terminated UTF-16 buffers that outlive the call, `options` borrows only
        // those buffers, and `context` is a pointer from `Arc::into_raw` whose referent
        // outlives every callback because the callback owns a strong reference to it.
        let status = unsafe {
            WinHttpGetProxyForUrlEx(
                resolver.0,
                PCWSTR(url_w.as_ptr()),
                &raw const options,
                Some(context as usize),
            )
        };

        if status != ERROR_IO_PENDING.0 {
            // The call did not go asynchronous, so `status_callback` will never run for
            // it and nobody else owns the reference we just handed out. Microsoft's docs
            // do not state this rule explicitly, and this branch is rarely exercised in
            // practice (see the WPAD-miss discussion on this method's doc comment) — the
            // guarantee rests on the general WinHTTP contract that a synchronous return
            // never also delivers an asynchronous notification for the same call.
            // SAFETY: `context` came from `Arc::into_raw` above and has not been consumed.
            unsafe { drop(Arc::from_raw(context)) };
            // Mapped the same way as the async branch below; see "Not an error,
            // synchronously either" on this method's doc comment.
            if is_wpad_miss(options.dwFlags, status) {
                return Ok(WpadOutcome::AutoDetectionFailed);
            }
            if status != ERROR_SUCCESS.0 {
                return Err(winhttp_error("WinHttpGetProxyForUrlEx", status));
            }
        } else {
            // SAFETY: the event handle is owned by `pending`, which is alive here.
            let waited =
                unsafe { WaitForSingleObject(pending.done.raw(), wait_millis(self.timeout)) };
            if waited != WAIT_OBJECT_0 {
                // Closing the handle is the documented way to cancel a pending WinHTTP
                // operation — `WinHttpGetProxyForUrlEx` lists
                // `ERROR_WINHTTP_OPERATION_CANCELLED` as "usually because the handle on
                // which the request was operating was closed before the operation
                // completed". The callback still fires, and the reference it owns keeps
                // `pending` alive until it does.
                //
                // Explicit, and before the return, because otherwise the order is the
                // wrong way round. Locals drop in reverse declaration order and `resolver`
                // is declared first, so falling out of here would free `url_w`,
                // `config_url_w` and `options` while the operation was still in flight and
                // close the handle only afterwards. Microsoft states no lifetime rule for
                // this function's arguments — checked against the reference page, which
                // annotates both pointers `[in]` and says nothing more, while the
                // comparable case that does have a rule states it (`WinHttpSendRequest`'s
                // `lpOptional`). "This function always executes out-of-process" argues the
                // same way, since arguments that cross a process boundary have to be
                // copied to get there. Neither is a guarantee: the in-process stub may
                // return `ERROR_IO_PENDING` first and marshal from a worker afterwards.
                // Cancelling first costs one line and means not needing the answer.
                drop(resolver);
                return Err(Error::PacTimeout {
                    timeout: self.timeout,
                });
            }
            let code = pending.status.load(Ordering::Acquire);
            if is_wpad_miss(options.dwFlags, code) {
                return Ok(WpadOutcome::AutoDetectionFailed);
            }
            if code != ERROR_SUCCESS.0 {
                return Err(winhttp_error("resolving the proxy for a URL", code));
            }
        }

        let mut raw = WINHTTP_PROXY_RESULT::default();
        // SAFETY: `resolver` is still open and `raw` is a valid, writable out-parameter.
        // On success WinHTTP allocates the entry array, which `ProxyResult` frees.
        let status = unsafe { WinHttpGetProxyResult(resolver.0, &raw mut raw) };
        if status != ERROR_SUCCESS.0 {
            return Err(winhttp_error("WinHttpGetProxyResult", status));
        }
        ProxyResult(raw).to_steps().map(WpadOutcome::Resolved)
    }

    /// Like [`resolve_with_pac`](crate::resolve_with_pac) but WinHTTP fetches the script.
    /// Direct/Manual → [`resolve`](crate::resolve()); hostless → Direct except
    /// [`PacInline`](ProxyMode::PacInline) → [`Error::PacNotSupported`].
    ///
    /// [`WpadAutoDetect`](ProxyMode::WpadAutoDetect) may re-read the live registry for
    /// PAC URL / static fallback — not a pure function of `config` alone.
    ///
    /// # Errors
    ///
    /// [`Error::PacNotSupported`] for `PacInline`, plus [`resolve`](Self::resolve)'s errors —
    /// and, for the Direct/Manual arm this hands over, [`resolve`](crate::resolve())'s, which
    /// is where [`Error::ProxyEntryUnusable`] comes from.
    pub fn resolve_config(&self, config: &ProxyConfig, url: &Url) -> Result<Vec<ProxyStep>, Error> {
        let mode = &config.effective;
        // Asked through `has_request_host`, not `Url::host`: the Direct/Manual arm below
        // routes on the former, and the two disagree about a URL whose host was emptied.
        let has_host = crate::endpoint::has_request_host(url);
        match mode {
            ProxyMode::Direct | ProxyMode::Manual { .. } => crate::resolve::resolve(config, url),
            ProxyMode::PacInline { .. } => Err(Error::PacNotSupported { mode: "pac-inline" }),
            ProxyMode::WpadAutoDetect if has_host => self.resolve_wpad_with_fallback(config, url),
            ProxyMode::WpadAutoDetect => Ok(vec![ProxyStep::Direct]),
            _ => match WinHttpPacSource::from_mode(mode) {
                Some(source) if has_host => self.resolve(url, &source),
                Some(_) => Ok(vec![ProxyStep::Direct]),
                // `ProxyMode` is `#[non_exhaustive]`; a variant added later that this
                // engine has no answer for must say so rather than guess.
                None => Err(Error::PacNotSupported { mode: "unknown" }),
            },
        }
    }

    // Resolve [`ProxyMode::WpadAutoDetect`] without confirming `Direct` when a PAC URL
    // or a static proxy is configured beneath auto-detect.
    fn resolve_wpad_with_fallback(
        &self,
        config: &ProxyConfig,
        url: &Url,
    ) -> Result<Vec<ProxyStep>, Error> {
        // `wpad_fallback` re-reads the per-user Windows store, so it may be called only when
        // that store is what produced `effective` — not merely when something did. For a
        // config this crate built the two always coincide: `in_precedence_order` puts
        // `Registry` first and `from_ordered_sources` takes `effective` from the first entry.
        // But `ProxyConfig::new` exists so a caller can resolve precedence itself, and
        // nothing stops it handing over a snapshot whose effective `WpadAutoDetect` came from
        // `GSettings`, `Kioslaverc` or either macOS scope — every one of which produces that
        // mode, and none of which is a Windows registry. Re-reading on their behalf answers a
        // question about another machine with this one's proxy. Matching on the mode alone
        // was not enough either: the first entry carrying it may be a store this arm cannot
        // read, and reading the one it can while calling it that entry's fallback is the same
        // wrong answer wearing the right source. So the entry has to be `Registry` *and*
        // carry the effective mode; anything else gets no fallback rather than an invented
        // one, and WPAD is then all it asked for.
        let (pac_url, beneath) =
            if config.source(ProxyConfigSource::Registry) == Some(&config.effective) {
                crate::sys::win::wpad_fallback()?
            } else {
                (None, ProxyMode::Direct)
            };

        let source = match &pac_url {
            Some(pac_url) => WinHttpPacSource::AutoDetectThenUrl(pac_url.clone()),
            // Nothing usable configured as an `AutoConfigURL`: probe WPAD alone.
            None => WinHttpPacSource::AutoDetect,
        };

        match self.resolve_raw(url, &source)? {
            WpadOutcome::Resolved(steps) => Ok(steps),
            // Neither WPAD discovery nor the `AutoConfigURL` above produced a script that
            // could be run, so the answer is whatever was configured beneath both — which
            // is a static proxy far more often than it is nothing. Returning the failure
            // instead throws that away whenever a PAC URL sits between the two. See
            // `wpad_fallback_beneath`.
            WpadOutcome::AutoDetectionFailed => match beneath {
                ProxyMode::Manual { .. } => {
                    // This mode is built here and dropped here, so any record it carries
                    // beyond the one an `Error::ProxyEntryUnusable` clones is lost with it —
                    // the caller still holds `WpadAutoDetect`. That error's `rejected` doc
                    // names this arm as the exception to its reachability sentence; give it
                    // somewhere else to go and the doc goes with it.
                    let manual = ProxyConfig::from_source(ProxyConfigSource::Registry, beneath);
                    crate::resolve::resolve(&manual, url)
                }
                // Nothing configured beneath auto-detect at all: a WPAD miss really does
                // mean direct here, the same answer `resolve` itself would give.
                _ => Ok(vec![ProxyStep::Direct]),
            },
        }
    }
}

// The outcome [`WinHttpPacResolver::resolve_raw`] reports, distinguishing a genuine
// `ERROR_WINHTTP_AUTODETECTION_FAILED` from every other terminal result — what
// [`WinHttpPacResolver::resolve_wpad_with_fallback`] needs and
// [`WinHttpPacResolver::resolve`] does not.
#[derive(Debug)]
enum WpadOutcome {
    // WinHTTP produced an ordinary result: a script ran (however it answered) or a URL
    // resolved via `WINHTTP_AUTOPROXY_CONFIG_URL`.
    Resolved(Vec<ProxyStep>),
    // `ERROR_WINHTTP_AUTODETECTION_FAILED`: no DHCP option 252, no `wpad.<domain>`
    // record, or the discovered script was unusable. Not an error, but also not a
    // script's own answer — the distinction this variant exists to carry.
    AutoDetectionFailed,
}

// `context` must be text this crate wrote, and every call site passes a literal. The
// requirement is the exit below, not the one above it: [`Error::pac_evaluation`] runs its
// argument through the masking constructor, so a `context` that one day interpolated a URL
// would still come out masked there — [`Error::io`] stores what it is handed. Written here
// rather than at either exit because the exit that needs the rule is the one with nothing
// in it to notice the rule being broken.
fn winhttp_error(context: &str, code: u32) -> Error {
    if code == ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT {
        // Through the masking constructor, for the reason `ProxyResult::steps` gives when
        // it builds `PacInvalidResult` out of text this crate wrote: the variant promises
        // in its own documentation that `reason` is masked at construction, and a promise
        // that holds only because no `context` has yet interpolated a URL is one edit away
        // from being false.
        return Error::pac_evaluation(format!(
            "{context}: the PAC script could not be executed by WinHTTP"
        ));
    }
    Error::io(
        format!("{context} (WinHTTP status {code:#010x})"),
        std::io::Error::from_raw_os_error(code as i32),
    )
}

// The shared state of one in-flight `WinHttpGetProxyForUrlEx` call.
#[derive(Debug)]
struct Pending {
    // Manual-reset: the waiter must be able to observe a completion that happened
    // before it reached `WaitForSingleObject`.
    done: Event,
    // The WinHTTP status code the callback saw, `ERROR_SUCCESS` on completion.
    status: AtomicU32,
}

// SAFETY: the only thing in `Pending` that is not already `Sync` is the event handle,
// which `Event` models as a raw `HANDLE`. `SetEvent` (from the WinHTTP callback thread)
// and `WaitForSingleObject` (from the caller) are documented as safe to call concurrently
// on the same event object, and neither side mutates the wrapper itself. Sharing is the
// entire point: the `Arc` is what lets the callback outlive a timed-out caller.
unsafe impl Sync for Pending {}

impl Pending {
    fn new() -> Result<Self, Error> {
        Ok(Self {
            done: Event::new(true, "creating the PAC resolution completion event")?,
            status: AtomicU32::new(ERROR_SUCCESS.0),
        })
    }

    // Record the outcome and wake the waiter.
    //
    // The discarded `SetEvent` result is the same invariant the `SAFETY` note below states,
    // read from the other side: the documented failure is an invalid handle, and the handle
    // is live for as long as `self` is. Discarded rather than propagated because there is
    // nobody here to propagate to — this runs on WinHTTP's callback thread, reached through
    // a raw `extern "system"` function, and the caller that wants the answer is blocked in
    // `WaitForSingleObject` inside `resolve_raw`.
    //
    // What it would cost if the invariant were ever broken is worth naming, because the
    // failure does not surface as itself: the waiter would sleep out its whole budget and
    // return [`Error::PacTimeout`] for a resolution that had already finished — the status
    // stored on the line above, and the proxy WinHTTP found, both discarded with it. That is
    // a wrong error rather than a silent one, so it is visible; it just points at the clock
    // instead of at the handle.
    fn finish(&self, code: u32) {
        self.status.store(code, Ordering::Release);
        // SAFETY: `self.done` owns a live event handle for as long as `self` exists, and
        // the caller of this function holds a strong reference to `self`.
        unsafe {
            let _ = SetEvent(self.done.raw());
        }
    }
}

// The session-wide status callback.
unsafe extern "system" fn status_callback(
    _handle: *mut c_void,
    context: usize,
    status: u32,
    info: *mut c_void,
    _info_len: u32,
) {
    let code = match status {
        WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE => ERROR_SUCCESS.0,
        WINHTTP_CALLBACK_STATUS_REQUEST_ERROR => {
            if info.is_null() {
                // Should not happen. Report something rather than claim success, but not
                // `ERROR_WINHTTP_AUTODETECTION_FAILED`: `resolve_raw` maps that onto a
                // non-error "go Direct", which would hide a genuine config-URL failure.
                ERROR_WINHTTP_INTERNAL_ERROR
            } else {
                // SAFETY: for `WINHTTP_CALLBACK_STATUS_REQUEST_ERROR`, WinHTTP documents
                // `lpvStatusInformation` as a pointer to a `WINHTTP_ASYNC_RESULT` that is
                // valid for the duration of the callback.
                unsafe { (*info.cast::<WINHTTP_ASYNC_RESULT>()).dwError }
            }
        }
        // Returning here must not consume the context reference, or a later real
        // notification would use freed memory.
        _ => return,
    };
    if context == 0 {
        return;
    }
    // SAFETY: `context` is the pointer produced by `Arc::into_raw` in
    // `WinHttpPacResolver::resolve_raw`, which transferred one strong reference to this
    // callback. Reclaiming it twice would be a double free, so what rules that out is worth
    // naming: `WinHttpGetProxyForUrlEx`'s Remarks pair the two statuses this function acts
    // on with the two outcomes of one pended call — "Once a callback of status
    // WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE is returned, the application can call
    // WinHttpGetProxyResult", and "If the call fails after returning ERROR_IO_PENDING then a
    // callback of WINHTTP_CALLBACK_STATUS_REQUEST_ERROR will be issued". One pended call has
    // one outcome, so the reference is reclaimed once and the allocation is still live.
    // *Terminal* is the reading of that pairing rather than a sentence Microsoft writes —
    // the same standing as the synchronous-return rule in `resolve_raw` — which is why the
    // arm above returns without consuming the context for every other status, and why
    // `Session::new` registers only these two flags.
    let pending: Arc<Pending> = unsafe { Arc::from_raw(context as *const Pending) };
    pending.finish(code);
}

// An owned WinHTTP session handle (`WinHttpOpen`), closed on drop.
#[derive(Debug)]
struct Session(*mut c_void);

// SAFETY: an `HINTERNET` is process-wide state behind an opaque integer; it is `!Send` and
// `!Sync` here only because it is modelled as a raw pointer, not because anything about the
// handle is thread-affine.
//
// The load-bearing half is what Microsoft states, and it is less than the `Send`/`Sync`
// above would suggest. Neither `WinHttpOpen`'s Remarks nor `WinHttpCreateProxyResolver`
// (which has no Remarks at all) says a handle may be used from any thread; the reference
// pages were checked for it rather than assumed. What "HINTERNET Handles in WinHTTP" does
// state is one rule, and it is a caution rather than a guarantee: "These HINTERNET handles
// cannot be closed while an API call using the handle is in progress. To avoid a race
// condition, applications should protect the handle and prevent it from being closed for as
// long as the API call is in progress."
//
// That rule is the one this impl has to answer, and ownership answers it without a lock.
// The session handle is closed by `Session::drop` alone, `resolve` borrows the owner as
// `&self`, and no `&self` method can run while the value is being dropped — through an
// `Arc` no differently, since the last reference is what drops it. So the close cannot race
// an in-progress call, for the same reason a `&mut` cannot coexist with a `&`. Resolver
// handles never reach a second thread at all: each is a local of `resolve_raw`.
//
// Concurrent use from several threads is then inference, held openly as such. It rests on
// the shape of the API rather than on a sentence: `WinHttpCreateProxyResolver` exists to
// mint a per-operation child from one long-lived session, `WinHttpOpen`'s Remarks call a
// single session "normally sufficient" for an application, and `WinHttpGetProxyForUrlEx`
// "always executes out-of-process" and so is not resolving anything in the caller's own
// address space. If that inference is ever wrong, the fix is a mutex around `Session`, not
// a different lifetime.
unsafe impl Send for Session {}
// SAFETY: as above.
unsafe impl Sync for Session {}

impl Session {
    // Open an asynchronous session that reaches the network without a proxy.
    fn open(timeout: Duration) -> Result<Self, Error> {
        let agent = wide(USER_AGENT);
        // SAFETY: `agent` is a NUL terminated UTF-16 buffer that outlives the call; the
        // two proxy arguments are unused with `WINHTTP_ACCESS_TYPE_NO_PROXY`.
        let handle = unsafe {
            WinHttpOpen(
                PCWSTR(agent.as_ptr()),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                WINHTTP_FLAG_ASYNC,
            )
        };
        if handle.is_null() {
            return Err(last_error("WinHttpOpen"));
        }
        let session = Self(handle);

        let millis = session_timeout_millis(timeout);
        // Failure here *is* fatal, deliberately: `millis` cannot be out of range, so the
        // only remaining cause is a session handle that is not what `WinHttpOpen` just
        // said it was, and every later call on it would fail too.
        //
        // SAFETY: `session` owns a live session handle.
        unsafe { WinHttpSetTimeouts(session.0, millis, millis, millis, millis) }
            .map_err(|e| crate::sys::win::ffi::hresult_error("WinHttpSetTimeouts", e))?;

        // SAFETY: `session` owns a live session handle and `status_callback` has the
        // signature WinHTTP requires. Resolver handles created from this session inherit
        // the callback.
        let previous = unsafe {
            WinHttpSetStatusCallback(
                session.0,
                Some(status_callback),
                WINHTTP_CALLBACK_FLAG_GETPROXYFORURL_COMPLETE | WINHTTP_CALLBACK_FLAG_REQUEST_ERROR,
                0,
            )
        };
        // `WINHTTP_INVALID_STATUS_CALLBACK` is `(WINHTTP_STATUS_CALLBACK)-1`, which the
        // `windows` crate surfaces as a `Some` holding an unusable function pointer.
        if previous.is_some_and(|callback| callback as usize == usize::MAX) {
            return Err(last_error("WinHttpSetStatusCallback"));
        }
        Ok(session)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `WinHttpOpen`, is owned solely by `self`, and every
        // resolver handle derived from it is closed before the resolver struct is dropped.
        unsafe {
            let _ = WinHttpCloseHandle(self.0);
        }
    }
}

// An owned proxy resolver handle (`WinHttpCreateProxyResolver`), closed on drop.
#[derive(Debug)]
struct Resolver(*mut c_void);

impl Resolver {
    fn create(session: &Session) -> Result<Self, Error> {
        let mut handle: *mut c_void = ptr::null_mut();
        // SAFETY: `session` owns a live session handle and `handle` is a valid, writable
        // out-parameter.
        let status = unsafe { WinHttpCreateProxyResolver(session.0, &raw mut handle) };
        if status != ERROR_SUCCESS.0 {
            return Err(winhttp_error("WinHttpCreateProxyResolver", status));
        }
        Ok(Self(handle))
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `WinHttpCreateProxyResolver` and is owned solely by
        // `self`. Closing it while an operation is still pending is the documented way to
        // cancel that operation; WinHTTP defers the actual release until its own callback
        // has run.
        unsafe {
            let _ = WinHttpCloseHandle(self.0);
        }
    }
}

// A `WINHTTP_PROXY_RESULT` whose entry array is released on drop.
struct ProxyResult(WINHTTP_PROXY_RESULT);

impl ProxyResult {
    // Convert the entry array into an ordered fallback chain.
    fn to_steps(&self) -> Result<Vec<ProxyStep>, Error> {
        let count = self.0.cEntries as usize;
        let entries = if count == 0 || self.0.pEntries.is_null() {
            &[][..]
        } else {
            // SAFETY: on success WinHTTP guarantees `pEntries` points at `cEntries`
            // initialised entries, owned by `self` until `WinHttpFreeProxyResult`.
            unsafe { std::slice::from_raw_parts(self.0.pEntries.cast_const(), count) }
        };

        // Sized from the array that is actually there, not from `cEntries`. The two agree
        // whenever WinHTTP keeps its promise, and the guard above is already written for the
        // case where it does not — reserving on the count would be believing it again, two
        // lines after refusing to. `cEntries` is a `u32`, so believing it once means an
        // allocation the process aborts on rather than the error this returns.
        let mut steps: Vec<ProxyStep> = Vec::with_capacity(entries.len());
        let mut seen = HashSet::with_capacity(entries.len());
        for entry in entries {
            // The membership test is the one
            // [`parse_find_proxy_result`](super::result::parse_find_proxy_result) makes, and
            // its reasoning carries over unchanged: a chain is a list of things to try in
            // order, and a proxy that just failed is no more alive the second time it is
            // named. Kept identical on purpose — the same PAC script reaches this path on
            // Windows and that one everywhere else, so a chain that collapsed differently
            // depending on which engine ran it would be a difference the script's author
            // never asked for.
            //
            // The cost is the same one too, and written on the same public doc: `resolve`
            // returns fewer steps than WinHTTP reported entries, so `len()` is not
            // `cEntries`. Nothing downstream counts them — the chain is walked in order —
            // but a caller comparing against the native API would see the gap.
            //
            // The membership test is a set for the same reason it is one over there. The
            // entries are WinHTTP's reading of the same remote script, so `cEntries` is as
            // much the script's number here as the candidate count is there; the quadratic on
            // that path is not a property of the parser it shows up in. Not observed here,
            // because reaching this line needs WinHTTP to return the entries itself.
            //
            // SAFETY: the entry belongs to the array borrowed above and its `pwszProxy`
            // member is either null or a NUL terminated UTF-16 string owned by it.
            if let Some(step) = unsafe { entry_to_step(entry) }
                && seen.insert(step.clone())
            {
                steps.push(step);
            }
        }
        if steps.is_empty() {
            // This crate wrote the message itself, but it still goes through the masking
            // constructor so `PacInvalidResult` is never built any other way.
            return Err(Error::pac_invalid_result(format!(
                "WinHTTP returned {count} proxy entries, none of them usable"
            )));
        }
        Ok(steps)
    }
}

impl Drop for ProxyResult {
    fn drop(&mut self) {
        // SAFETY: the structure was filled in by `WinHttpGetProxyResult` and is owned
        // solely by `self`, so its entry array is released exactly once.
        unsafe {
            WinHttpFreeProxyResult(&raw mut self.0);
        }
    }
}

// One `WINHTTP_PROXY_RESULT_ENTRY`, or `None` when it names no usable transport.
//
// # Safety
//
// `entry.pwszProxy` must be null or a NUL terminated UTF-16 string valid for the call.
unsafe fn entry_to_step(entry: &WINHTTP_PROXY_RESULT_ENTRY) -> Option<ProxyStep> {
    if !entry.fProxy.as_bool() {
        // `fBypass` distinguishes "the script said DIRECT" from "this destination is on
        // the bypass list", which is a provenance detail `ProxyStep` does not model:
        // either way the connection is made without a proxy.
        return Some(ProxyStep::Direct);
    }

    let scheme = match entry.ProxyScheme.0 {
        s if s == WINHTTP_INTERNET_SCHEME_HTTP.0 => ProxyScheme::Http,
        s if s == WINHTTP_INTERNET_SCHEME_HTTPS.0 => ProxyScheme::Https,
        // WinHTTP has one SOCKS constant and PAC's bare `SOCKS` keyword is the Netscape
        // original, i.e. SOCKS4 — the same reading as `parse_find_proxy_result`.
        s if s == WINHTTP_INTERNET_SCHEME_SOCKS.0 => ProxyScheme::Socks4,
        // `WINHTTP_INTERNET_SCHEME_FTP`, or anything a later Windows adds: not a proxy
        // transport this crate models. Skipped like a junk PAC candidate rather than
        // failing the whole chain.
        _ => return None,
    };

    // SAFETY: forwarded from this function's own contract.
    let host_text = unsafe { wide_ptr_to_string(entry.pwszProxy.0) }?;
    let host = parse_proxy_host(host_text.trim())?;
    // No call has been seen to take the zero branch: measured against a served script that
    // returns `PROXY 203.0.113.7` and one that returns `SOCKS 203.0.113.7`, WinHTTP fills
    // the port in itself, and with the same numbers `default_port` would have given. Kept
    // anyway, and named here so that the measurement is not mistaken for a reason to drop
    // it: `ProxyPort` is a `u16` with no documented default, and port 0 is an endpoint that
    // connects nowhere. The guard costs one comparison; removing it bets the whole native
    // path on an undocumented WinHTTP habit.
    let port = if entry.ProxyPort == 0 {
        scheme.default_port()
    } else {
        entry.ProxyPort
    };
    let endpoint = ProxyEndpoint::new(host, port).with_scheme_hint(scheme);
    // Same table as `parse_find_proxy_result`'s, and neither caller keeps its own `_` arm
    // over it: separate arms drift apart, and a `ProxyScheme` variant neither can produce
    // today then becomes a SOCKS4 step here and a SOCKS5 one there.
    Some(ProxyStep::from_endpoint(endpoint))
}

// The destination URL as `WinHttpGetProxyForUrlEx` is called with it.
//
// Sanitized for the same reason the boa engine sanitizes: WinHTTP hands this string to
// `FindProxyForURL`, whose script is a WPAD-discovered or plain-HTTP-delivered artefact.
//
// A WebSocket destination also has its scheme mapped, because WinHTTP's resolver does not
// accept one. Chromium measured that on Windows 10 build 16299 and still maps before every
// call — `ChangeWebSocketSchemeToHttpScheme`, applied in `ProxyResolverWinHttp::GetProxyForURL`
// in `net/proxy_resolution/win/proxy_resolver_winhttp.cc`, whose comment adds that the
// documented meaning of `ERROR_WINHTTP_UNRECOGNIZED_SCHEME` implies the same. Without it a
// `ws:`/`wss:` request gets an error from a machine that has a perfectly good PAC answer for
// it. The map is only on the string the native call sees; the `boa` engine still shows the
// script the scheme the caller asked about, which is also where Chromium draws the line —
// its own evaluator does not rewrite.
//
// Matched on the scheme rather than on a `"ws"` prefix: `wsx:` is a URL `Url::parse` accepts
// and no relation. Once matched, dropping those two characters and writing `http` back is the
// whole mapping, the surviving `s` of `wss` landing where WHATWG's own pairing puts it.
// Sanitizing first changes nothing — `sanitize_url` keeps the path and query for `ws` exactly
// as it does for `http`, and strips them for `wss` exactly as it does for `https`.
fn query_url(url: &Url) -> String {
    let sanitized = crate::pac::sanitize_url(url);
    match url.scheme() {
        "ws" | "wss" => format!("http{}", &sanitized.as_str()[2..]),
        _ => sanitized.into(),
    }
}

// Parse the host of a proxy entry.
//
// WinHTTP hands back the address exactly as the script wrote it, so an IPv6 literal may
// arrive bare (`::1`) rather than bracketed; [`Host::parse`] only accepts the bracketed
// form, so the bare one is tried first.
fn parse_proxy_host(text: &str) -> Option<Host> {
    if text.is_empty() {
        return None;
    }
    if let Ok(address) = text.parse::<Ipv6Addr>() {
        return Some(Host::Ipv6(address));
    }
    // No empty-domain arm below it: WHATWG host parsing makes an empty host a failure and
    // `url` implements it there, so every input that percent-decodes and IDNA-maps to
    // nothing arrives as `Err(ParseError::EmptyHost)` — `url-2.5.8` `src/host.rs:111`
    // returns it before the `Ok(Host::Domain(..))` at `:119`, the only one `Host::parse`
    // reaches. The file's other one (`:162`) is `parse_opaque_cow`'s, where an empty host is
    // legal and unguarded — but nothing here calls `Host::parse_opaque`. An arm for the empty
    // domain would be a rule no input could reach, and reads as a guard while being none.
    Host::parse(text).ok()
}

fn last_error(context: &str) -> Error {
    Error::io(context.to_owned(), std::io::Error::last_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Networking::WinHttp::WINHTTP_INTERNET_SCHEME;

    // The variant name is most of what this rendering carries: `AutoDetectThenUrl` says WPAD
    // is tried ahead of the URL, which is the ordering the type exists to hold. These rows
    // are the only thing holding it: printed as `Url`, the same value reads as a machine
    // configured with a plain `AutoConfigURL` and no auto-detect at all.
    //
    // No credentials in the URL, so these rows pin the framing rather than the masking,
    // which `debug_masking`'s registry owns for this type.
    #[test]
    fn every_pac_source_debug_names_itself_and_keeps_its_url() {
        let url = Url::parse("https://wpad.corp/proxy.pac").unwrap();
        for (source, expected) in [
            (WinHttpPacSource::AutoDetect, "AutoDetect"),
            (
                WinHttpPacSource::Url(url.clone()),
                "Url(https://wpad.corp/proxy.pac)",
            ),
            (
                WinHttpPacSource::AutoDetectThenUrl(url.clone()),
                "AutoDetectThenUrl(https://wpad.corp/proxy.pac)",
            ),
        ] {
            assert_eq!(format!("{source:?}"), expected);
        }
    }

    // [`INFINITE`] is never a legitimate answer for the resolution wait: saturating onto
    // its bit pattern would drop the budget `with_timeout` accepted and leave the call
    // blocked until WinHTTP's own timeouts fire instead, so `Error::PacTimeout` could
    // never come from `resolve_raw`.
    #[test]
    fn an_overlong_timeout_is_clamped_below_infinite() {
        use windows::Win32::System::Threading::INFINITE;

        for timeout in [
            Duration::MAX,
            // Fits `u32` but lands exactly on `INFINITE`'s own bit pattern.
            Duration::from_millis(u64::from(u32::MAX)),
            Duration::from_millis(u64::from(u32::MAX) + 1),
        ] {
            let millis = wait_millis(timeout);
            assert_eq!(millis, u32::MAX - 1, "{timeout:?}");
            assert!(millis < INFINITE, "{timeout:?}");
        }
    }

    // The clamp must not disturb the budgets anyone actually configures, including the
    // default this module ships.
    #[test]
    fn an_ordinary_timeout_converts_to_milliseconds() {
        assert_eq!(wait_millis(DEFAULT_WINHTTP_PAC_TIMEOUT), 5_000);
        assert_eq!(wait_millis(Duration::from_millis(250)), 250);
        assert_eq!(wait_millis(Duration::ZERO), 0);
    }

    // The other end of the same budget. `WinHttpSetTimeouts` reads 0 as "wait infinitely",
    // so truncating a sub-millisecond budget to 0 would hand the session the one meaning
    // `with_timeout` refuses to let a caller ask for — and would leave it there for every
    // later resolution, since the session's timeouts are set once.
    #[test]
    fn a_sub_millisecond_budget_never_reaches_winhttp_as_infinite() {
        assert_eq!(session_timeout_millis(Duration::from_micros(500)), 1);
        assert_eq!(session_timeout_millis(Duration::from_nanos(1)), 1);
    }

    // The floor must not disturb the budgets anyone actually configures, and the other end
    // must saturate rather than wrap into the negative range the API rejects outright.
    #[test]
    fn an_ordinary_budget_reaches_winhttp_unchanged() {
        assert_eq!(
            session_timeout_millis(DEFAULT_WINHTTP_PAC_TIMEOUT),
            5_000_i32
        );
        assert_eq!(session_timeout_millis(Duration::from_millis(250)), 250_i32);
        assert_eq!(session_timeout_millis(Duration::MAX), i32::MAX);
    }

    #[test]
    fn sources_come_from_the_auto_config_modes_only() {
        let url = Url::parse("http://wpad.corp/proxy.pac").unwrap();
        assert_eq!(
            WinHttpPacSource::from_mode(&ProxyMode::pac(url.clone())),
            Some(WinHttpPacSource::Url(url))
        );
        assert_eq!(
            WinHttpPacSource::from_mode(&ProxyMode::WpadAutoDetect),
            Some(WinHttpPacSource::AutoDetect)
        );
        assert_eq!(WinHttpPacSource::from_mode(&ProxyMode::Direct), None);
        assert_eq!(
            WinHttpPacSource::from_mode(&ProxyMode::pac_inline("body".to_owned())),
            None
        );
        // The fifth variant. `resolve_config` is not what it protects — that one returns
        // `Direct | Manual` to `resolve()` before reaching here, so the engine's own path
        // is safe whatever this answers. What it protects is the published contract: this
        // is a `pub fn`, and a caller that derives a source itself and hands it to
        // `resolve` would take a `Manual` machine to WPAD discovery, and this assertion is
        // the only thing in the tree that would say so.
        assert_eq!(
            WinHttpPacSource::from_mode(&ProxyMode::manual(
                std::collections::HashMap::new(),
                crate::BypassRules::new()
            )),
            None
        );
    }

    #[test]
    fn autoproxy_flags_match_the_variant() {
        let url = Url::parse("http://wpad.corp/proxy.pac").unwrap();
        assert_eq!(
            WinHttpPacSource::AutoDetect.flags(),
            WINHTTP_AUTOPROXY_AUTO_DETECT
        );
        assert_eq!(
            WinHttpPacSource::Url(url.clone()).flags(),
            WINHTTP_AUTOPROXY_CONFIG_URL
        );
        assert_eq!(
            WinHttpPacSource::AutoDetectThenUrl(url.clone()).flags(),
            WINHTTP_AUTOPROXY_AUTO_DETECT | WINHTTP_AUTOPROXY_CONFIG_URL
        );
        assert_eq!(WinHttpPacSource::AutoDetect.url(), None);
        assert_eq!(
            WinHttpPacSource::AutoDetectThenUrl(url.clone()).url(),
            Some(&url)
        );
    }

    // The degrade-to-`Direct` answer is spelled per request, not per status code: a
    // configured PAC URL that failed must not be reported as "there is no proxy".
    #[test]
    fn only_a_request_that_asked_for_auto_detect_can_report_a_wpad_miss() {
        let url = Url::parse("http://wpad.corp/proxy.pac").unwrap();
        for source in [
            WinHttpPacSource::AutoDetect,
            WinHttpPacSource::AutoDetectThenUrl(url.clone()),
        ] {
            assert!(
                is_wpad_miss(source.flags(), ERROR_WINHTTP_AUTODETECTION_FAILED),
                "{source:?}"
            );
        }
        assert!(!is_wpad_miss(
            WinHttpPacSource::Url(url).flags(),
            ERROR_WINHTTP_AUTODETECTION_FAILED
        ));
        // Every other status stays whatever it already was, auto-detect or not.
        assert!(!is_wpad_miss(
            WINHTTP_AUTOPROXY_AUTO_DETECT,
            ERROR_SUCCESS.0
        ));
    }

    // What `WinHttpGetProxyForUrlEx` is actually handed. The two WebSocket rows are the
    // scheme WinHTTP will not take; the rest are there so the map cannot grow past them —
    // `wsx` in particular, which shares the prefix and is an unrelated scheme.
    #[test]
    fn a_websocket_destination_reaches_winhttp_as_the_scheme_it_understands() {
        let cases = [
            // Path and query survive `ws`, as they do `http`.
            ("ws://chat.corp/room?id=1#f", "http://chat.corp/room?id=1"),
            // And are stripped from `wss`, as they are from `https`.
            ("wss://chat.corp/room?id=1", "https://chat.corp/"),
            ("http://alice:pw@a.corp/x?q=1#f", "http://a.corp/x?q=1"),
            ("https://a.corp/x?q=1", "https://a.corp/"),
            ("wsx://a.corp/x", "wsx://a.corp/x"),
        ];
        for (input, expected) in cases {
            assert_eq!(query_url(&Url::parse(input).unwrap()), expected, "{input}");
        }
    }

    #[test]
    fn proxy_hosts_parse_in_every_shape_winhttp_produces() {
        assert_eq!(
            parse_proxy_host("proxy.corp"),
            Some(Host::Domain("proxy.corp".to_owned()))
        );
        assert_eq!(
            parse_proxy_host("10.0.0.1"),
            Some(Host::Ipv4("10.0.0.1".parse().unwrap()))
        );
        // Bare and bracketed IPv6 both arrive in practice.
        assert_eq!(
            parse_proxy_host("::1"),
            Some(Host::Ipv6("::1".parse().unwrap()))
        );
        assert_eq!(
            parse_proxy_host("[2001:db8::1]"),
            Some(Host::Ipv6("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(parse_proxy_host(""), None);
    }

    // The zero branch of `entry_to_step` has no observed call — WinHTTP fills the port in
    // itself on every run seen here — so this test is the only thing holding the guard it
    // stands on. A hand-built entry asks the question a live run cannot: `ProxyPort` is a
    // bare `u16` with no documented default, and 0 is
    // an endpoint that connects nowhere, so a step carrying it would fail every attempt
    // while reading like a routable proxy.
    #[test]
    fn a_proxy_entry_without_a_port_takes_its_scheme_default() {
        use windows::core::PWSTR;

        for (native, scheme, port, expected) in [
            (WINHTTP_INTERNET_SCHEME_HTTP, ProxyScheme::Http, 0u16, 80u16),
            (WINHTTP_INTERNET_SCHEME_HTTPS, ProxyScheme::Https, 0, 443),
            (WINHTTP_INTERNET_SCHEME_SOCKS, ProxyScheme::Socks4, 0, 1080),
            // A port WinHTTP did fill in passes through untouched, so the guard cannot be
            // a rule that rewrites every entry.
            (WINHTTP_INTERNET_SCHEME_HTTP, ProxyScheme::Http, 8080, 8080),
        ] {
            let mut host = wide("proxy.corp");
            let entry = WINHTTP_PROXY_RESULT_ENTRY {
                fProxy: true.into(),
                fBypass: false.into(),
                ProxyScheme: native,
                pwszProxy: PWSTR(host.as_mut_ptr()),
                ProxyPort: port,
            };
            // SAFETY: `host` is a NUL terminated UTF-16 buffer that outlives the call and
            // is not aliased while it runs.
            let step = unsafe { entry_to_step(&entry) };
            assert_eq!(
                step,
                Some(ProxyStep::from_endpoint(
                    ProxyEndpoint::new(Host::Domain("proxy.corp".to_owned()), expected)
                        .with_scheme_hint(scheme)
                )),
                "{native:?} port {port}"
            );
        }
    }

    // One proxy candidate, built the way WinHTTP would have filled it in.
    fn proxy_entry(
        scheme: WINHTTP_INTERNET_SCHEME,
        host: &mut [u16],
        port: u16,
    ) -> WINHTTP_PROXY_RESULT_ENTRY {
        WINHTTP_PROXY_RESULT_ENTRY {
            fProxy: true.into(),
            fBypass: false.into(),
            ProxyScheme: scheme,
            pwszProxy: windows::core::PWSTR(host.as_mut_ptr()),
            ProxyPort: port,
        }
    }

    // Drive the real [`ProxyResult::to_steps`] over an array the test owns.
    //
    // `ProxyResult`'s `Drop` hands its array to `WinHttpFreeProxyResult`, and this one came
    // from a `let`, so the wrapper must not run it. Built as the wrapper rather than as a
    // conversion core split off onto a plain entry slice — which is what the finding
    // proposed — because the count and the pointer are what the last test below disagrees
    // about, and a slice is a shape that cannot hold that disagreement.
    fn steps_of(
        count: u32,
        entries: *mut WINHTTP_PROXY_RESULT_ENTRY,
    ) -> Result<Vec<ProxyStep>, Error> {
        let result = std::mem::ManuallyDrop::new(ProxyResult(WINHTTP_PROXY_RESULT {
            cEntries: count,
            pEntries: entries,
        }));
        result.to_steps()
    }

    fn endpoint_step(host: &str, port: u16, scheme: ProxyScheme) -> ProxyStep {
        ProxyStep::from_endpoint(
            ProxyEndpoint::new(Host::Domain(host.to_owned()), port).with_scheme_hint(scheme),
        )
    }

    // Which candidates of a mixed result reach the chain, and in which order. Four kinds are
    // dropped here without ending the resolution — a transport this crate does not model, a
    // pointer with no string behind it, a host that parses as nothing, and a repeat — and two
    // kinds survive.
    //
    // Three of the four drops can be told apart here; the null pointer cannot, because it is
    // refused twice over — `wide_ptr_to_string` gives nothing back, and the
    // empty string that would stand in for it is not a host either. Its entry is here for the
    // one thing that is its own: a null `pwszProxy` is a pointer this reader must not follow.
    //
    // This test is the only thing holding any of it. The live test in `tests/pac_winhttp.rs`
    // reads whatever the machine's own script answers and asks only for a non-empty chain,
    // and it is the only other caller that can reach `to_steps` at all, because the entry
    // array is WinHTTP's to allocate. It therefore cannot tell a chain that stops at the
    // first junk candidate from one that keeps the junk and hands the caller a step naming a
    // transport it cannot open.
    #[test]
    fn a_mixed_chain_keeps_the_usable_candidates_in_order() {
        use windows::Win32::Networking::WinHttp::WINHTTP_INTERNET_SCHEME_FTP;

        let mut good = wide("proxy.corp");
        let mut secure = wide("secure.corp");
        let mut files = wide("files.corp");
        let mut malformed = wide("proxy corp");
        let mut entries = [
            proxy_entry(WINHTTP_INTERNET_SCHEME_FTP, &mut files, 21),
            proxy_entry(WINHTTP_INTERNET_SCHEME_HTTP, &mut good, 3128),
            WINHTTP_PROXY_RESULT_ENTRY {
                pwszProxy: windows::core::PWSTR(ptr::null_mut()),
                ..proxy_entry(WINHTTP_INTERNET_SCHEME_HTTP, &mut good, 8080)
            },
            proxy_entry(WINHTTP_INTERNET_SCHEME_HTTP, &mut malformed, 8080),
            // The candidate already in the chain, named a second time.
            proxy_entry(WINHTTP_INTERNET_SCHEME_HTTP, &mut good, 3128),
            // `DIRECT`, which every other field of the entry is silent about.
            WINHTTP_PROXY_RESULT_ENTRY {
                fProxy: false.into(),
                ..proxy_entry(WINHTTP_INTERNET_SCHEME_HTTP, &mut good, 0)
            },
            proxy_entry(WINHTTP_INTERNET_SCHEME_HTTPS, &mut secure, 8443),
        ];

        let count = entries.len() as u32;
        assert_eq!(
            steps_of(count, entries.as_mut_ptr()).expect("three candidates were usable"),
            vec![
                endpoint_step("proxy.corp", 3128, ProxyScheme::Http),
                ProxyStep::Direct,
                endpoint_step("secure.corp", 8443, ProxyScheme::Https),
            ]
        );
    }

    // The all-junk chain, which is the one shape that must not fail open: a managed PAC whose
    // every candidate this reader refuses is a machine with no answer, not a machine allowed
    // to connect straight out. The portable parser holds the same rule over its own input,
    // and holds nothing about this reader — the two share a `FindProxyForURL` and no code.
    #[test]
    fn a_chain_with_nothing_usable_in_it_is_an_error_rather_than_a_direct_connection() {
        use windows::Win32::Networking::WinHttp::WINHTTP_INTERNET_SCHEME_FTP;

        let mut files = wide("files.corp");
        let mut malformed = wide("proxy corp");
        let mut entries = [
            proxy_entry(WINHTTP_INTERNET_SCHEME_FTP, &mut files, 21),
            proxy_entry(WINHTTP_INTERNET_SCHEME_HTTP, &mut malformed, 8080),
        ];

        let count = entries.len() as u32;
        let error = steps_of(count, entries.as_mut_ptr()).unwrap_err();
        assert!(matches!(error, Error::PacInvalidResult { .. }), "{error:?}");
        // Candidates arrived and were refused, which is not the event a script returning
        // nothing at all would be. The number is the only place the message says which.
        assert!(error.to_string().contains('2'), "{error}");
    }

    // A count with no array behind it. WinHTTP promises `cEntries` initialised entries on
    // success and the null check says that promise is not what the reader rests on, so the
    // number beside it is not to be believed either: a `u32` of them is a reservation the
    // allocator refuses and the process aborts on, in place of the error below. Reaching this
    // needs the count and the pointer to disagree, which is why the helper above takes them
    // apart.
    #[test]
    fn an_entry_count_with_no_array_behind_it_is_not_believed() {
        let error = steps_of(u32::MAX, ptr::null_mut()).unwrap_err();
        assert!(matches!(error, Error::PacInvalidResult { .. }), "{error:?}");
    }

    #[test]
    fn a_zero_timeout_is_refused_rather_than_meaning_forever() {
        let error = WinHttpPacResolver::with_timeout(Duration::ZERO).unwrap_err();
        assert!(matches!(error, Error::PacTimeout { .. }), "{error:?}");
    }

    // No caller passes a `context` like this one, which is the point: the masking must not
    // depend on that staying true, because `PacEvaluation` documents it as a property of
    // the variant rather than of who happens to build it.
    #[test]
    fn a_script_error_masks_its_context_even_when_that_context_carries_credentials() {
        let error = winhttp_error(
            "fetching http://alice:hunter2@wpad.corp/proxy.pac",
            ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT,
        );
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        // The password is the secret; the user name stays, as it does in `ProxyAuth`'s
        // own `Debug`.
        assert!(rendered.contains("alice:"), "{rendered}");
        assert!(rendered.contains("wpad.corp"), "{rendered}");
    }
}
