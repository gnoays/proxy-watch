//! What the Node, Python and C bindings share: the route for one URL under one snapshot,
//! the OS read that answers a Linux host without desktop settings as direct, the layering
//! of `*_proxy` over it, and a watch that drains a `ProxyWatcher` on a pump thread.
//!
//! Error codes are strings in the `ERR_*` form Node uses; Python puts the same string on
//! its exception, and C maps each to a stable number: `ERR_WATCHER_CLOSED` shares
//! `ERR_PROXY_WATCH`'s.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, TryLockError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, JoinHandle, Thread, ThreadId};
use std::time::Duration;

use futures_core::Stream;
use proxy_watch::pac::{PacPolicy, PacScript};
use proxy_watch::{
    BypassRules, CapturedEnv, EnvPrecedence, Error, Host, ProxyAuth, ProxyConfig, ProxyEntry,
    ProxyEnv, ProxyMode, ProxyScheme, ProxyStep, ProxyWatcher, RejectedValue, Scheme, Url,
    WatchEvent, WatchOptions,
};

/// Where a request to one URL goes.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// Try each in order.
    Steps(Vec<ProxyStep>),
    /// The configuration is a PAC script at this URL, left to the caller: no engine
    /// [`RouteOptions`] chose downloads it.
    Pac(String),
    /// The configuration is this PAC script body (macOS and iOS), left to the caller.
    PacInline(String),
    /// The configuration asks for WPAD discovery, left to the caller.
    Wpad,
}

/// Which engine produced a route's steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// No PAC ran: the mode is not PAC, the URL has no host, or the route is the caller's.
    None,
    /// The OS's PAC engine.
    Native,
    /// QuickJS, in this process, under [`RouteOptions`]'s policy.
    QuickJs,
}

impl Engine {
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Native => "native",
            Self::QuickJs => "quickjs",
        }
    }
}

/// A route and the engine that answered it. Two engines can answer one script differently
/// (the OS's runs with real DNS and the real local address, QuickJS under the policy), so a
/// caller can tell whose answer it holds.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    pub route: Route,
    pub engine: Engine,
}

/// A failure with the code each binding shows.
#[derive(Debug, PartialEq, Eq)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
}

impl Failure {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<&Error> for Failure {
    fn from(error: &Error) -> Self {
        // One code per variant: a caller has to tell `ERR_PROXY_ENTRY_UNUSABLE` (a proxy is
        // configured but unusable, so going direct would bypass it) from the rest.
        let code = match error {
            Error::InvalidProxyServer { .. } => "ERR_INVALID_PROXY_SERVER",
            Error::InvalidBypassPattern { .. } => "ERR_INVALID_BYPASS_PATTERN",
            Error::InvalidProxyUrl { .. } => "ERR_INVALID_PROXY_URL",
            Error::UnsupportedProxyScheme(_) => "ERR_UNSUPPORTED_PROXY_SCHEME",
            Error::CgiHttpProxy { .. } => "ERR_CGI_HTTP_PROXY",
            Error::Io { .. } => "ERR_IO",
            Error::Sandboxed { .. } => "ERR_SANDBOXED",
            Error::Unsupported => "ERR_UNSUPPORTED",
            Error::PacNotSupported { .. } => "ERR_PAC_NOT_SUPPORTED",
            Error::ProxyEntryUnusable { .. } => "ERR_PROXY_ENTRY_UNUSABLE",
            Error::PacFetchRequired { .. } => "ERR_PAC_FETCH_REQUIRED",
            Error::PacEvaluation { .. } => "ERR_PAC_EVALUATION",
            Error::PacTimeout { .. } => "ERR_PAC_TIMEOUT",
            Error::PacSaturated { .. } => "ERR_PAC_SATURATED",
            Error::PacInvalidResult { .. } => "ERR_PAC_INVALID_RESULT",
            Error::PacEngineUnavailable => "ERR_PAC_ENGINE_UNAVAILABLE",
            _ => "ERR_PROXY_WATCH",
        };
        Self::new(code, error.to_string())
    }
}

/// Who runs a PAC configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pac {
    /// No engine: the route is [`Route::Pac`], [`Route::PacInline`] or [`Route::Wpad`].
    None,
    /// The OS's PAC engine, which runs with real DNS and the real local address: WinHTTP
    /// on Windows, CFNetwork on macOS and iOS, Android's PAC service. A PAC URL is
    /// downloaded by the OS; a body, the configuration's own or `script`, runs only on
    /// CFNetwork. WPAD runs only with `wpad` on Windows, macOS and iOS. A mode the OS has
    /// no engine for stays the caller's route; a `script` with no engine to run it is
    /// [`Error::PacEngineUnavailable`].
    Native,
    /// QuickJS, in this process, under the policy. Runs a body, the configuration's own
    /// or `script`, and leaves a PAC URL or WPAD without `script` to the caller.
    QuickJs,
    /// [`Native`](Self::Native) where the OS has an engine for the mode, else
    /// [`QuickJs`](Self::QuickJs) where the build carries it, else the caller's route.
    /// Decided before anything runs: an engine's failure is returned, not retried on the
    /// other, whose answer could differ.
    Auto,
}

/// `"none"` (the default), `"native"`, `"quickjs"` or `"auto"`.
pub fn pac(name: Option<&str>) -> Result<Pac, Failure> {
    match name {
        None | Some("none") => Ok(Pac::None),
        Some("native") => Ok(Pac::Native),
        Some("quickjs") => Ok(Pac::QuickJs),
        Some("auto") => Ok(Pac::Auto),
        Some(other) => Err(Failure::new(
            "ERR_INVALID_ARG_VALUE",
            format!("unknown pac {other:?}"),
        )),
    }
}

/// The longest `script` [`RouteOptions::new`] accepts, in bytes. The copy QuickJS is handed
/// sits outside its own memory limit.
pub const MAX_SCRIPT_LEN: usize = 1 << 20;

/// The longest QuickJS budget a policy accepts.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60);

/// The policy QuickJS runs a script under; `None` keeps [`PacPolicy::new`]'s value. Those
/// defaults answer a script that asks where it runs (`myIpAddress()` is `127.0.0.1`,
/// `dnsResolve` answers `null`, local time is UTC), so a script choosing a proxy by
/// network answers as if off every network.
#[derive(Debug, Default, Clone)]
pub struct PolicyOptions {
    /// What `myIpAddress()` returns.
    pub my_ip_address: Option<String>,
    /// Whether `dnsResolve`, `isResolvable` and `isInNet` query DNS.
    pub resolve_dns: Option<bool>,
    /// Whether DNS answers in internal space (RFC 1918, loopback, …) reach the script.
    pub allow_internal_addresses: Option<bool>,
    /// Seconds east of UTC that the date and time functions take as local.
    pub utc_offset_seconds: Option<i32>,
    /// The budget for one evaluation, 1 ms to [`MAX_TIMEOUT`].
    pub timeout_ms: Option<u64>,
}

/// `options` as a [`PacPolicy`].
pub fn policy(options: &PolicyOptions) -> Result<PacPolicy, Failure> {
    let invalid = |message: String| Failure::new("ERR_INVALID_ARG_VALUE", message);
    let mut policy = PacPolicy::new();
    if let Some(address) = &options.my_ip_address {
        let address = address
            .parse()
            .map_err(|_| invalid(format!("my IP address {address:?} is not an IP address")))?;
        policy = policy.with_my_ip_address(address);
    }
    if let Some(enabled) = options.resolve_dns {
        policy = policy.with_dns_resolution(enabled);
    }
    if let Some(allowed) = options.allow_internal_addresses {
        policy = policy.with_internal_addresses(allowed);
    }
    if let Some(seconds) = options.utc_offset_seconds {
        if seconds.unsigned_abs() >= 86_400 {
            return Err(invalid(format!(
                "a UTC offset of {seconds} s is not within a day"
            )));
        }
        policy = policy.with_local_utc_offset(seconds);
    }
    if let Some(ms) = options.timeout_ms {
        let timeout = Duration::from_millis(ms);
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(invalid(format!(
                "a timeout of {ms} ms is not between 1 ms and {} ms",
                MAX_TIMEOUT.as_millis()
            )));
        }
        policy = policy.with_timeout(Some(timeout));
    }
    Ok(policy)
}

/// How [`route`] treats a PAC configuration.
#[derive(Debug, Clone)]
pub struct RouteOptions {
    pac: Pac,
    script: Option<PacScript>,
    wpad: bool,
    policy: PacPolicy,
}

impl Default for RouteOptions {
    fn default() -> Self {
        Self {
            pac: Pac::None,
            script: None,
            wpad: false,
            policy: PacPolicy::new(),
        }
    }
}

impl RouteOptions {
    /// `script` is a PAC body the caller fetched, for a PAC URL or after its own WPAD
    /// discovery, and runs in place of the configuration's. `wpad` lets the OS discover a
    /// script, which it does on Windows, macOS and iOS. `policy` applies to QuickJS alone.
    ///
    /// `ERR_INVALID_ARG_VALUE` for a `script` or `wpad` that `pac` gives nothing to run,
    /// and for a `script` over [`MAX_SCRIPT_LEN`].
    pub fn new(
        pac: Pac,
        script: Option<String>,
        wpad: bool,
        policy: PacPolicy,
    ) -> Result<Self, Failure> {
        let invalid = |message: &str| Err(Failure::new("ERR_INVALID_ARG_VALUE", message));
        if pac == Pac::None && script.is_some() {
            return invalid("script needs a pac engine to run it");
        }
        if matches!(pac, Pac::None | Pac::QuickJs) && wpad {
            return invalid("wpad is discovery by the OS, which needs pac \"native\" or \"auto\"");
        }
        if script
            .as_ref()
            .is_some_and(|script| script.len() > MAX_SCRIPT_LEN)
        {
            return invalid("script is longer than 1 MiB");
        }
        Ok(Self {
            pac,
            script: script.map(PacScript::new),
            wpad,
            policy,
        })
    }

    /// No engine: [`Pac::None`].
    pub fn none() -> Self {
        Self::default()
    }

    /// The OS's engine, with no script and no WPAD.
    pub fn native() -> Self {
        Self {
            pac: Pac::Native,
            ..Self::default()
        }
    }
}

// What this OS's engine runs. The shared crate builds `pac-native` on every target, so each
// OS that has an engine has it here.
const NATIVE_RUNS_URL: bool = cfg!(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "android"
));
const NATIVE_RUNS_BODY: bool = cfg!(any(target_os = "macos", target_os = "ios"));
const NATIVE_RUNS_WPAD: bool = cfg!(any(windows, target_os = "macos", target_os = "ios"));

// The engine that runs a body under `pac`, or `None` for the caller.
fn body_engine(pac: Pac) -> Option<Engine> {
    let native = NATIVE_RUNS_BODY.then_some(Engine::Native);
    let quickjs = proxy_watch::pac::QUICKJS_AVAILABLE.then_some(Engine::QuickJs);
    match pac {
        Pac::None => None,
        Pac::Native => native,
        Pac::QuickJs => quickjs,
        Pac::Auto => native.or(quickjs),
    }
}

/// The route for `url` under `config`. Unless `options` names an engine that runs it, a PAC
/// mode is answered from the mode itself: `resolve` refuses them without saying where the
/// script is. A URL with no host (`mailto:`, `file:`, `data:`) goes direct whatever the
/// mode, as `resolve_with_pac` answers it, so the engine does not change that answer.
pub fn route(config: &ProxyConfig, url: &str, options: &RouteOptions) -> Result<Answer, Failure> {
    let url =
        Url::parse(url).map_err(|error| Failure::new("ERR_INVALID_URL", error.to_string()))?;
    let hostless = matches!(url.host(), None | Some(Host::Domain("")));
    let answer = |route| {
        Ok(Answer {
            route,
            engine: Engine::None,
        })
    };
    let mode = &config.effective;
    let (inline, caller) = match mode {
        ProxyMode::Pac { .. } | ProxyMode::PacInline { .. } | ProxyMode::WpadAutoDetect
            if hostless =>
        {
            return answer(Route::Steps(vec![ProxyStep::Direct]));
        }
        ProxyMode::Pac { url, .. } => (false, Route::Pac(url.to_string())),
        ProxyMode::PacInline { script, .. } => (true, Route::PacInline(script.clone())),
        ProxyMode::WpadAutoDetect => (false, Route::Wpad),
        _ => {
            return proxy_watch::resolve(config, &url)
                .map_err(|error| Failure::from(&error))
                .and_then(|steps| answer(Route::Steps(steps)));
        }
    };
    let script = options.script.as_ref();
    let steps = if script.is_some() || inline {
        match body_engine(options.pac) {
            Some(Engine::QuickJs) => {
                let steps = proxy_watch::resolve_with_pac(config, &url, script, &options.policy);
                (steps, Engine::QuickJs)
            }
            Some(_) => (run_body_natively(config, &url, script), Engine::Native),
            // A script handed over to be run, or an engine asked for by name, with nothing
            // here to run it.
            None if script.is_some() || options.pac == Pac::QuickJs => {
                return Err(Failure::from(&Error::PacEngineUnavailable));
            }
            None => return answer(caller),
        }
    } else {
        let os_runs = match mode {
            ProxyMode::WpadAutoDetect => options.wpad && NATIVE_RUNS_WPAD,
            _ => NATIVE_RUNS_URL,
        };
        if !(os_runs && matches!(options.pac, Pac::Native | Pac::Auto)) {
            return answer(caller);
        }
        match run_natively(config, &url, options.wpad) {
            // A configuration the OS's engine does not take: one that did not come from the
            // OS. Said before anything ran, so the route is the caller's as without it.
            Err(Error::PacFetchRequired { .. } | Error::PacNotSupported { .. }) => {
                return answer(caller);
            }
            steps => (steps, Engine::Native),
        }
    };
    match steps {
        (Ok(steps), engine) => Ok(Answer {
            route: Route::Steps(steps),
            engine,
        }),
        (Err(error), _) => Err(Failure::from(&error)),
    }
}

// One per process and per `wpad`, so the OS's download cache is shared across snapshots.
// WinHTTP remembers a WPAD miss for as long as its session lives, and a resolver takes
// `wpad` when built, so the two settings never share one.
#[cfg(any(windows, target_os = "macos", target_os = "ios", target_os = "android"))]
fn run_natively(config: &ProxyConfig, url: &Url, wpad: bool) -> Result<Vec<ProxyStep>, Error> {
    use proxy_watch::pac::NativePacResolver;
    static NATIVE: [OnceLock<NativePacResolver>; 2] = [OnceLock::new(), OnceLock::new()];
    let slot = &NATIVE[usize::from(wpad)];
    let resolver = match slot.get() {
        Some(resolver) => resolver,
        None => {
            let built = open_native(wpad)?;
            slot.get_or_init(|| built)
        }
    };
    resolver.resolve_config(config, url)
}

#[cfg(windows)]
fn open_native(wpad: bool) -> Result<proxy_watch::pac::NativePacResolver, Error> {
    Ok(proxy_watch::pac::NativePacResolver::new()?.with_wpad(wpad))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn open_native(wpad: bool) -> Result<proxy_watch::pac::NativePacResolver, Error> {
    Ok(proxy_watch::pac::NativePacResolver::new().with_wpad(wpad))
}

// Android's settings carry no WPAD mode, and its resolver has no WPAD switch.
#[cfg(target_os = "android")]
fn open_native(_: bool) -> Result<proxy_watch::pac::NativePacResolver, Error> {
    Ok(proxy_watch::pac::NativePacResolver::new())
}

#[cfg(not(any(windows, target_os = "macos", target_os = "ios", target_os = "android")))]
fn run_natively(_: &ProxyConfig, _: &Url, _: bool) -> Result<Vec<ProxyStep>, Error> {
    Err(Error::PacEngineUnavailable)
}

// CFNetwork evaluating a body: `script`, or the configuration's own.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn run_body_natively(
    config: &ProxyConfig,
    url: &Url,
    script: Option<&PacScript>,
) -> Result<Vec<ProxyStep>, Error> {
    proxy_watch::pac::PacResolver::new(PacPolicy::new())
        .with_evaluator(proxy_watch::pac::CfNetworkPacEvaluator::new())
        .resolve_config(config, url, script)
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn run_body_natively(
    _: &ProxyConfig,
    _: &Url,
    _: Option<&PacScript>,
) -> Result<Vec<ProxyStep>, Error> {
    Err(Error::PacEngineUnavailable)
}

/// `"direct"`, or the proxy URL with its credentials and its `socks5h` / `socks4a` hint.
pub fn step_url(step: &ProxyStep) -> Result<String, Failure> {
    match step {
        ProxyStep::Direct => Ok("direct".to_owned()),
        step => step
            .to_url()
            .map(String::from)
            .ok_or_else(|| Failure::new("ERR_PROXY_WATCH", format!("{step:?} has no URL form"))),
    }
}

/// The OS settings, or a direct configuration where there are none to read (a Linux
/// server or container without a desktop), with `false` in that case.
///
/// `env` is captured on the thread that writes the process environment, so the read can
/// run on another.
pub fn read_os(env: &CapturedEnv) -> Result<(ProxyConfig, bool), Failure> {
    match proxy_watch::read_in(env) {
        Ok(config) => Ok((config, true)),
        Err(Error::Unsupported) => Ok((ProxyConfig::default(), false)),
        Err(error) => Err(Failure::from(&error)),
    }
}

/// `"before-system"` (the default), `"after-system"`, or `"ignore"` as `None`.
pub fn precedence(name: Option<&str>) -> Result<Option<EnvPrecedence>, Failure> {
    match name {
        None | Some("before-system") => Ok(Some(EnvPrecedence::BeforeSystem)),
        Some("after-system") => Ok(Some(EnvPrecedence::AfterSystem)),
        Some("ignore") => Ok(None),
        Some(other) => Err(Failure::new(
            "ERR_INVALID_ARG_VALUE",
            format!("unknown precedence {other:?}"),
        )),
    }
}

/// The environment layered over each OS reading, captured once.
#[derive(Debug)]
pub struct Layering(Option<(ProxyEnv, EnvPrecedence)>);

impl Layering {
    /// `vars`, or the process environment when `None`; nothing at all when `precedence`
    /// is `None`.
    pub fn new(
        vars: Option<HashMap<String, String>>,
        precedence: Option<EnvPrecedence>,
    ) -> Result<Self, Failure> {
        let Some(precedence) = precedence else {
            return Ok(Self(None));
        };
        let env = match vars {
            Some(vars) => ProxyEnv::from_vars(vars),
            None => ProxyEnv::from_env(),
        }
        .map_err(|error| Failure::from(&error))?;
        Ok(Self(Some((env, precedence))))
    }

    pub fn apply(&self, config: ProxyConfig) -> ProxyConfig {
        match &self.0 {
            Some((env, precedence)) => config.with_env(env, *precedence),
            None => config,
        }
    }
}

// Shared by the handle, its clones and the pump thread; whichever closes first wins and
// the others find nothing left to do.
struct Inner {
    closed: AtomicBool,
    // `None` where the OS has nothing to watch, or once the watch has stopped.
    watcher: Mutex<Option<ProxyWatcher>>,
    // Held by `close` across the join, so a second `close` returns only once it is done.
    pump: Mutex<Option<JoinHandle<()>>>,
    // Set by the pump thread as it starts, so a `close` from `deliver` knows not to wait
    // for itself without taking `pump`.
    pump_thread: OnceLock<ThreadId>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A `ProxyWatcher` drained by a pump thread. Clones share one watch.
#[derive(Clone)]
pub struct Watch {
    inner: Arc<Inner>,
    os_readable: bool,
}

impl std::fmt::Debug for Watch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watch")
            .field("closed", &self.inner.closed.load(Ordering::SeqCst))
            .field("os_readable", &self.os_readable)
            .finish_non_exhaustive()
    }
}

impl Watch {
    /// Start watching, handing each change after the first reading to `deliver` on the
    /// pump thread until it returns `false` or the watch closes. Where the OS has nothing
    /// to watch, no thread starts and [`Watch::current`] answers direct. The start and every
    /// re-read take the environment from `env`, as [`read_os`] does.
    pub fn start(
        poll_interval: Option<Duration>,
        env: &CapturedEnv,
        thread_name: &str,
        mut deliver: impl FnMut(Result<ProxyConfig, Failure>) -> bool + Send + 'static,
    ) -> Result<Self, Failure> {
        let options = WatchOptions::new().with_poll_interval(poll_interval);
        let (mut watcher, os_readable) = match ProxyWatcher::with_options_in(options, env) {
            Ok(watcher) => (Some(watcher), true),
            // Nothing to watch, as `read_os` reports it.
            Err(Error::Unsupported) => (None, false),
            Err(error) => return Err(Failure::from(&error)),
        };
        // The constructor's read is queued already and is what `current()` answers, so it is
        // taken here, before anyone can call `current()`. Left for the pump, a change that
        // lands before the pump's first poll folds into it and is discarded with it.
        if let Some(watcher) = watcher.as_mut() {
            let _ = Pin::new(&mut *watcher).poll_next(&mut Context::from_waker(Waker::noop()));
        }
        let first = watcher.as_ref().map(ProxyWatcher::current);
        let inner = Arc::new(Inner {
            closed: AtomicBool::new(false),
            watcher: Mutex::new(watcher),
            pump: Mutex::new(None),
            pump_thread: OnceLock::new(),
        });
        if let Some(first) = first {
            let pumped = Arc::clone(&inner);
            let pump = thread::Builder::new()
                .name(thread_name.to_owned())
                .spawn(move || pump(&pumped, first, &mut deliver))
                .map_err(|error| Failure::new("ERR_PROXY_WATCH", error.to_string()))?;
            *lock(&inner.pump) = Some(pump);
        }
        Ok(Self { inner, os_readable })
    }

    /// Whether the OS had settings to watch.
    pub fn os_readable(&self) -> bool {
        self.os_readable
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// The latest OS configuration, before any layering.
    pub fn current(&self) -> Result<ProxyConfig, Failure> {
        if self.is_closed() {
            return Err(Failure::new("ERR_WATCHER_CLOSED", "the watcher is closed"));
        }
        match lock(&self.inner.watcher).as_ref() {
            Some(watcher) => Ok(watcher.current()),
            // Nothing to watch: direct, as `read_os` reports it.
            None if !self.os_readable => Ok(ProxyConfig::default()),
            // A `close` from another thread between the check above and the lock.
            None if self.is_closed() => {
                Err(Failure::new("ERR_WATCHER_CLOSED", "the watcher is closed"))
            }
            // The platform watch ended and the pump dropped it. Answering direct here would
            // route around a proxy the OS still has configured.
            None => Err(stopped_on_its_own()),
        }
    }

    /// Stop watching and wait for the pump thread. Safe to call more than once and from
    /// several threads, each returning once the pump has stopped; from `deliver` itself it
    /// stops without waiting.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        if self.inner.pump_thread.get() == Some(&thread::current().id()) {
            // The pump drops the watcher itself on its way out.
            return;
        }
        let mut pump = lock(&self.inner.pump);
        if let Some(pump) = pump.take() {
            pump.thread().unpark();
            let _ = pump.join();
        }
        drop(pump);
        // Stops the platform thread, whether or not a pump ever ran.
        drop(lock(&self.inner.watcher).take());
    }

    /// Stop watching without waiting: the pump thread drops the watcher when it next
    /// wakes. For a host that must not block here, such as a garbage collector.
    pub fn close_in_background(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        // Busy means a `close` holds it across the join and finishes the job. Waiting for
        // it could wait on a pump that needs a lock this thread holds, such as the GIL.
        let pump = match self.inner.pump.try_lock() {
            Ok(pump) => pump,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        // Left in place for a later `close` to join.
        match pump.as_ref() {
            Some(pump) => pump.thread().unpark(),
            None => drop(lock(&self.inner.watcher).take()),
        }
    }
}

/// The values the sources held but `config` dropped (settings that silently stopped
/// applying), each as `"<kind> from <source>: <value>"`, credentials masked.
///
/// Every source's drops, not only the effective mode's: an environment holding nothing but
/// a malformed value does not win, and its drop is kept on its source. The winning source's
/// mode is also `effective`, hence the dedup.
pub fn rejected(config: &ProxyConfig) -> Vec<String> {
    let mut values = Vec::new();
    for mode in std::iter::once(&config.effective).chain(config.sources.iter().map(|(_, m)| m)) {
        let bypass = mode.bypass().map(|bypass| bypass.rejected.as_slice());
        for value in mode.rejected().into_iter().chain(bypass).flatten() {
            if !values.contains(&value) {
                values.push(value);
            }
        }
    }
    values.into_iter().map(rejected_text).collect()
}

fn rejected_text(value: &RejectedValue) -> String {
    format!(
        "{:?} from {:?}: {}",
        value.kind(),
        value.source(),
        value.redacted_input()
    )
}

/// A language-neutral tree each binding turns into its own dict or object.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<Value>),
    Map(Vec<(String, Value)>),
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Self::Str(text.to_owned())
    }
}

impl From<String> for Value {
    fn from(text: String) -> Self {
        Self::Str(text)
    }
}

impl From<bool> for Value {
    fn from(flag: bool) -> Self {
        Self::Bool(flag)
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Null, Into::into)
    }
}

fn map<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn list<T>(items: impl IntoIterator<Item = T>, each: impl Fn(T) -> Value) -> Value {
    Value::List(items.into_iter().map(each).collect())
}

/// The whole snapshot as data: the effective mode, every source's own, the sources left
/// out, and `os_readable`. A proxy's password is its value, not a mask. A dropped value
/// (`rejected`) stays masked, as [`rejected`] gives it: nothing uses it, so nothing needs
/// its secret. Enumerations are strings, a core variant's name where the bindings have no
/// name of their own, so a later variant is a new string rather than a failure.
pub fn describe(config: &ProxyConfig, os_readable: bool) -> Value {
    map([
        ("mode", describe_mode(&config.effective)),
        (
            "sources",
            list(&config.sources, |(source, mode)| {
                map([
                    ("source", format!("{source:?}").into()),
                    ("mode", describe_mode(mode)),
                ])
            }),
        ),
        (
            "fallbacks",
            list(&config.fallbacks, |source| format!("{source:?}").into()),
        ),
        ("rejected", list(rejected(config), Value::Str)),
        ("os_readable", os_readable.into()),
    ])
}

fn describe_mode(mode: &ProxyMode) -> Value {
    let rejected = |values: &[RejectedValue]| list(values, describe_rejected);
    match mode {
        ProxyMode::Direct => map([("kind", "direct".into())]),
        ProxyMode::Manual {
            per_scheme,
            bypass,
            rejected: dropped,
            ..
        } => {
            // In `Scheme::ALL`'s order, so the output does not follow the map's.
            let proxies = Scheme::ALL
                .iter()
                .filter_map(|scheme| {
                    per_scheme
                        .get(scheme)
                        .map(|entry| (scheme.as_str().to_owned(), describe_entry(entry)))
                })
                .collect();
            map([
                ("kind", "manual".into()),
                ("proxies", Value::Map(proxies)),
                ("bypass", describe_bypass(bypass)),
                ("rejected", rejected(dropped)),
            ])
        }
        ProxyMode::Pac {
            url,
            rejected: dropped,
            ..
        } => map([
            ("kind", "pac".into()),
            ("url", url.as_str().into()),
            ("rejected", rejected(dropped)),
        ]),
        ProxyMode::PacInline {
            script,
            rejected: dropped,
            ..
        } => map([
            ("kind", "pac-inline".into()),
            ("script", script.as_str().into()),
            ("rejected", rejected(dropped)),
        ]),
        ProxyMode::WpadAutoDetect => map([("kind", "wpad".into())]),
        other => map([("kind", format!("{other:?}").into())]),
    }
}

fn describe_entry(entry: &ProxyEntry) -> Value {
    match entry {
        ProxyEntry::Use(endpoint) => {
            let auth = endpoint.auth.as_ref();
            map([
                ("kind", "use".into()),
                (
                    "scheme",
                    endpoint.scheme_hint.map(ProxyScheme::as_str).into(),
                ),
                ("host", endpoint.host.to_string().into()),
                ("port", Value::Int(endpoint.port.into())),
                ("username", auth.map(ProxyAuth::username).into()),
                ("password", auth.and_then(ProxyAuth::password).into()),
                (
                    "password_state",
                    auth.map(|auth| format!("{:?}", auth.password_state()))
                        .into(),
                ),
            ])
        }
        ProxyEntry::Disabled => map([("kind", "disabled".into())]),
        ProxyEntry::Unusable(value) => map([
            ("kind", "unusable".into()),
            ("rejected", describe_rejected(value)),
        ]),
        other => map([("kind", format!("{other:?}").into())]),
    }
}

fn describe_bypass(bypass: &BypassRules) -> Value {
    map([
        (
            "patterns",
            list(&bypass.patterns, |pattern| pattern.to_string().into()),
        ),
        ("implicit", format!("{:?}", bypass.implicit).into()),
        (
            "exclude_simple_hostnames",
            bypass.exclude_simple_hostnames.into(),
        ),
        ("reversed_exceptions", bypass.reversed_exceptions.into()),
        ("require_explicit_port", bypass.require_explicit_port.into()),
        ("ipv4_mapped_as_ipv4", bypass.ipv4_mapped_as_ipv4.into()),
        ("strip_trailing_dot", bypass.strip_trailing_dot.into()),
        ("rejected", list(&bypass.rejected, describe_rejected)),
    ])
}

fn describe_rejected(value: &RejectedValue) -> Value {
    rejected_text(value).into()
}

fn stopped_on_its_own() -> Failure {
    Failure::new("ERR_PROXY_WATCH", "the watch has stopped; open a new one")
}

struct Unpark(Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

// Drains the watcher's stream into `deliver` until closed. `Watch::start` has taken the
// constructor's read already, and passes its configuration as `last`.
//
// A snapshot also arrives when only the watch's health changed (a route lost, or the watch
// stopped), with the configuration as it was. Neither is a change of the settings, and
// `deliver` promises only those, so a snapshot equal to `last` is not delivered. A watch
// that stopped on its own says so once, as the failure `current()` then answers with.
fn pump(
    inner: &Inner,
    mut last: ProxyConfig,
    deliver: &mut dyn FnMut(Result<ProxyConfig, Failure>) -> bool,
) {
    let _ = inner.pump_thread.set(thread::current().id());
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut cx = Context::from_waker(&waker);
    while !inner.closed.load(Ordering::SeqCst) {
        let polled = {
            let mut watcher = lock(&inner.watcher);
            let Some(watcher) = watcher.as_mut() else {
                return;
            };
            Pin::new(watcher).poll_next(&mut cx)
        };
        let event = match polled {
            Poll::Pending => {
                thread::park();
                continue;
            }
            Poll::Ready(None) => break,
            Poll::Ready(Some(event)) => event,
        };
        let value = match event {
            WatchEvent::Snapshot { state, .. } => {
                let stopped = state.health.stopped;
                if state.config != last {
                    last = state.config.clone();
                    if !deliver(Ok(state.config)) {
                        break;
                    }
                }
                // `deliver` above may have closed the watch from inside the callback; the
                // promise to the caller is that nothing is delivered after `close` returns,
                // and the loop's own check comes too late for this second call.
                if stopped {
                    if !inner.closed.load(Ordering::SeqCst) {
                        deliver(Err(stopped_on_its_own()));
                    }
                    break;
                }
                continue;
            }
            WatchEvent::Error { error, .. } => Err(Failure::from(&error)),
            _ => continue,
        };
        if !deliver(value) {
            break;
        }
    }
    drop(lock(&inner.watcher).take());
}

#[cfg(test)]
mod tests {
    use super::*;

    // `super::route` under `pac` alone, for the cases indifferent to which engine answers.
    fn route(config: &ProxyConfig, url: &str, pac: Pac) -> Result<Route, Failure> {
        let options = RouteOptions::new(pac, None, false, PacPolicy::new())?;
        super::route(config, url, &options).map(|answer| answer.route)
    }

    fn config(vars: &[(&str, &str)]) -> ProxyConfig {
        let env = ProxyEnv::from_vars(vars.iter().copied()).unwrap();
        ProxyConfig::default().with_env(&env, EnvPrecedence::BeforeSystem)
    }

    fn urls(route: Route) -> Vec<String> {
        let Route::Steps(steps) = route else {
            panic!("{route:?} is not steps");
        };
        steps.iter().map(|step| step_url(step).unwrap()).collect()
    }

    #[test]
    fn steps_carry_proxy_urls_with_their_credentials_and_socks_hints() {
        let config = config(&[
            ("https_proxy", "http://user:pass@proxy.example:3128"),
            ("all_proxy", "socks5h://socks.example:1080"),
            ("no_proxy", "internal.example"),
        ]);
        assert_eq!(
            urls(route(&config, "https://a.example/", Pac::None).unwrap()),
            ["http://user:pass@proxy.example:3128/"]
        );
        assert_eq!(
            urls(route(&config, "ftp://a.example/", Pac::None).unwrap()),
            ["socks5h://socks.example:1080"]
        );
        assert_eq!(
            urls(route(&config, "https://internal.example/", Pac::None).unwrap()),
            ["direct"]
        );
    }

    #[test]
    fn pac_modes_are_answered_with_where_the_script_is() {
        let pac = ProxyConfig::new(
            ProxyMode::pac(Url::parse("http://wpad.example/proxy.pac").unwrap()),
            Vec::new(),
        );
        assert_eq!(
            route(&pac, "https://a.example/", Pac::None).unwrap(),
            Route::Pac("http://wpad.example/proxy.pac".to_owned())
        );
        let wpad = ProxyConfig::new(ProxyMode::WpadAutoDetect, Vec::new());
        assert_eq!(
            route(&wpad, "https://a.example/", Pac::None).unwrap(),
            Route::Wpad
        );
        assert_eq!(
            route(&wpad, "https://a.example/", Pac::Native).unwrap(),
            Route::Wpad
        );
    }

    // A server on 127.0.0.1 answering every request with one PAC script.
    fn serve_pac(body: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let _ = stream.read(&mut [0; 4096]);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        format!("http://127.0.0.1:{port}/proxy.pac")
    }

    #[test]
    fn native_runs_a_pac_url_where_the_os_has_an_engine_and_names_it_elsewhere() {
        let script = serve_pac("function FindProxyForURL(u, h) { return 'PROXY p.example:8080'; }");
        let config = ProxyConfig::new(ProxyMode::pac(Url::parse(&script).unwrap()), Vec::new());
        let route = route(&config, "http://a.example/", Pac::Native).unwrap();
        if cfg!(any(windows, target_os = "macos")) {
            assert_eq!(urls(route), ["http://p.example:8080/"]);
        } else {
            assert_eq!(route, Route::Pac(script));
        }
    }

    // A URL with no host goes direct under every auto-config mode, and the same with or
    // without `Pac::Native`: the OS engines answer it so, and a URL they would not run a
    // script for is no URL to hand the caller one.
    #[test]
    fn a_url_with_no_host_goes_direct_whoever_would_run_the_script() {
        let pac = Url::parse("http://wpad.example/proxy.pac").unwrap();
        for mode in [
            ProxyMode::pac(pac.clone()),
            ProxyMode::pac_inline("function FindProxyForURL(u, h) { return 'DIRECT'; }".to_owned()),
            ProxyMode::WpadAutoDetect,
        ] {
            let config = ProxyConfig::new(mode.clone(), Vec::new());
            for url in ["mailto:someone@a.example", "file:///etc/hosts", "data:,x"] {
                for pac in [Pac::None, Pac::Native, Pac::QuickJs, Pac::Auto] {
                    assert_eq!(
                        urls(route(&config, url, pac).unwrap()),
                        ["direct"],
                        "{mode:?} {url} {pac:?}"
                    );
                }
            }
            assert!(!matches!(
                route(&config, "http://a.example/", Pac::None).unwrap(),
                Route::Steps(_)
            ));
        }
    }

    // The code is what every binding's caller branches on, so each variant's is pinned here
    // rather than read back from the table it would be checking.
    #[test]
    fn each_error_variant_has_its_own_code() {
        let text = || "x".to_owned();
        let cases = [
            (
                Error::InvalidProxyServer {
                    input: text(),
                    reason: text(),
                },
                "ERR_INVALID_PROXY_SERVER",
            ),
            (
                Error::InvalidBypassPattern {
                    input: text(),
                    reason: text(),
                },
                "ERR_INVALID_BYPASS_PATTERN",
            ),
            (
                Error::InvalidProxyUrl {
                    input: text(),
                    source: Url::parse("").unwrap_err(),
                },
                "ERR_INVALID_PROXY_URL",
            ),
            (
                Error::UnsupportedProxyScheme(text()),
                "ERR_UNSUPPORTED_PROXY_SCHEME",
            ),
            (
                Error::CgiHttpProxy { variable: text() },
                "ERR_CGI_HTTP_PROXY",
            ),
            (
                Error::Io {
                    context: text(),
                    source: std::io::Error::other("x"),
                },
                "ERR_IO",
            ),
            (
                Error::Sandboxed {
                    sandbox: text(),
                    reason: text(),
                },
                "ERR_SANDBOXED",
            ),
            (Error::Unsupported, "ERR_UNSUPPORTED"),
            (
                Error::PacNotSupported { mode: "wpad" },
                "ERR_PAC_NOT_SUPPORTED",
            ),
            (
                Error::PacFetchRequired {
                    url: Url::parse("http://a.example/p.pac").unwrap(),
                },
                "ERR_PAC_FETCH_REQUIRED",
            ),
            (
                Error::PacEvaluation { reason: text() },
                "ERR_PAC_EVALUATION",
            ),
            (
                Error::PacTimeout {
                    timeout: Duration::from_secs(1),
                },
                "ERR_PAC_TIMEOUT",
            ),
            (
                Error::PacSaturated {
                    timeout: Duration::from_secs(1),
                    limit: 1,
                },
                "ERR_PAC_SATURATED",
            ),
            (
                Error::PacInvalidResult { result: text() },
                "ERR_PAC_INVALID_RESULT",
            ),
            (Error::PacEngineUnavailable, "ERR_PAC_ENGINE_UNAVAILABLE"),
        ];
        for (error, code) in cases {
            assert_eq!(Failure::from(&error).code, code, "{error:?}");
        }
    }

    #[test]
    fn each_pac_name_maps_and_others_are_refused() {
        assert_eq!(pac(None).unwrap(), Pac::None);
        assert_eq!(pac(Some("none")).unwrap(), Pac::None);
        assert_eq!(pac(Some("native")).unwrap(), Pac::Native);
        assert_eq!(pac(Some("quickjs")).unwrap(), Pac::QuickJs);
        assert_eq!(pac(Some("auto")).unwrap(), Pac::Auto);
        assert_eq!(pac(Some("v8")).unwrap_err().code, "ERR_INVALID_ARG_VALUE");
    }

    #[test]
    fn a_script_or_wpad_with_no_engine_to_take_it_is_refused() {
        let refused = |pac, script: Option<&str>, wpad| {
            RouteOptions::new(pac, script.map(str::to_owned), wpad, PacPolicy::new())
                .unwrap_err()
                .code
        };
        assert_eq!(
            refused(Pac::None, Some(DIRECT), false),
            "ERR_INVALID_ARG_VALUE"
        );
        assert_eq!(refused(Pac::None, None, true), "ERR_INVALID_ARG_VALUE");
        assert_eq!(refused(Pac::QuickJs, None, true), "ERR_INVALID_ARG_VALUE");
        let long = " ".repeat(MAX_SCRIPT_LEN + 1);
        assert_eq!(
            refused(Pac::Auto, Some(&long), false),
            "ERR_INVALID_ARG_VALUE"
        );
        for pac in [Pac::Native, Pac::Auto] {
            RouteOptions::new(pac, Some(DIRECT.to_owned()), true, PacPolicy::new()).unwrap();
        }
    }

    #[test]
    fn a_policy_takes_each_field_and_refuses_values_out_of_range() {
        let policy = policy(&PolicyOptions {
            my_ip_address: Some("10.1.2.3".to_owned()),
            resolve_dns: Some(true),
            allow_internal_addresses: Some(true),
            utc_offset_seconds: Some(9 * 3600),
            timeout_ms: Some(250),
        })
        .unwrap();
        assert_eq!(policy.my_ip_address().to_string(), "10.1.2.3");
        assert!(policy.resolve_dns());
        assert!(policy.allow_internal_addresses());
        assert_eq!(policy.local_utc_offset(), 9 * 3600);
        assert_eq!(policy.timeout(), Some(Duration::from_millis(250)));

        let defaults = super::policy(&PolicyOptions::default()).unwrap();
        assert_eq!(defaults.my_ip_address(), PacPolicy::new().my_ip_address());
        assert!(!defaults.resolve_dns());
        assert_eq!(defaults.timeout(), PacPolicy::new().timeout());

        for options in [
            PolicyOptions {
                my_ip_address: Some("corp.example".to_owned()),
                ..PolicyOptions::default()
            },
            PolicyOptions {
                utc_offset_seconds: Some(-86_400),
                ..PolicyOptions::default()
            },
            PolicyOptions {
                timeout_ms: Some(0),
                ..PolicyOptions::default()
            },
            PolicyOptions {
                timeout_ms: Some(60_001),
                ..PolicyOptions::default()
            },
        ] {
            assert_eq!(
                super::policy(&options).unwrap_err().code,
                "ERR_INVALID_ARG_VALUE",
                "{options:?}"
            );
        }
    }

    const DIRECT: &str = "function FindProxyForURL(u, h) { return 'DIRECT'; }";
    // Answers by where the script runs, as a script choosing a proxy by network does.
    const BY_NETWORK: &str = "function FindProxyForURL(u, h) { \
        return isInNet(myIpAddress(), '10.0.0.0', '255.0.0.0') ? 'PROXY corp.example:8080' : 'DIRECT'; }";

    fn answer(
        config: &ProxyConfig,
        pac: Pac,
        script: Option<&str>,
        policy: PacPolicy,
    ) -> Result<Answer, Failure> {
        let options = RouteOptions::new(pac, script.map(str::to_owned), false, policy)?;
        super::route(config, "http://a.example/", &options)
    }

    fn steps(answer: Answer) -> (Vec<String>, &'static str) {
        let engine = answer.engine.name();
        (urls(answer.route), engine)
    }

    #[test]
    fn quickjs_runs_a_script_under_the_policy_and_says_so() {
        if !proxy_watch::pac::QUICKJS_AVAILABLE {
            return;
        }
        let pac = ProxyConfig::new(
            ProxyMode::pac(Url::parse("http://wpad.example/proxy.pac").unwrap()),
            Vec::new(),
        );
        // The defaults place the script off every network.
        assert_eq!(
            steps(answer(&pac, Pac::QuickJs, Some(BY_NETWORK), PacPolicy::new()).unwrap()),
            (vec!["direct".to_owned()], "quickjs")
        );
        let inside = PacPolicy::new().with_my_ip_address("10.1.2.3".parse().unwrap());
        assert_eq!(
            steps(answer(&pac, Pac::QuickJs, Some(BY_NETWORK), inside).unwrap()),
            (vec!["http://corp.example:8080/".to_owned()], "quickjs")
        );
        // Without a script, a PAC URL stays the caller's: QuickJS fetches nothing.
        let left = answer(&pac, Pac::QuickJs, None, PacPolicy::new()).unwrap();
        assert_eq!(
            left.route,
            Route::Pac("http://wpad.example/proxy.pac".to_owned())
        );
        assert_eq!(left.engine, Engine::None);
        // A body that is not a PAC script fails rather than going direct.
        assert_eq!(
            answer(
                &pac,
                Pac::QuickJs,
                Some("this is not javascript"),
                PacPolicy::new()
            )
            .unwrap_err()
            .code,
            "ERR_PAC_EVALUATION"
        );
    }

    #[test]
    fn an_inline_body_runs_on_the_engine_pac_names() {
        let inline = ProxyConfig::new(
            ProxyMode::pac_inline(
                "function FindProxyForURL(u, h) { return 'PROXY p.example:3128'; }".to_owned(),
            ),
            Vec::new(),
        );
        let ran = |answer: Answer| {
            assert_eq!(urls(answer.route), ["http://p.example:3128/"]);
            answer.engine
        };
        let native_body = cfg!(any(target_os = "macos", target_os = "ios"));
        let quickjs = proxy_watch::pac::QUICKJS_AVAILABLE;
        match answer(&inline, Pac::Native, None, PacPolicy::new()) {
            Ok(answer) if native_body => assert_eq!(ran(answer), Engine::Native),
            other => assert!(matches!(other.unwrap().route, Route::PacInline(_))),
        }
        match answer(&inline, Pac::QuickJs, None, PacPolicy::new()) {
            Ok(answer) if quickjs => assert_eq!(ran(answer), Engine::QuickJs),
            other => assert_eq!(other.unwrap_err().code, "ERR_PAC_ENGINE_UNAVAILABLE"),
        }
        let auto = answer(&inline, Pac::Auto, None, PacPolicy::new()).unwrap();
        match (native_body, quickjs) {
            (true, _) => assert_eq!(ran(auto), Engine::Native),
            (false, true) => assert_eq!(ran(auto), Engine::QuickJs),
            (false, false) => assert!(matches!(auto.route, Route::PacInline(_))),
        }
    }

    // `native` with a script on an OS whose engine takes no body fails rather than running
    // QuickJS, whose answer can differ from the OS's.
    #[test]
    fn native_never_hands_a_script_to_quickjs() {
        let pac = ProxyConfig::new(
            ProxyMode::pac(Url::parse("http://wpad.example/proxy.pac").unwrap()),
            Vec::new(),
        );
        let answered = answer(&pac, Pac::Native, Some(DIRECT), PacPolicy::new());
        if cfg!(any(target_os = "macos", target_os = "ios")) {
            assert_eq!(answered.unwrap().engine, Engine::Native);
        } else {
            assert_eq!(answered.unwrap_err().code, "ERR_PAC_ENGINE_UNAVAILABLE");
        }
    }

    #[test]
    fn wpad_without_a_script_is_the_callers_unless_the_os_is_asked_to_discover() {
        let wpad = ProxyConfig::new(ProxyMode::WpadAutoDetect, Vec::new());
        for pac in [Pac::None, Pac::Native, Pac::QuickJs, Pac::Auto] {
            let answered = answer(&wpad, pac, None, PacPolicy::new()).unwrap();
            assert_eq!(
                answered,
                Answer {
                    route: Route::Wpad,
                    engine: Engine::None
                },
                "{pac:?}"
            );
        }
    }

    #[test]
    fn a_mode_that_is_not_pac_runs_no_engine_and_ignores_the_script() {
        let manual = config(&[("http_proxy", "http://p.example:1")]);
        for pac in [Pac::Native, Pac::QuickJs, Pac::Auto] {
            let answered = answer(&manual, pac, Some(DIRECT), PacPolicy::new()).unwrap();
            assert_eq!(
                steps(answered),
                (vec!["http://p.example:1/".to_owned()], "none")
            );
        }
    }

    // The state the pump leaves when the platform watch ends on its own: the OS had
    // settings, and the watcher is gone without a `close`.
    #[test]
    fn current_refuses_rather_than_answering_direct_once_the_watch_has_stopped() {
        let watch = |os_readable| Watch {
            inner: Arc::new(Inner {
                closed: AtomicBool::new(false),
                watcher: Mutex::new(None),
                pump: Mutex::new(None),
                pump_thread: OnceLock::new(),
            }),
            os_readable,
        };
        assert_eq!(watch(true).current().unwrap_err().code, "ERR_PROXY_WATCH");
        assert_eq!(watch(false).current().unwrap(), ProxyConfig::default());
    }

    // The C header promises `on_change` is not running once `pw_watch_close` returns, and
    // that holds for a second closer too, which finds `closed` already set.
    #[test]
    fn a_second_close_waits_for_the_pump_as_the_first_does() {
        let (watch, stopped) = slow_pump();
        let first = {
            let watch = watch.clone();
            thread::spawn(move || watch.close())
        };
        while !watch.is_closed() {
            thread::yield_now();
        }
        watch.close();
        assert!(stopped.load(Ordering::SeqCst));
        first.join().unwrap();
    }

    #[test]
    fn a_close_after_a_background_close_waits_for_the_pump() {
        let (watch, stopped) = slow_pump();
        watch.clone().close_in_background();
        watch.close();
        assert!(stopped.load(Ordering::SeqCst));
    }

    // A pump that takes 200 ms to stop once closed, and says when it has.
    fn slow_pump() -> (Watch, Arc<AtomicBool>) {
        let inner = Arc::new(Inner {
            closed: AtomicBool::new(false),
            watcher: Mutex::new(None),
            pump: Mutex::new(None),
            pump_thread: OnceLock::new(),
        });
        let stopped = Arc::new(AtomicBool::new(false));
        let pump = {
            let (inner, stopped) = (Arc::clone(&inner), Arc::clone(&stopped));
            thread::spawn(move || {
                while !inner.closed.load(Ordering::SeqCst) {
                    thread::park();
                }
                thread::sleep(Duration::from_millis(200));
                stopped.store(true, Ordering::SeqCst);
            })
        };
        *lock(&inner.pump) = Some(pump);
        let watch = Watch {
            inner,
            os_readable: true,
        };
        (watch, stopped)
    }

    #[test]
    fn a_url_that_does_not_parse_is_an_invalid_url() {
        let error = route(&ProxyConfig::default(), "not a url", Pac::None).unwrap_err();
        assert_eq!(error.code, "ERR_INVALID_URL");
    }

    #[test]
    fn each_precedence_name_maps_ignore_layers_nothing_and_others_are_refused() {
        assert_eq!(precedence(Some("ignore")).unwrap(), None);
        assert_eq!(
            precedence(Some("after-system")).unwrap(),
            Some(EnvPrecedence::AfterSystem)
        );
        assert_eq!(
            precedence(None).unwrap(),
            precedence(Some("before-system")).unwrap()
        );
        assert_eq!(
            precedence(Some("sideways")).unwrap_err().code,
            "ERR_INVALID_ARG_VALUE"
        );
        let vars = HashMap::from([("https_proxy".to_owned(), "http://p.example:1".to_owned())]);
        let ignored = Layering::new(Some(vars), None).unwrap();
        assert_eq!(
            urls(
                route(
                    &ignored.apply(ProxyConfig::default()),
                    "https://a.example/",
                    Pac::None
                )
                .unwrap()
            ),
            ["direct"]
        );
    }
}
