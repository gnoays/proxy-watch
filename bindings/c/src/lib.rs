//! A C ABI over one snapshot of the proxy configuration: open a context, ask it for the
//! route to a URL, read the route's steps, free both. A watch hands out a fresh context
//! after each change. `include/proxy_watch.h` declares it.
//!
//! A function returning `int` returns a `pw_status` unless its comment says otherwise; one
//! returning a value answers `NULL`, `-1` or `0` on failure, as its comment says.
//! `pw_last_error()` holds the message of the calling thread's last failure. A context or
//! route never changes after it is made, and a watch locks what it shares, so any handle
//! may be read from several threads at once; the strings a handle returns live until the
//! handle is freed. No panic crosses the boundary.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::time::Duration;

use proxy_watch::{CapturedEnv, EnvPrecedence, ProxyConfig, ProxyStep};
use proxy_watch_shared::{self as shared, Answer, Engine, Failure, Layering, Pac, Route};

pub const PW_OK: c_int = 0;
pub const PW_ERR_PROXY_WATCH: c_int = 1;
pub const PW_ERR_UNSUPPORTED_PROXY_SCHEME: c_int = 2;
pub const PW_ERR_INVALID_URL: c_int = 3;
pub const PW_ERR_INVALID_PROXY_SERVER: c_int = 4;
pub const PW_ERR_INVALID_BYPASS_PATTERN: c_int = 5;
pub const PW_ERR_INVALID_PROXY_URL: c_int = 6;
pub const PW_ERR_CGI_HTTP_PROXY: c_int = 7;
pub const PW_ERR_IO: c_int = 8;
pub const PW_ERR_SANDBOXED: c_int = 9;
pub const PW_ERR_UNSUPPORTED: c_int = 10;
pub const PW_ERR_PAC_NOT_SUPPORTED: c_int = 11;
pub const PW_ERR_PROXY_ENTRY_UNUSABLE: c_int = 12;
pub const PW_ERR_PAC_FETCH_REQUIRED: c_int = 13;
pub const PW_ERR_PAC_EVALUATION: c_int = 14;
pub const PW_ERR_PAC_TIMEOUT: c_int = 15;
pub const PW_ERR_PAC_SATURATED: c_int = 16;
pub const PW_ERR_PAC_INVALID_RESULT: c_int = 17;
pub const PW_ERR_PAC_ENGINE_UNAVAILABLE: c_int = 18;
pub const PW_ERR_NULL_ARGUMENT: c_int = 50;
pub const PW_ERR_INVALID_UTF8: c_int = 51;
pub const PW_ERR_INVALID_ARGUMENT: c_int = 52;
pub const PW_ERR_EMBEDDED_NUL: c_int = 53;
pub const PW_ERR_PANIC: c_int = 54;

pub const PW_PRECEDENCE_BEFORE_SYSTEM: c_int = 0;
pub const PW_PRECEDENCE_AFTER_SYSTEM: c_int = 1;
pub const PW_PRECEDENCE_IGNORE: c_int = 2;

pub const PW_ROUTE_STEPS: c_int = 0;
pub const PW_ROUTE_PAC: c_int = 1;
pub const PW_ROUTE_PAC_INLINE: c_int = 2;
pub const PW_ROUTE_WPAD: c_int = 3;

pub const PW_STEP_DIRECT: c_int = 0;
pub const PW_STEP_HTTP: c_int = 1;
pub const PW_STEP_HTTPS: c_int = 2;
pub const PW_STEP_SOCKS4: c_int = 3;
pub const PW_STEP_SOCKS5: c_int = 4;

pub const PW_PAC_NONE: c_int = 0;
pub const PW_PAC_NATIVE: c_int = 1;
pub const PW_PAC_QUICKJS: c_int = 2;
pub const PW_PAC_AUTO: c_int = 3;

pub const PW_ENGINE_NONE: c_int = 0;
pub const PW_ENGINE_NATIVE: c_int = 1;
pub const PW_ENGINE_QUICKJS: c_int = 2;

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

struct Fail(c_int, String);

impl From<Failure> for Fail {
    fn from(failure: Failure) -> Self {
        // The shared crate names one code per core error variant; each keeps its number.
        let status = match failure.code {
            "ERR_UNSUPPORTED_PROXY_SCHEME" => PW_ERR_UNSUPPORTED_PROXY_SCHEME,
            "ERR_INVALID_URL" => PW_ERR_INVALID_URL,
            "ERR_INVALID_PROXY_SERVER" => PW_ERR_INVALID_PROXY_SERVER,
            "ERR_INVALID_BYPASS_PATTERN" => PW_ERR_INVALID_BYPASS_PATTERN,
            "ERR_INVALID_PROXY_URL" => PW_ERR_INVALID_PROXY_URL,
            "ERR_CGI_HTTP_PROXY" => PW_ERR_CGI_HTTP_PROXY,
            "ERR_IO" => PW_ERR_IO,
            "ERR_SANDBOXED" => PW_ERR_SANDBOXED,
            "ERR_UNSUPPORTED" => PW_ERR_UNSUPPORTED,
            "ERR_PAC_NOT_SUPPORTED" => PW_ERR_PAC_NOT_SUPPORTED,
            "ERR_PROXY_ENTRY_UNUSABLE" => PW_ERR_PROXY_ENTRY_UNUSABLE,
            "ERR_PAC_FETCH_REQUIRED" => PW_ERR_PAC_FETCH_REQUIRED,
            "ERR_PAC_EVALUATION" => PW_ERR_PAC_EVALUATION,
            "ERR_PAC_TIMEOUT" => PW_ERR_PAC_TIMEOUT,
            "ERR_PAC_SATURATED" => PW_ERR_PAC_SATURATED,
            "ERR_PAC_INVALID_RESULT" => PW_ERR_PAC_INVALID_RESULT,
            "ERR_PAC_ENGINE_UNAVAILABLE" => PW_ERR_PAC_ENGINE_UNAVAILABLE,
            "ERR_INVALID_ARG_VALUE" => PW_ERR_INVALID_ARGUMENT,
            _ => PW_ERR_PROXY_WATCH,
        };
        Self(status, failure.message)
    }
}

fn null(name: &str) -> Fail {
    Fail(PW_ERR_NULL_ARGUMENT, format!("{name} is NULL"))
}

fn c_string(value: impl Into<Vec<u8>>) -> Result<CString, Fail> {
    CString::new(value).map_err(|_| Fail(PW_ERR_EMBEDDED_NUL, "a value holds a NUL byte".into()))
}

// Runs `body`, records its failure for `pw_last_error`, and turns a panic into a status.
fn guard(body: impl FnOnce() -> Result<(), Fail>) -> c_int {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => PW_OK,
        Ok(Err(fail)) => record(fail),
        Err(_) => record(Fail(PW_ERR_PANIC, "proxy-watch panicked".to_owned())),
    }
}

// Keeps the message for this thread's `pw_last_error` and returns the status. During thread
// exit, after `LAST_ERROR` is destroyed, the message is dropped: `with` would panic there, and
// a panic out of an `extern "C"` function aborts.
fn record(Fail(status, message): Fail) -> c_int {
    let message = CString::new(message.replace('\0', " ")).unwrap_or_default();
    let _ = LAST_ERROR.try_with(|last| *last.borrow_mut() = message);
    status
}

// SAFETY (callers): `text` is NULL or a NUL-terminated string that outlives the borrow.
unsafe fn text<'a>(text: *const c_char, name: &str) -> Result<&'a str, Fail> {
    if text.is_null() {
        return Err(null(name));
    }
    unsafe { CStr::from_ptr(text) }
        .to_str()
        .map_err(|_| Fail(PW_ERR_INVALID_UTF8, format!("{name} is not UTF-8")))
}

/// One reading of the OS settings with the environment layered over it.
pub struct Context {
    config: ProxyConfig,
    os_readable: bool,
    describe: CString,
    rejected: Vec<CString>,
}

impl Context {
    fn new(config: ProxyConfig, os_readable: bool) -> Result<Self, Fail> {
        // `ProxyConfig`'s `Debug` masks credentials, so it is safe to log.
        let rejected = shared::rejected(&config)
            .into_iter()
            .map(c_string)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            describe: c_string(format!("{config:?}"))?,
            rejected,
            config,
            os_readable,
        })
    }
}

struct Step {
    kind: c_int,
    scheme: Option<CString>,
    uri: CString,
    uri_with_auth: CString,
    username: Option<CString>,
    password: Option<CString>,
}

/// The route to one URL, its strings made once so they live as long as the handle.
pub struct RouteHandle {
    kind: c_int,
    engine: c_int,
    pac: Option<CString>,
    steps: Vec<Step>,
}

fn step(step: &ProxyStep) -> Result<Step, Fail> {
    let kind = match step {
        ProxyStep::Direct => PW_STEP_DIRECT,
        ProxyStep::Http(_) => PW_STEP_HTTP,
        ProxyStep::Https(_) => PW_STEP_HTTPS,
        ProxyStep::Socks4(_) => PW_STEP_SOCKS4,
        ProxyStep::Socks5(_) => PW_STEP_SOCKS5,
        // Answering direct would route around a proxy the caller cannot see.
        step => {
            let message = format!("{step:?} has no step kind here");
            return Err(Failure::new("ERR_PROXY_WATCH", message).into());
        }
    };
    let with_auth = shared::step_url(step)?;
    let Some(mut url) = step.to_url() else {
        return Ok(Step {
            kind,
            scheme: None,
            uri: c_string(with_auth.clone())?,
            uri_with_auth: c_string(with_auth)?,
            username: None,
            password: None,
        });
    };
    let scheme = Some(c_string(url.scheme())?);
    let auth = step.endpoint().and_then(|endpoint| endpoint.auth.as_ref());
    let username = auth.map(|auth| c_string(auth.username())).transpose()?;
    let password = auth
        .and_then(|auth| auth.password())
        .map(c_string)
        .transpose()?;
    // Both setters fail only on a URL that cannot hold credentials, which then has none.
    let _ = url.set_username("");
    let _ = url.set_password(None);
    Ok(Step {
        kind,
        scheme,
        uri: c_string(String::from(url))?,
        uri_with_auth: c_string(with_auth)?,
        username,
        password,
    })
}

fn precedence(value: c_int) -> Result<Option<EnvPrecedence>, Fail> {
    match value {
        PW_PRECEDENCE_BEFORE_SYSTEM => Ok(Some(EnvPrecedence::BeforeSystem)),
        PW_PRECEDENCE_AFTER_SYSTEM => Ok(Some(EnvPrecedence::AfterSystem)),
        PW_PRECEDENCE_IGNORE => Ok(None),
        other => Err(Fail(
            PW_ERR_INVALID_ARGUMENT,
            format!("unknown precedence {other}"),
        )),
    }
}

fn open(
    precedence_value: c_int,
    vars: Option<HashMap<String, String>>,
    out: *mut *mut Context,
) -> Result<(), Fail> {
    if out.is_null() {
        return Err(null("out"));
    }
    let layering = Layering::new(vars, precedence(precedence_value)?)?;
    let (config, os_readable) = shared::read_os(&CapturedEnv::capture())?;
    let context = Box::new(Context::new(layering.apply(config), os_readable)?);
    // SAFETY: `out` is non-NULL and the caller's to write.
    unsafe { *out = Box::into_raw(context) };
    Ok(())
}

/// Hand the library the process's `JavaVM` and an `android.content.Context`, once, before
/// the first context or watch is opened. Android only: elsewhere `PW_ERR_UNSUPPORTED`.
///
/// # Safety
///
/// On Android, `vm` is the process's `JavaVM*` and `context` a JNI reference (local or
/// global) to a `Context`, alive for the call; the library keeps its application `Context`
/// and borrows `context` only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_android_init(vm: *mut c_void, context: *mut c_void) -> c_int {
    guard(|| {
        if !cfg!(target_os = "android") {
            return Err(Fail(
                PW_ERR_UNSUPPORTED,
                "pw_android_init is for Android".to_owned(),
            ));
        }
        if vm.is_null() {
            return Err(null("vm"));
        }
        if context.is_null() {
            return Err(null("context"));
        }
        #[cfg(target_os = "android")]
        // SAFETY: the caller's promises, passed on unchanged.
        unsafe { proxy_watch::android::init(vm, context) }
            .map_err(|error| Fail::from(Failure::from(&error)))?;
        Ok(())
    })
}

/// Read the OS settings and the process environment into a new context.
///
/// # Safety
///
/// `out` is NULL or points to writable storage for one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_context_open(precedence: c_int, out: *mut *mut Context) -> c_int {
    guard(|| open(precedence, None, out))
}

/// As `pw_context_open`, reading `*_proxy` from `envp` instead of the process environment:
/// a NULL-terminated array of `"NAME=VALUE"` strings, as `environ` is. A name that is not
/// UTF-8 is none of the names read and is skipped; a value that is not UTF-8 is read with
/// replacement characters, so a proxy variable holding one is refused and recorded as
/// rejected. A name given twice keeps its first value, as `getenv` and `pw_context_open` do.
///
/// # Safety
///
/// `envp` is NULL or a NULL-terminated array of NUL-terminated strings; `out` as for
/// `pw_context_open`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_context_open_with_env(
    precedence: c_int,
    envp: *const *const c_char,
    out: *mut *mut Context,
) -> c_int {
    guard(|| {
        if envp.is_null() {
            return Err(null("envp"));
        }
        // SAFETY: as this function's caller promises.
        open(precedence, Some(unsafe { vars(envp) }?), out)
    })
}

// SAFETY (callers): `envp` is a NULL-terminated array of NUL-terminated strings.
unsafe fn vars(envp: *const *const c_char) -> Result<HashMap<String, String>, Fail> {
    let mut vars = HashMap::new();
    for index in 0.. {
        // SAFETY: the array is NULL-terminated, and this index is at or before the NULL.
        let entry = unsafe { *envp.add(index) };
        if entry.is_null() {
            break;
        }
        // SAFETY: each entry is a NUL-terminated string.
        let entry = unsafe { CStr::from_ptr(entry) }.to_bytes();
        let split = entry.iter().position(|byte| *byte == b'=').ok_or_else(|| {
            Fail(
                PW_ERR_INVALID_ARGUMENT,
                "an envp entry has no '='".to_owned(),
            )
        })?;
        // The core's rule for the process environment, so that one unrelated entry cannot
        // fail the call.
        let Ok(name) = std::str::from_utf8(&entry[..split]) else {
            continue;
        };
        vars.entry(name.to_owned())
            .or_insert_with(|| String::from_utf8_lossy(&entry[split + 1..]).into_owned());
    }
    Ok(vars)
}

/// Free a context. NULL is accepted.
///
/// # Safety
///
/// `context` is NULL or came from `pw_context_open*` and is not used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_context_free(context: *mut Context) {
    if !context.is_null() {
        // SAFETY: the caller hands back ownership of a box this crate made.
        drop(unsafe { Box::from_raw(context) });
    }
}

/// 1 when the OS had proxy settings to read, 0 when it had none (a Linux host without a
/// desktop), -1 for NULL.
///
/// # Safety
///
/// `context` is NULL or a live context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_context_os_readable(context: *const Context) -> c_int {
    // SAFETY: NULL or live, as the caller promises.
    match unsafe { context.as_ref() } {
        Some(context) => c_int::from(context.os_readable),
        None => -1,
    }
}

/// The route to `url` under `context`.
///
/// # Safety
///
/// `context` is NULL or a live context; `url` is NULL or a NUL-terminated string; `out`
/// is NULL or points to writable storage for one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_resolve(
    context: *const Context,
    url: *const c_char,
    out: *mut *mut RouteHandle,
) -> c_int {
    // SAFETY: the caller's promises, passed on unchanged.
    unsafe { pw_resolve_with_pac(context, url, PW_PAC_NONE, out) }
}

/// [`pw_resolve_ex`] with only `pac` set.
///
/// # Safety
///
/// As [`pw_resolve`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_resolve_with_pac(
    context: *const Context,
    url: *const c_char,
    pac: c_int,
    out: *mut *mut RouteHandle,
) -> c_int {
    let options = RouteOptions {
        size: size_of::<RouteOptions>(),
        pac,
        ..RouteOptions::default()
    };
    // SAFETY: the caller's promises, passed on unchanged; `options` is live for the call.
    unsafe { pw_resolve_ex(context, url, &options, out) }
}

/// `struct pw_route_options`. Zeroed, every field but `size` is its default.
#[repr(C)]
pub struct RouteOptions {
    /// `sizeof(struct pw_route_options)` as the caller compiled it.
    pub size: usize,
    pub pac: c_int,
    pub script: *const c_char,
    pub wpad: c_int,
    pub my_ip_address: *const c_char,
    pub resolve_dns: c_int,
    pub allow_internal_addresses: c_int,
    pub utc_offset_seconds: c_int,
    pub timeout_ms: c_uint,
}

impl Default for RouteOptions {
    fn default() -> Self {
        Self {
            size: 0,
            pac: PW_PAC_NONE,
            script: ptr::null(),
            wpad: 0,
            my_ip_address: ptr::null(),
            resolve_dns: 0,
            allow_internal_addresses: 0,
            utc_offset_seconds: 0,
            timeout_ms: 0,
        }
    }
}

// SAFETY (callers): `options` is non-NULL, readable for its own `size` bytes, and its
// strings are NULL or NUL-terminated.
unsafe fn route_options(options: *const RouteOptions) -> Result<shared::RouteOptions, Fail> {
    // The fields a caller compiled against an older header lacks would be read past its
    // struct, so a smaller size is refused before any reference to the whole struct exists;
    // a newer, larger one is read up to what this version knows.
    // SAFETY: `size` is the first field, present in every version of the struct.
    let size = unsafe { ptr::addr_of!((*options).size).read() };
    if size < size_of::<RouteOptions>() {
        return Err(Fail(
            PW_ERR_INVALID_ARGUMENT,
            format!(
                "options->size {size} is under sizeof(struct pw_route_options), {}",
                size_of::<RouteOptions>()
            ),
        ));
    }
    // SAFETY: readable for the whole struct, as `size` just showed.
    let options = unsafe { &*options };
    let pac = match options.pac {
        PW_PAC_NONE => Pac::None,
        PW_PAC_NATIVE => Pac::Native,
        PW_PAC_QUICKJS => Pac::QuickJs,
        PW_PAC_AUTO => Pac::Auto,
        other => {
            return Err(Fail(
                PW_ERR_INVALID_ARGUMENT,
                format!("unknown pac {other}"),
            ));
        }
    };
    let script = match options.script.is_null() {
        true => None,
        // SAFETY: NUL-terminated, as the caller promises.
        false => Some(unsafe { text(options.script, "options->script") }?.to_owned()),
    };
    let my_ip_address = match options.my_ip_address.is_null() {
        true => None,
        // SAFETY: NUL-terminated, as the caller promises.
        false => Some(unsafe { text(options.my_ip_address, "options->my_ip_address") }?.to_owned()),
    };
    let policy = shared::policy(&shared::PolicyOptions {
        my_ip_address,
        resolve_dns: Some(options.resolve_dns != 0),
        allow_internal_addresses: Some(options.allow_internal_addresses != 0),
        utc_offset_seconds: Some(options.utc_offset_seconds),
        timeout_ms: (options.timeout_ms != 0).then_some(u64::from(options.timeout_ms)),
    })?;
    Ok(shared::RouteOptions::new(
        pac,
        script,
        options.wpad != 0,
        policy,
    )?)
}

/// As [`pw_resolve`], with `options` choosing who runs a PAC configuration. NULL `options`
/// is [`pw_resolve`].
///
/// # Safety
///
/// As [`pw_resolve`]; `options` is NULL or points to a `pw_route_options` whose `size`
/// says how much of it is readable, and whose strings are NULL or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_resolve_ex(
    context: *const Context,
    url: *const c_char,
    options: *const RouteOptions,
    out: *mut *mut RouteHandle,
) -> c_int {
    guard(|| {
        let options = match options.is_null() {
            true => shared::RouteOptions::none(),
            // SAFETY: readable for its `size`, with strings as the caller promises.
            false => unsafe { route_options(options) }?,
        };
        // SAFETY: NULL or live, as the caller promises.
        let context = unsafe { context.as_ref() }.ok_or_else(|| null("context"))?;
        // SAFETY: NULL or NUL-terminated, as the caller promises.
        let url = unsafe { text(url, "url") }?;
        if out.is_null() {
            return Err(null("out"));
        }
        let Answer { route, engine } = shared::route(&context.config, url, &options)?;
        let engine = match engine {
            Engine::None => PW_ENGINE_NONE,
            Engine::Native => PW_ENGINE_NATIVE,
            Engine::QuickJs => PW_ENGINE_QUICKJS,
        };
        let (kind, pac, steps) = match route {
            Route::Steps(steps) => (
                PW_ROUTE_STEPS,
                None,
                steps.iter().map(step).collect::<Result<_, _>>()?,
            ),
            Route::Pac(url) => (PW_ROUTE_PAC, Some(c_string(url)?), Vec::new()),
            Route::PacInline(script) => (PW_ROUTE_PAC_INLINE, Some(c_string(script)?), Vec::new()),
            Route::Wpad => (PW_ROUTE_WPAD, None, Vec::new()),
        };
        let handle = RouteHandle {
            kind,
            engine,
            pac,
            steps,
        };
        // SAFETY: `out` is non-NULL and the caller's to write.
        unsafe { *out = Box::into_raw(Box::new(handle)) };
        Ok(())
    })
}

/// Free a route. NULL is accepted.
///
/// # Safety
///
/// `route` is NULL or came from `pw_resolve` and is not used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_route_free(route: *mut RouteHandle) {
    if !route.is_null() {
        // SAFETY: the caller hands back ownership of a box this crate made.
        drop(unsafe { Box::from_raw(route) });
    }
}

/// A `PW_ROUTE_*` value, or -1 for NULL.
///
/// # Safety
///
/// `route` is NULL or a live route.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_route_kind(route: *const RouteHandle) -> c_int {
    // SAFETY: NULL or live, as the caller promises.
    unsafe { route.as_ref() }.map_or(-1, |route| route.kind)
}

/// The `PW_ENGINE_*` that answered the route, or -1 for NULL.
///
/// # Safety
///
/// `route` is NULL or a live route.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_route_engine(route: *const RouteHandle) -> c_int {
    // SAFETY: NULL or live, as the caller promises.
    unsafe { route.as_ref() }.map_or(-1, |route| route.engine)
}

/// The PAC URL of a `PW_ROUTE_PAC` route or the script of a `PW_ROUTE_PAC_INLINE` one;
/// NULL otherwise.
///
/// # Safety
///
/// `route` is NULL or a live route.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_route_pac(route: *const RouteHandle) -> *const c_char {
    // SAFETY: NULL or live, as the caller promises.
    unsafe { route.as_ref() }
        .and_then(|route| route.pac.as_deref())
        .map_or(ptr::null(), CStr::as_ptr)
}

/// The number of steps; 0 for the PAC and WPAD routes and for NULL.
///
/// # Safety
///
/// `route` is NULL or a live route.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_route_len(route: *const RouteHandle) -> usize {
    // SAFETY: NULL or live, as the caller promises.
    unsafe { route.as_ref() }.map_or(0, |route| route.steps.len())
}

// SAFETY (callers): `route` is NULL or live.
unsafe fn step_at<'a>(route: *const RouteHandle, index: usize) -> Option<&'a Step> {
    unsafe { route.as_ref() }?.steps.get(index)
}

fn as_ptr(value: Option<&CString>) -> *const c_char {
    value.map_or(ptr::null(), |value| value.as_ptr())
}

/// A `PW_STEP_*` value, or -1 for NULL or an index out of range.
///
/// # Safety
///
/// `route` is NULL or a live route.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_route_step_kind(route: *const RouteHandle, index: usize) -> c_int {
    // SAFETY: as the caller promises.
    unsafe { step_at(route, index) }.map_or(-1, |step| step.kind)
}

/// The URL scheme, keeping `socks5h` and `socks4a`; NULL for a direct step.
///
/// # Safety
///
/// `route` is NULL or a live route.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_route_scheme(route: *const RouteHandle, index: usize) -> *const c_char {
    // SAFETY: as the caller promises.
    as_ptr(unsafe { step_at(route, index) }.and_then(|step| step.scheme.as_ref()))
}

/// `"direct"` or the proxy URL without credentials, safe to log.
///
/// # Safety
///
/// `route` is NULL or a live route.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_route_uri(route: *const RouteHandle, index: usize) -> *const c_char {
    // SAFETY: as the caller promises.
    as_ptr(unsafe { step_at(route, index) }.map(|step| &step.uri))
}

/// As `pw_route_uri`, with the credentials in the URL. Do not log it.
///
/// # Safety
///
/// `route` is NULL or a live route.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_route_uri_with_auth(
    route: *const RouteHandle,
    index: usize,
) -> *const c_char {
    // SAFETY: as the caller promises.
    as_ptr(unsafe { step_at(route, index) }.map(|step| &step.uri_with_auth))
}

/// The proxy user name, NULL when the step has none.
///
/// # Safety
///
/// `route` is NULL or a live route.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_route_username(
    route: *const RouteHandle,
    index: usize,
) -> *const c_char {
    // SAFETY: as the caller promises.
    as_ptr(unsafe { step_at(route, index) }.and_then(|step| step.username.as_ref()))
}

/// The proxy password, NULL when the step has none.
///
/// # Safety
///
/// `route` is NULL or a live route.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_route_password(
    route: *const RouteHandle,
    index: usize,
) -> *const c_char {
    // SAFETY: as the caller promises.
    as_ptr(unsafe { step_at(route, index) }.and_then(|step| step.password.as_ref()))
}

/// The whole configuration on one line with credentials masked, for a log; NULL for NULL.
///
/// # Safety
///
/// `context` is NULL or a live context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_describe(context: *const Context) -> *const c_char {
    // SAFETY: NULL or live, as the caller promises.
    as_ptr(unsafe { context.as_ref() }.map(|context| &context.describe))
}

/// The number of values the sources held but the snapshot dropped as unparseable or
/// unsupported. Each one is a setting that silently stopped applying.
///
/// # Safety
///
/// `context` is NULL or a live context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_rejected_len(context: *const Context) -> usize {
    // SAFETY: NULL or live, as the caller promises.
    unsafe { context.as_ref() }.map_or(0, |context| context.rejected.len())
}

/// One dropped value as `"<kind> from <source>: <value>"`, credentials masked; NULL out of
/// range.
///
/// # Safety
///
/// `context` is NULL or a live context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_rejected_text(context: *const Context, index: usize) -> *const c_char {
    // SAFETY: NULL or live, as the caller promises.
    as_ptr(unsafe { context.as_ref() }.and_then(|context| context.rejected.get(index)))
}

/// The message of this thread's last failure, `""` before any and from thread-exit code that
/// runs after this library's thread-local storage is gone. Valid until this thread's next
/// failing call.
#[unsafe(no_mangle)]
pub extern "C" fn pw_last_error() -> *const c_char {
    LAST_ERROR
        .try_with(|last| last.borrow().as_ptr())
        .unwrap_or(c"".as_ptr())
}

/// Called on the watcher's own thread after each change of the OS settings, with `PW_OK`,
/// or with a failure's status whose message `pw_last_error()` holds on that thread.
pub type OnChange = Option<unsafe extern "C" fn(userdata: *mut c_void, status: c_int)>;

struct UserData(*mut c_void);

// SAFETY: the pointer is never dereferenced here, only handed to the caller's callback on
// the watcher's thread; the header makes that thread part of the callback's contract.
unsafe impl Send for UserData {}

impl UserData {
    fn get(&self) -> *mut c_void {
        self.0
    }
}

/// A watch of the OS settings. Dropping it stops the watch.
pub struct WatchHandle {
    watch: shared::Watch,
    layering: Layering,
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        self.watch.close();
    }
}

/// Watch the OS settings, calling `on_change` (which may be NULL) after each change.
/// `envp` is read as `pw_context_open_with_env` reads it, or the process environment is
/// read when it is NULL, once, here. `poll_interval_ms` 0 relies on the OS's notification.
///
/// # Safety
///
/// `envp` is NULL or as for `pw_context_open_with_env`; `out` as for `pw_context_open`.
/// `on_change` returns normally and may be called on another thread with `userdata`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_watch_open(
    env_precedence: c_int,
    envp: *const *const c_char,
    poll_interval_ms: c_uint,
    on_change: OnChange,
    userdata: *mut c_void,
    out: *mut *mut WatchHandle,
) -> c_int {
    guard(|| {
        if out.is_null() {
            return Err(null("out"));
        }
        // SAFETY: as this function's caller promises.
        let vars = (!envp.is_null())
            .then(|| unsafe { vars(envp) })
            .transpose()?;
        let layering = Layering::new(vars, precedence(env_precedence)?)?;
        let poll_interval =
            (poll_interval_ms > 0).then(|| Duration::from_millis(poll_interval_ms.into()));
        let userdata = UserData(userdata);
        let env = CapturedEnv::capture();
        let watch = shared::Watch::start(poll_interval, &env, "proxy-watch-c", move |value| {
            if let Some(on_change) = on_change {
                let status = match value {
                    Ok(_) => PW_OK,
                    Err(failure) => record(failure.into()),
                };
                // SAFETY: the caller's callback, with the caller's pointer.
                unsafe { on_change(userdata.get(), status) };
            }
            true
        })?;
        let handle = Box::new(WatchHandle { watch, layering });
        // SAFETY: `out` is non-NULL and the caller's to write.
        unsafe { *out = Box::into_raw(handle) };
        Ok(())
    })
}

/// A new context holding the watch's latest reading, layered with the environment
/// `pw_watch_open` captured.
///
/// # Safety
///
/// `watch` is NULL or a live watch; `out` as for `pw_context_open`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_watch_current(
    watch: *const WatchHandle,
    out: *mut *mut Context,
) -> c_int {
    guard(|| {
        // SAFETY: NULL or live, as the caller promises.
        let watch = unsafe { watch.as_ref() }.ok_or_else(|| null("watch"))?;
        if out.is_null() {
            return Err(null("out"));
        }
        let config = watch.layering.apply(watch.watch.current()?);
        let context = Box::new(Context::new(config, watch.watch.os_readable())?);
        // SAFETY: `out` is non-NULL and the caller's to write.
        unsafe { *out = Box::into_raw(context) };
        Ok(())
    })
}

/// Stop a watch and free it. Once this returns, `on_change` is not running and is not
/// called again; called from `on_change` itself, it returns without waiting and
/// `on_change` is not called again. NULL is accepted.
///
/// # Safety
///
/// `watch` is NULL or came from `pw_watch_open` in this process and is not used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_watch_close(watch: *mut WatchHandle) {
    if !watch.is_null() {
        // SAFETY: the caller hands back ownership of a box this crate made.
        drop(unsafe { Box::from_raw(watch) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_watch::{ProxyMode, Url};

    fn string(value: *const c_char) -> Option<String> {
        (!value.is_null()).then(|| {
            unsafe { CStr::from_ptr(value) }
                .to_str()
                .unwrap()
                .to_owned()
        })
    }

    fn context(vars: &[&str]) -> *mut Context {
        let vars: Vec<CString> = vars.iter().map(|var| CString::new(*var).unwrap()).collect();
        let mut envp: Vec<*const c_char> = vars.iter().map(|var| var.as_ptr()).collect();
        envp.push(ptr::null());
        let mut context = ptr::null_mut();
        let status = unsafe {
            pw_context_open_with_env(PW_PRECEDENCE_BEFORE_SYSTEM, envp.as_ptr(), &mut context)
        };
        assert_eq!(status, PW_OK, "{:?}", string(pw_last_error()));
        context
    }

    fn route(context: *const Context, url: &str) -> *mut RouteHandle {
        let url = CString::new(url).unwrap();
        let mut route = ptr::null_mut();
        assert_eq!(
            unsafe { pw_resolve(context, url.as_ptr(), &mut route) },
            PW_OK
        );
        route
    }

    #[test]
    fn a_step_keeps_its_credentials_out_of_the_uri_and_its_socks_hint_in_the_scheme() {
        let context = context(&[
            "https_proxy=http://user:pa%20ss@proxy.example:3128",
            "all_proxy=socks5h://socks.example:1080",
        ]);
        unsafe {
            let https = route(context, "https://a.example/");
            assert_eq!(pw_route_kind(https), PW_ROUTE_STEPS);
            assert_eq!(pw_route_len(https), 1);
            assert_eq!(pw_route_step_kind(https, 0), PW_STEP_HTTP);
            assert_eq!(
                string(pw_route_uri(https, 0)).unwrap(),
                "http://proxy.example:3128/"
            );
            assert_eq!(
                string(pw_route_uri_with_auth(https, 0)).unwrap(),
                "http://user:pa%20ss@proxy.example:3128/"
            );
            assert_eq!(string(pw_route_username(https, 0)).unwrap(), "user");
            assert_eq!(string(pw_route_password(https, 0)).unwrap(), "pa ss");
            assert!(pw_route_uri(https, 1).is_null());
            assert_eq!(pw_route_step_kind(https, 1), -1);
            pw_route_free(https);

            let ftp = route(context, "ftp://a.example/");
            assert_eq!(pw_route_step_kind(ftp, 0), PW_STEP_SOCKS5);
            assert_eq!(string(pw_route_scheme(ftp, 0)).unwrap(), "socks5h");
            assert!(pw_route_username(ftp, 0).is_null());
            pw_route_free(ftp);
            pw_context_free(context);
        }
    }

    // A panic stops at the boundary as a status: unwinding into C is undefined behaviour.
    #[test]
    fn a_panic_is_a_status_with_a_message() {
        let status = guard(|| panic!("simulated"));
        assert_eq!(status, PW_ERR_PANIC);
        assert_eq!(string(pw_last_error()).unwrap(), "proxy-watch panicked");
    }

    // A C caller can reach this library from its own thread-exit code, after this thread's
    // `LAST_ERROR` is gone. `LocalKey::with` panics there, and a panic in an `extern "C"`
    // function or a TLS destructor aborts the process.
    #[test]
    fn a_failure_after_the_thread_locals_are_gone_is_still_a_status() {
        struct Late(std::sync::mpsc::Sender<(c_int, Option<String>)>);
        impl Drop for Late {
            fn drop(&mut self) {
                let status = record(Fail(PW_ERR_IO, "late".to_owned()));
                let _ = self.0.send((status, string(pw_last_error())));
            }
        }
        thread_local! {
            static LATE: RefCell<Option<Late>> = const { RefCell::new(None) };
        }
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // Registered before `LAST_ERROR`, so destroyed after it.
            LATE.with(|late| *late.borrow_mut() = Some(Late(send)));
            record(Fail(PW_ERR_IO, "early".to_owned()));
        })
        .join()
        .unwrap();
        assert_eq!(receive.recv().unwrap(), (PW_ERR_IO, Some(String::new())));
    }

    // The header's answers for a NULL handle and for an index past the end.
    #[test]
    fn a_null_handle_and_an_index_past_the_end_answer_as_the_header_says() {
        unsafe {
            let none: *const RouteHandle = ptr::null();
            assert_eq!(pw_route_kind(none), -1);
            assert_eq!(pw_route_len(none), 0);
            assert!(pw_route_pac(none).is_null());
            assert_eq!(pw_route_step_kind(none, 0), -1);
            for text in [
                pw_route_scheme(none, 0),
                pw_route_uri(none, 0),
                pw_route_uri_with_auth(none, 0),
                pw_route_username(none, 0),
                pw_route_password(none, 0),
            ] {
                assert!(text.is_null());
            }
            let nothing: *const Context = ptr::null();
            assert_eq!(pw_context_os_readable(nothing), -1);
            assert!(pw_describe(nothing).is_null());
            assert_eq!(pw_rejected_len(nothing), 0);
            assert!(pw_rejected_text(nothing, 0).is_null());

            let context = context(&["https_proxy=http://u:p@proxy.example:1"]);
            let route = route(context, "https://a.example/");
            for text in [
                pw_route_scheme(route, 1),
                pw_route_uri(route, 1),
                pw_route_uri_with_auth(route, 1),
                pw_route_username(route, 1),
                pw_route_password(route, 1),
            ] {
                assert!(text.is_null());
            }
            assert_eq!(pw_route_step_kind(route, usize::MAX), -1);
            pw_route_free(route);
            pw_context_free(context);
        }
    }

    // As the core reads the process environment: an entry that is not UTF-8 fails nothing.
    // Its name, if that is what is broken, is none of the names read; its value is refused
    // and on the record. A repeated name keeps its first value, as `getenv` and the core's
    // reading of the process environment do.
    #[test]
    fn an_entry_that_is_not_utf8_fails_nothing_and_a_repeated_name_keeps_its_first_value() {
        let entries: [&[u8]; 5] = [
            b"JUNK=\xff\xfe",
            b"\xff=http://never.example:1",
            b"https_proxy=http://first.example:1",
            b"https_proxy=http://second.example:2",
            b"http_proxy=http://\xffbad:1",
        ];
        let entries: Vec<CString> = entries.iter().map(|e| CString::new(*e).unwrap()).collect();
        let mut envp: Vec<*const c_char> = entries.iter().map(|e| e.as_ptr()).collect();
        envp.push(ptr::null());
        let mut context = ptr::null_mut();
        unsafe {
            assert_eq!(
                pw_context_open_with_env(PW_PRECEDENCE_BEFORE_SYSTEM, envp.as_ptr(), &mut context),
                PW_OK,
                "{:?}",
                string(pw_last_error())
            );
            let https = route(context, "https://a.example/");
            assert_eq!(
                string(pw_route_uri(https, 0)).unwrap(),
                "http://first.example:1/"
            );
            pw_route_free(https);
            let rejected: Vec<String> = (0..pw_rejected_len(context))
                .map(|index| string(pw_rejected_text(context, index)).unwrap())
                .collect();
            assert_eq!(rejected.len(), 1, "{rejected:?}");
            assert!(rejected[0].contains("http_proxy"), "{rejected:?}");
            pw_context_free(context);
        }
    }

    #[test]
    fn each_proxy_kind_has_its_own_step_kind_and_scheme() {
        let context = context(&[
            "https_proxy=https://tls.example:443",
            "http_proxy=socks4a://socks.example:1080",
            "all_proxy=socks4://socks.example:1080",
        ]);
        unsafe {
            for (url, kind, scheme) in [
                ("https://a.example/", PW_STEP_HTTPS, "https"),
                ("http://a.example/", PW_STEP_SOCKS4, "socks4a"),
                ("ftp://a.example/", PW_STEP_SOCKS4, "socks4"),
            ] {
                let route = route(context, url);
                assert_eq!(pw_route_step_kind(route, 0), kind, "{url}");
                assert_eq!(string(pw_route_scheme(route, 0)).unwrap(), scheme, "{url}");
                pw_route_free(route);
            }
            pw_context_free(context);
        }
    }

    #[test]
    fn a_direct_step_is_named_direct_and_has_no_scheme() {
        let context = context(&[
            "https_proxy=http://proxy.example:3128",
            "no_proxy=a.example",
        ]);
        unsafe {
            let direct = route(context, "https://a.example/");
            assert_eq!(pw_route_step_kind(direct, 0), PW_STEP_DIRECT);
            assert_eq!(string(pw_route_uri(direct, 0)).unwrap(), "direct");
            assert!(pw_route_scheme(direct, 0).is_null());
            pw_route_free(direct);
            pw_context_free(context);
        }
    }

    #[test]
    fn bad_arguments_are_statuses_with_a_message() {
        let context = context(&[]);
        let mut route = ptr::null_mut();
        unsafe {
            let bad = CString::new("not a url").unwrap();
            assert_eq!(
                pw_resolve(context, bad.as_ptr(), &mut route),
                PW_ERR_INVALID_URL
            );
            assert!(route.is_null());
            assert!(!string(pw_last_error()).unwrap().is_empty());
            assert_eq!(
                pw_resolve(context, ptr::null(), &mut route),
                PW_ERR_NULL_ARGUMENT
            );
            assert_eq!(string(pw_last_error()).unwrap(), "url is NULL");
            // The message outlives a success, so a pointer to it held across one stays valid.
            let held = pw_last_error();
            pw_route_free(self::route(context, "https://a.example/"));
            assert_eq!(pw_last_error(), held);
            assert_eq!(string(held).unwrap(), "url is NULL");
            let invalid = [0xffu8, 0];
            assert_eq!(
                pw_resolve(context, invalid.as_ptr().cast(), &mut route),
                PW_ERR_INVALID_UTF8
            );
            let mut opened = ptr::null_mut();
            assert_eq!(pw_context_open(7, &mut opened), PW_ERR_INVALID_ARGUMENT);
            assert!(opened.is_null());
            let envp = [c"no_equals".as_ptr(), ptr::null()];
            assert_eq!(
                pw_context_open_with_env(PW_PRECEDENCE_IGNORE, envp.as_ptr(), &mut opened),
                PW_ERR_INVALID_ARGUMENT
            );
            let url = c"https://a.example/".as_ptr();
            let refused = |status, message| {
                assert_eq!(status, PW_ERR_NULL_ARGUMENT, "{message}");
                assert_eq!(string(pw_last_error()).unwrap(), message);
            };
            refused(pw_resolve(ptr::null(), url, &mut route), "context is NULL");
            refused(pw_resolve(context, url, ptr::null_mut()), "out is NULL");
            refused(
                pw_context_open(PW_PRECEDENCE_IGNORE, ptr::null_mut()),
                "out is NULL",
            );
            refused(
                pw_context_open_with_env(PW_PRECEDENCE_IGNORE, ptr::null(), &mut opened),
                "envp is NULL",
            );
            refused(
                pw_watch_open(
                    PW_PRECEDENCE_IGNORE,
                    ptr::null(),
                    0,
                    None,
                    ptr::null_mut(),
                    ptr::null_mut(),
                ),
                "out is NULL",
            );
            assert_eq!(
                pw_resolve_with_pac(context, url, 7, &mut route),
                PW_ERR_INVALID_ARGUMENT
            );
            assert!(route.is_null());
            assert!(opened.is_null());
            assert_eq!(pw_context_os_readable(ptr::null()), -1);
            assert_eq!(pw_route_len(ptr::null()), 0);
            pw_context_free(ptr::null_mut());
            pw_route_free(ptr::null_mut());
            pw_context_free(context);
        }
    }

    #[test]
    fn a_watch_layers_the_environment_it_read_at_open_over_each_reading() {
        let envp = [
            c"https_proxy=http://proxy.example:3128".as_ptr(),
            ptr::null(),
        ];
        let mut watch = ptr::null_mut();
        unsafe {
            let status = pw_watch_open(
                PW_PRECEDENCE_BEFORE_SYSTEM,
                envp.as_ptr(),
                50,
                None,
                ptr::null_mut(),
                &mut watch,
            );
            assert_eq!(status, PW_OK, "{:?}", string(pw_last_error()));
            let mut context = ptr::null_mut();
            assert_eq!(pw_watch_current(watch, &mut context), PW_OK);
            let https = route(context, "https://a.example/");
            assert_eq!(
                string(pw_route_uri(https, 0)).unwrap(),
                "http://proxy.example:3128/"
            );
            pw_route_free(https);
            pw_context_free(context);

            assert_eq!(
                pw_watch_current(ptr::null(), &mut context),
                PW_ERR_NULL_ARGUMENT
            );
            assert_eq!(
                pw_watch_current(watch, ptr::null_mut()),
                PW_ERR_NULL_ARGUMENT
            );
            pw_watch_close(watch);
            pw_watch_close(ptr::null_mut());
            let mut unopened = ptr::null_mut();
            let status = pw_watch_open(7, ptr::null(), 0, None, ptr::null_mut(), &mut unopened);
            assert_eq!(status, PW_ERR_INVALID_ARGUMENT);
            assert!(unopened.is_null());
        }
    }

    #[test]
    fn a_dropped_proxy_is_unusable_rather_than_direct_and_is_listed_once_masked() {
        let context = context(&[
            "https_proxy=http://user:hunter2@[bad",
            "http_proxy=http://proxy.example:3128",
        ]);
        unsafe {
            let url = CString::new("https://a.example/").unwrap();
            let mut route = ptr::null_mut();
            assert_eq!(
                pw_resolve(context, url.as_ptr(), &mut route),
                PW_ERR_PROXY_ENTRY_UNUSABLE
            );
            assert!(route.is_null());
            // Held by both `effective` and the winning `Env` source.
            assert_eq!(pw_rejected_len(context), 1);
            let text = string(pw_rejected_text(context, 0)).unwrap();
            assert!(text.contains("https_proxy"), "{text}");
            assert!(!text.contains("hunter2"), "{text}");
            assert!(pw_rejected_text(context, 1).is_null());
            assert!(!string(pw_describe(context)).unwrap().contains("hunter2"));
            pw_context_free(context);
        }
    }

    // The request's `Proxy` header lands in `HTTP_PROXY` under CGI, so the core refuses the
    // variable there rather than route through whoever sent the request.
    #[test]
    fn a_cgi_environment_holding_http_proxy_is_refused() {
        let vars: Vec<CString> = ["REQUEST_METHOD=GET", "http_proxy=http://attacker.example:1"]
            .iter()
            .map(|var| CString::new(*var).unwrap())
            .collect();
        let mut envp: Vec<*const c_char> = vars.iter().map(|var| var.as_ptr()).collect();
        envp.push(ptr::null());
        let mut context = ptr::null_mut();
        let status = unsafe {
            pw_context_open_with_env(PW_PRECEDENCE_BEFORE_SYSTEM, envp.as_ptr(), &mut context)
        };
        assert_eq!(status, PW_ERR_CGI_HTTP_PROXY);
        assert!(context.is_null());
    }

    #[test]
    fn a_malformed_only_environment_does_not_win_but_its_drop_is_listed() {
        let context = context(&["https_proxy=http://user:hunter2@[bad"]);
        unsafe {
            assert_eq!(pw_rejected_len(context), 1);
            let text = string(pw_rejected_text(context, 0)).unwrap();
            assert!(text.contains("https_proxy"), "{text}");
            pw_context_free(context);
        }
    }

    // The environment never yields these, so the context is built from a configuration.
    #[test]
    fn a_pac_or_wpad_configuration_is_its_own_route_kind_with_where_the_script_is() {
        let script = r#"function FindProxyForURL(url, host) { return "DIRECT"; }"#;
        let url = CString::new("https://a.example/").unwrap();
        for (mode, kind, pac) in [
            (
                ProxyMode::pac(Url::parse("http://wpad.example/proxy.pac").unwrap()),
                PW_ROUTE_PAC,
                Some("http://wpad.example/proxy.pac"),
            ),
            (
                ProxyMode::pac_inline(script.to_owned()),
                PW_ROUTE_PAC_INLINE,
                Some(script),
            ),
            (ProxyMode::WpadAutoDetect, PW_ROUTE_WPAD, None),
        ] {
            let context = Context::new(ProxyConfig::new(mode, Vec::new()), true)
                .ok()
                .unwrap();
            let mut route = ptr::null_mut();
            unsafe {
                assert_eq!(pw_resolve(&context, url.as_ptr(), &mut route), PW_OK);
                assert_eq!(pw_route_kind(route), kind);
                assert_eq!(string(pw_route_pac(route)).as_deref(), pac);
                assert_eq!(pw_route_len(route), 0);
                pw_route_free(route);
            }
        }
    }

    // A PAC URL with the body the caller fetched: QuickJS runs it under the options'
    // policy, and the defaults place the script off every network.
    #[test]
    fn quickjs_runs_a_script_under_the_options_policy() {
        if !proxy_watch::pac::QUICKJS_AVAILABLE {
            return;
        }
        let script = CString::new(
            "function FindProxyForURL(u, h) { return isInNet(myIpAddress(), '10.0.0.0', \
             '255.0.0.0') ? 'PROXY corp.example:8080' : 'DIRECT'; }",
        )
        .unwrap();
        let inside = CString::new("10.1.2.3").unwrap();
        let url = CString::new("http://a.example/").unwrap();
        let mode = ProxyMode::pac(Url::parse("http://wpad.example/proxy.pac").unwrap());
        let context = Context::new(ProxyConfig::new(mode, Vec::new()), true)
            .ok()
            .unwrap();
        let mut options = RouteOptions {
            size: size_of::<RouteOptions>(),
            pac: PW_PAC_QUICKJS,
            script: script.as_ptr(),
            ..RouteOptions::default()
        };
        unsafe {
            let resolve = |options: &RouteOptions| {
                let mut route = ptr::null_mut();
                assert_eq!(
                    pw_resolve_ex(&context, url.as_ptr(), options, &mut route),
                    PW_OK
                );
                let answer = (
                    pw_route_engine(route),
                    string(pw_route_uri(route, 0)).unwrap(),
                );
                pw_route_free(route);
                answer
            };
            assert_eq!(resolve(&options), (PW_ENGINE_QUICKJS, "direct".to_owned()));
            options.my_ip_address = inside.as_ptr();
            assert_eq!(
                resolve(&options),
                (PW_ENGINE_QUICKJS, "http://corp.example:8080/".to_owned())
            );
            let mut route = ptr::null_mut();
            options.timeout_ms = 60_001;
            assert_eq!(
                pw_resolve_ex(&context, url.as_ptr(), &options, &mut route),
                PW_ERR_INVALID_ARGUMENT
            );
            options.timeout_ms = 0;
            options.pac = PW_PAC_NONE;
            assert_eq!(
                pw_resolve_ex(&context, url.as_ptr(), &options, &mut route),
                PW_ERR_INVALID_ARGUMENT
            );
            assert!(route.is_null());
        }
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn android_init_is_refused_off_android() {
        unsafe {
            assert_eq!(
                pw_android_init(ptr::null_mut(), ptr::null_mut()),
                PW_ERR_UNSUPPORTED
            );
            assert!(string(pw_last_error()).unwrap().contains("Android"));
        }
    }

    #[test]
    fn each_precedence_number_names_its_layering() {
        for (value, expected) in [
            (
                PW_PRECEDENCE_BEFORE_SYSTEM,
                Some(EnvPrecedence::BeforeSystem),
            ),
            (PW_PRECEDENCE_AFTER_SYSTEM, Some(EnvPrecedence::AfterSystem)),
            (PW_PRECEDENCE_IGNORE, None),
        ] {
            assert_eq!(precedence(value).ok(), Some(expected), "{value}");
        }
    }

    // A C caller branches on the number, so two codes trading numbers is a silent misroute.
    #[test]
    fn each_shared_code_keeps_its_own_status() {
        for (code, status) in [
            (
                "ERR_UNSUPPORTED_PROXY_SCHEME",
                PW_ERR_UNSUPPORTED_PROXY_SCHEME,
            ),
            ("ERR_INVALID_URL", PW_ERR_INVALID_URL),
            ("ERR_INVALID_PROXY_SERVER", PW_ERR_INVALID_PROXY_SERVER),
            ("ERR_INVALID_BYPASS_PATTERN", PW_ERR_INVALID_BYPASS_PATTERN),
            ("ERR_INVALID_PROXY_URL", PW_ERR_INVALID_PROXY_URL),
            ("ERR_CGI_HTTP_PROXY", PW_ERR_CGI_HTTP_PROXY),
            ("ERR_IO", PW_ERR_IO),
            ("ERR_SANDBOXED", PW_ERR_SANDBOXED),
            ("ERR_UNSUPPORTED", PW_ERR_UNSUPPORTED),
            ("ERR_PAC_NOT_SUPPORTED", PW_ERR_PAC_NOT_SUPPORTED),
            ("ERR_PROXY_ENTRY_UNUSABLE", PW_ERR_PROXY_ENTRY_UNUSABLE),
            ("ERR_PAC_FETCH_REQUIRED", PW_ERR_PAC_FETCH_REQUIRED),
            ("ERR_PAC_EVALUATION", PW_ERR_PAC_EVALUATION),
            ("ERR_PAC_TIMEOUT", PW_ERR_PAC_TIMEOUT),
            ("ERR_PAC_SATURATED", PW_ERR_PAC_SATURATED),
            ("ERR_PAC_INVALID_RESULT", PW_ERR_PAC_INVALID_RESULT),
            ("ERR_PAC_ENGINE_UNAVAILABLE", PW_ERR_PAC_ENGINE_UNAVAILABLE),
            ("ERR_INVALID_ARG_VALUE", PW_ERR_INVALID_ARGUMENT),
            ("ERR_PROXY_WATCH", PW_ERR_PROXY_WATCH),
            ("ERR_WATCHER_CLOSED", PW_ERR_PROXY_WATCH),
        ] {
            let Fail(got, message) = Failure::new(code, "message").into();
            assert_eq!((got, message.as_str()), (status, "message"), "{code}");
        }
    }

    // The header is written by hand, so every number it names is checked against this
    // crate's.
    #[test]
    fn the_header_numbers_every_constant_as_the_crate_does() {
        let constants = [
            ("PW_OK", PW_OK),
            ("PW_ERR_PROXY_WATCH", PW_ERR_PROXY_WATCH),
            (
                "PW_ERR_UNSUPPORTED_PROXY_SCHEME",
                PW_ERR_UNSUPPORTED_PROXY_SCHEME,
            ),
            ("PW_ERR_INVALID_URL", PW_ERR_INVALID_URL),
            ("PW_ERR_INVALID_PROXY_SERVER", PW_ERR_INVALID_PROXY_SERVER),
            (
                "PW_ERR_INVALID_BYPASS_PATTERN",
                PW_ERR_INVALID_BYPASS_PATTERN,
            ),
            ("PW_ERR_INVALID_PROXY_URL", PW_ERR_INVALID_PROXY_URL),
            ("PW_ERR_CGI_HTTP_PROXY", PW_ERR_CGI_HTTP_PROXY),
            ("PW_ERR_IO", PW_ERR_IO),
            ("PW_ERR_SANDBOXED", PW_ERR_SANDBOXED),
            ("PW_ERR_UNSUPPORTED", PW_ERR_UNSUPPORTED),
            ("PW_ERR_PAC_NOT_SUPPORTED", PW_ERR_PAC_NOT_SUPPORTED),
            ("PW_ERR_PROXY_ENTRY_UNUSABLE", PW_ERR_PROXY_ENTRY_UNUSABLE),
            ("PW_ERR_PAC_FETCH_REQUIRED", PW_ERR_PAC_FETCH_REQUIRED),
            ("PW_ERR_PAC_EVALUATION", PW_ERR_PAC_EVALUATION),
            ("PW_ERR_PAC_TIMEOUT", PW_ERR_PAC_TIMEOUT),
            ("PW_ERR_PAC_SATURATED", PW_ERR_PAC_SATURATED),
            ("PW_ERR_PAC_INVALID_RESULT", PW_ERR_PAC_INVALID_RESULT),
            (
                "PW_ERR_PAC_ENGINE_UNAVAILABLE",
                PW_ERR_PAC_ENGINE_UNAVAILABLE,
            ),
            ("PW_ERR_NULL_ARGUMENT", PW_ERR_NULL_ARGUMENT),
            ("PW_ERR_INVALID_UTF8", PW_ERR_INVALID_UTF8),
            ("PW_ERR_INVALID_ARGUMENT", PW_ERR_INVALID_ARGUMENT),
            ("PW_ERR_EMBEDDED_NUL", PW_ERR_EMBEDDED_NUL),
            ("PW_ERR_PANIC", PW_ERR_PANIC),
            ("PW_PRECEDENCE_BEFORE_SYSTEM", PW_PRECEDENCE_BEFORE_SYSTEM),
            ("PW_PRECEDENCE_AFTER_SYSTEM", PW_PRECEDENCE_AFTER_SYSTEM),
            ("PW_PRECEDENCE_IGNORE", PW_PRECEDENCE_IGNORE),
            ("PW_ROUTE_STEPS", PW_ROUTE_STEPS),
            ("PW_ROUTE_PAC", PW_ROUTE_PAC),
            ("PW_ROUTE_PAC_INLINE", PW_ROUTE_PAC_INLINE),
            ("PW_ROUTE_WPAD", PW_ROUTE_WPAD),
            ("PW_STEP_DIRECT", PW_STEP_DIRECT),
            ("PW_STEP_HTTP", PW_STEP_HTTP),
            ("PW_STEP_HTTPS", PW_STEP_HTTPS),
            ("PW_STEP_SOCKS4", PW_STEP_SOCKS4),
            ("PW_STEP_SOCKS5", PW_STEP_SOCKS5),
            ("PW_PAC_NONE", PW_PAC_NONE),
            ("PW_PAC_NATIVE", PW_PAC_NATIVE),
            ("PW_PAC_QUICKJS", PW_PAC_QUICKJS),
            ("PW_PAC_AUTO", PW_PAC_AUTO),
            ("PW_ENGINE_NONE", PW_ENGINE_NONE),
            ("PW_ENGINE_NATIVE", PW_ENGINE_NATIVE),
            ("PW_ENGINE_QUICKJS", PW_ENGINE_QUICKJS),
        ];
        let header: HashMap<&str, c_int> = include_str!("../include/proxy_watch.h")
            .lines()
            .filter_map(|line| {
                let (name, value) = line.trim().trim_end_matches(',').split_once(" = ")?;
                Some((name, value.parse().ok()?))
            })
            .collect();
        assert_eq!(header.len(), constants.len(), "{header:?}");
        for (name, value) in constants {
            assert_eq!(header.get(name), Some(&value), "{name}");
        }
    }

    #[test]
    fn ignore_leaves_the_environment_out() {
        let mut context = ptr::null_mut();
        let envp = [
            c"https_proxy=http://proxy.example:3128".as_ptr(),
            ptr::null(),
        ];
        unsafe {
            assert_eq!(
                pw_context_open_with_env(PW_PRECEDENCE_IGNORE, envp.as_ptr(), &mut context),
                PW_OK
            );
            let url = CString::new("https://a.example/").unwrap();
            let mut route = ptr::null_mut();
            assert_eq!(pw_resolve(context, url.as_ptr(), &mut route), PW_OK);
            // The OS side of this machine decides the rest; the variable adds nothing.
            for index in 0..pw_route_len(route) {
                assert_ne!(
                    string(pw_route_uri(route, index)).as_deref(),
                    Some("http://proxy.example:3128/")
                );
            }
            pw_route_free(route);
            pw_context_free(context);
        }
    }
}
