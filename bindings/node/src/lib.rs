//! Node.js bindings: `read()` takes one snapshot of the OS proxy settings layered with the
//! environment, and `Snapshot.route(url)` answers from it without touching the OS again,
//! unless `pac` names an engine for the snapshot's PAC configuration: the OS's, which may
//! download the script, or QuickJS.
//!
//! Node writes `process.env` on the JavaScript thread, so the environment is copied there
//! and nowhere else. `read()` copies it, then runs the OS read on a libuv worker thread
//! from the copy; `readSync()` does both on the JavaScript thread. `Snapshot.routeAsync(url)`
//! also runs on a worker, as it can wait seconds for a script to download or run.
//!
//! `watch()` likewise copies the environment on the JavaScript thread and starts the
//! watcher on a worker; the start and every re-read use the copy, and `watchSync()` starts
//! it on the JavaScript thread. A pump thread drains the watcher's stream into a weak
//! threadsafe function, so an open watch never holds the event loop open.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use napi::bindgen_prelude::{
    AsyncTask, ClassInstance, Either, FnArgs, FromNapiValue, Function, JsObjectValue, JsValue,
    Null, Object, ToNapiValue, Undefined, Unknown, ValidateNapiValue,
};
use napi::bindgen_prelude::{TypeName, ValueType};
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{Env, Task, sys};
use napi_derive::napi;
use proxy_watch::{CapturedEnv, ProxyConfig};
use proxy_watch_shared::{self as shared, Answer, Failure, Layering, Route};

// napi puts the status on the thrown error as its `code`.
fn into_napi(failure: Failure) -> napi::Error<&'static str> {
    napi::Error::new(failure.code, failure.message)
}

/// The variables of an `env` option. napi reads a string, a number or an array as an object
/// holding no variables, and a `Map` or a `Date` the same way (their entries are not
/// enumerable properties), which would answer as though nothing were configured. So
/// anything `Object.prototype.toString` does not tag `[object Object]` is refused instead.
/// The tag rather than the prototype, because `process.env`'s prototype is not
/// `Object.prototype`.
pub struct EnvVars(HashMap<String, String>);

// `Object.prototype.toString.call(value)`, or `None` where any step of reaching it fails.
fn to_string_tag(env: sys::napi_env, value: sys::napi_value) -> Option<String> {
    // SAFETY: `env` and `value` are the handles napi passed in, valid for this call; every
    // other handle is created here and lives in the current scope.
    unsafe {
        let property = |object: sys::napi_value, name: &std::ffi::CStr| {
            let mut out = std::ptr::null_mut();
            (sys::napi_get_named_property(env, object, name.as_ptr(), &mut out)
                == sys::Status::napi_ok)
                .then_some(out)
        };
        let mut global = std::ptr::null_mut();
        if sys::napi_get_global(env, &mut global) != sys::Status::napi_ok {
            return None;
        }
        let to_string = property(
            property(property(global, c"Object")?, c"prototype")?,
            c"toString",
        )?;
        let mut tag = std::ptr::null_mut();
        if sys::napi_call_function(env, value, to_string, 0, std::ptr::null(), &mut tag)
            != sys::Status::napi_ok
        {
            return None;
        }
        String::from_napi_value(env, tag).ok()
    }
}

impl TypeName for EnvVars {
    fn type_name() -> &'static str {
        "Record<string, string>"
    }

    fn value_type() -> ValueType {
        ValueType::Object
    }
}

impl FromNapiValue for EnvVars {
    unsafe fn from_napi_value(env: sys::napi_env, value: sys::napi_value) -> napi::Result<Self> {
        let mut kind = 0;
        let mut array = false;
        // SAFETY: `env` and `value` are the handles napi passed in, valid for this call.
        let checked = unsafe {
            sys::napi_typeof(env, value, &mut kind) == sys::Status::napi_ok
                && sys::napi_is_array(env, value, &mut array) == sys::Status::napi_ok
        };
        if !checked
            || kind != sys::ValueType::napi_object
            || array
            || to_string_tag(env, value).as_deref() != Some("[object Object]")
        {
            return Err(napi::Error::new(
                napi::Status::ObjectExpected,
                "env must be an object of variable names to values",
            ));
        }
        // SAFETY: as above.
        unsafe { HashMap::from_napi_value(env, value) }.map(Self)
    }
}

// `#[napi(object)]` converts both ways; the variables go back out as they came in.
impl ToNapiValue for EnvVars {
    unsafe fn to_napi_value(env: sys::napi_env, value: Self) -> napi::Result<sys::napi_value> {
        // SAFETY: as for `HashMap`'s own conversion.
        unsafe { HashMap::to_napi_value(env, value.0) }
    }
}

fn layering(
    env: Option<EnvVars>,
    precedence: Option<&str>,
) -> napi::Result<Layering, &'static str> {
    shared::precedence(precedence)
        .and_then(|precedence| Layering::new(env.map(|vars| vars.0), precedence))
        .map_err(into_napi)
}

/// Options for `Snapshot.route()` and `Snapshot.routeAsync()`.
#[napi(object)]
pub struct RouteOptions {
    /// `"none"` (the default), `"native"`, `"quickjs"` or `"auto"`.
    pub pac: Option<String>,
    /// A PAC body the caller fetched, run in place of the configuration's.
    pub script: Option<String>,
    /// Let the OS discover a script by WPAD.
    pub wpad: Option<bool>,
    /// What QuickJS runs a script under.
    pub policy: Option<PacPolicy>,
}

/// The policy QuickJS runs a script under; each field left out keeps its default.
#[napi(object)]
pub struct PacPolicy {
    pub my_ip_address: Option<String>,
    pub resolve_dns: Option<bool>,
    pub allow_internal_addresses: Option<bool>,
    pub utc_offset_seconds: Option<i32>,
    pub timeout_ms: Option<u32>,
}

fn route_options(options: Option<RouteOptions>) -> Result<shared::RouteOptions, Failure> {
    let Some(options) = options else {
        return Ok(shared::RouteOptions::none());
    };
    let policy = options.policy.map(|policy| shared::PolicyOptions {
        my_ip_address: policy.my_ip_address,
        resolve_dns: policy.resolve_dns,
        allow_internal_addresses: policy.allow_internal_addresses,
        utc_offset_seconds: policy.utc_offset_seconds,
        timeout_ms: policy.timeout_ms.map(u64::from),
    });
    shared::RouteOptions::new(
        shared::pac(options.pac.as_deref())?,
        options.script,
        options.wpad.unwrap_or(false),
        shared::policy(&policy.unwrap_or_default())?,
    )
}

/// Options for `read()`.
#[napi(object)]
pub struct ReadOptions {
    /// The variables to read `*_proxy` from; `process.env` when absent.
    pub env: Option<EnvVars>,
    /// `"before-system"` (the default), `"after-system"` or `"ignore"`.
    pub precedence: Option<String>,
}

/// A route as JavaScript sees it: `kind`, the one field that kind carries, and the engine
/// that answered it.
#[napi(object)]
pub struct JsRoute {
    pub kind: String,
    /// `"direct"` or a proxy URL, credentials included.
    pub steps: Option<Vec<String>>,
    pub pac_url: Option<String>,
    pub script: Option<String>,
    /// `"none"`, `"native"` or `"quickjs"`.
    pub engine: String,
}

impl TryFrom<Answer> for JsRoute {
    type Error = Failure;

    fn try_from(Answer { route, engine }: Answer) -> Result<Self, Failure> {
        let (kind, steps, pac_url, script) = match route {
            Route::Steps(steps) => (
                "steps",
                Some(
                    steps
                        .iter()
                        .map(shared::step_url)
                        .collect::<Result<_, _>>()?,
                ),
                None,
                None,
            ),
            Route::Pac(url) => ("pac", None, Some(url), None),
            Route::PacInline(script) => ("pac-inline", None, None, Some(script)),
            Route::Wpad => ("wpad", None, None, None),
        };
        Ok(Self {
            kind: kind.to_owned(),
            steps,
            pac_url,
            script,
            engine: engine.name().to_owned(),
        })
    }
}

/// Where a snapshot's answer came from, without the proxy addresses or credentials.
#[napi(object)]
pub struct Diagnostics {
    /// Whether the OS had proxy settings to read.
    pub os_readable: bool,
    /// The sources that produced a configuration, highest precedence first.
    pub sources: Vec<String>,
    /// Sources that could not be read and were left out.
    pub fallbacks: Vec<String>,
    /// Values the sources held but the snapshot dropped (settings that silently stopped
    /// applying), each as `"<kind> from <source>: <value>"`, credentials masked.
    pub rejected: Vec<String>,
}

/// One reading of the proxy configuration.
#[napi]
pub struct Snapshot {
    config: ProxyConfig,
    os_readable: bool,
}

#[napi]
impl Snapshot {
    /// The route for `url`.
    #[napi]
    pub fn route(
        &self,
        url: String,
        options: Option<RouteOptions>,
    ) -> napi::Result<JsRoute, &'static str> {
        route_options(options)
            .and_then(|options| shared::route(&self.config, &url, &options))
            .and_then(JsRoute::try_from)
            .map_err(into_napi)
    }

    /// `route()` on a libuv worker thread, which may wait while a script downloads or runs.
    /// Bad options throw here; the promise rejects with the rest of `route()`'s codes.
    #[napi]
    pub fn route_async(
        &self,
        url: String,
        options: Option<RouteOptions>,
    ) -> napi::Result<AsyncTask<RouteTask>, &'static str> {
        let options = route_options(options).map_err(into_napi)?;
        Ok(AsyncTask::new(RouteTask {
            config: self.config.clone(),
            url,
            options,
        }))
    }

    /// `routeAsync(url, { pac: "native" })`.
    #[napi]
    pub fn route_native(&self, url: String) -> AsyncTask<RouteTask> {
        AsyncTask::new(RouteTask {
            config: self.config.clone(),
            url,
            options: shared::RouteOptions::native(),
        })
    }

    /// The configuration on one line, passwords masked.
    #[napi(js_name = "toString")]
    pub fn describe(&self) -> String {
        format!(
            "Snapshot {{ osReadable: {}, config: {:?} }}",
            self.os_readable, self.config
        )
    }

    /// The whole configuration as plain objects and arrays, which `JSON.stringify` also
    /// takes. A proxy's password is in it as the value.
    #[napi(js_name = "toJSON")]
    pub fn to_json(&self) -> Json {
        Json(shared::describe(&self.config, self.os_readable))
    }

    /// Which sources the snapshot came from.
    #[napi]
    pub fn diagnostics(&self) -> Diagnostics {
        Diagnostics {
            os_readable: self.os_readable,
            sources: self
                .config
                .sources
                .iter()
                .map(|(source, _)| format!("{source:?}"))
                .collect(),
            fallbacks: self
                .config
                .fallbacks
                .iter()
                .map(|source| format!("{source:?}"))
                .collect(),
            rejected: shared::rejected(&self.config),
        }
    }
}

// A route off the JavaScript thread. The native engines read no environment. QuickJS's
// `Date` can read `TZ` through the C library's local time, which a `process.env` write on the
// JavaScript thread can race on a C library older than glibc 2.41.
pub struct RouteTask {
    config: ProxyConfig,
    url: String,
    options: shared::RouteOptions,
}

impl Task for RouteTask {
    type Output = Result<Answer, Failure>;
    type JsValue = JsRoute;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(shared::route(&self.config, &self.url, &self.options))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<JsRoute> {
        output
            .and_then(JsRoute::try_from)
            .map_err(|failure| reject(env, failure))
    }
}

// A task's failure as a JavaScript error, made on the JavaScript thread in `resolve`: an
// error returned from `compute` carries only a napi status, and its `code` would lose the
// failure's own.
fn reject(env: Env, failure: Failure) -> napi::Error {
    // SAFETY: `env` is the live environment of the thread this runs on.
    let error = unsafe {
        ToNapiValue::to_napi_value(env.raw(), into_napi(failure))
            .and_then(|raw| Unknown::from_napi_value(env.raw(), raw))
    };
    match error {
        Ok(error) => napi::Error::from(error),
        Err(error) => error,
    }
}

// The OS read on a libuv worker thread, with the environment copied on the JavaScript
// thread, where Node writes `process.env`.
pub struct Read {
    layering: Layering,
    env: CapturedEnv,
}

impl Task for Read {
    type Output = Result<Snapshot, Failure>;
    type JsValue = Snapshot;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(
            shared::read_os(&self.env).map(|(config, os_readable)| Snapshot {
                config: self.layering.apply(config),
                os_readable,
            }),
        )
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<Snapshot> {
        output.map_err(|failure| reject(env, failure))
    }
}

fn read_options(options: Option<ReadOptions>) -> napi::Result<Layering, &'static str> {
    let options = options.unwrap_or(ReadOptions {
        env: None,
        precedence: None,
    });
    layering(options.env, options.precedence.as_deref())
}

/// Read the OS settings and the environment once, on a libuv worker thread.
#[napi(ts_return_type = "Promise<Snapshot>")]
pub fn read(options: Option<ReadOptions>) -> napi::Result<AsyncTask<Read>, &'static str> {
    Ok(AsyncTask::new(Read {
        layering: read_options(options)?,
        env: CapturedEnv::capture(),
    }))
}

/// `read()` on the JavaScript thread.
#[napi]
pub fn read_sync(options: Option<ReadOptions>) -> napi::Result<Snapshot, &'static str> {
    let layering = read_options(options)?;
    let (config, os_readable) = shared::read_os(&CapturedEnv::capture()).map_err(into_napi)?;
    Ok(Snapshot {
        config: layering.apply(config),
        os_readable,
    })
}

/// Options for `watch()`.
#[napi(object)]
pub struct WatchOptions {
    /// As for `read()`, captured once when the watch starts.
    pub env: Option<EnvVars>,
    /// As for `read()`.
    pub precedence: Option<String>,
    /// Also re-read on this interval. Required where the OS gives no change notification
    /// (a Flatpak or Snap sandbox, iOS, Android below API 26 or where in-memory code loading
    /// is refused, or a Linux session without a D-Bus session bus). Anything under 200, zero
    /// included, is raised to 200; leaving it out turns the timer off. A negative or
    /// non-finite value throws `ERR_INVALID_ARG_VALUE`.
    pub poll_interval_ms: Option<f64>,
}

// The napi error status `onChange` receives: napi puts it on the error as its `code`.
pub struct Code(String);

impl AsRef<str> for Code {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<napi::Status> for Code {
    fn from(status: napi::Status) -> Self {
        Self(status.to_string())
    }
}

type OnChange = ThreadsafeFunction<Snapshot, Undefined, Snapshot, Code, true, true>;

// The caller's `onChange`: `(err)` for a failure, `(null, snapshot)` for a change.
type UserArgs = FnArgs<(Unknown<'static>, Either<Unknown<'static>, Undefined>)>;
type UserOnChange<'f> = Function<'f, UserArgs, Unknown<'static>>;

// The threadsafe function's target is not `on_change` itself but a function that calls it
// while `open` holds. A call the pump queued before `close()` runs on the JavaScript thread
// after it, and `close()` runs there too, so the flag it clears stops that call from
// reaching the caller.
fn gated(
    env: &Env,
    on_change: &UserOnChange<'_>,
    open: Arc<AtomicBool>,
) -> napi::Result<OnChange, &'static str> {
    // Checked here: napi converts a `Function` argument without looking at it.
    // SAFETY: both handles belong to this call's environment.
    unsafe { <UserOnChange<'_> as ValidateNapiValue>::validate(env.raw(), on_change.raw()) }
        .map_err(|error| napi::Error::new("ERR_INVALID_ARG_TYPE", error.reason))?;
    gate(env, on_change, open).map_err(|error| napi::Error::new("ERR_PROXY_WATCH", error.reason))
}

fn gate(env: &Env, on_change: &UserOnChange<'_>, open: Arc<AtomicBool>) -> napi::Result<OnChange> {
    let on_change = on_change.create_ref()?;
    let gate =
        env.create_function_from_closure::<Snapshot, Undefined, _>("onChange", move |ctx| {
            if !open.load(Ordering::SeqCst) {
                return Ok(());
            }
            let first = ctx.get::<Unknown<'static>>(0)?;
            let second = if ctx.length() > 1 {
                Either::A(ctx.get::<Unknown<'static>>(1)?)
            } else {
                Either::B(())
            };
            on_change
                .borrow_back(ctx.env)?
                .call(FnArgs::from((first, second)))
                .map(drop)
        })?;
    gate.build_threadsafe_function::<Snapshot>()
        .error_status::<Code>()
        .callee_handled::<true>()
        .weak::<true>()
        .build()
}

/// [`shared::describe`]'s tree as JavaScript values.
pub struct Json(shared::Value);

impl ToNapiValue for Json {
    unsafe fn to_napi_value(
        env: sys::napi_env,
        Json(value): Self,
    ) -> napi::Result<sys::napi_value> {
        // SAFETY: `env` is the live environment napi hands every conversion.
        unsafe {
            match value {
                shared::Value::Null => Null::to_napi_value(env, Null),
                shared::Value::Bool(flag) => bool::to_napi_value(env, flag),
                shared::Value::Int(number) => i64::to_napi_value(env, number),
                shared::Value::Str(text) => String::to_napi_value(env, text),
                shared::Value::List(items) => {
                    Vec::to_napi_value(env, items.into_iter().map(Json).collect())
                }
                shared::Value::Map(entries) => {
                    let mut object = Object::new(&Env::from(env))?;
                    for (key, value) in entries {
                        object.set(camel_case(&key), Json(value))?;
                    }
                    Object::to_napi_value(env, object)
                }
            }
        }
    }
}

// `os_readable` as `osReadable`, the spelling the rest of this API uses. A scheme key
// (`http`, `all`) has no underscore and stays as it is.
fn camel_case(key: &str) -> String {
    let mut parts = key.split('_');
    let mut out = parts.next().unwrap_or_default().to_owned();
    for part in parts {
        let mut chars = part.chars();
        out.extend(chars.next().map(|first| first.to_ascii_uppercase()));
        out.push_str(chars.as_str());
    }
    out
}

/// A running watch. It keeps running while unreferenced, without keeping the process
/// alive, until `close()` or until its thread's environment shuts down.
#[napi]
pub struct Watcher {
    watch: shared::Watch,
    layering: Arc<Layering>,
    // Cleared by `close()`, on the JavaScript thread; see [`gated`].
    open: Arc<AtomicBool>,
}

#[napi]
impl Watcher {
    /// The latest configuration, layered with the environment captured at the start.
    #[napi]
    pub fn current(&self) -> napi::Result<Snapshot, &'static str> {
        let config = self.watch.current().map_err(into_napi)?;
        Ok(Snapshot {
            config: self.layering.apply(config),
            os_readable: self.watch.os_readable(),
        })
    }

    /// Stop watching. Safe to call more than once. Once it returns, `onChange` is not
    /// called again.
    #[napi]
    pub fn close(&self) {
        self.open.store(false, Ordering::SeqCst);
        self.watch.close();
    }

    /// `Watcher { open: <bool> }`.
    #[napi(js_name = "toString")]
    pub fn describe(&self) -> String {
        let open = self.open.load(Ordering::SeqCst) && !self.watch.is_closed();
        format!("Watcher {{ open: {open} }}")
    }
}

/// Gives `Snapshot` and `Watcher` a `util.inspect` form, their `toString()`: inspect shows
/// a class instance's own properties, and these hold none.
#[napi(module_exports)]
pub fn install_inspect(exports: Object, env: Env) -> napi::Result<()> {
    // `Symbol.for` from JavaScript: `Env::symbol_for` needs N-API 9, past Node 18.0.
    let custom = env
        .get_global()?
        .get_named_property::<Function<(), Unknown>>("Symbol")?
        .get_named_property::<Function<&str, Unknown>>("for")?
        .call("nodejs.util.inspect.custom")?;
    let snapshot = env.create_function_from_closure::<(), String, _>("inspect", |ctx| {
        // `this` is the prototype itself when the prototype is inspected.
        Ok(ctx
            .this::<ClassInstance<Snapshot>>()
            .map_or_else(|_| "Snapshot {}".to_owned(), |this| this.describe()))
    })?;
    let watcher = env.create_function_from_closure::<(), String, _>("inspect", |ctx| {
        Ok(ctx
            .this::<ClassInstance<Watcher>>()
            .map_or_else(|_| "Watcher {}".to_owned(), |this| this.describe()))
    })?;
    for (class, inspect) in [("Snapshot", snapshot), ("Watcher", watcher)] {
        exports
            .get_named_property::<Function<(), Unknown>>(class)?
            .get_named_property::<Object>("prototype")?
            .set_property(custom, inspect)?;
    }
    Ok(())
}

fn watch_options(
    options: Option<WatchOptions>,
) -> napi::Result<(Arc<Layering>, Option<Duration>), &'static str> {
    let options = options.unwrap_or(WatchOptions {
        env: None,
        precedence: None,
        poll_interval_ms: None,
    });
    let layering = Arc::new(layering(options.env, options.precedence.as_deref())?);
    // A number, not a `u32`: napi wraps `-1` into 49 days rather than refusing it.
    let poll_interval = options
        .poll_interval_ms
        .map(|ms| {
            (ms >= 0.0)
                .then(|| Duration::try_from_secs_f64(ms / 1000.0).ok())
                .flatten()
                .ok_or_else(|| {
                    napi::Error::new("ERR_INVALID_ARG_VALUE", format!("pollIntervalMs: {ms:?}"))
                })
        })
        .transpose()?;
    Ok((layering, poll_interval))
}

fn start(
    on_change: OnChange,
    layering: &Arc<Layering>,
    poll_interval: Option<Duration>,
    env: &CapturedEnv,
) -> Result<shared::Watch, Failure> {
    let delivered = Arc::clone(layering);
    shared::Watch::start(poll_interval, env, "proxy-watch-node", move |value| {
        let value = value
            .map(|config| Snapshot {
                config: delivered.apply(config),
                // A change arrives only where the OS had settings to watch.
                os_readable: true,
            })
            .map_err(|failure| napi::Error::new(Code(failure.code.to_owned()), failure.message));
        on_change.call(value, ThreadsafeFunctionCallMode::NonBlocking) != napi::Status::Closing
    })
}

// Runs on the JavaScript thread: the cleanup hook stops the watch when that thread's
// environment shuts down.
fn watcher(
    env: &Env,
    watch: shared::Watch,
    layering: Arc<Layering>,
    open: Arc<AtomicBool>,
) -> Result<Watcher, Failure> {
    if let Err(error) = env.add_env_cleanup_hook(watch.clone(), |watch| watch.close()) {
        watch.close_in_background();
        return Err(Failure::new("ERR_PROXY_WATCH", error.reason));
    }
    Ok(Watcher {
        watch,
        layering,
        open,
    })
}

// A started watch no `Watcher` owns yet. A worker that exits with `watch()` pending drops
// it without resolving, and dropping it stops the watch.
pub struct Started(Option<shared::Watch>);

impl Drop for Started {
    fn drop(&mut self) {
        if let Some(watch) = self.0.take() {
            watch.close_in_background();
        }
    }
}

// The watcher's start on a libuv worker thread, with the environment copied on the
// JavaScript thread.
pub struct StartWatch {
    on_change: Option<OnChange>,
    open: Arc<AtomicBool>,
    layering: Arc<Layering>,
    poll_interval: Option<Duration>,
    env: CapturedEnv,
}

impl Task for StartWatch {
    type Output = Result<Started, Failure>;
    type JsValue = Watcher;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let Some(on_change) = self.on_change.take() else {
            return Ok(Err(Failure::new(
                "ERR_PROXY_WATCH",
                "the watch already started",
            )));
        };
        Ok(
            start(on_change, &self.layering, self.poll_interval, &self.env)
                .map(|watch| Started(Some(watch))),
        )
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<Watcher> {
        output
            .and_then(|mut started| {
                let watch = started.0.take().expect("a started watch resolves once");
                watcher(
                    &env,
                    watch,
                    Arc::clone(&self.layering),
                    Arc::clone(&self.open),
                )
            })
            .map_err(|failure| reject(env, failure))
    }
}

/// Watch the OS settings, calling `onChange(err, snapshot)` after each change. The watcher
/// starts on a libuv worker thread; an invalid option throws before it does.
#[napi(
    ts_args_type = "onChange: (err: Error | null, snapshot?: Snapshot) => void, options?: WatchOptions",
    ts_return_type = "Promise<Watcher>"
)]
pub fn watch(
    env: Env,
    on_change: UserOnChange<'_>,
    options: Option<WatchOptions>,
) -> napi::Result<AsyncTask<StartWatch>, &'static str> {
    let (layering, poll_interval) = watch_options(options)?;
    let open = Arc::new(AtomicBool::new(true));
    let on_change = gated(&env, &on_change, Arc::clone(&open))?;
    Ok(AsyncTask::new(StartWatch {
        on_change: Some(on_change),
        open,
        layering,
        poll_interval,
        env: CapturedEnv::capture(),
    }))
}

/// `watch()` on the JavaScript thread, which it blocks while the watcher starts.
#[napi(
    ts_args_type = "onChange: (err: Error | null, snapshot?: Snapshot) => void, options?: WatchOptions"
)]
pub fn watch_sync(
    env: Env,
    on_change: UserOnChange<'_>,
    options: Option<WatchOptions>,
) -> napi::Result<Watcher, &'static str> {
    let (layering, poll_interval) = watch_options(options)?;
    let open = Arc::new(AtomicBool::new(true));
    let on_change = gated(&env, &on_change, Arc::clone(&open))?;
    start(on_change, &layering, poll_interval, &CapturedEnv::capture())
        .and_then(|watch| watcher(&env, watch, layering, open))
        .map_err(into_napi)
}
