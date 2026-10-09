//! Python bindings: `read()` takes one snapshot of the OS proxy settings layered with the
//! environment, and `Snapshot.route(url)` answers from it without touching the OS again,
//! unless `pac` names an engine for the snapshot's PAC configuration: the OS's, which may
//! download the script, or QuickJS.
//!
//! The environment is read only with the GIL held, so no other Python thread's
//! `os.environ` write (which calls `putenv`) lands while it is. `read()` and `watch()` copy
//! it, then release the GIL for the OS read or the watcher's start; the read, the start and
//! every re-read of the watcher use the copy.
//!
//! `on_change` runs on the pump thread, with the GIL. `close()` releases the GIL while it
//! waits for that thread, so a callback waiting for the GIL cannot deadlock it; a watcher
//! the garbage collector frees stops without waiting.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use proxy_watch::{CapturedEnv, ProxyConfig};
use proxy_watch_shared::{self as shared, Answer, Failure, Layering, Route as SharedRoute};
use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};
use pyo3::{IntoPyObjectExt, PyTypeInfo};
use pyo3::{PyTraverseError, PyVisit};

pyo3::create_exception!(
    proxy_watch,
    ProxyWatchError,
    PyException,
    "A failure; `code` names it, as `ERR_INVALID_URL` or `ERR_WATCHER_CLOSED`."
);

// Set by an `atexit` hook: a pump thread must not take the GIL while the interpreter
// finalizes.
static FINALIZING: AtomicBool = AtomicBool::new(false);

fn error(py: Python<'_>, failure: Failure) -> PyErr {
    let error = ProxyWatchError::new_err(failure.message);
    if let Err(set) = error.value(py).setattr("code", failure.code) {
        return set;
    }
    error
}

fn layering(
    py: Python<'_>,
    env: Option<Bound<'_, PyAny>>,
    precedence: Option<&str>,
) -> PyResult<Layering> {
    // Copied through `dict()`: `env` is any mapping, and `os.environ` is not a `dict`.
    //
    // The core's rule for the process environment, so that one unrelated variable cannot
    // fail the call: `os.environ` holds bytes that are not UTF-8 as surrogates. A name
    // holding one is none of the names read, so it is dropped; a value holding one is kept
    // with replacement characters, so a proxy variable holding one is refused and recorded
    // as rejected.
    let env = env
        .map(|env| -> PyResult<HashMap<String, String>> {
            let env = PyDict::type_object(py)
                .call1((env,))?
                .cast_into::<PyDict>()?;
            let mut vars = HashMap::with_capacity(env.len());
            for (name, value) in env.iter() {
                let name = name.cast_into::<PyString>()?;
                let value = value.cast_into::<PyString>()?;
                if let Ok(name) = name.extract::<String>() {
                    vars.insert(name, value.to_string_lossy().into_owned());
                }
            }
            Ok(vars)
        })
        .transpose()?;
    shared::precedence(precedence)
        .and_then(|precedence| Layering::new(env, precedence))
        .map_err(|failure| error(py, failure))
}

/// Where a request to one URL goes: `kind`, the one field that kind carries, and the engine
/// that answered it.
///
/// `kind` is `"steps"`, `"pac"`, `"pac-inline"` or `"wpad"`. `steps` holds `"direct"` or
/// proxy URLs with their credentials, so do not log it. `engine` is `"none"`, `"native"`
/// or `"quickjs"`.
#[pyclass(module = "proxy_watch", frozen, get_all, eq, hash)]
#[derive(PartialEq, Eq, Hash)]
pub struct Route {
    kind: &'static str,
    steps: Option<Vec<String>>,
    pac_url: Option<String>,
    script: Option<String>,
    engine: &'static str,
}

impl TryFrom<Answer> for Route {
    type Error = Failure;

    fn try_from(Answer { route, engine }: Answer) -> Result<Self, Failure> {
        let (kind, steps, pac_url, script) = match route {
            SharedRoute::Steps(steps) => (
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
            SharedRoute::Pac(url) => ("pac", None, Some(url), None),
            SharedRoute::PacInline(script) => ("pac-inline", None, None, Some(script)),
            SharedRoute::Wpad => ("wpad", None, None, None),
        };
        Ok(Self {
            kind,
            steps,
            pac_url,
            script,
            engine: engine.name(),
        })
    }
}

#[pymethods]
impl Route {
    /// The kind, the one field it carries, and the engine. A step's password shows as
    /// `***`, since a repr reaches tracebacks and logs unasked; `steps` itself keeps it.
    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let carried = match (&self.steps, &self.pac_url, &self.script) {
            (Some(steps), _, _) => {
                let masked: Vec<String> = steps.iter().map(|step| masked_url(step)).collect();
                format!(", steps={}", repr(py, masked)?)
            }
            (_, Some(pac_url), _) => format!(", pac_url={}", repr(py, pac_url)?),
            (_, _, Some(script)) => format!(", script=<{} chars>", script.chars().count()),
            _ => String::new(),
        };
        Ok(format!(
            "Route(kind={}{carried}, engine={})",
            repr(py, self.kind)?,
            repr(py, self.engine)?
        ))
    }
}

fn repr<'py>(py: Python<'py>, value: impl IntoPyObject<'py>) -> PyResult<String> {
    Ok(value.into_bound_py_any(py)?.repr()?.to_string())
}

fn to_python(py: Python<'_>, value: shared::Value) -> PyResult<Bound<'_, PyAny>> {
    match value {
        shared::Value::Null => Ok(py.None().into_bound(py)),
        shared::Value::Bool(flag) => flag.into_bound_py_any(py),
        shared::Value::Int(number) => number.into_bound_py_any(py),
        shared::Value::Str(text) => text.into_bound_py_any(py),
        shared::Value::List(items) => items
            .into_iter()
            .map(|item| to_python(py, item))
            .collect::<PyResult<Vec<_>>>()?
            .into_bound_py_any(py),
        shared::Value::Map(entries) => {
            let dict = PyDict::new(py);
            for (key, value) in entries {
                dict.set_item(key, to_python(py, value)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

fn masked_url(step: &str) -> String {
    match proxy_watch::Url::parse(step) {
        Ok(mut url) if url.password().is_some() => {
            // Refused only for a URL that cannot hold credentials, which this one does.
            let _ = url.set_password(Some("***"));
            url.into()
        }
        _ => step.to_owned(),
    }
}

/// What QuickJS runs a script under; each argument left out keeps its default.
#[pyclass(module = "proxy_watch", frozen, eq)]
#[derive(PartialEq)]
pub struct PacPolicy(proxy_watch::pac::PacPolicy);

#[pymethods]
impl PacPolicy {
    fn __repr__(&self) -> String {
        format!("<{:?}>", self.0)
    }

    #[new]
    #[pyo3(signature = (
        *,
        my_ip_address = None,
        resolve_dns = None,
        allow_internal_addresses = None,
        utc_offset_seconds = None,
        timeout = None,
    ))]
    fn new(
        py: Python<'_>,
        my_ip_address: Option<String>,
        resolve_dns: Option<bool>,
        allow_internal_addresses: Option<bool>,
        utc_offset_seconds: Option<i32>,
        timeout: Option<f64>,
    ) -> PyResult<Self> {
        let timeout_ms = match timeout {
            None => None,
            // Rounded up, so a positive budget never becomes none.
            Some(seconds) if seconds.is_finite() && seconds > 0.0 => {
                Some((seconds * 1000.0).ceil().min(u64::MAX as f64) as u64)
            }
            Some(seconds) => {
                return Err(error(
                    py,
                    Failure::new(
                        "ERR_INVALID_ARG_VALUE",
                        format!("timeout {seconds} is not a positive number of seconds"),
                    ),
                ));
            }
        };
        shared::policy(&shared::PolicyOptions {
            my_ip_address,
            resolve_dns,
            allow_internal_addresses,
            utc_offset_seconds,
            timeout_ms,
        })
        .map(Self)
        .map_err(|failure| error(py, failure))
    }
}

/// Where a snapshot's answer came from, without the proxy addresses or credentials.
#[pyclass(module = "proxy_watch", frozen, get_all, eq, hash)]
#[derive(PartialEq, Eq, Hash)]
pub struct Diagnostics {
    /// Whether the OS had proxy settings to read.
    os_readable: bool,
    /// The sources that produced a configuration, highest precedence first.
    sources: Vec<String>,
    /// Sources that could not be read and were left out.
    fallbacks: Vec<String>,
    /// Values the sources held but the snapshot dropped (settings that silently stopped
    /// applying), each as `"<kind> from <source>: <value>"`, credentials masked.
    rejected: Vec<String>,
}

#[pymethods]
impl Diagnostics {
    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!(
            "Diagnostics(os_readable={}, sources={}, fallbacks={}, rejected={})",
            repr(py, self.os_readable)?,
            repr(py, &self.sources)?,
            repr(py, &self.fallbacks)?,
            repr(py, &self.rejected)?
        ))
    }
}

/// One reading of the proxy configuration.
#[pyclass(module = "proxy_watch", frozen)]
pub struct Snapshot {
    config: ProxyConfig,
    os_readable: bool,
}

#[pymethods]
impl Snapshot {
    /// The configuration on one line, passwords masked.
    fn __repr__(&self) -> String {
        format!(
            "<Snapshot os_readable={} {:?}>",
            if self.os_readable { "True" } else { "False" },
            self.config
        )
    }

    /// The route for `url`. `pac` names who runs a PAC configuration: `"none"` (the
    /// default), `"native"`, `"quickjs"` or `"auto"`, with `script`, `wpad` and `policy` as
    /// the stub file describes. The GIL is released while an engine downloads or runs a
    /// script. A URL with no host (`mailto:`, `file:`, `data:`) is `["direct"]` under every
    /// choice.
    #[pyo3(signature = (url, *, pac = None, script = None, wpad = false, policy = None))]
    fn route(
        &self,
        py: Python<'_>,
        url: &str,
        pac: Option<&str>,
        script: Option<String>,
        wpad: bool,
        policy: Option<PyRef<'_, PacPolicy>>,
    ) -> PyResult<Route> {
        let policy = policy.map_or_else(proxy_watch::pac::PacPolicy::new, |policy| policy.0);
        shared::pac(pac)
            .and_then(|pac| shared::RouteOptions::new(pac, script, wpad, policy))
            .and_then(|options| py.detach(|| shared::route(&self.config, url, &options)))
            .and_then(Route::try_from)
            .map_err(|failure| error(py, failure))
    }

    /// The whole configuration as plain dicts and lists, the stub file describes the
    /// shape. A proxy's password is in it as the value.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_python(py, shared::describe(&self.config, self.os_readable))
    }

    /// Which sources the snapshot came from.
    fn diagnostics(&self) -> Diagnostics {
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

/// Read the OS settings and the environment once.
///
/// `env` is the mapping to read `*_proxy` from, `os.environ` when omitted. `precedence`
/// is `"before-system"` (the default), `"after-system"` or `"ignore"`.
#[pyfunction]
#[pyo3(signature = (*, env = None, precedence = None))]
fn read(
    py: Python<'_>,
    env: Option<Bound<'_, PyAny>>,
    precedence: Option<&str>,
) -> PyResult<Snapshot> {
    let layering = layering(py, env, precedence)?;
    let captured = CapturedEnv::capture();
    // Detached: the OS read can take seconds (macOS, a Linux sandbox), and other Python
    // threads (an asyncio loop behind `asyncio.to_thread`, for one) run meanwhile.
    let (config, os_readable) = py
        .detach(|| shared::read_os(&captured))
        .map_err(|failure| error(py, failure))?;
    Ok(Snapshot {
        config: layering.apply(config),
        os_readable,
    })
}

// `on_change`, held here and nowhere else: the pump borrows it for each call. A reference
// the pump held of its own would be invisible to the garbage collector, so a watcher whose
// `on_change` reaches back to it (`self.watcher = watch(self.on_change)`) would never be
// collected and its thread would never stop.
type OnChange = Arc<Mutex<Option<Py<PyAny>>>>;

/// A running watch. Use it as a context manager, or call `close()`.
#[pyclass(module = "proxy_watch", frozen)]
pub struct Watcher {
    watch: shared::Watch,
    layering: Arc<Layering>,
    on_change: OnChange,
    // A child of `fork` has none of the parent's threads to stop or wait for.
    pid: u32,
}

impl Watcher {
    fn forked(&self) -> bool {
        self.pid != std::process::id()
    }
}

#[pymethods]
impl Watcher {
    /// The latest configuration, layered with the environment captured at the start. In a
    /// child of `fork` it raises with `code` `ERR_FORKED`.
    fn current(&self, py: Python<'_>) -> PyResult<Snapshot> {
        if self.forked() {
            return Err(error(
                py,
                Failure::new("ERR_FORKED", "the watcher belongs to the parent process"),
            ));
        }
        let config = self.watch.current().map_err(|failure| error(py, failure))?;
        Ok(Snapshot {
            config: self.layering.apply(config),
            os_readable: self.watch.os_readable(),
        })
    }

    /// Stop watching and wait for the watch thread. Safe to call more than once, and from
    /// `on_change`.
    fn close(&self, py: Python<'_>) {
        if !self.forked() {
            py.detach(|| self.watch.close());
        }
        self.on_change
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    fn __repr__(&self) -> String {
        let state = if self.forked() {
            "forked"
        } else if self.watch.is_closed() {
            "closed"
        } else {
            "open"
        };
        format!("<Watcher {state}>")
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        // The pump takes the lock only while it holds the GIL, which the collector holds
        // now, so this does not wait; a lock that cannot be taken is skipped, not waited on.
        if let Ok(on_change) = self.on_change.try_lock()
            && let Some(on_change) = on_change.as_ref()
        {
            visit.call(on_change)?;
        }
        Ok(())
    }

    fn __clear__(&self) {
        if let Ok(mut on_change) = self.on_change.try_lock() {
            on_change.take();
        }
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (*_exc))]
    fn __exit__(&self, py: Python<'_>, _exc: &Bound<'_, pyo3::types::PyTuple>) {
        self.close(py);
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        if !self.forked() {
            self.watch.close_in_background();
        }
    }
}

/// Watch the OS settings, calling `on_change(err, snapshot)` after each change on a thread
/// of the watcher's own. A watch that stops on its own calls it a last time with
/// `ERR_PROXY_WATCH`.
///
/// `env` and `precedence` are as for `read()`, captured once. `poll_interval` (seconds)
/// also re-reads on that interval; it is required where the OS gives no change notification
/// (a Flatpak or Snap sandbox, iOS, Android below API 26 or where in-memory code loading is
/// refused, or a Linux session without a D-Bus session bus). Anything under 0.2, zero
/// included, is raised to 0.2; `None` turns the timer off. A negative, infinite or NaN
/// value raises `ValueError`, and an `on_change` that is not callable `TypeError`.
/// `on_change` can run before this returns.
#[pyfunction]
#[pyo3(signature = (on_change, *, env = None, precedence = None, poll_interval = None))]
fn watch(
    py: Python<'_>,
    on_change: Py<PyAny>,
    env: Option<Bound<'_, PyAny>>,
    precedence: Option<&str>,
    poll_interval: Option<f64>,
) -> PyResult<Watcher> {
    // Checked here, or every change would end in an unraisable `TypeError` on the watch's
    // thread instead of one exception where the mistake was made.
    if !on_change.bind(py).is_callable() {
        return Err(PyTypeError::new_err("on_change must be callable"));
    }
    let layering = Arc::new(layering(py, env, precedence)?);
    let poll_interval = poll_interval
        .map(Duration::try_from_secs_f64)
        .transpose()
        .map_err(|error| PyValueError::new_err(format!("poll_interval: {error}")))?;
    let delivered = Arc::clone(&layering);
    let on_change: OnChange = Arc::new(Mutex::new(Some(on_change)));
    let lent = Arc::clone(&on_change);
    let deliver = move |value: Result<ProxyConfig, Failure>| {
        if FINALIZING.load(Ordering::SeqCst) {
            return false;
        }
        Python::attach(|py| {
            // Cleared by `close()` or by the collector: the watcher is gone.
            let Some(on_change) = lent
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .map(|on_change| on_change.clone_ref(py))
            else {
                return false;
            };
            let args = match value {
                Ok(config) => Snapshot {
                    config: delivered.apply(config),
                    // A change arrives only where the OS had settings to watch.
                    os_readable: true,
                }
                .into_pyobject(py)
                .map(|snapshot| (py.None(), snapshot.into_any().unbind())),
                Err(failure) => Ok((error(py, failure).into_value(py).into_any(), py.None())),
            };
            if let Err(raised) = args.and_then(|args| on_change.call1(py, args)) {
                raised.write_unraisable(py, Some(on_change.bind(py)));
            }
            true
        })
    };
    let captured = CapturedEnv::capture();
    let watch = py
        .detach(|| shared::Watch::start(poll_interval, &captured, "proxy-watch-python", deliver))
        .map_err(|failure| error(py, failure))?;
    Ok(Watcher {
        watch,
        layering,
        on_change,
        pid: std::process::id(),
    })
}

#[pyfunction]
fn _finalizing() {
    FINALIZING.store(true, Ordering::SeqCst);
}

#[pymodule(name = "proxy_watch")]
fn proxy_watch_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add("ProxyWatchError", py.get_type::<ProxyWatchError>())?;
    m.add_class::<Route>()?;
    m.add_class::<PacPolicy>()?;
    m.add_class::<Diagnostics>()?;
    m.add_class::<Snapshot>()?;
    m.add_class::<Watcher>()?;
    m.add_function(wrap_pyfunction!(read, m)?)?;
    m.add_function(wrap_pyfunction!(watch, m)?)?;
    let finalizing = wrap_pyfunction!(_finalizing, m)?;
    py.import("atexit")?
        .call_method1("register", (finalizing,))?;
    Ok(())
}
