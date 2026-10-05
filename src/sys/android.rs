//! Android: `ConnectivityManager.getDefaultProxy()` through JNI, watched through the
//! `PROXY_CHANGE_ACTION` broadcast.
//!
//! The `JavaVM` and application `Context` come from [`crate::android::init`] when the host
//! called it, and otherwise from `ndk-context`, which `android-activity` and `tao` 0.36 and
//! later register themselves. `tao` before 0.36 (Tauri before 2.12) registers neither, so a
//! host built on it calls `init`. Until one of the two holds a `JavaVM`, every read is an
//! [`Error::Io`] saying so.
//!
//! Only a Java `BroadcastReceiver` subclass can receive the broadcast, so the crate carries
//! one as a compiled dex and loads it with `InMemoryDexClassLoader` (API 26+); see
//! [`receiver`]. Each broadcast wakes the [`super::poll`] thread, which re-reads. Below
//! API 26, or where the platform refuses in-memory code loading, the watcher falls back to
//! [`WatchOptions::poll_interval`], and fails to construct without one.
//!
//! A host that would rather not load code at run time can receive the broadcast itself and
//! call [`ProxyWatcher::poll_now`](crate::ProxyWatcher::poll_now) from its receiver, with a
//! long `poll_interval` as the backstop:
//!
//! ```kotlin
//! context.registerReceiver(object : BroadcastReceiver() {
//!     override fun onReceive(context: Context, intent: Intent) = nativePollNow()
//! }, IntentFilter(Proxy.PROXY_CHANGE_ACTION))
//! ```
//!
//! Chromium receives proxy changes this way, in
//! `net/android/java/src/org/chromium/net/ProxyChangeListener.java`.

use std::ffi::c_void;
use std::sync::OnceLock;

use jni::objects::{GlobalRef, JObject, JObjectArray, JString};
use jni::{JNIEnv, JavaVM};

#[cfg(feature = "pac-android-native")]
use super::proxy_info::SelectedProxy;
use super::proxy_info::{ProxyInfo, mode_from_proxy_info};
use crate::config::{ProxyConfig, ProxyConfigSource};
use crate::error::Error;
use crate::watch::WatchOptions;

mod receiver;

pub(crate) use receiver::Watch;

pub(crate) fn read_config(_options: &WatchOptions) -> Result<ProxyConfig, Error> {
    let info = read_proxy_info()?;
    let mode = mode_from_proxy_info(info.as_ref())?;
    Ok(ProxyConfig::from_source(
        ProxyConfigSource::ConnectivityManager,
        mode,
    ))
}

fn read_proxy_info() -> Result<Option<ProxyInfo>, Error> {
    with_framework(READING, read_in)
}

const READING: &str = "reading ConnectivityManager.getDefaultProxy() through JNI";

// The JavaVM and application Context [`init`] was given. Held for the life of the process,
// which is the life of both: dropping the reference would need an attached thread, and
// the receiver's unregistration needs the Context it was registered on.
static HOST: OnceLock<Host> = OnceLock::new();

struct Host {
    vm: JavaVM,
    app: GlobalRef,
}

const INITIALIZING: &str = "proxy_watch::android::init";

/// Hands the crate the process's `JavaVM` and a `Context`, from which it keeps the
/// application `Context` for the life of the process.
///
/// Once `init` has succeeded, the crate uses what it was given and ignores `ndk-context`.
/// A second call with the same `JavaVM` returns `Ok` and changes nothing, so a host whose
/// set-up code runs more than once needs no guard of its own.
///
/// # Errors
///
/// [`Error::Io`] when the thread cannot attach to `vm`, when `context` has no application
/// yet (`getApplicationContext()` is `null`), or when an earlier call succeeded with a
/// different `JavaVM`.
///
/// # Safety
///
/// `vm` is a valid `JavaVM*`, and `context` is a valid JNI reference (local or global) to
/// an `android.content.Context` (an `Activity`, a `Service` or the `Application`) alive for
/// the duration of the call. The crate only borrows `context`; the caller keeps ownership.
pub unsafe fn init(vm: *mut c_void, context: *mut c_void) -> Result<(), Error> {
    let raw = vm.cast::<jni::sys::JavaVM>();
    if let Some(host) = HOST.get() {
        return same_vm(host, raw);
    }
    // SAFETY: the caller passes a valid `JavaVM*`.
    let vm = unsafe { JavaVM::from_raw(raw) }.map_err(|e| jni_error(INITIALIZING, e))?;
    let app = call_in(INITIALIZING, &vm, |env| {
        // SAFETY: the caller passes a valid reference to a `Context`; it is only borrowed.
        let given = unsafe { JObject::from_raw(context.cast()) };
        let app = application_context(env, &given)?;
        if app.is_null() {
            // Only a Context whose application does not exist yet answers `null`.
            return Err(jni::errors::Error::NullPtr(
                "getApplicationContext() result",
            ));
        }
        env.new_global_ref(app)
    })?;
    match HOST.set(Host { vm, app }) {
        Ok(()) => Ok(()),
        // Another thread's `init` finished first.
        Err(_) => same_vm(HOST.get().expect("HOST is set"), raw),
    }
}

// A process has one JavaVM, so a second `init` with it is a repeat, not a conflict.
fn same_vm(host: &Host, raw: *mut jni::sys::JavaVM) -> Result<(), Error> {
    if host.vm.get_java_vm_pointer() == raw {
        Ok(())
    } else {
        Err(jni_error(
            INITIALIZING,
            "called again with a different JavaVM than the first call",
        ))
    }
}

// Run `body` on this thread, attached to the host's JavaVM, with the application Context:
// the one [`init`] holds, or else the one `ndk-context` holds.
fn with_framework<T>(
    what: &'static str,
    body: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<T>,
) -> Result<T, Error> {
    if let Some(host) = HOST.get() {
        return call_in(what, &host.vm, |env| body(env, host.app.as_obj()));
    }
    // Limitation: `android_context` panics when the host never registered one, and has no
    // fallible twin, so the panic is caught; the panic hook still runs, and under
    // `panic = "abort"` it aborts instead. A host that calls [`init`] never reaches it.
    let context = std::panic::catch_unwind(ndk_context::android_context).map_err(|_| {
        jni_error(
            what,
            "the host app has neither called proxy_watch::android::init nor registered its \
             JavaVM and Context with ndk_context::initialize_android_context",
        )
    })?;
    // SAFETY: `ndk-context` holds a `JavaVM*` the host registered and never releases while
    // the app runs.
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) }.map_err(|e| jni_error(what, e))?;
    call_in(what, &vm, |env| {
        // SAFETY: a global reference to the `Context` the host registered, valid for the process.
        let registered = unsafe { JObject::from_raw(context.context().cast()) };
        let app = application_context(env, &registered)?;
        let app = if app.is_null() { registered } else { app };
        body(env, &app)
    })
}

// The host may hold an Activity, and a receiver registered on an Activity is removed when
// it is destroyed. The application `Context` lives as long as the process; it is `null`
// only before the application exists.
fn application_context<'local>(
    env: &mut JNIEnv<'local>,
    context: &JObject,
) -> jni::errors::Result<JObject<'local>> {
    env.call_method(
        context,
        "getApplicationContext",
        "()Landroid/content/Context;",
        &[],
    )?
    .l()
}

fn call_in<T>(
    what: &'static str,
    vm: &JavaVM,
    body: impl FnOnce(&mut JNIEnv) -> jni::errors::Result<T>,
) -> Result<T, Error> {
    let mut env = vm.attach_current_thread().map_err(|e| jni_error(what, e))?;
    // A frame, so the local references die here even on a thread Java already owns.
    let result = env.with_local_frame(16, |env| body(env));
    result.map_err(|e| match take_exception(&mut env) {
        Some(thrown) => jni_error(what, format!("{e}: {thrown}")),
        None => jni_error(what, e),
    })
}

// Clear the exception pending on this thread and return its `toString()`, which names the
// class and the message: jni reports every thrown exception as the same `JavaException`.
fn take_exception(env: &mut JNIEnv) -> Option<String> {
    if !env.exception_check().unwrap_or(false) {
        return None;
    }
    let thrown = env.exception_occurred();
    let _ = env.exception_clear();
    let thrown = thrown.ok()?;
    let text = env
        .with_local_frame(4, |env| string_of(env, &thrown, "toString"))
        .ok()
        .flatten();
    // `toString()` can throw in turn; that one is dropped.
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    let _ = env.delete_local_ref(thrown);
    text
}

fn read_in(env: &mut JNIEnv, app: &JObject) -> jni::errors::Result<Option<ProxyInfo>> {
    let service = env
        .get_static_field(
            "android/content/Context",
            "CONNECTIVITY_SERVICE",
            "Ljava/lang/String;",
        )?
        .l()?;
    let manager = env
        .call_method(
            app,
            "getSystemService",
            "(Ljava/lang/String;)Ljava/lang/Object;",
            &[(&service).into()],
        )?
        .l()?;
    let info = env
        .call_method(
            &manager,
            "getDefaultProxy",
            "()Landroid/net/ProxyInfo;",
            &[],
        )?
        .l()?;
    if info.is_null() {
        return Ok(None);
    }
    let host = string_of(env, &info, "getHost")?;
    let port = env.call_method(&info, "getPort", "()I", &[])?.i()?;
    let list = JObjectArray::from(
        env.call_method(&info, "getExclusionList", "()[Ljava/lang/String;", &[])?
            .l()?,
    );
    let mut exclusions = Vec::new();
    if !list.is_null() {
        for index in 0..env.get_array_length(&list)? {
            let entry = JString::from(env.get_object_array_element(&list, index)?);
            if !entry.is_null() {
                exclusions.push(env.get_string(&entry)?.into());
            }
            // Freed per entry, so a long list does not outgrow the caller's frame.
            env.delete_local_ref(entry)?;
        }
    }
    let uri = env
        .call_method(&info, "getPacFileUrl", "()Landroid/net/Uri;", &[])?
        .l()?;
    let pac_url = if uri.is_null() {
        None
    } else {
        string_of(env, &uri, "toString")?
    };
    Ok(Some(ProxyInfo {
        host,
        port,
        exclusions,
        pac_url,
    }))
}

/// Ask `ProxySelector.getDefault()` where `uri` goes, the way `java.net` clients in this
/// process are routed. Under a PAC configuration the framework installs `PacProxySelector`,
/// which has the system PAC service evaluate the script for this URL.
///
/// Also returns the PAC URL `getDefaultProxy()` names now, read under the same attach, so
/// the caller can tell whether the selector answered for the configuration it holds.
/// `None` in place of the answer when the default selector is not `PacProxySelector`.
#[cfg(feature = "pac-android-native")]
pub(crate) fn select(uri: &str) -> Result<(Option<String>, Option<Vec<SelectedProxy>>), Error> {
    with_framework(READING, |env, app| {
        let pac_url = read_in(env, app)?.and_then(|info| info.pac_url);
        Ok((pac_url, select_in(env, uri)?))
    })
}

#[cfg(feature = "pac-android-native")]
const PAC_SELECTOR: &str = "android.net.PacProxySelector";

#[cfg(feature = "pac-android-native")]
fn select_in(env: &mut JNIEnv, uri: &str) -> jni::errors::Result<Option<Vec<SelectedProxy>>> {
    let selector = env
        .call_static_method(
            "java/net/ProxySelector",
            "getDefault",
            "()Ljava/net/ProxySelector;",
            &[],
        )?
        .l()?;
    if selector.is_null() {
        return Ok(None);
    }
    // The system installs `PacProxySelector` in each process from a message that is not
    // ordered with the `PROXY_CHANGE_ACTION` broadcast, so just after a switch to PAC the
    // process can still hold the previous selector, which answers for the old settings. A
    // selector the app installed answers for settings of its own.
    let class = env
        .call_method(&selector, "getClass", "()Ljava/lang/Class;", &[])?
        .l()?;
    if string_of(env, &class, "getName")?.as_deref() != Some(PAC_SELECTOR) {
        return Ok(None);
    }
    let text = env.new_string(uri)?;
    let uri = env
        .call_static_method(
            "java/net/URI",
            "create",
            "(Ljava/lang/String;)Ljava/net/URI;",
            &[(&text).into()],
        )?
        .l()?;
    let list = env
        .call_method(
            &selector,
            "select",
            "(Ljava/net/URI;)Ljava/util/List;",
            &[(&uri).into()],
        )?
        .l()?;
    let mut selected = Vec::new();
    for index in 0..env.call_method(&list, "size", "()I", &[])?.i()? {
        // A frame per entry, so a long list does not outgrow the caller's.
        selected.push(env.with_local_frame(8, |env| {
            let proxy = env
                .call_method(&list, "get", "(I)Ljava/lang/Object;", &[index.into()])?
                .l()?;
            let kind = env
                .call_method(&proxy, "type", "()Ljava/net/Proxy$Type;", &[])?
                .l()?;
            let kind = string_of(env, &kind, "name")?.unwrap_or_default();
            let address = env
                .call_method(&proxy, "address", "()Ljava/net/SocketAddress;", &[])?
                .l()?;
            let (host, port) = if address.is_null() {
                (None, 0)
            } else {
                let host = string_of(env, &address, "getHostString")?;
                (host, env.call_method(&address, "getPort", "()I", &[])?.i()?)
            };
            Ok::<_, jni::errors::Error>(SelectedProxy { kind, host, port })
        })?);
    }
    Ok(Some(selected))
}

// A `String`-returning getter, `None` for `null`.
fn string_of(
    env: &mut JNIEnv,
    object: &JObject,
    getter: &str,
) -> jni::errors::Result<Option<String>> {
    let value = JString::from(
        env.call_method(object, getter, "()Ljava/lang/String;", &[])?
            .l()?,
    );
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(env.get_string(&value)?.into()))
}

fn jni_error(what: &'static str, source: impl std::fmt::Display) -> Error {
    Error::io(what, std::io::Error::other(source.to_string()))
}
