//! GLib, GObject and GIO, opened at run time by soname.
//!
//! Nothing here links against GLib: the three libraries are opened with `dlopen` on first
//! use, and a machine without them (or with a GLib older than 2.44, which lacks
//! `g_settings_schema_list_children`) has no GNOME store rather than a process that fails
//! to start. [`gio`] answers `None` there, and every caller treats that exactly like an
//! uninstalled `org.gnome.system.proxy` schema.
//!
//! The table holds only the calls this crate makes. Each declaration matches its header
//! under GLib's `glib/`, `gobject/` or `gio/`; a wrong one is undefined
//! behaviour at run time, not a compile error, so a new entry is checked against the header
//! before it is added. Ownership follows the `(transfer …)` annotations on docs.gtk.org,
//! and each wrapper's `Drop` releases exactly what its constructor received.
//!
//! A table that loads completely never closes its libraries: GLib is not `dlclose`-safe (it
//! registers types, thread locals and `atexit` handlers), so each handle is leaked once
//! every symbol has resolved. A load that fails closes what it opened.

use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};
use std::mem;
use std::ptr::{self, NonNull};
use std::sync::OnceLock;

use libloading::os::unix::{Library, RTLD_LOCAL, RTLD_NOW};

type Ptr = *mut c_void;
type Gboolean = c_int;

// `{ GQuark domain; gint code; gchar *message; }`: `glib/gerror.h`.
#[repr(C)]
struct GError {
    domain: u32,
    code: c_int,
    message: *mut c_char,
}

// `G_BUS_TYPE_SESSION` in `GBusType` (`gio/gioenums.h`).
const G_BUS_TYPE_SESSION: c_int = 2;
// `G_DBUS_CALL_FLAGS_NONE`.
const G_DBUS_CALL_FLAGS_NONE: c_int = 0;

// The sonames. The unversioned `libgio-2.0.so` is a development symlink and is absent from
// a runtime-only machine.
const LIBRARIES: Libraries = Libraries {
    glib: "libglib-2.0.so.0",
    gobject: "libgobject-2.0.so.0",
    gio: "libgio-2.0.so.0",
};

struct Libraries {
    glib: &'static str,
    gobject: &'static str,
    gio: &'static str,
}

// Why GLib could not be loaded: the library that failed and, when the library opened, the
// symbol it lacked.
pub(crate) struct LoadError {
    library: &'static str,
    symbol: Option<&'static str>,
    message: String,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.symbol {
            Some(symbol) => write!(f, "{} has no {symbol}: {}", self.library, self.message),
            None => write!(f, "{} cannot be opened: {}", self.library, self.message),
        }
    }
}

macro_rules! symbols {
    ($($lib:ident . $name:ident : fn($($arg:ty),*) $(-> $ret:ty)?;)*) => {
        // Every GLib entry point this crate calls, resolved once.
        pub(crate) struct Gio {
            $($name: unsafe extern "C" fn($($arg),*) $(-> $ret)?,)*
        }

        impl Gio {
            fn load(names: &Libraries) -> Result<Self, LoadError> {
                let glib = open(names.glib)?;
                let gobject = open(names.gobject)?;
                let gio = open(names.gio)?;
                let table = Self {
                    $($name: {
                        // `$lib` names a local of this body, which macro hygiene hides
                        // from the caller's tokens; the name picks it instead.
                        let library = match stringify!($lib) {
                            "glib" => &glib,
                            "gobject" => &gobject,
                            _ => &gio,
                        };
                        // SAFETY: the declared type matches the GLib header for this name.
                        let symbol = unsafe {
                            library.get::<unsafe extern "C" fn($($arg),*) $(-> $ret)?>(
                                concat!(stringify!($name), "\0").as_bytes(),
                            )
                        }
                        .map_err(|error| LoadError {
                            library: names.$lib,
                            symbol: Some(stringify!($name)),
                            message: error.to_string(),
                        })?;
                        *symbol
                    },)*
                };
                mem::forget(glib);
                mem::forget(gobject);
                mem::forget(gio);
                Ok(table)
            }
        }
    };
}

symbols! {
    glib.g_free: fn(Ptr);
    glib.g_strfreev: fn(*mut *mut c_char);
    glib.g_error_free: fn(*mut GError);
    glib.g_variant_ref_sink: fn(Ptr) -> Ptr;
    glib.g_variant_unref: fn(Ptr);
    glib.g_variant_equal: fn(Ptr, Ptr) -> Gboolean;
    glib.g_variant_new_string: fn(*const c_char) -> Ptr;
    glib.g_variant_new_tuple: fn(*const Ptr, usize) -> Ptr;
    glib.g_variant_get_child_value: fn(Ptr, usize) -> Ptr;
    glib.g_variant_get_strv: fn(Ptr, *mut usize) -> *mut *const c_char;
    glib.g_variant_type_new: fn(*const c_char) -> Ptr;
    glib.g_variant_type_free: fn(Ptr);
    glib.g_main_context_new: fn() -> Ptr;
    glib.g_main_context_unref: fn(Ptr);
    glib.g_main_context_push_thread_default: fn(Ptr);
    glib.g_main_context_pop_thread_default: fn(Ptr);
    glib.g_main_context_iteration: fn(Ptr, Gboolean) -> Gboolean;
    glib.g_main_context_wakeup: fn(Ptr);
    gobject.g_object_unref: fn(Ptr);
    gobject.g_signal_connect_data:
        fn(Ptr, *const c_char, Option<unsafe extern "C" fn()>, Ptr,
           Option<unsafe extern "C" fn(Ptr, Ptr)>, c_int) -> c_ulong;
    gio.g_settings_schema_source_get_default: fn() -> Ptr;
    gio.g_settings_schema_source_lookup: fn(Ptr, *const c_char, Gboolean) -> Ptr;
    gio.g_settings_schema_unref: fn(Ptr);
    gio.g_settings_schema_list_children: fn(Ptr) -> *mut *mut c_char;
    gio.g_settings_schema_has_key: fn(Ptr, *const c_char) -> Gboolean;
    gio.g_settings_schema_get_key: fn(Ptr, *const c_char) -> Ptr;
    gio.g_settings_schema_key_unref: fn(Ptr);
    gio.g_settings_schema_key_get_default_value: fn(Ptr) -> Ptr;
    gio.g_settings_new: fn(*const c_char) -> Ptr;
    gio.g_settings_get_child: fn(Ptr, *const c_char) -> Ptr;
    gio.g_settings_get_string: fn(Ptr, *const c_char) -> *mut c_char;
    gio.g_settings_get_boolean: fn(Ptr, *const c_char) -> Gboolean;
    gio.g_settings_get_int: fn(Ptr, *const c_char) -> c_int;
    gio.g_settings_get_strv: fn(Ptr, *const c_char) -> *mut *mut c_char;
    gio.g_settings_get_user_value: fn(Ptr, *const c_char) -> Ptr;
    gio.g_settings_get_default_value: fn(Ptr, *const c_char) -> Ptr;
    gio.g_settings_is_writable: fn(Ptr, *const c_char) -> Gboolean;
    gio.g_bus_get_sync: fn(c_int, Ptr, *mut *mut GError) -> Ptr;
    gio.g_dbus_connection_call_sync:
        fn(Ptr, *const c_char, *const c_char, *const c_char, *const c_char, Ptr, Ptr,
           c_int, c_int, Ptr, *mut *mut GError) -> Ptr;
}

fn open(name: &'static str) -> Result<Library, LoadError> {
    // SAFETY: GLib's constructors are safe to run on load; it is loaded into processes that
    // never call it all the time (every GTK plugin host does).
    unsafe { Library::open(Some(name), RTLD_NOW | RTLD_LOCAL) }.map_err(|error| LoadError {
        library: name,
        symbol: None,
        message: error.to_string(),
    })
}

// The loaded table, or `None` when GLib is absent or too old. Loaded once per process.
pub(crate) fn gio() -> Option<&'static Gio> {
    static GIO: OnceLock<Option<Gio>> = OnceLock::new();
    GIO.get_or_init(|| match Gio::load(&LIBRARIES) {
        Ok(gio) => Some(gio),
        #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
        Err(error) => {
            crate::trace::debug!(error = %error, "GLib is not loadable");
            None
        }
    })
    .as_ref()
}

// A key or schema name as a C string. Every name this crate passes is built from its own
// constants or from names GLib returned, none of which holds an interior NUL.
fn c(name: &str) -> CString {
    CString::new(name).expect("GSettings names contain no NUL")
}

// Copy a NUL-terminated `gchar**` into owned strings and free it with `g_strfreev`.
//
// SAFETY: `array` is a `(transfer full)` string array from GLib, or null.
unsafe fn take_strv(g: &Gio, array: *mut *mut c_char) -> Vec<String> {
    let mut out = Vec::new();
    if array.is_null() {
        return out;
    }
    let mut cursor = array;
    // SAFETY: the array is NUL-terminated and every element is a valid C string.
    unsafe {
        while !(*cursor).is_null() {
            out.push(CStr::from_ptr(*cursor).to_string_lossy().into_owned());
            cursor = cursor.add(1);
        }
        (g.g_strfreev)(array);
    }
    out
}

// Take a set `GError*`'s message and free it.
//
// SAFETY: `error` is a non-null `GError*` this crate owns.
unsafe fn take_error(g: &Gio, error: *mut GError) -> String {
    // SAFETY: per the caller; `message` is a C string or null.
    unsafe {
        let message = (*error).message;
        let text = if message.is_null() {
            String::from("(no message)")
        } else {
            CStr::from_ptr(message).to_string_lossy().into_owned()
        };
        (g.g_error_free)(error);
        text
    }
}

// The default `GSettingsSchemaSource`. `g_settings_schema_source_get_default` is
// `(transfer none)`, so nothing is released.
#[derive(Clone, Copy)]
pub(crate) struct SchemaSource {
    g: &'static Gio,
    ptr: NonNull<c_void>,
}

impl SchemaSource {
    // `None` when no schema is installed on this machine at all.
    pub(crate) fn default(g: &'static Gio) -> Option<Self> {
        // SAFETY: no arguments; the result is borrowed from GLib for the process lifetime.
        let ptr = NonNull::new(unsafe { (g.g_settings_schema_source_get_default)() })?;
        Some(Self { g, ptr })
    }

    // Look `id` up, recursing into parent sources.
    pub(crate) fn lookup(&self, id: &str) -> Option<Schema> {
        let c_id = c(id);
        // SAFETY: `ptr` is a live source; the result is `(transfer full)` or null.
        let ptr = NonNull::new(unsafe {
            (self.g.g_settings_schema_source_lookup)(self.ptr.as_ptr(), c_id.as_ptr(), 1)
        })?;
        Some(Schema {
            g: self.g,
            ptr,
            id: id.to_owned(),
        })
    }

    pub(crate) fn gio(&self) -> &'static Gio {
        self.g
    }
}

// A `GSettingsSchema`, released with `g_settings_schema_unref`.
pub(crate) struct Schema {
    g: &'static Gio,
    ptr: NonNull<c_void>,
    id: String,
}

impl Schema {
    // The `GSettings` object for this schema. It is only reachable from a schema that
    // [`SchemaSource::lookup`] found: `g_settings_new` aborts the process on a schema that
    // is not installed.
    pub(crate) fn settings(&self) -> Settings {
        let id = c(&self.id);
        // SAFETY: C string naming an installed schema; `(transfer full)`.
        let ptr = unsafe { (self.g.g_settings_new)(id.as_ptr()) };
        Settings {
            g: self.g,
            ptr: NonNull::new(ptr).expect("g_settings_new returns an object"),
        }
    }

    pub(crate) fn list_children(&self) -> Vec<String> {
        // SAFETY: live schema; the array is `(transfer full)`.
        unsafe {
            take_strv(
                self.g,
                (self.g.g_settings_schema_list_children)(self.ptr.as_ptr()),
            )
        }
    }

    pub(crate) fn has_key(&self, key: &str) -> bool {
        let key = c(key);
        // SAFETY: live schema and C string.
        unsafe { (self.g.g_settings_schema_has_key)(self.ptr.as_ptr(), key.as_ptr()) != 0 }
    }

    // The compiled default of `key`. The key must exist ([`Self::has_key`]):
    // `g_settings_schema_get_key` on an unknown name is a programmer error in GLib.
    pub(crate) fn key_default_value(&self, key: &str) -> Variant {
        let key = c(key);
        // SAFETY: live schema; the key is `(transfer full)` and released here, the value is
        // `(transfer full)` and never null for an existing key.
        unsafe {
            let schema_key = (self.g.g_settings_schema_get_key)(self.ptr.as_ptr(), key.as_ptr());
            let value = (self.g.g_settings_schema_key_get_default_value)(schema_key);
            (self.g.g_settings_schema_key_unref)(schema_key);
            Variant::from_full(self.g, value).expect("a schema key has a default value")
        }
    }
}

impl Drop for Schema {
    fn drop(&mut self) {
        // SAFETY: the reference this value owns.
        unsafe { (self.g.g_settings_schema_unref)(self.ptr.as_ptr()) }
    }
}

// A `GSettings` object, released with `g_object_unref`. Not `Send`: it is bound to the
// thread-default `GMainContext` it was created under.
pub(crate) struct Settings {
    g: &'static Gio,
    ptr: NonNull<c_void>,
}

impl Settings {
    // The child `name`, which the schema offers ([`Schema::list_children`]).
    pub(crate) fn child(&self, name: &str) -> Self {
        let name = c(name);
        // SAFETY: live object; `(transfer full)`.
        let ptr = unsafe { (self.g.g_settings_get_child)(self.ptr.as_ptr(), name.as_ptr()) };
        Self {
            g: self.g,
            ptr: NonNull::new(ptr).expect("g_settings_get_child returns an object"),
        }
    }

    pub(crate) fn string(&self, key: &str) -> String {
        let key = c(key);
        // SAFETY: live object, existing `s` key; the string is `(transfer full)`.
        unsafe {
            let raw = (self.g.g_settings_get_string)(self.ptr.as_ptr(), key.as_ptr());
            let text = CStr::from_ptr(raw).to_string_lossy().into_owned();
            (self.g.g_free)(raw.cast());
            text
        }
    }

    pub(crate) fn boolean(&self, key: &str) -> bool {
        let key = c(key);
        // SAFETY: live object, existing `b` key.
        unsafe { (self.g.g_settings_get_boolean)(self.ptr.as_ptr(), key.as_ptr()) != 0 }
    }

    pub(crate) fn int(&self, key: &str) -> i32 {
        let key = c(key);
        // SAFETY: live object, existing `i` key.
        unsafe { (self.g.g_settings_get_int)(self.ptr.as_ptr(), key.as_ptr()) }
    }

    pub(crate) fn strv(&self, key: &str) -> Vec<String> {
        let key = c(key);
        // SAFETY: live object, existing `as` key; the array is `(transfer full)`.
        unsafe {
            take_strv(
                self.g,
                (self.g.g_settings_get_strv)(self.ptr.as_ptr(), key.as_ptr()),
            )
        }
    }

    pub(crate) fn user_value(&self, key: &str) -> Option<Variant> {
        let key = c(key);
        // SAFETY: live object; `(transfer full)` or null.
        unsafe {
            Variant::from_full(
                self.g,
                (self.g.g_settings_get_user_value)(self.ptr.as_ptr(), key.as_ptr()),
            )
        }
    }

    pub(crate) fn default_value(&self, key: &str) -> Option<Variant> {
        let key = c(key);
        // SAFETY: live object; `(transfer full)` or null.
        unsafe {
            Variant::from_full(
                self.g,
                (self.g.g_settings_get_default_value)(self.ptr.as_ptr(), key.as_ptr()),
            )
        }
    }

    pub(crate) fn is_writable(&self, key: &str) -> bool {
        let key = c(key);
        // SAFETY: live object.
        unsafe { (self.g.g_settings_is_writable)(self.ptr.as_ptr(), key.as_ptr()) != 0 }
    }

    // Run `f` on every emission of `signal`, a signal whose handler shape is
    // `void (GSettings *, const gchar *key, gpointer)`: `changed` and `writable-changed`
    // both are. `writable-change-event` is not: it returns `gboolean`, and connecting this
    // trampoline to it is undefined behaviour.
    //
    // The closure lives until GLib releases it, which it does when the handler is
    // disconnected, at the latest when this object is finalized.
    pub(crate) fn connect<F: Fn() + 'static>(&self, signal: &CStr, f: F) {
        unsafe extern "C" fn trampoline<F: Fn()>(_: Ptr, _: *const c_char, data: Ptr) {
            // SAFETY: `data` is the `Box<F>` below, alive until `release` runs.
            unsafe { (*data.cast::<F>())() }
        }
        unsafe extern "C" fn release<F>(data: Ptr, _closure: Ptr) {
            // SAFETY: GLib calls the destroy notify exactly once, with the pointer given.
            drop(unsafe { Box::from_raw(data.cast::<F>()) });
        }
        let data = Box::into_raw(Box::new(f)).cast::<c_void>();
        // SAFETY: `GCallback` is `void (*)(void)`; GLib calls it back with the signal's own
        // argument list, which `trampoline` declares.
        let handler = unsafe {
            mem::transmute::<unsafe extern "C" fn(Ptr, *const c_char, Ptr), unsafe extern "C" fn()>(
                trampoline::<F>,
            )
        };
        // SAFETY: live object and C string; ownership of `data` passes to GLib.
        unsafe {
            (self.g.g_signal_connect_data)(
                self.ptr.as_ptr(),
                signal.as_ptr(),
                Some(handler),
                data,
                Some(release::<F>),
                0,
            );
        }
    }
}

impl Drop for Settings {
    fn drop(&mut self) {
        // SAFETY: the reference this value owns.
        unsafe { (self.g.g_object_unref)(self.ptr.as_ptr()) }
    }
}

// A `GVariant` this crate holds a full (non-floating) reference to.
pub(crate) struct Variant {
    g: &'static Gio,
    ptr: NonNull<c_void>,
}

// SAFETY: a `GVariant` is immutable and its reference count is atomic.
unsafe impl Send for Variant {}
// SAFETY: as above.
unsafe impl Sync for Variant {}

impl Variant {
    // SAFETY: `ptr` is a `(transfer full)` non-floating reference, or null.
    unsafe fn from_full(g: &'static Gio, ptr: Ptr) -> Option<Self> {
        NonNull::new(ptr).map(|ptr| Self { g, ptr })
    }

    // `(s)`: a one-element tuple holding `text`.
    pub(crate) fn string_tuple(g: &'static Gio, text: &str) -> Self {
        let text = CString::new(text).expect("a probe URI contains no NUL");
        // SAFETY: the string is floating and the tuple sinks it; the tuple is floating and
        // `g_variant_ref_sink` turns it into the full reference this value owns.
        unsafe {
            let child = (g.g_variant_new_string)(text.as_ptr());
            let tuple = (g.g_variant_new_tuple)(&child, 1);
            let owned = (g.g_variant_ref_sink)(tuple);
            Self::from_full(g, owned).expect("g_variant_new_tuple returns a value")
        }
    }

    // The `index`th child of a container.
    pub(crate) fn child(&self, index: usize) -> Self {
        // SAFETY: live container with at least `index + 1` children; `(transfer full)`.
        unsafe {
            Self::from_full(
                self.g,
                (self.g.g_variant_get_child_value)(self.ptr.as_ptr(), index),
            )
            .expect("g_variant_get_child_value returns a value")
        }
    }

    // The strings of an `as` value.
    pub(crate) fn strv(&self) -> Vec<String> {
        let mut length = 0usize;
        // SAFETY: an `as` value. The array is `(transfer container)`: it is freed here with
        // `g_free`, while its strings belong to the variant and are copied out first.
        unsafe {
            let array = (self.g.g_variant_get_strv)(self.ptr.as_ptr(), &mut length);
            let out = (0..length)
                .map(|i| CStr::from_ptr(*array.add(i)).to_string_lossy().into_owned())
                .collect();
            (self.g.g_free)(array.cast());
            out
        }
    }

    // `g_variant_equal`. Both values have the same type (they come from one key).
    pub(crate) fn equals(&self, other: &Self) -> bool {
        // SAFETY: two live values.
        unsafe { (self.g.g_variant_equal)(self.ptr.as_ptr(), other.ptr.as_ptr()) != 0 }
    }
}

impl Drop for Variant {
    fn drop(&mut self) {
        // SAFETY: the reference this value owns.
        unsafe { (self.g.g_variant_unref)(self.ptr.as_ptr()) }
    }
}

// A `GMainContext` of this crate's own.
pub(crate) struct MainContext {
    g: &'static Gio,
    ptr: NonNull<c_void>,
}

// SAFETY: `GMainContext` is thread-safe: `g_main_context_wakeup` is documented for use from
// any thread, and iteration runs only on the thread that pushed the context.
unsafe impl Send for MainContext {}
// SAFETY: as above.
unsafe impl Sync for MainContext {}

impl MainContext {
    pub(crate) fn new(g: &'static Gio) -> Self {
        // SAFETY: no arguments; `(transfer full)`.
        let ptr = unsafe { (g.g_main_context_new)() };
        Self {
            g,
            ptr: NonNull::new(ptr).expect("g_main_context_new returns a context"),
        }
    }

    // Make this the calling thread's default context. [`Self::pop_thread_default`] on the
    // same thread undoes it, after every object created under it is dropped.
    pub(crate) fn push_thread_default(&self) {
        // SAFETY: live context.
        unsafe { (self.g.g_main_context_push_thread_default)(self.ptr.as_ptr()) }
    }

    pub(crate) fn pop_thread_default(&self) {
        // SAFETY: live context, pushed on this thread.
        unsafe { (self.g.g_main_context_pop_thread_default)(self.ptr.as_ptr()) }
    }

    // One blocking iteration.
    pub(crate) fn iteration(&self) {
        // SAFETY: live context, owned by this thread through `push_thread_default`.
        unsafe { (self.g.g_main_context_iteration)(self.ptr.as_ptr(), 1) };
    }

    pub(crate) fn wakeup(&self) {
        // SAFETY: live context; callable from any thread.
        unsafe { (self.g.g_main_context_wakeup)(self.ptr.as_ptr()) }
    }
}

impl Drop for MainContext {
    fn drop(&mut self) {
        // SAFETY: the reference this value owns.
        unsafe { (self.g.g_main_context_unref)(self.ptr.as_ptr()) }
    }
}

// A `GDBusConnection` to the session bus.
pub(crate) struct DBusConnection {
    g: &'static Gio,
    ptr: NonNull<c_void>,
}

impl DBusConnection {
    // The session bus, or the `GError` message saying why it is unreachable.
    pub(crate) fn session(g: &'static Gio) -> Result<Self, String> {
        let mut error: *mut GError = ptr::null_mut();
        // SAFETY: no cancellable; the connection is `(transfer full)`, null exactly when
        // `error` is set.
        let raw = unsafe { (g.g_bus_get_sync)(G_BUS_TYPE_SESSION, ptr::null_mut(), &mut error) };
        match NonNull::new(raw) {
            Some(ptr) => Ok(Self { g, ptr }),
            // SAFETY: GLib set `error` because it returned null.
            None => Err(unsafe { take_error(g, error) }),
        }
    }

    // A synchronous method call whose reply GLib checks against `reply_type` before it
    // returns: a mismatch is an error here, never a value of the wrong shape.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn call_sync(
        &self,
        bus_name: &str,
        object_path: &str,
        interface: &str,
        method: &str,
        parameters: &Variant,
        reply_type: &str,
        timeout_ms: i32,
    ) -> Result<Variant, String> {
        let (bus_name, object_path, interface, method, reply_type) = (
            c(bus_name),
            c(object_path),
            c(interface),
            c(method),
            c(reply_type),
        );
        let mut error: *mut GError = ptr::null_mut();
        // SAFETY: live connection and parameters (not floating, so GLib takes its own
        // reference); the type is freed here; the reply is `(transfer full)`, null exactly
        // when `error` is set.
        unsafe {
            let reply_type = (self.g.g_variant_type_new)(reply_type.as_ptr());
            let reply = (self.g.g_dbus_connection_call_sync)(
                self.ptr.as_ptr(),
                bus_name.as_ptr(),
                object_path.as_ptr(),
                interface.as_ptr(),
                method.as_ptr(),
                parameters.ptr.as_ptr(),
                reply_type,
                G_DBUS_CALL_FLAGS_NONE,
                timeout_ms,
                ptr::null_mut(),
                &mut error,
            );
            (self.g.g_variant_type_free)(reply_type);
            match Variant::from_full(self.g, reply) {
                Some(reply) => Ok(reply),
                None => Err(take_error(self.g, error)),
            }
        }
    }
}

impl Drop for DBusConnection {
    fn drop(&mut self) {
        // SAFETY: the reference this value owns.
        unsafe { (self.g.g_object_unref)(self.ptr.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_library_is_a_load_error_naming_it() {
        let names = Libraries {
            glib: "libproxy-watch-absent-glib.so.0",
            gobject: LIBRARIES.gobject,
            gio: LIBRARIES.gio,
        };
        let error = Gio::load(&names).err().expect("the library does not exist");
        assert_eq!(error.library, names.glib);
        assert_eq!(error.symbol, None);
    }

    // A library that opens but lacks the symbols: every GLib symbol is looked up in libc,
    // which has none of them, so the first entry of the table is the one reported.
    #[test]
    fn a_library_without_the_symbols_is_a_load_error_naming_the_symbol() {
        let names = Libraries {
            glib: "libc.so.6",
            gobject: "libc.so.6",
            gio: "libc.so.6",
        };
        let error = Gio::load(&names).err().expect("libc has no GLib symbols");
        assert_eq!(error.library, "libc.so.6");
        assert_eq!(error.symbol, Some("g_free"));
    }

    // Every symbol in the table must resolve against the installed GLib. A machine without
    // GLib skips, except under `CI`, where a skip would pass without checking anything.
    #[test]
    fn every_symbol_resolves_against_the_installed_glib() {
        if open(LIBRARIES.gio).is_err() {
            assert!(
                std::env::var_os("CI").is_none(),
                "GLib is not installed on a CI runner"
            );
            eprintln!("GLib is not installed; nothing to resolve against");
            return;
        }
        if let Err(error) = Gio::load(&LIBRARIES) {
            panic!("{error}");
        }
    }
}
