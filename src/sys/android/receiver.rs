//! The `PROXY_CHANGE_ACTION` receiver: `ProxyChangeReceiver.java`, compiled into
//! `receiver.dex`, loaded with `InMemoryDexClassLoader` and bound with `RegisterNatives`.
//!
//! Each receiver carries a [`WakeSlot`] id: `unregisterReceiver` does not wait for an
//! `onReceive` already running on the main thread.

use std::ffi::c_void;
use std::sync::Arc;
use std::sync::mpsc::SyncSender;

use jni::JNIEnv;
use jni::NativeMethod;
use jni::objects::{GlobalRef, JClass, JObject, JValue};
use jni::sys::jlong;

use super::super::poll::{self, WakeSlot};
use crate::config::ProxyConfigSource;
use crate::error::Error;
use crate::watch::{
    BackendHealth, Shared, WatchFailSoft, WatchOptions, fatal_watch_error,
    watch_fail_soft_reachable,
};

static DEX: &[u8] = include_bytes!("receiver.dex");
const CLASS: &str = "proxywatch.ProxyChangeReceiver";
const PROXY_CHANGE_ACTION: &str = "android.intent.action.PROXY_CHANGE";
// `InMemoryDexClassLoader` arrived in Android 8.0.
const MIN_SDK: i32 = 26;
// From Android 13 a registration states whether the receiver is exported; a broadcast only
// the system sends is delivered to one that is not.
const FLAGS_SDK: i32 = 33;
const RECEIVER_NOT_EXPORTED: i32 = 4;
const REGISTERING: &str = "registering the PROXY_CHANGE_ACTION receiver through JNI";

#[derive(Debug)]
pub(crate) struct Watch {
    // Declared first so it drops first: it holds a waker, and the poll thread ends only
    // once every waker is gone.
    registration: Option<Registration>,
    poll: poll::Watch,
}

impl Watch {
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    pub(crate) fn armed(options: &WatchOptions) -> Result<Self, Error> {
        let poll = poll::Watch::new(options);
        // With no JavaVM or Context every read fails as well.
        let registration = match watch_fail_soft_reachable(
            || super::with_framework(REGISTERING, |_, _| Ok(())),
            true,
            options.poll_interval,
            || Registration::new(poll.waker()),
        )? {
            WatchFailSoft::Live(registration) => Some(registration),
            WatchFailSoft::Degraded(error) => {
                crate::trace::warning!(
                    error = %crate::trace::SafeError(&error),
                    "registering the PROXY_CHANGE_ACTION receiver failed; continuing on \
                     WatchOptions::poll_interval alone"
                );
                None
            }
            WatchFailSoft::Fatal(error) => {
                return Err(fatal_watch_error(
                    "registering the PROXY_CHANGE_ACTION receiver",
                    "the broadcast is the only proxy change notification Android sends",
                    error,
                ));
            }
        };
        Ok(Self { registration, poll })
    }

    pub(crate) fn spawn(
        &mut self,
        options: &WatchOptions,
        shared: Arc<Shared>,
    ) -> Result<(), Error> {
        self.poll.spawn(options, shared)
    }

    pub(crate) fn health(&self) -> BackendHealth {
        let live = self.registration.is_some();
        BackendHealth {
            degraded: if live {
                Vec::new()
            } else {
                vec![ProxyConfigSource::ConnectivityManager]
            },
            has_live_notifications: live,
        }
    }

    pub(crate) fn poll_now(&self) {
        self.poll.poll_now();
    }
}

#[derive(Debug)]
struct Registration {
    receiver: GlobalRef,
    // Held for its `Drop`, which unfiles the waker after the receiver is unregistered.
    _slot: WakeSlot,
}

impl Registration {
    fn new(wake: SyncSender<()>) -> Result<Self, Error> {
        // Filed before the receiver exists, so its first broadcast is not lost.
        let slot = WakeSlot::new(wake);
        match super::with_framework(REGISTERING, |env, app| register(env, app, slot.id()))? {
            Some(receiver) => Ok(Self {
                receiver,
                _slot: slot,
            }),
            None => Err(Error::Unsupported),
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let _ = super::with_framework(REGISTERING, |env, app| {
            env.call_method(
                app,
                "unregisterReceiver",
                "(Landroid/content/BroadcastReceiver;)V",
                &[JValue::Object(self.receiver.as_obj())],
            )
            .map(drop)
        });
    }
}

// `Ok(None)` below [`MIN_SDK`].
fn register(env: &mut JNIEnv, app: &JObject, id: i64) -> jni::errors::Result<Option<GlobalRef>> {
    let sdk = env
        .get_static_field("android/os/Build$VERSION", "SDK_INT", "I")?
        .i()?;
    if sdk < MIN_SDK {
        return Ok(None);
    }
    let bytes = env.byte_array_from_slice(DEX)?;
    let buffer = env
        .call_static_method(
            "java/nio/ByteBuffer",
            "wrap",
            "([B)Ljava/nio/ByteBuffer;",
            &[JValue::Object(&bytes)],
        )?
        .l()?;
    let parent = env
        .call_method(app, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
        .l()?;
    let loader = env.new_object(
        "dalvik/system/InMemoryDexClassLoader",
        "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
        &[JValue::Object(&buffer), JValue::Object(&parent)],
    )?;
    let name = env.new_string(CLASS)?;
    let class = JClass::from(
        env.call_method(
            &loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&name)],
        )?
        .l()?,
    );
    env.register_native_methods(
        &class,
        &[NativeMethod {
            name: "changed".into(),
            sig: "(J)V".into(),
            fn_ptr: changed as *mut c_void,
        }],
    )?;
    // Global before it is registered: a registration with no handle could never be undone.
    let receiver = env.new_object(&class, "(J)V", &[JValue::Long(id)])?;
    let receiver = env.new_global_ref(receiver)?;
    let action = env.new_string(PROXY_CHANGE_ACTION)?;
    let filter = env.new_object(
        "android/content/IntentFilter",
        "(Ljava/lang/String;)V",
        &[JValue::Object(&action)],
    )?;
    if sdk >= FLAGS_SDK {
        env.call_method(
            app,
            "registerReceiver",
            "(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)Landroid/content/Intent;",
            &[
                JValue::Object(receiver.as_obj()),
                JValue::Object(&filter),
                JValue::Int(RECEIVER_NOT_EXPORTED),
            ],
        )?;
    } else {
        env.call_method(
            app,
            "registerReceiver",
            "(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;",
            &[JValue::Object(receiver.as_obj()), JValue::Object(&filter)],
        )?;
    }
    Ok(Some(receiver))
}

// `ProxyChangeReceiver.changed`, on the main thread. Only a send: the read happens on the
// poll thread.
extern "system" fn changed(_env: JNIEnv, _class: JClass, id: jlong) {
    poll::wake(id);
}
