//! Android: hand the crate the host's `JavaVM` and a `Context`.
//!
//! Every read goes through the Java framework, so the crate needs the process's `JavaVM`
//! and a `Context`. A host built on `android-activity` registers both with `ndk-context`,
//! which the crate reads without further setup, and so does `tao` from 0.36 (Tauri 2.12):
//! it registers the application `Context` in the Activity's `onCreate`, before any app
//! code runs. `tao` before 0.36 registers neither; such a host calls [`init`] once,
//! before the first [`read`](crate::read) or
//! [`ProxyWatcher`](crate::ProxyWatcher). Before then, in a host that registered nothing,
//! a read returns [`Error::Io`](crate::Error::Io) after the panic hook reports
//! `ndk-context`'s panic, and a build with `panic = "abort"` aborts the process there.
//!
//! `tao` keeps both for each Activity it creates, and `main_android_context` hands them
//! out, so a Tauri app makes the call in `setup`, with no Kotlin of its own. On `tao` 0.36
//! and later the call is redundant and harmless; `init` wins, and it keeps the same
//! application `Context`:
//!
//! ```ignore
//! tauri::Builder::default().setup(|_app| {
//!     #[cfg(target_os = "android")]
//!     if let Some(ctx) = tauri::tao::platform::android::prelude::main_android_context() {
//!         // SAFETY: tao holds a global reference to the Activity while it exists.
//!         unsafe { proxy_watch::android::init(ctx.java_vm, ctx.context_jobject) }?;
//!     }
//!     Ok(())
//! })
//! ```
//!
//! Elsewhere, `JNI_OnLoad` receives the `JavaVM` but no `Context`, so the call usually sits
//! in a JNI function the app's Kotlin or Java side calls with one, which reaches the
//! `JavaVM` through its `JNIEnv`.

pub use crate::sys::android::init;
