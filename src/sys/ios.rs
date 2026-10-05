//! iOS: `CFNetworkCopySystemProxySettings`, watched by polling with two early wake-ups.
//!
//! The dictionary carries the keys macOS's `SCDynamicStore` does (`HTTPEnable`,
//! `ProxyAutoConfigURLString`, `ExceptionsList`, ...), so [`super::proxy_dict`] reads it the
//! same way. iOS offers an app no proxy change notification, so the watcher polls (see
//! [`super::poll`]) and needs [`WatchOptions::poll_interval`]. Two events re-read before the
//! interval is up:
//!
//! - `UIApplicationDidBecomeActiveNotification`: a proxy is changed by hand in the Settings
//!   app, so the change is in place when the user comes back.
//! - a path update from `nw_path_monitor`: a proxy belongs to a Wi-Fi network or a VPN, so
//!   joining or leaving one changes it.
//!
//! A change that neither follows, such as an MDM profile arriving while the app stays
//! active on one network, waits for the interval. `Network.framework` needs iOS 12.

use std::ffi::c_void;
use std::sync::Arc;
use std::sync::mpsc::SyncSender;

use core_foundation::base::TCFType;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::CFStringRef;

use super::cf_dict::to_proxy_dict;
use super::poll::{self, WakeSlot};
use super::proxy_dict;
use crate::config::{ProxyConfig, ProxyConfigSource};
use crate::error::Error;
use crate::mode::ProxyMode;
use crate::watch::{BackendHealth, Shared, WatchOptions};

#[link(name = "CFNetwork", kind = "framework")]
unsafe extern "C" {
    fn CFNetworkCopySystemProxySettings() -> CFDictionaryRef;
}

pub(crate) fn read_config(_options: &WatchOptions) -> Result<ProxyConfig, Error> {
    // SAFETY: no arguments; the result follows the create rule and may be NULL.
    let settings = unsafe { CFNetworkCopySystemProxySettings() };
    let mode = if settings.is_null() {
        // NULL means either of two things the caller cannot tell apart: Apple's CFNetwork
        // release notes say the call "Returns NULL if no proxy settings have been defined or
        // if an error was encountered"
        // (<https://developer.apple.com/library/archive/releasenotes/Networking/RN-CFNetwork/index.html>).
        // Read as an error, every device with nothing configured would fail; so it is read
        // as absent, as Qt's `qnetworkproxy_darwin.cpp` does and as macOS reads a NULL that
        // reports no error here, with a warning, because the other meaning hides a proxy.
        crate::trace::warning!(
            "CFNetworkCopySystemProxySettings returned NULL; treating the settings as empty"
        );
        ProxyMode::Direct
    } else {
        // SAFETY: a non-NULL `CFDictionaryRef` this call owns, released when dropped.
        let settings: CFDictionary = unsafe { CFDictionary::wrap_under_create_rule(settings) };
        proxy_dict::mode_from_dict(&to_proxy_dict(&settings))?
    };
    Ok(ProxyConfig::from_source(
        ProxyConfigSource::CfNetworkSystemSettings,
        mode,
    ))
}

#[derive(Debug)]
pub(crate) struct Watch {
    // Declared first so it drops first: it holds a waker, and the poll thread ends only
    // once every waker is gone.
    _hints: Hints,
    poll: poll::Watch,
}

impl Watch {
    pub(crate) fn armed(options: &WatchOptions) -> Result<Self, Error> {
        let poll = poll::Watch::armed(options)?;
        Ok(Self {
            _hints: Hints::new(poll.waker()),
            poll,
        })
    }

    pub(crate) fn spawn(
        &mut self,
        options: &WatchOptions,
        shared: Arc<Shared>,
    ) -> Result<(), Error> {
        self.poll.spawn(options, shared)
    }

    pub(crate) fn health(&self) -> BackendHealth {
        self.poll.health()
    }

    pub(crate) fn poll_now(&self) {
        self.poll.poll_now();
    }
}

type CFNotificationCenterRef = *mut c_void;
type CFNotificationCallback = extern "C" fn(
    center: CFNotificationCenterRef,
    observer: *mut c_void,
    name: CFStringRef,
    object: *const c_void,
    user_info: CFDictionaryRef,
);
const DELIVER_IMMEDIATELY: isize = 4;

// Linked by `core-foundation`.
unsafe extern "C" {
    fn CFNotificationCenterGetLocalCenter() -> CFNotificationCenterRef;
    fn CFNotificationCenterAddObserver(
        center: CFNotificationCenterRef,
        observer: *const c_void,
        callback: CFNotificationCallback,
        name: CFStringRef,
        object: *const c_void,
        suspension_behavior: isize,
    );
    fn CFNotificationCenterRemoveObserver(
        center: CFNotificationCenterRef,
        observer: *const c_void,
        name: CFStringRef,
        object: *const c_void,
    );
}

// The local center also carries what UIKit posts through `NSNotificationCenter`.
#[link(name = "UIKit", kind = "framework")]
unsafe extern "C" {
    static UIApplicationDidBecomeActiveNotification: CFStringRef;
}

#[link(name = "Network", kind = "framework")]
unsafe extern "C" {
    fn nw_path_monitor_create() -> *mut c_void;
    fn nw_path_monitor_set_queue(monitor: *mut c_void, queue: *mut c_void);
    fn nw_path_monitor_set_update_handler(monitor: *mut c_void, handler: *const PathBlock);
    fn nw_path_monitor_start(monitor: *mut c_void);
    fn nw_path_monitor_cancel(monitor: *mut c_void);
    fn nw_release(object: *mut c_void);
}

// libSystem.
unsafe extern "C" {
    static _NSConcreteStackBlock: u8;
    fn dispatch_get_global_queue(identifier: isize, flags: usize) -> *mut c_void;
}
const QOS_CLASS_UTILITY: isize = 0x11;

// An `nw_path_monitor_update_handler_t` block in the Blocks ABI layout: a stack block whose
// one capture is `id`. `nw_path_monitor_set_update_handler` keeps a `Block_copy` of it on
// the heap and the monitor releases that copy with itself. A plain `i64` capture needs no
// copy or dispose helper, so the descriptor has none.
#[repr(C)]
struct PathBlock {
    isa: *const c_void,
    flags: i32,
    reserved: i32,
    invoke: unsafe extern "C" fn(block: *const PathBlock, path: *mut c_void),
    descriptor: &'static BlockDescriptor,
    id: i64,
}

#[repr(C)]
struct BlockDescriptor {
    reserved: usize,
    size: usize,
}

static PATH_BLOCK_DESCRIPTOR: BlockDescriptor = BlockDescriptor {
    reserved: 0,
    size: size_of::<PathBlock>(),
};

// The two early wake-ups, both waking the poll thread through one [`WakeSlot`] id.
#[derive(Debug)]
struct Hints {
    slot: WakeSlot,
    // NULL when `nw_path_monitor_create` returned none; the foreground hint still works.
    monitor: *mut c_void,
}

// SAFETY: `monitor` is a reference-counted `os_object`, and `Drop` only cancels and
// releases it, both of which Network.framework accepts from any thread.
unsafe impl Send for Hints {}
unsafe impl Sync for Hints {}

impl Hints {
    fn new(wake: SyncSender<()>) -> Self {
        let slot = WakeSlot::new(wake);
        // SAFETY: the local center lives for the process, the name is UIKit's constant,
        // and the observer is only a key; `Drop` removes it with the same three.
        unsafe {
            CFNotificationCenterAddObserver(
                CFNotificationCenterGetLocalCenter(),
                observer(slot.id()),
                became_active,
                UIApplicationDidBecomeActiveNotification,
                std::ptr::null(),
                DELIVER_IMMEDIATELY,
            );
        }
        // SAFETY: no arguments; the result is owned here and released in `Drop`.
        let monitor = unsafe { nw_path_monitor_create() };
        if !monitor.is_null() {
            let block = PathBlock {
                isa: (&raw const _NSConcreteStackBlock).cast(),
                flags: 0,
                reserved: 0,
                invoke: path_updated,
                descriptor: &PATH_BLOCK_DESCRIPTOR,
                id: slot.id(),
            };
            // SAFETY: a live monitor, a global queue that is never released, and a stack
            // block that outlives the call, which copies it.
            unsafe {
                nw_path_monitor_set_queue(monitor, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
                nw_path_monitor_set_update_handler(monitor, &block);
                nw_path_monitor_start(monitor);
            }
        }
        Self { slot, monitor }
    }
}

impl Drop for Hints {
    fn drop(&mut self) {
        // SAFETY: the same center, observer and name `new` registered.
        unsafe {
            CFNotificationCenterRemoveObserver(
                CFNotificationCenterGetLocalCenter(),
                observer(self.slot.id()),
                UIApplicationDidBecomeActiveNotification,
                std::ptr::null(),
            );
        }
        if !self.monitor.is_null() {
            // SAFETY: the monitor `new` created and started; released once, here.
            unsafe {
                nw_path_monitor_cancel(self.monitor);
                nw_release(self.monitor);
            }
        }
    }
}

// The observer key: the slot id, never dereferenced.
fn observer(id: i64) -> *const c_void {
    id as usize as *const c_void
}

extern "C" fn became_active(
    _center: CFNotificationCenterRef,
    observer: *mut c_void,
    _name: CFStringRef,
    _object: *const c_void,
    _user_info: CFDictionaryRef,
) {
    poll::wake(observer as usize as i64);
}

// Called once right after `nw_path_monitor_start` with the current path, then on each change.
unsafe extern "C" fn path_updated(block: *const PathBlock, _path: *mut c_void) {
    // SAFETY: the monitor passes its heap copy, which it holds while it can call it; the
    // copy carries `id` as the stack block had it.
    poll::wake(unsafe { (*block).id });
}
