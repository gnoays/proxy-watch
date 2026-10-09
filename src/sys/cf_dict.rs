//! Core Foundation proxies dictionaries, converted into [`ProxyDict`] for
//! [`super::proxy_dict`] to interpret. macOS reads them out of `SCDynamicStore` and iOS out
//! of `CFNetworkCopySystemProxySettings`; both are `CFString`-keyed with the same schema.

use std::ffi::c_void;

use core_foundation::array::{CFArray, CFArrayGetValueAtIndex};
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;

use super::proxy_dict::{self, DictValue, ProxyDict};

// `CFString::to_string()` (`Display`, which every call site below goes through) calls into
// `core-foundation` 0.10.1's own `Cow<str>: From<&CFString>`. For content its
// UTF-8-fast-path pointer cannot serve, that impl asks `CFStringGetBytes` to reencode with
// `lossByte: 0` and then does `assert_eq!(chars_written, char_len)`, so a CFString holding
// an unpaired UTF-16 surrogate (not data this crate ever writes, but not something
// `SCDynamicStore` refuses to hand back either) makes `to_string()` panic instead of
// returning anything. There is no lossy-fallback entry point in the public API to reach for
// instead, unlike Windows' `to_string_lossy()` (`super::win::ffi::wide_ptr_to_string`).
// Catching the unwind here keeps one malformed key or value from taking the whole read
// down, the same way an unmodeled Core Foundation type already does not (see
// `to_dict_value`'s `None` branch). The process's default panic hook still prints the
// message once to stderr: swapping it out here, process-wide, for what is a
// same-thread-only concern is not worth the race it would risk against any other thread
// panicking at the same moment. This only holds where panics unwind:
// `std::panic::catch_unwind` "only catches unwinding panics, not those that abort the
// process" (`library/std/src/panic.rs`), so under `panic = "abort"` such a string aborts
// the process, and nothing in this crate can prevent that there.
pub(super) fn cf_string_to_string(value: &CFString) -> Option<String> {
    std::panic::catch_unwind(|| value.to_string()).ok()
}

// Convert the Core Foundation dictionary into plain Rust data.
pub(super) fn to_proxy_dict(dictionary: &CFDictionary) -> ProxyDict {
    let mut dict = ProxyDict::new();
    let (keys, values) = dictionary.get_keys_and_values();
    for (key, value) in keys.into_iter().zip(values) {
        if key.is_null() || value.is_null() {
            continue;
        }
        // SAFETY: `get_keys_and_values` yields the dictionary's own key and value
        // pointers, which are valid for as long as `dictionary` is borrowed here, and each
        // is a Core Foundation object. `wrap_under_get_rule` retains, so the temporaries do
        // not steal the dictionary's references.
        let (key, value) = unsafe {
            (
                CFType::wrap_under_get_rule(key),
                CFType::wrap_under_get_rule(value),
            )
        };
        // Checked rather than assumed: the documented keys are all `CFString`, but a
        // `CFDictionaryRef` is untyped, and reading a key of another type as a string is
        // undefined behaviour rather than a panic `cf_string_to_string` could catch.
        let Some(key) = key.downcast::<CFString>() else {
            continue;
        };
        // Dropped outright, where an unreadable *value* under a known key is recorded a few
        // lines below: every key in [`proxy_dict`]'s schema is a Rust `&str` literal, so a
        // `CFString` that does not reencode equals none of them, and what is dropped is a
        // key the crate has no schema for. No test builds such a key: the value-side
        // drop below is what `an_unreadable_value_under_an_unread_key_is_still_dropped`
        // holds.
        let Some(key) = cf_string_to_string(&key) else {
            crate::trace::warning!(
                "a proxies dictionary key holds content that could not be reencoded as \
                 UTF-8; skipping the entry, which no key this crate reads can reach"
            );
            continue;
        };
        match to_dict_value(&value) {
            Some(value) => dict.insert(key, value),
            // Dropping the entry is only harmless under a key nothing reads. Under a key
            // [`proxy_dict`] *does* read, the drop collapses onto the absent case, and
            // absence changes the answer there: an absent `HTTPEnable` makes
            // [`proxy_dict::mode_from_dict`] skip the scheme outright, and an absent
            // `HTTPPort` reads as "no port configured" rather than as an unusable one. The
            // result is a plausible-looking configuration with a scheme missing without a
            // rejection record: the fail-open [`proxy_dict`] records a [`RejectedValue`]
            // over everywhere else. So the key arrives carrying [`DictValue::Unreadable`],
            // which says it was set without claiming to know what to; the readers over
            // there decide from the key alone whether that is worth recording. The value
            // itself is never carried and never logged; the key names alone are the fixed
            // schema spelled out in [`proxy_dict`].
            //
            // The warning stays because it names the *cause*, which no `RejectedValue`
            // can: from over there an unconvertible `CFData` and a `CFString` that will
            // not reencode are the same key. It is also the only channel at all on a build
            // without the `tracing` feature, which is every default build, and the reason
            // the record above is not left to it.
            None => {
                if proxy_dict::is_known_key(&key) {
                    crate::trace::warning!(
                        key = key.as_str(),
                        "a proxies key this crate reads holds a Core Foundation value this \
                         crate could not convert to its schema (not a string, number, \
                         boolean or array — or a string whose content could not be \
                         reencoded as UTF-8); recording it as set but unreadable"
                    );
                    dict.insert(key, DictValue::Unreadable);
                }
            }
        }
    }
    dict
}

// Map one Core Foundation value onto a [`DictValue`], or `None` for a type the schema
// does not use. [`to_proxy_dict`] is what decides whether that `None` is worth a warning:
// it is the only caller, and only it knows the key.
fn to_dict_value(value: &CFType) -> Option<DictValue> {
    if let Some(text) = value.downcast::<CFString>() {
        return cf_string_to_string(&text).map(DictValue::Text);
    }
    if let Some(number) = value.downcast::<CFNumber>() {
        return number.to_i64().map(DictValue::Number);
    }
    if let Some(flag) = value.downcast::<CFBoolean>() {
        return Some(DictValue::Number(i64::from(bool::from(flag))));
    }
    if value.instance_of::<CFArray>() {
        let (items, unreadable) = strings_in(value);
        return Some(DictValue::List { items, unreadable });
    }
    None
}

// Collect the `CFString` elements of a `CFArray`, and count the elements that were not one.
//
// The count is what a dropped element costs under `ExceptionsList`: one bypass rule the
// user configured, so one internal host reached through the proxy instead of past it.
// Silently returning a shorter list is the fail-open this crate refuses a port over, and
// unlike the key skip in [`to_proxy_dict`], nothing rules the case out, because the
// elements of a `CFArray` are whatever `configd` was handed.
// [`proxy_dict::bypass_from_dict`] turns the count into one
// [`RejectedValue`](crate::diagnostic::RejectedValue) apiece; nothing of the elements
// themselves travels, for the reason [`DictValue::Unreadable`] carries nothing.
fn strings_in(value: &CFType) -> (Vec<String>, usize) {
    // SAFETY: the caller checked `instance_of::<CFArray>()`, so the pointer is a
    // `CFArrayRef`; `wrap_under_get_rule` retains it for the lifetime of `array`.
    let array =
        unsafe { CFArray::<*const c_void>::wrap_under_get_rule(value.as_CFTypeRef().cast()) };

    let mut out = Vec::new();
    let mut unreadable = 0;
    for index in 0..array.len() {
        // SAFETY: `index` is below `CFArrayGetCount`, and `array` is alive here.
        let item = unsafe { CFArrayGetValueAtIndex(array.as_concrete_TypeRef(), index) };
        // Counted with the rest: the array said it had an element here, and it is gone.
        if item.is_null() {
            unreadable += 1;
            continue;
        }
        // SAFETY: the elements of a proxies-dictionary array are Core Foundation
        // objects owned by the array, which outlives this borrow; `wrap_under_get_rule`
        // retains so the array keeps its own reference.
        let item = unsafe { CFType::wrap_under_get_rule(item) };
        match item
            .downcast::<CFString>()
            .and_then(|text| cf_string_to_string(&text))
        {
            Some(text) => out.push(text),
            None => unreadable += 1,
        }
    }
    (out, unreadable)
}
