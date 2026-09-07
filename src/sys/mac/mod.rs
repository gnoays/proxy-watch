//! The macOS backend.
//!
//! # ⚠ CI-verified only — no macOS dev machine
//!
//! Cross-compiled from Windows; exercised on `macos-latest` CI (`tests/mac_watch.rs`).
//! Under `CI=1`, self-skip is failure.
//!
//! **Unverified:** registration retry, PrimaryService, and the GUI session — no macOS
//! hardware has ever run this backend, only the CI runner.
//! **Risk:** a `configd` that is slow to answer, or a proxy set on a network service that
//! is not the primary one, reads as "nothing is configured" instead of as an error,
//! because a missing key is deliberately not an error here. The registration retry
//! named just above does not cover it: that retry fires only while the session itself
//! cannot be opened, and a `configd` that opens a session and then answers with no key
//! never reaches it.
//! **Symptom:** on a Mac whose System Settings show a proxy on some *other* service than
//! the one carrying traffic, the stream yields [`ProxyMode::Direct`] and never publishes
//! an error; `RUST_LOG=proxy_watch=debug` shows both proxies keys reading successfully
//! with nothing in them.
//!
//! Configuring a proxy per network service is the only way macOS offers, so that is not
//! itself the risk: configd's IPMonitor builds the global key this backend reads from the
//! *primary* service (see [`super::proxy_dict`]), which is also the one key
//! `SCDynamicStoreCopyProxies` reads and the one Chromium and libproxy read. A proxy on
//! the service actually carrying traffic arrives here;
//! `tests/mac_watch.rs::a_sudo_networksetup_change_is_observed` sets one through
//! `networksetup` on a real service and requires the watcher to emit it.
//!
//! Two further readings reach that same [`ProxyMode::Direct`] and are not the same thing:
//! a copy that reports no error and still hands back NULL, and a value that is not a
//! `CFDictionary`. [`interpret_copied_value`] folds both into "absent", which is what the
//! Windows reader does with a registry value stored under a type its name does not carry —
//! this crate guesses at a malformed reading on neither platform. Neither is how absence
//! normally arrives, though: `an_absent_key_reports_no_key_and_is_not_an_error` asks a
//! real runner what a genuinely missing key reports, and the answer is
//! [`SC_STATUS_NO_KEY`]. So both fold *anomalies* into absence, and both log a warning
//! naming the key — that warning, not the `debug` line above, is what tells the two
//! apart. No `configd` can be asked to produce either, which is why the copy is injected
//! there rather than taken in place.
//!
//! Reads [`SETUP_PROXIES_KEY`] and [`STATE_PROXIES_KEY`] via `SCDynamicStore`, merged
//! State-first — the key `SCDynamicStoreCopyProxies` reads (see [`super::proxy_dict`]).
//! Missing key omitted, not Direct. **⚠** global `Setup:/Network/Global/Proxies` may not
//! exist at all; `Setup:` is reported in `sources` and loses to `State:` — except when
//! `State:` is the key that is missing, where it is the only reading there is. A `Setup:`
//! that exists but cannot be read is omitted from `sources` on the same ground, with a
//! warning, and fails the read only in that same no-`State:` case.
//!
//! Global dict only (no per-service); an enabled `GopherEnable`/`RTSPEnable` is never
//! routed through but is still recorded (see [`super::proxy_dict`]);
//! [`WatchOptions::watch_group_policy`] ignored.

mod notify;

use std::ffi::{c_int, c_void};
use std::io;

use core_foundation::array::{CFArray, CFArrayGetValueAtIndex};
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::propertylist::CFPropertyList;
use core_foundation::string::CFString;
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};

use crate::config::ProxyConfig;
use crate::error::Error;
use crate::mode::ProxyMode;
use crate::watch::WatchOptions;

use super::proxy_dict::{self, DictValue, ProxyDict};

pub(crate) use self::notify::Watch;

// The session name passed to `SCDynamicStoreCreateWithOptions`. It is only a label for
// diagnostics such as `scutil`.
const STORE_NAME: &str = "proxy-watch";

// `SCError()` — per-thread status of the last System Configuration call on this thread.
// Hand-written FFI: tiny surface, no safe equivalent (`system-configuration` drops errors to `None`).
#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCError() -> c_int;
}

// `kSCStatusOK`, from the status enum in `<SystemConfiguration/SystemConfiguration.h>`.
const SC_STATUS_OK: c_int = 0;

// `kSCStatusNoKey` — "no such key" (`1004`). Spelled out because `system-configuration-sys`
// does not export the enum; `system-configuration` 0.7 still collapses CopyValue to `None`.
const SC_STATUS_NO_KEY: c_int = 1004;

// The `State:` dynamic store key that carries the global proxy settings.
pub(crate) const STATE_PROXIES_KEY: &str = "State:/Network/Global/Proxies";

// The `Setup:` counterpart to [`STATE_PROXIES_KEY`], so that the two scopes can be
// reported and merged separately.
pub(crate) const SETUP_PROXIES_KEY: &str = "Setup:/Network/Global/Proxies";

// Read the current configuration.
//
// `options` is unused: [`WatchOptions::watch_group_policy`] names one Windows registry key,
// and there is no second store for it to turn on here — this reader has `SCDynamicStore`
// and nothing else. That is not the claim that no administrator can impose a proxy on a
// Mac: MDM does, through `GlobalHTTPProxy` (macOS 10.9, device channel) and
// `NetworkProxyConfiguration` (macOS 10.7). Where those land is a question about the keys
// read below, not about this flag.
pub(crate) fn read_config(_options: &WatchOptions) -> Result<ProxyConfig, Error> {
    let store = create_store()?;
    read_both_scopes(|key| read_scope(&store, key))
}

// Which raw key feeds which half of [`merge_setup_and_state`], and which of the two
// failures is fatal.
//
// `read` is injected because that binding is the entire content of this function and no
// machine can be asked to make the keys tell themselves apart: a runner's `Setup:` and
// `State:` scopes hold whatever the fleet was configured with, which is nothing, so
// exchanging the constants below changed no assertion anywhere. The pure merge tests over
// in [`proxy_dict`] cannot see it either — they take arguments already named `setup` and
// `state`. An injected reader can hand each key an answer only it could have given.
fn read_both_scopes(
    read: impl Fn(&str) -> Result<Option<ProxyMode>, Error>,
) -> Result<ProxyConfig, Error> {
    // `State:` is read first and with `?`, `Setup:` second and without: which of the two
    // failures ends the read is [`merge_setup_and_state`]'s rule, not this function's, and
    // it needs the `State:` scope to apply it.
    let state = read(STATE_PROXIES_KEY)?;
    let setup = read(SETUP_PROXIES_KEY);
    crate::trace::debug!(
        setup_present = setup.as_ref().is_ok_and(Option::is_some),
        state_present = state.is_some(),
        "read the SCDynamicStore proxies keys"
    );
    let config = proxy_dict::merge_setup_and_state(setup, state)?;
    crate::trace::debug!(
        config = %crate::trace::ConfigSummary(&config),
        "read the macOS proxy configuration"
    );
    Ok(config)
}

// Open a session with the System Configuration server, retrying the early-boot race.
//
// The cost, accepted when the retry went in: [`read_config`] also runs on the watcher
// thread for every notification, so a configd that dies mid-session blocks that thread —
// and a concurrent `Drop`'s `join` — for up to five seconds instead of failing at once.
// Waiting beats publishing an error for a daemon that is very likely coming back.
fn create_store() -> Result<SCDynamicStore, Error> {
    let mut attempt = 0;
    loop {
        if let Some(store) = SCDynamicStoreBuilder::new(STORE_NAME).build() {
            return Ok(store);
        }
        if !notify::should_retry(attempt) {
            return Err(Error::io(
                "creating an SCDynamicStore session",
                io::Error::other("SCDynamicStoreCreateWithOptions returned NULL"),
            ));
        }
        crate::trace::warning!(
            attempt = attempt + 1,
            max_retries = notify::REGISTRATION_MAX_RETRIES,
            "SCDynamicStoreCreateWithOptions returned NULL; retrying (configd may still \
             be starting)"
        );
        attempt += 1;
        std::thread::sleep(notify::REGISTRATION_RETRY_INTERVAL);
    }
}

// Read one scope (`Setup:` or `State:`) of the global proxies key through `store` and
// interpret it.
fn read_scope(store: &SCDynamicStore, key: &str) -> Result<Option<ProxyMode>, Error> {
    // SAFETY: `SCError` is a nullary `int`-returning C function reporting the status of the
    // `SCDynamicStoreCopyValue` that `SCDynamicStore::get` just made — `get` does nothing
    // between that call and its return, and `SCError` is per-thread, so no other System
    // Configuration call can have overwritten it in between. Both reads sit inside this one
    // closure so that nothing can be introduced between them later: what
    // [`interpret_copied_value`] receives is the pair, already taken.
    interpret_copied_value(key, || (store.get(key), unsafe { SCError() }))
}

// Interpret what one `SCDynamicStoreCopyValue` handed back, together with the `SCError()`
// that went with it.
//
// `copy` is injected for the reason [`super::win`]'s `read_user_mode` injects its query:
// which arm below answers is decided by *how* the copy came back, and a live `configd` can
// be asked for exactly one of the four — a real value under a real key. A NULL that reports
// success, a NULL under a status this code does not name, and a value that is not a
// dictionary are all shapes no store can be made to produce on demand, and all three are
// fail-softs that decide whether a machine reads as "no proxy" or as an error.
fn interpret_copied_value(
    key: &str,
    copy: impl FnOnce() -> (Option<CFPropertyList>, c_int),
) -> Result<Option<ProxyMode>, Error> {
    let (value, status) = copy();
    let Some(value) = value else {
        return match status {
            SC_STATUS_NO_KEY => {
                crate::trace::debug!(key, "the dynamic store has no such key");
                Ok(None)
            }
            SC_STATUS_OK => {
                crate::trace::warning!(
                    key,
                    "SCDynamicStoreCopyValue returned NULL but recorded no error; \
                     treating the key as absent"
                );
                Ok(None)
            }
            status => Err(Error::io(
                "reading a proxies key from the SCDynamicStore",
                io::Error::other(format!(
                    "SCDynamicStoreCopyValue({key}) failed with SCError() = {status}"
                )),
            )),
        };
    };
    let Some(dictionary) = CFPropertyList::downcast_into::<CFDictionary>(value) else {
        crate::trace::warning!(
            key,
            "the dynamic store value is not a CFDictionary; treating the key as absent"
        );
        return Ok(None);
    };
    proxy_dict::mode_from_dict(&to_proxy_dict(&dictionary)).map(Some)
}

// `CFString::to_string()` (`Display`, which every call site below goes through) calls
// into `core-foundation` 0.9.4's own `Cow<str>: From<&CFString>`. For content its
// UTF-8-fast-path pointer cannot serve, that impl asks `CFStringGetBytes` to reencode
// with `lossByte: 0` and then does `assert_eq!(chars_written, char_len)` — so a CFString
// holding an unpaired UTF-16 surrogate (not data this crate ever writes, but not
// something `SCDynamicStore` refuses to hand back either) makes `to_string()` panic
// instead of returning anything. There is no lossy-fallback entry point in the public
// API to reach for instead, unlike Windows' `to_string_lossy()`
// (`super::win::ffi::wide_ptr_to_string`). Catching the unwind here keeps one malformed
// key or value from taking the whole read down, the same way an unmodeled Core
// Foundation type already does not (see `to_dict_value`'s `None` branch). The process's
// default panic hook still prints the message once to stderr: swapping it out here,
// process-wide, for what is a same-thread-only concern is not worth the race it would
// risk against any other thread panicking at the same moment. This only holds where panics
// unwind: `std::panic::catch_unwind` "only catches unwinding panics, not those that abort
// the process" (`library/std/src/panic.rs`), so a build with `panic = "abort"` gets exactly
// the pre-`catch_unwind` behaviour back. Nothing in this crate can restore it there.
fn cf_string_to_string(value: &CFString) -> Option<String> {
    std::panic::catch_unwind(|| value.to_string()).ok()
}

// Convert the Core Foundation dictionary into plain Rust data.
fn to_proxy_dict(dictionary: &CFDictionary) -> ProxyDict {
    let mut dict = ProxyDict::new();
    let (keys, values) = dictionary.get_keys_and_values();
    for (key, value) in keys.into_iter().zip(values) {
        if key.is_null() || value.is_null() {
            continue;
        }
        // SAFETY: `get_keys_and_values` yields the dictionary's own key and value
        // pointers, which are valid for as long as `dictionary` is borrowed here. Both
        // `Setup:` and `State:` proxies dictionaries are documented (and, for `State:`,
        // confirmed by `SCDynamicStoreCopyProxies`'s own contract) to be keyed by
        // `CFString`, so the key pointer really is a `CFStringRef`. `wrap_under_get_rule`
        // retains, so the temporaries do not steal the dictionary's references.
        let (key, value) = unsafe {
            (
                CFString::wrap_under_get_rule(key.cast()),
                CFType::wrap_under_get_rule(value),
            )
        };
        // Dropped outright, where an unreadable *value* under a known key is recorded a few
        // lines below. The asymmetry is not a gap: a key that fails here cannot be one this
        // crate reads. Every key in [`proxy_dict`]'s schema is written as a Rust `&str`
        // literal, so each is well-formed UTF-8 and reencodes; a `CFString` whose content
        // does not reencode is therefore equal to none of them, and what is dropped is a key
        // the crate has no schema for — the case
        // `an_unreadable_value_under_an_unread_key_is_still_dropped` establishes must be
        // dropped rather than put in front of a caller as a value it lost. That follows from
        // the type of those constants rather than from an invariant that could drift, which
        // is why nothing below holds it.
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
            // absence is load-bearing there: an absent `HTTPEnable` makes
            // [`proxy_dict::mode_from_dict`] skip the scheme outright, and an absent
            // `HTTPPort` reads as "no port configured" rather than as an unusable one. The
            // result is a plausible-looking configuration with a scheme quietly missing —
            // the fail-open [`proxy_dict`] records a [`RejectedValue`] over everywhere
            // else, and it does not stop being one because the value was lost a layer
            // earlier. So the key arrives carrying [`DictValue::Unreadable`], which says
            // it was set without claiming to know what to; the readers over there decide
            // from the key alone whether that is worth recording. The value itself is
            // never carried and never logged; the key names alone are the fixed schema
            // spelled out in [`proxy_dict`].
            //
            // The warning stays because it names the *cause*, which no `RejectedValue`
            // can: from over there an unconvertible `CFData` and a `CFString` that will
            // not reencode are the same key. It is also the only channel at all on a build
            // without the `tracing` feature — which is every default build, and the reason
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
// The count is what a dropped element costs under `ExceptionsList`: one bypass rule the user
// configured, so one internal host reached through the proxy instead of past it. Silently
// returning a shorter list is the fail-open this crate refuses a port over — and unlike the
// key skip in [`to_proxy_dict`], nothing rules the case out, because the elements of a
// `CFArray` are whatever `configd` was handed. [`proxy_dict::bypass_from_dict`] turns the
// count into one [`RejectedValue`](crate::diagnostic::RejectedValue) apiece; nothing of the
// elements themselves travels, for the reason [`DictValue::Unreadable`] carries nothing.
fn strings_in(value: &CFType) -> (Vec<String>, usize) {
    // SAFETY: the caller checked `instance_of::<CFArray>()`, so the pointer really is a
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

#[cfg(test)]
mod tests {
    //! These run only on CI's `macos-latest` runner, which is this backend's only execution
    //! environment — see [`notify`]'s test module for the same caveat and what it does and
    //! does not buy.
    //!
    //! Running is the only part that needs the runner. This module *compiles* on a Windows
    //! development machine through `cargo check --target aarch64-apple-darwin --all-targets`,
    //! which reaches the lib test target and so type checks everything below; a rustup
    //! target is all it takes, because `check` never links. What that catches is a rename
    //! or a signature drift, and what it cannot catch is an assertion that is simply false.
    //! `.github/workflows/mac-tests.yml` is the dispatch that answers the rest without
    //! booting the whole board.
    //!
    //! The two `create_store` tests below need a live `configd`. The conversion tests do
    //! not: they build the Core Foundation dictionary in process, so they cover
    //! [`to_proxy_dict`] with *known* input — which is what the runner's own proxy
    //! configuration can never give. [`super::super::proxy_dict`] is table-driven-tested
    //! on every target; these close the gap between that table and the Core Foundation
    //! values it is actually fed.

    use core_foundation::data::CFData;
    use core_foundation::propertylist::CFPropertyListSubClass;

    use crate::config::ProxyConfigSource;
    use crate::diagnostic::RejectionKind;
    use crate::endpoint::Scheme;

    use super::*;

    // Build an untyped `CFDictionary` the way `SCDynamicStoreCopyValue` hands one over:
    // `CFString` keys, arbitrary Core Foundation values.
    fn cf_dict(pairs: &[(&str, CFType)]) -> CFDictionary {
        let pairs: Vec<(CFString, CFType)> = pairs
            .iter()
            .map(|(key, value)| (CFString::new(key), value.clone()))
            .collect();
        CFDictionary::from_CFType_pairs(&pairs).into_untyped()
    }

    fn expect(pairs: &[(&str, DictValue)]) -> ProxyDict {
        let mut dict = ProxyDict::new();
        for (key, value) in pairs {
            dict.insert(*key, value.clone());
        }
        dict
    }

    // Every Core Foundation type [`to_dict_value`] models, in one dictionary.
    #[test]
    fn the_modelled_value_types_convert() {
        let converted = to_proxy_dict(&cf_dict(&[
            ("HTTPProxy", CFString::new("proxy.corp").as_CFType()),
            ("HTTPPort", CFNumber::from(3128i64).as_CFType()),
            ("HTTPEnable", CFBoolean::true_value().as_CFType()),
            ("FTPEnable", CFBoolean::false_value().as_CFType()),
            (
                "ExceptionsList",
                CFArray::from_CFTypes(&[CFString::new("*.internal")]).as_CFType(),
            ),
        ]));

        assert_eq!(
            converted,
            expect(&[
                ("HTTPProxy", DictValue::Text("proxy.corp".to_owned())),
                ("HTTPPort", DictValue::Number(3128)),
                // `CFBoolean` and `CFNumber` both land on `DictValue::Number`, which is
                // what lets `ProxyDict::flag` read `HTTPEnable` either way round.
                ("HTTPEnable", DictValue::Number(1)),
                ("FTPEnable", DictValue::Number(0)),
                (
                    "ExceptionsList",
                    DictValue::List {
                        items: vec!["*.internal".to_owned()],
                        unreadable: 0,
                    }
                ),
            ])
        );
    }

    // The whole path, end to end: Core Foundation dictionary in, [`ProxyMode`] out. The
    // table-driven tests in [`super::super::proxy_dict`] start one step later, from a
    // hand-built [`ProxyDict`]; the tests in this module are the ones that tie the two
    // halves together, and this is the one that walks a realistic dictionary rather
    // than the consequence of a single rejected value.
    #[test]
    fn a_realistic_dictionary_reaches_the_expected_mode() {
        let converted = to_proxy_dict(&cf_dict(&[
            ("HTTPEnable", CFBoolean::true_value().as_CFType()),
            ("HTTPProxy", CFString::new("proxy.corp").as_CFType()),
            ("HTTPPort", CFNumber::from(3128i64).as_CFType()),
            ("SOCKSEnable", CFBoolean::false_value().as_CFType()),
            (
                "ExceptionsList",
                CFArray::from_CFTypes(&[CFString::new("*.internal"), CFString::new("localhost")])
                    .as_CFType(),
            ),
        ]));

        let mode = proxy_dict::mode_from_dict(&converted).expect("a well formed dictionary");
        assert_eq!(
            mode.endpoint_for(Scheme::Http)
                .expect("HTTP is enabled with a host")
                .authority(),
            "proxy.corp:3128"
        );
        assert!(
            mode.entry_for(Scheme::Socks)
                .expect("SOCKSEnable = 0 records an explicit entry")
                .is_disabled()
        );
    }

    // Keys the crate has no schema for are still carried through, because
    // [`ProxyDict`]'s `Debug` masks them rather than dropping them: what is logged is
    // the shape of the unread key, never its contents.
    #[test]
    fn an_unknown_key_is_carried_through() {
        let converted = to_proxy_dict(&cf_dict(&[(
            "ProxyWatchNoSuchKey",
            CFString::new("whatever").as_CFType(),
        )]));
        assert_eq!(
            converted,
            expect(&[(
                "ProxyWatchNoSuchKey",
                DictValue::Text("whatever".to_owned())
            )])
        );
    }

    // An array contributes only its `CFString` elements ([`strings_in`]), and says how many
    // it left behind. Holding the shortening on its own is not enough, because a shortened
    // bypass list is the one drop in this file that costs the user something: the host they
    // excluded is reached through the proxy. `<2 strings>` is what the sibling readers
    // would have made of it, but nothing asks them — the count is read by
    // [`super::super::proxy_dict::bypass_from_dict`], which is where the record is raised.
    #[test]
    fn non_string_array_elements_are_skipped_and_counted() {
        let converted = to_proxy_dict(&cf_dict(&[(
            "ExceptionsList",
            CFArray::from_CFTypes(&[
                CFString::new("*.internal").as_CFType(),
                CFNumber::from(7i64).as_CFType(),
            ])
            .as_CFType(),
        )]));
        assert_eq!(
            converted,
            expect(&[(
                "ExceptionsList",
                DictValue::List {
                    items: vec!["*.internal".to_owned()],
                    unreadable: 1,
                }
            )]),
            "the dropped element has to be counted — and when only the count differs the two \
             sides above print alike, because `ProxyDict`'s `Debug` deliberately says nothing \
             about members it could not read"
        );
    }

    // The case [`to_proxy_dict`] warns about, and what it does instead of dropping: a value
    // type the schema does not model still marks the key as *set*. Dropping it left the key
    // absent, and absence is not neutral —
    // [`super::super::proxy_dict::mode_from_dict`] skips a scheme whose `…Enable` key it
    // cannot see, so the mode came back indistinguishable from one where HTTP was never
    // configured, with the warning as its only trace and that warning compiled out of every
    // build without the `tracing` feature.
    #[test]
    fn an_unmodelled_value_type_marks_the_key_unreadable() {
        let converted = to_proxy_dict(&cf_dict(&[
            ("HTTPEnable", CFData::from_buffer(&[1, 2, 3]).as_CFType()),
            ("HTTPProxy", CFString::new("proxy.corp").as_CFType()),
        ]));

        assert_eq!(
            converted,
            expect(&[
                ("HTTPEnable", DictValue::Unreadable),
                ("HTTPProxy", DictValue::Text("proxy.corp".to_owned())),
            ]),
            "the CFData's contents must not reach ProxyDict, but the key must"
        );
        // What the reader then does with that key is not asserted here.
        // `proxy_dict`'s own `a_value_lost_at_the_core_foundation_boundary_is_recorded_under_
        // every_reader` pins the record for this exact key, and
        // `a_drop_under_one_scheme_takes_no_other_schemes_answer` pins the
        // [`Error::ProxyEntryUnusable`](crate::Error::ProxyEntryUnusable) a request gets
        // instead of Direct — both in a module that runs on every platform. A copy over here
        // would only be a rule that costs a macOS runner to keep true, and that cost is
        // real: the obvious such rule, asserting no entry at all, is one
        // [`ProxyMode::with_rejected`] has not satisfied since it began filling an
        // unanswered scheme with [`ProxyEntry::Unusable`](crate::ProxyEntry::Unusable).
    }

    // A key nothing reads is still dropped, and the warning above is still not raised for
    // it: recording it would put a [`RejectedValue`] in front of a caller for a setting
    // that never had an answer to lose. This is the other side of the arm above, and the
    // reason it asks [`proxy_dict::is_known_key`] first.
    #[test]
    fn an_unreadable_value_under_an_unread_key_is_still_dropped() {
        let converted = to_proxy_dict(&cf_dict(&[(
            "ProxyWatchNoSuchKey",
            CFData::from_buffer(&[1, 2, 3]).as_CFType(),
        )]));
        assert_eq!(converted, expect(&[]));
    }

    // A third way a modelled type still yields `None`: a `CFString` value can hold
    // content `CFString::to_string()` cannot losslessly reencode as UTF-8 (an unpaired
    // UTF-16 surrogate). Before `cf_string_to_string` caught the unwind, this panicked
    // — see its doc comment for the `core-foundation` internals that made it possible —
    // instead of taking the same unreadable path a `CFData` or a non-integral number
    // already do. That the three arrive at one `DictValue` is the point: the reader over
    // in [`proxy_dict`] answers from the key, and none of the three left it a value.
    #[test]
    fn a_string_that_cannot_be_reencoded_as_utf8_is_unreadable_not_absent() {
        // A lone UTF-16 surrogate has no UTF-8 representation.
        let chars: [core_foundation::string::UniChar; 1] = [0xD800];
        let malformed = unsafe {
            let string_ref = core_foundation::string::CFStringCreateWithCharacters(
                core_foundation::base::kCFAllocatorDefault,
                chars.as_ptr(),
                1,
            );
            CFString::wrap_under_create_rule(string_ref)
        };
        assert_eq!(cf_string_to_string(&malformed), None);

        let converted = to_proxy_dict(&cf_dict(&[
            ("HTTPEnable", CFData::from_buffer(&[1, 2, 3]).as_CFType()),
            ("HTTPProxy", malformed.as_CFType()),
        ]));
        assert_eq!(
            converted,
            expect(&[
                ("HTTPEnable", DictValue::Unreadable),
                ("HTTPProxy", DictValue::Unreadable),
            ]),
            "a HTTPProxy value that cannot be reencoded as UTF-8 must not reach ProxyDict"
        );
    }

    // The other way a modelled type still yields `None`: `CFNumber::to_i64` reports a
    // lossy conversion rather than truncating, so a non-integral number under a port key
    // takes the same unreadable path as an unmodelled type.
    //
    // This is the one where dropping costs most. An *absent* port means "never filled in",
    // and the scheme's default is dialled — so a dropped `3128.5` sends the request to
    // `proxy.corp:80`, a port the user never named, and leaves nothing to say so. The
    // reference does the same thing by a different route (`ProxyDictionaryToProxyChain`
    // truncates), and [`ProxyDict::port_is_unusable`] is where this crate says it will not.
    #[test]
    fn a_lossy_number_is_unreadable_not_absent() {
        let converted = to_proxy_dict(&cf_dict(&[
            ("HTTPEnable", CFBoolean::true_value().as_CFType()),
            ("HTTPProxy", CFString::new("proxy.corp").as_CFType()),
            ("HTTPPort", CFNumber::from(3128.5f64).as_CFType()),
        ]));

        assert_eq!(
            converted,
            expect(&[
                ("HTTPEnable", DictValue::Number(1)),
                ("HTTPProxy", DictValue::Text("proxy.corp".to_owned())),
                ("HTTPPort", DictValue::Unreadable),
            ])
        );

        let mode = proxy_dict::mode_from_dict(&converted).expect("a well formed dictionary");
        assert!(
            mode.endpoint_for(Scheme::Http).is_none(),
            "the scheme default may not stand in for a port that was filled in"
        );
        let rejected = mode.rejected().expect("a manual mode carries the list");
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0].kind(), RejectionKind::InvalidProxyEndpoint);
        assert_eq!(rejected[0].affected_scheme(), Some(Scheme::Http));
    }

    // The premise of [`read_scope`]'s NULL handling: `SCDynamicStoreCopyValue` reports
    // [`SC_STATUS_NO_KEY`] — and specifically the value `1004` this file spells out by
    // hand — for a key that genuinely does not exist, so an absent key stays `Ok(None)`
    // and does not become an `Err`.
    //
    // `read_scope`'s answer alone does not hold that, however much it looks as though it
    // does. [`SC_STATUS_OK`] returns `Ok(None)` as well, so a machine that reported *no
    // error at all* for a missing key would satisfy `matches!(result, Ok(None))` unchanged,
    // leaving the constant held by nothing. The status is therefore read directly, first. What
    // that buys beyond the constant is the one fact the two branches cannot establish about
    // themselves: absence is normally reported as [`SC_STATUS_NO_KEY`], so an
    // `SC_STATUS_OK` with a NULL value is an anomaly — which is why it warns where the
    // other only logs, and why folding it into "absent" is a fail-soft rather than the
    // ordinary path.
    #[test]
    fn an_absent_key_reports_no_key_and_is_not_an_error() {
        let store = create_store().expect("configd answers on the macOS runner");
        let key = "Setup:/Network/Global/ProxyWatchNoSuchKey";

        let value = store.get(key);
        // SAFETY: as in [`read_scope`] — `SCDynamicStore::get` does nothing between its own
        // `SCDynamicStoreCopyValue` and the line above, and `SCError` is per-thread.
        let status = unsafe { SCError() };
        assert!(
            value.is_none(),
            "the key must be absent for this to measure anything"
        );
        assert_eq!(
            status, SC_STATUS_NO_KEY,
            "SCError() after a key that does not exist"
        );

        let result = read_scope(&store, key);
        assert!(matches!(result, Ok(None)), "{result:?}");
    }

    // Which raw key reaches which argument of [`merge_setup_and_state`]. Exchanging the two
    // constants changes no assertion elsewhere: the merge tests in [`proxy_dict`] are
    // handed arguments already named `setup` and `state`, and `tests/mac_watch.rs` reads a
    // runner whose scopes are both empty, so the swap gives the same empty answer either
    // way. Here each key returns something only it could have returned, and the public
    // labels are read back — which is also what makes the `State:`-wins precedence
    // observable from outside rather than only inside the merge.
    #[test]
    fn each_scope_key_reaches_the_argument_named_after_it() {
        let configured = ProxyMode::pac(url::Url::parse("http://setup.example/proxy.pac").unwrap());
        let config = read_both_scopes(|key| {
            Ok(Some(match key {
                SETUP_PROXIES_KEY => configured.clone(),
                STATE_PROXIES_KEY => ProxyMode::WpadAutoDetect,
                other => panic!("read a key neither scope names: {other}"),
            }))
        })
        .expect("both scopes answered");

        assert_eq!(
            config.sources,
            vec![
                (
                    ProxyConfigSource::SystemConfigurationState,
                    ProxyMode::WpadAutoDetect
                ),
                (ProxyConfigSource::SystemConfigurationSetup, configured),
            ]
        );
        assert_eq!(config.effective, ProxyMode::WpadAutoDetect);
    }

    // A NULL copy that reports success, and a NULL copy under a status this file does not
    // name. Neither is a shape a live `configd` can be asked for, so
    // [`an_absent_key_reports_no_key_and_is_not_an_error`] above leaves both untouched — it
    // can only produce the ordinary absence. Each decides whether a machine reads as "no
    // proxy configured" or as a failure, and a runner's own configuration cannot produce
    // either; the injected copy is what makes them reachable at all.
    //
    // A status of `1003` is used for the failing row only because it is neither
    // [`SC_STATUS_OK`] nor [`SC_STATUS_NO_KEY`]; what that code means is not the subject
    // here and is not asserted.
    #[test]
    fn only_a_named_status_folds_a_null_copy_into_absence() {
        let anomaly = interpret_copied_value(STATE_PROXIES_KEY, || (None, SC_STATUS_OK));
        assert!(
            matches!(anomaly, Ok(None)),
            "a NULL that reports success is an anomaly, but still absence: {anomaly:?}"
        );

        let failure = interpret_copied_value(STATE_PROXIES_KEY, || (None, 1003));
        let failure = failure.expect_err("an unnamed status must not read as no proxy");
        let reported = format!("{failure:?}");
        assert!(
            reported.contains(STATE_PROXIES_KEY) && reported.contains("1003"),
            "the error has to name the key and the status it came back with: {reported}"
        );
    }

    // The value arm of the same split. A copy that succeeded still has to be a dictionary;
    // anything else is a reading this crate will not guess at, and folds into absence the
    // way an unmodelled *value type* does one layer down.
    #[test]
    fn a_copied_value_is_read_through_only_when_it_is_a_dictionary() {
        let not_a_dictionary = interpret_copied_value(STATE_PROXIES_KEY, || {
            (
                Some(CFString::new("Setup:/Network/Global/Proxies").into_CFPropertyList()),
                SC_STATUS_OK,
            )
        });
        assert!(matches!(not_a_dictionary, Ok(None)), "{not_a_dictionary:?}");

        // And the arm all of the above are the alternatives to. Without this row a copy
        // that reached [`to_proxy_dict`] and was thrown away would still look right here,
        // because the runner's own keys carry no proxy for the assertion to miss.
        let read = interpret_copied_value(STATE_PROXIES_KEY, || {
            (
                Some(
                    cf_dict(&[
                        ("HTTPEnable", CFBoolean::true_value().as_CFType()),
                        ("HTTPProxy", CFString::new("proxy.corp").as_CFType()),
                        ("HTTPPort", CFNumber::from(3128i64).as_CFType()),
                    ])
                    .into_CFPropertyList(),
                ),
                SC_STATUS_OK,
            )
        });
        let mode = read.expect("a well formed dictionary").expect("a value");
        assert_eq!(
            mode.endpoint_for(Scheme::Http)
                .expect("HTTP is enabled with a host")
                .authority(),
            "proxy.corp:3128"
        );
    }

    // The other half: whatever the runner's own proxy configuration happens to be, the
    // two real keys must read without error. Nothing is asserted about their *contents*
    // — that would make the test depend on GitHub's fleet configuration, which
    // `tests/mac_watch.rs` explains at length.
    #[test]
    fn the_real_proxies_keys_read_without_error() {
        let store = create_store().expect("configd answers on the macOS runner");
        for key in [SETUP_PROXIES_KEY, STATE_PROXIES_KEY] {
            let result = read_scope(&store, key);
            assert!(result.is_ok(), "{key}: {result:?}");
        }
    }
}
