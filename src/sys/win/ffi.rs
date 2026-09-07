//! Thin RAII wrappers over the Win32 handles and values the backend needs.
//!
//! The registry handles and events the backend needs are wrapped here, so that the
//! reading and mode-resolving code in `mod.rs` reads as ordinary Rust. Within this
//! backend (`src/sys/win/`) the `unsafe` that stays outside this file is deliberate and
//! local: `notify.rs`'s watch loop (`WatchedKey::arm`, `wait`) and the two `SetEvent`
//! calls that wake it from the owner's thread rather than from inside it
//! (`Watch::poll_now`, `Watch::drop`); and `mod.rs`'s two WinHTTP calls — the per-user
//! configuration it reads *first*, and the machine defaults — which carry their own RAII
//! wrappers next to their only caller (plus the test-only helpers in both files' `tests`
//! modules: `mod.rs` writes registry values, `notify.rs` signals events).
//!
//! `src/pac/winhttp.rs` — the `pac-windows-native` engine, which is Windows-only too —
//! reuses this file's [`Event`], [`wide`], [`wide_ptr_to_string`] and [`hresult_error`]
//! rather than duplicating them. It is not, though, the crate's largest body of
//! `unsafe`: this backend's own total (this file, `notify.rs`, and `mod.rs`) is larger.
//!
//! Note on the `windows` crate 0.62 API: most functions that used to return `BOOL` now
//! return `windows::core::Result<()>`, while the `Reg*` family returns a bare
//! [`WIN32_ERROR`] that must be compared against `ERROR_SUCCESS` by hand.

use std::ffi::{OsString, c_void};
use std::os::windows::ffi::OsStringExt;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS, HANDLE, WIN32_ERROR,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_DWORD, REG_EXPAND_SZ, REG_SAM_FLAGS, REG_SZ,
    REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
};
use windows::Win32::System::Threading::CreateEventW;
use windows::core::PCWSTR;

use crate::error::Error;

// Encode a Rust string as a NUL terminated UTF-16 buffer for the `*W` APIs.
pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

// Wrap a `WIN32_ERROR` into [`Error::Io`], annotated with what was being done.
pub(crate) fn win32_error(context: impl Into<String>, code: WIN32_ERROR) -> Error {
    Error::io(
        context,
        std::io::Error::from_raw_os_error(i32::try_from(code.0).unwrap_or(-1)),
    )
}

// Wrap a `windows::core::Error` (an `HRESULT`) into [`Error::Io`].
pub(crate) fn hresult_error(context: impl Into<String>, error: windows::core::Error) -> Error {
    Error::io(context, std::io::Error::from_raw_os_error(error.code().0))
}

// Name a predefined root, so that a read failure says which store it came from. The
// backend opens `Software\Microsoft\Windows\CurrentVersion\Internet Settings` under both
// of these roots, so a path on its own does not identify a key here.
fn root_name(root: HKEY) -> &'static str {
    // Not a `match`: an `HKEY` is a pointer newtype, so these constants cannot be
    // pattern operands. The final arm is unreachable in this backend, which opens no
    // other root; it exists because this function must be total.
    if root == HKEY_LOCAL_MACHINE {
        "HKLM"
    } else if root == HKEY_CURRENT_USER {
        "HKCU"
    } else {
        "HKEY"
    }
}

// An owned `HKEY`, closed on drop, that remembers which key it is.
#[derive(Debug)]
pub(super) struct RegKey {
    key: HKEY,
    // The caller's `context` names the key while *opening* it; these two carry that
    // identity into the failures of every later read, which the caller would otherwise
    // receive as a bare value name.
    root: &'static str,
    path: &'static str,
}

// SAFETY: an `HKEY` is a process-wide kernel handle; it is only `!Send` because the
// `windows` crate models it as a raw pointer. Registry handles may be used from any
// thread, and this wrapper is the sole owner, so moving it across threads is sound.
unsafe impl Send for RegKey {}

impl RegKey {
    // Open `root\path` for `access`.
    //
    // Returns `Ok(None)` when the key does not exist — the group policy key usually
    // does not — so that "absent" is not an error the caller has to pattern match on
    // an OS error code for.
    pub(super) fn open(
        root: HKEY,
        path: &'static str,
        access: REG_SAM_FLAGS,
        context: &str,
    ) -> Result<Option<Self>, Error> {
        let path_w = wide(path);
        let mut key = HKEY::default();
        // SAFETY: `path_w` is a NUL terminated UTF-16 buffer that outlives the call,
        // and `key` is a valid, writable `HKEY` slot. `root` is a predefined key
        // constant, which is always valid.
        let status =
            unsafe { RegOpenKeyExW(root, PCWSTR(path_w.as_ptr()), None, access, &raw mut key) };
        match status {
            ERROR_SUCCESS => Ok(Some(Self {
                key,
                root: root_name(root),
                path,
            })),
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(win32_error(context.to_owned(), other)),
        }
    }

    // The raw handle, for the notification API.
    pub(super) fn raw(&self) -> HKEY {
        self.key
    }

    // What a failed read of `value` was doing, named down to the key rather than to the
    // value alone.
    fn value_context(&self, value: &str) -> String {
        format!(
            r"reading registry value {value} under {}\{}",
            self.root, self.path
        )
    }

    // Read a `REG_SZ` / `REG_EXPAND_SZ` value.
    //
    // Returns `Ok(None)` when the value is absent or holds a non-string type; a
    // wrongly typed value is treated as "not configured" rather than as an error,
    // because a third party writing garbage there must not break the watcher.
    // A `REG_EXPAND_SZ`'s `%VAR%` references are returned exactly as stored, never
    // expanded — the same choice `kioslaverc`'s `apply` documents for `$e`: a
    // configuration read must not execute process environment substitution inside this
    // library. `RegQueryValueExW` above is the non-expanding half of the pair Win32 gives
    // (`RegGetValueW` expands unless told `RRF_NOEXPAND`), so the choice is also the one
    // this code path already had.
    //
    // Windows and KDE part company on what happens *next*, though, so do not read the
    // parallel any further than the expansion itself. KDE rejects the literal and records it
    // (`KioslavercSettings::needs_expansion`); here the literal is reported as ordinary
    // configuration, with nothing said about it. Aligning them would mean deciding whether
    // Windows itself expands these values, and it is not documented: the reference pages
    // for `WinHttpGetIEProxyConfigForCurrentUser` and `INTERNET_PER_CONN_OPTION` say
    // nothing about the registry type of `ProxyServer`/`AutoConfigURL`/`ProxyOverride` or
    // about substitution, and the readers that do not go through WinHTTP disagree (CPython's
    // `getproxies_registry` uses the non-expanding call; Chromium delegates to WinHTTP and
    // inherits whatever it does). The neighbouring `REG_SZ` case refuses to change
    // behaviour on a guess for the same reason, so this one is left as it is.
    pub(super) fn string_value(&self, name: &str) -> Result<Option<String>, Error> {
        let Some((kind, data)) = self.raw_value(name)? else {
            return Ok(None);
        };
        if kind != REG_SZ && kind != REG_EXPAND_SZ {
            return Ok(None);
        }
        // Taking only the whole pairs drops a trailing odd byte rather than erroring on
        // it — the same reading Win32 itself gives a byte count one short of a whole
        // `u16`. Once the units are decoded, `to_string_lossy` substitutes U+FFFD for a
        // UTF-16 sequence that is not valid (an unpaired surrogate) rather than refusing
        // the value — the same choice `kde`'s `String::from_utf8_lossy` documents for its
        // own not-quite-valid bytes.
        let units: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .take_while(|unit| *unit != 0)
            .collect();
        Ok(Some(
            OsString::from_wide(&units).to_string_lossy().into_owned(),
        ))
    }

    // Read a `REG_DWORD` value. Absent or wrongly typed values yield `Ok(None)`.
    //
    // A value declared `REG_DWORD` whose data is longer than four bytes keeps its low word
    // rather than being refused. Nothing documents that as an error: `RegSetValueExW` puts
    // no length rule on `cbData` for this type, and `RegGetValueW`'s `RRF_RT_REG_DWORD`
    // says only that a type outside the restriction fails, naming no error for a length
    // outside it. `base::win::RegKey::ReadValueDW` is stricter (`ERROR_CANTREAD` unless the
    // size is exactly four) and CPython's `getproxies_registry` checks nothing at all; this
    // sits with the second, for the reason the `REG_SZ` half above gives.
    pub(super) fn dword_value(&self, name: &str) -> Result<Option<u32>, Error> {
        let Some((kind, data)) = self.raw_value(name)? else {
            return Ok(None);
        };
        if kind != REG_DWORD || data.len() < 4 {
            return Ok(None);
        }
        Ok(Some(u32::from_le_bytes([
            data[0], data[1], data[2], data[3],
        ])))
    }

    // Query a value's type and bytes, sizing the buffer with the usual two-call dance.
    fn raw_value(&self, name: &str) -> Result<Option<(REG_VALUE_TYPE, Vec<u8>)>, Error> {
        let name_w = wide(name);

        for attempt in 0..MAX_REQUERY_ATTEMPTS {
            let mut kind = REG_VALUE_TYPE::default();
            let mut len: u32 = 0;

            // SAFETY: passing a null data pointer with a valid length slot is the
            // documented way to ask `RegQueryValueExW` for the required buffer size.
            let status = unsafe {
                RegQueryValueExW(
                    self.key,
                    PCWSTR(name_w.as_ptr()),
                    None,
                    Some(&raw mut kind),
                    None,
                    Some(&raw mut len),
                )
            };
            match status {
                ERROR_SUCCESS => {}
                ERROR_FILE_NOT_FOUND => return Ok(None),
                other => {
                    return Err(win32_error(self.value_context(name), other));
                }
            }

            let mut data = vec![0u8; len as usize];
            // SAFETY: `data` has exactly `len` writable bytes and `len` is passed by
            // pointer so the API can report how many it actually wrote.
            let status = unsafe {
                RegQueryValueExW(
                    self.key,
                    PCWSTR(name_w.as_ptr()),
                    None,
                    Some(&raw mut kind),
                    Some(data.as_mut_ptr()),
                    Some(&raw mut len),
                )
            };
            if classify_requery(status, attempt, MAX_REQUERY_ATTEMPTS) == Requery::Retry {
                crate::trace::debug!(
                    name = name,
                    attempt = attempt,
                    "the registry value grew between sizing it and reading it; requerying"
                );
                continue;
            }
            return match status {
                ERROR_SUCCESS => {
                    data.truncate(len as usize);
                    Ok(Some((kind, data)))
                }
                ERROR_FILE_NOT_FOUND => Ok(None),
                other => Err(win32_error(self.value_context(name), other)),
            };
        }
        // Unreachable: `classify_requery` only yields `Retry` while `attempt + 1 <
        // MAX_REQUERY_ATTEMPTS`, so the final iteration of the loop above always falls
        // through to one of the `return`s inside it.
        unreachable!("the requery loop always returns before exhausting its attempt budget")
    }
}

impl Drop for RegKey {
    fn drop(&mut self) {
        // SAFETY: `self.key` was returned by `RegOpenKeyExW` and this is the only owner,
        // so it is still open and is closed exactly once.
        unsafe {
            let _ = RegCloseKey(self.key);
        }
    }
}

// How many size-then-data query pairs [`RegKey::raw_value`] runs in all before it gives
// up on `ERROR_MORE_DATA` — not how many it redoes, which is one fewer: the first pair is
// the ordinary read. `classify_requery` compares `attempt + 1` against this for that
// reason. Bounded so a value that is rewritten on every poll cannot turn a single read
// into an infinite loop.
const MAX_REQUERY_ATTEMPTS: u32 = 3;

// What [`RegKey::raw_value`] should do after its data call, given the status it
// returned and how many size-then-data attempts have already run.
//
// A free function, rather than inline logic, so the retry decision can be tested
// without touching the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Requery {
    // The status is terminal — success, "not found", or any other error — and the
    // caller should turn it into the usual `Ok`/`Err`.
    Done,
    // `ERROR_MORE_DATA` with attempts still left in the budget: redo the query from the
    // size call.
    Retry,
    // `ERROR_MORE_DATA` recurred until the attempt budget ran out: give up and let the
    // caller report it as an ordinary error.
    Fail,
}

// Classify the data call's status for [`RegKey::raw_value`]'s retry loop.
fn classify_requery(status: WIN32_ERROR, attempt: u32, max_attempts: u32) -> Requery {
    match status {
        ERROR_MORE_DATA if attempt + 1 < max_attempts => Requery::Retry,
        ERROR_MORE_DATA => Requery::Fail,
        _ => Requery::Done,
    }
}

// An owned event handle, closed on drop.
#[derive(Debug)]
pub(crate) struct Event(HANDLE);

// SAFETY: event handles are process-wide kernel objects usable from any thread; the
// wrapper is the sole owner of the handle.
unsafe impl Send for Event {}

impl Event {
    // Create an unnamed, unsignalled event.
    pub(crate) fn new(manual_reset: bool, context: &str) -> Result<Self, Error> {
        // SAFETY: all pointer arguments are optional and passed as `None`/null; the
        // returned handle is checked for validity by the `windows` crate wrapper.
        let handle = unsafe { CreateEventW(None, manual_reset, false, PCWSTR::null()) }
            .map_err(|e| hresult_error(context.to_owned(), e))?;
        Ok(Self(handle))
    }

    // The raw handle, for the Win32 calls that take one — the waits, `SetEvent`,
    // `RegNotifyChangeKeyValue`. Those three are an example rather than a roster, and must
    // stay one: a comment that names a subset of the callers is wrong the moment one is
    // added. What holds at every use is that ownership stays with this `Event`, whose
    // `Drop` closes the handle, so a caller may not.
    pub(crate) fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `CreateEventW` and is owned solely by `self`.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

// Read a NUL terminated UTF-16 string that Win32 allocated for us.
//
// # Safety
//
// `ptr` must be null or point at a NUL terminated UTF-16 string that stays valid for
// the duration of the call.
pub(crate) unsafe fn wide_ptr_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: the caller guarantees a NUL terminated string, so the scan stops inside
    // the allocation.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `ptr` is valid for `len` `u16`s by the loop above.
    let units = unsafe { std::slice::from_raw_parts(ptr, len) };
    // `to_string_lossy` substitutes U+FFFD for a UTF-16 sequence that is not valid (an
    // unpaired surrogate) rather than refusing the value — see `string_value`'s doc
    // comment above for the same choice on the registry-string path.
    Some(OsString::from_wide(units).to_string_lossy().into_owned())
}

// A raw pointer that may be moved to the watcher thread.
//
// Used for the event handles the watcher struct owns and the thread must be able to wait
// on. Which ones is not written down here, for the reason [`Event::raw`] gives: the list
// went stale once already, when a second event was added beside the shutdown one without
// this file being touched.
#[derive(Debug, Clone, Copy)]
pub(super) struct SendPtr(pub(super) *mut c_void);

// SAFETY: the pointer is a kernel handle value, not a memory reference; the object it
// designates outlives the thread because `Watch::drop` joins the thread before the
// owning `Event` is dropped.
unsafe impl Send for SendPtr {}

impl SendPtr {
    pub(super) fn handle(self) -> HANDLE {
        HANDLE(self.0)
    }
}

#[cfg(test)]
mod tests {
    //! These tests cover [`classify_requery`], the pure decision at the heart of
    //! [`RegKey::raw_value`]'s retry loop, and the context that loop's failures carry.
    //!
    //! **Unverified:** the race `classify_requery` exists for — another process rewriting
    //! a value in the microsecond gap between the sizing call and the data call — is not
    //! exercised end to end, here or anywhere else in the tree. Reproducing it needs two
    //! threads racing a real registry write against a real read inside that window, which
    //! lands as a flaky test rather than as a regression test.
    //! **Risk:** the retry budget could be wrong — too small to outlast a real burst of
    //! rewrites, or spent on a status that was never going to clear — and these tests
    //! would still pass, because they ask only what the classifier decides and never
    //! whether the loop around it recovers.
    //! **Symptom:** a value another process rewrites often, `ProxyServer` while a
    //! settings dialog is open, comes back as an [`Error::Io`] carrying `ERROR_MORE_DATA`
    //! instead of as the value, on a machine where reading it by hand always works.

    use super::*;

    use windows::Win32::System::Registry::KEY_NOTIFY;

    #[test]
    fn error_more_data_retries_while_attempts_remain() {
        assert_eq!(
            classify_requery(ERROR_MORE_DATA, 0, MAX_REQUERY_ATTEMPTS),
            Requery::Retry
        );
        assert_eq!(
            classify_requery(
                ERROR_MORE_DATA,
                MAX_REQUERY_ATTEMPTS - 2,
                MAX_REQUERY_ATTEMPTS
            ),
            Requery::Retry
        );
    }

    #[test]
    fn error_more_data_fails_on_the_last_attempt() {
        assert_eq!(
            classify_requery(
                ERROR_MORE_DATA,
                MAX_REQUERY_ATTEMPTS - 1,
                MAX_REQUERY_ATTEMPTS
            ),
            Requery::Fail
        );
        // A budget of one attempt has no room to retry at all.
        assert_eq!(classify_requery(ERROR_MORE_DATA, 0, 1), Requery::Fail);
    }

    #[test]
    fn success_and_not_found_are_terminal_regardless_of_attempt() {
        for attempt in 0..MAX_REQUERY_ATTEMPTS {
            assert_eq!(
                classify_requery(ERROR_SUCCESS, attempt, MAX_REQUERY_ATTEMPTS),
                Requery::Done
            );
            assert_eq!(
                classify_requery(ERROR_FILE_NOT_FOUND, attempt, MAX_REQUERY_ATTEMPTS),
                Requery::Done
            );
        }
        // An unrelated hard error is just as terminal.
        assert_eq!(
            classify_requery(WIN32_ERROR(5), 0, MAX_REQUERY_ATTEMPTS),
            Requery::Done
        );
    }

    // The backend opens the same subkey path under both roots, so a failure that names
    // only the value leaves the caller unable to tell a machine-wide policy problem from
    // a problem with this user's own hive — two different people to escalate to.
    //
    // A key opened for notifications alone cannot answer a value query, which provokes a
    // real `RegQueryValueExW` failure without touching the machine: no ACL edit, no
    // elevation, and no value that has to already exist.
    #[test]
    fn a_value_read_failure_names_the_key_and_not_only_the_value() {
        fn read_failure(root: HKEY) -> String {
            let key = RegKey::open(root, "Software", KEY_NOTIFY, "opening a key for this test")
                .expect("opening `Software` for notifications must succeed")
                .expect("`Software` exists under both roots this backend opens");
            key.string_value("ProxyServer")
                .expect_err("a notify-only key cannot answer a value query")
                .to_string()
        }

        let user = read_failure(HKEY_CURRENT_USER);
        let machine = read_failure(HKEY_LOCAL_MACHINE);
        assert_ne!(
            user, machine,
            "the same path under two roots must not fail with the same message"
        );
        assert!(user.contains("HKCU"), "{user}");
        assert!(machine.contains("HKLM"), "{machine}");
    }
}
