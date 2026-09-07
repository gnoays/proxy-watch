//! The unsupported-platform path of the watcher façade.
//!
//! The crate implements the Windows, macOS and Linux backends, but the type
//! exists on every target so that downstream code compiles unconditionally, staying
//! additive with Cargo's feature model. These tests pin the stub's behaviour, and — by
//! existing — make a CI run on a
//! target without a backend meaningful rather than merely "it built".
//!
//! Linux is included only when **both** `linux-gnome` and `linux-kde` are off:
//!
//! ```text
//! cargo test --no-default-features --test unsupported_platform
//! ```
//!
//! That configuration behaves like a target with no backend, but not unconditionally, and
//! the difference is a precondition on running these three rather than a claim they make.
//! Linux still compiles its own backend in; what both features being off takes away is
//! every store it could read, so [`Error::Unsupported`] is what
//! `desktop::assemble` answers when neither store is there. Inside a Flatpak or Snap the
//! route is decided before any store is consulted, and the same build reports
//! [`Error::Sandboxed`] instead — so these tests hold on a host, and a run inside a
//! sandbox is measuring something they do not describe.
#![cfg(not(any(
    windows,
    target_os = "macos",
    all(
        target_os = "linux",
        any(feature = "linux-gnome", feature = "linux-kde")
    )
)))]

use proxy_watch::{Error, ProxyWatcher, WatchOptions, read, read_with_options};

#[test]
fn new_reports_that_the_platform_is_unsupported() {
    let error = ProxyWatcher::new().expect_err("no backend on this target");
    assert!(matches!(error, Error::Unsupported), "got {error:?}");
    assert!(error.to_string().contains("not supported"));
}

#[test]
fn with_options_reports_that_the_platform_is_unsupported() {
    let error = ProxyWatcher::with_options(WatchOptions::new().with_group_policy(false))
        .expect_err("no backend on this target");
    assert!(matches!(error, Error::Unsupported), "got {error:?}");
}

/// The one-shot read exists because arming notifications can fail where the settings
/// still read fine — but a target with no backend has no settings to read either, so
/// there is nothing for it to rescue here. It fails the same way construction does.
#[test]
fn reading_once_reports_that_the_platform_is_unsupported() {
    let error = read().expect_err("no backend on this target");
    assert!(matches!(error, Error::Unsupported), "got {error:?}");
    assert!(error.to_string().contains("not supported"));

    let error = read_with_options(&WatchOptions::new().with_group_policy(false))
        .expect_err("no backend on this target");
    assert!(matches!(error, Error::Unsupported), "got {error:?}");
}
