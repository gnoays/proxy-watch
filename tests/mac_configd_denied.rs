//! The macOS failure path, driven for real: what happens when `configd` never answers.
//!
//! # What this file closes
//!
//! This file is the only thing that executes the retry that runs when `configd` is
//! unreachable. `tests/mac_watch.rs` covers the opposite case — it *insists* construction
//! succeeds — so without a way to make `configd` unreachable on demand, the whole degraded
//! path, including the choice to place the retry in `create_store` (`src/sys/mac/mod.rs`)
//! itself rather than only in the later registration step, rests on nothing but a reading
//! of Apple's documentation and Chromium's `network_config_watcher_apple.cc`.
//!
//! A `sandbox-exec` profile that denies the `mach-lookup` of
//! `com.apple.SystemConfiguration.configd` makes `SCDynamicStoreCreateWithOptions`
//! return NULL — the mechanism behind anthropics/claude-code issue #42857 (same API,
//! same crate family: `system-configuration` 0.6 panicked on the NULL, 0.7 returns
//! `None`). It does not depend on SIP, which matters because GitHub's macOS runners run
//! with SIP **disabled** (actions/runner-images #8162), and that same fact is
//! what rules out the `DYLD_INSERT_LIBRARIES` alternative. The identical test binary
//! answers `Some` unsandboxed and `None` under the profile on one runner in one CI run;
//! the control described below is what puts both lines in the same log.
//!
//! No prior art was copied here because there is none. Chromium — the source of this
//! crate's own `kRetryInterval` / `kMaxRetry` — has no
//! `network_config_watcher_apple_unittest.cc` at all; `mullvad/system-configuration-rs`
//! and `mxinden/if-watch` call the API and test nothing about its failure; Tailscale,
//! sysproxy-rs, netwatcher and `x/net/http/httpproxy` sidestep the FFI boundary entirely
//! (`scutil` / `networksetup` / `AF_ROUTE`), and Tailscale's `manager_darwin.go` argues
//! parsing `scutil` output is the more durable choice.
//!
//! # What it can prove, and what it structurally cannot
//!
//! The deny is applied at `exec` and covers the whole process for its whole life, so the
//! only shape this can produce is *`configd` was never reachable*. Under that shape
//! [`ProxyWatcher::with_options`] runs `Watch::armed` → `sys::read_config` → `spawn`, and
//! `read_config`'s `create_store` fails first — so what these tests reach is
//! `create_store`'s retry loop, its budget, and the rule that exhausting the retries is
//! fatal to the constructor.
//!
//! Two things stay out of reach, and no assertion below pretends otherwise:
//!
//! * **Recovery** (fail, then succeed on a later attempt). The profile cannot be lifted
//!   mid-process, so only exhaustion is observable, never the retry *working*.
//! * **`Registration::new`'s degrade branch** — the case where, with a
//!   `poll_interval` set, construction should degrade and show that in `health()`. That
//!   branch is the `WatchFailSoft::Degraded` arm of `Registration::new`, which runs on the
//!   thread `spawn` starts, and this scenario never reaches it. (`establish_store`, which
//!   `Registration::new` calls, only retries and returns a `Result`; it has no degrade
//!   concept of its own.) That is not a shortcoming
//!   of the sandbox — it is the same asymmetry showing up as a *runtime* fact rather than
//!   a reading of the source: when `configd` is down from the start, the registration
//!   retry is unreachable in the very situation it was written for, which is why the same
//!   retry had to be added to `create_store` in the first place.
//!   [`exhausting_the_retries_is_fatal_even_with_a_poll_interval_configured`] is what
//!   pins that down.
//!
//! # How these are gated, and why not with `#[ignore]`
//!
//! The other "does not run by default" tests here are `#[ignore]`, but
//! that convention means something specific — *"rewrites the real machine's settings, so
//! CI is the only safe place to run it"* — and CI therefore passes `--include-ignored` on
//! its unit-test step and its three integration-test steps — the macOS one included.
//! These tests are the case that convention's own note in
//! `.github/workflows/ci.yml` warned about: they must **not** run in the ordinary macOS
//! test step, because outside the sandbox their assertions are simply false. `#[ignore]`
//! would not exclude them there, and using it anyway would quietly overload that
//! convention with a second, incompatible meaning.
//!
//! So the gate is an environment variable, `PROXY_WATCH_EXPECT_CONFIGD_DENIED`, set only
//! by a dedicated sandboxed CI step — `.github/workflows/ci.yml` has one, and
//! `.github/workflows/mac-tests.yml` carries the same one so that a dispatch aimed at
//! the macOS backend measures this path instead of printing `SKIPPED` at it:
//!
//! * **unset** — an ordinary `cargo test`, on a developer's Mac or in the normal CI step:
//!   nothing is asserted. [`sc_dynamic_store_build_reports_whether_configd_is_reachable`]
//!   still makes its one call and prints the result, because that outcome is the
//!   experiment's **control**: "`None` under the sandbox" proves nothing unless the same
//!   call is known to return `Some` on the same runner without it. Both lines land in the
//!   same CI log, and reading them together is the actual evidence.
//! * **set** — under `sandbox-exec` with the configd deny profile: everything is
//!   asserted.
//!
//! Run either way with `--nocapture` to see the printed lines.
#![cfg(target_os = "macos")]

use std::env;
use std::time::{Duration, Instant};

use proxy_watch::{Error, ProxyWatcher, WatchOptions};
use system_configuration::dynamic_store::SCDynamicStoreBuilder;

/// Set by the two sandboxed CI steps — `.github/workflows/ci.yml`'s and the one
/// `.github/workflows/mac-tests.yml` carries from it — and by nothing else.
const EXPECT_DENIED: &str = "PROXY_WATCH_EXPECT_CONFIGD_DENIED";

/// Distinct from the crate's own `STORE_NAME` (`src/sys/mac/mod.rs`), so a session
/// visible in `configd`'s state while this test runs is never mistaken for the crate's.
const SMOKE_STORE_NAME: &str = "proxy-watch-configd-smoke";

/// Whether the caller claims to have arranged for `configd` to be unreachable.
///
/// Everything below is an assertion when this is true and an observation when it is
/// false; see the module doc's gating section.
fn configd_is_denied() -> bool {
    env::var_os(EXPECT_DENIED).is_some()
}

// --------------------------------------------------------------------------------
// the premise
// --------------------------------------------------------------------------------

/// Call `SCDynamicStoreCreateWithOptions` once and report what came back.
///
/// Deliberately does not go through [`ProxyWatcher`]: this is the one test whose failure
/// must mean "the sandbox did not do what we expected on this runner" and can never mean
/// "our retry logic misbehaved". Every other test in this file is meaningless if this
/// one's premise does not hold, so it is kept as bare as possible.
#[test]
fn sc_dynamic_store_build_reports_whether_configd_is_reachable() {
    // Nothing but the one FFI call under test happens before this line: whatever else a
    // `ProxyWatcher` would do (notification keys, a run loop thread, a first read) could
    // fail for its own reasons and confuse the result.
    let store = SCDynamicStoreBuilder::new(SMOKE_STORE_NAME).build();
    let outcome = if store.is_some() { "Some" } else { "None" };

    if !configd_is_denied() {
        println!(
            "CONTROL: SCDynamicStoreBuilder::new({SMOKE_STORE_NAME:?}).build() returned \
             {outcome} with no sandbox in effect. {EXPECT_DENIED} is unset, so nothing is \
             asserted — this line exists to be read against the sandboxed run's line in \
             the same CI log (see this file's module doc)."
        );
        return;
    }

    assert!(
        store.is_none(),
        "{EXPECT_DENIED} is set, which means this process was supposed to be running under \
         a sandbox-exec profile that denies the mach-lookup of \
         com.apple.SystemConfiguration.configd — but \
         SCDynamicStoreBuilder::new({SMOKE_STORE_NAME:?}).build() still returned Some. The \
         premise every other test in this file rests on no longer holds on this runner: \
         the deny either does not apply to this lookup any more, or the framework reaches \
         configd some other way. Investigate that rather than weakening this assertion."
    );

    println!(
        "CONFIRMED: under the configd mach-lookup deny profile, \
         SCDynamicStoreBuilder::new({SMOKE_STORE_NAME:?}).build() returned None."
    );
}

// --------------------------------------------------------------------------------
// what the premise buys: the retry loop, executed
// --------------------------------------------------------------------------------

/// Chromium's `kMaxRetry`, mirrored by `src/sys/mac/notify.rs`'s
/// `REGISTRATION_MAX_RETRIES` — private to the crate, restated here because checking it
/// from the outside is exactly what this file is for.
const EXPECTED_MAX_RETRIES: u32 = 5;

/// Chromium's `kRetryInterval`, mirrored by `REGISTRATION_RETRY_INTERVAL`.
const EXPECTED_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// The floor the elapsed time must clear to prove the loop actually slept between
/// attempts rather than failing straight through.
///
/// `create_store` sleeps `EXPECTED_RETRY_INTERVAL` before each of its
/// `EXPECTED_MAX_RETRIES` retries, so the true floor is five seconds and `thread::sleep`
/// guarantees *at least* its argument. The 10% of slack is not for the sleeps — it is so
/// that a future change to either constant does not have to be mirrored here to the
/// millisecond for this assertion to keep meaning "it retried" rather than "it matched an
/// arithmetic identity".
const MIN_ELAPSED: Duration = Duration::from_millis(
    EXPECTED_RETRY_INTERVAL.as_millis() as u64 * EXPECTED_MAX_RETRIES as u64 * 9 / 10,
);

/// A ceiling a correct implementation cannot reach, so a retry loop that never terminates
/// fails as an ordinary assertion instead of as a CI timeout.
const MAX_ELAPSED: Duration = Duration::from_secs(30);

/// The core claim of this file, finally executed: with `configd` unreachable,
/// `create_store` retries against the real API, spends its real budget, and then fails
/// the constructor.
///
/// Three separate things are checked, because each has been asserted in documentation and
/// never once observed:
///
/// 1. **that it fails at all** — `SCDynamicStoreCreateWithOptions` returning NULL really
///    does surface as an `Err`, rather than as the panic `system-configuration` 0.6 would
///    have produced, or as a hang;
/// 2. **that it is the right failure** — `Error::Io` carrying `create_store`'s own
///    context, not some later step failing for an unrelated reason;
/// 3. **that the loop actually ran** — the elapsed time clears [`MIN_ELAPSED`], which is
///    what distinguishes "retried five times a second apart" from "returned the error on
///    the first attempt". Without this, the first two assertions would pass just as
///    happily against an implementation with no retry at all.
#[test]
fn the_create_store_retry_loop_spends_its_full_budget_before_giving_up() {
    if !configd_is_denied() {
        println!(
            "SKIPPED: {EXPECT_DENIED} is unset, so configd is reachable and \
             ProxyWatcher::new() is expected to *succeed* — which tests/mac_watch.rs \
             already asserts. This test only means something under the sandbox-exec \
             profile described in this file's module doc."
        );
        return;
    }

    let started = Instant::now();
    let result = ProxyWatcher::new();
    let elapsed = started.elapsed();

    let Err(error) = result else {
        panic!(
            "ProxyWatcher::new() succeeded with configd denied. Either the deny stopped \
             working (in which case \
             sc_dynamic_store_build_reports_whether_configd_is_reachable has already \
             failed, and that is the finding to read), or the macOS backend acquired a way \
             to produce a configuration without configd — which would be a confident wrong \
             answer of exactly the kind this backend must not produce."
        );
    };

    match &error {
        Error::Io { context, source } => assert!(
            context.contains("SCDynamicStore"),
            "the failure should be the one create_store raises after exhausting its \
             retries (context \"creating an SCDynamicStore session\"), but it came back as \
             Io {{ context: {context:?}, source: {source} }} — some other step failed \
             first, so this test is no longer exercising the retry loop"
        ),
        other => panic!(
            "expected Error::Io from create_store, got {other:?}: {other}. The retry loop \
             reports exhaustion through Error::io, so a different variant means the failure \
             took a different path than the exhausted retry loop"
        ),
    }

    assert!(
        elapsed >= MIN_ELAPSED,
        "ProxyWatcher::new() failed after only {elapsed:?}, short of the {MIN_ELAPSED:?} \
         floor implied by {EXPECTED_MAX_RETRIES} retries {EXPECTED_RETRY_INTERVAL:?} apart. \
         The error is right but the retry loop did not run — this is the assertion that \
         tells those two apart, so do not relax it without changing create_store in \
         src/sys/mac/mod.rs to match"
    );
    assert!(
        elapsed < MAX_ELAPSED,
        "ProxyWatcher::new() took {elapsed:?} to fail, past the {MAX_ELAPSED:?} ceiling: \
         the retry loop is not respecting REGISTRATION_MAX_RETRIES"
    );

    println!(
        "CONFIRMED: with configd denied, ProxyWatcher::new() failed after {elapsed:?} with \
         {error}. The create_store retry loop has now actually run against the real \
         SCDynamicStoreCreateWithOptions."
    );
}

/// The fail-soft policy's read-side rule, observed rather than reasoned about:
/// exhausting the retries is fatal to the constructor **even when a `poll_interval` is
/// configured**, because there is no initial snapshot to hand a degraded watcher.
///
/// This is what keeps the claim that, with a `poll_interval` set, construction should
/// degrade and show that in `health()`, from being written into this file as though the
/// sandbox had verified it.
/// It has not, and cannot: the degrade branch lives in `Registration::new`,
/// reached from `spawn`, which runs *after* `read_config` — so with `configd` down from
/// the start it is unreachable by construction. See the module doc's "what it
/// structurally cannot" section.
#[test]
fn exhausting_the_retries_is_fatal_even_with_a_poll_interval_configured() {
    if !configd_is_denied() {
        println!(
            "SKIPPED: {EXPECT_DENIED} is unset; see \
             the_create_store_retry_loop_spends_its_full_budget_before_giving_up"
        );
        return;
    }

    // Short enough that a watcher which *did* come up degraded would be visibly polling
    // rather than idle, so the fatal outcome below cannot be mistaken for "the option was
    // ignored".
    let options = WatchOptions::new().with_poll_interval(Some(Duration::from_millis(200)));

    let error = ProxyWatcher::with_options(options).expect_err(
        "ProxyWatcher::with_options succeeded with configd denied and a poll_interval set. \
         A poll_interval must not rescue this: the failure is in \
         read_config, before any watcher exists, and a degraded watcher would still need an \
         initial snapshot there is no way to produce. If this now returns Ok, the \
         constructor is publishing a configuration it never read",
    );

    assert!(
        matches!(&error, Error::Io { context, .. } if context.contains("SCDynamicStore")),
        "the poll_interval case must fail for the same reason the default case does, not \
         some later one: got {error:?}"
    );

    println!("CONFIRMED: a configured poll_interval does not rescue the constructor: {error}");
}
