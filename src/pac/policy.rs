//! [`PacPolicy`]: the safety envelope a PAC script is evaluated inside.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

/// The default evaluation timeout, five seconds.
pub const DEFAULT_PAC_TIMEOUT: Duration = Duration::from_secs(5);

/// The default loop-iteration cap (10M). Hitting it aborts with
/// [`Error::PacEvaluation`](crate::Error::PacEvaluation). Unlike the two constants below
/// this one is not `boa_engine`'s default: `RuntimeLimits::default()` leaves
/// `loop_iteration` at `u64::MAX`, so an unbounded `while` is left to the timeout — which
/// releases the caller without stopping the script (see [`PacPolicy::with_timeout`]).
pub const DEFAULT_PAC_LOOP_LIMIT: u64 = 10_000_000;

/// The default function-call recursion depth (512) — `boa_engine`'s own default,
/// kept so stating it is not a behaviour change. Tighten with
/// [`PacPolicy::with_recursion_limit`].
pub const DEFAULT_PAC_RECURSION_LIMIT: usize = 512;

/// The default engine value-stack length (10 240) — also `boa_engine`'s own default.
/// Entry count, not bytes or OS stack size — in particular not the native stack the
/// parser recurses on, which [`PacPolicy`] cannot bound at all.
pub const DEFAULT_PAC_STACK_SIZE_LIMIT: usize = 1024 * 10;

/// Safety envelope for PAC evaluation (`pac-boa`; ignored by `WinHttpPacResolver`).
///
/// Defaults: no DNS, drop internal answers, `myIpAddress()` → `127.0.0.1`, 5 s timeout,
/// boa's own recursion/stack limits, and a loop cap boa does not impose at all.
/// Heap unbounded — OS-sourced PAC + DNS = high severity.
///
/// One default is not a limit: the crate reads no time zone, so
/// [`local_utc_offset`](Self::local_utc_offset) is 0 and `weekdayRange`, `dateRange` and
/// `timeRange` answer in GMT whether or not the script passed `"GMT"` — a browser reads the
/// host's zone there. [`with_local_utc_offset`](Self::with_local_utc_offset) is the only way
/// to move them, and a fixed offset does not follow DST.
///
/// Every limit on this type is a VM limit: it bounds a script that is already running, and
/// none of them bounds parsing. `boa_parser` 0.21.1 is a recursive-descent parser with no
/// depth limit of its own, so nesting alone overflows the native stack before evaluation
/// starts — measured through this type on the thread `BoaEvaluator` spawns for a script
/// (x86-64 Windows, the stack `std::thread` gives a spawn by default): an optimized build
/// parses 99 nested `(` and aborts on 100, in a 256-byte script; the same source unoptimized
/// aborts on 17. A native stack overflow aborts the process rather than panicking, so
/// neither the dedicated evaluation thread nor the timeout contains it. A caller that
/// accepts a PAC body it does not control has to isolate the process itself; no setting here
/// substitutes for that.
///
/// Neither figure is a ceiling to design against. `(` is the shape they were taken on, not
/// the only one that recurses — `[` and `{a:` overflow too, and unoptimized they do it at a
/// comparable depth — so a screen written for `(` screens `(`. And with
/// [`with_timeout(None)`](Self::with_timeout) there is no spawned thread to measure at all:
/// the script parses on the calling thread, under whatever stack that thread was given.
/// Upstream has the bug open
/// ([boa#4397](https://github.com/boa-dev/boa/issues/4397)) and closed the parser guard
/// written for it ([boa#4772](https://github.com/boa-dev/boa/pull/4772)) unmerged over the
/// Test262 conformance it cost; 0.22.0 ships with none, so raising the dependency is not the
/// way out either.
///
/// The script arrives over the network, which is why the defaults are what they are:
/// standalone PAC libraries have been broken exactly there — `pac-resolver`
/// escaped its Node.js `vm` and reached RCE
/// ([CVE-2021-23406](https://github.com/advisories/GHSA-9j49-mfvp-vmhm)) and `pacparser`
/// had [CVE-2023-37360](https://github.com/manugarg/pacparser/security/advisories/GHSA-62q6-v997-f7v9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacPolicy {
    resolve_dns: bool,
    allow_internal_addresses: bool,
    my_ip_address: Option<IpAddr>,
    timeout: Option<Duration>,
    max_loop_iterations: u64,
    recursion_limit: usize,
    stack_size_limit: usize,
    local_utc_offset: i32,
    now: Option<SystemTime>,
}

impl Default for PacPolicy {
    fn default() -> Self {
        Self {
            resolve_dns: false,
            allow_internal_addresses: false,
            my_ip_address: None,
            timeout: Some(DEFAULT_PAC_TIMEOUT),
            max_loop_iterations: DEFAULT_PAC_LOOP_LIMIT,
            recursion_limit: DEFAULT_PAC_RECURSION_LIMIT,
            stack_size_limit: DEFAULT_PAC_STACK_SIZE_LIMIT,
            local_utc_offset: 0,
            now: None,
        }
    }
}

impl PacPolicy {
    /// The default policy: no DNS, no internal addresses, no real local IP, 5 s budget.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow `dnsResolve`, `isResolvable` and `isInNet` to perform name resolution.
    ///
    /// With the default `false`, `dnsResolve` returns `null` and no DNS query is made.
    #[must_use]
    pub fn with_dns_resolution(mut self, enabled: bool) -> Self {
        self.resolve_dns = enabled;
        self
    }

    /// Allow answers in internal space (loopback, RFC 1918, link-local, CGNAT, … and the
    /// IPv4-mapped spelling of those). Default `false` drops them.
    ///
    /// Classic `dnsResolve` is IPv4-only, so a native IPv6 answer — a ULA, say — never
    /// reaches this flag either way. IP literals in the script are never filtered.
    #[must_use]
    pub fn with_internal_addresses(mut self, allowed: bool) -> Self {
        self.allow_internal_addresses = allowed;
        self
    }

    /// Set the address `myIpAddress()` reports. Unset → `127.0.0.1` (no auto-discovery).
    #[must_use]
    pub fn with_my_ip_address(mut self, address: IpAddr) -> Self {
        self.my_ip_address = Some(address);
        self
    }

    /// Wall-clock budget, or `None` to remove it (blocks the caller if the script hangs).
    ///
    /// `Some(Duration::ZERO)` is a budget of nothing, not the absence of one: every
    /// evaluation answers [`Error::PacTimeout`](crate::Error::PacTimeout). `None` is how a
    /// caller asks for no limit. `WinHttpPacResolver::with_timeout` answers zero the same
    /// way — it is named in backticks rather than linked because that type exists only
    /// under `pac-windows-native` on Windows, and a link to it fails the doc build
    /// everywhere else.
    ///
    /// The budget bounds the call, not the script. On expiry `BoaEvaluator` returns
    /// [`Error::PacTimeout`](crate::Error::PacTimeout) and abandons the evaluation thread,
    /// which runs on until one of the VM limits stops it — so that thread, and whatever it
    /// has allocated by then, outlives the call that asked for it. Nothing here interrupts
    /// a running script: bounding the work is what the limits below are for.
    ///
    /// Read that per call and it sounds like untidiness; the cost is in the aggregate.
    /// Abandoned threads do not queue behind each other, so an application resolving
    /// repeatedly against a script that always overruns holds roughly
    /// `overrun ÷ timeout` of them at once, each spinning a core until its own VM limit
    /// lands. With the defaults that ratio is not small: a `while (true) {}` reaches
    /// [`DEFAULT_PAC_LOOP_LIMIT`] in about 93 seconds on an unoptimized build of this
    /// crate, against a budget of [`DEFAULT_PAC_TIMEOUT`]. Shortening the budget
    /// widens the ratio rather than narrowing it. What bounds this is a lower
    /// [`PacPolicy::with_max_loop_iterations`], or not letting the calls stack up.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Loop-iteration cap (`u64::MAX` disables). Honoured via `boa_engine` `RuntimeLimits`.
    ///
    /// Iterations, not allocations — the same distinction
    /// [`DEFAULT_PAC_STACK_SIZE_LIMIT`] draws. The limit is checked where the engine
    /// re-enters a loop body, so whatever a builtin allocates within a call it never
    /// reaches: a script that spends its memory in one `String.prototype.repeat` rather
    /// than in a loop has nothing stopping it — the cap never fires, and
    /// [`PacPolicy::with_timeout`] ends the wait rather than the work. That is the gap the
    /// type doc's "Heap unbounded" names.
    #[must_use]
    pub fn with_max_loop_iterations(mut self, limit: u64) -> Self {
        self.max_loop_iterations = limit;
        self
    }

    /// Recursion depth cap. Default [`DEFAULT_PAC_RECURSION_LIMIT`] is boa's own.
    #[must_use]
    pub fn with_recursion_limit(mut self, limit: usize) -> Self {
        self.recursion_limit = limit;
        self
    }

    /// Value-stack entry cap (not bytes / OS stack). Default [`DEFAULT_PAC_STACK_SIZE_LIMIT`].
    #[must_use]
    pub fn with_stack_size_limit(mut self, limit: usize) -> Self {
        self.stack_size_limit = limit;
        self
    }

    /// Seconds from UTC treated as "local" for date/time predicates (default 0 = GMT).
    #[must_use]
    pub fn with_local_utc_offset(mut self, seconds: i32) -> Self {
        self.local_utc_offset = seconds;
        self
    }

    /// Pin the clock the time-dependent host functions see.
    ///
    /// Intended for tests and for reproducing a routing decision after the fact.
    #[must_use]
    pub fn with_now(mut self, now: SystemTime) -> Self {
        self.now = Some(now);
        self
    }

    /// Whether name resolution is permitted.
    #[must_use]
    pub fn resolve_dns(&self) -> bool {
        self.resolve_dns
    }

    /// Whether resolution results in internal address space are kept.
    #[must_use]
    pub fn allow_internal_addresses(&self) -> bool {
        self.allow_internal_addresses
    }

    /// The address `myIpAddress()` reports, or `127.0.0.1` when unset.
    #[must_use]
    pub fn my_ip_address(&self) -> IpAddr {
        self.my_ip_address
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    /// The wall-clock evaluation budget.
    #[must_use]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// The loop iteration cap.
    #[must_use]
    pub fn max_loop_iterations(&self) -> u64 {
        self.max_loop_iterations
    }

    /// The function-call recursion depth cap.
    #[must_use]
    pub fn recursion_limit(&self) -> usize {
        self.recursion_limit
    }

    /// The cap on the engine's internal value-stack length.
    #[must_use]
    pub fn stack_size_limit(&self) -> usize {
        self.stack_size_limit
    }

    /// The offset from UTC, in seconds, that counts as local time.
    #[must_use]
    pub fn local_utc_offset(&self) -> i32 {
        self.local_utc_offset
    }

    /// The pinned clock, when [`with_now`](Self::with_now) was used.
    #[must_use]
    pub fn now(&self) -> Option<SystemTime> {
        self.now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Everything else on this type is held where a script can see it: the engine tests set a
    // flag and read what `dnsResolve`, `myIpAddress` or a range predicate answers. Two
    // defaults cannot be reached that way, because observing them means either hanging or
    // reading the real clock, and both of those are what a test sets out to avoid. So they
    // are held here, as values.
    //
    // `timeout` decides which door `BoaEvaluator::evaluate` opens: `Some` spawns the script
    // on a thread the call gives up on, `None` runs it on the caller's own thread with no
    // budget at all. A default of `None` therefore hands an application built on
    // `PacPolicy::new()` a remote script — under WPAD, one from whoever answered the
    // discovery query — with nothing to end it. The five seconds are stated in the type doc
    // and in the constant's own, and changing them changes what every default caller does
    // when a script does not come back.
    #[test]
    fn the_default_budget_is_five_seconds_and_not_the_absence_of_one() {
        assert_eq!(PacPolicy::new().timeout(), Some(DEFAULT_PAC_TIMEOUT));
        assert_eq!(DEFAULT_PAC_TIMEOUT, Duration::from_secs(5));
    }

    // `pac::time` reads `now()` and falls back to `SystemTime::now()`, so an unset default is
    // what makes the time predicates answer about today. Pinned instead, `dateRange`,
    // `weekdayRange` and `timeRange` would all answer about that one instant forever, and
    // every engine test would still pass: they each pin a clock of their own precisely so
    // they do not depend on this.
    #[test]
    fn the_default_clock_is_the_real_one() {
        assert_eq!(PacPolicy::new().now(), None);
    }

    // The loop cap is the third limit and the only one whose default this file has to hold.
    // `recursion_limit` and `stack_size_limit` are reached by scripts that boa tests here
    // actually run, so lowering either field draws red on its own. Ten million iterations is
    // not a number a test can spend, which is why the same field is invisible: set to
    // `u64::MAX` — the value `with_max_loop_iterations` documents as disabling the cap — the
    // whole suite still passes, because every loop test above passes a cap of its own.
    //
    // `boa.rs`'s `the_two_limits_that_claim_to_be_boas_still_are` holds the near half of this,
    // that the constant is not `u64::MAX`, and argues there about why an OS-supplied script's
    // `while (true)` must not be left to a timeout that ends the wait and not the work. The
    // constant staying 10 000 000 while the default stops carrying it is the gap between the
    // two. They are asserted apart because they fail for different reasons: that one when boa
    // changes, this one when this crate does.
    //
    // The setter is the same shape one level down. Folded into a floor —
    // `limit.max(DEFAULT_PAC_LOOP_LIMIT)` — it passes as well, because the one test that caps
    // an endless loop at 10 000 still gets its `PacEvaluation`, ten thousand times later. That
    // surfaces as half a minute of test time rather than as a failure.
    #[test]
    fn the_default_carries_the_loop_cap_and_the_setter_can_tighten_it() {
        assert_eq!(
            PacPolicy::new().max_loop_iterations(),
            DEFAULT_PAC_LOOP_LIMIT
        );
        assert_eq!(
            PacPolicy::new()
                .with_max_loop_iterations(5)
                .max_loop_iterations(),
            5
        );
    }

    // `with_timeout` takes an `Option` rather than a `Duration` so that removing the budget
    // is something a caller can ask for, and its doc says so. Folded back into the default,
    // the request is refused in silence — the caller that deliberately accepted a blocking
    // evaluation gets a five-second one instead, and finds out from a `PacTimeout` it was not
    // expecting. Zero is the other end of the same axis and means a budget of nothing.
    #[test]
    fn removing_the_budget_is_a_request_the_builder_honours() {
        assert_eq!(PacPolicy::new().with_timeout(None).timeout(), None);
        assert_eq!(
            PacPolicy::new()
                .with_timeout(Some(Duration::ZERO))
                .timeout(),
            Some(Duration::ZERO)
        );
    }
}
