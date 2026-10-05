//! [`PacPolicy`]: the safety envelope a PAC script is evaluated inside.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

/// The default evaluation timeout, five seconds.
pub const DEFAULT_PAC_TIMEOUT: Duration = Duration::from_secs(5);

/// Safety envelope for PAC evaluation (`pac-quickjs` and `pac-subprocess`; ignored by the
/// native resolvers, which hand the script to the OS).
///
/// Defaults: no DNS, drop internal answers, `myIpAddress()` → `127.0.0.1`, 5 s timeout.
/// `QuickJsEvaluator` interrupts the script at the deadline, and bounds the heap and the
/// native stack, the parser's included, with fixed limits of its own.
///
/// One default is not a limit: the crate reads no time zone, so
/// [`local_utc_offset`](Self::local_utc_offset) is 0 and `weekdayRange`, `dateRange` and
/// `timeRange` answer in GMT whether or not the script passed `"GMT"`; a browser reads the
/// host's zone there. [`with_local_utc_offset`](Self::with_local_utc_offset) is the only
/// way to move them, and a fixed offset does not follow DST.
///
/// The defaults restrict evaluation because scripts arrive over the network and standalone
/// PAC libraries have had security vulnerabilities: `pac-resolver` escaped its Node.js `vm`
/// and reached RCE ([CVE-2021-23406](https://github.com/advisories/GHSA-9j49-mfvp-vmhm)),
/// and `pacparser` had
/// [CVE-2023-37360](https://github.com/manugarg/pacparser/security/advisories/GHSA-62q6-v997-f7v9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacPolicy {
    resolve_dns: bool,
    allow_internal_addresses: bool,
    my_ip_address: Option<IpAddr>,
    timeout: Option<Duration>,
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
    /// Classic `dnsResolve` is IPv4-only, so a native IPv6 answer (a ULA, say) never
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
    /// `Some(Duration::ZERO)` is a zero budget, not an unlimited one: every evaluation
    /// returns [`Error::PacTimeout`](crate::Error::PacTimeout). `None` removes the limit.
    /// `WinHttpPacResolver::with_timeout` treats zero the same way. Its name is left
    /// unlinked because the type exists only under `pac-windows-native` on Windows; linking
    /// it breaks doc builds elsewhere.
    ///
    /// `QuickJsEvaluator` interrupts the script at the deadline, so its thread ends with
    /// the call unless a host function (`dnsResolve` with DNS on) is still running then.
    ///
    /// Evaluation threads are limited process-wide to the number of cores, with a minimum
    /// of 4. A thread holds its slot until its script ends, including after the call times
    /// out. When all slots are occupied, a call waits for one within the same budget and
    /// returns [`Error::PacSaturated`](crate::Error::PacSaturated) without running the
    /// script if the budget expires. Run untrusted scripts in a process the caller can kill
    /// (`pac-subprocess`). With `None`, the in-process engine runs on the calling thread
    /// without a slot, bypassing the thread limit as well as the timeout.
    /// `SubprocessEvaluator` (`pac-subprocess`) still requires a slot and waits without a
    /// time limit for a slot and its worker's response.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
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
    // `timeout` selects the execution mode for `QuickJsEvaluator::evaluate`: `Some` spawns
    // the script on a thread the call gives up on, `None` runs it on the caller's own
    // thread with no budget at all. A default of `None` therefore hands an application
    // built on `PacPolicy::new()` a remote script (under WPAD, one from whoever answered
    // the discovery query) with nothing to end it. The five seconds are stated in the type
    // doc and in the constant's own, and changing them changes what every default caller
    // does when a script does not come back.
    #[test]
    fn the_default_budget_is_five_seconds_and_not_the_absence_of_one() {
        assert_eq!(PacPolicy::new().timeout(), Some(DEFAULT_PAC_TIMEOUT));
        assert_eq!(DEFAULT_PAC_TIMEOUT, Duration::from_secs(5));
    }

    // `pac::time` reads `now()` and falls back to `SystemTime::now()`, so with the default
    // unset the time predicates answer about today. Pinned instead, `dateRange`,
    // `weekdayRange` and `timeRange` would all answer about that one instant forever, and
    // every engine test would still pass: they each pin a clock of their own so they do not
    // depend on this.
    #[test]
    fn the_default_clock_is_the_real_one() {
        assert_eq!(PacPolicy::new().now(), None);
    }

    // `with_timeout` takes an `Option` rather than a `Duration` so that removing the budget
    // is something a caller can ask for, and its doc says so. Folded back into the default,
    // the request is refused in silence: the caller that accepted a blocking evaluation
    // gets a five-second one instead, and finds out from a `PacTimeout` it was not
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
