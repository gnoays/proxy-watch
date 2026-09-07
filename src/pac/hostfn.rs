//! PAC host functions (engine-independent). Network ones go through [`PacPolicy`].
//! Set: [MDN PAC][mdn].
//!
//! # Known differences from the browser reference
//!
//! Target: Firefox/Chrome. A divergence may stand only if listed below with category:
//! **(a)** safety · **(b)** spec fidelity · **(c)** real-world comparison rule ·
//! **(d)** input robustness. Unlisted = bug — except for what this crate refuses to reach
//! for at all, which is [`PacPolicy`]'s contract and documented there: the network, and the
//! host's time zone, which is why the date/time functions answer in GMT by default where
//! the ref reads the host's.
//! Ref: Mozilla `ascii_pac_utils.js`.
//! (`timeRange` 2-arg does not wrap midnight here *or* in the ref; `dateRange` 2-value
//! does wrap in both.)
//!
//! * **[`sh_exp_match`]** — **(a)**. No regex; only `*`/`?`, so no pattern here can cost the
//!   exponential time a compiled one can. Quadratic time one still can, in the ref as much
//!   as here, so the `?` route gives up and answers `false` once it has gone round
//!   [`MAX_MATCH_STEPS`] times — a bound no call on a real URL and a real pattern comes
//!   near, and the ref has none. The ref builds a `RegExp` but escapes `.` first, so `.` is
//!   literal on both sides; it is the *other*
//!   metacharacters (`+`, `[`, `(`, `^`, `$`, `|`) that keep regex meaning there and are
//!   literal here. **(d)**: `*`/`?` match a line terminator too, where the ref's `.*`/`.`
//!   stop at one (no `s` flag, so `.` excludes `\n`, `\r`, `\u{2028}`, `\u{2029}`).
//! * **[`local_host_or_domain_is`]** — **(b)**. Requires `!host.contains('.')` before
//!   prefix match; ref is bare `startsWith(host + ".")`. **(c)**: case-insensitive on both
//!   sides, like [`dns_domain_is`]; the ref compares bytes.
//! * **[`dns_domain_is`]** — **(c)**. Case-insensitive; ref `endsWith` is case-sensitive.
//!   Both lack label-boundary checks (spec bug, reproduced).
//! * **`"GMT"` / weekday/month names** — **(d)**. Trim + case-insensitive here; ref is
//!   exact. Excess args after GMT peel → `false` here; ref often ignores them.
//! * **[`convert_addr`]** — **(b)**. Strict dotted quads; ref JS `&` coercion accepts
//!   `0x7f`/`1e2`/`-1`. See that fn's doc for the full list. [`is_in_net`] does *not*
//!   inherit this: its address arguments follow the ref's own `isValidIpAddress`
//!   grammar, zero padding and anchoring included.
//! * **[`is_resolvable`]** — **(d)**. An address literal answers `true` without a lookup,
//!   including the IPv6 spellings [`dns_resolve`] answers `None` for. The ref is bare
//!   `dnsResolve(host) != null`, so `[::1]` is unresolvable there. What counts as a
//!   literal is [`dns_resolve`]'s question, not [`is_in_net`]'s: see [`literal_ipv4`].
//!   The brackets are the only thing either binding rewrites, and only around an IPv6
//!   address — see [`unbracket_ipv6`] for why that one is owed and nothing else is.
//! * **Whitespace and numeric spelling** — **(d)**. The host handed to
//!   [`dns_resolve`]/[`is_resolvable`] and the numbers handed to
//!   [`date_range`]/[`time_range`] are trimmed, and a number is read as a Rust float
//!   where the ref uses `parseInt`: `"1e2"` is 100 here and 1 there, `"15abc"` is not a
//!   number here and is 15 there.
//! * **Arguments the script leaves out** — **(d)**. The `pac-boa` binding reads a missing
//!   argument as `""` (`arg_string`), so a short call is answered rather than refused. JS
//!   never puts `""` there — an omitted parameter is `undefined` — so whatever a reference
//!   makes of one, it is not this. [`is_plain_host_name`] is then handed a name
//!   carrying no dot and [`dns_domain_is`] a suffix every host ends with, so `isPlainHostName()`
//!   and `dnsDomainIs(host)` answer `true`; the rest answer `false`, `null` or `0`. A script
//!   that omits an argument is broken either way, and what this buys it is a rule matching
//!   every destination rather than a diagnosis. The WinHTTP engine is the OS's and answers
//!   for itself.
//! * **[`date_range`]/[`time_range`]** — **(d)**. Arguments are read by kind
//!   (day/month/year, h/m/s); the ref splits the list in half by position, so shapes it
//!   still gives a meaning (`dateRange(1, 2, 3)`, `dateRange("JAN", 15)`) are `false` here,
//!   as are 3 or 5 arguments to `timeRange`, where the ref throws. **(b)**: the ref builds
//!   the upper bound by `setMonth` on 31 December, so a shorter end month overflows into
//!   the next one — `dateRange("JAN", "FEB")` runs to 2/3 March there, and ends with
//!   February here. **(b)**: a numeric argument between 32 and 999 is refused rather than
//!   read as a year. The ref's rule is `parseInt(arg) < 32` for a day and *everything else*
//!   a year, with no lower bound, where [`classify_date_part`] wants 1000 before it will
//!   call a number a year. Only a range can tell the two readings apart — a lone `99` asks
//!   whether the current year is 99, which is `false` either way — but a range whose low end
//!   falls in 32..=999 starts at that year there, so `dateRange(99, 2100)` covers the present
//!   and matches nothing here. The stricter reading is deliberate: the set writes `year` as
//!   "the ordered full year integer number. For example, 2016 (**not** 16)" and `day` as
//!   1..=31, so 32..=999 is neither, and the ref's `< 32` is a day/year disambiguator rather
//!   than a claim that 99 is a year. Reading it as one buys a script no year it meant — the
//!   ref answers about the year 99 CE, not 1999 — only a range that happens to say "always".
//!
//! [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use super::policy::PacPolicy;
use super::time::{self, Civil};
use crate::util::strip_brackets;

// `isPlainHostName(host)` — true when the name carries no domain part.
//
// A colon disqualifies as well: an IPv6 literal carries no dot but is not a name. Both
// references say so — Firefox searches `(\.)|:`, and Chromium adds an `AssignFromIPLiteral`
// check under the comment "IPv6 literals might not contain any periods, however are not
// considered plain host names". Without it the common `if (isPlainHostName(host)) return
// "DIRECT";` opening sends every IPv6 destination direct.
pub(crate) fn is_plain_host_name(host: &str) -> bool {
    !host.contains('.') && !host.contains(':')
}

// `dnsDomainIs(host, domain)` — true when `host` ends with `domain`.
pub(crate) fn dns_domain_is(host: &str, domain: &str) -> bool {
    host.to_ascii_lowercase()
        .ends_with(&domain.to_ascii_lowercase())
}

// `localHostOrDomainIs(host, hostdom)` — an exact match, or an unqualified host name
// that is the first label of `hostdom`.
pub(crate) fn local_host_or_domain_is(host: &str, hostdom: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let hostdom = hostdom.to_ascii_lowercase();
    host == hostdom || (!host.contains('.') && hostdom.starts_with(&format!("{host}.")))
}

// `dnsDomainLevels(host)` — the number of dots in the name.
pub(crate) fn dns_domain_levels(host: &str) -> usize {
    host.matches('.').count()
}

// `shExpMatch(str, shexp)` — shell-style glob with `*` and `?`.
//
// The `*`-only case is delegated to the crate's existing `ProxyOverride` matcher so
// that a bypass pattern and a PAC pattern cannot drift apart.
pub(crate) fn sh_exp_match(text: &str, pattern: &str) -> bool {
    if !pattern.contains('?') {
        return crate::util::glob_match(pattern, text);
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    wildcard_match(&pattern, &text)
}

// How many times the loop below may go round before the answer is `false` whatever the
// rest of the subject holds. Only a subject and a pattern whose lengths multiply past this
// reach it: the loop is O(subject × pattern) in the worst case — 16,000 characters of `a`
// against `"*" + "a" * 8_000 + "?b"` took 1.58 s unoptimized, quadrupling on every doubling
// from 6.6 ms at 1,000 — and a script picks both arguments, so a megabyte of each is a few
// statements. Nothing upstream bounds that: the wall clock stops the *caller* waiting,
// never the thread, and one host call is one iteration to
// [`PacPolicy::max_loop_iterations`](super::policy::PacPolicy::with_max_loop_iterations),
// so the cap that ends a `while (true) {}` counts nothing here. The `?`-free route needs no
// such budget — [`crate::util::glob_match`] searches each literal run in the remainder of
// the subject and never revisits what it passed.
//
// Chosen an order of magnitude above what a real call can spend: an 8 KB subject against a
// 200-character pattern is 1.6 million.
const MAX_MATCH_STEPS: usize = 1 << 24;

// Backtracking `*` / `?` matcher. Iterative, so it cannot blow the stack, and bounded by
// [`MAX_MATCH_STEPS`], so one call cannot hold the thread it runs on for hours either.
//
// The `*` arm has to be tried before the literal one. A `*` in the *subject* is legal in
// a URL, and it compares equal to a `*` in the pattern, so a literal arm placed ahead of
// this one eats the star as an ordinary character and records no backtrack point:
// `shExpMatch("*ab", "*?")` answered `false` that way while the `?`-free route through
// [`crate::util::glob_match`] answered `true` for the same star. The reference has no
// such split — it escapes everything that is not `*` or `?` and lets `RegExp` decide.
fn wildcard_match(pattern: &[char], text: &[char]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut resume = 0usize;
    let mut budget = MAX_MATCH_STEPS;
    while t < text.len() {
        match budget.checked_sub(1) {
            Some(left) => budget = left,
            None => return false,
        }
        if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            resume = t;
            p += 1;
        } else if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if let Some(star) = star {
            p = star + 1;
            resume += 1;
            t = resume;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

// `convert_addr(ipaddr)` — a dotted quad as a **signed** 32-bit integer.
//
// The full list the module doc promises. The ref is `bytes[i] & 0xff` over `split('.')`,
// so JS `ToInt32` coercion reads spellings that `parse::<u32>` refuses and this turns
// into `0`: `0x7f` (hex), `1e2` (exponent), `-1` (negative — the ref's `& 0xff` makes it
// `255`). Everything else agrees: a decimal in range, one out of range (`300 & 0xff` is
// `44` on both sides), surrounding whitespace, and a missing component (`undefined &
// 0xff` is `0`, which is also what `unwrap_or(0)` gives).
pub(crate) fn convert_addr(addr: &str) -> i32 {
    let mut out = 0u32;
    for (index, part) in addr.split('.').take(4).enumerate() {
        let octet = part.trim().parse::<u32>().unwrap_or(0) & 0xff;
        out |= octet << (24 - 8 * index);
    }
    // The reference's `|` chain yields an int32; reinterpreting the assembled bits is
    // exactly that, and cannot overflow or panic.
    out as i32
}

// `alert(message)` — forwarded to the `tracing` feature's `debug` level, and dropped
// entirely without it.
pub(crate) fn alert(message: &str) {
    crate::trace::pac_alert(message);
}

// The network-touching functions. Everything below consults `PacPolicy`.

// `myIpAddress()` — the address the policy was told to report, else `127.0.0.1`.
//
// The crate never enumerates the machine's interfaces: doing so would leak the host's
// position on the network to a script it does not trust.
pub(crate) fn my_ip_address(policy: &PacPolicy) -> IpAddr {
    policy.my_ip_address()
}

// The address a name already is, read the way a resolver reads one — which is neither
// `Ipv4Addr::from_str` nor the [`reference_ipv4`] grammar below.
//
// The split is deliberate in the reference, not an inconsistency: the PAC library reads
// its *own* arguments, so `isInNet("010.1.2.3", …)` is 10.1.2.3, while `dnsResolve` is a
// host binding and reads the URL grammar its resolver does, so `dnsResolve("010.1.2.3")`
// is 8.1.2.3. The same string means one thing to each, on purpose.
//
// `Ipv4Addr::from_str` is neither: it refuses the padded, hex and short spellings both
// grammars accept, leaving them to fall through to [`resolve_ipv4`] and become a *name*
// lookup of a string that is an address — answered by whether the platform's `getaddrinfo`
// applies `inet_aton` rules, so one script gets two answers on two operating systems.
// `url::Host::parse` is the grammar this crate already reads destinations with.
fn literal_ipv4(host: &str) -> Option<Ipv4Addr> {
    match crate::endpoint::parse_host(host) {
        Ok(url::Host::Ipv4(v4)) => Some(v4),
        _ => None,
    }
}

// The `[…]` a host binding may unwrap, which is the IPv6 spelling and nothing else.
//
// Unwrapping at all is this crate paying for its own choice of `host` argument: [`evaluate`]
// hands the script Gecko's bracketed spelling, so `dnsResolve(host)` arrives here as `[::1]`
// and has to be understood. Neither reference unwraps anything — Gecko gives the string to
// its DNS service exactly as the script wrote it (`ProxyAutoConfig.cpp`, `PACResolve`), and
// Chromium's `GetHostnameArgument` does IDN-to-punycode and no bracket handling at all
// (`services/proxy_resolver/proxy_resolver_v8.cc`), having passed `GURL::HostNoBrackets()` in
// the first place.
//
// So unwrapping anything else is inventing a resolver neither reference has: `[10.1.2.3]` and
// `[example.com]` are strings a real lookup answers nothing for, and answering them turns a
// script's PROXY/DIRECT branch on a name that reached no network. The module doc lists the
// divergences a host binding is allowed; a bracketed address that is not IPv6 is not among
// them, and by that doc's own rule an unlisted divergence is a bug.
//
// [`evaluate`]: super::evaluate
fn unbracket_ipv6(host: &str) -> &str {
    let inner = strip_brackets(host);
    if inner.parse::<Ipv6Addr>().is_ok() {
        inner
    } else {
        host
    }
}

// `dnsResolve(host)` — the first IPv4 address of `host`, or `None` for JavaScript
// `null`.
pub(crate) fn dns_resolve(host: &str, policy: &PacPolicy) -> Option<Ipv4Addr> {
    let host = unbracket_ipv6(host.trim());
    if let Some(literal) = literal_ipv4(host) {
        return Some(literal);
    }
    if host.parse::<Ipv6Addr>().is_ok() {
        // Classic `dnsResolve` is IPv4-only; `dnsResolveEx` is not implemented.
        return None;
    }
    resolve_ipv4(host, policy)
}

// `isResolvable(host)` — whether `dnsResolve` would answer, with one deliberate
// exception.
pub(crate) fn is_resolvable(host: &str, policy: &PacPolicy) -> bool {
    let host = unbracket_ipv6(host.trim());
    // The IPv6 arm is the exception: `dns_resolve` answers `None` for those.
    if literal_ipv4(host).is_some() || host.parse::<Ipv6Addr>().is_ok() {
        return true;
    }
    resolve_ipv4(host, policy).is_some()
}

// `isInNet(host, pattern, mask)` — IPv4 network membership.
//
// The order is the reference's: an unusable `pattern` or `mask` answers `false` before
// `host` is looked at, so a rule that can never match cannot spend a DNS query either.
pub(crate) fn is_in_net(host: &str, pattern: &str, mask: &str, policy: &PacPolicy) -> bool {
    let (Some(pattern), Some(mask)) = (reference_ipv4(pattern), reference_ipv4(mask)) else {
        return false;
    };
    let address = match reference_ipv4(host) {
        Some(literal) => literal,
        None => match dns_resolve(host, policy) {
            Some(address) => address,
            None => return false,
        },
    };
    let (address, pattern, mask) = (u32::from(address), u32::from(pattern), u32::from(mask));
    address & mask == pattern & mask
}

// The address grammar `isInNet` reads its arguments with, which is the reference's own
// and not `Ipv4Addr::from_str`.
//
// `isValidIpAddress` is `/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/` plus a `> 255`
// check per group, and `convert_addr` then reads the groups as decimal. That accepts the
// zero padding in `isInNet(host, "192.168.001.000", "255.255.255.000")`, which
// `Ipv4Addr::from_str` rejects — read that way, the whole rule answers `false` for every
// host. The regex is anchored, so it also rejects surrounding whitespace that a `trim`
// would let through.
fn reference_ipv4(text: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut groups = text.split('.');
    for octet in &mut octets {
        let group = groups.next()?;
        if group.is_empty() || group.len() > 3 || !group.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *octet = u8::try_from(group.parse::<u16>().ok()?).ok()?;
    }
    if groups.next().is_some() {
        return None;
    }
    Some(Ipv4Addr::from(octets))
}

// Ask the system resolver, then apply the internal-address filter.
fn resolve_ipv4(host: &str, policy: &PacPolicy) -> Option<Ipv4Addr> {
    if !policy.resolve_dns() || host.is_empty() {
        return None;
    }
    // Port 0 keeps this a pure name lookup.
    let addresses = (host, 0u16).to_socket_addrs().ok()?;
    addresses
        .filter_map(|address| match address.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        })
        .find(|address| policy.allow_internal_addresses() || !is_internal(IpAddr::V4(*address)))
}

// Whether an address belongs to a range a PAC script must not be able to probe.
//
// The IPv4 half is one rule rather than a list: every block the IANA IPv4 Special-Purpose
// Address Registry marks `Globally Reachable: False`, plus multicast, which that registry
// does not cover. Anything IANA reserves next is already in scope, so it arrives as a
// reading of the rule and not as another arm someone has to argue for.
//
// Nothing but IPv4 reaches the IPv6 arm today: classic `dnsResolve` is IPv4-only, so
// `resolve_ipv4` folds the mapped spellings down and drops the rest before asking. The arm
// stays rather than the signature narrowing to `Ipv4Addr`, because `dnsResolveEx` is where
// an IPv6 answer would come from and would otherwise have to reinvent these ranges.
pub(crate) fn is_internal(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                // "This network", 0.0.0.0/8. RFC 1122 §3.2.1.3 reads `{0, host}` as a host
                // on *this* network — the same claim 169.254.0.0/16 makes, and internal for
                // the same reason. `Ipv4Addr::is_unspecified` is the `{0,0}` corner of this
                // and would be a rule no input could tell from it.
                || octets[0] == 0
                // Carrier-grade NAT, 100.64.0.0/10.
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                // IETF protocol assignments, 192.0.0.0/24. Two addresses in it — the PCP
                // and TURN anycasts — are globally reachable, and the whole block is
                // filtered anyway: over-refusing a PAC script costs it two addresses no
                // script resolves a name to, and splitting them out costs every later
                // reader the question of why.
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                // Documentation: TEST-NET-1 192.0.2.0/24, TEST-NET-2 198.51.100.0/24,
                // TEST-NET-3 203.0.113.0/24.
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                // 6to4 relay anycast, 192.88.99.0/24, deprecated by RFC 7526 and marked
                // unreachable along with it.
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                // Benchmarking, 198.18.0.0/15.
                || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
                // Reserved, 240.0.0.0/4. `Ipv4Addr::is_broadcast` is the 255.255.255.255
                // corner of this and would be a rule no input could tell from it.
                || octets[0] >= 240
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_internal(IpAddr::V4(mapped));
            }
            let segments = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique local, fc00::/7.
                || (segments[0] & 0xfe00) == 0xfc00
                // Link-local unicast, fe80::/10.
                || (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

// The time-dependent functions.

// `weekdayRange(wd1 [, wd2] [, "GMT"])`.
pub(crate) fn weekday_range(args: &[String], policy: &PacPolicy) -> bool {
    let (args, gmt) = time::split_gmt(args);
    if args.is_empty() || args.len() > 2 {
        return false;
    }
    let Some(first) = time::weekday_index(&args[0]) else {
        return false;
    };
    let last = match args.get(1) {
        Some(name) => match time::weekday_index(name) {
            Some(index) => index,
            None => return false,
        },
        None => first,
    };
    time::in_cyclic_range(time::civil_now(policy, gmt).weekday, first, last)
}

// One component of a `dateRange` argument list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatePart {
    Day(i64),
    Month(i64),
    Year(i64),
}

fn classify_date_part(text: &str) -> Option<DatePart> {
    if let Some(month) = time::month_index(text) {
        return Some(DatePart::Month(month));
    }
    let value = time::number(text)?;
    if (1..=31).contains(&value) {
        Some(DatePart::Day(value))
    } else if value >= 1000 {
        Some(DatePart::Year(value))
    } else {
        None
    }
}

// `dateRange(...)` in all of its documented shapes.
pub(crate) fn date_range(args: &[String], policy: &PacPolicy) -> bool {
    let (args, gmt) = time::split_gmt(args);
    let parts: Option<Vec<DatePart>> = args
        .iter()
        .map(|arg| classify_date_part(arg.as_str()))
        .collect();
    let Some(parts) = parts else {
        return false;
    };
    let now = time::civil_now(policy, gmt);

    match parts.as_slice() {
        [DatePart::Day(day)] => now.day == *day,
        [DatePart::Month(month)] => now.month == *month,
        [DatePart::Year(year)] => now.year == *year,
        [DatePart::Day(lo), DatePart::Day(hi)] => time::in_cyclic_range(now.day, *lo, *hi),
        [DatePart::Month(lo), DatePart::Month(hi)] => time::in_cyclic_range(now.month, *lo, *hi),
        [DatePart::Year(lo), DatePart::Year(hi)] => time::in_cyclic_range(now.year, *lo, *hi),
        [
            DatePart::Day(d1),
            DatePart::Month(m1),
            DatePart::Day(d2),
            DatePart::Month(m2),
        ] => time::in_cyclic_range(now.month * 100 + now.day, m1 * 100 + d1, m2 * 100 + d2),
        [
            DatePart::Month(m1),
            DatePart::Year(y1),
            DatePart::Month(m2),
            DatePart::Year(y2),
        ] => match (checked_my(*y1, *m1), checked_my(*y2, *m2)) {
            (Some(lo), Some(hi)) => time::in_cyclic_range(now.year * 100 + now.month, lo, hi),
            _ => false,
        },
        [
            DatePart::Day(d1),
            DatePart::Month(m1),
            DatePart::Year(y1),
            DatePart::Day(d2),
            DatePart::Month(m2),
            DatePart::Year(y2),
        ] => match (checked_ymd(*y1, *m1, *d1), checked_ymd(*y2, *m2, *d2)) {
            (Some(lo), Some(hi)) => time::in_cyclic_range(date_key(now), lo, hi),
            _ => false,
        },
        _ => false,
    }
}

fn date_key(now: Civil) -> i64 {
    now.year * 10_000 + now.month * 100 + now.day
}

// `year * 100 + month` with overflow reported as `None` instead of panicking (debug) or
// wrapping (release). `classify_date_part` accepts any `value >= 1000` as a year with no
// upper bound, so a PAC script can hand `dateRange` a year large enough to overflow this
// multiplication; treat that as "does not match" rather than a crash.
fn checked_my(year: i64, month: i64) -> Option<i64> {
    year.checked_mul(100)?.checked_add(month)
}

// `year * 10_000 + month * 100 + day`, same overflow handling as [`checked_my`].
fn checked_ymd(year: i64, month: i64, day: i64) -> Option<i64> {
    year.checked_mul(10_000)?.checked_add(month * 100 + day)
}

// `timeRange(...)` in all of its documented shapes.
pub(crate) fn time_range(args: &[String], policy: &PacPolicy) -> bool {
    let (args, gmt) = time::split_gmt(args);
    let values: Option<Vec<i64>> = args.iter().map(|arg| time::number(arg.as_str())).collect();
    let Some(values) = values else {
        return false;
    };
    let now = time::civil_now(policy, gmt);
    let seconds = now.hour * 3600 + now.minute * 60 + now.second;

    match values.as_slice() {
        [hour] => now.hour == *hour,
        [lo, hi] => *lo <= now.hour && now.hour <= *hi,
        [h1, m1, h2, m2] => match (checked_hms(*h1, *m1, 0), checked_hms(*h2, *m2, 59)) {
            (Some(lo), Some(hi)) => time::in_cyclic_range(seconds, lo, hi),
            _ => false,
        },
        [h1, m1, s1, h2, m2, s2] => {
            match (checked_hms(*h1, *m1, *s1), checked_hms(*h2, *m2, *s2)) {
                (Some(lo), Some(hi)) => time::in_cyclic_range(seconds, lo, hi),
                _ => false,
            }
        }
        _ => false,
    }
}

// `hour * 3600 + minute * 60 + second` with overflow reported as `None` instead of
// panicking (debug) or wrapping (release). `timeRange`'s arguments arrive as unbounded
// `i64`s straight out of [`time::number`] — a PAC script can hand it a value large enough
// to overflow this multiplication. `classify_date_part` bounds `DatePart::Day` and
// `DatePart::Month` but leaves `DatePart::Year` open at the top for the same reason, which
// is why [`checked_my`] and [`checked_ymd`] guard the same way rather than relying on
// their arguments being in range.
fn checked_hms(hour: i64, minute: i64, second: i64) -> Option<i64> {
    hour.checked_mul(3600)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    // 2024-02-29T13:45:07Z — a Thursday, on a leap day.
    fn pinned() -> PacPolicy {
        PacPolicy::new().with_now(UNIX_EPOCH + Duration::from_secs(1_709_214_307))
    }

    #[test]
    fn plain_host_names_and_domains() {
        assert!(is_plain_host_name("intranet"));
        assert!(!is_plain_host_name("intranet.corp.example"));
        // An IPv6 literal has no dot but is not a name, in either spelling. Both
        // references disqualify it, and the usual `if (isPlainHostName(host)) return
        // "DIRECT";` opening would otherwise send every IPv6 destination direct.
        assert!(!is_plain_host_name("::1"));
        assert!(!is_plain_host_name("[::1]"));
        assert!(!is_plain_host_name("2001:db8::1"));
        assert!(!is_plain_host_name("10.0.0.1"));

        assert!(dns_domain_is("www.corp.example", ".corp.example"));
        assert!(dns_domain_is("WWW.Corp.Example", ".corp.example"));
        assert!(!dns_domain_is("www.other.example", ".corp.example"));
        // The module doc's "spec bug, reproduced". `dnsDomainIs` is a bare `endsWith` in
        // Mozilla's `ascii_pac_utils.js` and in Chromium alike, so a domain written
        // without a leading dot matches across the label boundary. Pinned deliberately:
        // adding the boundary check would be a silent divergence from both references
        // rather than a fix, and every assert above still passes with it added.
        assert!(dns_domain_is("evilcorp.example", "corp.example"));
        assert!(dns_domain_is("corp.example", "corp.example"));
        // The bug reproduced above is the *boundary*, not the anchor: `endsWith` still has
        // to end the name. Read as containment, a host somebody else named would answer to
        // the corporate domain — and the usual `if (dnsDomainIs(host, ".corp.example"))
        // return "DIRECT";` then sends that traffic straight out.
        assert!(!dns_domain_is(
            "www.corp.example.attacker.test",
            ".corp.example"
        ));

        assert!(local_host_or_domain_is(
            "www.corp.example",
            "www.corp.example"
        ));
        assert!(local_host_or_domain_is("www", "www.corp.example"));
        assert!(!local_host_or_domain_is(
            "home.corp.example",
            "www.corp.example"
        ));
        assert!(!local_host_or_domain_is("ww", "www.corp.example"));
        // Case folds on both sides — the module doc's **(c)**. Mozilla's
        // `ascii_pac_utils.js` compares bytes
        // (`host == hostdom || hostdom.lastIndexOf(host + ".", 0) == 0`), so these
        // two are `false` in Firefox and Chrome alike.
        assert!(local_host_or_domain_is("WWW", "www.corp.example"));
        assert!(local_host_or_domain_is(
            "WWW.Corp.Example",
            "www.corp.example"
        ));
        // The module doc's **(b)**: the prefix branch is for an *unqualified* name, so a
        // dotted `host` reaches it only as an exact match. The ref's bare
        // `hostdom.lastIndexOf(host + ".", 0) == 0` says otherwise and calls one domain
        // local because a longer one starts with it.
        assert!(!local_host_or_domain_is(
            "www.corp.example",
            "www.corp.example.attacker.test"
        ));

        assert_eq!(dns_domain_levels("host"), 0);
        assert_eq!(dns_domain_levels("host.corp.example"), 2);
    }

    #[test]
    fn glob_matching_handles_star_and_question_mark() {
        assert!(sh_exp_match(
            "http://home.example/people/x.html",
            "*/people/*"
        ));
        assert!(!sh_exp_match("http://home.example/x.html", "*/people/*"));
        assert!(sh_exp_match("abc", "a?c"));
        assert!(!sh_exp_match("ac", "a?c"));
        assert!(sh_exp_match("aXbYc", "a?b?c"));
        assert!(sh_exp_match("anything", "*"));
        assert!(sh_exp_match("", "*"));
        assert!(!sh_exp_match("", "?"));
        assert!(sh_exp_match("a.b.c", "a.*.?"));
        // Both wildcards cross a line terminator — the module doc's **(d)**. The ref's
        // `new RegExp("^" + pattern + "$")` carries no `s` flag, so its `.*`/`.` stop at
        // one and both of these are `false` there.
        assert!(sh_exp_match("a\nb", "a*b"));
        assert!(sh_exp_match("a\nb", "a?b"));
        // A `*` left over after the subject runs out still matches, because it stands for
        // nothing as readily as for something. The loop only advances while the subject
        // does, so what is left of the pattern is judged after it — asking whether the
        // pattern was consumed instead would refuse every trailing star.
        assert!(sh_exp_match("ab", "a?*"));
        assert!(sh_exp_match("ab", "a?**"));
        assert!(!sh_exp_match("ab", "a?*c"));
    }

    // A `*` in the URL being matched is an ordinary character to the reference, which
    // escapes it into the `RegExp` — only the *pattern* carries wildcards. Comparing the
    // star in the subject against the star in the pattern, before the pattern's star is
    // read as one, consumes it and leaves nothing to backtrack to.
    #[test]
    fn a_star_in_the_subject_does_not_consume_the_pattern_s_star() {
        assert!(sh_exp_match("*ab", "*?"));
        assert!(sh_exp_match("http://home.example/a*b/x.html", "*a*?"));
        assert!(sh_exp_match("x*ab", "x*?"));
        // The same star, asked of the `?`-free route: `glob_match` answers this one on its
        // own, so the row is what holds the two routes to the same reading of `*`.
        assert!(sh_exp_match("*ab", "*b"));
        // Still bounded by what `?` requires: one character, and the subject has none left.
        assert!(!sh_exp_match("*", "*??"));
    }

    // The script picks both arguments, and the `?` route is O(subject × pattern): without
    // `MAX_MATCH_STEPS` bounding the loop, 16,000 characters against an 8,000-character
    // pattern takes 1.58 s unoptimized and grows fourfold on every doubling. Unbounded, the
    // pair below is still inside the call **ten minutes** later, so what this asserts is not
    // a speed-up but the difference between an answer and none. Nothing upstream shortens it
    // — the wall clock releases the caller and leaves the thread running, and this whole call
    // is one iteration to the loop cap.
    // `false` is the honest answer here as well as the budgeted one: the pattern ends in a `b`
    // the subject never holds.
    //
    // The call always spends the whole of `MAX_MATCH_STEPS`, so the budget below bounds
    // contention rather than the matcher: unoptimized, that is 1.1 s here, while a bound
    // raised to `1 << 30` takes 56.7 s and a bound removed never returns at all. 20 s — what
    // the other stall tests in this crate use — sits under the first regression and well over
    // a loaded machine. At 5 s a run costs 5.4 s while merely sharing 4 cores with a build.
    #[test]
    fn a_pathological_pattern_does_not_stall_the_matcher() {
        let text = "a".repeat(200_000);
        let pattern = format!("*{}?b", "a".repeat(100_000));
        let start = std::time::Instant::now();
        assert!(!sh_exp_match(&text, &pattern));
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(20),
            "matching took {elapsed:?}"
        );
    }

    // The other side of that budget, and the side with no upper bound on how wrong it can
    // be: the guard answers `false`, which is also what "does not match" looks like, so a
    // cap set too low turns an ordinary `shExpMatch` into a silent no. A script asking
    // `shExpMatch(host, "*.corp.example.com")` and being told no sends internal traffic down
    // whichever branch it wrote for the outside world.
    //
    // Held here is the floor rather than the constant: a call must be able to walk a subject
    // of the size the constant's own note names. The pair below spends about the subject's
    // length, because the star resumes one character at a time and the tail then matches —
    // the 1.6 million that note quotes is the worst case for these sizes, not this shape's
    // cost, and no shape that *matches* reaches it. So what a cap below roughly 8 400 breaks
    // is this; the headroom above that is still held by nothing, and measuring it would need
    // a step count the matcher does not hand back.
    //
    // The `?` is not decoration. Without one, `sh_exp_match` hands the whole thing to
    // `glob_match`, which has no budget to be cut short by, and the row would hold nothing.
    #[test]
    fn an_ordinary_pattern_is_not_cut_short_by_the_step_budget() {
        let subject = format!("{}.corp.example.com", "a".repeat(8 * 1024));
        let pattern = format!("*{}?*.corp.example.com", "a".repeat(180));
        assert!(
            pattern.chars().count() >= 200,
            "the pattern has to be the size the budget was chosen against"
        );
        assert!(sh_exp_match(&subject, &pattern));
    }

    #[test]
    fn addresses_convert_to_integers() {
        assert_eq!(convert_addr("0.0.0.0"), 0);
        assert_eq!(convert_addr("127.0.0.1"), 0x7f00_0001);
        assert_eq!(convert_addr("nonsense"), 0);
        // A missing component is zero, the same as the reference's `undefined & 0xff`.
        assert_eq!(convert_addr("1.2"), 0x0102_0000);
        // A script picks this argument, so the extra components are its choice too. The
        // reference's `|` chain reads four and stops; reading a fifth here would shift by
        // more than the accumulator has, which is a panic in a debug build and a wrong
        // answer in a release one.
        assert_eq!(convert_addr("1.2.3.4.5"), 0x0102_0304);
        // Whitespace around a component is trimmed, which this function's doc lists among
        // the spellings that agree with the reference — JS `ToNumber` trims before `&`.
        // This line is the only thing holding it: without the trim a spaced component reads
        // as the `0` that junk gets, so the address quietly loses an octet instead of being
        // refused.
        assert_eq!(convert_addr("127.0.0. 1"), 0x7f00_0001);
    }

    // The `|` chain in Mozilla's `ascii_pac_utils.js` evaluates to a *signed* int32, so every
    // address with the high bit set comes back negative — `255.255.255.255` is `-1` in Firefox.
    #[test]
    fn the_high_bit_makes_the_result_negative_as_in_the_reference() {
        assert_eq!(convert_addr("255.255.255.255"), -1);
        assert_eq!(convert_addr("128.0.0.0"), i32::MIN);
        assert_eq!(convert_addr("192.168.0.1"), 0xc0a8_0001_u32 as i32);
        assert!(
            convert_addr("200.0.0.0") < convert_addr("10.0.0.0"),
            "the browser ordering is what a PAC file was written against"
        );
    }

    #[test]
    fn the_default_policy_makes_the_network_functions_inert() {
        let policy = PacPolicy::new();
        assert_eq!(dns_resolve("example.com", &policy), None);
        assert!(!is_resolvable("example.com", &policy));
        assert!(!is_in_net("example.com", "10.0.0.0", "255.0.0.0", &policy));
        assert_eq!(my_ip_address(&policy), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn literals_never_need_the_resolver() {
        let policy = PacPolicy::new();
        assert_eq!(
            dns_resolve("10.1.2.3", &policy),
            Some(Ipv4Addr::new(10, 1, 2, 3))
        );
        assert!(is_resolvable("10.1.2.3", &policy));
        // The module doc's **(d)**: the host is trimmed before anything reads it, and the
        // bracket strip runs on the trimmed text. Without that order a padded literal is no
        // literal, so it falls through to a name lookup — of a string with spaces in it,
        // which under a policy that does resolve costs a query and answers nothing.
        assert!(is_resolvable(" ::1 ", &policy));
        assert!(is_resolvable(" [::1] ", &policy));
        assert!(is_in_net("10.1.2.3", "10.0.0.0", "255.0.0.0", &policy));
        assert!(!is_in_net("11.1.2.3", "10.0.0.0", "255.0.0.0", &policy));
        assert!(!is_in_net("10.1.2.3", "10.0.0.0", "not-a-mask", &policy));
    }

    // Which spellings count as a literal is the resolver's question for `dnsResolve` and
    // the PAC library's for `isInNet`, so the same string means different things to them —
    // in the reference as well, where `isInNet` gates on `isValidIpAddress` and
    // `dnsResolve` is a host binding. `Ipv4Addr::from_str` answers neither question: read
    // through it, a padded, hex or short spelling becomes a *name* lookup of a string that
    // is an address, which the default policy answers with JavaScript `null`.
    #[test]
    fn dns_resolve_reads_a_literal_the_way_a_resolver_does() {
        let policy = PacPolicy::new();
        assert_eq!(
            dns_resolve("010.1.2.3", &policy),
            Some(Ipv4Addr::new(8, 1, 2, 3)),
            "a leading zero is octal"
        );
        assert_eq!(
            dns_resolve("0x7f.0.0.1", &policy),
            Some(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            dns_resolve("123", &policy),
            Some(Ipv4Addr::new(0, 0, 0, 123)),
            "a short form fills from the right"
        );
        assert!(is_resolvable("192.168.001.007", &policy));
        // `isInNet` keeps the library's decimal reading of the same string.
        assert!(is_in_net(
            "010.1.2.3",
            "10.1.2.3",
            "255.255.255.255",
            &policy
        ));
        assert!(!is_in_net(
            "010.1.2.3",
            "8.1.2.3",
            "255.255.255.255",
            &policy
        ));
        // A name is still a name, and a spelling neither grammar accepts is not an address.
        assert_eq!(dns_resolve("example.com", &policy), None);
        assert!(!is_resolvable("1.2.3.4.5", &policy));
        assert_eq!(dns_resolve("256.0.0.1", &policy), None);
    }

    // `isValidIpAddress` is `\d{1,3}` per group plus a `> 255` check, so the zero padding
    // an administrator writes into a PAC file is a valid address in both references — and
    // the anchored regex means surrounding whitespace is not. `Ipv4Addr::from_str` had it
    // exactly the other way round, so a rule spelled `192.168.001.000` matched no host at
    // all and one spelled ` 10.0.0.0` matched where the browsers match nothing.
    #[test]
    fn is_in_net_reads_addresses_with_the_reference_grammar() {
        let policy = PacPolicy::new();
        let mask = "255.255.255.000";
        assert!(is_in_net(
            "192.168.001.007",
            "192.168.001.000",
            mask,
            &policy
        ));
        assert!(!is_in_net(
            "192.168.002.007",
            "192.168.001.000",
            mask,
            &policy
        ));
        // The unpadded spelling keeps working, on either side of the comparison.
        assert!(is_in_net(
            "192.168.1.7",
            "192.168.001.000",
            "255.255.255.0",
            &policy
        ));
        // Anchored, so no surrounding whitespace...
        assert!(!is_in_net("10.1.2.3", " 10.0.0.0", "255.0.0.0", &policy));
        assert!(!is_in_net("10.1.2.3", "10.0.0.0", "255.0.0.0 ", &policy));
        // ...and no group longer than the `\d{1,3}` the regex allows.
        assert!(!is_in_net("10.1.2.3", "0010.0.0.0", "255.0.0.0", &policy));
        // ...and nothing after the fourth group, which is the other half of the `$` and the
        // half these two lines alone hold. It is not a spelling nobody writes — a fifth
        // group is what a typo in a hand-maintained PAC file looks like, and reading
        // `10.0.0.0.9` as `10.0.0.0` would silently turn a rule the browsers ignore into one
        // that matches a sixteenth of the address space. `1.2.3.4.5` is already refused on
        // the `dnsResolve` side, by the other grammar; this is the same claim about the one
        // `isInNet` reads.
        assert!(!is_in_net("10.1.2.3", "10.0.0.0.9", "255.0.0.0", &policy));
        assert!(!is_in_net("10.1.2.3", "10.0.0.0", "255.0.0.0.9", &policy));
        // A group over 255 is still not an address, padded or not.
        assert!(!is_in_net("10.1.2.3", "256.0.0.0", "255.0.0.0", &policy));
        assert!(!is_in_net("10.1.2.3", "10.0.0.0", "255.0.0.256", &policy));
    }

    #[test]
    fn bracketed_ipv6_literals_count_as_resolvable() {
        let policy = PacPolicy::new();
        assert_eq!(dns_resolve("[::1]", &policy), None);
        assert!(is_resolvable("[::1]", &policy));
        assert!(is_resolvable("[2001:db8::1]", &policy));
    }

    /// Brackets are unwrapped around an IPv6 address and nowhere else, because the IPv6
    /// spelling is the only one this crate's own `host` argument can carry (`evaluate`
    /// passes Gecko's bracketed form) and neither reference unwraps at all: Gecko's
    /// `PACResolve` hands the string to its DNS service as written, and Chromium's
    /// `GetHostnameArgument` does IDN-to-punycode only, over a host it already stripped
    /// with `GURL::HostNoBrackets()`.
    ///
    /// The general strip answered these: `dnsResolve("[10.1.2.3]")` was 10.1.2.3 and
    /// `isResolvable("[example.com]")` asked the resolver about `example.com`, so a script
    /// branching on either got an answer for a host it had not named. Now the bracketed
    /// text goes to the resolver as written, which under a policy that does not resolve is
    /// `null`/`false` and under one that does is a lookup that fails.
    #[test]
    fn only_an_ipv6_literal_loses_its_brackets() {
        let policy = PacPolicy::new();
        assert_eq!(dns_resolve("[10.1.2.3]", &policy), None);
        assert!(!is_resolvable("[10.1.2.3]", &policy));
        assert!(!is_resolvable("[example.com]", &policy));
        // Not a bracket rule that leaked into the bare spellings: those still answer.
        assert_eq!(
            dns_resolve("10.1.2.3", &policy),
            Some(Ipv4Addr::new(10, 1, 2, 3))
        );
        // A half-bracketed string is not bracketed at all, in `strip_brackets` and here.
        assert!(!is_resolvable("[::1", &policy));
        assert!(!is_resolvable("::1]", &policy));
    }

    // One row per arm of the filter, because a row is the only thing that holds an arm —
    // the broadcast, multicast, protocol-assignment, unspecified-IPv6 and IPv6-multicast
    // arms answer to nothing else in the tree. What that costs is not
    // hypothetical — this is the filter that decides which addresses `dnsResolve` may hand
    // back to an untrusted script, so an arm that quietly stops firing turns a range the
    // script must not be able to probe into one it can.
    #[test]
    fn internal_ranges_are_recognised() {
        for internal in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            // The far end of each range written by hand, so that the width is pinned and
            // not just the near edge. Without these rows, the shared-address block can lose
            // a second octet and the benchmarking block can shrink to a /16 unnoticed.
            "100.127.255.255",
            "198.18.0.1",
            "198.19.255.255",
            "0.0.0.0",
            // "This network" is the whole 0.0.0.0/8, not just its `{0,0}` corner:
            // RFC 1122 §3.2.1.3 reads `{0, host}` as a host on *this* network, which is
            // the same thing 169.254.0.0/16 says and belongs in the filter for the same
            // reason. `Ipv4Addr::is_unspecified` covers one address of the sixteen million.
            "0.1.2.3",
            "0.255.255.255",
            // Reserved, 240.0.0.0/4, whose last address is the limited broadcast.
            "240.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            // IETF protocol assignments, which is where the DNS64 well-known prefix and
            // the port-control anycast address live.
            "192.0.0.1",
            // Documentation, all three blocks.
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            // Deprecated 6to4 relay anycast.
            "192.88.99.1",
            "::1",
            "::",
            "ff02::1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_internal(internal.parse().unwrap()), "{internal}");
        }
        for external in [
            "8.8.8.8",
            "93.184.216.34",
            // One address outside each range written as an octet test rather than taken
            // from `std`, which is where an off-by-one in any of them would show. The
            // last globally reachable address is 223.255.255.254: 224.0.0.0 upwards is
            // multicast and then reserved, with nothing routable in between.
            "192.0.1.1",
            "192.0.3.1",
            "192.88.100.1",
            "198.51.101.1",
            "203.0.114.1",
            "223.255.255.254",
            "100.128.0.1",
            "198.20.0.1",
            "1.0.0.1",
            "2606:2800:220:1::1",
        ] {
            assert!(!is_internal(external.parse().unwrap()), "{external}");
        }
    }

    // Which addresses `with_internal_addresses` governs is a question the flag has to
    // answer itself, because its own doc names ULA — a range only IPv6 can be in.
    #[test]
    fn allowing_internal_addresses_admits_the_mapped_spelling_and_not_the_native_one() {
        let allowed = PacPolicy::new()
            .with_dns_resolution(true)
            .with_internal_addresses(true);
        let denied = PacPolicy::new().with_dns_resolution(true);

        // `(literal, 0).to_socket_addrs()` answers from the literal, without a resolver.
        let mapped = "::ffff:10.0.0.1";
        assert_eq!(
            resolve_ipv4(mapped, &allowed),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(resolve_ipv4(mapped, &denied), None);

        // The ULA spelling of an internal address is dropped either way: `dnsResolve` is
        // IPv4-only, so it never reaches the rule `is_internal` keeps for it.
        assert_eq!(resolve_ipv4("fd00::1", &allowed), None);
        assert_eq!(resolve_ipv4("fd00::1", &denied), None);
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn weekday_ranges() {
        let policy = pinned(); // Thursday
        assert!(weekday_range(&strings(&["THU"]), &policy));
        assert!(!weekday_range(&strings(&["FRI"]), &policy));
        assert!(weekday_range(&strings(&["MON", "FRI"]), &policy));
        assert!(weekday_range(&strings(&["MON", "FRI", "GMT"]), &policy));
        assert!(!weekday_range(&strings(&["SAT", "SUN"]), &policy));
        // A wrapping range: Friday through Monday covers the weekend, not Thursday.
        assert!(!weekday_range(&strings(&["FRI", "MON"]), &policy));
        assert!(!weekday_range(&strings(&["NOPE"]), &policy));
        assert!(!weekday_range(&[], &policy));
        // "Excess args after GMT peel → `false` here; ref often ignores them" is a claim
        // the module doc makes and this row alone holds. Ignoring the tail — the ref's reading —
        // leaves Monday-to-Friday, which covers the pinned Thursday, so the row that
        // separates the two answers has to be one whose prefix matches.
        assert!(!weekday_range(&strings(&["MON", "FRI", "THU"]), &policy));
    }

    #[test]
    fn date_ranges() {
        let policy = pinned(); // 2024-02-29
        assert!(date_range(&strings(&["29"]), &policy));
        assert!(!date_range(&strings(&["28"]), &policy));
        assert!(date_range(&strings(&["FEB"]), &policy));
        assert!(date_range(&strings(&["2024"]), &policy));
        assert!(date_range(&strings(&["JAN", "MAR"]), &policy));
        assert!(date_range(&strings(&["1", "31"]), &policy));
        assert!(date_range(&strings(&["2020", "2030"]), &policy));
        // The wrapping half of the two-value form, which the module doc contrasts with
        // `timeRange`'s two-argument form: a range whose end precedes its start runs
        // through the turn of the year rather than matching nothing. Only the ordered
        // direction was pinned, so the branch the doc singles out went unexercised.
        assert!(date_range(&strings(&["NOV", "FEB"]), &policy));
        assert!(!date_range(&strings(&["NOV", "JAN"]), &policy));
        assert!(date_range(&strings(&["25", "5"]), &policy));
        assert!(!date_range(&strings(&["1", "28"]), &policy));
        assert!(date_range(&strings(&["1", "FEB", "5", "MAR"]), &policy));
        assert!(!date_range(&strings(&["1", "MAR", "5", "APR"]), &policy));
        assert!(date_range(
            &strings(&["JAN", "2024", "DEC", "2024"]),
            &policy
        ));
        assert!(date_range(
            &strings(&["1", "JAN", "2024", "31", "DEC", "2024"]),
            &policy
        ));
        assert!(!date_range(
            &strings(&["1", "JAN", "2025", "31", "DEC", "2025"]),
            &policy
        ));
        assert!(!date_range(&strings(&["bogus"]), &policy));
        assert!(!date_range(&strings(&["1", "2", "3"]), &policy));
        // The day/year boundary, which this row alone holds: reading a number from 32 upwards
        // as a year — the ref's rule, and the divergence the module doc lists — turns this
        // into a range spanning 2024 and matching. Refused here, because the range has no
        // year in it that anyone meant.
        assert!(!date_range(&strings(&["99", "2024"]), &policy));
        // The far end of that refused span. The module doc names it as 32..=999, and the row
        // above only holds where it starts — nothing there separates a threshold of 100 from
        // one of 32. 999 is the last number the doc says is neither a day nor a year,
        // and it is what makes the threshold read 1000 — four digits, the shape of the
        // "2016 (not 16)" the argument set asks for.
        assert!(!date_range(&strings(&["999", "2024"]), &policy));
    }

    // The two references build `dateRange`'s upper bound by calling `setMonth` on 31
    // December, and JavaScript normalises the overflow: `setMonth(1)` on 31 December is
    // 31 February, i.e. 2 or 3 March. `dateRange("JAN", "FEB")` therefore keeps matching
    // for the first days of March in both Firefox and Chrome. Reproducing an arithmetic
    // slip is not fidelity, so this crate ends the range with February — the module doc
    // lists the difference, and this pins it.
    #[test]
    fn a_range_ending_in_a_short_month_does_not_spill_into_the_next_one() {
        // 2024-03-02T00:00:00Z, inside the ref's overflow and outside February.
        let march = PacPolicy::new().with_now(UNIX_EPOCH + Duration::from_secs(1_709_337_600));
        assert!(!date_range(&strings(&["JAN", "FEB"]), &march));
        // The last instant that *is* February still matches, so the range itself is intact.
        assert!(date_range(&strings(&["JAN", "FEB"]), &pinned()));
    }

    #[test]
    fn date_range_overflowing_years_do_not_panic() {
        // A year large enough that `year * 10_000` (or `year * 100`) overflows `i64` must
        // report no match rather than panicking in a debug build.
        let policy = pinned();
        assert!(!date_range(
            &strings(&[
                "1",
                "JAN",
                "999999999999999999",
                "31",
                "DEC",
                "999999999999999999"
            ]),
            &policy
        ));
        assert!(!date_range(
            &strings(&["JAN", "999999999999999999", "DEC", "999999999999999999"]),
            &policy
        ));
    }

    #[test]
    fn time_ranges() {
        let policy = pinned(); // 13:45:07
        assert!(time_range(&strings(&["13"]), &policy));
        assert!(!time_range(&strings(&["14"]), &policy));
        assert!(time_range(&strings(&["8", "17"]), &policy));
        assert!(!time_range(&strings(&["18", "20"]), &policy));
        assert!(time_range(&strings(&["13", "0", "13", "59"]), &policy));
        assert!(!time_range(&strings(&["13", "0", "13", "30"]), &policy));
        // The ending minute is whole — the four-argument form runs to :59 — so 13:45:07 is
        // inside a range written as ending at 13:45. This row is the only thing that would
        // see it end at :00 instead — the `13,0,13,59` above included, because that end is a
        // quarter of an hour past the pinned clock whichever second it carries.
        assert!(time_range(&strings(&["13", "0", "13", "45"]), &policy));
        assert!(time_range(
            &strings(&["13", "45", "0", "13", "45", "10"]),
            &policy
        ));
        assert!(!time_range(
            &strings(&["13", "45", "0", "13", "45", "5"]),
            &policy
        ));
        // Wrapping across midnight.
        assert!(!time_range(&strings(&["22", "0", "6", "0"]), &policy));
        assert!(time_range(&strings(&["12", "0", "6", "0"]), &policy));
        assert!(!time_range(&strings(&["nope"]), &policy));
    }

    #[test]
    fn time_range_two_argument_form_never_wraps_midnight() {
        // 2024-02-29T23:30:00Z: 23:30, an hour that a *wrapping* 22-6 range would cover.
        let policy = PacPolicy::new().with_now(UNIX_EPOCH + Duration::from_secs(1_709_249_400));
        assert!(!time_range(&strings(&["22", "6"]), &policy));
        // The 4-argument form, at the same instant, does wrap.
        assert!(time_range(&strings(&["22", "0", "6", "0"]), &policy));
    }

    #[test]
    fn time_range_overflowing_hours_do_not_panic() {
        // The arguments are unbounded `i64`s, unlike `dateRange`'s classified parts, so
        // `hour * 3600` must not overflow into a debug-build panic.
        let policy = pinned();
        assert!(!time_range(
            &strings(&["999999999999999999", "0", "999999999999999999", "0"]),
            &policy
        ));
        assert!(!time_range(
            &strings(&[
                "999999999999999999",
                "0",
                "0",
                "999999999999999999",
                "0",
                "0"
            ]),
            &policy
        ));
    }

    #[test]
    fn the_local_offset_shifts_the_clock() {
        // 13:45 UTC becomes 22:45 in UTC+9.
        let policy = pinned().with_local_utc_offset(9 * 3600);
        assert!(time_range(&strings(&["22"]), &policy));
        assert!(time_range(&strings(&["13", "GMT"]), &policy));
    }

    #[test]
    fn the_default_policy_reads_the_clock_as_gmt() {
        // `time_ranges` above already pins 13:45 as the hour, but not why. The offset is 0
        // unless the caller sets it, so an argument list without `"GMT"` answers exactly as
        // one with it — the divergence from the browser reference that `PacPolicy`'s doc
        // records. A non-zero default separates the two, and would otherwise show up as an
        // arithmetic failure in every other test here rather than as a moved default.
        let policy = pinned();
        assert_eq!(
            time_range(&strings(&["13"]), &policy),
            time_range(&strings(&["13", "GMT"]), &policy)
        );
        assert!(time_range(&strings(&["13", "GMT"]), &policy));
    }

    #[test]
    fn alert_never_fails_whatever_it_is_handed() {
        // Without the `tracing` feature this goes nowhere; with it, `crate::trace` owns
        // the sanitising, which is tested there.
        alert("this goes nowhere");
        alert("newlines\nand\rcontrol\u{7}characters");
        alert(&"x".repeat(100_000));
    }
}
