//! Calendar arithmetic for `weekdayRange`, `dateRange` and `timeRange`.
//!
//! The crate takes no time zone dependency, so the whole calendar is derived from a
//! Unix timestamp with Howard Hinnant's `civil_from_days` algorithm. "Local time" is
//! UTC shifted by [`PacPolicy::local_utc_offset`](super::PacPolicy::local_utc_offset).

use std::time::{SystemTime, UNIX_EPOCH};

use super::policy::PacPolicy;

// A broken-down calendar instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Civil {
    pub(crate) year: i64,
    // 1..=12.
    pub(crate) month: i64,
    // 1..=31.
    pub(crate) day: i64,
    pub(crate) hour: i64,
    pub(crate) minute: i64,
    pub(crate) second: i64,
    // 0 = Sunday .. 6 = Saturday.
    pub(crate) weekday: i64,
}

// The instant the policy says "now" is, in GMT or in its notion of local time.
pub(crate) fn civil_now(policy: &PacPolicy, gmt: bool) -> Civil {
    let base = policy.now().unwrap_or_else(SystemTime::now);
    let secs = match base.duration_since(UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        // Before 1970: `duration_since` reports the *magnitude* of the negative delta, so
        // negating `as_secs()` truncates towards zero — away from the instant. The rest of
        // this module floors (`civil_from_unix`), and mixing the two rounds
        // 1969-12-31T23:59:59.5Z up to 1970-01-01T00:00:00Z, which is a different day, a
        // different weekday and the far side of any `dateRange` drawn at the epoch. Carry
        // the fraction into the magnitude before negating so that this side floors too.
        Err(err) => {
            let magnitude = err.duration();
            let secs = magnitude
                .as_secs()
                .saturating_add(u64::from(magnitude.subsec_nanos() != 0));
            -i64::try_from(secs).unwrap_or(i64::MAX)
        }
    };
    let secs = if gmt {
        secs
    } else {
        secs.saturating_add(i64::from(policy.local_utc_offset()))
    };
    civil_from_unix(secs)
}

// Break a Unix timestamp down into a [`Civil`] instant.
pub(crate) fn civil_from_unix(secs: i64) -> Civil {
    // Floor division, so that instants before 1970 land on the right day.
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Civil {
        year,
        month,
        day,
        hour: rem / 3600,
        minute: (rem / 60) % 60,
        second: rem % 60,
        // 1970-01-01 was a Thursday, which is index 4 in a Sunday-first week.
        weekday: (days + 4).rem_euclid(7),
    }
}

// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a proleptic Gregorian
// year/month/day. Exact for the whole range this crate can produce.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March-based
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// `lo..=hi` on a cycle: when `lo > hi` the range wraps around the end of the cycle,
// which is what `weekdayRange("FRI", "MON")` and `timeRange(22, 0, 6, 0)` mean.
pub(crate) fn in_cyclic_range(value: i64, lo: i64, hi: i64) -> bool {
    if lo <= hi {
        lo <= value && value <= hi
    } else {
        value >= lo || value <= hi
    }
}

// `SUN`..`SAT` to 0..6, case-insensitively. `None` for anything else.
pub(crate) fn weekday_index(name: &str) -> Option<i64> {
    const DAYS: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];
    let name = name.trim().to_ascii_uppercase();
    DAYS.iter()
        .position(|day| *day == name)
        .map(|index| index as i64)
}

// `JAN`..`DEC` to 1..12, case-insensitively. `None` for anything else.
//
// Trimmed and case-insensitive for the same reason as [`weekday_index`], and with the
// same documented divergence from the reference implementation.
pub(crate) fn month_index(name: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
    ];
    let name = name.trim().to_ascii_uppercase();
    MONTHS
        .iter()
        .position(|month| *month == name)
        .map(|index| index as i64 + 1)
}

// Peel off a trailing `"GMT"` argument. The three time functions — `weekdayRange`,
// `dateRange` and `timeRange` — each take it as an optional last parameter, so stripping
// it lives here rather than in each of them.
pub(crate) fn split_gmt(args: &[String]) -> (&[String], bool) {
    match args.last() {
        Some(last) if last.trim().eq_ignore_ascii_case("GMT") => (&args[..args.len() - 1], true),
        _ => (args, false),
    }
}

// Read a PAC numeric argument. JavaScript hands numbers to the host as `12`, so the
// textual form is parsed as a float and truncated.
pub(crate) fn number(text: &str) -> Option<i64> {
    let value: f64 = text.trim().parse().ok()?;
    if value.is_finite() {
        Some(value as i64)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn epoch_is_a_thursday() {
        let civil = civil_from_unix(0);
        assert_eq!((civil.year, civil.month, civil.day), (1970, 1, 1));
        assert_eq!(civil.weekday, 4);
        assert_eq!((civil.hour, civil.minute, civil.second), (0, 0, 0));
    }

    #[test]
    fn known_instants_round_trip() {
        // 2024-02-29T13:45:07Z, a leap day, Thursday.
        let civil = civil_from_unix(1_709_214_307);
        assert_eq!((civil.year, civil.month, civil.day), (2024, 2, 29));
        assert_eq!((civil.hour, civil.minute, civil.second), (13, 45, 7));
        assert_eq!(civil.weekday, 4);

        // 2000-03-01T00:00:00Z, the day after the century leap day, Wednesday.
        let civil = civil_from_unix(951_868_800);
        assert_eq!((civil.year, civil.month, civil.day), (2000, 3, 1));
        assert_eq!(civil.weekday, 3);
    }

    // `civil_from_days` is the one piece of arithmetic here that is copied rather than derived,
    // and two of its terms are reached by no date above. This test is the only thing holding
    // either of them.
    //
    // 2000-02-29 is the only day in four hundred years that reaches the last correction in
    // `yoe`. `doe` runs 0..=146096 and `doe / 146_096` is 1 on that final day of an era alone —
    // the century leap day the 400-year rule keeps. Without it that date answers 2000-03-01, one
    // day late, and the row above cannot see it because it pins 2000-03-01 itself and an ordinary
    // leap day, either side of the only day that moves. The weekday does not move with it, being
    // counted from the day index rather than from the year, so `dateRange` and `weekdayRange`
    // start disagreeing about which day it is instead of both being wrong.
    //
    // The floor in `era` is the other. Before 0000-03-01 the shift by 146_096 is what keeps that
    // division flooring, and without it this instant answers year 1, month 2, day **-29** — a
    // `Civil` with a negative day, which `date_range` then compares numerically. That end is
    // reachable rather than theoretical: `SystemTime` is not clamped at its platform epoch, and
    // `UNIX_EPOCH.checked_sub` of sixty-two billion seconds answers `Some` even on Windows, whose
    // `FILETIME` counts from 1601 — measured, and `with_now` carries the result into `civil_now`
    // unchanged. The module doc calls the algorithm exact for the whole range this crate can
    // produce; this is where that range ends.
    #[test]
    fn the_two_era_corrections_are_each_reached_by_one_date() {
        let civil = civil_from_unix(951_782_400);
        assert_eq!((civil.year, civil.month, civil.day), (2000, 2, 29));

        let civil = civil_from_unix(-62_167_219_200);
        assert_eq!((civil.year, civil.month, civil.day), (0, 1, 1));
    }

    // `civil_from_unix` is what `instants_before_the_epoch_floor_correctly` below pins, and
    // it floors. This one pins the step *before* it — the `SystemTime` → seconds conversion
    // in `civil_now`, the only place where the sign is recovered from a magnitude and so
    // the only place the two roundings can disagree. `with_now` is public and documented
    // for "reproducing a routing decision after the fact", which is how a caller reaches a
    // pre-1970 instant at all; half a second is enough, because the whole question is what
    // happens to the fraction.
    #[test]
    fn a_pre_epoch_instant_with_a_fraction_floors_like_every_other_one() {
        let policy = PacPolicy::default().with_now(UNIX_EPOCH - Duration::from_millis(500));
        let civil = civil_now(&policy, true);
        assert_eq!(
            (civil.year, civil.month, civil.day),
            (1969, 12, 31),
            "1969-12-31T23:59:59.5Z must not round up into 1970"
        );
        assert_eq!((civil.hour, civil.minute, civil.second), (23, 59, 59));
        // Wednesday, not the epoch's Thursday: a `weekdayRange("WED")` and a `dateRange`
        // drawn either side of the epoch both answer differently from the truncated value.
        assert_eq!(civil.weekday, 3);
    }

    #[test]
    fn instants_before_the_epoch_floor_correctly() {
        // 1969-12-31T23:59:59Z, a Wednesday.
        let civil = civil_from_unix(-1);
        assert_eq!((civil.year, civil.month, civil.day), (1969, 12, 31));
        assert_eq!((civil.hour, civil.minute, civil.second), (23, 59, 59));
        assert_eq!(civil.weekday, 3);

        // 1969-01-01T00:00:00Z, also a Wednesday, and the row the weekday rounding needs:
        // the day index is `-1` above, where `%` and `rem_euclid` still agree, and every
        // other pre-epoch instant in this file is inside those four days. This row is the
        // only thing that would notice the weekday read with `%`, which answers `-4` here —
        // an index no name in `weekday_index`'s table has, so `weekdayRange("WED")` stops
        // matching on a Wednesday rather than failing. `PacPolicy::with_now` is public and
        // documented for replaying a decision after the fact, which is how a script reaches
        // an instant this old at all.
        let civil = civil_from_unix(-31_536_000);
        assert_eq!((civil.year, civil.month, civil.day), (1969, 1, 1));
        assert_eq!(civil.weekday, 3);
    }

    #[test]
    fn cyclic_ranges_wrap() {
        assert!(in_cyclic_range(3, 1, 5));
        assert!(!in_cyclic_range(6, 1, 5));
        // FRI(5) .. MON(1) covers the weekend.
        assert!(in_cyclic_range(6, 5, 1));
        assert!(in_cyclic_range(0, 5, 1));
        assert!(!in_cyclic_range(3, 5, 1));
    }

    // Every name, not two of each: `position` hands each entry its index, so one typo
    // makes that name permanently unmatchable and a transposition shifts two — and either
    // way the PAC function just answers "no", with nothing for the caller to see. Sampling
    // the first and last entry cannot reach that; the interior is where it hides. The
    // lists here are a second, independently written copy on purpose: editing one table
    // without the other is exactly what has to go red.
    #[test]
    fn name_tables() {
        for (index, name) in ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
            .into_iter()
            .enumerate()
        {
            assert_eq!(weekday_index(name), Some(index as i64), "{name}");
        }
        for (index, name) in [
            "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(month_index(name), Some(index as i64 + 1), "{name}");
        }
        assert_eq!(weekday_index("sun"), Some(0));
        assert_eq!(month_index("jan"), Some(1));
        assert_eq!(weekday_index("Someday"), None);
        assert_eq!(month_index("Smarch"), None);
    }

    // `hostfn`'s module doc files the whole vocabulary of these functions under **(d)**:
    // trimmed and case-folded here, exact in the reference. The row above reaches the case
    // half for the names and nothing reaches the padding, and the `"GMT"` argument had
    // neither — yet it is the one whose loss moves an answer rather than merely refusing it.
    // Read strictly, a script that wrote it in lower case still gets a trailing argument,
    // just not this one: `weekdayRange("MON", "gmt")` becomes a range whose far end is not a
    // day at all, and `timeRange` reads the local clock the caller asked to step out of.
    #[test]
    fn the_gmt_peel_and_the_name_tables_forgive_padding_and_case() {
        for spelling in ["GMT", "gmt", " GMT", "Gmt\t"] {
            let args = [String::from("MON"), String::from(spelling)];
            let (rest, gmt) = split_gmt(&args);
            assert!(gmt, "{spelling}");
            assert_eq!(rest, [String::from("MON")], "{spelling}");
        }

        // A trailing argument that is not the flag stays where the script put it.
        let args = [String::from("FRI"), String::from("MON")];
        assert_eq!(split_gmt(&args), (&args[..], false));

        assert_eq!(weekday_index(" sun\t"), Some(0));
        assert_eq!(month_index("\ndec "), Some(12));
    }

    // JavaScript spells its non-finite numbers `NaN` and `Infinity`, `boa` hands host
    // functions the spelling rather than the value, and `f64::from_str` reads both back.
    // Neither is a bound a script can have meant: `as i64` saturates the one to the largest
    // there is and truncates the other to zero, so `dateRange(1/0)` would cover every day
    // and `timeRange(0/0)` the hour after midnight. Refusing them is what leaves the call
    // malformed, which is the answer the reference gives it too.
    #[test]
    fn a_non_finite_argument_is_not_a_bound() {
        assert_eq!(number("NaN"), None);
        assert_eq!(number("Infinity"), None);
        assert_eq!(number("-Infinity"), None);

        // The ordinary readings stand: padded, and truncated where JS wrote a fraction.
        assert_eq!(number(" 12 "), Some(12));
        assert_eq!(number("13.9"), Some(13));
        assert_eq!(number("MON"), None);
    }
}
