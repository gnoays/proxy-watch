//! Leading desktop store from `XDG_CURRENT_DESKTOP` (colon list; case-insensitive).
//! Fallback when that variable is unset or holds nothing but whitespace: Chromium-style
//! `DESKTOP_SESSION` / `GNOME_DESKTOP_SESSION_ID` / `KDE_FULL_SESSION`
//! ([`classify_with_fallback`]). A value that is present and names some *other* desktop is
//! an answer, not a gap, so it stops there rather than falling back.

// Compiled on every target under `cfg(test)` so that the tables below are exercised in
// CI on Windows and macOS too. Off Linux nothing outside this module's own tests calls in
// at all; on Linux with both features off the backend still calls in, but the items that
// answer for a compiled-out store do not. That is what the allow below is for; it is not
// that the items disappear in such a build.
#![cfg_attr(
    not(all(
        target_os = "linux",
        any(feature = "linux-gnome", feature = "linux-kde")
    )),
    allow(dead_code)
)]

use crate::config::{ProxyConfig, ProxyConfigSource};
use crate::error::Error;
use crate::mode::ProxyMode;

pub(crate) const XDG_CURRENT_DESKTOP: &str = "XDG_CURRENT_DESKTOP";

// Chromium's next fallback after `XDG_CURRENT_DESKTOP` (`base/nix/xdg_util.cc`,
// `GetDesktopEnvironment()`) — "what everyone used in 2010", in that function's own
// comment.
pub(crate) const DESKTOP_SESSION: &str = "DESKTOP_SESSION";

// A variable Chromium only checks for *presence*, after `DESKTOP_SESSION` has also
// produced no recognised value — an older, GNOME-specific signal. "No recognised value"
// rather than "empty": a `DESKTOP_SESSION` Chromium does not know falls through to here
// just as an absent one does.
pub(crate) const GNOME_DESKTOP_SESSION_ID: &str = "GNOME_DESKTOP_SESSION_ID";

// The KDE twin of [`GNOME_DESKTOP_SESSION_ID`], also checked for presence only.
pub(crate) const KDE_FULL_SESSION: &str = "KDE_FULL_SESSION";

// A desktop settings store this crate can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Store {
    // GNOME's `org.gnome.system.proxy` GSettings schema.
    GSettings,
    // KDE's `kioslaverc`.
    Kioslaverc,
}

// The desktop `XDG_CURRENT_DESKTOP` named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Desktop {
    // A GSettings-based desktop: GNOME itself, or one of its forks.
    Gnome,
    // Plasma / KDE.
    Kde,
    // Nothing recognisable — an empty variable, a bare login shell, a container, a
    // tiling window manager, …
    Unknown,
}

// Tokens that mean "this desktop keeps its proxy settings in `kioslaverc`".
const KDE_TOKENS: [&str; 2] = ["kde", "plasma"];

// Tokens that mean "this desktop keeps its proxy settings in GSettings".
//
// The GNOME forks are listed explicitly because they all ship
// `gsettings-desktop-schemas` and write `org.gnome.system.proxy`, while their
// `XDG_CURRENT_DESKTOP` says nothing about GNOME.
const GNOME_TOKENS: [&str; 8] = [
    "gnome",
    "gnome-classic",
    "gnome-flashback",
    "unity",
    "x-cinnamon",
    "cinnamon",
    "mate",
    "pantheon",
];

// Classify the value of `XDG_CURRENT_DESKTOP`.
//
// KDE wins over GNOME when both appear, because a session that advertises Plasma at all
// is a Plasma session: the GNOME schemas may still be installed (KDE distributions ship
// them for GTK applications) but nothing writes them.
pub(crate) fn classify(value: Option<&str>) -> Desktop {
    let Some(value) = value else {
        return Desktop::Unknown;
    };
    // No empty-token filter. An empty token is equal to no entry of either list, so the
    // two `any` calls below skip it without being told to, and a filter that removes it is
    // a step no value of the variable can tell apart from its absence.
    let tokens: Vec<String> = value
        .split(':')
        .map(|token| token.trim().to_ascii_lowercase())
        .collect();

    if tokens.iter().any(|t| KDE_TOKENS.contains(&t.as_str())) {
        return Desktop::Kde;
    }
    if tokens.iter().any(|t| GNOME_TOKENS.contains(&t.as_str())) {
        return Desktop::Gnome;
    }
    Desktop::Unknown
}

// [`classify`], but falling back — only when `xdg_current_desktop` is itself unset or
// empty — to the chain Chromium's `GetDesktopEnvironment()` (`base/nix/xdg_util.cc`)
// uses for the same purpose: `desktop_session`, then the mere presence of
// `gnome_desktop_session_id_present` or `kde_full_session_present`, in that order.
//
// That gate is where this parts company with Chromium, which drops through to the same
// chain whenever *no token matched*, set or not. The reason to stop instead: a
// `XDG_CURRENT_DESKTOP` that names something is an answer, even when it is an answer this
// crate has no store for, and the variables below it are the ones that go stale —
// `DESKTOP_SESSION` is written from the session file a display manager launched, and
// `GNOME_DESKTOP_SESSION_ID` lingers in environments GNOME no longer runs. Overruling the
// modern variable with either would be trusting the older signal precisely where the two
// disagree.
//
// The difference is narrow in any case: it only shows when the chain would have said KDE,
// because [`order`] already puts GSettings first for [`Desktop::Unknown`], which is what
// every GNOME-family answer would have produced anyway.
pub(crate) fn classify_with_fallback(
    xdg_current_desktop: Option<&str>,
    desktop_session: Option<&str>,
    gnome_desktop_session_id_present: bool,
    kde_full_session_present: bool,
) -> Desktop {
    let primary = classify(xdg_current_desktop);
    if !matches!(primary, Desktop::Unknown) {
        return primary;
    }
    let unset_or_empty = xdg_current_desktop.is_none_or(|value| value.trim().is_empty());
    if !unset_or_empty {
        return Desktop::Unknown;
    }

    let from_session = classify_desktop_session(desktop_session.unwrap_or(""));
    if !matches!(from_session, Desktop::Unknown) {
        return from_session;
    }
    // Chromium checks `GNOME_DESKTOP_SESSION_ID` before `KDE_FULL_SESSION`
    // (`base/nix/xdg_util.cc`); mirrored here even though this crate has no case where
    // both would be set on a real machine.
    if gnome_desktop_session_id_present {
        return Desktop::Gnome;
    }
    if kde_full_session_present {
        return Desktop::Kde;
    }
    Desktop::Unknown
}

// Map a `DESKTOP_SESSION` value onto the two stores [`Store`] distinguishes, using the
// value set Chromium's `GetDesktopEnvironment()` (`base/nix/xdg_util.cc`) checks at this
// stage, kept where it resolves to a store this crate has.
//
// These are session-file names, not `XDG_CURRENT_DESKTOP` tokens, which is why the list
// does not simply repeat [`KDE_TOKENS`] and [`GNOME_TOKENS`]: a display manager writes
// `DESKTOP_SESSION` from the name of the session file it launched (`kde4`, `kde-plasma`),
// while the token lists hold the desktop names the XDG spec puts in `XDG_CURRENT_DESKTOP`
// (`kde`, `plasma`). [`classify`] compares whole tokens for equality, so neither `kde4`
// nor `kde-plasma` would be recognised there.
fn classify_desktop_session(value: &str) -> Desktop {
    match value.trim().to_ascii_lowercase().as_str() {
        "gnome" | "mate" => Desktop::Gnome,
        "kde4" | "kde-plasma" | "kde" => Desktop::Kde,
        _ => Desktop::Unknown,
    }
}

// The stores to consult, in descending precedence order.
pub(crate) fn order(desktop: Desktop) -> [Store; 2] {
    match desktop {
        Desktop::Kde => [Store::Kioslaverc, Store::GSettings],
        Desktop::Gnome | Desktop::Unknown => [Store::GSettings, Store::Kioslaverc],
    }
}

// Whether this build can read `store` at all.
//
// The one place the store-to-feature mapping is written. Both the read path
// ([`note_if_the_leading_store_was_compiled_out`]) and the watch
// path ([`watcher::is_leading_store`](super::watcher)) ask this about
// [`order`]`(desktop)[0]`, and a build where the two disagreed would warn about one store
// while watching the other.
pub(crate) fn is_compiled_in(store: Store) -> bool {
    match store {
        Store::GSettings => cfg!(feature = "linux-gnome"),
        Store::Kioslaverc => cfg!(feature = "linux-kde"),
    }
}

// Classify the desktop of the current process.
//
// Reads `XDG_CURRENT_DESKTOP` and, only when needed, the fallback chain
// [`classify_with_fallback`] documents.
pub(crate) fn current() -> Desktop {
    classify_with_fallback(
        text_if_set(std::env::var_os(XDG_CURRENT_DESKTOP)).as_deref(),
        text_if_set(std::env::var_os(DESKTOP_SESSION)).as_deref(),
        std::env::var_os(GNOME_DESKTOP_SESSION_ID).is_some(),
        std::env::var_os(KDE_FULL_SESSION).is_some(),
    )
}

// One variable as [`classify_with_fallback`] needs to see it: `None` only when it is
// genuinely unset.
//
// `env::var().ok()` cannot tell "unset" from "set to bytes that are not UTF-8", and those
// are the two classes [`classify_with_fallback`] divides on: a present-but-unrecognised
// `XDG_CURRENT_DESKTOP` stops there, an unset one falls through to `DESKTOP_SESSION` and
// the presence-only variables — the older signals that go stale, which the doc above
// refuses to consult while the modern variable has spoken. A mangled value belongs to the
// class that stops, and `to_string_lossy` puts it there: its replacement character matches
// no token and is not whitespace, so the value stays present and unrecognised. It is also
// the conversion [`sys::win::ffi`](crate::sys) already applies to registry text that is not
// valid UTF-16. Taking the value rather than the name so the judgement can be tested
// without the process environment, the way the classifiers above are.
fn text_if_set(value: Option<std::ffi::OsString>) -> Option<String> {
    value.map(|value| value.to_string_lossy().into_owned())
}

// What one store had to say when the backend read it.
//
// The three-way split is the whole point: **"nobody configured this store" and "this
// store is deliberately set to go direct" are different answers**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reading {
    // The store does not exist here at all: GNOME's schema is not installed,
    // `kioslaverc` does not exist, or that half of the backend was not compiled in. It
    // contributes nothing, and a machine where *both* stores are `Absent` is
    // [`Error::Unsupported`](crate::Error::Unsupported).
    //
    // A store whose read failed **while the leading store was already `Configured`**
    // also arrives here, softened by [`read_store_fail_soft`] below: its
    // answer would not have been used anyway, so failing the whole lookup over it would
    // refuse an answer this crate is holding. So `Absent` means "contributes nothing",
    // not strictly "does not exist" — which is worth knowing, because it is the one way a
    // store that *did* have something to say can end up contributing nothing at all. A
    // failure with no configured store ahead of it does *not* arrive here: there the
    // store that failed was the effective one, and its error is returned.
    Absent,
    // The store exists, but nobody has ever configured it — see
    // [`super::gsettings_map::configured_mode`] and
    // [`super::kioslaverc::configured_from_kioslaverc`] for how each store tells that
    // apart from an explicit "no proxy".
    Unset,
    // The store carries a configuration, **including a deliberate
    // [`ProxyMode::Direct`]**.
    Configured {
        // Where the values came from. Usually the store itself, but a `ProxyType = 4`
        // `kioslaverc` reports [`ProxyConfigSource::KioslavercEnv`].
        source: ProxyConfigSource,
        // What the store says.
        mode: ProxyMode,
    },
}

impl Reading {
    // A configured store.
    pub(crate) fn configured(source: ProxyConfigSource, mode: ProxyMode) -> Self {
        Self::Configured { source, mode }
    }
}

// Read both stores in precedence order, returning them as `(gsettings, kioslaverc)`.
//
// The two closures are the stores themselves, taken as parameters so this rule can be
// exercised without a GSettings schema or a `kioslaverc` on disk. Written straight through
// rather than as a loop over [`order`] because the rule below is entirely about *which*
// call gets what: the leading store is read with no answer behind it and the trailing one
// with the leading store's answer, and a loop can only keep that true by maintaining a
// mutable "have I read the leading one yet" flag. Here it is the shape of the code.
pub(crate) fn read_in_order(
    desktop: Desktop,
    gnome: impl Fn() -> Result<Reading, Error>,
    kde: impl Fn() -> Result<Reading, Error>,
    fallbacks: &mut Vec<ProxyConfigSource>,
) -> Result<(Reading, Reading), Error> {
    let [leading_store, trailing_store] = order(desktop);
    let leading = match leading_store {
        Store::GSettings => read_store_fail_soft(leading_store, None, &gnome, fallbacks),
        Store::Kioslaverc => read_store_fail_soft(leading_store, None, &kde, fallbacks),
    }?;
    let trailing = match trailing_store {
        Store::GSettings => read_store_fail_soft(trailing_store, Some(&leading), &gnome, fallbacks),
        Store::Kioslaverc => read_store_fail_soft(trailing_store, Some(&leading), &kde, fallbacks),
    }?;
    Ok(match leading_store {
        Store::GSettings => (leading, trailing),
        Store::Kioslaverc => (trailing, leading),
    })
}

// Read one desktop store, softening its error into [`Reading::Absent`] when the leading
// store has already answered with a configuration.
//
// `leading` is what the leading store answered, and `None` when `read` *is* the leading
// store. Softening rests on this store's answer not being the one the caller gets, and
// that holds only while the leading store has an answer of its own: against a leading
// `Configured` — the effective value — this store's failure costs nothing that would have
// been reported. A leading `Unset` or `Absent` makes *this* store the effective one, and
// softening there replaces a configured proxy with a `Direct` that measured nothing. That
// is the silent misdetection this backend exists to prevent; it is also what
// [`super::kde`]'s cascade refuses to produce one layer down, for the same reason, when it
// fails the whole read rather than skipping a layer it cannot parse.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn read_store_fail_soft(
    store: Store,
    leading: Option<&Reading>,
    read: impl FnOnce() -> Result<Reading, Error>,
    fallbacks: &mut Vec<ProxyConfigSource>,
) -> Result<Reading, Error> {
    match read() {
        Ok(reading) => Ok(reading),
        Err(error) if !matches!(leading, Some(Reading::Configured { .. })) => Err(error),
        Err(error) => {
            crate::trace::warning!(
                store = ?store,
                error = %crate::trace::SafeError(&error),
                "a Linux desktop store failed to read, but the leading store is already \
                 configured and is the effective one; treating the failure as absent \
                 instead of failing the whole read"
            );
            // `Reading::Absent` is also what a session with no such store at all produces,
            // and [`assemble`] cannot tell the two apart by the time it runs. This is
            // where the difference still exists, so it is where it gets written down.
            fallbacks.push(match store {
                Store::GSettings => ProxyConfigSource::GSettings,
                Store::Kioslaverc => ProxyConfigSource::Kioslaverc,
            });
            Ok(Reading::Absent)
        }
    }
}

// Warn when the store that would have won is not in this build, and the store that
// therefore wins instead belongs to a desktop nobody is running.
//
// Also the second thing `fallbacks` records on this platform, and the one with the worse
// consequence: a store that failed to read at least tried, while this one was never
// consulted, so the answer below it is confidently wrong rather than merely incomplete.
//
// Here rather than beside its one caller in [`super::backend`] for the reason that file
// states about everything it does not decide itself: these tests are compiled on every
// target, and a `cfg(feature)` rule whose tests only run on Linux is one nothing on this
// project's development machines ever exercises. `compiled_in` is [`is_compiled_in`] taken
// as a parameter for the second half of the same reason — the condition this whole function
// is about never holds in an `--all-features` build, which is the one the tests run in.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
pub(crate) fn note_if_the_leading_store_was_compiled_out(
    desktop: Desktop,
    gsettings: &Reading,
    kioslaverc: &Reading,
    compiled_in: impl Fn(Store) -> bool,
    fallbacks: &mut Vec<ProxyConfigSource>,
) {
    let leading = order(desktop)[0];
    if compiled_in(leading) {
        return;
    }
    let other = match leading {
        Store::GSettings => kioslaverc,
        Store::Kioslaverc => gsettings,
    };
    // Not in the `Absent` arm below: there the caller hears `Error::Unsupported` and never
    // sees a `ProxyConfig` to read this from.
    if !matches!(other, Reading::Absent) {
        fallbacks.push(match leading {
            Store::GSettings => ProxyConfigSource::GSettings,
            Store::Kioslaverc => ProxyConfigSource::Kioslaverc,
        });
    }
    // Every arm below is the same missing store; they differ only in what the caller ends
    // up being told. `Absent` needs no warning of its own: with the leading store compiled
    // out, an `Absent` other store is the case where neither store exists, which the
    // caller already hears as `Error::Unsupported`.
    match other {
        Reading::Configured { .. } => crate::trace::warning!(
            desktop = ?desktop,
            leading_store = ?order(desktop)[0],
            effective_store = ?order(desktop)[1],
            "the desktop store this session's proxy settings would normally come from is not \
             compiled into this build, so the configuration being reported is \
             the other desktop's — which may be stale. Enable the feature for the desktop \
             this process actually runs under."
        ),
        // The quieter half of the same fault, and the more misleading one: nothing is
        // left to report, so the answer is a `Direct` that never measured anything.
        Reading::Unset => crate::trace::warning!(
            desktop = ?desktop,
            leading_store = ?order(desktop)[0],
            effective_store = ?order(desktop)[1],
            "the desktop store this session's proxy settings would normally come from is not \
             compiled into this build, and the other desktop's store holds nothing, so the \
             configuration being reported is `Direct` by default rather than a reading that \
             found no proxy. Enable the feature for the desktop this process actually runs \
             under."
        ),
        Reading::Absent => {}
    }
}

// Turn the two store readings into an effective value and a `sources` list.
pub(crate) fn assemble(
    desktop: Desktop,
    gsettings: &Reading,
    kioslaverc: &Reading,
) -> Option<ProxyConfig> {
    if matches!(gsettings, Reading::Absent) && matches!(kioslaverc, Reading::Absent) {
        return None;
    }

    let mut sources = Vec::with_capacity(2);
    for store in order(desktop) {
        let reading = match store {
            Store::GSettings => gsettings,
            Store::Kioslaverc => kioslaverc,
        };
        if let Reading::Configured { source, mode } = reading {
            sources.push((*source, mode.clone()));
        }
    }

    Some(ProxyConfig::from_ordered_sources(sources))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_common_spellings_are_recognised() {
        for (value, expected) in [
            ("GNOME", Desktop::Gnome),
            ("ubuntu:GNOME", Desktop::Gnome),
            ("GNOME-Classic:GNOME", Desktop::Gnome),
            ("X-Cinnamon", Desktop::Gnome),
            ("MATE", Desktop::Gnome),
            ("Unity:Unity7:ubuntu", Desktop::Gnome),
            ("KDE", Desktop::Kde),
            ("plasma", Desktop::Kde),
            ("KDE:GNOME", Desktop::Kde),
            ("sway", Desktop::Unknown),
            ("", Desktop::Unknown),
            ("   ", Desktop::Unknown),
        ] {
            assert_eq!(classify(Some(value)), expected, "for {value:?}");
        }
        assert_eq!(classify(None), Desktop::Unknown);
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(classify(Some("gnome")), Desktop::Gnome);
        assert_eq!(classify(Some("kDe")), Desktop::Kde);
    }

    // ------------------------------------------------------------------------------
    // classify_with_fallback: every case is exercised through plain
    // arguments, never the real environment.
    // ------------------------------------------------------------------------------

    #[test]
    fn a_present_xdg_current_desktop_never_consults_the_fallback_chain() {
        // `true, true` would answer both Gnome and Kde if the fallback fired; it must
        // not, because XDG_CURRENT_DESKTOP already gave a real answer.
        assert_eq!(
            classify_with_fallback(Some("GNOME"), Some("kde"), true, true),
            Desktop::Gnome
        );
    }

    #[test]
    fn an_unset_xdg_current_desktop_falls_back_to_desktop_session() {
        assert_eq!(
            classify_with_fallback(None, Some("gnome"), false, false),
            Desktop::Gnome
        );
        assert_eq!(
            classify_with_fallback(None, Some("kde-plasma"), false, false),
            Desktop::Kde
        );
    }

    // The `DESKTOP_SESSION` list is not a narrowing of the `XDG_CURRENT_DESKTOP` token
    // lists and must not be rewritten into one: the two variables hold different
    // namespaces — session-file names against XDG desktop names — so a value that is
    // recognised in one and not the other is the reason the second list exists.
    #[test]
    fn a_session_file_name_is_recognised_only_in_the_desktop_session_fallback() {
        for session in ["kde4", "kde-plasma"] {
            assert_eq!(
                classify(Some(session)),
                Desktop::Unknown,
                "{session} is not an XDG_CURRENT_DESKTOP token"
            );
            assert_eq!(
                classify_with_fallback(None, Some(session), false, false),
                Desktop::Kde,
                "{session} is a DESKTOP_SESSION value"
            );
        }
    }

    // Each classifier lower-cases *and* trims, and neither trim was held — the case rows
    // above pass either way, and the whitespace-only rows answer `Unknown` whether the spaces
    // are removed or merely fail to match. Padding is not what a display manager writes, but
    // these are ordinary environment variables and a session script that exports one with a
    // stray space is enough. Untrimmed, the token matches nothing, the desktop reads
    // `Unknown`, and [`order`] then puts GSettings ahead of `kioslaverc` on a machine running
    // Plasma: the store nothing writes, in front of the store the user configured.
    #[test]
    fn a_token_with_spaces_around_it_still_names_its_desktop() {
        assert_eq!(classify(Some(" plasma ")), Desktop::Kde);
        assert_eq!(
            classify_with_fallback(None, Some(" kde-plasma "), false, false),
            Desktop::Kde
        );
    }

    #[test]
    fn an_empty_xdg_current_desktop_also_falls_back() {
        assert_eq!(
            classify_with_fallback(Some(""), Some("kde"), false, false),
            Desktop::Kde
        );
        assert_eq!(
            classify_with_fallback(Some("   "), Some("mate"), false, false),
            Desktop::Gnome,
            "whitespace-only counts as empty, same as classify()"
        );
    }

    #[test]
    fn a_present_but_unrecognised_xdg_current_desktop_does_not_fall_back() {
        // Chromium's own chain (`base/nix/xdg_util.cc`) would still consult DESKTOP_SESSION
        // (and beyond) here; this crate deliberately stops — see classify_with_fallback's
        // doc comment.
        assert_eq!(
            classify_with_fallback(Some("sway"), Some("gnome"), true, true),
            Desktop::Unknown
        );
    }

    // A variable set to bytes that are not UTF-8 is *set*, and the two classes above are
    // not interchangeable. Read with `env::var().ok()` it arrived as `None`, so a mangled
    // `XDG_CURRENT_DESKTOP` fell through to `DESKTOP_SESSION` and the presence-only
    // variables — precisely the older, staler signals `classify_with_fallback` refuses to
    // consult while the modern variable has spoken, and the store precedence flips with
    // them. Only these two families can *build* such a value; anywhere else the test would
    // set nothing and pass on nothing.
    #[cfg(any(windows, unix))]
    #[test]
    fn a_variable_that_is_not_unicode_still_counts_as_set() {
        #[cfg(windows)]
        // A lone UTF-16 surrogate has no UTF-8 representation.
        let raw = {
            use std::os::windows::ffi::OsStringExt;
            std::ffi::OsString::from_wide(&[0xD800])
        };
        #[cfg(unix)]
        // 0xFF is not a valid UTF-8 lead byte.
        let raw = {
            use std::os::unix::ffi::OsStringExt;
            std::ffi::OsString::from_vec(vec![0xFF])
        };

        let text = text_if_set(Some(raw)).expect("a variable that is set must not read as unset");
        assert!(
            !text.trim().is_empty(),
            "an unreadable value must not read as empty either: {text:?}"
        );
        assert_eq!(
            classify_with_fallback(Some(&text), Some("kde"), true, true),
            Desktop::Unknown,
            "a mangled XDG_CURRENT_DESKTOP must stop here, not fall through to the older \
             variables"
        );
    }

    #[test]
    fn an_unrecognised_desktop_session_falls_through_to_the_presence_only_variables() {
        assert_eq!(
            classify_with_fallback(None, Some("default"), true, false),
            Desktop::Gnome
        );
        assert_eq!(
            classify_with_fallback(None, Some("default"), false, true),
            Desktop::Kde
        );
    }

    #[test]
    fn gnome_desktop_session_id_is_checked_before_kde_full_session() {
        // Mirrors Chromium's own order (base/nix/xdg_util.cc): GNOME_DESKTOP_SESSION_ID
        // comes first.
        assert_eq!(
            classify_with_fallback(None, None, true, true),
            Desktop::Gnome
        );
    }

    #[test]
    fn nothing_recognised_anywhere_is_still_unknown() {
        assert_eq!(
            classify_with_fallback(None, None, false, false),
            Desktop::Unknown
        );
        assert_eq!(
            classify_with_fallback(Some(""), Some(""), false, false),
            Desktop::Unknown
        );
    }

    // Every token of [`GNOME_TOKENS`], each shown to shut the fallback chain rather than
    // merely to produce a [`Desktop::Gnome`] nobody can tell from [`Desktop::Unknown`]:
    // `order` maps the two onto the same pair, so a row asserting the variant alone would
    // be a restatement of the table rather than a hold on it. The chain here is stacked to
    // answer KDE from all three of its rungs at once, so a token that stops being
    // recognised does not stay quiet — it flips the leading store.
    //
    // Half the table is named nowhere else: `the_common_spellings_are_recognised` reaches
    // `gnome`, `x-cinnamon`, `mate` and `unity`, spells `gnome-classic` only as
    // `GNOME-Classic:GNOME` — where the bare `GNOME` beside it answers first — and never
    // mentions `gnome-flashback`, `cinnamon` or `pantheon` at all. Those four answer to this
    // test alone, on Windows and under WSL alike.
    //
    // Cinnamon and Pantheon are the two that carry weight rather than redundancy: Mint
    // sets `XDG_CURRENT_DESKTOP=X-Cinnamon` on some releases and `Cinnamon` on others, and
    // elementary OS sets `Pantheon` with no second token behind it, so for those sessions
    // the entry here is the only thing standing between the desktop and a fallback chain
    // that any leftover `KDE_FULL_SESSION` turns into a KDE answer. The other two are
    // belt-and-braces — GNOME Classic and Flashback both append `:GNOME` — and are held
    // anyway, because a table is easier to keep right when no row is exempt.
    #[test]
    fn every_gnome_token_stops_the_fallback_chain() {
        // Spelled out rather than iterated over [`GNOME_TOKENS`]. A loop over the constant
        // renames itself along with the table, so it would stay green through a rename of
        // the four entries above; written out, the strings answer to the table instead of
        // repeating it. The length check is what a loop would otherwise have bought — a
        // token added to the table and not to this list.
        const TOKENS: [&str; 8] = [
            "gnome",
            "gnome-classic",
            "gnome-flashback",
            "unity",
            "x-cinnamon",
            "cinnamon",
            "mate",
            "pantheon",
        ];
        assert_eq!(TOKENS.len(), GNOME_TOKENS.len());

        for token in TOKENS {
            assert_eq!(
                classify_with_fallback(Some(token), Some("kde"), true, true),
                Desktop::Gnome,
                "{token} is a GNOME token"
            );
            assert_eq!(
                order(classify(Some(token))),
                [Store::GSettings, Store::Kioslaverc],
                "{token} reads GSettings first"
            );
        }
    }

    #[test]
    fn kde_wins_when_both_are_advertised() {
        assert_eq!(
            order(classify(Some("KDE:GNOME"))),
            [Store::Kioslaverc, Store::GSettings]
        );
    }

    #[test]
    fn gsettings_leads_everywhere_else() {
        for value in ["GNOME", "sway", ""] {
            assert_eq!(
                order(classify(Some(value))),
                [Store::GSettings, Store::Kioslaverc],
                "for {value:?}"
            );
        }
    }

    // Which store this build can actually read, in the configurations where the question
    // has an answer worth asking. Under `--all-features` [`is_compiled_in`] answers
    // `true` for `Store::GSettings` and for `Store::Kioslaverc` alike, so exchanging the
    // answers there changes nothing, so a run that only ever builds `--all-features`
    // cannot hold this mapping at all. CI's feature matrix already carries
    // `resolve,linux-kde` and `resolve,linux-gnome`, so what follows runs without a
    // new job.
    //
    // Stated as literal truths of one build rather than as `cfg!(feature = ...)`, which
    // would only re-derive the expression under test. Answering `Store::GSettings` with
    // `linux-kde` and `Store::Kioslaverc` with `linux-gnome` fails each of these, and so
    // does an arm that answers the same for every store.
    //
    // The consequence a swap would have is a warning naming the wrong store
    // ([`note_if_the_leading_store_was_compiled_out`]) and a watcher judging the wrong
    // one leading (`watcher::is_leading_store`) — neither of which changes a public
    // value, so there is no end-to-end reading that would catch it instead.
    #[cfg(all(feature = "linux-kde", not(feature = "linux-gnome")))]
    #[test]
    fn a_kde_only_build_can_read_kioslaverc_and_not_gsettings() {
        assert!(is_compiled_in(Store::Kioslaverc));
        assert!(!is_compiled_in(Store::GSettings));
    }

    #[cfg(all(feature = "linux-gnome", not(feature = "linux-kde")))]
    #[test]
    fn a_gnome_only_build_can_read_gsettings_and_not_kioslaverc() {
        assert!(is_compiled_in(Store::GSettings));
        assert!(!is_compiled_in(Store::Kioslaverc));
    }

    // A manual mode, i.e. an unmistakably configured proxy.
    fn manual(authority: &str) -> ProxyMode {
        crate::parse::windows_manual(authority, "")
    }

    // A configured GSettings store.
    fn gnome(mode: ProxyMode) -> Reading {
        Reading::configured(ProxyConfigSource::GSettings, mode)
    }

    // A configured `kioslaverc`.
    fn kde(mode: ProxyMode) -> Reading {
        Reading::configured(ProxyConfigSource::Kioslaverc, mode)
    }

    // The regression test for the rule that the running desktop's store wins even when
    // it is configured to go direct: an explicit "no proxy" in the desktop the user is
    // actually running must not be overruled by the other store.
    #[test]
    fn an_explicit_direct_in_the_leading_store_wins() {
        let assembled = assemble(
            Desktop::Gnome,
            &gnome(ProxyMode::Direct),
            &kde(manual("stale.corp:8080")),
        )
        .expect("both stores exist");
        assert_eq!(
            assembled.effective,
            ProxyMode::Direct,
            "a proxy the user switched off in their own desktop must stay off"
        );
        // Both are still visible, in precedence order, so the answer can be explained.
        assert_eq!(
            assembled.sources,
            vec![
                (ProxyConfigSource::GSettings, ProxyMode::Direct),
                (ProxyConfigSource::Kioslaverc, manual("stale.corp:8080")),
            ]
        );
    }

    // The same, the other way round: on Plasma it is `kioslaverc` that decides.
    #[test]
    fn the_leading_store_is_the_running_desktops() {
        let assembled = assemble(
            Desktop::Kde,
            &gnome(manual("gnome.corp:8080")),
            &kde(ProxyMode::Direct),
        )
        .expect("both stores exist");
        assert_eq!(assembled.effective, ProxyMode::Direct);
        assert_eq!(assembled.sources[0].0, ProxyConfigSource::Kioslaverc);
    }

    #[test]
    fn an_unset_leading_store_falls_through_to_the_other() {
        let assembled = assemble(Desktop::Gnome, &Reading::Unset, &kde(manual("p.corp:3128")))
            .expect("kioslaverc exists");
        assert_eq!(assembled.effective, manual("p.corp:3128"));
        assert_eq!(
            assembled.sources,
            vec![(ProxyConfigSource::Kioslaverc, manual("p.corp:3128"))],
            "an unconfigured store contributes no source at all"
        );
    }

    #[test]
    fn both_configured_means_the_leading_one_wins() {
        let assembled = assemble(
            Desktop::Gnome,
            &gnome(manual("gnome.corp:8080")),
            &kde(manual("kde.corp:3128")),
        )
        .expect("both stores exist");
        assert_eq!(assembled.effective, manual("gnome.corp:8080"));
        assert_eq!(assembled.sources.len(), 2);
    }

    #[test]
    fn both_unset_is_direct_with_no_sources() {
        let assembled =
            assemble(Desktop::Unknown, &Reading::Unset, &Reading::Unset).expect("a store exists");
        assert_eq!(assembled.effective, ProxyMode::Direct);
        assert!(
            assembled.sources.is_empty(),
            "a store nobody configured must not be reported as a source"
        );
    }

    // An existing-but-unconfigured store is still a readable store: only a machine with
    // nothing at all is unsupported.
    #[test]
    fn only_two_absent_stores_have_no_answer() {
        assert!(assemble(Desktop::Unknown, &Reading::Absent, &Reading::Absent).is_none());
        for reading in [Reading::Unset, gnome(ProxyMode::Direct)] {
            assert!(
                assemble(Desktop::Unknown, &reading, &Reading::Absent).is_some(),
                "{reading:?} is a readable store"
            );
        }
    }

    // `ProxyType = 4` labels its source [`ProxyConfigSource::KioslavercEnv`]; the precedence
    // rule keys off the *store*, not off the label it carries.
    #[test]
    fn a_relabelled_source_still_occupies_its_stores_slot() {
        let assembled = assemble(
            Desktop::Kde,
            &gnome(manual("gnome.corp:8080")),
            &Reading::configured(ProxyConfigSource::KioslavercEnv, manual("env.corp:3128")),
        )
        .expect("both stores exist");
        assert_eq!(assembled.effective, manual("env.corp:3128"));
        assert_eq!(assembled.sources[0].0, ProxyConfigSource::KioslavercEnv);
    }

    // A cheap-to-construct error: its variant does not matter to [`read_store_fail_soft`],
    // only whether `read` returned `Err` at all.
    fn some_error() -> Error {
        Error::Unsupported
    }

    #[test]
    fn a_successful_read_passes_its_value_through_unchanged() {
        let reading = gnome(ProxyMode::Direct);
        let leading = [None, Some(Reading::Unset), Some(reading.clone())];
        // Collected rather than asserted per iteration, for the reason the next test
        // states: a loop that panics on the first row never reaches the rest.
        let passed_through: Vec<Reading> = leading
            .iter()
            .map(|leading| {
                let value = reading.clone();
                read_store_fail_soft(
                    Store::GSettings,
                    leading.as_ref(),
                    move || Ok(value),
                    &mut Vec::new(),
                )
                .expect("the closure returned Ok")
            })
            .collect();
        assert_eq!(passed_through, vec![reading; leading.len()]);
    }

    // The trailing store's failure against each of the leading store's three answers. Only
    // a leading `Configured` is an effective value, and only then is the trailing store's
    // answer one the caller was never going to get — the sole reading under which losing
    // it costs nothing. A leading `Unset` or `Absent` makes the store that failed the
    // effective one, so softening there hands back a `Direct` nobody measured.
    #[test]
    fn a_second_store_error_is_softened_only_when_the_leading_store_is_configured() {
        let leading = [Reading::Absent, Reading::Unset, gnome(ProxyMode::Direct)];
        // All three at once rather than an assert per iteration: a loop that panics on the
        // first mismatch never reaches the later readings, so a change that softened every
        // one of them would still be reported against `Absent` alone.
        let mut recorded = Vec::new();
        let softened: Vec<bool> = leading
            .iter()
            .map(|leading| {
                match read_store_fail_soft(
                    Store::Kioslaverc,
                    Some(leading),
                    || Err(some_error()),
                    &mut recorded,
                ) {
                    Ok(Reading::Absent) => true,
                    Err(Error::Unsupported) => false,
                    other => panic!("leading = {leading:?}: {other:?}"),
                }
            })
            .collect();
        assert_eq!(softened, [false, false, true], "against {leading:?}");
        // The row that softened is the only one that has anything to report: the other two
        // handed the error to the caller, who is not being told twice.
        assert_eq!(recorded, [ProxyConfigSource::Kioslaverc]);
    }

    #[test]
    fn a_leading_store_error_propagates() {
        let result = read_store_fail_soft(
            Store::GSettings,
            None,
            || Err(some_error()),
            &mut Vec::new(),
        );
        assert!(
            matches!(result, Err(Error::Unsupported)),
            "the running desktop's own store must not be silenced: {result:?}"
        );
    }

    // Which store may fail without failing the whole read is decided by the desktop, not by
    // the argument order of [`read_in_order`]. GSettings always fails below and
    // `kioslaverc` always answers: under GNOME the failing store is the leading one and the
    // read fails, under KDE it is the trailing one and its failure softens away behind an
    // answer that was going to win anyway.
    #[test]
    fn the_store_that_cannot_be_softened_is_the_one_the_desktop_leads_with() {
        let answer = kde(manual("kde.corp:8080"));
        // Both desktops at once rather than an assert per row, for the reason above.
        let mut recorded = Vec::new();
        let softened: Vec<bool> = [Desktop::Gnome, Desktop::Kde]
            .iter()
            .map(|desktop| {
                match read_in_order(
                    *desktop,
                    || Err(some_error()),
                    || Ok(answer.clone()),
                    &mut recorded,
                ) {
                    Err(Error::Unsupported) => false,
                    Ok((Reading::Absent, kioslaverc)) if kioslaverc == answer => true,
                    other => panic!("{desktop:?}: {other:?}"),
                }
            })
            .collect();
        assert_eq!(softened, [false, true]);
        // GSettings is the store that fails in both rows, so the name recorded under KDE is
        // the failing store's and not the leading one's. Transpose the match that maps a
        // `Store` to a `ProxyConfigSource` and this is where it shows: nothing else in the
        // crate reads that pair back out.
        assert_eq!(recorded, [ProxyConfigSource::GSettings]);
    }

    // The other way a source ends up in `fallbacks` on this platform, and the one no
    // `--all-features` build can reach: a store this build left out was never consulted at
    // all, so whatever answers underneath it is confidently wrong rather than merely
    // incomplete. All four rows share one list, because what has to hold is as much about
    // the rows that record *nothing* as about the two that record something.
    #[test]
    fn a_leading_store_this_build_left_out_is_recorded_unless_nothing_is_left_to_report() {
        let configured = Reading::configured(ProxyConfigSource::GSettings, ProxyMode::Direct);
        let mut recorded = Vec::new();
        // KDE leads with `kioslaverc`. Compiled out, GSettings answers in its place.
        note_if_the_leading_store_was_compiled_out(
            Desktop::Kde,
            &configured,
            &Reading::Absent,
            |store| store == Store::GSettings,
            &mut recorded,
        );
        // Same build, but nothing else answered either: the caller hears
        // `Error::Unsupported` and never sees a `ProxyConfig` this could be read from.
        note_if_the_leading_store_was_compiled_out(
            Desktop::Kde,
            &Reading::Absent,
            &Reading::Absent,
            |store| store == Store::GSettings,
            &mut recorded,
        );
        // The leading store is present: nothing went wrong, so nothing is recorded.
        note_if_the_leading_store_was_compiled_out(
            Desktop::Kde,
            &configured,
            &Reading::Unset,
            |_| true,
            &mut recorded,
        );
        // The mirror image, which is what says the name recorded is the missing store's
        // rather than the one that answered. An `Unset` other store still counts: it makes
        // the answer a `Direct` that measured nothing.
        note_if_the_leading_store_was_compiled_out(
            Desktop::Gnome,
            &Reading::Absent,
            &Reading::Unset,
            |store| store == Store::Kioslaverc,
            &mut recorded,
        );
        assert_eq!(
            recorded,
            [ProxyConfigSource::Kioslaverc, ProxyConfigSource::GSettings]
        );
    }

    // [`assemble`] takes the two readings by store, so [`read_in_order`] has to undo the
    // precedence order it read them in. Under KDE the store it read first is the *second*
    // element of the pair it returns, which is the one place a swap would show.
    #[test]
    fn the_two_readings_come_back_in_store_order_whichever_store_led() {
        let from_gsettings = gnome(manual("gnome.corp:8080"));
        let from_kioslaverc = kde(manual("kde.corp:3128"));
        let pairs: Vec<(Reading, Reading)> = [Desktop::Gnome, Desktop::Kde]
            .iter()
            .map(|desktop| {
                read_in_order(
                    *desktop,
                    || Ok(from_gsettings.clone()),
                    || Ok(from_kioslaverc.clone()),
                    &mut Vec::new(),
                )
                .expect("both stores answered")
            })
            .collect();
        assert_eq!(
            pairs,
            [
                (from_gsettings.clone(), from_kioslaverc.clone()),
                (from_gsettings, from_kioslaverc)
            ]
        );
    }
}
