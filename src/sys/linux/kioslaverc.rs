//! Pure `[Proxy Settings]` → [`ProxyMode`] (KDE twin of [`super::gsettings_map`]).
//! Strips KConfig `[$…]` flags without performing the env expansion `[$e]` asks for; a
//! value that still holds a `$` is rejected rather than reported
//! ([`KioslavercSettings::needs_expansion`]). That covers every key that names a proxy, or
//! names the variable holding one, which is what the rule exists to keep this crate from
//! inventing. Three keys are read without it — `ProxyType`, `ReversedException`, and
//! `NoProxyFor` under `ProxyType = 4` — and fall to their defaults instead; each carries
//! the reason at its own site.
//!
//! Every `KProtocolManager` quotation below is read against KIO's `kf5` branch. `master`
//! kept the file and dropped the proxying: `src/core/kprotocolmanager.cpp` there holds
//! `proxyConnectTimeout` and nothing else on the subject — no `proxyForUrl`, no
//! `ManualProxy`, no `useReverseProxy`. So KDE is quoted for what it meant each key to
//! say, and libproxy's `config-kde` for what reads them on the live path today. Where the
//! two disagree the comment at hand names which one this crate follows and why.

// Compiled on every target under `cfg(test)`, exactly like `super::gsettings_map`, and
// also on Linux with `linux-kde` off, where it likewise has no caller.
#![cfg_attr(not(all(target_os = "linux", feature = "linux-kde")), allow(dead_code))]

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv6Addr;

use url::Url;

use crate::bypass::BypassRules;
use crate::config::ProxyConfigSource;
use crate::diagnostic::{RejectedValue, RejectionKind, RejectionSource};
use crate::endpoint::{ProxyEndpoint, ProxyEntry, ProxyScheme, Scheme};
use crate::env::ProxyEnv;
use crate::error::Error;
use crate::mode::ProxyMode;
use crate::parse;

// The file name, unchanged in KF6 (`kioworkerrc` does not exist).
pub(crate) const FILE_NAME: &str = "kioslaverc";

// The only section this crate reads.
pub(crate) const SECTION: &str = "Proxy Settings";

// `ProxyType`: the KDE proxy mode, an implicitly numbered enum.
const KEY_PROXY_TYPE: &str = "ProxyType";
// `NoProxyFor`: the bypass list — or, when `ProxyType = 4`, the *name* of the variable
// holding it.
const KEY_NO_PROXY_FOR: &str = "NoProxyFor";
// `ReversedException`: invert `NoProxyFor` into an "only these hosts" list.
const KEY_REVERSED_EXCEPTION: &str = "ReversedException";
// `Proxy Config Script`: the PAC URL or path used by `ProxyType = 2`.
const KEY_CONFIG_SCRIPT: &str = "Proxy Config Script";

// KDE's `ProxyType` enum.
//
// The `…Proxy` suffix on every variant is KDE's own spelling, kept verbatim so that a
// reader can match this against `KProtocolManager`'s enum without a translation table.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyType {
    // `0` — no proxy.
    NoProxy,
    // `1` — the static `<scheme>Proxy` entries.
    ManualProxy,
    // `2` — the PAC script named by `Proxy Config Script`.
    PacProxy,
    // `3` — WPAD auto-discovery.
    WpadProxy,
    // `4` — the `<scheme>Proxy` values name **environment variables** to read.
    EnvVarProxy,
}

impl ProxyType {
    pub(crate) fn from_i64(value: i64) -> Option<Self> {
        match value {
            0 => Some(ProxyType::NoProxy),
            1 => Some(ProxyType::ManualProxy),
            2 => Some(ProxyType::PacProxy),
            3 => Some(ProxyType::WpadProxy),
            4 => Some(ProxyType::EnvVarProxy),
            _ => None,
        }
    }
}

// One `<scheme>Proxy` key.
struct SlotKeys {
    scheme: Scheme,
    key: &'static str,
    // The lowercase environment variable name used when delegating to [`ProxyEnv`].
    // `None` for schemes [`ProxyEnv`] does not model.
    env_var: Option<&'static str>,
    // The port assumed when the value carries none — a source-specific default, not one
    // crate-wide number. These are the four the GNOME sibling picked, so the two Linux
    // sources cannot disagree about a port neither file names; why 8080 rather than the
    // scheme's own 80 is argued once, at [`ChildKeys::default_port`](super::gsettings_map).
    default_port: u16,
    // The wire protocol assumed when the value carries no `scheme://` of its own. Not read
    // out of the file — see the SOCKS slot for what that costs.
    hint: Option<ProxyScheme>,
}

const SLOTS: [SlotKeys; 4] = [
    SlotKeys {
        scheme: Scheme::Http,
        key: "httpProxy",
        env_var: Some("http_proxy"),
        default_port: 8080,
        hint: None,
    },
    SlotKeys {
        scheme: Scheme::Https,
        key: "httpsProxy",
        env_var: Some("https_proxy"),
        default_port: 8080,
        hint: None,
    },
    SlotKeys {
        scheme: Scheme::Ftp,
        key: "ftpProxy",
        env_var: Some("ftp_proxy"),
        default_port: 8080,
        hint: None,
    },
    SlotKeys {
        scheme: Scheme::Socks,
        key: "socksProxy",
        // `ProxyEnv` models `http`/`https`/`ftp`/`all` only — there is no `socks_proxy`
        // convention — so a `ProxyType = 4` SOCKS entry is skipped rather than guessed.
        env_var: None,
        default_port: 1080,
        // The third of the version-less SOCKS settings, and pinned like the other two. KF5-era
        // KIO left no version to read even when the value carried a token:
        // `KProtocolManager::proxyFor("socks")` stripped whatever `scheme://` it found and glued
        // a bare `socks://` back on, so a stored `socks4://` reached KDE's own consumers as
        // `socks`. v5 here is a compatibility choice, not a reading. Chromium routes this very
        // key into the same `PROXY_SOCKS_HOST` slot its GNOME reader fills and pins that slot to
        // `SCHEME_SOCKS5` for both, calling it a policy decision in
        // `proxy_config_service_linux.cc`. The siblings and what the choice costs a
        // SOCKS4-only proxy are in `sys/linux/gsettings_map.rs` and on [`ProxyScheme`].
        hint: Some(ProxyScheme::Socks5),
    },
];

// The `[Proxy Settings]` section as plain Rust data.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct KioslavercSettings {
    entries: HashMap<String, KconfigEntry>,
    group_immutable: bool,
}

// Hand-written for the map's **keys**, which a derive would print as written. A key is
// whatever stood left of the first `=` on the line (`kde.rs`'s scanner), and a stray PAC
// URL pasted into `[Proxy Settings]` puts its query's `=` there:
// `http://alice:pw@wpad.corp/proxy.pac?a=1` is applied as the key
// `http://alice:pw@wpad.corp/proxy.pac?a`. Real key names carry no credential shape and
// come through untouched, so masking here costs nothing that a reader wanted.
// The values are [`KconfigEntry`]'s own business.
impl fmt::Debug for KioslavercSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Sorted as a side effect, which a `HashMap` was not: a diff between two of these
        // reads as one.
        let entries: std::collections::BTreeMap<String, &KconfigEntry> = self
            .entries
            .iter()
            .map(|(key, entry)| (crate::util::redact_offending_token(key), entry))
            .collect();
        f.debug_struct("KioslavercSettings")
            .field("entries", &entries)
            .field("group_immutable", &self.group_immutable)
            .finish()
    }
}

// KConfig keeps deleted entries as tombstones, because an immutable deletion must also
// refuse a later attempt to recreate the key. A plain `HashMap<String, String>` cannot
// represent that state.
#[derive(Clone, PartialEq, Eq)]
struct KconfigEntry {
    value: Option<String>,
    immutable: bool,
    // The entry carried `[$e]`. Kept rather than discarded with the rest of the flag,
    // because a value this crate refuses to expand is a value it does not know — see
    // [`KioslavercSettings::needs_expansion`].
    expand: bool,
}

// Hand-written, so that `KioslavercSettings`'s derive above delegates here instead of
// printing the raw value. `httpProxy = http://user:password@host:8080` is ordinary KDE
// configuration, not a corner case, and the entry holds the file's bytes: nothing has
// parsed them into a `Url` and stripped the userinfo. Neither type is printed by this
// crate today, which is exactly why the derive was easy to leave in place — the same
// shape reached `ProxyDict` on macOS and was caught there.
//
// [`redact_offending_token`](crate::util::redact_offending_token) rather than
// `redact_userinfo` alone, for the reason spelled out at `sys/proxy_dict.rs`: the mask
// cannot reach back past whitespace, so `alice:my pass@host` survives it whole, and this
// value may hold whitespace because KConfig never promised it would not.
impl fmt::Debug for KconfigEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self
            .value
            .as_deref()
            .map(crate::util::redact_offending_token);
        f.debug_struct("KconfigEntry")
            .field("value", &value)
            .field("immutable", &self.immutable)
            .field("expand", &self.expand)
            .finish()
    }
}

impl KioslavercSettings {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    // Record one key/value pair, normalising the key (see [`normalize_key`]).
    pub(crate) fn insert(&mut self, key: &str, value: impl Into<String>) {
        self.entries.insert(
            normalize_key(key).to_owned(),
            KconfigEntry {
                value: Some(value.into()),
                immutable: false,
                expand: has_kconfig_flag(key, 'e'),
            },
        );
    }

    // Apply one physical KConfig entry in file order. `$i` (or an immutable group)
    // freezes the resulting logical key; `$d` records a deletion tombstone. `$e` is
    // deliberately not expanded because a configuration file must not execute process
    // environment substitution inside this library.
    pub(crate) fn apply(&mut self, raw_key: &str, value: Option<String>, group_immutable: bool) {
        let key = normalize_key(raw_key).to_owned();
        if self.entries.get(&key).is_some_and(|entry| entry.immutable) {
            return;
        }

        let immutable = group_immutable || has_kconfig_flag(raw_key, 'i');
        let deleted = has_kconfig_flag(raw_key, 'd');
        // KEntryMap::setEntry treats a deletion for a key that does not yet exist as a
        // no-op. In particular, `key[$di]` must not invent an immutable tombstone that
        // blocks a value supplied by a later, more specific config layer.
        if deleted && !self.entries.contains_key(&key) {
            return;
        }
        self.entries.insert(
            key,
            KconfigEntry {
                value: if deleted { None } else { value },
                immutable,
                expand: has_kconfig_flag(raw_key, 'e'),
            },
        );
    }

    // Whether an earlier, less-specific file made the whole `[Proxy Settings]` group
    // immutable. KConfig applies the marker only after finishing the file that carries
    // it, so entries repeated inside that same file are still processed in order.
    pub(crate) fn group_is_immutable(&self) -> bool {
        self.group_immutable
    }

    pub(crate) fn mark_group_immutable(&mut self) {
        self.group_immutable = true;
    }

    // Read a key; an empty value is reported as absent.
    //
    // Not trimmed here. The padding an administrator typed around a row is already gone —
    // [`super::kde::proxy_settings`] removes it from the raw line, before the escapes are
    // read — so the only whitespace a value can still carry is whitespace an escape *made*,
    // and `\s` exists in KConfig for the sole purpose of carrying one that no other spelling
    // survives. Trimming after the decode is the one order that takes it back off again.
    fn text(&self, key: &str) -> Option<&str> {
        self.entries
            .get(key)
            .and_then(|entry| entry.value.as_deref())
            .filter(|value| !value.is_empty())
    }

    // Whether the key's value is one KDE would have substituted from the environment and
    // this crate will not.
    //
    // `KConfigGroup::readEntry` on an entry written with `[$e]` runs it through
    // `KConfigPrivate::expandString`, so the desktop's effective value is whatever
    // `$VAR` held in the session that read it. Expanding it here would let a
    // configuration file pull process environment into a library that only reports, so
    // this crate does not — which leaves the literal `$VAR` text, and that is not the
    // value the desktop is using. Reporting it as a proxy host would invent a
    // destination nobody configured, so the slot is rejected instead: a caller sees the
    // entry in [`ProxyMode::rejected`] rather than a `$http_proxy` it would try to
    // resolve. A `[$e]` value with no `$` in it expands to itself and is left alone.
    fn needs_expansion(&self, key: &str) -> bool {
        self.entries.get(key).is_some_and(|entry| {
            entry.expand && entry.value.as_deref().is_some_and(|v| v.contains('$'))
        })
    }

    // Whether the key is present at all, even with an empty value.
    fn has(&self, key: &str) -> bool {
        self.entries
            .get(key)
            .is_some_and(|entry| entry.value.is_some())
    }

    // Whether `ReversedException` is set, under the **narrower** of the two readings the
    // KDE stack has for this one key.
    //
    // Read without the [`KioslavercSettings::needs_expansion`] guard the proxy keys carry:
    // an unexpanded `$VAR` is not a number and not one of `KCONFIG_FALSE`, so it answers
    // `false` here and `true` at `reversed_exception_is_disputed`, which is the log line.
    // A flag has no destination to invent, and the one caller
    // ([`bypass_from`]) has already built the list this would invert.
    fn reversed_exception(&self) -> bool {
        self.text(KEY_REVERSED_EXCEPTION)
            .is_some_and(atoi_is_nonzero)
    }

    // Whether `ReversedException` holds a value KConfig would have read as true but
    // [`KioslavercSettings::reversed_exception`] does not — worth a log line rather than a
    // silent divergence.
    fn reversed_exception_is_disputed(&self) -> bool {
        self.text(KEY_REVERSED_EXCEPTION).is_some_and(|value| {
            !atoi_is_nonzero(value)
                && !KCONFIG_FALSE
                    .iter()
                    .any(|no| value.eq_ignore_ascii_case(no))
        })
    }
}

// The whole of `KConfigGroup`'s falsehood: `convertToQVariant`'s `negatives` array.
const KCONFIG_FALSE: [&str; 4] = ["false", "no", "off", "0"];

// C's `atoi`, reduced to the only question [`KioslavercSettings::reversed_exception`]
// asks of it: is the result non-zero? Leading whitespace included, because `\s` can put
// some back after the raw line was trimmed — what is not modelled is the string libproxy
// passes it, which `config-kde.c` strips of every `"` and colonises the spaces of first.
// That edge is a row in `the_reversed_exception_flag_follows_libproxys_atoi`.
fn atoi_is_nonzero(value: &str) -> bool {
    let value = value.trim_ascii_start();
    let rest = value.strip_prefix(['+', '-']).unwrap_or(value);
    let digits = rest
        .find(|c: char| !c.is_ascii_digit())
        .map_or(rest, |end| &rest[..end]);
    digits.bytes().any(|byte| byte != b'0')
}

impl FromIterator<(String, String)> for KioslavercSettings {
    fn from_iter<I: IntoIterator<Item = (String, String)>>(iter: I) -> Self {
        let mut settings = Self::new();
        for (key, value) in iter {
            settings.insert(&key, value);
        }
        settings
    }
}

// Strip a KConfig entry flag such as the `[$e]` of `Proxy Config Script[$e]`.
//
// ASCII trims, because `kconfigini.cpp` reaches this point holding a `QByteArrayView` and
// trims with `trimmed()`, which recognises ASCII spacing characters only. A key KDE keeps
// a U+00A0 on is not the key this crate is looking for either.
pub(crate) fn normalize_key(key: &str) -> &str {
    let key = key.trim_ascii();
    match key.find("[$") {
        Some(index) if key.ends_with(']') => key[..index].trim_ascii_end(),
        _ => key,
    }
}

// Strip a KConfig group flag such as the `][$i]` of `[Proxy Settings][$i]`.
//
// The input is the section name an INI parser produced, i.e. the text *between* the
// outermost brackets: `Proxy Settings][$i`.
//
// Dropping a suffix that is not `$i` matches upstream rather than losing information:
// `kconfigini.cpp` tests a group suffix for exactly `$i`, and its writer emits no other
// flag on a group header. A group-level `[$d]` therefore names no deletion to honour.
pub(crate) fn normalize_section(name: &str) -> &str {
    let name = name.trim_ascii();
    match name.find("][$") {
        Some(index) => name[..index].trim_ascii_end(),
        None => name,
    }
}

// Whether the KConfig suffix contains `flag`. KConfig combines entry flags in one suffix
// (`[$ie]`), while group flags arrive here as `Proxy Settings][$i`; looking only after the
// first `[$` handles both forms without interpreting ordinary brackets in a key name.
pub(crate) fn has_kconfig_flag(name: &str, flag: char) -> bool {
    let Some(start) = name.find("[$") else {
        return false;
    };
    let tail = &name[start + 2..];
    match tail.find(']') {
        Some(end) => tail[..end].contains(flag),
        // `normalize_section` receives the text between a section's outer brackets, so
        // `[Proxy Settings][$i]` arrives as `Proxy Settings][$i`: the group-closing `]`
        // remains before the flag while the final flag-closing one has been stripped.
        None if name[..start].ends_with(']') => tail.contains(flag),
        None => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KdeConfig {
    // Where the values ultimately came from: [`ProxyConfigSource::Kioslaverc`], or
    // [`ProxyConfigSource::KioslavercEnv`] for `ProxyType = 4`, where the file only *names* the
    // variables that hold them.
    pub(crate) source: ProxyConfigSource,
    // The resolved mode.
    pub(crate) mode: ProxyMode,
}

// Collapse the `[Proxy Settings]` section into a [`ProxyMode`].
pub(crate) fn config_from_kioslaverc<F>(
    settings: &KioslavercSettings,
    env: F,
) -> Result<KdeConfig, Error>
where
    F: Fn(&str) -> Option<std::ffi::OsString>,
{
    let kind = settings
        .text(KEY_PROXY_TYPE)
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(ProxyType::from_i64)
        // KDE's default, and what a file without a `ProxyType` line means. A value that is
        // *present but unreadable* lands here too, with no record, which is the one place
        // in this file that does not follow the rule `manual_mode` states below
        // ("recorded, not skipped, so the caller can tell …"). The two combinators above
        // drop one upstream case each, and not for the same reason. `ProxyType=banana`
        // fails the conversion, and so does `KConfigGroup`'s `convertToQVariant`, silently:
        // `QVariant tmp = value; if (!tmp.convert(aDefault.metaType())) { tmp = aDefault; }`.
        // `ProxyType=7` converts perfectly well and reaches the reader as the integer 7; it
        // dies one step later, at a `switch` over the type with no label for it (libproxy
        // `config-kde.c`, `KProtocolManager`'s enum). Either way the silent fall to the
        // default *is* the upstream predicate rather than a divergence from it. There is
        // also nowhere for a record to go: every unreadable `ProxyType` resolves to
        // `Direct`, and `Direct` is one of the two modes [`ProxyMode::rejected`] answers
        // `None` for. (The PAC arm below does have a slot — the list stopped being
        // `Manual`'s alone — and declines it for a different reason.)
        .unwrap_or(ProxyType::NoProxy);

    let mode = match kind {
        ProxyType::NoProxy => ProxyMode::Direct,
        ProxyType::WpadProxy => ProxyMode::WpadAutoDetect,
        ProxyType::PacProxy => pac_mode(settings)?,
        ProxyType::ManualProxy => manual_mode(settings)?,
        ProxyType::EnvVarProxy => {
            return Ok(KdeConfig {
                source: ProxyConfigSource::KioslavercEnv,
                mode: env_mode(settings, env)?,
            });
        }
    };

    Ok(KdeConfig {
        source: ProxyConfigSource::Kioslaverc,
        mode,
    })
}

// [`config_from_kioslaverc`], but reporting an **unconfigured** store as `None`.
pub(crate) fn configured_from_kioslaverc<F>(
    settings: &KioslavercSettings,
    env: F,
) -> Result<Option<KdeConfig>, Error>
where
    F: Fn(&str) -> Option<std::ffi::OsString>,
{
    // Presence, not readability. A `ProxyType=` line with nothing after the `=` is a
    // configured store whose value KDE reads as its default: `KConfigGroup::readEntry`
    // only returns `aDefault` early when `lookupData` gives a **null** `QByteArray`, and
    // an entry that exists with an empty value is empty-but-not-null, so it goes on to
    // `convertToQVariant`, whose Int arm cannot convert `""` and lands on the same 0 =
    // `NoProxy`. Either way KDE proxies nothing *because the file said so*. Gating on
    // `text` instead would fold that into "nobody ever configured this store" and hand
    // the answer to GSettings — reporting a proxy on a Plasma session where KIO is going
    // direct. `config_from_kioslaverc` already resolves the unreadable value to
    // `Direct`, which is exactly what the empty one has to mean.
    if !settings.has(KEY_PROXY_TYPE) {
        return Ok(None);
    }
    config_from_kioslaverc(settings, env).map(Some)
}

// `ProxyType = 2`: the PAC script named by `Proxy Config Script`.
fn pac_mode(settings: &KioslavercSettings) -> Result<ProxyMode, Error> {
    let Some(script) = settings.text(KEY_CONFIG_SCRIPT) else {
        // "PAC, but no script": nothing usable, and reporting `Direct` would be a lie
        // only in the sense that KDE itself would proxy nothing either.
        return Ok(ProxyMode::Direct);
    };
    // See [`KioslavercSettings::needs_expansion`], and note that this key is the one where
    // the literal is *least* likely to announce itself: `$` is a legal URL path character,
    // so `/home/$USER/proxy.pac` becomes a perfectly well-formed `file:` URL pointing at
    // nothing. That is the shape the `NoProxyFor` arm of [`bypass_from`] calls the more
    // damaging of the two. `ProxyMode::Pac` does carry a `rejected` slot now, but putting
    // the record there would mean handing out the wrong URL beside it, and a caller that
    // fetches before it reads records is the whole reason this arm exists. `Manual` with
    // an empty `per_scheme` is how this file already reports "KDE configured something this
    // crate cannot map" — see [`env_mode`]'s SOCKS slot — and it keeps `is_direct` false.
    // `Scheme::All` because a PAC script is not scoped to one scheme.
    if settings.needs_expansion(KEY_CONFIG_SCRIPT) {
        return Ok(
            ProxyMode::manual(HashMap::new(), BypassRules::new()).with_rejected(vec![
                RejectedValue::new(
                    RejectionKind::UnsupportedMapping,
                    RejectionSource::Kioslaverc(KEY_CONFIG_SCRIPT.to_owned()),
                    script,
                )
                .for_scheme(Some(Scheme::All)),
            ]),
        );
    }
    Ok(ProxyMode::pac(parse_script_location(script)?))
}

// Parse a `Proxy Config Script` value, which KDE's dialog stores either as a URL or as
// a plain absolute path.
fn parse_script_location(script: &str) -> Result<Url, Error> {
    if let Ok(url) = Url::parse(script) {
        return Ok(url);
    }
    let invalid = |source| Error::invalid_proxy_url(script, source);
    if !script.starts_with('/') {
        return Err(invalid(url::ParseError::RelativeUrlWithoutBase));
    }
    // A path, not a URL, and the grammars disagree about bytes a POSIX file name is free to
    // contain — only `/` and NUL are not. Spliced in raw, `#` and `?` *end* the path
    // (`/home/a#b/proxy.pac` becomes `file:///home/a` with the rest in a fragment), `\` is a
    // separator too because `file` is one of WHATWG's "special" schemes, tab and the newline
    // characters are deleted outright, a leading or trailing C0 control or space is deleted
    // as well, `%` starts an escape, and a first segment of `c|` names a Windows drive. Not
    // hypothetical spellings: `kde.rs`'s `printable_to_string` decodes `\\`, `\t`, `\n`, `\r`
    // and `\s` into bytes on that list, so the byte KDE stored is restored and then lost one
    // call later — `\s` exists in KConfig precisely because a trailing space survives no
    // other way.
    //
    // So the escape set is an allowlist, not a list of the rules above: RFC 3986's unreserved
    // and sub-delims, plus the separator. It cannot be short by a character nobody thought to
    // test, and it does not have to track which of WHATWG's file-URL rules this version of
    // `url` implements — `:` is escaped too, so the drive-letter rule cannot fire either way.
    // Percent-encoding says "this was a name, not syntax"; `Url::to_file_path` gives the
    // original path back. A value that parsed as a URL above keeps the WHATWG reading,
    // because there it really is syntax.
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut path = String::with_capacity(script.len());
    for byte in script.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=/".contains(&byte) {
            path.push(char::from(byte));
        } else {
            path.push('%');
            path.push(char::from(HEX[usize::from(byte >> 4)]));
            path.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    Url::parse(&format!("file://{path}")).map_err(invalid)
}

// `ProxyType = 1`: the static `<scheme>Proxy` entries.
fn manual_mode(settings: &KioslavercSettings) -> Result<ProxyMode, Error> {
    let mut per_scheme = HashMap::new();
    let mut rejected = Vec::new();
    let mut socks = None;
    // Set for any SOCKS slot that had a value, but read below only where `socks` stayed
    // `None` — which is what makes it mean "named but rejected" rather than "never named at
    // all". Both leave `socks` at `None`, but only the second means nothing was lost. The
    // meaning is the read site's: move that read out from under `socks.is_none()` and this
    // flag stops saying it.
    let mut socks_unusable = false;
    let mut blank = Vec::new();
    for slot in &SLOTS {
        if !settings.has(slot.key) {
            continue;
        }
        let Some(raw) = settings.text(slot.key) else {
            // Deferred, because whether this is `Disabled` depends on whether a SOCKS
            // entry turns up later in `SLOTS` to catch it — see the catch-all below.
            blank.push(slot.scheme);
            continue;
        };
        // The SOCKS slot is also `manual_mode`'s catch-all for every scheme with no slot
        // of its own (see the block below this loop). A rejected `socksProxy` loses that
        // fallback too, so it is attributed as widely as the fallback it prevented rather
        // than to its own scheme — and marks `socks_unusable` so the catch-all
        // composition does not paper over the loss with `Disabled`.
        let attributed_scheme = if slot.scheme == Scheme::Socks {
            socks_unusable = true;
            Scheme::All
        } else {
            slot.scheme
        };
        // See [`KioslavercSettings::needs_expansion`]. Recorded, not skipped, so the
        // caller can tell "KDE names a proxy this crate will not expand" from "KDE names
        // no proxy". Routing is unchanged either way — the slot is left empty here, so the
        // SOCKS catch-all below fills it exactly as it fills a blank one, and only when
        // there is no catch-all does the record `ProxyMode::with_rejected` files there
        // become the answer.
        if settings.needs_expansion(slot.key) {
            rejected.push(
                RejectedValue::new(
                    RejectionKind::UnsupportedMapping,
                    RejectionSource::Kioslaverc(slot.key.to_owned()),
                    raw,
                )
                .for_scheme(Some(attributed_scheme)),
            );
            continue;
        }
        let mut endpoint = match ProxyEndpoint::parse(&normalize_address(raw), slot.default_port) {
            Ok(endpoint) => endpoint,
            // The `WARN` compiles to nothing without the `tracing` feature, which is what
            // leaves `err` unused there; the `rejected` entry below is what carries the
            // drop either way.
            #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
            Err(err) => {
                crate::trace::warning!(
                    error = %crate::trace::SafeError(&err),
                    "skipping an unparseable kioslaverc <scheme>Proxy value"
                );
                rejected.push(
                    RejectedValue::new(
                        RejectionKind::InvalidProxyEndpoint,
                        RejectionSource::Kioslaverc(slot.key.to_owned()),
                        raw,
                    )
                    .for_scheme(Some(attributed_scheme)),
                );
                continue;
            }
        };
        if let Some(hint) = slot.hint
            && endpoint.scheme_hint.is_none()
        {
            endpoint = endpoint.with_scheme_hint(hint);
        }
        if slot.scheme == Scheme::Socks {
            socks = Some(endpoint.clone());
        }
        per_scheme.insert(slot.scheme, ProxyEntry::Use(endpoint));
    }

    // `socksProxy` is the alternate for every scheme that named no proxy of its own,
    // exactly as in [`super::gsettings_map`] and in Windows' `socks=`
    // (`parse::apply_socks_catch_all`). KDE's own `KProtocolManager::proxyForUrl()`
    // spells it out in its `ManualProxy` case: it takes `proxyFor(url.scheme())` and
    // then appends `proxyFor("socks")` to the list whatever the scheme was, so a scheme
    // with nothing of its own is left with the SOCKS proxy alone. Chromium reaches the
    // same place by feeding `kioslaverc` into the `GetConfigFromSettings()` it also uses
    // for GNOME, where SOCKS lands in `fallback_proxies`.
    //
    // libproxy's `config-kde` is the third reference and the only one that disagrees: its
    // scheme test is an `else if` chain (`ftp`, `https`, `http`, else SOCKS), so an
    // `http://` destination with a blank `httpProxy` never reaches the SOCKS arm and gets
    // no proxy at all. Two references to one, and the majority is also the direction that
    // proxies rather than silently going direct, so the catch-all stays — unlike
    // `ReversedException` below, where libproxy is the one this crate follows.
    //
    // A blank `<scheme>Proxy=` is therefore *not* an explicit "off" here: KDE reads it
    // with `readEntry()`, which cannot tell it from an absent key, and falls back to
    // SOCKS for both. `Disabled` — the marker that suppresses the fallback — is written
    // only when there is no catch-all for it to suppress. (Windows differs on purpose:
    // there the `ftp=` token was authored inside a proxy string, not left blank in a
    // settings file, and `tests/resolve.rs`
    // `an_explicitly_disabled_scheme_still_beats_the_socks_catch_all` pins that.)
    if let Some(endpoint) = socks {
        per_scheme.insert(Scheme::All, ProxyEntry::Use(endpoint));
    } else if !socks_unusable {
        for scheme in blank {
            per_scheme.insert(scheme, ProxyEntry::Disabled);
        }
    }
    // `socks_unusable` and no valid SOCKS: `blank` gets no `Disabled`, the same way a
    // rejected non-SOCKS slot already gets none — leaving the slots empty is what lets
    // `ProxyMode::with_rejected` put the `Scheme::All` record above where the lookup will
    // reach it, instead of a `Disabled` answering Direct in front of it.

    // Reject-only stays `Manual` so the drops are not lost — `parse::windows_manual`'s
    // doc is where that rule is written.
    if per_scheme.values().all(ProxyEntry::is_disabled) && rejected.is_empty() {
        return Ok(ProxyMode::Direct);
    }
    Ok(ProxyMode::manual(per_scheme, bypass_from(settings)?).with_rejected(rejected))
}

// `ProxyType = 4`: the values are variable *names*; resolve them and delegate to
// [`ProxyEnv`].
//
// [`SLOTS`]' `env_var` is `None` for SOCKS — [`ProxyEnv`] has no convention to resolve the
// named variable through — and that slot is recorded in `rejected` rather than skipped
// silently, which would fall through to "no entry means direct". Note the asymmetry: the
// record goes in **without** checking that the named variable exists, unlike the slots that
// delegate. It reports a modelling gap in the file, not a resolved value, and this
// process's environment is not the one KDE's KIO workers run with, so an absent variable
// here proves nothing. The cost is that a SOCKS-only `kioslaverc` reports
// [`ProxyMode::Manual`] with an empty `per_scheme` and a non-empty `rejected`, so
// `is_direct` answers `false` even when no proxy is reachable from here — the fail-closed
// direction, and the intended reading of `rejected`.
fn env_mode<F>(settings: &KioslavercSettings, env: F) -> Result<ProxyMode, Error>
where
    F: Fn(&str) -> Option<std::ffi::OsString>,
{
    // Lossy rather than `env::var().ok()`, which cannot tell "unset" from "set to bytes
    // that are not UTF-8" and would answer this whole function's `None` — the fall-through
    // to "no entry means direct" the paragraph above refuses to take for a slot it merely
    // cannot map. A mangled value is a *present* one: [`ProxyEnv`] either rejects it and
    // records the drop, or keeps an endpoint that fails loudly. Both stay fail-closed,
    // where silently dropping the variable does not. Same conversion, for the same reason,
    // as [`super::desktop`]'s `text_if_set`.
    let env = |name: &str| env(name).map(|value| value.to_string_lossy().into_owned());
    // The CGI refusal keys on the name the *file* stored, and it has to be applied here
    // rather than left to [`ProxyEnv`], because under `ProxyType = 4` the name and the slot
    // come apart: the loop below hands `ProxyEnv` the canonical `http_proxy` whatever
    // `httpProxy` was set to. Leaving the rule down there therefore got it wrong in both
    // directions — it refused a `MY_HTTP_PROXY` no request header can reach, and let a file
    // naming `HTTP_PROXY` for `httpsProxy`, `ftpProxy` or `NoProxyFor` through unrefused,
    // which is httpoxy with the scheme changed. `REQUEST_METHOD` is no longer forwarded, so
    // the rule is raised once, here, on the name an administrator actually wrote.
    //
    // Non-empty rather than merely present, for the reason [`ProxyEnv::from_vars`] gives.
    let in_cgi = env(crate::env::CGI_MARKER_VAR).is_some_and(|method| !method.is_empty());
    let mut vars: Vec<(String, String)> = Vec::new();
    let mut skipped = Vec::new();
    for slot in &SLOTS {
        let Some(name) = settings.text(slot.key) else {
            continue;
        };
        let Some(canonical) = slot.env_var else {
            warn_skipped_env_var_scheme(slot.key, name);
            skipped.push(
                RejectedValue::new(
                    RejectionKind::UnsupportedMapping,
                    RejectionSource::Kioslaverc(slot.key.to_owned()),
                    format!("{}={name}", slot.key),
                )
                // The slot names its scheme, so the drop does too: `is_direct` answering
                // `false` is only half of not falling through, and `resolve` needs the
                // attribution for the other half.
                .for_scheme(Some(slot.scheme)),
            );
            continue;
        };
        // See [`KioslavercSettings::needs_expansion`]. Here the literal is a *variable
        // name* this crate cannot determine, so the lookup below would miss and the slot
        // would vanish — the fall-through to "no entry means direct" the paragraph above
        // refuses to take. The same modelling gap as a slot with no `env_var`, recorded the
        // same way. A miss on a name this crate *could* read is not recorded, because this
        // process's environment is not KIO's and an absent variable there proves nothing.
        if settings.needs_expansion(slot.key) {
            skipped.push(
                RejectedValue::new(
                    RejectionKind::UnsupportedMapping,
                    RejectionSource::Kioslaverc(slot.key.to_owned()),
                    name,
                )
                .for_scheme(Some(slot.scheme)),
            );
            continue;
        }
        let Some(value) = env(name) else {
            continue;
        };
        if in_cgi && forgeable_by_a_request_header(name) {
            return Err(Error::CgiHttpProxy {
                variable: name.to_owned(),
            });
        }
        vars.push((canonical.to_owned(), value));
    }
    // Deliberately without the `needs_expansion` guard the slots above carry. An
    // unresolvable bypass list means nothing is bypassed, which sends more traffic through
    // the proxy rather than around it — the direction [`bypass_from`] records precisely
    // because it fails closed. There is also nowhere to put the record: it belongs in
    // `BypassRules::rejected`, and a file whose only unexpanded key is this one has an
    // empty `per_scheme`, so the collapse below would answer `Direct` and drop it anyway.
    if let Some(name) = settings.text(KEY_NO_PROXY_FOR)
        && let Some(value) = env(name)
    {
        if in_cgi && forgeable_by_a_request_header(name) {
            return Err(Error::CgiHttpProxy {
                variable: name.to_owned(),
            });
        }
        vars.push(("no_proxy".to_owned(), value));
    }

    let resolved = ProxyEnv::from_vars(vars)?;
    // `ProxyEnv::is_empty` rather than its expression again, for the reason `to_mode`
    // gives — plus `skipped`, which that method has no way to know about: a SOCKS-only
    // `ProxyType = 4` file must keep the record instead of collapsing to `Direct`.
    let collapses = resolved.is_empty() && skipped.is_empty();
    let mut rejected = resolved.rejected().to_vec();
    rejected.extend(skipped);

    let mode = if collapses {
        ProxyMode::Direct
    } else {
        ProxyMode::manual(resolved.per_scheme().clone(), resolved.bypass().clone())
            .with_rejected(rejected)
    };
    // `ReversedException` is deliberately **not** applied here, unlike in [`bypass_from`].
    // `KProtocolManagerPrivate::shouldIgnoreProxyFor` gates the flag on
    // the proxy type and excludes this one:
    //
    // ```cpp
    // const bool useRevProxy = ((type == KProtocolManager::ManualProxy) && useReverseProxy());
    // ```
    //
    // while the *list* is read for both (`useNoProxyList` covers `ManualProxy` and
    // `EnvVarProxy`). So under `ProxyType = 4` KIO dereferences `NoProxyFor` as a variable
    // name — which this function does above, at `KEY_NO_PROXY_FOR` — and then uses the
    // resulting list the ordinary way round.
    //
    // libproxy's `config-kde` does apply its own `reversed_exception` to type 4, but only
    // because it does not model `ProxyType = 4` as environment-variable indirection at
    // all: its `KDE_PROXY_TYPE_SYSTEM = 4` falls into the same arm as manual and reads
    // `httpProxy` as a literal proxy URL. Following it here would reverse a typical
    // `no_proxy` (`localhost,127.0.0.1`) into "only those use the proxy" and send every
    // other destination direct with a proxy configured.
    Ok(mode)
}

// Whether a request header could have set the environment variable `name`, and so whether
// a `ProxyType = 4` slot naming it is under the caller's control in a CGI process.
//
// RFC 3875 §4.1.18 builds a meta-variable out of a field name by upper-casing it, replacing
// every `-` with `_` and prepending `HTTP_`, so `Proxy:` gives `HTTP_PROXY` and `Proxy-Url:`
// gives `HTTP_PROXY_URL`, while `HTTPS_PROXY` is the image of no field name at all. The
// prefix is the whole surface; httpoxy (CVE-2016-5385) is one name inside it, and the reason
// that one name is the only one anybody guards is that it is the only one whose *meaning* is
// fixed — here the file supplies the meaning, so the surface has to be read as it is.
//
// Case-insensitively, for the reason [`ProxyEnv::from_vars`] gives for `http_proxy`: the
// RFC's own production is upper case, and the lower spelling is refused anyway rather than
// trusting every server to have followed it.
fn forgeable_by_a_request_header(name: &str) -> bool {
    name.get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("HTTP_"))
}

// Log-only sink for a `ProxyType = 4` slot [`env_mode`] cannot delegate to [`ProxyEnv`]
// (see [`SLOTS`]). `name` is the *variable name* `kioslaverc` stored, not a resolved
// secret, but it is redacted anyway: nothing stops an administrator from writing a full
// address into the slot instead of a bare identifier.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn warn_skipped_env_var_scheme(key: &str, name: &str) {
    crate::trace::warning!(
        key = %key,
        variable = %crate::util::redact_offending_token(name),
        "kioslaverc: ProxyType=4 names an environment variable for a scheme ProxyEnv \
         cannot delegate to; skipping it, but recording it in \
         ProxyMode::Manual::rejected rather than dropping it without a trace"
    );
}

// Build the bypass rules from `NoProxyFor` + `ReversedException`, for `ProxyType = 1`.
fn bypass_from(settings: &KioslavercSettings) -> Result<BypassRules, Error> {
    let mut rules = match settings.text(KEY_NO_PROXY_FOR) {
        // The same rule [`manual_mode`] applies to every `<scheme>Proxy` slot, on the key
        // it also has to apply to. Skipping it here was the more damaging half of the two:
        // `$VAR` contains no character [`crate::endpoint::parse_host`] forbids, so the
        // literal parses into a perfectly ordinary domain pattern that no host can ever
        // match. The list would read as configured and bypass nothing — and under
        // `ReversedException` it is worse still, because a non-empty `patterns` is what
        // `warn_empty_reversed_exception` below takes as proof there is a list to invert.
        // Recorded rather than dropped, so `rejected` says the list exists and could not
        // be used, which is also what makes `BypassRules::matches` fail closed.
        Some(list) if settings.needs_expansion(KEY_NO_PROXY_FOR) => {
            let mut rules = BypassRules::new();
            rules.rejected.push(RejectedValue::new(
                RejectionKind::UnsupportedMapping,
                RejectionSource::Kioslaverc(KEY_NO_PROXY_FOR.to_owned()),
                list,
            ));
            rules
        }
        Some(list) => parse::no_proxy(list),
        None => BypassRules::new(),
    };
    if settings.reversed_exception() {
        rules.reversed_exceptions = true;
        if rules.patterns.is_empty() && rules.rejected.is_empty() {
            warn_empty_reversed_exception();
        }
    } else if settings.reversed_exception_is_disputed() {
        warn_reversed_exception_not_applied();
    }
    Ok(rules)
}

// Log-only sink for [`KioslavercSettings::reversed_exception_is_disputed`].
fn warn_reversed_exception_not_applied() {
    crate::trace::warning!(
        key = KEY_REVERSED_EXCEPTION,
        "kioslaverc: ReversedException is set to a value KConfig reads as true but \
         libproxy's config-kde parses with !!atoi, which reads the leading run of digits \
         and yields 0 unless one of them is non-zero, so 000, 0x10 and yes all come out \
         false here. libproxy is the implementation on the live path \
         since KIO 6.0.0, so the exception list is used the ordinary way round rather \
         than inverted"
    );
}

// Log-only sink for the `ReversedException = true` + empty `NoProxyFor` combination. The
// message says why the behaviour is kept rather than corrected.
fn warn_empty_reversed_exception() {
    crate::trace::warning!(
        key = KEY_REVERSED_EXCEPTION,
        list = KEY_NO_PROXY_FOR,
        "kioslaverc: ReversedException is set but NoProxyFor is empty, so the list of \
         destinations that use the proxy is empty too; every destination will resolve \
         Direct even though a proxy is configured. KIO and libproxy both behave this way, \
         so it is not corrected here — but it is almost certainly not what was intended"
    );
}

// Normalise a `<scheme>Proxy` value into something [`ProxyEndpoint::parse`] accepts.
//
// KDE writes the port after a space, not after a colon, and a `scheme://` prefix does not
// replace that: libproxy's `tests/data/sample-kde-proxy-manual` — the only sample of the file
// any reference implementation ships — has `socksProxy=socks://127.0.0.1 8080`, both at once.
// `KProtocolManagerPrivate::proxyFor` splits at the last space before anything looks at the
// scheme, so the conversion here is unconditional too. Anything with no such port keeps its
// bytes and loses only the padding around them.
//
// KIO goes one step further and *clears* a value whose tail after the last space is not all
// digits, where this returns it unchanged and lets `ProxyEndpoint::parse` reject it. Both end
// with no proxy for that scheme; only the rejection record differs.
fn normalize_address(raw: &str) -> Cow<'_, str> {
    let trimmed = raw.trim();
    // No emptiness test on the head: the split runs on an already-trimmed string, so the
    // separator it finds cannot be at index 0, and whatever is in front of it starts with a
    // character `trim` does not remove. A guard for an empty `host` here would be one no
    // input can reach.
    if let Some((host, port)) = trimmed.rsplit_once(char::is_whitespace) {
        let host = host.trim();
        if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            // Brackets first, or the fold is not reversible. KDE keeps the host and the port
            // apart; `host:port` puts them back together in a grammar where `:` is also the
            // group separator of an IPv6 address, and `::1 8080` written out as `::1:8080`
            // *is* a valid address — `0:0:0:0:0:0:1:8080`. Nothing downstream can tell which
            // colon was meant to be the port, so the endpoint names a machine the file never
            // named and falls back to the scheme's default port, without an error anywhere.
            // GNOME and macOS never meet this because they read the port from a key of its
            // own and assign `endpoint.port` after the host is parsed.
            let (prefix, bare) = match host.split_once("://") {
                Some((scheme, rest)) => (&host[..scheme.len() + 3], rest),
                None => ("", host),
            };
            if bare.parse::<Ipv6Addr>().is_ok() {
                return Cow::Owned(format!("{prefix}[{bare}]:{port}"));
            }
            return Cow::Owned(format!("{host}:{port}"));
        }
    }
    Cow::Borrowed(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a `[Proxy Settings]` section from `(key, value)` literals.
    macro_rules! kioslaverc {
        ($($key:literal => $value:literal),* $(,)?) => {{
            #[allow(unused_mut)]
            let mut settings = KioslavercSettings::new();
            $(settings.insert($key, $value);)*
            settings
        }};
    }

    // An environment that knows nothing.
    fn no_env(_: &str) -> Option<std::ffi::OsString> {
        None
    }

    // An environment built from literals.
    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<std::ffi::OsString> + use<> {
        let map: HashMap<String, std::ffi::OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).into()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    // A value the process environment can hold but `env::var` refuses to return. Unix
    // environment blocks are byte strings, so a lone `0xff` is a real value there; on
    // Windows they are potentially ill-formed UTF-16, so an unpaired surrogate is. These
    // tests are compiled on every target, hence both.
    #[cfg(unix)]
    fn not_unicode() -> std::ffi::OsString {
        std::os::unix::ffi::OsStringExt::from_vec(vec![0xff])
    }
    #[cfg(windows)]
    fn not_unicode() -> std::ffi::OsString {
        std::os::windows::ffi::OsStringExt::from_wide(&[0xD800])
    }

    fn mode_of(settings: &KioslavercSettings) -> ProxyMode {
        config_from_kioslaverc(settings, no_env).unwrap().mode
    }

    // `KconfigEntry`'s impl and `KioslavercSettings`' impl are each hand-written to mask a
    // value, the masking is what `debug_masking` holds, and neither type is printed
    // anywhere else — so this test is the only thing naming the flags beside the value. Each
    // names a state a reading cannot be re-derived without: `[$i]` on the group is the policy
    // lock that refuses every later write to the file, and `[$e]` is why a value this crate
    // declines to expand comes back unresolved. Dropped from the impl, a dump taken to
    // explain either answer shows neither.
    //
    // Exact string, so a label or a field order cannot change unseen. The value keeps its own
    // masked rendering, which `debug_masking`'s registry owns.
    #[test]
    fn both_kconfig_debugs_name_every_field_they_hold() {
        let mut settings = kioslaverc! { "httpProxy[$e]" => "http://proxy.corp:8080" };
        settings.mark_group_immutable();
        assert_eq!(
            format!("{settings:?}"),
            "KioslavercSettings { entries: {\"httpProxy\": KconfigEntry { \
             value: Some(\"http://proxy.corp:8080\"), immutable: false, expand: true }}, \
             group_immutable: true }"
        );
    }

    #[test]
    fn kconfig_markers_are_normalised() {
        assert_eq!(
            normalize_key("Proxy Config Script[$e]"),
            "Proxy Config Script"
        );
        assert_eq!(normalize_key("httpProxy"), "httpProxy");
        assert_eq!(normalize_key("  ProxyType  "), "ProxyType");
        // Trimming the outside is held by the row above; the space in front of the flag is
        // its own trim, and `kde.rs` cannot have removed it — that parser trims the key's
        // ends, not its middle.
        assert_eq!(
            normalize_key("Proxy Config Script [$e]"),
            "Proxy Config Script"
        );
        // KConfig combines flags into a single bracket, so an immutable entry that also
        // asks for expansion is written `[$ie]` — one bracket, not two.
        assert_eq!(
            normalize_key("Proxy Config Script[$ie]"),
            "Proxy Config Script"
        );
        assert_eq!(normalize_key("httpProxy[$i]"), "httpProxy");
        // Not a flag: no closing bracket at the very end.
        assert_eq!(normalize_key("weird[$e"), "weird[$e");

        assert_eq!(normalize_section("Proxy Settings][$i"), "Proxy Settings");
        assert_eq!(normalize_section("Proxy Settings"), "Proxy Settings");
        assert_eq!(normalize_section("$Version"), "$Version");
        // Both trims below, because each is a separate failure. `kde.rs` trims the line and
        // then strips the outer brackets, so padding *inside* them is still attached when
        // the name arrives, and KConfig removes it. Left in place the name matches nothing,
        // `[Proxy Settings]` never opens, and the store reads as unconfigured on a session
        // where KIO is proxying.
        assert_eq!(normalize_section(" Proxy Settings "), "Proxy Settings");
        assert_eq!(normalize_section("Proxy Settings ][$i"), "Proxy Settings");
        assert!(has_kconfig_flag("Proxy Config Script[$ie]", 'i'));
        assert!(has_kconfig_flag("Proxy Config Script[$ie]", 'e'));
        assert!(has_kconfig_flag("Proxy Settings][$i", 'i'));
        assert!(!has_kconfig_flag("Proxy Config Script[$e]", 'i'));
    }

    #[test]
    fn an_empty_section_is_direct() {
        let settings = KioslavercSettings::new();
        assert_eq!(mode_of(&settings), ProxyMode::Direct);
    }

    // The `[Proxy Settings]` group exists and names `ProxyType`, so the store is
    // configured however unreadable the value is. Only a group that never names the key
    // at all is unconfigured — that is the one case where the KDE answer has to come
    // from somewhere else.
    #[test]
    fn a_proxy_type_that_is_present_but_blank_still_configures_the_store() {
        let blank = kioslaverc! { "ProxyType" => "" };
        let configured = configured_from_kioslaverc(&blank, no_env)
            .unwrap()
            .expect("a `ProxyType` line, even an empty one, is a configured store");
        assert_eq!(configured.mode, ProxyMode::Direct);
        assert_eq!(configured.source, ProxyConfigSource::Kioslaverc);

        let other_keys_only = kioslaverc! { "httpProxy" => "http://proxy.corp:8080" };
        assert!(
            configured_from_kioslaverc(&other_keys_only, no_env)
                .unwrap()
                .is_none(),
            "no `ProxyType` at all is the unconfigured store"
        );
    }

    #[test]
    fn proxy_type_zero_is_direct_and_ignores_other_keys() {
        let with_keys = kioslaverc! {
            "ProxyType" => "0",
            "httpProxy" => "http://proxy.corp:8080",
        };
        assert_eq!(mode_of(&with_keys), ProxyMode::Direct);

        let bare = kioslaverc! { "ProxyType" => "0" };
        let config = configured_from_kioslaverc(&bare, no_env)
            .unwrap()
            .expect("an explicit ProxyType=0 is a decision, not an absent store");
        assert_eq!(config.source, ProxyConfigSource::Kioslaverc);
        assert_eq!(config.mode, ProxyMode::Direct);
    }

    #[test]
    fn proxy_type_three_is_wpad() {
        let settings = kioslaverc! { "ProxyType" => "3" };
        assert_eq!(mode_of(&settings), ProxyMode::WpadAutoDetect);
    }

    #[test]
    fn an_unknown_proxy_type_is_direct() {
        let settings = kioslaverc! { "ProxyType" => "9", "httpProxy" => "http://p:1" };
        assert_eq!(mode_of(&settings), ProxyMode::Direct);

        let bare = kioslaverc! { "ProxyType" => "9" };
        assert_eq!(
            configured_from_kioslaverc(&bare, no_env)
                .unwrap()
                .map(|config| config.mode),
            Some(ProxyMode::Direct)
        );
    }

    // The KDE-side twin of this lives in `super::kde`, which only compiles on Linux with
    // `linux-kde` on — so it is not a test this crate's primary target ever runs. This one
    // is here, in the module that compiles everywhere.
    #[test]
    fn an_unexpanded_reference_is_rejected_not_reported_as_a_host() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy[$e]" => "$PROXY_WATCH_KDE_TEST:8080",
        };
        let mode = mode_of(&settings);
        assert!(
            mode.endpoint_for(Scheme::Http).is_none(),
            "`$PROXY_WATCH_KDE_TEST` is a variable name, not a host: {mode:?}"
        );
        assert_eq!(
            mode.rejected().unwrap()[0].redacted_input(),
            "$PROXY_WATCH_KDE_TEST:8080"
        );
        assert_eq!(
            mode.rejected().unwrap()[0].kind(),
            RejectionKind::UnsupportedMapping
        );
    }

    // The one case where answering `Direct` would state the opposite of the live desktop:
    // KDE expands `$PROXY_WATCH_KDE_TEST` and proxies the request, this crate will not
    // expand it, and with no `socksProxy` there is nothing else to cover HTTP.
    #[cfg(feature = "resolve")]
    #[test]
    fn an_unexpanded_http_proxy_is_reported_rather_than_resolved_direct() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy[$e]" => "$PROXY_WATCH_KDE_TEST:8080",
        };
        let mode = mode_of(&settings);
        assert_eq!(
            mode.rejected().unwrap()[0].affected_scheme(),
            Some(Scheme::Http)
        );
        let config = crate::ProxyConfig::new(mode, Vec::new());
        let url = url::Url::parse("http://intranet.corp/x").unwrap();
        let err = crate::resolve(&config, &url).unwrap_err();
        assert!(
            matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                if *scheme == Scheme::Http),
            "{err:?}"
        );
    }

    // The composed fix this round adds: a rejected `socksProxy` costs `manual_mode`'s SOCKS
    // catch-all too, not just `socks://` itself, so it must be attributed to `Scheme::All`
    // (not `Scheme::Socks`) *and* must not let `blank`'s `Disabled` fill pre-empt the report
    // by resolving `https` before `resolve` ever consults `rejected`. A blank `httpsProxy`
    // is what puts `Https` in `blank` in the first place — without it, `blank` stays empty
    // and this test cannot tell the shadowing half of the fix from its absence. Either half
    // missing and this falls through to `Ok(Direct)` instead of naming the drop.
    #[cfg(feature = "resolve")]
    #[test]
    fn an_unusable_socks_entry_is_reported_for_a_scheme_it_would_have_covered() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpsProxy" => "",
            "socksProxy" => "not a host with spaces",
        };
        let config = crate::ProxyConfig::new(mode_of(&settings), Vec::new());
        let url = url::Url::parse("https://intranet.corp/x").unwrap();
        let err = crate::resolve(&config, &url).unwrap_err();
        assert!(
            matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                if *scheme == Scheme::All),
            "{err:?}"
        );
    }

    // `[$e]` on a value with nothing to substitute expands to itself, so it is honoured.
    #[test]
    fn an_expansion_flag_over_a_plain_value_changes_nothing() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy[$e]" => "http://proxy.corp:8080",
        };
        assert_eq!(
            mode_of(&settings)
                .endpoint_for(Scheme::Http)
                .unwrap()
                .authority(),
            "proxy.corp:8080"
        );
    }

    // The mirror of the row above, and the half this test alone holds: [`needs_expansion`]
    // wants the flag *and* a `$`, and nothing else notices the flag half going. `$` is a
    // legal URL character, so it reaches this key without KConfig ever having written
    // `[$e]` — the query string below, or the `/home/$USER/proxy.pac` the comment on
    // `pac_mode` uses. Read without the flag, the crate refuses a script KDE fetches
    // happily and reports an empty `Manual` with a record naming a value nothing is wrong
    // with.
    #[test]
    fn a_dollar_sign_without_the_expansion_flag_is_an_ordinary_value() {
        let settings = kioslaverc! {
            "ProxyType" => "2",
            "Proxy Config Script" => "http://wpad.corp/proxy.pac?for=$site",
        };
        match mode_of(&settings) {
            ProxyMode::Pac { url, .. } => {
                assert_eq!(url.as_str(), "http://wpad.corp/proxy.pac?for=$site");
            }
            other => panic!("expected Pac, got {other:?}"),
        }
    }

    #[test]
    fn proxy_type_two_reads_the_config_script() {
        let settings = kioslaverc! {
            "ProxyType" => "2",
            "Proxy Config Script[$e]" => "http://wpad.corp/proxy.pac",
        };
        match mode_of(&settings) {
            ProxyMode::Pac { url, .. } => assert_eq!(url.as_str(), "http://wpad.corp/proxy.pac"),
            other => panic!("expected Pac, got {other:?}"),
        }
    }

    #[test]
    fn a_config_script_path_becomes_a_file_url() {
        let settings = kioslaverc! {
            "ProxyType" => "2",
            "Proxy Config Script" => "/home/alice/proxy.pac",
        };
        match mode_of(&settings) {
            ProxyMode::Pac { url, .. } => {
                assert_eq!(url.scheme(), "file");
                assert!(url.path().ends_with("/home/alice/proxy.pac"));
            }
            other => panic!("expected Pac, got {other:?}"),
        }
    }

    #[test]
    fn a_relative_config_script_is_an_error() {
        let settings = kioslaverc! { "ProxyType" => "2", "Proxy Config Script" => "proxy.pac" };
        assert!(matches!(
            config_from_kioslaverc(&settings, no_env),
            Err(Error::InvalidProxyUrl { .. })
        ));
    }

    // The PAC twin of `an_unexpanded_no_proxy_for_is_rejected_rather_than_parsed_as_a_dead_pattern`
    // — and silent for the same reason, which the first assertion pins: `$` is a legal path
    // character, so the literal parses into a `file:` URL that is well-formed and points at
    // nothing. Without the `needs_expansion` check this reports a PAC script as ordinary
    // configuration with an empty `rejected`.
    #[test]
    fn an_unexpanded_config_script_is_rejected_rather_than_reported_as_a_dead_url() {
        assert!(
            Url::parse("file:///home/$USER/proxy.pac").is_ok(),
            "the literal has to parse, or the fold would not be silent"
        );
        let settings = kioslaverc! {
            "ProxyType" => "2",
            "Proxy Config Script[$e]" => "/home/$USER/proxy.pac",
        };
        let mode = mode_of(&settings);
        assert!(
            !matches!(mode, ProxyMode::Pac { .. }),
            "a script path this crate will not expand is not a script URL: {mode:?}"
        );
        assert_eq!(
            mode.rejected().unwrap()[0].redacted_input(),
            "/home/$USER/proxy.pac"
        );
        assert_eq!(
            mode.rejected().unwrap()[0].kind(),
            RejectionKind::UnsupportedMapping
        );
    }

    // The half `an_unexpanded_config_script_is_rejected_rather_than_reported_as_a_dead_url`
    // cannot state on its own: not reporting the dead URL is only useful if what replaces it
    // does not resolve `Direct`. KDE fetches the expanded script and proxies whatever it says.
    #[cfg(feature = "resolve")]
    #[test]
    fn an_unexpanded_config_script_does_not_resolve_direct() {
        let settings = kioslaverc! {
            "ProxyType" => "2",
            "Proxy Config Script[$e]" => "/home/$USER/proxy.pac",
        };
        let config = crate::ProxyConfig::new(mode_of(&settings), Vec::new());
        let url = url::Url::parse("http://intranet.corp/x").unwrap();
        let err = crate::resolve(&config, &url).unwrap_err();
        assert!(
            matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                if *scheme == Scheme::All),
            "{err:?}"
        );
    }

    // `ProxyType = 4` reads the *name* of a variable, so an unexpanded value is a name this
    // crate cannot determine — the same modelling gap as a slot with no `env_var`, and
    // recorded the same way. Dropping it instead leaves an empty `per_scheme` that reads as
    // "KDE names no proxy".
    #[test]
    fn an_unexpanded_env_var_name_is_recorded_rather_than_looked_up_literally() {
        let settings = kioslaverc! {
            "ProxyType" => "4",
            "httpProxy[$e]" => "$PROXY_WATCH_NAME_OF_A_VAR",
        };
        let mode = config_from_kioslaverc(&settings, env_of(&[("PROXY_WATCH_NAME_OF_A_VAR", "x")]))
            .unwrap()
            .mode;
        assert!(mode.endpoint_for(Scheme::Http).is_none(), "{mode:?}");
        assert_eq!(
            mode.rejected().unwrap()[0].kind(),
            RejectionKind::UnsupportedMapping
        );
        assert_eq!(
            mode.rejected().unwrap()[0].affected_scheme(),
            Some(Scheme::Http)
        );
    }

    // A POSIX file name may hold any byte but `/` and NUL, and `parse_script_location`
    // splices one straight into a `file:` URL, where some of those bytes are grammar
    // instead: `#` and `?` end the path (`/home/a#b/proxy.pac` names `/home/a`), `\` is a
    // separator too because `file` is a WHATWG "special" scheme, tab and newline are
    // deleted outright, a *trailing* C0 control goes with them, and `%` starts an escape.
    // All but `%` are what `printable_to_string` decodes `\\`, `\t`, `\n` and `\r` *into*,
    // so the crate restores the byte KDE stored and loses it one call later — see the
    // end-to-end twin in `kde.rs`. The last two rows are what an escape set written from
    // that list of rules misses and an allowlist covers without being told: `\x01` is a
    // KConfig escape and survives `text`'s trim, and `c|` is a Windows drive letter to
    // WHATWG, which this version of `url` happens not to rewrite and the next one may.
    #[test]
    fn a_config_script_path_keeps_the_bytes_url_syntax_would_have_taken() {
        for path in [
            "/home/a#b/proxy.pac",
            "/home/a?b/proxy.pac",
            "/home/a\\b/proxy.pac",
            "/home/a\tb/proxy.pac",
            "/home/a\nb/proxy.pac",
            "/home/a%2Fb/proxy.pac",
            "/home/proxy.pac\u{1}",
            "/c|/proxy.pac",
        ] {
            let mut settings = KioslavercSettings::new();
            settings.insert("ProxyType", "2");
            settings.insert(KEY_CONFIG_SCRIPT, path);
            match mode_of(&settings) {
                ProxyMode::Pac { url, .. } => assert_eq!(
                    crate::util::percent_decode(url.path()),
                    path,
                    "{path:?} did not survive the splice into a file: URL"
                ),
                other => panic!("expected Pac for {path:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn proxy_type_two_without_a_script_is_direct() {
        let settings = kioslaverc! { "ProxyType" => "2" };
        assert_eq!(mode_of(&settings), ProxyMode::Direct);
    }

    #[test]
    fn manual_entries_map_onto_their_schemes() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "http://http.corp:3128",
            "httpsProxy" => "http://https.corp:3129",
            "ftpProxy" => "http://ftp.corp:3130",
            "socksProxy" => "socks://socks.corp:1081",
        };
        let mode = mode_of(&settings);
        assert_eq!(
            mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "http.corp:3128"
        );
        assert_eq!(
            mode.endpoint_for(Scheme::Https).unwrap().authority(),
            "https.corp:3129"
        );
        assert_eq!(
            mode.endpoint_for(Scheme::Ftp).unwrap().authority(),
            "ftp.corp:3130"
        );
        assert_eq!(
            mode.endpoint_for(Scheme::Socks).unwrap().authority(),
            "socks.corp:1081"
        );
    }

    #[test]
    fn the_legacy_space_separated_form_is_accepted() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "proxy.corp 3128",
        };
        assert_eq!(
            mode_of(&settings)
                .endpoint_for(Scheme::Http)
                .unwrap()
                .authority(),
            "proxy.corp:3128"
        );
    }

    // Every slot here carries a `scheme://` prefix *and* a space-separated port at once,
    // because that is the shape KDE tooling writes — `normalize_address` above holds the
    // evidence — and the combination is what that function has to get right. `httpsProxy`
    // naming an `http://` proxy belongs to the shape too: the proxy that carries HTTPS
    // traffic is itself reached over HTTP.
    //
    // `ftp://` is where this crate stops agreeing with either reference. [`ProxyScheme`] has
    // no FTP variant — an FTP-protocol proxy is a transport this crate does not model — so the
    // slot is rejected rather than guessed at. libproxy hands `ftp://127.0.0.1:8080` back to
    // its caller unchanged; Chromium strips the scheme and calls it HTTP
    // (`FixupProxyHostScheme`). Rejecting leaves the drop in `rejected` for the caller to see,
    // which neither of those does.
    #[test]
    fn every_slot_reads_a_scheme_and_a_space_separated_port() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "ftpProxy" => "ftp://proxy.corp 8080",
            "httpProxy" => "http://proxy.corp 8080",
            "httpsProxy" => "http://proxy.corp 8080",
            "socksProxy" => "socks://proxy.corp 8080",
        };
        let config = config_from_kioslaverc(&settings, no_env).unwrap();
        for scheme in [Scheme::Http, Scheme::Https, Scheme::Socks] {
            let endpoint = config.mode.endpoint_for(scheme).unwrap();
            assert_eq!(endpoint.authority(), "proxy.corp:8080", "{scheme}");
        }
        assert_eq!(
            config.mode.endpoint_for(Scheme::Socks).unwrap().scheme_hint,
            Some(ProxyScheme::Socks5)
        );

        let rejected = config.mode.rejected().unwrap();
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0].redacted_input(), "ftp://proxy.corp 8080");
        assert_eq!(rejected[0].kind(), RejectionKind::InvalidProxyEndpoint);
        // Four slots were read and one failed; `source` is the only field that says which,
        // and it is the field a user acts on. Unread, `slot.key` can name any of the other
        // three and nothing else in this file objects, while the reader is pointed at a
        // setting that parsed perfectly well.
        assert_eq!(
            rejected[0].source(),
            &RejectionSource::Kioslaverc("ftpProxy".to_owned())
        );
        // The SOCKS catch-all is what an FTP destination is left with, exactly as if the slot
        // had named nothing — the rejection does not turn into a bypass.
        assert_eq!(
            config.mode.endpoint_for(Scheme::Ftp).unwrap().authority(),
            "proxy.corp:8080"
        );
    }

    // The escape hatch [`ProxyScheme`]'s doc promises, on the source that has no test for it
    // — `gsettings_map::tests::a_host_stored_as_a_url_keeps_its_scheme_hint` is the GNOME
    // half. Same rule, two `SLOTS` tables, so one test cannot stand for both.
    #[test]
    fn a_version_written_into_the_value_beats_the_socks5_default() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "socksProxy" => "socks4://socks.corp 1080",
        };
        assert_eq!(
            mode_of(&settings)
                .endpoint_for(Scheme::Socks)
                .unwrap()
                .scheme_hint,
            Some(ProxyScheme::Socks4)
        );
    }

    #[test]
    fn a_value_without_a_port_uses_the_source_default() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "proxy.corp",
            "socksProxy" => "socks.corp",
        };
        let mode = mode_of(&settings);
        assert_eq!(mode.endpoint_for(Scheme::Http).unwrap().port, 8080);
        let socks = mode.endpoint_for(Scheme::Socks).unwrap();
        assert_eq!(socks.port, 1080);
        assert_eq!(socks.scheme_hint, Some(ProxyScheme::Socks5));
    }

    #[test]
    fn an_empty_value_is_disabled_and_an_absent_key_is_nothing() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "proxy.corp:3128",
            "ftpProxy" => "",
        };
        let mode = mode_of(&settings);
        assert!(
            mode.entry_for(Scheme::Ftp)
                .expect("ftp entry")
                .is_disabled()
        );
        assert!(
            mode.entry_for(Scheme::Https).is_none(),
            "httpsProxy was never written, so there is no entry at all"
        );
    }

    // KDE's `KProtocolManager::proxyForUrl()` appends `proxyFor("socks")` to the list
    // for every URL, so a scheme that named nothing of its own is left with the SOCKS
    // proxy alone — including one whose key is present but blank, which `readEntry()`
    // cannot tell from an absent key.
    #[test]
    fn a_socks_entry_catches_every_scheme_that_named_nothing() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "http.corp 3128",
            "ftpProxy" => "",
            "socksProxy" => "socks.corp 1081",
        };
        let mode = mode_of(&settings);
        assert_eq!(
            mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "http.corp:3128",
            "a scheme with its own proxy is never overridden by the catch-all"
        );
        for scheme in [Scheme::Https, Scheme::Ftp] {
            let endpoint = mode.endpoint_for(scheme).unwrap_or_else(|| {
                panic!("{scheme} named no proxy, so the SOCKS entry must carry it")
            });
            assert_eq!(endpoint.authority(), "socks.corp:1081");
            assert_eq!(endpoint.scheme_hint, Some(ProxyScheme::Socks5));
        }
    }

    #[test]
    fn manual_with_only_empty_values_is_direct() {
        let settings = kioslaverc! { "ProxyType" => "1", "httpProxy" => "", "ftpProxy" => "" };
        assert_eq!(mode_of(&settings), ProxyMode::Direct);
    }

    // A malformed `<scheme>Proxy` value drops only that slot and is recorded on
    // `Manual.rejected`, instead of failing the whole section.
    #[test]
    fn malformed_scheme_hosts_are_dropped_and_recorded() {
        for label in ["mixed", "only_malformed", "masked"] {
            let settings = match label {
                "mixed" => kioslaverc! {
                    "ProxyType" => "1",
                    "httpProxy" => "http.corp:3128",
                    "httpsProxy" => "not a host with spaces",
                    "ftpProxy" => "ftp.corp:3130",
                },
                "only_malformed" => kioslaverc! {
                    "ProxyType" => "1",
                    "httpProxy" => "not a host with spaces",
                },
                "masked" => kioslaverc! {
                    "ProxyType" => "1",
                    "httpProxy" => "http://alice:hunter2@bad host:8080",
                },
                _ => unreachable!(),
            };
            let mode = mode_of(&settings);
            match label {
                "mixed" => {
                    assert_eq!(
                        mode.endpoint_for(Scheme::Http).unwrap().authority(),
                        "http.corp:3128"
                    );
                    assert_eq!(
                        mode.endpoint_for(Scheme::Ftp).unwrap().authority(),
                        "ftp.corp:3130"
                    );
                    assert!(mode.endpoint_for(Scheme::Https).is_none());
                    assert_eq!(
                        mode.rejected().unwrap()[0].redacted_input(),
                        "not a host with spaces"
                    );
                }
                "only_malformed" => {
                    assert!(!mode.is_direct());
                    assert!(mode.endpoint_for(Scheme::Http).is_none());
                    assert_eq!(
                        mode.rejected().unwrap()[0].redacted_input(),
                        "not a host with spaces"
                    );
                }
                "masked" => {
                    assert_eq!(
                        mode.rejected().unwrap()[0].redacted_input(),
                        "http://alice:***@bad host:8080"
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn no_proxy_for_becomes_bypass_rules() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "http://proxy.corp:8080",
            "NoProxyFor" => "localhost,.corp.example,10.0.0.0/8",
        };
        let mode = mode_of(&settings);
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        assert!(bypass.matches_authority("api.corp.example"));
        assert!(bypass.matches_authority("10.1.2.3"));
        assert!(!bypass.matches_authority("example.net"));
        assert!(!bypass.reversed_exceptions);
    }

    // The list above splits the same way under either separator set, so it does not pin
    // which parser this key is wired to. Sent through `parse::proxy_override` instead — the
    // Windows one, which also splits on `;` and on whitespace — it invents bypass entries the
    // user did not write, and this test is the only thing that sees it.
    // libproxy is the implementation on the live path since KIO 6.0.0 and splits
    // on `,` alone (`g_strsplit (value->str, ",", -1)`, `config-kde.c:148`), so `;` is an
    // ordinary host character: this is one unmatchable name, not two rules.
    #[test]
    fn a_semicolon_does_not_separate_a_no_proxy_for_list() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "http://proxy.corp:8080",
            "NoProxyFor" => "a.example;b.example",
        };
        let mode = mode_of(&settings);
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        assert_eq!(bypass.patterns.len(), 1);
        assert!(!bypass.matches_authority("a.example"));
        assert!(!bypass.matches_authority("b.example"));
    }

    // `ReversedException` with no `NoProxyFor` is an empty inclusion list, so *nothing*
    // uses the proxy. Pinned because it looks like the silent-`Direct` bug shape, and the
    // only thing separating it from one is that KIO and libproxy agree — see
    // `warn_empty_reversed_exception`.
    #[test]
    fn a_reversed_exception_with_no_list_sends_everything_direct() {
        for settings in [
            kioslaverc! {
                "ProxyType" => "1",
                "httpProxy" => "http://proxy.corp:8080",
                "ReversedException" => "1",
            },
            // `NoProxyFor=` — the key present but empty, which is what clearing the list
            // in the settings dialog leaves behind while the checkbox stays on.
            kioslaverc! {
                "ProxyType" => "1",
                "httpProxy" => "http://proxy.corp:8080",
                "NoProxyFor" => "",
                "ReversedException" => "1",
            },
        ] {
            let mode = mode_of(&settings);
            let bypass = mode.bypass().expect("manual mode has bypass rules");
            assert!(bypass.reversed_exceptions);
            assert!(bypass.patterns.is_empty());
            assert!(bypass.rejected.is_empty());
            for host in ["example.net", "api.corp.example", "10.1.2.3"] {
                assert!(
                    bypass.matches_authority(host),
                    "{host} must be direct: an empty reversed list names no destination \
                     that uses the proxy"
                );
            }
        }
    }

    // `ProxyType = 4` must ignore `ReversedException`.
    #[test]
    fn proxy_type_4_ignores_reversed_exception() {
        let settings = kioslaverc! {
            "ProxyType" => "4",
            "httpProxy" => "MY_HTTP_PROXY",
            "NoProxyFor" => "MY_NO_PROXY",
            // `1`, not `true`: the narrower atoi-based reading would decline `true` on its
            // own, and then this test would pass without exercising the ProxyType=4
            // exclusion at all.
            "ReversedException" => "1",
        };
        let mode = env_mode(&settings, |name| match name {
            "MY_HTTP_PROXY" => Some("http://proxy.corp:8080".into()),
            "MY_NO_PROXY" => Some("localhost,127.0.0.1,api.corp.example".into()),
            _ => None,
        })
        .expect("env mode");
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        assert!(
            !bypass.reversed_exceptions,
            "ProxyType=4 must not reverse: KIO's useRevProxy requires ManualProxy"
        );
        // The list means what it says, so an ordinary destination still uses the proxy.
        assert!(!bypass.matches_authority("example.net"));
        // And a name from the list bypasses. It has to be a name outside the implicit set:
        // `127.0.0.1` bypasses on the loopback rule alone, so a `NoProxyFor` that resolved
        // to nothing at all would pass that too.
        assert!(bypass.matches_authority("api.corp.example"));
    }

    // The named variable exists and holds something; only `String` cannot carry it. The
    // fall-through this guards against is silent: `env::var().ok()` would answer `None`,
    // `env_mode` would collect no vars at all, and a `kioslaverc` that configures a proxy
    // would read back as `Direct`.
    #[cfg(any(unix, windows))]
    #[test]
    fn a_named_variable_whose_value_is_not_unicode_does_not_read_back_as_direct() {
        let settings = kioslaverc! {
            "ProxyType" => "4",
            "httpProxy" => "MY_HTTP_PROXY",
        };
        let mode = env_mode(&settings, |name| {
            (name == "MY_HTTP_PROXY").then(not_unicode)
        })
        .expect("env mode");
        assert!(
            !matches!(mode, ProxyMode::Direct),
            "a present-but-unreadable value must not become \"no proxy configured\": {mode:?}"
        );
    }

    // The bypass half of `an_unexpanded_http_proxy_is_reported_rather_than_resolved_direct`.
    // The failure it guards is quieter than the scheme-slot one: `$MY_NO_PROXY` parses,
    // so without the check the list is not empty — it is full of one entry that matches
    // nothing.
    #[test]
    fn an_unexpanded_no_proxy_for_is_rejected_rather_than_parsed_as_a_dead_pattern() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "http://proxy.corp:8080",
            "NoProxyFor[$e]" => "$MY_NO_PROXY",
        };
        let bypass = mode_of(&settings)
            .bypass()
            .expect("manual mode has bypass rules")
            .clone();
        assert!(
            bypass.patterns.is_empty(),
            "the literal variable name must not become a pattern: {:?}",
            bypass.patterns
        );
        assert_eq!(
            bypass.rejected.len(),
            1,
            "the list has to be reported as unusable: {:?}",
            bypass.rejected
        );
        // The bypass list is reached by a different constructor than the scheme slots
        // above, on a key of its own, so it needs its own reading of `source`.
        assert_eq!(
            bypass.rejected[0].source(),
            &RejectionSource::Kioslaverc("NoProxyFor".to_owned())
        );
    }

    // The same file with `ReversedException` on. Everything hangs on `rejected`: the
    // reversed reading of an unusable list is "no destination bypasses", and the empty
    // list that would otherwise be indistinguishable means the opposite.
    #[test]
    fn an_unexpanded_reversed_no_proxy_for_does_not_send_every_destination_direct() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "http://proxy.corp:8080",
            "NoProxyFor[$e]" => "$MY_NO_PROXY",
            "ReversedException" => "1",
        };
        let bypass = mode_of(&settings)
            .bypass()
            .expect("manual mode has bypass rules")
            .clone();
        assert!(bypass.reversed_exceptions);
        assert!(
            !bypass.matches_authority("example.net"),
            "an unusable inclusion list must not disable the proxy for everything"
        );
    }

    #[test]
    fn reversed_exception_inverts_the_list() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "http://proxy.corp:8080",
            "NoProxyFor" => ".corp.example",
            "ReversedException" => "1",
        };
        let mode = mode_of(&settings);
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        assert!(bypass.reversed_exceptions);
        // Reversed: the *listed* hosts use the proxy, everything else goes direct.
        assert!(!bypass.matches_authority("api.corp.example"));
        assert!(bypass.matches_authority("example.net"));
        // Loopback is still bypassed either way.
        assert!(bypass.matches_authority("localhost"));
    }

    // A typo in `NoProxyFor` must not turn KDE's "only these use the proxy" list into
    // "everything goes direct". `10.0.0/8` is an octet short of a CIDR block, so
    // [`parse::no_proxy`] rejects it, and [`BypassRules::matches`] then refuses to send
    // unlisted destinations direct.
    #[test]
    fn a_typo_in_a_reversed_no_proxy_for_list_does_not_silently_bypass_the_proxy() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "http://proxy.corp:8080",
            "NoProxyFor" => ".corp.example,10.0.0/8",
            "ReversedException" => "1",
        };
        let mode = mode_of(&settings);
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        assert!(bypass.reversed_exceptions);
        assert_eq!(bypass.rejected[0].redacted_input(), "10.0.0/8");

        // The network the dropped entry named, and everything else unlisted, keeps using
        // the proxy instead of quietly going direct.
        assert!(!bypass.matches_authority("10.1.2.3"));
        assert!(!bypass.matches_authority("example.net"));
        // What survived parsing still means what it says.
        assert!(!bypass.matches_authority("api.corp.example"));
        // And the implicit bypasses are unaffected.
        assert!(bypass.matches_authority("localhost"));
    }

    // `ReversedException=true` — the only spelling KDE's own dialog writes — is **not**
    // applied, because libproxy's `config-kde` parses the key with `!!atoi` and
    // `atoi("true")` is 0. Following KIO here would report `Direct` for every destination
    // the live path in fact sends through the proxy.
    #[test]
    fn a_dialog_written_reversed_exception_is_not_applied() {
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "http://proxy.corp:8080",
            "NoProxyFor" => ".corp.example",
            "ReversedException" => "true",
        };
        let mode = mode_of(&settings);
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        assert!(!bypass.reversed_exceptions);
        // The list means what it says: the named suffix is bypassed, everything else uses
        // the proxy.
        assert!(bypass.matches_authority("api.corp.example"));
        assert!(!bypass.matches_authority("example.net"));

        // And the empty-list form, where applying the reversal turns *every* destination
        // direct while `httpProxy` is set, from a file the settings dialog wrote unaided.
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "http://proxy.corp:8080",
            "ReversedException" => "true",
        };
        let mode = mode_of(&settings);
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        assert!(!bypass.reversed_exceptions);
        assert!(!bypass.matches_authority("example.net"));
    }

    // The `atoi`-based rule, spelling by spelling: `atoi`-non-zero is applied, everything
    // else is not, and the disputed middle (KConfig-true but `atoi`-zero) is the set that
    // earns `warn_reversed_exception_not_applied`.
    #[test]
    fn the_reversed_exception_flag_follows_libproxys_atoi() {
        // (value, applied, disputed)
        let cases = [
            // What KDE's dialog writes. KConfig says true, `atoi` says 0.
            ("true", false, true),
            ("false", false, false),
            // KConfig's other three falsehoods, verbatim from its `negatives` array, and
            // case-insensitively as `compare(..., Qt::CaseInsensitive)` reads them.
            ("no", false, false),
            ("off", false, false),
            ("OFF", false, false),
            ("0", false, false),
            // Not KConfig's `0`, so KConfig reads it as true while `atoi` still says 0.
            // These two are why the warning cannot say `atoi` returns 0 for values that
            // do not start with a digit: both start with one, and both still return 0.
            ("000", false, true),
            ("0x10", false, true),
            // KConfig-true spellings `atoi` cannot see a digit in.
            ("yes", false, true),
            ("on", false, true),
            ("maybe", false, true),
            // Where the two readings coincide.
            ("1", true, false),
            ("2", true, false),
            ("007", true, false),
            ("1abc", true, false),
            // `atoi` takes one optional sign before the digits.
            ("-1", true, false),
            ("+1", true, false),
            // Where this reader and libproxy part company, because libproxy never hands
            // `atoi` the raw value: `config-kde.c` deletes every `"` and turns every space
            // into `:` before the call, and it reverses no KConfig escape. So
            // `ReversedException=\s1` — which `kde.rs` expands to `" 1"`, and which reaches
            // `atoi` with the space on, as it would in C — is applied here and is
            // `atoi("\s1") == 0` there, while the quoted spelling goes the other way.
            //
            // Left as written: following `config-kde.c` through means holding one key's bytes
            // unparsed inside a reader that is KConfig-shaped everywhere else, for spellings
            // no dialog writes. Do not read the divergence as one-sided: this reader applies
            // `\s1` where libproxy does not, so what it applies is not a subset of what
            // `config-kde.c` applies.
            (" 1", true, false),
            ("\"1\"", false, true),
            // Present but empty. `text` collapses it onto absent, as it does for every
            // other key in this module, so it is not reported as disputed either — even
            // though `KConfigGroup` would technically convert the empty (non-null) value
            // to true. Nothing writes it, and a warning about it would be noise.
            ("", false, false),
        ];
        for (value, applied, disputed) in cases {
            // Built by hand rather than through `kioslaverc!`, whose value slot is a
            // macro `literal` and cannot take the loop variable.
            let mut settings = KioslavercSettings::new();
            settings.insert(KEY_REVERSED_EXCEPTION, value);
            assert_eq!(
                settings.reversed_exception(),
                applied,
                "ReversedException={value:?}"
            );
            assert_eq!(
                settings.reversed_exception_is_disputed(),
                disputed,
                "ReversedException={value:?}"
            );
        }

        let absent = kioslaverc! {};
        assert!(!absent.reversed_exception());
        assert!(!absent.reversed_exception_is_disputed());
    }

    #[test]
    fn env_var_proxy_dereferences_the_variable_names() {
        let settings = kioslaverc! {
            "ProxyType" => "4",
            "httpProxy" => "MY_HTTP_PROXY",
            "httpsProxy" => "MY_HTTPS_PROXY",
            "NoProxyFor" => "MY_NO_PROXY",
        };
        let env = env_of(&[
            ("MY_HTTP_PROXY", "http://env.corp:3128"),
            ("MY_HTTPS_PROXY", "http://env.corp:3129"),
            ("MY_NO_PROXY", ".corp.example"),
            // Must be ignored: KDE names the variable, it is not a fixed convention.
            ("http_proxy", "http://wrong.corp:1"),
        ]);
        let config = config_from_kioslaverc(&settings, env).unwrap();
        assert_eq!(config.source, ProxyConfigSource::KioslavercEnv);
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "env.corp:3128"
        );
        assert_eq!(
            config.mode.endpoint_for(Scheme::Https).unwrap().authority(),
            "env.corp:3129"
        );
        assert!(
            config
                .mode
                .bypass()
                .unwrap()
                .matches_authority("api.corp.example")
        );
    }

    #[test]
    fn env_var_proxy_with_unset_variables_is_direct() {
        let settings = kioslaverc! { "ProxyType" => "4", "httpProxy" => "MY_HTTP_PROXY" };
        let config = config_from_kioslaverc(&settings, no_env).unwrap();
        assert_eq!(config.source, ProxyConfigSource::KioslavercEnv);
        assert_eq!(config.mode, ProxyMode::Direct);
    }

    // `ProxyType = 4`'s `socksProxy` slot cannot be delegated to `ProxyEnv`
    // (no `socks_proxy` convention — see `SLOTS`), so it must not vanish without a
    // trace (see `crate::parse`'s module doc: a silently dropped scheme-endpoint entry
    // is fail-open).
    #[test]
    fn proxy_type_4_records_or_directs_skipped_socks_slots() {
        for label in ["socks_only", "socks_and_http", "empty_socks"] {
            let (settings, env) = match label {
                "socks_only" => (
                    kioslaverc! { "ProxyType" => "4", "socksProxy" => "MY_SOCKS_PROXY" },
                    env_of(&[("MY_SOCKS_PROXY", "socks5://socks.corp:1080")]),
                ),
                "socks_and_http" => (
                    kioslaverc! {
                        "ProxyType" => "4",
                        "httpProxy" => "MY_HTTP_PROXY",
                        "socksProxy" => "MY_SOCKS_PROXY",
                    },
                    env_of(&[
                        ("MY_HTTP_PROXY", "http://env.corp:3128"),
                        ("MY_SOCKS_PROXY", "socks5://socks.corp:1080"),
                    ]),
                ),
                "empty_socks" => (
                    kioslaverc! { "ProxyType" => "4", "socksProxy" => "" },
                    env_of(&[]),
                ),
                _ => unreachable!(),
            };
            let config = config_from_kioslaverc(&settings, env).unwrap();
            match label {
                "socks_only" => {
                    assert_eq!(config.source, ProxyConfigSource::KioslavercEnv);
                    assert!(
                        !config.mode.is_direct(),
                        "the skipped socksProxy slot must not be silently lost: {:?}",
                        config.mode
                    );
                    assert_eq!(
                        config.mode.rejected().unwrap()[0].redacted_input(),
                        "socksProxy=MY_SOCKS_PROXY"
                    );
                    assert_eq!(
                        config.mode.rejected().unwrap()[0].kind(),
                        RejectionKind::UnsupportedMapping
                    );
                    // `is_direct` is the mode-level half. `resolve` is the other one, and
                    // it only reaches the record through the scheme the slot named.
                    #[cfg(feature = "resolve")]
                    {
                        let url = crate::Url::parse("socks://socks.corp/").unwrap();
                        let resolved = crate::ProxyConfig::new(config.mode.clone(), Vec::new());
                        let err = crate::resolve(&resolved, &url).unwrap_err();
                        assert!(
                            matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                                if *scheme == Scheme::Socks),
                            "{err:?}"
                        );
                    }
                }
                "socks_and_http" => {
                    assert_eq!(
                        config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
                        "env.corp:3128",
                        "the resolvable slot must still resolve"
                    );
                    assert_eq!(
                        config.mode.rejected().unwrap()[0].redacted_input(),
                        "socksProxy=MY_SOCKS_PROXY",
                        "the unmodellable slot must still be recorded"
                    );
                }
                "empty_socks" => {
                    assert_eq!(config.mode, ProxyMode::Direct);
                }
                _ => unreachable!(),
            }
        }
    }

    // The variable *name* `kioslaverc` stores for `socksProxy` is redacted like every
    // other `rejected` entry — see `warn_skipped_env_var_scheme`'s doc comment.
    #[test]
    fn a_skipped_socks_slot_is_redacted_in_the_rejected_list() {
        let settings = kioslaverc! {
            "ProxyType" => "4",
            "socksProxy" => "http://alice:hunter2@bad host:1080",
        };
        let config = config_from_kioslaverc(&settings, no_env).unwrap();
        assert_eq!(
            config.mode.rejected().unwrap()[0].redacted_input(),
            "socksProxy=http://alice:***@bad host:1080"
        );
    }

    // The CGI rule under `ProxyType = 4`, which is about the variable `kioslaverc` named
    // and not about the slot that name fills. Each row is a file, an environment, and
    // whether the read must be refused; the two directions a slot-based rule gets wrong are
    // the first row (a name no request header can produce) and the fourth (a name that is
    // exactly the forged one, under a slot such a rule does not reach).
    #[test]
    fn the_cgi_refusal_follows_the_named_variable_and_not_the_slot() {
        // Slot key, variable name, whether the read must be refused, and why.
        let cases: &[(&str, &str, bool, &str)] = &[
            (
                "httpProxy",
                "MY_HTTP_PROXY",
                false,
                "a field name mapping onto MY_HTTP_PROXY would have to be `My-Http-Proxy`, \
                 which RFC 3875 §4.1.18 turns into HTTP_MY_HTTP_PROXY instead",
            ),
            ("httpProxy", "http_proxy", true, "httpoxy itself"),
            (
                "httpProxy",
                "HTTP_PROXY",
                true,
                "httpoxy itself, upper case",
            ),
            (
                "httpsProxy",
                "HTTP_PROXY",
                true,
                "the forged variable does not stop being forged because the file filed it \
                 under another scheme",
            ),
            (
                "httpsProxy",
                "HTTPS_PROXY",
                false,
                "no field name has HTTPS_PROXY as its image",
            ),
            (
                "httpProxy",
                "HTTP_CORPORATE_PROXY",
                true,
                "the header `Corporate-Proxy:` produces it",
            ),
        ];
        for (key, variable, refused, why) in cases {
            let mut settings = KioslavercSettings::new();
            settings.insert("ProxyType", "4");
            settings.insert(key, *variable);
            let env = env_of(&[
                (*variable, "http://env.corp:3128"),
                ("REQUEST_METHOD", "GET"),
            ]);
            let result = config_from_kioslaverc(&settings, env);
            assert_eq!(
                matches!(&result, Err(Error::CgiHttpProxy { variable: named }) if named == variable),
                *refused,
                "{key}={variable}: {why} ({result:?})"
            );
            if !refused {
                // Not being refused is half of what an allowed row claims; the other half
                // is that the variable is still read. Checking only for the absence of
                // `CgiHttpProxy` let `Ok` with no endpoint at all — and every other error
                // besides — pass as an allow.
                let config =
                    result.unwrap_or_else(|error| panic!("{key}={variable}: {why} ({error:?})"));
                let scheme = if *key == "httpsProxy" {
                    Scheme::Https
                } else {
                    Scheme::Http
                };
                assert_eq!(
                    config
                        .mode
                        .endpoint_for(scheme)
                        .unwrap_or_else(|| panic!("{key}={variable}: no endpoint in the slot"))
                        .authority(),
                    "env.corp:3128",
                    "{key}={variable}"
                );
            }
        }
    }

    // The rule is the CGI one and not a ban on the name: outside a CGI process the same
    // file is read as written.
    #[test]
    fn a_forgeable_variable_name_is_only_refused_under_cgi() {
        let settings = kioslaverc! { "ProxyType" => "4", "httpProxy" => "HTTP_PROXY" };
        let env = env_of(&[("HTTP_PROXY", "http://env.corp:3128")]);
        assert_eq!(
            config_from_kioslaverc(&settings, env)
                .unwrap()
                .mode
                .endpoint_for(Scheme::Http)
                .unwrap()
                .authority(),
            "env.corp:3128"
        );
    }

    // The refusal is raised on the name the *file* stored, and `NoProxyFor` stores a name
    // too. `the_cgi_refusal_follows_the_named_variable_and_not_the_slot` walks the
    // `<scheme>Proxy` slots only, so this arm answers to this test alone — and it is the arm where the
    // forgery buys something the others do not: a `Proxy:` header landing here does not name
    // a proxy, it names the destinations that skip one, so a request can switch the egress
    // proxy off for whatever it likes while every proxy slot still reads as configured.
    //
    // `MY_PROXY` in the `httpProxy` slot is the control on the attribution: no field name
    // maps onto it, so the error can only have come from the bypass slot.
    #[test]
    fn the_bypass_slot_is_refused_under_cgi_like_the_proxy_slots() {
        let settings = kioslaverc! {
            "ProxyType" => "4",
            "httpProxy" => "MY_PROXY",
            "NoProxyFor" => "HTTP_PROXY",
        };
        let env = env_of(&[
            ("MY_PROXY", "http://env.corp:3128"),
            ("HTTP_PROXY", "*"),
            ("REQUEST_METHOD", "GET"),
        ]);
        assert!(matches!(
            config_from_kioslaverc(&settings, env),
            Err(Error::CgiHttpProxy { variable }) if variable == "HTTP_PROXY"
        ));
    }

    // `REQUEST_METHOD` marks a CGI process by *holding a method*, not by existing —
    // [`ProxyEnv::from_vars`] says so for its own read, and this file raises the rule again,
    // separately, on the name an administrator wrote. Only the first spelling was held.
    // Reading presence alone costs a process that exports the name empty — a shell that ran
    // `export REQUEST_METHOD=`, a runner that clears it between requests — its whole
    // `kioslaverc`: `read_store` propagates the error rather than falling back, so a machine
    // with a working KDE proxy configuration reports failure instead of the proxy.
    #[test]
    fn an_empty_request_method_is_not_a_cgi_environment() {
        let settings = kioslaverc! { "ProxyType" => "4", "httpProxy" => "HTTP_PROXY" };
        let env = env_of(&[
            ("HTTP_PROXY", "http://env.corp:3128"),
            ("REQUEST_METHOD", ""),
        ]);
        assert_eq!(
            config_from_kioslaverc(&settings, env)
                .unwrap()
                .mode
                .endpoint_for(Scheme::Http)
                .unwrap()
                .authority(),
            "env.corp:3128"
        );
    }

    #[test]
    fn a_manual_file_is_attributed_to_kioslaverc() {
        let settings = kioslaverc! { "ProxyType" => "1", "httpProxy" => "proxy.corp:8080" };
        assert_eq!(
            config_from_kioslaverc(&settings, no_env).unwrap().source,
            ProxyConfigSource::Kioslaverc
        );
    }

    #[test]
    fn a_section_without_a_proxy_type_is_unset() {
        // Some other tool's keys, or a section KDE has written but never applied a proxy
        // dialog to: there is no mode switch, so this store has no opinion.
        let settings = kioslaverc! { "NoProxyFor" => "localhost" };
        assert!(
            configured_from_kioslaverc(&settings, no_env)
                .unwrap()
                .is_none()
        );
        assert!(
            configured_from_kioslaverc(&KioslavercSettings::new(), no_env)
                .unwrap()
                .is_none()
        );
        // Present but empty is a different question, and a different answer: see
        // `a_proxy_type_that_is_present_but_blank_still_configures_the_store`.
    }

    #[test]
    fn addresses_are_normalised_conservatively() {
        assert_eq!(normalize_address("http://h:8080"), "http://h:8080");
        assert_eq!(normalize_address("  h 8080 "), "h:8080");
        assert_eq!(normalize_address("h:8080"), "h:8080");
        assert_eq!(normalize_address("h notaport"), "h notaport");
        // The pass-through arm keeps the trim the row above only shows on the folding arm.
        // Production cannot tell the two apart today, because `text` has trimmed already —
        // but the trim is what makes the head of the split non-empty, and that is what the
        // missing emptiness guard rests on.
        assert_eq!(normalize_address("  h notaport  "), "h notaport");
        assert_eq!(normalize_address("[::1]:8080"), "[::1]:8080");
        // The *last* whitespace, which is where `KProtocolManagerPrivate::proxyFor` splits.
        // A hand-written double space still names a port; split at the first one instead and
        // the port carries a space, nothing here matches, and the proxy the desktop is
        // using is dropped as an unparseable address.
        assert_eq!(normalize_address("h  8080"), "h:8080");
    }

    // KDE stores the host and the port as two things separated by a space, and
    // `normalize_address` folds them into one `host:port` string. For an unbracketed IPv6
    // host that fold is not
    // reversible: `::1 3128` written out as `::1:3128` *is itself a valid IPv6 address*
    // (`0:0:0:0:0:0:1:3128`), so nothing downstream can tell which colon was the port. It
    // comes back unbracketed as the host `::1:3128` on the slot's default port — a machine
    // the file never named, with no rejection and no warning. The `socks://` row is the same
    // fold under the scheme prefix libproxy's `tests/data/sample-kde-proxy-manual` shows
    // KDE writing.
    #[test]
    fn an_unbracketed_ipv6_host_keeps_its_port_when_the_two_are_folded_together() {
        assert_eq!(normalize_address("::1 3128"), "[::1]:3128");
        assert_eq!(normalize_address("socks://::1 1080"), "socks://[::1]:1080");
        let settings = kioslaverc! {
            "ProxyType" => "1",
            "httpProxy" => "::1 3128",
            "socksProxy" => "socks://::1 1080",
        };
        let config = config_from_kioslaverc(&settings, no_env).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "[::1]:3128"
        );
        assert_eq!(
            config.mode.endpoint_for(Scheme::Socks).unwrap().authority(),
            "[::1]:1080"
        );
        assert_eq!(config.mode.rejected().unwrap_or_default(), &[]);
    }
}
