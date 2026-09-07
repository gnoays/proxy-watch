//! The macOS proxies dictionary, reduced to a pure Rust value.
//!
//! `SCDynamicStoreCopyProxies` hands back a `CFDictionary` whose values are `CFString`,
//! `CFNumber`, `CFBoolean` and `CFArray<CFString>`. Everything below the Core Foundation
//! boundary lives here: [`ProxyDict`] is an ordinary `HashMap`, so the whole mapping
//! from Apple's schema onto [`ProxyMode`] is a *total function of its input* and can be
//! unit tested on any operating system — which matters because the macOS backend was
//! written without access to a Mac (see [`crate::sys`]).
//!
//! The key names come from `SCSchemaDefinitions.h` in
//! [`apple-oss-distributions/configd`](https://github.com/apple-oss-distributions/configd).
//!
//! A key holding something the reader cannot use is either *recorded* or merely *logged*,
//! and one rule decides which: whether what it configures survives the loss. A key whose
//! loss takes a setting with it leaves a [`RejectedValue`]: the `<Scheme>Enable`,
//! `<Scheme>Proxy` and `<Scheme>Port` keys, which skip a scheme between them, the PAC and
//! WPAD switches, which cost a whole mode, and `ExceptionsList` / `ExcludeSimpleHostnames`,
//! which cost every exception at once. Answering with nothing to show for a setting the
//! user made is the fail-open this crate refuses everywhere, and it does not stop being one
//! because the direction is a host reaching the proxy rather than skipping it.
//!
//! One key stops at the log line, and not because its loss is small: `<Scheme>User`, whose
//! value is the half of a credential this crate does hold, so not even the log carries it.
//!
//! That rule is about the *key*, so it may not depend on how far the value got. A value the
//! Core Foundation reader could not carry at all arrives as [`DictValue::Unreadable`] rather
//! than not arriving, because the alternative — dropping it — is indistinguishable here from
//! a key nobody ever set, and the whole rule above turns on being able to tell those apart.
//!
//! # Known limitations
//!
//! * `GopherEnable` / `RTSPEnable` name proxy families macOS recognises but this crate has
//!   no [`Scheme`] variant for, so nothing is ever routed through one. An enabled family
//!   that names a host is still recorded as a [`RejectedValue`] rather than dropped —
//!   exactly as [`crate::parse::proxy_server`] records a Windows `gopher=` entry. Their
//!   `…Port` and `…User` keys are not read at all, so [`Debug`] withholds those.
//! * The `*User` keys (macOS 15.0+) become a [`ProxyAuth`] with no password; the
//!   password itself lives in the keychain and is deliberately not fetched.

// The module is compiled on every target under `cfg(test)` so that its table driven
// tests run in CI on Windows and Linux too; there it has no caller.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use url::Url;

use crate::auth::ProxyAuth;
use crate::bypass::{BypassDialect, BypassRules};
use crate::config::{ProxyConfig, ProxyConfigSource};
use crate::diagnostic::{RejectedValue, RejectionKind, RejectionSource};
use crate::endpoint::{ProxyEndpoint, ProxyEntry, ProxyScheme, Scheme};
use crate::error::Error;
use crate::mode::ProxyMode;
use crate::util::{port_from_digits, redact_offending_token};

const AUTO_DISCOVERY_ENABLE: &str = "ProxyAutoDiscoveryEnable";
// The master switch for both PAC forms.
const AUTO_CONFIG_ENABLE: &str = "ProxyAutoConfigEnable";
const AUTO_CONFIG_URL: &str = "ProxyAutoConfigURLString";
const AUTO_CONFIG_JAVASCRIPT: &str = "ProxyAutoConfigJavaScript";
const EXCEPTIONS_LIST: &str = "ExceptionsList";
// Bypass host names without a dot.
const EXCLUDE_SIMPLE_HOSTNAMES: &str = "ExcludeSimpleHostnames";

// One row of Apple's `<Scheme>Enable` / `<Scheme>Proxy` / `<Scheme>Port` /
// `<Scheme>User` key family.
struct SchemeKeys {
    scheme: Scheme,
    enable: &'static str,
    // The `…Proxy` key holding the host.
    host: &'static str,
    port: &'static str,
    // The `…User` key (macOS 15.0+).
    user: &'static str,
    // The port assumed when the `…Port` key is missing or zero.
    default_port: u16,
    // The wire protocol hint, set only where the schema actually implies one.
    hint: Option<ProxyScheme>,
}

// The four macOS key families with a [`Scheme`] of their own, in [`Scheme::ALL`] order.
const SCHEMES: [SchemeKeys; 4] = [
    SchemeKeys {
        scheme: Scheme::Http,
        enable: "HTTPEnable",
        host: "HTTPProxy",
        port: "HTTPPort",
        user: "HTTPUser",
        default_port: 80,
        hint: None,
    },
    SchemeKeys {
        scheme: Scheme::Https,
        enable: "HTTPSEnable",
        host: "HTTPSProxy",
        port: "HTTPSPort",
        user: "HTTPSUser",
        // The proxy for `https://` requests is still reached over plain HTTP
        // (`CONNECT`), so this is an HTTP proxy and its default port is 80 — 443 would be
        // the *destination*'s port, which is not what goes here. Chromium says the same
        // twice: `proxy_chain_util_apple.cc` maps `kCFProxyTypeHTTPS` to `SCHEME_HTTP`
        // ("the proxy itself is still expected to be an HTTP proxy") and falls back to
        // `GetDefaultPortForScheme(SCHEME_HTTP)`; libproxy's `config-osx.c` builds
        // `http://` for HTTP/HTTPS/FTP alike. Same reason for `hint: None`.
        default_port: 80,
        hint: None,
    },
    SchemeKeys {
        scheme: Scheme::Ftp,
        enable: "FTPEnable",
        host: "FTPProxy",
        port: "FTPPort",
        user: "FTPUser",
        // 80, not 21, and for the same reason: Chromium passes `kCFProxyTypeHTTP` for
        // this family, so an `ftp://` request goes through an HTTP proxy here as well.
        default_port: 80,
        hint: None,
    },
    SchemeKeys {
        scheme: Scheme::Socks,
        enable: "SOCKSEnable",
        host: "SOCKSProxy",
        port: "SOCKSPort",
        user: "SOCKSUser",
        default_port: 1080,
        // Borrowed, not observed: the dictionary carries no version, and the same
        // `proxy_chain_util_apple.cc` maps `kCFProxyTypeSOCKS` to `SCHEME_SOCKS5` saying
        // "we can't tell whether this was v4 or v5" and assuming v5 as the only version
        // macOS offers. GNOME's `socks` child is pinned the same way and for the same
        // reason — see `sys/linux/gsettings_map.rs`.
        hint: Some(ProxyScheme::Socks5),
    },
];

// One row of a key family macOS has and this crate has no [`Scheme`] for. Only the two
// keys that decide whether a record is owed are named: the `…Port` and `…User` keys are
// never read, so listing them would make [`is_known_key`] claim more than it does.
struct UnroutableKeys {
    enable: &'static str,
    // The `…Proxy` key holding the host, kept for the record, never for routing.
    host: &'static str,
}

const UNROUTABLE: [UnroutableKeys; 2] = [
    UnroutableKeys {
        enable: "GopherEnable",
        host: "GopherProxy",
    },
    UnroutableKeys {
        enable: "RTSPEnable",
        host: "RTSPProxy",
    },
];

// What every reader below hands back for a value it can only describe by shape. The
// spelling is shared with the `<n strings>` arms for the same reason those exist: a value
// this crate could not read is not one it may quote.
const UNREADABLE: &str = "<unreadable value>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DictValue {
    Number(i64),
    Text(String),
    // The `CFString` elements of a `CFArray`, and how many of its elements were not one this
    // reader could carry across.
    //
    // The count is here rather than folded into [`DictValue::Unreadable`] because a list that
    // lost a member is still a list every reader below can use, and because under
    // `ExceptionsList` each lost member is one bypass rule the user configured and will not
    // get — a host they meant to reach directly, proxied instead. Shorter by exactly the
    // members that went missing is the one thing a caller cannot see from `items` alone.
    // Nothing about the lost members is carried: a value this crate could not read is not one
    // it may quote, the same line [`UNREADABLE`] draws.
    List {
        items: Vec<String>,
        unreadable: usize,
    },
    // A value that reached the reader and could not be carried across the Core Foundation
    // boundary at all: an unmodelled type, or a `CFString` whose content does not reencode
    // as UTF-8. It holds nothing, on purpose — the point is that the key was *set*, which
    // is the one thing dropping the entry could not say.
    Unreadable,
}

#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct ProxyDict {
    entries: HashMap<String, DictValue>,
}

// Whether this module reads this key by name, i.e. whether the value under it is one
// this crate has a schema for.
//
// Visible to the rest of [`crate::sys`] because the macOS reader needs the same answer
// before this module ever sees the dictionary: dropping an unmodelled value is only
// harmless under a key nothing reads (see `to_proxy_dict` in `src/sys/mac/mod.rs`).
pub(super) fn is_known_key(key: &str) -> bool {
    const SINGLES: [&str; 6] = [
        AUTO_DISCOVERY_ENABLE,
        AUTO_CONFIG_ENABLE,
        AUTO_CONFIG_URL,
        AUTO_CONFIG_JAVASCRIPT,
        EXCEPTIONS_LIST,
        EXCLUDE_SIMPLE_HOSTNAMES,
    ];
    SINGLES.contains(&key)
        || SCHEMES
            .iter()
            .any(|keys| [keys.enable, keys.host, keys.port, keys.user].contains(&key))
        || UNROUTABLE
            .iter()
            .any(|keys| [keys.enable, keys.host].contains(&key))
}

impl fmt::Debug for ProxyDict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut keys: Vec<&str> = self.entries.keys().map(String::as_str).collect();
        keys.sort_unstable();

        let mut map = f.debug_map();
        for key in keys {
            let value = &self.entries[key];
            match (key, value) {
                (AUTO_CONFIG_JAVASCRIPT, DictValue::Text(script)) => map.entry(
                    &key,
                    &format_args!(
                        "<{} bytes, fnv1a {:016x}>",
                        script.len(),
                        crate::util::fnv1a(script.as_bytes())
                    ),
                ),
                // Raw text from `SCDynamicStore`, not a parsed `Url` — nothing upstream has
                // asked it to be one, so it may hold whatever `configd` was handed. That
                // rules out `redact_userinfo` alone: its scan restarts at whitespace, so a
                // password with a space in it (`alice:my pass@host`) puts the `user:` half
                // and the `@` on opposite sides of the restart and comes out unmasked
                // entirely. The withhold pass is what covers the shapes the mask cannot.
                (AUTO_CONFIG_URL, DictValue::Text(url)) => {
                    map.entry(&key, &format_args!("{}", redact_offending_token(url)))
                }
                // The same two keys carrying a value of a type the schema does not model.
                // `to_dict_value` in `src/sys/mac/mod.rs` picks the `DictValue` off the Core
                // Foundation runtime type and never looks at the key, so a `CFArray` stored
                // under `ProxyAutoConfigJavaScript` arrives as a `List`: it matches neither
                // arm above, which require `Text`, nor the three below, whose guard is
                // `!is_known_key`. Without this arm it would reach the masking arms at the
                // bottom, which hide a credential but not a script body — and under these
                // two keys the whole value is the secret, not a fragment of it. What the key
                // promises about its value is not something this crate gets to assume —
                // `configd` is what wrote it — and the value is unusable here either way, so
                // name only its shape.
                (AUTO_CONFIG_JAVASCRIPT | AUTO_CONFIG_URL, _) => {
                    map.entry(&key, &format_args!("<unmodelled type, withheld>"))
                }
                // Nothing was carried across the boundary, so there is nothing to mask and
                // nothing to count — and no "key not read" spelling either: `to_proxy_dict`
                // stores this variant only under a key [`is_known_key`] answers for.
                (_, DictValue::Unreadable) => map.entry(&key, &format_args!("{UNREADABLE}")),
                (_, DictValue::Text(text)) if !is_known_key(key) => {
                    map.entry(&key, &format_args!("<{} bytes, key not read>", text.len()))
                }
                (_, DictValue::List { items, .. }) if !is_known_key(key) => map.entry(
                    &key,
                    &format_args!("<{} strings, key not read>", items.len()),
                ),
                (_, DictValue::Number(_)) if !is_known_key(key) => {
                    map.entry(&key, &format_args!("<number, key not read>"))
                }
                // The keys this crate *does* read. `<Scheme>Proxy` holds an address, and
                // [`ProxyEndpoint::parse`](crate::endpoint::ProxyEndpoint::parse) accepts a
                // bare `user:pass@host` there — that spelling is supported input, not a
                // corner case — so the value carries a password as readily as
                // `AUTO_CONFIG_URL` does. `ExceptionsList` holds bypass entries, which is
                // where a stranded `bob:hunter2` fragment turns up. Masked, not counted:
                // unlike an unread key, what these hold is the thing a reader is debugging.
                (_, DictValue::Text(text)) => {
                    map.entry(&key, &format_args!("{}", redact_offending_token(text)))
                }
                // The lost members are absent here as well as from `items`, and deliberately:
                // there is nothing of them to print that would not be a guess. What a reader
                // debugging a missing bypass rule has instead is the [`RejectedValue`] per
                // lost member that [`bypass_from_dict`] records, which is a public carrier
                // rather than a `tracing`-only one.
                (_, DictValue::List { items, .. }) => map.entry(
                    &key,
                    &items
                        .iter()
                        .map(|item| redact_offending_token(item))
                        .collect::<Vec<_>>(),
                ),
                // No catch-all: a new `DictValue` variant must be given an arm here rather
                // than falling through to the derive. That fallthrough is what left the
                // scheme keys in the clear after the `AUTO_CONFIG_*` pair was fixed.
                (_, DictValue::Number(number)) => map.entry(&key, number),
            };
        }
        map.finish()
    }
}

impl ProxyDict {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn insert(&mut self, key: impl Into<String>, value: DictValue) {
        self.entries.insert(key.into(), value);
    }

    // Read a flag key: `None` when the key is absent *or* holds something this reader
    // cannot make a flag out of, otherwise "non-zero".
    //
    // The first distinction matters: an absent `HTTPEnable` means "this scheme is not
    // configured at all", while `HTTPEnable = 0` means "explicitly off" and therefore
    // becomes [`ProxyEntry::Disabled`].
    // The second is the one this `None` cannot express, which is why
    // [`ProxyDict::flag_is_unusable`] exists — a caller that needs to tell "never set"
    // from "set to something unreadable" asks that instead.
    // The text arm is this crate's own tolerance, not the reference's: Chromium's
    // `GetBoolFromDictionary` asks for a `CFNumberRef` and returns its caller's default
    // when the value is a `CFString`, so `HTTPEnable = "1"` leaves the whole scheme
    // unconfigured there and the request goes direct. That silent direct is the outcome
    // this crate exists to avoid, and reading the digits costs nothing.
    fn flag(&self, key: &str) -> Option<bool> {
        match self.entries.get(key)? {
            DictValue::Number(value) => Some(*value != 0),
            DictValue::Text(text) => text.trim().parse::<i64>().ok().map(|value| value != 0),
            DictValue::List { .. } | DictValue::Unreadable => None,
        }
    }

    // Whether the flag key holds something that is neither absent nor a flag: `"yes"`, an
    // array. [`ProxyDict::flag`] folds those into the same `None` as "never set", so the
    // scheme is skipped exactly as if nothing had been configured — and a proxy the user
    // switched on then goes direct with no record, which is the fail-open
    // [`record_unroutable_schemes`] refuses one key over.
    //
    // Sibling of [`ProxyDict::port_is_unusable`], which draws the same line on the same
    // dictionary and hands back a value for the same reason: what it guards does not
    // survive the drop. A `Number` is absent from the arms because every `i64` is a flag.
    fn flag_is_unusable(&self, key: &str) -> Option<String> {
        match self.entries.get(key)? {
            DictValue::Number(_) => None,
            DictValue::Text(text) => self.flag(key).is_none().then(|| text.trim().to_owned()),
            // Reduced to its shape, in the spelling `Debug` uses for the same reason: what
            // an array holds under a flag key is not something this crate can vouch for.
            // Counting only `items` is not an undercount: the spelling says "strings", and
            // the members that were dropped are exactly the ones that were not.
            DictValue::List { items, .. } => Some(format!("<{} strings>", items.len())),
            DictValue::Unreadable => Some(UNREADABLE.to_owned()),
        }
    }

    fn text(&self, key: &str) -> Option<&str> {
        match self.entries.get(key)? {
            DictValue::Text(text) => Some(text.trim()).filter(|text| !text.is_empty()),
            _ => None,
        }
    }

    // Read a string key *without* trimming — used for the inline PAC script, whose
    // leading whitespace is part of the source.
    fn raw_text(&self, key: &str) -> Option<&str> {
        match self.entries.get(key)? {
            DictValue::Text(text) => Some(text.as_str()).filter(|text| !text.trim().is_empty()),
            _ => None,
        }
    }

    // Whether the string key holds something that is neither absent nor a string: a number,
    // an array. [`ProxyDict::text`] and [`ProxyDict::raw_text`] fold those into the same
    // `None` as "never set", and every caller reads that `None` as "nothing was configured
    // here" — so an `HTTPProxy` the user filled in leaves `HTTPEnable = 1` pointing at
    // nothing, and `Direct` comes back with no record, which is the fail-open
    // [`record_unroutable_schemes`] refuses one key over.
    //
    // Third of the trio with [`ProxyDict::flag_is_unusable`] and
    // [`ProxyDict::port_is_unusable`], and it hands back a value to record for the same
    // reason the flag one does: what it guards does not survive the drop.
    //
    // A blank string is absent from the arms on purpose. `text` rejects it, but "filled in
    // with nothing" is how a key that was never filled in reads at this layer — the line
    // `port_is_unusable` already draws around `""`.
    fn text_is_unusable(&self, key: &str) -> Option<String> {
        match self.entries.get(key)? {
            DictValue::Text(_) => None,
            DictValue::Number(value) => Some(value.to_string()),
            // Reduced to its shape, in the spelling `flag_is_unusable` uses for the same
            // reason: what an array holds under a string key is not something this crate
            // can vouch for. `<Scheme>Proxy` and `ProxyAutoConfigURLString` are among the
            // keys this guards, and both can name a host.
            DictValue::List { items, .. } => Some(format!("<{} strings>", items.len())),
            DictValue::Unreadable => Some(UNREADABLE.to_owned()),
        }
    }

    // Read a port key. Zero is treated as "not set", which is how macOS stores a port
    // that was never filled in.
    //
    // Same tolerance as [`ProxyDict::flag`], and the reference falls back the same way:
    // `ProxyDictionaryToProxyChain` takes the port as a `CFNumberRef` and, failing that,
    // uses `GetDefaultPortForScheme` — so a string port means Chromium talks to 80 while
    // the plist says 8080. The text arm goes through [`port_from_digits`] rather than its
    // own `parse` so that the port grammar (`1*DIGIT`) has one definition, not one per
    // reader.
    fn port(&self, key: &str) -> Option<u16> {
        let port = match self.entries.get(key)? {
            DictValue::Number(value) => u16::try_from(*value).ok(),
            DictValue::Text(text) => port_from_digits(text.trim()),
            DictValue::List { .. } | DictValue::Unreadable => None,
        };
        port.filter(|port| *port != 0)
    }

    // Whether the port key holds something that is neither absent nor a port: `70000`,
    // `-1`, `"http"`, an array. [`ProxyDict::port`] folds all of those into the same
    // `None` as "never filled in", so a scheme that kept its default port here would send
    // a typed-in `70000` to `proxy.corp:80` — a service the user never named, reached over
    // a connection they asked to have proxied. Every other backend refuses that: the port
    // travels inside the host string there, [`crate::util::split_host_port`] rejects
    // `proxy.corp:70000` outright, and the scheme is dropped with a record so `resolve`
    // answers `Error::ProxyEntryUnusable`. This hands back a value so the reader that has
    // the host and the port in two keys can reach the same answer.
    //
    // Chromium substitutes rather than refusing (`ProxyDictionaryToProxyChain` reads the
    // `CFNumberRef` into an `int` and hands it to
    // `FromSchemeHostAndPort(Scheme, string_view, optional<uint16_t>)`, so `70000`
    // truncates to 4464 and `-1` to 65535) and says nothing about it either way. The
    // divergence from it is deliberate: a port the user filled in and this crate cannot
    // read is not a port this crate may guess at.
    fn port_is_unusable(&self, key: &str) -> Option<String> {
        let value = self.entries.get(key)?;
        if self.port(key).is_some() {
            return None;
        }
        match value {
            // `0` is Apple's own "not set" for the `<Scheme>Port` keys of
            // `SCSchemaDefinitions.h`, not a mistake.
            DictValue::Number(value) => (*value != 0).then(|| value.to_string()),
            DictValue::Text(text) => {
                (!matches!(text.trim(), "" | "0")).then(|| text.trim().to_owned())
            }
            // Reduced to its shape, in the spelling the sibling readers use for the same
            // reason: what an array holds under a port key is not something this crate can
            // vouch for.
            DictValue::List { items, .. } => Some(format!("<{} strings>", items.len())),
            DictValue::Unreadable => Some(UNREADABLE.to_owned()),
        }
    }

    // The strings under an array key, together with the number of members the reader could
    // not carry across. The count travels with the strings rather than through a second
    // lookup because the only caller needs both to say what it read and what it lost.
    fn list(&self, key: &str) -> Option<(&[String], usize)> {
        match self.entries.get(key)? {
            DictValue::List { items, unreadable } => Some((items.as_slice(), *unreadable)),
            _ => None,
        }
    }

    // Whether the array key holds something that is neither absent nor an array.
    // [`ProxyDict::list`] folds those into the same `None` as "never set", and the only
    // caller then builds an empty [`BypassRules`].
    //
    // It hands back a value like its siblings, but the record goes somewhere else: no
    // scheme lost an answer, so there is no scheme-endpoint entry to carry it, and
    // [`BypassRules::rejected`] is the carrier instead — the same one `kioslaverc`'s
    // unexpanded `NoProxyFor` uses, and the one a malformed *entry* of this very list
    // already reaches. The direction is the opposite of the fold the siblings guard: a
    // host the user meant to reach directly goes through the proxy instead, rather than a
    // proxy the user configured being skipped or dialled somewhere else. Fail-closed, and
    // still not something a caller may be left unable to see.
    //
    // A blank string is "filled in with nothing", the line `text_is_unusable` and
    // `port_is_unusable` draw around `""`.
    fn list_is_unusable(&self, key: &str) -> Option<String> {
        match self.entries.get(key)? {
            // An array is what this key is supposed to hold, however few of its members
            // survived the crossing — a list that lost members is not a list of the wrong
            // *type*, and folding it in here would report it as one. The loss is recorded by
            // [`bypass_from_dict`] instead, one entry per member.
            DictValue::List { .. } => None,
            DictValue::Text(text) => Some(text.trim().to_owned()).filter(|text| !text.is_empty()),
            DictValue::Number(value) => Some(value.to_string()),
            DictValue::Unreadable => Some(UNREADABLE.to_owned()),
        }
    }
}

impl FromIterator<(String, DictValue)> for ProxyDict {
    fn from_iter<I: IntoIterator<Item = (String, DictValue)>>(iter: I) -> Self {
        Self {
            entries: iter.into_iter().collect(),
        }
    }
}

// Collapse the proxies dictionary into a single [`ProxyMode`].
pub(crate) fn mode_from_dict(dict: &ProxyDict) -> Result<ProxyMode, Error> {
    let mut rejected = Vec::new();

    // `== Some(true)` folds "unreadable" into "off", the same fold the scheme loop below
    // records rather than swallows — and these two flags are the wider drop of the three:
    // WPAD or a PAC the user switched on is skipped whole, not one scheme of four. Which is
    // why they are attributed to `Scheme::All` and not left unattributed: an unattributed
    // record is one `resolve` cannot find, and the widest drop would be the only one that
    // still answered Direct.
    record_unreadable_flag(
        dict,
        AUTO_DISCOVERY_ENABLE,
        Some(Scheme::All),
        &mut rejected,
    );
    if dict.flag(AUTO_DISCOVERY_ENABLE) == Some(true) {
        // The one return that drops `rejected` on purpose, and the only one that can: getting
        // here means the flag above read as `Some(true)`, and `record_unreadable_flag` pushes
        // only when the flag is unreadable, so the list is still empty. Record anything ahead
        // of this line and it needs somewhere to go — `WpadAutoDetect` has no slot for it.
        return Ok(ProxyMode::WpadAutoDetect);
    }

    record_unreadable_flag(dict, AUTO_CONFIG_ENABLE, Some(Scheme::All), &mut rejected);
    if dict.flag(AUTO_CONFIG_ENABLE) == Some(true) {
        // Both PAC returns carry the list rather than dropping it: unlike the WPAD one above,
        // the scheme-key loop is not the only thing that can have recorded by now — a
        // `ProxyAutoDiscoveryEnable` that was present but unreadable is recorded and then
        // folded into "off", which lands here.
        if let Some(script) = dict.raw_text(AUTO_CONFIG_JAVASCRIPT) {
            return Ok(ProxyMode::pac_inline(script.to_owned()).with_rejected(rejected));
        }
        if let Some(url) = dict.text(AUTO_CONFIG_URL) {
            let parsed = Url::parse(url).map_err(|source| Error::invalid_proxy_url(url, source))?;
            return Ok(ProxyMode::pac(parsed).with_rejected(rejected));
        }
        // Neither key produced a script, and the enable flag said there is one: whatever is
        // in them, the PAC the user switched on is what falling through loses.
        record_unreadable_text(
            dict,
            AUTO_CONFIG_JAVASCRIPT,
            Some(Scheme::All),
            &mut rejected,
        );
        record_unreadable_text(dict, AUTO_CONFIG_URL, Some(Scheme::All), &mut rejected);
    }

    let mut per_scheme = HashMap::new();
    let mut any_enabled = false;
    for keys in &SCHEMES {
        // SOCKS is the one family in `SCHEMES` `apply_socks_fallback` (below) also reads:
        // a valid entry fills every scheme with none of its own. A drop under `SOCKSEnable`
        // or `SOCKSProxy` therefore costs that fallback too, not just `socks://` itself, so
        // it is attributed as widely as the fallback it prevented rather than to its own
        // scheme — the same reasoning `mode_from_dict`'s PAC/WPAD attribution above uses.
        let attributed_scheme = if keys.scheme == Scheme::Socks {
            Scheme::All
        } else {
            keys.scheme
        };
        let Some(enabled) = dict.flag(keys.enable) else {
            // Out of `per_scheme`, so an unreadable flag is not read as "off".
            record_unreadable_flag(dict, keys.enable, Some(attributed_scheme), &mut rejected);
            continue;
        };
        let host = if enabled { dict.text(keys.host) } else { None };
        let Some(host) = host else {
            // Only when the scheme is on: an unreadable host under a scheme the user turned
            // off is a key nobody was going to read. Recording it also keeps the scheme out
            // of `per_scheme`, where `Disabled` would answer Direct for a proxy the user
            // switched on. An enabled scheme whose host key is absent or blank does take
            // `Disabled`: nothing was dropped, because there was nothing to route to.
            if enabled
                && record_unreadable_text(dict, keys.host, Some(attributed_scheme), &mut rejected)
            {
                continue;
            }
            per_scheme.insert(keys.scheme, ProxyEntry::Disabled);
            continue;
        };

        let mut endpoint = match ProxyEndpoint::parse(host, keys.default_port) {
            Ok(endpoint) => endpoint,
            // The `WARN` compiles to nothing without the `tracing` feature, which is what
            // leaves `err` unused there; the `rejected` entry below is what carries the
            // drop either way.
            #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
            Err(err) => {
                crate::trace::warning!(
                    error = %crate::trace::SafeError(&err),
                    "skipping an unparseable <Scheme>Proxy host"
                );
                rejected.push(
                    RejectedValue::new(
                        RejectionKind::InvalidProxyEndpoint,
                        RejectionSource::SystemConfiguration(keys.host.to_owned()),
                        host,
                    )
                    .for_scheme(Some(attributed_scheme)),
                );
                continue;
            }
        };
        if let Some(port) = dict.port(keys.port) {
            endpoint.port = port;
        } else if let Some(value) = dict.port_is_unusable(keys.port) {
            // Out of `per_scheme`, so the scheme default is not dialled in place of a port
            // the user filled in. The host survives in the record, which is what lets
            // `resolve` name the scheme instead of answering Direct for it.
            crate::trace::warning!(
                key = keys.port,
                "skipping a scheme whose port is not a port"
            );
            rejected.push(
                RejectedValue::new(
                    RejectionKind::InvalidProxyEndpoint,
                    RejectionSource::SystemConfiguration(keys.port.to_owned()),
                    &value,
                )
                .for_scheme(Some(attributed_scheme)),
            );
            continue;
        }
        if let Some(hint) = keys.hint
            && endpoint.scheme_hint.is_none()
        {
            endpoint = endpoint.with_scheme_hint(hint);
        }
        if let Some(user) = dict.text(keys.user) {
            endpoint = endpoint.with_auth(ProxyAuth::from_username(user));
        } else if dict.text_is_unusable(keys.user).is_some() {
            // Not even the log line carries the value: a username is the half of a
            // credential this crate does hold.
            warn_unusable_username(keys.user);
        }
        per_scheme.insert(keys.scheme, ProxyEntry::Use(endpoint));
        any_enabled = true;
    }

    record_unroutable_schemes(dict, &mut rejected);

    apply_socks_fallback(&mut per_scheme);

    // A `Disabled` entry answers Direct, so it may only stand where nothing was lost that
    // would have covered the scheme instead. Every drop this reader attributes to
    // `Scheme::All` is one that would have: an unreadable SOCKS entry costs the fallback
    // above, which *overwrites* `Disabled` rather than filling around it, and an unreadable
    // PAC or WPAD switch costs a mode that replaces the manual answer whole. Dropping the
    // entry is what lets `resolve` reach the record in `rejected` instead of a `Disabled`
    // pre-empting it — GNOME's `socks_unusable` guard is the same rule one backend over.
    //
    // This is here rather than in `ProxyMode::with_rejected` because the overwrite is what
    // makes it true, and only this reader does one: Windows' `apply_socks_catch_all` fills
    // with `or_insert_with`, so a dropped `socks=` there never covered a scheme holding an
    // explicit `http=`, and an env `all_proxy=` never covered one holding `http_proxy=`.
    if rejected
        .iter()
        .any(|value| value.affected_scheme() == Some(Scheme::All))
    {
        per_scheme.retain(|_, entry| !entry.is_disabled());
    }

    // Reject-only stays `Manual` so the drops are not lost — `parse::windows_manual`'s
    // doc is where that rule is written. Only that half is shared: the emptiness test here
    // is "nothing was switched on", not "`per_scheme` is empty", so a dict holding nothing
    // but `Disabled` entries collapses instead of answering Direct the long way round.
    if !any_enabled && rejected.is_empty() {
        return Ok(ProxyMode::Direct);
    }
    Ok(ProxyMode::manual(per_scheme, bypass_from_dict(dict)).with_rejected(rejected))
}

// Let an enabled `SOCKSEnable` stand in for every scheme that has no proxy of its own.
fn apply_socks_fallback(per_scheme: &mut HashMap<Scheme, ProxyEntry>) {
    let Some(ProxyEntry::Use(endpoint)) = per_scheme.get(&Scheme::Socks) else {
        return;
    };
    let endpoint = endpoint.clone();
    for scheme in [Scheme::Http, Scheme::Https, Scheme::Ftp, Scheme::All] {
        if matches!(per_scheme.get(&scheme), Some(ProxyEntry::Use(_))) {
            continue;
        }
        per_scheme.insert(scheme, ProxyEntry::Use(endpoint.clone()));
    }
}

// A proxy family with no [`Scheme`] cannot be routed through, so there is no endpoint to
// build; an enabled one that names a host is recorded instead — the same call
// [`crate::parse::proxy_server`] makes for a Windows `gopher=` entry.
fn record_unroutable_schemes(dict: &ProxyDict, rejected: &mut Vec<RejectedValue>) {
    for keys in &UNROUTABLE {
        if dict.flag(keys.enable) != Some(true) {
            // Called here too, and not only in the loop over [`SCHEMES`], so that an
            // unreadable flag is recorded on whichever family carries it. Splitting that
            // would leave the two loops disagreeing about what an unreadable flag is worth,
            // which is the shape of defect this record exists to prevent.
            record_unreadable_flag(dict, keys.enable, None, rejected);
            continue;
        }
        let Some(host) = dict.text(keys.host) else {
            record_unreadable_text(dict, keys.host, None, rejected);
            continue;
        };
        crate::trace::warning!(
            key = keys.enable,
            "skipping an enabled proxy whose scheme this crate has no variant for"
        );
        rejected.push(RejectedValue::new(
            RejectionKind::UnknownProxyScheme,
            RejectionSource::SystemConfiguration(keys.host.to_owned()),
            host,
        ));
    }
}

// Both of these answer whether they recorded anything, and both take the request scheme
// the drop takes an answer away from. Attributing it is what makes `resolve` report
// [`Error::ProxyEntryUnusable`] instead of answering Direct for a scheme whose setting was
// dropped, so the question each caller answers is *which requests lost an answer*, not
// which key was read:
//
// - one scheme's `<Scheme>Enable` / `<Scheme>Proxy` — that scheme, except SOCKS, which is
//   also every unclaimed scheme's fallback and so is attributed to [`Scheme::All`]
//   (`attributed_scheme`);
// - the PAC and WPAD switches — [`Scheme::All`]. A PAC the user switched on decides every
//   request, so losing it loses every answer, and `All` is the slot every lookup falls
//   back to, which is where `ProxyMode::with_rejected` files a record attributed to it;
// - the [`UNROUTABLE`] families — `None`. Gopher and the rest have no [`Scheme`] variant,
//   so no request was ever going to be routed by them and none lost an answer.
fn record_unreadable_flag(
    dict: &ProxyDict,
    key: &str,
    scheme: Option<Scheme>,
    rejected: &mut Vec<RejectedValue>,
) -> bool {
    let Some(value) = dict.flag_is_unusable(key) else {
        return false;
    };
    crate::trace::warning!(key, "skipping a setting whose enable flag is not a flag");
    rejected.push(
        RejectedValue::new(
            RejectionKind::UnsupportedMapping,
            RejectionSource::SystemConfiguration(key.to_owned()),
            &value,
        )
        .for_scheme(scheme),
    );
    true
}

fn record_unreadable_text(
    dict: &ProxyDict,
    key: &str,
    scheme: Option<Scheme>,
    rejected: &mut Vec<RejectedValue>,
) -> bool {
    let Some(value) = dict.text_is_unusable(key) else {
        return false;
    };
    crate::trace::warning!(key, "skipping a key whose value is not a string");
    rejected.push(
        RejectedValue::new(
            RejectionKind::UnsupportedMapping,
            RejectionSource::SystemConfiguration(key.to_owned()),
            &value,
        )
        .for_scheme(scheme),
    );
    true
}

#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn warn_unusable_username(key: &str) {
    crate::trace::warning!(key, "ignoring a username key that is not a string");
}

#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn warn_unusable_exceptions_list(key: &str) {
    crate::trace::warning!(key, "ignoring a bypass list that is not an array");
}

// Build the bypass rules from `ExceptionsList` + `ExcludeSimpleHostnames`.
//
// Both drops here are recorded on the rules rather than on the mode: a bypass key names no
// scheme, so `resolve` has nothing to refuse for it, but a reader asking why a host it
// excluded is being proxied has [`BypassRules::rejected`] to look at either way.
fn bypass_from_dict(dict: &ProxyDict) -> BypassRules {
    let mut rules = BypassRules::new();
    if let Some(value) = dict.list_is_unusable(EXCEPTIONS_LIST) {
        warn_unusable_exceptions_list(EXCEPTIONS_LIST);
        rules.rejected.push(RejectedValue::new(
            RejectionKind::UnsupportedMapping,
            RejectionSource::SystemConfiguration(EXCEPTIONS_LIST.to_owned()),
            &value,
        ));
    }
    // `MacOs` because CFNetwork was asked. `Suffix` is the majority reading, and taking it
    // here would rest on no evidence but that majority: the only evidence within reach was
    // Chromium's macOS reader, which is a reimplementation and not the OS.
    // `tests/mac_exceptions_list.rs` put the rows to `CFNetworkCopyProxiesForURL` on a macOS
    // runner instead — it takes the settings dictionary as an argument, so no store, no
    // write and no network — and three of them came back against the suffix reading, every
    // one of them fail-open. The dialect carries which three.
    //
    // `expand_abbreviated_cidr` stays in front of it: the same runs confirmed `169.254/16`
    // covers `169.254.1.1` and not `169.0.0.254`, which is the padding this does and not
    // the URL-standard reading Chromium applies to the same text.
    let (entries, unreadable) = dict.list(EXCEPTIONS_LIST).unwrap_or((&[], 0));
    for entry in entries {
        rules.push_entry_in(&expand_abbreviated_cidr(entry), BypassDialect::MacOs);
    }
    rules.dedup_patterns();
    // A member the Core Foundation reader could not carry across is one bypass rule the user
    // configured and will not get — the same direction as the unusable-list case above, and
    // recorded the same way rather than left to a warning, because the missing rules are
    // exactly what a caller cannot reconstruct from `patterns`. One record per member: the
    // number lost is the part that carries the information, since nothing of the members
    // themselves may be quoted. `dedup_patterns` above does not reach `rejected`, so the
    // repeats survive.
    for _ in 0..unreadable {
        rules.rejected.push(RejectedValue::new(
            RejectionKind::UnsupportedMapping,
            RejectionSource::SystemConfiguration(EXCEPTIONS_LIST.to_owned()),
            UNREADABLE,
        ));
    }
    if dict.flag(EXCLUDE_SIMPLE_HOSTNAMES) == Some(true) {
        rules.exclude_simple_hostnames = true;
    } else if let Some(value) = dict.flag_is_unusable(EXCLUDE_SIMPLE_HOSTNAMES) {
        warn_unusable_exclude_simple_hostnames(EXCLUDE_SIMPLE_HOSTNAMES);
        rules.rejected.push(RejectedValue::new(
            RejectionKind::UnsupportedMapping,
            RejectionSource::SystemConfiguration(EXCLUDE_SIMPLE_HOSTNAMES.to_owned()),
            &value,
        ));
    }
    rules
}

// Losing this rule sends traffic *through* the proxy rather than past it — the opposite
// direction from every other drop here, and still not one the endpoint fails to survive.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn warn_unusable_exclude_simple_hostnames(key: &str) {
    crate::trace::warning!(key, "ignoring a simple-hostname switch that is not a flag");
}

// Pad an abbreviated IPv4 CIDR to its full four octets: macOS ships `169.254/16` in the
// default `ExceptionsList`, a spelling `IpNet` rejects outright. Chromium accepts it and
// means something else — `ParseCIDRBlock` uses the URL standard's IPv4 parser, which
// spreads a short form's last component over the trailing bytes, so `169.254/16` is
// `169.0.0.254/16` there rather than the link-local range Apple wrote.
//
// Read whole rather than trimmed, because `BypassDialect::MacOs` does not trim either and
// this runs in front of it: padding a short CIDR here would hand `parse_in` an entry the
// machine never had, and the padded one is live where ` 169.254/16` is dead. The leading
// space fails the all-digits test on the first octet, so the entry goes through untouched
// and meets the whitespace guard, which is where every other dead macOS spelling lands.
fn expand_abbreviated_cidr(entry: &str) -> Cow<'_, str> {
    let Some((address, prefix)) = entry.split_once('/') else {
        return Cow::Borrowed(entry);
    };
    if address.contains(':') || prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return Cow::Borrowed(entry);
    }
    let octets: Vec<&str> = address.split('.').collect();
    if octets.len() >= 4
        || !octets
            .iter()
            .all(|octet| !octet.is_empty() && octet.bytes().all(|b| b.is_ascii_digit()))
    {
        return Cow::Borrowed(entry);
    }
    let mut padded = String::from(address);
    for _ in octets.len()..4 {
        padded.push_str(".0");
    }
    Cow::Owned(format!("{padded}/{prefix}"))
}

// Resolve an independently read `Setup:` and `State:` scope of the global proxies key into
// one [`ProxyConfig`], `State:` first. Apple documents no precedence between the two — the
// discussion section of `SCDynamicStoreCopyProxies` is a key/type table — and the call
// itself reads only `SCDynamicStoreKeyCreateProxies`, the global proxies entity in the
// `State:` domain (configd `SystemConfiguration.fproj/SCProxies.c`), so it never sees
// `Setup:` at all. Every reference goes through that one call (Chromium
// `proxy_config_service_mac.cc`, libproxy `config-osx.c`), which is what makes `State:` the
// view the rest of the machine acts on. It is also already the *output* of a resolution
// that saw `Setup:`: configd's IPMonitor builds it from the primary service, and the
// function that takes a service's proxies entity — `get_proxies_changes`, registered
// against `kSCEntNetProxies` in `Plugins/IPMonitor/ip_plugin.c` — is handed that service's
// `State:` and `Setup:` dictionaries both. Which of the two wins *there* is left unstated
// because nothing below depends on it: what makes `State:` the effective scope here is
// that every reference reads it and none reads `Setup:`. `Setup:` stays in `sources` — a
// configured-but-not-yet-in-effect setting is worth showing — and it does not win against
// `State:`. With no `State:` scope at all, though, there is nothing for it to lose to and
// it becomes the effective mode: reporting `Direct` while the machine holds a configured
// proxy would be the worse answer.
//
// That asymmetry is also what decides a `Setup:` scope the reader could not interpret at
// all, which is why `setup` arrives as a `Result`: a failure there costs the report and
// not the answer, so with a `State:` scope to fall back on it is warned about and the
// scope is dropped from `sources`. `State:` is unaffected — it is the only scope
// `effective` was ever built from when it exists — so nothing observable changes but the
// entry that could not be built. With no `State:` scope the failure is the whole read's,
// exactly as the paragraph above makes `Setup:` the effective mode there.
//
// No error kind is exempt, and that is the opposite of [`group_policy_source`]'s rule on
// Windows, which softens only [`Error::Io`]. The two differ because the precedence does:
// group policy is the scope that *overrides*, so softening a value it handed over and the
// crate refused would reinstate the per-user proxy the policy exists to replace. `Setup:`
// overrides nothing.
pub(crate) fn merge_setup_and_state(
    setup: Result<Option<ProxyMode>, Error>,
    state: Option<ProxyMode>,
) -> Result<ProxyConfig, Error> {
    let mut fallbacks = Vec::new();
    let setup = match setup {
        Ok(setup) => setup,
        #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
        Err(error) if state.is_some() => {
            crate::trace::warning!(
                error = %crate::trace::SafeError(&error),
                "the Setup: proxies scope could not be read; reporting the State: scope \
                 alone, which is the one in effect"
            );
            // What the paragraph above calls costing the report and not the answer. The
            // cost is now itemised: without this, a scope that failed to read and a
            // machine with no `Setup:` scope at all produce the same `sources`.
            fallbacks.push(ProxyConfigSource::SystemConfigurationSetup);
            None
        }
        Err(error) => return Err(error),
    };

    let mut sources = Vec::new();
    if let Some(mode) = &state {
        sources.push((ProxyConfigSource::SystemConfigurationState, mode.clone()));
    }
    if let Some(mode) = &setup {
        sources.push((ProxyConfigSource::SystemConfigurationSetup, mode.clone()));
    }
    Ok(ProxyConfig::from_ordered_sources(sources).with_fallbacks(fallbacks))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a dictionary from `(key, value)` literals, `Text` for `&str` and `Number`
    // for integers.
    macro_rules! dict {
        ($($key:literal => $value:expr),* $(,)?) => {{
            #[allow(unused_mut)]
            let mut dict = ProxyDict::new();
            $(dict.insert($key, $value.into_dict_value());)*
            dict
        }};
    }

    trait IntoDictValue {
        fn into_dict_value(self) -> DictValue;
    }
    impl IntoDictValue for &str {
        fn into_dict_value(self) -> DictValue {
            DictValue::Text(self.to_owned())
        }
    }
    impl IntoDictValue for i64 {
        fn into_dict_value(self) -> DictValue {
            DictValue::Number(self)
        }
    }
    impl IntoDictValue for &[&str] {
        fn into_dict_value(self) -> DictValue {
            DictValue::List {
                items: self.iter().map(|s| (*s).to_owned()).collect(),
                unreadable: 0,
            }
        }
    }

    // The dictionary carries every key the system had, including ones this crate has no
    // schema for. `Debug` must not print such a value, and must reduce the two
    // known-but-sensitive keys the same way [`ProxyMode`]'s own `Debug` does.
    #[test]
    fn debug_never_prints_an_unvetted_value() {
        const SECRET: &str = "hunter2";

        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "HTTPPort" => 8080i64,
            "HTTPUser" => "alice",
            // A key Apple has never shipped, which is the point: `SCSchemaDefinitions.h`
            // has no `Proxies…Password` at any version, and the six `*User` keys it does
            // have all arrived in macOS 15.0. So this stands in for *any* key outside
            // this module's schema, not for a real one it forgot — and an unvetted key is
            // exactly what must not reach `Debug`.
            "HTTPProxyPassword" => SECRET,
            "SomeFutureList" => &[SECRET][..],
            // An unread key can arrive as a number too — `to_proxy_dict` copies whatever
            // Core Foundation held. `GopherEnable` / `GopherProxy` are read, for the
            // record they owe; the port under an unroutable family is read by nothing.
            "GopherPort" => 7070i64,
            "ProxyAutoConfigURLString" => "http://alice:hunter2@wpad.corp/proxy.pac",
            "ProxyAutoConfigJavaScript" => "function FindProxyForURL(u, h) { return 'DIRECT'; }",
        };

        let rendered = format!("{dict:?}");
        assert!(
            !rendered.contains(SECRET),
            "an unread key's value reached Debug: {rendered}"
        );
        assert!(
            !rendered.contains("7070"),
            "an unread key's number reached Debug: {rendered}"
        );
        // What is vetted is still printed, or the dump would be useless.
        assert!(rendered.contains("proxy.corp"), "{rendered}");
        assert!(rendered.contains("alice"), "{rendered}");
        // The two known-but-sensitive keys are reduced, not dropped.
        assert!(rendered.contains("wpad.corp"), "{rendered}");
        assert!(rendered.contains("fnv1a"), "{rendered}");
        assert!(
            !rendered.contains("FindProxyForURL"),
            "the inline PAC body reached Debug: {rendered}"
        );
    }

    // The reduction above must key off the name, not off the value's type. `to_dict_value`
    // decides the `DictValue` from the Core Foundation runtime type alone, so nothing stops
    // either sensitive key from arriving as a list or a number — and the reductions that
    // cover every *other* key are guarded by `!is_known_key`, which is false for these two.
    // That leaves exactly this combination with no arm of its own.
    #[test]
    fn a_sensitive_key_is_reduced_even_when_its_value_is_the_wrong_type() {
        const SECRET: &str = "hunter2";
        // One carrier for both keys: userinfo is what the URL key's own reduction removes,
        // and it is equally a secret inside a script body.
        let carrier = format!("http://alice:{SECRET}@wpad.corp/proxy.pac");

        for key in [AUTO_CONFIG_JAVASCRIPT, AUTO_CONFIG_URL] {
            let mut dict = ProxyDict::new();
            dict.insert(
                key,
                DictValue::List {
                    items: vec![carrier.clone()],
                    unreadable: 0,
                },
            );
            let rendered = format!("{dict:?}");
            assert!(
                !rendered.contains(SECRET),
                "{key} as a list reached Debug: {rendered}"
            );
            assert!(rendered.contains(key), "the key itself is not the secret");

            let mut dict = ProxyDict::new();
            dict.insert(key, DictValue::Number(7070));
            let rendered = format!("{dict:?}");
            assert!(!rendered.contains("7070"), "{rendered}");
        }

        // The controls: the `Text` reductions still run — a URL that really did arrive as
        // one keeps its host and path, which is the whole point of reducing rather than
        // dropping — and an unread key with a list still reports its length.
        let mut dict = ProxyDict::new();
        dict.insert(AUTO_CONFIG_URL, DictValue::Text(carrier.clone()));
        dict.insert(
            "SomeFutureList",
            DictValue::List {
                items: vec![carrier.clone()],
                unreadable: 0,
            },
        );
        let rendered = format!("{dict:?}");
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(rendered.contains("wpad.corp/proxy.pac"), "{rendered}");
        assert!(rendered.contains("1 strings, key not read"), "{rendered}");
    }

    #[test]
    fn an_empty_dictionary_is_direct() {
        assert_eq!(
            mode_from_dict(&ProxyDict::new()).unwrap(),
            ProxyMode::Direct
        );
    }

    #[test]
    fn all_enable_keys_zero_is_direct() {
        let dict = dict! {
            "HTTPEnable" => 0i64,
            "HTTPSEnable" => 0i64,
            "FTPEnable" => 0i64,
            "SOCKSEnable" => 0i64,
            "ProxyAutoConfigEnable" => 0i64,
            "ProxyAutoDiscoveryEnable" => 0i64,
        };
        assert_eq!(mode_from_dict(&dict).unwrap(), ProxyMode::Direct);
    }

    // macOS recognises a Gopher and an RTSP proxy; this crate has no [`Scheme`] for
    // either, so nothing can be routed through one and `endpoint_for` must stay empty.
    // Dropping it without a trace is the other half — the fail-open `parse::proxy_server`
    // refuses on Windows for `gopher=proxy:80`, so an enabled family with a host has to
    // leave a record behind here too.
    #[test]
    fn an_enabled_proxy_this_crate_cannot_route_through_is_still_recorded() {
        let dict = dict! {
            "GopherEnable" => 1i64,
            "GopherProxy" => "gopher.corp",
            "GopherPort" => 7070i64,
        };
        let mode = mode_from_dict(&dict).unwrap();

        let rejected = mode
            .rejected()
            .expect("an enabled Gopher proxy left no record");
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0].kind(), RejectionKind::UnknownProxyScheme);
        assert_eq!(
            *rejected[0].source(),
            RejectionSource::SystemConfiguration("GopherProxy".to_owned())
        );
        assert_eq!(rejected[0].redacted_input(), "gopher.corp");
        for scheme in Scheme::ALL {
            assert!(mode.endpoint_for(scheme).is_none(), "{scheme:?}");
        }
    }

    // What the record above is allowed to *cost*, which is the half the test above does not
    // reach: `affected_scheme` is `None` for all three of [`record_unroutable_schemes`]'s
    // pushes, and this test is the only thing holding that against `Scheme::All` — the value
    // every other unreadable switch in this file takes.
    //
    // `All` is the widest thing a record can say. `ProxyMode::with_rejected` files an `All`
    // drop as a [`ProxyEntry::Unusable`] in the slot every unmatched lookup falls back to, so
    // a Mac whose only oddity is a Gopher proxy would answer [`Error::ProxyEntryUnusable`]
    // for every request it has — including `http://`, which no Gopher key was ever going to
    // route. Gopher and RTSP have no [`Scheme`] variant at all, so nothing was routed by
    // them and nothing lost an answer; the record exists to say a key was seen, not to
    // refuse a request. `resolve`'s answer is the assertion that says so — a record that did
    // refuse would surface here as `ProxyEntryUnusable`; the attribution is restated as well only
    // because that block compiles away without the `resolve` feature, and a build that
    // cannot reach the cost should still hold the field it comes from.
    #[test]
    fn a_family_this_crate_cannot_route_through_takes_no_answer_away() {
        let mut unreadable_host = dict! { "GopherEnable" => 1i64 };
        unreadable_host.insert("GopherProxy", DictValue::Unreadable);

        for dict in [
            dict! { "GopherEnable" => 1i64, "GopherProxy" => "gopher.corp" },
            // Not a flag this crate can read, so the family is neither on nor off.
            ProxyDict::from_iter([("GopherEnable".to_owned(), DictValue::Unreadable)]),
            unreadable_host,
        ] {
            let mode = mode_from_dict(&dict).unwrap();
            let rejected = mode
                .rejected()
                .unwrap_or_else(|| panic!("{dict:?} left no record: {mode:?}"))
                .to_vec();
            assert_eq!(rejected.len(), 1, "{rejected:?}");
            assert_eq!(rejected[0].affected_scheme(), None, "{rejected:?}");

            #[cfg(feature = "resolve")]
            {
                let config = crate::ProxyConfig::new(mode, Vec::new());
                let url = url::Url::parse("http://intranet.corp/x").unwrap();
                assert_eq!(
                    crate::resolve(&config, &url).unwrap(),
                    vec![crate::ProxyStep::Direct],
                    "{rejected:?}"
                );
            }
        }
    }

    // The same argument as the test above, one key to the left. An `HTTPEnable` holding
    // text that is not a number is a proxy the user switched on in a spelling this crate
    // cannot read, and [`ProxyDict::flag`] folds it into the same `None` as a key that was
    // never set — so the scheme is skipped and `Direct` comes back with nothing to show for
    // it. The sibling reader refuses that fold: [`ProxyDict::port_is_unusable`] tells
    // "absent" from "present and unreadable" precisely so the second can be recorded.
    #[test]
    fn an_enable_flag_this_crate_cannot_read_is_still_recorded() {
        for value in ["yes", "on"] {
            let dict = dict! {
                "HTTPEnable" => value,
                "HTTPProxy" => "proxy.corp",
                "HTTPPort" => 8080i64,
            };
            let mode = mode_from_dict(&dict).unwrap();

            let rejected = mode
                .rejected()
                .unwrap_or_else(|| panic!("HTTPEnable = {value:?} left no record"));
            assert_eq!(rejected.len(), 1, "{rejected:?}");
            assert_eq!(rejected[0].kind(), RejectionKind::UnsupportedMapping);
            assert_eq!(
                *rejected[0].source(),
                RejectionSource::SystemConfiguration("HTTPEnable".to_owned())
            );
            assert_eq!(rejected[0].redacted_input(), value);
            assert_eq!(rejected[0].affected_scheme(), Some(Scheme::Http));
            // Unreadable is not "on": nothing is routed through a flag nobody could read.
            assert!(mode.endpoint_for(Scheme::Http).is_none(), "{mode:?}");
        }

        // A list under a flag key reaches the same `None` by the other arm.
        let listed = dict! {
            "HTTPEnable" => &["1"][..],
            "HTTPProxy" => "proxy.corp",
        };
        assert!(
            mode_from_dict(&listed).unwrap().rejected().is_some(),
            "a list-valued HTTPEnable left no record"
        );
    }

    // The same argument as the test above, one key to the right. `HTTPEnable` is readable
    // and says yes; `HTTPProxy` holds something [`ProxyDict::text`] cannot read, and that
    // `None` is the same one a key that was never set produces. What separates them is the
    // record: an unreadable host puts the record itself in `per_scheme`, where the
    // `Disabled` an absent one earns would answer `Direct` for a proxy the user switched on.
    #[test]
    fn an_enabled_schemes_unreadable_host_is_still_recorded() {
        let numeric = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => 8080i64,
        };
        let mode = mode_from_dict(&numeric).unwrap();
        let rejected = mode.rejected().expect("a numeric HTTPProxy left no record");
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0].kind(), RejectionKind::UnsupportedMapping);
        assert_eq!(
            *rejected[0].source(),
            RejectionSource::SystemConfiguration("HTTPProxy".to_owned())
        );
        assert_eq!(rejected[0].redacted_input(), "8080");
        assert_eq!(rejected[0].affected_scheme(), Some(Scheme::Http));
        // Unreadable is not a host: nothing is routed through a value nobody could read.
        assert!(mode.endpoint_for(Scheme::Http).is_none(), "{mode:?}");
        // And not `Disabled` either, which `resolve` reads as a deliberate "no proxy here":
        // the entry *is* the record, which is how a lookup reaches it at all.
        let entry = mode
            .entry_for(Scheme::Http)
            .expect("an unreadable host left the slot empty");
        assert!(!entry.is_disabled(), "{entry:?}");
        assert_eq!(entry.rejected(), Some(&rejected[0]), "{entry:?}");

        // A list under a host key reaches the same `None` by the other arm, and is reduced
        // to its shape rather than carried — an array under `HTTPProxy` can name hosts.
        let listed = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => &["proxy.corp", "other.corp"][..],
        };
        let mode = mode_from_dict(&listed).unwrap();
        let rejected = mode.rejected().expect("a list HTTPProxy left no record");
        assert_eq!(rejected[0].redacted_input(), "<2 strings>");
    }

    // An enabled PAC setting whose script key holds a non-string is the same fold again,
    // and falling through to the manual schemes hides it: with nothing else configured the
    // answer is `Direct`, which is what the user turned PAC on to avoid.
    #[test]
    fn an_enabled_pac_url_that_is_not_a_string_is_still_recorded() {
        let dict = dict! {
            "ProxyAutoConfigEnable" => 1i64,
            "ProxyAutoConfigURLString" => 7i64,
        };
        let mode = mode_from_dict(&dict).unwrap();
        let rejected = mode.rejected().expect("a numeric PAC URL left no record");
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(
            *rejected[0].source(),
            RejectionSource::SystemConfiguration("ProxyAutoConfigURLString".to_owned())
        );
        assert_ne!(mode, ProxyMode::Direct, "{mode:?}");
        // Not `ProxyMode::Direct` is the weaker half: `resolve` reaches `Direct` from a
        // `Manual` with nothing in it just as well, and only the record's scheme stops it.
        #[cfg(feature = "resolve")]
        {
            let config = crate::ProxyConfig::new(mode, Vec::new());
            let url = url::Url::parse("http://intranet.corp/x").unwrap();
            let err = crate::resolve(&config, &url).unwrap_err();
            assert!(
                matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                    if *scheme == Scheme::All),
                "{err:?}"
            );
        }
    }

    // The two `Proxy*Enable` keys kept taking the fold the scheme enables stopped taking:
    // `== Some(true)` reads an unreadable value as "off", so a machine with WPAD or PAC
    // switched on came back `Direct` with nothing to show for it.
    #[test]
    fn an_unreadable_auto_enable_flag_is_recorded_rather_than_read_as_off() {
        for key in [AUTO_DISCOVERY_ENABLE, AUTO_CONFIG_ENABLE] {
            let dict = ProxyDict::from_iter([(key.to_owned(), DictValue::Text("yes".to_owned()))]);
            let mode = mode_from_dict(&dict).unwrap();
            let rejected = mode
                .rejected()
                .unwrap_or_else(|| panic!("an unreadable {key} left no record: {mode:?}"));
            assert_eq!(rejected.len(), 1, "{rejected:?}");
            assert_eq!(
                *rejected[0].source(),
                RejectionSource::SystemConfiguration(key.to_owned())
            );
            assert_eq!(rejected[0].redacted_input(), "yes");
            // `All`, not unattributed: a PAC or WPAD switch decides every request, so the
            // widest drop of the three would otherwise be the only one `resolve` could not
            // find — see the test below for what that costs.
            assert_eq!(rejected[0].affected_scheme(), Some(Scheme::All), "{key}");
        }
    }

    // Everything the Core Foundation boundary loses arrives as one value, and the point of
    // it arriving at all is that each reader then answers from the *key*. `to_proxy_dict`
    // must not drop it: dropped, an `HTTPEnable` the user switched on is in the same state as
    // a machine where HTTP was never configured — with a `trace::warning!` as the only trace
    // of it, and that macro compiles to `()` on every build without the `tracing` feature,
    // which is every default one.
    //
    // The recorded token is pinned too, and it is the same for all of them: a value this
    // crate could not read is one it must not quote, so there is nothing to record but the
    // fact that something was there.
    #[test]
    fn a_value_lost_at_the_core_foundation_boundary_is_recorded_under_every_reader() {
        for (key, kind, scheme) in [
            // Through `flag_is_unusable`.
            (
                "HTTPEnable",
                RejectionKind::UnsupportedMapping,
                Scheme::Http,
            ),
            // Through `text_is_unusable`.
            ("HTTPProxy", RejectionKind::UnsupportedMapping, Scheme::Http),
            // Through `port_is_unusable`, which the base dictionary below is what reaches:
            // the scheme has to be switched on and addressed before its port is read.
            (
                "HTTPPort",
                RejectionKind::InvalidProxyEndpoint,
                Scheme::Http,
            ),
            // `flag_is_unusable` again, one key over, for the scheme it costs rather than
            // the reader it goes through: a PAC switch decides every request.
            (
                AUTO_CONFIG_ENABLE,
                RejectionKind::UnsupportedMapping,
                Scheme::All,
            ),
        ] {
            let mut dict = dict! { "HTTPEnable" => 1, "HTTPProxy" => "proxy.corp" };
            dict.insert(key, DictValue::Unreadable);

            let mode = mode_from_dict(&dict).unwrap();
            let rejected = mode
                .rejected()
                .unwrap_or_else(|| panic!("an unreadable {key} left no record: {mode:?}"));
            assert_eq!(rejected.len(), 1, "{key}: {rejected:?}");
            assert_eq!(
                *rejected[0].source(),
                RejectionSource::SystemConfiguration(key.to_owned())
            );
            assert_eq!(rejected[0].kind(), kind, "{key}");
            assert_eq!(rejected[0].affected_scheme(), Some(scheme), "{key}");
            assert_eq!(rejected[0].redacted_input(), UNREADABLE, "{key}");
        }

        // The fifth reader, `list_is_unusable`, files its record on the rules instead — a
        // bypass key names no scheme for `resolve` to refuse for. Paired with a working
        // proxy on purpose: with nothing switched on the answer is Direct, and an exception
        // list that excludes hosts from nothing has lost none of them.
        let mut dict = dict! { "HTTPEnable" => 1, "HTTPProxy" => "proxy.corp" };
        dict.insert(EXCEPTIONS_LIST, DictValue::Unreadable);
        let mode = mode_from_dict(&dict).unwrap();
        let rejected = &mode.bypass().expect("a manual mode carries rules").rejected;
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(
            *rejected[0].source(),
            RejectionSource::SystemConfiguration(EXCEPTIONS_LIST.to_owned())
        );
        assert_eq!(rejected[0].redacted_input(), UNREADABLE);
    }

    // A list that arrived shorter than it was sent. This is the drop the whole-list reader
    // above cannot see: the key holds an array, so `list_is_unusable` answers `None` and the
    // surviving entries parse into real patterns — the record has to come from the count.
    //
    // Held here rather than only on the macOS side because the count is carried across a
    // module boundary: `strings_in` produces it, this file is what has to turn it into
    // something a caller can read, and only the second half runs on every target. One record
    // per lost member, so that the caller learns how many rules went missing and not merely
    // that some did.
    #[test]
    fn every_element_a_bypass_list_lost_is_recorded_on_the_rules() {
        let mut dict = dict! { "HTTPEnable" => 1, "HTTPProxy" => "proxy.corp" };
        dict.insert(
            EXCEPTIONS_LIST,
            DictValue::List {
                items: vec!["*.internal".to_owned()],
                unreadable: 2,
            },
        );

        let mode = mode_from_dict(&dict).unwrap();
        let rules = mode.bypass().expect("a manual mode carries rules");
        // The control the count is measured against: what survived is still in force, so a
        // record that came from throwing the list away instead would fail here.
        assert!(
            rules.matches_authority("db.internal"),
            "the element that did arrive still excludes its host: {rules:?}"
        );
        assert_eq!(rules.rejected.len(), 2, "{:?}", rules.rejected);
        for record in &rules.rejected {
            assert_eq!(
                *record.source(),
                RejectionSource::SystemConfiguration(EXCEPTIONS_LIST.to_owned())
            );
            assert_eq!(record.kind(), RejectionKind::UnsupportedMapping);
            assert_eq!(record.redacted_input(), UNREADABLE);
        }
    }

    // The half of the record above that only `resolve` can show, and the reason the record
    // carries a scheme at all: an unreadable `Proxy*Enable` leaves nothing in `per_scheme`,
    // so without the attribution every request falls through to `Direct` — the answer the
    // user turned PAC or WPAD on to avoid.
    #[cfg(feature = "resolve")]
    #[test]
    fn an_unreadable_auto_enable_flag_is_reported_rather_than_resolved_direct() {
        for key in [AUTO_DISCOVERY_ENABLE, AUTO_CONFIG_ENABLE] {
            let dict = ProxyDict::from_iter([(key.to_owned(), DictValue::Text("yes".to_owned()))]);
            let config = crate::ProxyConfig::new(mode_from_dict(&dict).unwrap(), Vec::new());
            // Every request, not one scheme's: `ws` reaches the same record through
            // `websocket_entry`'s wider cover.
            for text in [
                "http://intranet.corp/x",
                "https://intranet.corp/x",
                "ws://h/",
            ] {
                let url = url::Url::parse(text).unwrap();
                let err = crate::resolve(&config, &url).unwrap_err();
                assert!(
                    matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                        if *scheme == Scheme::All),
                    "{key} {text}: {err:?}"
                );
            }
        }
    }

    // The scheme a helper records is the one it was called for, and every test that pins
    // that uses `HTTP*`, which cannot tell it from a hard-coded [`Scheme::Http`]. One
    // non-HTTP key through each helper closes that: the request that loses an answer must
    // be the one whose key was dropped, and no other.
    #[cfg(feature = "resolve")]
    #[test]
    fn a_drop_under_one_scheme_takes_no_other_schemes_answer() {
        let cases = [
            // Through `record_unreadable_flag`.
            (dict! { "HTTPSEnable" => "yes" }, Scheme::Https, "https"),
            // Through `record_unreadable_text`.
            (
                dict! { "FTPEnable" => 1i64, "FTPProxy" => 7i64 },
                Scheme::Ftp,
                "ftp",
            ),
        ];
        for (dict, scheme, dropped) in cases {
            let config = crate::ProxyConfig::new(mode_from_dict(&dict).unwrap(), Vec::new());
            let url = url::Url::parse(&format!("{dropped}://intranet.corp/x")).unwrap();
            let err = crate::resolve(&config, &url).unwrap_err();
            assert!(
                matches!(&err, crate::Error::ProxyEntryUnusable { scheme: got, .. }
                    if *got == scheme),
                "{dropped}: {err:?}"
            );

            let other = url::Url::parse("http://intranet.corp/x").unwrap();
            assert_eq!(
                crate::resolve(&config, &other).unwrap(),
                vec![crate::ProxyStep::Direct],
                "{dropped} took http's answer away too"
            );
        }
    }

    // The unroutable families get the record for the same reason they get one when the host
    // *is* readable: there is no endpoint to build either way, so the record is the whole
    // product.
    #[test]
    fn an_enabled_unroutable_scheme_with_an_unreadable_host_is_still_recorded() {
        let dict = dict! {
            "GopherEnable" => 1i64,
            "GopherProxy" => 70i64,
        };
        let mode = mode_from_dict(&dict).unwrap();
        let rejected = mode
            .rejected()
            .expect("a numeric GopherProxy left no record");
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0].kind(), RejectionKind::UnsupportedMapping);
        assert_eq!(rejected[0].redacted_input(), "70");
    }

    // The other side of the line: what the new reader must *not* call unusable. A blank
    // string is how "never filled in" reads at this layer, and a host key under a scheme
    // the user switched off is a key nobody was going to read.
    #[test]
    fn a_blank_or_switched_off_host_is_not_recorded() {
        let blank = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "   ",
        };
        assert_eq!(mode_from_dict(&blank).unwrap(), ProxyMode::Direct);

        let switched_off = dict! {
            "HTTPEnable" => 0i64,
            "HTTPProxy" => 8080i64,
        };
        assert_eq!(mode_from_dict(&switched_off).unwrap(), ProxyMode::Direct);
    }

    // The collapse above names `parse::windows_manual` as the half it does *not* share, and
    // nothing pinned the difference — two reviews in a row read the two as one rule. The
    // routing answer is what may not drift; the mode is deliberately not the same value.
    #[test]
    fn a_switched_off_scheme_collapses_here_and_stays_manual_on_windows() {
        let dict = dict! {
            "HTTPEnable" => 0i64,
            "HTTPProxy" => "proxy.corp",
        };
        let mac = mode_from_dict(&dict).unwrap();
        let windows = crate::parse::windows_manual("http=", "");

        assert!(mac.is_direct(), "{mac:?}");
        assert!(!windows.is_direct(), "{windows:?}");
        assert_eq!(windows.entry_for(Scheme::Http), Some(&ProxyEntry::Disabled));

        // The half that needs the router. The mode assertions above are the point of the
        // test and hold without it, so only this block is gated — every sibling here does
        // the same, and the feature matrix builds four configurations with `resolve` off.
        #[cfg(feature = "resolve")]
        {
            let url = url::Url::parse("http://example.net/").unwrap();
            for (source, mode) in [
                (ProxyConfigSource::SystemConfigurationState, mac),
                (ProxyConfigSource::Registry, windows),
            ] {
                let config = ProxyConfig::from_source(source, mode);
                assert_eq!(
                    crate::resolve::resolve(&config, &url).unwrap(),
                    vec![crate::resolve::ProxyStep::Direct]
                );
            }
        }
    }

    // The record is about a value the reader could not make sense of. A flag key that is
    // simply absent, or one holding digits it can read, is nothing to report.
    #[test]
    fn a_flag_that_is_absent_or_readable_is_not_recorded() {
        let absent = dict! { "HTTPProxy" => "proxy.corp" };
        assert_eq!(mode_from_dict(&absent).unwrap(), ProxyMode::Direct);

        // The text arm this crate added on purpose: digits in a string are still a flag.
        let text_digits = dict! {
            "HTTPEnable" => "0",
            "HTTPProxy" => "proxy.corp",
        };
        assert_eq!(mode_from_dict(&text_digits).unwrap(), ProxyMode::Direct);
    }

    // The record is about a proxy that is actually on. A family left disabled, or enabled
    // with no host to go to, is nothing to report.
    #[test]
    fn an_unroutable_proxy_that_is_off_or_hostless_is_not_recorded() {
        let off = dict! {
            "RTSPEnable" => 0i64,
            "RTSPProxy" => "stream.corp",
        };
        assert_eq!(mode_from_dict(&off).unwrap(), ProxyMode::Direct);

        let hostless = dict! { "RTSPEnable" => 1i64 };
        assert_eq!(mode_from_dict(&hostless).unwrap(), ProxyMode::Direct);
    }

    #[test]
    fn http_enable_with_host_and_port_is_manual() {
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "HTTPPort" => 8080i64,
        };
        let mode = mode_from_dict(&dict).unwrap();
        let endpoint = mode.endpoint_for(Scheme::Http).expect("http endpoint");
        assert_eq!(endpoint.authority(), "proxy.corp:8080");
        assert_eq!(endpoint.scheme_hint, None);
        // No `All` entry, so an unconfigured scheme resolves to nothing.
        assert!(mode.endpoint_for(Scheme::Ftp).is_none());
    }

    #[test]
    fn a_missing_port_falls_back_to_the_scheme_default() {
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "HTTPSEnable" => 1i64,
            "HTTPSProxy" => "secure.corp",
            "FTPEnable" => 1i64,
            "FTPProxy" => "files.corp",
            "SOCKSEnable" => 1i64,
            "SOCKSProxy" => "socks.corp",
        };
        let mode = mode_from_dict(&dict).unwrap();
        // 80 for all three: every one of these families names an *HTTP* proxy, so 443/21
        // — the ports of the destination protocol — would dial the wrong service. See
        // the comments on `SCHEMES` for the two references that agree.
        assert_eq!(mode.endpoint_for(Scheme::Http).unwrap().port, 80);
        assert_eq!(mode.endpoint_for(Scheme::Https).unwrap().port, 80);
        assert_eq!(mode.endpoint_for(Scheme::Ftp).unwrap().port, 80);
        let socks = mode.endpoint_for(Scheme::Socks).unwrap();
        assert_eq!(socks.port, 1080);
        assert_eq!(socks.scheme_hint, Some(ProxyScheme::Socks5));
    }

    #[test]
    fn a_zero_port_is_treated_as_unset() {
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "HTTPPort" => 0i64,
        };
        let mode = mode_from_dict(&dict).unwrap();
        assert_eq!(mode.endpoint_for(Scheme::Http).unwrap().port, 80);
        // `0` is Apple's "never filled in" for `HTTPPort`, so it is not the unusable case.
        assert!(dict.port_is_unusable("HTTPPort").is_none());
    }

    // A port that cannot be a port drops the scheme and records the value, rather than
    // dialling the scheme default: `proxy.corp:80` is a service the user never named. The
    // other backends read the port out of the host string, where `split_host_port` refuses
    // it, so this is what makes the two spellings of one configuration agree. Chromium
    // truncates instead (`70000` → 4464) and this crate deliberately does not follow it.
    #[test]
    fn an_out_of_range_port_drops_the_scheme_and_is_recorded() {
        for value in [70000i64, -1i64] {
            let dict = dict! {
                "HTTPEnable" => 1i64,
                "HTTPProxy" => "proxy.corp",
                "HTTPPort" => value,
            };
            let mode = mode_from_dict(&dict).unwrap();
            assert!(
                matches!(mode.entry_for(Scheme::Http), Some(ProxyEntry::Unusable(_))),
                "{value}"
            );
            assert_eq!(
                dict.port_is_unusable("HTTPPort").as_deref(),
                Some(value.to_string().as_str()),
                "{value}"
            );

            let rejected = mode.rejected().expect("an unusable port left no record");
            assert_eq!(rejected.len(), 1, "{rejected:?}");
            assert_eq!(rejected[0].kind(), RejectionKind::InvalidProxyEndpoint);
            assert_eq!(
                *rejected[0].source(),
                RejectionSource::SystemConfiguration("HTTPPort".to_owned())
            );
            assert_eq!(rejected[0].affected_scheme(), Some(Scheme::Http), "{value}");
        }
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "HTTPPort" => "http",
        };
        assert!(matches!(
            mode_from_dict(&dict).unwrap().entry_for(Scheme::Http),
            Some(ProxyEntry::Unusable(_))
        ));
        assert_eq!(dict.port_is_unusable("HTTPPort").as_deref(), Some("http"));
    }

    // The half of the drop above that only `resolve` can show: the scheme leaves
    // `per_scheme`, and what the caller must not get back is `Direct` for a proxy the user
    // switched on. The macOS twin of `kioslaverc.rs`'s
    // `an_unexpanded_http_proxy_is_reported_rather_than_resolved_direct`.
    #[cfg(feature = "resolve")]
    #[test]
    fn an_unusable_port_under_an_enabled_scheme_is_reported_rather_than_resolved_direct() {
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "HTTPPort" => 70000i64,
        };
        let config = crate::ProxyConfig::new(mode_from_dict(&dict).unwrap(), Vec::new());
        let url = url::Url::parse("http://intranet.corp/x").unwrap();
        let err = crate::resolve(&config, &url).unwrap_err();
        assert!(
            matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                if *scheme == Scheme::Http),
            "{err:?}"
        );
    }

    #[test]
    fn a_disabled_scheme_is_recorded_and_suppresses_the_all_fallback() {
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "FTPEnable" => 0i64,
        };
        let mode = mode_from_dict(&dict).unwrap();
        assert!(
            mode.entry_for(Scheme::Ftp)
                .expect("ftp entry")
                .is_disabled()
        );
        assert!(mode.endpoint_for(Scheme::Ftp).is_none());
    }

    #[test]
    fn an_enabled_scheme_without_a_host_is_disabled() {
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "   ",
            "FTPEnable" => 1i64,
            "FTPProxy" => "files.corp",
        };
        let mode = mode_from_dict(&dict).unwrap();
        assert!(mode.entry_for(Scheme::Http).unwrap().is_disabled());
        assert!(mode.endpoint_for(Scheme::Ftp).is_some());
    }

    // The shape a real Mac stores when only the SOCKS box is ticked: the other three
    // keys stay behind as explicit zeros, so a fallback that filled only *absent*
    // entries would do nothing here.
    #[test]
    fn a_socks_only_dictionary_routes_every_scheme_through_socks() {
        let dict = dict! {
            "HTTPEnable" => 0i64,
            "HTTPSEnable" => 0i64,
            "FTPEnable" => 0i64,
            "SOCKSEnable" => 1i64,
            "SOCKSProxy" => "socks.corp",
            "SOCKSPort" => 1080i64,
        };
        let mode = mode_from_dict(&dict).unwrap();
        // `Scheme::All` is in the list because it is the slot `resolve` sends every
        // scheme this crate does not model to (its `_ => Scheme::All` arm), so
        // [`apply_socks_fallback`] fills it alongside the schemes that have a key of
        // their own.
        for scheme in [
            Scheme::Http,
            Scheme::Https,
            Scheme::Ftp,
            Scheme::Socks,
            Scheme::All,
        ] {
            let endpoint = mode
                .endpoint_for(scheme)
                .unwrap_or_else(|| panic!("{scheme:?} must fall back to SOCKS"));
            assert_eq!(endpoint.authority(), "socks.corp:1080");
            assert_eq!(endpoint.scheme_hint, Some(ProxyScheme::Socks5));
        }
    }

    #[test]
    fn an_explicit_socks_scheme_is_not_overwritten_by_the_default_hint() {
        let dict = dict! {
            "SOCKSEnable" => 1i64,
            "SOCKSProxy" => "socks4://socks.corp",
            "SOCKSPort" => 1080i64,
        };
        let mode = mode_from_dict(&dict).unwrap();
        let socks = mode.endpoint_for(Scheme::Socks).unwrap();
        assert_eq!(
            socks.scheme_hint,
            Some(ProxyScheme::Socks4),
            "an explicit scheme in SOCKSProxy must not be overwritten by the SOCKS5 default"
        );
    }

    #[test]
    fn a_scheme_with_its_own_proxy_is_not_overwritten_by_socks() {
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "HTTPPort" => 8080i64,
            "HTTPSEnable" => 0i64,
            "SOCKSEnable" => 1i64,
            "SOCKSProxy" => "socks.corp",
        };
        let mode = mode_from_dict(&dict).unwrap();
        assert_eq!(
            mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "proxy.corp:8080",
            "an explicit HTTP proxy outranks the SOCKS fallback"
        );
        assert_eq!(
            mode.endpoint_for(Scheme::Https).unwrap().authority(),
            "socks.corp:1080",
            "HTTPS has none of its own, so the fallback covers it"
        );
    }

    // An unusable `SOCKSProxy` must not smear a half-parsed endpoint over the other
    // schemes: the entry it leaves behind is `Disabled`, not `Use`.
    #[test]
    fn a_malformed_socks_host_does_not_become_the_fallback() {
        let dict = dict! {
            "HTTPEnable" => 0i64,
            "SOCKSEnable" => 1i64,
            "SOCKSProxy" => "http://[not-an-address/",
        };
        let mode = mode_from_dict(&dict).unwrap();
        assert!(mode.endpoint_for(Scheme::Http).is_none());
        assert!(mode.endpoint_for(Scheme::Socks).is_none());
        assert!(
            !mode.rejected().unwrap_or_default().is_empty(),
            "the drop still has to be recorded"
        );
    }

    // The half of the drop above that only `resolve` can show: SOCKS is also
    // `apply_socks_fallback`'s catch-all for every scheme with no proxy of its own, so an
    // unusable `SOCKSProxy` costs HTTP that fallback too — not just `socks://` itself. The
    // rejection must be attributed as widely as what it took away (`Scheme::All`), or a
    // request for a scheme SOCKS would have covered resolves silently to Direct instead of
    // reporting the drop.
    #[cfg(feature = "resolve")]
    #[test]
    fn an_unusable_socks_endpoint_is_reported_for_a_scheme_it_would_have_covered() {
        let dict = dict! {
            "SOCKSEnable" => 1i64,
            "SOCKSProxy" => "http://[not-an-address/",
        };
        let config = crate::ProxyConfig::new(mode_from_dict(&dict).unwrap(), Vec::new());
        let url = url::Url::parse("http://intranet.corp/x").unwrap();
        let err = crate::resolve(&config, &url).unwrap_err();
        assert!(
            matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                if *scheme == Scheme::All),
            "{err:?}"
        );
    }

    // The same drop against the dictionary a real Mac stores: the boxes the user left
    // unticked are present as explicit zeros, and each of them is a scheme
    // `apply_socks_fallback` would have overwritten had `SOCKSProxy` been readable. A
    // `Disabled` kept for one of those answers Direct before `resolve` ever reaches
    // `rejected`, so the drop above becomes invisible exactly where SOCKS was the only
    // proxy configured.
    #[cfg(feature = "resolve")]
    #[test]
    fn an_off_switch_does_not_answer_direct_for_a_drop_that_would_have_covered_it() {
        let dict = dict! {
            "HTTPEnable" => 0i64,
            "SOCKSEnable" => 1i64,
            "SOCKSProxy" => "http://[not-an-address/",
        };
        let config = crate::ProxyConfig::new(mode_from_dict(&dict).unwrap(), Vec::new());
        let url = url::Url::parse("http://intranet.corp/x").unwrap();
        let err = crate::resolve(&config, &url).unwrap_err();
        assert!(
            matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                if *scheme == Scheme::All),
            "{err:?}"
        );
    }

    #[test]
    fn ipv6_hosts_are_bracketed_back() {
        let dict = dict! {
            "SOCKSEnable" => 1i64,
            "SOCKSProxy" => "::1",
            "SOCKSPort" => 1081i64,
        };
        let mode = mode_from_dict(&dict).unwrap();
        assert_eq!(
            mode.endpoint_for(Scheme::Socks).unwrap().authority(),
            "[::1]:1081"
        );
    }

    // Spells out every family's `…Port` and `…User` key, because [`SCHEMES`] is the only
    // place in the crate they appear: without this, four of the eight could be misspelled
    // and nothing would go red. Both failures are silent — a `…Port` nobody finds falls
    // back to the scheme default, a `…User` nobody finds drops the username — and neither
    // records a rejection, so on macOS the first symptom is traffic on the wrong port or
    // an unauthenticated proxy. Each dialled port differs from that family's default, so
    // reading the wrong key cannot produce the expected answer. The spellings are Apple's
    // `kSCPropNetProxies…` constants; `…User` is macOS 15.0+.
    #[test]
    fn every_scheme_reads_its_own_port_and_user_key() {
        for (scheme, enable, host, port, user, dialled) in [
            (
                Scheme::Http,
                "HTTPEnable",
                "HTTPProxy",
                "HTTPPort",
                "HTTPUser",
                8080u16,
            ),
            (
                Scheme::Https,
                "HTTPSEnable",
                "HTTPSProxy",
                "HTTPSPort",
                "HTTPSUser",
                8443,
            ),
            (
                Scheme::Ftp,
                "FTPEnable",
                "FTPProxy",
                "FTPPort",
                "FTPUser",
                8021,
            ),
            (
                Scheme::Socks,
                "SOCKSEnable",
                "SOCKSProxy",
                "SOCKSPort",
                "SOCKSUser",
                1081,
            ),
        ] {
            let mut dict = ProxyDict::new();
            dict.insert(enable, DictValue::Number(1));
            dict.insert(host, DictValue::Text("proxy.corp".to_owned()));
            dict.insert(port, DictValue::Number(i64::from(dialled)));
            dict.insert(user, DictValue::Text("alice".to_owned()));

            let mode = mode_from_dict(&dict).unwrap();
            let endpoint = mode
                .endpoint_for(scheme)
                .unwrap_or_else(|| panic!("{scheme:?} must be configured"));
            assert_eq!(endpoint.port, dialled, "{scheme:?} read {port}");
            let auth = endpoint
                .auth
                .as_ref()
                .unwrap_or_else(|| panic!("{scheme:?} must read {user}"));
            assert_eq!(auth.username(), "alice", "{scheme:?}");
            // A `…User` key is a username and nothing else: macOS keeps the password in
            // the keychain, which this crate does not read.
            assert!(!auth.has_password(), "{scheme:?}");
        }
    }

    #[test]
    fn pac_url_becomes_pac() {
        let dict = dict! {
            "ProxyAutoConfigEnable" => 1i64,
            "ProxyAutoConfigURLString" => "http://wpad.corp/proxy.pac",
        };
        let mode = mode_from_dict(&dict).unwrap();
        match mode {
            ProxyMode::Pac { url, .. } => assert_eq!(url.as_str(), "http://wpad.corp/proxy.pac"),
            other => panic!("expected Pac, got {other:?}"),
        }
    }

    #[test]
    fn an_inline_script_wins_over_the_pac_url() {
        let dict = dict! {
            "ProxyAutoConfigEnable" => 1i64,
            "ProxyAutoConfigURLString" => "http://wpad.corp/proxy.pac",
            "ProxyAutoConfigJavaScript" => "function FindProxyForURL(u, h) { return \"DIRECT\"; }",
        };
        match mode_from_dict(&dict).unwrap() {
            ProxyMode::PacInline { script, .. } => assert!(script.contains("FindProxyForURL")),
            other => panic!("expected PacInline, got {other:?}"),
        }
    }

    // The script is read through [`ProxyDict::raw_text`] rather than [`ProxyDict::text`]
    // because its leading whitespace is part of the JavaScript source. Nothing above
    // notices the difference -- every script there starts at `function` -- so the two
    // readers need one case that tells them apart.
    #[test]
    fn an_inline_script_keeps_its_leading_whitespace() {
        let script = "  \n  function FindProxyForURL(u, h) { return \"DIRECT\"; }";
        let dict = dict! {
            "ProxyAutoConfigEnable" => 1i64,
            "ProxyAutoConfigJavaScript" => script,
        };
        match mode_from_dict(&dict).unwrap() {
            ProxyMode::PacInline { script: got, .. } => assert_eq!(got, script),
            other => panic!("expected PacInline, got {other:?}"),
        }
    }

    // The two PAC returns were the one exit that threw the record list away. Nothing above
    // them is unreachable: `ProxyAutoDiscoveryEnable` present but unreadable is recorded and
    // *then* folded into "off", which lands on exactly this branch, so the drop that hid a
    // WPAD switch left with it. `Manual`'s exit has always carried the list.
    #[test]
    fn a_drop_on_the_way_to_a_pac_answer_survives_it() {
        let cases = [
            (
                "url",
                dict! {
                    "ProxyAutoDiscoveryEnable" => "yes",
                    "ProxyAutoConfigEnable" => 1i64,
                    "ProxyAutoConfigURLString" => "http://wpad.corp/proxy.pac",
                },
            ),
            (
                "inline",
                dict! {
                    "ProxyAutoDiscoveryEnable" => "yes",
                    "ProxyAutoConfigEnable" => 1i64,
                    "ProxyAutoConfigJavaScript" => "function FindProxyForURL(u, h) { return \"DIRECT\"; }",
                },
            ),
        ];
        for (label, dict) in cases {
            let mode = mode_from_dict(&dict).unwrap();
            let rejected = mode
                .rejected()
                .unwrap_or_else(|| panic!("{label}: the PAC mode carries no list: {mode:?}"));
            assert_eq!(rejected.len(), 1, "{label}: {rejected:?}");
            assert_eq!(
                *rejected[0].source(),
                RejectionSource::SystemConfiguration(AUTO_DISCOVERY_ENABLE.to_owned()),
                "{label}"
            );
            assert_eq!(rejected[0].redacted_input(), "yes", "{label}");
        }
    }

    #[test]
    fn auto_discovery_wins_over_everything() {
        let dict = dict! {
            "ProxyAutoDiscoveryEnable" => 1i64,
            "ProxyAutoConfigEnable" => 1i64,
            "ProxyAutoConfigURLString" => "http://wpad.corp/proxy.pac",
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
        };
        assert_eq!(
            mode_from_dict(&dict).unwrap(),
            ProxyMode::WpadAutoDetect,
            "auto-discovery must win, exactly as it does on Windows"
        );
    }

    #[test]
    fn pac_enabled_but_empty_falls_through_to_the_manual_entries() {
        let dict = dict! {
            "ProxyAutoConfigEnable" => 1i64,
            "ProxyAutoConfigURLString" => "",
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "HTTPPort" => 3128i64,
        };
        let mode = mode_from_dict(&dict).unwrap();
        assert_eq!(
            mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "proxy.corp:3128"
        );
    }

    // The configuration that reads like a fail-open: the PAC switch on with neither payload
    // key filled in, and nothing else set. It answers `Direct` with an empty record. This
    // pins that as the contract, because the reference falls through the same way.
    //
    // The reference falls through the same way. `proxy_config_service_mac.cc` reads
    // `kSCPropNetProxiesProxyAutoConfigURLString` only to skip setting a PAC URL when the
    // key is not there, then goes on to the per-scheme keys exactly as this reader does —
    // no PAC was named, so there is no PAC to lose. And this file already draws the same
    // line one family over: an enabled `HTTPEnable` whose `HTTPProxy` is absent takes
    // `Disabled` because "there was nothing to route to", and a dictionary holding nothing
    // else collapses past it to `Direct`. Recording here would make PAC the one family
    // where switching a flag on and filling nothing in counts as a drop.
    //
    // The blank spelling sits beside the absent one because `text_is_unusable` folds the
    // two together deliberately, and this is the configuration where that fold decides the
    // answer rather than merely agreeing with it. Each entry has its own control, and they
    // are different ones: giving the `get` in `text_is_unusable` an `Unreadable` fallback
    // fails the first, and an arm that reads a blank string as unreadable fails the second.
    // Both land as `Manual` carrying two rejections — which is what the proposed fix would
    // have made this configuration return.
    #[test]
    fn the_pac_switch_alone_is_direct_because_no_pac_was_ever_named() {
        for dict in [
            dict! { "ProxyAutoConfigEnable" => 1i64 },
            dict! {
                "ProxyAutoConfigEnable" => 1i64,
                "ProxyAutoConfigURLString" => "",
                "ProxyAutoConfigJavaScript" => "   ",
            },
        ] {
            assert_eq!(mode_from_dict(&dict).unwrap(), ProxyMode::Direct);
        }
    }

    #[test]
    fn a_malformed_pac_url_is_an_error() {
        let dict = dict! {
            "ProxyAutoConfigEnable" => 1i64,
            "ProxyAutoConfigURLString" => "not a url",
        };
        assert!(matches!(
            mode_from_dict(&dict),
            Err(Error::InvalidProxyUrl { .. })
        ));
    }

    #[test]
    fn exceptions_and_simple_hostnames_become_bypass_rules() {
        let list: &[&str] = &[
            "*.local",
            "169.254/16",
            "192.168.7/24",
            "example.com",
            "10.0.0.0/8",
        ];
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "ExceptionsList" => list,
            "ExcludeSimpleHostnames" => 1i64,
        };
        let mode = mode_from_dict(&dict).unwrap();
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        assert!(bypass.excludes_simple_hostnames());
        assert!(bypass.matches_authority("printer.local"));
        assert!(bypass.matches_authority("intranet"), "<local> equivalent");
        // The abbreviated form on a range that is not already bypassed. `169.254/16` is the
        // spelling Apple ships and is below too, but it cannot carry this: link-local is in
        // the implicit set, so `169.254.1.2` bypasses whether the entry parsed or not, and an
        // assertion on it here would hold nothing.
        assert!(bypass.matches_authority("192.168.7.9"), "abbreviated CIDR");
        assert!(
            !bypass.matches_authority("192.168.8.9"),
            "and only that /24"
        );
        // The network Chromium's `ParseCIDRBlock` reads `169.254/16` as, which is not the
        // one Apple wrote. Outside the implicit set, so this row does hold.
        assert!(!bypass.matches_authority("169.0.0.254"), "Chromium");
        // A bare name is that host and no other. Measured off CFNetwork, not assumed:
        // `tests/mac_exceptions_list.rs` holds the row on a macOS runner.
        assert!(bypass.matches_authority("example.com"));
        assert!(!bypass.matches_authority("www.example.com"));
        assert!(bypass.matches_authority("10.1.2.3:443"));
        assert!(!bypass.matches_authority("example.net"));
    }

    // The rest of that reading: three spellings CFNetwork matches no destination with.
    // Storing one as a live rule is fail-open on its own — the crate would report
    // [`ProxyStep::Direct`] for traffic the Mac hands the proxy.
    #[test]
    fn an_exception_entry_macos_matches_nothing_with_is_recorded_rather_than_stored() {
        let list: &[&str] = &[
            "*",
            "*ample*",
            "cor*.example",
            "*.co*p.example",
            ".corp.*",
            "example.com:8080",
            "corp.*",
        ];
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "ExceptionsList" => list,
        };
        let mode = mode_from_dict(&dict).unwrap();
        let bypass = mode.bypass().expect("manual mode has bypass rules");

        // The one worth the arm: a `*` stored as `HostPattern::All` is every destination
        // on the machine reported direct, on a machine that proxies every one of them.
        assert!(!bypass.matches_authority("anything.example"));
        assert!(!bypass.matches_authority("www.example.com"));
        // A star past the one that opened the entry is a character again, and one that
        // leaves a name no destination carries is refused rather than stored as the dead
        // glob it would be — the rule the guards in `HostPattern::parse_in` all share.
        assert!(!bypass.matches_authority("www.corp.example"));
        // A port does not narrow an entry there, it kills it.
        assert!(!bypass.matches_authority("example.com:8080"));

        // A trailing `.*` is the one star that survives, and it takes the host with it —
        // except that the glob needs the dot, so `corp` alone is the row this reads more
        // narrowly than the machine. Held here because it is the only divergence left, and
        // it is the safe direction: reported proxied, actually bypassed.
        assert!(bypass.matches_authority("corp.example"));
        assert!(!bypass.matches_authority("corp"));

        assert_eq!(bypass.rejected.len(), 6, "{:?}", bypass.rejected);
    }

    // The fourth spelling of the same fail-open, on a different axis: not what the entry
    // says but what surrounds it. Do not let `BypassDialect::trim` cut either end for
    // macOS — CFNetwork cuts neither, so a padded entry is dead there, and trimming it
    // here would make it live (`tests/mac_exceptions_list.rs` holds that on a runner).
    //
    // An array element is a whole entry — nothing splits it — so the padding a plist carries
    // reaches the parser intact, which is what makes this reachable rather than theoretical.
    #[test]
    fn an_exception_entry_padded_with_whitespace_is_dead_on_macos_and_recorded() {
        let list: &[&str] = &[" example.com", "example.com ", " 10.0/16"];
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "ExceptionsList" => list,
        };
        let mode = mode_from_dict(&dict).unwrap();
        let bypass = mode.bypass().expect("manual mode has bypass rules");

        assert!(!bypass.matches_authority("example.com"));
        // The CIDR row goes through `expand_abbreviated_cidr` first, so it has its own
        // control: pad a leading-space entry there and `parse_in` receives `10.0.0.0/16`
        // with no whitespace left in it, which is live here and dead on the Mac. Not
        // `169.254/16`, the spelling Apple actually ships, because link-local is in the
        // implicit set — that row would pass whatever this list holds.
        assert!(!bypass.matches_authority("10.0.1.1"));

        // Refused rather than dropped, so a reader sees what became of them.
        assert_eq!(bypass.rejected.len(), 3, "{:?}", bypass.rejected);
    }

    // A malformed `<Scheme>Proxy` host drops only that one
    // scheme and is recorded on `Manual.rejected`, instead of failing the whole
    // dictionary the way `?` used to.
    #[test]
    fn a_malformed_scheme_host_is_dropped_and_recorded_while_the_rest_survive() {
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "HTTPSEnable" => 1i64,
            "HTTPSProxy" => "not a host with spaces",
            "FTPEnable" => 1i64,
            "FTPProxy" => "files.corp",
        };
        let mode = mode_from_dict(&dict).unwrap();
        assert_eq!(
            mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "proxy.corp:80"
        );
        assert_eq!(
            mode.endpoint_for(Scheme::Ftp).unwrap().authority(),
            "files.corp:80"
        );
        assert!(mode.endpoint_for(Scheme::Https).is_none());
        assert_eq!(
            mode.rejected().unwrap()[0].redacted_input(),
            "not a host with spaces"
        );
        assert_eq!(
            mode.rejected().unwrap()[0].affected_scheme(),
            Some(Scheme::Https)
        );
    }

    // The macOS twin of `kioslaverc`'s
    // `an_unexpanded_http_proxy_is_reported_rather_than_resolved_direct`: the one case
    // where answering `Direct` would state the opposite of what the Mac does. `HTTPEnable`
    // says yes, the host is a value this crate cannot read, and with no `SOCKSProxy` there
    // is nothing else to cover HTTP — so the drop is the reason the request has no answer.
    #[cfg(feature = "resolve")]
    #[test]
    fn an_unreadable_host_under_an_enabled_scheme_is_reported_rather_than_resolved_direct() {
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => 8080i64,
        };
        let config = crate::ProxyConfig::new(mode_from_dict(&dict).unwrap(), Vec::new());
        let url = url::Url::parse("http://intranet.corp/x").unwrap();
        let err = crate::resolve(&config, &url).unwrap_err();
        assert!(
            matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                if *scheme == Scheme::Http),
            "{err:?}"
        );
    }

    // The macOS twin of `tests/proxy_server.rs`'s
    // `windows_manual_keeps_the_record_even_when_nothing_else_parses`:
    // a dictionary where every enabled scheme is malformed must not collapse to
    // `Direct` and silently lose the record.
    #[test]
    fn a_dictionary_with_only_a_malformed_host_keeps_the_record() {
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "not a host with spaces",
        };
        let mode = mode_from_dict(&dict).unwrap();
        assert!(!mode.is_direct());
        assert_eq!(
            mode.rejected().unwrap()[0].redacted_input(),
            "not a host with spaces"
        );
    }

    // Like a malformed `<Scheme>Proxy` host above, an `ExceptionsList` entry
    // `HostPattern::parse` rejects drops just that entry, recorded on
    // `BypassRules::rejected`, instead of failing the whole list.
    #[test]
    fn a_malformed_exception_entry_is_dropped_and_recorded_while_the_rest_survive() {
        let list: &[&str] = &["example.com", "[::1:broken", "10.0.0.0/8"];
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "ExceptionsList" => list,
        };
        let mode = mode_from_dict(&dict).unwrap();
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        assert!(bypass.matches_authority("example.com"));
        assert!(bypass.matches_authority("10.1.2.3"));
        // Recorded, but withheld rather than echoed: an unbalanced bracket leaves a `:`
        // that `redact_offending_token` cannot tell from a stranded `user:password`.
        assert_eq!(bypass.rejected.len(), 1);
        assert!(
            bypass.rejected[0].redacted_input().contains("withheld"),
            "{:?}",
            bypass.rejected
        );
    }

    // The wider version of the drop above: not one entry this crate cannot read but a
    // whole list that is not a list, and a simple-hostname switch that is not a flag.
    // Letting either reach the trace and nothing else leaves `bypass.rejected` empty, and a
    // Mac whose exceptions could not be read indistinguishable from one that had none — the
    // outcome the crate root names as the reason records exist at all.
    #[test]
    fn a_bypass_key_of_the_wrong_type_is_recorded_rather_than_read_as_absent() {
        for (value, expected) in [
            (
                DictValue::Text("*.corp.example".to_owned()),
                "*.corp.example",
            ),
            (DictValue::Number(1), "1"),
        ] {
            let mut dict = dict! {
                "HTTPEnable" => 1i64,
                "HTTPProxy" => "proxy.corp",
                "ExcludeSimpleHostnames" => "sometimes",
            };
            dict.insert(EXCEPTIONS_LIST, value);
            let mode = mode_from_dict(&dict).unwrap();
            let bypass = mode.bypass().expect("manual mode has bypass rules");
            // Neither key was applied, which is the half that already worked.
            assert!(!bypass.matches_authority("www.corp.example"));
            assert!(!bypass.excludes_simple_hostnames());
            assert_eq!(bypass.rejected.len(), 2, "{:?}", bypass.rejected);
            assert_eq!(bypass.rejected[0].redacted_input(), expected);
            assert_eq!(bypass.rejected[1].redacted_input(), "sometimes");
        }

        // A blank string is where `list_is_unusable` draws "filled in with nothing", the
        // same line its two siblings draw, so it stays out of the record.
        let dict = dict! {
            "HTTPEnable" => 1i64,
            "HTTPProxy" => "proxy.corp",
            "ExceptionsList" => "   ",
        };
        let mode = mode_from_dict(&dict).unwrap();
        assert!(mode.bypass().expect("manual").rejected.is_empty());
    }

    // Reading a `CFString` where the reference insists on a `CFNumber` is a deliberate
    // divergence: Chromium's `GetBoolFromDictionary` would leave the scheme unconfigured
    // and `ProxyDictionaryToProxyChain` would fall back to port 80. The tolerance stops at
    // the port *grammar*, though — a string port is still `1*DIGIT`, so the sign this
    // crate's own authority parser rejects is rejected here too, and to the same effect:
    // `split_host_port("h:+80")` is an error rather than a missing port, so the scheme is
    // dropped with a record here rather than dialled on 80.
    #[test]
    fn boolean_flags_stored_as_numbers_or_strings_both_work() {
        let dict = dict! {
            "HTTPEnable" => "1",
            "HTTPProxy" => "proxy.corp",
            "HTTPPort" => "8080",
        };
        let mode = mode_from_dict(&dict).unwrap();
        assert_eq!(
            mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "proxy.corp:8080"
        );

        let signed = dict! {
            "HTTPEnable" => "1",
            "HTTPProxy" => "proxy.corp",
            "HTTPPort" => "+8080",
        };
        let mode = mode_from_dict(&signed).unwrap();
        assert!(
            matches!(mode.entry_for(Scheme::Http), Some(ProxyEntry::Unusable(_))),
            "{mode:?}"
        );
        assert_eq!(
            mode.rejected().expect("a signed port left no record")[0].affected_scheme(),
            Some(Scheme::Http)
        );
    }

    #[test]
    fn abbreviated_cidrs_are_padded_and_everything_else_is_left_alone() {
        assert_eq!(expand_abbreviated_cidr("169.254/16"), "169.254.0.0/16");
        assert_eq!(expand_abbreviated_cidr("10/8"), "10.0.0.0/8");
        assert_eq!(expand_abbreviated_cidr("10.0.0.0/8"), "10.0.0.0/8");
        assert_eq!(expand_abbreviated_cidr("*.local"), "*.local");
        assert_eq!(expand_abbreviated_cidr("2001:db8::/32"), "2001:db8::/32");
        assert_eq!(expand_abbreviated_cidr("a.b/16"), "a.b/16");
        assert_eq!(expand_abbreviated_cidr("10./8"), "10./8");
        // A prefix length is what makes the short form a CIDR at all, and the emptiness
        // check is the only thing that sees it missing — `"".bytes().all(..)` is true, so
        // the digit check reads a blank prefix as digits. This row is the only thing holding
        // it. `169.254/` is not the shape Apple ships, so padding it invents
        // three octets, and since the `/` guard in `HostPattern::parse` refuses it either
        // way, the only trace it leaves is a `BypassRules::rejected` record naming a
        // network nobody wrote.
        assert_eq!(expand_abbreviated_cidr("169.254/"), "169.254/");
    }

    // `merge_setup_and_state` (the `Setup:`/`State:` split). Table driven like the
    // rest of this file, so it runs on every platform even though only the macOS
    // backend ever calls the function it tests.
    #[test]
    fn merge_setup_and_state_combinations() {
        use crate::config::ProxyConfigSource;

        // Setup value, state value, expected mode, expected attributions.
        type Case = (
            Option<ProxyMode>,
            Option<ProxyMode>,
            ProxyMode,
            Vec<(ProxyConfigSource, ProxyMode)>,
        );

        let setup_wpad = ProxyMode::WpadAutoDetect;
        let setup_pac = ProxyMode::pac(Url::parse("http://setup.example/proxy.pac").unwrap());
        let state_wpad = ProxyMode::WpadAutoDetect;
        let direct = ProxyMode::Direct;

        let cases: &[Case] = &[
            (
                Some(setup_wpad.clone()),
                None,
                setup_wpad.clone(),
                vec![(
                    ProxyConfigSource::SystemConfigurationSetup,
                    setup_wpad.clone(),
                )],
            ),
            (
                None,
                Some(state_wpad.clone()),
                state_wpad.clone(),
                vec![(
                    ProxyConfigSource::SystemConfigurationState,
                    state_wpad.clone(),
                )],
            ),
            (None, None, direct.clone(), vec![]),
            // Both scopes present and disagreeing: `State:` wins, because that is the
            // key `SCDynamicStoreCopyProxies` — and so every reference — reads.
            (
                Some(setup_pac.clone()),
                Some(state_wpad.clone()),
                state_wpad.clone(),
                vec![
                    (
                        ProxyConfigSource::SystemConfigurationState,
                        state_wpad.clone(),
                    ),
                    (
                        ProxyConfigSource::SystemConfigurationSetup,
                        setup_pac.clone(),
                    ),
                ],
            ),
            (
                Some(direct.clone()),
                Some(direct.clone()),
                direct.clone(),
                vec![
                    (ProxyConfigSource::SystemConfigurationState, direct.clone()),
                    (ProxyConfigSource::SystemConfigurationSetup, direct.clone()),
                ],
            ),
        ];
        for (setup, state, effective, sources) in cases {
            let config = merge_setup_and_state(Ok(setup.clone()), state.clone())
                .expect("a readable Setup: scope cannot fail the merge");
            assert_eq!(config.effective, *effective);
            assert_eq!(config.sources, *sources);
            // Every row here is a read that worked, including the ones where a scope is
            // simply not there. None of them is a degradation.
            assert!(config.fallbacks.is_empty());
        }
    }

    // The scope that decides nothing must not be able to fail the read. `Setup:` never
    // reaches `effective` while a `State:` scope exists, so a `Setup:` the reader cannot
    // interpret — a malformed `ProxyAutoConfigURLString` is the one value in this schema
    // that fails rather than degrades — costs the `sources` entry and nothing else.
    // The two error kinds a `Setup:` read can fail with, for the pair of tests below. The
    // rule the function documents is that no kind is exempt — the opposite of
    // `group_policy_source` on Windows — and one kind alone cannot hold that: a softening arm
    // narrowed to `InvalidProxyUrl` is invisible to a single-kind test, while a `Setup:`
    // scope that fails on I/O takes a perfectly readable `State:` scope down with it.
    fn unreadable_setup_scopes() -> [Error; 2] {
        [
            Error::invalid_proxy_url("http://", url::ParseError::EmptyHost),
            Error::io(
                "reading the Setup: proxies scope",
                std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            ),
        ]
    }

    #[test]
    fn an_unreadable_setup_scope_does_not_take_a_usable_state_scope_down() {
        for error in unreadable_setup_scopes() {
            let case = format!("{error:?}");
            let config = merge_setup_and_state(Err(error), Some(ProxyMode::WpadAutoDetect))
                .expect("the State: scope is readable, so the read has an answer");
            assert_eq!(config.effective, ProxyMode::WpadAutoDetect, "{case}");
            assert_eq!(
                config.sources,
                vec![(
                    ProxyConfigSource::SystemConfigurationState,
                    ProxyMode::WpadAutoDetect
                )],
                "the scope that could not be read must not be reported as if it had been: \
                 {case}"
            );
            // The assertion above is also what a machine with no `Setup:` scope produces,
            // so on its own it cannot say the failure was noticed at all. This is the half
            // that distinguishes them.
            assert_eq!(
                config.fallbacks,
                vec![ProxyConfigSource::SystemConfigurationSetup],
                "{case}"
            );
        }
    }

    // The other half of the same rule: with no `State:` scope, `Setup:` *is* the effective
    // mode, so failing to read it fails the read. Answering `Direct` here would report no
    // proxy for a machine that holds a configured one.
    #[test]
    fn an_unreadable_setup_scope_is_the_whole_read_when_there_is_no_state_scope() {
        for error in unreadable_setup_scopes() {
            let expected = format!("{error:?}");
            let propagated = merge_setup_and_state(Err(error), None)
                .expect_err("nothing is left to answer with");
            assert_eq!(
                format!("{propagated:?}"),
                expected,
                "the scope's own error is what propagates, whatever kind it is"
            );
        }
    }
}
