//! Pure GNOME `org.gnome.system.proxy` → [`ProxyMode`] (twin of `proxy_dict`).
//! [`super::gnome`] fills [`GnomeSettings`]. `http.authentication-password` is mapped
//! but **never read** by default ([`super::gnome::READ_AUTHENTICATION_PASSWORD`] = false).

// Compiled on every target under `cfg(test)` so that the table driven tests below run in
// CI on Windows and macOS as well — and on Linux with `linux-gnome` off, where the tests
// are equally worth running. In both cases the module has no caller.
#![cfg_attr(
    not(all(target_os = "linux", feature = "linux-gnome")),
    allow(dead_code)
)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use url::Url;

use crate::auth::ProxyAuth;
use crate::bypass::{BypassDialect, BypassRules};
use crate::diagnostic::{RejectedValue, RejectionKind, RejectionSource};
use crate::endpoint::{ProxyEndpoint, ProxyEntry, ProxyScheme, Scheme};
use crate::error::Error;
use crate::mode::ProxyMode;
use crate::parse;

// The schema the whole backend is built on.
pub(crate) const SCHEMA: &str = "org.gnome.system.proxy";

// `mode`: the enum `none` / `manual` / `auto`.
pub(crate) const KEY_MODE: &str = "mode";
// `autoconfig-url`: the PAC URL used when `mode = auto`.
pub(crate) const KEY_AUTOCONFIG_URL: &str = "autoconfig-url";
// `ignore-hosts`: the bypass list, an array of strings.
pub(crate) const KEY_IGNORE_HOSTS: &str = "ignore-hosts";
// `use-same-proxy`: whether the HTTP proxy covers every protocol.
pub(crate) const KEY_USE_SAME_PROXY: &str = "use-same-proxy";

// `<child>.host`.
pub(crate) const KEY_HOST: &str = "host";
// `<child>.port`.
pub(crate) const KEY_PORT: &str = "port";
// `http.use-authentication` (the `http` child only).
pub(crate) const KEY_USE_AUTHENTICATION: &str = "use-authentication";
// `http.authentication-user` (the `http` child only).
pub(crate) const KEY_AUTHENTICATION_USER: &str = "authentication-user";
// `http.authentication-password` — see the module documentation above.
pub(crate) const KEY_AUTHENTICATION_PASSWORD: &str = "authentication-password";

// The `mode` value that means "no proxy".
const MODE_NONE: &str = "none";
// The `mode` value that means "static entries in the child schemas".
const MODE_MANUAL: &str = "manual";
// The `mode` value that means "PAC URL, or WPAD when it is empty".
const MODE_AUTO: &str = "auto";

// One child schema of `org.gnome.system.proxy`.
pub(crate) struct ChildKeys {
    // The [`Scheme`] this child configures.
    pub(crate) scheme: Scheme,
    // The child name, i.e. the `http` in `org.gnome.system.proxy.http`.
    pub(crate) child: &'static str,
    // The port assumed when the child's `port` key is `0`.
    //
    // GNOME stores `0` for "never filled in" and the schema's own default for
    // `http.port` is `8080`, so that is the default assumed for the three HTTP-family
    // children when this source names no port of its own — a source-specific default,
    // not a single crate-wide one. SOCKS gets the usual 1080.
    //
    // Nobody agrees here, so a default has to be picked rather than copied. The schema
    // says a `0` port means the child is not in use at all ("HTTP proxying is enabled
    // when the host key is non-empty and the port is non-0", in the description of the
    // `enabled` key it also marks "Unused; ignore"), yet neither reader does that:
    // glib-networking formats the port straight into the URI and gets `http://host:0`,
    // and Chromium omits it and lands on the *scheme's* default, 80 for the HTTP family.
    // A named host that reaches nothing is the outcome to avoid, and 8080 is the port the
    // schema itself expects an HTTP proxy to be on. `https`/`ftp`/`socks` are the children
    // whose schema default is `0`, so they are the ones that reach this by simply going
    // unfilled; `http` starts at 8080 and only lands here if someone stored `0` over it.
    default_port: u16,
    // The wire protocol hint, set only where the schema implies one.
    hint: Option<ProxyScheme>,
}

// The four child schemas, in the order the schema lists them: `rejected` records its drops
// in this sequence. [`manual_mode`] looks its two special children (`http`, `socks`) up by
// [`Scheme`], not by position, so this order is a presentation choice and nothing else.
pub(crate) const CHILDREN: [ChildKeys; 4] = [
    ChildKeys {
        scheme: Scheme::Http,
        child: "http",
        default_port: 8080,
        hint: None,
    },
    ChildKeys {
        scheme: Scheme::Https,
        child: "https",
        default_port: 8080,
        hint: None,
    },
    ChildKeys {
        scheme: Scheme::Ftp,
        child: "ftp",
        default_port: 8080,
        // `None` is read as HTTP by `ProxyStep::from_endpoint`, and for this child that is a
        // decision rather than an omission: the key names the proxy *for* FTP destinations,
        // not a proxy spoken to in FTP. glib-networking does hand out `ftp://host:port` built
        // from these two keys (`gproxyresolvergnome.c:334`, against `http://` for the `https`
        // child at `:294`), but nothing implements that protocol — GIO's
        // `G_PROXY_EXTENSION_POINT_NAME` has `http`, `https`, `socks4`, `socks4a` and
        // `socks5` and no other, and glib-networking registers none — so a client that took
        // the URI at its word would get `Proxy protocol "ftp" is not supported.`
        // (`gsocketclient.c:1265`) and reach nothing. Chromium reads the same keys and pins
        // `SCHEME_HTTP` for all of them but SOCKS (`proxy_config_service_linux.cc:1065`).
        //
        // Recording the child as unsupported instead was the other candidate, and it is the
        // worse one: the drop lands in `rejected` and an FTP destination answers Direct, so a
        // machine with a configured proxy sends that traffic past it. Reporting a transport
        // the administrator did configure beats reporting none.
        hint: None,
    },
    ChildKeys {
        scheme: Scheme::Socks,
        child: "socks",
        default_port: 1080,
        // Not something the schema says: the `socks` child has a `host` and a `port` and no
        // version anywhere. It is the URI glib builds from them — `socks://host:port` — and
        // `socks://` is SOCKS5 by the reading this crate takes. GIO widens that URI again
        // (`g_simple_proxy_resolver_set_default_proxy` documents the bare form as covering
        // socks5, socks4a and socks4 alike), which is a set `ProxyScheme` has no spelling
        // for; Chromium does not widen it either, pinning `SCHEME_SOCKS5` for
        // `PROXY_SOCKS_HOST` in `proxy_config_service_linux.cc`.
        hint: Some(ProxyScheme::Socks5),
    },
];

// One `GSettings` value, after the GLib types have been erased.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum GValue {
    // A `s` (string) key.
    Text(String),
    // An `i` (int32) key.
    Int(i32),
    // A `b` (boolean) key.
    Flag(bool),
    // An `as` (string array) key.
    List(Vec<String>),
}

// Hand-written for the `Text` arm, which is the only one a secret can reach.
// `autoconfig-url` is a `s` key and a PAC URL may carry userinfo, so the risk does not
// depend on [`super::gnome::READ_AUTHENTICATION_PASSWORD`] — but that constant is a
// `false` someone could flip, and `authentication-password` is already mapped
// ([`KEY_AUTHENTICATION_PASSWORD`]), so flipping it would otherwise have turned this
// derive into a plaintext-password path silently. `Int`, `Flag` and `List` are printed
// as they were: a port, a boolean, and `ignore-hosts`, which holds host patterns.
impl fmt::Debug for GValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => f
                .debug_tuple("Text")
                .field(&crate::util::redact_offending_token(text))
                .finish(),
            Self::Int(value) => f.debug_tuple("Int").field(value).finish(),
            Self::Flag(value) => f.debug_tuple("Flag").field(value).finish(),
            Self::List(values) => f.debug_tuple("List").field(values).finish(),
        }
    }
}

// The whole schema flattened into one map.
//
// Child keys are stored dotted: `http.host`, `socks.port`, … The flattening is what
// makes the type constructible from a test literal without GLib.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GnomeSettings {
    // Ordered rather than hashed only so that the derived `Debug` prints the same text
    // twice for the same schema; a `HashMap` seeds its iteration order per instance. The
    // KDE twin buys that with a hand-written `Debug` (`kioslaverc.rs`), which it needed
    // anyway for masking. Nothing here needs masking, so the container is the cheaper
    // half of the same decision. Both maps are schema-sized.
    entries: BTreeMap<String, GValue>,
    // The subset of `entries` somebody set — see [`GnomeSettings::mark_written`] and
    // [`configured_mode`]. "Somebody" is wider than "the user": an administrator's dconf
    // profile counts too, which is why this is not called `user_values`.
    written_values: BTreeSet<String>,
}

impl GnomeSettings {
    // An empty map, i.e. "the schema said nothing" (which reads as `mode = none`).
    pub(crate) fn new() -> Self {
        Self::default()
    }

    // Record one key/value pair.
    pub(crate) fn insert(&mut self, key: impl Into<String>, value: GValue) {
        self.entries.insert(key.into(), value);
    }

    // Note that `key` was set by somebody rather than left at the compiled schema's own
    // default. `g_settings_get_user_value()` alone cannot answer that — it sees only the
    // user's own layer, so a key an administrator's dconf profile set is invisible to it.
    // `gnome::was_written` holds the whole rule and the reason for each part of it.
    pub(crate) fn mark_written(&mut self, key: impl Into<String>) {
        self.written_values.insert(key.into());
    }

    // The dotted key of a child schema key, e.g. `("http", "host")` → `http.host`.
    pub(crate) fn child_key(child: &str, key: &str) -> String {
        format!("{child}.{key}")
    }

    // Whether *any* key this crate reads was set by somebody.
    fn has_written_value(&self) -> bool {
        !self.written_values.is_empty()
    }

    // Read a string key, trimmed; empty strings are reported as absent, which is how
    // GNOME stores "not configured".
    fn text(&self, key: &str) -> Option<&str> {
        match self.entries.get(key)? {
            GValue::Text(text) => Some(text.trim()).filter(|text| !text.is_empty()),
            _ => None,
        }
    }

    // Read a boolean key.
    fn flag(&self, key: &str) -> Option<bool> {
        match self.entries.get(key)? {
            GValue::Flag(flag) => Some(*flag),
            _ => None,
        }
    }

    // Read a port key. `0` is GNOME's "never filled in" and is reported as absent.
    //
    // The `try_from` cannot fold an out-of-range port into that same "absent" — the sibling
    // `ProxyDict::port_is_unusable` exists on the macOS side precisely because there it can.
    // All four `port` keys declare `<range min="0" max="65535"/>`, and GSettings replaces a
    // stored value outside a key's declared range with the schema default before any reader
    // sees it, so `settings.int()` in `gnome::read_key` cannot hand this an `i32` a `u16`
    // will not hold. Measured against gsettings-desktop-schemas 42.0 / GLib 2.72.4:
    // `port=70000` written straight into `$XDG_CONFIG_HOME/glib-2.0/settings/keyfile` reads
    // back through `GSETTINGS_BACKEND=keyfile gsettings get org.gnome.system.proxy.http
    // port` as `8080`, the schema default. The `try_from` stays as the total function this
    // signature needs, not as a case that arises.
    fn port(&self, key: &str) -> Option<u16> {
        match self.entries.get(key)? {
            GValue::Int(value) => u16::try_from(*value).ok().filter(|port| *port != 0),
            _ => None,
        }
    }

    // Read a string array key.
    fn list(&self, key: &str) -> Option<&[String]> {
        match self.entries.get(key)? {
            GValue::List(items) => Some(items.as_slice()),
            _ => None,
        }
    }
}

impl FromIterator<(String, GValue)> for GnomeSettings {
    fn from_iter<I: IntoIterator<Item = (String, GValue)>>(iter: I) -> Self {
        Self {
            entries: iter.into_iter().collect(),
            written_values: BTreeSet::new(),
        }
    }
}

// The mode this store is *configured* with, or `None` when it was never configured.
//
// A `Direct` that nobody wrote is the schema speaking, not a decision: every machine with
// the GNOME schemas installed answers `mode = 'none'`, including a KDE one, and reporting
// that as a configured source would put GNOME ahead of the store the user really uses.
pub(crate) fn configured_mode(settings: &GnomeSettings) -> Result<Option<ProxyMode>, Error> {
    let mode = mode_from_settings(settings)?;
    if settings.has_written_value() || !mode.is_direct() {
        Ok(Some(mode))
    } else {
        Ok(None)
    }
}

// Collapse the schema into a single [`ProxyMode`].
pub(crate) fn mode_from_settings(settings: &GnomeSettings) -> Result<ProxyMode, Error> {
    match settings.text(KEY_MODE).unwrap_or(MODE_NONE) {
        MODE_MANUAL => manual_mode(settings),
        MODE_AUTO => match settings.text(KEY_AUTOCONFIG_URL) {
            Some(url) => {
                let parsed =
                    Url::parse(url).map_err(|source| Error::invalid_proxy_url(url, source))?;
                Ok(ProxyMode::pac(parsed))
            }
            None => Ok(ProxyMode::WpadAutoDetect),
        },
        _ => Ok(ProxyMode::Direct),
    }
}

// Build the `mode = manual` case from the four child schemas.
fn manual_mode(settings: &GnomeSettings) -> Result<ProxyMode, Error> {
    let mut per_scheme = HashMap::new();
    let mut rejected = Vec::new();

    // The two readers of this schema disagree about `use-same-proxy`, so following either
    // one alone would be a choice, not a rule. Chromium's `SettingGetterImplGSettings`
    // never reads the key: its `GetBool` returns the "unavailable" `false` under the
    // comment "it is never set to false by the proxy config utility. We ignore it", so
    // `GetConfigFromSettings`'s `same_proxy` keeps the `false` it was initialised with and
    // Chrome always takes the per-scheme branch below;
    // glib-networking's `gproxyresolvergnome.c` honours it, making the HTTP child the
    // *default* proxy while still letting a configured child win for its own scheme. The
    // key is honoured here, glib's way: it is the one the schema actually documents
    // ("Whether to use the HTTP proxy for all protocols"), its default is `true`, and
    // ignoring a `true` would drop the catch-all a GNOME user asked for.
    // Read every child once, in schema order, so that `rejected` records the same
    // sequence whichever branch below runs.
    let resolved: Vec<(Scheme, Option<ProxyEndpoint>)> = CHILDREN
        .iter()
        .map(|keys| (keys.scheme, endpoint_for(settings, keys, &mut rejected)))
        .collect();
    let endpoint_of = |wanted| {
        resolved
            .iter()
            .find(|(scheme, _)| *scheme == wanted)
            .and_then(|(_, endpoint)| endpoint.clone())
    };
    let socks = endpoint_of(Scheme::Socks);
    let http = endpoint_of(Scheme::Http);
    // `socks.is_none()` alone cannot tell "no socks child at all" (nothing was lost, so the
    // `Disabled` below is correct) from "a socks child was named but rejected" (its
    // catch-all was lost too, and the schemes that would have relied on it must stay out of
    // `per_scheme` so `resolve` can find the record in `rejected` instead of a `Disabled`
    // pre-empting it). A raw `socks.host` value with no usable endpoint is exactly the
    // second case.
    let socks_unusable = socks.is_none()
        && CHILDREN
            .iter()
            .find(|keys| keys.scheme == Scheme::Socks)
            .is_some_and(|keys| {
                settings
                    .text(&GnomeSettings::child_key(keys.child, KEY_HOST))
                    .is_some()
            });

    if settings.flag(KEY_USE_SAME_PROXY) == Some(true) {
        if let Some(endpoint) = http.clone() {
            per_scheme.insert(Scheme::All, ProxyEntry::Use(endpoint));
        }
        // No `Disabled` entries here: an empty child must fall through to `All`, and a
        // `Disabled` entry is precisely what suppresses that fallback.
        for (scheme, endpoint) in resolved
            .iter()
            .filter(|(scheme, _)| *scheme != Scheme::Http)
        {
            if let Some(endpoint) = endpoint {
                per_scheme.insert(*scheme, ProxyEntry::Use(endpoint.clone()));
            }
        }
    } else {
        // `https` has a rule of its own, and the schema states it outside `use-same-proxy`,
        // in the `mode` key's description: "If an http proxy is configured, but an https
        // proxy is not, then the http proxy is also used for https." glib-networking does
        // exactly that — `else if (http_proxy) set_uri_proxy (simple, "https", http_proxy)`
        // sits outside its `use-same-proxy` block, and a per-scheme proxy beats the
        // `set_default_proxy()` the SOCKS child installs. This crate follows glib here.
        // Only an *absent* child inherits: `endpoint_for`
        // answers `None` both for a child with no host and for one whose host would not
        // parse, and the second is already in `rejected`, where serving the HTTP proxy in
        // its place would send HTTPS to a proxy nobody named
        // (`malformed_child_hosts_are_dropped_and_recorded` pins that). Neither the schema
        // nor glib gives `ftp` this rule.
        let inherited_https = match CHILDREN
            .iter()
            .find(|keys| keys.scheme == Scheme::Https)
            .and_then(|keys| settings.text(&GnomeSettings::child_key(keys.child, KEY_HOST)))
        {
            Some(_) => None,
            None => {
                // Inheriting writes the `http` child's value into a second slot, so losing it
                // loses two answers. `rejected` carries one record per slot lost —
                // `affected_scheme` holds a single `Scheme` and cannot say "both", and
                // `Scheme::All` would over-claim `ftp`, which inherits nothing — or `resolve`
                // would answer Direct for `https` with the record for the very proxy it was
                // meant to use sitting right there. Only the `http` child is ever attributed
                // `Http`, so this cannot pick up someone else's drop.
                let lost = rejected
                    .iter()
                    .find(|value| value.affected_scheme() == Some(Scheme::Http))
                    .cloned();
                if let Some(value) = lost {
                    rejected.push(value.for_scheme(Some(Scheme::Https)));
                }
                http.clone()
            }
        };

        for (scheme, endpoint) in &resolved {
            let endpoint = if endpoint.is_none() && *scheme == Scheme::Https {
                &inherited_https
            } else {
                endpoint
            };
            match endpoint {
                Some(endpoint) => {
                    per_scheme.insert(*scheme, ProxyEntry::Use(endpoint.clone()));
                }
                // `Disabled` is what stops a scheme from reaching `Scheme::All`, so it
                // may only be written where nothing is meant to catch it. With a SOCKS
                // child configured something is, and the entry is left absent instead —
                // whether that something resolved (`socks: Some`) or was rejected
                // (`socks_unusable`): either way `Disabled` would answer Direct in place
                // of a proxy the user actually named. The child's own host is the same
                // rule one step nearer: `endpoint_for` answers `None` for an absent host
                // and for an unparseable one alike, and only the first of those is
                // configured to go direct. `ProxyMode::with_rejected` fills the slot this
                // leaves empty with the record itself, and does not overwrite a `Disabled`
                // — which is why the guard stays here, where the backend still knows that
                // it is looking at the host it dropped rather than at a blank key.
                None if socks.is_none()
                    && !socks_unusable
                    && !rejected
                        .iter()
                        .any(|value| value.affected_scheme() == Some(*scheme)) =>
                {
                    per_scheme.insert(*scheme, ProxyEntry::Disabled);
                }
                None => {}
            }
        }
    }

    // A configured SOCKS child catches every scheme that named no proxy of its own —
    // the same rule as Windows' `socks=` catch-all (`parse::apply_socks_catch_all`).
    // Both readers of this schema arrive at that rule, by different routes:
    // glib-networking calls `g_simple_proxy_resolver_set_default_proxy()` with the SOCKS
    // URI, and Chromium puts it in `fallback_proxies`, which `ProxyRules::Apply()`
    // reaches for whenever the scheme's own list is empty. Chromium's
    // `num_proxies_specified == 1` promotion is the *same* outcome expressed one layer
    // up, not a narrower rule: a lone SOCKS child is simply the case where no scheme has
    // anything else.
    //
    // Where they stop agreeing is the overlap, and this side is the one that diverges:
    // glib's SOCKS block runs *after* its `use-same-proxy` one and calls
    // `set_default_proxy()` unconditionally, so there a SOCKS child overwrites the HTTP
    // catch-all for every scheme glib did not name outright — it copies the HTTP proxy
    // onto `https` by hand, so that one survives, but `ftp` and anything else land on
    // SOCKS. The guard below instead leaves the `use-same-proxy` answer standing
    // (`a_child_with_its_own_host_overrides_use_same_proxy` pins that).
    // Chromium cannot break the tie — it never reads that key, so its `same_proxy` stays
    // `false` and the overlap never arises there. Standing is what the key literally asks
    // for ("use the HTTP proxy for all protocols"), and it costs nothing in the case that
    // motivated this block: the key defaults to `true`, so a GNOME user who configures
    // nothing but a SOCKS proxy is otherwise never covered.
    if let Some(endpoint) = socks
        && !per_scheme.contains_key(&Scheme::All)
    {
        per_scheme.insert(Scheme::All, ProxyEntry::Use(endpoint));
    }

    // Reject-only stays `Manual` so the drops are not lost — `parse::windows_manual`'s
    // doc is where that rule is written.
    if per_scheme.values().all(ProxyEntry::is_disabled) && rejected.is_empty() {
        return Ok(ProxyMode::Direct);
    }
    Ok(ProxyMode::manual(per_scheme, bypass_from_settings(settings)?).with_rejected(rejected))
}

// The endpoint of one child schema, or `None` when it has no host or an unparseable
// one.
fn endpoint_for(
    settings: &GnomeSettings,
    keys: &ChildKeys,
    rejected: &mut Vec<RejectedValue>,
) -> Option<ProxyEndpoint> {
    let host = settings.text(&GnomeSettings::child_key(keys.child, KEY_HOST))?;

    let mut endpoint = match ProxyEndpoint::parse(host, keys.default_port) {
        Ok(endpoint) => endpoint,
        // The `WARN` compiles to nothing without the `tracing` feature, which is what
        // leaves `err` unused there; the `rejected` entry below is what carries the drop
        // either way.
        #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
        Err(err) => {
            crate::trace::warning!(
                error = %crate::trace::SafeError(&err),
                "skipping an unparseable GNOME <child>.host"
            );
            // The `socks` child is also `manual_mode`'s catch-all for every scheme with no
            // child of its own (see the block below this function), and under
            // `use-same-proxy` — the schema default — so is the `http` one, which is written
            // to `Scheme::All` rather than to `Scheme::Http`. A malformed host in either
            // loses that fallback too, so it is attributed as widely as the fallback it
            // prevented rather than to its own scheme: `resolve` looks for a drop under the
            // request's own scheme or `All`, so an `Http` attribution would leave `https`
            // and `ftp` answering Direct with the record right there. `settings` is a
            // snapshot, so reading the key here and in the branch below cannot disagree.
            let attributed_scheme = if keys.scheme == Scheme::Socks
                || (keys.scheme == Scheme::Http && settings.flag(KEY_USE_SAME_PROXY) == Some(true))
            {
                Scheme::All
            } else {
                keys.scheme
            };
            rejected.push(
                RejectedValue::new(
                    RejectionKind::InvalidProxyEndpoint,
                    RejectionSource::GSettings(format!("{}.{}", keys.child, KEY_HOST)),
                    host,
                )
                .for_scheme(Some(attributed_scheme)),
            );
            return None;
        }
    };
    if let Some(port) = settings.port(&GnomeSettings::child_key(keys.child, KEY_PORT)) {
        endpoint.port = port;
    }
    if let Some(hint) = keys.hint
        && endpoint.scheme_hint.is_none()
    {
        endpoint = endpoint.with_scheme_hint(hint);
    }
    // The authentication keys exist on the `http` child only.
    if keys.scheme == Scheme::Http
        && settings.flag(&GnomeSettings::child_key(
            keys.child,
            KEY_USE_AUTHENTICATION,
        )) == Some(true)
        && let Some(user) = settings.text(&GnomeSettings::child_key(
            keys.child,
            KEY_AUTHENTICATION_USER,
        ))
    {
        endpoint = endpoint.with_auth(ProxyAuth::new(
            user,
            settings.text(&GnomeSettings::child_key(
                keys.child,
                KEY_AUTHENTICATION_PASSWORD,
            )),
        ));
    }
    Some(endpoint)
}

// Build the bypass rules from `ignore-hosts`, the way the code that resolves on GNOME
// reads them — GLib's `GSimpleProxyResolver`, which `GProxyResolverGnome` fills from these
// same keys. [`BypassDialect::Gnome`] carries the three differences that are pattern
// shapes; the fourth is the port, which is not a shape and rides on the rule set.
//
// Not `no_proxy(&items.join(","))`: the array is the delimiter, so rejoining and splitting
// on `,` would read `['localhost,127.0.0.1']` as two rules the desktop does not have —
// GLib matches that element against a host of that name and bypasses nothing, so inventing
// the boundary sends two hosts direct that GNOME proxies.
//
// The WinINet tokens stay recognised: `HostPattern::parse_in` reads `<local>` and
// `<-loopback>` before it reads the dialect, so every source that fills a list one entry
// at a time reads the same vocabulary. GLib reads neither and matches either token against
// a host literally so named. That divergence is left standing rather than answered here,
// because a GNOME writer has no reason to type a WinINet token.
fn bypass_from_settings(settings: &GnomeSettings) -> Result<BypassRules, Error> {
    match settings.list(KEY_IGNORE_HOSTS) {
        Some(items) => {
            let mut rules =
                parse::bypass_entries_in(items.iter().map(String::as_str), BypassDialect::Gnome);
            rules.require_explicit_port = true;
            Ok(rules)
        }
        None => Ok(BypassRules::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a settings map from `(key, value)` literals: `&str` becomes `Text`, an
    // integer `Int`, a `bool` `Flag` and a `&[&str]` `List`.
    macro_rules! settings {
        ($($key:literal => $value:expr),* $(,)?) => {{
            #[allow(unused_mut)]
            let mut settings = GnomeSettings::new();
            $(settings.insert($key, $value.into_gvalue());)*
            settings
        }};
    }

    trait IntoGValue {
        fn into_gvalue(self) -> GValue;
    }
    impl IntoGValue for &str {
        fn into_gvalue(self) -> GValue {
            GValue::Text(self.to_owned())
        }
    }
    impl IntoGValue for i32 {
        fn into_gvalue(self) -> GValue {
            GValue::Int(self)
        }
    }
    impl IntoGValue for bool {
        fn into_gvalue(self) -> GValue {
            GValue::Flag(self)
        }
    }
    impl IntoGValue for &[&str] {
        fn into_gvalue(self) -> GValue {
            GValue::List(self.iter().map(|s| (*s).to_owned()).collect())
        }
    }

    // This type exists to erase the GLib types, so the variant name is most of what a dump
    // carries: `Int` says a port, `Flag` says a boolean key. This row is the only thing
    // holding them apart, and `Flag(8080)` is not a reading anyone can act on.
    // Only the `Text` arm masks, and `debug_masking`'s registry holds that half; this row is
    // the other one. Rendered together and compared once, so that a failure names every arm
    // that moved rather than stopping at the first.
    #[test]
    fn every_gvalue_debug_names_the_type_it_erased() {
        let rendered: Vec<String> = [
            GValue::Text("proxy.corp".to_owned()),
            GValue::Int(8080),
            GValue::Flag(true),
            GValue::List(vec!["localhost".to_owned()]),
        ]
        .iter()
        .map(|value| format!("{value:?}"))
        .collect();
        assert_eq!(
            rendered,
            [
                "Text(\"proxy.corp\")",
                "Int(8080)",
                "Flag(true)",
                "List([\"localhost\"])",
            ]
        );
    }

    #[test]
    fn an_empty_map_is_direct() {
        assert_eq!(
            mode_from_settings(&GnomeSettings::new()).unwrap(),
            ProxyMode::Direct
        );
    }

    #[test]
    fn mode_none_ignores_every_other_key() {
        let settings = settings! {
            "mode" => "none",
            "autoconfig-url" => "http://wpad.corp/proxy.pac",
            "http.host" => "proxy.corp",
            "http.port" => 8080i32,
        };
        assert_eq!(mode_from_settings(&settings).unwrap(), ProxyMode::Direct);
    }

    #[test]
    fn an_unknown_mode_value_is_direct() {
        let settings = settings! { "mode" => "something-new" };
        assert_eq!(mode_from_settings(&settings).unwrap(), ProxyMode::Direct);
    }

    #[test]
    fn mode_auto_with_a_url_is_pac() {
        let settings = settings! {
            "mode" => "auto",
            "autoconfig-url" => "http://wpad.corp/proxy.pac",
        };
        match mode_from_settings(&settings).unwrap() {
            ProxyMode::Pac { url, .. } => assert_eq!(url.as_str(), "http://wpad.corp/proxy.pac"),
            other => panic!("expected Pac, got {other:?}"),
        }
    }

    #[test]
    fn mode_auto_without_a_url_is_wpad() {
        let settings = settings! { "mode" => "auto", "autoconfig-url" => "" };
        assert_eq!(
            mode_from_settings(&settings).unwrap(),
            ProxyMode::WpadAutoDetect
        );
    }

    #[test]
    fn a_malformed_autoconfig_url_is_an_error() {
        let settings = settings! { "mode" => "auto", "autoconfig-url" => "not a url" };
        assert!(matches!(
            mode_from_settings(&settings),
            Err(Error::InvalidProxyUrl { .. })
        ));
    }

    #[test]
    fn manual_without_any_host_is_direct() {
        let settings = settings! {
            "mode" => "manual",
            "http.host" => "",
            "http.port" => 8080i32,
            "https.host" => "",
        };
        assert_eq!(mode_from_settings(&settings).unwrap(), ProxyMode::Direct);
    }

    #[test]
    fn manual_maps_each_child_onto_its_scheme() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => false,
            "http.host" => "http.corp",
            "http.port" => 3128i32,
            "https.host" => "https.corp",
            "https.port" => 3129i32,
            "ftp.host" => "ftp.corp",
            "ftp.port" => 3130i32,
            "socks.host" => "socks.corp",
            "socks.port" => 1081i32,
        };
        let mode = mode_from_settings(&settings).unwrap();
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
        let socks = mode.endpoint_for(Scheme::Socks).unwrap();
        assert_eq!(socks.authority(), "socks.corp:1081");
        assert_eq!(socks.scheme_hint, Some(ProxyScheme::Socks5));
    }

    // A malformed `<child>.host` drops only that one child
    // and is recorded on `Manual.rejected`, instead of failing the whole schema the
    // way `?` used to.
    #[test]
    fn malformed_child_hosts_are_dropped_and_recorded() {
        for label in ["mixed", "use_same_proxy", "lone_socks"] {
            let settings = match label {
                "mixed" => settings! {
                    "mode" => "manual",
                    "use-same-proxy" => false,
                    "http.host" => "http.corp",
                    "https.host" => "not a host with spaces",
                    "ftp.host" => "ftp.corp",
                },
                "use_same_proxy" => settings! {
                    "mode" => "manual",
                    "use-same-proxy" => true,
                    "http.host" => "not a host with spaces",
                },
                "lone_socks" => settings! {
                    "mode" => "manual",
                    "use-same-proxy" => false,
                    "socks.host" => "not a host with spaces",
                },
                _ => unreachable!(),
            };
            let mode = mode_from_settings(&settings).unwrap();
            match label {
                "mixed" => {
                    assert_eq!(
                        mode.endpoint_for(Scheme::Http).unwrap().authority(),
                        "http.corp:8080"
                    );
                    assert_eq!(
                        mode.endpoint_for(Scheme::Ftp).unwrap().authority(),
                        "ftp.corp:8080"
                    );
                    assert!(mode.endpoint_for(Scheme::Https).is_none());
                    assert_eq!(
                        mode.rejected().unwrap()[0].redacted_input(),
                        "not a host with spaces"
                    );
                }
                "use_same_proxy" => {
                    assert!(!mode.is_direct());
                    assert!(mode.endpoint_for(Scheme::Http).is_none());
                    assert_eq!(
                        mode.rejected().unwrap()[0].redacted_input(),
                        "not a host with spaces"
                    );
                }
                "lone_socks" => {
                    assert!(mode.endpoint_for(Scheme::Socks).is_none());
                    assert!(mode.endpoint_for(Scheme::Http).is_none());
                    assert_eq!(
                        mode.rejected().unwrap()[0].redacted_input(),
                        "not a host with spaces"
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    // The composed fix this round adds: a rejected `socks.host` costs `manual_mode`'s SOCKS
    // catch-all too, not just its own scheme, so it must be attributed to `Scheme::All`
    // (not `Scheme::Socks`) *and* must not let the `None if socks.is_none()` branch fill
    // `http` with `Disabled` before `resolve` ever consults `rejected`. Either half missing
    // and this falls through to `Ok(Direct)` instead of naming the drop.
    #[cfg(feature = "resolve")]
    #[test]
    fn an_unusable_socks_child_is_reported_for_a_scheme_it_would_have_covered() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => false,
            "socks.host" => "not a host with spaces",
        };
        let config = crate::ProxyConfig::new(mode_from_settings(&settings).unwrap(), Vec::new());
        let url = url::Url::parse("http://intranet.corp/x").unwrap();
        let err = crate::resolve(&config, &url).unwrap_err();
        assert!(
            matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                if *scheme == Scheme::All),
            "{err:?}"
        );
    }

    // The same rule one child over. Under `use-same-proxy` the `http` child *is* the
    // catch-all, so a malformed `http.host` costs every scheme that named nothing — and the
    // URL here cannot be `http://`, because `Scheme::Http` is what the attribution used to
    // say and `http://` would find the record either way. `https` is the one that could not.
    #[cfg(feature = "resolve")]
    #[test]
    fn an_unusable_http_child_is_reported_for_the_schemes_use_same_proxy_gave_it() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => true,
            "http.host" => "not a host with spaces",
        };
        let config = crate::ProxyConfig::new(mode_from_settings(&settings).unwrap(), Vec::new());
        for url in ["https://intranet.corp/x", "ftp://intranet.corp/x"] {
            let err = crate::resolve(&config, &url::Url::parse(url).unwrap()).unwrap_err();
            assert!(
                matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                    if *scheme == Scheme::All),
                "{url}: {err:?}"
            );
        }
    }

    // A schema old enough not to declare `use-same-proxy` leaves the key out of the map
    // altogether — `gnome::read_key` skips what `has_key` denies — and the branch that routes
    // and the attribution inside `endpoint_for` have to read that absence the same way. They
    // do, by both asking for `Some(true)`: with no key there is no catch-all, so the `http`
    // child answers for `http` alone and the record for its malformed host is filed under
    // that scheme. Read instead as the default the schema documents, the branch would take
    // the catch-all while the attribution stayed narrow, and `https` would answer Direct with
    // the drop that took its proxy away sitting unreachable in `rejected`.
    #[cfg(feature = "resolve")]
    #[test]
    fn a_schema_that_never_declared_use_same_proxy_is_not_a_catch_all() {
        let settings = settings! {
            "mode" => "manual",
            "http.host" => "not a host with spaces",
        };
        let config = crate::ProxyConfig::new(mode_from_settings(&settings).unwrap(), Vec::new());
        // `https` inherits the `http` child when it names no host of its own, so it carries
        // its own copy of the record; `ftp` inherits nothing and is left going direct.
        for (url, expected) in [
            ("http://intranet.corp/x", Scheme::Http),
            ("https://intranet.corp/x", Scheme::Https),
        ] {
            let err = crate::resolve(&config, &url::Url::parse(url).unwrap()).unwrap_err();
            assert!(
                matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                    if *scheme == expected),
                "{url}: {err:?}"
            );
        }
        assert_eq!(
            crate::resolve(&config, &url::Url::parse("ftp://intranet.corp/x").unwrap()).unwrap(),
            vec![crate::ProxyStep::Direct]
        );
    }

    // The `mixed` case above carried one step further, to the half only `resolve` can show.
    // `endpoint_for` answers `None` for a child with no host and for one whose host would
    // not parse, and only the first of those is "configured to go direct" — writing
    // `Disabled` for the second answers Direct while `rejected` holds the record saying the
    // scheme was meant to be proxied.
    #[cfg(feature = "resolve")]
    #[test]
    fn a_child_whose_own_host_was_rejected_is_not_recorded_as_disabled() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => false,
            "http.host" => "http.corp",
            "https.host" => "not a host with spaces",
        };
        let config = crate::ProxyConfig::new(mode_from_settings(&settings).unwrap(), Vec::new());
        let url = url::Url::parse("https://intranet.corp/x").unwrap();
        let err = crate::resolve(&config, &url).unwrap_err();
        assert!(
            matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                if *scheme == Scheme::Https),
            "{err:?}"
        );
    }

    // Turning `use-same-proxy` off narrows what the `http` child covers but does not empty
    // it: `https` still inherits it when that child names no host, so a malformed
    // `http.host` costs two schemes an answer and each must find its own record. `ftp` is
    // the control — the schema gives it no such rule, so it goes Direct here, which is what
    // a single `Scheme::All` attribution would have got wrong in the other direction.
    #[cfg(feature = "resolve")]
    #[test]
    fn an_unusable_http_child_is_reported_for_the_https_that_would_have_inherited_it() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => false,
            "http.host" => "not a host with spaces",
        };
        let config = crate::ProxyConfig::new(mode_from_settings(&settings).unwrap(), Vec::new());
        for (url, expected) in [
            ("http://intranet.corp/x", Scheme::Http),
            ("https://intranet.corp/x", Scheme::Https),
        ] {
            let err = crate::resolve(&config, &url::Url::parse(url).unwrap()).unwrap_err();
            assert!(
                matches!(&err, crate::Error::ProxyEntryUnusable { scheme, .. }
                    if *scheme == expected),
                "{url}: {err:?}"
            );
        }

        let url = url::Url::parse("ftp://intranet.corp/x").unwrap();
        let steps = crate::resolve(&config, &url).unwrap();
        assert!(
            matches!(steps.as_slice(), [crate::ProxyStep::Direct]),
            "{steps:?}"
        );
    }

    // The `ftp` child names the proxy *for* FTP destinations, not one spoken to in FTP, so
    // the hop is HTTP. Elsewhere only the SOCKS child's hint is read back, so this test is
    // the only thing holding the two other readings of this child — and both fail in a
    // direction nothing else here catches. An FTP hint has no transport behind it in the
    // GNOME stack at all, and
    // recording the child as unsupported instead answers Direct for a machine that has a
    // proxy configured. The `CHILDREN` entry carries the sources.
    #[cfg(feature = "resolve")]
    #[test]
    fn the_ftp_child_is_reported_as_an_http_hop() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => false,
            "ftp.host" => "ftp-proxy.corp",
            "ftp.port" => 2121i32,
        };
        let config = crate::ProxyConfig::new(mode_from_settings(&settings).unwrap(), Vec::new());
        let url = url::Url::parse("ftp://files.example/x").unwrap();
        let steps = crate::resolve(&config, &url).unwrap();
        assert!(
            matches!(steps.as_slice(), [crate::ProxyStep::Http(endpoint)]
                if endpoint.authority() == "ftp-proxy.corp:2121"),
            "{steps:?}"
        );
    }

    // The record an inheriting `https` gets a copy of is specifically the `http` child's, and
    // the tests above all arrange for that to be the only drop there is, so nothing there
    // separates it from whichever record comes first. Here the `ftp` child is the one that
    // failed, `https` still inherits a working `http` endpoint, and the copy lands in a slot
    // `entry_for` never consults. The list is what a caller reads to say which key was lost
    // and what it cost, and the copy says `https` lost an `ftp.host` it was never going to use.
    #[test]
    fn only_the_http_drop_is_copied_onto_an_inheriting_https() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => false,
            "http.host" => "http.corp",
            "ftp.host" => "not a host with spaces",
        };
        let mode = mode_from_settings(&settings).unwrap();
        let rejected = mode.rejected().expect("manual carries a list");
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0].affected_scheme(), Some(Scheme::Ftp));
        // `affected_scheme` says who lost a proxy; `source` says which key to go fix, and
        // it is the only half a user can act on. Nothing else on either Linux backend reads
        // it back, so without this row the `format!` that composes it can name any child or
        // any key — `http.host` for an `ftp` drop, `ftp.port` for a host — and send the
        // reader to a setting that is not the one that failed.
        assert_eq!(
            rejected[0].source(),
            &RejectionSource::GSettings("ftp.host".to_owned())
        );
    }

    // All four children, and not only the two an obvious reading of this row would name.
    // The other two are the ones whose numbers nothing else reaches: `https` at 8080 can be
    // set to the scheme's own 80 — exactly the value [`ChildKeys::default_port`] argues
    // against — with nothing else on the Linux side seeing it, and `ftp` is held only in passing,
    // by a test about malformed hosts. `https` and `ftp` are also the two that arrive here
    // by doing nothing at all: their schema default *is* `0`, so an administrator who
    // filled in a host and left the port alone lands on this number rather than on one
    // they chose.
    #[test]
    fn a_zero_port_falls_back_to_the_source_default() {
        let settings = settings! {
            "mode" => "manual",
            "http.host" => "proxy.corp",
            "http.port" => 0i32,
            "https.host" => "secure.corp",
            "https.port" => 0i32,
            "ftp.host" => "files.corp",
            "ftp.port" => 0i32,
            "socks.host" => "socks.corp",
            "socks.port" => 0i32,
        };
        let mode = mode_from_settings(&settings).unwrap();
        assert_eq!(mode.endpoint_for(Scheme::Http).unwrap().port, 8080);
        assert_eq!(mode.endpoint_for(Scheme::Https).unwrap().port, 8080);
        assert_eq!(mode.endpoint_for(Scheme::Ftp).unwrap().port, 8080);
        assert_eq!(mode.endpoint_for(Scheme::Socks).unwrap().port, 1080);
    }

    #[test]
    fn a_child_without_a_host_is_disabled_and_suppresses_the_all_fallback() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => false,
            "http.host" => "proxy.corp",
            "ftp.host" => "",
        };
        let mode = mode_from_settings(&settings).unwrap();
        assert!(
            mode.entry_for(Scheme::Ftp)
                .expect("ftp entry")
                .is_disabled()
        );
        assert!(mode.endpoint_for(Scheme::Ftp).is_none());
    }

    // `""` above is GNOME's own spelling of "not configured", and the row for it is the only
    // other thing holding [`GnomeSettings::text`]. The trim in front of that check answers to
    // this test alone, and a
    // host key reaches this crate through a text entry field and `gsettings set` alike, so
    // spaces around it are what a person types rather than what the schema stores. Untrimmed,
    // the padded host below stops parsing and the blank one starts counting as configured:
    // both become drops, and the second takes `https`' inheritance with it, because a child
    // that holds *something* is a child that named a host of its own.
    #[test]
    fn a_host_key_is_trimmed_and_blanks_read_as_unset() {
        let settings = settings! {
            "mode" => "manual",
            "http.host" => "  proxy.corp  ",
            "https.host" => "   ",
        };
        let mode = mode_from_settings(&settings).unwrap();
        for scheme in [Scheme::Http, Scheme::Https] {
            assert_eq!(
                mode.endpoint_for(scheme).unwrap().authority(),
                "proxy.corp:8080",
                "{scheme}"
            );
        }
        assert!(mode.rejected().expect("manual carries a list").is_empty());
    }

    // A SOCKS child catches every scheme that named nothing of its own, whether or not
    // anything else is configured and whichever way `use-same-proxy` is set. Both
    // readers of the schema do this — glib-networking through `set_default_proxy()`,
    // Chromium through `fallback_proxies` — and the crate does it on Windows too.
    #[test]
    fn a_socks_child_catches_every_scheme_that_named_nothing() {
        // `use-same-proxy` is not the switch that decides this, so both settings of it
        // are here; `true` is the one the schema defaults to, and the one a GNOME user
        // who only ever filled in a SOCKS proxy is actually running under.
        for same_proxy in [true, false] {
            let settings = settings! {
                "mode" => "manual",
                "use-same-proxy" => same_proxy,
                "socks.host" => "socks.corp",
                "socks.port" => 1081i32,
            };
            let mode = mode_from_settings(&settings).unwrap();
            for scheme in [Scheme::Http, Scheme::Https, Scheme::Ftp, Scheme::Socks] {
                let endpoint = mode.endpoint_for(scheme).unwrap_or_else(|| {
                    panic!("{scheme} should fall back to the SOCKS proxy (same_proxy={same_proxy})")
                });
                assert_eq!(endpoint.authority(), "socks.corp:1081");
                assert_eq!(
                    endpoint.scheme_hint,
                    Some(ProxyScheme::Socks5),
                    "{scheme} must keep the SOCKS5 hint after falling back"
                );
            }
        }
    }

    // Chromium's `num_proxies_specified == 1` guard picks the *encoding* — one proxy
    // list for everything, or per-scheme lists with SOCKS in `fallback_proxies` — not
    // the outcome. A second configured child therefore keeps its own scheme and leaves
    // the rest on SOCKS, rather than sending them Direct.
    #[test]
    fn socks_alongside_http_still_catches_the_rest() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => false,
            "http.host" => "http.corp",
            "http.port" => 3128i32,
            "socks.host" => "socks.corp",
            "socks.port" => 1081i32,
        };
        let mode = mode_from_settings(&settings).unwrap();
        assert_eq!(
            mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "http.corp:3128",
            "a child with its own host is never overridden by the catch-all"
        );
        assert_eq!(
            mode.endpoint_for(Scheme::Socks).unwrap().authority(),
            "socks.corp:1081"
        );
        assert_eq!(
            mode.endpoint_for(Scheme::Ftp).unwrap().authority(),
            "socks.corp:1081",
            "ftp named no proxy, so the SOCKS child carries it"
        );
        // `https` is the exception the schema writes out, and it outranks the catch-all:
        // glib gives it the HTTP proxy with `set_uri_proxy()`, which is consulted before
        // the `set_default_proxy()` the SOCKS child installs.
        assert_eq!(
            mode.endpoint_for(Scheme::Https).unwrap().authority(),
            "http.corp:3128"
        );
    }

    // "If an http proxy is configured, but an https proxy is not, then the http proxy is
    // also used for https" — the `mode` key's own description, stated apart from
    // `use-same-proxy`. `ftp` is the control: the schema gives it no such rule, and a fix
    // that reached for `Scheme::All` instead would carry `ftp` along unnoticed.
    #[test]
    fn an_absent_https_child_inherits_the_http_proxy_and_ftp_does_not() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => false,
            "http.host" => "http.corp",
            "http.port" => 3128i32,
        };
        let mode = mode_from_settings(&settings).unwrap();
        assert_eq!(
            mode.endpoint_for(Scheme::Https).unwrap().authority(),
            "http.corp:3128"
        );
        assert!(
            mode.entry_for(Scheme::Ftp)
                .expect("ftp entry")
                .is_disabled()
        );
        assert!(mode.endpoint_for(Scheme::Ftp).is_none());
    }

    #[test]
    fn use_same_proxy_puts_the_http_child_under_all() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => true,
            "http.host" => "proxy.corp",
            "http.port" => 8080i32,
        };
        let mode = mode_from_settings(&settings).unwrap();
        // Every scheme resolves through the `All` fallback.
        for scheme in [Scheme::Http, Scheme::Https, Scheme::Ftp, Scheme::Socks] {
            assert_eq!(
                mode.endpoint_for(scheme).unwrap().authority(),
                "proxy.corp:8080",
                "{scheme} should fall back to the shared proxy"
            );
        }
        // "Written to `Scheme::All` rather than to `Scheme::Http`" is what `endpoint_for`'s
        // attribution comment reasons from, and the loop above cannot see it: an `Http` entry
        // holding the same endpoint answers identically through every scheme, so this
        // assertion is the only thing that would see the http child written to its own key as
        // well. `per_scheme` is a
        // public field, so the duplicate reaches anyone who renders the configuration instead
        // of resolving through it, and it puts the map at odds with the prose that decides
        // where a malformed `http.host` is attributed.
        let ProxyMode::Manual { per_scheme, .. } = &mode else {
            panic!("{mode:?}");
        };
        assert_eq!(per_scheme.keys().collect::<Vec<_>>(), [&Scheme::All]);
    }

    #[test]
    fn a_child_with_its_own_host_overrides_use_same_proxy() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => true,
            "http.host" => "proxy.corp",
            "socks.host" => "socks.corp",
            "socks.port" => 1081i32,
        };
        let mode = mode_from_settings(&settings).unwrap();
        assert_eq!(
            mode.endpoint_for(Scheme::Https).unwrap().authority(),
            "proxy.corp:8080"
        );
        assert_eq!(
            mode.endpoint_for(Scheme::Socks).unwrap().authority(),
            "socks.corp:1081",
            "a concrete scheme always wins over All"
        );
    }

    #[test]
    fn ipv6_hosts_are_bracketed_back() {
        let settings = settings! {
            "mode" => "manual",
            "socks.host" => "::1",
            "socks.port" => 1081i32,
        };
        let mode = mode_from_settings(&settings).unwrap();
        assert_eq!(
            mode.endpoint_for(Scheme::Socks).unwrap().authority(),
            "[::1]:1081"
        );
    }

    #[test]
    fn a_host_stored_as_a_url_keeps_its_scheme_hint() {
        let settings = settings! {
            "mode" => "manual",
            "socks.host" => "socks4://socks.corp",
        };
        let mode = mode_from_settings(&settings).unwrap();
        let socks = mode.endpoint_for(Scheme::Socks).unwrap();
        assert_eq!(
            socks.scheme_hint,
            Some(ProxyScheme::Socks4),
            "an explicit scheme must not be overwritten by the SOCKS5 default hint"
        );
    }

    #[test]
    fn ignore_hosts_becomes_bypass_rules() {
        let list: &[&str] = &["localhost", "10.0.0.0/8", "::1", "*.corp.example"];
        let settings = settings! {
            "mode" => "manual",
            "http.host" => "proxy.corp",
            "ignore-hosts" => list,
        };
        let mode = mode_from_settings(&settings).unwrap();
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        // A range outside the implicit set, because a range inside it holds nothing here:
        // all of `127.0.0.0/8` is `is_loopback`, so `127.0.0.1` bypasses whether the CIDR
        // entry parsed or not and the assertion would pass either way. `localhost` and
        // `::1` stay in the list as the shape a real `ignore-hosts` has — what they cover
        // is held by name in `tests/bypass.rs`, not here.
        assert!(bypass.matches_authority("10.1.2.3"));
        assert!(!bypass.matches_authority("11.1.2.3"));
        assert!(bypass.matches_authority("api.corp.example"));
        // The domain itself, which reading `*.` as "subdomains only" denies. GLib strips it
        // and stores `corp.example` as a plain name (`gsimpleproxyresolver.c:227`), then
        // matches it with `offset == 0` permitted (`:311`) — so on GNOME the three
        // spellings `corp.example`, `.corp.example` and `*.corp.example` are one rule
        // covering the domain and everything under it. `*.` narrowing to the subdomains is
        // the majority reading, not this one.
        assert!(bypass.matches_authority("corp.example"));
        assert!(!bypass.matches_authority("example.net"));
        // Not a string suffix: the boundary is still a label.
        assert!(!bypass.matches_authority("xcorp.example"));
    }

    /// GLib's only wildcard is the leading `*.`, and it strips that rather than matching
    /// it; every other `*` stays in the name it then compares whole
    /// (`gsimpleproxyresolver.c:227-231`, `:312`), and no host contains one. Its trim is
    /// `g_strchomp` (`:183`), the trailing end only, so a leading space stays in the name
    /// and kills the rule the same way.
    ///
    /// This test is the only thing holding either shape. Read through the majority dialect
    /// instead, `foo*.corp.example` bypasses `foo1.corp.example` and ` lead.example` bypasses
    /// `lead.example` — both destinations GNOME sends to the proxy, reported as direct.
    /// Refused rather than stored, so the entry is visible in `rejected` instead of sitting
    /// in the list looking live.
    ///
    /// The bare `*` is the same rule and the largest version of it. `HostPattern::All` is
    /// reached by every dialect except macOS, so read that way a GNOME `ignore-hosts` of
    /// `['*']` switches the proxy off for every destination while GLib stores the `*` whole
    /// and matches it against none. Held here by the negatives below rather than by a row of
    /// its own, because under that reading the star answers for the entire list and there is
    /// no destination left to assert about.
    #[test]
    fn gnome_reads_a_star_literally_and_trims_only_the_tail() {
        let list: &[&str] = &[
            "*",
            "foo*.corp.example",
            "*.bar*.corp.example",
            " lead.example",
            "trail.example ",
            ".dot.example",
        ];
        let settings = settings! {
            "mode" => "manual",
            "http.host" => "proxy.corp",
            "ignore-hosts" => list,
        };
        let mode = mode_from_settings(&settings).unwrap();
        let bypass = mode.bypass().expect("manual mode has bypass rules");

        for host in [
            "foo1.corp.example",
            "foo.corp.example",
            "bar1.corp.example",
            // Under no rule in this list at all, which is what the bare `*` costs: read as
            // `HostPattern::All` it answers for this host and every other one.
            "unrelated.example",
        ] {
            assert!(
                !bypass.matches_authority(host),
                "{host} is not a GNOME rule"
            );
        }
        assert!(!bypass.matches_authority("lead.example"));

        // What survives: the tail is chomped, and the `.` prefix is the same rule as the
        // bare name — domain and subdomains alike.
        assert!(bypass.matches_authority("trail.example"));
        assert!(bypass.matches_authority("api.trail.example"));
        assert!(bypass.matches_authority("dot.example"));
        assert!(bypass.matches_authority("api.dot.example"));

        // The entries that match nothing are recorded rather than dropped, the bare `*`
        // among them and under the same reason string as the rest.
        let refused: Vec<_> = bypass
            .rejected
            .iter()
            .map(RejectedValue::redacted_input)
            .collect();
        assert_eq!(
            refused,
            [
                "*",
                "foo*.corp.example",
                "*.bar*.corp.example",
                " lead.example"
            ]
        );
    }

    /// GLib asks its own matcher about the port the destination wrote, and about 0 when it
    /// wrote none — `G_URI_FLAGS_NONE` at `gsimpleproxyresolver.c:341`, with the default
    /// port filled only under `G_URI_FLAGS_SCHEME_NORMALIZE` (`guri.c:1006`). This is the
    /// reader's half of that; `resolve`'s half is
    /// `a_bypass_list_that_wants_an_explicit_port_does_not_get_a_default_one`.
    #[test]
    fn ignore_hosts_asks_resolve_not_to_infer_a_port() {
        let list: &[&str] = &["intranet.corp:80"];
        let settings = settings! {
            "mode" => "manual",
            "http.host" => "proxy.corp",
            "ignore-hosts" => list,
        };
        let mode = mode_from_settings(&settings).unwrap();
        assert!(mode.bypass().unwrap().require_explicit_port);

        // Not a property of every rule set this crate builds — the flag names GNOME and
        // only GNOME, so a Windows list of the same shape must not carry it.
        assert!(!parse::proxy_override("intranet.corp:80").require_explicit_port);
        assert!(!parse::no_proxy("intranet.corp:80").require_explicit_port);
    }

    // `ignore-hosts` arrives as an array, where the boundary between entries is the array
    // itself. Feeding it to a parser that looks for a separator character reintroduces one
    // and reads a comma inside an element as an entry boundary the desktop never saw:
    // GNOME matches `a.example,b.example` against a host of that exact name and so bypasses
    // nothing, while this crate would report two working bypass rules and send both hosts
    // direct. A mistyped `gsettings set … "['a.example,b.example']"` is all it takes.
    #[test]
    fn a_separator_inside_one_ignore_hosts_element_is_not_an_entry_boundary() {
        let list: &[&str] = &["a.example,b.example", "c.example;d.example"];
        let settings = settings! {
            "mode" => "manual",
            "http.host" => "proxy.corp",
            "ignore-hosts" => list,
        };
        let mode = mode_from_settings(&settings).unwrap();
        let bypass = mode.bypass().expect("manual mode has bypass rules");
        for host in ["a.example", "b.example", "c.example", "d.example"] {
            assert!(
                !bypass.matches_authority(host),
                "{host} is half of an element, not an entry of its own"
            );
        }
        assert!(bypass.matches_authority("a.example,b.example"));
        assert!(bypass.matches_authority("c.example;d.example"));
    }

    #[test]
    fn authentication_needs_the_flag_and_the_user() {
        let without_flag = settings! {
            "mode" => "manual",
            "http.host" => "proxy.corp",
            "http.authentication-user" => "alice",
        };
        assert!(
            mode_from_settings(&without_flag)
                .unwrap()
                .endpoint_for(Scheme::Http)
                .unwrap()
                .auth
                .is_none(),
            "use-authentication = false must not produce credentials"
        );

        let with_flag = settings! {
            "mode" => "manual",
            "http.host" => "proxy.corp",
            "http.use-authentication" => true,
            "http.authentication-user" => "alice",
        };
        let auth = mode_from_settings(&with_flag)
            .unwrap()
            .endpoint_for(Scheme::Http)
            .unwrap()
            .auth
            .clone()
            .expect("authentication-user");
        assert_eq!(auth.username(), "alice");
        assert!(
            !auth.has_password(),
            "nothing supplied a password here and this mapper does not invent one. That \
             the live reader never supplies one is `gnome::READ_AUTHENTICATION_PASSWORD`, \
             which no test on this side can reach — and the next test shows this mapper \
             maps a password perfectly well once something hands it one"
        );
    }

    #[test]
    fn an_opted_in_password_is_masked_in_debug() {
        let settings = settings! {
            "mode" => "manual",
            "http.host" => "proxy.corp",
            "http.use-authentication" => true,
            "http.authentication-user" => "alice",
            "http.authentication-password" => "hunter2",
        };
        let mode = mode_from_settings(&settings).unwrap();
        let auth = mode.endpoint_for(Scheme::Http).unwrap().auth.clone();
        assert_eq!(auth.as_ref().unwrap().password(), Some("hunter2"));
        assert!(
            !format!("{mode:?}").contains("hunter2"),
            "a password must never reach a Debug rendering"
        );
    }

    #[test]
    fn a_store_nobody_wrote_to_and_no_proxy_is_unset() {
        // What `gsettings reset-recursively org.gnome.system.proxy` leaves behind: the
        // schema defaults, and nothing written by anybody.
        let settings = settings! { "mode" => "none", "http.host" => "", "http.port" => 0i32 };
        assert_eq!(configured_mode(&settings).unwrap(), None);
        assert_eq!(configured_mode(&GnomeSettings::new()).unwrap(), None);
    }

    #[test]
    fn an_explicit_mode_none_is_configured_direct() {
        // Either spelling of "somebody wrote it" reaches here identically: the user's own
        // dconf layer, or an administrator's profile that `gnome::read_key` detected by
        // the key's default differing from the compiled schema's.
        let mut settings = settings! { "mode" => "none" };
        settings.mark_written("mode");
        assert_eq!(
            configured_mode(&settings).unwrap(),
            Some(ProxyMode::Direct),
            "somebody wrote mode='none'; that is a decision, not an absent store"
        );
    }

    #[test]
    fn a_written_value_on_any_key_configures_the_store() {
        // GNOME Settings switched back to "Off": `mode` is `none` again, but the host the
        // user typed is still in the user's dconf database.
        let mut settings = settings! { "mode" => "none", "http.host" => "proxy.corp" };
        settings.mark_written("http.host");
        assert_eq!(configured_mode(&settings).unwrap(), Some(ProxyMode::Direct));
    }

    #[test]
    fn a_proxy_nobody_marked_as_written_is_still_configured() {
        // The value itself carries the decision, so this holds even if `read_key` never
        // noticed who set it — a proxy is real and must not be dropped.
        let settings = settings! { "mode" => "manual", "http.host" => "proxy.corp" };
        let mode = configured_mode(&settings)
            .unwrap()
            .expect("a real proxy is always configured");
        assert_eq!(
            mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "proxy.corp:8080"
        );
    }

    #[test]
    fn authentication_only_applies_to_the_http_child() {
        let settings = settings! {
            "mode" => "manual",
            "use-same-proxy" => false,
            "http.host" => "proxy.corp",
            "https.host" => "secure.corp",
            "http.use-authentication" => true,
            "http.authentication-user" => "alice",
        };
        let mode = mode_from_settings(&settings).unwrap();
        assert!(mode.endpoint_for(Scheme::Http).unwrap().auth.is_some());
        assert!(mode.endpoint_for(Scheme::Https).unwrap().auth.is_none());

        // That row only shows an `http.` key not reaching the `https` child, which is
        // `child_key`'s prefixing and would hold with no guard in `endpoint_for` at all. The
        // case the name promises is the other one: the keys spelled for a child that has
        // none. No machine produces this map — `gnome.rs` reads them off the `http` child
        // alone, and `read_key` drops what the schema does not declare — so the guard here is
        // what makes the mapper answer the same way read on its own terms, without standing
        // on how its only caller happens to fill the map today.
        let spelled_for_another_child = settings! {
            "mode" => "manual",
            "use-same-proxy" => false,
            "https.host" => "secure.corp",
            "https.use-authentication" => true,
            "https.authentication-user" => "alice",
        };
        assert!(
            mode_from_settings(&spelled_for_another_child)
                .unwrap()
                .endpoint_for(Scheme::Https)
                .unwrap()
                .auth
                .is_none()
        );
    }
}
