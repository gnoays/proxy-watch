//! The environment variable snapshot type.

use std::collections::HashMap;
use std::fmt;
use std::time::SystemTime;

use crate::bypass::BypassRules;
use crate::config::{ProxyConfig, ProxyConfigSource};
use crate::diagnostic::{RejectedValue, RejectionKind, RejectionSource};
use crate::endpoint::{ProxyEndpoint, ProxyEntry, Scheme};
use crate::error::Error;
use crate::mode::ProxyMode;
use crate::parse;

/// The variable whose presence *with a method in it* marks a CGI environment (see
/// [`Error::CgiHttpProxy`]).
pub const CGI_MARKER_VAR: &str = "REQUEST_METHOD";

// Lowercase variable name for each scheme, in the order they are looked up.
const SCHEME_VARS: [(Scheme, &str); 4] = [
    (Scheme::Http, "http_proxy"),
    (Scheme::Https, "https_proxy"),
    (Scheme::Ftp, "ftp_proxy"),
    (Scheme::All, "all_proxy"),
];

const NO_PROXY_VAR: &str = "no_proxy";

/// Env snapshot of `*_proxy` / `no_proxy` (not a [`Stream`](crate::Stream);
/// [`ProxyWatcher`](crate::ProxyWatcher) does not merge these in — except where an OS
/// setting names them, which KDE's `ProxyType=4` does).
///
/// Lowercase beats uppercase; empty value → [`ProxyEntry::Disabled`]; port explicit, else
/// the `scheme://` default, else 80 (so `all_proxy=socks5://h` is 1080, `http_proxy=h` is
/// 80) — the rule [`ProxyEndpoint::parse`] states. On Windows only,
/// any other letter case the variable was actually set in (`Http_Proxy`) is read too, after
/// both conventional spellings. `no_proxy` via [`parse::no_proxy`]. Bad `*_proxy` →
/// [`rejected`](Self::rejected). A **non-empty** `REQUEST_METHOD` + `http_proxy` →
/// [`Error::CgiHttpProxy`]. Merge with a watcher is caller-defined precedence.
#[derive(Clone)]
pub struct ProxyEnv {
    per_scheme: HashMap<Scheme, ProxyEntry>,
    bypass: BypassRules,
    rejected: Vec<RejectedValue>,
    captured_at: SystemTime,
}

impl ProxyEnv {
    /// Read the snapshot from the current process environment.
    ///
    /// [`std::env::vars`] panics on a variable whose name or value is not valid Unicode,
    /// so this reads [`std::env::vars_os`] instead: one unrelated variable elsewhere in
    /// the process must not be able to take the whole snapshot down. What that costs is
    /// split by half: a variable whose *name* is not valid Unicode is none of the ones
    /// read here, so it is dropped, while a mangled *value* is kept and refused — it
    /// lands in [`rejected`](Self::rejected) rather than reading as unset.
    ///
    /// # Errors
    ///
    /// [`Error::CgiHttpProxy`] in a CGI environment carrying an `http_proxy`
    /// variable. A malformed value is no longer one of these, but the two kinds are
    /// recorded apart: a dropped `*_proxy` endpoint lands in
    /// [`rejected`](Self::rejected), a dropped `no_proxy` entry in
    /// [`bypass()`](Self::bypass)`.rejected`. Reading only the first and finding it
    /// empty says nothing about the second.
    pub fn from_env() -> Result<Self, Error> {
        Self::from_vars(std::env::vars_os().filter_map(readable_var))
    }

    /// Explicit map for tests (avoids mutating the process-global env).
    ///
    /// ```
    /// # use proxy_watch::{ProxyEnv, Scheme};
    /// let env = ProxyEnv::from_vars([
    ///     ("HTTP_PROXY", "http://upper:8080"),
    ///     ("http_proxy", "http://lower:8080"),
    ///     ("no_proxy", "*.internal"),
    /// ])
    /// .unwrap();
    /// // Lowercase wins.
    /// let endpoint = env.endpoint_for(Scheme::Http).unwrap();
    /// assert_eq!(endpoint.host.to_string(), "lower");
    /// assert!(env.bypass().matches_authority("api.internal"));
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::CgiHttpProxy`] when a non-empty `REQUEST_METHOD` and an `http_proxy` are
    /// both present. Malformed values are recorded instead of returned; see
    /// [`from_env`](Self::from_env) for which of the two lists each kind reaches.
    pub fn from_vars<I, K, V>(vars: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let map: HashMap<String, String> = vars
            .into_iter()
            .map(|(k, v)| (k.as_ref().to_owned(), v.as_ref().to_owned()))
            .collect();

        // CGI marker: exact + Windows any-case, and it has to carry a method. Presence
        // alone is not the test — Go reads it as `os.Getenv("REQUEST_METHOD") != ""`
        // (`httpproxy.FromEnvironment`), and RFC 3875 §4.1.12 has no empty production for
        // it (`method = "GET" | "POST" | "HEAD" | extension-method`), so no conforming
        // CGI server ever sets it empty. Refuse any-case `http_proxy` (`min` for a stable
        // name).
        let in_cgi = map
            .get(CGI_MARKER_VAR)
            .or_else(|| any_case_on_windows(&map, CGI_MARKER_VAR).map(|(_, value)| value))
            .is_some_and(|method| !method.is_empty());
        if in_cgi
            && let Some(variable) = map
                .keys()
                .filter(|k| k.eq_ignore_ascii_case(SCHEME_VARS[0].1))
                .min()
        {
            return Err(Error::CgiHttpProxy {
                variable: variable.clone(),
            });
        }

        let mut per_scheme = HashMap::new();
        let mut rejected = Vec::new();
        for (scheme, name) in SCHEME_VARS {
            let Some(value) = lookup(&map, name) else {
                continue;
            };
            let trimmed = value.trim();
            if trimmed.is_empty() {
                per_scheme.insert(scheme, ProxyEntry::Disabled);
                continue;
            }
            match ProxyEndpoint::parse(trimmed, 80) {
                Ok(endpoint) => {
                    per_scheme.insert(scheme, ProxyEntry::Use(endpoint));
                }
                // The `WARN` compiles to nothing without the `tracing` feature, which is
                // what leaves `err` unused there; the `rejected` entry below is what
                // carries the drop either way.
                #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
                Err(err) => {
                    crate::trace::warning!(
                        variable = name,
                        error = %crate::trace::SafeError(&err),
                        "skipping an unparseable *_proxy value"
                    );
                    rejected.push(
                        RejectedValue::new(
                            RejectionKind::InvalidProxyEndpoint,
                            RejectionSource::EnvironmentVariable(name.to_owned()),
                            trimmed,
                        )
                        .for_scheme(Some(scheme)),
                    );
                }
            }
        }

        let bypass = match lookup(&map, NO_PROXY_VAR) {
            Some(value) => parse::no_proxy(value),
            None => BypassRules::new(),
        };

        Ok(Self {
            per_scheme,
            bypass,
            rejected,
            captured_at: SystemTime::now(),
        })
    }

    /// The parsed per-scheme entries. Never [`Unusable`](ProxyEntry::Unusable): a drop stays
    /// on [`rejected`](Self::rejected) alone until [`to_mode`](Self::to_mode) files it into
    /// the [`ProxyMode`]'s map, so a snapshot and the mode built from it differ here.
    #[must_use]
    pub fn per_scheme(&self) -> &HashMap<Scheme, ProxyEntry> {
        &self.per_scheme
    }

    /// The parsed `no_proxy` rules.
    #[must_use]
    pub fn bypass(&self) -> &BypassRules {
        &self.bypass
    }

    /// Redacted `*_proxy` values [`ProxyEndpoint::parse`] rejected (fail-open drop,
    /// not whole-snapshot failure). Threaded into [`ProxyMode`] via [`to_mode`](Self::to_mode).
    /// Not the `no_proxy` drops: those are exclusions rather than endpoints and stay on
    /// [`bypass()`](Self::bypass)`.rejected`. [`to_mode`](Self::to_mode) carries them
    /// across inside the [`BypassRules`], but only on the branch that returns a
    /// [`Manual`](ProxyMode::Manual): a snapshot holding nothing but a `no_proxy` is
    /// [`Direct`](ProxyMode::Direct), and an exclusion list with no proxy to be excluded
    /// from does not outlive the conversion.
    #[must_use]
    pub fn rejected(&self) -> &[RejectedValue] {
        &self.rejected
    }

    /// When the snapshot was taken. Excluded from equality comparisons.
    #[must_use]
    pub fn captured_at(&self) -> SystemTime {
        self.captured_at
    }

    /// No `*_proxy` set (malformed-but-present still counts as set via [`rejected`](Self::rejected)).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.per_scheme.is_empty() && self.rejected.is_empty()
    }

    /// Whether these variables *specify* a configuration — something the environment asked
    /// for, as opposed to something it merely mentioned.
    ///
    /// This neither implies [`is_empty`](Self::is_empty) nor follows from it, which is why
    /// both exist. `is_empty` answers "was any scheme variable set", counting a value that
    /// failed to parse and ignoring `no_proxy`; this one ignores the failures and counts
    /// `no_proxy`:
    ///
    /// | environment | `is_empty` | `is_configured` |
    /// | --- | --- | --- |
    /// | nothing set | `true` | `false` |
    /// | `http_proxy=http://p:8080` | `false` | `true` |
    /// | `http_proxy=` — a deliberate direct for http | `false` | `true` |
    /// | `no_proxy=.corp.example` alone | `true` | `true` |
    /// | every scheme variable malformed | `false` | `false` |
    ///
    /// The last two rows are the ones with consequences, and both follow Chromium's
    /// `net/proxy_resolution/proxy_config_service_linux.cc`. A `no_proxy` on its own is a
    /// configuration there — "having no rules specified only means the user explicitly asks
    /// for direct connections" — and a value that fails to parse is logged and then treated
    /// exactly as if the variable were unset. A malformed value is a diagnostic, kept in
    /// [`rejected`](Self::rejected); reading it as an instruction would let a typo in
    /// `http_proxy` mask a working OS proxy.
    ///
    /// [`ProxyConfig::with_env`](crate::ProxyConfig::with_env) is what acts on the
    /// distinction. [`to_mode`](Self::to_mode) does not: a `no_proxy` with no proxy to
    /// exclude from is still [`Direct`](ProxyMode::Direct), which is the same answer
    /// Chromium's config produces once it has no proxy servers in it.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        !self.per_scheme.is_empty() || !self.bypass.is_empty()
    }

    /// The endpoint for `scheme`, under the same [`Scheme::All`] fallback as
    /// [`ProxyMode::entry_for`](crate::ProxyMode::entry_for): `All` itself has none, and a
    /// [`Disabled`](ProxyEntry::Disabled) entry answers `None` instead of falling through.
    #[must_use]
    pub fn endpoint_for(&self, scheme: Scheme) -> Option<&ProxyEndpoint> {
        // Written the same way as [`ProxyMode::entry_for`], which is what the doc above
        // claims, and for the `All` case for the reason given there. `entry_for`'s one further
        // rule — step over a drop and let a later slot answer — has nothing to act on in this
        // map, which never holds one; the two stay the same lookup as long as that holds.
        self.per_scheme
            .get(&scheme)
            .or_else(|| self.per_scheme.get(&Scheme::All))?
            .endpoint()
    }

    /// Into [`ProxyMode`]: empty → [`Direct`](ProxyMode::Direct); else Manual (keeping
    /// [`rejected`](Self::rejected) even when every scheme value failed to parse).
    #[must_use]
    pub fn to_mode(&self) -> ProxyMode {
        // `is_empty` rather than its expression again: "empty" here is that method's
        // question, and two copies of it can only ever drift apart.
        if self.is_empty() {
            ProxyMode::Direct
        } else {
            ProxyMode::manual(self.per_scheme.clone(), self.bypass.clone())
                .with_rejected(self.rejected.clone())
        }
    }

    /// Convert the snapshot into a [`ProxyConfig`] attributed to
    /// [`ProxyConfigSource::Env`], carrying this snapshot's
    /// [`captured_at`](Self::captured_at) rather than the time of the conversion.
    #[must_use]
    pub fn to_config(&self) -> ProxyConfig {
        let mut config = ProxyConfig::from_source(ProxyConfigSource::Env, self.to_mode());
        // `from_source` stamps now, which is the wrong instant: the variables were read when
        // this snapshot was taken. A snapshot held and converted once per request would
        // otherwise hand back a `ProxyConfig` claiming to be fresh every time.
        config.captured_at = self.captured_at;
        config
    }
}

// Not a derive, only so that `per_scheme` prints in a fixed order — a `HashMap` seeds its
// iteration order per instance, so a derive would render the same snapshot differently on
// each run. [`ProxyMode`]'s own `Debug` says the rest.
impl fmt::Debug for ProxyEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyEnv")
            .field(
                "per_scheme",
                &self
                    .per_scheme
                    .iter()
                    .collect::<std::collections::BTreeMap<_, _>>(),
            )
            .field("bypass", &self.bypass)
            .field("rejected", &self.rejected)
            .field("captured_at", &self.captured_at)
            .finish()
    }
}

impl PartialEq for ProxyEnv {
    // Compares the parsed values only, ignoring `captured_at` (consistent with
    // [`ProxyConfig`]).
    fn eq(&self, other: &Self) -> bool {
        self.per_scheme == other.per_scheme
            && self.bypass == other.bypass
            && self.rejected == other.rejected
    }
}

impl Eq for ProxyEnv {}

// One environment variable as [`ProxyEnv::from_vars`] needs to see it.
//
// The two halves are not the same question. A *name* that is not valid Unicode cannot be
// any of the variables in [`SCHEME_VARS`] or [`NO_PROXY_VAR`], which are ASCII, so it is
// one of the unrelated variables sharing the process environment and dropping it changes
// no answer. A *value* is where `into_string().ok()` would be the misreading this crate
// keeps finding: it cannot tell "unset" from "set to bytes that are not UTF-8", and those
// are opposite answers here — a dropped `http_proxy` leaves the snapshot saying nobody
// configured a proxy at all, with nothing in [`ProxyEnv::rejected`] to say otherwise. So
// the value is converted the lossy way instead, which is what
// [`sys::linux::desktop::text_if_set`](crate::sys) and `kde`'s `ProxyType = 4` lookup do
// for the same reason: the replacement characters are what
// [`ProxyEndpoint::parse`] refuses the address on, so the variable is recorded rather than
// vanishing. That refusal reads the whole authority and not only the host — see the check
// itself for why a password in the authority is part of what it refuses on.
//
// Taking the pair rather than reading the environment so the split can be tested without
// a process-global variable.
fn readable_var(
    (name, value): (std::ffi::OsString, std::ffi::OsString),
) -> Option<(String, String)> {
    Some((
        name.into_string().ok()?,
        value.to_string_lossy().into_owned(),
    ))
}

// Lowercase name first, uppercase name second — then, on Windows only, whatever other
// letter case the variable was actually set in.
fn lookup<'a>(map: &'a HashMap<String, String>, lower: &str) -> Option<&'a str> {
    map.get(lower)
        .or_else(|| map.get(&lower.to_ascii_uppercase()))
        .or_else(|| any_case_on_windows(map, lower).map(|(_, value)| value))
        .map(String::as_str)
}

// The entry whose key equals `name` ignoring case — on Windows only, where that is the
// same variable rather than a different one.
fn any_case_on_windows<'a>(
    map: &'a HashMap<String, String>,
    name: &str,
) -> Option<(&'a String, &'a String)> {
    if !cfg!(windows) {
        return None;
    }
    map.iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .min_by_key(|(key, _)| *key)
}

// The tests below need an `OsString` that is not valid Unicode, and only Windows and Unix can
// build one; anywhere else they would run on an ordinary string and prove nothing. The gate
// is on the module and not on each test because an empty `mod tests` still carries its
// `use super::*`, and on `wasm32-unknown-unknown` — the one target that reaches `sys::stub` —
// that unused import is an error under `-D warnings`.
#[cfg(all(test, any(windows, unix)))]
mod tests {
    use super::*;

    // The impl above is hand-written for the whole struct, and its comment names only the
    // scheme order as the reason, so this test is the only thing holding the field list.
    // `captured_at` is the field `PartialEq` refuses to compare and `to_config` carries over
    // on purpose — it is how old the reading is — so a snapshot printed without it has no
    // age, and two taken minutes apart render identically.
    //
    // Exact string, so a label, a field order or the scheme order cannot change unseen. The
    // entries, the bypass rules and the timestamp keep their own renderings, which this impl
    // does not own, so the expectation defers to them rather than copying them out.
    #[test]
    fn the_env_debug_lists_every_field_and_sorts_the_schemes() {
        let env = ProxyEnv::from_vars([
            ("https_proxy", "http://secure.corp:8443"),
            ("http_proxy", "http://plain.corp:8080"),
            ("no_proxy", ".example.com"),
        ])
        .expect("no REQUEST_METHOD is set here");
        assert_eq!(
            format!("{env:?}"),
            format!(
                "ProxyEnv {{ per_scheme: {{Http: {:?}, Https: {:?}}}, bypass: {:?}, \
                 rejected: [], captured_at: {:?} }}",
                env.per_scheme[&Scheme::Http],
                env.per_scheme[&Scheme::Https],
                env.bypass,
                env.captured_at
            )
        );
    }

    // A variable set to bytes with no UTF-8 reading is *set*, and the answer this crate
    // exists to avoid is "nobody configured a proxy" when somebody did. Read with
    // `into_string().ok()` the variable arrived as absent, so a mangled `http_proxy` was
    // indistinguishable from an unset one — not even a `rejected` entry to look at.
    #[test]
    fn an_http_proxy_that_is_not_unicode_is_refused_rather_than_dropped() {
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

        let (name, value) = readable_var((std::ffi::OsString::from("http_proxy"), raw))
            .expect("a variable whose name is ASCII stays in the snapshot");
        let env = ProxyEnv::from_vars([(name, value)]).expect("no REQUEST_METHOD is set here");
        assert!(
            env.endpoint_for(Scheme::Http).is_none(),
            "replacement characters are not an address to send traffic to"
        );
        assert_eq!(
            env.rejected().len(),
            1,
            "the variable is set, so its drop has to be visible: {:?}",
            env.rejected()
        );
    }

    // The same promise, at the place it is hardest to keep. The test above puts the
    // undecodable byte where the whole value is the host, and a host never survives one. Put
    // it in the password instead and the address around it is well formed, so without the
    // authority-wide refusal in `ProxyEndpoint::parse` this reads `Ok`: the snapshot names
    // `proxy.corp:8080` with `rejected` empty and a secret the reader invented attached to it.
    #[test]
    fn a_password_that_is_not_unicode_is_refused_like_a_host_that_is_not() {
        #[cfg(windows)]
        let raw = {
            use std::os::windows::ffi::OsStringExt;
            let mut units: Vec<u16> = "http://alice:".encode_utf16().collect();
            units.push(0xD800);
            units.extend("@proxy.corp:8080".encode_utf16());
            std::ffi::OsString::from_wide(&units)
        };
        #[cfg(unix)]
        let raw = {
            use std::os::unix::ffi::OsStringExt;
            let mut bytes = b"http://alice:".to_vec();
            bytes.push(0xFF);
            bytes.extend_from_slice(b"@proxy.corp:8080");
            std::ffi::OsString::from_vec(bytes)
        };

        let (name, value) = readable_var((std::ffi::OsString::from("http_proxy"), raw))
            .expect("a variable whose name is ASCII stays in the snapshot");
        // Not vacuous: everything but the password is a perfectly ordinary address.
        assert!(value.contains("@proxy.corp:8080"), "{value}");

        let env = ProxyEnv::from_vars([(name, value)]).expect("no REQUEST_METHOD is set here");
        assert!(
            env.endpoint_for(Scheme::Http).is_none(),
            "a credential the reader had to invent is not one to offer a proxy"
        );
        assert_eq!(
            env.rejected().len(),
            1,
            "the variable is set, so its drop has to be visible: {:?}",
            env.rejected()
        );
    }

    // The other half: a name that cannot be one of the ASCII variables this crate reads is
    // dropped, and dropping it has to stay silent — every process carries some of these.
    #[test]
    fn a_variable_whose_name_is_not_unicode_is_dropped_without_a_trace() {
        #[cfg(windows)]
        let raw = {
            use std::os::windows::ffi::OsStringExt;
            std::ffi::OsString::from_wide(&[0xD800])
        };
        #[cfg(unix)]
        let raw = {
            use std::os::unix::ffi::OsStringExt;
            std::ffi::OsString::from_vec(vec![0xFF])
        };

        assert_eq!(
            readable_var((raw, std::ffi::OsString::from("http://p:8080"))),
            None
        );
    }
}
