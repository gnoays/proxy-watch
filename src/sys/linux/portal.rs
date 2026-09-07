//! XDG portal fallback when [`super::sandbox`] says GSettings would lie (`mode = 'none'`).
//!
//! `org.freedesktop.portal.ProxyResolver.Lookup` via `gio` D-Bus. Probes rebuild
//! [`ProxyMode::Manual`] (bypass always empty; PAC already resolved by host), or
//! [`ProxyMode::Direct`] when every probe answered `direct://`. No change
//! signal — needs [`WatchOptions::poll_interval`](crate::WatchOptions::poll_interval).
//!
//! <div class="warning">
//!
//! **Unverified:** no real Flatpak or Snap runtime has ever exercised this fallback. The
//! read itself is exercised — `tests/portal_watch.rs` puts a fake `ProxyResolver` on a
//! private session bus and drives [`read_mode`] through it — so what no test can reach is
//! the *routing*: whether a real runtime is detected as a sandbox and sent here at all.
//! The tests below cover the pure parts ([`first_choice`] and the probe table).
//! **Risk:** the portal is asked about a fixed probe host, not the caller's real
//! destination, so a host-side PAC that branches on the host name can answer `direct://`
//! for every probe while the real destination would be proxied. The fallback then yields
//! [`ProxyMode::Direct`], and the caller cannot tell that from a host with no proxy at
//! all. A reply the probes cannot rebuild is *not* that case: an unparseable proxy string
//! propagates its parse error, and an unreachable bus or a failed call raises
//! [`Error::Sandboxed`](crate::Error::Sandboxed) — all three the caller does see.
//! **Also lost:** `Lookup` answers with a list, and `direct://` inside it is a permission
//! rather than noise — "Direct connection should not be attempted unless it is part of the
//! returned array of proxies"
//! ([`ProxyResolver.lookup`](https://docs.gtk.org/gio/method.ProxyResolver.lookup.html)).
//! [`first_choice`] keeps the head and [`ProxyMode::Manual`] holds one endpoint per scheme,
//! so an answer of `["PROXY p", "direct://"]` is reported as "use `p`", never as "use `p`,
//! and connecting directly is permitted if `p` will not carry you". What is dropped is the
//! fallback and not the choice — the head is the entry GLib itself would connect with — and
//! carrying the rest would take an ordered candidate list per source, which no public type
//! here has.
//! **Symptom:** inside the sandbox the crate reports no proxy while the host clearly
//! has one, and no error is published; `flatpak-spawn --host gsettings get
//! org.gnome.system.proxy mode` shows the real value.
//!
//! </div>

use std::collections::HashMap;

use gio::prelude::*;

use crate::bypass::BypassRules;
use crate::endpoint::{ProxyEndpoint, ProxyEntry, Scheme};
use crate::error::Error;
use crate::mode::ProxyMode;

use super::sandbox::Sandbox;

// The portal's well-known bus name.
const BUS_NAME: &str = "org.freedesktop.portal.Desktop";
// The portal's object path.
const OBJECT_PATH: &str = "/org/freedesktop/portal/desktop";
// The interface that resolves proxies.
const INTERFACE: &str = "org.freedesktop.portal.ProxyResolver";
// The only method it has.
const METHOD: &str = "Lookup";
// The reply signature, `(as)`.
const REPLY_SIGNATURE: &str = "(as)";
// Bounds a hung session bus: a probe that goes unanswered for this long fails the read
// with [`Error::Sandboxed`] rather than parking the watcher thread indefinitely, and
// [`read_mode`] returns on the first failed `Lookup`, so a read pays the bound as a
// *failure* only once. It does not bound the read: the timeout is per call and [`PROBES`]
// has five entries, so answers arriving just inside it cost five times this.
//
// The value is a choice rather than a measurement. Nothing here knows whether the portal
// answers from its own resolver's cache or goes and fetches a PAC script first, and no
// Flatpak or Snap runtime has ever run this code — see the module documentation.
const TIMEOUT_MS: i32 = 5_000;

const DIRECT: &str = "direct://";

// RFC 2606 reserves `.invalid`; RFC 6761 §6.4 has resolvers and caching servers answer it
// locally, but at SHOULD strength — only the registrar prohibition is a MUST. So a probe
// under it is very unlikely to reach a real nameserver rather than guaranteed not to. The
// name is never connected to, only asked about.
macro_rules! probe_host {
    () => {
        "proxy-watch-probe.invalid"
    };
}

// One probe: the scheme it establishes and the URI used to ask about it.
//
// `none` is not a transport. It is the scheme `ProxyResolver.lookup` documents for asking
// without naming one — "If you don't know what network protocol is being used on the socket,
// you should use `none` as the URI protocol. In this case, the resolver might still return a
// generic proxy type (such as SOCKS), but would not return protocol-specific proxy types
// (such as http)" — which is the question [`Scheme::All`] is the answer to, and `resolve.rs`
// sends every URL scheme this crate does not model there. Without this row a sandboxed
// caller reads `Direct` for `gopher://` and its like while the host has a generic proxy.
//
// Nothing on the path can refuse it, so the row cannot turn a working read into
// [`Error::Sandboxed`]: xdg-desktop-portal hands the URI to `g_proxy_resolver_lookup`
// unexamined (`desktop-portal/proxy-resolver.c`), and `g_simple_proxy_resolver_lookup` —
// what glib-networking's GNOME backend delegates to — lowercases the text before the first
// `:`, misses its per-scheme table, and falls to the default proxy. It has no failure path
// at all, and that default is the SOCKS proxy when one is configured, which is the "generic
// proxy type" the page promises.
const PROBES: [(Scheme, &str); 5] = [
    (Scheme::Http, concat!("http://", probe_host!(), "/")),
    (Scheme::Https, concat!("https://", probe_host!(), "/")),
    (Scheme::Ftp, concat!("ftp://", probe_host!(), "/")),
    (Scheme::Socks, concat!("socks://", probe_host!(), "/")),
    (Scheme::All, concat!("none://", probe_host!(), "/")),
];

// The port assumed when a portal answer carries neither a port nor a scheme.
const DEFAULT_PORT: u16 = 80;

// Probe the portal and reconstruct a [`ProxyMode`].
pub(crate) fn read_mode(sandbox: Sandbox) -> Result<ProxyMode, Error> {
    let connection =
        gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE).map_err(|error| {
            let message = safe_message(&error);
            crate::trace::warning!(
                sandbox = sandbox.name(),
                error = %message,
                "the session bus is not reachable, so the portal cannot be probed"
            );
            sandboxed(sandbox, "the session bus is not reachable", &message)
        })?;

    let mut per_scheme = HashMap::new();
    for (scheme, uri) in PROBES {
        // Any probe failure aborts the whole read (partial Manual would be silent lie).
        let answers = lookup(&connection, uri).map_err(|error| {
            let message = safe_message(&error);
            crate::trace::warning!(
                sandbox = sandbox.name(),
                interface = INTERFACE,
                uri = uri,
                error = %message,
                "the ProxyResolver portal call failed"
            );
            sandboxed(
                sandbox,
                &format!("the ProxyResolver portal call failed for {uri}"),
                &message,
            )
        })?;
        match first_choice(&answers) {
            // Unparseable proxy still surfaces as Err, not silent Direct.
            Some(proxy) => {
                per_scheme.insert(
                    scheme,
                    ProxyEntry::Use(ProxyEndpoint::parse(proxy, DEFAULT_PORT)?),
                );
            }
            // Not left absent, and since the `none` probe this decides an answer rather than
            // only recording one. `per_scheme` now holds a [`Scheme::All`], and
            // [`ProxyMode::entry_for`] stops at a `Disabled` it finds instead of falling
            // through to the catch-all — so a scheme the portal answered `direct://` for
            // reads as Direct, while one left absent would inherit the generic proxy. A host
            // whose PAC proxies the generic question but not FTP must not have FTP silently
            // proxied. `per_scheme` is a public field too, so the same distinction is one a
            // caller can read directly, which is why the loop in `tests/portal_watch.rs`
            // asserts the entry rather than the endpoint.
            None => {
                per_scheme.insert(scheme, ProxyEntry::Disabled);
            }
        }
    }

    if per_scheme.values().all(ProxyEntry::is_disabled) {
        warn_every_probe_answered_direct();
        return Ok(ProxyMode::Direct);
    }
    // The bypass list is deliberately empty; see the module documentation.
    let mode = ProxyMode::manual(per_scheme, BypassRules::new());
    crate::trace::debug!(
        mode = %crate::trace::ModeSummary(&mode),
        "reconstructed a mode from the portal's answers"
    );
    Ok(mode)
}

// One `Lookup` call.
fn lookup(connection: &gio::DBusConnection, uri: &str) -> Result<Vec<String>, glib::Error> {
    let reply = connection.call_sync(
        Some(BUS_NAME),
        OBJECT_PATH,
        INTERFACE,
        METHOD,
        Some(&(uri,).to_variant()),
        Some(glib::VariantTy::new(REPLY_SIGNATURE).expect("(as) is a valid signature")),
        gio::DBusCallFlags::NONE,
        TIMEOUT_MS,
        gio::Cancellable::NONE,
    )?;
    let (proxies,): (Vec<String>,) = reply
        .get()
        .expect("the reply was type-checked against (as) by call_sync");
    Ok(proxies)
}

// The host's first choice, when that names a proxy: `None` for an empty list, and for one
// whose first non-blank entry is `direct://`.
//
// Position is rank. Skipping a leading `direct://` to take the proxy behind it is the
// tempting reading, on the ground that `ProxyResolver.lookup`'s page documents no order for
// the array — which it does not. But silence in the page is not a licence to reorder, and
// the two implementations that bracket the array both read position as rank. GLib's own
// consumer walks it forward from index 0 and never rewinds (`next_enumerator` in
// `gio/gproxyaddressenumerator.c` advances with `*priv->next_proxy++`), connecting directly
// the moment it reaches a `direct` entry; upstream, libproxy appends each PAC result in the
// script's own order (`px_manager_run_pac` in `src/backend/px-manager.c` splits the response
// on `;`), and glib-networking passes that through unreordered. So a PAC as ordinary as
// `DIRECT; PROXY p:8080` arrives here as `["direct://", "http://p:8080"]`, and taking `p`
// from it hands the destination's name to a proxy the host ranked below connecting directly.
fn first_choice(answers: &[String]) -> Option<&str> {
    answers
        .iter()
        .map(|answer| answer.trim())
        .find(|answer| !answer.is_empty())
        .filter(|answer| *answer != DIRECT)
}

// Log-only sink for "every probe came back `direct://`".
fn warn_every_probe_answered_direct() {
    crate::trace::warning!(
        probe_host = probe_host!(),
        "the portal answered direct:// for every probed scheme, so the reported mode is \
         Direct. If the sandbox host resolves proxies with a PAC script that branches on \
         the host name, this is what that looks like from inside the sandbox — the script \
         saw the probe host, not the real destination — and the real answer for a real \
         destination may well be a proxy"
    );
}

// A [`glib::Error`]'s message, made safe to store in a public [`Error`] or write to a
// log.
fn safe_message(error: &glib::Error) -> String {
    crate::util::redact_and_sanitize_untrusted(&error.to_string())
}

// `message` must already be [`safe_message`]'d (same string for log + public Error).
fn sandboxed(sandbox: Sandbox, reason: &str, message: &str) -> Error {
    Error::Sandboxed {
        sandbox: sandbox.name().to_owned(),
        reason: format!(
            "{reason} ({message}); GSettings cannot be trusted here because GLib would \
             answer from the keyfile backend with the schema default mode='none'"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_answers_are_recognised() {
        assert_eq!(first_choice(&["direct://".to_owned()]), None);
        assert_eq!(first_choice(&[]), None);
        assert_eq!(first_choice(&["  ".to_owned()]), None);
    }

    // The shape an earlier rule got wrong, and it is not an exotic one: libproxy builds the
    // array in the PAC script's order, so `DIRECT; PROXY p` — a script anyone might write —
    // arrives exactly like this. Reaching past the head to `proxy.corp` would send the
    // destination's name to a proxy the host ranked below connecting directly.
    #[test]
    fn a_leading_direct_is_the_answer_and_not_something_to_reach_past() {
        let answers = ["direct://".to_owned(), "http://proxy.corp:8080".to_owned()];
        assert_eq!(first_choice(&answers), None);
    }

    // The other side of it, so that honouring the head does not become "any `direct://`
    // anywhere means Direct": a proxy at the head is the answer whatever trails it.
    #[test]
    fn a_proxy_at_the_head_wins_over_everything_behind_it() {
        let answers = [
            "http://proxy.corp:8080".to_owned(),
            "direct://".to_owned(),
            "http://backup.corp:8080".to_owned(),
        ];
        assert_eq!(first_choice(&answers), Some("http://proxy.corp:8080"));
    }

    // Two independent properties of the table, because the host alone leaves the pairing
    // free: swap the `Scheme::Http` and `Scheme::Https` rows and every URI still names the
    // reserved host, while the answers land under each other's scheme — a caller asking
    // for the HTTP proxy would be handed the HTTPS one and told nothing.
    #[test]
    fn every_probe_asks_about_the_scheme_it_records_at_the_reserved_host() {
        for (scheme, uri) in PROBES {
            assert!(
                uri.ends_with(concat!(probe_host!(), "/")),
                "{uri} must not name a real host"
            );
            // One row is not named after the scheme it records: the catch-all is asked for
            // with GIO's `none`, never with `all`. See [`PROBES`] for why that is the right
            // question rather than a spelling accident.
            let asks_about = if scheme == Scheme::All {
                "none"
            } else {
                scheme.as_str()
            };
            assert!(
                uri.starts_with(&format!("{asks_about}://")),
                "{uri} is filed under {scheme}, which is asked about with {asks_about}://"
            );
        }
        for scheme in Scheme::ALL {
            assert_eq!(
                PROBES
                    .iter()
                    .filter(|(probed, _)| *probed == scheme)
                    .count(),
                1,
                "{scheme} is probed the wrong number of times"
            );
        }
    }
}
