//! The XDG portal fallback, driven by a fake `org.freedesktop.portal.ProxyResolver`.
//!
//! `src/sys/linux/portal.rs` documents itself as unverified: no real Flatpak or Snap
//! runtime has ever exercised it, and its own unit tests reach only the pure parts,
//! `first_choice` and the probe table, because `read_mode` opens a session bus. This file
//! reaches the read, through the public [`proxy_watch::read`], without a sandbox runtime
//! and without widening anything to `pub`.
//!
//! Two things make that possible. `Sandbox::Snap` is decided from `$SNAP/meta/snap.yaml`
//! (GLib's own rule, `gio/gsandbox.c`), and `SNAP` is an environment variable a test can
//! set — unlike Flatpak's `/.flatpak-info`, an absolute path only root can create. And the
//! portal is reached by bus name, so a service this file owns answers in its place.
//!
//! ```text
//! dbus-run-session -- cargo test --test portal_watch
//! ```
//!
//! The bus is not optional and neither is owning the name: on a real GNOME or KDE session
//! `org.freedesktop.portal.Desktop` already has an owner, `DO_NOT_QUEUE` turns that into a
//! refusal rather than a wait, and this file self-skips through `support::skip_or_fail`.
//! The real portal is never contacted in that case — the skip happens before the first
//! read. CI's ubuntu job runs the integration tests under `dbus-run-session`, where the
//! name is free, so a skip there means the bus is missing and must turn the job red.
//!
//! **Not covered:** `TIMEOUT_MS`. A service that never replies would prove only that the
//! constant reaches `call_sync`, at a cost of five seconds of wall clock per run.
#![cfg(all(target_os = "linux", feature = "linux-gnome"))]

mod support;

use std::sync::Mutex;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use gio::prelude::*;

use proxy_watch::{Error, ProxyConfigSource, ProxyEntry, ProxyMode, Scheme};

// The catch-all assertion is the only thing in this file that resolves a URL, and the
// gate above asks for `linux-gnome`, not for `resolve`. Imported unconditionally these
// three named `proxy_watch::resolve` in a build that has none, so
// `--no-default-features --features linux-gnome` failed to compile the test target while
// the library itself built clean. No CI leg could see it: neither feature matrix carries
// an entry with a Linux backend on and `resolve` off.
#[cfg(feature = "resolve")]
use proxy_watch::{ProxyEndpoint, ProxyStep, Url};

use support::skip_or_fail;

/// What the fake portal answers next. Written by the test, read by the service thread.
static ANSWER: Mutex<Answer> = Mutex::new(Answer::PerScheme);

#[derive(Debug, Clone, Copy)]
enum Answer {
    /// A different proxy per probed scheme, so the five answers can be told apart.
    PerScheme,
    /// What a host with no proxy at all looks like.
    Direct,
    /// The portal call itself failed.
    Refused,
    /// A proxy string no endpoint can be built from.
    Unparseable,
    /// One probed scheme is proxied and the other four are not — the shape that tells
    /// "every probe said direct" apart from "some probe did".
    OneProxiedRestDirect,
    /// A proxy named without a scheme and without a port, so that the answer's port is
    /// the crate's own default rather than anything the portal said.
    NoPort,
}

/// The scheme prefixes `src/sys/linux/portal.rs`'s `PROBES` asks about, in its order.
/// `https://` does not start with `http://`, so a prefix match here is unambiguous. The
/// last row is the catch-all, which GIO is asked about with `none://` rather than `all://`.
const PROBED: [(&str, Scheme); 5] = [
    ("http://", Scheme::Http),
    ("https://", Scheme::Https),
    ("ftp://", Scheme::Ftp),
    ("socks://", Scheme::Socks),
    ("none://", Scheme::All),
];

#[test]
fn the_portal_fallback_rebuilds_a_mode_from_its_five_probes() {
    let snap = std::env::temp_dir().join(format!("proxy-watch-portal-{}", std::process::id()));
    std::fs::create_dir_all(snap.join("meta")).expect("creating the fake snap directory");
    std::fs::write(
        snap.join("meta/snap.yaml"),
        "name: proxy-watch\nconfinement: strict\n",
    )
    .expect("writing the fake snap manifest");
    // SAFETY: this is the only test in this binary and the only write to the environment
    // in it, and no thread below has been started yet — so nothing can be reading.
    unsafe {
        std::env::set_var("SNAP", &snap);
    }

    if !serve_the_fake_portal() {
        let _ = std::fs::remove_dir_all(&snap);
        return;
    }

    // 1. Five probes, five distinguishable answers. A probe table whose rows were swapped,
    //    or a read that asked about one scheme and filed the answer under another, lands
    //    here rather than in an assertion every scheme would satisfy. `Scheme::All` is in
    //    the loop like any other: a concrete entry beats it, so an answer misfiled there is
    //    invisible to every assertion that asks about a scheme the portal also answered.
    let config = proxy_watch::read().expect("the fake portal answered every probe");
    assert_eq!(
        config.source(ProxyConfigSource::Portal),
        Some(&config.effective),
        "the sandbox route reports the portal as the source: {:?}",
        config.sources
    );
    for (index, (_, scheme)) in PROBED.into_iter().enumerate() {
        assert_eq!(
            config
                .effective
                .endpoint_for(scheme)
                .unwrap_or_else(|| panic!("an endpoint for {scheme}"))
                .authority(),
            format!("127.0.0.1:1808{index}"),
            "{scheme} was given another probe's answer: {:?}",
            config.effective
        );
    }

    // And what the catch-all row is *for*, read off the public answer rather than off the
    // slot it was filed under. `resolve` sends every URL scheme this crate does not model
    // to `Scheme::All`, so without the `none://` probe a sandboxed caller was told `Direct`
    // for these while the host had a proxy for them — the misdetection this module exists
    // to prevent, in the one shape the per-scheme loop above cannot see, because every
    // scheme it asks about has a concrete entry that beats the catch-all.
    #[cfg(feature = "resolve")]
    {
        let steps = proxy_watch::resolve(
            &config,
            &Url::parse("gopher://example.invalid/x").expect("a valid URL"),
        )
        .expect("resolving a scheme the crate does not model");
        assert_eq!(
            steps
                .first()
                .and_then(ProxyStep::endpoint)
                .map(ProxyEndpoint::authority)
                .as_deref(),
            Some("127.0.0.1:18084"),
            "an unmodelled scheme takes what the portal answered for none://: {steps:?}"
        );
    }

    // 2. `direct://` from every probe is the one shape that collapses to `Direct`.
    *ANSWER.lock().expect("the answer lock") = Answer::Direct;
    assert_eq!(
        proxy_watch::read()
            .expect("a direct answer is not a failure")
            .effective,
        ProxyMode::Direct
    );

    // 3. *Every* probe, not any of them. `read_mode` collapses to `Direct` only when no
    //    probed scheme came back with a proxy; a single proxied scheme keeps the mode
    //    `Manual`, with the four that answered `direct://` recorded as having answered it
    //    rather than left absent. This step is the only thing holding the `all`: relaxing it
    //    to `any` leaves the rest of the tree green, because step 2 above is the only other
    //    shape that reaches the branch and it satisfies both readings. What the
    //    relaxation costs is the sandbox misdetection this module exists to prevent, in its
    //    quietest form: a host that proxies HTTP and nothing else would be reported as
    //    having no proxy at all, with no error anywhere, and `direct://` for four of five
    //    probes is what an ordinary split-tunnel PAC answers.
    *ANSWER.lock().expect("the answer lock") = Answer::OneProxiedRestDirect;
    let config = proxy_watch::read().expect("a partly direct answer is not a failure");
    assert_eq!(
        config
            .effective
            .endpoint_for(Scheme::Http)
            .expect("the one proxied scheme keeps its endpoint")
            .authority(),
        "127.0.0.1:18090",
        "{:?}",
        config.effective
    );
    for (_, scheme) in PROBED.into_iter().skip(1) {
        // The entry, not the endpoint. `endpoint_for` answers `None` for a slot the read
        // never filled just as readily as for one it filled with `Disabled`, so asking it
        // cannot tell "the portal said direct for this scheme" from "this scheme was never
        // probed" — and `per_scheme` is a public field, so that is a distinction a caller
        // can see. Ask about endpoints here instead and dropping the `Disabled` insert leaves
        // the whole tree green. The last row is `Scheme::All`, where the record
        // decides rather than merely informs: were it absent, every scheme the portal
        // answered `direct://` for would fall through to whatever the catch-all holds.
        assert_eq!(
            config.effective.entry_for(scheme),
            Some(&ProxyEntry::Disabled),
            "{scheme} answered direct:// and must be recorded as answering it: {:?}",
            config.effective
        );
    }

    // 4. The port the crate supplies when the portal names none. GLib hands out a URI and
    //    nothing in the reply is required to carry a port, so `DEFAULT_PORT` is a decision
    //    this crate makes on the sandbox's behalf and one nothing else measures — changing
    //    it from 80 to 8080 leaves every other test green. A wrong constant sends the
    //    sandbox's traffic to a port on the right host that is very likely closed, which
    //    surfaces as a connection failure the caller cannot trace back to a proxy setting.
    *ANSWER.lock().expect("the answer lock") = Answer::NoPort;
    let config = proxy_watch::read().expect("a portless answer is not a failure");
    assert_eq!(
        config
            .effective
            .endpoint_for(Scheme::Http)
            .expect("an endpoint built from a bare host")
            .authority(),
        "127.0.0.1:80",
        "{:?}",
        config.effective
    );

    // 5. A portal that fails is an error, not a quiet `Direct` — the misdetection the
    //    whole sandbox branch exists to prevent.
    *ANSWER.lock().expect("the answer lock") = Answer::Refused;
    let error = proxy_watch::read().expect_err("a failed Lookup must not read as Direct");
    let Error::Sandboxed { sandbox, reason } = &error else {
        panic!("a failed portal call names the sandbox: {error:?}");
    };
    // Named the way it was detected. The manifest written at the top of this test says
    // `confinement: strict`, so the kind here is Snap and nothing else, and the word is a
    // public field — the one thing this error tells whoever has to work out why a host with
    // a proxy read as having none. This assertion is the only thing holding that mapping:
    // transposing the `Flatpak` and `Snap` arms of `Sandbox::name` leaves the rest of the
    // tree green, because every other test that reaches this error matches
    // `Error::Sandboxed { .. }` without looking inside.
    assert_eq!(sandbox, "Snap", "a strict snap is not a Flatpak: {error:?}");
    // And carries the other process's words neutralised. The portal is a peer on the bus,
    // its error message is text this crate did not write, and `reason` is a public field a
    // caller may log or print. This is the only thing holding that the portal read sanitises
    // at all: dropping the redaction leaves the rest of the tree green, because every other
    // answer this fake gives succeeds. The `util` tests cover what the pass does; this covers that the
    // pass is applied to this string.
    assert!(
        !reason.contains('\n') && reason.contains("fail.alice:***@corp"),
        "the portal's own message must not reach a public field with its newline or its \
         credential intact: {reason}"
    );

    // 6. So is an answer no endpoint can be built from.
    *ANSWER.lock().expect("the answer lock") = Answer::Unparseable;
    let error = proxy_watch::read().expect_err("an unparseable proxy must not read as Direct");
    assert!(
        matches!(error, Error::InvalidProxyServer { .. }),
        "the parse failure is what propagates: {error:?}"
    );

    let _ = std::fs::remove_dir_all(&snap);
}

/// How the service thread reports whether it got the name.
type Outcome = mpsc::Sender<Result<(), String>>;

/// Own `org.freedesktop.portal.Desktop`, answer `Lookup` from [`ANSWER`], and report
/// whether this machine let it.
fn serve_the_fake_portal() -> bool {
    let (ready, acquired) = mpsc::channel();
    let lost = ready.clone();

    thread::spawn(move || {
        let context = glib::MainContext::new();
        // Everything the service does happens inside this, because the context that is
        // thread-default at registration time is the one GDBus dispatches its callbacks
        // on — both the method call and the two name handlers.
        context
            .with_thread_default(|| serve(&context, ready, lost))
            .expect("a freshly created main context is not owned by another thread");
    });

    let reason = match acquired.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => return true,
        Ok(Err(reason)) => reason,
        Err(_) => "no answer from the session bus within 5s".to_owned(),
    };
    skip_or_fail(&format!(
        "{reason}. Run this under `dbus-run-session -- cargo test --test portal_watch`."
    ));
    false
}

/// The body of [`serve_the_fake_portal`]'s thread, with `context` already thread-default.
///
/// Returns only if the session bus cannot be reached: the loop it ends on is never
/// stopped, and neither the registration nor the [`gio::OwnerId`] is ever dropped — the
/// service lives as long as the test binary.
fn serve(context: &glib::MainContext, ready: Outcome, lost: Outcome) {
    let connection = match gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE) {
        Ok(connection) => connection,
        Err(error) => {
            let _ = ready.send(Err(format!("the session bus is not reachable: {error}")));
            return;
        }
    };
    let node = gio::DBusNodeInfo::for_xml(INTERFACE_XML).expect("the interface XML is valid");
    let interface = node
        .lookup_interface("org.freedesktop.portal.ProxyResolver")
        .expect("the XML declares that interface");
    let _registration = connection
        .register_object("/org/freedesktop/portal/desktop", &interface)
        .method_call(
            |_connection, _sender, _path, _interface, method, parameters, call| {
                assert_eq!(method, "Lookup", "the crate calls no other method");
                let (uri,) = parameters
                    .get::<(String,)>()
                    .expect("Lookup takes one string, as the XML says");
                // The reply shape the portal documents: a list of proxy strings, in which
                // `direct://` is an entry rather than an empty list.
                let proxies = match *ANSWER.lock().expect("the answer lock") {
                    Answer::Refused => {
                        // The text is chosen, not incidental: a D-Bus error message is
                        // written by another process and reaches a public `Error` field, so
                        // step 5 below asserts that the crate neutralises it. The newline
                        // is what would forge a second log or error line; the `user:pass@`
                        // is what `redact_userinfo` exists for.
                        call.return_error(
                            gio::IOErrorEnum::Failed,
                            "the fake portal was asked to fail\nalice:hunter2@corp",
                        );
                        return;
                    }
                    Answer::Direct => vec!["direct://".to_owned()],
                    Answer::OneProxiedRestDirect => {
                        if uri.starts_with("http://") {
                            vec!["http://127.0.0.1:18090".to_owned()]
                        } else {
                            vec!["direct://".to_owned()]
                        }
                    }
                    // No scheme and no port. `ProxyEndpoint::parse` takes the port from the
                    // default it is handed, which is the constant under test.
                    Answer::NoPort => vec!["127.0.0.1".to_owned()],
                    // A scheme and no host: `ProxyEndpoint::parse` cannot build an endpoint
                    // from it, and `first_choice` does not filter it out.
                    Answer::Unparseable => vec!["http://".to_owned()],
                    // Every answer is spelled `http://` whichever scheme was asked about,
                    // because what is under test is which answer lands under which scheme;
                    // giving each its own proxy scheme as well would put
                    // `ProxyEndpoint::parse`'s spelling rules inside that assertion.
                    Answer::PerScheme => {
                        let index = PROBED
                            .iter()
                            .position(|(prefix, _)| uri.starts_with(prefix))
                            .unwrap_or_else(|| panic!("{uri} is not one of the five probes"));
                        vec![format!("http://127.0.0.1:1808{index}")]
                    }
                };
                call.return_value(Some(&(proxies,).to_variant()));
            },
        )
        .build()
        .expect("registering the fake portal");

    let _owner = gio::bus_own_name_on_connection(
        &connection,
        "org.freedesktop.portal.Desktop",
        gio::BusNameOwnerFlags::DO_NOT_QUEUE,
        move |_connection, _name| {
            let _ = ready.send(Ok(()));
        },
        move |_connection, _name| {
            let _ = lost.send(Err(
                "org.freedesktop.portal.Desktop already has an owner".to_owned()
            ));
        },
    );
    glib::MainLoop::new(Some(context), false).run();
}

/// Only the method the crate calls, declared with the signature the portal documents.
/// GDBus checks a reply against it on the way out as well as against the caller's expected
/// type on the way in, so a reply built here cannot drift from `(as)` unnoticed.
const INTERFACE_XML: &str = "\
<node>
  <interface name='org.freedesktop.portal.ProxyResolver'>
    <method name='Lookup'>
      <arg type='s' name='uri' direction='in'/>
      <arg type='as' name='proxies' direction='out'/>
    </method>
  </interface>
</node>";
