//! PAC/WPAD resolution delegated to WinHTTP (`pac-windows-native`).
//!
//! ```text
//! cargo test --features pac-windows-native --test pac_winhttp
//! ```
//!
//! The tests that patch the machine's real registry to exercise the WPAD-fallback path
//! live in `tests/pac_winhttp_registry.rs` instead, so that they get a test binary
//! of their own; see that file's module doc for the measurement that forced the split
//! (in short: their fixture is machine-wide, so it perturbs the WinHTTP calls the tests
//! here make, and a binary holding both needs `--test-threads=1` to pass). Nothing in
//! *this* file writes to the registry, and it passes under a plain
//! `cargo test`.
//!
//! # These tests must pass on a machine with no proxy at all
//!
//! Nothing here depends on the machine's own proxy configuration, on a corporate network
//! or on internet access:
//!
//! * the PAC scripts that are actually *evaluated* are served by a throw-away
//!   [`PacServer`] on `127.0.0.1`, built out of `std::net::TcpListener` alone;
//! * the WPAD test accepts every outcome, because whether DHCP option 252 or a
//!   `wpad.<domain>` record exists is a property of the network, not of this crate — it
//!   only asserts that the call terminates inside its budget and yields a sane shape;
//!   and
//! * the failure tests use RFC 5737 / RFC 6890 addresses that are guaranteed not to be
//!   routed anywhere.
//!
//! The target URL passed to `FindProxyForURL` is never connected to, so `example.net`
//! below costs no traffic.

#![cfg(all(windows, feature = "pac-windows-native"))]

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use proxy_watch::pac::{WinHttpPacResolver, WinHttpPacSource};
use proxy_watch::{
    Error, ProxyConfig, ProxyConfigSource, ProxyMode, ProxyStep, Url, parse, resolve,
};

/// The budget the *success* paths run under. Generous on purpose: nothing here measures
/// it, and every one of these tests only has to let WinHTTP fetch a few hundred bytes from
/// a server inside this process. Three seconds looked like plenty and was not — WinHTTP's
/// autoproxy service takes its own time to warm up, and the whole file failed as
/// `PacTimeout` whenever it did, which reads exactly like a real regression and never is.
const BUDGET: Duration = Duration::from_secs(30);

/// The budget the *give-up* paths measure against. Small on purpose: their point is that
/// the deadline is enforced, and [`BUDGET`] is far too loose to prove that.
const GIVE_UP_BUDGET: Duration = Duration::from_secs(3);

/// The URL whose routing is being asked about. Never connected to.
fn target() -> Url {
    Url::parse("http://example.net/some/path").unwrap()
}

fn resolver() -> WinHttpPacResolver {
    WinHttpPacResolver::with_timeout(BUDGET).expect("opening a WinHTTP session")
}

fn give_up_resolver() -> WinHttpPacResolver {
    WinHttpPacResolver::with_timeout(GIVE_UP_BUDGET).expect("opening a WinHTTP session")
}

// ---------------------------------------------------------------------------
// A PAC file server in ~40 lines of std.
// ---------------------------------------------------------------------------

/// Serves one fixed body on `127.0.0.1` to every request, until dropped.
struct PacServer {
    address: SocketAddr,
    /// Tells this server's URL apart from every other one's — see [`PacServer::url`].
    serial: u64,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl PacServer {
    /// Bind an ephemeral loopback port and start serving `body`.
    fn start(body: &'static str) -> Self {
        Self::spawn(Some(body))
    }

    /// Bind a port that accepts connections and then says nothing, ever.
    ///
    /// The deterministic way to make a resolution overrun its budget without depending
    /// on how the machine treats an unroutable address.
    fn stalling() -> Self {
        Self::spawn(None)
    }

    fn spawn(body: Option<&'static str>) -> Self {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binding a loopback port");
        let address = listener.local_addr().expect("reading the bound port");
        // Non-blocking accept is what lets the thread notice `stop` and exit.
        listener
            .set_nonblocking(true)
            .expect("switching the listener to non-blocking");

        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                // Accepted-but-unanswered sockets, held open so that the peer sees a
                // stall rather than an immediate EOF.
                let mut stalled = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => match body {
                            Some(body) => serve_one(stream, body),
                            None => stalled.push(stream),
                        },
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        Self {
            address,
            serial: SERIAL.fetch_add(1, Ordering::Relaxed),
            stop,
            thread: Some(thread),
        }
    }

    /// The URL WinHTTP should download the script from.
    ///
    /// The serial and the process id are in the path because WinHTTP caches a downloaded
    /// script under the URL it came from, and that cache belongs to the autoproxy service
    /// rather than to the session this file opens — dropping a [`WinHttpPacResolver`] does
    /// not clear it. Every server here binds an ephemeral port, so the OS is free to hand a
    /// later one the port a finished one released; with a fixed path that made the URL
    /// repeat, and WinHTTP then answered out of the cache without ever contacting the new
    /// server. What that looks like is not a timeout but a *wrong success*: a test reading
    /// the previous script's answer and reporting it as its own. It was first seen that way
    /// — `a_server_that_never_answers_is_abandoned_and_the_resolver_still_works` receiving
    /// `proxy.corp.example:8080`, `an_ipv6_proxy_literal_survives_the_round_trip` receiving
    /// the timeout test's `after-timeout.example:8080`, results shifted by one test — in
    /// about one run of the whole target in six. Forcing the condition rather than waiting
    /// for it (a literal port here, and this path back to a constant) makes it every run and
    /// every test: each one reads whichever script the run downloaded first. The timing
    /// races the tests below document are a separate thing, and none of them predicts a
    /// resolution that succeeds with someone else's answer.
    fn url(&self) -> Url {
        Url::parse(&format!(
            "http://{}/proxy-{}-{}.pac",
            self.address,
            std::process::id(),
            self.serial
        ))
        .unwrap()
    }
}

/// Source of [`PacServer::serial`]. Unique within the run; the process id in the path
/// covers the rest.
static SERIAL: AtomicU64 = AtomicU64::new(0);

impl Drop for PacServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Read the request headers (and discard them), then write the PAC file back.
fn serve_one(mut stream: TcpStream, body: &str) {
    stream
        .set_nonblocking(false)
        .expect("switching the accepted socket to blocking");
    let mut reader = BufReader::new(stream.try_clone().expect("cloning the accepted socket"));
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/x-ns-proxy-autoconfig\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

// ---------------------------------------------------------------------------
// End to end: a real script, downloaded and executed by WinHTTP.
// ---------------------------------------------------------------------------

#[test]
fn a_served_script_is_downloaded_and_its_chain_comes_back_in_order() {
    let server = PacServer::start(
        "function FindProxyForURL(url, host) {
             return 'PROXY proxy.corp.example:8080; SOCKS socks.corp.example:1080; DIRECT';
         }",
    );

    let steps = resolver()
        .resolve(&target(), &WinHttpPacSource::Url(server.url()))
        .expect("resolving through the served PAC file");

    assert_eq!(steps.len(), 3, "{steps:?}");
    assert_eq!(steps[0].scheme(), Some("http"));
    assert_eq!(
        steps[0].endpoint().unwrap().authority(),
        "proxy.corp.example:8080"
    );
    // WinHTTP reports the bare `SOCKS` keyword as its single SOCKS scheme, which this
    // crate reads as SOCKS4 — the same rule `parse_find_proxy_result` applies.
    assert_eq!(steps[1].scheme(), Some("socks4"));
    assert_eq!(
        steps[1].endpoint().unwrap().authority(),
        "socks.corp.example:1080"
    );
    assert_eq!(steps[2], ProxyStep::Direct);
}

/// A hop the script names twice is tried once.
///
/// `wpad_auto_detect_terminates_and_never_returns_an_empty_chain` below already loops over
/// the chain looking for a repeat, and its comment calls that the thing the call can still
/// get wrong. It is not, on any machine measured: dropping the `seen.insert` half of the
/// membership test in `ProxyResult::to_steps` left that test — and the whole tree — green,
/// because the WPAD this network answers with names one hop and the runner's names none.
/// The assertion is a guard on a shape that never arrives, so this one serves the script
/// itself and makes the repeat certain.
///
/// It also settles the question that assertion cannot: WinHTTP does **not** fold a repeated
/// proxy itself. With the membership test removed the four tokens below come back as three
/// steps — the two `PROXY` entries both survive, and it is the repeated `DIRECT` that
/// WinHTTP collapses on its own. So the `DIRECT` pair measures WinHTTP rather than this
/// crate; it stays in the script because that asymmetry is the reason the rule cannot be
/// left to the platform.
///
/// What the rule is worth is written on `to_steps`: the same script reaches WinHTTP here
/// and `parse_find_proxy_result` everywhere else, and a chain that collapsed differently
/// depending on which engine ran it would be a difference the script's author never asked
/// for.
#[test]
fn a_hop_the_script_names_twice_is_tried_once() {
    let server = PacServer::start(
        "function FindProxyForURL(url, host) {
             return 'PROXY dup.example:8080; PROXY dup.example:8080; DIRECT; DIRECT';
         }",
    );

    let steps = resolver()
        .resolve(&target(), &WinHttpPacSource::Url(server.url()))
        .expect("resolving through the served PAC file");

    assert_eq!(steps.len(), 2, "{steps:?}");
    assert_eq!(
        steps[0].endpoint().unwrap().authority(),
        "dup.example:8080",
        "{steps:?}"
    );
    assert_eq!(steps[1], ProxyStep::Direct, "{steps:?}");
}

/// And named *again after another hop*, which is the half of that rule the test above cannot
/// reach. Its two `PROXY` entries sit next to each other, so a membership test that only
/// compares a step against the one before it folds them just the same and keeps every
/// assertion in this file green: with `to_steps`'s `seen.insert` replaced by
/// `Some(&step) != steps.last()`, the test above passes and this one fails with three steps.
///
/// Those three steps also settle a question the adjacent shape raises and cannot answer on
/// its own. WinHTTP folds a repeated `DIRECT` on its own but leaves a repeated `PROXY`
/// alone; the same asymmetry holds one shape further out, and the return here arrives as its
/// own entry rather than being collapsed by the platform.
///
/// The row is not this file's alone. `duplicates_collapse` in `src/pac/result.rs` holds it for
/// the parser every other platform reaches, and `to_steps` says the two are held identical
/// on purpose — a chain that collapsed differently depending on which engine ran it would be
/// a difference the script's author never asked for. This is the Windows side of that claim.
#[test]
fn a_hop_the_script_returns_to_is_still_tried_once() {
    let server = PacServer::start(
        "function FindProxyForURL(url, host) {
             return 'PROXY first.example:8080; PROXY second.example:8080; PROXY first.example:8080';
         }",
    );

    let steps = resolver()
        .resolve(&target(), &WinHttpPacSource::Url(server.url()))
        .expect("resolving through the served PAC file");

    assert_eq!(steps.len(), 2, "{steps:?}");
    assert_eq!(
        steps[0].endpoint().unwrap().authority(),
        "first.example:8080",
        "{steps:?}"
    );
    assert_eq!(
        steps[1].endpoint().unwrap().authority(),
        "second.example:8080",
        "{steps:?}"
    );
}

#[test]
fn a_script_returning_direct_yields_exactly_one_direct_step() {
    let server = PacServer::start("function FindProxyForURL(url, host) { return 'DIRECT'; }");

    let steps = resolver()
        .resolve(&target(), &WinHttpPacSource::Url(server.url()))
        .expect("resolving through the served PAC file");

    assert_eq!(steps, vec![ProxyStep::Direct]);
}

#[test]
fn the_script_actually_sees_the_url_and_host_arguments() {
    // The two arguments are branched on, so a wrong answer proves they were not passed.
    let server = PacServer::start(
        "function FindProxyForURL(url, host) {
             if (host === 'example.net' && url.indexOf('http://example.net') === 0) {
                 return 'PROXY matched.example:3128';
             }
             return 'PROXY wrong.example:1';
         }",
    );

    let steps = resolver()
        .resolve(&target(), &WinHttpPacSource::Url(server.url()))
        .expect("resolving through the served PAC file");

    assert_eq!(
        steps[0].endpoint().unwrap().authority(),
        "matched.example:3128",
        "{steps:?}"
    );
}

/// WinHTTP's resolver refuses a WebSocket scheme, so `query_url` (`src/pac/winhttp.rs`)
/// maps it before the call. That mapping had a unit test on the function and nothing on
/// the path: `resolve_raw` calling `sanitize_url` directly instead would have left it
/// green while every `ws:`/`wss:` destination came back as
/// `ERROR_WINHTTP_UNRECOGNIZED_SCHEME` on a machine with a perfectly good answer for it.
///
/// The script echoes the scheme it was shown into the proxy host, so the assertion names
/// what WinHTTP was handed. Both failure directions are caught: no mapping at all is an
/// error rather than a chain, and a mapping to the wrong member of the pair answers
/// `http.example` where the `s` belongs.
#[test]
fn a_websocket_destination_is_resolved_through_the_scheme_winhttp_understands() {
    let server = PacServer::start(
        "function FindProxyForURL(url, host) {
             return 'PROXY ' + url.split(':')[0] + '.example:3128';
         }",
    );

    let steps = resolver()
        .resolve(
            &Url::parse("wss://chat.example/room").unwrap(),
            &WinHttpPacSource::Url(server.url()),
        )
        .expect("a wss: destination has to reach WinHTTP as something it will route");

    assert_eq!(
        steps[0].endpoint().unwrap().authority(),
        "https.example:3128",
        "{steps:?}"
    );
}

/// `query_url` sanitizes before the call, and only the Boa engine had that held end to end
/// (`pac::tests::the_script_is_handed_the_sanitized_url_end_to_end`). WinHTTP is a second
/// engine down a second path, and its own unit test reads `query_url`'s return rather than
/// what the platform did with it. The script is the only witness to the latter, and the
/// test above already shows the argument reaching it.
///
/// What it witnesses is the fragment, and that is a measurement rather than a choice.
/// Handing `WinHttpGetProxyForUrlEx` the URL unsanitized, this machine's WinHTTP passed
/// the fragment through to the script and removed the userinfo on its own — the credential
/// branch below never fired, at either scheme. So the crate's stripping of a password is
/// not observable here, and the fragment is exactly the cut that would otherwise reach a
/// script with no test naming it. `http` rather than `https`, for the same reason measured
/// the same way: WinHTTP reduces an `https` destination to its origin before the script
/// runs, which leaves nothing for this to tell apart.
///
/// The branches are ordered so the returned proxy names which cut failed, not merely that
/// one did — and the last of them is the opposite direction: an `http` destination keeps
/// its path and query, so a sanitiser that reached them would break routing on every
/// script that reads the path, and that has to fail here too.
#[test]
fn the_script_is_handed_the_sanitized_url_through_winhttp_too() {
    let server = PacServer::start(
        "function FindProxyForURL(url, host) {
             if (url.indexOf('alice') >= 0 || url.indexOf('hunter2') >= 0) {
                 return 'PROXY credentials.example:1';
             }
             if (url.indexOf('#') >= 0 || url.indexOf('frag') >= 0) {
                 return 'PROXY fragment.example:1';
             }
             if (url.indexOf('/room?q=1') < 0) {
                 return 'PROXY overcut.example:1';
             }
             return 'PROXY clean.example:3128';
         }",
    );

    let steps = resolver()
        .resolve(
            &Url::parse("http://alice:hunter2@chat.example/room?q=1#frag").unwrap(),
            &WinHttpPacSource::Url(server.url()),
        )
        .expect("a destination carrying userinfo still has to resolve");

    assert_eq!(
        steps[0].endpoint().unwrap().authority(),
        "clean.example:3128",
        "{steps:?}"
    );
}

#[test]
fn an_ipv6_proxy_literal_survives_the_round_trip() {
    let server = PacServer::start(
        "function FindProxyForURL(url, host) { return 'PROXY [2001:db8::1]:8080'; }",
    );

    let steps = resolver()
        .resolve(&target(), &WinHttpPacSource::Url(server.url()))
        .expect("resolving through the served PAC file");

    assert_eq!(
        steps[0].endpoint().unwrap().authority(),
        "[2001:db8::1]:8080",
        "{steps:?}"
    );
}

#[test]
fn a_script_that_does_not_parse_is_an_error_not_a_silent_direct() {
    let server = PacServer::start("this is not JavaScript at all {{{");

    let error = resolver()
        .resolve(&target(), &WinHttpPacSource::Url(server.url()))
        .expect_err("a broken script must not resolve");

    // WinHTTP reports either a script error or a generic autoproxy failure depending on
    // where its parser gives up; both are errors, and neither may be `Direct`.
    assert!(
        matches!(error, Error::PacEvaluation { .. } | Error::Io { .. }),
        "{error:?}"
    );
}

/// A script that runs and answers, but names nothing this crate can route.
///
/// WinHTTP does not treat that as a failure — it returns success with zero entries, so the
/// only place the emptiness becomes an error is the check at the end of `to_steps`, and this
/// test is the only thing holding it: letting the empty `Vec` through leaves the rest of the
/// tree green.
///
/// What that would cost is an answer that is neither a proxy nor a refusal. `resolve`
/// promises an ordered chain to try, and a caller walking an empty one finds no step, no
/// proxy and nothing saying why — the same silence as a successful Direct, from a script
/// that never said Direct. Both bodies below are shapes a real script reaches by accident:
/// a transport nobody here models, and a keyword whose address went missing.
#[test]
fn a_script_that_names_nothing_routable_is_an_error_not_an_empty_chain() {
    for body in [
        "function FindProxyForURL(url, host) { return 'FTP 203.0.113.7:21'; }",
        "function FindProxyForURL(url, host) { return 'PROXY '; }",
    ] {
        let server = PacServer::start(body);
        let error = resolver()
            .resolve(&target(), &WinHttpPacSource::Url(server.url()))
            .expect_err(body);
        assert!(matches!(error, Error::PacInvalidResult { .. }), "{error:?}");
    }
}

// ---------------------------------------------------------------------------
// Failure paths that need no network.
// ---------------------------------------------------------------------------

#[test]
fn a_pac_url_with_nothing_listening_fails_promptly() {
    // Bound and immediately dropped, so the port is (almost certainly) free and the
    // connection is refused rather than blackholed.
    let port = {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    let url = Url::parse(&format!("http://127.0.0.1:{port}/missing.pac")).unwrap();

    let started = Instant::now();
    let error = give_up_resolver()
        .resolve(&target(), &WinHttpPacSource::Url(url))
        .expect_err("an undownloadable script must not resolve");

    let elapsed = started.elapsed();

    // Inside the budget the refusal is the only thing that can have ended the call, so it
    // has to be reported as one: a timeout there would mean the refusal went unnoticed.
    // Past the budget the two race, and on a loaded machine either can win — the deadline
    // can expire before WinHTTP is even scheduled, or the refusal can simply arrive that
    // late. Both are the budget being enforced rather than a hang, which is what the
    // sibling tests below already say about their own races.
    //
    // Demanding the refusal unconditionally made this the one flaky test in the file:
    // 0 failures in 20 runs idle, 16 in 20 at 2x CPU oversubscription. An idle run already
    // spends 2.0s of the 3s budget here, so there was never much to lose.
    if elapsed < GIVE_UP_BUDGET {
        assert!(
            matches!(error, Error::Io { .. } | Error::PacEvaluation { .. }),
            "{error:?} after {elapsed:?}"
        );
    } else {
        assert!(
            matches!(
                error,
                Error::PacTimeout { .. } | Error::Io { .. } | Error::PacEvaluation { .. }
            ),
            "{error:?} after {elapsed:?}"
        );
    }
    assert!(elapsed < GIVE_UP_BUDGET * 2, "took {elapsed:?}");
}

#[test]
fn a_server_that_never_answers_is_abandoned_and_the_resolver_still_works() {
    let stalling = PacServer::stalling();
    let budget = Duration::from_millis(400);
    let resolver = WinHttpPacResolver::with_timeout(budget).expect("opening a WinHTTP session");

    let started = Instant::now();
    let error = resolver
        .resolve(&target(), &WinHttpPacSource::Url(stalling.url()))
        .expect_err("a script that never arrives must not resolve");
    let elapsed = started.elapsed();

    // Either the wait here or WinHTTP's own receive timeout wins the race; both are the
    // budget being enforced, and neither is a hang.
    assert!(
        matches!(
            error,
            Error::PacTimeout { .. } | Error::PacEvaluation { .. } | Error::Io { .. }
        ),
        "{error:?}"
    );
    assert!(elapsed < budget * 8, "took {elapsed:?}");

    // The real point: after giving up, the pending WinHTTP callback still fires against
    // state this crate abandoned. If that were unsound — or if the cancelled handle left
    // the session permanently wedged — no later resolution would ever succeed.
    //
    // A resolution attempted immediately after does still fail: the abandoned operation
    // has not finished draining, and with a budget this tight the follow-up runs out of
    // time behind it. That is a delay, not damage, so the assertion is that the session
    // *recovers*, not that it is instantly ready.
    //
    // How much patience that takes is a property of the machine, not of the crate: a 400ms
    // budget on a loaded one loses the race repeatedly, and ten seconds of retries was not
    // always enough (one failure in 20 runs at 2x CPU oversubscription). Thirty is still
    // far short of a hang, which is the thing this loop exists to catch.
    let working = PacServer::start(
        "function FindProxyForURL(url, host) { return 'PROXY after-timeout.example:8080'; }",
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let steps = loop {
        match resolver.resolve(&target(), &WinHttpPacSource::Url(working.url())) {
            Ok(steps) => break steps,
            Err(error) => assert!(
                Instant::now() < deadline,
                "the session never recovered from a cancelled resolution: {error:?}"
            ),
        }
    };
    assert_eq!(
        steps[0].endpoint().unwrap().authority(),
        "after-timeout.example:8080"
    );
}

#[test]
fn an_unroutable_pac_url_gives_up_inside_the_budget() {
    // TEST-NET-1 (RFC 5737): reserved for documentation and never routed.
    let url = Url::parse("http://192.0.2.1/proxy.pac").unwrap();

    let started = Instant::now();
    let error = give_up_resolver()
        .resolve(&target(), &WinHttpPacSource::Url(url))
        .expect_err("an unreachable script must not resolve");
    let elapsed = started.elapsed();

    assert!(
        matches!(error, Error::PacTimeout { .. } | Error::Io { .. }),
        "{error:?}"
    );
    // The point of the test: the budget is real. A generous slack absorbs the WinHTTP
    // worker thread's own scheduling.
    assert!(elapsed < GIVE_UP_BUDGET * 3, "took {elapsed:?}");
}

#[test]
fn a_url_scheme_winhttp_cannot_route_is_an_error() {
    let server = PacServer::start("function FindProxyForURL(url, host) { return 'DIRECT'; }");

    let error = resolver()
        .resolve(
            &Url::parse("gopher://example.net/").unwrap(),
            &WinHttpPacSource::Url(server.url()),
        )
        .expect_err("WinHTTP does not understand gopher:// destinations");

    assert!(matches!(error, Error::Io { .. }), "{error:?}");
}

#[test]
fn a_zero_budget_is_refused_at_construction() {
    let error = WinHttpPacResolver::with_timeout(Duration::ZERO)
        .expect_err("a zero timeout cannot be honoured");
    assert!(matches!(error, Error::PacTimeout { .. }), "{error:?}");
}

// ---------------------------------------------------------------------------
// WPAD: whatever this machine's network says, the call must behave.
// ---------------------------------------------------------------------------

#[test]
fn wpad_auto_detect_terminates_and_never_returns_an_empty_chain() {
    let started = Instant::now();
    // The tight budget on purpose: this asserts termination, and a failure to discover
    // WPAD in time is one of the outcomes the match below already accepts.
    let outcome = give_up_resolver().resolve(&target(), &WinHttpPacSource::AutoDetect);
    let elapsed = started.elapsed();

    match outcome {
        // The usual answer on a network with no WPAD: not an error, just `Direct`.
        Ok(steps) => {
            // Non-emptiness is enforced at the source — `ProxyResult::to_steps` returns
            // `PacInvalidResult` rather than an empty chain — so this holds for every
            // `Ok` the crate can construct. It stays as a guard on that contract, but it
            // is not what this call can still get wrong.
            assert!(!steps.is_empty(), "an empty chain is never a valid answer");
            // Neither is the loop below, though it reads like it. `to_steps` does drop
            // repeated entries, but no measured network answers WPAD with one: removing
            // that membership test left this test green here and on the runner alike, and
            // what holds the rule is `a_hop_the_script_names_twice_is_tried_once`, which
            // serves a script that makes the repeat certain. This stays as a guard on the
            // shape rather than as the thing that measures it.
            for (i, step) in steps.iter().enumerate() {
                assert!(
                    !steps[..i].contains(step),
                    "duplicate step {step:?} in {steps:?}"
                );
            }
        }
        // A network *with* a broken WPAD entry is allowed to fail; a panic or a hang is
        // not.
        Err(error) => assert!(
            matches!(
                error,
                Error::Io { .. } | Error::PacTimeout { .. } | Error::PacEvaluation { .. }
            ),
            "{error:?}"
        ),
    }
    assert!(elapsed < GIVE_UP_BUDGET * 3, "took {elapsed:?}");
}

#[test]
fn auto_detect_falling_back_to_a_url_still_reaches_the_url() {
    // On a machine with no WPAD, `AutoDetectThenUrl` must land on the served script.
    // On a machine that *does* have WPAD, any well-formed chain is acceptable.
    let server = PacServer::start(
        "function FindProxyForURL(url, host) { return 'PROXY fallback.example:9000'; }",
    );

    let resolver = resolver();
    // Which of those two machines this is decides what the answer may be, so ask before
    // judging rather than accepting anything non-empty: `to_steps` refuses to build an
    // empty chain, so `!steps.is_empty()` is true of every `Ok` and asserts nothing about
    // the fallback actually having happened.
    let wpad_alone = resolver.resolve(&target(), &WinHttpPacSource::AutoDetect);

    let steps = resolver
        .resolve(
            &target(),
            &WinHttpPacSource::AutoDetectThenUrl(server.url()),
        )
        .expect("the configured URL must be used when auto-detection finds nothing");

    if matches!(wpad_alone.as_deref(), Ok([ProxyStep::Direct])) {
        // Auto-detection alone found nothing, so the served script is the only source
        // left and its answer is the only chain that proves the URL was reached.
        assert_eq!(
            steps
                .first()
                .and_then(ProxyStep::endpoint)
                .map(|e| e.authority()),
            Some("fallback.example:9000".to_owned()),
            "{steps:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The snapshot-level entry point.
// ---------------------------------------------------------------------------

fn config(mode: ProxyMode) -> ProxyConfig {
    ProxyConfig::from_source(ProxyConfigSource::Registry, mode)
}

#[test]
fn resolve_config_answers_the_modes_plain_resolve_refuses() {
    let server = PacServer::start(
        "function FindProxyForURL(url, host) { return 'PROXY snapshot.example:8080'; }",
    );
    let snapshot = config(ProxyMode::pac(server.url()));

    // `resolve` alone still says "I would need a script".
    assert!(matches!(
        resolve(&snapshot, &target()),
        Err(Error::PacNotSupported { .. })
    ));

    let steps = resolver()
        .resolve_config(&snapshot, &target())
        .expect("the native resolver needs no script from the caller");
    assert_eq!(
        steps[0].endpoint().unwrap().authority(),
        "snapshot.example:8080"
    );
}

#[test]
fn resolve_config_delegates_the_non_pac_modes_verbatim() {
    let resolver = resolver();

    let direct = config(ProxyMode::Direct);
    assert_eq!(
        resolver.resolve_config(&direct, &target()).unwrap(),
        vec![ProxyStep::Direct]
    );

    let manual = config(parse::windows_manual("http=p.example:8080", "<local>"));
    let url = target();
    assert_eq!(
        resolver.resolve_config(&manual, &url).unwrap(),
        resolve(&manual, &url).unwrap()
    );
    assert_eq!(
        resolver.resolve_config(&manual, &url).unwrap()[0]
            .endpoint()
            .unwrap()
            .authority(),
        "p.example:8080"
    );

    // The bypass list still applies to manual mode, because that path is `resolve`.
    let intranet = Url::parse("http://intranet/").unwrap();
    assert_eq!(
        resolver.resolve_config(&manual, &intranet).unwrap(),
        vec![ProxyStep::Direct]
    );
}

#[test]
fn an_inline_script_is_refused_because_winhttp_takes_no_body() {
    let snapshot = config(ProxyMode::pac_inline(
        "function FindProxyForURL(u, h) { return 'DIRECT'; }".to_owned(),
    ));

    let error = resolver()
        .resolve_config(&snapshot, &target())
        .expect_err("WinHTTP has no entry point taking a script body");
    assert!(
        matches!(error, Error::PacNotSupported { mode: "pac-inline" }),
        "{error:?}"
    );

    // The exception to the rule the test below pins: every other mode answers a hostless
    // URL Direct without asking WinHTTP anything, and this one still refuses. Direct here
    // would report "no proxy" for a script that was never consulted, and the caller cannot
    // tell that answer from one the script gave. Which mode was refused is part of it —
    // fall through to the arm that names the unknown ones and the message stops telling
    // the caller their inline script is the thing this engine cannot take.
    let error = resolver()
        .resolve_config(
            &snapshot,
            &Url::parse("mailto:someone@example.net").unwrap(),
        )
        .expect_err("a body WinHTTP cannot take is refused with or without a host");
    assert!(
        matches!(error, Error::PacNotSupported { mode: "pac-inline" }),
        "{error:?}"
    );
}

#[test]
fn a_url_without_a_host_never_reaches_winhttp() {
    let server = PacServer::start("function FindProxyForURL(url, host) { return 'PROXY p:1'; }");
    let snapshot = config(ProxyMode::pac(server.url()));

    let steps = resolver()
        .resolve_config(
            &snapshot,
            &Url::parse("mailto:someone@example.net").unwrap(),
        )
        .expect("a URL with no host has no destination to proxy");
    assert_eq!(steps, vec![ProxyStep::Direct]);

    // The other spelling of "no host": `Url::host` answers `Some(Host::Domain(""))` here,
    // not `None`. `set_host(None)` on a non-special scheme is what builds it (measured on
    // url 2.5.8; the special schemes refuse with `EmptyHost`). `resolve` and
    // `resolve_with_pac` route through `resolve::request_host`, which refuses an empty
    // domain, so asking `Url::host` directly here would send a URL with nothing to connect
    // to through a full PAC fetch and hand the script `socks5:/path`.
    let mut emptied = Url::parse("socks5://host:1080/path").unwrap();
    emptied
        .set_host(None)
        .expect("a non-special scheme may drop its host");
    let steps = resolver()
        .resolve_config(&snapshot, &emptied)
        .expect("an empty host is still no destination to proxy");
    assert_eq!(steps, vec![ProxyStep::Direct]);

    // The `WpadAutoDetect` arm asked the same question with the same wrong predicate and is
    // reached by a different match arm, so `Pac` above does not cover it. No network is
    // needed for the passing side: the short-circuit answers before any discovery starts,
    // which is the whole point of testing it here.
    let wpad = config(ProxyMode::WpadAutoDetect);
    for url in [Url::parse("mailto:someone@example.net").unwrap(), emptied] {
        let steps = resolver()
            .resolve_config(&wpad, &url)
            .expect("auto-detect has nothing to discover for a hostless URL");
        assert_eq!(steps, vec![ProxyStep::Direct], "{url}");
    }
}

// ---------------------------------------------------------------------------
// Shape.
// ---------------------------------------------------------------------------

#[test]
fn a_resolver_may_be_shared_between_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WinHttpPacResolver>();

    let server = PacServer::start(
        "function FindProxyForURL(url, host) { return 'PROXY shared.example:8080'; }",
    );
    let source = WinHttpPacSource::Url(server.url());
    let shared = Arc::new(resolver());

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let shared = Arc::clone(&shared);
            let source = source.clone();
            thread::spawn(move || {
                shared
                    .resolve(&target(), &source)
                    .expect("concurrent resolution")
            })
        })
        .collect();

    for handle in handles {
        let steps = handle.join().expect("the worker must not panic");
        assert_eq!(
            steps[0].endpoint().unwrap().authority(),
            "shared.example:8080"
        );
    }
}

#[test]
fn the_default_budget_is_reported() {
    let resolver = WinHttpPacResolver::new().expect("opening a WinHTTP session");
    assert_eq!(
        resolver.timeout(),
        proxy_watch::pac::DEFAULT_WINHTTP_PAC_TIMEOUT
    );
}

#[test]
fn sources_map_onto_the_auto_config_modes() {
    let url = Url::parse("http://wpad.corp.example/proxy.pac").unwrap();
    assert_eq!(
        WinHttpPacSource::from_mode(&ProxyMode::pac(url.clone())),
        Some(WinHttpPacSource::Url(url))
    );
    assert_eq!(
        WinHttpPacSource::from_mode(&ProxyMode::WpadAutoDetect),
        Some(WinHttpPacSource::AutoDetect)
    );
    assert_eq!(WinHttpPacSource::from_mode(&ProxyMode::Direct), None);
    assert_eq!(
        WinHttpPacSource::from_mode(&ProxyMode::pac_inline(String::new())),
        None
    );
}
