//! `SubprocessEvaluator` against the real `proxy-watch-pac-worker` binary.
#![cfg(all(feature = "pac-subprocess", pac_quickjs))]

use std::time::{Duration, Instant};

use proxy_watch::pac::{PacEvaluator, PacPolicy, PacScript, SubprocessEvaluator};
use proxy_watch::{Error, ProxyStep, Url};

const WORKER: &str = env!("CARGO_BIN_EXE_proxy-watch-pac-worker");

// Where the worker confines itself.
const CONFINED: bool = cfg!(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
));

// Elsewhere the worker cannot confine itself, and these tests run it unconfined.
fn run(policy: PacPolicy, body: &str) -> Result<Vec<ProxyStep>, Error> {
    let evaluator = SubprocessEvaluator::new(WORKER, policy);
    let evaluator = if CONFINED {
        evaluator
    } else {
        evaluator.allow_unsandboxed()
    };
    let url = Url::parse("http://example.net/path").unwrap();
    evaluator.evaluate(&PacScript::new(body), &url, "example.net")
}

// What a script can reach inside the sandbox: the clock and local time, randomness, a name
// lookup through the parent, a recursion or allocation QuickJS stops, and a thrown error. A
// call the filter does not allow would kill the worker instead of answering. Filling the
// heap to its limit takes seconds, close to the default deadline, so the deadline is widened.
#[test]
fn a_script_runs_its_whole_repertoire_inside_the_sandbox() {
    let body = "function FindProxyForURL() {
        var d = new Date();
        var local = d.toString() + d.getTimezoneOffset() + Date.now() + Math.random();
        var deep = false;
        try { (function f() { f(); })(); } catch (e) { deep = e instanceof RangeError; }
        var big = false;
        try { var a = []; for (;;) a.push(new Array(1e6).fill(1)); } catch (e) { a = null; big = true; }
        var caught = false;
        try { throw new Error('x'); } catch (e) { caught = true; }
        var looked = dnsResolve('localhost');
        return local && deep && big && caught && looked === null ? 'DIRECT' : 'PROXY no:1';
    }";
    let policy = PacPolicy::new().with_timeout(Some(Duration::from_secs(60)));
    assert!(run(policy, body).unwrap()[0].is_direct());
}

#[test]
fn an_unconfined_worker_is_refused_unless_allowed() {
    let url = Url::parse("http://example.net/").unwrap();
    let script = PacScript::new("function FindProxyForURL() { return 'DIRECT'; }");
    let result =
        SubprocessEvaluator::new(WORKER, PacPolicy::new()).evaluate(&script, &url, "example.net");
    if CONFINED {
        assert!(result.unwrap()[0].is_direct());
    } else {
        match result {
            Err(Error::Io { source, .. }) => {
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied)
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn the_worker_answers_and_the_parent_parses() {
    let steps = run(
        PacPolicy::new(),
        "function FindProxyForURL(url, host) { return 'PROXY p.example:3128; DIRECT'; }",
    )
    .unwrap();
    assert_eq!(steps.len(), 2);
    assert!(steps[1].is_direct());
}

#[test]
fn a_script_that_throws_is_an_evaluation_error() {
    let error = run(
        PacPolicy::new(),
        "function FindProxyForURL() { throw 'nope'; }",
    )
    .unwrap_err();
    assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
    // The worker sends the engine's reason, not its own `Display`, so the prefix is said once.
    assert_eq!(
        error.to_string().matches("PAC evaluation failed").count(),
        1,
        "{error}"
    );
}

// Killed at the deadline, and the slot comes back: more loops than there are slots all
// time out rather than the later ones reporting saturation.
#[test]
fn a_script_that_never_returns_is_killed_at_the_deadline() {
    let policy = PacPolicy::new().with_timeout(Some(Duration::from_millis(500)));
    for _ in 0..std::thread::available_parallelism().map_or(4, |n| n.get().max(4)) + 1 {
        let started = Instant::now();
        let error = run(policy, "function FindProxyForURL() { for (;;) {} }").unwrap_err();
        assert!(matches!(error, Error::PacTimeout { .. }), "{error:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }
}

// Lookups go to the parent and are answered under the parent's policy.
#[test]
fn name_lookups_follow_the_parent_policy() {
    let body = "function FindProxyForURL() { \
                return isResolvable('localhost') ? 'PROXY yes:1' : 'DIRECT'; }";
    assert!(run(PacPolicy::new(), body).unwrap()[0].is_direct());
    let open = PacPolicy::new()
        .with_dns_resolution(true)
        .with_internal_addresses(true);
    assert!(!run(open, body).unwrap()[0].is_direct());
}

#[test]
fn the_clock_and_address_reach_the_worker() {
    let policy = PacPolicy::new()
        .with_my_ip_address("192.0.2.7".parse().unwrap())
        // 2001-09-09T01:46:40Z, a Sunday.
        .with_now(std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000));
    let body = "function FindProxyForURL() { \
                return myIpAddress() == '192.0.2.7' && weekdayRange('SUN') ? 'DIRECT' : 'PROXY no:1'; }";
    assert!(run(policy, body).unwrap()[0].is_direct());
}

#[test]
fn a_worker_that_is_not_there_is_an_io_error() {
    let url = Url::parse("http://example.net/").unwrap();
    let evaluator = SubprocessEvaluator::new(
        std::path::Path::new(WORKER).with_file_name("no-such-worker"),
        PacPolicy::new(),
    );
    let error = evaluator
        .evaluate(&PacScript::new(""), &url, "example.net")
        .unwrap_err();
    assert!(matches!(error, Error::Io { .. }), "{error:?}");
}

// A bare name is refused rather than looked up on the `PATH`, even when the directory it
// would be found in holds the real worker.
#[test]
fn a_worker_named_without_a_path_is_refused() {
    let worker = std::path::Path::new(WORKER);
    let directory = worker.parent().unwrap().to_owned();
    let path = std::env::join_paths(std::iter::once(directory).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    // SAFETY: the other tests in this binary reach the environment only through `std`
    // (spawning the worker), which takes the same lock `set_var` does.
    unsafe { std::env::set_var("PATH", path) };
    let url = Url::parse("http://example.net/").unwrap();
    let evaluator = SubprocessEvaluator::new(worker.file_name().unwrap(), PacPolicy::new());
    let error = evaluator
        .evaluate(
            &PacScript::new("function FindProxyForURL() { return 'DIRECT'; }"),
            &url,
            "example.net",
        )
        .unwrap_err();
    assert!(matches!(error, Error::Io { .. }), "{error:?}");
}
