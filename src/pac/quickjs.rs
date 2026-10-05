//! `pac-quickjs`: PAC on QuickJS (`rquickjs`). Hostfns in [`super::hostfn`].
//!
//! The PAC host functions only: no fetch/XHR/FS; `rquickjs` without its `loader` feature
//! has no module loader and no `std`/`os` objects to leave out. The engine can be
//! stopped: the wall-clock deadline is checked from inside the interpreter, the
//! regular-expression matcher included, and the parser checks the native stack instead of
//! overflowing it.

use std::time::Instant;

use rquickjs::context::EvalOptions;
use rquickjs::convert::Coerced;
use rquickjs::function::{Opt, Rest};
use rquickjs::{CatchResultExt, CaughtError, Context, Ctx, FromJs, Function, Runtime, Value};
use url::Url;

use crate::error::Error;
use crate::resolve::ProxyStep;

use super::policy::PacPolicy;
use super::result::parse_find_proxy_result;
use super::{PacEvaluator, PacScript, budget, hostfn};

// Heap for one evaluation. PAC scripts are a few kilobytes of string tests; this is room
// for a large one many times over, and a script that allocates past it gets an exception
// instead of the host's memory. `rquickjs`'s `rust-alloc` and `allocator`
// features make the limit a no-op, and Cargo unions features across the build, so a
// dependent that turns either on removes it.
const MEMORY_LIMIT: usize = 64 * 1024 * 1024;

// Native stack the interpreter and the parser may use before they raise `RangeError`. It is
// measured from where the runtime is created, and with `PacPolicy::with_timeout(None)` that
// is the caller's own thread (1 MiB on a Windows main thread), so it stays well under that.
const STACK_LIMIT: usize = 256 * 1024;

/// [`PacEvaluator`] on QuickJS. Prefers `FindProxyForURL`; `FindProxyForURLEx` only if it
/// is the sole entry point (Ex-only hostfns are not registered).
///
/// Of [`PacPolicy`]'s limits it honours the timeout, and enforces it: a script still
/// running at the deadline is interrupted, so the evaluation thread ends with the call,
/// unless it is inside a host function then, such as `dnsResolve` waiting on the system
/// resolver, which holds the thread until it returns. A fixed 64 MiB heap and a fixed 256
/// KiB native stack bound the rest, and a script that exceeds either gets an exception
/// rather than aborting the process. The heap bound holds only while nothing in the build
/// turns on `rquickjs`'s `rust-alloc` or `allocator` feature, which removes it. The
/// host-function settings (DNS, internal addresses, `myIpAddress`, the clock and the UTC
/// offset) all apply.
///
/// ```
/// # #[cfg(pac_quickjs)] {
/// use proxy_watch::pac::{PacEvaluator, PacPolicy, PacScript, QuickJsEvaluator};
/// use proxy_watch::Url;
///
/// let evaluator = QuickJsEvaluator::new(PacPolicy::new());
/// let script = PacScript::new("function FindProxyForURL(url, host) { return 'DIRECT'; }");
/// let url = Url::parse("http://example.com/").unwrap();
///
/// let steps = evaluator.evaluate(&script, &url, "example.com")?;
/// assert!(steps[0].is_direct());
/// # }
/// # Ok::<(), proxy_watch::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct QuickJsEvaluator {
    policy: PacPolicy,
}

impl QuickJsEvaluator {
    /// Build an evaluator that runs scripts under `policy`.
    #[must_use]
    pub fn new(policy: PacPolicy) -> Self {
        Self { policy }
    }

    /// The policy this evaluator applies.
    #[must_use]
    pub fn policy(&self) -> &PacPolicy {
        &self.policy
    }
}

impl PacEvaluator for QuickJsEvaluator {
    fn evaluate(&self, script: &PacScript, url: &Url, host: &str) -> Result<Vec<ProxyStep>, Error> {
        // Idempotent, and repeated here because this impl is reachable without going
        // through `pac::evaluate_with_host`; see `PacEvaluator::evaluate`'s doc.
        let url = &crate::pac::sanitize_url(url);
        let policy = self.policy;
        // The thread and its slot stay even though the script can be interrupted: the
        // interrupt is not checked while a host function runs, and `dnsResolve` with DNS
        // enabled can sit in the system resolver past the deadline.
        match policy.timeout() {
            Some(timeout) => {
                let (source, url, host) = (
                    script.source().to_owned(),
                    url.as_str().to_owned(),
                    host.to_owned(),
                );
                // The interrupt and the caller's wait end at the same instant, and whichever
                // is first decides the answer. A failure at or past the deadline is the
                // interrupt, and is reported as the timeout it is.
                budget::run_with_timeout(timeout, &budget::SLOTS, move |deadline| {
                    run(&source, &url, &host, policy, deadline).map_err(|error| match deadline {
                        Some(deadline) if Instant::now() >= deadline => {
                            Error::PacTimeout { timeout }
                        }
                        _ => error,
                    })
                })
            }
            None => run(script.source(), url.as_str(), host, policy, None),
        }
    }
}

// Build a runtime, load the script, call `FindProxyForURL` and parse the answer, stopping
// the script at `deadline`.
fn run(
    source: &str,
    url: &str,
    host: &str,
    policy: PacPolicy,
    deadline: Option<Instant>,
) -> Result<Vec<ProxyStep>, Error> {
    parse_find_proxy_result(&run_raw(source, url, host, policy, deadline)?)
}

// `run` up to the string `FindProxyForURL` returned, unparsed.
pub(super) fn run_raw(
    source: &str,
    url: &str,
    host: &str,
    policy: PacPolicy,
    deadline: Option<Instant>,
) -> Result<String, Error> {
    let setup = |error: rquickjs::Error| {
        Error::pac_evaluation(format!("could not start the QuickJS runtime: {error}"))
    };
    let runtime = Runtime::new().map_err(setup)?;
    runtime.set_memory_limit(MEMORY_LIMIT);
    runtime.set_max_stack_size(STACK_LIMIT);
    if let Some(deadline) = deadline {
        runtime.set_interrupt_handler(Some(Box::new(move || Instant::now() >= deadline)));
    }
    let context = Context::full(&runtime).map_err(setup)?;

    context.with(|ctx| {
        register_host_functions(&ctx, policy).map_err(|error| {
            Error::pac_evaluation(format!("could not install the PAC host functions: {error}"))
        })?;

        // Sloppy, as a browser loads a PAC file: `rquickjs`'s default options are strict,
        // which turns an undeclared assignment (common in hand-written PAC files) into a
        // `ReferenceError` and the whole script into an evaluation failure.
        let mut options = EvalOptions::default();
        options.strict = false;
        ctx.eval_with_options::<(), _>(source, options)
            .catch(&ctx)
            .map_err(|error| failure("the PAC script failed to load", &ctx, error))?;

        // Reading the entry point can throw (an accessor or `Proxy` trap under the name);
        // that is propagated rather than read as absence.
        let globals = ctx.globals();
        let mut callee = None;
        for name in ["FindProxyForURL", "FindProxyForURLEx"] {
            let value: Value = globals
                .get(name)
                .catch(&ctx)
                .map_err(|error| failure("reading the PAC entry point failed", &ctx, error))?;
            if let Some(function) = value.into_function() {
                callee = Some(function);
                break;
            }
        }
        let Some(callee) = callee else {
            return Err(Error::pac_evaluation(
                "the PAC script defines no FindProxyForURL function",
            ));
        };

        let returned: Value = callee
            .call((url, host))
            .catch(&ctx)
            .map_err(|error| failure("FindProxyForURL failed", &ctx, error))?;
        let text = Coerced::<String>::from_js(&ctx, returned)
            .catch(&ctx)
            .map_err(|error| {
                failure(
                    "FindProxyForURL returned a value that is not a string",
                    &ctx,
                    error,
                )
            })?
            .0;

        Ok(text)
    })
}

// What the script threw, as text for `Error::pac_evaluation` to mask and sanitize.
fn failure<'js>(what: &str, ctx: &Ctx<'js>, error: CaughtError<'js>) -> Error {
    let detail = match error {
        CaughtError::Exception(exception) => exception.message().unwrap_or_default(),
        CaughtError::Value(value) => Coerced::<String>::from_js(ctx, value)
            .map_or_else(|_| "a value that is not a string".to_owned(), |text| text.0),
        CaughtError::Error(error) => error.to_string(),
    };
    Error::pac_evaluation(format!("{what}: {detail}"))
}

// Argument as a string, a missing one read as `""`.
fn text(arg: Opt<Coerced<String>>) -> String {
    arg.0.map(|text| text.0).unwrap_or_default()
}

// The longest call `dateRange` or `timeRange` answers: a full day-month-year or
// hour-minute-second range, then `GMT`.
const MAX_RANGE_ARGS: usize = 7;

// The range functions' arguments as strings, or `None` for a list too long to answer.
// The count is checked before any conversion: a Rust `String` sits outside the QuickJS
// memory limit, so `timeRange.apply(null, Array(10000).fill(s))` with one shared 1 MiB
// `s` would otherwise ask the host for 10 GiB before the call could say `false`.
fn texts<'js>(args: Rest<Value<'js>>) -> rquickjs::Result<Option<Vec<String>>> {
    if args.0.len() > MAX_RANGE_ARGS {
        return Ok(None);
    }
    args.0
        .into_iter()
        .map(|value| Ok(Coerced::<String>::from_js(&value.ctx().clone(), value)?.0))
        .collect::<rquickjs::Result<_>>()
        .map(Some)
}

// Install the PAC host functions on the global object.
fn register_host_functions<'js>(ctx: &Ctx<'js>, policy: PacPolicy) -> rquickjs::Result<()> {
    let globals = ctx.globals();
    let bind = |name: &str, function: Function<'js>| globals.set(name, function);

    bind(
        "isPlainHostName",
        Function::new(ctx.clone(), |host| hostfn::is_plain_host_name(&text(host)))?,
    )?;
    bind(
        "dnsDomainIs",
        Function::new(ctx.clone(), |host, domain| {
            hostfn::dns_domain_is(&text(host), &text(domain))
        })?,
    )?;
    bind(
        "localHostOrDomainIs",
        Function::new(ctx.clone(), |host, hostdom| {
            hostfn::local_host_or_domain_is(&text(host), &text(hostdom))
        })?,
    )?;
    bind(
        "isResolvable",
        Function::new(ctx.clone(), move |host| {
            hostfn::is_resolvable(&text(host), &policy)
        })?,
    )?;
    bind(
        "isInNet",
        Function::new(ctx.clone(), move |host, pattern, mask| {
            hostfn::is_in_net(&text(host), &text(pattern), &text(mask), &policy)
        })?,
    )?;
    bind(
        "dnsResolve",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, host| -> rquickjs::Result<Value<'js>> {
                Ok(match hostfn::dns_resolve(&text(host), &policy) {
                    Some(address) => {
                        rquickjs::String::from_str(ctx, &address.to_string())?.into_value()
                    }
                    // The PAC contract is `null`, not `undefined`: scripts test it with
                    // `if (ip == null)`, and only `===` tells the two apart.
                    None => Value::new_null(ctx),
                })
            },
        )?,
    )?;
    bind(
        "myIpAddress",
        Function::new(ctx.clone(), move || {
            hostfn::my_ip_address(&policy).to_string()
        })?,
    )?;
    bind(
        "dnsDomainLevels",
        Function::new(ctx.clone(), |host| {
            hostfn::dns_domain_levels(&text(host)) as f64
        })?,
    )?;
    bind(
        "shExpMatch",
        Function::new(ctx.clone(), |text_arg, pattern| {
            hostfn::sh_exp_match(&text(text_arg), &text(pattern))
        })?,
    )?;
    bind(
        "weekdayRange",
        Function::new(ctx.clone(), move |args| {
            Ok::<_, rquickjs::Error>(
                texts(args)?.is_some_and(|args| hostfn::weekday_range(&args, &policy)),
            )
        })?,
    )?;
    bind(
        "dateRange",
        Function::new(ctx.clone(), move |args| {
            Ok::<_, rquickjs::Error>(
                texts(args)?.is_some_and(|args| hostfn::date_range(&args, &policy)),
            )
        })?,
    )?;
    bind(
        "timeRange",
        Function::new(ctx.clone(), move |args| {
            Ok::<_, rquickjs::Error>(
                texts(args)?.is_some_and(|args| hostfn::time_range(&args, &policy)),
            )
        })?,
    )?;
    bind(
        "alert",
        Function::new(ctx.clone(), |message| hostfn::alert(&text(message)))?,
    )?;
    bind(
        "convert_addr",
        Function::new(ctx.clone(), |address| {
            f64::from(hostfn::convert_addr(&text(address)))
        })?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    fn steps(source: &str, url: &str, policy: PacPolicy) -> Result<Vec<ProxyStep>, Error> {
        let url = Url::parse(url).unwrap();
        let host = url.host_str().unwrap_or_default().to_owned();
        QuickJsEvaluator::new(policy).evaluate(&PacScript::new(source), &url, &host)
    }

    // `run` on the test's own thread with a deadline, so the only thing that can end an
    // endless script is the interrupt: no abandoned thread, no `recv_timeout` giving up.
    fn run_until(source: &str, budget: Duration) -> Result<Vec<ProxyStep>, Error> {
        run(
            source,
            "http://a/",
            "a",
            PacPolicy::new(),
            Some(Instant::now() + budget),
        )
    }

    #[test]
    fn a_constant_script_returns_direct() {
        let result = steps(
            "function FindProxyForURL(url, host) { return 'DIRECT'; }",
            "http://example.com/",
            PacPolicy::new(),
        )
        .unwrap();
        assert_eq!(result, vec![ProxyStep::Direct]);
    }

    // PAC files are written for browsers, which load them as ordinary (sloppy) scripts: an
    // undeclared assignment creates a global, and a legacy octal literal is a number.
    #[test]
    fn a_script_loads_as_a_sloppy_script_as_browsers_load_it() {
        let result = steps(
            "function FindProxyForURL(url, host) {
                 ip = '10.0.0.1';
                 if (ip === '10.0.0.1' && 010 === 8) { return 'PROXY p.example:8080'; }
                 return 'DIRECT';
             }",
            "http://example.com/",
            PacPolicy::new(),
        )
        .unwrap();
        assert_eq!(result.len(), 1, "{result:?}");
        assert_ne!(result[0], ProxyStep::Direct);
    }

    #[test]
    fn a_zero_timeout_is_a_budget_of_nothing_not_the_absence_of_one() {
        let error = steps(
            "function FindProxyForURL(url, host) { return 'DIRECT'; }",
            "http://example.com/",
            PacPolicy::new().with_timeout(Some(Duration::ZERO)),
        )
        .unwrap_err();
        assert!(
            matches!(error, Error::PacTimeout { timeout } if timeout.is_zero()),
            "{error:?}"
        );
    }

    #[test]
    fn the_script_is_handed_a_sanitized_url_and_the_host() {
        let source = "function FindProxyForURL(url, host) {
                 if (url === 'http://example.net/a/b?q=1' && host === 'example.net') {
                     return 'DIRECT';
                 }
                 return 'PROXY leaked:1';
             }";
        let result = steps(
            source,
            "http://alice:hunter2@example.net/a/b?q=1#frag",
            PacPolicy::new(),
        )
        .unwrap();
        assert_eq!(result, vec![ProxyStep::Direct]);
    }

    #[test]
    fn the_plain_entry_point_wins_and_ex_runs_when_alone() {
        let both = "function FindProxyForURL(url, host) { return 'PROXY plain:1'; }
                    function FindProxyForURLEx(url, host) { return 'PROXY ex:1'; }";
        let result = steps(both, "http://example.com/", PacPolicy::new()).unwrap();
        assert_eq!(result[0].endpoint().unwrap().authority(), "plain:1");

        let ex = "function FindProxyForURLEx(url, host) { return 'PROXY ex:1'; }";
        let result = steps(ex, "http://example.com/", PacPolicy::new()).unwrap();
        assert_eq!(result[0].endpoint().unwrap().authority(), "ex:1");
    }

    #[test]
    fn every_host_function_is_bound() {
        let source = "function FindProxyForURL(url, host) {
                 alert('hello');
                 var used = [
                     isPlainHostName(host),
                     dnsDomainIs(host, '.example'),
                     localHostOrDomainIs(host, 'www.example'),
                     isResolvable(host),
                     isInNet(host, '10.0.0.0', '255.0.0.0'),
                     dnsResolve(host),
                     myIpAddress(),
                     dnsDomainLevels(host),
                     shExpMatch(url, 'http:*'),
                     weekdayRange('MON', 'FRI'),
                     dateRange('JAN', 'DEC'),
                     timeRange(0, 23),
                     convert_addr('127.0.0.1')
                 ];
                 return 'PROXY ok:' + used.length;
             }";
        let result = steps(source, "http://example.com/", PacPolicy::new()).unwrap();
        assert_eq!(result[0].endpoint().unwrap().port, 13);
    }

    // A left-out argument is read as `""`, and `dnsResolve` answers `null`.
    #[test]
    fn an_argument_the_script_leaves_out_is_read_as_the_empty_string() {
        let source = "function FindProxyForURL(url, host) {
                 return 'PROXY ' + [
                     isPlainHostName(),
                     dnsDomainIs(host),
                     localHostOrDomainIs(host),
                     shExpMatch(url),
                     isInNet(host, '10.0.0.0'),
                     dnsResolve(),
                     dnsDomainLevels(),
                     weekdayRange(),
                     dateRange(),
                     timeRange()
                 ].map(String).join('-') + ':1';
             }";
        let result = steps(source, "http://example.com/", PacPolicy::new()).unwrap();
        assert_eq!(
            result[0].endpoint().unwrap().authority(),
            "true-true-false-false-false-null-0-false-false-false:1"
        );
    }

    // Past `MAX_RANGE_ARGS` no argument is converted: `n` counts the `toString` calls.
    #[test]
    fn a_range_call_too_long_to_answer_converts_none_of_its_arguments() {
        let source = "function FindProxyForURL(url, host) {
                 var n = 0;
                 var o = { toString: function () { n++; return '1'; } };
                 var eight = [o, o, o, o, o, o, o, o];
                 var answers = [
                     weekdayRange.apply(null, eight),
                     dateRange.apply(null, eight),
                     timeRange.apply(null, eight)
                 ];
                 var before = n;
                 timeRange(o, o, o, o, o, o, o);
                 return 'PROXY ' + answers.join('-') + '-' + before + '-' + n + ':1';
             }";
        let result = steps(source, "http://example.com/", PacPolicy::new()).unwrap();
        assert_eq!(
            result[0].endpoint().unwrap().authority(),
            "false-false-false-0-7:1"
        );
    }

    // Each row moves if that call's arguments are exchanged.
    #[test]
    fn each_host_function_receives_its_arguments_in_the_documented_order() {
        let source = "function FindProxyForURL(url, host) {
                 return 'PROXY ' + [
                     dnsDomainIs('www.corp.example', '.corp.example'),
                     localHostOrDomainIs('www', 'www.corp.example'),
                     isInNet('10.0.1.5', '10.0.0.0', '255.255.0.0'),
                     isInNet('10.0.1.5', '10.0.0.0', '255.255.255.0'),
                     shExpMatch('http://www.corp.example/x', 'http://*.corp.example/*')
                 ].map(String).join('-') + ':1';
             }";
        let result = steps(source, "http://example.com/", PacPolicy::new()).unwrap();
        assert_eq!(
            result[0].endpoint().unwrap().authority(),
            "true-true-true-false-true:1"
        );
    }

    #[test]
    fn the_policy_reaches_the_host_functions() {
        let source = "function FindProxyForURL(url, host) {
                 if (dnsResolve(host) != null) { return 'PROXY leaked:1'; }
                 if (weekdayRange('MON', 'FRI') && timeRange(9, 17) && dateRange('FEB')) {
                     return 'PROXY ' + myIpAddress() + ':1';
                 }
                 return 'DIRECT';
             }";
        // 2024-02-29T13:45:07Z, a Thursday.
        let policy = PacPolicy::new()
            .with_my_ip_address("192.0.2.7".parse().unwrap())
            .with_now(UNIX_EPOCH + Duration::from_secs(1_709_214_307));
        let result = steps(source, "http://example.com/", policy).unwrap();
        assert_eq!(result[0].endpoint().unwrap().authority(), "192.0.2.7:1");
    }

    // The interrupt, not the wall clock of a caller that stopped waiting: `run` is on this
    // thread, so returning at all means the script was stopped.
    #[test]
    fn an_endless_loop_is_interrupted_at_the_deadline() {
        let started = Instant::now();
        let error = run_until(
            "function FindProxyForURL(url, host) { for (;;) {} }",
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    // A loop split across calls, which no per-frame iteration cap would ever stop.
    #[test]
    fn a_loop_split_across_calls_is_interrupted_too() {
        let started = Instant::now();
        let error = run_until(
            "function spin() { for (var i = 0; i < 1000; i++) {} }
             function FindProxyForURL(url, host) { for (;;) { spin(); } }",
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    // Catastrophic backtracking runs inside one `test` call; the matcher polls the same
    // interrupt handler. 40 characters is far past what finishes in the lifetime of a test.
    #[test]
    fn a_backtracking_regular_expression_is_interrupted() {
        let started = Instant::now();
        let error = run_until(
            "function FindProxyForURL(url, host) {
                 return /^(a+)+$/.test('a'.repeat(40) + 'b') ? 'DIRECT' : 'PROXY p:1';
             }",
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    // Nesting that overflows a recursive-descent parser without a depth check is an
    // exception here: the parser checks the native stack as it goes.
    #[test]
    fn deep_nesting_is_an_error_not_an_abort() {
        let source = format!(
            "function FindProxyForURL(url, host) {{ return {}1{}; }}",
            "(".repeat(100_000),
            ")".repeat(100_000)
        );
        let error = steps(&source, "http://a/", PacPolicy::new()).unwrap_err();
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
    }

    #[test]
    fn unbounded_recursion_is_an_error() {
        let error = steps(
            "function boom(n) { return boom(n + 1); }
             function FindProxyForURL(url, host) { return boom(0); }",
            "http://a/",
            PacPolicy::new(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
    }

    // One 128 MiB buffer: a script that finishes without `MEMORY_LIMIT` and fails with it.
    // Doubling a string is no test of the limit, since QuickJS's own string-length cap stops
    // that first. No timeout, so the limit is the only thing that can end it.
    #[test]
    fn the_heap_is_bounded() {
        let error = steps(
            "function FindProxyForURL(url, host) {
                 var kept = new ArrayBuffer(128 * 1024 * 1024);
                 return kept.byteLength > 0 ? 'DIRECT' : 'PROXY p:1';
             }",
            "http://a/",
            PacPolicy::new().with_timeout(None),
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
    }

    #[test]
    fn a_thrown_string_is_masked_and_sanitized_end_to_end() {
        let error = steps(
            "function FindProxyForURL(url, host) { \
                 throw 'leaked http://alice:hunter2@proxy.corp/x.pac\\nWARN forged line'; \
             }",
            "http://a/",
            PacPolicy::new(),
        )
        .unwrap_err();
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
        assert!(!display.contains("hunter2"), "{display}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(!display.contains('\n'), "{display}");
        assert!(display.contains("proxy.corp"), "{display}");
    }

    #[test]
    fn a_throwing_entry_point_getter_is_not_reported_as_a_missing_entry_point() {
        let error = steps(
            "Object.defineProperty(globalThis, 'FindProxyForURL', {
                 get: function () { throw new Error('tripwire'); }
             });",
            "http://a/",
            PacPolicy::new(),
        )
        .unwrap_err();
        let display = error.to_string();
        assert!(!display.contains("defines no FindProxyForURL"), "{display}");
        assert!(display.contains("tripwire"), "{display}");
    }

    #[test]
    fn a_script_without_the_entry_point_is_an_error() {
        let error = steps("var x = 1;", "http://a/", PacPolicy::new()).unwrap_err();
        assert!(
            error.to_string().contains("defines no FindProxyForURL"),
            "{error}"
        );
    }

    #[test]
    fn a_nonsense_return_value_is_an_error() {
        let error = steps(
            "function FindProxyForURL(url, host) { return 'GOPHER g:70'; }",
            "http://a/",
            PacPolicy::new(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacInvalidResult { .. }), "{error:?}");
    }

    #[test]
    fn the_runtime_offers_no_way_out() {
        for escape in [
            "fetch('http://evil/')",
            "require('fs')",
            "XMLHttpRequest",
            "process.exit(1)",
            "std.loadFile('/etc/passwd')",
            "os.exec(['sh'])",
            "globalThis.WebAssembly.compile",
        ] {
            let source =
                format!("function FindProxyForURL(url, host) {{ {escape}; return 'DIRECT'; }}");
            let error = steps(&source, "http://a/", PacPolicy::new()).unwrap_err();
            assert!(
                matches!(error, Error::PacEvaluation { .. }),
                "{escape} gave {error:?}"
            );
        }
    }
}
