//! `pac-boa`: PAC on `boa_engine`. Hostfns in [`super::hostfn`]; limits in [`PacPolicy`].
//!
//! The PAC host functions only — no fetch/XHR/FS. Loop/recursion/stack caps plus
//! optional wall-clock timeout on a dedicated thread (overrun thread abandoned).
//! Untrusted PAC: enable DNS/local-IP only via [`PacPolicy`]; bound heap/work outside this crate.
//! None of those caps reaches the parse phase — deep nesting overflows the native stack and
//! aborts the process before `run` gets a chance to enforce anything. [`PacPolicy`]'s own
//! documentation carries the measurement and what a caller has to do about it.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use boa_engine::{Context, JsResult, JsValue, NativeFunction, Source, js_string};
use url::Url;

use crate::error::Error;
use crate::resolve::ProxyStep;

use super::hostfn;
use super::policy::PacPolicy;
use super::result::parse_find_proxy_result;
use super::{PacEvaluator, PacScript};

/// [`PacEvaluator`] on `boa_engine`. Prefers `FindProxyForURL`; `FindProxyForURLEx` only if
/// it is the sole entry point (Ex-only hostfns are not registered).
///
/// A deeply nested script aborts the process while parsing, before any [`PacPolicy`] limit
/// applies; see [`PacPolicy`] for the measurement and the caller-side mitigation.
///
/// ```
/// # #[cfg(feature = "pac-boa")] {
/// use proxy_watch::pac::{BoaEvaluator, PacEvaluator, PacPolicy, PacScript};
/// use proxy_watch::Url;
///
/// let evaluator = BoaEvaluator::new(PacPolicy::new());
/// let script = PacScript::new("function FindProxyForURL(url, host) { return 'DIRECT'; }");
/// let url = Url::parse("http://example.com/").unwrap();
///
/// let steps = evaluator.evaluate(&script, &url, "example.com")?;
/// assert!(steps[0].is_direct());
/// # }
/// # Ok::<(), proxy_watch::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct BoaEvaluator {
    policy: PacPolicy,
}

impl BoaEvaluator {
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

impl PacEvaluator for BoaEvaluator {
    fn evaluate(&self, script: &PacScript, url: &Url, host: &str) -> Result<Vec<ProxyStep>, Error> {
        // Idempotent, and repeated here because this impl is reachable without going
        // through `pac::evaluate_with_host` — see `PacEvaluator::evaluate`'s doc.
        let url = &crate::pac::sanitize_url(url);
        match self.policy.timeout() {
            Some(timeout) => run_with_timeout(
                script.source().to_owned(),
                url.as_str().to_owned(),
                host.to_owned(),
                self.policy,
                timeout,
            ),
            None => run(script.source(), url.as_str(), host, self.policy),
        }
    }
}

// Run the script on a throw-away thread and give up on it after `timeout`.
//
// A zero `timeout` means "no budget at all" here, not "unlimited", and is answered before
// the thread exists. Letting it through would spawn the script and then `recv_timeout` would
// return at once, leaving untrusted code running on a thread nothing is waiting on — a budget
// of nothing has to buy nothing, not an unsupervised run.
// [`super::winhttp::WinHttpPacResolver`] refuses zero too, for a reason of its own
// (`WinHttpSetTimeouts` reads it as infinite), and one step earlier: at construction rather
// than per evaluation.
//
// What the timeout does not do is stop the thread. `recv_timeout` gives up on the answer; the
// script keeps running. In the ordinary case that still ends, because [`run`] applies the loop,
// recursion and value-stack caps to the context it builds, and an abandoned evaluation walks
// into one of them. The caps are not a termination proof, though, and two paths leave them
// behind outright. Parsing is one, and it is worse than unbounded — it aborts the process, as
// this module's own doc says up top. The other is [`super::hostfn::dns_resolve`], which asks
// the system resolver through `(host, 0).to_socket_addrs()`; std puts no timeout on that call,
// so a script naming a host nothing answers for parks the abandoned thread in the resolver for
// as long as the OS takes, with no cap of ours in the way. That second path is off unless the
// caller opens it: [`PacPolicy::resolve_dns`] is `false` by default, and `resolve_ipv4` returns
// `None` on that flag before it reaches the network.
fn run_with_timeout(
    source: String,
    url: String,
    host: String,
    policy: PacPolicy,
    timeout: Duration,
) -> Result<Vec<ProxyStep>, Error> {
    if timeout.is_zero() {
        return Err(Error::PacTimeout { timeout });
    }

    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("proxy-watch-pac".to_owned())
        .spawn(move || {
            // The receiver may already be gone; the send failing is the normal outcome
            // of a timeout and is not an error here.
            let _ = sender.send(run(&source, &url, &host, policy));
        })
        .map_err(|source| Error::io("spawning the PAC evaluation thread", source))?;

    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(Error::PacTimeout { timeout }),
        Err(RecvTimeoutError::Disconnected) => Err(Error::pac_evaluation(
            "the PAC evaluation thread ended without producing a result",
        )),
    }
}

// Copy the loop, recursion and value-stack limits from `policy` onto `context`.
fn apply_runtime_limits(context: &mut Context, policy: PacPolicy) {
    let limits = context.runtime_limits_mut();
    limits.set_loop_iteration_limit(policy.max_loop_iterations());
    limits.set_recursion_limit(policy.recursion_limit());
    limits.set_stack_size_limit(policy.stack_size_limit());
}

// Build a context, load the script, call `FindProxyForURL` and parse the answer.
fn run(source: &str, url: &str, host: &str, policy: PacPolicy) -> Result<Vec<ProxyStep>, Error> {
    let mut context = Context::default();
    apply_runtime_limits(&mut context, policy);

    register_host_functions(&mut context, policy).map_err(|error| {
        Error::pac_evaluation(format!("could not install the PAC host functions: {error}"))
    })?;

    context.eval(Source::from_bytes(source)).map_err(|error| {
        Error::pac_evaluation(format!("the PAC script failed to load: {error}"))
    })?;

    // Prefer `FindProxyForURL`; fall back to `FindProxyForURLEx` only when it is the sole
    // entry point (Ex-only hostfns like `dnsResolveEx` are not registered — Chromium
    // always calls plain `FindProxyForURL` instead).
    let global = context.global_object();
    let mut callee = None;
    for name in [
        js_string!("FindProxyForURL"),
        js_string!("FindProxyForURLEx"),
    ] {
        // Reading the property can itself throw: the script is free to install an accessor
        // (or a `Proxy` trap) under the entry-point name. Propagate that instead of
        // treating it as absence — a script that throws from the getter has defined the
        // name, so "defines no FindProxyForURL function" would be a false report, and it
        // is also not the "sole entry point" case the `Ex` fallback below exists for.
        let value = global.get(name, &mut context).map_err(|error| {
            Error::pac_evaluation(format!("reading the PAC entry point failed: {error}"))
        })?;
        if let Some(function) = value.as_callable() {
            callee = Some(function);
            break;
        }
    }
    let Some(callee) = callee else {
        return Err(Error::pac_evaluation(
            "the PAC script defines no FindProxyForURL function",
        ));
    };

    let args = [
        JsValue::from(js_string!(url)),
        JsValue::from(js_string!(host)),
    ];
    let returned = callee
        .call(&JsValue::undefined(), &args, &mut context)
        .map_err(|error| Error::pac_evaluation(format!("FindProxyForURL failed: {error}")))?;

    // `to_std_string_escaped` keeps a JS string's content whole even when it holds a
    // UTF-16 code unit no `char` can represent: an unpaired surrogate becomes a
    // `\uXXXX`-style literal in the returned `String` rather than a replacement
    // character. That is the right call for JS text — round-trippable, and boa's own
    // established convention — but it is not what this crate's WinHTTP-side UTF-16
    // conversions do (`sys::win::ffi::wide_ptr_to_string` substitutes U+FFFD). The two
    // never actually compare a script's raw return string against each other, though:
    // WinHTTP's own native engine parses `FindProxyForURL`'s "PROXY host:port; DIRECT"
    // grammar in its own code before this crate ever sees a wide string, so only
    // already-tokenised hostnames — not arbitrary script-authored text — reach that
    // lossy conversion. A script that returns a string containing an unpaired surrogate
    // is the one case where "same script, same result" (the claim this module's sibling
    // documents for the two engines) does not hold: this line keeps the surrogate as
    // literal escape text.
    let text = returned
        .to_string(&mut context)
        .map_err(|error| {
            Error::pac_evaluation(format!(
                "FindProxyForURL returned a value that is not a string: {error}"
            ))
        })?
        .to_std_string_escaped();

    parse_find_proxy_result(&text)
}

// Read argument `index` as a string, treating a missing argument as `""`.
fn arg_string(args: &[JsValue], index: usize, context: &mut Context) -> JsResult<String> {
    match args.get(index) {
        Some(value) => Ok(value.to_string(context)?.to_std_string_escaped()),
        None => Ok(String::new()),
    }
}

// Read every argument as a string, for the variadic date/time functions.
fn arg_strings(args: &[JsValue], context: &mut Context) -> JsResult<Vec<String>> {
    let mut out = Vec::with_capacity(args.len());
    for value in args {
        out.push(value.to_string(context)?.to_std_string_escaped());
    }
    Ok(out)
}

// Install the fourteen host functions on the global object.
//
// `policy` is [`Copy`], which is what lets every binding be a plain
// `NativeFunction::from_copy_closure` with no garbage-collected capture and no `unsafe`.
fn register_host_functions(context: &mut Context, policy: PacPolicy) -> JsResult<()> {
    context.register_global_callable(
        js_string!("isPlainHostName"),
        1,
        NativeFunction::from_copy_closure(|_this, args, context| {
            let host = arg_string(args, 0, context)?;
            Ok(JsValue::from(hostfn::is_plain_host_name(&host)))
        }),
    )?;

    context.register_global_callable(
        js_string!("dnsDomainIs"),
        2,
        NativeFunction::from_copy_closure(|_this, args, context| {
            let host = arg_string(args, 0, context)?;
            let domain = arg_string(args, 1, context)?;
            Ok(JsValue::from(hostfn::dns_domain_is(&host, &domain)))
        }),
    )?;

    context.register_global_callable(
        js_string!("localHostOrDomainIs"),
        2,
        NativeFunction::from_copy_closure(|_this, args, context| {
            let host = arg_string(args, 0, context)?;
            let hostdom = arg_string(args, 1, context)?;
            Ok(JsValue::from(hostfn::local_host_or_domain_is(
                &host, &hostdom,
            )))
        }),
    )?;

    context.register_global_callable(
        js_string!("isResolvable"),
        1,
        NativeFunction::from_copy_closure(move |_this, args, context| {
            let host = arg_string(args, 0, context)?;
            Ok(JsValue::from(hostfn::is_resolvable(&host, &policy)))
        }),
    )?;

    context.register_global_callable(
        js_string!("isInNet"),
        3,
        NativeFunction::from_copy_closure(move |_this, args, context| {
            let host = arg_string(args, 0, context)?;
            let pattern = arg_string(args, 1, context)?;
            let mask = arg_string(args, 2, context)?;
            Ok(JsValue::from(hostfn::is_in_net(
                &host, &pattern, &mask, &policy,
            )))
        }),
    )?;

    context.register_global_callable(
        js_string!("dnsResolve"),
        1,
        NativeFunction::from_copy_closure(move |_this, args, context| {
            let host = arg_string(args, 0, context)?;
            Ok(match hostfn::dns_resolve(&host, &policy) {
                Some(address) => JsValue::from(js_string!(address.to_string())),
                // The PAC contract is `null`, not the empty string: scripts test it
                // with `if (ip == null)`.
                None => JsValue::null(),
            })
        }),
    )?;

    context.register_global_callable(
        js_string!("myIpAddress"),
        0,
        NativeFunction::from_copy_closure(move |_this, _args, _context| {
            Ok(JsValue::from(js_string!(
                hostfn::my_ip_address(&policy).to_string()
            )))
        }),
    )?;

    context.register_global_callable(
        js_string!("dnsDomainLevels"),
        1,
        NativeFunction::from_copy_closure(|_this, args, context| {
            let host = arg_string(args, 0, context)?;
            Ok(JsValue::from(hostfn::dns_domain_levels(&host) as f64))
        }),
    )?;

    context.register_global_callable(
        js_string!("shExpMatch"),
        2,
        NativeFunction::from_copy_closure(|_this, args, context| {
            let text = arg_string(args, 0, context)?;
            let pattern = arg_string(args, 1, context)?;
            Ok(JsValue::from(hostfn::sh_exp_match(&text, &pattern)))
        }),
    )?;

    context.register_global_callable(
        js_string!("weekdayRange"),
        2,
        NativeFunction::from_copy_closure(move |_this, args, context| {
            let args = arg_strings(args, context)?;
            Ok(JsValue::from(hostfn::weekday_range(&args, &policy)))
        }),
    )?;

    context.register_global_callable(
        js_string!("dateRange"),
        6,
        NativeFunction::from_copy_closure(move |_this, args, context| {
            let args = arg_strings(args, context)?;
            Ok(JsValue::from(hostfn::date_range(&args, &policy)))
        }),
    )?;

    context.register_global_callable(
        js_string!("timeRange"),
        6,
        NativeFunction::from_copy_closure(move |_this, args, context| {
            let args = arg_strings(args, context)?;
            Ok(JsValue::from(hostfn::time_range(&args, &policy)))
        }),
    )?;

    context.register_global_callable(
        js_string!("alert"),
        1,
        NativeFunction::from_copy_closure(|_this, args, context| {
            let message = arg_string(args, 0, context)?;
            hostfn::alert(&message);
            Ok(JsValue::undefined())
        }),
    )?;

    context.register_global_callable(
        js_string!("convert_addr"),
        1,
        NativeFunction::from_copy_closure(|_this, args, context| {
            let address = arg_string(args, 0, context)?;
            Ok(JsValue::from(f64::from(hostfn::convert_addr(&address))))
        }),
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
        BoaEvaluator::new(policy).evaluate(&PacScript::new(source), &url, &host)
    }

    // [`PacPolicy::with_timeout`] says `Some(Duration::ZERO)` is "a budget of nothing, not
    // the absence of one", and this test is the only thing holding it on this side. Let a
    // zero fall through to the untimed route — `Some(t) if !t.is_zero()`, so `None` catches
    // it — and a zero timeout means the opposite of what it says. What a caller loses is the
    // wall clock on
    // attacker-supplied JavaScript: the loop and recursion caps still hold, but the one
    // bound that answers for work those caps consider legal is gone. A timeout computed as
    // `deadline - now` reaches zero on its own.
    //
    // The script is one that plainly succeeds without a budget
    // (`a_constant_script_returns_direct` runs the same source), so the `Err` here can only
    // mean the budget was applied.
    //
    // What this holds is the answer, not the guard inside `run_with_timeout`. With that
    // guard disabled, all four of a valid script, an endless one, a syntax error
    // and a script with no entry point still come back `PacTimeout { timeout: 0ns }`,
    // because `recv_timeout(ZERO)` gives up before the thread it spawned can reply. The
    // guard's whole worth is that no thread is spawned to keep running unwatched, and no
    // return value can see that — so the guard gets no case of its own.
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
    fn a_constant_script_returns_direct() {
        let result = steps(
            "function FindProxyForURL(url, host) { return 'DIRECT'; }",
            "http://example.com/",
            PacPolicy::new(),
        )
        .unwrap();
        assert_eq!(result, vec![ProxyStep::Direct]);
    }

    #[test]
    fn the_url_and_host_arguments_reach_the_script() {
        let result = steps(
            "function FindProxyForURL(url, host) {
                 if (url.indexOf('/secret') != -1 && host == 'example.com') {
                     return 'PROXY hit:1';
                 }
                 return 'PROXY miss:1';
             }",
            "http://example.com/secret",
            PacPolicy::new(),
        )
        .unwrap();
        assert_eq!(result[0].endpoint().unwrap().authority(), "hit:1");
    }

    // Sanitising is repeated inside this impl because a caller holding a `BoaEvaluator`
    // reaches it without going through [`crate::pac::evaluate_with_host`], and the script
    // it hands the URL to is the untrusted party in the room. Nothing else could catch a
    // dropped call: [`crate::pac::sanitize_url`]'s own tests exercise the function, not
    // whether an engine still asks for it.
    #[test]
    fn the_script_is_handed_a_sanitized_url() {
        let source = "function FindProxyForURL(url, host) {
                 if (url === 'http://example.net/a/b?q=1') { return 'DIRECT'; }
                 if (url.indexOf('hunter2') != -1) { return 'PROXY password:1'; }
                 if (url.indexOf('alice') != -1) { return 'PROXY username:1'; }
                 if (url.indexOf('#frag') != -1) { return 'PROXY fragment:1'; }
                 return 'PROXY unexpected:1';
             }";
        let result = steps(
            source,
            "http://alice:hunter2@example.net/a/b?q=1#frag",
            PacPolicy::new(),
        )
        .unwrap();
        assert_eq!(
            result,
            vec![ProxyStep::Direct],
            "the endpoint names what the script was still able to read"
        );
    }

    #[test]
    fn the_plain_entry_point_wins_when_both_exist() {
        let source = "function FindProxyForURL(url, host) { return 'PROXY plain:1'; }
                      function FindProxyForURLEx(url, host) { return 'PROXY ex:1'; }";
        let result = steps(source, "http://example.com/", PacPolicy::new()).unwrap();
        assert_eq!(result[0].endpoint().unwrap().authority(), "plain:1");
    }

    #[test]
    fn the_ex_entry_point_still_runs_when_it_is_the_only_one() {
        let source = "function FindProxyForURLEx(url, host) { return 'PROXY ex:1'; }";
        let result = steps(source, "http://example.com/", PacPolicy::new()).unwrap();
        assert_eq!(result[0].endpoint().unwrap().authority(), "ex:1");
    }

    #[test]
    fn a_realistic_corporate_script() {
        // Full routing semantics live in tests/pac.rs; here we only need one chain parse.
        let source = "function FindProxyForURL(url, host) {
                 return 'PROXY edge:8080; PROXY backup:8080; DIRECT';
             }";
        let chain = steps(source, "https://example.net/", PacPolicy::new()).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].endpoint().unwrap().authority(), "edge:8080");
        assert_eq!(chain[1].endpoint().unwrap().authority(), "backup:8080");
        assert!(chain[2].is_direct());
    }

    #[test]
    fn every_host_function_is_bound() {
        // Calling every one of them in one script: a missing binding is a ReferenceError.
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

    // What a call that leaves an argument out comes back with. `arg_string` reads the gap as
    // `""`, and this test is the only thing holding that against `"undefined"` — the value
    // JS actually puts there.
    //
    // The substitution is not neutral. `isPlainHostName` is handed a name carrying no dot
    // and `dnsDomainIs` a suffix every host ends with, so each answers `true`, and `true`
    // in the usual `if (…) return "PROXY internal:8080"` shape is a rule that matches every
    // destination. `hostfn`'s known-differences list now carries the divergence; this is
    // the reading it was written from, and what keeps the answers from moving again unseen.
    //
    // Rendered together and compared once, so a failure names every answer that moved. The
    // `map(String)` is load-bearing: `join` renders `dnsResolve`'s `null` as nothing, which
    // would leave that row asserting an empty gap and unable to tell `null` from `""`.
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

    // Which argument is which, for the four bindings whose two arguments are not
    // interchangeable.
    //
    // [`hostfn`] is tested exhaustively, but it is tested through Rust calls. The wiring in
    // [`register_host_functions`] — which `arg_string` index reaches which parameter — is
    // written once per binding, and this test is the only thing holding it. Swap `isInNet`'s
    // `pattern` and `mask`, or `localHostOrDomainIs`'s `host` and `hostdom`, and nothing else
    // in the tree objects, `--include-ignored` and every integration suite included. The
    // other two swaps are caught only in passing, by tests aimed elsewhere — `dnsDomainIs`
    // by the missing-argument test above (whose `dnsDomainIs(host)` happens to be
    // asymmetric) and `shExpMatch` by a script inside `tests/pac.rs`. Neither would survive
    // being rewritten for its own reasons.
    //
    // What a swap costs is a script that reads correctly and routes wrongly. `isInNet(host,
    // "10.0.0.0", "255.0.0.0")` is how a corporate script says "internal traffic goes
    // direct"; with the last two arguments exchanged it answers about a different network
    // and the internal/external decision inverts, silently, for every destination.
    //
    // Each row is chosen so that exchanging that call's arguments moves the answer.
    // `isInNet` gets two rows: the `/16` and the `/24` differ only in the mask, so the
    // `false` is the mask being read as a mask rather than the call being broken — and it
    // is the row with teeth, because a `pattern`/`mask` exchange turns exactly that one
    // true. The `host`/`pattern` pair is left out on purpose: `is_in_net` compares
    // `address & mask == pattern & mask`, which is symmetric in those two, so no input
    // could tell them apart.
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
    fn the_default_policy_makes_dns_resolve_null() {
        let source = "function FindProxyForURL(url, host) {
                 return dnsResolve(host) == null ? 'DIRECT' : 'PROXY leaked:1';
             }";
        assert!(steps(source, "http://example.com/", PacPolicy::new()).unwrap()[0].is_direct());
    }

    #[test]
    fn my_ip_address_is_loopback_unless_configured() {
        let source =
            "function FindProxyForURL(url, host) { return 'PROXY ' + myIpAddress() + ':1'; }";
        let result = steps(source, "http://example.com/", PacPolicy::new()).unwrap();
        assert_eq!(result[0].endpoint().unwrap().authority(), "127.0.0.1:1");

        let policy = PacPolicy::new().with_my_ip_address("192.0.2.7".parse().unwrap());
        let result = steps(source, "http://example.com/", policy).unwrap();
        assert_eq!(result[0].endpoint().unwrap().authority(), "192.0.2.7:1");
    }

    #[test]
    fn the_time_functions_see_the_pinned_clock() {
        // 2024-02-29T13:45:07Z, a Thursday.
        let policy = PacPolicy::new().with_now(UNIX_EPOCH + Duration::from_secs(1_709_214_307));
        let source = "function FindProxyForURL(url, host) {
                 if (weekdayRange('MON', 'FRI') && timeRange(9, 17) && dateRange('FEB')) {
                     return 'PROXY office:8080';
                 }
                 return 'DIRECT';
             }";
        let result = steps(source, "http://example.com/", policy).unwrap();
        assert_eq!(result[0].endpoint().unwrap().authority(), "office:8080");
    }

    #[test]
    fn a_throwing_script_is_an_error() {
        let error = steps(
            "function FindProxyForURL(url, host) { throw new Error('nope'); }",
            "http://a/",
            PacPolicy::new(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
    }

    // A hostile script controls what it `throw`s, and `boa_engine` quotes that value
    // verbatim in the `JsError` it returns — which is exactly what `run()` embeds in
    // `Error::PacEvaluation.reason` via `Error::pac_evaluation`. This mimics a script
    // that throws a string shaped like credentials plus a forged log line, and checks
    // that neither survives `Display`/`Debug` on the resulting error, end to end
    // through the real evaluator rather than through `Error::pac_evaluation` directly.
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
        assert!(!debug.contains('\n'), "{debug}");
        // Not vacuous: the rest of the thrown text is still there.
        assert!(display.contains("proxy.corp"), "{display}");
    }

    #[test]
    fn a_script_without_the_entry_point_is_an_error() {
        let error = steps("var x = 1;", "http://a/", PacPolicy::new()).unwrap_err();
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
    }

    // The entry point exists but is an accessor that throws. Both before and after this
    // is an `Err`, so only the message distinguishes them: it must not claim the script
    // defines no entry point, because it does.
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
        assert!(
            !display.contains("defines no FindProxyForURL"),
            "the getter threw, so the name is defined: {display}"
        );
        assert!(display.contains("tripwire"), "{display}");
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
    fn an_infinite_loop_hits_the_wall_clock_timeout() {
        // A cap far too high to fire inside the timeout, so it is the wall clock that
        // stops this.
        //
        // "Far too high" is measured rather than assumed. Reaching this cap with the
        // timeout switched off takes about 93 seconds on an unoptimized build of this
        // crate, so the 250 ms below buys on the order of 54_000 iterations against a cap
        // of 20_000_000. For the cap to win instead, an optimized build would have to
        // outrun the measured rate by a factor in the hundreds.
        //
        // The same measurement says what becomes of the thread this abandons. The worker
        // keeps running, and the cap it is heading for is those same 93 seconds away; this
        // lib test binary has been measured in the tens of seconds, run to run, and the
        // argument needs only that it stay under 93 — do not replace this with whatever one
        // run says. So the worker is reaped by process exit, not by the cap, and the margin
        // above is paid for with a core spinning for the whole rest of the run.
        // There is no setting that buys both: [`run_with_timeout`] hands the evaluation to
        // a thread it can stop waiting for but cannot cancel, so a cap low enough to
        // unwind promptly is a cap an optimized build might reach first.
        // The finite cap is still the right thing to have — it is what bounds the same
        // script in a consumer process, which unlike a test binary does not exit.
        let policy = PacPolicy::new()
            .with_max_loop_iterations(20_000_000)
            .with_timeout(Some(Duration::from_millis(250)));
        let start = std::time::Instant::now();
        let error = steps(
            "function FindProxyForURL(url, host) { while (true) {} }",
            "http://a/",
            policy,
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacTimeout { .. }), "{error:?}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn an_infinite_loop_hits_the_iteration_cap() {
        // No timeout, so only the engine's loop cap can stop this.
        let policy = PacPolicy::new()
            .with_max_loop_iterations(10_000)
            .with_timeout(None);
        let error = steps(
            "function FindProxyForURL(url, host) { while (true) {} }",
            "http://a/",
            policy,
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
    }

    // The other half of that cap's contract, which
    // [`PacPolicy::with_max_loop_iterations`] states and nothing pinned: the limit is
    // charged where the engine re-enters a loop body, so iteration a builtin does inside
    // one call escapes it entirely. Same cap and same absent timeout as the test above —
    // the only thing that moves is where the iteration happens, and 1 000 000 characters
    // is a hundred times the cap that stops the `while`.
    #[test]
    fn iteration_inside_a_builtin_is_not_charged_to_the_loop_cap() {
        let policy = PacPolicy::new()
            .with_max_loop_iterations(10_000)
            .with_timeout(None);
        let result = steps(
            "function FindProxyForURL(url, host) {
                 var filler = 'a'.repeat(1000000);
                 return filler.length === 1000000 ? 'DIRECT' : 'PROXY p:1';
             }",
            "http://a/",
            policy,
        )
        .unwrap();
        assert_eq!(result, vec![ProxyStep::Direct]);
    }

    #[test]
    fn unbounded_recursion_does_not_blow_the_stack() {
        let error = steps(
            "function boom(n) { return boom(n + 1); }
             function FindProxyForURL(url, host) { return boom(0); }",
            "http://a/",
            PacPolicy::new(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
    }

    // A recursion depth tighter than `boa_engine`'s own default trips before the
    // script's own (finite, otherwise unremarkable) recursion completes.
    #[test]
    fn a_tight_recursion_limit_rejects_deep_recursion() {
        let policy = PacPolicy::new().with_recursion_limit(10);
        let error = steps(
            "function depth(n) { return n <= 0 ? 0 : 1 + depth(n - 1); }
             function FindProxyForURL(url, host) { return 'PROXY d:' + depth(100); }",
            "http://a/",
            policy,
        )
        .unwrap_err();
        assert!(matches!(error, Error::PacEvaluation { .. }), "{error:?}");
    }

    // No-regression check: a recursion depth well inside `boa_engine`'s own default
    // (512), run under the crate's default [`PacPolicy`], still completes. Guards
    // against the default value drifting away from `boa_engine`'s own default and
    // silently breaking a PAC script that happens to recurse.
    #[test]
    fn the_default_recursion_limit_still_runs_an_ordinary_recursive_script() {
        let result = steps(
            "function depth(n) { return n <= 0 ? 0 : 1 + depth(n - 1); }
             function FindProxyForURL(url, host) { return 'PROXY d:' + depth(100); }",
            "http://a/",
            PacPolicy::new(),
        )
        .unwrap();
        assert_eq!(result[0].endpoint().unwrap().port, 100);
    }

    // `recursion_limit` and `stack_size_limit` are honoured through `apply_runtime_limits`,
    // the exact code `run()` calls.
    #[test]
    fn recursion_and_stack_size_limits_reach_the_engine() {
        let policy = PacPolicy::new()
            .with_recursion_limit(7)
            .with_stack_size_limit(42);
        let mut context = Context::default();
        apply_runtime_limits(&mut context, policy);
        assert_eq!(context.runtime_limits().recursion_limit(), 7);
        assert_eq!(context.runtime_limits().stack_size_limit(), 42);
    }

    // Two of the three limits in [`PacPolicy`]'s default are documented as being boa's own
    // "kept so stating it is not a behaviour change", and the third is documented as one
    // boa does not impose. Those are claims about a dependency, not about this crate, and
    // an upgrade can falsify them without anyone editing this file: `RuntimeLimits`
    // carries them as plain literals too. Asserting against `Context::default()` instead
    // of against 512 and 10 240 is the whole point — a literal would only restate the
    // constant, and 0.21.1 → next is exactly when the answer changes.
    #[test]
    fn the_two_limits_that_claim_to_be_boas_still_are() {
        let boa = Context::default().runtime_limits();
        assert_eq!(
            boa.recursion_limit(),
            crate::pac::DEFAULT_PAC_RECURSION_LIMIT
        );
        assert_eq!(
            boa.stack_size_limit(),
            crate::pac::DEFAULT_PAC_STACK_SIZE_LIMIT
        );
        // The third: boa leaves loops unbounded, which is the reason this crate caps them
        // at all. If boa ever starts capping them, the doc on `DEFAULT_PAC_LOOP_LIMIT`
        // stops being true even though the number in it is unchanged.
        assert_eq!(boa.loop_iteration_limit(), u64::MAX);
        // And that the default is a cap at all: every `while (true)` test above passes an
        // explicit one, so `u64::MAX` here — the value
        // [`PacPolicy::with_max_loop_iterations`] documents as "disables" — would leave an
        // OS-supplied script's infinite loop with nothing but the timeout, which ends the
        // wait and not the work. Asserted rather than run: the comment on
        // [`an_infinite_loop_hits_the_wall_clock_timeout`] explains why nothing here
        // evaluates a loop against the real cap.
        assert_ne!(crate::pac::DEFAULT_PAC_LOOP_LIMIT, u64::MAX);
    }

    #[test]
    fn the_runtime_offers_no_way_out() {
        // None of these exist in the PAC runtime; every one must be a ReferenceError
        // rather than a working escape hatch.
        for escape in [
            "fetch('http://evil/')",
            "require('fs')",
            "XMLHttpRequest",
            "process.exit(1)",
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
