//! Tests for the environment variable snapshot type.

use proxy_watch::{
    Error, ProxyConfigSource, ProxyEnv, ProxyScheme, RejectedValue, RejectionKind, RejectionSource,
    Scheme,
};

fn rejected_texts(values: &[RejectedValue]) -> Vec<&str> {
    values.iter().map(RejectedValue::redacted_input).collect()
}

fn env(vars: &[(&str, &str)]) -> ProxyEnv {
    ProxyEnv::from_vars(vars.iter().copied()).expect("environment should parse")
}

#[test]
fn lowercase_wins_over_uppercase() {
    let cases: &[(&[(&str, &str)], &str)] = &[
        (&[("http_proxy", "lower:80")], "lower:80"),
        (&[("HTTP_PROXY", "upper:80")], "upper:80"),
        (
            &[("http_proxy", "lower:80"), ("HTTP_PROXY", "upper:80")],
            "lower:80",
        ),
    ];
    for (vars, expected) in cases {
        let endpoint = env(vars).endpoint_for(Scheme::Http).unwrap().authority();
        assert_eq!(&endpoint, expected, "{vars:?}");
    }
}

#[test]
fn every_scheme_variable_is_read() {
    let e = env(&[
        ("http_proxy", "h:1"),
        ("https_proxy", "h:2"),
        ("ftp_proxy", "h:3"),
        ("all_proxy", "h:4"),
    ]);
    assert_eq!(e.endpoint_for(Scheme::Http).unwrap().authority(), "h:1");
    assert_eq!(e.endpoint_for(Scheme::Https).unwrap().authority(), "h:2");
    assert_eq!(e.endpoint_for(Scheme::Ftp).unwrap().authority(), "h:3");
    assert_eq!(e.endpoint_for(Scheme::All).unwrap().authority(), "h:4");
}

#[test]
fn all_proxy_is_only_a_fallback() {
    let e = env(&[("http_proxy", "specific:1"), ("all_proxy", "fallback:2")]);
    // A concrete scheme always wins ...
    assert_eq!(
        e.endpoint_for(Scheme::Http).unwrap().authority(),
        "specific:1"
    );
    // ... and `all_proxy` covers the schemes that have no variable of their own.
    assert_eq!(
        e.endpoint_for(Scheme::Https).unwrap().authority(),
        "fallback:2"
    );
}

#[test]
fn empty_value_disables_the_scheme_and_suppresses_the_fallback() {
    let e = env(&[("http_proxy", ""), ("all_proxy", "fallback:2")]);
    assert!(e.per_scheme()[&Scheme::Http].is_disabled());
    assert!(e.endpoint_for(Scheme::Http).is_none());
    assert_eq!(
        e.endpoint_for(Scheme::Https).unwrap().authority(),
        "fallback:2"
    );
}

/// A value that is nothing but whitespace is the same off switch, and the emptiness test has
/// to be the trimmed one for it to be: read untrimmed, a shell that exported a stray space
/// turns an off switch into a drop, and a drop is [`ProxyEntry::Unusable`] once the mode is
/// built — the scheme answers an error where the writer asked for no proxy at all. Nothing
/// lands in `rejected` either, because there is no value here to report.
#[test]
fn a_value_that_is_only_whitespace_is_the_same_off_switch() {
    let e = env(&[("http_proxy", " \t "), ("all_proxy", "fallback:2")]);
    assert!(e.per_scheme()[&Scheme::Http].is_disabled());
    assert!(e.rejected().is_empty(), "{:?}", e.rejected());
    assert!(e.endpoint_for(Scheme::Http).is_none());
}

#[test]
fn scheme_and_credentials_are_extracted() {
    let e = env(&[("all_proxy", "socks5h://user:p%40ss@[::1]")]);
    let endpoint = e.endpoint_for(Scheme::All).unwrap();
    assert_eq!(endpoint.scheme_hint, Some(ProxyScheme::Socks5h));
    assert_eq!(endpoint.port, 1080);
    assert_eq!(endpoint.authority(), "[::1]:1080");
    let auth = endpoint.auth.as_ref().unwrap();
    assert_eq!(auth.username(), "user");
    assert_eq!(auth.password(), Some("p@ss"));
}

/// The last tier of the port rule `ProxyEnv::from_vars` publishes: explicit port, else the
/// `scheme://` default, else 80. The middle tier is the test above — `socks5h://[::1]` is
/// 1080 with no port written anywhere. This is the tier below it, where the value names
/// neither, and 80 is the number the environment reader passes
/// [`ProxyEndpoint::parse`](proxy_watch::ProxyEndpoint::parse) for every scheme alike: an
/// `https_proxy` with a bare host is 80 and not 443, because the port being defaulted is the
/// *proxy's*, not the one the request would have used without it. Nothing else in the tree
/// held the number — the literal could be changed to any other port and every test still
/// passed.
#[test]
fn a_bare_host_takes_port_80_whatever_the_scheme() {
    let e = env(&[("http_proxy", "plain.corp"), ("https_proxy", "secure.corp")]);
    assert_eq!(
        e.endpoint_for(Scheme::Http).unwrap().authority(),
        "plain.corp:80"
    );
    assert_eq!(
        e.endpoint_for(Scheme::Https).unwrap().authority(),
        "secure.corp:80"
    );
}

#[test]
fn no_proxy_is_parsed() {
    for name in ["no_proxy", "NO_PROXY"] {
        let e = env(&[("http_proxy", "h:1"), (name, ".example.com,10.0.0.0/8")]);
        assert!(e.bypass().matches_authority("www.example.com"));
        assert!(e.bypass().matches_authority("10.1.2.3:443"));
        assert!(!e.bypass().matches_authority("example.net"));
    }
}

/// `;` separates entries in the Windows `ProxyOverride` list and nowhere else. Every
/// list above splits the same way under either separator set, so this test is the only thing
/// pinning which one `no_proxy` is wired to: routing it through
/// [`proxy_watch::parse::proxy_override`] leaves every other test in this file green while
/// turning one dead rule into two live ones — a bypass the user never wrote.
///
/// The reference splits on `,` alone (`config.init` in Go's `http/httpproxy/proxy.go`),
/// so the semicolon is an ordinary host character here: `a.example;b.example` is a
/// single name that no destination can ever carry, and it bypasses neither side of it.
#[test]
fn a_semicolon_does_not_separate_a_no_proxy_list() {
    let e = env(&[("http_proxy", "h:1"), ("no_proxy", "a.example;b.example")]);
    assert_eq!(e.bypass().patterns.len(), 1);
    assert!(!e.bypass().matches_authority("a.example"));
    assert!(!e.bypass().matches_authority("b.example"));
}

/// A `no_proxy` value used to make [`ProxyEnv::from_vars`] fail
/// outright the moment one entry was malformed, which meant the *other* `*_proxy`
/// variables became unreadable too — a config-wide outage caused by a single typo in
/// an exclusion list. The bad entry is now dropped and recorded instead.
#[test]
fn a_malformed_no_proxy_entry_does_not_break_from_vars() {
    let e = ProxyEnv::from_vars([
        ("http_proxy", "h:1"),
        (
            "no_proxy",
            "good.example,https://bad.example,also-good.example",
        ),
    ])
    .expect("a malformed no_proxy entry must not fail the whole snapshot");

    // The valid entries are still active ...
    assert!(e.bypass().matches_authority("good.example"));
    assert!(e.bypass().matches_authority("also-good.example"));
    // ... and the bad one is recorded rather than silently dropped (the "logs alone are
    // invisible without the tracing feature" lesson).
    assert_eq!(
        rejected_texts(&e.bypass().rejected),
        ["https://bad.example"]
    );

    // Other settings remain readable — this is the actual bug being fixed.
    assert_eq!(e.endpoint_for(Scheme::Http).unwrap().authority(), "h:1");
}

/// The two `rejected` lists are not one list, and this test is the only thing pinning that.
/// A dropped exclusion never reaches [`ProxyEnv::rejected`], so a caller that checks only
/// that one reads "nothing was dropped" off a snapshot that dropped something — the
/// fail-open read of a record `parse`'s module doc keeps fail-closed on purpose.
#[test]
fn a_dropped_exclusion_and_a_dropped_endpoint_are_recorded_in_different_places() {
    let bad_exclusion_only = env(&[("http_proxy", "h:1"), ("no_proxy", "https://bad")]);
    assert!(
        bad_exclusion_only.rejected().is_empty(),
        "an exclusion is not an endpoint: {:?}",
        rejected_texts(bad_exclusion_only.rejected())
    );
    assert_eq!(
        rejected_texts(&bad_exclusion_only.bypass().rejected),
        ["https://bad"]
    );

    let bad_endpoint_only = env(&[("http_proxy", "h:-1"), ("no_proxy", "good.example")]);
    assert_eq!(rejected_texts(bad_endpoint_only.rejected()), ["h:-1"]);
    assert!(bad_endpoint_only.bypass().rejected.is_empty());

    // And `to_mode` keeps them apart on the way out, rather than merging them into the
    // mode-level list where the exclusion would read as a dropped proxy.
    let mode = bad_exclusion_only.to_mode();
    assert!(mode.rejected().unwrap_or_default().is_empty());
    assert_eq!(
        rejected_texts(&mode.bypass().expect("manual mode carries rules").rejected),
        ["https://bad"]
    );
}

/// The scheme-endpoint twin of the
/// `no_proxy` fix above. A malformed `http_proxy` used to fail `ProxyEnv::from_vars`
/// outright via `?`, which took `https_proxy` and `no_proxy` down with it even though
/// neither was at fault.
#[test]
fn a_malformed_http_proxy_does_not_break_from_vars() {
    let e = ProxyEnv::from_vars([
        ("http_proxy", "not a host with spaces"),
        ("https_proxy", "h:2"),
        ("no_proxy", ".example.com"),
    ])
    .expect("a malformed http_proxy entry must not fail the whole snapshot");

    // The other scheme and no_proxy are still readable ...
    assert_eq!(e.endpoint_for(Scheme::Https).unwrap().authority(), "h:2");
    assert!(e.bypass().matches_authority("api.example.com"));
    // ... http_proxy itself is dropped, not silently defaulted to something else.
    assert!(e.endpoint_for(Scheme::Http).is_none());
    // ... and the bad value is recorded rather than silently dropped.
    assert_eq!(
        rejected_texts(e.rejected()),
        ["not a host with spaces"],
        "the dropped http_proxy value must be recorded on ProxyEnv::rejected"
    );
    assert_eq!(e.rejected()[0].kind(), RejectionKind::InvalidProxyEndpoint);
    assert_eq!(
        e.rejected()[0].source(),
        &RejectionSource::EnvironmentVariable("http_proxy".to_owned())
    );
}

/// The bad value can legitimately carry credentials (`http://user:pass@host`); they
/// must be masked wherever the raw text is retained, exactly like
/// `BypassRules::rejected` and `ProxyMode::Manual::rejected` already do.
#[test]
fn a_malformed_scheme_value_is_masked_in_rejected() {
    let e = ProxyEnv::from_vars([("http_proxy", "http://alice:hunter2@bad host:8080")])
        .expect("a malformed http_proxy entry must not fail the whole snapshot");

    assert_eq!(
        rejected_texts(e.rejected()),
        ["http://alice:***@bad host:8080"],
        "the password must be masked, never the raw text"
    );
}

/// Every `*_proxy` variable malformed at once: `per_scheme` ends up empty, but the drops
/// must still be visible on `rejected` rather than the snapshot silently reading as
/// "nothing was ever set" ("have the information, return nothing" is the
/// worst failure mode). `to_mode()` must not collapse this to `Direct` either.
#[test]
fn every_scheme_value_malformed_still_records_every_drop() {
    let e = ProxyEnv::from_vars([
        ("http_proxy", "not a host with spaces"),
        ("https_proxy", "also not a host"),
    ])
    .expect("malformed *_proxy values must not fail the whole snapshot");

    assert!(e.endpoint_for(Scheme::Http).is_none());
    assert!(e.endpoint_for(Scheme::Https).is_none());
    assert_eq!(
        rejected_texts(e.rejected()),
        ["not a host with spaces", "also not a host"]
    );
    // A variable was set (even though every one of them was malformed), so this is not
    // "empty" in the sense of "no *_proxy variable was set at all".
    assert!(!e.is_empty());
    // The record must survive the trip through `to_mode()` too, not vanish into `Direct`.
    let mode = e.to_mode();
    assert!(!mode.is_direct());
    assert_eq!(
        rejected_texts(mode.rejected().unwrap()),
        ["not a host with spaces", "also not a host"]
    );
}

#[test]
fn empty_environment_is_direct() {
    let e = env(&[("PATH", "/usr/bin")]);
    assert!(e.is_empty());
    assert!(e.to_mode().is_direct());
    assert!(e.to_config().effective.is_direct());
}

/// `to_config()`'s whole content is the label it attaches, and `src/env.rs` promises in
/// prose that the label is [`ProxyConfigSource::Env`]. This test is the only thing holding
/// it: spelling it `Registry` instead leaves every other test in this tree green, because
/// the other call — `empty_environment_is_direct` above — reads `.effective` and never
/// looks at `.sources`.
///
/// Provenance is the only question `ProxyConfig::source` answers, so the wrong label is
/// not cosmetic. A caller asking what the environment contributed gets `None`, and a
/// caller asking what the registry contributed gets a process-local `*_proxy` value
/// presented as a machine-wide setting — the direction that overstates the authority of
/// what it found.
#[test]
fn a_snapshot_converted_to_a_config_is_attributed_to_the_environment() {
    // Both modes `to_mode` can produce, because attribution is not supposed to depend on
    // which one came out: an empty environment is `Direct`, a set one is `Manual`.
    for vars in [&[("PATH", "/usr/bin")][..], &[("http_proxy", "h:1")][..]] {
        let config = env(vars).to_config();
        assert_eq!(
            config.source(ProxyConfigSource::Env),
            Some(&config.effective),
            "{vars:?}"
        );
        // One source and no other, so the assertion above cannot pass by the label being
        // present alongside a second one that is doing the real work.
        assert_eq!(config.sources.len(), 1, "{vars:?}");
    }
}

/// Converting is not a second reading. `ProxyConfig::from_source` stamps now, so a snapshot
/// taken once and converted on every request would otherwise hand back a config claiming to
/// be fresh each time — the direction that overstates how current the data is, the same one
/// the wrong source label would take above.
///
/// The sleep is the control: without it the two instants can be equal by accident, and the
/// assertion would pass against a `to_config` that never carried anything over.
#[test]
fn a_config_carries_the_instant_the_environment_was_read() {
    let e = env(&[("http_proxy", "h:1")]);
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert_eq!(e.to_config().captured_at, e.captured_at());
}

#[test]
fn cgi_environment_refuses_http_proxy_in_any_case() {
    for name in ["HTTP_PROXY", "http_proxy", "Http_Proxy"] {
        let result = ProxyEnv::from_vars([("REQUEST_METHOD", "GET"), (name, "http://evil:8080")]);
        match result {
            Err(Error::CgiHttpProxy { variable }) => assert_eq!(variable, name),
            other => panic!("{name} should have been refused, got {other:?}"),
        }
    }
}

#[test]
fn cgi_environment_still_allows_https_and_no_proxy() {
    // Go applies the CGI rule to the HTTP variable only.
    let e = env(&[
        ("REQUEST_METHOD", "POST"),
        ("HTTPS_PROXY", "secure:8443"),
        ("NO_PROXY", ".internal"),
    ]);
    assert_eq!(
        e.endpoint_for(Scheme::Https).unwrap().authority(),
        "secure:8443"
    );
    assert!(e.bypass().matches_authority("api.internal"));
}

/// An *empty* `http_proxy` is refused too, unlike in Go — where `parseProxy("")`
/// is `nil` and the CGI branch never fires. Here an empty value is `ProxyEntry::Disabled`,
/// and `Disabled` suppresses the `all_proxy` fallback, so honouring it would let a
/// bare `Proxy:` request header switch off the operator's HTTP proxy for that request.
#[test]
fn cgi_environment_refuses_an_empty_http_proxy_too() {
    let result = ProxyEnv::from_vars([
        ("REQUEST_METHOD", "GET"),
        ("http_proxy", ""),
        ("all_proxy", "http://corp-proxy:8080"),
    ]);
    match result {
        Err(Error::CgiHttpProxy { variable }) => assert_eq!(variable, "http_proxy"),
        other => panic!("an empty http_proxy should have been refused, got {other:?}"),
    }
}

/// An *empty* `REQUEST_METHOD` is not a CGI environment. Go tests the same variable with
/// `os.Getenv("REQUEST_METHOD") != ""`, and RFC 3875 §4.1.12 gives it no empty production
/// (`method = "GET" | "POST" | "HEAD" | extension-method`), so no conforming CGI server
/// sets it empty. Deciding on the variable's mere presence refused the whole snapshot —
/// `no_proxy` and `https_proxy` included — for a process that is not a CGI script at all.
#[test]
fn an_empty_request_method_is_not_a_cgi_environment() {
    let e = env(&[("REQUEST_METHOD", ""), ("http_proxy", "http://corp:8080")]);
    assert_eq!(
        e.endpoint_for(Scheme::Http).unwrap().authority(),
        "corp:8080"
    );
}

/// Windows environment variable names are case-insensitive — `set Http_Proxy=…`
/// sets the same variable `HTTP_PROXY` names — but `std::env::vars` reports the key in
/// whatever case it was set, so an exact-match lookup silently ignored it. Everywhere
/// else the two really are different variables and the curl convention (lowercase, then
/// uppercase, and nothing more) is the whole rule.
#[test]
fn a_mixed_case_scheme_variable_is_read_on_windows_only() {
    let e = env(&[("Http_Proxy", "http://mixed:8080")]);
    let found = e.endpoint_for(Scheme::Http).map(|e| e.authority());
    if cfg!(windows) {
        assert_eq!(found.as_deref(), Some("mixed:8080"));
    } else {
        assert_eq!(found, None, "a case-sensitive OS must not fold the two");
    }
}

/// The Windows fold must not outrank the conventional spellings: `http_proxy` still
/// beats `HTTP_PROXY`, which still beats anything else.
#[test]
fn the_conventional_spellings_still_come_first() {
    let e = env(&[
        ("Http_Proxy", "http://mixed:8080"),
        ("HTTP_PROXY", "http://upper:8080"),
    ]);
    assert_eq!(
        e.endpoint_for(Scheme::Http).unwrap().authority(),
        "upper:8080"
    );

    let e = env(&[
        ("Http_Proxy", "http://mixed:8080"),
        ("HTTP_PROXY", "http://upper:8080"),
        ("http_proxy", "http://lower:8080"),
    ]);
    assert_eq!(
        e.endpoint_for(Scheme::Http).unwrap().authority(),
        "lower:8080"
    );
}

/// The Windows fold picks a *representative* when more than one spelling is present and
/// none of them is one of the two conventional ones, and that choice must not come out of
/// `HashMap` iteration order — the same input has to resolve to the same proxy every run.
/// `the_refused_variable_name_is_deterministic` says this for the CGI refusal, which reaches
/// its own tie-break; this is the other one, and this test is the only thing holding it:
/// replacing the `min` with a `max` changes which proxy the process talks to, and nothing
/// else notices.
///
/// A real Windows process cannot hold two spellings at once — the OS keeps one name per
/// variable — so the case only arises through `from_vars`, which is public and takes
/// whatever map the caller assembled.
#[test]
fn the_spelling_that_wins_the_windows_fold_is_deterministic() {
    for _ in 0..8 {
        let e = env(&[
            ("HTTP_Proxy", "http://first:1"),
            ("Http_proxy", "http://second:2"),
        ]);
        let found = e.endpoint_for(Scheme::Http).map(|e| e.authority());
        if cfg!(windows) {
            // Ordered by name, not by hash: `HTTP_Proxy` sorts before `Http_proxy`.
            assert_eq!(found.as_deref(), Some("first:1"));
        } else {
            assert_eq!(found, None, "a case-sensitive OS must not fold the two");
        }
    }
}

/// With two spellings present, the reported variable name must not depend on `HashMap`
/// iteration order — the same input has to produce the same error every run.
#[test]
fn the_refused_variable_name_is_deterministic() {
    for _ in 0..8 {
        let result = ProxyEnv::from_vars([
            ("REQUEST_METHOD", "GET"),
            ("HTTP_PROXY", "http://a:8080"),
            ("http_proxy", "http://b:8080"),
        ]);
        match result {
            Err(Error::CgiHttpProxy { variable }) => assert_eq!(variable, "HTTP_PROXY"),
            other => panic!("expected a CGI refusal, got {other:?}"),
        }
    }
}

#[test]
fn without_the_cgi_marker_http_proxy_is_used() {
    let e = env(&[("HTTP_PROXY", "http://proxy:8080")]);
    assert_eq!(
        e.endpoint_for(Scheme::Http).unwrap().authority(),
        "proxy:8080"
    );
}

#[test]
fn equality_ignores_the_timestamp() {
    let a = env(&[("http_proxy", "h:1")]);
    std::thread::sleep(std::time::Duration::from_millis(20));
    let b = env(&[("http_proxy", "h:1")]);
    assert_ne!(a.captured_at(), b.captured_at());
    assert_eq!(a, b);
}

/// The other half of the same promise: two snapshots that compare equal must also *read*
/// the same. `ProxyEnv`'s `Debug` is hand-written so `per_scheme` prints in `Scheme`
/// order; a derive would print it in `HashMap` order, and a diff between two logged
/// snapshots would report changes nobody made. `ProxyMode`'s twin is pinned in
/// `src/mode.rs`; this is the other public map. Repeated because a derive would come out
/// sorted by chance one time in twenty-four.
#[test]
fn debug_prints_the_schemes_in_a_fixed_order() {
    for _ in 0..8 {
        let rendered = format!(
            "{:?}",
            env(&[
                ("all_proxy", "e:5"),
                ("ftp_proxy", "c:3"),
                ("https_proxy", "b:2"),
                ("http_proxy", "a:1"),
            ])
        );
        let mut at = 0;
        // `Scheme::Socks` has no `*_proxy` variable, so the four below are every scheme
        // this snapshot can hold, in `Scheme::ALL`'s order.
        for scheme in [Scheme::Http, Scheme::Https, Scheme::Ftp, Scheme::All] {
            // With the `:` the map's separator prints, so `Http` does not match inside
            // `Https`.
            let name = format!("{scheme:?}:");
            let found = rendered[at..]
                .find(&name)
                .unwrap_or_else(|| panic!("{name} out of order or missing in {rendered}"));
            at += found + name.len();
        }
    }
}

/// Serialises the only two tests in this file that touch the process environment: the one
/// below, which *reads* all of it, and `from_env_survives_a_variable_that_is_not_valid_unicode`,
/// which *writes* to it. Every other test here builds its input with `ProxyEnv::from_vars`
/// and is unaffected. Cargo serialises test *binaries*, not the tests inside one, so
/// without this the write and the read overlap — which is unsound, not merely flaky, and
/// therefore produces no failing test to notice it by. Same five lines of `std`, and for
/// the same reason, as `REGISTRY_LOCK` in `tests/windows_watch.rs`.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A poisoned lock means the writing test panicked between its `set_var` and its
/// `remove_var`. Proceeding is right: the reader below asserts nothing about the variable,
/// and propagating the poison would turn one real failure into two.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn from_env_does_not_panic() {
    let _lock = env_lock();
    // The real environment may or may not carry proxy variables; either outcome is
    // fine, we only assert that reading it is well defined.
    let _ = ProxyEnv::from_env();
}

// Only these two families have a way to *build* a non-Unicode environment value. Anywhere
// else both branches below vanish, and what is left is a test that sets nothing, asserts
// that reading nothing worked, and reports a pass.
#[cfg(any(windows, unix))]
#[test]
fn from_env_survives_a_variable_that_is_not_valid_unicode() {
    // `std::env::vars()` panics if *any* variable in the whole process environment is
    // not valid Unicode, not only the ones this crate reads (that is its documented
    // `# Panics` contract). Before `from_env` switched to `vars_os`, setting the
    // variable below and calling `from_env()` crashed the process instead of
    // returning a `Result`.
    const BROKEN_VAR: &str = "PROXY_WATCH_TEST_INVALID_UNICODE";

    // Held across the write, the read, and the restore below. See `ENV_LOCK`: what makes
    // the `unsafe` blocks sound is this lock, not `--test-threads=1` — a flag the default
    // `cargo test` does not pass is not an invariant.
    let _lock = env_lock();

    // SAFETY: mutating the process environment is only sound while no other thread is
    // concurrently reading or writing it. `ENV_LOCK` is held for the rest of this test and
    // the only other test in this binary that reads the environment takes it too; no
    // watcher — and hence no backend thread of this crate's that reads process env on
    // Linux — is constructed here at all. `BROKEN_VAR` is a name unique to this test.
    unsafe {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            // A lone UTF-16 surrogate has no UTF-8 representation.
            std::env::set_var(BROKEN_VAR, std::ffi::OsString::from_wide(&[0xD800]));
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            // 0xFF is not a valid UTF-8 lead byte.
            std::env::set_var(BROKEN_VAR, std::ffi::OsString::from_vec(vec![0xFF]));
        }
    }

    let result = ProxyEnv::from_env();

    // SAFETY: see above.
    unsafe {
        std::env::remove_var(BROKEN_VAR);
    }

    result.expect("a variable that is not valid Unicode must not fail the whole snapshot");
}
