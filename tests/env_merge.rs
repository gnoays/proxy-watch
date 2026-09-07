//! Controls for `ProxyConfig::with_env`: what the environment is allowed to do to an OS
//! snapshot, and what it must not.
//!
//! Each test here is written against a mutation that would otherwise survive the rest of
//! the tree, because a test with no control it can fail is not evidence. The mutation each
//! one kills is named above it.
//!
//! Two of those names are a *design* rather than a line. No single edit to the current code
//! produces the slot-by-slot merge or the KDE special case that
//! `a_kde_environment_source_does_not_stand_in_for_the_process_environment` and
//! `the_winning_source_answers_for_every_scheme` rule out; what they guard is a rewrite
//! reaching for either shape again. The rest name an edit.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use proxy_watch::{
    BypassRules, EnvPrecedence, ProxyConfig, ProxyConfigSource, ProxyEndpoint, ProxyEntry,
    ProxyEnv, ProxyMode, Scheme, parse,
};

fn env(vars: &[(&str, &str)]) -> ProxyEnv {
    ProxyEnv::from_vars(vars.iter().copied()).expect("environment should parse")
}

fn manual(authority: &str) -> ProxyMode {
    let endpoint = ProxyEndpoint::parse(authority, 80).expect("endpoint should parse");
    let mut per_scheme = HashMap::new();
    per_scheme.insert(Scheme::Http, ProxyEntry::Use(endpoint));
    ProxyMode::manual(per_scheme, BypassRules::new())
}

fn os(authority: &str) -> ProxyConfig {
    ProxyConfig::from_source(ProxyConfigSource::Registry, manual(authority))
}

fn http_authority(mode: &ProxyMode) -> Option<String> {
    mode.endpoint_for(Scheme::Http)
        .map(|endpoint| endpoint.authority())
}

/// Mutation: drop the "nothing was set" early return, so an unset environment is folded in
/// anyway. It still does not reach `effective` under either rank — `is_configured` is what
/// keeps it from winning, not this return — but `sources` grows an `Env` entry standing for
/// nothing that was set and nothing that was dropped.
#[test]
fn an_unset_environment_changes_nothing() {
    let mut before = os("os.corp:8080");
    // Stamped ahead of the environment's read, or the stamp assertion below has nothing to
    // catch: `min` of the two picks the older, and an environment constructed after this
    // snapshot is already the newer one.
    before.captured_at = SystemTime::now() + Duration::from_secs(3600);
    for precedence in [EnvPrecedence::BeforeSystem, EnvPrecedence::AfterSystem] {
        let after = before
            .clone()
            .with_env(&env(&[("PATH", "/usr/bin")]), precedence);
        assert_eq!(after, before, "{precedence:?}");
        assert_eq!(after.sources.len(), 1, "{precedence:?}");
        // `PartialEq for ProxyConfig` skips `captured_at`, so the line above cannot see the
        // stamp. Moving the correction above the early return leaves this environment
        // rewriting a freshness it contributed nothing to, and every assertion but this one
        // still passes.
        assert_eq!(after.captured_at, before.captured_at, "{precedence:?}");
    }
}

/// Mutation: replace the `insert(0, ..)` that puts the winner at the front with a `push`.
/// Swapping the two `EnvPrecedence` variants fails here too, but not only here — the
/// `AfterSystem` controls below catch that one as well.
#[test]
fn precedence_decides_which_side_answers() {
    let os = os("os.corp:8080");
    let env = env(&[("http_proxy", "http://env.corp:3128")]);

    let env_first = os.clone().with_env(&env, EnvPrecedence::BeforeSystem);
    let os_first = os.with_env(&env, EnvPrecedence::AfterSystem);

    assert_eq!(
        http_authority(&env_first.effective).as_deref(),
        Some("env.corp:3128")
    );
    assert_eq!(
        http_authority(&os_first.effective).as_deref(),
        Some("os.corp:8080")
    );
    // The losing side is kept either way: precedence ranks the sources, it does not drop one.
    for merged in [&env_first, &os_first] {
        assert_eq!(merged.sources.len(), 2);
        assert!(merged.source(ProxyConfigSource::Env).is_some());
        assert!(merged.source(ProxyConfigSource::Registry).is_some());
    }
    // ...and the winner is at the front. `sources` is documented descending, so a consumer
    // reading `sources[0]` gets the same answer as `effective`. Nothing above sees this:
    // `effective` is assigned separately from the insert, and `source()` searches by label,
    // so replacing the `insert(0, ..)` with a `push` leaves every assertion so far green.
    assert_eq!(env_first.sources[0].0, ProxyConfigSource::Env);
    assert_eq!(os_first.sources[0].0, ProxyConfigSource::Registry);
}

/// Mutation: make `AfterSystem` mean "the environment never becomes effective". It reads
/// that way, and every machine with a configured OS store agrees with the misreading.
#[test]
fn after_system_still_answers_when_no_os_source_exists() {
    let merged = ProxyConfig::direct().with_env(
        &env(&[("http_proxy", "http://env.corp:3128")]),
        EnvPrecedence::AfterSystem,
    );
    assert_eq!(
        http_authority(&merged.effective).as_deref(),
        Some("env.corp:3128")
    );
}

/// Mutation: build the result with `ProxyConfig::from_ordered_sources`, or otherwise stop
/// carrying `fallbacks` across. A degraded read that merges an environment would then look
/// like a clean one, which is the direction that overstates what the snapshot knows.
#[test]
fn a_degraded_read_stays_degraded_through_the_merge() {
    let merged = os("os.corp:8080")
        .with_fallbacks(vec![ProxyConfigSource::WinHttpDefault])
        .with_env(
            &env(&[("http_proxy", "http://env.corp:3128")]),
            EnvPrecedence::BeforeSystem,
        );
    assert_eq!(merged.fallbacks, vec![ProxyConfigSource::WinHttpDefault]);
}

/// Mutation: drop the `captured_at` correction, leaving the OS snapshot's stamp (or the
/// merge's own `SystemTime::now()`).
///
/// `assert_eq!` on two `ProxyConfig`s cannot see this — `PartialEq` skips `captured_at` by
/// design — so this control has to read the field.
#[test]
fn the_merged_snapshot_is_as_fresh_as_its_stalest_half() {
    let env = env(&[("http_proxy", "http://env.corp:3128")]);

    // OS read first: its stamp is the older one and must survive.
    let mut stale_os = os("os.corp:8080");
    stale_os.captured_at = SystemTime::UNIX_EPOCH;
    let merged = stale_os.with_env(&env, EnvPrecedence::BeforeSystem);
    assert_eq!(merged.captured_at, SystemTime::UNIX_EPOCH);

    // Environment read first: now the *other* side is the older one, which a mutation
    // hard-coding either input would get wrong in one direction or the other.
    let mut fresh_os = os("os.corp:8080");
    fresh_os.captured_at = SystemTime::now() + Duration::from_secs(3600);
    let merged = fresh_os.with_env(&env, EnvPrecedence::BeforeSystem);
    assert_eq!(merged.captured_at, env.captured_at());
}

/// Mutation: add the KDE special case this crate rejects — "if the OS snapshot already
/// speaks for the environment, leave the process variables out". A `ProxyType = 4`
/// `kioslaverc` that resolves to `Direct` would then swallow an explicit `http_proxy`.
///
/// The label split is what lets the two be reached separately below, but holding it is not
/// this test's job: `with_env` never reads the labels already in `sources`, and the reader
/// that picks `KioslavercEnv` over `Env` is fixed in `src/sys/linux/desktop.rs`.
#[test]
fn a_kde_environment_source_does_not_stand_in_for_the_process_environment() {
    let kde = ProxyConfig::from_source(ProxyConfigSource::KioslavercEnv, ProxyMode::Direct);
    let merged = kde.with_env(
        &env(&[("http_proxy", "http://env.corp:3128")]),
        EnvPrecedence::BeforeSystem,
    );

    assert_eq!(
        http_authority(&merged.effective).as_deref(),
        Some("env.corp:3128")
    );
    assert!(merged.source(ProxyConfigSource::KioslavercEnv).is_some());
    assert_eq!(
        http_authority(merged.source(ProxyConfigSource::Env).expect("env source")).as_deref(),
        Some("env.corp:3128"),
        "the two sources must be reachable separately: {:?}",
        merged.sources
    );
}

/// Mutation: guard the merge with `ProxyEnv::is_empty` instead of
/// `ProxyEnv::is_configured`. `no_proxy` alone leaves `per_scheme` and `rejected` empty, so
/// `is_empty` calls it unset and the source never enters — the OS proxy keeps applying and
/// the bypass the user wrote is silently gone.
///
/// Chromium's `proxy_config_service_linux.cc` takes the opposite reading and says why:
/// having only `no_proxy` set "makes it explicit that env vars do specify a configuration".
#[test]
fn a_no_proxy_only_environment_is_a_configuration() {
    let e = env(&[("no_proxy", ".corp.example")]);
    assert!(e.is_empty(), "the precondition this control exists for");
    assert!(e.is_configured());

    let merged = os("os.corp:8080").with_env(&e, EnvPrecedence::BeforeSystem);
    assert!(merged.source(ProxyConfigSource::Env).is_some());
    assert!(
        merged.effective.is_direct(),
        "the environment answered, and its answer is direct: {:?}",
        merged.effective
    );
    // The OS is outranked, not erased.
    assert_eq!(
        http_authority(
            merged
                .source(ProxyConfigSource::Registry)
                .expect("os source")
        )
        .as_deref(),
        Some("os.corp:8080")
    );
}

/// Mutation: let a malformed-only environment take the rank it asked for. `is_empty` is
/// `false` for it — a value *was* set — so a guard written on that predicate hands it
/// `effective`, where the dropped scheme sits as `ProxyEntry::Unusable` and every http
/// request fails outright. A typo in `http_proxy` would take a working OS proxy down with
/// it — the same consequence the test below spells out from a `Direct` starting point.
#[test]
fn a_malformed_only_environment_is_recorded_but_never_wins() {
    let e = env(&[("http_proxy", "not a host with spaces")]);
    assert!(!e.is_empty(), "the precondition this control exists for");
    assert!(!e.is_configured());

    // The stamp is corrected on the way past whichever branch this environment takes. The
    // freshness control above only ever exercises the winning one, so moving the correction
    // inside `if wins` survives it; the losing branch is this test's to hold.
    let mut fresh_os = os("os.corp:8080");
    fresh_os.captured_at = SystemTime::now() + Duration::from_secs(3600);
    let lost = fresh_os.with_env(&e, EnvPrecedence::BeforeSystem);
    assert_eq!(lost.captured_at, e.captured_at());

    let merged = os("os.corp:8080").with_env(&e, EnvPrecedence::BeforeSystem);
    assert_eq!(
        http_authority(&merged.effective).as_deref(),
        Some("os.corp:8080"),
        "a value nothing can be done with must not outrank one that works"
    );
    // Recorded rather than dropped: the rejection is the only evidence the variable existed.
    let recorded = merged.source(ProxyConfigSource::Env).expect("env source");
    assert_eq!(
        recorded
            .rejected()
            .expect("the drop must survive the merge")
            .len(),
        1
    );
}

/// The same environment with no OS source to lose to. Widening the winning branch to
/// `if wins || self.effective.is_direct()` reads safe — a snapshot already answering
/// `Direct` has nothing to lose by letting the environment through — and is not: the
/// environment replaces `Direct` with a `Manual` whose only entry is unusable, and every
/// http request fails where it would otherwise go direct. (Dropping the recording branch outright
/// fails here too, but the two controls above catch that one first.)
#[test]
fn a_malformed_only_environment_is_recorded_even_with_nothing_to_lose_to() {
    let merged = ProxyConfig::direct().with_env(
        &env(&[("http_proxy", "not a host with spaces")]),
        EnvPrecedence::BeforeSystem,
    );
    assert!(merged.effective.is_direct());
    assert!(merged.source(ProxyConfigSource::Env).is_some());
}

/// A `no_proxy` whose every entry was dropped configures nothing and rejects something, so
/// it takes the recording branch too. Mutation: write the skip condition on
/// `ProxyEnv::rejected` alone — the scheme-variable list — and this environment vanishes,
/// `no_proxy` drops included.
#[test]
fn a_no_proxy_whose_entries_were_all_dropped_is_still_recorded() {
    let e = env(&[("no_proxy", "a..b")]);
    assert!(
        !e.is_configured() && e.rejected().is_empty(),
        "the precondition: nothing usable, and nothing on the scheme-variable list"
    );
    assert!(
        !e.bypass().rejected.is_empty(),
        "the drop has to be somewhere for the merge to have a reason to keep it"
    );

    let merged = os("os.corp:8080").with_env(&e, EnvPrecedence::BeforeSystem);
    assert_eq!(
        http_authority(&merged.effective).as_deref(),
        Some("os.corp:8080")
    );
    let recorded = merged.source(ProxyConfigSource::Env).expect("env source");
    // And what it records is the *label*, not the drop. `to_mode` answers `Direct` for a
    // snapshot holding nothing but a `no_proxy`, and `Direct` has nowhere to keep an
    // exclusion list — so unlike the malformed-scheme half of this shape, the text of the
    // drop does not survive the merge. Mutation: send this env down `to_mode`'s `Manual`
    // branch (`if self.is_empty() && self.bypass.rejected.is_empty()`) so the bypass list
    // rides along; the `with_env` doc claims exactly one of these two halves is readable
    // here, and nothing else in the tree reads the recorded mode for it.
    assert!(
        recorded.is_direct(),
        "the recorded mode must be the one `to_mode` builds, not a reconstruction: {recorded:?}"
    );
    assert!(
        recorded.rejected().is_none_or(<[_]>::is_empty),
        "a `Direct` carrying rejections would mean the drop *did* survive: {recorded:?}"
    );
}

/// Mutation: write `AfterSystem`'s test as `self.sources.is_empty()` alone. Every snapshot
/// this crate builds has `Direct` as its `effective` when `sources` is empty, so the whole
/// rest of the file agrees with the narrower predicate — including
/// `after_system_still_answers_when_no_os_source_exists`, whose `ProxyConfig::direct()` is
/// `Direct` too. What the narrower predicate loses is the caller who resolved their own
/// configuration and handed it over with no provenance behind it: they asked for the OS to
/// outrank the environment, and the only OS value they had is the one that gets overwritten.
#[test]
fn after_system_does_not_overwrite_a_resolved_mode_with_no_source_behind_it() {
    let chosen = ProxyConfig::new(manual("chosen.corp:9090"), Vec::new());
    let merged = chosen.with_env(
        &env(&[("http_proxy", "http://env.corp:3128")]),
        EnvPrecedence::AfterSystem,
    );

    assert_eq!(
        http_authority(&merged.effective).as_deref(),
        Some("chosen.corp:9090")
    );
    // Ranked below, not dropped — the same treatment every other losing source gets.
    assert!(merged.source(ProxyConfigSource::Env).is_some());
}

/// The other half of the same predicate. Mutation: keep only `self.effective.is_direct()`
/// and drop the `self.sources.iter().all(..)` conjunct beside it. Nothing else in the tree
/// sees it: every control with an OS source gives that source a proxy, so none of them ever
/// holds a snapshot that is sourced *and* `Direct` — which is exactly what Windows reports
/// for `ProxyEnable = 0`. Under the mutation an explicit "proxy off" would lose to
/// `http_proxy` at the rank that asked to come second, which is the promise
/// [`EnvPrecedence::AfterSystem`] makes about Windows in so many words.
///
/// That promise is about the rank and not about the call: the environment still lands in
/// `sources`, which the last assertion below is here to hold.
#[test]
fn an_os_source_that_answered_direct_still_outranks_the_environment() {
    let off = ProxyConfig::from_source(ProxyConfigSource::Registry, ProxyMode::Direct);
    let merged = off.with_env(
        &env(&[("http_proxy", "http://env.corp:3128")]),
        EnvPrecedence::AfterSystem,
    );
    assert!(
        merged.effective.is_direct(),
        "the OS answered direct and it outranks: {:?}",
        merged.effective
    );
    assert_eq!(merged.sources[0].0, ProxyConfigSource::Registry);
    assert!(merged.source(ProxyConfigSource::Env).is_some());

    // And from the other side, so that `BeforeSystem` cannot quietly become conditional on
    // there being an OS source to outrank. Mutation: `BeforeSystem => !self.sources.is_empty()`.
    let merged = ProxyConfig::direct().with_env(
        &env(&[("http_proxy", "http://env.corp:3128")]),
        EnvPrecedence::BeforeSystem,
    );
    assert_eq!(
        http_authority(&merged.effective).as_deref(),
        Some("env.corp:3128")
    );
}

/// The last piece of the same predicate, and the one that was wrong. Mutation: write the
/// first conjunct as `self.sources.is_empty()`, the shape it had until this control.
///
/// `sources` is not "the OS settings". The second shape in [`ProxyConfig::with_env`]'s docs
/// puts an `Env` entry there for an environment that specified nothing — a record, kept so a
/// drop is not silent, and documented as unable to reach `effective` so that a typo cannot
/// mask the OS. Under the narrower predicate it masked something else: the next fold, which
/// found a non-empty `sources` and lost to the merge's own bookkeeping. Testing the label
/// instead is safe because no OS reader ever writes `Env` — KDE's `ProxyType = 4` is
/// [`ProxyConfigSource::KioslavercEnv`], split off for exactly this reason.
#[test]
fn a_recorded_env_that_specified_nothing_does_not_stand_in_for_an_os_source() {
    let malformed = env(&[("http_proxy", "not a host with spaces")]);
    // The premise: this fold is a record, not a configuration. If it ever starts winning,
    // the assertions below stop testing what they are named for.
    assert!(!malformed.is_configured());

    let merged = ProxyConfig::direct()
        .with_env(&malformed, EnvPrecedence::AfterSystem)
        .with_env(
            &env(&[("http_proxy", "http://env.corp:3128")]),
            EnvPrecedence::AfterSystem,
        );

    assert_eq!(
        http_authority(&merged.effective).as_deref(),
        Some("env.corp:3128"),
        "the OS said nothing, and the only entry in `sources` was this merge's own record: {:?}",
        merged.sources
    );
    // Both folds are kept, and the winner is at the front — the record is ranked below it,
    // the same treatment every other losing source gets.
    assert_eq!(merged.sources.len(), 2);
    assert_eq!(merged.sources[0].0, ProxyConfigSource::Env);
}

/// The source-level rule itself: the environment enters whole, so the winning side answers
/// for schemes it never named. Mutation: merge slot by slot instead, filling the schemes
/// the environment left out from the OS entry. That is what hyper-util does, and it makes
/// one request's proxy depend on a variable naming a different scheme.
#[test]
fn the_winning_source_answers_for_every_scheme() {
    let mut per_scheme = HashMap::new();
    per_scheme.insert(
        Scheme::Https,
        ProxyEntry::Use(ProxyEndpoint::parse("os.corp:8443", 80).unwrap()),
    );
    let os = ProxyConfig::from_source(
        ProxyConfigSource::Registry,
        ProxyMode::manual(per_scheme, parse::no_proxy("")),
    );

    let merged = os.with_env(
        &env(&[("http_proxy", "http://env.corp:3128")]),
        EnvPrecedence::BeforeSystem,
    );
    assert_eq!(
        http_authority(&merged.effective).as_deref(),
        Some("env.corp:3128")
    );
    assert!(
        merged.effective.endpoint_for(Scheme::Https).is_none(),
        "the OS https entry must not leak into the environment's mode: {:?}",
        merged.effective
    );
}

/// Configured *and* dropping something, which the two predicates read in opposite directions:
/// `is_configured` says a malformed value reads as unset, while `to_mode` mirrors a drop that
/// names a scheme into the entry map as `Unusable`. The bypass list decides — it is a
/// configuration — so this environment wins and the drop reaches `effective`, where http hard
/// errors rather than falling through to the OS proxy or to direct. Mutation: give `wins` an
/// `&& env.rejected().is_empty()`, on the reading that an environment holding a drop should
/// never outrank a working OS proxy. It would silently proxy every `.corp.example` host the
/// operator excluded.
#[test]
fn a_bypass_list_beside_a_broken_scheme_value_takes_the_rank_and_carries_the_drop() {
    let e = env(&[
        ("no_proxy", ".corp.example"),
        ("http_proxy", "not a host with spaces"),
    ]);
    assert!(
        e.per_scheme().is_empty(),
        "the precondition: nothing survived on the scheme side"
    );
    assert_eq!(e.rejected().len(), 1);
    assert!(
        e.is_configured(),
        "the bypass list alone is what makes this a configuration"
    );

    let merged = os("os.corp:8080").with_env(&e, EnvPrecedence::BeforeSystem);
    assert_eq!(
        merged.sources[0].0,
        ProxyConfigSource::Env,
        "it took the rank: {:?}",
        merged.sources
    );
    assert!(
        http_authority(&merged.effective).is_none(),
        "the OS proxy must not answer for a scheme the environment outranked: {:?}",
        merged.effective
    );
    assert!(
        matches!(
            merged.effective.entry_for(Scheme::Http),
            Some(ProxyEntry::Unusable(_))
        ),
        "the drop must be visible where the request resolves, not only in `rejected`: {:?}",
        merged.effective
    );
}

/// `http_proxy=` is a configuration: the variable was set, and what it says is "no proxy for
/// http". Mutation: write `is_configured` on the entries that carry an endpoint —
/// `per_scheme.values().any(|e| e.endpoint().is_some()) || !self.bypass.is_empty()` — and an
/// explicitly disabled scheme stops outranking the OS, so the proxy the operator turned off
/// answers anyway.
#[test]
fn an_explicitly_disabled_scheme_is_a_configuration() {
    let e = env(&[("http_proxy", "")]);
    assert!(!e.is_empty());
    assert!(e.is_configured());

    let merged = os("os.corp:8080").with_env(&e, EnvPrecedence::BeforeSystem);
    assert_eq!(merged.sources[0].0, ProxyConfigSource::Env);
    assert!(
        http_authority(&merged.effective).is_none(),
        "the disabled scheme must answer, not the OS proxy: {:?}",
        merged.effective
    );
    // Outranked, not erased — the same guarantee the `no_proxy` case above checks.
    assert_eq!(
        http_authority(
            merged
                .source(ProxyConfigSource::Registry)
                .expect("os source")
        )
        .as_deref(),
        Some("os.corp:8080")
    );
}

/// And so is a scheme other than `http`. Mutation: narrow `is_configured`'s first half to the
/// slot that happens to be set in every other control here —
/// `per_scheme.contains_key(&Scheme::Http) || !self.bypass.is_empty()`.
///
/// The whole tree agreed with that narrowing: every environment folded anywhere else names
/// `http_proxy`, so an `https_proxy` or `all_proxy` on its own — the shape
/// [`ProxyConfig::with_env`]'s docs give `all_proxy` a job in, covering the schemes the
/// environment did not name — read as unset and lost the rank it asked for.
#[test]
fn a_scheme_other_than_http_is_a_configuration_too() {
    let e = env(&[("https_proxy", "http://env.corp:3128")]);
    assert!(e.is_configured());

    let merged = os("os.corp:8080").with_env(&e, EnvPrecedence::BeforeSystem);
    assert_eq!(merged.sources[0].0, ProxyConfigSource::Env);
    assert_eq!(
        merged
            .effective
            .endpoint_for(Scheme::Https)
            .map(|endpoint| endpoint.authority())
            .as_deref(),
        Some("env.corp:3128"),
        "an environment that named only https still takes the rank: {:?}",
        merged.sources
    );
}

/// Two folds are two entries under one label, and `source` promises the first.
/// `a_recorded_env_that_specified_nothing_does_not_stand_in_for_an_os_source` builds the same
/// two-entry snapshot but reads `sources[0]` directly; reading one back through `source` is this
/// test's part. Mutation: `source` searching `.iter().rev()`, which answers with the older
/// environment — the one that lost the front — for every caller reading a double-folded
/// snapshot back.
#[test]
fn a_second_configured_fold_takes_the_front_from_the_first() {
    let merged = os("os.corp:8080")
        .with_env(
            &env(&[("http_proxy", "http://first.corp:3128")]),
            EnvPrecedence::BeforeSystem,
        )
        .with_env(
            &env(&[("http_proxy", "http://second.corp:3128")]),
            EnvPrecedence::BeforeSystem,
        );

    assert_eq!(merged.sources.len(), 3, "{:?}", merged.sources);
    assert_eq!(
        http_authority(&merged.effective).as_deref(),
        Some("second.corp:3128")
    );
    assert_eq!(
        http_authority(merged.source(ProxyConfigSource::Env).expect("env source")).as_deref(),
        Some("second.corp:3128"),
        "`source` answers with the entry that is first, which is the fold that took the front"
    );
}
