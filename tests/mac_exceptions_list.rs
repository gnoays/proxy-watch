//! What CFNetwork does with an `ExceptionsList`, asked on a real Mac.
//!
//! # Why this is a CI job
//!
//! WinINet and WinHTTP, handed a bypass list directly, match a bare `example.com` in
//! `ProxyOverride` to that name and **not** `api.example.com`
//! (`a_bare_name_in_a_windows_list_is_the_one_host` in `tests/bypass.rs`). CFNetwork does
//! the same with `ExceptionsList`, and the only other evidence within reach, Chromium's
//! macOS reader, is a reimplementation and not the OS. Reading a bare name as a suffix
//! reports a **wider** bypass than the machine has, so traffic a user believes is proxied
//! comes back as [`ProxyStep::Direct`] (fail-open). `bypass_from_dict`
//! (`src/sys/proxy_dict.rs`) therefore reads the list as `BypassDialect::MacOs`, and the
//! rows here are held rather than read once: a macOS release that moves any of them fails
//! this test rather than leaving the crate's incorrect answer undetected.
//!
//! # Why this can be a plain test and the Windows probe could not
//!
//! `CFNetworkCopyProxiesForURL` takes the proxy settings **as an argument**: the header's
//! own wording is "a dictionary describing the available proxy settings; the dictionary's
//! format should match the dictionary returned by `CFNetworkCopySystemProxySettings`". So
//! the question can be put to the real matcher without reading the dynamic store, without
//! writing it, and without a single packet: no `networksetup`, no `sudo`, no listener, no
//! DNS lookup. That is strictly less invasive than the Windows probe, which had to observe
//! whether a TCP connection reached a dead local listener, and it is why those scripts
//! stayed out of the tree while this one comes in.
//!
//! It also means the file is safe on a developer's own Mac. It is not `#[ignore]`, because
//! `#[ignore]` in this repository means "touches the real machine or its network, so CI
//! runs it" and this touches neither.
//!
//! # What is asserted, and what is only read
//!
//! [`the_harness_can_tell_a_proxied_destination_from_a_bypassed_one`] is the premise, and
//! it is asserted: an `http://` destination goes to the proxy when the list is empty, is
//! bypassed when the list names it, and is bypassed when the list holds `*.` plus its
//! parent domain. Nothing below means anything unless those three hold: the first proves
//! the harness produces "proxy" at all, the second that CFNetwork honours a
//! caller-supplied `ExceptionsList` at all, and the third that it honours one on a host
//! that is not spelled out literally.
//!
//! Everything below the premise is **printed first and asserted afterwards**. A row goes
//! into a `hold_row` only once the machine has answered it; a row not yet measured stays in
//! the "still being read" section, where it prints and asserts nothing beyond being
//! readable at all (a NULL array, an empty one, or an entry with no `kCFProxyTypeKey` fails
//! the test rather than being silently scored). A reading written down before the machine
//! gives it is a guess, and a guess in a table row is indistinguishable from a measurement.
//!
//! Run with `--nocapture` to see the table; CI's macOS integration step already passes it.
//!
//! # The answer the runner gives
//!
//! An `ExceptionsList` entry is compared to the destination as a **name**, with four
//! spellings and nothing else:
//!
//! | entry | matches |
//! |---|---|
//! | `name` | that host, and nothing under it |
//! | `*.name`, `.name` | what is under it, at any depth, and not the host itself |
//! | `name.*` | that host, and anything whose leading labels are it |
//! | a CIDR block | the addresses in it, `169.254/16` included |
//!
//! The third is the mirror of the second and not a suffix rule: `pw-probe.*` matched
//! `pw-probe.invalid`, which is not *under* `pw-probe` in any sense DNS would recognise.
//! Every other `*` is a character, so `*probe*`, `*invalid`, `pw-*.invalid` and a bare `*`
//! match nothing. A `:port` in an entry kills it the same way, and so does a space at
//! either end, because neither end is trimmed. Case is folded.
//!
//! Separately from any entry, **a bypass key's presence turns on a loopback bypass**.
//! `127.0.0.1` and `localhost` go to the proxy when the settings carry neither
//! `ExceptionsList` nor `ExcludeSimpleHostnames`, and bypass as soon as either is there,
//! whatever is in it, including one empty string. The macOS reader carries this as
//! [`ImplicitBypass::CfNetwork`] when a key is there and [`ImplicitBypass::Empty`] when
//! neither is; [`BypassRules::bypass_loopback`] reads only `<-loopback>` and does not
//! follow the key.
//!
//! # Where the Mac differs from the other sources
//!
//! `169.254/16`, `ExcludeSimpleHostnames` and the two subdomain spellings read the way the
//! shared suffix reading has them. Four spellings do not, and reading any of them that way
//! is **fail-open** (`Direct` for traffic the Mac hands the proxy):
//!
//!   * a bare name read as a suffix,
//!   * a `*` read as a glob, the bare `*` worst of all (`HostPattern::All` is the proxy
//!     switched off for every destination on a machine that proxies every one),
//!   * a `:port` read as a constraint on an entry rather than the thing that kills it,
//!   * whitespace around an entry trimmed off, when nothing here trims it and the entry it
//!     surrounds is therefore a name no destination carries.
//!
//! `BypassDialect::MacOs` reads those four as the Mac does, and `bypass_from_dict` pushes
//! with it. Two known divergences are left standing. `<local>` and `<-loopback>` bypass
//! nothing here and stay recognised anyway, for the reason `src/sys/linux/gsettings_map.rs`
//! gives for GLib: the tokens are read before the dialect so every source shares one
//! vocabulary, and no macOS writer types a WinINet token. And `name.*` is built as a glob,
//! which needs the dot and so misses the host itself; that one is fail-*closed*, measured
//! in [`a_trailing_star_reaches_the_bare_host_and_this_crate_does_not`] rather than
//! assumed.
//!
//! One row answered a question larger than the grammar: a dead entry costs itself and not
//! the list, so `bypass_from_dict` dropping one entry and keeping the rest is what the
//! machine does too.
//!
//! # The stand-in for "what this crate answers"
//!
//! The printed comparison uses [`parse::no_proxy`], not the macOS reader, because the macOS
//! reader takes an `SCDynamicStore` and is `pub(crate)` besides. `no_proxy` parses with
//! `BypassDialect::Suffix` and the macOS reader no longer does, so the column is the
//! majority reading rather than this crate's macOS answer; for the rows that moved, it
//! prints the majority reading beside what the machine does. The two other divergences are
//! called out where they appear: the abbreviated CIDR (`169.254/16`), which only the macOS
//! path expands, and `ExcludeSimpleHostnames`, which has no `no_proxy` spelling at all.
//!
//! [`BypassRules::bypass_loopback`]: proxy_watch::BypassRules::bypass_loopback
//! [`ImplicitBypass::CfNetwork`]: proxy_watch::ImplicitBypass::CfNetwork
//! [`ImplicitBypass::Empty`]: proxy_watch::ImplicitBypass::Empty
//!
//! [`ProxyStep::Direct`]: proxy_watch::ProxyStep::Direct
#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::ptr;

use core_foundation::array::{CFArray, CFArrayGetValueAtIndex, CFArrayRef};
use core_foundation::base::{CFAllocatorRef, CFType, TCFType, kCFAllocatorDefault};
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::url::{CFURL, CFURLRef};

use proxy_watch::parse;

// Hand-written FFI, for the same reason `SCError` is hand-written in `src/sys/mac/mod.rs`:
// a two-symbol surface with no safe equivalent in the `core-foundation` family.
//
// `kCFProxyTypeKey` and `kCFProxyTypeNone` are linked rather than spelled as string
// literals because their *values* are not documented anywhere this crate can cite, only
// their symbol names are, and a wrong literal would fail silently, scoring every row as
// "proxy". A wrong symbol name is a link error instead, which is loud. The dictionary keys
// below go the other way and are literals: `HTTPEnable`, `HTTPProxy`, `HTTPPort`,
// `ExceptionsList` and `ExcludeSimpleHostnames` are the same strings
// `src/sys/proxy_dict.rs` matches on against the dictionaries CI reads off real runners.
#[link(name = "CFNetwork", kind = "framework")]
#[allow(non_upper_case_globals)]
unsafe extern "C" {
    fn CFNetworkCopyProxiesForURL(url: CFURLRef, proxy_settings: CFDictionaryRef) -> CFArrayRef;
    static kCFProxyTypeKey: CFStringRef;
    static kCFProxyTypeNone: CFStringRef;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFURLCreateWithString(
        allocator: CFAllocatorRef,
        url_string: CFStringRef,
        base_url: CFURLRef,
    ) -> CFURLRef;
}

/// The proxy the settings dictionary names. Never contacted: `CFNetworkCopyProxiesForURL`
/// answers from the dictionary, so nothing here opens a socket, but it has to be somewhere
/// a reader would not mistake for a real one if it ever did.
const PROXY_HOST: &str = "127.0.0.1";
const PROXY_PORT: i64 = 8080;

/// The domain every destination sits under. `.invalid` is reserved by RFC 6761 §6.4 and
/// cannot resolve, so a stray lookup would fail rather than reach anyone.
const DOMAIN: &str = "pw-probe.invalid";

/// Ask CFNetwork whether `http://destination/` bypasses the proxy under these settings.
///
/// `true` means the first returned proxy entry is `kCFProxyTypeNone`: the header's "no
/// proxy should be used; contact the origin server directly". Anything else means the
/// request would go to the proxy, so the entry did not match.
fn cfnetwork_bypasses(exceptions: &[&str], exclude_simple_hostnames: bool, dest: &str) -> bool {
    let mut settings: Vec<(CFString, CFType)> = vec![
        (
            CFString::new("HTTPEnable"),
            CFNumber::from(1i64).as_CFType(),
        ),
        (
            CFString::new("HTTPProxy"),
            CFString::new(PROXY_HOST).as_CFType(),
        ),
        (
            CFString::new("HTTPPort"),
            CFNumber::from(PROXY_PORT).as_CFType(),
        ),
    ];
    // An empty list is left out rather than written as an empty array: the control row
    // wants the shape of a machine with no exceptions configured, not one configured with
    // none, and only the former is what an unconfigured Mac hands over.
    if !exceptions.is_empty() {
        let entries: Vec<CFString> = exceptions.iter().map(|e| CFString::new(e)).collect();
        settings.push((
            CFString::new("ExceptionsList"),
            CFArray::from_CFTypes(&entries).as_CFType(),
        ));
    }
    if exclude_simple_hostnames {
        settings.push((
            CFString::new("ExcludeSimpleHostnames"),
            CFNumber::from(1i64).as_CFType(),
        ));
    }
    let settings = CFDictionary::from_CFType_pairs(&settings);

    let text = CFString::new(&format!("http://{dest}/"));
    // SAFETY: `CFURLCreateWithString` takes a `CFStringRef` alive for the call and a NULL
    // base URL, which the API documents as "no base". It follows the Create rule, so
    // `wrap_under_create_rule` takes the reference rather than adding one.
    let url = unsafe {
        let raw =
            CFURLCreateWithString(kCFAllocatorDefault, text.as_concrete_TypeRef(), ptr::null());
        assert!(
            !raw.is_null(),
            "CFURLCreateWithString rejected http://{dest}/"
        );
        CFURL::wrap_under_create_rule(raw)
    };

    // SAFETY: both arguments are alive for the call. The name says Copy, so the returned
    // array follows the Create rule too.
    let proxies = unsafe {
        let raw =
            CFNetworkCopyProxiesForURL(url.as_concrete_TypeRef(), settings.as_concrete_TypeRef());
        assert!(
            !raw.is_null(),
            "CFNetworkCopyProxiesForURL returned NULL for {dest} under {exceptions:?}"
        );
        CFArray::<*const c_void>::wrap_under_create_rule(raw)
    };
    assert!(
        !proxies.is_empty(),
        "CFNetworkCopyProxiesForURL returned an empty array for {dest} under {exceptions:?}"
    );

    // SAFETY: index 0 is below the count just checked, and the array outlives this borrow.
    let first = unsafe { CFArrayGetValueAtIndex(proxies.as_concrete_TypeRef(), 0) };
    assert!(!first.is_null(), "the first proxy entry for {dest} is NULL");
    // SAFETY: the header states every element is a dictionary and every dictionary has an
    // entry for `kCFProxyTypeKey`; the array owns the element and outlives this borrow, and
    // `wrap_under_get_rule` retains rather than stealing the array's reference.
    let (entry, type_key, type_none) = unsafe {
        (
            CFDictionary::<CFString, CFType>::wrap_under_get_rule(first.cast()),
            CFString::wrap_under_get_rule(kCFProxyTypeKey),
            CFString::wrap_under_get_rule(kCFProxyTypeNone),
        )
    };
    let kind = entry
        .find(&type_key)
        .expect("a proxy entry with no kCFProxyTypeKey")
        .downcast::<CFString>()
        .expect("a kCFProxyTypeKey holding something that is not a CFString");
    kind == type_none
}

/// What this crate answers for the same row, through the public API.
///
/// See the module doc for why `no_proxy` stands in for the macOS reader, and for the two
/// rows where it does not.
fn this_crate_bypasses(exceptions: &[&str], dest: &str) -> bool {
    parse::no_proxy(&exceptions.join(",")).matches_authority(dest)
}

fn verdict(bypasses: bool) -> &'static str {
    if bypasses { "bypass" } else { "proxy " }
}

/// Print one row and hand back CFNetwork's answer, so a caller can still assert on it.
fn read_row(exceptions: &[&str], dest: &str) -> bool {
    let measured = cfnetwork_bypasses(exceptions, false, dest);
    println!(
        "CFNETWORK  {:<24} {:<26} -> {}   (this crate: {})",
        exceptions.join(","),
        dest,
        verdict(measured),
        verdict(this_crate_bypasses(exceptions, dest)),
    );
    measured
}

// --------------------------------------------------------------------------------
// the premise
// --------------------------------------------------------------------------------

/// Three rows that must hold whatever the dialect turns out to be, because every reading
/// below is meaningless without them.
///
/// Without the first, the harness might report "bypass" for everything and the table would
/// read as a list of matches. Without the second, `CFNetworkCopyProxiesForURL` might be
/// ignoring the `ExceptionsList` key in a caller-built dictionary entirely, which is the
/// only way this whole approach could be invalid, since the header only promises the
/// dictionary's *format* matches `CFNetworkCopySystemProxySettings`, not that every key in
/// it is honoured. Without the third, it might be honouring the list only as a literal
/// string comparison, which would make the disputed rows uninteresting for a different
/// reason.
///
/// `*.` plus the parent domain is the shape Apple's own default `ExceptionsList` ships
/// (`*.local`), and the shape macOS System Settings offers as the example, so the third row
/// is the one the platform is least likely to disagree about.
#[test]
fn the_harness_can_tell_a_proxied_destination_from_a_bypassed_one() {
    assert!(
        !cfnetwork_bypasses(&[], false, DOMAIN),
        "with no ExceptionsList at all, {DOMAIN} should have gone to the proxy"
    );
    assert!(
        cfnetwork_bypasses(&[DOMAIN], false, DOMAIN),
        "an ExceptionsList naming {DOMAIN} exactly did not bypass it — \
         CFNetworkCopyProxiesForURL may be ignoring a caller-supplied list, \
         which would invalidate every reading in this file"
    );
    let subdomain = format!("api.{DOMAIN}");
    assert!(
        cfnetwork_bypasses(&[&format!("*.{DOMAIN}")], false, &subdomain),
        "an ExceptionsList of *.{DOMAIN} did not bypass {subdomain}"
    );
}

/// Assert one row and print it either way, so a passing run still prints the whole table.
///
/// Every row held below is the machine's answer, not a prediction. The one that invited a prediction, `<-loopback>` against
/// `127.0.0.1`, goes the other way from the one the grammar suggests.
fn hold_row(exceptions: &[&str], dest: &str, bypasses: bool) {
    assert_eq!(
        read_row(exceptions, dest),
        bypasses,
        "CFNetwork changed its answer for {dest} under {exceptions:?}"
    );
}

// --------------------------------------------------------------------------------
// what the machine answered
// --------------------------------------------------------------------------------

/// A bare entry is one host and not a suffix.
///
/// A bare `pw-probe.invalid` in an `ExceptionsList` is **that host and no other**.
/// `api.pw-probe.invalid` goes to the proxy. WinINet and WinHTTP answer the same way, and
/// `BypassDialect::Suffix` (what `bypass_from_dict` reaches for if nothing stops it)
/// answers the opposite.
///
/// The third row is what keeps this from being a narrower quirk: `xpw-probe.invalid` also
/// proxies, so the rule is not "suffix on a dot boundary" *or* "suffix by bare string", it
/// is equality. The fourth is the control that separates the two verdicts at all.
#[test]
fn a_bare_name_is_the_one_host_and_not_anything_under_it() {
    println!("--- CFNetwork ExceptionsList, a bare name ---");
    hold_row(&[DOMAIN], DOMAIN, true);
    hold_row(&[DOMAIN], &format!("api.{DOMAIN}"), false);
    hold_row(&[DOMAIN], &format!("x{DOMAIN}"), false);
    hold_row(&[DOMAIN], "other.invalid", false);
    // Case is folded, so equality is on the name and not on the bytes. Matching this row is
    // the only behaviour on which `Suffix` and `Exact` necessarily agree; it is here so the
    // rule above cannot be mistaken for "compares the string as given".
    hold_row(&[&DOMAIN.to_uppercase()], DOMAIN, true);
    // A reverse containment, to fix the direction: the entry being *longer* than the
    // destination does not match either.
    hold_row(&[&format!("api.{DOMAIN}")], DOMAIN, false);
}

/// `*.` and a leading `.` are the same rule, and neither takes the domain itself.
///
/// It is worth holding because the bare-name rule above must not break it. The leading-dot
/// pair is the one with no counterpart
/// anywhere else: WinINet **rejects** an entry beginning with `.` outright (`123`,
/// `ERROR_INVALID_NAME`), so a list that is valid on macOS is not valid on Windows.
#[test]
fn a_leading_star_dot_or_dot_takes_what_is_under_the_domain_and_not_the_domain() {
    println!("--- CFNetwork ExceptionsList, subdomain forms ---");
    for entry in [format!("*.{DOMAIN}"), format!(".{DOMAIN}")] {
        hold_row(&[&entry], &format!("api.{DOMAIN}"), true);
        hold_row(&[&entry], &format!("a.b.{DOMAIN}"), true);
        hold_row(&[&entry], DOMAIN, false);
        hold_row(&[&entry], &format!("x{DOMAIN}"), false);
    }
}

/// `169.254/16` is Apple's reading, not Chromium's.
///
/// The abbreviated form is Apple's own default `ExceptionsList` spelling and one `IpNet`
/// rejects outright, so `expand_abbreviated_cidr` in `src/sys/proxy_dict.rs` pads it. It
/// pads to `169.254.0.0/16`, the link-local range; Chromium's URL-standard IPv4 parser
/// makes the same text `169.0.0.254/16`. The two rows are the two readings put to
/// CFNetwork as destinations, and CFNetwork bypasses the first and proxies the second.
///
/// Read alone rather than through [`read_row`], because `no_proxy` is not the code that
/// expands this and its column would be answering about the wrong function.
#[test]
fn the_abbreviated_cidr_means_what_apple_means_by_it() {
    println!("--- CFNetwork ExceptionsList, abbreviated CIDR ---");
    for (dest, bypasses) in [("169.254.1.1", true), ("169.0.0.254", false)] {
        let measured = cfnetwork_bypasses(&["169.254/16"], false, dest);
        println!(
            "CFNETWORK  {:<24} {:<26} -> {}",
            "169.254/16",
            dest,
            verdict(measured)
        );
        assert_eq!(measured, bypasses, "169.254/16 against {dest}");
    }
    // The unabbreviated spelling, so the rows above are about the abbreviation and not
    // about whether CIDR works at all, and a prefix that does not contain the address, so
    // "bypass" is not what every CIDR entry returns.
    hold_row(&["10.0.0.0/8"], "10.1.2.3", true);
    hold_row(&["10.0.0.0/8"], "11.1.2.3", false);
}

/// `ExcludeSimpleHostnames` is exactly the dotless names, which is what this crate assumed.
///
/// The second row is the one worth having: a switch that also caught dotted names would
/// make `BypassRules::exclude_simple_hostnames` too narrow rather than too wide. It does
/// not. Read alone because the flag has no `no_proxy` spelling at all.
#[test]
fn exclude_simple_hostnames_is_the_names_with_no_dot_in_them() {
    println!("--- CFNetwork ExcludeSimpleHostnames ---");
    for (dest, bypasses) in [("simplehost", true), (DOMAIN, false)] {
        let measured = cfnetwork_bypasses(&[], true, dest);
        println!(
            "CFNETWORK  {:<24} {:<26} -> {}",
            "(ExcludeSimpleHostnames)",
            dest,
            verdict(measured)
        );
        assert_eq!(measured, bypasses, "ExcludeSimpleHostnames against {dest}");
    }
    // It is also a flag and not a spelling (writing `<local>` into the list enables none
    // of this behaviour), but that row belongs to the token below, where it is asserted
    // rather than mentioned.
}

/// `<local>` is an ordinary name to CFNetwork, and this crate reads a rule where the
/// machine reads none.
///
/// It bypasses nothing on macOS (not a dotless name, not a dotted one), which is what
/// every other rule here predicts, since `<`, `>` and `l` are compared as characters and
/// no host is spelled that way. But `HostPattern::parse_in` reads the token before it
/// looks at the dialect, so this crate turns a macOS `ExceptionsList` entry of `<local>`
/// into a bypass of every dotless name. GNOME's `ignore-hosts` has the same shape and is
/// left standing for want of a way to ask; for macOS there was one.
///
/// The other token, `<-loopback>`, is held in
/// [`a_bypass_key_is_what_turns_on_the_loopback_bypass_not_any_entry_in_it`] instead: it
/// appeared to bypass `127.0.0.1`, and what was actually bypassing it was the list.
#[test]
fn the_local_token_bypasses_nothing_here() {
    println!("--- CFNetwork ExceptionsList, WinINet tokens ---");
    hold_row(&["<local>"], "simplehost", false);
    hold_row(&["<local>"], DOMAIN, false);
}

/// A `*` is syntax at a label boundary at either end of the entry, and a literal anywhere
/// else.
///
/// The forms that work are `*.name` and `.name` for what is under a domain, and `name.*`
/// for the host plus anything whose *leading* labels are it. The last is the mirror of the
/// first and not the suffix rule it resembles: `pw-probe.*` matches `pw-probe.invalid`,
/// which is not under `pw-probe`. So `ExceptionsList` has no spelling for "this domain and
/// everything beneath it" at all: the two directions are separate entries.
///
/// Everywhere else a `*` matches nothing, because it is compared as a character and no host
/// contains one: `*probe*`, `*invalid` (no dot before the star), `pw-*.invalid` (a star
/// inside a label) and a bare `*` are all dead entries. WinINet answers three of those the
/// other way (`pw-probe.*` **and** `*probe*` both match there), so `*` is a general glob
/// on Windows and is not one here. `BypassDialect::MacOs` refuses the four dead spellings,
/// so they land in `BypassRules::rejected` rather than in the list; the WinINet reading
/// would admit every one of them.
#[test]
fn a_star_is_syntax_at_a_label_boundary_and_a_literal_anywhere_else() {
    println!("--- CFNetwork ExceptionsList, star placement ---");
    // A trailing `.*` takes the domain itself, unlike a leading `*.`.
    hold_row(&[&format!("{DOMAIN}.*")], DOMAIN, true);
    hold_row(
        &[&format!("{DOMAIN}.*")],
        &format!("{DOMAIN}.example"),
        true,
    );
    hold_row(&["pw-probe.*"], DOMAIN, true);
    // And a leading `*.` reaches an arbitrary depth, not one label.
    hold_row(&["*.invalid"], DOMAIN, true);

    // Everything else is a character.
    hold_row(&["*probe*"], &format!("api.{DOMAIN}"), false);
    hold_row(&["*probe*"], DOMAIN, false);
    hold_row(&["*invalid"], DOMAIN, false);
    hold_row(&["pw-*.invalid"], DOMAIN, false);
    hold_row(&["*"], DOMAIN, false);
    hold_row(&[""], DOMAIN, false);
}

/// A port in an entry makes the entry match nothing: the port is not ignored, the entry
/// is dead.
///
/// A portless destination cannot tell those apart. The middle two rows separate them: an
/// entry of `{DOMAIN}:8081` does not match a destination on 8081. `HostPattern` carries a port and matches on it, so on macOS this
/// crate has a rule the machine does not.
///
/// The last row is the other direction, and it is the one that shows the port is not part
/// of the comparison at all: a portless entry matches a destination that has one.
#[test]
fn a_port_in_an_entry_makes_it_match_nothing() {
    println!("--- CFNetwork ExceptionsList, ports ---");
    hold_row(&[&format!("{DOMAIN}:80")], DOMAIN, false);
    hold_row(
        &[&format!("{DOMAIN}:8081")],
        &format!("{DOMAIN}:8081"),
        false,
    );
    hold_row(
        &[&format!("{DOMAIN}:8081")],
        &format!("{DOMAIN}:8082"),
        false,
    );
    hold_row(&[DOMAIN], &format!("{DOMAIN}:8081"), true);
}

/// macOS bypasses its own machine as soon as the settings carry a bypass key at all, and
/// not before, which is not a rule about any entry.
///
/// With no `ExceptionsList` key, CFNetwork sends `127.0.0.1`, `localhost` and `[::1]` to
/// the proxy, and the macOS reader carries `ImplicitBypass::Empty` for such a dictionary
/// and `ImplicitBypass::CfNetwork` once either key is there. A Mac configured through
/// System Settings always has the key (the `SCDynamicStore` dictionary the watcher test
/// reads off this same runner carries `*.local` and `169.254/16`) and any entry at all
/// turns the bypass on.
///
/// No entry is matching loopback: `<-loopback>` (a WinINet token, a dead literal here by
/// every rule above), `<local>`, `other.invalid` and an empty-string entry all bypass
/// `127.0.0.1`, while the control row has `<-loopback>` still proxying an ordinary
/// destination. `ExcludeSimpleHostnames` alone does it as well, and `127.0.0.1` is not a
/// simple hostname.
///
/// The keyless row is a dictionary only this harness builds, and it is held because it
/// shows the loopback bypass is a property of a configured machine, not of CFNetwork.
#[test]
fn a_bypass_key_is_what_turns_on_the_loopback_bypass_not_any_entry_in_it() {
    println!("--- CFNetwork, loopback with no bypass key at all ---");
    for dest in ["127.0.0.1", "localhost", "[::1]"] {
        let measured = cfnetwork_bypasses(&[], false, dest);
        println!(
            "CFNETWORK  {:<24} {:<26} -> {}",
            "(no list)",
            dest,
            verdict(measured)
        );
        assert!(
            !measured,
            "a Mac with no bypass key at all sent {dest} to the proxy on three runs"
        );
    }

    println!("--- CFNetwork, loopback with a list present ---");
    // Four entries with nothing in common: a token, a token, an unrelated name, and no
    // name at all. All four bypass, so the entry is not what is doing it.
    for entry in ["<-loopback>", "<local>", "other.invalid", ""] {
        for dest in ["127.0.0.1", "localhost"] {
            hold_row(&[entry], dest, true);
        }
    }
    // The control: whatever the presence of a list switches on, it is not a bypass of
    // everything: the ordinary destination every other row here proxies still proxies.
    hold_row(&["<-loopback>"], DOMAIN, false);

    // The other bypass key does it too, and `127.0.0.1` is not a name with no dot in it,
    // so this is not `ExcludeSimpleHostnames` doing what it says either.
    println!("--- CFNetwork ExcludeSimpleHostnames, addresses ---");
    for dest in ["127.0.0.1", "localhost"] {
        let measured = cfnetwork_bypasses(&[], true, dest);
        println!(
            "CFNETWORK  {:<24} {:<26} -> {}",
            "(ExcludeSimpleHostnames)",
            dest,
            verdict(measured)
        );
        assert!(measured, "ExcludeSimpleHostnames did not bypass {dest}");
    }
}

// --------------------------------------------------------------------------------
// what the grammar does not decide
// --------------------------------------------------------------------------------

/// Neither end of an entry is trimmed, so a pasted space kills it.
///
/// `BypassDialect::trim` must not cut either end for macOS. Trimming on the majority
/// dialect's habit rather than on anything measured is a fail-open of the same class as the
/// three the dialect already carries: ` pw-probe.invalid` proxies on the Mac, and a trim
/// makes it a live bypass rule here. macOS is the one dialect that trims neither end (GNOME
/// trims the trailing one because `g_strchomp` does) and the surviving space meets the
/// whitespace guard in `HostPattern::parse_in`, so the entry reaches
/// `BypassRules::rejected` instead of sitting in the list looking live.
#[test]
fn whitespace_around_an_entry_is_part_of_the_name_and_kills_it() {
    println!("--- CFNetwork ExceptionsList, whitespace around an entry ---");
    for entry in [format!(" {DOMAIN}"), format!("{DOMAIN} ")] {
        hold_row(&[&entry], DOMAIN, false);
    }
}

/// One unreadable entry costs itself and nothing else.
///
/// This was the row worth more than the rest together, and it came back the affordable way.
/// `bypass_from_dict` drops the entry it cannot read and keeps the list; had CFNetwork
/// abandoned the whole list instead, a Mac with one bad exception would be proxying
/// everything while this crate reported the good entries as live bypasses, a defect an
/// order larger than any single-entry disagreement, and one no amount of per-entry accuracy
/// would have reached.
///
/// Three shapes of dead entry, because "unreadable" is not one thing: `*probe*` parses as a
/// name CFNetwork then matches nothing with, `!!!` is not a host at all, and `" "` is a row
/// left blank in the settings list.
#[test]
fn a_dead_entry_beside_a_live_one_costs_only_itself() {
    println!("--- CFNetwork ExceptionsList, one dead entry beside a live one ---");
    hold_row(&["*probe*", DOMAIN], DOMAIN, true);
    hold_row(&[" ", DOMAIN], DOMAIN, true);
    hold_row(&["!!!", DOMAIN], DOMAIN, true);
}

/// `name.*` reaches the bare `name`, and this crate does not follow it there.
///
/// The last open row of the star grammar. Every `name.*` row held above has two labels in
/// the head, so none of them separated "the host plus what leads with it" from "what leads
/// with it". This one does: `pw-probe.*` bypasses a bare `pw-probe`.
///
/// Left standing rather than fixed, and the direction is why. This crate builds `name.*` as
/// a glob that needs the literal dot, so it answers `proxy` for a destination the Mac sends
/// direct: reported through the proxy, actually bypassed, which costs a reader accuracy and
/// costs no traffic its confidentiality. Following it would cost a `HostPattern` variant
/// for one spelling. Held so the divergence is measured rather than assumed, the same way
/// [`the_local_token_bypasses_nothing_here`] holds the other one.
#[test]
fn a_trailing_star_reaches_the_bare_host_and_this_crate_does_not() {
    println!("--- CFNetwork ExceptionsList, a trailing star over no labels ---");
    hold_row(&["pw-probe.*"], "pw-probe", true);
}

/// IPv6 loopback bypasses once a list is present, which is what `ImplicitBypass::CfNetwork`
/// answers.
///
/// The keyless rows in [`a_bypass_key_is_what_turns_on_the_loopback_bypass_not_any_entry_in_it`] show
/// `[::1]` going to the proxy with no bypass key at all; this is the other half. Both halves
/// matter: the loopback bypass belongs to a configured machine rather than to CFNetwork,
/// which is why the macOS reader picks the set by whether the dictionary has a key.
#[test]
fn ipv6_loopback_bypasses_with_a_list_present() {
    println!("--- CFNetwork, IPv6 loopback with a list present ---");
    hold_row(&["other.invalid"], "[::1]", true);
}

/// CFNetwork's implicit set is three destinations (`localhost`, `127.0.0.1` and `[::1]`),
/// and this crate's macOS reader carries exactly those, as `ImplicitBypass::CfNetwork`.
///
/// Every other destination below went to the proxy with a list present that names none of
/// them: the rest of `127.0.0.0/8`, `*.localhost`, a trailing dot, `loopback`, the
/// IPv4-mapped spelling, and both link-local ranges. `ImplicitBypass::Broad` answers each
/// of those direct, which is why macOS does not carry it. The default list a Mac ships with names
/// `169.254/16`, so the IPv4 link-local rows go direct on a stock Mac through that entry;
/// `fe80::/10` has no entry and goes to the proxy.
#[test]
fn cfnetwork_implicit_bypass_is_three_destinations() {
    println!("--- CFNetwork, implicit set with a list present ---");
    let mut rules = proxy_watch::BypassRules::new();
    rules.implicit = proxy_watch::ImplicitBypass::CfNetwork;
    for (dest, bypasses) in [
        ("localhost", true),
        ("LOCALHOST", true),
        ("127.0.0.1", true),
        ("[::1]", true),
        ("localhost.", false),
        ("loopback", false),
        ("app.localhost", false),
        ("127.0.0.2", false),
        ("[::ffff:127.0.0.1]", false),
        ("169.254.169.254", false),
        ("169.254.1.1", false),
        ("[fe80::1]", false),
        ("[febf::1]", false),
    ] {
        hold_row(&["other.invalid"], dest, bypasses);
        assert_eq!(
            rules.matches_authority(dest),
            bypasses,
            "this crate on {dest}"
        );
    }
}

/// Hold every row and report all the ones that moved together, so one surprise does not
/// hide the answers behind it: the first run of the two tests below stopped at its first
/// row and left the rest unread.
fn hold_rows(rows: &[(&[&str], &str, bool)]) {
    let moved: Vec<String> = rows
        .iter()
        .filter(|(list, dest, bypasses)| read_row(list, dest) != *bypasses)
        .map(|(list, dest, bypasses)| format!("{dest} under {list:?}: expected {bypasses}"))
        .collect();
    assert!(moved.is_empty(), "CFNetwork changed its answer: {moved:#?}");
}

/// CFNetwork reads a trailing dot as the DNS root, on the destination and on the entry
/// alike: `pw-probe.invalid` bypasses `pw-probe.invalid.` and `pw-probe.invalid.`
/// bypasses `pw-probe.invalid` (run 36878816049). The macOS reader sets
/// `BypassRules::strip_trailing_dot` and keeps a dotted entry on that reading. The
/// implicit set is the exception: `localhost.` is proxied
/// ([`cfnetwork_implicit_bypass_is_three_destinations`]).
#[test]
fn cfnetwork_sheds_a_trailing_dot() {
    println!("--- CFNetwork, a trailing dot ---");
    let dotted = format!("{DOMAIN}.");
    let api = format!("api.{DOMAIN}");
    let api_dotted = format!("{api}.");
    let star = format!("*.{DOMAIN}");
    let star_dotted = format!("*.{DOMAIN}.");
    hold_rows(&[
        (&[DOMAIN], DOMAIN, true),
        (&[DOMAIN], &dotted, true),
        (&[&dotted], DOMAIN, true),
        (&[&dotted], &dotted, true),
        (&[&star], &api, true),
        (&[&star], &api_dotted, true),
        (&[&star_dotted], &api, true),
    ]);
}

/// An entry written as an IPv4 address does not reach the same address in its IPv4-mapped
/// IPv6 spelling (run 36878816049), which is why the macOS reader clears
/// `BypassRules::ipv4_mapped_as_ipv4`.
#[test]
fn cfnetwork_reads_a_mapped_destination_as_written() {
    println!("--- CFNetwork, an IPv4 entry against a mapped destination ---");
    hold_rows(&[
        (&["192.0.2.7"], "192.0.2.7", true),
        (&["192.0.2.7"], "[::ffff:192.0.2.7]", false),
    ]);
}

/// An IPv4 entry or destination written other than as four decimal octets is compared as
/// text (run 37111301355). The URL grammar reads `012` as octal, `0xa` as hex and
/// `10.66051` as a short form, all `10.1.2.3`; CFNetwork matches an address entry only to
/// the same spelling, and a `*` glob against the spelling as written, the same table
/// WinINet gives. The macOS reader refuses such an entry, since a destination reaches it
/// already folded. The `no_proxy` column folds both sides and differs on purpose.
#[test]
fn non_decimal_ipv4_spellings_are_compared_as_text() {
    println!("--- CFNetwork, IPv4 spellings ---");
    let spellings = [
        "10.1.2.3",
        "012.1.2.3",
        "0xa.1.2.3",
        "10.66051",
        "10.1.2.03",
    ];
    let mut rows: Vec<(&[&str], &str, bool)> = Vec::new();
    for entry in &spellings {
        for dest in spellings {
            rows.push((std::slice::from_ref(entry), dest, *entry == dest));
        }
    }
    // Columns in the order of `spellings`.
    let globs: [(&[&str], [bool; 5]); 4] = [
        (&["10.*"], [true, false, false, true, true]),
        (&["*.3"], [true, true, true, false, false]),
        (&["012.*"], [false, true, false, false, false]),
        (&["10.0.0.0/8"], [true, false, false, false, true]),
    ];
    for (entry, verdicts) in globs {
        for (dest, bypasses) in spellings.into_iter().zip(verdicts) {
            rows.push((entry, dest, bypasses));
        }
    }
    hold_rows(&rows);
}

/// A CIDR entry is read as decimal on both sides (run 37118881978): `012.1.2.0/24` is
/// `12.1.2.0/24`, a destination written `010.1.2.5` is `10.1.2.5`, a leading zero in the
/// prefix is still 24, and `0xa` is no address. Chromium reading the same list folds
/// `012.1.2.0/24` to `10.1.2.0/24`, so the macOS reader refuses a CIDR address written
/// other than as four decimal octets.
#[test]
fn cidr_addresses_are_read_as_decimal() {
    println!("--- CFNetwork, CIDR address spellings ---");
    // Columns: 10.1.2.5, 012.1.2.5, 010.1.2.5, 12.1.2.5.
    let dests = ["10.1.2.5", "012.1.2.5", "010.1.2.5", "12.1.2.5"];
    let ten = [true, false, true, false];
    let table: [(&[&str], [bool; 4]); 6] = [
        (&["10.1.2.0/24"], ten),
        (&["012.1.2.0/24"], [false, true, false, true]),
        (&["010.1.2.0/24"], ten),
        (&["0xa.1.2.0/24"], [false; 4]),
        (&["10.1.2.0/024"], ten),
        (&["10.1.2.00/24"], ten),
    ];
    let mut rows: Vec<(&[&str], &str, bool)> = Vec::new();
    for (entry, verdicts) in table {
        for (dest, bypasses) in dests.into_iter().zip(verdicts) {
            rows.push((entry, dest, bypasses));
        }
    }
    hold_rows(&rows);
}
