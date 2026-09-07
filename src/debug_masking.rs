//! Gate: every hand-written `Debug` in `src/` is in [`REGISTRY`]. [`Exposure::Secret`]
//! entries need a value-level case that hides the secret *and* keeps a named fragment
//! (masking ≠ erasure). Platform/`pac` availability is per [`Registered::available`].
//!
//! A registry of impls cannot see text kept in a `#[derive(Debug)]` container, and that
//! blind spot is where the last two leaks were: `KconfigEntry` and `GValue` held a KDE /
//! GNOME value under a derive, and `KioslavercSettings` held the map key. [`DERIVED`] is
//! the other half of the gate — every derived item in `src/` whose fields name a text type
//! carries a row saying why its `Debug` is safe, and [`Reason`] decides what that row has
//! to prove rather than merely assert.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

// Fixture password: long and unlike hosts, hex digests, or byte counts.
const SECRET: &str = "s3cr3t-hunter2-do-not-print";

fn secret_url() -> url::Url {
    url::Url::parse(&format!("https://alice:{SECRET}@wpad.corp:8080/proxy.pac"))
        .expect("the fixture URL parses")
}

fn secret_script() -> String {
    format!("function FindProxyForURL(u, h) {{ return \"PROXY alice:{SECRET}@p:8080\"; }}")
}

// What a hand-written `Debug` is trusted with.
#[derive(Debug, Clone, Copy)]
enum Exposure {
    // It can reach a URL, a script body or a password, so it needs a case in
    // [`cases`] proving it does not print one.
    Secret,
    // It holds no secret of its own and prints another registered impl's output. The
    // string names that impl's type, which must itself be [`Exposure::Secret`] — checked
    // by `every_verdict_that_skips_a_value_case_justifies_itself`, so this verdict
    // cannot be used to park a type nobody checks.
    Delegates(&'static str),
    // Nothing it prints can carry a secret. The string says what it does print, because
    // "inert" is a claim about the fields and the next person needs to be able to
    // re-check it against the impl without re-deriving the argument.
    Inert(&'static str),
}

// One hand-written `Debug`, as [`every_hand_written_debug_is_registered`] expects to
// find it in the tree.
#[derive(Debug)]
struct Registered {
    // Path under `src/`, with `/` separators on every platform.
    file: &'static str,
    // The type the impl is written for, without generic arguments.
    ty: &'static str,
    exposure: Exposure,
    // Whether the impl compiles under the target and features running this test.
    // Written with `cfg!` so it tracks the same conditions the impl itself is gated on.
    available: bool,
}

// Every hand-written `Debug` in `src/`, with what it is allowed to reveal.
//
// Kept in the order the scan reports (by path, then type) so a diff against a failure
// message reads cleanly.
const REGISTRY: &[Registered] = &[
    Registered {
        file: "auth.rs",
        ty: "ProxyAuth",
        exposure: Exposure::Secret,
        available: true,
    },
    Registered {
        file: "env.rs",
        ty: "ProxyEnv",
        exposure: Exposure::Secret,
        available: true,
    },
    Registered {
        file: "error.rs",
        ty: "Error",
        exposure: Exposure::Secret,
        available: true,
    },
    Registered {
        file: "mode.rs",
        ty: "ProxyMode",
        exposure: Exposure::Secret,
        available: true,
    },
    Registered {
        file: "pac/mod.rs",
        ty: "PacRequirement",
        exposure: Exposure::Secret,
        available: cfg!(feature = "pac"),
    },
    Registered {
        file: "pac/mod.rs",
        ty: "PacScript",
        exposure: Exposure::Secret,
        available: cfg!(feature = "pac"),
    },
    Registered {
        file: "pac/winhttp.rs",
        ty: "WinHttpPacSource",
        exposure: Exposure::Secret,
        available: cfg!(all(
            windows,
            feature = "pac",
            feature = "pac-windows-native"
        )),
    },
    Registered {
        file: "sys/linux/gnome.rs",
        ty: "Handle",
        exposure: Exposure::Inert("a stop flag and whether the thread is joined, both bool"),
        available: cfg!(all(target_os = "linux", feature = "linux-gnome")),
    },
    Registered {
        file: "sys/linux/gsettings_map.rs",
        ty: "GValue",
        exposure: Exposure::Secret,
        // `#[cfg(any(target_os = "linux", test))]` on the module, and this is a test.
        available: true,
    },
    Registered {
        file: "sys/linux/kde.rs",
        ty: "FileWatch",
        exposure: Exposure::Inert("nothing at all — the struct name and `..`"),
        available: cfg!(all(target_os = "linux", feature = "linux-kde")),
    },
    Registered {
        file: "sys/linux/kioslaverc.rs",
        ty: "KconfigEntry",
        exposure: Exposure::Secret,
        // Same module gating as `GValue` above.
        available: true,
    },
    Registered {
        file: "sys/linux/kioslaverc.rs",
        ty: "KioslavercSettings",
        exposure: Exposure::Secret,
        available: true,
    },
    Registered {
        file: "sys/linux/watcher.rs",
        ty: "Watch",
        exposure: Exposure::Inert(
            "whether the portal route was forced, whether it polls, whether it runs — all bool",
        ),
        available: cfg!(target_os = "linux"),
    },
    Registered {
        file: "sys/mac/notify.rs",
        ty: "Watch",
        exposure: Exposure::Inert("a stop flag, whether the thread runs, and `degraded`"),
        available: cfg!(target_os = "macos"),
    },
    Registered {
        file: "sys/proxy_dict.rs",
        ty: "ProxyDict",
        exposure: Exposure::Secret,
        // `#[cfg(any(target_os = "macos", test))]`, and this is a test.
        available: true,
    },
    Registered {
        file: "watch.rs",
        ty: "ProxyWatcher",
        // Prints `config.effective` and `health` off a single `self.state()`: a
        // `ProxyMode`, and a `WatchHealth` whose `Debug` is derived over a
        // `Vec<ProxyConfigSource>`, two `bool`s and an `Option<Duration>` — none of which
        // can hold a secret. Constructing one means starting a real platform watcher, so
        // the delegation is checked structurally instead.
        exposure: Exposure::Delegates("ProxyMode"),
        available: true,
    },
];

// Why a `#[derive(Debug)]` item whose fields name a text type cannot print a secret.
//
// The three verdicts are graded by what a reader has to take on trust, and the ones that
// ask for more are checked harder — the same shape as [`Exposure`], for the same reason:
// the excuse from a value-level case is where a leak would be parked.
enum Reason {
    // Every value *this crate* stores in the type is masked or refused first, so nothing it
    // read can be printed back. Needs a case in [`derived_cases`] built around [`SECRET`]:
    // "closed at fill" is a claim about a code path, and paths move.
    //
    // It says nothing about a caller. Where the type is fillable from outside — `pub` fields,
    // or a `pub enum` whose variants carry them — a downstream crate can write its own string
    // in and print it out again: its own text, never a value read from a file, a registry or
    // `configd`. A reason on such a type has to name that second way in rather than call the
    // type sealed, because the constructor it cites is not the only way to fill one. Where
    // construction is closed to other crates as well (`RejectedValue`: private fields,
    // `#[non_exhaustive]`, a `pub(crate)` constructor), naming the constructor is the whole
    // answer.
    ClosedAtFill(&'static str),
    // The only text it can print belongs to a registered [`Exposure::Secret`] impl, named
    // here and checked to be one. The second string says which way the containment runs,
    // because holding a masked type and being held by a masking type are different
    // protections and only one of them survives someone printing this type directly.
    ViaRegistered { ty: &'static str, why: &'static str },
    // The strings are written by this crate rather than read from a file, a registry, an
    // environment variable or `configd`. Nothing mechanical checks this, which makes it the
    // bucket a wrong answer would hide in, so the reason has to name where they come from —
    // `KioslavercSettings`'s keys looked like this and were not.
    CrateText(&'static str),
}

// One `#[derive(…Debug…)]` item that holds text, as
// [`every_derived_debug_that_can_hold_text_is_declared`] expects to find it.
struct Derived {
    // Path under `src/`, with `/` separators on every platform.
    file: &'static str,
    ty: &'static str,
    reason: Reason,
    // Whether the item compiles under the target and features running this test. The scan
    // is textual and so sees every item regardless; this only decides whether a
    // [`Reason::ClosedAtFill`] row is expected to render a case here.
    available: bool,
}

// Every derived `Debug` in `src/` that can hold text, with why it is safe.
//
// Kept in the order the scan reports (by path, then type), as [`REGISTRY`] is.
static DERIVED: &[Derived] = &[
    Derived {
        file: "bypass.rs",
        ty: "HostPattern",
        reason: Reason::ClosedAtFill(
            "`HostPattern::parse` refuses any entry containing `@` before it parses a port, \
             and phrases the refusal through `redact_offending_token`, so a proxy URL \
             pasted into a bypass list never becomes a pattern in the first place. The \
             variants' fields are `pub` and `#[non_exhaustive]` on an enum does not seal \
             its existing variants, so a caller can also hand-build one — `tests/bypass.rs` \
             does, deliberately — and print back whatever it wrote there. That is the \
             caller's own string; `parse` stays the only way a value this crate read gets in",
        ),
        available: true,
    },
    Derived {
        file: "debug_masking.rs",
        ty: "Exposure",
        reason: Reason::CrateText("the `&'static str` verdicts are the ones written in this file"),
        available: true,
    },
    Derived {
        file: "debug_masking.rs",
        ty: "Registered",
        reason: Reason::CrateText("`file` and `ty` are the literals in [`REGISTRY`]"),
        available: true,
    },
    Derived {
        file: "diagnostic.rs",
        ty: "RejectedValue",
        reason: Reason::ClosedAtFill(
            "`RejectedValue::new` is the only constructor taking raw input and it stores \
             `redact_offending_token(input)`, never the input",
        ),
        available: true,
    },
    Derived {
        file: "diagnostic.rs",
        ty: "RejectionSource",
        reason: Reason::CrateText(
            "each payload names *which* setting was read, not what it held: \
             `EnvironmentVariable` gets a name out of `SCHEME_VARS`, `Kioslaverc` a \
             `SlotKeys::key`, `GSettings` a GNOME schema key, `SystemConfiguration` a \
             `SCHEMES` or `UNROUTABLE` host key — all crate constants. A KDE key read \
             from the file would \
             not be one, which is why this row names the source and not just the type",
        ),
        available: true,
    },
    Derived {
        file: "endpoint.rs",
        ty: "ProxyEndpoint",
        reason: Reason::ClosedAtFill(
            "`parse` and `new` are the constructors, and `parse` splits `user:password@` \
             off into `auth` before the rest becomes the `host` — so the `url::Host` here \
             holds an address and the credential prints through `ProxyAuth`'s registered \
             impl. The fields are `pub`, so a caller holding one can overwrite `host` \
             afterwards; what it writes is its own string, not a value this crate read",
        ),
        available: true,
    },
    Derived {
        file: "sys/linux/gsettings_map.rs",
        ty: "GnomeSettings",
        reason: Reason::ViaRegistered {
            ty: "GValue",
            why: "it holds the values, and every one of them prints through `GValue`'s own \
                  impl. Its keys are `String` but are built by `read_key` from `ROOT_KEYS` / \
                  `CHILD_KEYS` / `HTTP_AUTH_KEYS` and a child name, so unlike KDE's they \
                  cannot come from the file",
        },
        available: true,
    },
    Derived {
        file: "sys/proxy_dict.rs",
        ty: "DictValue",
        reason: Reason::ViaRegistered {
            ty: "ProxyDict",
            why: "the containment runs the other way: this is the leaf that holds the text, \
                  and it is safe only for as long as `ProxyDict`'s hand-written impl is the \
                  only thing that prints one. A `{:?}` on a bare `DictValue` would bypass \
                  every mask, which is what a catch-all arm here would give it",
        },
        available: true,
    },
    Derived {
        file: "sys/win/ffi.rs",
        ty: "RegKey",
        reason: Reason::CrateText(
            "`root` is one of the names `root_name` returns and `path` is the `&'static \
             str` the caller opened it with — always one of this backend's own key-path \
             constants. Both name *where* a value lives; neither can hold the value, \
             which is the side a proxy password would be on",
        ),
        available: cfg!(target_os = "windows"),
    },
    Derived {
        file: "sys/win/notify.rs",
        ty: "WatchedKey",
        reason: Reason::CrateText(
            "`path` is the `&'static str` registry path this backend opened, and the rest \
             of the struct is two handles, a `bool` and a `ProxyConfigSource`",
        ),
        available: cfg!(windows),
    },
];

// The type a line like `impl fmt::Debug for Foo<'_> {` is written for, if it is one.
//
// Text, not syntax: the point is to see impls the current target does not compile, which
// rules out anything that works from the item tree. `impl` must start the line so that
// prose and doc comments mentioning the same words are skipped.
fn impl_debug_target(line: &str) -> Option<&str> {
    let line = line.trim_start();
    if !(line.starts_with("impl ") || line.starts_with("impl<")) {
        return None;
    }
    let rest = line.split_once("Debug for ")?.1;
    let end = rest
        .find(|c: char| c == '<' || c == '{' || c.is_whitespace())
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

// Whether `line` is an `impl` header written in a shape that hides the impl below it from
// [`impl_debug_target`], which reads text one line at a time. Either way the header matches
// nothing, the impl never reaches [`REGISTRY`], and this gate passes while a hand-written
// `Debug` goes unchecked. [`scan_src`] refuses these rather than growing a parser.
//
// A header broken at one of the two places around `for`: before it, leaving the trait at
// the end of the line, or after it, leaving the type on the next one. The break after `for`
// is refused whatever the trait is. `impl fmt::Debug for` and `impl<T: fmt::Debug> Show for`
// are the same line to anything that has not read the next one, so a rule that tried to tell
// them apart would be guessing about precisely the case it exists to catch. A `Debug` *bound*
// alone (`impl<T: fmt::Debug> …`) ends on `>` or `{` and is neither.
//
// Or a block comment, which hides a header two ways. Put one between the trait and `for`
// and what is left either side of it is not the substring the parser splits on; put one in
// front and the line no longer begins with `impl`. Cutting it out is not enough — that
// leaves the parser's single space doubled — and a comment that opens on one line and
// closes on another is past a line-at-a-time reader however it is written.
//
// Or a `use` that renames the trait. That one hides no single header — it hides every impl
// written against the new name at once, and unlike the shapes above there is nothing in the
// header itself left to recognise, so the import is where it has to be caught.
//
// So the shape is refused, on any line naming the trait. `src/` has no block comment at all
// outside a string literal, and none of those name it. This paragraph is careful never to
// put a delimiter and the trait's name on one line, because the rule reads this file too;
// the samples are in the test, built from a variable for the reason given at
// [`rejected_list_binding`]'s.
//
// Nothing in `src/` is written any of these ways, so refusing them costs a real header
// nothing.
fn hides_a_debug_impl_header(line: &str) -> bool {
    let line = line.trim();
    // Two lines rather than one condition, and this is the reason: joined up, the line
    // would carry a delimiter and the trait's name together, and this function is applied
    // to its own source.
    let block_comment = line.contains("/*") || line.contains("*/");
    if block_comment && line.contains("Debug") {
        return true;
    }
    // A `use` that renames the trait puts every impl of it past the split just as surely:
    // the header would name something this scan has never heard of, and no shape rule
    // could tell that name from any other trait's. Two substrings rather than the spelling
    // itself, for the reason above.
    if line.starts_with("use ") && line.contains("Debug") && line.contains(" as ") {
        return true;
    }
    if !(line.starts_with("impl ") || line.starts_with("impl<")) {
        return false;
    }
    line.ends_with("Debug") || line.split_whitespace().next_back() == Some("for")
}

// Every `.rs` file under `src/`, as `(path with '/' separators, contents)`.
fn read_src_files() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    let mut pending = vec![src.clone()];

    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).expect("a directory under src/ is readable") {
            let path = entry
                .expect("a directory entry under src/ is readable")
                .path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let text = fs::read_to_string(&path).expect("a source file under src/ is UTF-8");
            let rel = path
                .strip_prefix(&src)
                .expect("the file was found under src/")
                .to_string_lossy()
                .replace('\\', "/");
            files.push((rel, text));
        }
    }
    files
}

// Every `(file, type)` pair in `src/` that writes its own `Debug`.
fn scan_src() -> BTreeSet<(String, String)> {
    let mut found = BTreeSet::new();
    for (rel, text) in read_src_files() {
        for line in text.lines() {
            assert!(
                !hides_a_debug_impl_header(line),
                "{rel} writes a line this scanner reads past without seeing the impl it \
                 covers — a header broken across lines at `for`, or interrupted by a block \
                 comment, or a `use` renaming the trait so that no header names it — so a \
                 hand-written `Debug` there would never reach REGISTRY and the gate would \
                 pass without checking it. Keep the whole `impl … Debug for Type` on one \
                 line, with no `/* … */` in it (`#[rustfmt::skip]` if it is too long to \
                 fit, and on one line even then), and import the trait under its own name."
            );
            if let Some(ty) = impl_debug_target(line) {
                found.insert((rel.clone(), ty.to_string()));
            }
        }
    }
    found
}

// `line` with any `//` comment cut off, so that neither the brace counting below nor the
// field scan reads prose. A doc comment starts with `//` too, and dropping it from the
// first slash is enough for both.
//
// Safe against string literals because a Rust item body has no place to put one: fields
// carry types, not values.
fn code_only(line: &str) -> &str {
    line.split("//").next().unwrap_or(line)
}

// Whether `line` is a `#[derive(…)]` attribute listing `Debug`.
//
// Text, and for the same reason as [`impl_debug_target`]: most of these items are in
// backends this target does not compile, so nothing that works from the item tree can see
// them.
fn derives_debug(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with("#[derive(")
        && line
            .split(|c: char| !is_name_byte(c))
            .any(|word| word == "Debug")
}

// Whether `line` opens a `#[derive(…)]` that rustfmt broke across lines.
//
// The counterpart of [`hides_a_debug_impl_header`], and refused for the same reason:
// [`derives_debug`] reads one line at a time, so a `Debug` pushed onto the next line would
// make the item invisible to the scan while this gate stayed green.
fn splits_a_derive_attribute(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with("#[derive(") && !line.contains(")]")
}

// Whether `line` is one of the things that can stand between a derive and the item it
// applies to: another attribute, a comment, or nothing.
fn stands_between_a_derive_and_its_item(line: &str) -> bool {
    let line = line.trim();
    line.is_empty() || line.starts_with("#[") || line.starts_with("//")
}

// The name of the item a derive applies to: `pub(crate) enum DictValue {` → `DictValue`.
fn derived_item_name(line: &str) -> Option<&str> {
    let mut words = line.split_whitespace();
    let mut word = words.next()?;
    if word.starts_with("pub") {
        word = words.next()?;
    }
    if !matches!(word, "struct" | "enum" | "union") {
        return None;
    }
    let name = words.next()?;
    let end = name.find(|c: char| !is_name_byte(c)).unwrap_or(name.len());
    (end > 0).then(|| &name[..end])
}

// Whether `line` names a type that can carry text this crate did not write.
//
// A generic bound (`S: AsRef<str>`) counts, which over-reports rather than under-reports:
// a row saying why the type is safe is cheap, and a missing row is a type nobody looked at.
//
// `Host` is here because the scan reads names, not types, and so cannot follow one into
// another crate: `url::Host<S = String>` carries its `String` through a default type
// argument, and a field written `host: Host` names no text type at all. The blind spot is
// not inert — "every leaf is scanned" is false for a leaf that is not in this crate to
// scan. Any other borrowed text carrier has to be added by hand for the same reason.
//
// `Url` is that same blind spot with more at stake: a `#[derive(Debug)]` over a `url::Url`
// field goes unseen here, while `url`'s own
// `Debug` prints the string whole — userinfo included, which is where this crate's
// passwords live. `MaskedUrl` and every registered impl carrying a URL exist because that
// rendering is unsafe, so a container that reaches one under a derive has to say why it is
// not. Nothing in `src/` trips this today; it is here for the next one.
//
// `aliases` is the third form of the same blind spot, and the only one this scan can close
// by reading rather than by listing: see [`text_carrier_aliases`].
fn names_a_text_type(line: &str, aliases: &BTreeSet<String>) -> bool {
    code_only(line)
        .split(|c: char| !is_name_byte(c))
        .any(|word| {
            matches!(
                word,
                "String"
                    | "str"
                    | "OsString"
                    | "OsStr"
                    | "PathBuf"
                    | "Path"
                    | "Cow"
                    | "Host"
                    | "Url"
            ) || aliases.contains(word)
        })
}

// The crate's own names for a text type. `type CredentialText = String;` makes
// `CredentialText` one, and a field written with it names nothing on the list above — so a
// derive that prints the whole string is invisible to a scan that reads names.
//
// The same shape as the `Host` and `Url` entries above, one step closer: those live in
// another crate's source, which nothing here can read, so they are listed by hand. An alias
// is in `src/`, so it is read instead. Collected from the whole tree before any item is,
// because an alias and the field that uses it need not share a file.
//
// Chains are followed by repeating the pass until it finds nothing new. Collecting the inner
// alias is not enough on its own: `type Outer = Inner;` names a text type only once `Inner`
// is already in the set, and the two need not share a file or fall in a helpful order, so a
// single pass reaches whichever of them it happens to read second and no further. A newtype
// (`struct Secret(String);`) is not an alias at all: it is an item, and its own derive is
// scanned like any other. What is left out is an alias whose right-hand side is a type from
// another crate that carries text without naming it, which is the hand-listed case again and
// not something more passes would find.
//
// `pub` in front is skipped the way [`derived_item_name`] skips it. Reading only the bare
// spelling made every exported alias invisible — and an alias worth exporting is the one a
// field in another module is most likely to be written with.
//
// An associated type is picked up by the same spelling (`type Item = …` inside an `impl`),
// which over-reports in the direction this file always takes: a name that cannot appear as a
// field type costs a row saying so, and a missing one costs a password.
fn text_carrier_aliases(files: &[(String, String)]) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    loop {
        let known = aliases.len();
        for (_, text) in files {
            for line in text.lines() {
                let Some((head, definition)) = code_only(line).trim_start().split_once('=') else {
                    continue;
                };
                let mut words = head.split_whitespace();
                let mut word = words.next();
                if word.is_some_and(|word| word.starts_with("pub")) {
                    word = words.next();
                }
                if word != Some("type") {
                    continue;
                }
                let Some(name) = words.next() else { continue };
                let end = name.find(|c: char| !is_name_byte(c)).unwrap_or(name.len());
                if end > 0 && names_a_text_type(definition, &aliases) {
                    aliases.insert(name[..end].to_string());
                }
            }
        }
        if aliases.len() == known {
            return aliases;
        }
    }
}

// The lines of an item starting at `lines[0]`, up to and including the one that closes it.
//
// Depth over `{`/`(` so that a tuple struct and a braced one both terminate; a unit struct
// opens neither and ends on its own `;`.
fn item_body<'a>(lines: &[&'a str]) -> Vec<&'a str> {
    let mut body = Vec::new();
    let mut depth = 0i32;
    let mut opened = false;
    for line in lines {
        body.push(*line);
        for c in code_only(line).chars() {
            match c {
                '{' | '(' => {
                    depth += 1;
                    opened = true;
                }
                '}' | ')' => depth -= 1,
                _ => {}
            }
        }
        if opened && depth <= 0 {
            break;
        }
        if !opened && code_only(line).trim_end().ends_with(';') {
            break;
        }
    }
    body
}

// Every `(file, type)` pair in `src/` that derives `Debug` over a field naming a text type.
fn scan_derived_text_holders() -> BTreeSet<(String, String)> {
    let files = read_src_files();
    let aliases = text_carrier_aliases(&files);
    let mut found = BTreeSet::new();
    for (rel, text) in &files {
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            assert!(
                !splits_a_derive_attribute(line),
                "{rel}:{} splits a `#[derive(…)]` across lines, which this scanner reads \
                 one line at a time — a `Debug` below the break would never reach DERIVED \
                 and the gate would pass without checking it. Keep the attribute on one \
                 line (`#[rustfmt::skip]` if it is too long to fit).",
                index + 1
            );
            if !derives_debug(line) {
                continue;
            }
            let mut at = index + 1;
            while lines
                .get(at)
                .is_some_and(|line| stands_between_a_derive_and_its_item(line))
            {
                at += 1;
            }
            let head = lines.get(at).copied().unwrap_or_default();
            let ty = derived_item_name(head).unwrap_or_else(|| {
                panic!(
                    "{rel}:{} derives `Debug` for something this scan cannot name: {head:?}",
                    index + 1
                )
            });
            if item_body(&lines[at..])
                .iter()
                .any(|l| names_a_text_type(l, &aliases))
            {
                found.insert((rel.clone(), ty.to_string()));
            }
        }
    }
    found
}

// Whether `line` appends to a list of tokens that failed to parse but are kept for the
// caller to see (`BypassRules::rejected`, `ProxyEnv::rejected`, `kioslaverc`'s `skipped`).
//
// Text again, and for the same reason as [`impl_debug_target`]: most of these sites are
// in backends this target does not compile. The call must start the line for the same
// reason too — otherwise prose, and this file's own tests, match themselves.
fn keeps_a_rejected_token(line: &str) -> bool {
    let line = line.trim_start();
    let line = line.strip_prefix("self.").unwrap_or(line);
    [
        "rejected.push(",
        "skipped.push(",
        "rejected.extend(",
        "skipped.extend(",
    ]
    .iter()
    .any(|call| line.starts_with(call))
}

// The name a field or parameter holding a list of rejected tokens is bound to.
//
// [`keeps_a_rejected_token`] recognises appends by the spelling of that name, which is a
// guess; this is what the guess is checked against. A return type carries no binding to
// append to, so a line that reaches the type without a name and a colon in front of it is
// not one of these, and neither is prose.
fn rejected_list_binding(line: &str) -> Option<&str> {
    if line.trim_start().starts_with("//") {
        return None;
    }
    let (head, _) = [": Vec<RejectedValue>", ": &mut Vec<RejectedValue>"]
        .iter()
        .find_map(|separator| line.split_once(separator))?;
    let name = head.rsplit(|c: char| !is_name_byte(c)).next()?;
    (!name.is_empty()).then_some(name)
}

fn is_name_byte(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

// A rendered `Debug` and what it has to look like.
struct Case {
    file: &'static str,
    ty: &'static str,
    // What `{:?}` produced for a value built around [`SECRET`].
    rendered: String,
    // Fragments that must survive the masking, so that erasing the whole field cannot
    // pass for redacting it.
    must_contain: &'static [&'static str],
}

// One rendered `Debug` per [`Exposure::Secret`] entry that compiles here.
fn cases() -> Vec<Case> {
    let mut cases = vec![
        Case {
            file: "auth.rs",
            ty: "ProxyAuth",
            rendered: format!("{:?}", crate::auth::ProxyAuth::new("alice", Some(SECRET))),
            must_contain: &["alice", "***"],
        },
        Case {
            file: "auth.rs",
            ty: "ProxyAuth",
            // `%3A` is *data*, so this parses to the single user name `alice:{SECRET}` with
            // no password at all (see `endpoint::parse_userinfo`). Nothing downstream can
            // tell that colon from a credential delimiter, so the `Debug` masks past it —
            // that masking, not the split, is what keeps the tail out of a snapshot. The
            // second `%3A` is what makes the mask start at the *first* colon rather than the
            // last: read from the end, everything up to the final delimiter is printed as a
            // user name, and a password holding a colon of its own is the ordinary case.
            rendered: {
                let endpoint = crate::endpoint::ProxyEndpoint::parse(
                    &format!("http://alice%3A{SECRET}%3Atail@proxy.corp:8080"),
                    80,
                )
                .expect("percent-encoded userinfo must parse");
                format!("{:?}", endpoint.auth.expect("auth present"))
            },
            must_contain: &["alice", "***"],
        },
        Case {
            file: "auth.rs",
            ty: "ProxyAuth",
            rendered: format!(
                "{:?}",
                crate::auth::ProxyAuth::from_username(format!("alice:{SECRET}"))
            ),
            must_contain: &["alice", "***"],
        },
        Case {
            file: "error.rs",
            ty: "Error",
            rendered: format!(
                "{:?}",
                crate::error::Error::PacFetchRequired { url: secret_url() }
            ),
            must_contain: &["wpad.corp", "***"],
        },
        Case {
            file: "mode.rs",
            ty: "ProxyMode",
            rendered: format!("{:?}", crate::mode::ProxyMode::pac(secret_url())),
            must_contain: &["wpad.corp", "***"],
        },
        Case {
            file: "mode.rs",
            ty: "ProxyMode",
            // The same variant with the `%3A` spelling of the delimiter, which `Url` reads
            // as one long user name with no password at all. `MaskedUrl` has a branch for
            // that shape and a test to hold it (`a_percent_encoded_password_is_still_masked`
            // in `trace.rs`); this `Debug` reaches `redact_userinfo` directly, with nothing
            // pinning the same input against it until here.
            rendered: format!(
                "{:?}",
                crate::mode::ProxyMode::pac(
                    url::Url::parse(&format!(
                        "https://alice%3A{SECRET}@wpad.corp:8080/proxy.pac"
                    ))
                    .expect("percent-encoded userinfo must parse")
                )
            ),
            must_contain: &["wpad.corp", "***"],
        },
        Case {
            file: "mode.rs",
            ty: "ProxyMode",
            rendered: format!("{:?}", crate::mode::ProxyMode::pac_inline(secret_script())),
            must_contain: &["len", "fnv1a"],
        },
    ];

    {
        // The other half of `ProxyMode`: `Manual` keeps what failed to parse, so its
        // `Debug` prints attacker- (or administrator-) supplied text that never reached
        // a URL type. Built from the real parsers rather than a literal, because the
        // masking that has to hold is the one on the path a snapshot actually takes.
        let env = crate::env::ProxyEnv::from_vars([
            (
                "http_proxy",
                format!("http://alice:{SECRET}@proxy.corp:99999"),
            ),
            ("no_proxy", format!("[alice:{SECRET}]")),
        ])
        .expect("malformed values are rejected entries, not a snapshot failure");
        cases.push(Case {
            file: "mode.rs",
            ty: "ProxyMode",
            rendered: format!("{:?}", env.to_mode()),
            // The endpoint keeps its host and shows `***`; the bypass entry has no `@`
            // to make the userinfo recognisable, so the whole token is withheld instead.
            must_contain: &["proxy.corp", "***", "withheld"],
        });

        // The same values one step earlier, before `to_mode` moved them. `ProxyEnv`'s
        // `Debug` is hand-written for the field order, not for masking, so this case is
        // what keeps the two apart: rewriting it must not cost the masking its delegates
        // already do.
        cases.push(Case {
            file: "env.rs",
            ty: "ProxyEnv",
            rendered: format!("{env:?}"),
            must_contain: &["proxy.corp", "***", "withheld"],
        });
    }

    {
        // The KDE twin of the `ProxyDict` case below, and the reason it is here: the file
        // holds whatever an administrator wrote, and `httpProxy=http://user:pw@host` is
        // ordinary KDE configuration. Rendered through `KioslavercSettings`, whose derive
        // delegates to the registered `KconfigEntry`, because that is the shape a caller
        // would actually print.
        let mut settings = crate::sys::linux::kioslaverc::KioslavercSettings::new();
        settings.insert("httpProxy", secret_url().to_string());
        cases.push(Case {
            file: "sys/linux/kioslaverc.rs",
            ty: "KconfigEntry",
            rendered: format!("{settings:?}"),
            must_contain: &["wpad.corp", "***"],
        });

        // The key half, which the same struct's `Debug` owns. A line's key is whatever
        // stood left of its first `=`, so a PAC URL pasted into the section is applied
        // under a key that holds its own credentials, the query having supplied the `=`.
        // The ordinary key above has to survive it, which is what pins masking to the
        // credential shape rather than to "this is a key".
        let mut settings = crate::sys::linux::kioslaverc::KioslavercSettings::new();
        settings.insert(
            &format!("https://alice:{SECRET}@wpad.corp/proxy.pac?a"),
            "1",
        );
        settings.insert("httpProxy", "http://proxy.corp:8080");
        cases.push(Case {
            file: "sys/linux/kioslaverc.rs",
            ty: "KioslavercSettings",
            rendered: format!("{settings:?}"),
            must_contain: &["wpad.corp", "***", "httpProxy", "proxy.corp"],
        });
    }

    {
        // `autoconfig-url` is where a secret reaches `GValue` today; the password key is
        // mapped but not read (`gnome::READ_AUTHENTICATION_PASSWORD`). Both go through
        // the same `Text` arm, so one case covers the flag being flipped as well.
        let mut settings = crate::sys::linux::gsettings_map::GnomeSettings::new();
        settings.insert(
            crate::sys::linux::gsettings_map::KEY_AUTOCONFIG_URL,
            crate::sys::linux::gsettings_map::GValue::Text(secret_url().to_string()),
        );
        cases.push(Case {
            file: "sys/linux/gsettings_map.rs",
            ty: "GValue",
            rendered: format!("{settings:?}"),
            must_contain: &["wpad.corp", "***"],
        });
    }

    {
        let mut dict = crate::sys::proxy_dict::ProxyDict::new();
        dict.insert(
            "ProxyAutoConfigURLString",
            crate::sys::proxy_dict::DictValue::Text(secret_url().to_string()),
        );
        dict.insert(
            "ProxyAutoConfigJavaScript",
            crate::sys::proxy_dict::DictValue::Text(secret_script()),
        );
        cases.push(Case {
            file: "sys/proxy_dict.rs",
            ty: "ProxyDict",
            rendered: format!("{dict:?}"),
            must_contain: &["wpad.corp", "***", "fnv1a"],
        });
    }

    {
        // The same key holding a password with a space in it. Nothing upstream rejects one:
        // the value is whatever `SCDynamicStore` hands back for
        // `ProxyAutoConfigURLString`, read as raw text long before anything asks it to
        // parse as a URL. `redact_userinfo` alone cannot mask this — its scan restarts past
        // whitespace, so the `user:` half and the `@` end up on opposite sides of the
        // restart — which is why this key goes through `redact_offending_token`.
        let mut dict = crate::sys::proxy_dict::ProxyDict::new();
        dict.insert(
            "ProxyAutoConfigURLString",
            crate::sys::proxy_dict::DictValue::Text(format!(
                "http://alice:my {SECRET}@wpad.corp:8080/proxy.pac"
            )),
        );
        cases.push(Case {
            file: "sys/proxy_dict.rs",
            ty: "ProxyDict",
            rendered: format!("{dict:?}"),
            must_contain: &["withheld"],
        });
    }

    {
        // The keys this crate reads, as opposed to the `AUTO_CONFIG_*` pair above. Both of
        // these reach the fallthrough arm unless the mask names them: `is_known_key` guards
        // the three "key not read" arms, so being *known* is what would take a value past
        // every mask and into `DictValue`'s derive. `HTTPProxy` holding a bare
        // `user:pass@host` is
        // documented input (`ProxyEndpoint::parse`), and `ExceptionsList` is where a
        // stranded credential fragment turns up — the same shape `no_proxy` produces.
        let mut dict = crate::sys::proxy_dict::ProxyDict::new();
        dict.insert(
            "HTTPProxy",
            crate::sys::proxy_dict::DictValue::Text(format!("alice:{SECRET}@proxy.corp:8080")),
        );
        dict.insert(
            "ExceptionsList",
            crate::sys::proxy_dict::DictValue::List {
                items: vec!["example.com".to_owned(), format!("[bob:{SECRET}]")],
                unreadable: 0,
            },
        );
        cases.push(Case {
            file: "sys/proxy_dict.rs",
            ty: "ProxyDict",
            rendered: format!("{dict:?}"),
            // The address keeps its host and shows `***`; the bypass entry has no `@` to
            // make the userinfo recognisable, so the whole token is withheld instead.
            must_contain: &["proxy.corp", "***", "example.com", "withheld"],
        });
    }

    {
        // The same two keys holding a value of a type Apple's schema does not put there.
        // `to_dict_value` reads the Core Foundation runtime type and never the key, so this
        // combination is reachable; it has an arm of its own in `ProxyDict`'s `Debug`, and
        // a second case here is what keeps the tree-wide sweep passing over it.
        let mut dict = crate::sys::proxy_dict::ProxyDict::new();
        dict.insert(
            "ProxyAutoConfigURLString",
            crate::sys::proxy_dict::DictValue::List {
                items: vec![secret_url().to_string()],
                unreadable: 0,
            },
        );
        dict.insert(
            "ProxyAutoConfigJavaScript",
            crate::sys::proxy_dict::DictValue::List {
                items: vec![secret_script()],
                unreadable: 0,
            },
        );
        cases.push(Case {
            file: "sys/proxy_dict.rs",
            ty: "ProxyDict",
            rendered: format!("{dict:?}"),
            // Nothing of the value survives: unlike the `Text` forms above there is no
            // schema to reduce it by, so there is no safe part to keep.
            must_contain: &["withheld"],
        });
    }

    #[cfg(feature = "pac")]
    {
        let url = secret_url();
        let script = secret_script();
        cases.push(Case {
            file: "pac/mod.rs",
            ty: "PacRequirement",
            rendered: format!("{:?}", crate::pac::PacRequirement::Fetch(&url)),
            must_contain: &["wpad.corp", "***"],
        });
        cases.push(Case {
            file: "pac/mod.rs",
            ty: "PacRequirement",
            rendered: format!("{:?}", crate::pac::PacRequirement::Inline(&script)),
            must_contain: &["len", "fnv1a"],
        });
        cases.push(Case {
            file: "pac/mod.rs",
            ty: "PacScript",
            rendered: format!("{:?}", crate::pac::PacScript::new(script)),
            must_contain: &["len", "fnv1a"],
        });
    }

    #[cfg(all(windows, feature = "pac", feature = "pac-windows-native"))]
    {
        let url = secret_url();
        cases.push(Case {
            file: "pac/winhttp.rs",
            ty: "WinHttpPacSource",
            rendered: format!("{:?}", crate::pac::WinHttpPacSource::Url(url.clone())),
            must_contain: &["wpad.corp", "***"],
        });
        cases.push(Case {
            file: "pac/winhttp.rs",
            ty: "WinHttpPacSource",
            rendered: format!("{:?}", crate::pac::WinHttpPacSource::AutoDetectThenUrl(url)),
            must_contain: &["wpad.corp", "***"],
        });
    }

    cases
}

// One rendered `Debug` per [`Reason::ClosedAtFill`] row that compiles here.
//
// These render the *fill* path rather than the type, because that is what the verdict
// claims: the value is put out of reach before it is stored, so the type's own derive has
// nothing left to leak.
fn derived_cases() -> Vec<Case> {
    let mut cases = Vec::new();

    {
        // A pasted proxy URL and an ordinary suffix, through the same entry point. The
        // refusal has to be the thing that hides the password — `HostPattern` itself never
        // sees it — so both halves are rendered together.
        let refused = crate::bypass::HostPattern::parse(&format!("alice:{SECRET}@proxy.corp"));
        let kept = crate::bypass::HostPattern::parse(".example.com");
        cases.push(Case {
            file: "bypass.rs",
            ty: "HostPattern",
            rendered: format!("{refused:?} {kept:?}"),
            must_contain: &["proxy.corp", "***", "example.com"],
        });
    }

    {
        // The whole endpoint, not just its `auth`: the point of the row is that the split
        // happens at `parse`, so the password is in the `auth` half being masked and the
        // `host` half is left with an address. Printing only the credential would test
        // `ProxyAuth` over again and say nothing about where the text went.
        let endpoint = crate::endpoint::ProxyEndpoint::parse(
            &format!("http://alice:{SECRET}@proxy.corp:8080"),
            80,
        )
        .expect("a credential-bearing proxy URL must parse");
        cases.push(Case {
            file: "endpoint.rs",
            ty: "ProxyEndpoint",
            rendered: format!("{endpoint:?}"),
            must_contain: &["alice", "***", "proxy.corp", "8080"],
        });
    }

    {
        // `new` is the only constructor that takes raw input, so masking there is what the
        // derived `Debug` below it rests on.
        let rejected = crate::diagnostic::RejectedValue::new(
            crate::diagnostic::RejectionKind::InvalidProxyEndpoint,
            crate::diagnostic::RejectionSource::BypassList,
            secret_url(),
        );
        cases.push(Case {
            file: "diagnostic.rs",
            ty: "RejectedValue",
            rendered: format!("{rejected:?}"),
            must_contain: &["wpad.corp", "***", "BypassList"],
        });
    }

    cases
}

#[cfg(test)]
mod tests {
    use super::*;

    // What both value-level gates mean by "masked": the password is gone and the rest is
    // not, because a `Debug` that printed `<redacted>` and nothing else would pass the
    // first half while being useless for the thing a reader turned it on for.
    fn hides_the_secret_without_erasing_the_rest(case: &Case) {
        assert!(
            !case.rendered.contains(SECRET),
            "{}'s `Debug` ({}) printed the password: {}",
            case.ty,
            case.file,
            case.rendered
        );
        for fragment in case.must_contain {
            assert!(
                case.rendered.contains(fragment),
                "{}'s `Debug` ({}) dropped {fragment:?} — that is erasure, not masking: {}",
                case.ty,
                case.file,
                case.rendered
            );
        }
    }

    // The half that makes the other half impossible to forget: what is in the tree and
    // what is in [`REGISTRY`] have to be the same set, both ways round. A new
    // hand-written `Debug` fails this; so does a registry row for an impl that was
    // deleted or renamed, which is what keeps the table from rotting into a list of
    // types that no longer exist.
    #[test]
    fn every_hand_written_debug_is_registered() {
        let found: BTreeSet<(String, String)> = scan_src();
        let registered: BTreeSet<(String, String)> = REGISTRY
            .iter()
            .map(|r| (r.file.to_string(), r.ty.to_string()))
            .collect();

        let unregistered: Vec<_> = found.difference(&registered).collect();
        assert!(
            unregistered.is_empty(),
            "hand-written `Debug` impls missing from REGISTRY in src/debug_masking.rs: \
             {unregistered:?}. Add a row saying whether the type can reach a URL, a \
             script body or a password; if it can, mark it Exposure::Secret and add a \
             case to `cases`."
        );

        let stale: Vec<_> = registered.difference(&found).collect();
        assert!(
            stale.is_empty(),
            "REGISTRY rows with no matching impl in src/: {stale:?}. The impl was \
             renamed, moved or deleted — update the row rather than leaving it."
        );
    }

    // Two of the three verdicts excuse a type from having a value-level case, which
    // makes them the way a leak would get parked rather than fixed. Neither is allowed
    // to be a bare assertion: a delegate has to name an impl that *is* checked, and an
    // inert type has to say what it prints instead, so that re-checking the claim later
    // is reading two lines rather than re-deriving the argument.
    #[test]
    fn every_verdict_that_skips_a_value_case_justifies_itself() {
        for entry in REGISTRY {
            match entry.exposure {
                Exposure::Secret => {}
                Exposure::Delegates(target) => {
                    let delegate = REGISTRY.iter().find(|r| r.ty == target).unwrap_or_else(|| {
                        panic!("{}'s delegate {target} is not registered", entry.ty)
                    });
                    assert!(
                        matches!(delegate.exposure, Exposure::Secret),
                        "{} delegates to {target}, which is not itself checked as a \
                         secret bearer — the delegation proves nothing",
                        entry.ty
                    );
                }
                Exposure::Inert(reason) => assert!(
                    !reason.trim().is_empty(),
                    "{} ({}) is registered inert with no account of what it does print",
                    entry.ty,
                    entry.file
                ),
            }
        }
    }

    // The value-level half, plus the check that it covers every [`Exposure::Secret`]
    // entry this target can build. The coverage assertion is the reason a leak cannot be
    // hidden by simply not writing a case.
    #[test]
    fn every_secret_bearing_debug_hides_it() {
        let cases = cases();

        for case in &cases {
            hides_the_secret_without_erasing_the_rest(case);
        }

        let covered: BTreeSet<(&str, &str)> = cases.iter().map(|c| (c.file, c.ty)).collect();
        let expected: BTreeSet<(&str, &str)> = REGISTRY
            .iter()
            .filter(|r| matches!(r.exposure, Exposure::Secret) && r.available)
            .map(|r| (r.file, r.ty))
            .collect();
        assert_eq!(
            covered, expected,
            "the secret-bearing impls available on this target and the ones `cases` \
             actually renders have drifted apart"
        );
    }

    // The same both-ways check as [`every_hand_written_debug_is_registered`], for the half
    // of the tree that gate cannot see. A new derived item holding text fails this; so does
    // a row for one that lost its text field or its derive, which is what stops the table
    // from silently outliving its reasons.
    #[test]
    fn every_derived_debug_that_can_hold_text_is_declared() {
        let found: BTreeSet<(String, String)> = scan_derived_text_holders();
        let declared: BTreeSet<(String, String)> = DERIVED
            .iter()
            .map(|d| (d.file.to_string(), d.ty.to_string()))
            .collect();

        let undeclared: Vec<_> = found.difference(&declared).collect();
        assert!(
            undeclared.is_empty(),
            "these derive `Debug` over a field naming a text type, with no row in DERIVED \
             (src/debug_masking.rs): {undeclared:?}. Say why the text cannot be a secret — \
             and if it can be, hand-write the impl instead and register it in REGISTRY."
        );

        let stale: Vec<_> = declared.difference(&found).collect();
        assert!(
            stale.is_empty(),
            "DERIVED rows with no matching derived item in src/: {stale:?}. The item was \
             renamed, lost its text field, or now writes its `Debug` by hand — in the last \
             case the row belongs in REGISTRY."
        );
    }

    // Two of the three verdicts excuse a derive from rendering a case, so neither is
    // allowed to be a bare assertion: `ViaRegistered` has to name an impl that *is*
    // checked, and `CrateText` has to say where the strings come from. The second is the
    // weaker of the two on purpose — nothing can mechanically prove a `String` never
    // touched the environment — which is why it has to be argued in the row rather than
    // chosen by default.
    #[test]
    fn every_reason_a_derive_is_safe_says_what_it_rests_on() {
        for entry in DERIVED {
            let why = match entry.reason {
                Reason::ClosedAtFill(why) | Reason::CrateText(why) => why,
                Reason::ViaRegistered { ty, why } => {
                    let target = REGISTRY.iter().find(|r| r.ty == ty).unwrap_or_else(|| {
                        panic!("{}'s masked type {ty} is not in REGISTRY", entry.ty)
                    });
                    assert!(
                        matches!(target.exposure, Exposure::Secret),
                        "{} rests on {ty}, which is not itself checked as a secret bearer — \
                         the reason proves nothing",
                        entry.ty
                    );
                    why
                }
            };
            assert!(
                !why.trim().is_empty(),
                "{} ({}) is declared safe with no account of why",
                entry.ty,
                entry.file
            );
        }
    }

    // The value-level half of the derive gate. `ClosedAtFill` is the one verdict that names
    // a code path rather than a shape, so it is the one that can quietly stop being true —
    // these render the path itself, not the type.
    #[test]
    fn every_value_closed_at_fill_is_shown_to_be() {
        let cases = derived_cases();

        for case in &cases {
            hides_the_secret_without_erasing_the_rest(case);
        }

        let covered: BTreeSet<(&str, &str)> = cases.iter().map(|c| (c.file, c.ty)).collect();
        let expected: BTreeSet<(&str, &str)> = DERIVED
            .iter()
            .filter(|d| matches!(d.reason, Reason::ClosedAtFill(_)) && d.available)
            .map(|d| (d.file, d.ty))
            .collect();
        assert_eq!(
            covered, expected,
            "the fill paths declared closed on this target and the ones `derived_cases` \
             actually renders have drifted apart"
        );
    }

    // The hole the rest of this file cannot see: rejected tokens live in derived-Debug
    // containers. The invariant lives at construction: either the append visibly masks
    // through `redact_offending_token`, or it constructs `RejectedValue`, whose only raw
    // input constructor performs that same masking before the value can be observed.
    #[test]
    fn every_kept_token_is_masked_where_it_is_kept() {
        let mut unmasked = Vec::new();
        for (rel, text) in read_src_files() {
            let lines: Vec<&str> = text.lines().collect();
            for (number, line) in lines.iter().enumerate() {
                if !keeps_a_rejected_token(line) {
                    continue;
                }
                // Moving an already-masked record into another list masks nothing further:
                // `skipped` holds `RejectedValue`s, and the second only re-labels one that
                // `endpoint_for` had already built through `RejectedValue::new`.
                let trimmed = line.trim();
                if matches!(
                    trimmed,
                    "rejected.extend(skipped);"
                        | "rejected.push(value.for_scheme(Some(Scheme::Https)));"
                ) {
                    continue;
                }
                // Once the call carries a builder step rustfmt breaks the constructor onto
                // its own line, so the append and its masking are not always one line. The
                // window is the append plus the two lines a broken-up call needs.
                let masked = lines[number..lines.len().min(number + 3)].iter().any(|l| {
                    l.contains("redact_offending_token") || l.contains("RejectedValue::new")
                });
                if !masked {
                    unmasked.push(format!("{rel}:{}: {trimmed}", number + 1));
                }
            }
        }
        assert!(
            unmasked.is_empty(),
            "these keep a token that failed to parse without masking it: {unmasked:#?}. \
             Wrap it in `RejectedValue::new` or `util::redact_offending_token`; \
             `redact_userinfo` is not enough, \
             because a token that failed to parse may never have reached its `@`. If the \
             append genuinely carries no untrusted text, say so where it is written and \
             exempt it here."
        );
    }

    // The gate above finds its sites by the spelling of the list being appended to, which
    // is a guess — and a guess is the one thing a gate must not rest on quietly. A
    // caller-visible list declared as `refused` or `dropped` would be appended to by lines
    // the scan never looks at, and the append would go unmasked with every test in this
    // file still green. So hold the guess to the declarations it is guessing at.
    //
    // A local with an inferred type is not reached here, and does not need to be: it can
    // only become visible to a caller by being moved into one of these lists, and that move
    // is itself an append the scan sees.
    #[test]
    fn every_declared_list_of_rejected_values_is_named_something_the_scan_looks_for() {
        let mut unseen = Vec::new();
        for (rel, text) in read_src_files() {
            for (number, line) in text.lines().enumerate() {
                let Some(name) = rejected_list_binding(line) else {
                    continue;
                };
                if !keeps_a_rejected_token(&format!("{name}.push(value);")) {
                    unseen.push(format!("{rel}:{}: {}", number + 1, line.trim()));
                }
            }
        }
        assert!(
            unseen.is_empty(),
            "these hold rejected tokens under a name `keeps_a_rejected_token` does not \
             look for, so appends to them are never checked for masking: {unseen:#?}. \
             Either rename the binding or add its spelling to that scan."
        );
    }

    // The scan is the load-bearing half, so its parser gets its own test rather than
    // being trusted because the tree happens to pass today.
    #[test]
    fn the_scanner_reads_the_shapes_this_tree_uses() {
        assert_eq!(
            impl_debug_target("impl fmt::Debug for ProxyAuth {"),
            Some("ProxyAuth")
        );
        assert_eq!(
            impl_debug_target("impl std::fmt::Debug for Error {"),
            Some("Error")
        );
        assert_eq!(
            impl_debug_target("impl fmt::Debug for PacRequirement<'_> {"),
            Some("PacRequirement")
        );
        assert_eq!(
            impl_debug_target("impl<T> fmt::Debug for Wrapper<T> {"),
            Some("Wrapper")
        );
        assert_eq!(
            impl_debug_target("    impl Debug for Indented {"),
            Some("Indented")
        );
        // No space before the brace. rustfmt would not write this and so the tree cannot
        // contain it, but this parser is textual precisely so that it sees headers the
        // formatter and the compiler between them do not. Nothing but this line holds the
        // `{` terminator.
        assert_eq!(
            impl_debug_target("impl fmt::Debug for Tight{"),
            Some("Tight")
        );

        assert_eq!(
            impl_debug_target("/// impl fmt::Debug for Mentioned {"),
            None
        );
        assert_eq!(impl_debug_target("#[derive(Debug)]"), None);
        assert_eq!(impl_debug_target("impl fmt::Display for ProxyAuth {"), None);

        // The shapes `impl_debug_target` cannot see, and the reason `scan_src` refuses them
        // instead of returning `None` and moving on: with the header broken at `for`, the
        // impl reaches neither this parser nor REGISTRY, and the gate passes blind.
        let before = "impl<'a, T: Bound> fmt::Debug";
        assert_eq!(impl_debug_target(before), None);
        assert!(hides_a_debug_impl_header(before));
        assert!(hides_a_debug_impl_header("impl std::fmt::Debug"));

        // The other side of the same break, and the side no reader expects to be broken:
        // `split_once("Debug for ")` wants the trailing space, so this parses to `None`
        // exactly like the case above.
        let after = "impl fmt::Debug for";
        assert_eq!(impl_debug_target(after), None);
        assert!(hides_a_debug_impl_header(after));
        // Refused whatever the trait is, deliberately: this line and `after` are
        // indistinguishable without reading the next one.
        assert!(hides_a_debug_impl_header("impl<T: fmt::Debug> Show for"));

        // The third shape, and the one that is a whole valid header rather than half of
        // one: a block comment leaves nothing here to notice. Written through `comment`
        // for the reason given at `rejected_list_binding`'s samples — spelled out, these
        // lines would be the very declarations the scan refuses when it reads this file.
        let comment = "/* audited later */";
        for hidden in [
            format!("impl fmt::Debug {comment} for NewType {{"),
            format!("{comment} impl fmt::Debug for NewType {{"),
        ] {
            assert_ne!(impl_debug_target(&hidden), Some("NewType"), "{hidden}");
            assert!(hides_a_debug_impl_header(&hidden), "{hidden}");
        }
        // The delimiter alone is not the shape — `src/` has one in a glob pattern.
        assert!(!hides_a_debug_impl_header("            \"*/people/*\""));
        // The closing half beside the trait's name is the shape, and this line is the only
        // thing holding it: both samples above carry an opener too, so the pair's closing
        // spelling answers to nothing else. This is the one that arrives without its
        // opener — a comment begun further up and ended just before a live header, which is
        // then a line that no longer begins with `impl` and so reaches neither the parser
        // above nor REGISTRY. Assembled from a binding for the same reason those are.
        let closer = "*/";
        assert!(hides_a_debug_impl_header(&format!(
            "{closer} impl fmt::Debug for NewType {{"
        )));

        // A `Debug` bound is not a hidden header; neither is a whole one.
        assert!(!hides_a_debug_impl_header(
            "impl<T: fmt::Debug> Show for T {"
        ));
        assert!(!hides_a_debug_impl_header(
            "impl fmt::Debug for ProxyAuth {"
        ));
        assert!(!hides_a_debug_impl_header("/// impl fmt::Debug"));

        // The fourth shape, which is not a header at all: rename the trait at the import
        // and every impl of it names something the parser has never heard of. Assembled
        // from a variable rather than written out, for the reason the block comments above
        // are — this file is one of the ones the rule reads.
        let renamed = format!("use std::fmt::Debug {} Shown;", "as");
        assert!(hides_a_debug_impl_header(&renamed));
        assert_eq!(impl_debug_target("impl Shown for ProxyAuth {"), None);
        // An import renaming anything else is not it, and neither is a plain one.
        assert!(!hides_a_debug_impl_header("use std::fmt::Write as _;"));
        assert!(!hides_a_debug_impl_header("use std::fmt::Debug;"));

        assert!(keeps_a_rejected_token("        rejected.push(x);"));
        assert!(keeps_a_rejected_token("self.rejected.push(x);"));
        assert!(keeps_a_rejected_token(
            "skipped.push(format!(\"{k}={v}\"));"
        ));
        assert!(keeps_a_rejected_token("rejected.extend(skipped);"));
        // The fourth spelling the scan looks for, and the one this line alone holds: `src/`
        // has no `skipped.extend(` today, so nothing live exercises that row.
        assert!(keeps_a_rejected_token("skipped.extend(more);"));
        assert!(keeps_a_rejected_token("rejected.push(RejectedValue::new("));
        assert!(!keeps_a_rejected_token("patterns.push(pattern);"));

        // The type is spelled through a variable, not written into each sample, because
        // this file is one of the files the scan reads: a sample carrying the type
        // verbatim would be a declaration the gate then finds in its own test.
        let owned = ": Vec<RejectedValue>,";
        let borrowed = ": &mut Vec<RejectedValue>,";
        assert_eq!(
            rejected_list_binding(&format!("    pub rejected{owned}")),
            Some("rejected")
        );
        assert_eq!(
            rejected_list_binding(&format!("    rejected{borrowed}")),
            Some("rejected")
        );
        // The whole point: a list under another name is still found, and so still has to
        // be a name `keeps_a_rejected_token` looks for.
        assert_eq!(
            rejected_list_binding(&format!("    pub refused{owned}")),
            Some("refused")
        );
        // And that the pairing has teeth: `refused` is exactly a name the masking scan
        // does not look for, so declaring one is what the gate above would refuse.
        assert!(!keeps_a_rejected_token("refused.push(value);"));
        // A return type binds nothing to append to, and prose is not a declaration.
        assert_eq!(
            rejected_list_binding("fn parse() -> (Config, Vec<RejectedValue>) {"),
            None
        );
        assert_eq!(
            rejected_list_binding(&format!("    // rejected{owned} is what this holds")),
            None
        );
    }

    // The derive scan's parser, held to the same standard as the impl scan's above. Its
    // samples are built from `attribute` rather than written out, for the reason given at
    // `rejected_list_binding`'s: a literal `#[derive(…)]` starting a line in this file is
    // one the scan would read as a declaration of whatever follows it here.
    #[test]
    fn the_derive_scanner_reads_the_shapes_this_tree_uses() {
        let attribute = |list: &str| format!("#[derive({list})]");

        assert!(derives_debug(&attribute("Debug")));
        assert!(derives_debug(&format!("    {}", attribute("Clone, Debug"))));
        assert!(derives_debug(&attribute("Debug, Clone, Copy")));
        // A derive that does not print, and prose that mentions one.
        assert!(!derives_debug(&attribute("Clone, PartialEq, Eq")));
        assert!(!derives_debug(&format!("/// {}", attribute("Debug"))));
        // `Debug` has to be a list entry, not a substring of one.
        assert!(!derives_debug(&attribute("DebugCustom")));

        // The shape the scan refuses rather than parses: with `Debug` a line below, the
        // item reaches neither `derives_debug` nor DERIVED, and the gate passes blind.
        let split = "#[derive(";
        assert!(!derives_debug(split));
        assert!(splits_a_derive_attribute(split));
        assert!(splits_a_derive_attribute("#[derive(Clone,"));
        assert!(!splits_a_derive_attribute(&attribute("Debug")));
        assert!(!splits_a_derive_attribute("#[non_exhaustive]"));

        assert_eq!(
            derived_item_name("pub(crate) enum DictValue {"),
            Some("DictValue")
        );
        assert_eq!(derived_item_name("struct WatchedKey {"), Some("WatchedKey"));
        assert_eq!(
            derived_item_name("pub struct Wrapper(String);"),
            Some("Wrapper")
        );
        assert_eq!(derived_item_name("pub enum Kind<'a> {"), Some("Kind"));
        assert_eq!(derived_item_name("pub struct Unit;"), Some("Unit"));
        assert_eq!(derived_item_name("impl Debug for Thing {"), None);
        // A keyword with nothing nameable after it. No compiling file holds this line, so
        // this assertion is the only thing keeping the guard. `None` is what the caller's
        // panic is written for; an empty name — `Some(&name[..0])` — would instead be carried
        // into the comparison against DERIVED, where it reads as a declared item gone missing
        // rather than as a line the scan cannot parse.
        assert_eq!(derived_item_name("enum {"), None);

        let none = BTreeSet::new();
        assert!(names_a_text_type("    value: Option<String>,", &none));
        assert!(names_a_text_type(
            "    entries: HashMap<String, GValue>,",
            &none
        ));
        assert!(names_a_text_type("    path: &'static str,", &none));
        // The carriers whose text lives in another crate, so nothing here can follow a
        // field type down to the `String` inside it. `url::Url` is the one that holds a
        // password: without this row a derive over such a field goes unseen, while `url`'s
        // `Debug` prints the userinfo whole.
        assert!(names_a_text_type("    url: Url,", &none));
        assert!(names_a_text_type("    host: Host,", &none));
        // The rest of the same list. Nothing in `src/` holds one of these under a derive
        // today, so these five lines are the only thing holding them. They are defensive in
        // exactly the way `Url` above is, and a defensive entry nothing checks is the one a
        // tidy-up deletes.
        assert!(names_a_text_type("    a: OsString,", &none));
        assert!(names_a_text_type("    b: &OsStr,", &none));
        assert!(names_a_text_type("    c: PathBuf,", &none));
        assert!(names_a_text_type("    d: &Path,", &none));
        // `Cow` is the one that has to be sampled generically: every ordinary spelling names
        // its element as well (`Cow<'_, str>`, `Cow<'_, Path>`) and would be caught by that
        // word instead, so a `Cow` over a type parameter is the only field for which the
        // entry itself is what does the work.
        assert!(names_a_text_type("    e: Cow<'a, T>,", &none));
        assert!(!names_a_text_type("    port: Option<u16>,", &none));
        // Prose naming a text type is not a field holding one — the field scan reads whole
        // item bodies, doc comments included.
        assert!(!names_a_text_type("    /// The host as a String.", &none));

        // The carrier this crate could name itself. The field is the same line in both
        // rows and is text in exactly one of them, which is the whole difference an alias
        // makes to a scan that reads names — and it is `text_carrier_aliases`, not the
        // field, that has to supply it.
        let field = "    credential: CredentialText,";
        assert!(!names_a_text_type(field, &none));
        let declaration = "type CredentialText = String;";
        let aliases = text_carrier_aliases(&[(String::from("new.rs"), declaration.to_string())]);
        assert!(names_a_text_type(field, &aliases));
        // An alias that carries no text is not collected, and neither is prose about one.
        assert!(
            text_carrier_aliases(&[(
                String::from("new.rs"),
                format!("type Port = u16;\n// {declaration}\n")
            )])
            .is_empty()
        );

        // Exported the same way, and in the two files the order argues about: the chain is
        // declared before the alias it rests on, so one pass over them reads `Outer` while
        // `Inner` is still unknown and stops there.
        let chain = text_carrier_aliases(&[
            (
                String::from("outer.rs"),
                String::from("pub type Outer = Inner;"),
            ),
            (
                String::from("inner.rs"),
                String::from("pub(crate) type Inner = String;"),
            ),
        ]);
        assert!(names_a_text_type("    a: Inner,", &chain));
        assert!(names_a_text_type("    b: Outer,", &chain));

        // Braced, tuple and unit items all have to terminate, and a doc comment carrying an
        // unbalanced brace must not make one run past its end.
        assert_eq!(
            item_body(&[
                "struct A {",
                "    /// takes a `{`",
                "    a: u8,",
                "}",
                "next"
            ])
            .len(),
            4
        );
        assert_eq!(item_body(&["struct B(String);", "next"]).len(), 1);
        assert_eq!(item_body(&["struct C;", "next"]).len(), 1);
        assert_eq!(
            item_body(&["struct D(", "    String,", ");", "next"]).len(),
            3
        );

        assert!(stands_between_a_derive_and_its_item("#[non_exhaustive]"));
        assert!(stands_between_a_derive_and_its_item("// a note"));
        assert!(stands_between_a_derive_and_its_item("   "));
        assert!(!stands_between_a_derive_and_its_item("pub struct E {"));
    }
}
