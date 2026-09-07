//! Gate: a comment that names an external project must land the reader on a
//! specific document — a URL, an RFC or CVE number, a path with an extension, or a
//! backticked API name.
//!
//! This is a check on the repository, not on the library, so it lives in the `xtask`
//! package rather than the library's own `tests/`, and reaches no consumer either way.
//! `src/debug_masking.rs` is the one gate that belongs in `src/`, because it
//! exercises private types by value. Placing a tree-scanning gate in `src/` ships
//! it to every consumer and constrains it to reading `src/`; here neither applies.
//!
//! Landing keys (any one in the same blank-line-delimited comment paragraph):
//! URL, `RFC`+digits, `CVE-…`, a path with a source/doc extension, or a backticked
//! API / symbol name. Project names with none of those fail the gate.
//!
//! [`no_comment_names_a_document_the_published_tree_leaves_behind`] rules out the one landing
//! key that is dead on arrival: a `docs/` path, which neither published form carries.

use std::fs;
use std::path::{Path, PathBuf};

// Browsers and reference implementations only. The vendors this crate is written against —
// Microsoft, Apple, GLib — stay out until after the first release: the paragraphs that would
// fail on them sit under the private `sys` module, which docs.rs does not render, so the scan
// would guard landings no consumer can reach.
//
// An engine belongs here for the same reason its browser does: `src/pac/mod.rs` cites Gecko
// where it means the Firefox behaviour. `Blink` and `Go` are the exception, because the match
// is token-wise and case-insensitive: they fire on a cursor that blinks and on traffic that
// goes direct. Adding `Go` catches two real paragraphs against eight of that kind, so the two
// carry their own landings (`config.init`, `http/httpproxy/proxy.go`) instead.
const PROJECTS: &[&str] = &[
    "Chromium", "WebKit", "curl", "libproxy", "Firefox", "Mozilla", "Chrome", "Gecko",
];

// No exemption table. A paragraph that names a project and lands nowhere is repaired by
// adding the landing; a name with no landing to add belongs outside [`PROJECTS`], with the
// reason beside it, because a per-paragraph escape hatch takes the next paragraph too.

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives directly under the repository root")
        .to_path_buf()
}

fn src_root() -> PathBuf {
    repo_root().join("src")
}

// The rest of what `Cargo.toml`'s `include` ships (`/examples/*.rs` alongside
// `/src/**/*.rs`). The module doc above says a tree-scanning gate placed here is not
// constrained to reading `src/`; this is that freedom being used. Paths reported with no
// directory in them are under `src/`.
fn examples_root() -> PathBuf {
    repo_root().join("examples")
}

// Line comments only, and one test of them: `///` and `//!` already start with `//`, so
// naming them separately reads as three checks while being one. Block comments are out of
// reach by construction — this tree writes none, and a `/* Chromium … */` would go unread.
fn is_comment_line(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

fn strip_comment(line: &str) -> &str {
    let t = line.trim_start();
    t.strip_prefix("///")
        .or_else(|| t.strip_prefix("//!"))
        .or_else(|| t.strip_prefix("//"))
        .unwrap_or(t)
}

// Case-insensitively, for the same reason the `RFC` key below is: the gate is about which
// paragraphs name an outside project, and English capitalises the first word of a sentence.
// `curl` is listed in its own lowercase spelling, so a sentence opening with `Curl` would
// otherwise be the one paragraph shape that names a project and is never asked to land.
fn has_project_name(text: &str) -> Option<&'static str> {
    PROJECTS.iter().copied().find(|name| {
        text.split(|c: char| !c.is_ascii_alphanumeric())
            .any(|tok| tok.eq_ignore_ascii_case(name))
    })
}

fn has_landing(text: &str) -> bool {
    if text.contains("https://") || text.contains("http://") {
        return true;
    }
    if text.contains("CVE-") {
        return true;
    }
    if has_rfc_number(text) {
        return true;
    }
    // path with a recognisable extension
    for ext in [
        ".cc", ".cpp", ".c", ".h", ".hpp", ".rs", ".md", ".html", ".js", ".txt", ".toml",
    ] {
        if let Some(idx) = text.find(ext) {
            let before = &text[..idx];
            if before
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.'))
                .count()
                > 0
            {
                return true;
            }
        }
    }
    // backticked API / symbol: `Foo::Bar`, `kMaxRetry`, `GetDefaultPortForScheme`
    let mut rest = text;
    while let Some(start) = rest.find('`') {
        let after = &rest[start + 1..];
        if let Some(end) = after.find('`') {
            let inner = &after[..end];
            if looks_like_symbol(inner) {
                return true;
            }
            rest = &after[end + 1..];
        } else {
            break;
        }
    }
    false
}

// `RFC 6455` / `RFC6455`: a number that identifies a document a reader can go and open.
//
// The number has to be the RFC's own, so only what immediately follows the token counts.
// Accepting a digit anywhere later in the paragraph instead would let a sentence that says
// `RFC` without a number land on any unrelated figure that happens to follow it — a year, a
// section count, a port — and the paragraph would never be asked for a real citation.
fn has_rfc_number(text: &str) -> bool {
    // Emphasis is removed rather than turned into a separator, which is the one difference
    // from the sibling gates' normalisation and the reason the one-separator rule below
    // survives it: `**RFC** 6455` becomes `RFC 6455`, not `  RFC   6455`, so a bolded
    // token is exactly as close to its number as an unbolded one. Skipping a single `*`
    // instead would not have been enough — bold is two of them.
    let lower = text.to_ascii_lowercase().replace('*', "");
    let bytes = lower.as_bytes();
    let mut from = 0;
    while let Some(offset) = lower[from..].find("rfc") {
        let start = from + offset;
        from = start + 3;
        if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
            continue;
        }
        // At most one separator between the token and its number. `\n` is one of them
        // because [`scan_file`] joins a comment block's lines with it, and these blocks are
        // wrapped to a column: "RFC" at the end of one line and its number at the start of
        // the next is a citation a reader follows without noticing the break. Reading it as
        // an unnumbered `RFC` would fail the paragraph for missing the landing point it has.
        let at = if matches!(bytes.get(from), Some(b' ' | b'-' | b'_' | b'\n')) {
            from + 1
        } else {
            from
        };
        if bytes.get(at).is_some_and(u8::is_ascii_digit) {
            return true;
        }
    }
    false
}

fn looks_like_symbol(s: &str) -> bool {
    // Strip trailing () from `foo()` call spellings.
    let s = s.trim_end_matches("()");
    if s.is_empty() || s.contains(' ') {
        return false;
    }
    // A run with no letter in it is a value, not a name: `255.255.255.255`, `10.0.0.1` and
    // the abbreviated CIDR `169.254/16` all reach the `contains('.')` rule below and would
    // land a paragraph on nothing. Comments about address handling are exactly where
    // external projects get named, so without this the gate passes the paragraphs it exists
    // to catch. Testing for the *absence* of a letter rather than listing the punctuation a
    // value may contain is what makes `/` — and the next separator — land here too.
    if !s.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    if s.contains("::") || s.contains('.') {
        return true;
    }
    let chars: Vec<char> = s.chars().collect();
    // CamelCase or kConstant
    if chars.iter().any(|c| c.is_ascii_uppercase()) && chars.iter().any(|c| c.is_ascii_lowercase())
    {
        return true;
    }
    if s.starts_with('k') && chars.len() > 1 && chars[1].is_ascii_uppercase() {
        return true;
    }
    // SCREAMING_SNAKE
    if s.contains('_')
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return true;
    }
    // snake_case identifiers (`set_default_proxy`, `fallback_proxies`)
    if s.contains('_')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && s.len() > 3
    {
        return true;
    }
    // hyphenated schema keys (`use-same-proxy`)
    if s.contains('-')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && s.len() > 3
    {
        return true;
    }
    false
}

struct Hit {
    file: String,
    start_line: usize,
    project: &'static str,
    excerpt: String,
}

// Panics rather than returning no hits, because the floor below counts this file as
// scanned whether or not it could be read: [`walk`] pushes the name after the call, not
// inside it. Returning an empty `Vec` here therefore satisfies
// [`the_walk_reaches_the_source_tree`] with a file the gate never looked at, which is
// exactly the confusion that floor exists to prevent — and it makes "every `.rs` file
// actually read", written above `walk`, false.
fn scan_file(path: &Path, rel: &str) -> Vec<Hit> {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("reading {} for the citation walk: {e}", path.display()));
    let lines: Vec<&str> = text.lines().collect();
    let mut hits = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !is_comment_line(lines[i]) {
            i += 1;
            continue;
        }
        let start = i;
        let mut paragraph = String::new();
        while i < lines.len() && is_comment_line(lines[i]) {
            if !paragraph.is_empty() {
                paragraph.push('\n');
            }
            paragraph.push_str(strip_comment(lines[i]).trim());
            i += 1;
            // blank comment line ("//") ends the paragraph
            if i < lines.len()
                && is_comment_line(lines[i])
                && strip_comment(lines[i]).trim().is_empty()
            {
                break;
            }
        }
        if let Some(project) = has_project_name(&paragraph) {
            if has_landing(&paragraph) {
                continue;
            }
            let excerpt: String = paragraph.chars().take(160).collect();
            hits.push(Hit {
                file: rel.to_owned(),
                start_line: start + 1,
                project,
                excerpt,
            });
        }
    }
    hits
}

// `scanned` collects every `.rs` file actually read. Finding no hits is this gate's pass
// state, so a walk that reaches nothing at all passes it too; the scan list is what tells
// those apart, and `the_walk_reaches_the_source_tree` holds it to a floor.
fn walk(dir: &Path, rel_prefix: &str, out: &mut Vec<Hit>, scanned: &mut Vec<String>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {} for the citation walk: {e}", dir.display()));
    let mut paths: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        // `to_string_lossy`, not `to_str().unwrap_or("")`: a name that is not valid
        // Unicode must still be walked and counted, only spelled with U+FFFD in its
        // place — dropping it outright would shrink the scanned population by exactly
        // one file with nothing to show for it, the same silent loss
        // `the_walk_reaches_the_source_tree`'s floor exists to catch.
        let name = path
            .file_name()
            .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
        if path.is_dir() {
            let next = if rel_prefix.is_empty() {
                name
            } else {
                format!("{rel_prefix}/{name}")
            };
            walk(&path, &next, out, scanned);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let rel = if rel_prefix.is_empty() {
                name
            } else {
                format!("{rel_prefix}/{name}")
            };
            out.extend(scan_file(&path, &rel));
            scanned.push(rel);
        }
    }
}

fn all_hits() -> (Vec<Hit>, Vec<String>) {
    let mut hits = Vec::new();
    let mut scanned = Vec::new();
    walk(&src_root(), "", &mut hits, &mut scanned);
    walk(&examples_root(), "examples", &mut hits, &mut scanned);
    (hits, scanned)
}

// Control for the gate below, which reports a clean tree and an unreached one the same
// way. This file has already been relocated once, and `src_root()` is derived from
// `CARGO_MANIFEST_DIR`: another move that left it pointing somewhere without the crate's
// sources would disarm the gate in silence. The sibling gates keep the same kind of
// control: `single_source.rs` and `claim_counts.rs` `expect` on their reads, and
// `unverified_surface.rs` panics on both reads this walk does — the `read_dir` that lists
// a file and the `read_to_string` that opens it. Hardening only the first leaves the
// population shrinkable one file at a time instead of one directory at a time.
#[test]
fn the_walk_reaches_the_source_tree() {
    let (_, scanned) = all_hits();
    assert!(
        scanned.contains(&"lib.rs".to_owned()),
        "the walk never reached src/lib.rs: {scanned:?}"
    );
    assert!(
        scanned.len() > 20,
        "only {} files scanned, so the walk stopped short: {scanned:?}",
        scanned.len()
    );
    // The second root gets its own floor rather than riding on the count above, which
    // `src/` alone already clears — without this, dropping the `examples/` walk would leave
    // every assertion here still passing.
    assert!(
        scanned.contains(&"examples/watch.rs".to_owned()),
        "the walk never reached examples/: {scanned:?}"
    );
}

#[test]
fn every_external_project_name_has_a_landing() {
    let (hits, _) = all_hits();
    if hits.is_empty() {
        return;
    }
    let mut msg = String::from(
        "comment paragraphs name an external project with no landing key \
         (URL / RFC / CVE / path-with-extension / backticked API):\n",
    );
    for h in &hits {
        msg.push_str(&format!(
            "  {}:{}\n    [{}] {}\n",
            h.file, h.start_line, h.project, h.excerpt
        ));
    }
    panic!("{msg}");
}

#[test]
fn gate_catches_a_bare_chromium_mention() {
    // The shape this gate exists for: a project name with nothing to open.
    let para = "Chromium counts a trailing dot as \"has a period\" for simple-hostname exclusion.";
    assert!(has_project_name(para).is_some());
    assert!(!has_landing(para));
    // Same claim with a path lands.
    let landed = "Chromium's `proxy_bypass_rules.cc` counts a trailing dot as \"has a period\".";
    assert!(has_landing(landed));
}

// The two ways a paragraph would otherwise get past the gate without citing anything:
// naming the project in a spelling the list does not hold letter for letter, and saying
// `RFC` with the number belonging to some other figure in the sentence.
#[test]
fn a_name_in_another_case_and_a_numberless_rfc_are_not_ways_out() {
    let sentence_start = "Curl resolves the host itself before consulting the proxy.";
    assert_eq!(has_project_name(sentence_start), Some("curl"));
    assert!(!has_landing(sentence_start));

    assert!(!has_landing(
        "Chromium follows the RFC guidance it has used since 2020."
    ));
    assert!(!has_landing(
        "WebKit reads the RFC the same way, per its 3 rules."
    ));
    // A real citation still lands, spaced or not.
    assert!(has_landing("Chromium follows RFC 6455 here."));
    assert!(has_landing("Chromium follows RFC6455 here."));
    assert!(has_landing("Chromium follows rfc-6455 here."));
    // …and wrapped. [`scan_file`] joins a block's lines with `\n`, so without this a
    // paragraph wide enough to break between the token and its number is told it has no
    // landing point — a failure earned by where the wrap fell rather than by what was said.
    assert!(has_landing("Chromium follows RFC\n6455 here."));
    // The numberless cases stay refused across a break too: a wrap is not a number.
    assert!(!has_landing(
        "Chromium follows the RFC\nguidance it has used since 2020."
    ));
    // Emphasis separates the token from its number the same way a wrap does, and the
    // sibling gate strips `*` for that reason. Leaving it out here makes the same sentence
    // pass or fail on whether its author bolded the token.
    assert!(has_landing("Chromium follows **RFC** 6455 here."));
    assert!(has_landing("Chromium follows *RFC 6455* here."));
    // Stripping emphasis is not a licence to reach further: one separator is still the
    // limit, so a number the token does not own stays out of reach.
    assert!(!has_landing(
        "Chromium follows the **RFC**, which has 3 rules."
    ));
}

// Every `docs/` path in `text` that names a file of the tree at `root`. Asking the filesystem
// rather than matching a prefix keeps an external project's own `docs/` path — Chromium's
// `docs/proxy.md`, curl's `docs/url-syntax.html` — a landing key while this tree's is not.
// `root` is a parameter so the control can build its own tree, the way `doc_pages_under`'s is
// in `single_source.rs`.
fn in_tree_doc_paths(root: &Path, text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(idx) = rest.find("docs/") {
        let tail = &rest[idx..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.')))
            .unwrap_or(tail.len());
        let path = tail[..end].trim_end_matches('.');
        if root.join(path).is_file() {
            found.push(path.to_owned());
        }
        rest = &tail[end..];
    }
    found
}

fn collect_rs(dir: &Path, rel_prefix: &str, out: &mut Vec<(String, PathBuf)>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {} for the landing walk: {e}", dir.display()));
    let mut paths: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
        let rel = format!("{rel_prefix}/{name}");
        if path.is_dir() {
            collect_rs(&path, &rel, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push((rel, path));
        }
    }
}

// Neither published form carries `docs/`. A comment naming a file there sends the only reader
// who has the comment somewhere they cannot go, and the decision the pointer stood in for
// leaves with it; the repair is to say the decision in place, or to name the test that holds
// it. The walk covers every directory that travels, `xtask/` included — a gate names `docs/`
// in its code, which this scan does not read, but its comments reach the same reader.
#[test]
fn no_comment_names_a_document_the_published_tree_leaves_behind() {
    let root = repo_root();
    let mut files = Vec::new();
    for dir in ["src", "examples", "tests", "xtask"] {
        collect_rs(&root.join(dir), dir, &mut files);
    }
    // The same floor `the_walk_reaches_the_source_tree` keeps, for the same reason: an empty
    // report is this gate's pass state, so a walk that reached one root and missed the others
    // passes it in silence.
    for expected in [
        "src/lib.rs",
        "examples/watch.rs",
        "tests/bypass.rs",
        "xtask/tests/citation_landing.rs",
    ] {
        assert!(
            files.iter().any(|(rel, _)| rel == expected),
            "the walk never reached {expected}, so its root went unscanned"
        );
    }

    let mut msg = String::new();
    for (rel, path) in &files {
        let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {rel}: {e}"));
        for (n, line) in text.lines().enumerate() {
            if !is_comment_line(line) {
                continue;
            }
            for target in in_tree_doc_paths(&root, strip_comment(line)) {
                msg.push_str(&format!("  {rel}:{}  ->  {target}\n", n + 1));
            }
        }
    }
    assert!(
        msg.is_empty(),
        "comments name documents the published tree does not carry — write the decision in \
         the comment, or name the test that holds it:\n{msg}"
    );
}

#[test]
fn an_external_docs_path_is_still_a_landing() {
    // The distinction the gate above rests on. Chromium's and curl's own `docs/` paths are
    // not files of this repository, so they stay citations; this tree's are not.
    let root = repo_root();
    assert!(in_tree_doc_paths(&root, "Chromium's `docs/proxy.md` describes the flow.").is_empty());
    assert!(in_tree_doc_paths(&root, "curl documents this in `docs/url-syntax.html`.").is_empty());
    assert!(has_landing(
        "Chromium's `docs/proxy.md` describes the flow."
    ));

    // The finding arm, against a tree built for it. Naming a real page here would tie the
    // control to one filename in the directory this whole gate treats as disposable, so a
    // rename would report the gate broken and say nothing about the gate.
    let fixture = std::env::temp_dir().join(format!("proxy-watch-landing-{}", std::process::id()));
    fs::create_dir_all(fixture.join("docs")).expect("the temporary tree is creatable");
    fs::write(fixture.join("docs").join("NOTE.md"), "x").expect("the note is writable");
    assert_eq!(
        in_tree_doc_paths(&fixture, "The rule is in `docs/NOTE.md`."),
        vec!["docs/NOTE.md".to_owned()]
    );
    // …and the same fixture still refuses a path it does not carry, so "finds it" is about
    // the file being there and not about the text saying `docs/`.
    assert!(in_tree_doc_paths(&fixture, "See `docs/ABSENT.md` for the rule.").is_empty());
    fs::remove_dir_all(&fixture).ok();
}

#[test]
fn a_backticked_address_is_not_a_landing() {
    // The shape this catches in `pac/hostfn.rs`: a claim about a reference implementation whose
    // only backticked run is the address it is about. `contains('.')` reads that as a
    // qualified name, so the paragraphs most likely to name a browser are the ones such a
    // rule waves through.
    // `169.254/16` is the shape a rule written the other way misses: listing the
    // punctuation a value may contain (`.`) instead of asking whether the run has a letter
    // in it leaves a `/` enough to make an address read as a qualified name.
    for value in [
        "255.255.255.255",
        "10.0.0.1",
        "1.2",
        "0.0.0.0",
        "169.254/16",
    ] {
        assert!(!looks_like_symbol(value), "{value} is a value, not a name");
    }
    let para = "`255.255.255.255` is `-1` in Firefox.";
    assert!(has_project_name(para).is_some());
    assert!(!has_landing(para));
    // A name that merely contains digits and dots still lands.
    assert!(looks_like_symbol("net.IP.Equal"));
    assert!(looks_like_symbol("nsIURI::GetAsciiHost"));
}
