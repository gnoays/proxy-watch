//! Gate: a comment that admits a surface is unverified must say what could break and
//! how a reader would notice.
//!
//! Like `xtask/tests/citation_landing.rs`, this checks the repository rather than the
//! library, so it lives in the `xtask` package and reaches no consumer. What it scans does:
//! the admissions that matter are the ones a consumer reads, and `Cargo.toml`'s `include`
//! puts `/src/**/*.rs` and `/examples/*.rs` in the `.crate` — so both are walked. The
//! delegation target and the reader-visibility check below stay `src/`-rooted, because a
//! declaration lives in a module and `examples/` generates no module page; a path with no
//! directory in it is therefore under `src/`.
//!
//! An admission is any of [`PHRASES`] appearing in a comment block (a maximal run of
//! consecutive comment lines, blank `//!` lines included — a module doc is one block).
//! Each such block must either
//!
//! * **declare**: carry `Unverified:` + `Risk:` + `Symptom:`, each followed by at least
//!   [`MIN_FIELD`] characters of prose; or
//! * **delegate**: name a `src/…​.rs` path that exists and itself declares.
//!
//! Why those three fields and not a free-text warning: "this is untested" tells a reader
//! nothing they can act on. `Risk` names the failure, `Symptom` names what they would
//! see — together they turn an admission into something a user can recognise in the
//! field and a maintainer can later write a test against.
//!
//! Both checks above ask only whether a declaration is *in* `src/`. The last one asks
//! whether it *arrives*: docs.rs builds without `--document-private-items`, so a module
//! behind a non-`pub` `mod` generates no page and its `//!` is as far from a consumer as
//! anything under `docs/`. Every declaring surface here is such a module, which is why
//! the rule is that a page the reader does see must name it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

// The vocabulary that counts as admitting a surface is unverified. Matched
// case-insensitively as a substring, so "Not verified" and "not verified" both hit.
const PHRASES: &[&str] = &[
    "unverified",
    "not verified",
    "never verified",
    "cannot be verified",
    "ci-verified only",
    "ci only",
    "untested",
    "not exercised",
    "never been run",
    "no macos dev machine",
    "no hardware",
];

// The three fields a declaration must carry, in the spelling the gate looks for.
const FIELDS: [&str; 3] = ["Unverified:", "Risk:", "Symptom:"];

// The shortest prose that counts as filling a field. Long enough that `Risk: unknown`
// does not pass, short enough not to reward padding.
const MIN_FIELD: usize = 24;

// Files that must still carry a declaration. Each is a surface this crate has admitted
// it cannot verify; if one is ever genuinely verified, the entry comes out of this list
// in the same commit as the admission it replaces — never on its own.
//
// Not every declaring block in the tree: `src/sys/win/ffi.rs`'s `#[cfg(test)] mod tests`
// declares one too, and is deliberately absent. This list is what
// `every_declared_surface_reaches_a_page_a_reader_sees` walks, and a `cfg(test)` module
// is not in any build a reader has — not docs.rs, not `--document-private-items`, not the
// `.crate` a consumer compiles. Demanding that `docs/` name it would be demanding a
// warning about something the reader cannot reach, which is the opposite of the rule's
// purpose. The tree-walking check above still holds it to the three fields, so the
// admission is not unpoliced — only its arrival is out of scope.
const DECLARED_SURFACES: &[&str] = &[
    "sys/mac/mod.rs",
    "sys/linux/portal.rs",
    "sys/linux/sandbox.rs",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives directly under the repository root")
        .to_path_buf()
}

fn src_root() -> PathBuf {
    repo_root().join("src")
}

// The other half of what `Cargo.toml`'s `include` ships. Walked by the tree check and by
// nothing else here: `examples/` is compiled, not rendered, so an admission in one reaches
// a reader who opens the file rather than one who opens a page.
fn examples_root() -> PathBuf {
    repo_root().join("examples")
}

// Line comments only. A block comment, or a `//` that starts partway along a line of code,
// is not read. The tree writes no block comments, but it does write mid-line ones (`mod
// debug_masking; // hand-written Debug gate`) — none carrying a phrase today, and one that
// did would pass this gate unexamined.
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

// Line breaks and Markdown emphasis are removed before matching, the same normalisation
// [`field_body`] does. These blocks are wrapped to a column, so a two-word phrase lands
// across a break about as often as not, and matching the text as written let an admission
// through on nothing but where the wrap happened to fall — `src/sys/win/ffi.rs` carried
// "is not / exercised end to end here" past this gate for as long as the gate has existed.
// Emphasis splits a phrase the same way and for the same reason: this tree writes a bolded
// word mid-sentence (`**both** stores`, `src/sys/linux/backend.rs`), so "**not** verified"
// is a form a writer reaches for, and it reads as the admission it is.
fn admits_being_unverified(block: &str) -> Option<&'static str> {
    let lower = block.to_ascii_lowercase();
    let flat = lower
        .replace(['*', '\n'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    PHRASES.iter().copied().find(|p| flat.contains(p))
}

// Whether `block` carries all three fields, each with real prose behind it.
fn declares(block: &str) -> bool {
    FIELDS
        .iter()
        .all(|field| field_body(block, field).is_some())
}

// The prose behind one field: everything from the field marker up to the next field
// marker (or the end of the block), with Markdown emphasis and comment noise removed.
fn field_body(block: &str, field: &str) -> Option<String> {
    let start = block.find(field)? + field.len();
    let rest = &block[start..];
    let end = FIELDS
        .iter()
        .filter(|other| **other != field)
        .filter_map(|other| rest.find(other))
        .min()
        .unwrap_or(rest.len());
    let body: String = rest[..end]
        .replace(['*', '\n'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (body.chars().count() >= MIN_FIELD).then_some(body)
}

// Every `src/…​.rs` path named in `block`, as a path relative to `src/`.
fn delegations(block: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = block;
    while let Some(idx) = rest.find("src/") {
        let after = &rest[idx + "src/".len()..];
        let path: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.'))
            .collect();
        if path.ends_with(".rs") {
            out.push(path.clone());
        }
        // The path is all ASCII by construction, so its byte length is the prefix length
        // to skip. When it is empty the skip is instead the one character that stopped
        // the scan, and that character need not be one byte: `src/…` is a form the
        // failure message of `every_unverified_admission_declares_risk_and_symptom` tells
        // a maintainer to write, and a fixed skip of 1 sliced into the middle of it.
        let skip = if path.is_empty() {
            after.chars().next().map_or(0, char::len_utf8)
        } else {
            path.len()
        };
        if skip == 0 {
            break;
        }
        rest = &after[skip..];
    }
    out
}

// Whether *every* path named in `block` exists under `src/` and declares. One declaring
// neighbour must not vouch for the files named alongside it: that is how a block comes to
// point at a row of modules where only the first of them says anything.
fn delegates(block: &str) -> bool {
    let named = delegations(block);
    !named.is_empty()
        && named.iter().all(|rel| {
            fs::read_to_string(src_root().join(rel))
                .is_ok_and(|text| blocks(&text).iter().any(|(_, block)| declares(block)))
        })
}

// Split a file into (1-based start line, block text) pairs.
fn blocks(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !is_comment_line(lines[i]) {
            i += 1;
            continue;
        }
        let start = i;
        let mut block = String::new();
        while i < lines.len() && is_comment_line(lines[i]) {
            block.push_str(strip_comment(lines[i]).trim());
            block.push('\n');
            i += 1;
        }
        out.push((start + 1, block));
    }
    out
}

// The module files rustdoc renders a page for, as paths relative to `src/`.
//
// The walk follows `pub mod` and nothing else, because that is what decides whether a
// page exists: docs.rs builds `--all-features` (per `[package.metadata.docs.rs]`) but
// not `--document-private-items`, so a `mod` that is not `pub` takes its whole subtree
// off the rendered surface. `#[cfg]` above a `pub mod` is ignored here for the same
// reason — all features are on in the build this models.
//
// Scope: module documentation. An item re-exported out of a private module does get a
// page of its own, so a `///` on such an item reaches a reader even though this function
// does not list the file it lives in. Every surface in [`DECLARED_SURFACES`] declares in
// its `//!`, and nothing under `src/sys/` is re-exported, so the distinction does not
// arise today; it would need handling before this gate covered `///` declarations.
fn reader_visible_files() -> BTreeSet<String> {
    let mut visible = BTreeSet::new();
    let mut pending = vec!["lib.rs".to_owned()];

    while let Some(rel) = pending.pop() {
        if !visible.insert(rel.clone()) {
            continue;
        }
        let Ok(text) = fs::read_to_string(src_root().join(&rel)) else {
            continue;
        };
        // `a/b/mod.rs` and `a/b.rs` both hold module `a::b`; children resolve against
        // the directory the file's own children live in.
        let dir = match rel.strip_suffix("/mod.rs") {
            Some(parent) => parent.to_owned(),
            None => rel.trim_end_matches(".rs").to_owned(),
        };
        let dir = if rel == "lib.rs" { String::new() } else { dir };
        for child in pub_mod_children(&text) {
            let stem = if dir.is_empty() {
                child
            } else {
                format!("{dir}/{child}")
            };
            let flat = format!("{stem}.rs");
            let nested = format!("{stem}/mod.rs");
            pending.push(if src_root().join(&nested).is_file() {
                nested
            } else {
                flat
            });
        }
    }
    visible
}

// The names declared `pub mod <name>;` in one file.
fn pub_mod_children(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("pub mod ")?;
            let name = rest.strip_suffix(';').or_else(|| rest.strip_suffix(" {"))?;
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                .then(|| name.to_owned())
        })
        .collect()
}

struct Hit {
    file: String,
    start_line: usize,
    phrase: &'static str,
    excerpt: String,
}

// The same silence one level down from [`walk`], and the argument written there applies to
// it unchanged: a `.rs` file that cannot be read yields no hits, and no hits is this gate's
// pass state, so the population shrinks and the gate still reports clean. The walk reaches
// this file either way — it is `read_dir` that lists it and `read_to_string` that fails —
// so nothing downstream can tell a file that held no admission from one that was never
// looked at. Hardening the directory and not the file leaves the same hole a directory
// narrower.
fn scan_file(path: &Path, rel: &str) -> Vec<Hit> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "reading {} for the unverified-surface walk: {e}",
            path.display()
        )
    });
    let mut hits = Vec::new();
    for (start_line, block) in blocks(&text) {
        let Some(phrase) = admits_being_unverified(&block) else {
            continue;
        };
        if declares(&block) || delegates(&block) {
            continue;
        }
        hits.push(Hit {
            file: rel.to_owned(),
            start_line,
            phrase,
            excerpt: block.chars().take(200).collect(),
        });
    }
    hits
}

// Finding no hits is this gate's pass state, so a directory that cannot be read must not
// be skipped in silence: it would subtract files from the population and the gate would
// still report clean. `citation_landing.rs` keeps the same control on the same walk, and
// says so where it does.
//
// `scanned` is the other half of that control, and the reason it exists here too. An
// unreadable directory panics, but a *root that is never walked* does not — and with
// `examples/` added as a second root, "the call was dropped" became a way for the
// population to shrink while every assertion still passed.
// [`the_known_unverified_surfaces_still_declare`] cannot see that: it reads its files by
// name rather than through this walk, so it holds `src_root()` honest and says nothing
// about the second root.
fn walk(dir: &Path, rel_prefix: &str, out: &mut Vec<Hit>, scanned: &mut Vec<String>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| {
        panic!(
            "reading {} for the unverified-surface walk: {e}",
            dir.display()
        )
    });
    let mut paths: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        // `to_string_lossy`, not `to_str().unwrap_or("")`: a name that is not valid
        // Unicode must still be walked and counted, only spelled with U+FFFD in its
        // place. Dropping it outright is exactly the one-file-at-a-time population
        // shrink this function's own doc comment above says must not happen in silence.
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
            // After the scan, not before: `scan_file` panics on an unreadable file, so a
            // path counted here is one that was actually read.
            scanned.push(rel);
        }
    }
}

#[test]
fn every_unverified_admission_declares_risk_and_symptom() {
    let mut hits = Vec::new();
    let mut scanned = Vec::new();
    walk(&src_root(), "", &mut hits, &mut scanned);
    walk(&examples_root(), "examples", &mut hits, &mut scanned);

    // Both roots, each named, before any verdict: this gate passes by finding nothing, so a
    // root that contributed no files is indistinguishable from a clean one.
    for expected in ["lib.rs", "examples/watch.rs"] {
        assert!(
            scanned.contains(&expected.to_owned()),
            "the walk never reached {expected}, so the population it reports clean is not \
             the one this gate is for: {scanned:?}"
        );
    }

    if hits.is_empty() {
        return;
    }
    let mut msg = String::from(
        "comment blocks admit a surface is unverified without saying what breaks and how \
         a reader would notice. Add `Unverified:` / `Risk:` / `Symptom:` to the block, or \
         name the `src/….rs` that carries them:\n",
    );
    for h in &hits {
        msg.push_str(&format!(
            "  {}:{}\n    [{}] {}\n",
            h.file, h.start_line, h.phrase, h.excerpt
        ));
    }
    panic!("{msg}");
}

// A declaration that has been quietly deleted is indistinguishable, to the gate above,
// from a surface that was never admitted to be unverified — so the list is checked
// directly rather than left to the scan.
#[test]
fn the_known_unverified_surfaces_still_declare() {
    for rel in DECLARED_SURFACES {
        let path = src_root().join(rel);
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
        let declared = blocks(&text).iter().any(|(_, block)| declares(block));
        assert!(
            declared,
            "{rel} no longer carries an Unverified/Risk/Symptom declaration. If the \
             surface is now genuinely verified, drop it from DECLARED_SURFACES in the \
             same commit; if not, put the declaration back"
        );
    }
}

// Being in `src/` is not being read. Everything checked above is satisfied by a
// declaration sitting in a module docs.rs never renders a page for, which is where all of
// [`DECLARED_SURFACES`] sit — so each one has to be named from a page a reader does
// reach, in a block that itself declares. That reverses the direction of `delegates`:
// there, a visible block borrows a hidden file's declaration; here, a hidden file needs a
// visible block to carry it.
#[test]
fn every_declared_surface_reaches_a_page_a_reader_sees() {
    let visible = reader_visible_files();
    let carriers: Vec<String> = visible
        .iter()
        .flat_map(|rel| {
            let text = fs::read_to_string(src_root().join(rel)).unwrap_or_default();
            blocks(&text)
                .into_iter()
                .filter(|(_, block)| declares(block))
                .flat_map(|(_, block)| delegations(&block))
                .collect::<Vec<_>>()
        })
        .collect();

    for rel in DECLARED_SURFACES {
        assert!(
            visible.contains(*rel) || carriers.iter().any(|named| named == rel),
            "src/{rel} declares, but no page docs.rs renders names it: the module is \
             behind a private `mod`, so a consumer never sees the declaration. Name it \
             from a declaring block in one of {visible:?}, or make the module `pub`"
        );
    }
}

// The reach walk has to stop where rustdoc stops. If it ever returned the whole tree,
// the test above would pass for every surface at once and say nothing.
#[test]
fn the_reach_walk_follows_pub_mod_only() {
    let visible = reader_visible_files();
    assert!(visible.contains("lib.rs"));
    // `pub mod pac;` / `pub mod parse;` — reachable, and `pac` resolves through `mod.rs`.
    assert!(visible.contains("pac/mod.rs"), "{visible:?}");
    assert!(visible.contains("parse.rs"), "{visible:?}");
    // `mod sys;` is private, so nothing under it is rendered — including its own
    // `pub(crate) mod` children, which are not `pub`.
    assert!(!visible.contains("sys/mod.rs"), "{visible:?}");
    assert!(!visible.contains("sys/mac/mod.rs"), "{visible:?}");
    // A private `mod` inside a public one still stops the walk.
    assert!(!visible.contains("pac/policy.rs"), "{visible:?}");

    assert_eq!(
        pub_mod_children("mod a;\npub mod b;\npub(crate) mod c;\n    pub mod d;\n"),
        ["b", "d"]
    );
}

#[test]
fn gate_catches_a_bare_admission() {
    // The shape this gate exists to reject: honest, and useless to a reader.
    let bare = "**⚠ Unverified** on a real Flatpak/Snap.\n";
    assert!(admits_being_unverified(bare).is_some());
    assert!(!declares(bare));
    assert!(!delegates(bare));

    // The same admission, declared.
    let declared = "Unverified: no Flatpak or Snap runtime has ever run this path.\n\
                    Risk: the sandbox probe reads a synthetic file only, so a real \
                    runtime could take the GSettings path and report Direct.\n\
                    Symptom: inside Flatpak the crate reports no proxy while the host \
                    clearly has one, and no error is published.\n";
    assert!(declares(declared));

    // Padding does not pass.
    let padded = "Unverified: everything here.\nRisk: unknown.\nSymptom: none.\n";
    assert!(!declares(padded));
}

#[test]
fn a_phrase_split_across_a_line_break_is_still_an_admission() {
    // How this gate actually failed: comment blocks are wrapped to a column, so the
    // phrase falls across the break whenever the words land either side of it, and the
    // block reads identically to a reader. `src/sys/win/ffi.rs` sat on the wrong side of
    // that coin flip and went unexamined until an unrelated rewrap moved it.
    let wrapped = "The race it reacts to is not\nexercised end to end here.\n";
    assert_eq!(admits_being_unverified(wrapped), Some("not exercised"));
    // The same words on one line were caught all along; both must behave alike.
    assert_eq!(
        admits_being_unverified("The race it reacts to is not exercised end to end here.\n"),
        Some("not exercised")
    );
    // Emphasis splits a phrase the same way a wrap does, and the first repair here fixed
    // only the wrap: `field_body` had been stripping `*` since before either, so the file
    // disagreed with itself about whether a bolded word is part of its sentence.
    assert_eq!(
        admits_being_unverified("The race it reacts to is **not** exercised here.\n"),
        Some("not exercised")
    );
    assert_eq!(
        admits_being_unverified("The race it reacts to is **not**\nexercised here.\n"),
        Some("not exercised")
    );
}

#[test]
fn a_delegation_must_name_a_file_that_declares() {
    assert_eq!(
        delegations("macOS is CI-verified only (`src/sys/mac/mod.rs`).\n"),
        vec!["sys/mac/mod.rs".to_owned()]
    );
    // A path that does not exist cannot be delegated to.
    assert!(!delegates("CI only — see `src/sys/mac/no_such_file.rs`.\n"));

    // One declaring file does not vouch for the file named next to it. `src/sys/mod.rs`
    // exists and carries no declaration, so the second block fails where the first passes
    // — the difference is the whole point of checking every named path rather than any.
    assert!(delegates("CI only — see `src/sys/mac/mod.rs`.\n"));
    assert!(!delegates(
        "CI only — see `src/sys/mac/mod.rs` and `src/sys/mod.rs`.\n"
    ));
}

#[test]
fn a_delegation_written_the_way_this_gate_asks_for_it_is_read() {
    // `every_unverified_admission_declares_risk_and_symptom` tells a maintainer to "name
    // the `src/….rs` that carries them". Left as written — which is what copying the
    // instruction produces — the scan stepped one byte past a `src/` it could not read a
    // path from, and one byte is inside `…`.
    assert!(delegations("name the `src/….rs` that carries them").is_empty());
    // Which mattered beyond the panic itself: the step is how the scan reaches the rest
    // of the block, so a real delegation standing after one of these was never seen.
    assert_eq!(
        delegations("CI only — see `src/…` and `src/sys/mac/mod.rs`.\n"),
        vec!["sys/mac/mod.rs".to_owned()]
    );
}
