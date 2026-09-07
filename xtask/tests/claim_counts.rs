//! Gate: every numeral+noun claim in `src/` prose the scanner reaches must have a row
//! here, and every row is recounted against the tree. It is not every such claim in the
//! tree, and the difference is deliberate rather
//! than unmeasured: [`the_scanner_reads_the_shapes_this_tree_uses`] pins each shape the
//! scanner does and does not read. It declines in four ways, and none is enumerable —
//! a scanner cannot list the sentences it declines to read.
//!
//! By distance: a numeral two words from its noun — `Fourteen PAC host functions` — is out
//! of reach, and a rule loose enough to take it starts attaching numerals to the wrong noun
//! entirely. Reword the sentence to sit inside what the scanner reads rather than widening
//! the rule; that is the preferred repair for every silence below.
//!
//! By noun: [`NOUNS`] is a closed list, so a numeral quantifying anything outside it is
//! unread however close its noun sits — "the three switches" (`src/bypass.rs`), "the two
//! references" (`src/pac/hostfn.rs`, `src/pac/result.rs`, `src/sys/proxy_dict.rs`), "the
//! same two keys" (`src/debug_masking.rs`). This is the largest of the silences.
//! Widening [`NOUNS`] buys rows one word at a time, not coverage of a known set, which is why
//! the list stays at the entities a wrong number would actually mislead a reader about.
//!
//! By line break: [`scan`] reads one line at a time, so a numeral that ends a line is
//! never joined to a noun that begins the next. The sibling gates concatenate a comment
//! block before matching and this one deliberately does not — [`REGISTRY`] rows find their
//! sentence by `anchor`, a substring of the line the numeral sits on, and joining a block
//! would let a row match an anchor belonging to a different claim in the same paragraph.
//! Trading a silent miss for a silent mismatch is not a repair. The shape has no instance
//! in the tree today: every comment line under `src/` ending in a numeral is followed by a
//! word outside [`NOUNS`]. Rewrap the sentence if one appears.
//!
//! By spelling: [`NUMERALS`] holds number words, so a numeral written in digits is not
//! looked for at all. Widening it to digits closes less than it looks like it closes: what
//! sits in this silence quantifies units rather than entities this tree can recount — "~11
//! orders of magnitude" is the shape — so no row here could exist for one anyway, and
//! widening [`NOUNS`] to units buys back the excuses that list is closed to keep out. No
//! digit stands in front of a [`NOUNS`] word anywhere under `src/` today, so this silence
//! holds none of the claims the gate is for.
//!
//! Every registered numeral is recounted against the tree; no verdict excuses one, and no
//! such verdict should be added. A verdict for a number counting something outside the
//! tree, or for a sentence that lists its own items, is a place to park a number no test
//! reads: a numeral the tree cannot recount is a sentence to reword, and a numeral whose
//! items are named beside it does not need the numeral. Markdown / `README.md` are out of
//! scope because the README states no numeral this scanner recognises, so reaching into it
//! would add a scan that is true by construction.
//!
//! `tests/` is out of scope too. A claim a test file makes about its own tests is prose
//! that is not in the `.crate`, is not on docs.rs, and is read by nobody who is not already
//! editing the file — upkeep with no reader on the other end. What stays in scope is the
//! surface a consumer can actually read a wrong number off.
//!
//! This is a check on the development tree, not on the library, so it lives in the `xtask`
//! package rather than the library's own `tests/`. Do not move it back:
//! [`the_exclusion_of_tests_still_excludes_something`] walks `tests/` off the manifest
//! directory, and a copy shipped inside the `.crate` would find that directory absent.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

// `both` ≡ 2; same drift failure mode as the number words.
const NUMERALS: &[(&str, usize)] = &[
    ("both", 2),
    ("two", 2),
    ("three", 3),
    ("four", 4),
    ("five", 5),
    ("six", 6),
    ("seven", 7),
    ("eight", 8),
    ("nine", 9),
    ("ten", 10),
    // Past ten a numeral stops being a number a reader recounts at a glance, which is
    // exactly when the gate starts earning its keep — and exactly where a table written
    // for the numbers a reader checks anyway would stop, leaving `src/pac/boa.rs`'s
    // `the fourteen host functions` unreadable and so unregistered.
    ("eleven", 11),
    ("twelve", 12),
    ("thirteen", 13),
    ("fourteen", 14),
    ("fifteen", 15),
    ("sixteen", 16),
    ("seventeen", 17),
    ("eighteen", 18),
    ("nineteen", 19),
    ("twenty", 20),
];

// Countable nouns only — vague ones ("ways", "cases") produced excuses, not checks.
const NOUNS: &[&str] = &[
    "callers",
    "call sites",
    "constructors",
    "tests",
    "variants",
    "arms",
    "backends",
    "modules",
    "functions",
    "methods",
    "fields",
    "impls",
];

// Nothing here walks `xtask/`, so this gate cannot answer for itself and does not name its
// own path among the scanned ones. Do not add that name back without first making the walk
// reach this directory: `the_exclusion_of_tests_still_excludes_something` would then be
// counting this file's own quoted sentences when it decides whether the exclusion did any
// work.

enum Scope {
    // `src/**/*.rs`, each file truncated at its `#[cfg(test)]` module.
    SrcOutsideTests,
    // Whole file (claims about a test file's own tests).
    File(&'static str),
}

// One numeral, identified by the line it sits on rather than by a line number, which every
// edit above it would invalidate.
//
// A row is a promise that the tree can be recounted for this numeral. There is no way to
// register one and skip the recount; the verdicts that allowed that are gone.
struct Claim {
    // Repo-relative, forward slashes.
    file: &'static str,
    // A substring that picks this line out of the file. Must be unique within the file.
    anchor: &'static str,
    // Which noun of [`NOUNS`] the numeral quantifies — a line may carry more than one.
    noun: &'static str,
    scope: Scope,
    // `needle` must appear on exactly as many qualifying lines as the numeral says.
    //
    // A qualifying line contains `needle`, is not a comment, and is not the definition
    // itself (`needle` preceded by `fn ` on the same line) — so "three callers" counts
    // callers and not the function they call, and a doc comment that mentions the name
    // cannot pad the total.
    needle: &'static str,
}

// Every numeral under [`SCANNED`] that quantifies a countable code entity.
//
// Ordered by file, the same order the scan produces — `src/` first, then `examples/` — so
// that a diff to this table reads next to the diff that provoked it.
const REGISTRY: &[Claim] = &[
    Claim {
        file: "src/pac/boa.rs",
        anchor: "Install the fourteen host functions",
        noun: "functions",
        scope: Scope::SrcOutsideTests,
        needle: "register_global_callable",
    },
    Claim {
        file: "src/pac/time.rs",
        anchor: "The three time functions",
        noun: "functions",
        scope: Scope::SrcOutsideTests,
        // The callers, not the definition: `split_gmt`'s own `fn` line carries no module
        // qualifier, so it cannot pad the count it is being counted against.
        needle: "time::split_gmt(",
    },
    Claim {
        file: "src/sys/linux/mod.rs",
        anchor: "The four pure modules are compiled",
        noun: "modules",
        scope: Scope::File("src/sys/linux/mod.rs"),
        needle: "pub(crate) mod ",
    },
    Claim {
        file: "src/sys/mac/mod.rs",
        anchor: "The two `create_store` tests below",
        noun: "tests",
        scope: Scope::File("src/sys/mac/mod.rs"),
        // The tests are the calls that `expect` rather than `?`: production reaches
        // `create_store` once, at [`read_config`], and propagates the error instead.
        needle: "create_store().expect(",
    },
    Claim {
        file: "src/sys/win/notify.rs",
        anchor: "both call sites ([`arm_group_policy_key`]",
        noun: "call sites",
        scope: Scope::SrcOutsideTests,
        needle: "arm_first_available(",
    },
    Claim {
        file: "examples/pac.rs",
        anchor: "as the two call sites",
        noun: "call sites",
        // The file and not [`Scope::SrcOutsideTests`]: the sentence says "below", and an
        // example is one file a reader opens end to end. Counting it across the whole scan
        // would let a third call appear in another example and satisfy a numeral that is
        // about this one.
        scope: Scope::File("examples/pac.rs"),
        needle: "without_credentials(",
    },
];

// Every numeral-and-noun pair on `line`, with the number the numeral asserts.
//
// Text, not syntax, for the same reason `src/debug_masking.rs` scans text: prose is what
// is being checked, and prose does not survive into the item tree. The shape recognised is
// a numeral word, then at most one intervening lowercase word, then the noun — "two
// callers", "three real backends", "both call sites". Anything looser matched sentences
// where the numeral belonged to a different noun.
fn claims_in_line(line: &str) -> Vec<(usize, &'static str)> {
    let lower = line.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut found = Vec::new();

    for &(word, value) in NUMERALS {
        let mut from = 0;
        while let Some(offset) = lower[from..].find(word) {
            let start = from + offset;
            from = start + word.len();

            let preceded_by_word = start > 0 && is_word_byte(bytes[start - 1]);
            if preceded_by_word {
                continue;
            }
            // Step over Markdown emphasis as well as the space, because this tree writes it
            // (`**both** stores`, `src/sys/linux/backend.rs`): a numeral wrapped in `**`
            // is followed by `*`, not by a space, and stopping at the first one would drop
            // the claim silently. Backticks are deliberately not skipped here — they are
            // what [`is_intervening_word`] uses to recognise a backticked identifier.
            let mut after = from;
            while matches!(bytes.get(after), Some(b' ' | b'*')) {
                after += 1;
            }
            if after == from {
                continue;
            }
            if let Some(noun) = noun_after(&lower[after..]) {
                found.push((value, noun));
            }
        }
    }
    found
}

// The noun a numeral quantifies, given the text right after it, or `None`.
fn noun_after(rest: &str) -> Option<&'static str> {
    for skipped in [0, 1] {
        let tail = if skipped == 0 {
            rest
        } else {
            // At most one intervening word, and only a plain lowercase one — an adjective
            // ("three real backends") or a backticked identifier ("two `create_store`
            // tests") — never a second numeral or a punctuated clause.
            let end = rest.find(' ')?;
            if !is_intervening_word(&rest[..end]) {
                return None;
            }
            &rest[end + 1..]
        };
        for &noun in NOUNS {
            let Some(after) = tail.strip_prefix(noun) else {
                continue;
            };
            if after.bytes().next().is_none_or(|b| !is_word_byte(b)) {
                return Some(noun);
            }
        }
    }
    None
}

// Whether `word` may stand between a numeral and the noun it quantifies.
//
// A bare lowercase word is the adjective case. The backticked case is here because this
// tree writes a code entity's own name in backticks far more often than it writes a plain
// adjective, so a scanner that stops at a backtick stops right where the prose it is
// checking actually goes: `src/sys/mac/mod.rs`'s "The two `create_store` tests below" is a
// numeral+noun claim that went unregistered for as long as the rule excluded it.
fn is_intervening_word(word: &str) -> bool {
    let inner = word
        .strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
        .unwrap_or(word);
    !inner.is_empty()
        && inner
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// One numeral found in the tree.
struct Hit {
    file: String,
    line: String,
    stated: usize,
    noun: &'static str,
}

// Every `.rs` file under `dir`, recursively, as repo-relative paths.
fn rust_files(root: &Path, dir: &str) -> Vec<(String, PathBuf)> {
    let mut files = Vec::new();
    let mut pending = vec![root.join(dir)];

    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current).expect("a source directory is readable") {
            let path = entry.expect("a source directory entry is readable").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .expect("the file was found under the manifest directory")
                .to_string_lossy()
                .replace('\\', "/");
            files.push((rel, path));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives directly under the repository root")
        .to_path_buf()
}

// What the scan walks: the directories `Cargo.toml`'s `include` puts in the `.crate`
// (`/src/**/*.rs` and `/examples/*.rs`). The registry is sized for the surface a consumer
// reads, and an example is read by every consumer who opens one — a miscount there is the
// same defect in the same package. `tests/` is excluded on purpose; see
// [`the_exclusion_of_tests_still_excludes_something`] for what that exclusion is worth.
//
// Widening this widens what every row of [`REGISTRY`] has to account for, so widen the
// registry in the same edit.
const SCANNED: &[&str] = &["src", "examples"];

// Every numeral under [`SCANNED`] that quantifies one of [`NOUNS`].
fn scan() -> Vec<Hit> {
    let root = manifest_dir();
    let mut hits = Vec::new();

    for dir in SCANNED {
        for (rel, path) in rust_files(&root, dir) {
            let text = fs::read_to_string(&path).expect("a Rust source file is UTF-8");
            for line in text.lines() {
                for (stated, noun) in claims_in_line(line) {
                    hits.push(Hit {
                        file: rel.clone(),
                        line: line.to_string(),
                        stated,
                        noun,
                    });
                }
            }
        }
    }
    hits
}

// How many qualifying lines carry `needle` within `scope`.
//
// No self-exclusion here: this file lives under `tests/`, and the only whole-directory
// scope is `src/`, so its own string literals cannot pad a count.
fn count(scope: &Scope, needle: &str) -> usize {
    let root = manifest_dir();
    let files: Vec<PathBuf> = match scope {
        Scope::SrcOutsideTests => rust_files(&root, "src")
            .into_iter()
            .map(|(_, path)| path)
            .collect(),
        Scope::File(rel) => vec![root.join(rel)],
    };

    let mut total = 0;
    for path in files {
        let text = fs::read_to_string(&path).expect("a counted source file is UTF-8");
        for line in text.lines() {
            if matches!(scope, Scope::SrcOutsideTests) && starts_test_module(line) {
                break;
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            let Some(at) = line.find(needle) else {
                continue;
            };
            // The definition is not one of its own call sites.
            if line.find("fn ").is_some_and(|f| f < at) {
                continue;
            }
            total += 1;
        }
    }
    total
}

// Whether `line` opens the file's test module — where a production-call-site count stops.
//
// The `#[cfg(test)]` attribute itself is deliberately not the marker. It also sits on
// test-only items that appear *in the middle* of a file — `src/lib.rs`'s
// `mod debug_masking;` declaration and `src/sys/linux/kde.rs`'s `proxy_settings` helper —
// and stopping there would hide every production line after them from the count while
// leaving them visible to `scan()`. A numeral added below such a line would then be
// reported as "0 actual vs N stated" with nothing in the message to say why.
fn starts_test_module(line: &str) -> bool {
    line.trim_start().starts_with("mod tests")
}

// Which rows of [`REGISTRY`] a hit matches. Exactly one is the only healthy answer.
fn matching_rows(hit: &Hit) -> Vec<&'static Claim> {
    REGISTRY
        .iter()
        .filter(|claim| {
            claim.file == hit.file && claim.noun == hit.noun && hit.line.contains(claim.anchor)
        })
        .collect()
}

// The half that makes the other half impossible to forget. A numeral written into the
// tree without a row here fails; so does a row whose sentence was reworded or deleted,
// which is what keeps the table from silently becoming a list of claims nobody makes
// any more.
#[test]
fn every_counting_numeral_is_registered() {
    let hits = scan();

    let unregistered: Vec<String> = hits
        .iter()
        .filter(|hit| matching_rows(hit).is_empty())
        .map(|hit| format!("{}: {}", hit.file, hit.line.trim()))
        .collect();
    assert!(
        unregistered.is_empty(),
        "numerals with no row in xtask/tests/claim_counts.rs:\n{}\n\nA row has to name a \
         needle the gate can recount. If the tree cannot be recounted for this numeral, \
         reword the sentence to name its items instead — there is no row that excuses one.",
        unregistered.join("\n")
    );

    let matched: BTreeSet<(&str, &str, &str)> = hits
        .iter()
        .flat_map(|hit| matching_rows(hit))
        .map(|claim| (claim.file, claim.anchor, claim.noun))
        .collect();
    let stale: Vec<&str> = REGISTRY
        .iter()
        .filter(|claim| !matched.contains(&(claim.file, claim.anchor, claim.noun)))
        .map(|claim| claim.anchor)
        .collect();
    assert!(
        stale.is_empty(),
        "rows in xtask/tests/claim_counts.rs matching no sentence in the tree: {stale:?}. The \
         sentence was reworded, moved or deleted — update the row rather than leaving it."
    );
}

// An anchor that picks out two sentences would let one of them drift unchecked behind
// the other's row.
#[test]
fn every_anchor_identifies_exactly_one_sentence() {
    for hit in scan() {
        let rows = matching_rows(&hit);
        assert!(
            rows.len() <= 1,
            "{} numerals matched {} rows at once ({}); make each anchor longer until \
             it picks out one sentence",
            hit.file,
            rows.len(),
            hit.line.trim()
        );
    }
}

// The part that catches drift rather than novelty: every registered numeral gets
// recounted, which is what makes a number gone stale a build failure instead of something
// a reader has to happen to notice.
//
// There is no row this loop skips. A verdict that opted out of the recount would be the one
// place an unchecked number could sit, so the table carries no such verdict: a sentence the
// tree cannot be recounted for is reworded to name its items instead.
#[test]
fn every_countable_numeral_matches_the_tree() {
    for hit in scan() {
        let [claim] = matching_rows(&hit)[..] else {
            continue; // reported by the two tests above
        };
        let actual = count(&claim.scope, claim.needle);
        assert_eq!(
            actual, hit.stated,
            "{}: \"{}\" says {} but `{}` is on {actual} lines. Either the \
             sentence or the code moved; fix whichever is wrong.",
            claim.file, claim.anchor, hit.stated, claim.needle
        );
    }
}

// The scanner has to recognise the shapes this tree actually writes. Without this, a
// pattern that quietly stops matching turns the gate into a table no sentence in the tree
// reaches any more, which passes green and checks nothing.
#[test]
fn the_scanner_reads_the_shapes_this_tree_uses() {
    assert_eq!(
        claims_in_line("/// This function's own two callers,"),
        [(2, "callers")]
    );
    assert_eq!(
        claims_in_line("/// none of the three real backends (`src/sys/win`,"),
        [(3, "backends")]
    );
    assert_eq!(
        claims_in_line("/// failing the caller — both call sites ([`arm_group_policy_key`],"),
        [(2, "call sites")]
    );
    // Past ten, where a table of single-word spellings would stop.
    assert_eq!(
        claims_in_line("// Install the fourteen host functions on the global object."),
        [(14, "functions")]
    );
    // The two shapes this tree writes that a space-and-lowercase-only rule stops at: a
    // backticked identifier between the numeral and its noun, and a numeral under Markdown
    // emphasis. The first hides `src/sys/mac/mod.rs`'s "two `create_store` tests" from
    // the registry; the second is the spelling `src/sys/linux/backend.rs` uses.
    assert_eq!(
        claims_in_line("//! The two `create_store` tests below need a live `configd`."),
        [(2, "tests")]
    );
    assert_eq!(
        claims_in_line("//! **both** backends are read; the desktop orders them."),
        [(2, "backends")]
    );
    // A numeral belonging to a different noun, and a word that merely contains one.
    assert_eq!(claims_in_line("/// three more time out because"), []);
    assert_eq!(claims_in_line("/// the twofold cost of methods"), []);
    // Two intervening words are still one too many: a numeral held off its noun by
    // `PAC host` goes unread, and the repair is to reword rather than to widen the rule.
    assert_eq!(claims_in_line("//! Fourteen PAC host functions only"), []);
    // The other silence, and the larger one: `NOUNS` is closed, so a numeral whose noun is
    // outside it goes unread however close the two sit. Both lines below are live sentences
    // in the tree (`src/bypass.rs`, `src/pac/result.rs`) with counts that happen to
    // be right; nothing here would notice if they stopped being.
    assert_eq!(
        claims_in_line("/// is empty. The three switches apply first"),
        []
    );
    assert_eq!(claims_in_line("// The two references split here"), []);
    // The third silence: a numeral that ends its line. Nothing follows it to be a noun, so
    // the claim is not read even though `NOUNS` holds the word on the next line. Whether a
    // sentence is examined then turns on where the wrap fell. `unverified_surface.rs` joins
    // its lines before scanning; this gate does not, because the alternative is worse (see
    // the module doc). [`no_claim_in_the_tree_is_split_across_a_line_break`] keeps it empty.
    assert_eq!(claims_in_line("// The scanner has two"), []);
    assert_eq!(claims_in_line("// callers that reach it."), []);
}

// The line-break silence, held at zero instances. A `NOUNS` word at the start of a comment
// line whose predecessor ends in a numeral is a claim this gate cannot see, so the repair
// is to rewrap the sentence rather than to widen the scanner.
#[test]
fn no_claim_in_the_tree_is_split_across_a_line_break() {
    // The marker has to come off the second line before the two are joined, or the numeral
    // would be looking at `//` rather than at a word and this test could never fire on
    // anything — a gate whose population is unreachable by construction.
    fn body(line: &str) -> &str {
        let t = line.trim();
        t.strip_prefix("//!")
            .or_else(|| t.strip_prefix("///"))
            .or_else(|| t.strip_prefix("//"))
            .unwrap_or(t)
            .trim_start()
    }
    fn split_claim(first: &str, second: &str) -> bool {
        let joined = format!("{} {}", body(first), body(second));
        !claims_in_line(&joined).is_empty()
            && claims_in_line(first).is_empty()
            && claims_in_line(second).is_empty()
    }

    // The control, so a zero below means "the tree has none" and not "this cannot see any".
    assert!(split_claim(
        "// The scanner has two",
        "// callers that reach it."
    ));

    // [`SCANNED`] and not `src` alone, so that this silence is held over exactly the
    // population [`scan`] reads. A claim the scanner cannot see is not less invisible for
    // sitting in an example.
    let root = manifest_dir();
    let mut split = Vec::new();
    for dir in SCANNED {
        for (rel, path) in rust_files(&root, dir) {
            let text = fs::read_to_string(&path).expect("a Rust source file is UTF-8");
            let lines: Vec<&str> = text.lines().collect();
            for pair in lines.windows(2) {
                if split_claim(pair[0], pair[1]) {
                    split.push(format!("{rel}: {} / {}", pair[0].trim(), pair[1].trim()));
                }
            }
        }
    }
    assert!(
        split.is_empty(),
        "a numeral+noun claim falls across a line break, where this scanner cannot read \
         it — rewrap the sentence so the pair sits on one line:\n{}",
        split.join("\n")
    );
}

// An exclusion nobody can see excluding anything is an unchecked place wearing the clothes
// of a decision. `tests/` was dropped from the scan because thirteen rows of upkeep bought
// prose no reader reaches; if the numerals there ever went away by themselves, the right
// move would be to scan it again rather than to keep a line that does nothing.
#[test]
fn the_exclusion_of_tests_still_excludes_something() {
    let root = manifest_dir();
    let mut excluded = 0;
    for (_rel, path) in rust_files(&root, "tests") {
        let text = fs::read_to_string(&path).expect("a Rust source file is UTF-8");
        excluded += text.lines().flat_map(claims_in_line).count();
    }
    assert!(
        excluded > 0,
        "no numeral is left under tests/ for the exclusion to exclude — either the scan \
         should cover tests/ again or the exclusion should stop being described as one"
    );
}
