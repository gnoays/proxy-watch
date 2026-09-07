//! Gate: no comment tells the reader what the comment, the doc, the test, the row, the
//! line or the file it sits in stated before. Prose whose subject is the text's own past —
//! a correction addressed to a reader who never saw the text being corrected — is the whole
//! of what this looks for.
//!
//! The cost it exists to stop is one-sided. A sentence about a wrong belief someone held is
//! read by every future reader of the file and instructs none of them: a reader cannot act
//! on a version of the text they have never seen, so the sentence spends attention and
//! returns nothing. The forward sentence is available in every case, and it is shorter —
//! what a reader must not do, and the mechanism that makes it wrong. Where a wrong move is
//! genuinely tempting, saying so forward ("not X: X does Y") carries the same warning
//! without the archaeology, and reads as a rule rather than as a confession.
//!
//! # What is deliberately out of scope
//!
//! A negation is not the target. "Does not allocate", "is not thread-safe",
//! "`contoso.com` does not bypass `api.contoso.com`" each carry what a reader would
//! otherwise assume the opposite of, and no forward sentence replaces them. Of the 154
//! negative doc-comment lines under `src/` when this gate was written, [`PHRASES`] matched
//! none.
//!
//! The system's own past is not the target either, and separating the two is the whole
//! design of [`PHRASES`]. "The parser used to leave HTTP going direct" and "the failure
//! reason echoed whatever sat past the last `:`" are facts about the code, and a regression
//! test's reason for existing rests on them: a reader who cannot see that the defect was
//! reachable is a reader who deletes the test as redundant. A first list that reached those
//! sentences too matched 50 comment blocks across this tree; naming the text as the subject
//! brings it to 21, and the 29 it drops are that category in full. Which of those still
//! reads better forward is a judgement for review, not for a scanner — a scanner that
//! forces a true sentence to be reworded leaves the sentence worse than it found it.
//!
//! # No exemption table
//!
//! There is deliberately nowhere to register a match. The repair is to reword, always. If a
//! phrase here ever matches a sentence that is not about the text's past, that phrase will
//! do it again, so the repair is to narrow the phrase with the reason written beside it —
//! not to exempt the one sentence and leave the pattern to misfire on the next. Its sibling
//! `claim_counts.rs` carried two excuse verdicts and deleted both, on the ground that each
//! was a place to park a claim no test read; this gate starts without the place.
//!
//! # What is scanned
//!
//! [`SCANNED`] reaches the whole Rust tree — `src`, `examples`, `tests`, and this directory
//! — where `claim_counts.rs` stops at the surface a consumer reads. The harms differ. A
//! miscounted numeral in `tests/` misleads nobody who is not already editing the file, which
//! is why that gate dropped `tests/`. Text archaeology has its whole effect on somebody who
//! *is* editing the file, and it concentrates there.
//!
//! Reaching this directory puts the gate inside its own scope, so the prose here answers to
//! the rule it enforces ([`this_gate_is_inside_the_tree_it_scans`]). What that costs is one
//! thing: a matched sentence cannot be quoted in a comment here. The fixtures below quote
//! theirs in string literals, which the scan does not read.
//!
//! # What it does not see
//!
//! Three silences, each measured rather than assumed.
//!
//! By subject word: [`PHRASES`] is a closed list of the nouns this tree uses for its own
//! text, so a sentence that withdraws a claim without naming what made it walks past. There
//! was one — `tests/windows_watch.rs` named a fix and then took it back with a bare "That
//! was wrong", which no entry here reaches; it was reworded by hand in the same pass that
//! added this gate. Widening to the bare demonstrative is what would have caught it, and it
//! is also what reaches "that was wrong about the port", a fact about the code. The list
//! buys its precision by requiring a subject, and this is what the precision costs.
//!
//! By comment syntax: [`comment_blocks`] reads `//`, `///` and `//!` and nothing else.
//! [`the_tree_states_its_prose_in_line_comments`] measures that this is the whole of the
//! tree's prose. It reads physical lines, so a multi-line string literal whose continuation
//! line begins with a comment marker is read as prose; the fixtures below keep their
//! literals on one line for that reason.
//!
//! By intervening code: a run of comment lines is joined before matching, so a phrase split
//! across a line break is still found ([`the_scanner_joins_a_block_before_matching`]), but a
//! run interrupted by a statement is two blocks. No phrase in the tree straddles code.
//!
//! This checks the development tree rather than the library, so it lives in the `xtask`
//! package, which the published `.crate` does not carry at all.

use std::fs;
use std::path::{Path, PathBuf};

// Phrases whose subject is the text rather than the system it describes.
//
// The distinction is the point. A sentence about what the code did before is a fact about
// the code, and a regression test can need it; a sentence about what the surrounding prose
// declared before instructs nobody, because its reader never held the belief being
// withdrawn. So every entry here names a piece of text — the comment, the doc, the test,
// the row, the line, the file, or a version of one — and the general "used to" is left
// alone, since English spells "employed in order to" the same way and the past of a value
// ("U+FFFD where the undecodable bytes had been") the same way again.
//
// The article is part of the phrase and carries none of the meaning, so a noun spelled with
// a demonstrative is spelled with an article too. "The docs" names what "this doc" names
// and reaches the body of prose no demonstrative points at.
//
// The last two entries name no subject and need none: neither has a reading that is about
// present behaviour.
//
// Matching is case-insensitive and word-bounded at both ends, so a phrase ending in a past
// tense does not fire on the present tense of the same verb.
const PHRASES: &[&str] = &[
    "an earlier version of this",
    "the previous version of this",
    "the first version of this",
    "the first draft of this",
    "this comment claimed",
    "this comment said",
    "this comment used to",
    "this doc claimed",
    "this doc used to",
    "the docs claimed",
    "the docs used to",
    "this test claimed",
    "this test asserted",
    "this test used to",
    "this row used to",
    "this line read",
    "this line used to",
    "this file used to",
    "was simply wrong",
    "had never been tried",
];

struct Hit {
    file: String,
    // 1-based line where the comment block opens.
    line: usize,
    phrase: &'static str,
    block: String,
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

// The whole Rust tree. Widening this is free; narrowing it needs a reason written here.
const SCANNED: &[&str] = &["src", "examples", "tests", "xtask/tests"];

// The comment blocks of `text`: each maximal run of consecutive comment lines, joined into
// one lowercased, whitespace-collapsed string, with the line the run opens on.
//
// Joining is what lets a phrase be found across the line break a rewrap put in it. The
// marker (`//`, `///`, `//!`) is stripped, so a run that mixes them still joins.
fn comment_blocks(text: &str) -> Vec<(usize, String)> {
    let mut blocks: Vec<(usize, String)> = Vec::new();
    let mut open: Option<(usize, String)> = None;

    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("//") {
            let body = rest
                .strip_prefix('!')
                .or_else(|| rest.strip_prefix('/'))
                .unwrap_or(rest);
            let (_, joined) = open.get_or_insert_with(|| (index + 1, String::new()));
            for word in body.split_whitespace() {
                if !joined.is_empty() {
                    joined.push(' ');
                }
                joined.push_str(&word.to_lowercase());
            }
        } else if let Some(block) = open.take() {
            blocks.push(block);
        }
    }
    if let Some(block) = open.take() {
        blocks.push(block);
    }
    blocks
}

// Whether `haystack` holds `needle` with a non-word character on each side.
fn find_bounded(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(offset) = haystack[from..].find(needle) {
        let start = from + offset;
        let end = start + needle.len();
        let before = start == 0 || !is_word_byte(bytes[start - 1]);
        let after = end == bytes.len() || !is_word_byte(bytes[end]);
        if before && after {
            return true;
        }
        from = start + 1;
    }
    false
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn scan() -> Vec<Hit> {
    let root = manifest_dir();
    let mut hits = Vec::new();

    for dir in SCANNED {
        for (rel, path) in rust_files(&root, dir) {
            let text = fs::read_to_string(&path).expect("a Rust source file is UTF-8");
            for (line, block) in comment_blocks(&text) {
                for phrase in PHRASES {
                    if find_bounded(&block, phrase) {
                        hits.push(Hit {
                            file: rel.clone(),
                            line,
                            phrase,
                            block: block.clone(),
                        });
                    }
                }
            }
        }
    }
    hits
}

// An excerpt of `block` around `phrase`, so a failure message names the sentence.
fn excerpt(block: &str, phrase: &str) -> String {
    let at = block.find(phrase).unwrap_or(0);
    let start = block[..at].rfind(". ").map_or(0, |stop| stop + 2);
    let tail = &block[start..];
    let end = tail.find(". ").map_or(tail.len(), |stop| stop + 1);
    tail[..end].to_string()
}

#[test]
fn no_comment_states_what_the_text_around_it_stated_before() {
    let mut found = Vec::new();
    for hit in scan() {
        found.push(format!(
            "{}:{} — {:?}\n    {}",
            hit.file,
            hit.line,
            hit.phrase,
            excerpt(&hit.block, hit.phrase)
        ));
    }
    assert!(
        found.is_empty(),
        "prose about its own past, addressed to a reader who cannot have seen what it \
         corrects. State the rule forward instead — what a reader must not do, and the \
         mechanism that makes it wrong:\n{}",
        found.join("\n")
    );
}

// A gate with nothing to report passes whether it read the tree or read nothing at all.
// This is what says which.
#[test]
fn the_scan_reaches_every_directory_it_names() {
    let root = manifest_dir();
    for dir in SCANNED {
        let files = rust_files(&root, dir);
        assert!(
            !files.is_empty(),
            "{dir} holds no Rust file the scan can see"
        );
        let blocks: usize = files
            .iter()
            .map(|(_, path)| {
                let text = fs::read_to_string(path).expect("a Rust source file is UTF-8");
                comment_blocks(&text).len()
            })
            .sum();
        assert!(blocks > 0, "{dir} yields no comment block");
    }
}

// The line-break silence, closed: a rewrap must not be able to hide a phrase.
#[test]
fn the_scanner_joins_a_block_before_matching() {
    let split = "// The worker keeps running, which is not what an earlier\n// version of this comment claimed.\nlet x = 1;\n";
    let blocks = comment_blocks(split);
    assert_eq!(blocks.len(), 1, "one run of comment lines is one block");
    assert_eq!(blocks[0].0, 1, "a block reports the line it opens on");
    assert!(
        find_bounded(&blocks[0].1, "an earlier version of this"),
        "a phrase split across a line break is still found"
    );
}

// The boundary, without which a present-tense verb reads as a past one. `single_source.rs`
// says "this gate reads the Rust tree"; an unbounded match calls that a claim about text.
#[test]
fn a_phrase_needs_a_word_boundary_at_both_ends() {
    assert!(find_bounded("this line read suffix", "this line read"));
    assert!(!find_bounded(
        "this line reads the rust tree",
        "this line read"
    ));
}

// The half of the design that a widened phrase list would break: the code's own past stays
// sayable, because a regression test's reason for existing is made of it.
#[test]
fn a_sentence_about_the_codes_past_is_not_a_sentence_about_the_text() {
    let about_code = [
        "the failure reason used to be a format! that echoed whatever sat past the last :",
        "h:+80 used to be the one spelling this crate honoured",
        "u+fffd where bytes it could not decode used to be",
    ];
    for sentence in about_code {
        assert!(
            !PHRASES.iter().any(|phrase| find_bounded(sentence, phrase)),
            "{sentence:?} is a fact about the code, and no phrase may reach it"
        );
    }
    let about_text = [
        "not what an earlier version of this comment claimed",
        "this test asserted the opposite until the claim was checked",
        "the two this row used to name were the two nothing else could reach",
    ];
    for sentence in about_text {
        assert!(
            PHRASES.iter().any(|phrase| find_bounded(sentence, phrase)),
            "{sentence:?} is a claim about the text, and some phrase must reach it"
        );
    }
}

// The comment shapes the scan reads, against the shapes the tree writes.
#[test]
fn the_scanner_reads_the_comment_shapes_this_tree_uses() {
    let sample = "//! module\n/// item\n// plain\nlet s = \"// not a comment\";\n";
    let blocks = comment_blocks(sample);
    assert_eq!(blocks.len(), 1, "the three markers join into one run");
    assert_eq!(blocks[0].1, "module item plain");
}

// The block-comment silence, measured rather than assumed.
#[test]
fn the_tree_states_its_prose_in_line_comments() {
    let root = manifest_dir();
    let mut opened = Vec::new();
    for dir in SCANNED {
        for (rel, path) in rust_files(&root, dir) {
            let text = fs::read_to_string(&path).expect("a Rust source file is UTF-8");
            for (index, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("/*") {
                    opened.push(format!("{rel}:{}", index + 1));
                }
            }
        }
    }
    assert!(
        opened.is_empty(),
        "a block comment is prose this gate cannot read; state it in `//` lines:\n{}",
        opened.join("\n")
    );
}

// The gate answers to its own rule. `claim_counts.rs` cannot: nothing walks its directory.
#[test]
fn this_gate_is_inside_the_tree_it_scans() {
    let root = manifest_dir();
    let reached = SCANNED.iter().any(|dir| {
        rust_files(&root, dir)
            .iter()
            .any(|(rel, _)| rel == "xtask/tests/comment_provenance.rs")
    });
    assert!(
        reached,
        "the scan reaches this file, so its prose obeys the rule it enforces"
    );
}
