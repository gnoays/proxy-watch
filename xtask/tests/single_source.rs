//! Gate: restated facts (MSRV, features, deps, `unsafe` sites) must match their source.
//! Values are parsed from `Cargo.toml` / CI / the tree; only exemptions are hand-written,
//! and each row must say why.
//!
//! This is a check on the repository, not on the library, so it lives in the `xtask`
//! package rather than the library's own `tests/`. Do not move it back: it reads `.github/`
//! and `docs/` off the manifest directory to derive its values, and neither of those is
//! inside the published `.crate`.
//!
//! Of those authorities, `docs/` is the one a checkout need not have, so this gate also runs
//! with the doc pages absent — see [`doc_pages_under`] for why that is a supported shape and
//! not a hole.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

// `gated_files` walks `src/`, `tests/` and `examples/`, none of which reaches `xtask/`, so
// this gate sits outside the list it walks even though it quotes the very strings it checks
// for. Do not add a self-exclusion without first making the walk reach here.

// Non-Rust restatements of the manifest. HTML pages use [`EXEMPT_DOCS`] instead.
const PROSE_FILES: &[&str] = &[
    "README.md",
    "CONTRIBUTING.md",
    "Cargo.toml",
    ".github/workflows/ci.yml",
];

// Ungated `docs/*.html` pages. Directory-checked: add/remove requires a row change.
const EXEMPT_DOCS: &[(&str, &str)] = &[(
    "docs/SURVEY.html",
    "other crates' versions / download counts — not this manifest",
)];

// Toolchain strings that are not this crate's MSRV.
const TOOLCHAIN_EXCEPTIONS: &[(&str, &str)] =
    &[("1.85", "edition-2024 floor, not this crate's MSRV")];

// A dependency version stated in prose that is not the one the manifest requires.
const VERSION_EXCEPTIONS: &[(&str, &str, &str)] = &[(
    "system-configuration",
    "0.6",
    "the release *before* the requirement, named to explain what changed: 0.6 panicked \
         on a NULL result where 0.7 returns an error",
)];

// The sentence in `README.md` that says where `unsafe` is allowed to be, and the paths
// it allows.
//
// This is the claim that broke in four consecutive audit rounds: `unsafe` moved, or a new
// call site appeared, and the sentence stayed. The paths are the *only* hand-written part;
// which files actually contain `unsafe` is read off the tree, in both directions — an
// `unsafe` outside them fails, and an entry that no longer contains any fails too, because
// a permission nobody uses is a claim that has quietly become false.
const UNSAFE_CLAIM: &str = "`unsafe` is confined to the code that calls the OS directly.";

// Paths the claim above allows `unsafe` in, with the reason the claim gives.
const UNSAFE_ALLOWED: &[(&str, &str)] = &[
    ("src/sys/win/", "the Windows backend: the OS APIs are C"),
    ("src/sys/mac/", "the macOS backend: the OS APIs are C"),
    (
        "src/pac/winhttp.rs",
        "the WinHTTP PAC engine behind `pac-windows-native`, which is the same C API \
         surface reached from the PAC side",
    ),
];

// A version stated in prose, and where it was found.
#[derive(Debug)]
struct Mention {
    file: String,
    line: String,
    value: String,
}

// What `Cargo.toml` declares, parsed rather than transcribed.
#[derive(Debug)]
struct Manifest {
    rust_version: String,
    features: BTreeSet<String>,
    deps: BTreeMap<String, String>,
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives directly under the repository root")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    fs::read_to_string(manifest_dir().join(rel))
        .unwrap_or_else(|e| panic!("{rel} is readable as UTF-8: {e}"))
}

// Strip a `# …` comment, respecting the fact that TOML strings can contain `#`.
fn strip_toml_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_string = !in_string,
            b'#' if !in_string => return &line[..i],
            _ => {}
        }
    }
    line
}

// The first `"…"` on the line, if any.
fn quoted(line: &str) -> Option<&str> {
    let start = line.find('"')? + 1;
    let end = line[start..].find('"')? + start;
    Some(&line[start..end])
}

// Parse the manifest far enough to know what it declares. Not a TOML implementation —
// it understands exactly the table shapes this manifest uses, and
// [`the_parser_reads_the_shapes_this_manifest_uses`] fails if that stops being true.
fn parse_manifest() -> Manifest {
    let text = read("Cargo.toml");
    let mut rust_version = String::new();
    let mut features = BTreeSet::new();
    let mut deps: BTreeMap<String, String> = BTreeMap::new();

    // The table we are inside, and — when the header named a single dependency — that
    // dependency's name, so its `version = "…"` line can be attributed to it.
    let mut in_features = false;
    let mut in_deps = false;
    let mut single_dep: Option<String> = None;

    for raw in text.lines() {
        let line = strip_toml_comment(raw).trim_end();
        if line.starts_with('[') {
            let header = line.trim_start_matches('[').trim_end_matches(']');
            // `target.'cfg(…)'.dependencies` and `target.'cfg(…)'.dev-dependencies`
            // differ from the plain tables only in the prefix.
            let tail = header.rsplit('.').next().unwrap_or(header);
            in_features = header == "features";
            in_deps = tail == "dependencies" || tail == "dev-dependencies";
            single_dep = None;
            if !in_deps && !in_features {
                // `[dependencies.boa_engine]` — the last component is the crate name and
                // the one before it says which table it belongs to.
                let mut parts = header.rsplitn(2, '.');
                let name = parts.next().unwrap_or_default();
                let rest = parts.next().unwrap_or_default();
                if rest.ends_with("dependencies") {
                    single_dep = Some(name.to_string());
                }
            }
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());

        if let Some(name) = &single_dep {
            if key == "version"
                && let Some(v) = quoted(value)
            {
                deps.insert(name.clone(), v.to_string());
            }
            continue;
        }
        if in_features {
            if !key.is_empty() && !key.contains(' ') {
                features.insert(key.to_string());
            }
            continue;
        }
        if in_deps {
            // Either `name = "0.9"` or `name = { version = "0.9", … }`.
            if let Some(v) = value
                .strip_prefix('{')
                .and_then(|inline| inline.find("version").map(|i| &inline[i..]))
                .and_then(quoted)
                .or_else(|| {
                    if value.starts_with('"') {
                        quoted(value)
                    } else {
                        None
                    }
                })
            {
                deps.insert(key.to_string(), v.to_string());
            }
            continue;
        }
        if key == "rust-version"
            && let Some(v) = quoted(value)
        {
            rust_version = v.to_string();
        }
    }

    Manifest {
        rust_version,
        features,
        deps,
    }
}

// The toolchains the `msrv` CI job actually builds.
//
// `- toolchain: "1.88"` is the matrix row shape; the other `toolchain` lines in the
// workflow are the `toolchain: stable` input under a `uses:` and the
// `${{ matrix.toolchain }}` expansion, neither of which carries a version literal, and
// neither of which starts with `- `.
fn ci_toolchains() -> BTreeSet<String> {
    read(".github/workflows/ci.yml")
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("- toolchain:").and_then(quoted)
        })
        .map(str::to_string)
        .collect()
}

// Files this gate reads: the Rust tree, the prose files, and every non-exempt doc page.
//
// `examples/` is in the walk because it is in `Cargo.toml`'s `include` — a version number
// restated in an example travels to the consumer exactly as one restated in `src/` does,
// and [`doc_pages_under`] below already names it as part of the tree that travels.
//
// `tests/` is in the walk for the opposite reason, and is where this gate and
// `claim_counts` deliberately differ: that gate dropped `tests/` because its subject is a
// numeral a consumer can read off the shipped surface, and test prose ships to nobody.
// This gate's subject is a *restatement* — two copies of one fact drifting apart — which
// costs the same upkeep whether or not the second copy is published.
fn gated_files() -> Vec<String> {
    let root = manifest_dir();
    let mut files: Vec<String> = PROSE_FILES.iter().map(|f| (*f).to_string()).collect();

    for dir in ["src", "tests", "examples"] {
        let mut pending = vec![root.join(dir)];
        while let Some(current) = pending.pop() {
            for entry in fs::read_dir(&current).expect("a source directory is readable") {
                let path = entry.expect("a directory entry is readable").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    files.push(relative(&root, &path));
                }
            }
        }
    }

    for page in doc_pages() {
        if !EXEMPT_DOCS.iter().any(|(exempt, _)| *exempt == page) {
            files.push(page);
        }
    }

    files.sort();
    files
}

fn doc_pages() -> Vec<String> {
    doc_pages_under(&manifest_dir())
}

// The `docs/*.html` pages under `root`, or nothing when `root` has no `docs/`.
//
// An absent `docs/` is a tree this gate supports rather than an error. This gate travels
// with the crate, so `cargo test` has to pass in a checkout that carries the crate and the
// gates that check it and no prose pages at all — that is where a copy which took too much
// or too little gets caught, and a gate that panicked on the absence would make the check
// it exists for impossible to run there.
//
// It is the only absence supported. A `docs/` that is present and unreadable still
// panics, and so does a missing prose file, because every prose file travels.
fn doc_pages_under(root: &Path) -> Vec<String> {
    let dir = root.join("docs");
    if !dir.is_dir() {
        return Vec::new();
    }
    let mut pages = Vec::new();
    for entry in fs::read_dir(&dir).expect("docs/ is readable") {
        let path = entry.expect("a docs/ entry is readable").path();
        if path.extension().is_some_and(|ext| ext == "html") {
            pages.push(relative(root, &path));
        }
    }
    pages.sort();
    pages
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("a scanned path is inside the manifest directory")
        .to_string_lossy()
        .replace('\\', "/")
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

// Every `1.<80–99>` token on the line — the shape of a Rust toolchain this crate could
// plausibly require. A narrower net than "any version", and deliberately so: it must not
// match `0.21`, `2.5` or an IPv4 literal.
fn toolchain_versions(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while let Some(rel) = line[i..].find("1.") {
        let start = i + rel;
        if start > 0 && (is_word_byte(bytes[start - 1]) || bytes[start - 1] == b'.') {
            i = start + 2;
            continue;
        }
        let digits: String = line[start + 2..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let after = start + 2 + digits.len();
        let bounded = after >= bytes.len() || !is_word_byte(bytes[after]);
        if digits.len() == 2 && digits.as_str() >= "80" && bounded {
            found.push(format!("1.{digits}"));
        }
        i = start + 2;
    }
    found
}

// Every feature name the line names *as a feature*: `feature = "x"`, `--features a,b`,
// and `required-features = ["a"]`. Backticked prose is out — `` `pac` `` has no shape
// that distinguishes a feature from anything else, so a stale name there is invisible to
// any gate. What is checked instead is that every declared feature is documented; see
// [`every_feature_is_documented`].
fn feature_names(line: &str) -> Vec<String> {
    let mut names = Vec::new();

    let mut rest = line;
    while let Some(at) = rest.find("feature = \"") {
        rest = &rest[at + "feature = \"".len()..];
        if let Some(end) = rest.find('"') {
            names.push(rest[..end].to_string());
        }
    }

    let mut rest = line;
    while let Some(at) = rest.find("--features") {
        rest = &rest[at + "--features".len()..];
        let list: String = rest
            .trim_start_matches([' ', '=', '"'])
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || matches!(c, '-' | ',' | '0'..='9'))
            .collect();
        names.extend(
            list.split(',')
                .filter(|n| !n.is_empty())
                .map(str::to_string),
        );
    }

    let mut rest = line;
    while let Some(at) = rest.find("required-features") {
        rest = &rest[at + "required-features".len()..];
        let Some(open) = rest.find('[') else { break };
        let Some(close) = rest[open..].find(']') else {
            break;
        };
        names.extend(
            rest[open + 1..open + close]
                .split(',')
                .filter_map(quoted_or_bare)
                .map(str::to_string),
        );
        rest = &rest[open + close..];
    }

    names
}

fn quoted_or_bare(item: &str) -> Option<&str> {
    let item = item.trim().trim_matches('"');
    (!item.is_empty()).then_some(item)
}

// Whether a captured string is shaped like a Cargo feature name at all.
//
// `#[cfg(feature = "...")]` appears in prose as a *placeholder* — a sentence about the
// shape of a gate rather than about any one feature. Cargo feature names are lowercase
// ASCII with hyphens, so an ellipsis, a `{}` or a metavariable simply is not one, and
// demanding that it exist would make the gate wrong rather than strict.
fn is_feature_shaped(name: &str) -> bool {
    !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

// Every `` `name` version `` pair on the line where `name` is a manifest dependency.
//
// Backticks are required. Without them the scan matches prose about the *system* library
// a crate binds — "GLib 2.72" is the GLib on the machine the backend was verified on, not
// the `glib` crate this manifest depends on, and conflating the two would make the gate
// wrong rather than strict.
fn dependency_versions(line: &str, deps: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else { break };
        let name = &after[..close];
        let tail = after[close + 1..].trim_start_matches([' ', ',', ':']);
        if deps.contains_key(name) {
            let version: String = tail
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            let version = version.trim_end_matches('.').to_string();
            if version.contains('.') {
                found.push((name.to_string(), version));
            }
        }
        rest = &after[close + 1..];
    }
    found
}

// `<code>` is HTML's backtick, so a `docs/*.html` page is read on the same rule as the
// Markdown. Without this the scan matched nothing on any of those pages, and a version
// written on one was gated in name only.
fn backticked(line: &str) -> String {
    line.replace("<code>", "`").replace("</code>", "`")
}

// Whether a version written in prose is talking about the release the manifest requires.
//
// `0.21.1` satisfies a `0.21` requirement and `0.62.2` satisfies `0.62`; `0.6` does not
// satisfy `0.7`. Comparison is by component so that `0.2` is not read as a prefix of
// `0.21`.
fn describes(requirement: &str, stated: &str) -> bool {
    let req: Vec<&str> = requirement.split('.').collect();
    let said: Vec<&str> = stated.split('.').collect();
    let shared = req.len().min(said.len());
    req[..shared] == said[..shared]
}

// Whether the line contains an `unsafe` keyword rather than the *word* "unsafe".
//
// Comment lines are out: the prose talks about `unsafe` far more often than the code uses
// it, and a doc comment explaining why something needs no `unsafe` must not be read as
// needing one. `unsafe_code` and `unsafe_op_in_unsafe_fn` are lint names, excluded by the
// word boundary since `_` is a word byte.
fn uses_unsafe(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('*') {
        return false;
    }
    let bytes = trimmed.as_bytes();
    let mut from = 0;
    while let Some(rel) = trimmed[from..].find("unsafe") {
        let at = from + rel;
        let after = at + "unsafe".len();
        let before_ok = at == 0 || !is_word_byte(bytes[at - 1]);
        let after_ok = after >= bytes.len() || !is_word_byte(bytes[after]);
        // A backticked `unsafe` inside a non-comment line is still prose — it happens in
        // `expect` strings and attribute reasons.
        let quoted = at > 0 && bytes[at - 1] == b'`';
        if before_ok && after_ok && !quoted {
            return true;
        }
        from = after;
    }
    false
}

// Every file under `src/` that actually uses the `unsafe` keyword.
fn files_using_unsafe() -> Vec<String> {
    let root = manifest_dir();
    let mut found: Vec<String> = gated_files()
        .into_iter()
        .filter(|file| file.starts_with("src/"))
        .filter(|file| {
            fs::read_to_string(root.join(file))
                .expect("a source file is UTF-8")
                .lines()
                .any(uses_unsafe)
        })
        .collect();
    found.sort();
    found
}

fn mentions(files: &[String]) -> Vec<Mention> {
    let root = manifest_dir();
    let mut out = Vec::new();
    for file in files {
        let text = fs::read_to_string(root.join(file))
            .unwrap_or_else(|e| panic!("{file} is readable as UTF-8: {e}"));
        for line in text.lines() {
            for value in toolchain_versions(line) {
                out.push(Mention {
                    file: file.clone(),
                    line: line.trim().to_string(),
                    value,
                });
            }
        }
    }
    out
}

// The MSRV is declared in the manifest and built in CI. Every other statement of it
// has to agree with both, or explain itself.
//
// This is the round-17 defect made mechanical: `Cargo.toml` was corrected and
// `README.md` was not, and nothing noticed for seven rounds.
#[test]
fn every_rust_version_agrees_with_the_manifest_and_ci() {
    let manifest = parse_manifest();
    let ci = ci_toolchains();
    let mut authority: BTreeSet<String> = ci.clone();
    authority.insert(manifest.rust_version.clone());

    let stale: Vec<String> = mentions(&gated_files())
        .into_iter()
        .filter(|m| {
            !authority.contains(&m.value)
                && !TOOLCHAIN_EXCEPTIONS
                    .iter()
                    .any(|(value, _)| *value == m.value)
        })
        .map(|m| format!("{}: {} in {:?}", m.file, m.value, m.line))
        .collect();

    assert!(
        stale.is_empty(),
        "Rust versions stated nowhere the manifest or the msrv CI job declares \
         (declared: {:?}, built in CI: {ci:?}):\n{}",
        manifest.rust_version,
        stale.join("\n")
    );
}

// The declared floor has to be one CI actually builds, or the declaration is a guess.
#[test]
fn the_declared_floor_is_one_ci_builds() {
    let manifest = parse_manifest();
    let ci = ci_toolchains();
    assert!(
        ci.contains(&manifest.rust_version),
        "`rust-version` declares {} but the msrv job builds {ci:?} — a floor nothing \
         builds is a claim, not a measurement",
        manifest.rust_version
    );
}

// Every exception has a reason, is not the authority, and is still excusing a line that
// exists.
//
// The last of those is the check [`every_version_exception_justifies_itself`] calls the
// one that decays silently, and it was written there and not here. The two tables excuse
// the same shape of thing and rot the same way, so the discipline belongs to both.
#[test]
fn every_toolchain_exception_justifies_itself() {
    let manifest = parse_manifest();
    let ci = ci_toolchains();
    let stated = mentions(&gated_files());
    for (value, reason) in TOOLCHAIN_EXCEPTIONS {
        assert!(
            reason.len() > 30,
            "the exception for {value} has to say what that version is instead"
        );
        assert!(
            !ci.contains(*value) && *value != manifest.rust_version,
            "{value} is an authority now — delete its exception row rather than \
             letting two rules cover it"
        );
        assert!(
            stated.iter().any(|m| m.value == *value),
            "no gated file states {value}, so the exception excuses nothing — delete \
             the row rather than leaving it to read as coverage"
        );
    }
}

// A feature named in a `cfg`, a `--features` list or `required-features` has to exist.
//
// The compiler's `unexpected_cfgs` lint covers the `cfg` half inside `src/`; nothing
// covers a `--features` line in a workflow, a README build instruction, or a doc page.
#[test]
fn every_feature_named_as_a_feature_exists() {
    let manifest = parse_manifest();
    let root = manifest_dir();
    let mut unknown = Vec::new();

    for file in gated_files() {
        // The manifest is where features are *defined*; reading it here would only
        // confirm that it agrees with itself, and its dependency tables carry
        // `features = [...]` lists belonging to other crates.
        if file == "Cargo.toml" {
            continue;
        }
        let text = fs::read_to_string(root.join(&file)).expect("a gated file is UTF-8");
        for line in text.lines() {
            for name in feature_names(line) {
                if is_feature_shaped(&name) && !manifest.features.contains(&name) {
                    unknown.push(format!("{file}: `{name}` in {:?}", line.trim()));
                }
            }
        }
    }

    assert!(
        unknown.is_empty(),
        "features named that `[features]` does not declare (declared: {:?}):\n{}",
        manifest.features,
        unknown.join("\n")
    );
}

// Every feature is described where a consumer looks for it.
//
// The other direction of the check above: a feature that exists but appears in
// neither the crate's feature table nor the README is one nobody can find.
#[test]
fn every_feature_is_documented() {
    let manifest = parse_manifest();
    let lib = read("src/lib.rs");
    let readme = read("README.md");

    let undocumented: Vec<&String> = manifest
        .features
        .iter()
        .filter(|name| *name != "default")
        .filter(|name| {
            let quoted = format!("`{name}`");
            !lib.contains(&quoted) || !readme.contains(&quoted)
        })
        .collect();

    assert!(
        undocumented.is_empty(),
        "features declared but absent from `src/lib.rs`'s feature table or from \
         `README.md`: {undocumented:?}"
    );
}

// A dependency version written in prose has to be the one the manifest requires.
#[test]
fn every_dependency_version_in_prose_matches_the_manifest() {
    let manifest = parse_manifest();
    let root = manifest_dir();
    let mut wrong = Vec::new();

    for file in gated_files() {
        if file == "Cargo.toml" {
            continue;
        }
        let text = fs::read_to_string(root.join(&file)).expect("a gated file is UTF-8");
        for line in text.lines() {
            for (name, stated) in dependency_versions(&backticked(line), &manifest.deps) {
                let required = &manifest.deps[&name];
                if describes(required, &stated) {
                    continue;
                }
                if VERSION_EXCEPTIONS
                    .iter()
                    .any(|(dep, value, _)| *dep == name && *value == stated)
                {
                    continue;
                }
                wrong.push(format!(
                    "{file}: `{name}` {stated} but the manifest requires {required} — \
                     in {:?}",
                    line.trim()
                ));
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "dependency versions in prose that the manifest does not require:\n{}",
        wrong.join("\n")
    );
}

// Every version exception names a real dependency, says why, is still not what the
// manifest requires — and is still excusing a line that exists.
//
// The last of those is the one that decays silently: a row whose prose was rewritten or
// deleted goes on passing the other three checks forever, and reads as coverage.
#[test]
fn every_version_exception_justifies_itself() {
    let manifest = parse_manifest();
    let root = manifest_dir();
    let mut stated: Vec<(String, String)> = Vec::new();
    for file in gated_files() {
        if file == "Cargo.toml" {
            continue;
        }
        let text = fs::read_to_string(root.join(&file)).expect("a gated file is UTF-8");
        for line in text.lines() {
            stated.extend(dependency_versions(&backticked(line), &manifest.deps));
        }
    }

    for (dep, value, reason) in VERSION_EXCEPTIONS {
        assert!(
            stated
                .iter()
                .any(|(name, version)| name == dep && version == value),
            "no gated file states `{dep}` {value}, so the exception excuses nothing — \
             delete the row"
        );
        assert!(
            manifest.deps.contains_key(*dep),
            "the exception for `{dep}` {value} names something the manifest no longer \
             depends on"
        );
        assert!(
            reason.len() > 30,
            "the exception for `{dep}` {value} has to say why that version is written"
        );
        assert!(
            !describes(&manifest.deps[*dep], value),
            "`{dep}` {value} is what the manifest requires now — delete the exception"
        );
    }
}

// The HTML pages are read on the same rule as the Markdown, and were not before.
#[test]
fn a_version_written_in_html_is_read_like_one_written_in_markdown() {
    let manifest = parse_manifest();
    let html = "<li><code>system-configuration</code> 0.7 + <code>core-foundation</code> 0.9</li>";
    assert_eq!(
        dependency_versions(&backticked(html), &manifest.deps),
        vec![
            ("system-configuration".to_owned(), "0.7".to_owned()),
            ("core-foundation".to_owned(), "0.9".to_owned()),
        ]
    );
    // The control: unnormalized, the same line states nothing the gate can see, so the
    // normalization is what makes a `docs/*.html` version checkable at all.
    assert!(dependency_versions(html, &manifest.deps).is_empty());
}

// Every exemption names a page that exists, says why, and is still doing work.
//
// A page nobody has decided about needs no row: [`gated_files`] subtracts
// [`EXEMPT_DOCS`] from the directory listing, so a new page is gated by default. That
// leaves the exemptions themselves to check, and asserting the *other* direction —
// that a non-exempt page is gated — asserts only what `gated_files` makes true by
// construction. What matters is whether each exemption is still load-bearing: one for
// a page that would now pass anyway goes on excusing whatever is added there later.
#[test]
fn every_exemption_names_a_page_and_still_earns_it() {
    let pages = doc_pages();
    if pages.is_empty() {
        // No pages — a checkout with no `docs/` at all. A `docs/` that is present and
        // scans to nothing lands here too; that shape is not silently tolerated, it is
        // what `the_gate_reaches_the_whole_tree_that_travels` fails on. Either way every
        // row names a page that is not here, so there is nothing to hold to account. Do
        // not delete the rows to suit such a checkout: they are what gates the pages
        // wherever the pages are present.
        return;
    }
    let manifest = parse_manifest();
    let ci = ci_toolchains();
    let mut authority: BTreeSet<String> = ci;
    authority.insert(manifest.rust_version.clone());

    for (page, reason) in EXEMPT_DOCS {
        assert!(
            pages.iter().any(|existing| existing == page),
            "an exemption row for {page}, which is not in docs/ — the page was renamed \
             or deleted; move the row with it"
        );
        assert!(
            reason.len() > 30,
            "{page} is exempt without saying why it can be"
        );

        let stale_toolchain = mentions(&[(*page).to_string()])
            .into_iter()
            .any(|m| !authority.contains(&m.value));
        let text = read(page);
        let stale_feature = text.lines().any(|line| {
            feature_names(line)
                .iter()
                .any(|name| is_feature_shaped(name) && !manifest.features.contains(name))
        });
        let stale_version = text.lines().any(|line| {
            // `backticked` for the same reason the gate itself uses it: an exempt page is
            // usually HTML, and a version written `<code>0.6</code>` is invisible without
            // it. Reading the raw line here would judge an exemption by a weaker rule than
            // the one it is an exemption from.
            dependency_versions(&backticked(line), &manifest.deps)
                .into_iter()
                .any(|(name, stated)| !describes(&manifest.deps[&name], &stated))
        });
        assert!(
            stale_toolchain || stale_feature || stale_version,
            "{page} is exempt but would pass the gate as it stands — delete the row \
             rather than leaving an exemption that only covers what gets added later"
        );
    }
}

// A tree with no `docs/` is read, not rejected.
#[test]
fn a_tree_without_docs_yields_no_pages_rather_than_panicking() {
    let base =
        std::env::temp_dir().join(format!("proxy-watch-single-source-{}", std::process::id()));
    let present = base.join("with-docs");
    let absent = base.join("without-docs");
    fs::create_dir_all(present.join("docs")).expect("the temporary tree is creatable");
    fs::create_dir_all(&absent).expect("the temporary tree is creatable");
    fs::write(present.join("docs").join("PAGE.html"), "<p>x</p>").expect("the page is writable");
    fs::write(present.join("docs").join("notes.md"), "x").expect("the note is writable");

    // The control. Without a tree that *does* have the directory, "yields nothing" would
    // also pass for a helper that yields nothing whatever it is handed.
    assert_eq!(doc_pages_under(&present), vec!["docs/PAGE.html".to_owned()]);
    assert_eq!(doc_pages_under(&absent), Vec::<String>::new());

    fs::remove_dir_all(&base).ok();
}

// The install line is the one line of the README a reader runs before reading anything
// else, and it restates a name the manifest owns. A rename that reaches `Cargo.toml` and
// not the README leaves a command that fetches the wrong crate or none, and it reads
// correctly to whoever made it — the old name is still the name they have in mind.
#[test]
fn the_readme_installs_the_crate_the_manifest_names() {
    let manifest = read("Cargo.toml");
    let name = manifest
        .lines()
        .map(strip_toml_comment)
        .find(|line| line.trim_start().starts_with("name "))
        .and_then(quoted)
        .expect("Cargo.toml opens with `[package]` and a `name = \"…\"` line");

    let readme = read("README.md");
    let installs: Vec<&str> = readme
        .lines()
        .filter_map(|line| line.split_once("cargo add "))
        .map(|(_, rest)| rest.split_whitespace().next().unwrap_or(""))
        .collect();

    // Every one of them, not merely one: the README installs the crate twice — plainly, and
    // again with the default features off — so a check satisfied by a single line passes
    // while the two disagree.
    assert!(
        !installs.is_empty(),
        "README.md gives a reader no `cargo add` line at all"
    );
    for installed in installs {
        assert_eq!(
            installed, name,
            "Cargo.toml publishes the crate as `{name}`, so `cargo add {installed}` in \
             README.md fetches something else, or nothing"
        );
    }
}

// What the gate covers must not quietly shrink. Everything asserted here is in every
// checkout; the doc pages are the part that need not be, so their presence is tied to the
// directory's rather than assumed either way.
//
// What this cannot see is a `docs/` deleted by mistake — from inside, that is
// indistinguishable from a checkout that never carried one, which is the price of
// supporting the absence.
#[test]
fn the_gate_reaches_the_whole_tree_that_travels() {
    let files = gated_files();
    // `gated_files` seeds its list from `PROSE_FILES`, so asking whether the list contains
    // them answers itself — and asking anyway would read as a check. What is worth asking
    // is whether each one is still a file this gate can read: a `PROSE_FILES` entry that
    // was renamed would otherwise surface as a panic somewhere downstream rather than as
    // the missing coverage it is.
    for prose in PROSE_FILES {
        assert!(
            manifest_dir().join(prose).is_file(),
            "{prose} is listed as gated prose but is not a file — restated prose that \
             travels with the crate has to be readable here or it is not gated at all"
        );
    }
    for dir in ["src/", "tests/", "examples/"] {
        assert!(
            files.iter().any(|f| f.starts_with(dir)),
            "nothing under {dir} is gated, so the scan found no source tree to walk"
        );
    }
    assert_eq!(
        manifest_dir().join("docs").is_dir(),
        !doc_pages().is_empty(),
        "a docs/ that is here scans to nothing, which is the answer a checkout without \
         one gives — the pages were renamed off `.html`, or the walk stopped finding them"
    );
}

// The manifest parser understands the shapes this manifest actually uses.
//
// A parser that silently stopped recognising a table would make every check above
// pass by finding nothing, which is the way a gate dies quietly.
#[test]
fn the_parser_reads_the_shapes_this_manifest_uses() {
    let manifest = parse_manifest();

    assert!(
        !manifest.rust_version.is_empty(),
        "the parser found no `rust-version`"
    );
    assert!(
        manifest.features.len() >= 8,
        "the parser found {} features; the manifest declares more than that",
        manifest.features.len()
    );

    // One of each table shape the manifest uses, so that dropping support for any of
    // them fails here rather than downgrading a check to a no-op.
    for (name, shape) in [
        ("url", "[dependencies] with a bare string"),
        ("futures-core", "[dependencies] with an inline table"),
        ("boa_engine", "[dependencies.name]"),
        ("windows", "[target.'cfg(…)'.dependencies.name]"),
        ("gio", "[target.'cfg(…)'.dependencies] inline table"),
        ("system-configuration", "[target.'cfg(…)'.dependencies]"),
        ("futures-executor", "[dev-dependencies]"),
    ] {
        assert!(
            manifest.deps.contains_key(name),
            "the parser missed `{name}`, which is the only {shape} case here"
        );
    }

    assert_eq!(
        ci_toolchains().len(),
        2,
        "the msrv job's matrix is no longer two rows — check that the parser still \
         reads it before trusting the toolchain check"
    );
}

// `unsafe` is where the README says it is — and nowhere the README does not.
//
// Both directions matter. A new `unsafe` in the OS-independent core would make the
// README's "contain none of their own" false; an allowance that has emptied out
// would make the list of permitted places false in the other direction, and that is
// how this claim broke four rounds running.
#[test]
fn unsafe_lives_only_where_the_readme_says() {
    assert!(
        read("README.md").contains(UNSAFE_CLAIM),
        "the README no longer makes the claim this gate enforces ({UNSAFE_CLAIM:?}) — \
         the sentence was reworded or deleted; update the gate with it"
    );

    let actual = files_using_unsafe();
    let stray: Vec<&String> = actual
        .iter()
        .filter(|file| {
            !UNSAFE_ALLOWED
                .iter()
                .any(|(allowed, _)| file.starts_with(allowed))
        })
        .collect();
    assert!(
        stray.is_empty(),
        "`unsafe` outside the places the README allows: {stray:?}"
    );

    for (allowed, reason) in UNSAFE_ALLOWED {
        assert!(
            reason.len() > 30,
            "the allowance for {allowed} has to say why the OS forces it"
        );
        assert!(
            actual.iter().any(|file| file.starts_with(allowed)),
            "{allowed} is allowed to contain `unsafe` but no longer does — narrow the \
             claim rather than leaving the reader a wider one than the code needs"
        );
    }
}
