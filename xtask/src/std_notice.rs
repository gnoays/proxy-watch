//! The Rust standard library's part of a binding artifact's third-party notice.
//!
//! Every artifact links `std`, `core`, `alloc` and the crates they depend on, and `cargo about`
//! sees none of them: they are not in the Cargo graph. This section names them for one target
//! and carries their license texts, from three places in the toolchain that builds the
//! artifact, so the notice and the binary come from the same release:
//!
//! - `lib/rustlib/<target>/lib/*.rlib`: which crates the standard library has on that target.
//!   Windows has no `addr2line`, `object` or `miniz_oxide`, for one.
//! - `lib/rustlib/src/rust/library` (the `rust-src` component): the vendored crates' own
//!   license files and `compiler-builtins`' license, which `COPYRIGHT-library.html` leaves out,
//!   and the notices written into in-tree sources taken from other projects.
//! - `share/doc/rust/COPYRIGHT-library.html` and `share/doc/rust/licenses/`: the in-tree
//!   files' copyright holders and the texts of their licenses.
//!
//! An update that moves any of these fails the rendering instead of shipping a notice that
//! skips a crate.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Sysroot rlibs that a `cdylib` or `staticlib` does not link: the test harness, the compiler's
/// proc-macro bridge, their dependencies, the profiler runtime, and the workspace shims.
const NOT_LINKED: [&str; 6] = [
    "getopts",
    "proc_macro",
    "profiler_builtins",
    "rustc_literal_escaper",
    "sysroot",
    "test",
];

/// The section for `target`, to be appended after the `cargo about` output.
pub(crate) fn render(target: &str) -> Result<String, String> {
    let sysroot = PathBuf::from(rustc(&["--print", "sysroot"])?);
    let lib = sysroot.join("lib/rustlib").join(target).join("lib");
    let library = sysroot.join("lib/rustlib/src/rust/library");
    let doc = sysroot.join("share/doc/rust");
    if !lib.is_dir() {
        return Err(format!(
            "{}: no standard library (`rustup target add {target}` installs it)",
            lib.display()
        ));
    }
    if !library.is_dir() {
        return Err(format!(
            "{}: no standard library sources (`rustup component add rust-src` installs them)",
            library.display()
        ));
    }
    let vendor = library.join("vendor");
    if !vendor.is_dir() {
        return Err(format!(
            "{}: the vendored crates are missing; `rust-src` ships `library/vendor` from Rust 1.97 \
             (`rustup update` installs it)",
            vendor.display()
        ));
    }
    let crates = linked_crates(&lib)?;
    let mut vendored = Vec::new();
    let mut in_tree = Vec::new();
    for name in &crates {
        match vendored_dir(&vendor, name)? {
            Some(found) => vendored.push(found),
            None => in_tree.push(name.as_str()),
        }
    }
    check_in_tree(&in_tree, &vendor)?;
    if vendored.is_empty() {
        return Err(format!(
            "{}: no `<name>-<version>` directory matches a linked crate; the layout of `library/vendor` has moved",
            vendor.display()
        ));
    }
    let entries = in_tree_entries(&read(&doc.join("COPYRIGHT-library.html"))?)?;

    let rule = "=".repeat(80);
    let thin = "-".repeat(80);
    let mut out = format!(
        "\n{rule}\nThe Rust standard library\n\n\
         This artifact links the Rust standard library built for {target}, from {}.\n\
         In-tree crates: {}.\n\
         The crates it vendors from crates.io are listed after the in-tree files, each with its \
         own license text.\n\n\
         In-tree files, as the Rust release lists them:\n",
        rustc(&["-V"])?,
        in_tree.join(", ")
    );
    // The release ships one text per license id, as an SPDX template whose copyright line is a
    // placeholder. It is quoted as shipped: the listing above says which holder goes with which
    // file, and filling the template per id would put each holder under every license of the
    // files it shares an id with.
    let mut ids: Vec<String> = Vec::new();
    for entry in &entries {
        out.push_str(&format!(
            "\n  {}\n    License: {}\n",
            entry.path, entry.license
        ));
        for holder in &entry.copyright {
            out.push_str(&format!("    Copyright: {holder}\n"));
        }
        for id in chosen(&entry.license) {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    for id in &ids {
        let template = read(&doc.join("licenses").join(format!("{id}.txt")))?;
        out.push_str(&format!(
            "\n{thin}\n{id}, as the Rust release ships it for the in-tree files above\n{thin}\n{template}"
        ));
    }
    for (file, notice) in source_notices(&library, &in_tree)? {
        out.push_str(&format!(
            "\n{thin}\nlibrary/{file}: its notice, as written in the source\n{thin}\n{notice}"
        ));
    }

    // `compiler_builtins` is in-tree but carries licenses of its own: MIT for its Rust code,
    // Apache-2.0 WITH LLVM-exception for what derives from LLVM's compiler-rt, and MIT for the
    // `libm` it contains, whose license file also names musl's copyright holders.
    if in_tree.contains(&"compiler_builtins") {
        for (file, title) in [
            (
                "LICENSE.txt",
                "compiler_builtins (MIT AND Apache-2.0 WITH LLVM-exception)",
            ),
            ("libm/LICENSE.txt", "libm, inside compiler_builtins (MIT)"),
        ] {
            let text = read(&library.join("compiler-builtins").join(file))?;
            out.push_str(&format!("\n{thin}\n{title}\n{thin}\n{text}"));
        }
        for (notice, files) in libm_notices(&library)? {
            out.push_str(&format!(
                "\n{thin}\nlibm, inside compiler_builtins: the notice written in\n  library/{}\n{thin}\n{notice}",
                files.join("\n  library/")
            ));
        }
    }

    for (dir, name, version) in &vendored {
        let license = manifest_license(&dir.join("Cargo.toml"))?;
        if license.contains(" AND ") || license.contains(" WITH ") {
            return Err(format!(
                "{name} {version}: `{license}` obliges more than the MIT text this notice quotes"
            ));
        }
        if !license
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .any(|term| term == "MIT")
        {
            return Err(format!("{name} {version}: `{license}` offers no MIT terms"));
        }
        let text = ["LICENSE-MIT", "LICENSE-MIT.md", "LICENSE-MIT.txt"]
            .iter()
            .map(|file| dir.join(file))
            .find(|path| path.is_file())
            .ok_or_else(|| format!("{}: no MIT license file", dir.display()))?;
        let mut section = format!(
            "\n{thin}\n{name} {version} ({license}; taken under MIT)\n{thin}\n{}",
            read(&text)?
        );
        for extra in extra_notices(dir, &text)? {
            let shown = extra.strip_prefix(dir).unwrap_or(&extra).display();
            section.push_str(&format!(
                "\n{thin}\n{name} {version}: {shown}\n{thin}\n{}",
                read(&extra)?
            ));
        }
        // adler2's MIT file names no holder; its `LICENSE-0BSD` does. A crate whose files name
        // none at all needs a decision about where its notice comes from.
        if !has_copyright_line(&section) {
            return Err(format!(
                "{name} {version}: no copyright line in its license files"
            ));
        }
        out.push_str(&section);
    }
    Ok(out)
}

/// The compiler binary of the sysroot this notice quotes. A build given it as `RUSTC` is built
/// by the release the notice names, whatever `CARGO_BUILD_RUSTC` or `build.rustc` would pick.
pub(crate) fn rustc_binary() -> Result<PathBuf, String> {
    let sysroot = PathBuf::from(rustc(&["--print", "sysroot"])?);
    let binary = sysroot
        .join("bin")
        .join(format!("rustc{}", std::env::consts::EXE_SUFFIX));
    if !binary.is_file() {
        return Err(format!("{}: no compiler in the sysroot", binary.display()));
    }
    Ok(binary)
}

/// What `rustc` (or `$RUSTC`) prints for `args`. The sysroot and the version come from the
/// same compiler, so the notice names the release whose files it quotes.
fn rustc(args: &[&str]) -> Result<String, String> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(&rustc)
        .args(args)
        .output()
        .map_err(|e| format!("rustc {}: {e}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "rustc {} exited with {}",
            args.join(" "),
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// The crates the standard library builds from its own tree. A linked crate outside this list
/// and outside `library/vendor` has no license text here, so it stops the rendering: either
/// the vendored layout moved or the library gained an in-tree crate that needs a decision.
const IN_TREE: [&str; 9] = [
    "alloc",
    "compiler_builtins",
    "core",
    "panic_abort",
    "panic_unwind",
    "std",
    "std_detect",
    "unwind",
    "windows_link",
];

fn check_in_tree(in_tree: &[&str], vendor: &Path) -> Result<(), String> {
    let unknown: Vec<&str> = in_tree
        .iter()
        .copied()
        .filter(|name| !IN_TREE.contains(name))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{}: no `<name>-<version>` directory for {}, and {} not among the in-tree crates",
        vendor.display(),
        unknown.join(", "),
        if unknown.len() == 1 {
            "it is"
        } else {
            "they are"
        }
    ))
}

/// The crate names of the rlibs in `lib`, minus [`NOT_LINKED`] and the `rustc-std-workspace-*`
/// shims, which hold no code.
fn linked_crates(lib: &Path) -> Result<Vec<String>, String> {
    let mut crates = Vec::new();
    for entry in std::fs::read_dir(lib).map_err(|e| format!("{}: {e}", lib.display()))? {
        let name = entry
            .map_err(|e| format!("{}: {e}", lib.display()))?
            .file_name()
            .into_string()
            .map_err(|name| format!("{}: file name {name:?} is not Unicode", lib.display()))?;
        let Some(stem) = name
            .strip_prefix("lib")
            .and_then(|rest| rest.strip_suffix(".rlib"))
        else {
            continue;
        };
        let name = stem.rsplit_once('-').map_or(stem, |(name, _)| name);
        if !NOT_LINKED.contains(&name) && !name.starts_with("rustc_std_workspace_") {
            crates.push(name.to_owned());
        }
    }
    crates.sort();
    crates.dedup();
    if !crates.iter().any(|name| name == "std") {
        return Err(format!("{}: no `std` rlib", lib.display()));
    }
    Ok(crates)
}

/// `vendor/<name>-<version>` with its crate name and version, for either the `-` or the `_`
/// spelling of `name`; `None` for an in-tree crate.
fn vendored_dir(vendor: &Path, name: &str) -> Result<Option<(PathBuf, String, String)>, String> {
    let spellings = [name.to_owned(), name.replace('_', "-")];
    let mut found = Vec::new();
    for entry in std::fs::read_dir(vendor).map_err(|e| format!("{}: {e}", vendor.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let Ok(dir) = entry.file_name().into_string() else {
            continue;
        };
        for spelling in &spellings {
            let version = dir
                .strip_prefix(spelling.as_str())
                .and_then(|rest| rest.strip_prefix('-'))
                .filter(|version| version.starts_with(|c: char| c.is_ascii_digit()));
            if let Some(version) = version {
                found.push((entry.path(), spelling.clone(), version.to_owned()));
                break;
            }
        }
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => Err(format!("{name}: more than one vendored version")),
    }
}

/// Whether `text` has a line that starts with `Copyright`: a holder's notice, as opposed to the
/// license body's "the above copyright notice" and "COPYRIGHT HOLDERS".
fn has_copyright_line(text: &str) -> bool {
    text.lines()
        .any(|line| line.trim_start().starts_with("Copyright"))
}

/// The files of a vendored crate that carry notices beyond its MIT text: those whose name
/// contains `copyright`, `licence`, `license`, `author` or `notice` in any case, and everything
/// under a directory so named. The rule is the one the Rust release's own copyright listing
/// uses. Apache-named files stay out: the crate is taken under MIT, and Apache's `NOTICE`
/// duty follows its own terms.
fn extra_notices(dir: &Path, mit: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    collect_notices(dir, false, mit, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_notices(
    dir: &Path,
    inside: bool,
    mit: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_lowercase();
        let named = ["copyright", "licence", "license", "author", "notice"]
            .iter()
            .any(|word| name.contains(word));
        if path.is_dir() {
            if named || inside {
                collect_notices(&path, true, mit, files)?;
            }
        } else if (named || inside) && path != mit && !name.contains("apache") {
            files.push(path);
        }
    }
    Ok(())
}

fn manifest_license(manifest: &Path) -> Result<String, String> {
    read(manifest)?
        .lines()
        .find_map(|line| {
            let value = line
                .strip_prefix("license")?
                .trim_start()
                .strip_prefix('=')?;
            Some(value.trim().trim_matches('"').to_owned())
        })
        .ok_or_else(|| format!("{}: no `license`", manifest.display()))
}

struct Entry {
    path: String,
    license: String,
    copyright: Vec<String>,
}

/// The "In-tree files" section of `COPYRIGHT-library.html`: one entry per file or directory,
/// in the order the release lists them.
fn in_tree_entries(html: &str) -> Result<Vec<Entry>, String> {
    let start = html
        .find("id=\"in-tree-files\"")
        .ok_or("COPYRIGHT-library.html: no in-tree-files section")?;
    let end = html[start..]
        .find("id=\"out-of-tree-dependencies\"")
        .map_or(html.len(), |end| start + end);
    let mut entries: Vec<Entry> = Vec::new();
    for line in html[start..end].lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("<b>File/Directory:</b> <code>") {
            let path = rest.split("</code>").next().unwrap_or(rest);
            entries.push(Entry {
                path: unescape(path),
                license: String::new(),
                copyright: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("<p><b>License:</b> ") {
            let entry = entries.last_mut().ok_or("License before File/Directory")?;
            if !entry.license.is_empty() {
                return Err(format!(
                    "COPYRIGHT-library.html: {} has two licenses",
                    entry.path
                ));
            }
            entry.license = unescape(rest.trim_end_matches("</p>"));
        } else if let Some(rest) = line.strip_prefix("<p><b>Copyright:</b> ") {
            let entry = entries
                .last_mut()
                .ok_or("Copyright before File/Directory")?;
            entry
                .copyright
                .push(unescape(rest.trim_end_matches("</p>")));
        }
    }
    if entries.is_empty() || entries.iter().any(|e| e.license.is_empty()) {
        return Err("COPYRIGHT-library.html: the in-tree-files section did not parse".into());
    }
    Ok(entries)
}

/// The licenses whose texts an SPDX expression obliges: every `AND` term, and from each `OR`
/// group the MIT arm when there is one, else the first.
fn chosen(expression: &str) -> Vec<String> {
    expression
        .split(" AND ")
        .map(|term| term.trim().trim_start_matches('(').trim_end_matches(')'))
        .map(|group| {
            let arms: Vec<&str> = group.split(" OR ").map(str::trim).collect();
            arms.iter()
                .find(|arm| **arm == "MIT")
                .unwrap_or(&arms[0])
                .to_string()
        })
        .collect()
}

/// The in-tree files, under `library/`, whose sources carry a copyright notice of their own:
/// code taken from crossbeam-channel, Fuchsia's libsync and rust-memchr. A file joining or
/// leaving this set stops the rendering, so a new notice is read before it ships.
const SOURCE_NOTICES: [&str; 3] = [
    "core/src/slice/memchr.rs",
    "std/src/sync/mpmc/mod.rs",
    "std/src/sys/sync/mutex/fuchsia.rs",
];

/// Each notice in the sources of the in-tree crates other than `compiler_builtins`, whose
/// license files are quoted whole: `(path under library/, the comment block holding a line
/// that starts with Copyright, with its comment markers removed)`.
fn source_notices(library: &Path, in_tree: &[&str]) -> Result<Vec<(String, String)>, String> {
    let mut files = Vec::new();
    for name in in_tree.iter().filter(|name| **name != "compiler_builtins") {
        let src = library.join(name).join("src");
        if !src.is_dir() {
            return Err(format!("{}: no sources for `{name}`", src.display()));
        }
        collect_rs(&src, &mut files)?;
    }
    files.sort();
    let mut notices = Vec::new();
    for path in &files {
        let shown = path
            .strip_prefix(library)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        for text in notices_in(path)? {
            notices.push((shown.clone(), text));
        }
    }
    let found: Vec<&str> = notices.iter().map(|(file, _)| file.as_str()).collect();
    let mut expected: Vec<&str> = SOURCE_NOTICES
        .iter()
        .copied()
        .filter(|file| {
            in_tree
                .iter()
                .any(|name| file.starts_with(&format!("{name}/")))
        })
        .collect();
    expected.sort();
    if found != expected {
        return Err(format!(
            "{}: the in-tree sources with a copyright notice are {found:?}, not {expected:?}",
            library.display()
        ));
    }
    Ok(notices)
}

/// The line comment marker `line` starts with, longest first.
fn comment_prefix(line: &str) -> Option<&'static str> {
    let line = line.trim_start();
    ["//!", "///", "//"]
        .into_iter()
        .find(|prefix| line.starts_with(prefix))
}

/// Each copyright notice in `path`: the comment holding a line that starts with Copyright,
/// with its comment markers removed. A line comment's notice is the run of lines with the
/// same marker; a block comment's runs from its `/*` to its `*/`.
fn notices_in(path: &Path) -> Result<Vec<String>, String> {
    let source = read(path)?;
    let lines: Vec<&str> = source.lines().collect();
    let mut notices = Vec::new();
    let mut at = 0;
    while at < lines.len() {
        let line = lines[at].trim_start();
        if !line
            .trim_start_matches(['/', '!', '*'])
            .trim_start()
            .starts_with("Copyright")
        {
            at += 1;
            continue;
        }
        let (end, text) = if let Some(prefix) = comment_prefix(line) {
            let in_block = |line: &str| comment_prefix(line) == Some(prefix);
            let start = (0..at)
                .rev()
                .take_while(|&i| in_block(lines[i]))
                .last()
                .unwrap_or(at);
            let end = (at..lines.len())
                .find(|&i| !in_block(lines[i]))
                .unwrap_or(lines.len());
            let text: Vec<&str> = lines[start..end]
                .iter()
                .map(|line| {
                    let body = line.trim_start().strip_prefix(prefix).unwrap_or_default();
                    body.strip_prefix(' ').unwrap_or(body)
                })
                .collect();
            (end, text)
        } else if line.starts_with(['/', '*']) {
            let unclosed = || {
                format!(
                    "{}:{}: a copyright line outside a closed comment",
                    path.display(),
                    at + 1
                )
            };
            let start = (0..=at)
                .rev()
                .find(|&i| lines[i].contains("/*"))
                .ok_or_else(unclosed)?;
            if lines[start..at].iter().any(|line| line.contains("*/")) {
                return Err(unclosed());
            }
            let end = (at..lines.len())
                .find(|&i| lines[i].contains("*/"))
                .ok_or_else(unclosed)?
                + 1;
            let text: Vec<&str> = lines[start..end]
                .iter()
                .map(|line| {
                    let body = line.trim();
                    let body = body.strip_suffix("*/").unwrap_or(body);
                    let body = body
                        .strip_prefix("/*")
                        .or_else(|| body.strip_prefix('*'))
                        .unwrap_or(body);
                    body.strip_prefix(' ').unwrap_or(body).trim_end()
                })
                .collect();
            (end, text)
        } else {
            return Err(format!(
                "{}:{}: a copyright line that is neither a line comment nor in a block comment's `*` lines",
                path.display(),
                at + 1
            ));
        };
        notices.push(format!("{}\n", text.join("\n").trim_matches('\n')));
        at = end;
    }
    Ok(notices)
}

/// The notices in `libm`'s sources, each text once with the files under `library/` that carry
/// it. `libm/LICENSE.txt` names Sun Microsystems and FreeBSD's authors only in summary; their
/// terms (Sun's "provided that this notice is preserved", a BSD clause that a binary
/// reproduce the notice) and CORE-MATH's holders are in the sources. All of them are quoted:
/// which `libm` functions a target's `compiler_builtins` exports differs by target, and the C
/// binding's static library carries every object of `compiler_builtins`.
fn libm_notices(library: &Path) -> Result<Vec<(String, Vec<String>)>, String> {
    let src = library.join("compiler-builtins/libm/src");
    let mut files = Vec::new();
    collect_rs(&src, &mut files)?;
    files.sort();
    let mut notices: Vec<(String, Vec<String>)> = Vec::new();
    for path in &files {
        let shown = path
            .strip_prefix(library)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let found = notices_in(path)?;
        // A notice the parser does not recognise, `Copyright` mid-line among them, stops the
        // rendering instead of leaving its file out.
        if found.is_empty() && read(path)?.contains("Copyright") {
            return Err(format!(
                "{}: `Copyright` in a form no notice is read from",
                path.display()
            ));
        }
        for text in found {
            match notices.iter_mut().find(|(known, _)| *known == text) {
                Some((_, carriers)) => carriers.push(shown.clone()),
                None => notices.push((text, vec![shown.clone()])),
            }
        }
    }
    if notices.is_empty() {
        return Err(format!(
            "{}: no copyright notice in `libm`'s sources; its layout has moved",
            src.display()
        ));
    }
    Ok(notices)
}

fn collect_rs(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.is_dir() {
            collect_rs(&path, files)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn unescape(text: &str) -> String {
    text.replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&#60;", "<")
        .replace("&#62;", ">")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chosen_takes_mit_from_each_or_group_and_every_and_term() {
        assert_eq!(chosen("Apache-2.0 OR MIT"), ["MIT"]);
        assert_eq!(chosen("Unicode-3.0"), ["Unicode-3.0"]);
        assert_eq!(
            chosen("BSD-2-Clause AND (Apache-2.0 OR MIT)"),
            ["BSD-2-Clause", "MIT"]
        );
    }

    /// A `library/vendor` with one directory per name in `dirs`, under a fresh temp dir.
    fn vendor_with(tag: &str, dirs: &[&str]) -> PathBuf {
        let root = std::env::temp_dir().join(format!("std-notice-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in dirs {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        root
    }

    #[test]
    fn vendored_dir_matches_either_spelling_and_only_a_version() {
        let vendor = vendor_with("match", &["rustc-demangle-0.1.24", "std-detect-0.1.5"]);
        let found = vendored_dir(&vendor, "rustc_demangle").unwrap().unwrap();
        assert_eq!(
            (found.1.as_str(), found.2.as_str()),
            ("rustc-demangle", "0.1.24")
        );
        // `std` is a prefix of `std-detect-…`, whose tail does not start with a digit.
        assert!(vendored_dir(&vendor, "std").unwrap().is_none());
        assert!(vendored_dir(&vendor, "gimli").unwrap().is_none());
        std::fs::remove_dir_all(&vendor).unwrap();
    }

    #[test]
    fn a_copyright_line_is_a_holder_not_the_license_body() {
        let body = "Permission is hereby granted\n\nThe above copyright notice and this\n\
                    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE\n";
        assert!(!has_copyright_line(body));
        assert!(has_copyright_line(&format!("Copyright (C) A\n{body}")));
        assert!(has_copyright_line(
            "MIT License\n\n  Copyright (c) 2015 B\n"
        ));
    }

    /// Renders the notice from the installed toolchain for `$STD_NOTICE_TARGET` (default: the
    /// host): `RUSTC=<rustc> cargo test -- --ignored installed_toolchain --nocapture
    /// --test-threads=1`. Reads only.
    #[test]
    #[ignore = "needs a toolchain with rust-src and the target's std"]
    fn installed_toolchain_renders() {
        let host = rustc(&["-vV"]).unwrap();
        let host = host
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .unwrap()
            .to_owned();
        let target = std::env::var("STD_NOTICE_TARGET").unwrap_or(host);
        let notice = render(&target).unwrap();
        assert!(notice.contains("hashbrown") && notice.contains("In-tree crates:"));
        println!("{notice}");
    }

    #[test]
    fn vendored_dir_refuses_two_versions() {
        let vendor = vendor_with("two", &["hashbrown-0.15.2", "hashbrown-0.16.0"]);
        assert!(vendored_dir(&vendor, "hashbrown").is_err());
        std::fs::remove_dir_all(&vendor).unwrap();
    }

    #[test]
    fn extra_notices_take_named_files_and_named_directories_but_not_apache() {
        let root = vendor_with("extra", &["licenses", "src", "other"]);
        for file in [
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "NOTICE",
            "AUTHORS",
            "Cargo.toml",
            "licenses/inner.txt",
            "src/license.rs",
            "other/x.txt",
        ] {
            std::fs::write(root.join(file), "x").unwrap();
        }
        let found = extra_notices(&root, &root.join("LICENSE-MIT")).unwrap();
        let found: Vec<_> = found
            .iter()
            .map(|path| {
                path.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(found, ["AUTHORS", "NOTICE", "licenses/inner.txt"]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_in_tree_crate_outside_the_list_stops_the_rendering() {
        let vendor = Path::new("vendor");
        assert!(check_in_tree(&["core", "std", "compiler_builtins"], vendor).is_ok());
        let err = check_in_tree(&["core", "hashbrown"], vendor).unwrap_err();
        assert!(err.contains("hashbrown") && !err.contains("core,"));
    }

    /// A `library` holding `files` (path under `library/`, contents), under a fresh temp dir.
    fn library_with(tag: &str, files: &[(&str, &str)]) -> PathBuf {
        let root = vendor_with(tag, &["core/src", "std/src"]);
        for (file, text) in files {
            let path = root.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        root
    }

    #[test]
    fn source_notices_quote_the_whole_comment_block_without_markers() {
        let library = library_with(
            "sources",
            &[
                (
                    SOURCE_NOTICES[0],
                    "// Taken from x.\n// Copyright 2015 A\n\nuse y;\n",
                ),
                (
                    SOURCE_NOTICES[1],
                    "//! ```\n\n// From z:\n//\n// Copyright (c) B\n//\n// Permission\nmod a;\n",
                ),
                (
                    SOURCE_NOTICES[2],
                    "//! Doc.\n//!\n//!    Copyright C.\n//! ok\nuse z;\n",
                ),
                (
                    "std/src/plain.rs",
                    "// The above copyright notice\nfn f() {}\n",
                ),
            ],
        );
        let notices = source_notices(&library, &["core", "std"]).unwrap();
        let texts: Vec<&str> = notices.iter().map(|(_, text)| text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "Taken from x.\nCopyright 2015 A\n",
                "From z:\n\nCopyright (c) B\n\nPermission\n",
                "Doc.\n\n   Copyright C.\nok\n",
            ]
        );
        std::fs::remove_dir_all(&library).unwrap();
    }

    #[test]
    fn a_source_notice_joining_or_leaving_the_set_stops_the_rendering() {
        let notice = "// Copyright A\n";
        let library = library_with(
            "sources-moved",
            &[
                (SOURCE_NOTICES[0], notice),
                (SOURCE_NOTICES[1], notice),
                (SOURCE_NOTICES[2], notice),
                ("core/src/new.rs", notice),
            ],
        );
        assert!(source_notices(&library, &["core", "std"]).is_err());
        std::fs::write(library.join("core/src/new.rs"), "").unwrap();
        std::fs::write(library.join(SOURCE_NOTICES[1]), "").unwrap();
        assert!(source_notices(&library, &["core", "std"]).is_err());
        std::fs::write(library.join(SOURCE_NOTICES[1]), "/* Copyright A */\n").unwrap();
        assert!(source_notices(&library, &["core", "std"]).is_ok());
        std::fs::remove_dir_all(&library).unwrap();
    }

    #[test]
    fn libm_notices_read_block_comments_and_list_each_text_once() {
        let sun = "/* origin: FreeBSD a.c */\n/*\n * ====\n * Copyright (C) 1993 by Sun.\n *\n * \
                   Permission is granted, provided that this notice\n * is preserved.\n * ====\n \
                   */\n/* a(x) */\nfn a() {}\n";
        let library = library_with(
            "libm",
            &[
                ("compiler-builtins/libm/src/math/a.rs", sun),
                ("compiler-builtins/libm/src/math/b.rs", sun),
                (
                    "compiler-builtins/libm/src/math/c.rs",
                    "/* SPDX-License-Identifier: MIT */\n/* origin: core-math c.c\n * Copyright (c) 2022 S.\n */\n\nfn c() {}\n",
                ),
                ("compiler-builtins/libm/src/math/d.rs", "fn d() {}\n"),
            ],
        );
        let notices = libm_notices(&library).unwrap();
        assert_eq!(
            notices,
            [
                (
                    "====\nCopyright (C) 1993 by Sun.\n\nPermission is granted, provided that \
                     this notice\nis preserved.\n====\n"
                        .to_owned(),
                    vec![
                        "compiler-builtins/libm/src/math/a.rs".to_owned(),
                        "compiler-builtins/libm/src/math/b.rs".to_owned()
                    ]
                ),
                (
                    "origin: core-math c.c\nCopyright (c) 2022 S.\n".to_owned(),
                    vec!["compiler-builtins/libm/src/math/c.rs".to_owned()]
                ),
            ]
        );
        std::fs::write(
            library.join("compiler-builtins/libm/src/math/d.rs"),
            "/* x */\n * Copyright B\n",
        )
        .unwrap();
        assert!(libm_notices(&library).is_err());
        // A block whose lines carry no `*`, and a holder named mid-line.
        for unread in ["/*\nCopyright B\n*/\n", "/* (C) Copyright B */\n"] {
            std::fs::write(library.join("compiler-builtins/libm/src/math/d.rs"), unread).unwrap();
            assert!(libm_notices(&library).is_err(), "{unread:?}");
        }
        std::fs::remove_dir_all(&library).unwrap();
    }

    #[test]
    fn in_tree_entries_refuses_a_second_license_for_one_entry() {
        let html = "<h2 id=\"in-tree-files\">x</h2>
            <b>File/Directory:</b> <code>a</code>
            <p><b>License:</b> MIT</p>
            <p><b>License:</b> Unicode-3.0</p>
";
        assert!(in_tree_entries(html).is_err());
    }

    #[test]
    fn in_tree_entries_reads_paths_licenses_and_holders() {
        let html = "<h2 id=\"in-tree-files\">In-tree files</h2>\n\
            <b>File/Directory:</b> <code>.</code>\n\
            <p><b>License:</b> Apache-2.0 OR MIT</p>\n\
            <p><b>Copyright:</b> The Rust Project Developers</p>\n\
            <b>File/Directory:</b> <code>library/core/src/unicode/unicode_data.rs</code>\n\
            <p><b>License:</b> Unicode-3.0</p>\n\
            <p><b>Copyright:</b> 1991-2024 Unicode, Inc</p>\n\
            <h2 id=\"out-of-tree-dependencies\">\n\
            <b>File/Directory:</b> <code>ignored</code>\n";
        let entries = in_tree_entries(html).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].path, "library/core/src/unicode/unicode_data.rs");
        assert_eq!(entries[1].license, "Unicode-3.0");
        assert_eq!(entries[0].copyright, ["The Rust Project Developers"]);
    }
}
