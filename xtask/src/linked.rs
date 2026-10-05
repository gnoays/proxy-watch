//! Narrows `cargo about`'s output to the crates a binding artifact links.
//!
//! `cargo about` lists every normal dependency, proc-macros and the crates only they use
//! (`syn`, `quote`, `proc-macro2`, ...) among them. A proc-macro runs inside the compiler and
//! leaves none of its own code in the artifact, so it is no more part of what ships than a
//! build script, which `about.toml` already leaves out. `cargo tree -e normal,no-proc-macro`
//! names what remains; a license block keeps only the crates in that set, and a block left
//! with none is dropped. A crate in that set that no block lists stops the notice: an
//! `about.toml` exclusion or a target `cargo about` resolves differently would otherwise drop
//! its license without a sound.

use std::collections::HashSet;
use std::process::Command;

use crate::repo;

/// `(name, version)` of every crate `proxy-watch-<binding>` links on `target`, except those
/// read from a local path: the workspace's own, which ship under `LICENSE-MIT` and
/// `LICENSE-APACHE` rather than in the notice.
pub(crate) fn crates(binding: &str, target: &str) -> Result<HashSet<(String, String)>, String> {
    let mut cargo = Command::new(env!("CARGO"));
    cargo
        .args([
            "tree",
            "--quiet",
            "--offline",
            "--locked",
            "--manifest-path",
        ])
        .arg(repo().join("Cargo.toml"))
        .args(["--package", &format!("proxy-watch-{binding}")])
        .args(["--target", target])
        .args([
            "--edges",
            "normal,no-proc-macro",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ]);
    let output = cargo.output().map_err(|e| format!("{cargo:?}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{cargo:?} exited with {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let crates: HashSet<_> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let name = words.next()?;
            let version = words.next()?.strip_prefix('v')?;
            // `{p}` appends `(<path>)` to a path crate, `(<url>)` to a git one and `(*)` to
            // a repeat.
            let local = words
                .next()
                .is_some_and(|source| source != "(*)" && !source.contains("://"));
            (!local).then(|| (name.to_owned(), version.to_owned()))
        })
        .collect();
    if crates.is_empty() {
        return Err(format!("{cargo:?} listed no crates"));
    }
    Ok(crates)
}

/// `notice` (rendered through `about.hbs`) with each block's "Used by" list cut to `linked`.
/// A "Used by" line that is not `name version`, or a notice left with no block, is an `Err`:
/// either means `about.hbs` and this parser no longer agree, and every crate would read as
/// unlinked. So is a crate in `linked` that no block lists.
pub(crate) fn keep(notice: &str, linked: &HashSet<(String, String)>) -> Result<String, String> {
    let mut unread = None;
    let mut blocks = 0;
    let mut listed = HashSet::new();
    let kept = rewrite(notice, |_, users, text| {
        let kept: Vec<&str> = users
            .iter()
            .copied()
            .filter(|line| match name_version(line) {
                Some((name, version)) => {
                    let crate_ = (name.to_owned(), version.to_owned());
                    let linked = linked.contains(&crate_);
                    if linked {
                        listed.insert(crate_);
                    }
                    linked
                }
                None => {
                    unread.get_or_insert(line.to_string());
                    false
                }
            })
            .collect();
        blocks += usize::from(!kept.is_empty());
        (!kept.is_empty()).then(|| (kept, text.to_owned()))
    })?;
    if let Some(line) = unread {
        return Err(format!(
            "a \"Used by\" line that is not `name version`: {line:?}"
        ));
    }
    if blocks == 0 {
        return Err("the notice keeps no license block".into());
    }
    let mut missing: Vec<String> = linked
        .difference(&listed)
        .map(|(name, version)| format!("{name} {version}"))
        .collect();
    if !missing.is_empty() {
        missing.sort();
        return Err(format!(
            "linked, but in no license block of `cargo about`'s output: {}",
            missing.join(", ")
        ));
    }
    Ok(kept)
}

/// `notice` with the text of each block whose users are all in `texts`, as
/// `(name, version, text)`, and all map to one text, replaced by that text. A block with any
/// other user keeps what `cargo about` wrote.
pub(crate) fn fill(notice: &str, texts: &[(&str, &str, String)]) -> Result<String, String> {
    rewrite(notice, |_, users, text| {
        let found: Vec<Option<&String>> = users
            .iter()
            .map(|line| {
                let (name, version) = name_version(line)?;
                texts
                    .iter()
                    .find(|(n, v, _)| *n == name && *v == version)
                    .map(|(_, _, text)| text)
            })
            .collect();
        let text = match found.first() {
            Some(Some(first)) if found.iter().all(|other| *other == Some(*first)) => {
                first.to_string()
            }
            _ => text.to_owned(),
        };
        Some((users.to_vec(), text))
    })
}

fn name_version(line: &str) -> Option<(&str, &str)> {
    let mut words = line.split_whitespace();
    Some((words.next()?, words.next()?))
}

/// `notice` with each license block passed through `each(title, users, text)`, which returns
/// the block's users and text, or `None` to drop the block.
fn rewrite<'n>(
    notice: &'n str,
    mut each: impl FnMut(&'n str, &[&'n str], &'n str) -> Option<(Vec<&'n str>, String)>,
) -> Result<String, String> {
    let rule = format!("\n\n{}\n", "=".repeat(80));
    let thin = "-".repeat(80);
    let mut blocks = notice.split(rule.as_str());
    let mut out = blocks.next().unwrap_or_default().to_owned();
    // A template checked out with CRLF line ends renders no `rule`, and every block would pass
    // through unfiltered as the header.
    if out.contains("Used by:") {
        return Err(
            "the notice's license blocks did not split; `about.hbs` must have LF line ends".into(),
        );
    }
    for block in blocks {
        let (head, text) = block
            .split_once(&format!("\n{thin}\n"))
            .ok_or("a license block without its text")?;
        let (title, users) = head
            .split_once("\n\nUsed by:\n")
            .ok_or("a license block without its users")?;
        let users: Vec<&str> = users.lines().collect();
        if let Some((users, text)) = each(title, &users, text) {
            out.push_str(&format!(
                "{rule}{title}\n\nUsed by:\n{}\n{thin}\n{text}",
                users.join("\n")
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(title: &str, users: &[&str], text: &str) -> String {
        format!(
            "\n\n{}\n{title}\n\nUsed by:\n{}\n{}\n{text}",
            "=".repeat(80),
            users.join("\n"),
            "-".repeat(80)
        )
    }

    #[test]
    fn keep_drops_unlinked_users_and_emptied_blocks() {
        let notice = format!(
            "Third-party licenses\n\nheader{}{}",
            block(
                "MIT License (MIT)",
                &["  url 2.5.8", "  syn 2.0.1"],
                "mit text\n"
            ),
            block(
                "Unicode License v3 (Unicode-3.0)",
                &["  unicode-ident 1.0.0"],
                "uni\n"
            ),
        );
        let linked = HashSet::from([("url".to_owned(), "2.5.8".to_owned())]);
        let kept = keep(&notice, &linked).unwrap();
        assert!(kept.starts_with("Third-party licenses\n\nheader"));
        assert!(kept.contains("  url 2.5.8") && kept.contains("mit text"));
        assert!(!kept.contains("syn") && !kept.contains("Unicode"));
    }

    #[test]
    fn keep_matches_the_version_too() {
        let notice = format!(
            "{}{}",
            block("MIT License (MIT)", &["  hashbrown 0.15.0"], "t\n"),
            block("ISC License (ISC)", &["  url 2.5.8"], "u\n")
        );
        let linked = HashSet::from([("url".to_owned(), "2.5.8".to_owned())]);
        assert!(!keep(&notice, &linked).unwrap().contains("hashbrown"));
    }

    #[test]
    fn keep_refuses_a_linked_crate_no_block_lists() {
        let notice = format!(
            "{}{}",
            block("MIT License (MIT)", &["  hashbrown 0.15.0"], "t\n"),
            block("ISC License (ISC)", &["  url 2.5.8"], "u\n")
        );
        let linked = HashSet::from([
            ("hashbrown".to_owned(), "0.17.1".to_owned()),
            ("url".to_owned(), "2.5.8".to_owned()),
        ]);
        let error = keep(&notice, &linked).unwrap_err();
        assert!(error.contains("hashbrown 0.17.1") && !error.contains("url"));
    }

    #[test]
    fn keep_refuses_a_user_line_it_cannot_read_and_an_emptied_notice() {
        let linked = HashSet::from([("url".to_owned(), "2.5.8".to_owned())]);
        let unread = block("MIT License (MIT)", &["  url 2.5.8", "  syn"], "t\n");
        assert!(keep(&unread, &linked).is_err());
        let emptied = block("MIT License (MIT)", &["  url v2.5.8"], "t\n");
        assert!(keep(&emptied, &linked).is_err());
    }

    #[test]
    fn fill_replaces_a_text_only_when_every_user_maps_to_it() {
        let canonical = "Copyright (c) <year> <copyright holders>\n";
        let notice = format!(
            "header{}{}",
            block(
                "MIT License (MIT)",
                &["  napi 3.13.0", "  napi-sys 3.3.2"],
                canonical
            ),
            block(
                "MIT License (MIT)",
                &["  napi 3.13.0", "  other 1.0.0"],
                canonical
            ),
        );
        let upstream = "Copyright (c) 2020-present A\n".to_owned();
        let texts = [
            ("napi", "3.13.0", upstream.clone()),
            ("napi-sys", "3.3.2", upstream.clone()),
        ];
        let filled = fill(&notice, &texts).unwrap();
        assert_eq!(filled.matches(upstream.as_str()).count(), 1);
        assert_eq!(filled.matches(canonical).count(), 1);
        assert!(filled.contains("  other 1.0.0\n--------"));
        // Another version of a listed crate is not filled.
        let texts = [
            ("napi", "3.12.0", upstream.clone()),
            ("napi-sys", "3.3.2", upstream),
        ];
        assert_eq!(fill(&notice, &texts).unwrap(), notice);
    }

    #[test]
    fn keep_refuses_blocks_it_cannot_split() {
        let notice = format!(
            "header{}",
            block("MIT License (MIT)", &["  syn 2.0.1"], "t\n")
        )
        .replace('\n', "\r\n");
        let linked = HashSet::from([("url".to_owned(), "2.5.8".to_owned())]);
        assert!(keep(&notice, &linked).is_err());
    }
}
