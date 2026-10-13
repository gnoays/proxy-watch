//! KDE: read/watch `kioslaverc` (`linux-kde`: pure Rust `notify` + `configparser`).
//!
//! File-based on purpose: see [`super::kioslaverc`] (KIO 6 → libproxy `config-kde`).
//! Watches the **directory** (not the inode): KConfig atomic rename would orphan a file
//! watch; also catches a first-time create, in the directories that exist when the watch
//! is set up (`watch::watch_targets` drops the rest). Like `KSharedConfig::openConfig` with
//! `KConfig::CascadeConfig`, files from `XDG_CONFIG_DIRS` through `XDG_CONFIG_HOME` are
//! applied from least to most specific ([`search_dirs`] / `watch::watch_targets`).
//!
//! A `kioslaverc` that is a symlink is read through the link, but only its directory is
//! watched, so an edit to a target in another directory fires nothing and the watch still
//! reports itself live. `poll_now_re_reads_a_change_no_watch_can_see` in
//! `tests/linux_watch.rs` uses that as its fixture; `WatchOptions::poll_interval`
//! is the remedy.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::error::Error;

use super::Env;
use super::desktop::Reading;
use super::kioslaverc::{self, FILE_NAME, KdeConfig, KioslavercSettings};

mod watch;

pub(crate) use watch::{FileWatch, LossFlags, watch};

// `XDG_CONFIG_DIRS`: the colon separated, left-to-right priority list of *system*
// configuration directories (XDG Base Directory Specification). Unset, empty, or left with
// nothing after [`search_dirs`] drops the relative entries defaults to the single entry
// [`DEFAULT_CONFIG_DIRS`].
const XDG_CONFIG_DIRS: &str = "XDG_CONFIG_DIRS";

// `XDG_CONFIG_DIRS`'s default, per the XDG Base Directory Specification.
const DEFAULT_CONFIG_DIRS: &str = "/etc/xdg";

// The ordered list of directories [`read_store`] and [`watch`] look for `kioslaverc` in.
fn search_dirs(
    xdg_config_home: Option<&OsStr>,
    home: Option<&OsStr>,
    xdg_config_dirs: Option<&OsStr>,
) -> Vec<PathBuf> {
    // A relative path is not a location: it resolves against the process's current
    // directory, so a watcher built before a `chdir` would go on watching one directory
    // while re-reading another. The XDG Base Directory Specification requires it to be
    // ignored, "All paths set in these environment variables must be absolute. If an
    // implementation encounters a relative path in any of these variables it should
    // consider the path invalid and ignore it", and ignoring `XDG_CONFIG_HOME` means
    // falling back to `$HOME/.config`, which is why this takes the first *usable* of the
    // two rather than filtering afterwards. `HOME` is held to the same rule because
    // `$HOME/.config` inherits whatever it held.
    let mut dirs: Vec<PathBuf> = non_empty(xdg_config_home)
        .map(PathBuf::from)
        .into_iter()
        .chain(non_empty(home).map(|home| Path::new(home).join(".config")))
        .find(|dir| dir.is_absolute())
        .into_iter()
        .collect();

    // Split on raw bytes rather than through `str`, which would reject a non-UTF-8 path.
    let mut system: Vec<PathBuf> = non_empty(xdg_config_dirs)
        .unwrap_or_else(|| OsStr::new(DEFAULT_CONFIG_DIRS))
        .as_bytes()
        .split(|&b| b == b':')
        .filter(|entry| !entry.is_empty())
        .map(|entry| PathBuf::from(OsStr::from_bytes(entry)))
        .filter(|dir| dir.is_absolute())
        .collect();
    // An `XDG_CONFIG_DIRS` whose every entry was dropped is as good as unset.
    if system.is_empty() {
        system.push(PathBuf::from(DEFAULT_CONFIG_DIRS));
    }

    // `dirs.contains` scans a vector this loop is filling; `BypassRules::dedup_patterns`
    // and `parse_find_proxy_result` use indexed deduplication. The quadratic scan is
    // acceptable here because every surviving directory requires a `kioslaverc` open on
    // each read and watcher wake. A list long enough for deduplication to matter is already
    // too expensive to walk once. `XDG_CONFIG_DIRS` is written only by the process
    // launcher; the other three sources are a remote script, a registry value set by group
    // policy, and a `configd` array.
    for candidate in system {
        if !dirs.contains(&candidate) {
            dirs.push(candidate);
        }
    }
    dirs
}

// `value`, unless it is absent or the empty string, the shared "unset or empty" rule
// `XDG_CONFIG_HOME` and `XDG_CONFIG_DIRS` both follow.
//
// No input can observe it, because the empty string fails every downstream test as well:
// `""` is not an absolute path, and an `XDG_CONFIG_DIRS` of `""` splits into one empty
// entry that the split's own filter drops. It says the spec's rule in the spec's words
// rather than leaving it to be inferred from three separate guards.
fn non_empty(value: Option<&OsStr>) -> Option<&OsStr> {
    value.filter(|v| !v.is_empty())
}

// [`search_dirs`], reading `env`.
fn config_search_dirs(env: &Env) -> Vec<PathBuf> {
    search_dirs(
        env.var_os("XDG_CONFIG_HOME").as_deref(),
        env.var_os("HOME").as_deref(),
        env.var_os(XDG_CONFIG_DIRS).as_deref(),
    )
}

struct KioslavercRead {
    settings: KioslavercSettings,
    // Outside the tests the only reader is the `layers =` trace in [`read_store`], which
    // expands to `()` with `tracing` off, so in that build the field has no
    // reader. It is kept rather than cfg-ed away because the tests assert which layers the
    // cascade walked, and `settings` alone cannot show that.
    #[cfg_attr(not(feature = "tracing"), allow(dead_code))]
    paths: Vec<PathBuf>,
    found_proxy_settings: bool,
}

// Read every existing layer from least to most specific, matching KConfig's cascade.
// A file-level immutable marker ends the cascade before any more-specific file is read.
//
// A layer that exists but cannot be read ends the whole read with an `Err`, rather than
// being skipped like a missing one. The layers overwrite each other key by key, so a
// dropped layer does not leave a gap a caller could see; it leaves a different answer,
// and one that looks exactly like a correct one. Refusing to answer is the only outcome
// that stays distinguishable.
fn read_kioslaverc(dirs: Vec<PathBuf>) -> Result<Option<KioslavercRead>, Error> {
    let mut settings = KioslavercSettings::new();
    let mut paths = Vec::new();
    let mut found_proxy_settings = false;

    for dir in dirs.into_iter().rev() {
        let path = dir.join(FILE_NAME);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let outcome = apply_proxy_settings(&text, &path, &mut settings)?;
                found_proxy_settings |= outcome.found_proxy_settings;
                paths.push(path);
                if outcome.file_immutable {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(Error::io(format!("reading {}", path.display()), error)),
        }
    }

    Ok((!paths.is_empty()).then_some(KioslavercRead {
        settings,
        paths,
        found_proxy_settings,
    }))
}

// Read and interpret `kioslaverc`.
pub(crate) fn read_store(env: &Env) -> Result<Reading, Error> {
    let Some(read) = read_kioslaverc(config_search_dirs(env))? else {
        return Ok(Reading::Absent);
    };

    // Which absence, not which answer: entries are stored only while the scanner is inside
    // the section, so no section found means an empty store, and an empty store carries no
    // `ProxyType` for `configured_from_kioslaverc` to read; the arm below reaches the same
    // `Unset`. Distinguishing them lets the debug line avoid reporting a file that has no
    // `[Proxy Settings]` at all as one that merely sets no `ProxyType`.
    if !read.found_proxy_settings {
        return Ok(Reading::Unset);
    }
    Ok(
        // `var_os`, not `var().ok()`: the latter cannot tell an unset variable from one
        // holding bytes that are not UTF-8, and `env_mode` divides on that.
        match kioslaverc::configured_from_kioslaverc(&read.settings, |name: &str| env.var_os(name))?
        {
            Some(KdeConfig { source, mode }) => Reading::configured(source, mode),
            None => {
                crate::trace::debug!(
                    layers = read.paths.len(),
                    "kioslaverc carries no ProxyType; the KDE store is unconfigured"
                );
                Reading::Unset
            }
        },
    )
}

// Build the `configparser::ini::Ini` parser [`proxy_settings`] reads `kioslaverc`
// with.
fn kioslaverc_ini() -> configparser::ini::Ini {
    // `IniDefault` is `#[non_exhaustive]`, so the fields are set on an owned instance
    // rather than through a struct literal.
    let mut defaults = configparser::ini::IniDefault::default();
    defaults.case_sensitive = true;
    defaults.comment_symbols = vec!['#'];
    defaults.enable_inline_comments = false;
    // KConfigIniBackend recognises `=`, not configparser's additional default `:`.
    // Keeping validation and the sequential scanner on the same delimiter avoids
    // accepting a row the scanner would then interpret as valueless.
    defaults.delimiters = vec!['='];
    configparser::ini::Ini::new_from_defaults(defaults)
}

// One group header line, read as `KConfigIniBackend::parseConfig` reads it
// (`kconfigini.cpp`, KF5 and KF6 alike): bracketed parts, each up to the first `]`, joined
// with `\x1d` into a subgroup path while the next character is `[`; anything after the last
// part is ignored. A part is exactly `$i` only when it is the line's last bracket: then it
// marks the file immutable if it comes first, the group otherwise. A part is taken as
// written (`printableToString` trims and unescapes only a part holding a backslash), so
// `[ Proxy Settings ]` names a group KDE never reads, and `[Proxy Settings][$e]` names a
// subgroup of it. `None` for a line with no closing `]`, which KConfig skips.
struct GroupHeader {
    name: String,
    file_immutable: bool,
    group_immutable: bool,
}

fn group_header(line: &str) -> Option<GroupHeader> {
    let bytes = line.as_bytes();
    let mut header = GroupHeader {
        name: String::new(),
        file_immutable: false,
        group_immutable: false,
    };
    let mut start = 1;
    loop {
        let end = start + bytes.get(start..)?.iter().position(|&byte| byte == b']')?;
        let part = &line[start..end];
        if end + 1 == bytes.len() && part == "$i" {
            if header.name.is_empty() {
                header.file_immutable = true;
            } else {
                header.group_immutable = true;
            }
        } else {
            if !header.name.is_empty() {
                header.name.push('\x1d');
            }
            if part.contains('\\') {
                header
                    .name
                    .push_str(&printable_to_string(part.trim_ascii()));
            } else {
                header.name.push_str(part);
            }
        }
        start = end + 2;
        if start > bytes.len() || bytes[end + 1] != b'[' {
            return Some(header);
        }
    }
}

// Reverse `KConfigIniBackend::stringToPrintable`'s escaping (`kconfigini.cpp`) for one
// `[Proxy Settings]` value.
fn printable_to_string(raw: &str) -> String {
    // printableToString's own fast path: a value with no backslash at all is untouched.
    if !raw.contains('\\') {
        return raw.to_owned();
    }

    let chars: Vec<char> = raw.chars().collect();
    let len = chars.len();
    // Bytes, not characters, because `\x` names a byte: upstream unescapes into a
    // `QByteArray` and only then reads the whole thing as UTF-8. `\xc3\xa9` is one 'é'
    // there and would be two Latin-1 characters if each escape became a `char` here --
    // a different spelling of the same host, which matches nothing and says so nowhere.
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < len {
        if chars[i] != '\\' {
            push_char(&mut out, chars[i]);
            i += 1;
            continue;
        }
        if i + 1 >= len {
            // A lone trailing backslash is kept literally, as upstream does.
            out.push(b'\\');
            break;
        }
        match chars[i + 1] {
            's' => {
                out.push(b' ');
                i += 2;
            }
            't' => {
                out.push(b'\t');
                i += 2;
            }
            'n' => {
                out.push(b'\n');
                i += 2;
            }
            'r' => {
                out.push(b'\r');
                i += 2;
            }
            '\\' => {
                out.push(b'\\');
                i += 2;
            }
            ';' => {
                // Not a real escape (`.desktop` compatibility): written back out as the
                // same two characters, neither expanded nor stripped.
                out.extend_from_slice(b"\\;");
                i += 2;
            }
            ',' => {
                out.extend_from_slice(b"\\,");
                i += 2;
            }
            'x' => {
                if i + 3 < len {
                    match (chars[i + 2].to_digit(16), chars[i + 3].to_digit(16)) {
                        (Some(hi), Some(lo)) => out.push((hi * 16 + lo) as u8),
                        _ => {
                            warn_invalid_hex_escape();
                            out.push(b'x');
                        }
                    }
                    i += 4;
                } else {
                    // Fewer than two digits remain before the value ends: `x` is
                    // substituted and the partial digit, if any, is discarded.
                    out.push(b'x');
                    i = len;
                }
            }
            unknown => {
                // Upstream parts company here, and this is the one arm that is not a
                // port of it. `printableToString` writes the backslash, warns, and
                // returns `false`; its caller counts the error and stores the entry
                // anyway, half-converted, and un-truncated because the early return
                // skips the final `truncate`. Handing the value back exactly as written
                // is the only outcome that is never half of two readings, and it does
                // not smuggle anything through: every reader that names a destination
                // either refuses a backslash, `crate::endpoint::parse_host` and
                // `HostPattern::parse` both count it a forbidden host character, so the
                // value lands in `rejected`, or carries it into what it reports, which
                // is `parse_script_location` percent-encoding it so the `file:` URL names
                // the path KDE stored rather than one a `\` separator invented.
                warn_unknown_kconfig_escape(unknown);
                return raw.to_owned();
            }
        }
    }
    // `QString::fromUtf8` is what upstream finishes with, and it substitutes U+FFFD for a
    // byte sequence that is not UTF-8 rather than refusing the value.
    String::from_utf8_lossy(&out).into_owned()
}

fn push_char(out: &mut Vec<u8>, c: char) {
    let mut buf = [0u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}

// Log-only sink for an unrecognised `\X` escape [`printable_to_string`] gives up on.
// `escape` is a single character, never a secret on its own, so it is safe to log even
// though the value it came from may be a password.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
fn warn_unknown_kconfig_escape(escape: char) {
    crate::trace::warning!(
        escape = %escape,
        "kioslaverc: unrecognized KConfig escape sequence in a value; leaving it as written"
    );
}

// Log-only sink for a `\x` escape whose following characters are not both valid hex
// digits.
fn warn_invalid_hex_escape() {
    crate::trace::warning!(
        "kioslaverc: invalid hex digits in a \\x escape; substituting a literal 'x'"
    );
}

// Pull and sequentially apply every `[Proxy Settings]` occurrence in a `kioslaverc`.
// KConfig flags are stateful: `$i` refuses later writes and `$d` deletes an earlier key.
// Parsing into configparser's HashMaps first would irreversibly lose the file order needed
// for both rules, so configparser is retained only as the syntax validator.
#[cfg(test)]
fn proxy_settings(text: &str, path: &Path) -> Result<Option<KioslavercSettings>, Error> {
    let mut settings = KioslavercSettings::new();
    let outcome = apply_proxy_settings(text, path, &mut settings)?;
    Ok(outcome.found_proxy_settings.then_some(settings))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ApplyOutcome {
    found_proxy_settings: bool,
    file_immutable: bool,
}

// Apply one file to an existing cascade. KConfig defers a group-immutable marker until
// the end of its file: repeated sections in that file still contribute entries, while
// every more-specific file is locked out.
fn apply_proxy_settings(
    text: &str,
    path: &Path,
    settings: &mut KioslavercSettings,
) -> Result<ApplyOutcome, Error> {
    let mut ini = kioslaverc_ini();
    ini.read(text.to_owned()).map_err(|reason| {
        Error::io(
            format!("parsing {}", path.display()),
            io::Error::new(io::ErrorKind::InvalidData, reason),
        )
    })?;

    let mut in_proxy_settings = false;
    let group_was_immutable = settings.group_is_immutable();
    let mut current_group_immutable = false;
    let mut pending_group_immutable = false;
    let mut file_immutable = false;
    let mut found = false;

    for line in text.lines() {
        let trimmed = line.trim_ascii();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Every trim in this loop is the ASCII one on purpose. `kconfigini.cpp` reads the
        // file as bytes and trims with `QByteArrayView::trimmed()`, which Qt documents as
        // recognising "only ASCII spacing characters"
        // (<https://doc.qt.io/qt-6/qbytearray.html#spacing-characters>). Stripping a
        // U+00A0 or U+3000 that KDE keeps would make this crate honour a proxy setting
        // the desktop it is reporting on ignores, which is the worse of the two wrong
        // answers. A UTF-8 BOM ahead of a first-line `[Proxy Settings]` therefore also
        // defeats the header: U+FEFF is not whitespace on either side, and KConfig
        // carries no BOM handling anywhere. Do not add BOM stripping for the same reason.
        if trimmed.starts_with('[') {
            let Some(header) = group_header(trimmed) else {
                // KConfig warns and skips the line, staying in the group it was in, but
                // only after resetting the group's lock to the file's, which it does first.
                current_group_immutable = in_proxy_settings && file_immutable;
                continue;
            };
            file_immutable |= header.file_immutable;
            in_proxy_settings = header.name == kioslaverc::SECTION;
            // `file_immutable ||` is this function stating its own half of the rule, and no
            // input can observe it: the only caller that walks more than one file,
            // [`read_kioslaverc`], stops on the same flag, so the entries this marks are
            // never offered to a later file. It stays because the sentence above is a
            // contract about `apply_proxy_settings`: a caller that read on rather than
            // breaking would need this term, and would get no test failure if it
            // were gone.
            current_group_immutable =
                in_proxy_settings && (file_immutable || header.group_immutable);
            pending_group_immutable |= current_group_immutable;
            found |= in_proxy_settings;
            continue;
        }

        if !in_proxy_settings || group_was_immutable {
            continue;
        }

        // On `trimmed`, like every test above it: the section test and the comment test
        // both run on the trimmed line, and a row that split on the raw one would disagree
        // with them about what the file says. Trimming the key half here as well would be
        // the same rule in a second place; [`kioslaverc::normalize_key`] already does it,
        // and it is the one function every reader of a key goes through.
        let (raw_key, value) = match trimmed.split_once('=') {
            Some((key, value)) => (key, Some(printable_to_string(value.trim_ascii()))),
            None => (trimmed, None),
        };
        // A valueless `$d` is how KConfig serializes a deletion. Other valueless rows
        // carry no setting and are ignored.
        if value.is_some() || kioslaverc::has_kconfig_flag(raw_key, 'd') {
            settings.apply(raw_key, value, current_group_immutable);
        }
    }

    if pending_group_immutable {
        settings.mark_group_immutable();
    }
    Ok(ApplyOutcome {
        found_proxy_settings: found,
        file_immutable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::ProxyConfigSource;
    use crate::endpoint::Scheme;
    use crate::mode::ProxyMode;

    // ----------------------------------------------------------------------------
    // search_dirs: pure, so no real filesystem or environment involved.
    // ----------------------------------------------------------------------------

    #[test]
    fn search_dirs_respects_xdg_config_home_dirs_and_defaults() {
        // `XDG_CONFIG_HOME`, `HOME`, `XDG_CONFIG_DIRS`, the whole expected list.
        type Case<'a> = (
            Option<&'a OsStr>,
            Option<&'a OsStr>,
            Option<&'a OsStr>,
            &'a [PathBuf],
        );

        let cases: &[Case<'_>] = &[
            (
                Some(OsStr::new("/home/alice/.config")),
                Some(OsStr::new("/home/alice")),
                Some(OsStr::new("/etc/xdg/kde:/usr/local/etc/xdg")),
                &[
                    PathBuf::from("/home/alice/.config"),
                    PathBuf::from("/etc/xdg/kde"),
                    PathBuf::from("/usr/local/etc/xdg"),
                ],
            ),
            // Unset and empty `XDG_CONFIG_HOME` both derive `$HOME/.config`, and it leads.
            // `/etc/xdg` follows it because `XDG_CONFIG_DIRS` is unset here too -- these two
            // rows say what the *whole* list is, not just what its head is.
            (
                None,
                Some(OsStr::new("/home/alice")),
                None,
                &[
                    PathBuf::from("/home/alice/.config"),
                    PathBuf::from("/etc/xdg"),
                ],
            ),
            (
                Some(OsStr::new("")),
                Some(OsStr::new("/home/alice")),
                None,
                &[
                    PathBuf::from("/home/alice/.config"),
                    PathBuf::from("/etc/xdg"),
                ],
            ),
            (
                Some(OsStr::new("/home/alice/.config")),
                None,
                None,
                &[
                    PathBuf::from("/home/alice/.config"),
                    PathBuf::from("/etc/xdg"),
                ],
            ),
            (
                Some(OsStr::new("/home/alice/.config")),
                None,
                Some(OsStr::new("")),
                &[
                    PathBuf::from("/home/alice/.config"),
                    PathBuf::from("/etc/xdg"),
                ],
            ),
            (
                None,
                None,
                Some(OsStr::new("/etc/xdg::/opt/xdg:")),
                &[PathBuf::from("/etc/xdg"), PathBuf::from("/opt/xdg")],
            ),
            (
                Some(OsStr::new("/home/alice/.config")),
                None,
                Some(OsStr::new("/etc/xdg:/etc/xdg:/opt/xdg")),
                &[
                    PathBuf::from("/home/alice/.config"),
                    PathBuf::from("/etc/xdg"),
                    PathBuf::from("/opt/xdg"),
                ],
            ),
            // A daemon with a scrubbed environment: no user directory to derive, but the
            // system-wide default is still searched.
            (
                None,
                None,
                Some(OsStr::new("/etc/xdg")),
                &[PathBuf::from("/etc/xdg")],
            ),
            (None, None, None, &[PathBuf::from(DEFAULT_CONFIG_DIRS)]),
            // A relative path is invalid, not a path to resolve. Ignoring
            // `XDG_CONFIG_HOME` leaves `$HOME/.config` to be derived, exactly as an unset
            // one would -- so `relative/kioslaverc` under the current directory is never
            // opened, and the user layer is not lost either.
            (
                Some(OsStr::new("relative")),
                Some(OsStr::new("/home/alice")),
                None,
                &[
                    PathBuf::from("/home/alice/.config"),
                    PathBuf::from("/etc/xdg"),
                ],
            ),
            // With nothing absolute to fall back to, the user layer drops out rather than
            // becoming a directory that means something different after a `chdir`.
            (
                Some(OsStr::new("relative")),
                Some(OsStr::new("also/relative")),
                None,
                &[PathBuf::from("/etc/xdg")],
            ),
            (
                None,
                Some(OsStr::new("relative")),
                None,
                &[PathBuf::from("/etc/xdg")],
            ),
            // A relative entry is dropped from the list, and a list left with nothing
            // falls back the same way an unset one does.
            (
                None,
                None,
                Some(OsStr::new("relative:/opt/xdg:./also")),
                &[PathBuf::from("/opt/xdg")],
            ),
            (
                None,
                None,
                Some(OsStr::new("relative:./also")),
                &[PathBuf::from("/etc/xdg")],
            ),
        ];
        for (xdg_config_home, home, xdg_config_dirs, expected) in cases {
            let dirs = search_dirs(*xdg_config_home, *home, *xdg_config_dirs);
            assert_eq!(
                dirs, *expected,
                "for {xdg_config_home:?}, {home:?}, {xdg_config_dirs:?}"
            );
        }
    }

    // Build `<temp>/proxy-watch-kde-<name>-<pid>/{a,b,c,…}`, creating the directories
    // named in `existing` and a `kioslaverc` in each directory named in `holding`.
    // Returns the root plus the full candidate list, existing or not.
    pub(super) fn fixture(
        name: &str,
        candidates: &[&str],
        existing: &[&str],
        holding: &[&str],
    ) -> Fixture {
        let root =
            std::env::temp_dir().join(format!("proxy-watch-kde-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in existing {
            std::fs::create_dir_all(root.join(dir)).expect("creating a fixture directory");
        }
        for dir in holding {
            std::fs::write(
                root.join(dir).join(FILE_NAME),
                "[Proxy Settings]\nProxyType=0\n",
            )
            .expect("creating a fixture kioslaverc");
        }
        Fixture {
            dirs: candidates.iter().map(|dir| root.join(dir)).collect(),
            root,
        }
    }

    pub(super) struct Fixture {
        pub(super) root: PathBuf,
        pub(super) dirs: Vec<PathBuf>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    // A realistic file, complete with the KConfig flags a generic INI parser keeps.
    const SAMPLE: &str = "\
[$Version]
update_info=kioslave.upd:kioslave

[Proxy Settings][$i]
ProxyType=1
httpProxy=http://proxy.corp:8080
httpsProxy=proxy.corp 3128
NoProxyFor=localhost,.corp.example
ReversedException=false
Proxy Config Script[$e]=/home/alice/proxy.pac
";

    #[test]
    fn the_flagged_section_and_keys_are_found() {
        let settings = proxy_settings(SAMPLE, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings][$i] is the section");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        assert_eq!(config.source, ProxyConfigSource::Kioslaverc);
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "proxy.corp:8080"
        );
        assert_eq!(
            config.mode.endpoint_for(Scheme::Https).unwrap().authority(),
            "proxy.corp:3128"
        );
    }

    // KConfig applies physical rows in file order. The second row replaces the first and
    // then `$i` freezes the logical key.
    #[test]
    fn a_later_immutable_spelling_replaces_an_earlier_value() {
        let text = "\
[Proxy Settings]
ProxyType=1
httpProxy=http://unflagged.corp:8080
httpProxy[$i]=http://flagged.corp:9090
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings] is the section");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "flagged.corp:9090"
        );
    }

    #[test]
    fn an_immutable_entry_refuses_a_later_unflagged_write() {
        let text = "\
[Proxy Settings]
ProxyType[$i]=1
ProxyType=0
httpProxy=proxy.corp:8080
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings] is present");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "proxy.corp:8080"
        );
    }

    // The group marker freezes the keys it covered, not only the group. The *group* lock is
    // deferred to the end of the file, so a repeated section in that same file is still read;
    // what stops it overwriting the administrator's value is the immutability the marker put
    // on the entry itself. Nothing else in this file observes that argument, a later file
    // is refused by the deferred group lock instead.
    #[test]
    fn a_group_marker_freezes_its_keys_against_a_later_section_in_the_same_file() {
        let text = "\
[Proxy Settings][$i]
ProxyType=1
httpProxy=locked.corp:8080

[Proxy Settings]
httpProxy=later.corp:9090
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings] is present");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "locked.corp:8080"
        );
    }

    #[test]
    fn a_deleted_entry_does_not_survive_as_an_older_proxy() {
        let text = "\
[Proxy Settings]
ProxyType=1
httpProxy=old.corp:8080
httpProxy[$d]
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings] is present");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        assert!(config.mode.endpoint_for(Scheme::Http).is_none());
    }

    // The row above only shows the deleted value not coming back, which a blank would do
    // too. A deletion is not a blank: `[$d]` removes the key, so the slot was never named
    // and no entry is filed for it, while `httpProxy=` names the slot with nothing in it
    // and files `Disabled`. Both route direct, so only the map tells them apart, and that
    // is the difference between "KDE turned this scheme's proxy off" and "KDE says nothing
    // about this scheme". Another slot has to carry a proxy for either to be visible at
    // all: with nothing left in the map `manual_mode` answers `Direct` whichever way this
    // goes.
    #[test]
    fn a_deleted_entry_is_not_a_blank_one() {
        let mode_after = |last_row: &str| {
            let text = format!(
                "[Proxy Settings]\nProxyType=1\nftpProxy=ftp.corp:2121\nhttpProxy=old.corp:8080\n{last_row}\n"
            );
            let settings = proxy_settings(&text, Path::new("kioslaverc"))
                .unwrap()
                .expect("[Proxy Settings] is present");
            kioslaverc::config_from_kioslaverc(&settings, |_| None)
                .unwrap()
                .mode
        };
        assert!(
            mode_after("httpProxy[$d]")
                .entry_for(Scheme::Http)
                .is_none()
        );
        assert!(matches!(
            mode_after("httpProxy=").entry_for(Scheme::Http),
            Some(crate::endpoint::ProxyEntry::Disabled)
        ));
    }

    // KConfig reads a flag suffix left to right and stops at `d`, so the immutability counts
    // only when `i` comes first. `[$di]` is what KConfig's own writer emits for an immutable
    // deletion, and reads back as a plain one; reading it as immutable would refuse a value
    // KDE applies and answer Direct where the desktop proxies.
    #[test]
    fn an_immutable_deletion_refuses_a_later_recreation_only_when_i_comes_first() {
        let http_after = |flags: &str| {
            let text = format!(
                "[Proxy Settings]\nProxyType=1\nhttpProxy=old.corp:8080\nhttpProxy[{flags}]\n\
                 httpProxy=new.corp:9090\n"
            );
            let settings = proxy_settings(&text, Path::new("kioslaverc"))
                .unwrap()
                .expect("[Proxy Settings] is present");
            kioslaverc::config_from_kioslaverc(&settings, |_| None)
                .unwrap()
                .mode
                .endpoint_for(Scheme::Http)
                .map(|endpoint| endpoint.authority())
        };
        assert_eq!(http_after("$id"), None);
        assert_eq!(http_after("$di").as_deref(), Some("new.corp:9090"));
        assert_eq!(http_after("$d").as_deref(), Some("new.corp:9090"));
    }

    #[test]
    fn a_normal_duplicate_key_uses_the_last_value() {
        let text = "\
[Proxy Settings]
ProxyType=1
httpProxy=first.corp:8080
httpProxy=last.corp:9090
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings] is present");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "last.corp:9090"
        );
    }

    #[test]
    fn an_expansion_flag_never_reads_or_expands_the_environment() {
        let text = "\
[Proxy Settings]
ProxyType=1
httpProxy[$e]=$PROXY_WATCH_KDE_TEST:8080
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings] is present");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| {
            panic!("ProxyType=1 must not consult the environment")
        })
        .unwrap();
        assert!(config.mode.endpoint_for(Scheme::Http).is_none());
        assert_eq!(
            config.mode.rejected().unwrap()[0].redacted_input(),
            "$PROXY_WATCH_KDE_TEST:8080"
        );
    }

    #[test]
    fn repeated_logical_sections_are_merged_in_file_order() {
        let text = "\
[Proxy Settings]
ProxyType=1
httpProxy=first.corp:8080

[Other]
value=ignored

[Proxy Settings]
httpsProxy=second.corp:8443
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings] is present");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "first.corp:8080"
        );
        assert_eq!(
            config.mode.endpoint_for(Scheme::Https).unwrap().authority(),
            "second.corp:8443"
        );
    }

    #[test]
    fn more_specific_files_override_normal_system_values() {
        let f = fixture("cascade", &["home", "etc"], &["home", "etc"], &[]);
        std::fs::write(
            f.dirs[1].join(FILE_NAME),
            "[Proxy Settings]\nProxyType=1\nhttpProxy=system.corp:8080\n",
        )
        .unwrap();
        std::fs::write(
            f.dirs[0].join(FILE_NAME),
            "[Proxy Settings]\nhttpProxy=user.corp:9090\n",
        )
        .unwrap();

        let read = read_kioslaverc(f.dirs.clone()).unwrap().unwrap();
        assert_eq!(
            read.paths,
            vec![f.dirs[1].join(FILE_NAME), f.dirs[0].join(FILE_NAME)]
        );
        let config = kioslaverc::config_from_kioslaverc(&read.settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "user.corp:9090"
        );
    }

    #[test]
    fn system_immutable_entry_refuses_a_user_override() {
        let f = fixture("immutable-entry", &["home", "etc"], &["home", "etc"], &[]);
        std::fs::write(
            f.dirs[1].join(FILE_NAME),
            "[Proxy Settings]\nProxyType=1\nhttpProxy[$i]=system.corp:8080\n",
        )
        .unwrap();
        std::fs::write(
            f.dirs[0].join(FILE_NAME),
            "[Proxy Settings]\nhttpProxy=user.corp:9090\n",
        )
        .unwrap();

        let read = read_kioslaverc(f.dirs.clone()).unwrap().unwrap();
        let config = kioslaverc::config_from_kioslaverc(&read.settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "system.corp:8080"
        );
    }

    #[test]
    fn system_immutable_group_refuses_existing_and_new_user_keys() {
        let f = fixture("immutable-group", &["home", "etc"], &["home", "etc"], &[]);
        std::fs::write(
            f.dirs[1].join(FILE_NAME),
            "[Proxy Settings][$i]\nProxyType=1\nhttpProxy=system.corp:8080\n",
        )
        .unwrap();
        std::fs::write(
            f.dirs[0].join(FILE_NAME),
            "[Proxy Settings]\nhttpProxy=user.corp:9090\nhttpsProxy=user.corp:9443\n",
        )
        .unwrap();

        let read = read_kioslaverc(f.dirs.clone()).unwrap().unwrap();
        let config = kioslaverc::config_from_kioslaverc(&read.settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "system.corp:8080"
        );
        assert!(config.mode.endpoint_for(Scheme::Https).is_none());
    }

    // The group lock is deferred to the end of the file, so `pending_group_immutable`
    // accumulates rather than following the last header it saw: a `[Proxy Settings][$i]`
    // and then a plain `[Proxy Settings]` in the same file must still lock the group.
    // Tracking the last header instead lets the administrator's lock be undone by an
    // unflagged repetition of its own group, which is what KConfig writes whenever a
    // second component appends a key to a file that already has the section.
    //
    // The test above cannot see that: the marker also marks the entries it covered, so a
    // user file rewriting the *same* keys is refused either way. Only a key the system file
    // never named separates the group lock from the per-entry one.
    #[test]
    fn a_repeated_group_after_the_marker_does_not_unlock_it() {
        let f = fixture(
            "immutable-group-again",
            &["home", "etc"],
            &["home", "etc"],
            &[],
        );
        std::fs::write(
            f.dirs[1].join(FILE_NAME),
            "[Proxy Settings][$i]\nProxyType=1\nhttpProxy=system.corp:8080\n\n\
             [Proxy Settings]\nhttpProxy=system.corp:8080\n",
        )
        .unwrap();
        std::fs::write(
            f.dirs[0].join(FILE_NAME),
            "[Proxy Settings]\nhttpsProxy=user.corp:9443\n",
        )
        .unwrap();

        let read = read_kioslaverc(f.dirs.clone()).unwrap().unwrap();
        let config = kioslaverc::config_from_kioslaverc(&read.settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "system.corp:8080"
        );
        assert!(
            config.mode.endpoint_for(Scheme::Https).is_none(),
            "a slot the locked group never named is still refused"
        );
    }

    // Whether a `[Proxy Settings]` group was seen is a fold over the whole cascade, not the
    // most-specific layer's own answer, and the two differ on an ordinary KDE desktop:
    // `~/.config/kioslaverc` carries a great deal that has nothing to do with proxying, so a
    // user layer that exists and names no proxy group is the common case rather than a
    // contrived one. [`read_store`] turns a `false` here straight into [`Reading::Unset`]
    // without ever asking what `ProxyType` the merged settings hold: the equivalence its
    // comment argues (no group means an empty store means no `ProxyType`) is true of one
    // file and false across a cascade. Folded per-layer instead of accumulated, the machine
    // below reports no KDE configuration at all and sends its traffic straight past the
    // proxy its administrator set.
    #[test]
    fn a_user_layer_without_the_group_does_not_unfind_the_system_layer() {
        let f = fixture("group-fold", &["home", "etc"], &["home", "etc"], &[]);
        std::fs::write(
            f.dirs[1].join(FILE_NAME),
            "[Proxy Settings]\nProxyType=1\nhttpProxy=system.corp:8080\n",
        )
        .unwrap();
        std::fs::write(
            f.dirs[0].join(FILE_NAME),
            "[General]\nBrowserApplication=firefox\n",
        )
        .unwrap();

        let read = read_kioslaverc(f.dirs.clone()).unwrap().unwrap();
        assert!(
            read.found_proxy_settings,
            "the system layer named the group: {:?}",
            read.paths
        );
        let config = kioslaverc::config_from_kioslaverc(&read.settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "system.corp:8080"
        );
    }

    #[test]
    fn system_file_immutable_marker_ends_the_cascade() {
        let f = fixture("immutable-file", &["home", "etc"], &["home", "etc"], &[]);
        std::fs::write(
            f.dirs[1].join(FILE_NAME),
            "[Proxy Settings]\nProxyType=1\nhttpProxy=system.corp:8080\n\n[$i]\n",
        )
        .unwrap();
        std::fs::write(
            f.dirs[0].join(FILE_NAME),
            "[Proxy Settings]\nhttpProxy=user.corp:9090\n",
        )
        .unwrap();

        let read = read_kioslaverc(f.dirs.clone()).unwrap().unwrap();
        assert_eq!(read.paths, vec![f.dirs[1].join(FILE_NAME)]);
        let config = kioslaverc::config_from_kioslaverc(&read.settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "system.corp:8080"
        );
    }

    // KConfig takes a bracketed part as written, so `[ $i ]` is a group named ` $i `, not the
    // file marker: it locks nothing, and the user layer above reads on. Treating it as the
    // marker would answer with a lock the desktop does not apply.
    #[test]
    fn a_padded_file_immutable_marker_is_an_ordinary_group() {
        let f = fixture(
            "immutable-file-padded",
            &["home", "etc"],
            &["home", "etc"],
            &[],
        );
        std::fs::write(
            f.dirs[1].join(FILE_NAME),
            "[Proxy Settings]\nProxyType=1\nhttpProxy=system.corp:8080\n\n[ $i ]\n",
        )
        .unwrap();
        std::fs::write(
            f.dirs[0].join(FILE_NAME),
            "[Proxy Settings]\nhttpProxy=user.corp:9090\n",
        )
        .unwrap();

        let read = read_kioslaverc(f.dirs.clone()).unwrap().unwrap();
        assert_eq!(read.paths.len(), 2, "{:?}", read.paths);
        let config = kioslaverc::config_from_kioslaverc(&read.settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "user.corp:9090"
        );
    }

    // Group headers as `kconfigini.cpp` reads them: anything after the closing `]` is ignored
    // (so the section still opens, losing it reads a proxied desktop as unconfigured), a
    // second bracket that is not a final `$i` names a subgroup, and padding inside the
    // brackets is part of the name.
    #[test]
    fn a_group_header_is_read_as_kconfig_reads_it() {
        let opens = |header: &str| {
            let text = format!("{header}\nProxyType=1\nhttpProxy=p.corp 8080\n");
            proxy_settings(&text, Path::new("kioslaverc"))
                .unwrap()
                .is_some()
        };
        assert!(opens("[Proxy Settings]"));
        assert!(opens("[Proxy Settings] trailing text"));
        assert!(opens("[Proxy Settings]# a comment KConfig does not have"));
        assert!(opens("[Proxy Settings][$i]"));
        assert!(!opens("[ Proxy Settings ]"));
        assert!(!opens("[Proxy Settings][$e]"));
        // The space ends the header, so the `[$i]` after it is ignored text, not a lock.
        assert!(opens("[Proxy Settings] [$i]"));
        assert!(
            !group_header("[Proxy Settings] [$i]")
                .unwrap()
                .group_immutable
        );
        // No closing bracket: KConfig skips the line, and the validator here refuses the file.
        assert!(proxy_settings("[Proxy Settings\nProxyType=1\n", Path::new("kioslaverc")).is_err());

        let header = group_header("[Proxy Settings][$i]").unwrap();
        assert_eq!(header.name, "Proxy Settings");
        assert!(header.group_immutable && !header.file_immutable);
        let header = group_header("[$i]").unwrap();
        assert!(header.file_immutable && header.name.is_empty());
        assert_eq!(group_header("[a][b]x").unwrap().name, "a\x1db");
    }

    // A layer that exists but cannot be read ends the whole read; see [`read_kioslaverc`].
    // Skipped instead, this reads as `system.corp:8080`, indistinguishable from a correct
    // reading of a machine whose user layer holds nothing, so a caller has no way to
    // tell that the layer which was supposed to have the last word never spoke.
    //
    // The unreadable layer is a directory rather than a mode-000 file because root ignores
    // the mode bits, and this has to mean the same thing in a container that runs the suite
    // as root as it does on a developer's machine.
    #[test]
    fn a_layer_that_exists_but_cannot_be_read_refuses_the_whole_read() {
        let f = fixture("unreadable", &["home", "etc"], &["home", "etc"], &[]);
        std::fs::write(
            f.dirs[1].join(FILE_NAME),
            "[Proxy Settings]\nProxyType=1\nhttpProxy=system.corp:8080\n",
        )
        .unwrap();
        std::fs::create_dir(f.dirs[0].join(FILE_NAME)).expect("a kioslaverc that is not a file");

        let Err(error) = read_kioslaverc(f.dirs.clone()) else {
            panic!("a layer that is neither missing nor readable is not an answer");
        };
        let Error::Io { context, .. } = &error else {
            panic!("the refusal is an I/O error, not {error:?}");
        };
        assert!(
            context.ends_with(&f.dirs[0].join(FILE_NAME).display().to_string()),
            "the refusal names the layer that could not be read: {context}"
        );
    }

    #[test]
    fn a_user_deletion_removes_a_system_value() {
        let f = fixture("delete", &["home", "etc"], &["home", "etc"], &[]);
        std::fs::write(
            f.dirs[1].join(FILE_NAME),
            "[Proxy Settings]\nProxyType=1\nhttpProxy=system.corp:8080\n",
        )
        .unwrap();
        std::fs::write(
            f.dirs[0].join(FILE_NAME),
            "[Proxy Settings]\nhttpProxy[$d]\n",
        )
        .unwrap();

        let read = read_kioslaverc(f.dirs.clone()).unwrap().unwrap();
        let config = kioslaverc::config_from_kioslaverc(&read.settings, |_| None).unwrap();
        assert!(config.mode.endpoint_for(Scheme::Http).is_none());
    }

    // A deletion of a key no layer has set yet still leaves a tombstone, as `setEntry`
    // inserts one; an immutable one (`[$id]`) blocks the more specific layer.
    #[test]
    fn an_absent_immutable_deletion_blocks_a_later_layer() {
        let f = fixture("absent-delete-id", &["home", "etc"], &["home", "etc"], &[]);
        std::fs::write(
            f.dirs[1].join(FILE_NAME),
            "[Proxy Settings]\nProxyType=1\nhttpProxy[$id]\n",
        )
        .unwrap();
        std::fs::write(
            f.dirs[0].join(FILE_NAME),
            "[Proxy Settings]\nhttpProxy=user.corp:9090\n",
        )
        .unwrap();

        let read = read_kioslaverc(f.dirs.clone()).unwrap().unwrap();
        let config = kioslaverc::config_from_kioslaverc(&read.settings, |_| None).unwrap();
        assert!(config.mode.endpoint_for(Scheme::Http).is_none());
    }

    // `[$di]` is not immutable when read back, so the same layout lets the user layer win.
    #[test]
    fn an_absent_immutable_deletion_does_not_block_a_later_layer() {
        let f = fixture("absent-delete", &["home", "etc"], &["home", "etc"], &[]);
        std::fs::write(
            f.dirs[1].join(FILE_NAME),
            "[Proxy Settings]\nProxyType=1\nhttpProxy[$di]\n",
        )
        .unwrap();
        std::fs::write(
            f.dirs[0].join(FILE_NAME),
            "[Proxy Settings]\nhttpProxy=user.corp:9090\n",
        )
        .unwrap();

        let read = read_kioslaverc(f.dirs.clone()).unwrap().unwrap();
        let config = kioslaverc::config_from_kioslaverc(&read.settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "user.corp:9090"
        );
    }

    #[test]
    fn a_file_without_the_section_is_no_source() {
        let text = "[$Version]\nupdate_info=x\n";
        assert!(
            proxy_settings(text, Path::new("kioslaverc"))
                .unwrap()
                .is_none()
        );
    }

    // KConfig reads the file as bytes and trims with `QByteArrayView::trimmed()`, which Qt
    // documents as recognising "only ASCII spacing characters"
    // (<https://doc.qt.io/qt-6/qbytearray.html#spacing-characters>). U+3000 is therefore
    // not whitespace to KDE: the first line is not a group header, the section never
    // opens, and the desktop applies none of this. Reading it as a header would make this
    // crate report a proxy the desktop ignores.
    #[test]
    fn a_non_ascii_space_does_not_open_a_section_kconfig_leaves_shut() {
        let text = "\u{3000}[Proxy Settings]\nProxyType=1\nhttpProxy=http://proxy.corp:8080\n";
        assert!(
            proxy_settings(text, Path::new("kioslaverc"))
                .unwrap()
                .is_none(),
            "U+3000 ahead of `[` leaves the line an ordinary one for KConfig"
        );
    }

    // The same predicate one level down: a key KConfig keeps a U+00A0 on is not the key
    // this crate is looking for, so the entry configures nothing on the desktop either.
    #[test]
    fn a_non_ascii_space_stays_on_a_key_the_way_kconfig_keeps_it() {
        let text = "[Proxy Settings]\nProxyType=1\n\u{a0}httpProxy=http://proxy.corp:8080\n";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings] is the section");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        assert!(
            config.mode.endpoint_for(Scheme::Http).is_none(),
            "`\u{a0}httpProxy` is not `httpProxy`: {:?}",
            config.mode
        );
    }

    // ----------------------------------------------------------------------------
    // `#`/`;` inside a value must not be mistaken for a comment introducer.
    // ----------------------------------------------------------------------------

    // The *full* value reaches `manual_mode` (see [`kioslaverc_ini`]).
    // `ProxyEndpoint::parse` still cannot treat a `#` inside userinfo as a literal
    // character, so this entry ends up in `rejected` rather than resolving. What this
    // checks is that `rejected` carries the true, masked address, not a truncated one.
    #[test]
    fn a_hash_in_a_manual_proxy_password_is_not_truncated_by_the_ini_parser() {
        let text = "\
[Proxy Settings][$i]
ProxyType=1
httpProxy=http://user:pa#ss@proxy.example:8080
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings][$i] is the section");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        assert!(
            config.mode.endpoint_for(Scheme::Http).is_none(),
            "endpoint.rs's own userinfo/`#` gap still drops this entry"
        );
        assert_eq!(
            config.mode.rejected().unwrap()[0].redacted_input(),
            "http://user:***@proxy.example:8080",
            "rejected must carry the full, un-truncated (and masked) address, not a \
             truncated remnant"
        );
    }

    // The `;` twin of the test above. Unlike `#`, a `;` inside userinfo is not a
    // delimiter anywhere downstream either, so this one resolves completely.
    #[test]
    fn a_semicolon_in_a_manual_proxy_password_is_not_truncated_by_the_ini_parser() {
        let text = "\
[Proxy Settings][$i]
ProxyType=1
httpProxy=http://user:pa;ss@proxy.example:8080
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings][$i] is the section");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        let endpoint = config
            .mode
            .endpoint_for(Scheme::Http)
            .expect("a `;` must not be mistaken for a comment introducer");
        assert_eq!(endpoint.authority(), "proxy.example:8080");
        let auth = endpoint.auth.as_ref().expect("userinfo was present");
        assert_eq!(auth.username(), "user");
        assert_eq!(auth.password(), Some("pa;ss"));
    }

    // `Proxy Config Script` twin: a `#` in the *path* survives the INI read intact.
    // `parse_script_location` escapes it, because in a file name a `#` is a byte and not
    // the fragment delimiter it would be in a URL. What this isolates is the INI layer:
    // a truncated read would have dropped the `#…` suffix, showing up here as a path that
    // stops at `proxy`.
    #[test]
    fn a_hash_in_a_proxy_config_script_path_is_not_truncated_by_the_ini_parser() {
        let text = "\
[Proxy Settings][$i]
ProxyType=2
Proxy Config Script[$e]=/home/alice/proxy#1.pac
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings][$i] is the section");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        match config.mode {
            ProxyMode::Pac { url, .. } => {
                assert_eq!(url.path(), "/home/alice/proxy%231.pac");
                assert_eq!(
                    url.fragment(),
                    None,
                    "the `#` names a byte in the file, so nothing is left over as a fragment"
                );
            }
            other => panic!("expected a PAC mode, got {other:?}"),
        }
    }

    // Only *inline* comment stripping is disabled: a `#` at the very start of a line,
    // `kconfigini.cpp`'s own rule, must still drop the whole line.
    //
    // Exercises `configparser` directly (through [`kioslaverc_ini`]), because a dropped
    // line and a kept line that matches no known key are both invisible higher up.
    #[test]
    fn a_leading_hash_line_is_still_dropped_as_a_comment() {
        let text = "\
[Proxy Settings][$i]
# httpProxy=http://ignored.example:1
ProxyType=1
";
        let mut ini = kioslaverc_ini();
        let map = ini.read(text.to_owned()).unwrap();
        let entries = &map["Proxy Settings][$i"];
        assert!(
            !entries.keys().any(|key| key.contains("httpProxy")),
            "a line starting with `#` must not surface as a key at all: {entries:?}"
        );
    }

    // KConfig gives `;` no comment role at all, so a `;`-led line is not dropped; the
    // `;` is retained as the literal first character of a key. Intentional.
    #[test]
    fn a_leading_semicolon_line_is_not_a_comment() {
        let text = "\
[Proxy Settings][$i]
ProxyType=1
;httpProxy=http://proxy.corp:8080
";
        let mut ini = kioslaverc_ini();
        let map = ini.read(text.to_owned()).unwrap();
        let entries = &map["Proxy Settings][$i"];
        assert_eq!(
            entries.get(";httpProxy"),
            Some(&Some("http://proxy.corp:8080".to_owned())),
            "a leading `;` must be retained as ordinary text, not treated as a \
             comment: {entries:?}"
        );
    }

    // The `configparser` read is kept only as a syntax validator (nothing higher up looks
    // at the maps it builds), and this is what the validation is worth. The sequential
    // scanner below it is forgiving: a row it cannot make sense of is not a
    // section header and carries no `=`, so it is skipped in silence, and the file goes on
    // to answer with the keys around it. So a `kioslaverc` truncated mid-write, or one an
    // editor mangled, would otherwise be reported as an ordinary proxy configuration whose
    // damaged part happens to say nothing. Refusing the file is what keeps that
    // distinguishable, and only the validator can refuse it.
    #[test]
    fn a_file_the_ini_syntax_refuses_is_refused_whole() {
        let text = "\
[Proxy Settings]
ProxyType=1
httpProxy=http://proxy.corp:8080
[truncated
";
        // The scanner on its own would answer with the proxy above: `[truncated` opens no
        // section and holds no `=`, so it never reaches `KioslavercSettings`.
        let Err(error) = proxy_settings(text, Path::new("/etc/xdg/kioslaverc")) else {
            panic!("an unclosed section is not a kioslaverc");
        };
        let Error::Io { context, source } = &error else {
            panic!("the refusal is an I/O error, not {error:?}");
        };
        assert_eq!(context, "parsing /etc/xdg/kioslaverc");
        assert_eq!(source.kind(), io::ErrorKind::InvalidData);
    }

    // ----------------------------------------------------------------------------
    // KConfig's escaping must be reversed before a value reaches `manual_mode`, see
    // `printable_to_string` for the escape table. Every test below goes through the real
    // `configparser` INI read, because a hand-built `KioslavercSettings` cannot see this
    // class of bug at all.
    // ----------------------------------------------------------------------------

    // KConfig protects a value's *leading or trailing* space, never one in the middle,
    // by writing `\s`. Unreversed, `\shttp://…\s` reaches `ProxyEndpoint::parse` as
    // literal characters and fails to parse at all.
    #[test]
    fn leading_and_trailing_space_is_reversed_before_the_url_is_parsed() {
        let text = "\
[Proxy Settings][$i]
ProxyType=1
httpProxy=\\shttp://user:secret@proxy.example.test:8080\\s
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings][$i] is the section");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();

        let endpoint = config
            .mode
            .endpoint_for(Scheme::Http)
            .expect("the padding spaces must not stop the URL from parsing");
        assert_eq!(endpoint.authority(), "proxy.example.test:8080");
        let auth = endpoint.auth.as_ref().expect("userinfo was present");
        assert_eq!(auth.username(), "user");
        assert_eq!(auth.password(), Some("secret"));
        assert!(
            config.mode.rejected().unwrap().is_empty(),
            "nothing should have been dropped once \\s is reversed"
        );
    }

    // KConfig escape sequences are reversed before a value reaches `manual_mode`. Values
    // that still fail `ProxyEndpoint::parse` land in `rejected()` with decoded text.
    #[test]
    fn kconfig_escape_sequences_are_reversed_before_parsing() {
        enum Expectation<'a> {
            Password(&'a str),
            Rejected(&'a str),
        }

        let cases: &[(&str, Expectation<'_>)] = &[
            (
                "http://user:pa\\\\ss@proxy.example.test:8080",
                Expectation::Password("pa\\ss"),
            ),
            (
                "bad host\\twith\\ntab\\rand\\rcr",
                Expectation::Rejected("bad host\twith\ntab\rand\rcr"),
            ),
            (
                "bad\\x2Ehost value",
                Expectation::Rejected("bad.host value"),
            ),
            (
                "weird\\qvalue with space",
                Expectation::Rejected("weird\\qvalue with space"),
            ),
            // The same refusal where it can be told apart from upstream's. `printable_to_string`
            // hands the *whole* value back as written once it meets an escape it does not know,
            // rather than keeping the conversions it had already made and the backslash it did
            // not, the half-converted reading upstream stores. With no other escape in the
            // value the two spellings coincide, which is why the row above cannot see the
            // difference; here the `\s` in front is what separates them.
            (
                "bad\\shost\\qtail",
                Expectation::Rejected("bad\\shost\\qtail"),
            ),
            // `\x` names a byte, so a UTF-8 sequence written one escape at a time is one
            // character on the way out -- "Ã©" would be a different host from "é".
            (
                "bad caf\\xc3\\xa9 host",
                Expectation::Rejected("bad café host"),
            ),
            // The other direction: a character KDE wrote as itself, in a value that also
            // holds an escape. The unescaper works in bytes because `\x` names one, so the
            // characters around the escapes have to be re-encoded rather than truncated to
            // their low byte, "café" narrowed that way is not UTF-8 at all, and the
            // `from_utf8_lossy` at the end turns it into a host with U+FFFD in it that
            // matches nothing and says so nowhere.
            (
                "bad caf\u{e9}\\shost",
                Expectation::Rejected("bad café host"),
            ),
            // And a byte that begins no UTF-8 sequence is the replacement character, which
            // is what `QString::fromUtf8` puts there, not U+00FF.
            ("bad \\xff byte", Expectation::Rejected("bad \u{fffd} byte")),
            // A lone trailing backslash names no escape at all. Upstream keeps it
            // literally rather than dropping it or reading past the end of the value.
            ("bad host\\", Expectation::Rejected("bad host\\")),
            // `\;` and `\,` are `.desktop` compatibility, not KConfig escapes: both
            // characters survive, so the value cannot be smuggled through as a shorter
            // one that happens to parse.
            (
                "bad host\\;and\\,more",
                Expectation::Rejected("bad host\\;and\\,more"),
            ),
            // `\x` followed by something that is not two hex digits substitutes a literal
            // `x` and consumes all four characters, matching upstream rather than leaving
            // the digits behind to be read as host text.
            ("bad \\xzz byte", Expectation::Rejected("bad x byte")),
            // The same substitution when the value ends before the second digit; the
            // partial digit is discarded.
            ("bad host \\xA", Expectation::Rejected("bad host x")),
        ];
        for (http_proxy, expectation) in cases {
            let text = format!(
                "\
[Proxy Settings][$i]
ProxyType=1
httpProxy={http_proxy}
"
            );
            let settings = proxy_settings(&text, Path::new("kioslaverc"))
                .unwrap()
                .expect("[Proxy Settings][$i] is the section");
            let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();

            match expectation {
                Expectation::Password(password) => {
                    let endpoint = config
                        .mode
                        .endpoint_for(Scheme::Http)
                        .expect("a literal backslash in the password must not break parsing");
                    let auth = endpoint.auth.as_ref().expect("userinfo was present");
                    assert_eq!(auth.password(), Some(*password), "for {http_proxy:?}");
                }
                Expectation::Rejected(rejected) => {
                    assert!(
                        config.mode.endpoint_for(Scheme::Http).is_none(),
                        "for {http_proxy:?}"
                    );
                    assert_eq!(
                        config.mode.rejected().unwrap()[0].redacted_input(),
                        *rejected,
                        "for {http_proxy:?}"
                    );
                }
            }
        }
    }

    // The escape table above is only worth reversing if what it produces survives the next
    // step. `\\` and `\t` decode to bytes a `file:` URL reads as syntax (a path separator
    // and a character to delete), so the script location is where reversing an escape and
    // then splicing the result into a URL hands back a path KDE never wrote. Both
    // spellings here are legal POSIX file names.
    #[test]
    fn a_decoded_escape_survives_into_the_script_url() {
        for (written, decoded) in [
            ("/home/a\\\\b/proxy.pac", "/home/a\\b/proxy.pac"),
            ("/home/a\\tb/proxy.pac", "/home/a\tb/proxy.pac"),
        ] {
            let text = format!(
                "\
[Proxy Settings][$i]
ProxyType=2
Proxy Config Script={written}
"
            );
            let settings = proxy_settings(&text, Path::new("kioslaverc"))
                .unwrap()
                .expect("[Proxy Settings][$i] is the section");
            let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
            match &config.mode {
                crate::ProxyMode::Pac { url, .. } => assert_eq!(
                    crate::util::percent_decode(url.path()),
                    decoded,
                    "for {written:?}"
                ),
                other => panic!("expected Pac for {written:?}, got {other:?}"),
            }
        }
    }

    // Padding around a hand-edited row is removed before the escapes are read, and the
    // order matters: `\s` exists in KConfig so that a space the value ends with survives
    // being written to a file, and a trim applied after the decode would take that one back
    // off again.
    //
    // The script location is the only slot that can tell. `normalize_address` trims the
    // `<scheme>Proxy` values a second time on its own, so padding there is invisible either
    // way; `parse_script_location` escapes what it is handed instead, so a space that
    // reached it becomes `%20` in the file name and points at a script that is not there.
    #[test]
    fn a_padded_script_row_is_trimmed_before_its_escapes_are_read() {
        let text = "\
[Proxy Settings]
ProxyType=2
Proxy Config Script  =   /home/alice/proxy.pac\\s
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings] is the section");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        let crate::ProxyMode::Pac { url, .. } = &config.mode else {
            panic!("ProxyType=2 is a PAC mode, got {:?}", config.mode);
        };
        assert_eq!(
            crate::util::percent_decode(url.path()),
            "/home/alice/proxy.pac ",
            "the administrator's own trailing space is the one that survives"
        );
    }
}
