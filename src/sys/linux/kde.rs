//! KDE: read/watch `kioslaverc` (`linux-kde`: pure Rust `notify` + `configparser`).
//!
//! File-based on purpose — see [`super::kioslaverc`] (KIO 6 → libproxy `config-kde`).
//! Watches the **directory** (not the inode): KConfig atomic rename would orphan a file
//! watch; also catches a first-time create, in the directories that exist when the watch
//! is set up ([`watch_targets`] drops the rest). Like `KSharedConfig::openConfig` with
//! `KConfig::CascadeConfig`, files from `XDG_CONFIG_DIRS` through `XDG_CONFIG_HOME` are
//! applied from least to most specific ([`search_dirs`] / [`watch_targets`]).

use std::env;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::SyncSender;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use crate::error::Error;

use super::desktop::Reading;
use super::kioslaverc::{self, FILE_NAME, KdeConfig, KioslavercSettings};

// `XDG_CONFIG_DIRS` — the colon separated, left-to-right priority list of *system*
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
    // ignored — "All paths set in these environment variables must be absolute. If an
    // implementation encounters a relative path in any of these variables it should
    // consider the path invalid and ignore it" — and ignoring `XDG_CONFIG_HOME` means
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

    // `dirs.contains` scans a vector this loop is filling, the same shape
    // `BypassRules::dedup_patterns` and `parse_find_proxy_result` moved off. It stays a
    // scan here because the quantity it is quadratic in is not the one that would hurt
    // first: every directory that survives becomes a `kioslaverc` open on each read and on
    // each watcher wake, so a list long enough for the dedup to matter is already a list
    // this module cannot afford to walk once. `XDG_CONFIG_DIRS` is also the only one of the
    // four sources with no writer but the process's own launcher — the others are a remote
    // script, a registry value group policy sets, and a `configd` array.
    for candidate in system {
        if !dirs.contains(&candidate) {
            dirs.push(candidate);
        }
    }
    dirs
}

// `value`, unless it is absent or the empty string — the shared "unset or empty" rule
// `XDG_CONFIG_HOME` and `XDG_CONFIG_DIRS` both follow.
//
// No input can observe it, because the empty string fails every downstream test as well:
// `""` is not an absolute path, and an `XDG_CONFIG_DIRS` of `""` splits into one empty
// entry that the split's own filter drops. It says the spec's rule in the spec's words
// rather than leaving it to be inferred from three separate guards.
fn non_empty(value: Option<&OsStr>) -> Option<&OsStr> {
    value.filter(|v| !v.is_empty())
}

// [`search_dirs`], reading the real environment.
fn config_search_dirs() -> Vec<PathBuf> {
    search_dirs(
        env::var_os("XDG_CONFIG_HOME").as_deref(),
        env::var_os("HOME").as_deref(),
        env::var_os(XDG_CONFIG_DIRS).as_deref(),
    )
}

struct KioslavercRead {
    settings: KioslavercSettings,
    // Outside the tests the only reader is the `layers =` trace in [`read_store`], which
    // expands to `()` with `tracing` off — so in that build the field genuinely has no
    // reader. It is kept rather than cfg-ed away because the tests assert which layers the
    // cascade actually walked, and `settings` alone cannot show that.
    #[cfg_attr(not(feature = "tracing"), allow(dead_code))]
    paths: Vec<PathBuf>,
    found_proxy_settings: bool,
}

// Read every existing layer from least to most specific, matching KConfig's cascade.
// A file-level immutable marker ends the cascade before any more-specific file is read.
//
// A layer that exists but cannot be read ends the whole read with an `Err`, rather than
// being skipped like a missing one. The layers overwrite each other key by key, so a
// dropped layer does not leave a gap a caller could see — it leaves a different answer,
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
pub(crate) fn read_store() -> Result<Reading, Error> {
    let Some(read) = read_kioslaverc(config_search_dirs())? else {
        return Ok(Reading::Absent);
    };

    // Which absence, not which answer: entries are stored only while the scanner is inside
    // the section, so no section found means an empty store, and an empty store carries no
    // `ProxyType` for `configured_from_kioslaverc` to read — the arm below reaches the same
    // `Unset`. What separating them buys is the debug line, which would otherwise report a
    // file that has no `[Proxy Settings]` at all as one that merely sets no `ProxyType`.
    if !read.found_proxy_settings {
        return Ok(Reading::Unset);
    }
    Ok(
        // `var_os`, not `var().ok()`: the latter cannot tell an unset variable from one
        // holding bytes that are not UTF-8, and `env_mode` divides on exactly that.
        // Spelled as a closure because naming the function would pin `K` to one lifetime
        // rather than the higher-ranked bound the parameter asks for.
        match kioslaverc::configured_from_kioslaverc(&read.settings, |name: &str| {
            std::env::var_os(name)
        })? {
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
                // anyway — half-converted, and un-truncated because the early return
                // skips the final `truncate`. Handing the value back exactly as written
                // is the only outcome that is never half of two readings, and it does
                // not smuggle anything through: every reader that names a destination
                // either refuses a backslash — `crate::endpoint::parse_host` and
                // `HostPattern::parse` both count it a forbidden host character, so the
                // value lands in `rejected` — or carries it into what it reports, which
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
        // defeats the header — U+FEFF is not whitespace on either side, and KConfig
        // carries no BOM handling anywhere. Do not add BOM stripping for the same reason.
        if let Some(section) = trimmed
            .strip_prefix('[')
            .and_then(|section| section.strip_suffix(']'))
        {
            if section.trim_ascii() == "$i" {
                file_immutable = true;
                in_proxy_settings = false;
                current_group_immutable = false;
                continue;
            }
            in_proxy_settings = kioslaverc::normalize_section(section) == kioslaverc::SECTION;
            // `file_immutable ||` is this function stating its own half of the rule, and no
            // input can observe it: the only caller that walks more than one file,
            // [`read_kioslaverc`], stops on the same flag, so the entries this marks are
            // never offered to a later file. It stays because the sentence above is a
            // contract about `apply_proxy_settings` — a caller that read on rather than
            // breaking would need exactly this term, and would get no test failure if it
            // were gone.
            current_group_immutable =
                in_proxy_settings && (file_immutable || kioslaverc::has_kconfig_flag(section, 'i'));
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
        // the same rule in a second place — [`kioslaverc::normalize_key`] already does it,
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

// The `kioslaverc` file watch. Dropping it removes the inotify registration.
pub(crate) struct FileWatch {
    _watcher: RecommendedWatcher,
    // What is left of the registration; see [`LossFlags`].
    flags: LossFlags,
}

// How much of a [`FileWatch`]'s registration is still alive.
#[derive(Clone)]
pub(crate) struct LossFlags {
    // Seeded by [`watch`] when [`watch_targets`] dropped the leading candidate, and set by
    // the `notify` callback the first time it sees an event that ends *any* one of the
    // watched directories; see [`drop_ended_directories`] for what qualifies. The two are
    // the same statement — some layer of the cascade cannot report — arrived at before and
    // after construction.
    lost: Arc<AtomicBool>,
    // How many watched directories can still deliver an event. Starts at the number
    // [`watch`] registered and only ever falls; zero means the route is completely dark.
    live_directories: Arc<AtomicUsize>,
}

impl LossFlags {
    // Whether at least one directory of the cascade is beyond the watch: removed or
    // renamed since, or the leading candidate that was never there to register.
    //
    // The route is degraded from this moment on — the directory can be created and
    // written to and nothing will report it — even while [`LossFlags::is_live`] is still
    // `true` for the directories that survive.
    // `Acquire`, paired with the callback's `Release` store: whoever reads `true` here is
    // then guaranteed to see the `live_directories` decrement that preceded it. Without
    // that pairing the coordinator's `LossReport::check` could read `true` with a stale
    // count, report only the first half of the loss, and never get a second look —
    // once the last directory is gone no further event arrives to bring it back.
    pub(crate) fn any_lost(&self) -> bool {
        self.lost.load(Ordering::Acquire)
    }

    // Whether this watch is still capable of reporting a `kioslaverc` change.
    //
    // `false` only once **every** watched directory has been removed or renamed out from
    // under the registration. The two are not the same mechanism: removal makes `notify`
    // drop the watch, whereas a rename leaves it armed on the moved inode (`notify` 8.2.0
    // handles `MOVE_SELF` without removing the watch). Either way nothing further arrives
    // for the path `read_store` reads. While one directory remains, changes to it still do.
    pub(crate) fn is_live(&self) -> bool {
        self.live_directories.load(Ordering::Relaxed) > 0
    }
}

impl FileWatch {
    // Whether this watch is still capable of reporting a `kioslaverc` change.
    //
    // [`Watch::health`](super::watcher::Watch::health) consults this so that
    // `has_live_notifications` stops claiming a route that has gone permanently silent.
    pub(crate) fn is_live(&self) -> bool {
        self.flags.is_live()
    }

    // Whether any watched directory has been lost; see [`LossFlags::any_lost`].
    pub(crate) fn any_lost(&self) -> bool {
        self.flags.any_lost()
    }

    // A handle on the same counters [`FileWatch::is_live`] reads, for the coordinator.
    pub(crate) fn loss_flags(&self) -> LossFlags {
        self.flags.clone()
    }
}

impl std::fmt::Debug for FileWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileWatch").finish_non_exhaustive()
    }
}

#[cfg(test)]
impl LossFlags {
    // One more watched directory ended, staged the way the `notify` callback stages it:
    // the count down first, then the flag with `Release` so a reader that sees the flag
    // sees the count. For [`LossReport`](super::watcher::LossReport), whose two halves are
    // reported at different losses and so cannot be shown by any single staged state.
    pub(crate) fn lose_one_for_test(&self) {
        self.live_directories.fetch_sub(1, Ordering::Relaxed);
        self.lost.store(true, Ordering::Release);
    }
}

#[cfg(test)]
impl FileWatch {
    // A watch registered on no directory at all, with the counters left where a real one
    // would be after `n` losses. The registration is real so that the field holds what it
    // holds in production; only the flags are staged.
    //
    // For [`Watch::health`](super::watcher::Watch::health), which reads `any_lost` through
    // this type and cannot be shown a loss any other way: the callback that sets the flag
    // fires on a `DELETE_SELF`/`MOVE_SELF` the kernel delivers, so reaching it from a test
    // would mean removing a directory the watcher had already registered and then waiting
    // on an inotify round-trip for a flag that is *supposed* to be readable without one.
    pub(crate) fn with_flags_for_test(lost: bool, live_directories: usize) -> Self {
        FileWatch {
            _watcher: notify::recommended_watcher(|_: notify::Result<notify::Event>| {})
                .expect("a watcher that watches nothing still needs an inotify handle"),
            flags: LossFlags {
                lost: Arc::new(AtomicBool::new(lost)),
                live_directories: Arc::new(AtomicUsize::new(live_directories)),
            },
        }
    }
}

// Which directories [`watch`] hands to `notify`. A candidate that does not exist is dropped
// rather than failing the watch: inotify cannot watch a path that is not there, and a
// machine whose only layer is `/etc/xdg` is still perfectly readable.
//
// What that costs is a layer created *later*. [`read_store`] walks [`config_search_dirs`]
// unfiltered, so a `kioslaverc` written into a directory that did not exist here is read —
// and being the more specific layer, it wins — while no event ever announces it. Watching
// the parent instead would close it, but for `~/.config` the parent is `$HOME`, written to
// constantly for reasons that have nothing to do with proxies. Only
// [`crate::WatchOptions::poll_interval`] actually closes the hole.
//
// So the second return says the hole is open, and `watch` seeds [`LossFlags::lost`] from
// it. That much is owed by consistency alone: a `~/.config` deleted a second *after*
// construction reaches `drop_ended_directories` and is reported degraded, while the same
// directory already absent a second *before* it was reported as nothing at all — one end
// state, two opposite answers from `health()`.
//
// It is deliberately only the *leading* candidate, not any dropped one. Debian's shipped
// `/etc/X11/Xsession.d/60x11-common_xdg_path` prepends `/etc/xdg/xdg-$DESKTOP_SESSION` to
// `XDG_CONFIG_DIRS` without ever checking that it is there, and on Ubuntu 22.04 here it is
// not — so "any dropped candidate" would report a degraded route on an ordinary desktop
// session, every time. (`/etc/xdg` itself exists and is owned by four packages including
// `systemd`, so a machine with no `/etc/xdg` at all is not the noisy case; the session's
// own profile directory is.) The leading candidate is the one that wins the cascade
// outright, so a `kioslaverc` appearing there changes the answer whatever the layers below
// hold, whereas one appearing in a dropped middle layer only changes it when no higher
// layer sets the key. The severe half is bought, and no noise is paid.
fn watch_targets(dirs: Vec<PathBuf>) -> (Vec<PathBuf>, bool) {
    let leading_dropped = dirs.first().is_some_and(|dir| !dir.is_dir());
    let kept: Vec<PathBuf> = dirs.into_iter().filter(|dir| dir.is_dir()).collect();
    // With nothing left to watch there is no route to call degraded: `watch` answers
    // `Ok(None)` and the KDE arm is the not-configured-at-all case instead.
    let leading_dropped = leading_dropped && !kept.is_empty();
    (kept, leading_dropped)
}

// Start watching `kioslaverc`, sending `()` on `trigger` for every relevant event.
pub(crate) fn watch(trigger: SyncSender<()>) -> Result<Option<FileWatch>, Error> {
    let (directories, leading_dropped) = watch_targets(config_search_dirs());
    // Nothing observable rides on this — a watch registered on no directory answers `false`
    // to `is_live` from birth, so `health()` reads the same either way. What it saves is the
    // inotify instance itself, held open for a registration that can never fire.
    if directories.is_empty() {
        return Ok(None);
    }
    if leading_dropped {
        crate::trace::warning!(
            file = FILE_NAME,
            "the most specific configuration directory does not exist, so it cannot be \
             watched; a kioslaverc created there later would win the cascade and be read, \
             but no event would announce it — health() reports this route as degraded, and \
             WatchOptions::poll_interval is what closes it"
        );
    }

    let flags = LossFlags {
        lost: Arc::new(AtomicBool::new(leading_dropped)),
        live_directories: Arc::new(AtomicUsize::new(directories.len())),
    };
    let mut watcher =
        notify::recommended_watcher(loss_callback(flags.clone(), directories.clone(), trigger))
            .map_err(|source| notify_error("creating the kioslaverc watcher", source))?;

    for directory in &directories {
        watcher
            .watch(directory, RecursiveMode::NonRecursive)
            .map_err(|source| {
                notify_error(
                    format!("watching {} for kioslaverc", directory.display()),
                    source,
                )
            })?;

        crate::trace::debug!(
            directory = %directory.display(),
            file = FILE_NAME,
            "watching the configuration directory with inotify"
        );
    }
    Ok(Some(FileWatch {
        _watcher: watcher,
        flags,
    }))
}

// The callback [`watch`] hands to `notify`, built here rather than inline so that a test
// can hold the same closure production runs and drive it with a synthesized event.
//
// `watch` is its only caller, and the seam is what it is for. Inside `watch` the only way
// to reach the join below — `drop_ended_directories` deciding how many directories ended,
// the counters recording it, the wake that publishes it — is to remove a directory the
// watcher has already registered and wait on the kernel. The halves are covered separately,
// so without the seam a decrement that publishes the wrong count, or a flag set only on the
// *last* loss, is held by nothing.
fn loss_callback(
    flags: LossFlags,
    directories: Vec<PathBuf>,
    trigger: SyncSender<()>,
) -> impl FnMut(notify::Result<notify::Event>) {
    // Whether the WARN below has already been emitted. A local rather than `lost`, which
    // now starts `true` on the machine above: the two questions stopped being the same one
    // the moment the flag could be seeded before any directory had ended.
    let mut warned = false;
    // Owned by the callback and shrunk as directories end, so the same directory reported
    // twice — a `DELETE_SELF` and a `MOVE_SELF` can both name it — is counted once.
    let mut watched = directories;
    move |event: notify::Result<notify::Event>| {
        // A failed event is still evidence that *something* happened; re-reading is
        // cheap and `Shared::emit` skips an unchanged snapshot.
        let mut dark = false;
        let relevant = match event {
            Ok(event) => {
                let ended = drop_ended_directories(&event, &mut watched);
                if ended > 0 {
                    let live = flags.live_directories.fetch_sub(ended, Ordering::Relaxed) - ended;
                    // `Release` publishes the `fetch_sub` above along with the flag; see
                    // [`LossFlags::any_lost`]. The WARN is guarded separately so that it is
                    // still emitted once even though every watched directory can terminate
                    // separately — reaching zero needs no such guard, since `watched` is
                    // empty afterwards.
                    flags.lost.store(true, Ordering::Release);
                    let first = !std::mem::replace(&mut warned, true);
                    if live == 0 {
                        dark = true;
                        crate::trace::warning!(
                            file = FILE_NAME,
                            "every watched configuration directory has been removed or \
                             renamed; the watches are dropped or now follow the moved \
                             directories, so no kioslaverc change will be noticed at all \
                             from here on"
                        );
                    } else if first {
                        crate::trace::warning!(
                            file = FILE_NAME,
                            ended = ended,
                            remaining = live,
                            "watched configuration directories were removed or renamed; \
                             those watches are dropped or now follow the moved directories, \
                             so kioslaverc changes there will no longer be noticed — \
                             health() now reports this route as degraded, though the \
                             remaining directories still report"
                        );
                    }
                    true
                } else {
                    is_interesting(&event)
                }
            }
            Err(_) => true,
        };
        if relevant {
            // Every other loss has a second chance — a surviving directory can fire again
            // and `LossReport::check` runs on every one of those. This one has none: with
            // the last directory gone no further event exists, so if this wake is the one
            // that gets refused, the flags above may never be published to the coordinator
            // at all and `has_live_notifications` keeps claiming a route that is silent.
            if dark {
                super::watcher::wake_delivered(&trigger);
            } else {
                super::watcher::wake(&trigger);
            }
        }
    }
}

// Remove from `watched` every directory this event says is gone, and answer how many
// that was.
fn drop_ended_directories(event: &notify::Event, watched: &mut Vec<PathBuf>) -> usize {
    use notify::EventKind;
    use notify::event::ModifyKind;

    if !matches!(
        event.kind,
        EventKind::Remove(_) | EventKind::Modify(ModifyKind::Name(_))
    ) {
        return 0;
    }
    let before = watched.len();
    watched.retain(|directory| !event.paths.iter().any(|path| path == directory));
    before - watched.len()
}

// Whether an event concerns `kioslaverc` at all.
fn is_interesting(event: &notify::Event) -> bool {
    use notify::EventKind;

    if event.need_rescan() {
        return true;
    }
    if !matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) | EventKind::Any
    ) {
        return false;
    }
    event
        .paths
        .iter()
        .any(|path| path.file_name().is_some_and(|name| name == FILE_NAME))
}

// Wrap a `notify` failure as an [`Error::Io`].
fn notify_error(context: impl Into<String>, source: notify::Error) -> Error {
    // `notify::Error` carries an `io::Error` for the cases that have one; the rest are
    // rendered into the message so nothing is lost.
    let text = source.to_string();
    let io_error = match source.kind {
        notify::ErrorKind::Io(error) => error,
        _ => io::Error::other(text),
    };
    Error::io(context, io_error)
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

    // ----------------------------------------------------------------------------
    // watch_targets: needs real directories, so each case builds its own fixture tree
    // under the temp directory and removes it again. `dirs` is passed in, so no
    // process-wide environment is touched and these stay parallel-safe.
    // ----------------------------------------------------------------------------

    // Build `<temp>/proxy-watch-kde-<name>-<pid>/{a,b,c,…}`, creating the directories
    // named in `existing` and a `kioslaverc` in each directory named in `holding`.
    // Returns the root plus the full candidate list, existing or not.
    fn fixture(name: &str, candidates: &[&str], existing: &[&str], holding: &[&str]) -> Fixture {
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

    struct Fixture {
        root: PathBuf,
        dirs: Vec<PathBuf>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    // The case the directory walk exists for: `kioslaverc` lives only in the *last*
    // candidate (an `/etc/xdg` default), so the higher-priority directories must be
    // watched too — that is where the file that will take over gets created.
    #[test]
    fn a_lower_priority_holder_still_watches_the_directories_ahead_of_it() {
        let f = fixture("lower", &["home", "etc"], &["home", "etc"], &["etc"]);
        assert_eq!(watch_targets(f.dirs.clone()), (f.dirs.clone(), false));
    }

    // Every existing layer contributes to the cascade, even when the most-specific file
    // already exists, so every candidate directory remains relevant.
    #[test]
    fn the_leading_holder_does_not_hide_lower_layers_from_the_watch() {
        let f = fixture("leading", &["home", "etc"], &["home", "etc"], &["home"]);
        assert_eq!(watch_targets(f.dirs.clone()), (f.dirs.clone(), false));
    }

    // A lower-priority file can change defaults or immutable policy, so candidates below
    // a holder are watched as well.
    #[test]
    fn candidates_below_a_holder_are_watched() {
        let f = fixture(
            "below",
            &["home", "etc", "opt"],
            &["home", "etc", "opt"],
            &["etc"],
        );
        assert_eq!(watch_targets(f.dirs.clone()), (f.dirs.clone(), false));
    }

    // A candidate directory that does not exist cannot be handed to inotify, so it is
    // dropped from the prefix rather than failing the watch — and when the one dropped is
    // the *leading* candidate, the watch that remains cannot report the layer that would
    // win, so it says so.
    #[test]
    fn a_candidate_directory_that_does_not_exist_is_skipped() {
        let f = fixture("absent", &["home", "etc"], &["etc"], &["etc"]);
        assert_eq!(
            watch_targets(f.dirs.clone()),
            (vec![f.dirs[1].clone()], true)
        );
    }

    // The shape Debian's `60x11-common_xdg_path` puts on an ordinary desktop session: it
    // prepends `/etc/xdg/xdg-$DESKTOP_SESSION` to `XDG_CONFIG_DIRS` without checking that
    // the directory is there, and usually it is not. Reporting that as a degraded route
    // would fire on every such machine, and it is the weaker hole besides — a `kioslaverc`
    // appearing in a middle layer only changes the answer when no higher layer sets the
    // key, and the higher layer here is watched.
    #[test]
    fn a_dropped_middle_candidate_is_not_reported() {
        let f = fixture(
            "middle",
            &["home", "session", "etc"],
            &["home", "etc"],
            &["etc"],
        );
        assert_eq!(
            watch_targets(f.dirs.clone()),
            (vec![f.dirs[0].clone(), f.dirs[2].clone()], false)
        );
    }

    // With no `kioslaverc` anywhere, a first-time creation in any layer changes the
    // cascade, so all existing candidates are watched.
    #[test]
    fn with_no_kioslaverc_anywhere_all_existing_directories_are_watched() {
        let f = fixture("none", &["home", "etc"], &["home", "etc"], &[]);
        assert_eq!(watch_targets(f.dirs.clone()), (f.dirs.clone(), false));
    }

    // Nothing exists at all: there is nothing to watch, which `watch` reports as
    // `Ok(None)` rather than as a failure — and no degraded route either, even though the
    // leading candidate is among the missing. A route that was never established is the
    // not-configured-at-all case `WatchHealth::degraded` excludes by its own documentation.
    #[test]
    fn with_no_candidate_directory_at_all_there_is_nothing_to_watch() {
        let f = fixture("empty", &["home", "etc"], &[], &[]);
        assert_eq!(watch_targets(f.dirs.clone()), (Vec::new(), false));
    }

    // ----------------------------------------------------------------------------
    // drop_ended_directories: pure over a synthesized event, so no inotify involved.
    // ----------------------------------------------------------------------------

    // `drop_ended_directories` reduced to the question the tests below ask, against a
    // throwaway copy of the watch list.
    fn ends_the_watch(event: &notify::Event, watched: &[PathBuf]) -> bool {
        drop_ended_directories(event, &mut watched.to_vec()) > 0
    }

    // An event shaped like the ones `notify`'s inotify backend produces for a watched
    // directory that is itself removed (`DELETE_SELF`) or renamed (`MOVE_SELF`).
    fn directory_event(kind: notify::EventKind, path: &str) -> notify::Event {
        notify::Event::new(kind).add_path(PathBuf::from(path))
    }

    fn watched() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/home/alice/.config"),
            PathBuf::from("/etc/xdg"),
        ]
    }

    // `DELETE_SELF`. `notify` removes the watch without re-arming, so this must be
    // recognised rather than dropped for not naming `kioslaverc`.
    #[test]
    fn removing_a_watched_directory_ends_the_watch() {
        use notify::event::RemoveKind;

        let event = directory_event(
            notify::EventKind::Remove(RemoveKind::Folder),
            "/home/alice/.config",
        );
        assert!(ends_the_watch(&event, &watched()));
        assert!(
            !is_interesting(&event),
            "the basename is not kioslaverc, which is exactly why is_interesting alone \
             let this route go silent"
        );
    }

    // `MOVE_SELF`. The registration survives but now follows the moved inode instead of
    // the path `read_store` reads, which is the same blindness.
    #[test]
    fn renaming_a_watched_directory_ends_the_watch() {
        use notify::event::{ModifyKind, RenameMode};

        let event = directory_event(
            notify::EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            "/etc/xdg",
        );
        assert!(ends_the_watch(&event, &watched()));
    }

    // The ordinary case: `kioslaverc` itself is deleted. That is a configuration change,
    // not a lost watch — the directory is still registered.
    #[test]
    fn removing_the_file_itself_does_not_end_the_watch() {
        use notify::event::RemoveKind;

        let event = directory_event(
            notify::EventKind::Remove(RemoveKind::File),
            "/home/alice/.config/kioslaverc",
        );
        assert!(!ends_the_watch(&event, &watched()));
        assert!(is_interesting(&event), "it is still a change to report");
    }

    // A directory nobody asked us to watch, and an unrelated file next to the one we do.
    #[test]
    fn events_elsewhere_do_not_end_the_watch() {
        use notify::event::{DataChange, ModifyKind, RemoveKind};

        for event in [
            directory_event(notify::EventKind::Remove(RemoveKind::Folder), "/tmp/other"),
            directory_event(
                notify::EventKind::Modify(ModifyKind::Data(DataChange::Content)),
                "/home/alice/.config/kdeglobals",
            ),
        ] {
            assert!(!ends_the_watch(&event, &watched()));
        }
    }

    // A write *to* a watched directory's path is not a disappearance. Only removal and
    // rename end the registration, so nothing else may set the flag.
    #[test]
    fn a_non_terminal_event_on_the_directory_itself_is_not_terminal() {
        use notify::event::{CreateKind, MetadataKind, ModifyKind};

        for kind in [
            notify::EventKind::Create(CreateKind::Folder),
            notify::EventKind::Modify(ModifyKind::Metadata(MetadataKind::Permissions)),
            notify::EventKind::Any,
        ] {
            let event = directory_event(kind, "/home/alice/.config");
            assert!(!ends_the_watch(&event, &watched()));
        }
    }

    // Losing one of two watched directories is a degradation, not a dead route: the
    // other one is still registered and still delivers. Only the second loss makes the
    // count zero, which is what turns `has_live_notifications` off.
    #[test]
    fn directories_are_lost_one_at_a_time() {
        use notify::event::{ModifyKind, RemoveKind, RenameMode};

        let mut live = watched();
        assert_eq!(
            drop_ended_directories(
                &directory_event(
                    notify::EventKind::Remove(RemoveKind::Folder),
                    "/home/alice/.config",
                ),
                &mut live,
            ),
            1
        );
        assert_eq!(live, vec![PathBuf::from("/etc/xdg")]);

        // The same directory reported a second time — inotify can produce both shapes —
        // must not be subtracted twice.
        assert_eq!(
            drop_ended_directories(
                &directory_event(
                    notify::EventKind::Modify(ModifyKind::Name(RenameMode::From)),
                    "/home/alice/.config",
                ),
                &mut live,
            ),
            0
        );
        assert_eq!(live, vec![PathBuf::from("/etc/xdg")]);

        assert_eq!(
            drop_ended_directories(
                &directory_event(
                    notify::EventKind::Modify(ModifyKind::Name(RenameMode::From)),
                    "/etc/xdg",
                ),
                &mut live,
            ),
            1
        );
        assert!(live.is_empty());
    }

    // One event can name several watched directories at once; each counts.
    #[test]
    fn one_event_can_end_more_than_one_directory() {
        use notify::event::RemoveKind;

        let event = notify::Event::new(notify::EventKind::Remove(RemoveKind::Folder))
            .add_path(PathBuf::from("/home/alice/.config"))
            .add_path(PathBuf::from("/etc/xdg"));
        let mut live = watched();
        assert_eq!(drop_ended_directories(&event, &mut live), 2);
        assert!(live.is_empty());
    }

    // A watch over [`watched`] with nothing lost yet, and the callback `watch` installs
    // over it. The channel holds one wake, exactly as the coordinator's does.
    fn callback_over_two_directories() -> (
        LossFlags,
        std::sync::mpsc::Receiver<()>,
        impl FnMut(notify::Result<notify::Event>),
    ) {
        let flags = LossFlags {
            lost: Arc::new(AtomicBool::new(false)),
            live_directories: Arc::new(AtomicUsize::new(2)),
        };
        let (trigger, wakes) = std::sync::mpsc::sync_channel(1);
        let callback = loss_callback(flags.clone(), watched(), trigger);
        (flags, wakes, callback)
    }

    // The join neither half above reaches: the callback `watch` installs, driven with the
    // events `notify` delivers. A partial loss has to set the flag `health()` reads *and*
    // leave the survivors counted — that is the state the middle row of
    // `a_kioslaverc_watch_that_lost_a_directory_is_degraded_while_the_rest_still_report`
    // (`super::watcher`) stages by hand, and staging it is all that held it: nothing showed
    // the callback could produce it.
    //
    // What this cannot see is which *kind* of wake the last loss sends; that is
    // `the_wake_that_reports_a_dark_route_is_not_allowed_to_be_refused` below.
    #[test]
    fn a_partial_loss_is_published_before_the_route_goes_dark() {
        use notify::event::{DataChange, ModifyKind, RemoveKind, RenameMode};

        let (flags, wakes, mut callback) = callback_over_two_directories();

        // An ordinary configuration change first: a wake, and nothing lost.
        callback(Ok(directory_event(
            notify::EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            "/etc/xdg/kioslaverc",
        )));
        assert!(wakes.try_recv().is_ok());
        assert!(!flags.any_lost());
        assert!(flags.is_live());

        // One of the two directories ends. Degraded from here on, and still reporting.
        callback(Ok(directory_event(
            notify::EventKind::Remove(RemoveKind::Folder),
            "/home/alice/.config",
        )));
        assert!(wakes.try_recv().is_ok(), "a lost directory is itself news");
        assert!(flags.any_lost());
        assert!(flags.is_live(), "/etc/xdg still delivers");

        // The second, and the route is dark. The wake that carries it is a blocking `send`,
        // so the buffer has to be empty when it runs — as it is here, and as it is for the
        // coordinator, which consumes a wake before opening the read it leads to.
        callback(Ok(directory_event(
            notify::EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            "/etc/xdg",
        )));
        assert!(wakes.try_recv().is_ok());
        assert!(flags.any_lost());
        assert!(!flags.is_live());
    }

    // One event can name every watched directory at once, and then the route is dark in a
    // single step. `drop_ended_directories` answering 2 is held above; that the count falls
    // by that many rather than by one event's worth is what this holds.
    #[test]
    fn an_event_that_ends_every_directory_at_once_goes_dark_in_one_step() {
        use notify::event::RemoveKind;

        let (flags, wakes, mut callback) = callback_over_two_directories();

        callback(Ok(notify::Event::new(notify::EventKind::Remove(
            RemoveKind::Folder,
        ))
        .add_path(PathBuf::from("/home/alice/.config"))
        .add_path(PathBuf::from("/etc/xdg"))));

        assert!(wakes.try_recv().is_ok());
        assert!(flags.any_lost());
        assert!(!flags.is_live());
    }

    // The last loss of all sends a wake that is not allowed to be refused, because there is
    // no later event to carry the same news: every watched directory is gone. A `try_send`
    // onto a full buffer publishes nothing — `Full` leaves no happens-before edge — so the
    // flags stored just above it can stay invisible to the coordinator, and
    // `has_live_notifications` goes on claiming a route that is silent for good.
    //
    // The buffer being full is the ordinary state, not a contrived one: it holds one wake
    // and the coordinator empties it only when it starts a read.
    //
    // Driven from a second thread so that the blocking send has somewhere to block. The
    // flags are stored before either kind of wake, so waiting on `is_live` puts this thread
    // past the store and at the send; the pause after it is the window in which a `try_send`
    // would be refused and lost.
    #[test]
    fn the_wake_that_reports_a_dark_route_is_not_allowed_to_be_refused() {
        use notify::event::{DataChange, ModifyKind, RemoveKind};

        let (flags, wakes, mut callback) = callback_over_two_directories();

        // An ordinary change nobody has consumed yet fills the one slot.
        callback(Ok(directory_event(
            notify::EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            "/etc/xdg/kioslaverc",
        )));

        let ending = std::thread::spawn(move || {
            callback(Ok(notify::Event::new(notify::EventKind::Remove(
                RemoveKind::Folder,
            ))
            .add_path(PathBuf::from("/home/alice/.config"))
            .add_path(PathBuf::from("/etc/xdg"))));
        });

        while flags.is_live() {
            std::thread::yield_now();
        }
        std::thread::sleep(std::time::Duration::from_millis(200));

        let timeout = std::time::Duration::from_secs(5);
        assert_eq!(
            wakes.recv_timeout(timeout),
            Ok(()),
            "the ordinary change is still queued"
        );
        assert_eq!(
            wakes.recv_timeout(timeout),
            Ok(()),
            "the wake that says the route went dark must survive a full buffer"
        );
        ending.join().expect("the callback thread must finish");
        assert!(flags.any_lost());
        assert!(!flags.is_live());
    }

    // `notify` reports an exhausted `fs.inotify.max_user_watches` as an `io::Error` carrying
    // ENOSPC, and [`Error::Io`]'s `source` is a public field — so which `io::ErrorKind` a
    // caller can match on is part of what this crate returns, not an implementation detail.
    // Rendering every `notify` failure through `io::Error::other` would collapse that one
    // into the same shapeless `Other` as a failure with no `io::Error` behind it at all.
    #[test]
    fn a_notify_failure_keeps_the_io_kind_it_arrived_with() {
        let Error::Io { context, source } = notify_error(
            "watching /etc/xdg for kioslaverc",
            notify::Error::io(io::Error::from_raw_os_error(28)),
        ) else {
            panic!("a notify failure is an I/O error");
        };
        assert_eq!(context, "watching /etc/xdg for kioslaverc");
        assert_eq!(source.raw_os_error(), Some(28));

        // A `notify` failure with no `io::Error` under it keeps its text instead, which is
        // the only place that text exists.
        let Error::Io { source, .. } = notify_error("creating", notify::Error::generic("no fds"))
        else {
            panic!("a notify failure is an I/O error");
        };
        assert!(
            source.to_string().contains("no fds"),
            "the message is all there is: {source}"
        );
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
    // on the entry itself. Nothing else in this file observes that argument — a later file is
    // refused by the deferred group lock instead.
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
    // and files `Disabled`. Both route direct, so only the map tells them apart — and that
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

    #[test]
    fn an_immutable_deletion_refuses_a_later_recreation() {
        let text = "\
[Proxy Settings]
ProxyType=1
httpProxy=old.corp:8080
httpProxy[$di]
httpProxy=new.corp:9090
";
        let settings = proxy_settings(text, Path::new("kioslaverc"))
            .unwrap()
            .expect("[Proxy Settings] is present");
        let config = kioslaverc::config_from_kioslaverc(&settings, |_| None).unwrap();
        assert!(config.mode.endpoint_for(Scheme::Http).is_none());
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
    // unflagged repetition of its own group — which is what KConfig writes whenever a
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
    // without ever asking what `ProxyType` the merged settings hold — the equivalence its
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

    // The marker's line is trimmed before the brackets come off, so padding *inside* them
    // survives to the comparison — the same reason `normalize_section` trims a group name.
    // Compared untrimmed, `[ $i ]` is no longer the marker and is not `[Proxy Settings]`
    // either, so it silently becomes an ordinary group nobody reads: the admin who wrote it
    // locks nothing, and the user layer below overrides the lock it thinks it set.
    #[test]
    fn a_padded_file_immutable_marker_still_ends_the_cascade() {
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
        assert_eq!(read.paths, vec![f.dirs[1].join(FILE_NAME)]);
        let config = kioslaverc::config_from_kioslaverc(&read.settings, |_| None).unwrap();
        assert_eq!(
            config.mode.endpoint_for(Scheme::Http).unwrap().authority(),
            "system.corp:8080"
        );
    }

    // A layer that exists but cannot be read ends the whole read; see [`read_kioslaverc`].
    // Skipped instead, this reads as `system.corp:8080` — indistinguishable from a correct
    // reading of a machine whose user layer simply holds nothing, so a caller has no way to
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

    // Only *inline* comment stripping is disabled: a `#` at the very start of a line —
    // `kconfigini.cpp`'s own rule — must still drop the whole line.
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

    // KConfig gives `;` no comment role at all, so a `;`-led line is not dropped — the
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

    // The `configparser` read is kept only as a syntax validator — nothing higher up looks
    // at the maps it builds — and this is what the validation is worth. The sequential
    // scanner below it is deliberately forgiving: a row it cannot make sense of is not a
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
    // KConfig's escaping must be reversed before a value reaches `manual_mode` — see
    // `printable_to_string` for the escape table. Every test below goes through the real
    // `configparser` INI read, because a hand-built `KioslavercSettings` cannot see this
    // class of bug at all.
    // ----------------------------------------------------------------------------

    // KConfig protects a value's *leading or trailing* space — never one in the middle
    // — by writing `\s`. Unreversed, `\shttp://…\s` reaches `ProxyEndpoint::parse` as
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
            // not — the half-converted reading upstream stores. With no other escape in the
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
            // their low byte — "café" narrowed that way is not UTF-8 at all, and the
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
    // step. `\\` and `\t` decode to bytes a `file:` URL reads as syntax — a path separator
    // and a character to delete — so the script location is where reversing an escape and
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

    // Padding around a hand-edited row is removed before the escapes are read, and the order
    // is the whole point: `\s` exists in KConfig so that a space the value really ends with
    // survives being written to a file, and a trim applied after the decode would take that
    // one back off again.
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

    #[test]
    fn only_kioslaverc_events_are_interesting() {
        use notify::event::{CreateKind, ModifyKind};
        use notify::{Event, EventKind};

        let kioslaverc = PathBuf::from("/home/alice/.config/kioslaverc");
        let other = PathBuf::from("/home/alice/.config/kdeglobals");

        let hit = Event::new(EventKind::Modify(ModifyKind::Any)).add_path(kioslaverc.clone());
        assert!(is_interesting(&hit));

        let miss = Event::new(EventKind::Modify(ModifyKind::Any)).add_path(other);
        assert!(!is_interesting(&miss));

        let created = Event::new(EventKind::Create(CreateKind::File)).add_path(kioslaverc.clone());
        assert!(is_interesting(&created));

        let accessed =
            Event::new(EventKind::Access(notify::event::AccessKind::Read)).add_path(kioslaverc);
        assert!(
            !is_interesting(&accessed),
            "reads must not wake the watcher"
        );
    }

    // What an overflowed inotify queue looks like: `notify` raises the rescan flag and
    // carries no path, because the kernel dropped the events themselves. Every later
    // question in [`is_interesting`] therefore answers "not about kioslaverc", so without
    // the flag being asked first the wake is refused and the change that overflowed the
    // queue is never noticed — the watch stays registered, `health()` keeps reporting a
    // live route, and the caller holds a stale answer until something unrelated happens to
    // touch the file again or `WatchOptions::poll_interval` re-reads on its own.
    #[test]
    fn a_dropped_event_queue_wakes_the_watcher_even_though_it_names_nothing() {
        use notify::event::Flag;
        use notify::{Event, EventKind};

        let overflow = Event::new(EventKind::Any).set_flag(Flag::Rescan);
        assert!(
            overflow.paths.is_empty(),
            "an overflow reports no path, which is the whole difficulty"
        );
        assert!(is_interesting(&overflow));
    }
}
