//! The `kioslaverc` watch: one inotify registration per directory of the cascade, and how
//! much of it is still alive as directories are removed or renamed.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::SyncSender;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use crate::error::Error;

use super::{Env, FILE_NAME, config_search_dirs};

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
    // the same statement, some layer of the cascade cannot report, arrived at before and
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
    // The route is degraded from this moment on, the directory can be created and
    // written to and nothing will report it, even while [`LossFlags::is_live`] is still
    // `true` for the directories that survive.
    // `Acquire`, paired with the callback's `Release` store: whoever reads `true` here is
    // then guaranteed to see the `live_directories` decrement that preceded it. Without
    // that pairing the coordinator's `LossReport::check` could read `true` with a stale
    // count, report only the first half of the loss, and never get a second look,
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
    // [`Watch::health`](super::super::watcher::Watch::health) consults this so that
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
    // sees the count. For [`LossReport`](super::super::watcher::LossReport), whose two halves are
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
    // For [`Watch::health`](super::super::watcher::Watch::health), which reads `any_lost` through
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
// unfiltered, so a `kioslaverc` written into a directory that did not exist here is read,
// and being the more specific layer, it wins, while no event ever announces it. Watching
// the parent instead would close it, but for `~/.config` the parent is `$HOME`, written to
// constantly for reasons that have nothing to do with proxies. Only
// [`crate::WatchOptions::poll_interval`] closes the hole.
//
// So the second return says the hole is open, and `watch` seeds [`LossFlags::lost`] from
// it. That much is owed by consistency alone: a `~/.config` deleted a second *after*
// construction reaches `drop_ended_directories` and is reported degraded, while the same
// directory already absent a second *before* it was reported as nothing at all: one end
// state, two opposite answers from `health()`.
//
// It is only the *leading* candidate, not any dropped one. Debian's shipped
// `/etc/X11/Xsession.d/60x11-common_xdg_path` prepends `/etc/xdg/xdg-$DESKTOP_SESSION` to
// `XDG_CONFIG_DIRS` without ever checking that it is there, and on Ubuntu 22.04 here it is
// not, so "any dropped candidate" would report a degraded route on an ordinary desktop
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
pub(crate) fn watch(trigger: SyncSender<()>, env: &Env) -> Result<Option<FileWatch>, Error> {
    let (directories, leading_dropped) = watch_targets(config_search_dirs(env));
    // Nothing observable rides on this: a watch registered on no directory answers `false`
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
             but no event would announce it; health() reports this route as degraded, and \
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
// to reach the join below, `drop_ended_directories` deciding how many directories ended,
// the counters recording it, the wake that publishes it, is to remove a directory the
// watcher has already registered and wait on the kernel. The halves are covered separately,
// so without the seam a decrement that publishes the wrong count, or a flag set only on the
// *last* loss, is held by nothing.
fn loss_callback(
    flags: LossFlags,
    directories: Vec<PathBuf>,
    trigger: SyncSender<()>,
) -> impl FnMut(notify::Result<notify::Event>) {
    // Track whether the WARN below has been emitted separately from `lost`: that flag can
    // start `true` on the machine above, before any directory ends or warning is emitted.
    let mut warned = false;
    // Owned by the callback and shrunk as directories end, so the same directory reported
    // twice, a `DELETE_SELF` and a `MOVE_SELF` can both name it, is counted once.
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
                    // separately, reaching zero needs no such guard, since `watched` is
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
                             so kioslaverc changes there will no longer be noticed; \
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
            // Every other loss has a second chance: a surviving directory can fire again
            // and `LossReport::check` runs on every one of those. This one has none: with
            // the last directory gone no further event exists, so if this wake is the one
            // that gets refused, the flags above may never be published to the coordinator
            // at all and `has_live_notifications` keeps claiming a route that is silent.
            if dark {
                super::super::watcher::wake_delivered(&trigger);
            } else {
                super::super::watcher::wake(&trigger);
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

    use super::super::tests::fixture;

    // ----------------------------------------------------------------------------
    // watch_targets: needs real directories, so each case builds its own fixture tree
    // under the temp directory and removes it again. `dirs` is passed in, so no
    // process-wide environment is touched and these stay parallel-safe.
    // ----------------------------------------------------------------------------

    // The case the directory walk exists for: `kioslaverc` lives only in the *last*
    // candidate (an `/etc/xdg` default), so the higher-priority directories must be
    // watched too; that is where the file that will take over gets created.
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
    // dropped from the prefix rather than failing the watch, and when the one dropped is
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
    // would fire on every such machine, and it is the weaker hole besides: a `kioslaverc`
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
    // `Ok(None)` rather than as a failure, and no degraded route either, even though the
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
    // not a lost watch: the directory is still registered.
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

    // A directory outside the requested watch set, and an unrelated file beside the
    // watched file.
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

        // The same directory reported a second time (inotify can produce both shapes)
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
    // leave the survivors counted; that is the state the middle row of
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
        // so the buffer has to be empty when it runs, as it is here, and as it is for the
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
    // onto a full buffer publishes nothing (`Full` leaves no happens-before edge), so the
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

        // An ordinary unconsumed change fills the one slot.
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
    // ENOSPC, and [`Error::Io`]'s `source` is a public field, so which `io::ErrorKind` a
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
    // queue is never noticed; the watch stays registered, `health()` keeps reporting a
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
