//! GNOME: `org.gnome.system.proxy` read + `changed` / `writable-changed`
//! (`linux-gnome` → `gio`/`glib`).
//!
//! Prefer `GSettings::changed` over `GProxyResolver` (no notify). Subscribe to root **and**
//! each child schema this machine offers, on both signals — GLib emits `writable-changed`
//! on its own path, and a lock is a change to what [`was_written`] answers. Objects stay on the watcher thread (`!Send`).
//! Schema/key/child lookups are guarded — missing schemas must not abort the process.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::thread::{self, JoinHandle};

use gio::prelude::*;

use crate::config::ProxyConfigSource;
use crate::error::Error;

use super::desktop::Reading;
use super::gsettings_map::{
    self, CHILDREN, GValue, GnomeSettings, KEY_AUTHENTICATION_PASSWORD, KEY_AUTHENTICATION_USER,
    KEY_AUTOCONFIG_URL, KEY_HOST, KEY_IGNORE_HOSTS, KEY_MODE, KEY_PORT, KEY_USE_AUTHENTICATION,
    KEY_USE_SAME_PROXY, SCHEMA,
};

// Whether `http.authentication-password` is read.
pub(crate) const READ_AUTHENTICATION_PASSWORD: bool = false;

// The GLib type of a key, in `GVariant` type-string spelling, so that the reader knows
// which getter to call.
#[derive(Debug, Clone, Copy)]
enum Kind {
    // `s`
    Text,
    // `b`
    Flag,
    // `i`
    Int,
    // `as`
    List,
}

// The keys of the root schema.
const ROOT_KEYS: [(&str, Kind); 4] = [
    (KEY_MODE, Kind::Text),
    (KEY_AUTOCONFIG_URL, Kind::Text),
    (KEY_IGNORE_HOSTS, Kind::List),
    (KEY_USE_SAME_PROXY, Kind::Flag),
];

// The keys every child schema has.
const CHILD_KEYS: [(&str, Kind); 2] = [(KEY_HOST, Kind::Text), (KEY_PORT, Kind::Int)];

// The extra keys of the `http` child (they exist on no other child).
const HTTP_AUTH_KEYS: [(&str, Kind); 2] = [
    (KEY_USE_AUTHENTICATION, Kind::Flag),
    (KEY_AUTHENTICATION_USER, Kind::Text),
];

// Read the current GNOME configuration.
pub(crate) fn read_store() -> Result<Reading, Error> {
    let Some(settings) = read_settings() else {
        crate::trace::debug!(
            schema = SCHEMA,
            "the GSettings schema is not installed; there is no GNOME source here"
        );
        return Ok(Reading::Absent);
    };
    Ok(match gsettings_map::configured_mode(&settings)? {
        Some(mode) => Reading::configured(ProxyConfigSource::GSettings, mode),
        None => {
            crate::trace::debug!(
                schema = SCHEMA,
                "the GSettings schema holds nothing but its defaults; GNOME is unconfigured"
            );
            Reading::Unset
        }
    })
}

// The installed `org.gnome.system.proxy` schema and the source it was found in, or
// `None` when `gsettings-desktop-schemas` is not installed at all.
fn installed_proxy_schema() -> Option<(gio::SettingsSchemaSource, gio::SettingsSchema)> {
    let source = gio::SettingsSchemaSource::default()?;
    let schema = source.lookup(SCHEMA, true)?;
    Some((source, schema))
}

// The schema of the `<SCHEMA>.<name>` child, or `None` when this machine's schema does
// not offer it.
fn child_schema(
    source: &gio::SettingsSchemaSource,
    parent: &gio::SettingsSchema,
    name: &str,
) -> Option<gio::SettingsSchema> {
    if !parent
        .list_children()
        .iter()
        .any(|child| child.as_str() == name)
    {
        return None;
    }
    source.lookup(&format!("{SCHEMA}.{name}"), true)
}

// Copy every key of the schema into a plain map, or `None` when it is not installed.
fn read_settings() -> Option<GnomeSettings> {
    let (source, schema) = installed_proxy_schema()?;
    let root = gio::Settings::new(SCHEMA);

    let mut map = GnomeSettings::new();
    for (key, kind) in ROOT_KEYS {
        read_key(&mut map, &root, &schema, "", key, kind);
    }

    for child in &CHILDREN {
        let Some(child_schema) = child_schema(&source, &schema, child.child) else {
            continue;
        };
        let child_settings = root.child(child.child);
        for (key, kind) in CHILD_KEYS {
            read_key(
                &mut map,
                &child_settings,
                &child_schema,
                child.child,
                key,
                kind,
            );
        }
        if child.scheme == crate::endpoint::Scheme::Http {
            for (key, kind) in HTTP_AUTH_KEYS {
                read_key(
                    &mut map,
                    &child_settings,
                    &child_schema,
                    child.child,
                    key,
                    kind,
                );
            }
            if READ_AUTHENTICATION_PASSWORD {
                read_key(
                    &mut map,
                    &child_settings,
                    &child_schema,
                    child.child,
                    KEY_AUTHENTICATION_PASSWORD,
                    Kind::Text,
                );
            }
        }
    }

    Some(map)
}

// Read one key into `map`, doing nothing when the schema does not declare it.
fn read_key(
    map: &mut GnomeSettings,
    settings: &gio::Settings,
    schema: &gio::SettingsSchema,
    prefix: &str,
    key: &str,
    kind: Kind,
) {
    if !schema.has_key(key) {
        return;
    }
    let value = match kind {
        Kind::Text => GValue::Text(settings.string(key).to_string()),
        Kind::Flag => GValue::Flag(settings.boolean(key)),
        Kind::Int => GValue::Int(settings.int(key)),
        Kind::List => GValue::List(settings.strv(key).iter().map(ToString::to_string).collect()),
    };
    let full = if prefix.is_empty() {
        key.to_owned()
    } else {
        GnomeSettings::child_key(prefix, key)
    };
    if was_written(settings, schema, key) {
        map.mark_written(full.clone());
    }
    map.insert(full, value);
}

// Whether somebody set `key`, rather than it still standing at the compiled schema's
// default.
//
// Three questions, because no one of them sees every administrator on its own.
//
// `g_settings_get_user_value()` answers only for the user's own layer — a site-wide dconf
// profile is invisible to it (<https://docs.gtk.org/gio/method.Settings.get_user_value.html>).
// The profile does move `g_settings_get_default_value()`, which "may be a different value
// than returned by `g_settings_schema_key_get_default_value()` if the system administrator
// has provided a default value"
// (<https://docs.gtk.org/gio/method.Settings.get_default_value.html>), so those two differ
// only when somebody outside the schema has spoken. A vendor's `.gschema.override` is
// compiled into the schema and moves both: nothing *written*, which is not nothing
// configured — a non-Direct override still reaches [`gsettings_map::configured_mode`] as
// this store's configuration.
//
// The converse fails, and the third question is what closes it: an administrator forcing
// `mode='none'` — the schema's own default — moves neither value, and only the lock carries
// the intent. Measured on GLib 2.72.4 through a real `file-db:` profile: locked,
// `g_settings_is_writable()` is the only one of the three that fires; unlocked, an
// administrator default equal to the schema default is invisible to all three and to every
// other GSettings call, and stays unset here — a default offered, not a choice made. Asking
// about the lock costs one case: a backend read-only for some other reason makes every key
// unwritable and so reads as configured. A sandbox is routed to the portal by
// [`super::sandbox`] before this runs, so what is left is `GSETTINGS_BACKEND`. `memory` is
// always writable; `keyfile` takes writability from the settings directory's own
// permissions, so there a `chmod` is enough — measured, not only a backend somebody chose
// to make read-only.
fn was_written(settings: &gio::Settings, schema: &gio::SettingsSchema, key: &str) -> bool {
    settings.user_value(key).is_some()
        || !settings.is_writable(key)
        || settings
            .default_value(key)
            .is_some_and(|effective| effective != schema.key(key).default_value())
}

// The GNOME watcher thread, driving a `GMainContext` of its own.
pub(crate) struct Handle {
    // Set by [`Drop`] to make the thread return.
    stop: Arc<AtomicBool>,
    // Woken by [`Drop`] so the thread can see `stop`. `glib::MainContext` is
    // `Send + Sync`.
    context: glib::MainContext,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle")
            .field("stopped", &self.stop.load(Ordering::SeqCst))
            .field("running", &self.thread.is_some())
            .finish_non_exhaustive()
    }
}

impl Handle {
    // Start the thread and **block until the subscription is live**, so that
    // [`ProxyWatcher::new`](crate::ProxyWatcher::new) cannot return before a change
    // made right after it would be seen.
    pub(crate) fn start(trigger: SyncSender<()>) -> Result<Option<Self>, Error> {
        if installed_proxy_schema().is_none() {
            crate::trace::debug!(
                schema = SCHEMA,
                "the GSettings proxy schema is not installed; there is nothing to \
                 subscribe to on this machine"
            );
            return Ok(None);
        }

        let context = glib::MainContext::new();
        let stop = Arc::new(AtomicBool::new(false));

        // Never more than one message is read; the extra `Sender` clone only exists so
        // that the `with_thread_default` failure path can still report.
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), Error>>();
        let not_acquired = ready_tx.clone();
        let thread_context = context.clone();
        let thread_stop = Arc::clone(&stop);

        let thread = thread::Builder::new()
            .name("proxy-watch-gsettings".to_owned())
            .spawn(move || {
                let inner = thread_context.clone();
                // `g_main_context_push_thread_default` + `pop`, in RAII form.
                // `GSettings` binds to whatever the thread default is when it is
                // constructed, so `subscribe` has to run *inside*.
                let acquired = thread_context.with_thread_default(move || {
                    match subscribe(&trigger) {
                        Ok(settings) => {
                            let _ = ready_tx.send(Ok(()));
                            while !thread_stop.load(Ordering::SeqCst) {
                                // Blocks until a source — a dconf change, or `Drop`'s
                                // `wakeup` — is ready.
                                inner.iteration(true);
                            }
                            // Held until here on purpose: dropping the `GSettings`
                            // objects disconnects their handlers.
                            drop(settings);
                        }
                        Err(error) => {
                            let _ = ready_tx.send(Err(error));
                        }
                    }
                });

                if let Err(error) = acquired {
                    let _ = not_acquired.send(Err(Error::io(
                        "acquiring a GMainContext for the proxy-watch GSettings thread",
                        io::Error::other(error.to_string()),
                    )));
                }
            })
            .map_err(|source| Error::io("spawning the proxy-watch GSettings thread", source))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Some(Self {
                stop,
                context,
                thread: Some(thread),
            })),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            // The sender was dropped without a message, i.e. the thread panicked.
            Err(_) => Err(Error::io(
                "starting the proxy-watch GSettings thread",
                io::Error::other("the watcher thread exited before it became ready"),
            )),
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // Set the flag first: `wakeup` is persistent, so the thread cannot block again
        // without re-checking it.
        self.stop.store(true, Ordering::SeqCst);
        self.context.wakeup();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// Connect both signals on the root schema and on every child this machine's schema offers,
// and return the objects that must stay alive for the connections to stay live.
//
// A child the schema does not offer is skipped rather than subscribed to: [`child_schema`]
// is what decides, and it is the same guard the reads use.
//
// Must run on the thread whose default `GMainContext` the loop will drive: `GSettings`
// binds to the thread-default context at construction time.
fn subscribe(trigger: &SyncSender<()>) -> Result<Vec<gio::Settings>, Error> {
    let missing = |what: &str| {
        Error::io(
            "subscribing to org.gnome.system.proxy",
            io::Error::other(format!("{what} is not installed")),
        )
    };

    let source = gio::SettingsSchemaSource::default()
        .ok_or_else(|| missing("the default GSettings schema source"))?;
    let schema = source.lookup(SCHEMA, true).ok_or_else(|| missing(SCHEMA))?;

    let root = gio::Settings::new(SCHEMA);
    let mut kept = Vec::with_capacity(CHILDREN.len() + 1);

    for child in std::iter::once(None).chain(CHILDREN.iter().map(|c| Some(c.child))) {
        let settings = match child {
            None => root.clone(),
            Some(name) => {
                if child_schema(&source, &schema, name).is_none() {
                    continue;
                }
                root.child(name)
            }
        };
        // Both callbacks do the minimum possible: reading here would run inside GLib's own
        // dispatch and defeat the debounce window.
        let changed = trigger.clone();
        settings.connect_changed(None, move |_, _| {
            super::watcher::wake(&changed);
        });
        // Writability is half of what [`was_written`] answers, and GLib keeps the two
        // notifications apart: `g_settings_real_writable_change_event` emits
        // `writable-changed` alone and never `changed`. So an administrator locking a key
        // whose value does not move is a change to what this crate reports and no change at
        // all to `changed` — without this second connection the watcher would go on
        // publishing the pre-lock mode until something unrelated woke it.
        let writable = trigger.clone();
        settings.connect_writable_changed(None, move |_, _| {
            super::watcher::wake(&writable);
        });
        kept.push(settings);
    }

    crate::trace::debug!(
        schemas = kept.len(),
        root = SCHEMA,
        "subscribed to GSettings::changed and ::writable-changed on the root schema and \
         its children"
    );
    Ok(kept)
}
