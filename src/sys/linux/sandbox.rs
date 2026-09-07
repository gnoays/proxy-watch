//! Sandbox detection before GSettings (Flatpak without `ca.desrt.dconf` talk → keyfile
//! backend silently reports Direct). Mirrors GLib's dconf-access check via
//! `/.flatpak-info`. Snap via `$SNAP/meta/snap.yaml` ([`snap_confinement`]), *not* the
//! bare `SNAP` variable — GLib's `is_snap` excludes `confinement: classic`. No-dconf →
//! [`super::portal`] else [`Error::Sandboxed`](crate::Error::Sandboxed).
//!
//! Under strict confinement GLib asks `snapctl is-connected gsettings`
//! (`glib_has_dconf_access_in_sandbox`, `gio/gportalsupport.c`) rather than refusing
//! outright; this crate assumes no access instead. Spawning `snapctl` is not something a
//! library should do from a read — GLib itself guards that call with a setuid check — and
//! the assumption errs towards the portal, never towards a silent `Direct`.
//!
//! <div class="warning">
//!
//! **Unverified:** no real Flatpak or Snap runtime has ever run this detection — the
//! tests build a synthetic `/.flatpak-info` and `snap.yaml` instead.
//! **Risk:** the paths are not the exposure — GLib hardcodes the same `/.flatpak-info`
//! (`read_flatpak_info`, `gio/gportalsupport.c`) and the same `$SNAP/meta/snap.yaml`, so a
//! runtime that spelled either differently would take GLib's own check with it. What can
//! still diverge is the reading: parse the metadata more leniently than GKeyFile and
//! GSettings is trusted after all, which is precisely the case this module exists to
//! prevent — the keyfile backend answers `Direct` there instead of failing.
//! **Symptom:** inside the sandbox the crate reports no proxy while the host has one,
//! and [`Error::Sandboxed`](crate::Error::Sandboxed) is never returned.
//!
//! </div>

// Compiled on every target under `cfg(test)`: the parser is pure and its tests are the
// only ones that can run without a sandbox.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

// The file Flatpak places in every sandbox.
const FLATPAK_INFO: &str = "/.flatpak-info";

// The section of `/.flatpak-info` that lists the session bus policy.
const SESSION_BUS_POLICY: &str = "Session Bus Policy";

// The bus name of the dconf service.
const DCONF_BUS_NAME: &str = "ca.desrt.dconf";

// The one policy value GLib accepts, byte for byte (`gio/gportalsupport.c`):
const DCONF_POLICY_TALK: &str = "talk";

// The environment variable snapd sets to the snap's install directory. The only one
// consulted, because it is the only one that leads anywhere: GLib's `is_snap`
// (`gio/gsandbox.c`) reads `$SNAP/meta/snap.yaml` and needs the path, and a `SNAP_NAME`
// with no `SNAP` alongside it — a snapcraft build shell, a snap hook — names no manifest
// to check.
const SNAP_DIR: &str = "SNAP";

// The manifest inside a snap, relative to [`SNAP_DIR`].
const SNAP_YAML: &str = "meta/snap.yaml";

// The line of `snap.yaml` that carries the confinement level, in the spelling GLib's
// `get_snap_confinement` looks for: `g_str_has_prefix`, so anchored at column zero.
const CONFINEMENT_PREFIX: &str = "confinement:";

// The one confinement level that is not a sandbox. GLib's own comment in
// `get_snap_confinement` (`gio/gsandbox.c`): "Classic snaps are de-facto no sandboxed
// apps, so we can ignore them" — they run with full system access, so GSettings reaches
// dconf exactly as it would outside a snap.
const CONFINEMENT_CLASSIC: &str = "classic";

// What kind of sandbox — if any — the process is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sandbox {
    // Not sandboxed: GSettings talks to dconf and can be trusted.
    None,
    // Flatpak, with the outcome of the `ca.desrt.dconf` policy check.
    Flatpak {
        // `true` when the manifest grants exactly `talk` on `ca.desrt.dconf` — `own`
        // does not count, for the reason [`has_dconf_access`] gives.
        dconf_access: bool,
    },
    // A snap under any confinement GLib's `is_snap` still calls a sandbox — that is,
    // anything but `classic`. Treated as "sandboxed, dconf access unknown" — see the
    // module docs.
    Snap,
}

impl Sandbox {
    // Whether GSettings can be believed.
    //
    // `false` is exactly the case where GSettings would answer `mode = 'none'` without
    // erroring, so the answer has to come from the portal instead.
    pub(crate) fn gsettings_is_trustworthy(self) -> bool {
        match self {
            Sandbox::None => true,
            Sandbox::Flatpak { dconf_access } => dconf_access,
            Sandbox::Snap => false,
        }
    }

    // A human readable name for [`Error::Sandboxed`](crate::Error::Sandboxed).
    pub(crate) fn name(self) -> &'static str {
        match self {
            Sandbox::None => "unsandboxed",
            Sandbox::Flatpak { .. } => "Flatpak",
            Sandbox::Snap => "Snap",
        }
    }
}

// Detect the sandbox of the current process.
pub(crate) fn detect() -> Sandbox {
    sandbox_from_flatpak_read(std::fs::read_to_string(FLATPAK_INFO), is_snap)
}

// The decision half of [`detect`], taking the read result rather than doing the read
// itself: the real path is a hardcoded absolute filesystem path, so this is the piece a
// test can actually drive.
fn sandbox_from_flatpak_read(
    read: std::io::Result<String>,
    is_snap: impl FnOnce() -> bool,
) -> Sandbox {
    match read {
        Ok(text) => Sandbox::Flatpak {
            dconf_access: has_dconf_access(&text),
        },
        // A `/.flatpak-info` present but unreadable — non-UTF-8 content
        // (`read_to_string`'s `InvalidData`), denied permissions, or any other I/O
        // error — still means the sandbox is real; it is *absence* that means it is
        // not. GLib's own load fails the same way on a file it cannot parse
        // (`has_dconf_access`'s doc above: "a file GKeyFile refuses denies access") and
        // answers `dconf_access: false` rather than pretending the file was never
        // there. A read failure earns the same answer here, for the same reason:
        // skipping it would be the misdetection this whole module exists to prevent,
        // not just a parse-time instance of it.
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => Sandbox::Flatpak {
            dconf_access: false,
        },
        Err(_) if is_snap() => Sandbox::Snap,
        Err(_) => Sandbox::None,
    }
}

// Whether this process is inside a snap that actually confines it.
//
// GLib's `is_snap` (`gio/gsandbox.c`) in full: `$SNAP` must be set, `$SNAP/meta/snap.yaml`
// must be *readable* — an unreadable manifest sets its `GError` and makes the answer
// `FALSE`, not `TRUE` — and the confinement it declares must not be `classic`.
fn is_snap() -> bool {
    let Some(snap_dir) = std::env::var_os(SNAP_DIR) else {
        return false;
    };
    let manifest = std::path::Path::new(&snap_dir).join(SNAP_YAML);
    let Ok(yaml) = std::fs::read_to_string(&manifest) else {
        return false;
    };
    snap_is_confined(&yaml)
}

// The decision half of [`is_snap`], taking the manifest text rather than reading it — the
// same split, and for the same reason, as [`sandbox_from_flatpak_read`] above: the path
// comes from the environment, so this is the piece a test can drive.
//
// A manifest with no `confinement:` line at all still counts as confined: GLib compares with
// `g_strcmp0`, for which a missing value is simply "not classic". Read the other way round —
// only a manifest that names a level is believed — a snap whose manifest this crate could
// not find a level in would be trusted, and that is the silent `mode = 'none'` the module
// exists to prevent.
fn snap_is_confined(yaml: &str) -> bool {
    snap_confinement(yaml) != Some(CONFINEMENT_CLASSIC)
}

// The confinement level `snap.yaml` declares, read the way `get_snap_confinement` does.
//
// The prefix is matched with no leading-whitespace trim (`g_str_has_prefix`), the first
// matching line wins, and the value is everything up to the newline with both ends
// stripped (`g_strstrip`).
fn snap_confinement(yaml: &str) -> Option<&str> {
    yaml.lines()
        .find_map(|line| line.strip_prefix(CONFINEMENT_PREFIX))
        .map(str::trim_ascii)
}

// Whether `/.flatpak-info` grants the sandbox access to dconf.
//
// GLib does not scan the file for the one line it wants: it loads the whole thing with
// `g_key_file_load_from_file` and reads the key out of the result (`read_flatpak_info`,
// `gio/gportalsupport.c`). That call is the sole guard on a `dconf_access` initialised to
// `FALSE`, so **a file GKeyFile refuses denies access**. Hence the `return false`s below:
// skipping a line GKeyFile would reject is the dangerous reading, because it grants a
// GSettings read that GLib — having rejected the same file — serves from the keyfile
// backend as `mode = 'none'`, the silent `Direct` this module exists to prevent.
pub(crate) fn has_dconf_access(flatpak_info: &str) -> bool {
    let mut in_section = false;
    let mut in_group = false;
    let mut granted = false;
    for line in flatpak_info.lines() {
        // `g_key_file_parse_line` strips a line's leading whitespace and nothing else,
        // then sorts what is left into exactly three shapes. A line that is none of them
        // is `G_KEY_FILE_ERROR_PARSE`, which fails the load.
        let line = line.trim_ascii_start();
        // `g_key_file_line_is_comment` is `#` and the empty line — and nothing else. A
        // `;` opens a *key* here, not a comment.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let Some(name) = group_name(rest) else {
                return false;
            };
            // `g_key_file_parse_group` keeps the name exactly as written, so
            // `[ Session Bus Policy ]` is a *different* group to GLib.
            in_section = name == SESSION_BUS_POLICY;
            in_group = true;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        // "Key file does not start with a group" — a parse error like any other.
        if !in_group {
            return false;
        }
        // The key's trailing whitespace is chomped by GKeyFile and the value's *leading*
        // whitespace is chugged; the value's trailing whitespace stays. An empty key name
        // is rejected ("No empty keys, please").
        let key = key.trim_ascii_end();
        if key.is_empty() {
            return false;
        }
        // `g_key_file_is_key_name` accepts exactly one shape carrying a bracket — a
        // trailing `[locale]`, well formed and with no space before it. Measured on GLib
        // 2.72: `bad]key`, `bad[key`, `foo[` and `a]b[c` are each `Invalid key name`,
        // while inner spaces, tabs and control characters are not. Flatpak writes no
        // localised key, so refusing every bracket diverges only on a shape this file
        // does not contain, and refusing is the direction the doc above requires.
        if key.bytes().any(|byte| byte == b'[' || byte == b']') {
            return false;
        }
        if in_section && key == DCONF_BUS_NAME {
            // GKeyFile is last-wins for duplicate keys in a group.
            granted = value.trim_ascii_start() == DCONF_POLICY_TALK;
        }
    }
    granted
}

// The name of a `[group]` line whose `[` has already been stripped, or `None` when
// GKeyFile would not accept the line as a group at all.
//
// `g_key_file_line_is_group` wants a `]` with nothing but spaces and tabs after it, and
// `g_key_file_is_group_name` wants a non-empty name carrying no `[`, no `]` and no ASCII
// control character.
fn group_name(after_bracket: &str) -> Option<&str> {
    // The first `]` is the only one an accepted line can have: anything after it that is
    // not a blank already disqualifies the line.
    let (name, rest) = after_bracket.split_once(']')?;
    if !rest.bytes().all(|byte| byte == b' ' || byte == b'\t') {
        return None;
    }
    if name.is_empty()
        || name
            .bytes()
            .any(|byte| byte == b'[' || byte.is_ascii_control())
    {
        return None;
    }
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The shape of a real `/.flatpak-info`, trimmed to what matters here.
    const TEMPLATE: &str = "\
[Application]
name=org.example.App
runtime=runtime/org.gnome.Platform/x86_64/45

[Context]
shared=network;ipc;
sockets=x11;wayland;

[Session Bus Policy]
org.freedesktop.Notifications=talk
{DCONF}

[Instance]
instance-id=1234567890
";

    fn info(dconf_line: &str) -> String {
        TEMPLATE.replace("{DCONF}", dconf_line)
    }

    #[test]
    fn a_talk_policy_grants_dconf_access() {
        assert!(has_dconf_access(&info("ca.desrt.dconf=talk")));
        // GKeyFile drops a line's leading whitespace, a key's trailing whitespace and a
        // value's *leading* whitespace, so this still reaches `strcmp` as exactly `talk`.
        assert!(has_dconf_access(&info("  ca.desrt.dconf = talk")));
        // The other half of `g_key_file_line_is_comment`, and the half this row alone holds: `#`
        // opens a comment and the line is skipped, where the `;` below is a key and fails
        // the load. Treating `#` as a key too would deny access over a file GLib reads
        // without complaint — the cautious direction, but a wrong one, and it would send
        // every such sandbox to the portal for no reason.
        assert!(has_dconf_access(&info("# a comment\nca.desrt.dconf=talk")));
    }

    #[test]
    fn a_missing_or_weaker_policy_does_not() {
        // The default Flatpak manifest: no dconf line at all. This is the silent
        // misdetection case.
        assert!(!has_dconf_access(&info("")));
        assert!(!has_dconf_access(&info("ca.desrt.dconf=see")));
        assert!(!has_dconf_access(&info("ca.desrt.dconf=none")));
        assert!(!has_dconf_access(""));
    }

    // Each of these was accepted here and is rejected by GLib's
    // `strcmp (dconf_policy, "talk") == 0`, so each meant trusting a `GSettings` read
    // that GLib serves from the keyfile backend as `mode = 'none'` — the silent `Direct`
    // this whole module exists to prevent.
    #[test]
    fn a_policy_glib_itself_would_reject_does_not_grant_access() {
        assert!(
            !has_dconf_access(&info("ca.desrt.dconf=own")),
            "`own` implies `talk` on the bus, and GLib still does not compare against it"
        );
        assert!(
            !has_dconf_access(&info("ca.desrt.dconf=talk ")),
            "GKeyFile keeps a value's trailing whitespace, so `strcmp` fails on this"
        );
        assert!(
            !has_dconf_access(&info("ca.desrt.dconf=Talk")),
            "`strcmp` is case sensitive"
        );
        assert!(
            !has_dconf_access(&info("ca.desrt.dconf=\u{a0}talk")),
            "GKeyFile chugs with `g_ascii_isspace`, which is ASCII and locale independent"
        );
    }

    #[test]
    fn duplicate_dconf_keys_are_last_wins() {
        assert!(!has_dconf_access(&info(
            "ca.desrt.dconf=talk\nca.desrt.dconf=none"
        )));
        assert!(has_dconf_access(&info(
            "ca.desrt.dconf=none\nca.desrt.dconf=talk"
        )));
    }

    #[test]
    fn the_policy_only_counts_inside_its_own_section() {
        let text = "\
[Session Bus Policy]
org.freedesktop.Notifications=talk

[Environment]
ca.desrt.dconf=talk
";
        assert!(
            !has_dconf_access(text),
            "a key outside [Session Bus Policy] must not grant access"
        );
    }

    // GLib loads this file with `g_key_file_load_from_file`, which fails the *whole
    // document* over one bad line and leaves `read_flatpak_info`'s `dconf_access` at
    // `FALSE`. Skipping the bad line and reading on would be the fail-open direction:
    // trusting a `GSettings` that GLib, having rejected the same file, answers
    // `mode = 'none'`.
    #[test]
    fn a_line_gkeyfile_would_reject_denies_access() {
        assert!(
            !has_dconf_access(&info("ca.desrt.dconf=talk\nnot a key-value pair")),
            "a line that is neither comment, group nor `key=value` is G_KEY_FILE_ERROR_PARSE"
        );
        assert!(
            !has_dconf_access(&info("; a comment\nca.desrt.dconf=talk")),
            "`g_key_file_line_is_comment` is `#` and the blank line only — `;` opens a key"
        );
        // Every row here needs a granting `ca.desrt.dconf` line *after* the bad one, or it
        // cannot fail: without it the answer is `false` because nothing granted anything,
        // not because the load was refused. This row had no such line and did not hold the
        // empty-key check at all.
        assert!(
            !has_dconf_access(&info("=talk\nca.desrt.dconf=talk")),
            "\"No empty keys, please\""
        );
        assert!(
            !has_dconf_access("[]\n\n[Session Bus Policy]\nca.desrt.dconf=talk\n"),
            "`g_key_file_is_group_name` wants a non-empty name"
        );
        assert!(
            !has_dconf_access("[App\u{1}]\n\n[Session Bus Policy]\nca.desrt.dconf=talk\n"),
            "and rejects an ASCII control character inside one"
        );
        // The second `[` opens nothing — `g_key_file_line_is_group` stops at the first `]`
        // and hands `App[1` to `g_key_file_is_group_name`, which refuses it. Measured on
        // GLib 2.72 through `g_key_file_load_from_data`: `Invalid group name: App[1`.
        // This row is the only thing holding that half — the control character above is a
        // different refusal — so without it a manifest carrying this line is read on past a
        // load GLib refuses.
        assert!(
            !has_dconf_access("[App[1]\n\n[Session Bus Policy]\nca.desrt.dconf=talk\n"),
            "and a `[` inside one, which no locale suffix can excuse in a group name"
        );
        assert!(
            !has_dconf_access("ca.desrt.dconf=talk\n[Session Bus Policy]\nca.desrt.dconf=talk\n"),
            "\"Key file does not start with a group\""
        );
        assert!(
            !has_dconf_access("[Session Bus Policy\nca.desrt.dconf=talk\n"),
            "`g_key_file_line_is_group` wants the closing `]`"
        );
        assert!(
            !has_dconf_access("[Session Bus Policy] x\nca.desrt.dconf=talk\n"),
            "only spaces and tabs may follow the `]`"
        );
        // Measured on GLib 2.72 through `g_key_file_load_from_data`. The key is in another
        // group, exactly as a real one would be — the load fails before the policy line is
        // ever reached.
        assert!(
            !has_dconf_access(
                "[Application]\nbad]key=v\n\n[Session Bus Policy]\nca.desrt.dconf=talk\n"
            ),
            "`g_key_file_is_key_name` rejects a `]` outside a locale suffix"
        );
        assert!(
            !has_dconf_access(&info("bad[key=v\nca.desrt.dconf=talk")),
            "and rejects a `[` that opens no locale suffix"
        );
    }

    // `g_key_file_parse_group` keeps the name exactly as written, so the padded header
    // names a group GLib never looks in — while `g_key_file_line_is_group` does allow
    // blanks *after* the `]`.
    #[test]
    fn a_group_header_is_taken_exactly_as_written() {
        assert!(!has_dconf_access(
            "[ Session Bus Policy ]\nca.desrt.dconf=talk\n"
        ));
        assert!(has_dconf_access(
            "[Session Bus Policy] \t\nca.desrt.dconf=talk\n"
        ));
    }

    // The shape of a real `meta/snap.yaml`, trimmed to what matters here.
    const SNAP_YAML_TEMPLATE: &str = "\
name: example
version: '1.0'
summary: An example snap
{CONFINEMENT}
grade: stable
";

    fn snap_yaml(confinement_line: &str) -> String {
        SNAP_YAML_TEMPLATE.replace("{CONFINEMENT}", confinement_line)
    }

    #[test]
    fn the_confinement_line_is_read_the_way_glib_reads_it() {
        assert_eq!(
            snap_confinement(&snap_yaml("confinement: strict")),
            Some("strict")
        );
        // `g_strstrip` takes both ends, so the padding never reaches the comparison.
        assert_eq!(
            snap_confinement(&snap_yaml("confinement:   classic  ")),
            Some(CONFINEMENT_CLASSIC)
        );
        // A manifest with no confinement at all: `get_snap_confinement` returns NULL.
        assert_eq!(snap_confinement(&snap_yaml("grade: devel")), None);
        assert_eq!(snap_confinement(""), None);
    }

    // `g_str_has_prefix` is anchored, unlike the `/.flatpak-info` reader above, which goes
    // through GKeyFile and does trim. An indented line is therefore not the confinement
    // line — and mistaking one for it would be the wrong way round, turning a strict snap
    // into an unsandboxed one.
    #[test]
    fn an_indented_confinement_line_is_not_the_confinement_line() {
        assert_eq!(snap_confinement(&snap_yaml("  confinement: classic")), None);
    }

    #[test]
    fn the_first_confinement_line_wins() {
        assert_eq!(
            snap_confinement("confinement: strict\nconfinement: classic\n"),
            Some("strict"),
            "GLib breaks out of its scan at the first match"
        );
    }

    // `snap_confinement` answering `None` is pinned above; what that `None` then *means* was
    // not. A manifest this crate finds no level in is still a sandbox, and reading it the
    // other way — believing only a manifest that names one — trusts GSettings inside a snap,
    // which answers `mode = 'none'` from the keyfile backend.
    #[test]
    fn a_manifest_naming_no_confinement_is_still_confined() {
        assert!(snap_is_confined(&snap_yaml("grade: devel")));
        assert!(snap_is_confined(""));
        assert!(snap_is_confined(&snap_yaml("confinement: strict")));
        assert!(!snap_is_confined(&snap_yaml("confinement: classic")));
    }

    #[test]
    fn gsettings_trust_follows_the_policy() {
        assert!(Sandbox::None.gsettings_is_trustworthy());
        assert!(Sandbox::Flatpak { dconf_access: true }.gsettings_is_trustworthy());
        assert!(
            !Sandbox::Flatpak {
                dconf_access: false
            }
            .gsettings_is_trustworthy(),
            "this is the silent `mode = none` case that must never reach the user"
        );
        assert!(!Sandbox::Snap.gsettings_is_trustworthy());
    }

    // Before `sandbox_from_flatpak_read` split the decision out of `detect`, *any*
    // `/.flatpak-info` read failure — not only "the file does not exist" — fell straight
    // through to the snap check and then `Sandbox::None`: a present-but-non-UTF-8 (or
    // permission-denied) file read exactly like an absent one, trusting GSettings even
    // though the sandbox is real. That is the silent `Direct` this whole module exists
    // to prevent, one step earlier than the parse failures the tests above already cover.
    #[test]
    fn an_unreadable_flatpak_info_denies_dconf_access_instead_of_looking_unsandboxed() {
        let invalid_utf8 = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        );
        assert_eq!(
            sandbox_from_flatpak_read(Err(invalid_utf8), || false),
            Sandbox::Flatpak {
                dconf_access: false
            }
        );

        let permission_denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            sandbox_from_flatpak_read(Err(permission_denied), || true),
            Sandbox::Flatpak {
                dconf_access: false
            },
            "a real Flatpak sandbox, not the snap check, decides this even when is_snap() would say yes"
        );
    }

    // Only outright absence — not any other read failure — means "not a Flatpak", so
    // only it falls through to the snap check.
    #[test]
    fn a_missing_flatpak_info_falls_through_to_the_snap_check() {
        let not_found = || std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(
            sandbox_from_flatpak_read(Err(not_found()), || false),
            Sandbox::None
        );
        assert_eq!(
            sandbox_from_flatpak_read(Err(not_found()), || true),
            Sandbox::Snap
        );
    }
}
