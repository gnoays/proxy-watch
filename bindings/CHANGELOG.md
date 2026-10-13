# Changelog

Notable changes to the Node (`proxy-watch` on npm), Python (`proxy-watch` on PyPI) and C
bindings, newest first. The three are released together under one `bindings-vX.Y.Z` tag
and one version. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the version numbers follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each binding is built from the `proxy-watch` crate in the same tree, so its version moves
independently of the crate's. An entry names the crate version it is built from; how a
route is answered is the crate's, and `CHANGELOG.md` at the repository root lists those
changes.

## [Unreleased]

## [0.2.1] - 2026-10-13

Built from crate 0.3.1, which changes some routing answers (a PAC result split at ASCII
whitespace only and kept to its first 64 steps, Android's duplicate steps kept once, and
macOS's PAC engine answering an HTTP proxy for an `https:` URL) and escapes a `%` in a step's user name or password as `%25`.

### Changed

- Node: `read()`, `readSync()`, `watch()` and `watchSync()` without `env` read `*_proxy`
  from the calling thread's `process.env`, not the process environment. On the main
  thread under Node the two hold the same; a worker thread's own copy is read now, and
  under Bun, whose `process.env` writes do not reach the process environment, so is a
  variable set at run time. A `process.env` that is missing or not an object of strings
  now throws `ERR_PROXY_WATCH`.

### Fixed

- Python: `repr()` of a `Route` masks a password in its `pac_url` as `***`, as it does a
  step's.
- Node: `Watcher.close()` removes the watch's cleanup hook and frees what it held. Each
  watch opened and closed kept about 500 bytes until its thread's environment ended, so
  a process that opens and closes watches in a loop grew without bound.

## [0.2.0] - 2026-10-09

Built from crate 0.3.0, which changes some routing answers (macOS with an empty bypass
list, KDE's `ReversedException`, link-local destinations under `no_proxy`).

### Added

- Node `Snapshot.toJSON()` and Python `Snapshot.to_dict()`: the whole configuration as
  plain data, with the mode in effect, each source's mode, the fallbacks, the masked
  rejected values and whether the OS settings were readable. A manual mode carries each
  scheme's proxy, its user name and password, why a password is missing, and the bypass
  rules. Not in the C binding yet.
- Python: `Route` and `Diagnostics` compare and hash by value, `PacPolicy` compares by
  value, and every class has a `repr()`; `Route`'s masks a step's password.
- Node: `Snapshot` and `Watcher` have `toString()` and a `util.inspect` form.
- ARMv7 Linux with glibc: the npm package `proxy-watch-linux-arm-gnueabihf` and a
  `manylinux2014_armv7l` wheel, with QuickJS. The C archive is not built for it.
- A CPython 3.14t (free-threaded) wheel beside the abi3 one on every platform.

### Changed

- Python: the type stub's explanations are docstrings, so editors show them, and the stub
  declares `PacPolicy` unhashable, as it is at run time.

## [0.1.1]

Built from crate 0.2.0. The first version on npm; npm and PyPI carry the same version from
here on.

## [0.1.0]

The first version. Reached PyPI only: the npm publish stopped before it published.
