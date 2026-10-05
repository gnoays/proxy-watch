"""Checks what `cargo xtask package` wrote into a directory before any of it is published.

Every artifact carries LICENSE-MIT and LICENSE-APACHE, and every one with compiled code
also carries the THIRD-PARTY-LICENSES.txt rendered for its target. Every such notice ends
with the Rust standard library's section. A desktop or Linux artifact links QuickJS, so its
notice names QuickJS's authors; an Android one does not, and names bionic's crtbegin_so.o
instead.

Usage: check_bindings_artifacts.py <dir>
"""

import sys
import tarfile
import zipfile
from pathlib import Path

LICENSES = ("LICENSE-MIT", "LICENSE-APACHE")
NOTICE = "THIRD-PARTY-LICENSES.txt"
QUICKJS = "Fabrice Bellard"
STD = "The Rust standard library"
BIONIC = "The Android Open Source Project"


def wheel(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        licenses = [n for n in names if "/licenses/" in n]
        notice = next((n for n in licenses if n.endswith(NOTICE)), None)
        text = archive.read(notice).decode() if notice else ""
    return names, [Path(n).name for n in licenses], text


def tarball(path):
    with tarfile.open(path) as archive:
        names = archive.getnames()
        notice = next((n for n in names if n.endswith(NOTICE)), None)
        text = archive.extractfile(notice).read().decode() if notice else ""
    return names, [Path(n).name for n in names], text


def c_zip(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        notice = next((n for n in names if n.endswith(NOTICE)), None)
        text = archive.read(notice).decode() if notice else ""
    return names, [Path(n).name for n in names], text


def check(path):
    name = path.name
    if name.endswith(".whl"):
        names, files, notice = wheel(path)
        compiled = True
    elif name.endswith(".tgz"):
        names, files, notice = tarball(path)
        compiled = any(n.endswith(".node") for n in names)
    elif name.endswith(".tar.gz") or name.endswith(".zip"):
        names, files, notice = (tarball if name.endswith(".tar.gz") else c_zip)(path)
        compiled = True
        if not any(n.endswith("include/proxy_watch.h") for n in names):
            return [f"{name}: no include/proxy_watch.h"]
        if not any(n.endswith("lib/native-static-libs.txt") for n in names):
            return [f"{name}: no lib/native-static-libs.txt"]
    else:
        return []
    errors = [f"{name}: no {f}" for f in LICENSES if f not in files]
    if compiled:
        if NOTICE not in files:
            errors.append(f"{name}: no {NOTICE}")
        elif STD not in notice:
            errors.append(f"{name}: {NOTICE} lacks the Rust standard library")
        elif ("android" in name) != (BIONIC in notice):
            errors.append(f"{name}: {NOTICE} {'names' if BIONIC in notice else 'lacks'} bionic's crtbegin_so")
        elif ("android" in name) == (QUICKJS in notice):
            errors.append(f"{name}: {NOTICE} {'names' if QUICKJS in notice else 'lacks'} QuickJS")
    return errors


def main():
    directory = Path(sys.argv[1])
    artifacts = sorted(p for p in directory.iterdir() if p.is_file())
    errors = [e for p in artifacts for e in check(p)]
    for path in artifacts:
        print(path.name)
    for error in errors:
        print(f"::error::{error}")
    if not artifacts:
        print(f"::error::{directory} holds nothing")
        return 1
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
