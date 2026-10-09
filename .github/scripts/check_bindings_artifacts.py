"""Checks what `cargo xtask package` wrote into a directory before any of it is published.

Every artifact carries LICENSE-MIT and LICENSE-APACHE, and every one with compiled code
also carries the THIRD-PARTY-LICENSES.txt rendered for its target. Every such notice ends
with the Rust standard library's section. A desktop or Linux artifact links QuickJS, so its
notice names QuickJS's authors; an Android one does not, and names bionic's crtbegin_so.o
instead. A wheel built for one interpreter rather than for abi3 holds an extension module
whose suffix names the architecture and C library of the wheel's platform tag, since the
interpreter imports no other.

Usage: check_bindings_artifacts.py <dir>
"""

import re
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


def suffix_for(platform):
    """What a version-specific extension module's file name holds on `platform`, a wheel's
    first platform tag, or None where the suffix names no architecture (macOS)."""
    linux = re.fullmatch(r"(many|musl)linux_\d+_\d+_(\w+)", platform)
    if linux:
        libc, arch = linux.groups()
        libc = "gnu" if libc == "many" else "musl"
        if arch == "armv7l":
            return f"-arm-linux-{libc}eabihf."
        return f"-{arch}-linux-{libc}."
    if platform.startswith("win_"):
        return f"-{platform}.pyd"
    return None


def interpreter_errors(name, names):
    abi, platform = name[: -len(".whl")].split("-")[3:5]
    if abi == "abi3":
        return []
    marker = suffix_for(platform.split(".")[0])
    modules = [n for n in names if n.endswith((".so", ".pyd"))]
    if marker is None or any(marker in m for m in modules):
        return []
    return [f"{name}: no extension module for {platform}: {', '.join(modules)}"]


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
        mismatch = interpreter_errors(name, names)
        if mismatch:
            return mismatch
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
