"""Reads a linker map and reports what went into the linked binary, by origin.

Usage: link_inventory.py <map> <msvc|ld64|lld> <label> [notice]

Prints, for one binary:
- the Rust crates whose rlibs contributed objects;
- every other archive with the members it contributed, and the standalone objects;
- with a notice (a rendered THIRD-PARTY-LICENSES.txt), the linked crates it does not name.

A map this script cannot parse still yields its raw input lines, so a run is never wasted
on a format it misreads. The output is plain text for the job log and Markdown for the step
summary.
"""

import os
import re
import sys
from collections import defaultdict
from pathlib import PureWindowsPath, PurePosixPath

OWN = {"proxy_watch", "proxy_watch_shared", "proxy_watch_node", "proxy_watch_python", "proxy_watch_c"}
RLIB = re.compile(r"^lib([A-Za-z0-9_]+)-[0-9a-f]{8,}(?:\.rlib)?$")
# `/path/lib.a(member.o)`, `/path/lib.a[3](member.o)` (newer ld64), or `/path/obj.o`.
POSIX_INPUT = re.compile(
    r"((?:/|[A-Za-z]:[\\/])[^\s():\[\]]+?\.(?:a|rlib|o|tbd|dylib|so))(?=$|[\s(\[])(?:\[\d+\])?(?:\(([^()]+)\))?"
)


def basename(path):
    return (PureWindowsPath if "\\" in path else PurePosixPath)(path).name


def inputs_lld(text):
    for line in text.splitlines():
        match = re.search(r"\s((?:/|[A-Za-z]:[\\/])\S+?)(?:\(([^()]+)\))?:\(", line)
        if match:
            yield match.group(1), match.group(2)


def inputs_ld64(text):
    section = text.split("# Object files:", 1)[-1].split("# Sections:", 1)[0]
    for line in section.splitlines():
        match = POSIX_INPUT.search(line)
        if match:
            yield match.group(1), match.group(2)


def inputs_msvc(text):
    for line in text.splitlines():
        token = line.split()[-1] if line.split() else ""
        if token.startswith("<") or not re.search(r"\.(obj|o|dll)$", token, re.I):
            continue
        if ":" in token:
            lib, obj = token.split(":", 1)
            yield lib, obj
        else:
            yield None, token


def crate_of(archive, member):
    """The crate an input belongs to, from its rlib or from a crate's own `.rcgu.o`."""
    if archive:
        match = RLIB.match(basename(archive))
        if match:
            return match.group(1)
    for name in (member, archive and basename(archive)):
        if name and name.endswith(".rcgu.o"):
            return name.split("-")[0].split(".")[0]
    return None


def notice_crates(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    names = set(re.findall(r"^  ([A-Za-z0-9_\-]+) \d", text, re.M))
    for line in re.findall(r"^In-tree crates: (.*)\.$", text, re.M):
        names.update(n.strip() for n in line.split(","))
    names.update(re.findall(r"^([A-Za-z0-9_\-]+) \d[^\s]* \(.*taken under MIT\)$", text, re.M))
    return {n.replace("-", "_") for n in names}


def main():
    map_path, kind, label = sys.argv[1:4]
    notice = sys.argv[4] if len(sys.argv) > 4 else None
    text = open(map_path, encoding="utf-8", errors="replace").read()
    reader = {"msvc": inputs_msvc, "ld64": inputs_ld64, "lld": inputs_lld}[kind]

    crates = set()
    archives = defaultdict(set)
    foreign = defaultdict(set)
    standalone = set()
    dlls = set()
    for archive, member in reader(text):
        crate = crate_of(archive, member)
        if crate:
            crates.add(crate)
            # C objects that a crate's build script compiled into its rlib: QuickJS in
            # `rquickjs-sys`, LLVM's compiler-rt in `compiler_builtins`.
            if member and "rcgu" not in member and not member.endswith(".rmeta"):
                foreign[crate].add(member)
        elif member and member.lower().endswith(".dll"):
            dlls.add(f"{archive}:{member}" if archive else member)
        elif archive and member:
            archives[basename(archive)].add(member)
        elif archive:
            standalone.add(basename(archive))
        elif member:
            standalone.add(member)

    lines = [f"### {label}", f"map: {os.path.getsize(map_path)} bytes, format {kind}"]
    lines.append(f"Rust crates ({len(crates)}): {', '.join(sorted(crates)) or '(none)'}")
    lines.append(f"C objects inside Rust crates ({len(foreign)}):")
    for name in sorted(foreign):
        members = sorted(foreign[name])
        shown = ", ".join(members[:60]) + (f", ... ({len(members)} in all)" if len(members) > 60 else "")
        lines.append(f"  {name}: {shown}")
    lines.append(f"Other archives ({len(archives)}):")
    for name in sorted(archives):
        members = sorted(archives[name])
        shown = ", ".join(members[:40]) + (f", ... ({len(members)} in all)" if len(members) > 40 else "")
        lines.append(f"  {name}: {shown}")
    lines.append(f"Standalone inputs ({len(standalone)}): {', '.join(sorted(standalone)) or '(none)'}")
    if dlls:
        lines.append(f"Import entries ({len(dlls)}): {', '.join(sorted(dlls)[:80])}")
    if notice:
        named = notice_crates(notice)
        missing = sorted(c for c in crates if c not in named and c not in OWN)
        lines.append(f"Linked crates the notice does not name: {', '.join(missing) or '(none)'}")
    if not crates and not archives:
        lines.append("Nothing parsed; raw input lines follow.")
        raw = sorted({l.strip() for l in text.splitlines() if re.search(r"\.(obj|o|a|rlib|lib)\b", l)})
        lines.extend(f"  {l[:300]}" for l in raw[:400])

    print("\n".join(lines))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write("\n".join(lines).replace("\n  ", "\n- ") + "\n\n")


if __name__ == "__main__":
    main()
