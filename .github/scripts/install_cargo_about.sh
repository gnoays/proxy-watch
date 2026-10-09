#!/usr/bin/env bash
# Puts cargo-about's release binary for this runner on the job's PATH, for the steps after
# this one.
#
# The release binary renders every notice `cargo xtask third-party-licenses` writes
# byte-for-byte as a `cargo install --locked cargo-about --features cli` build of the same
# version does, and arrives in seconds where the build takes minutes. Each archive is
# checked against the SHA-256 below, copied from the `.sha256` file the release publishes
# beside it; a new version replaces the version and all three sums together.
set -euo pipefail

version=0.9.2
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    target=x86_64-unknown-linux-musl
    sha256=9099a59e820c38a68b9d65f300662a567d56562f9a10f6aa4c7e86c17c2566af ;;
  Darwin-arm64)
    target=aarch64-apple-darwin
    sha256=ae72f0df0c399a1e96336f696fa55b1b28679fd725632eba8cf8e4568467cc3e ;;
  MINGW*-x86_64 | MSYS*-x86_64)
    target=x86_64-pc-windows-msvc
    sha256=1c03e5890238562497c2d89a3b75b02560af349c1fc3e713d3284f532a5cd748 ;;
  *)
    echo "::error::no cargo-about $version release binary for $(uname -s)-$(uname -m)"
    exit 1 ;;
esac

name="cargo-about-$version-$target"
dir="$RUNNER_TEMP/cargo-about"
mkdir -p "$dir"
# Relative names from here on: GNU tar reads `D:` in a Windows path as a remote host.
cd "$dir"
curl -sSfL --retry 3 -o "$name.tar.gz" \
  "https://github.com/EmbarkStudios/cargo-about/releases/download/$version/$name.tar.gz"
if command -v sha256sum > /dev/null; then
  echo "$sha256  $name.tar.gz" | sha256sum -c -
else
  echo "$sha256  $name.tar.gz" | shasum -a 256 -c -
fi
tar -xzf "$name.tar.gz"
echo "$dir/$name" >> "$GITHUB_PATH"
