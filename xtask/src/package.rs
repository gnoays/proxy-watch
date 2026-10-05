//! `cargo xtask package`: builds one binding for one target and packs what a registry or a
//! release page takes, with the license files beside it.
//!
//! Linux artifacts are linked with `cargo zigbuild` against glibc 2.17 (or musl), so they load
//! on any distribution as old as manylinux2014; `cargo zigbuild` and `zig` come from PyPI
//! (`cargo-zigbuild`, `ziglang`). Every other target builds with the host toolchain: macOS
//! builds both architectures, Windows MSVC both, and Android takes the NDK linker the caller
//! names in `CARGO_TARGET_<TRIPLE>_LINKER`. That NDK's `sysroot/NOTICE` must carry the bionic
//! text the Android notice quotes, or the packaging stops.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{render_notice, repo, run};

/// The npm platform suffix napi-rs gives each target the Node binding is built for.
const NODE_PLATFORMS: [(&str, &str); 8] = [
    ("x86_64-unknown-linux-gnu", "linux-x64-gnu"),
    ("aarch64-unknown-linux-gnu", "linux-arm64-gnu"),
    ("x86_64-unknown-linux-musl", "linux-x64-musl"),
    ("aarch64-unknown-linux-musl", "linux-arm64-musl"),
    ("x86_64-apple-darwin", "darwin-x64"),
    ("aarch64-apple-darwin", "darwin-arm64"),
    ("x86_64-pc-windows-msvc", "win32-x64-msvc"),
    ("aarch64-pc-windows-msvc", "win32-arm64-msvc"),
];

/// `binding` for `target` into `out`: an npm tarball, a wheel, or a C archive. `target` is
/// `root` for the Node package that holds the loader and the typings.
pub(crate) fn package(binding: &str, target: &str, out: &Path) -> Result<(), String> {
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let out = &std::path::absolute(out).map_err(|e| e.to_string())?;
    match (binding, target) {
        ("node", "root") => node_root(out),
        ("node", _) => node(target, out),
        ("python", _) => python(target, out),
        ("c", _) => c(target, out),
        _ => Err(format!("unknown binding {binding:?}")),
    }
}

/// `LICENSE-MIT`, `LICENSE-APACHE` and the notice for `binding` on `target` into `dir`.
pub(crate) fn stage(binding: &str, target: &str, dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    copy_licenses(dir)?;
    run(Command::new(env!("CARGO"))
        .args(["fetch", "--locked", "--manifest-path"])
        .arg(repo().join("Cargo.toml")))?;
    render_notice(binding, target, &dir.join("THIRD-PARTY-LICENSES.txt"))
}

fn copy_licenses(dir: &Path) -> Result<(), String> {
    for name in ["LICENSE-MIT", "LICENSE-APACHE"] {
        std::fs::copy(repo().join(name), dir.join(name)).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(())
}

fn node_root(out: &Path) -> Result<(), String> {
    let dir = repo().join("bindings/node");
    copy_licenses(&dir)?;
    npm_pack(&dir, out)
}

fn node(target: &str, out: &Path) -> Result<(), String> {
    let platform = NODE_PLATFORMS
        .iter()
        .find(|(triple, _)| *triple == target)
        .map(|(_, platform)| *platform)
        .ok_or_else(|| format!("the Node binding is not built for {target}"))?;
    let (built, _) = cargo_build("proxy-watch-node", target, Build::Addon)?;
    let dir = repo().join("bindings/node/npm").join(platform);
    let lib = built.join(shared_library("proxy_watch_node", target));
    let addon = dir.join(format!("proxy-watch.{platform}.node"));
    std::fs::copy(&lib, &addon).map_err(|e| format!("{}: {e}", lib.display()))?;
    stage("node", target, &dir)?;
    npm_pack(&dir, out)
}

fn python(target: &str, out: &Path) -> Result<(), String> {
    let dir = repo().join("bindings/python");
    stage("python", target, &dir)?;
    let mut maturin = Command::new("maturin");
    maturin
        .env("RUSTC", crate::std_notice::rustc_binary()?)
        .current_dir(&dir)
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            target,
            "--out",
        ])
        .arg(out);
    if target.ends_with("-linux-gnu") {
        maturin.args(["--zig", "--compatibility", "manylinux2014"]);
    } else if target.ends_with("-linux-musl") {
        maturin.args(["--zig", "--compatibility", "musllinux_1_2"]);
    }
    run(&mut maturin)
}

fn c(target: &str, out: &Path) -> Result<(), String> {
    if target.contains("-android") {
        crate::crt_notice::check_ndk(target)?;
    }
    let (built, native) = cargo_build("proxy-watch-c", target, Build::Library)?;
    let native = native.ok_or("rustc printed no native-static-libs line for the static library")?;
    let name = format!(
        "proxy-watch-c-{}-{target}",
        version("bindings/c/Cargo.toml")?
    );
    let root = out.join(&name);
    let _ = std::fs::remove_dir_all(&root);
    let (include, lib) = (root.join("include"), root.join("lib"));
    for dir in [&include, &lib] {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    copy(
        &repo().join("bindings/c/include/proxy_watch.h"),
        &include.join("proxy_watch.h"),
    )?;
    let windows = target.contains("-windows-");
    let mut libs = vec![
        static_library("proxy_watch_c", target),
        shared_library("proxy_watch_c", target),
    ];
    if windows {
        // The import library a program links to load the DLL.
        libs.push("proxy_watch_c.dll.lib".to_owned());
    }
    for file in libs {
        copy(&built.join(&file), &lib.join(&file))?;
    }
    // What a program linking the static library adds to its link line, as rustc reports it
    // for this target.
    std::fs::write(lib.join("native-static-libs.txt"), format!("{native}\n"))
        .map_err(|e| e.to_string())?;
    copy(
        &repo().join("bindings/c/README.md"),
        &root.join("README.md"),
    )?;
    stage("c", target, &root)?;
    // `tar` on a Windows runner is bsdtar, which writes a zip when the name says so.
    let archive = if windows {
        format!("{name}.zip")
    } else {
        format!("{name}.tar.gz")
    };
    let flags = if windows { "-a -cf" } else { "-czf" };
    run(Command::new("tar")
        .args(flags.split(' '))
        .arg(&archive)
        .arg(&name)
        .current_dir(out))?;
    std::fs::remove_dir_all(&root).map_err(|e| e.to_string())
}

/// What a [`cargo_build`] produces, which decides how it links.
#[derive(Clone, Copy, PartialEq)]
enum Build {
    /// A Node addon. On Windows it links the C runtime statically: `node.exe` carries its
    /// own and loads no `VCRUNTIME140.dll`, so an addon that needs one fails to load on a
    /// machine without the Visual C++ Redistributable.
    Addon,
    /// The C library, which links the C runtime the way its consumer's toolchain expects and
    /// reports the system libraries a static link needs.
    Library,
}

// Builds `package` for `target` in release mode and returns the directory its libraries land
// in, and for `Build::Library` the libraries rustc says a program linking its static library
// needs as well.
fn cargo_build(
    package: &str,
    target: &str,
    build: Build,
) -> Result<(PathBuf, Option<String>), String> {
    let mut cargo = Command::new(env!("CARGO"));
    // The compiler whose standard library the notice quotes.
    cargo.env("RUSTC", crate::std_notice::rustc_binary()?);
    // Every flag goes in this one variable: `RUSTFLAGS`, when set, replaces it rather than
    // adding to it.
    let mut flags = Vec::new();
    if build == Build::Addon && target.ends_with("-windows-msvc") {
        flags.push("-C target-feature=+crt-static");
    }
    if target.ends_with("-linux-gnu") {
        // The `.2.17` suffix is `cargo zigbuild`'s: link against that glibc's symbols.
        cargo.args(["zigbuild", "--target", &format!("{target}.2.17")]);
    } else if target.ends_with("-linux-musl") {
        // A musl target links the C library statically by default, which leaves no
        // `cdylib` to build; a Node addon, a Python module or a shared C library has to load
        // into a process that already has one.
        cargo.args(["zigbuild", "--target", target]);
        flags.push("-C target-feature=-crt-static");
    } else {
        cargo.args(["build", "--target", target]);
    }
    if build == Build::Library {
        // rustc prints the line only while it writes a static library, so the build that
        // produces it is the one that reports it.
        flags.push("--print native-static-libs");
    }
    if !flags.is_empty() {
        let triple = target.to_uppercase().replace('-', "_");
        cargo.env(format!("CARGO_TARGET_{triple}_RUSTFLAGS"), flags.join(" "));
    }
    cargo
        .args(["--release", "--locked", "--package", package])
        .current_dir(repo());
    if build == Build::Addon {
        run(&mut cargo)?;
        return Ok((repo().join("target").join(target).join("release"), None));
    }
    let output = cargo.output().map_err(|e| format!("{cargo:?}: {e}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprint!("{stderr}");
    if !output.status.success() {
        return Err(format!("{cargo:?} exited with {}", output.status));
    }
    let native = stderr
        .lines()
        .find_map(|line| line.split_once("native-static-libs: "))
        .map(|(_, libs)| libs.trim().to_owned());
    Ok((repo().join("target").join(target).join("release"), native))
}

fn shared_library(stem: &str, target: &str) -> String {
    if target.contains("-windows-") {
        format!("{stem}.dll")
    } else if target.contains("-apple-") {
        format!("lib{stem}.dylib")
    } else {
        format!("lib{stem}.so")
    }
}

fn static_library(stem: &str, target: &str) -> String {
    if target.contains("-windows-") {
        format!("{stem}.lib")
    } else {
        format!("lib{stem}.a")
    }
}

fn npm_pack(dir: &Path, out: &Path) -> Result<(), String> {
    // A batch file is spawned by its full name; `npm` alone is not found on Windows.
    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };
    run(Command::new(npm)
        .args(["pack", "--pack-destination"])
        .arg(out)
        .current_dir(dir))
}

fn copy(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::copy(from, to)
        .map(drop)
        .map_err(|e| format!("{}: {e}", from.display()))
}

// The `version` of the package in the manifest at `path`, relative to the repository.
fn version(path: &str) -> Result<String, String> {
    let manifest =
        std::fs::read_to_string(repo().join(path)).map_err(|e| format!("{path}: {e}"))?;
    manifest
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
        .ok_or_else(|| format!("{path} has no version line"))
}
