//! Runs the repository's prose and documentation gates, rebuilds the Android receiver dex,
//! renders the bindings' third-party license notices, and packages the bindings.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

mod crt_notice;
mod linked;
mod package;
mod std_notice;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next().as_deref(), args.next()) {
        (Some("audit-docs"), None, None) => run_audit_tests(),
        (Some("android-dex"), None, None) => android_dex(false),
        (Some("android-dex"), Some("--check"), None) => android_dex(true),
        (Some("third-party-licenses"), None, None) => third_party_licenses(),
        (Some(command @ ("stage-licenses" | "package")), Some(binding), Some(target)) => {
            match (args.next(), args.next()) {
                (Some(dir), None) if command == "package" => {
                    exit(package::package(binding, &target, Path::new(&dir)))
                }
                (Some(dir), None) => exit(package::stage(binding, &target, Path::new(&dir))),
                _ => usage(),
            }
        }
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: cargo xtask audit-docs | cargo xtask android-dex [--check] \
         | cargo xtask third-party-licenses \
         | cargo xtask stage-licenses <node|python|c> <target> <dir> \
         | cargo xtask package <node|python|c> <target|root> <out>"
    );
    ExitCode::FAILURE
}

fn exit(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run_audit_tests() -> ExitCode {
    let status = Command::new(env!("CARGO"))
        .args([
            "test",
            "--package",
            "proxy-watch-repo-audit",
            "--tests",
            "--",
            "--test-threads=1",
        ])
        .status();
    match status {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1).clamp(1, 255) as u8),
        Err(error) => {
            eprintln!("failed to start cargo for repository audit: {error}");
            ExitCode::FAILURE
        }
    }
}

// d8 stamps its own version into the dex, so the check holds only against this one.
const BUILD_TOOLS: &str = "36.1.0";
const PLATFORM: &str = "android-36";

// Compiles `ProxyChangeReceiver.java` with `javac` from `PATH`, against `android.jar` from
// `$ANDROID_HOME`, and dexes it with that SDK's `d8`, then
// writes `receiver.dex` next to it, or with `check` compares against the committed one.
fn android_dex(check: bool) -> ExitCode {
    match build_dex() {
        Ok(built) => {
            let committed = repo().join("src/sys/android/receiver.dex");
            if check {
                if std::fs::read(&committed).ok().as_deref() == Some(&built[..]) {
                    ExitCode::SUCCESS
                } else {
                    eprintln!(
                        "{} is not what ProxyChangeReceiver.java compiles to; run `cargo xtask android-dex`",
                        committed.display()
                    );
                    ExitCode::FAILURE
                }
            } else if let Err(error) = std::fs::write(&committed, built) {
                eprintln!("writing {}: {error}", committed.display());
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn build_dex() -> Result<Vec<u8>, String> {
    let sdk = std::env::var_os("ANDROID_HOME")
        .or_else(|| std::env::var_os("ANDROID_SDK_ROOT"))
        .map(PathBuf::from)
        .ok_or("set ANDROID_HOME to the Android SDK")?;
    let android_jar = sdk.join("platforms").join(PLATFORM).join("android.jar");
    let d8 = sdk
        .join("build-tools")
        .join(BUILD_TOOLS)
        .join(if cfg!(windows) { "d8.bat" } else { "d8" });
    for needed in [&android_jar, &d8] {
        if !needed.exists() {
            return Err(format!(
                "{} is missing; install build-tools {BUILD_TOOLS} and {PLATFORM}",
                needed.display()
            ));
        }
    }
    let out = repo().join("target/android-dex");
    let _ = std::fs::remove_dir_all(&out);
    let classes = out.join("classes");
    let dex = out.join("dex");
    std::fs::create_dir_all(&dex).map_err(|e| e.to_string())?;
    run(Command::new("javac")
        .args(["--release", "8", "-Xlint:-options", "-cp"])
        .arg(&android_jar)
        .arg("-d")
        .arg(&classes)
        .arg(repo().join("src/sys/android/ProxyChangeReceiver.java")))?;
    // Every class `javac` wrote, sorted, so an inner or anonymous class added to the Java
    // reaches the dex instead of being left out on both sides of the comparison alike.
    let mut compiled: Vec<_> = std::fs::read_dir(classes.join("proxywatch"))
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "class"))
        .collect();
    compiled.sort();
    run(Command::new(&d8)
        .args(["--release", "--min-api", "26", "--lib"])
        .arg(&android_jar)
        .arg("--output")
        .arg(&dex)
        .args(&compiled))?;
    std::fs::read(dex.join("classes.dex")).map_err(|e| e.to_string())
}

// The desktop targets a binding artifact is built for: x86-64 and AArch64 on each desktop
// OS, the targets `bindings/shared/Cargo.toml` builds QuickJS for.
const DESKTOP: [&str; 6] = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
];
// Linux with musl (Alpine and other distroless images); QuickJS is built there too.
const MUSL: [&str; 2] = ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"];
// The C ABI also has `pw_android_init`, so an Android app can link it.
const ANDROID: [&str; 2] = ["aarch64-linux-android", "x86_64-linux-android"];

// Renders `bindings/about.toml` through `bindings/about.hbs` with `cargo about`, narrowed to
// the crates the artifact links, followed by the Rust standard library's section for the
// target and, on Android, the NDK's start file, into
// `target/third-party-licenses/<binding>-<target>.txt`: the notice an artifact for that
// binding and target ships beside `LICENSE-MIT` and `LICENSE-APACHE`. Fails on a license
// outside `accepted` and on a license text left with a template placeholder for its holder,
// which is what a crate without a readable license file, or a clarified text whose checksum
// moved, renders to. Offline, so the texts are
// the ones in the downloaded crates and nothing depends on a remote service; the crates
// are fetched first.
fn third_party_licenses() -> ExitCode {
    let out = repo().join("target/third-party-licenses");
    let result = run(Command::new(env!("CARGO"))
        .args(["fetch", "--locked", "--manifest-path"])
        .arg(repo().join("Cargo.toml")))
    .and_then(|()| std::fs::create_dir_all(&out).map_err(|e| e.to_string()))
    .and_then(|()| {
        for binding in ["node", "python", "c"] {
            let android: &[&str] = if binding == "c" { &ANDROID } else { &[] };
            for target in DESKTOP.iter().chain(&MUSL).chain(android) {
                render_notice(
                    binding,
                    target,
                    &out.join(format!("{binding}-{target}.txt")),
                )?;
            }
        }
        Ok(())
    });
    if result.is_ok() {
        println!("{}", out.display());
    }
    exit(result)
}

// Crates that ship no license file while their repository has one, which `cargo about` reads
// offline from nowhere. The repository's file is kept in `bindings/licenses/`, byte for byte as
// the commit the crate's `.cargo_vcs_info.json` names holds it, and stands in for the
// placeholder text. Each is pinned to a version: another release of the crate renders the
// placeholder again and fails below until its file is read. The last field is the upstream
// file's git blob id, which a test holds the kept copy to.
const UPSTREAM_LICENSES: [(&str, &str, &str, &str); 2] = [
    // napi-rs/napi-rs `LICENSE` at the commit both crates name.
    (
        "napi",
        "3.14.0",
        "napi-rs-LICENSE",
        "7fe7e35eff46457f65a4e30a717fada632de9e03",
    ),
    (
        "napi-sys",
        "3.4.0",
        "napi-rs-LICENSE",
        "7fe7e35eff46457f65a4e30a717fada632de9e03",
    ),
];

fn render_notice(binding: &str, target: &str, path: &Path) -> Result<(), String> {
    let bindings = repo().join("bindings");
    run(Command::new(env!("CARGO"))
        .args([
            "about",
            "generate",
            "--offline",
            "--locked",
            // Fails on a clarification it cannot apply instead of warning and going on.
            "--fail",
            "--manifest-path",
        ])
        .arg(bindings.join(binding).join("Cargo.toml"))
        .arg("--config")
        .arg(bindings.join("about.toml"))
        .args(["--target", target, "--output-file"])
        .arg(path)
        .arg(bindings.join("about.hbs")))
    .map_err(|error| {
        format!("{error}\n(`cargo install --locked cargo-about --features cli` installs it)")
    })?;
    // `cargo about` writes its unfiltered output to `path`; a failure past this point removes it
    // so no unchecked notice is left where a packaging step would pick it up.
    let finished = finish_notice(binding, target, path, &bindings);
    if finished.is_err() {
        let _ = std::fs::remove_file(path);
    }
    finished
}

fn finish_notice(binding: &str, target: &str, path: &Path, bindings: &Path) -> Result<(), String> {
    let rendered = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut notice = linked::keep(&rendered, &linked::crates(binding, target)?)?;
    let mut texts = Vec::new();
    for (name, version, file, _) in UPSTREAM_LICENSES {
        let path = bindings.join("licenses").join(file);
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        texts.push((name, version, text));
    }
    notice = linked::fill(&notice, &texts)?;
    // `cargo about` quotes the canonical text of a license it finds no file for, with the
    // template's placeholders where the holder would be. The standard library's section is
    // appended after the check: it quotes the release's templates as shipped, beside the
    // holders the release lists.
    if let Some(placeholder) = ["<year>", "<copyright holders>", "<owner>"]
        .into_iter()
        .find(|placeholder| notice.contains(placeholder))
    {
        let crates = notice
            .split(placeholder)
            .next()
            .and_then(|before| before.rsplit("\nUsed by:\n").next())
            .and_then(|users| users.split(&"-".repeat(80)).next())
            .unwrap_or_default()
            .trim();
        return Err(format!(
            "{binding} {target}: a license text with `{placeholder}` in it, used by\n{crates}\n\
             The crate ships no license file `cargo about` reads; clarify it in `bindings/about.toml`"
        ));
    }
    notice.push_str(&std_notice::render(target)?);
    notice.push_str(&crt_notice::render(target));
    std::fs::write(path, notice).map_err(|e| format!("{}: {e}", path.display()))
}

fn run(command: &mut Command) -> Result<(), String> {
    match command.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("{command:?} exited with {status}")),
        Err(error) => Err(format!("{command:?}: {error}")),
    }
}

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits in the repository")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_upstream_licenses_are_the_upstream_blobs() {
        for (_, _, file, blob) in UPSTREAM_LICENSES {
            let output = Command::new("git")
                .arg("hash-object")
                .arg(repo().join("bindings/licenses").join(file))
                .output()
                .expect("git runs");
            assert!(output.status.success(), "git hash-object {file}");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout).trim(),
                blob,
                "{file}"
            );
        }
    }
}
