//! The C runtime start files a target's linker puts into every shared library, where their
//! license asks for a notice in binary form.
//!
//! On Android the NDK's clang links bionic's `crtbegin_so.o` into each `.so`, and its sources
//! are BSD-2-Clause (which asks binaries to reproduce the notice) plus one Apache-2.0 header.
//! The NDK's `libunwind.a` it also links is Apache-2.0 WITH LLVM-exception and needs no
//! notice. A macOS library links only system dylibs, and a Linux one glibc's and LLVM's
//! objects, neither of which asks for a notice. On Windows the Python module and the C library
//! link the CRT startup objects of MSVC's `msvcrt.lib` and `vcruntime.lib` and load
//! `VCRUNTIME140.dll` and the Universal CRT at run time, and the Node addon links the whole C
//! runtime statically; the Visual Studio license terms govern all of it, and the notice does
//! not reproduce them.

/// The section for `target`, or nothing when its start files need no notice.
pub(crate) fn render(target: &str) -> String {
    if !target.contains("-android") {
        return String::new();
    }
    let rule = "=".repeat(80);
    format!(
        "\n{rule}\nAndroid NDK: crtbegin_so.o\n\n\
         The NDK links bionic's crtbegin_so.o into this library. Its sources\n\
         (libc/arch-common/bionic/crtbegin_so.c, __dso_handle_so.h, atexit.h, crtbrand.S)\n\
         are under the license below; pthread_atfork.h, which it also includes, is under\n\
         Apache-2.0, whose text is in LICENSE-APACHE beside this file.\n\n\
         {BIONIC_BSD_2}"
    )
}

/// Holds [`BIONIC_BSD_2`] to the `sysroot/NOTICE` of the NDK whose clang links `target`, found
/// from `CARGO_TARGET_<triple>_LINKER` (`<ndk>/toolchains/llvm/prebuilt/<host>/bin/<clang>`).
/// The NOTICE carries each holder in a block of its own with the same terms; an NDK whose
/// blocks differ stops the packaging until the text is read again.
pub(crate) fn check_ndk(target: &str) -> Result<(), String> {
    let var = format!(
        "CARGO_TARGET_{}_LINKER",
        target.to_uppercase().replace('-', "_")
    );
    let linker = std::env::var_os(&var)
        .ok_or_else(|| format!("{var} is unset; it names the NDK clang that links {target}"))?;
    let path = std::path::Path::new(&linker)
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| format!("{var}: not a path inside an NDK"))?
        .join("sysroot/NOTICE");
    let notice = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    match missing_block(&notice) {
        Some(holder) => Err(format!(
            "{}: no block for `{holder}` with the terms the Android notice quotes",
            path.display()
        )),
        None => Ok(()),
    }
}

/// The first holder of [`BIONIC_BSD_2`] whose block `notice` does not carry word for word.
fn missing_block(notice: &str) -> Option<&'static str> {
    let (holders, terms) = BIONIC_BSD_2.split_once("All rights reserved.\n")?;
    holders
        .lines()
        .find(|holder| !notice.contains(&format!("{holder}\nAll rights reserved.\n{terms}")))
}

const BIONIC_BSD_2: &str = "\
Copyright (C) 2012 The Android Open Source Project
Copyright (C) 2015 The Android Open Source Project
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
 * Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
";

#[cfg(test)]
mod tests {
    use super::{BIONIC_BSD_2, missing_block, render};

    #[test]
    fn only_android_carries_the_bionic_notice() {
        assert!(render("aarch64-linux-android").contains("The Android Open Source Project"));
        assert!(render("x86_64-linux-android").contains("crtbegin_so.o"));
        assert_eq!(render("x86_64-unknown-linux-gnu"), "");
        assert_eq!(render("aarch64-apple-darwin"), "");
    }

    #[test]
    fn the_ndk_notice_must_carry_each_holder_with_the_quoted_terms() {
        let (holders, terms) = BIONIC_BSD_2.split_once("All rights reserved.\n").unwrap();
        let mut lines = holders.lines();
        let (first, second) = (lines.next().unwrap(), lines.next().unwrap());
        let block = |holder: &str, terms: &str| {
            format!("---\n\n{holder}\nAll rights reserved.\n{terms}\n---\n")
        };
        let ndk = format!("{}{}", block(first, terms), block(second, terms));
        assert_eq!(missing_block(&ndk), None);
        assert_eq!(missing_block(&block(first, terms)), Some(second));
        let reworded = terms.replace("binary form", "object form");
        assert_eq!(
            missing_block(&format!(
                "{}{}",
                block(first, &reworded),
                block(second, terms)
            )),
            Some(first)
        );
    }
}
