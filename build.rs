//! `pac_quickjs` is the `pac-quickjs` feature on every target but Android and iOS, where
//! `rquickjs-sys` ships no bindings and the feature builds without an engine. The library's
//! own code tests this cfg, never the feature.
//!
//! `pac_cfnetwork` is `pac-macos-native` on macOS or `pac-ios-native` on iOS: one CFNetwork
//! implementation behind two per-OS features.
//!
//! `pac_native` is set wherever one of the native PAC resolvers is compiled in.
fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(pac_quickjs)");
    println!("cargo::rustc-check-cfg=cfg(pac_cfnetwork)");
    println!("cargo::rustc-check-cfg=cfg(pac_native)");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if std::env::var_os("CARGO_FEATURE_PAC_QUICKJS").is_some() && os != "android" && os != "ios" {
        println!("cargo::rustc-cfg=pac_quickjs");
    }
    let feature = |name| std::env::var_os(name).is_some();
    let cfnetwork = (os == "macos" && feature("CARGO_FEATURE_PAC_MACOS_NATIVE"))
        || (os == "ios" && feature("CARGO_FEATURE_PAC_IOS_NATIVE"));
    if cfnetwork {
        println!("cargo::rustc-cfg=pac_cfnetwork");
    }
    if cfnetwork
        || (os == "windows" && feature("CARGO_FEATURE_PAC_WINDOWS_NATIVE"))
        || (os == "android" && feature("CARGO_FEATURE_PAC_ANDROID_NATIVE"))
    {
        println!("cargo::rustc-cfg=pac_native");
    }
}
