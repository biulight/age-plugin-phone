use std::{env, path::PathBuf, process::Command};

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    println!("cargo:rerun-if-changed=native/Keys.swift");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo:rerun-if-env-changed=SDKROOT");
    let target = env::var("TARGET").expect("Cargo TARGET");
    let arch = match target.as_str() {
        "aarch64-apple-darwin" => "arm64",
        "x86_64-apple-darwin" => "x86_64",
        _ => panic!("hardware backend requires macOS"),
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let optimization = "-O";
    let result = Command::new("xcrun")
        .args([
            "swiftc",
            "-emit-library",
            "-static",
            "-parse-as-library",
            "-module-name",
            "AgePhoneKeys",
            "-target",
            &format!("{arch}-apple-macosx14.0"),
            optimization,
            "-module-cache-path",
        ])
        .arg(output.join("swift-cache"))
        .arg("native/Keys.swift")
        .arg("-o")
        .arg(output.join("libAgePhoneKeys.a"))
        .status()
        .expect("Xcode or Command Line Tools with swiftc required");
    assert!(
        result.success(),
        "Swift hardware backend compilation failed"
    );
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-lib=static=AgePhoneKeys");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}
