use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=native/Probe.swift");
    println!("cargo:rerun-if-env-changed=M0_SWIFT_OPT");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo:rerun-if-env-changed=SDKROOT");
    let target = env::var("TARGET").expect("Cargo TARGET");
    let arch = match target.as_str() {
        "aarch64-apple-darwin" => "arm64",
        "x86_64-apple-darwin" => "x86_64",
        _ => panic!("M0 probe requires macOS"),
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let optimization = env::var("M0_SWIFT_OPT").unwrap_or_else(|_| "-Onone".into());
    assert!(matches!(optimization.as_str(), "-Onone" | "-O"));
    let result = Command::new("xcrun")
        .args([
            "swiftc",
            "-emit-library",
            "-static",
            "-parse-as-library",
            "-module-name",
            "AgePhoneM0",
            "-target",
            &format!("{arch}-apple-macosx14.0"),
            &optimization,
            "-module-cache-path",
        ])
        .arg(output.join("swift-cache"))
        .arg("native/Probe.swift")
        .arg("-o")
        .arg(output.join("libAgePhoneM0.a"))
        .status()
        .expect("Xcode or Command Line Tools with swiftc required");
    assert!(result.success(), "Swift M0 compilation failed");
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-lib=static=AgePhoneM0");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}
