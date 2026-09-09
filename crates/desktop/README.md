# age-plugin-phone

Experimental offline phone-backed age CLI, unsuitable for real secrets.

Windows hardware use requires Windows 11 x64 and TPM 2.0. The macOS source implementation
uses distinct Secure Enclave signing and selection keys, native private storage and journaled
setup/cleanup. It has no software-key fallback. macOS remains experimental: snapshot rollback
and the complete physical acceptance matrix are unresolved. Other desktop targets retain
software prototypes.

Source builds require Rust 1.88+, a C/C++ compiler and platform SDK. macOS additionally requires
Xcode Command Line Tools with `xcrun swiftc`; the Swift bridge is included in the crate archive.
Only the CLI and its three libraries are needed, not mobile build tools or a signing certificate.

See https://github.com/biulight/age-plugin-phone for architecture, platform evidence and installation.
