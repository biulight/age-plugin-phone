//! Windows TPM-backed P-256 key custody.
//!
//! This crate is the only desktop crate allowed to contain Windows CNG FFI. It always opens the
//! Microsoft Platform Crypto Provider and never falls back to the software provider or DPAPI.

#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{
    Error, RequirementStatus, WindowsCngKeySet, WindowsPlatformReport, ensure_supported_platform,
    probe_windows_platform,
};

/// Whether the current build can access Windows CNG.
pub const AVAILABLE: bool = cfg!(windows);
