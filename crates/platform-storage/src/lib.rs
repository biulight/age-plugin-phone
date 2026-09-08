//! Platform filesystem boundaries with explicit native semantics.
#![allow(clippy::missing_errors_doc)]
#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;
