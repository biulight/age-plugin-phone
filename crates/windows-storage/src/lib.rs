//! Private Windows filesystem operations for locator, key metadata, and replay state.
//!
//! Every created object has a protected current-user-only DACL. Opens reject reparse points,
//! multiple hard links, foreign owners, and widened ACLs. Replacement uses a same-directory
//! temporary file and `MoveFileExW` with replace and write-through semantics.

#![cfg_attr(not(windows), allow(dead_code))]
#![allow(clippy::missing_errors_doc)]

#[cfg(windows)]
mod network;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use network::ipv4_interface_subnets;
#[cfg(windows)]
pub use windows::{
    Error, PrivateLock, atomic_create, atomic_replace, ensure_private_directory, open_private_lock,
    read_private_file, read_regular_file, remove_private_file, remove_regular_file,
    validate_private_directory,
};

/// Whether this build contains the Windows storage boundary.
pub const AVAILABLE: bool = cfg!(windows);
