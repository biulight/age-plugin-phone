//! Unix filesystem primitives extracted without changing replay durability semantics.
//!
//! `private_file` retains the locator path's stricter hard-link check and error
//! distinctions. Callers own record encoding, size limits, lock names and poisoning.
#![allow(clippy::missing_errors_doc)]
use rustix::fs::{FlockOperation, flock};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
#[derive(Debug, thiserror::Error)]
#[error("private filesystem operation failed")]
pub enum Error {
    Invalid,
}
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
pub fn acquire_lock(lock_path: &Path) -> Result<File, Error> {
    reject_symlink_if_present(lock_path)?;
    let lock = private_options()
        .read(true)
        .write(true)
        .create(true)
        .open(lock_path)
        .map_err(|_| Error::Invalid)?;
    ensure_private_regular(&lock)?;
    flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| Error::Invalid)?;
    Ok(lock)
}

pub fn read_private_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, Error> {
    let read_limit = max_bytes.checked_add(1).ok_or(Error::Invalid)?;
    reject_symlink_if_present(path)?;
    let file = File::open(path).map_err(|_| Error::Invalid)?;
    ensure_private_regular(&file)?;
    if file.metadata().map_err(|_| Error::Invalid)?.len() > max_bytes {
        return Err(Error::Invalid);
    }
    let mut encoded = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut encoded)
        .map_err(|_| Error::Invalid)?;
    if encoded.is_empty() || u64::try_from(encoded.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(Error::Invalid);
    }
    Ok(encoded)
}

pub fn persist_create(path: &Path, encoded: &[u8]) -> Result<(), Error> {
    let temporary = write_temporary(path, encoded)?;
    if fs::hard_link(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(Error::Invalid);
    }
    let remove_result = fs::remove_file(&temporary);
    let sync_result = sync_parent(path);
    if remove_result.is_err() || sync_result.is_err() {
        return Err(Error::Invalid);
    }
    Ok(())
}

pub fn atomic_replace(path: &Path, encoded: &[u8]) -> Result<(), Error> {
    let temporary = write_temporary(path, encoded)?;
    if fs::rename(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(Error::Invalid);
    }
    sync_parent(path)
}

fn write_temporary(path: &Path, encoded: &[u8]) -> Result<PathBuf, Error> {
    for _ in 0..32 {
        let suffix = format!(
            ".{}.{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let temporary = sibling_path(path, &suffix)?;
        let mut file = match private_options()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(Error::Invalid),
        };
        if file.write_all(encoded).is_err() || file.sync_all().is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(Error::Invalid);
        }
        return Ok(temporary);
    }
    Err(Error::Invalid)
}

fn sync_parent(path: &Path) -> Result<(), Error> {
    File::open(path.parent().ok_or(Error::Invalid)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Error::Invalid)
}

fn sibling_path(path: &Path, suffix: &str) -> Result<PathBuf, Error> {
    let mut name = OsString::from(path.file_name().ok_or(Error::Invalid)?);
    name.push(suffix);
    Ok(path.parent().ok_or(Error::Invalid)?.join(name))
}

fn reject_symlink_if_present(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::Invalid),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::Invalid),
    }
}

fn ensure_private_regular(file: &File) -> Result<(), Error> {
    let metadata = file.metadata().map_err(|_| Error::Invalid)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.mode(0o600);
    options
}

pub mod private_file;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reads_reject_overflow_oversize_and_widened_permissions() {
        let path =
            std::env::temp_dir().join(format!("phone-storage-bounds-{}", std::process::id()));
        let mut file = private_options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&[1, 2]).unwrap();
        drop(file);
        assert_eq!(read_private_file(&path, 2).unwrap(), [1, 2]);
        assert_eq!(private_file::read_private_file(&path, 2).unwrap(), [1, 2]);
        for limit in [0, 1, u64::MAX] {
            assert!(read_private_file(&path, limit).is_err());
            assert!(private_file::read_private_file(&path, limit).is_err());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_file(&path, 2).is_err());
        assert!(private_file::read_private_file(&path, 2).is_err());
        fs::remove_file(path).unwrap();
    }
}
