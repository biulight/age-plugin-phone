//! Unix private files with single-link validation, used by desktop locators.
use std::{
    fs::{File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("private directory is unavailable")]
    Config,
    #[error("file already exists")]
    AlreadyExists,
    #[error("file is missing")]
    Missing,
    #[error("invalid private file")]
    Invalid,
    #[error("storage operation failed")]
    Storage,
}
pub fn read_private_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, Error> {
    use std::io::Read as _;
    let read_limit = max_bytes.checked_add(1).ok_or(Error::Invalid)?;
    reject_symlink(path)?;
    let file = File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::Missing
        } else {
            Error::Invalid
        }
    })?;
    validate_private_file(&file)?;
    if file.metadata().map_err(|_| Error::Invalid)?.len() > max_bytes {
        return Err(Error::Invalid);
    }
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Invalid)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

pub fn prepare_directory(root: &Path) -> Result<PathBuf, Error> {
    use std::os::unix::fs::PermissionsExt as _;
    if !root.is_absolute() {
        return Err(Error::Config);
    }
    std::fs::create_dir_all(root).map_err(|_| Error::Config)?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| Error::Config)?;
    checked_directory(root)
}

pub fn checked_directory(root: &Path) -> Result<PathBuf, Error> {
    use std::os::unix::fs::PermissionsExt as _;
    reject_symlink(root)?;
    let metadata = std::fs::metadata(root).map_err(|_| Error::Config)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::Config);
    }
    Ok(root.to_path_buf())
}

pub fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::AlreadyExists
            } else {
                Error::Storage
            }
        })?;
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(Error::Storage);
    }
    validate_private_file(&file)
}

fn validate_private_file(file: &File) -> Result<(), Error> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = file.metadata().map_err(|_| Error::Invalid)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::Invalid),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::Invalid),
    }
}

pub fn sync_directory(path: &Path) -> Result<(), Error> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Error::Storage)
}
