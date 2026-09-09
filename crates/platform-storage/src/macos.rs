//! Descriptor-relative macOS private files. Business callers own names, formats and recovery.
//! Existing unsafe permissions are rejected, never repaired through a caller-supplied path.
#![allow(clippy::missing_errors_doc)]
#[path = "macos_network.rs"]
pub mod network;

use std::{
    ffi::{CString, c_void},
    fs::File,
    io::{Read as _, Write as _},
    os::{
        fd::{AsRawFd as _, FromRawFd as _},
        unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("private state missing")]
    Missing,
    #[error("private state already exists")]
    AlreadyExists,
    #[error("private state invalid or insecure")]
    Invalid,
    #[error("private storage unavailable or uncertain")]
    Storage,
}
fn os_error() -> Error {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOENT) => Error::Missing,
        Some(libc::EEXIST) => Error::AlreadyExists,
        _ => Error::Storage,
    }
}
unsafe extern "C" {
    fn acl_get_fd(fd: i32) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry: i32, out: *mut *mut c_void) -> i32;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut i32) -> i32;
    fn acl_free(acl: *mut c_void) -> i32;
}
fn acl(file: &File, private: bool) -> Result<(), Error> {
    // SAFETY: ACL is owned here, inspected with SDK-defined constants and freed once; no pointers escape.
    unsafe {
        let value = acl_get_fd(file.as_raw_fd());
        if value.is_null() {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(Error::Invalid)
            };
        }
        let result = (|| {
            let mut entry = std::ptr::null_mut();
            let mut index = 0; // ACL_FIRST_ENTRY; ACL_NEXT_ENTRY = -1.
            for _ in 0..=169 {
                let status = acl_get_entry(value, index, &raw mut entry);
                if status == -1 {
                    // Darwin returns -1/EINVAL at the end of the list.
                    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                        return Ok(());
                    }
                    return Err(Error::Invalid);
                }
                if status != 0 || entry.is_null() {
                    return Err(Error::Invalid);
                }
                let mut tag = 0;
                if private || acl_get_tag_type(entry, &raw mut tag) != 0 || tag != 2 {
                    return Err(Error::Invalid); // Protected items: no ACL; ancestors: deny entries only.
                }
                index = -1;
            }
            Err(Error::Invalid)
        })();
        acl_free(value);
        result
    }
}
fn check(file: &File, private: bool, directory: bool) -> Result<(), Error> {
    let m = file.metadata().map_err(|_| Error::Invalid)?;
    // SAFETY: geteuid has no pointer arguments or side effects.
    let uid = unsafe { libc::geteuid() };
    if m.is_dir() != directory
        || (!directory && (!m.is_file() || m.nlink() != 1))
        || (private && (m.uid() != uid || m.mode() & 0o7077 != 0))
        || (!private && (m.uid() != 0 && m.uid() != uid))
        || (!private
            && m.mode() & 0o022 != 0
            && !(directory && m.uid() == 0 && m.mode() & 0o1000 != 0))
    {
        return Err(Error::Invalid);
    }
    acl(file, private)
}
fn name(path: &Path) -> Result<CString, Error> {
    if path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(Error::Invalid);
    }
    CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Invalid)
}
fn open_at(parent: &File, name: &CString, flags: i32) -> Result<File, Error> {
    // SAFETY: name is NUL terminated; successful descriptor is transferred to File exactly once.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn same(first: &File, second: &File) -> Result<(), Error> {
    let a = first.metadata().map_err(|_| Error::Invalid)?;
    let b = second.metadata().map_err(|_| Error::Invalid)?;
    if a.dev() != b.dev() || a.ino() != b.ino() {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
#[cfg(test)]
std::thread_local! { static FAILURE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) }; }
#[cfg_attr(not(test), allow(clippy::unnecessary_wraps))]
fn checkpoint(stage: &'static str) -> Result<(), Error> {
    #[cfg(test)]
    if FAILURE.with(|f| {
        if f.get() == Some(stage) {
            f.set(None);
            true
        } else {
            false
        }
    }) {
        return Err(Error::Storage);
    }
    let _ = stage;
    Ok(())
}
const MAX_BYTES: u64 = 1_048_576;
fn bounded(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() as u64 > MAX_BYTES {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
fn full_sync(file: &File) -> Result<(), Error> {
    checkpoint("sync")?;
    file.sync_all().map_err(|_| Error::Storage)?;
    // SAFETY: F_FULLFSYNC takes no third argument and borrows a valid fd.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } != 0 {
        return Err(Error::Storage);
    }
    Ok(())
}

// Native Time Machine sticky exclusion metadata, encoded as a binary plist string.
// This is backup hygiene, not an anti-rollback or key-custody boundary.
fn exclude_from_backup(file: &File) -> Result<(), Error> {
    const VALUE: &[u8] = &[
        98, 112, 108, 105, 115, 116, 48, 48, 95, 16, 17, 99, 111, 109, 46, 97, 112, 112, 108, 101,
        46, 98, 97, 99, 107, 117, 112, 100, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28,
    ];
    // SAFETY: xattr borrows the live descriptor, NUL-terminated name and bounded value.
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"com.apple.metadata:com_apple_backup_excludeItem".as_ptr(),
            VALUE.as_ptr().cast(),
            VALUE.len(),
            0,
            0,
        )
    } != 0
    {
        return Err(Error::Storage);
    }
    full_sync(file)
}

pub struct Directory {
    path: PathBuf,
    file: File,
}
impl Directory {
    pub fn open(path: &Path) -> Result<Self, Error> {
        if !path.is_absolute() {
            return Err(Error::Invalid);
        }
        let mut current = File::open("/").map_err(|_| Error::Storage)?;
        check(&current, false, true)?;
        let parts: Vec<_> = path.components().skip(1).collect();
        if parts.is_empty() {
            return Err(Error::Invalid);
        }
        for (index, part) in parts.iter().enumerate() {
            let Component::Normal(part) = part else {
                return Err(Error::Invalid);
            };
            current = open_at(
                &current,
                &name(Path::new(part))?,
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
            check(&current, index + 1 == parts.len(), true)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            file: current,
        })
    }
    pub fn prepare(path: &Path) -> Result<Self, Error> {
        match Self::open(path) {
            Ok(value) => {
                exclude_from_backup(&value.file)?;
                return Ok(value);
            }
            Err(Error::Missing) => {}
            Err(e) => return Err(e),
        }
        let parent = path.parent().ok_or(Error::Invalid)?;
        // Traverse the existing ancestor with the same no-follow policy, but without requiring
        // that Application Support itself have owner-only mode.
        let parent_file = open_ancestor(parent)?;
        let child = name(Path::new(path.file_name().ok_or(Error::Invalid)?))?;
        // SAFETY: directory fd and NUL-terminated child are valid; mode is owner only.
        if unsafe { libc::mkdirat(parent_file.as_raw_fd(), child.as_ptr(), 0o700) } != 0 {
            return Err(os_error());
        }
        let value = Self::open(path)?;
        exclude_from_backup(&value.file)?;
        value.sync()?;
        full_sync(&parent_file)?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        check(&self.file, true, true)?;
        same(&self.file, &Self::open(&self.path)?.file)
    }
    pub fn sync(&self) -> Result<(), Error> {
        self.validate()?;
        full_sync(&self.file)
    }
    pub fn read(&self, child: &Path, max: u64) -> Result<Vec<u8>, Error> {
        if max > MAX_BYTES {
            return Err(Error::Invalid);
        }
        let limit = max.checked_add(1).ok_or(Error::Invalid)?;
        self.validate()?;
        let file = open_at(&self.file, &name(child)?, libc::O_RDONLY)?;
        check(&file, true, false)?;
        if file.metadata().map_err(|_| Error::Invalid)?.len() > max {
            return Err(Error::Invalid);
        }
        let mut bytes = Vec::new();
        (&file)
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Storage)?;
        if bytes.is_empty() || bytes.len() as u64 > max {
            return Err(Error::Invalid);
        }
        self.validate()?;
        check(&file, true, false)?;
        same(&file, &open_at(&self.file, &name(child)?, libc::O_RDONLY)?)?;
        Ok(bytes)
    }
    pub fn create(&self, child: &Path, bytes: &[u8]) -> Result<(), Error> {
        bounded(bytes)?;
        self.validate()?;
        let mut file = open_at(
            &self.file,
            &name(child)?,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        check(&file, true, false)?;
        checkpoint("write")?;
        file.write_all(bytes).map_err(|_| Error::Storage)?;
        full_sync(&file)?;
        self.sync()?;
        same(&file, &open_at(&self.file, &name(child)?, libc::O_RDONLY)?)
    }
    pub fn replace(&self, child: &Path, bytes: &[u8]) -> Result<(), Error> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        bounded(bytes)?;
        self.validate()?;
        let child = name(child)?;
        let previous = open_at(&self.file, &child, libc::O_RDONLY)?;
        check(&previous, true, false)?;
        let prefix = temporary_prefix(child.as_bytes());
        let temp = CString::new(format!(
            "{prefix}{}-{}.tmp",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
        .map_err(|_| Error::Invalid)?;
        let mut file = open_at(
            &self.file,
            &temp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        check(&file, true, false)?;
        checkpoint("write")?;
        file.write_all(bytes).map_err(|_| Error::Storage)?;
        full_sync(&file)?;
        self.validate()?;
        same(&previous, &open_at(&self.file, &child, libc::O_RDONLY)?)?;
        same(&file, &open_at(&self.file, &temp, libc::O_RDONLY)?)?;
        checkpoint("rename")?;
        // SAFETY: both names are direct children of the same live directory descriptor.
        if unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                temp.as_ptr(),
                self.file.as_raw_fd(),
                child.as_ptr(),
            )
        } != 0
        {
            return Err(os_error());
        }
        self.sync()?;
        same(&file, &open_at(&self.file, &child, libc::O_RDONLY)?)
    }
    /// Removes only replacement temporaries belonging to this exact direct-child name.
    /// Callers must hold their lifecycle/replay lock and a durable teardown journal.
    /// Legacy unscoped `.state-*` temporaries are never attributed or deleted here.
    pub fn remove_replacement_temporaries(&self, child: &Path) -> Result<(), Error> {
        let prefix = temporary_prefix(name(child)?.as_bytes());
        self.validate()?;
        let entries = std::fs::read_dir(&self.path).map_err(|_| Error::Storage)?;
        for entry in entries {
            let entry = entry.map_err(|_| Error::Storage)?;
            let filename = entry.file_name();
            let bytes = filename.as_bytes();
            if bytes.starts_with(prefix.as_bytes()) && bytes.ends_with(b".tmp") {
                self.remove(Path::new(&filename))?;
            }
        }
        self.sync()
    }
    /// Returns a bounded snapshot of direct child names, validating the held namespace.
    pub fn child_names(&self, max: usize) -> Result<Vec<PathBuf>, Error> {
        self.validate()?;
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.path).map_err(|_| Error::Storage)? {
            if names.len() >= max {
                return Err(Error::Invalid);
            }
            names.push(PathBuf::from(
                entry.map_err(|_| Error::Storage)?.file_name(),
            ));
        }
        self.validate()?;
        Ok(names)
    }
    pub fn remove(&self, child: &Path) -> Result<(), Error> {
        self.validate()?;
        let child = name(child)?;
        let file = open_at(&self.file, &child, libc::O_RDONLY)?;
        check(&file, true, false)?;
        // SAFETY: child is a direct child; unlinkat does not traverse a final symlink.
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), child.as_ptr(), 0) } != 0 {
            return Err(os_error());
        }
        self.sync()
    }
    pub fn lock(&self, child: &Path) -> Result<PrivateLock, Error> {
        self.validate()?;
        let child_name = name(child)?;
        let file = open_at(&self.file, &child_name, libc::O_RDWR | libc::O_CREAT)?;
        check(&file, true, false)?;
        // SAFETY: flock only borrows a live descriptor; lock persists until File is dropped.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::Storage);
        }
        let value = PrivateLock {
            file,
            child: child.to_path_buf(),
        };
        value.validate(self)?;
        Ok(value)
    }
}
fn temporary_prefix(child: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::from(".replace-");
    for byte in child {
        write!(value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value.push('-');
    value
}
fn open_ancestor(path: &Path) -> Result<File, Error> {
    if !path.is_absolute() {
        return Err(Error::Invalid);
    }
    let mut current = File::open("/").map_err(|_| Error::Storage)?;
    check(&current, false, true)?;
    for part in path.components().skip(1) {
        let Component::Normal(part) = part else {
            return Err(Error::Invalid);
        };
        current = open_at(
            &current,
            &name(Path::new(part))?,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        check(&current, false, true)?;
    }
    Ok(current)
}
pub struct PrivateLock {
    file: File,
    child: PathBuf,
}
impl PrivateLock {
    pub fn validate(&self, directory: &Directory) -> Result<(), Error> {
        directory.validate()?;
        check(&self.file, true, false)?;
        same(
            &self.file,
            &open_at(&directory.file, &name(&self.child)?, libc::O_RDONLY)?,
        )
    }
}
pub fn read_private_file(path: &Path, max: u64) -> Result<Vec<u8>, Error> {
    Directory::open(path.parent().ok_or(Error::Invalid)?)?
        .read(Path::new(path.file_name().ok_or(Error::Invalid)?), max)
}
pub fn atomic_create(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    Directory::open(path.parent().ok_or(Error::Invalid)?)?
        .create(Path::new(path.file_name().ok_or(Error::Invalid)?), bytes)
}
pub fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    Directory::open(path.parent().ok_or(Error::Invalid)?)?
        .replace(Path::new(path.file_name().ok_or(Error::Invalid)?), bytes)
}
pub fn remove_private_file(path: &Path) -> Result<(), Error> {
    Directory::open(path.parent().ok_or(Error::Invalid)?)?
        .remove(Path::new(path.file_name().ok_or(Error::Invalid)?))
}

/// Bounded no-follow read for public files, without requiring a private parent directory.
pub fn read_regular_file(path: &Path, max: u64) -> Result<Vec<u8>, Error> {
    if max > MAX_BYTES {
        return Err(Error::Invalid);
    }
    let parent = path.parent().ok_or(Error::Invalid)?;
    let directory = open_ancestor(parent)?;
    let child = name(Path::new(path.file_name().ok_or(Error::Invalid)?))?;
    let file = open_at(&directory, &child, libc::O_RDONLY)?;
    check(&file, false, false)?;
    let mut bytes = Vec::new();
    (&file)
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Storage)?;
    if bytes.is_empty() || bytes.len() as u64 > max {
        return Err(Error::Invalid);
    }
    check(&file, false, false)?;
    same(&directory, &open_ancestor(parent)?)?;
    same(&file, &open_at(&directory, &child, libc::O_RDONLY)?)?;
    Ok(bytes)
}

/// Removes a checked, single-link public file and fully synchronizes its parent.
pub fn remove_regular_file(path: &Path) -> Result<(), Error> {
    let parent = path.parent().ok_or(Error::Invalid)?;
    let directory = open_ancestor(parent)?;
    let child = name(Path::new(path.file_name().ok_or(Error::Invalid)?))?;
    let file = open_at(&directory, &child, libc::O_RDONLY)?;
    check(&file, false, false)?;
    same(&directory, &open_ancestor(parent)?)?;
    same(&file, &open_at(&directory, &child, libc::O_RDONLY)?)?;
    // SAFETY: child is one NUL-terminated name under the owned directory descriptor.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), child.as_ptr(), 0) } != 0 {
        return Err(os_error());
    }
    full_sync(&directory)?;
    same(&directory, &open_ancestor(parent)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    fn root() -> PathBuf {
        static COUNT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().canonicalize().unwrap().join(format!(
            "phone-m2-{}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed)
        ))
    }
    #[test]
    fn private_operations_and_full_sync() {
        let root = root();
        let dir = Directory::prepare(&root).unwrap();
        let item = Path::new("state");
        dir.create(item, b"one").unwrap();
        assert!(dir.create(item, b"overwrite").is_err());
        assert_eq!(dir.read(item, 3).unwrap(), b"one");
        assert!(dir.read(item, 2).is_err());
        assert!(dir.read(item, u64::MAX).is_err());
        dir.replace(item, b"two").unwrap();
        let lock = dir.lock(Path::new("lock")).unwrap();
        assert!(dir.lock(Path::new("lock")).is_err());
        drop(lock);
        dir.remove(item).unwrap();
        assert!(matches!(dir.read(item, 10), Err(Error::Missing)));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn teardown_removes_only_exact_target_replacement_temporaries() {
        let root = root();
        let dir = Directory::prepare(&root).unwrap();
        for child in ["state", "state-other"] {
            dir.create(Path::new(child), b"old").unwrap();
            FAILURE.with(|failure| failure.set(Some("rename")));
            assert!(dir.replace(Path::new(child), b"new").is_err());
        }
        dir.create(Path::new(".state-legacy-1.tmp"), b"unattributed")
            .unwrap();
        dir.remove_replacement_temporaries(Path::new("state"))
            .unwrap();
        let filenames: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            !filenames
                .iter()
                .any(|name| name.starts_with(&temporary_prefix(b"state")))
        );
        assert!(
            filenames
                .iter()
                .any(|name| name.starts_with(&temporary_prefix(b"state-other")))
        );
        assert!(root.join(".state-legacy-1.tmp").exists());
        assert_eq!(dir.read(Path::new("state"), 10).unwrap(), b"old");
        let alias_name = format!("{}hostile.tmp", temporary_prefix(b"state"));
        std::os::unix::fs::symlink(root.join("state-other"), root.join(alias_name)).unwrap();
        assert!(
            dir.remove_replacement_temporaries(Path::new("state"))
                .is_err()
        );
        assert_eq!(dir.read(Path::new("state-other"), 10).unwrap(), b"old");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn public_files_are_bounded_single_link_and_never_followed() {
        let root = root();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = root.join("public");
        std::fs::write(&path, b"public").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_regular_file(&path, 6).unwrap(), b"public");
        assert!(read_regular_file(&path, 5).is_err());
        let alias = root.join("alias");
        symlink(&path, &alias).unwrap();
        assert!(read_regular_file(&alias, 6).is_err());
        assert!(remove_regular_file(&alias).is_err());
        std::fs::remove_file(&alias).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(read_regular_file(&path, 6).is_err());
        assert!(remove_regular_file(&path).is_err());
        std::fs::remove_file(alias).unwrap();
        remove_regular_file(&path).unwrap();
        assert!(matches!(read_regular_file(&path, 6), Err(Error::Missing)));
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn links_permissions_and_replaced_paths_fail_closed() {
        let root = root();
        let dir = Directory::prepare(&root).unwrap();
        dir.create(Path::new("state"), b"one").unwrap();
        symlink("state", root.join("soft")).unwrap();
        assert!(dir.read(Path::new("soft"), 10).is_err());
        std::fs::hard_link(root.join("state"), root.join("hard")).unwrap();
        assert!(dir.read(Path::new("state"), 10).is_err());
        assert!(dir.replace(Path::new("state"), b"two").is_err());
        std::fs::remove_file(root.join("hard")).unwrap();
        std::fs::set_permissions(root.join("state"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(dir.read(Path::new("state"), 10).is_err());
        let moved = root.with_extension("moved");
        std::fs::rename(&root, &moved).unwrap();
        let replacement = Directory::prepare(&root).unwrap();
        assert!(dir.create(Path::new("wrong"), b"no").is_err());
        assert!(replacement.read(Path::new("wrong"), 10).is_err());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(moved).unwrap();
    }
    #[test]
    fn directory_preparation_never_follows_or_chmods_existing_state() {
        let root = root();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Directory::prepare(&root).is_err());
        assert_eq!(std::fs::metadata(&root).unwrap().mode() & 0o777, 0o755);
        let alias = root.with_extension("link");
        symlink(&root, &alias).unwrap();
        assert!(Directory::prepare(&alias).is_err());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    use std::process::Command;
    fn root() -> PathBuf {
        static COUNT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().canonicalize().unwrap().join(format!(
            "phone-m2-fault-{}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed)
        ))
    }
    #[test]
    fn write_sync_and_rename_failure_preserve_old_state() {
        let root = root();
        let dir = Directory::prepare(&root).unwrap();
        dir.create(Path::new("state"), b"old").unwrap();
        for stage in ["write", "sync", "rename"] {
            FAILURE.with(|f| f.set(Some(stage)));
            assert!(dir.replace(Path::new("state"), b"new").is_err());
            assert_eq!(dir.read(Path::new("state"), 3).unwrap(), b"old");
        }
        // Failed temporary writes are retained, never treated as a reason to reset state.
        assert!(std::fs::read_dir(&root).unwrap().count() > 1);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn acl_widening_and_backup_exclusion() {
        let root = root();
        let dir = Directory::prepare(&root).unwrap();
        let output = Command::new("/usr/bin/tmutil")
            .arg("isexcluded")
            .arg(&root)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("[Excluded]"));
        dir.create(Path::new("state"), b"value").unwrap();
        assert!(
            Command::new("/bin/chmod")
                .args(["+a", "everyone allow read"])
                .arg(root.join("state"))
                .status()
                .unwrap()
                .success()
        );
        assert!(dir.read(Path::new("state"), 5).is_err());
        assert!(dir.replace(Path::new("state"), b"new").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
