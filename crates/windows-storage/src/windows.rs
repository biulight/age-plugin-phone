use std::{
    ffi::{OsStr, c_void},
    fs::File,
    io::{Read as _, Write as _},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt as _,
        io::{AsRawHandle as _, FromRawHandle as _},
    },
    path::{Path, PathBuf},
    ptr,
    sync::atomic::{AtomicU64, Ordering},
};

use thiserror::Error;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND,
        ERROR_PATH_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
        LocalFree,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetNamedSecurityInfoW, SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
        GetSecurityDescriptorControl, GetTokenInformation, INHERITED_ACE, IsValidSid,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE,
        FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ,
        FileDispositionInfo, GetFileInformationByHandle, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_ALWAYS, OPEN_EXISTING,
        SetFileInformationByHandle,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const MAX_SID_STRING_CHARS: usize = 184;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("path is missing")]
    Missing,
    #[error("path already exists")]
    AlreadyExists,
    #[error("path is locked by another process")]
    Locked,
    #[error("path, owner, ACL, link count, or file type is insecure")]
    Insecure,
    #[error("private Windows storage operation failed")]
    Storage,
}

/// An exclusive, non-blocking Windows file lock held until drop.
pub struct PrivateLock {
    _file: File,
}

pub fn ensure_private_directory(path: &Path) -> Result<(), Error> {
    validate_absolute(path)?;
    match validate_private_directory(path) {
        Ok(()) => return Ok(()),
        Err(Error::Missing) => {}
        Err(error) => return Err(error),
    }
    let security = OwnedSecurityDescriptor::current_user_only()?;
    let mut attributes = security.attributes();
    let wide = wide(path)?;
    if unsafe { CreateDirectoryW(wide.as_ptr(), &raw mut attributes) } == 0 {
        let code = unsafe { GetLastError() };
        if code != ERROR_ALREADY_EXISTS {
            return Err(Error::Storage);
        }
    }
    validate_private_directory(path)
}

pub fn validate_private_directory(path: &Path) -> Result<(), Error> {
    validate_absolute(path)?;
    let file = open_handle(path, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, true)?;
    validate_handle(&file, true)?;
    validate_acl(path)
}

pub fn atomic_create(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    validate_parent(path)?;
    let temporary = write_temporary(path, bytes)?;
    let old = wide(&temporary)?;
    let new = wide(path)?;
    if unsafe { MoveFileExW(old.as_ptr(), new.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        let code = unsafe { GetLastError() };
        let _ = std::fs::remove_file(&temporary);
        return if code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS {
            Err(Error::AlreadyExists)
        } else {
            Err(Error::Storage)
        };
    }
    validate_private_file(path).map(drop)
}

pub fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    validate_parent(path)?;
    validate_private_file(path)?;
    let temporary = write_temporary(path, bytes)?;
    let old = wide(&temporary)?;
    let new = wide(path)?;
    if unsafe {
        MoveFileExW(
            old.as_ptr(),
            new.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(Error::Storage);
    }
    validate_private_file(path).map(drop)
}

pub fn read_private_file(path: &Path, maximum: u64) -> Result<Vec<u8>, Error> {
    let file = validate_private_file(path)?;
    read_bounded(file, maximum)
}

/// Reads one ordinary file through a no-share handle after rejecting reparse points, hard links,
/// directories, and oversized input. Unlike private state, a public identity stub need not have a
/// current-user-only ACL.
pub fn read_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, Error> {
    validate_absolute_file_path(path)?;
    let file = open_handle(path, GENERIC_READ, 0, OPEN_EXISTING, true)?;
    validate_handle(&file, false)?;
    read_bounded(file, maximum)
}

/// Deletes one private file by its already-validated handle.
pub fn remove_private_file(path: &Path) -> Result<(), Error> {
    validate_parent(path)?;
    remove_file_by_handle(path, true)
}

/// Deletes one ordinary public file by its already-validated handle.
pub fn remove_regular_file(path: &Path) -> Result<(), Error> {
    validate_absolute_file_path(path)?;
    remove_file_by_handle(path, false)
}

fn read_bounded(file: File, maximum: u64) -> Result<Vec<u8>, Error> {
    let length = file.metadata().map_err(|_| Error::Storage)?.len();
    if length == 0 || length > maximum {
        return Err(Error::Insecure);
    }
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Storage)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(Error::Insecure);
    }
    Ok(bytes)
}

fn remove_file_by_handle(path: &Path, private: bool) -> Result<(), Error> {
    let file = open_handle(path, GENERIC_READ | DELETE, 0, OPEN_EXISTING, true)?;
    validate_handle(&file, false)?;
    if private {
        validate_acl(path)?;
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>()).map_err(|_| Error::Storage)?,
        )
    } == 0
    {
        return Err(Error::Storage);
    }
    drop(file);
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(Error::Storage),
    }
}

pub fn open_private_lock(path: &Path) -> Result<PrivateLock, Error> {
    validate_parent(path)?;
    let existed = path.exists();
    let security = OwnedSecurityDescriptor::current_user_only()?;
    let mut attributes = security.attributes();
    let wide = wide(path)?;
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            &raw mut attributes,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return if existed {
            Err(Error::Locked)
        } else {
            Err(Error::Storage)
        };
    }
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    validate_handle(&file, false)?;
    validate_acl(path)?;
    Ok(PrivateLock { _file: file })
}

fn validate_private_file(path: &Path) -> Result<File, Error> {
    validate_parent(path)?;
    let file = open_handle(path, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, true)?;
    validate_handle(&file, false)?;
    validate_acl(path)?;
    Ok(file)
}

fn write_temporary(path: &Path, bytes: &[u8]) -> Result<PathBuf, Error> {
    for _ in 0..32 {
        let name = path.file_name().ok_or(Error::Insecure)?;
        let temporary = path.with_file_name(format!(
            ".{}.{}.{}.tmp",
            name.to_string_lossy(),
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        let security = OwnedSecurityDescriptor::current_user_only()?;
        let mut attributes = security.attributes();
        let wide = wide(&temporary)?;
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                &raw mut attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let code = unsafe { GetLastError() };
            if code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS {
                continue;
            }
            return Err(Error::Storage);
        }
        let mut file = unsafe { File::from_raw_handle(handle.cast()) };
        if file.write_all(bytes).is_err() || file.sync_all().is_err() {
            drop(file);
            let _ = std::fs::remove_file(&temporary);
            return Err(Error::Storage);
        }
        validate_handle(&file, false)?;
        validate_acl(&temporary)?;
        drop(file);
        return Ok(temporary);
    }
    Err(Error::Storage)
}

fn open_handle(
    path: &Path,
    access: u32,
    sharing: u32,
    disposition: u32,
    reparse: bool,
) -> Result<File, Error> {
    let wide = wide(path)?;
    let flags = FILE_ATTRIBUTE_NORMAL
        | FILE_FLAG_BACKUP_SEMANTICS
        | if reparse {
            FILE_FLAG_OPEN_REPARSE_POINT
        } else {
            0
        };
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            sharing,
            ptr::null(),
            disposition,
            flags,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
            Err(Error::Missing)
        } else {
            Err(Error::Storage)
        }
    } else {
        Ok(unsafe { File::from_raw_handle(handle.cast()) })
    }
}

fn validate_handle(file: &File, directory: bool) -> Result<(), Error> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut info) } == 0 {
        return Err(Error::Storage);
    }
    let is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.nNumberOfLinks != 1
        || is_directory != directory
    {
        return Err(Error::Insecure);
    }
    Ok(())
}

fn validate_acl(path: &Path) -> Result<(), Error> {
    let wide = wide(path)?;
    let mut owner = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() || owner.is_null() || dacl.is_null() {
        return Err(Error::Insecure);
    }
    let descriptor = LocalAllocation(descriptor);
    let token = CurrentUserToken::open()?;
    let user = token.user_sid()?;
    let user = user.as_ptr().cast_mut().cast();
    let mut control = 0_u16;
    let mut revision = 0_u32;
    let mut size: ACL_SIZE_INFORMATION = unsafe { zeroed() };
    let valid = unsafe {
        EqualSid(owner, user) != 0
            && GetSecurityDescriptorControl(descriptor.0, &raw mut control, &raw mut revision) != 0
            && control & SE_DACL_PROTECTED != 0
            && GetAclInformation(
                dacl,
                (&raw mut size).cast(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap(),
                AclSizeInformation,
            ) != 0
            && size.AceCount == 1
    };
    if !valid {
        return Err(Error::Insecure);
    }
    let mut raw_ace: *mut c_void = ptr::null_mut();
    if unsafe { GetAce(dacl, 0, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
        return Err(Error::Insecure);
    }
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    let sid = (&raw const ace.SidStart).cast_mut().cast();
    if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE
        || u32::from(ace.Header.AceFlags) & INHERITED_ACE != 0
        || ace.Mask != FILE_ALL_ACCESS
        || unsafe { EqualSid(sid, user) } == 0
    {
        return Err(Error::Insecure);
    }
    Ok(())
}

fn validate_parent(path: &Path) -> Result<(), Error> {
    validate_absolute_file_path(path)?;
    validate_private_directory(path.parent().ok_or(Error::Insecure)?)
}

fn validate_absolute_file_path(path: &Path) -> Result<(), Error> {
    validate_absolute(path)?;
    path.file_name()
        .is_some()
        .then_some(())
        .ok_or(Error::Insecure)
}

fn validate_absolute(path: &Path) -> Result<(), Error> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(Error::Insecure)
    }
}

fn wide(path: &Path) -> Result<Vec<u16>, Error> {
    wide_os(path.as_os_str())
}

fn wide_os(value: &OsStr) -> Result<Vec<u16>, Error> {
    let encoded: Vec<u16> = value.encode_wide().collect();
    if encoded.is_empty() || encoded.contains(&0) {
        return Err(Error::Insecure);
    }
    Ok(encoded.into_iter().chain(Some(0)).collect())
}

struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl OwnedSecurityDescriptor {
    fn current_user_only() -> Result<Self, Error> {
        let token = CurrentUserToken::open()?;
        let sid = token.user_sid()?;
        let sid = sid.as_ptr().cast_mut().cast();
        let mut string_sid = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &raw mut string_sid) } == 0 || string_sid.is_null()
        {
            return Err(Error::Storage);
        }
        let string_sid = LocalWideString(string_sid);
        let length = (0..MAX_SID_STRING_CHARS)
            .take_while(|index| unsafe { *string_sid.0.add(*index) } != 0)
            .count();
        if length == MAX_SID_STRING_CHARS {
            return Err(Error::Storage);
        }
        let sid_text =
            String::from_utf16(unsafe { std::slice::from_raw_parts(string_sid.0, length) })
                .map_err(|_| Error::Storage)?;
        let sddl = format!("O:{sid_text}D:P(A;;FA;;;{sid_text})");
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SECURITY_DESCRIPTOR_REVISION,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(Error::Storage);
        }
        Ok(Self(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

struct CurrentUserToken(*mut c_void);

impl CurrentUserToken {
    fn open() -> Result<Self, Error> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0
            || token.is_null()
        {
            Err(Error::Storage)
        } else {
            Ok(Self(token))
        }
    }

    fn user_sid(&self) -> Result<Vec<u8>, Error> {
        let mut needed = 0_u32;
        unsafe {
            GetTokenInformation(self.0, TokenUser, ptr::null_mut(), 0, &raw mut needed);
        }
        if needed < u32::try_from(size_of::<TOKEN_USER>()).unwrap() {
            return Err(Error::Storage);
        }
        // This allocation cannot be returned independently of the SID. Callers only use this
        // helper while the token remains open, but TokenUser itself still needs stable storage.
        let needed_usize = usize::try_from(needed).map_err(|_| Error::Storage)?;
        let words = needed_usize.div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        if unsafe {
            GetTokenInformation(
                self.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &raw mut needed,
            )
        } == 0
        {
            return Err(Error::Storage);
        }
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let sid_bytes = sid_length(sid)?;
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), sid_bytes) }.to_vec())
    }
}

impl Drop for CurrentUserToken {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn sid_length(sid: *mut c_void) -> Result<usize, Error> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(Error::Storage);
    }
    usize::try_from(unsafe { GetLengthSid(sid) }).map_err(|_| Error::Storage)
}

struct LocalAllocation(PSECURITY_DESCRIPTOR);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

struct LocalWideString(*mut u16);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;

    fn root() -> PathBuf {
        let base = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
        let root = base.join(format!(
            "age-plugin-phone-storage-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        ensure_private_directory(&root).unwrap();
        root
    }

    #[test]
    fn private_create_replace_bounded_read_and_lock() {
        let root = root();
        let state = root.join("state.cbor");
        atomic_create(&state, b"one").unwrap();
        assert_eq!(read_private_file(&state, 3).unwrap(), b"one");
        assert_eq!(atomic_create(&state, b"again"), Err(Error::AlreadyExists));
        atomic_replace(&state, b"two").unwrap();
        assert_eq!(read_private_file(&state, 3).unwrap(), b"two");
        assert!(read_private_file(&state, 2).is_err());

        let lock_path = root.join("state.lock");
        let lock = open_private_lock(&lock_path).unwrap();
        assert!(open_private_lock(&lock_path).is_err());
        assert_eq!(remove_private_file(&lock_path), Err(Error::Storage));
        drop(lock);
        open_private_lock(&lock_path).unwrap();

        remove_private_file(&lock_path).unwrap();
        remove_private_file(&state).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn rejects_hard_linked_state() {
        let root = root();
        let state = root.join("state.cbor");
        let alias = root.join("alias.cbor");
        atomic_create(&state, b"state").unwrap();
        std::fs::hard_link(&state, &alias).unwrap();
        assert_eq!(read_private_file(&state, 32), Err(Error::Insecure));
        assert_eq!(remove_private_file(&state), Err(Error::Insecure));
        std::fs::remove_file(&alias).unwrap();
        remove_private_file(&state).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn rejects_widened_acl() {
        let root = root();
        let state = root.join("state.cbor");
        atomic_create(&state, b"state").unwrap();
        let mut path = wide(&state).unwrap();
        assert_eq!(
            unsafe {
                SetNamedSecurityInfoW(
                    path.as_mut_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null(),
                )
            },
            0
        );
        assert_eq!(read_private_file(&state, 32), Err(Error::Insecure));
        std::fs::remove_file(&state).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn bounded_public_file_read_and_handle_bound_removal() {
        let root = root();
        let public = root.join("identity.txt");
        std::fs::write(&public, b"public stub").unwrap();
        assert_eq!(read_regular_file(&public, 32).unwrap(), b"public stub");
        assert_eq!(read_regular_file(&public, 4), Err(Error::Insecure));
        remove_regular_file(&public).unwrap();
        assert_eq!(remove_regular_file(&public), Err(Error::Missing));
        std::fs::remove_dir(&root).unwrap();
    }
}
