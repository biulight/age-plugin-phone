//! Explicit, crash-safe removal of one hardware desktop pairing.

#![cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]

use std::path::{Path, PathBuf};

#[cfg(windows)]
use age_plugin_phone_platform_storage::windows as platform;
#[cfg(target_os = "macos")]
use macos_platform as platform;
use thiserror::Error;

#[cfg(target_os = "macos")]
mod macos_platform {
    use age_plugin_phone_platform_storage::macos::Directory;
    pub use age_plugin_phone_platform_storage::macos::{
        Error, PrivateLock, read_regular_file, remove_private_file, remove_regular_file,
    };
    use std::path::Path;
    pub fn validate_private_directory(path: &Path) -> Result<(), Error> {
        Directory::open(path).map(|_| ())
    }
    pub fn open_private_lock(path: &Path) -> Result<PrivateLock, Error> {
        Directory::open(path.parent().ok_or(Error::Invalid)?)?
            .lock(Path::new(path.file_name().ok_or(Error::Invalid)?))
    }
}

use crate::cleanup_journal::CleanupJournal;
#[cfg(any(windows, target_os = "macos", test))]
use crate::cleanup_journal::CleanupTarget;

const MAX_IDENTITY_STUB_BYTES: u64 = 16_384;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CleanupError {
    #[error(
        "desktop state removal is supported only on the Windows or macOS hardware desktop platforms"
    )]
    Unsupported,
    #[error("the public identity stub or cleanup target is unavailable or malformed")]
    InvalidTarget,
    #[error("desktop cleanup confirmation did not match the full transcript fingerprint")]
    ConfirmationMismatch,
    #[error("desktop cleanup is already active or the response replay state is in use")]
    Busy,
    #[error("desktop cleanup could not be durably started or completed")]
    Storage,
}

/// Returns the exact transcript fingerprint that must be typed before destructive cleanup.
///
/// # Errors
///
/// Returns an error when the platform is unsupported or the target state is unavailable.
#[cfg(any(windows, target_os = "macos"))]
pub fn confirmation_fingerprint(identity_stub: &Path) -> Result<String, CleanupError> {
    let root = cleanup_root()?;
    let supplied_path = absolute_path(identity_stub)?;
    let stub = match crate::cleanup_journal::read(&root).map_err(|_| CleanupError::Storage)? {
        Some(journal) => {
            ensure_same_stub_path(&supplied_path, &journal)?;
            validate_existing_stub_if_present(&supplied_path, &journal)?;
            journal
                .paired()
                .map(|(stub, _)| stub.clone())
                .ok_or(CleanupError::InvalidTarget)?
        }
        None => read_stub(&supplied_path)?.0,
    };
    Ok(hex(&stub.transcript_fingerprint))
}

/// Removes one exact hardware desktop pairing after revalidating the typed full fingerprint.
///
/// # Errors
///
/// Returns an error when confirmation fails or any target cannot be securely removed.
#[cfg(any(windows, target_os = "macos"))]
pub fn remove_desktop_state(
    identity_stub: &Path,
    entered_fingerprint: &str,
) -> Result<(), CleanupError> {
    let expected = confirmation_fingerprint(identity_stub)?;
    verify_confirmation(&expected, entered_fingerprint)?;

    let root = cleanup_root()?;
    let supplied_path = absolute_path(identity_stub)?;
    let _cleanup_lock =
        platform::open_private_lock(&crate::cleanup_journal::journal_lock_path(&root))
            .map_err(|_| CleanupError::Busy)?;
    if crate::setup::read_optional(&root)
        .map_err(|_| CleanupError::Storage)?
        .is_some()
    {
        return Err(CleanupError::Busy);
    }

    let journal = match crate::cleanup_journal::read(&root).map_err(|_| CleanupError::Storage)? {
        Some(journal) => {
            ensure_same_stub_path(&supplied_path, &journal)?;
            validate_existing_stub_if_present(&supplied_path, &journal)?;
            if hex(&journal.transcript_fingerprint()) != expected {
                return Err(CleanupError::InvalidTarget);
            }
            journal
        }
        None => start_cleanup(&root, &supplied_path, &expected)?,
    };

    execute_native_cleanup(&journal, &root)
}

/// Returns the exact transcript fingerprint for one private locator whose public stub is missing.
///
/// # Errors
///
/// Returns an error when the platform is unsupported or the locator is not a canonical private
/// record in the configured private product root.
#[cfg(any(windows, target_os = "macos"))]
pub fn orphan_confirmation_fingerprint(locator_path: &Path) -> Result<String, CleanupError> {
    let root = cleanup_root()?;
    orphan_confirmation_fingerprint_in(&root, locator_path)
}

#[cfg(any(windows, target_os = "macos"))]
fn orphan_confirmation_fingerprint_in(
    root: &Path,
    locator_path: &Path,
) -> Result<String, CleanupError> {
    let supplied_path = absolute_path(locator_path)?;
    let fingerprint = if let Some(journal) =
        crate::cleanup_journal::read(root).map_err(|_| CleanupError::Storage)?
    {
        ensure_same_orphan_locator(&supplied_path, &journal)?;
        journal.transcript_fingerprint()
    } else {
        let (_, record) = crate::locator::open_pairing_locator_for_cleanup(root, &supplied_path)
            .map_err(|_| CleanupError::InvalidTarget)?;
        record.transcript_fingerprint
    };
    Ok(hex(&fingerprint))
}

/// Removes private hardware desktop state addressed by a canonical locator after exact confirmation.
///
/// This recovery-only path intentionally does not discover or remove public identity stubs. It is
/// for a locator whose original public stub is already unavailable.
///
/// # Errors
///
/// Returns an error when confirmation, locator/state binding, replay scope, locking, or durable
/// cleanup fails.
#[cfg(any(windows, target_os = "macos"))]
pub fn remove_orphaned_desktop_state(
    locator_path: &Path,
    entered_fingerprint: &str,
) -> Result<(), CleanupError> {
    let root = cleanup_root()?;
    remove_orphaned_desktop_state_in(&root, locator_path, entered_fingerprint)
}

#[cfg(any(windows, target_os = "macos"))]
fn remove_orphaned_desktop_state_in(
    root: &Path,
    locator_path: &Path,
    entered_fingerprint: &str,
) -> Result<(), CleanupError> {
    let expected = orphan_confirmation_fingerprint_in(root, locator_path)?;
    verify_confirmation(&expected, entered_fingerprint)?;

    let supplied_path = absolute_path(locator_path)?;
    let _cleanup_lock =
        platform::open_private_lock(&crate::cleanup_journal::journal_lock_path(root))
            .map_err(|_| CleanupError::Busy)?;
    if crate::setup::read_optional(root)
        .map_err(|_| CleanupError::Storage)?
        .is_some()
    {
        return Err(CleanupError::Busy);
    }

    let journal = match crate::cleanup_journal::read(root).map_err(|_| CleanupError::Storage)? {
        Some(journal) => {
            ensure_same_orphan_locator(&supplied_path, &journal)?;
            if hex(&journal.transcript_fingerprint()) != expected {
                return Err(CleanupError::InvalidTarget);
            }
            journal
        }
        None => start_orphan_cleanup(root, &supplied_path, &expected)?,
    };

    execute_native_cleanup(&journal, root)
}

#[cfg(not(any(windows, target_os = "macos")))]
/// Reports that desktop cleanup is unavailable outside the Windows or macOS hardware desktop platforms.
///
/// # Errors
///
/// Always returns [`CleanupError::Unsupported`].
pub fn confirmation_fingerprint(_identity_stub: &Path) -> Result<String, CleanupError> {
    Err(CleanupError::Unsupported)
}

#[cfg(not(any(windows, target_os = "macos")))]
/// Reports that desktop cleanup is unavailable outside the Windows or macOS hardware desktop platforms.
///
/// # Errors
///
/// Always returns [`CleanupError::Unsupported`].
pub fn remove_desktop_state(
    _identity_stub: &Path,
    _entered_fingerprint: &str,
) -> Result<(), CleanupError> {
    Err(CleanupError::Unsupported)
}

#[cfg(not(any(windows, target_os = "macos")))]
/// Reports that orphan desktop cleanup is unavailable outside the Windows or macOS hardware desktop platforms.
///
/// # Errors
///
/// Always returns [`CleanupError::Unsupported`].
pub fn orphan_confirmation_fingerprint(_locator_path: &Path) -> Result<String, CleanupError> {
    Err(CleanupError::Unsupported)
}

#[cfg(not(any(windows, target_os = "macos")))]
/// Reports that orphan desktop cleanup is unavailable outside the Windows or macOS hardware desktop platforms.
///
/// # Errors
///
/// Always returns [`CleanupError::Unsupported`].
pub fn remove_orphaned_desktop_state(
    _locator_path: &Path,
    _entered_fingerprint: &str,
) -> Result<(), CleanupError> {
    Err(CleanupError::Unsupported)
}

fn verify_confirmation(expected: &str, entered: &str) -> Result<(), CleanupError> {
    if entered == expected {
        Ok(())
    } else {
        Err(CleanupError::ConfirmationMismatch)
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn cleanup_root() -> Result<PathBuf, CleanupError> {
    let root = crate::locator::default_config_root().map_err(|_| CleanupError::InvalidTarget)?;
    platform::validate_private_directory(&root).map_err(|_| CleanupError::InvalidTarget)?;
    Ok(root)
}

#[cfg(any(windows, target_os = "macos"))]
fn start_cleanup(
    root: &Path,
    stub_path: &Path,
    expected_fingerprint: &str,
) -> Result<CleanupJournal, CleanupError> {
    #[cfg(windows)]
    use age_plugin_phone_core::protocol::{
        DEFAULT_REPLAY_CAPACITY, FileReplayGuard, PairingRecord, ReplayRole, ReplayScope,
    };

    let (stub, canonical_stub_path) = read_stub(stub_path)?;
    if hex(&stub.transcript_fingerprint) != expected_fingerprint {
        return Err(CleanupError::InvalidTarget);
    }
    let locator = crate::locator::open_pairing_locator(root, &stub)
        .map_err(|_| CleanupError::InvalidTarget)?;
    #[cfg(windows)]
    let replay = {
        let desktop = crate::pairing::DesktopKeyState::open(&locator.desktop_state)
            .map_err(|_| CleanupError::InvalidTarget)?;
        if desktop.desktop_id != stub.desktop_id
            || desktop
                .signing_public_key()
                .map_err(|_| CleanupError::InvalidTarget)?
                != stub.desktop_signing_public_key
            || desktop
                .selection_public_key()
                .map_err(|_| CleanupError::InvalidTarget)?
                != stub.desktop_selection_public_key
        {
            return Err(CleanupError::InvalidTarget);
        }
        let pairing = PairingRecord {
            desktop_id: stub.desktop_id,
            identity_id: stub.identity_id,
            desktop_signing_public_key: stub.desktop_signing_public_key,
            desktop_selection_public_key: stub.desktop_selection_public_key,
            phone_signing_public_key: stub.phone_signing_public_key,
        };
        FileReplayGuard::open(
            &locator.replay_state,
            ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing),
            DEFAULT_REPLAY_CAPACITY,
        )
        .map_err(|_| CleanupError::Busy)?
    };
    #[cfg(target_os = "macos")]
    let replay = validate_macos_cleanup_state(
        root,
        &locator.desktop_state,
        &locator.replay_state,
        stub.desktop_id,
        stub.identity_id,
        Some((
            &stub.desktop_signing_public_key,
            &stub.desktop_selection_public_key,
        )),
    )?;
    let locator_path = crate::locator::existing_pairing_locator_path(root, &stub)
        .map_err(|_| CleanupError::InvalidTarget)?;
    let journal = CleanupJournal {
        target: CleanupTarget::Paired {
            stub,
            stub_path: canonical_stub_path,
        },
        locator_path,
        desktop_state: locator.desktop_state,
        replay_state: locator.replay_state,
    };
    #[cfg(target_os = "macos")]
    crate::locator::ensure_exclusive_cleanup_target(
        root,
        &journal.locator_path,
        &journal.desktop_state,
        &journal.replay_state,
    )
    .map_err(|_| CleanupError::InvalidTarget)?;
    crate::cleanup_journal::create(root, &journal).map_err(|_| CleanupError::Storage)?;
    drop(replay);
    Ok(journal)
}

#[cfg(any(windows, target_os = "macos"))]
fn start_orphan_cleanup(
    root: &Path,
    locator_path: &Path,
    expected_fingerprint: &str,
) -> Result<CleanupJournal, CleanupError> {
    #[cfg(windows)]
    use age_plugin_phone_core::protocol::{
        DEFAULT_REPLAY_CAPACITY, FileReplayGuard, ReplayRole, ReplayScope,
    };

    let (canonical_locator_path, record) =
        crate::locator::open_pairing_locator_for_cleanup(root, locator_path)
            .map_err(|_| CleanupError::InvalidTarget)?;
    if hex(&record.transcript_fingerprint) != expected_fingerprint {
        return Err(CleanupError::InvalidTarget);
    }
    #[cfg(windows)]
    let replay = {
        let desktop = crate::pairing::DesktopKeyState::open(&record.locator.desktop_state)
            .map_err(|_| CleanupError::InvalidTarget)?;
        if desktop.desktop_id != record.desktop_id {
            return Err(CleanupError::InvalidTarget);
        }
        FileReplayGuard::open(
            &record.locator.replay_state,
            ReplayScope::new(
                ReplayRole::DesktopResponses,
                record.desktop_id,
                record.identity_id,
            ),
            DEFAULT_REPLAY_CAPACITY,
        )
        .map_err(|_| CleanupError::Busy)?
    };
    #[cfg(target_os = "macos")]
    let replay = validate_macos_cleanup_state(
        root,
        &record.locator.desktop_state,
        &record.locator.replay_state,
        record.desktop_id,
        record.identity_id,
        None,
    )?;
    let journal = CleanupJournal {
        target: CleanupTarget::Orphan {
            desktop_id: record.desktop_id,
            identity_id: record.identity_id,
            transcript_fingerprint: record.transcript_fingerprint,
        },
        locator_path: canonical_locator_path,
        desktop_state: record.locator.desktop_state,
        replay_state: record.locator.replay_state,
    };
    #[cfg(target_os = "macos")]
    crate::locator::ensure_exclusive_cleanup_target(
        root,
        &journal.locator_path,
        &journal.desktop_state,
        &journal.replay_state,
    )
    .map_err(|_| CleanupError::InvalidTarget)?;
    crate::cleanup_journal::create(root, &journal).map_err(|_| CleanupError::Storage)?;
    drop(replay);
    Ok(journal)
}

#[cfg(target_os = "macos")]
fn validate_macos_cleanup_state(
    root: &Path,
    desktop_state: &Path,
    replay_state: &Path,
    desktop_id: [u8; 16],
    identity_id: [u8; 16],
    public_keys: Option<(&[u8; 33], &[u8; 33])>,
) -> Result<MacosCleanupGuard, CleanupError> {
    use age_plugin_phone_platform_storage::macos::{self, Error};
    // Unavailable state can be removed only under its deterministic managed name. Arbitrary
    // explicit-state paths still require valid metadata and replay scope to prove ownership.
    let managed = desktop_state == root.join(format!("desktop-{}.state", hex(&desktop_id)))
        && replay_state == root.join(format!("replay-{}.state", hex(&desktop_id)));
    match crate::pairing::cleanup_desktop_binding(desktop_state) {
        Ok((id, signing, selection)) => {
            if id != desktop_id
                || public_keys.is_some_and(|(expected_signing, expected_selection)| {
                    *expected_signing != signing || *expected_selection != selection
                })
            {
                return Err(CleanupError::InvalidTarget);
            }
        }
        Err(_) if managed => {
            // Known partial hardware state is a cleanup target, never an import/repair source.
            match macos::read_private_file(desktop_state, 16_384).map(zeroize::Zeroizing::new) {
                Ok(bytes) if bytes.starts_with(b"APSE2") || bytes.as_slice() == b"pending" => {}
                Err(Error::Missing) => {}
                _ => return Err(CleanupError::InvalidTarget),
            }
        }
        Err(_) => return Err(CleanupError::InvalidTarget),
    }
    if !managed {
        use age_plugin_phone_core::protocol::{
            DEFAULT_REPLAY_CAPACITY, FileReplayGuard, ReplayRole, ReplayScope,
        };
        let replay = FileReplayGuard::open(
            replay_state,
            ReplayScope::new(ReplayRole::DesktopResponses, desktop_id, identity_id),
            DEFAULT_REPLAY_CAPACITY,
        )
        .map_err(|_| CleanupError::InvalidTarget)?;
        return Ok(MacosCleanupGuard {
            _native: None,
            _replay: Some(replay),
        });
    }
    let lock = platform::open_private_lock(&replay_lock_path(replay_state)?)
        .map_err(|_| CleanupError::Busy)?;
    Ok(MacosCleanupGuard {
        _native: Some(lock),
        _replay: None,
    })
}

#[cfg(target_os = "macos")]
struct MacosCleanupGuard {
    _native: Option<platform::PrivateLock>,
    _replay: Option<age_plugin_phone_core::protocol::FileReplayGuard>,
}

#[cfg(any(windows, target_os = "macos"))]
fn read_stub(path: &Path) -> Result<(crate::pairing::PublicIdentityStub, PathBuf), CleanupError> {
    let absolute = absolute_path(path)?;
    let bytes = platform::read_regular_file(&absolute, MAX_IDENTITY_STUB_BYTES)
        .map_err(|_| CleanupError::InvalidTarget)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| CleanupError::InvalidTarget)?;
    let stub =
        crate::pairing::decode_identity_stub_text(text).map_err(|_| CleanupError::InvalidTarget)?;
    Ok((stub, absolute))
}

#[cfg(any(windows, target_os = "macos"))]
fn absolute_path(path: &Path) -> Result<PathBuf, CleanupError> {
    std::path::absolute(path).map_err(|_| CleanupError::InvalidTarget)
}

#[cfg(any(windows, target_os = "macos"))]
fn ensure_same_stub_path(path: &Path, journal: &CleanupJournal) -> Result<(), CleanupError> {
    journal
        .paired()
        .is_some_and(|(_, stub_path)| path == stub_path)
        .then_some(())
        .ok_or(CleanupError::InvalidTarget)
}

#[cfg(any(windows, target_os = "macos"))]
fn ensure_same_orphan_locator(path: &Path, journal: &CleanupJournal) -> Result<(), CleanupError> {
    (matches!(&journal.target, CleanupTarget::Orphan { .. }) && path == journal.locator_path)
        .then_some(())
        .ok_or(CleanupError::InvalidTarget)
}

#[cfg(any(windows, target_os = "macos"))]
fn validate_existing_stub_if_present(
    path: &Path,
    journal: &CleanupJournal,
) -> Result<(), CleanupError> {
    let (expected_stub, _) = journal.paired().ok_or(CleanupError::InvalidTarget)?;
    match platform::read_regular_file(path, MAX_IDENTITY_STUB_BYTES) {
        Ok(bytes) => {
            let text = std::str::from_utf8(&bytes).map_err(|_| CleanupError::InvalidTarget)?;
            let stub = crate::pairing::decode_identity_stub_text(text)
                .map_err(|_| CleanupError::InvalidTarget)?;
            (stub == *expected_stub)
                .then_some(())
                .ok_or(CleanupError::InvalidTarget)
        }
        Err(platform::Error::Missing) => Ok(()),
        Err(_) => Err(CleanupError::InvalidTarget),
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn execute_native_cleanup(journal: &CleanupJournal, root: &Path) -> Result<(), CleanupError> {
    #[cfg(target_os = "macos")]
    {
        if crate::cleanup_journal::read(root)
            .map_err(|_| CleanupError::Storage)?
            .as_ref()
            != Some(journal)
        {
            return Err(CleanupError::InvalidTarget);
        }
        crate::locator::ensure_exclusive_cleanup_target(
            root,
            &journal.locator_path,
            &journal.desktop_state,
            &journal.replay_state,
        )
        .map_err(|_| CleanupError::InvalidTarget)?;
        let mut operations = CheckedMacosCleanupOperations::new(root, &journal.replay_state)?;
        execute_cleanup(journal, root, &mut operations)
    }
    #[cfg(windows)]
    {
        execute_cleanup(journal, root, &mut NativeCleanupOperations)
    }
}

#[cfg(target_os = "macos")]
struct CheckedMacosCleanupOperations {
    directory: age_plugin_phone_platform_storage::macos::Directory,
    lock: platform::PrivateLock,
    lock_path: PathBuf,
    lock_removed: bool,
}

#[cfg(target_os = "macos")]
impl CheckedMacosCleanupOperations {
    fn new(root: &Path, replay: &Path) -> Result<Self, CleanupError> {
        let directory = age_plugin_phone_platform_storage::macos::Directory::open(root)
            .map_err(|_| CleanupError::InvalidTarget)?;
        let lock_path = replay_lock_path(replay)?;
        let lock = platform::open_private_lock(&lock_path).map_err(|_| CleanupError::Busy)?;
        Ok(Self {
            directory,
            lock,
            lock_path,
            lock_removed: false,
        })
    }
    fn validate(&self) -> Result<(), CleanupError> {
        self.directory
            .validate()
            .map_err(|_| CleanupError::Storage)?;
        if !self.lock_removed {
            self.lock
                .validate(&self.directory)
                .map_err(|_| CleanupError::Busy)?;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl CleanupOperations for CheckedMacosCleanupOperations {
    fn remove_private(&mut self, path: &Path) -> Result<(), CleanupError> {
        self.validate()?;
        NativeCleanupOperations.remove_private(path)?;
        if path == self.lock_path {
            self.lock_removed = true;
        }
        Ok(())
    }
    fn remove_public(&mut self, path: &Path) -> Result<(), CleanupError> {
        self.validate()?;
        NativeCleanupOperations.remove_public(path)
    }
    fn remove_keys(&mut self, desktop_id: [u8; 16]) -> Result<(), CleanupError> {
        self.validate()?;
        NativeCleanupOperations.remove_keys(desktop_id)
    }
}

trait CleanupOperations {
    fn remove_private(&mut self, path: &Path) -> Result<(), CleanupError>;
    fn remove_public(&mut self, path: &Path) -> Result<(), CleanupError>;
    fn remove_keys(&mut self, desktop_id: [u8; 16]) -> Result<(), CleanupError>;
}

fn execute_cleanup(
    journal: &CleanupJournal,
    root: &Path,
    operations: &mut impl CleanupOperations,
) -> Result<(), CleanupError> {
    operations.remove_private(&journal.replay_state)?;
    #[cfg(target_os = "macos")]
    operations.remove_private(&replay_pending_path(&journal.replay_state)?)?;
    operations.remove_keys(journal.desktop_id())?;
    operations.remove_private(&journal.desktop_state)?;
    operations.remove_private(&journal.locator_path)?;
    operations.remove_private(&replay_lock_path(&journal.replay_state)?)?;
    if let Some((_, stub_path)) = journal.paired() {
        operations.remove_public(stub_path)?;
    }
    operations.remove_private(&crate::cleanup_journal::journal_path(root))
}

#[cfg(target_os = "macos")]
fn replay_pending_path(path: &Path) -> Result<PathBuf, CleanupError> {
    let mut name = path
        .file_name()
        .ok_or(CleanupError::InvalidTarget)?
        .to_os_string();
    name.push(".pending");
    Ok(path.parent().ok_or(CleanupError::InvalidTarget)?.join(name))
}

fn replay_lock_path(path: &Path) -> Result<PathBuf, CleanupError> {
    let mut name = path
        .file_name()
        .ok_or(CleanupError::InvalidTarget)?
        .to_os_string();
    name.push(".lock");
    Ok(path.parent().ok_or(CleanupError::InvalidTarget)?.join(name))
}

#[cfg(any(windows, target_os = "macos"))]
struct NativeCleanupOperations;

#[cfg(any(windows, target_os = "macos"))]
impl CleanupOperations for NativeCleanupOperations {
    fn remove_private(&mut self, path: &Path) -> Result<(), CleanupError> {
        #[cfg(target_os = "macos")]
        age_plugin_phone_platform_storage::macos::Directory::open(
            path.parent().ok_or(CleanupError::InvalidTarget)?,
        )
        .and_then(|directory| {
            directory.remove_replacement_temporaries(Path::new(
                path.file_name().ok_or(platform::Error::Invalid)?,
            ))
        })
        .map_err(|_| CleanupError::Storage)?;
        match platform::remove_private_file(path) {
            Ok(()) | Err(platform::Error::Missing) => Ok(()),
            Err(_) => Err(CleanupError::Storage),
        }
    }

    fn remove_public(&mut self, path: &Path) -> Result<(), CleanupError> {
        match platform::remove_regular_file(path) {
            Ok(()) | Err(platform::Error::Missing) => Ok(()),
            Err(_) => Err(CleanupError::Storage),
        }
    }

    fn remove_keys(&mut self, desktop_id: [u8; 16]) -> Result<(), CleanupError> {
        #[cfg(windows)]
        return age_plugin_phone_platform_keys::windows::remove_key_set(desktop_id)
            .map_err(|_| CleanupError::Storage);
        #[cfg(target_os = "macos")]
        {
            // CryptoKit references have no irreversible per-key destroy operation. The next
            // journaled step removes the exact metadata and its owned replacement temporaries.
            let _ = desktop_id;
            Ok(())
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut value, byte| {
            write!(value, "{byte:02x}").expect("writing to String cannot fail");
            value
        })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use age_plugin_phone_core::recipient::Recipient;
    use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint as _};
    use rand_core::OsRng;

    struct FakeOperations {
        remaining: HashSet<PathBuf>,
        keys: bool,
        unrelated: PathBuf,
        fail_at: Option<usize>,
        calls: usize,
    }

    impl CleanupOperations for FakeOperations {
        fn remove_private(&mut self, path: &Path) -> Result<(), CleanupError> {
            self.remove(path)
        }

        fn remove_public(&mut self, path: &Path) -> Result<(), CleanupError> {
            self.remove(path)
        }

        fn remove_keys(&mut self, _desktop_id: [u8; 16]) -> Result<(), CleanupError> {
            self.maybe_fail()?;
            self.keys = false;
            Ok(())
        }
    }

    impl FakeOperations {
        fn remove(&mut self, path: &Path) -> Result<(), CleanupError> {
            self.maybe_fail()?;
            self.remaining.remove(path);
            Ok(())
        }

        fn maybe_fail(&mut self) -> Result<(), CleanupError> {
            let call = self.calls;
            self.calls += 1;
            if self.fail_at == Some(call) {
                self.fail_at = None;
                return Err(CleanupError::Storage);
            }
            Ok(())
        }
    }

    fn journal(root: &Path) -> CleanupJournal {
        let identity = SecretKey::random(&mut OsRng);
        let signing = SigningKey::random(&mut OsRng);
        let selection = SigningKey::random(&mut OsRng);
        let phone = SigningKey::random(&mut OsRng);
        CleanupJournal {
            target: CleanupTarget::Paired {
                stub: crate::pairing::PublicIdentityStub {
                    desktop_id: [1; 16],
                    identity_id: [2; 16],
                    recipient: Recipient::from_public_key_bytes(
                        identity.public_key().to_encoded_point(true).as_bytes(),
                    )
                    .unwrap()
                    .to_string()
                    .unwrap(),
                    desktop_signing_public_key: signing
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                    desktop_selection_public_key: selection
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                    phone_signing_public_key: phone
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                    offer_digest: [3; 32],
                    transcript_fingerprint: [4; 32],
                },
                stub_path: root.join("identity.txt"),
            },
            locator_path: root.join("locator.cbor"),
            desktop_state: root.join("desktop.state"),
            replay_state: root.join("replay.state"),
        }
    }

    fn orphan_journal(root: &Path) -> CleanupJournal {
        let paired = journal(root);
        CleanupJournal {
            target: CleanupTarget::Orphan {
                desktop_id: paired.desktop_id(),
                identity_id: paired.identity_id(),
                transcript_fingerprint: paired.transcript_fingerprint(),
            },
            locator_path: paired.locator_path,
            desktop_state: paired.desktop_state,
            replay_state: paired.replay_state,
        }
    }

    fn operations(root: &Path, journal: &CleanupJournal, fail_at: usize) -> FakeOperations {
        let unrelated = root.join("unrelated.state");
        let mut remaining = HashSet::from([
            journal.locator_path.clone(),
            journal.desktop_state.clone(),
            journal.replay_state.clone(),
            replay_lock_path(&journal.replay_state).unwrap(),
            crate::cleanup_journal::journal_path(root),
            unrelated.clone(),
        ]);
        #[cfg(target_os = "macos")]
        remaining.insert(replay_pending_path(&journal.replay_state).unwrap());
        if let Some((_, stub_path)) = journal.paired() {
            remaining.insert(stub_path.to_path_buf());
        }
        FakeOperations {
            remaining,
            keys: true,
            unrelated,
            fail_at: Some(fail_at),
            calls: 0,
        }
    }

    #[cfg(windows)]
    fn windows_unstarted_fixture() -> (
        PathBuf,
        crate::pairing::PublicIdentityStub,
        PathBuf,
        age_plugin_phone_core::protocol::FileReplayGuard,
    ) {
        use age_plugin_phone_core::protocol::{
            DEFAULT_REPLAY_CAPACITY, FileReplayGuard, PairingRecord, ReplayRole, ReplayScope,
        };

        let root = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap()).join(format!(
            "age-phone-desktop-cleanup-test-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut OsRng),
        ));
        age_plugin_phone_platform_storage::windows::ensure_private_directory(&root).unwrap();
        let desktop_path = root.join("desktop.state");
        let desktop =
            crate::pairing::DesktopKeyState::open_or_create(&desktop_path, &mut OsRng).unwrap();
        let identity = SecretKey::random(&mut OsRng);
        let phone = SigningKey::random(&mut OsRng);
        let stub = crate::pairing::PublicIdentityStub {
            desktop_id: desktop.desktop_id,
            identity_id: [0x42; 16],
            recipient: Recipient::from_public_key_bytes(
                identity.public_key().to_encoded_point(true).as_bytes(),
            )
            .unwrap()
            .to_string()
            .unwrap(),
            desktop_signing_public_key: desktop.signing_public_key().unwrap(),
            desktop_selection_public_key: desktop.selection_public_key().unwrap(),
            phone_signing_public_key: phone
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            offer_digest: [3; 32],
            transcript_fingerprint: [4; 32],
        };
        let pairing = PairingRecord {
            desktop_id: stub.desktop_id,
            identity_id: stub.identity_id,
            desktop_signing_public_key: stub.desktop_signing_public_key,
            desktop_selection_public_key: stub.desktop_selection_public_key,
            phone_signing_public_key: stub.phone_signing_public_key,
        };
        let replay_path = root.join("replay.state");
        let replay = FileReplayGuard::create(
            &replay_path,
            ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing),
            DEFAULT_REPLAY_CAPACITY,
            10,
        )
        .unwrap();
        let stub_path = root.join("identity.txt");
        crate::pairing::create_identity_stub_file(&stub_path, &stub).unwrap();
        crate::locator::create_pairing_locator(&root, &stub, &desktop_path, &replay_path).unwrap();
        drop(desktop);
        (root, stub, stub_path, replay)
    }

    #[cfg(windows)]
    fn windows_fixture() -> (PathBuf, CleanupJournal) {
        let (root, stub, stub_path, replay) = windows_unstarted_fixture();
        drop(replay);
        let journal = start_cleanup(&root, &stub_path, &hex(&stub.transcript_fingerprint)).unwrap();
        (root, journal)
    }

    #[cfg(windows)]
    fn windows_orphan_unstarted_fixture() -> (
        PathBuf,
        crate::pairing::PublicIdentityStub,
        PathBuf,
        age_plugin_phone_core::protocol::FileReplayGuard,
    ) {
        let (root, stub, stub_path, replay) = windows_unstarted_fixture();
        let locator_path = crate::locator::existing_pairing_locator_path(&root, &stub).unwrap();
        age_plugin_phone_platform_storage::windows::remove_regular_file(&stub_path).unwrap();
        (root, stub, locator_path, replay)
    }

    #[cfg(windows)]
    fn remove_cleanup_lock(root: &Path) {
        age_plugin_phone_platform_storage::windows::remove_private_file(
            &crate::cleanup_journal::journal_lock_path(root),
        )
        .unwrap();
    }

    #[test]
    fn confirmation_is_exact_and_non_windows_is_unsupported() {
        assert_eq!(verify_confirmation("abcd", "abcd"), Ok(()));
        assert_eq!(
            verify_confirmation("abcd", "ABCD"),
            Err(CleanupError::ConfirmationMismatch)
        );
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            assert_eq!(
                confirmation_fingerprint(Path::new("identity.txt")),
                Err(CleanupError::Unsupported)
            );
            assert_eq!(
                orphan_confirmation_fingerprint(Path::new("locator.cbor")),
                Err(CleanupError::Unsupported)
            );
            assert_eq!(
                remove_orphaned_desktop_state(Path::new("locator.cbor"), "abcd"),
                Err(CleanupError::Unsupported)
            );
        }
    }

    #[test]
    fn every_interrupted_phase_resumes_without_touching_unrelated_state() {
        let root = PathBuf::from("/private/config");
        for (journal, phases) in [(journal(&root), 7), (orphan_journal(&root), 6)] {
            let phases = phases + usize::from(cfg!(target_os = "macos"));
            for fail_at in 0..phases {
                let mut operations = operations(&root, &journal, fail_at);
                assert_eq!(
                    execute_cleanup(&journal, &root, &mut operations),
                    Err(CleanupError::Storage)
                );
                operations.calls = 0;
                assert_eq!(execute_cleanup(&journal, &root, &mut operations), Ok(()));
                assert!(!operations.keys);
                assert_eq!(operations.remaining, HashSet::from([operations.unrelated]));
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn macos_fixture() -> (
        PathBuf,
        crate::pairing::PublicIdentityStub,
        PathBuf,
        age_plugin_phone_core::protocol::FileReplayGuard,
    ) {
        use age_plugin_phone_core::protocol::{
            DEFAULT_REPLAY_CAPACITY, FileReplayGuard, ReplayRole, ReplayScope,
        };
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "phone-cleanup-test-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut OsRng)
        ));
        age_plugin_phone_platform_storage::macos::Directory::prepare(&root).unwrap();
        let mut value = journal(&root);
        let source = root.join("fixture-key");
        let keys = crate::pairing::DesktopKeyState::open_or_create(&source, &mut OsRng).unwrap();
        let CleanupTarget::Paired { stub, stub_path } = &mut value.target else {
            unreachable!()
        };
        stub.desktop_id = keys.desktop_id;
        stub.desktop_signing_public_key = keys.signing_public_key().unwrap();
        stub.desktop_selection_public_key = keys.selection_public_key().unwrap();
        value.desktop_state = root.join(format!("desktop-{}.state", hex(&keys.desktop_id)));
        value.replay_state = root.join(format!("replay-{}.state", hex(&keys.desktop_id)));
        std::fs::rename(source, &value.desktop_state).unwrap();
        let replay = FileReplayGuard::create(
            &value.replay_state,
            ReplayScope::new(
                ReplayRole::DesktopResponses,
                stub.desktop_id,
                stub.identity_id,
            ),
            DEFAULT_REPLAY_CAPACITY,
            100,
        )
        .unwrap();
        crate::pairing::create_identity_stub_file(stub_path, stub).unwrap();
        crate::locator::create_pairing_locator(
            &root,
            stub,
            &value.desktop_state,
            &value.replay_state,
        )
        .unwrap();
        (root, stub.clone(), stub_path.clone(), replay)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_cleanup_rejects_busy_and_shared_state_then_resumes_exact_teardown() {
        let (root, stub, stub_path, replay) = macos_fixture();
        let fingerprint = hex(&stub.transcript_fingerprint);
        assert_eq!(
            start_cleanup(&root, &stub_path, "wrong"),
            Err(CleanupError::InvalidTarget)
        );
        assert_eq!(
            start_cleanup(&root, &stub_path, &fingerprint),
            Err(CleanupError::Busy)
        );
        assert!(!crate::cleanup_journal::journal_path(&root).exists());
        drop(replay);
        let locator = crate::locator::open_pairing_locator(&root, &stub).unwrap();
        assert!(matches!(
            validate_macos_cleanup_state(
                &root,
                &locator.desktop_state,
                &locator.replay_state,
                [0; 16],
                stub.identity_id,
                None
            ),
            Err(CleanupError::InvalidTarget)
        ));
        assert!(matches!(
            validate_macos_cleanup_state(
                &root,
                &locator.desktop_state,
                &locator.replay_state,
                stub.desktop_id,
                stub.identity_id,
                Some((&[0; 33], &[0; 33]))
            ),
            Err(CleanupError::InvalidTarget)
        ));
        let mut other = stub.clone();
        other.identity_id = [91; 16];
        other.transcript_fingerprint = [92; 32];
        let shared_path = crate::locator::create_pairing_locator(
            &root,
            &other,
            &locator.desktop_state,
            &locator.replay_state,
        )
        .unwrap();
        assert_eq!(
            start_cleanup(&root, &stub_path, &fingerprint),
            Err(CleanupError::InvalidTarget)
        );
        assert!(!crate::cleanup_journal::journal_path(&root).exists());
        platform::remove_private_file(&shared_path).unwrap();
        let value = start_cleanup(&root, &stub_path, &fingerprint).unwrap();
        assert!(crate::locator::open_pairing_locator(&root, &stub).is_err());
        let unrelated = root.join("unrelated.state");
        age_plugin_phone_platform_storage::macos::atomic_create(&unrelated, b"keep").unwrap();
        // A late public-file failure must retain the journal after earlier private deletions.
        let alias = root.join("public-hardlink");
        std::fs::hard_link(&stub_path, &alias).unwrap();
        assert_eq!(
            execute_native_cleanup(&value, &root),
            Err(CleanupError::Storage)
        );
        assert!(crate::cleanup_journal::journal_path(&root).exists());
        assert!(!value.desktop_state.exists());
        std::fs::remove_file(alias).unwrap();
        execute_native_cleanup(&value, &root).unwrap();
        assert_eq!(std::fs::read(unrelated).unwrap(), b"keep");
        assert!(!stub_path.exists());
        assert!(!value.replay_state.exists());
        assert!(!value.locator_path.exists());
        assert!(!crate::cleanup_journal::journal_path(&root).exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_replaced_cleanup_lock_rejects_before_deleting_state() {
        let (root, stub, _, replay) = macos_fixture();
        drop(replay);
        let locator = crate::locator::open_pairing_locator(&root, &stub).unwrap();
        let mut operations =
            CheckedMacosCleanupOperations::new(&root, &locator.replay_state).unwrap();
        platform::remove_private_file(&operations.lock_path).unwrap();
        let replacement = platform::open_private_lock(&operations.lock_path).unwrap();
        assert_eq!(
            operations.remove_private(&locator.replay_state),
            Err(CleanupError::Busy)
        );
        assert!(locator.replay_state.exists());
        assert!(locator.desktop_state.exists());
        drop(replacement);
        drop(operations);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_journal_rejects_redirected_and_overlapping_cleanup_targets() {
        let (root, stub, stub_path, replay) = macos_fixture();
        drop(replay);
        let value = start_cleanup(&root, &stub_path, &hex(&stub.transcript_fingerprint)).unwrap();
        let journal_path = crate::cleanup_journal::journal_path(&root);
        platform::remove_private_file(&journal_path).unwrap();
        let mut variants = Vec::new();
        let mut changed = value.clone();
        changed.desktop_state = root.parent().unwrap().join("outside.state");
        variants.push(changed);
        let mut changed = value.clone();
        changed.replay_state.clone_from(&changed.desktop_state);
        variants.push(changed);
        let mut changed = value.clone();
        changed.desktop_state.clone_from(&journal_path);
        variants.push(changed);
        let mut changed = value.clone();
        changed.locator_path = root.join("wrong.cbor");
        variants.push(changed);
        let mut changed = value.clone();
        if let CleanupTarget::Paired { stub_path, .. } = &mut changed.target {
            stub_path.clone_from(&changed.replay_state);
        }
        variants.push(changed);
        for changed in variants {
            assert!(crate::cleanup_journal::create(&root, &changed).is_err());
            assert!(!journal_path.exists());
            age_plugin_phone_platform_storage::macos::atomic_create(
                &journal_path,
                &changed.encode().unwrap(),
            )
            .unwrap();
            assert!(crate::cleanup_journal::read(&root).is_err());
            assert!(execute_native_cleanup(&changed, &root).is_err());
            assert!(value.desktop_state.exists());
            assert!(value.replay_state.exists());
            platform::remove_private_file(&journal_path).unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_orphan_cleanup_handles_lost_keys_and_uncertain_replay_without_reset() {
        let (root, stub, stub_path, replay) = macos_fixture();
        drop(replay);
        let locator = crate::locator::open_pairing_locator(&root, &stub).unwrap();
        let locator_path = crate::locator::existing_pairing_locator_path(&root, &stub).unwrap();
        platform::remove_regular_file(&stub_path).unwrap();
        platform::remove_private_file(&locator.desktop_state).unwrap();
        age_plugin_phone_platform_storage::macos::atomic_replace(
            &locator.replay_state,
            b"uncertain",
        )
        .unwrap();
        let pending = replay_pending_path(&locator.replay_state).unwrap();
        age_plugin_phone_platform_storage::macos::atomic_create(&pending, b"uncertain").unwrap();
        let fingerprint = hex(&stub.transcript_fingerprint);
        assert_eq!(
            remove_orphaned_desktop_state_in(&root, &locator_path, "wrong"),
            Err(CleanupError::ConfirmationMismatch)
        );
        assert!(pending.exists());
        remove_orphaned_desktop_state_in(&root, &locator_path, &fingerprint).unwrap();
        assert!(!pending.exists());
        assert!(!locator.replay_state.exists());
        assert!(!locator.desktop_state.exists());
        assert!(!locator_path.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn native_cleanup_removes_exact_files_and_tpm_keys() {
        let (root, journal) = windows_fixture();
        let (stub, stub_path) = journal.paired().unwrap();
        let stub = stub.clone();
        let stub_path = stub_path.to_path_buf();
        assert_eq!(
            crate::cleanup_journal::ensure_pairing_available(&root, &stub),
            Err(crate::cleanup_journal::JournalError::Pending)
        );
        execute_cleanup(&journal, &root, &mut NativeCleanupOperations).unwrap();
        for path in [
            &stub_path,
            &journal.locator_path,
            &journal.desktop_state,
            &journal.replay_state,
            &replay_lock_path(&journal.replay_state).unwrap(),
            &crate::cleanup_journal::journal_path(&root),
        ] {
            assert!(!path.exists());
        }
        assert!(
            age_plugin_phone_platform_keys::windows::WindowsCngKeySet::open(journal.desktop_id())
                .is_err()
        );
        std::fs::remove_dir(&root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn concurrent_replay_owner_prevents_cleanup_journal_creation() {
        let (root, stub, stub_path, replay) = windows_unstarted_fixture();
        assert_eq!(
            start_cleanup(&root, &stub_path, &hex(&stub.transcript_fingerprint)),
            Err(CleanupError::Busy)
        );
        assert!(!crate::cleanup_journal::journal_path(&root).exists());
        drop(replay);
        let journal = start_cleanup(&root, &stub_path, &hex(&stub.transcript_fingerprint)).unwrap();
        execute_cleanup(&journal, &root, &mut NativeCleanupOperations).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn native_orphan_cleanup_requires_exact_confirmation_and_removes_private_state() {
        let (root, stub, locator_path, replay) = windows_orphan_unstarted_fixture();
        drop(replay);
        let expected = hex(&stub.transcript_fingerprint);
        assert_eq!(
            orphan_confirmation_fingerprint_in(&root, &locator_path).unwrap(),
            expected
        );
        assert_eq!(
            remove_orphaned_desktop_state_in(&root, &locator_path, &format!("{expected}0")),
            Err(CleanupError::ConfirmationMismatch)
        );
        assert!(locator_path.exists());

        remove_orphaned_desktop_state_in(&root, &locator_path, &expected).unwrap();
        for path in [
            locator_path,
            root.join("desktop.state"),
            root.join("replay.state"),
            root.join("replay.state.lock"),
            crate::cleanup_journal::journal_path(&root),
        ] {
            assert!(!path.exists());
        }
        assert!(
            age_plugin_phone_platform_keys::windows::WindowsCngKeySet::open(stub.desktop_id)
                .is_err()
        );
        remove_cleanup_lock(&root);
        std::fs::remove_dir(&root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn orphan_cleanup_rejects_concurrent_replay_owner_without_a_journal() {
        let (root, stub, locator_path, replay) = windows_orphan_unstarted_fixture();
        let expected = hex(&stub.transcript_fingerprint);
        assert_eq!(
            remove_orphaned_desktop_state_in(&root, &locator_path, &expected),
            Err(CleanupError::Busy)
        );
        assert!(!crate::cleanup_journal::journal_path(&root).exists());
        drop(replay);
        remove_orphaned_desktop_state_in(&root, &locator_path, &expected).unwrap();
        remove_cleanup_lock(&root);
        std::fs::remove_dir(&root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn orphan_cleanup_rejects_locator_bound_to_the_wrong_desktop_state() {
        let (root, stub, stub_path, replay) = windows_unstarted_fixture();
        drop(replay);
        let original_locator = crate::locator::existing_pairing_locator_path(&root, &stub).unwrap();
        age_plugin_phone_platform_storage::windows::remove_private_file(&original_locator).unwrap();
        let wrong_desktop_path = root.join("wrong-desktop.state");
        let wrong_desktop =
            crate::pairing::DesktopKeyState::open_or_create(&wrong_desktop_path, &mut OsRng)
                .unwrap();
        let locator_path = crate::locator::create_pairing_locator(
            &root,
            &stub,
            &wrong_desktop_path,
            &root.join("replay.state"),
        )
        .unwrap();
        age_plugin_phone_platform_storage::windows::remove_regular_file(&stub_path).unwrap();

        let expected = hex(&stub.transcript_fingerprint);
        assert_eq!(
            remove_orphaned_desktop_state_in(&root, &locator_path, &expected),
            Err(CleanupError::InvalidTarget)
        );
        assert!(!crate::cleanup_journal::journal_path(&root).exists());

        age_plugin_phone_platform_storage::windows::remove_private_file(&locator_path).unwrap();
        age_plugin_phone_platform_storage::windows::remove_private_file(
            &root.join("desktop.state"),
        )
        .unwrap();
        age_plugin_phone_platform_storage::windows::remove_private_file(&wrong_desktop_path)
            .unwrap();
        age_plugin_phone_platform_storage::windows::remove_private_file(&root.join("replay.state"))
            .unwrap();
        age_plugin_phone_platform_storage::windows::remove_private_file(
            &root.join("replay.state.lock"),
        )
        .unwrap();
        let wrong_desktop_id = wrong_desktop.desktop_id;
        drop(wrong_desktop);
        age_plugin_phone_platform_keys::windows::remove_key_set(stub.desktop_id).unwrap();
        age_plugin_phone_platform_keys::windows::remove_key_set(wrong_desktop_id).unwrap();
        remove_cleanup_lock(&root);
        std::fs::remove_dir(&root).unwrap();
    }
}
