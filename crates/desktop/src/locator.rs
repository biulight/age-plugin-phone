//! Private desktop locator records for public plugin identities.

#![allow(clippy::missing_errors_doc)]

#[cfg(not(windows))]
use std::fs::File;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{fs::OpenOptions, io::Write as _};

use minicbor::{Decoder, Encoder};
use thiserror::Error;

use crate::cleanup_journal::{self, JournalError};
use crate::pairing::PublicIdentityStub;

const LOCATOR_VERSION: u16 = 2;
const MAX_LOCATOR_BYTES: u64 = 4_096;
const CONFIG_OVERRIDE: &str = "AGE_PLUGIN_PHONE_CONFIG_DIR";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingLocator {
    pub desktop_state: PathBuf,
    pub replay_state: PathBuf,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocatorError {
    #[error("phone plugin configuration directory is unavailable or insecure")]
    Config,
    #[error("pairing locator already exists")]
    AlreadyExists,
    #[error("pairing locator is missing")]
    Missing,
    #[error("pairing locator is malformed, mismatched, or insecure")]
    Invalid,
    #[error("desktop cleanup is pending for this pairing")]
    CleanupPending,
    #[error("pairing locator could not be durably stored")]
    Storage,
}

pub fn default_config_root() -> Result<PathBuf, LocatorError> {
    if let Some(value) = std::env::var_os(CONFIG_OVERRIDE) {
        let path = PathBuf::from(value);
        return path
            .is_absolute()
            .then_some(path)
            .ok_or(LocatorError::Config);
    }
    #[cfg(windows)]
    return std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|path| path.join("age-plugin-phone"))
        .ok_or(LocatorError::Config);
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(LocatorError::Config)?;
    #[cfg(target_os = "macos")]
    return Ok(home
        .join("Library")
        .join("Application Support")
        .join("age-plugin-phone"));
    #[cfg(all(not(target_os = "macos"), not(windows)))]
    {
        Ok(std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| home.join(".config"))
            .join("age-plugin-phone"))
    }
}

/// Creates the platform-private configuration root or validates an existing one.
pub fn prepare_config_root(root: &Path) -> Result<PathBuf, LocatorError> {
    prepare_directory(root)
}

pub fn create_pairing_locator(
    root: &Path,
    stub: &PublicIdentityStub,
    desktop_state: &Path,
    replay_state: &Path,
) -> Result<PathBuf, LocatorError> {
    let directory = prepare_directory(root)?;
    ensure_not_pending(&directory, stub)?;
    let path = pairing_locator_path(&directory, stub);
    let locator = PairingLocator {
        desktop_state: absolute_existing(desktop_state)?,
        replay_state: absolute_existing(replay_state)?,
    };
    let encoded = encode(stub, &locator)?;
    create_private_file(&path, &encoded)?;
    #[cfg(not(windows))]
    sync_directory(&directory)?;
    Ok(path)
}

pub fn open_pairing_locator(
    root: &Path,
    stub: &PublicIdentityStub,
) -> Result<PairingLocator, LocatorError> {
    let directory = checked_directory(root)?;
    ensure_not_pending(&directory, stub)?;
    let path = pairing_locator_path(&directory, stub);
    let bytes = read_locator_file(&path)?;
    decode(stub, &bytes)
}

#[cfg(unix)]
fn read_locator_file(path: &Path) -> Result<Vec<u8>, LocatorError> {
    use std::io::Read as _;
    reject_symlink(path)?;
    let file = File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            LocatorError::Missing
        } else {
            LocatorError::Invalid
        }
    })?;
    validate_private_file(&file)?;
    if file.metadata().map_err(|_| LocatorError::Invalid)?.len() > MAX_LOCATOR_BYTES {
        return Err(LocatorError::Invalid);
    }
    let mut bytes = Vec::new();
    file.take(MAX_LOCATOR_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LocatorError::Invalid)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_LOCATOR_BYTES {
        return Err(LocatorError::Invalid);
    }
    Ok(bytes)
}

#[cfg(windows)]
fn read_locator_file(path: &Path) -> Result<Vec<u8>, LocatorError> {
    age_plugin_phone_windows_storage::read_private_file(path, MAX_LOCATOR_BYTES).map_err(|error| {
        match error {
            age_plugin_phone_windows_storage::Error::Missing => LocatorError::Missing,
            _ => LocatorError::Invalid,
        }
    })
}

#[cfg(not(any(unix, windows)))]
fn read_locator_file(_path: &Path) -> Result<Vec<u8>, LocatorError> {
    Err(LocatorError::Invalid)
}

fn encode(stub: &PublicIdentityStub, locator: &PairingLocator) -> Result<Vec<u8>, LocatorError> {
    let desktop = locator
        .desktop_state
        .to_str()
        .filter(|value| !value.contains('\n'))
        .ok_or(LocatorError::Invalid)?;
    let replay = locator
        .replay_state
        .to_str()
        .filter(|value| !value.contains('\n'))
        .ok_or(LocatorError::Invalid)?;
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(6)
        .map_err(|_| LocatorError::Invalid)?
        .u16(LOCATOR_VERSION)
        .map_err(|_| LocatorError::Invalid)?
        .bytes(&stub.desktop_id)
        .map_err(|_| LocatorError::Invalid)?
        .bytes(&stub.identity_id)
        .map_err(|_| LocatorError::Invalid)?
        .bytes(&stub.transcript_fingerprint)
        .map_err(|_| LocatorError::Invalid)?
        .str(desktop)
        .map_err(|_| LocatorError::Invalid)?
        .str(replay)
        .map_err(|_| LocatorError::Invalid)?;
    Ok(encoder.into_writer())
}

fn decode(stub: &PublicIdentityStub, bytes: &[u8]) -> Result<PairingLocator, LocatorError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.array().map_err(|_| LocatorError::Invalid)? != Some(6)
        || decoder.u16().map_err(|_| LocatorError::Invalid)? != LOCATOR_VERSION
        || decoder.bytes().map_err(|_| LocatorError::Invalid)? != stub.desktop_id
        || decoder.bytes().map_err(|_| LocatorError::Invalid)? != stub.identity_id
        || decoder.bytes().map_err(|_| LocatorError::Invalid)? != stub.transcript_fingerprint
    {
        return Err(LocatorError::Invalid);
    }
    let locator = PairingLocator {
        desktop_state: PathBuf::from(decoder.str().map_err(|_| LocatorError::Invalid)?),
        replay_state: PathBuf::from(decoder.str().map_err(|_| LocatorError::Invalid)?),
    };
    if decoder.position() != bytes.len()
        || encode(stub, &locator).map_err(|_| LocatorError::Invalid)? != bytes
        || !locator.desktop_state.is_absolute()
        || !locator.replay_state.is_absolute()
    {
        return Err(LocatorError::Invalid);
    }
    Ok(locator)
}

pub(crate) fn pairing_locator_path(root: &Path, stub: &PublicIdentityStub) -> PathBuf {
    root.join(locator_name(stub))
}

fn locator_name(stub: &PublicIdentityStub) -> String {
    format!("{}.cbor", hex(&stub.identity_id))
}

fn ensure_not_pending(root: &Path, stub: &PublicIdentityStub) -> Result<(), LocatorError> {
    cleanup_journal::ensure_pairing_available(root, stub).map_err(|error| match error {
        JournalError::Pending => LocatorError::CleanupPending,
        JournalError::Invalid | JournalError::Storage => LocatorError::Invalid,
    })
}

fn absolute_existing(path: &Path) -> Result<PathBuf, LocatorError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| LocatorError::Config)?
            .join(path)
    };
    absolute.canonicalize().map_err(|_| LocatorError::Invalid)
}

#[cfg(unix)]
fn prepare_directory(root: &Path) -> Result<PathBuf, LocatorError> {
    use std::os::unix::fs::PermissionsExt as _;
    if !root.is_absolute() {
        return Err(LocatorError::Config);
    }
    std::fs::create_dir_all(root).map_err(|_| LocatorError::Config)?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| LocatorError::Config)?;
    checked_directory(root)
}

#[cfg(not(unix))]
#[cfg(not(windows))]
fn prepare_directory(_root: &Path) -> Result<PathBuf, LocatorError> {
    Err(LocatorError::Config)
}

#[cfg(windows)]
fn prepare_directory(root: &Path) -> Result<PathBuf, LocatorError> {
    age_plugin_phone_windows_storage::ensure_private_directory(root)
        .map_err(|_| LocatorError::Config)?;
    checked_directory(root)
}

#[cfg(unix)]
fn checked_directory(root: &Path) -> Result<PathBuf, LocatorError> {
    use std::os::unix::fs::PermissionsExt as _;
    reject_symlink(root)?;
    let metadata = std::fs::metadata(root).map_err(|_| LocatorError::Config)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(LocatorError::Config);
    }
    Ok(root.to_path_buf())
}

#[cfg(not(unix))]
#[cfg(not(windows))]
fn checked_directory(_root: &Path) -> Result<PathBuf, LocatorError> {
    Err(LocatorError::Config)
}

#[cfg(windows)]
fn checked_directory(root: &Path) -> Result<PathBuf, LocatorError> {
    age_plugin_phone_windows_storage::validate_private_directory(root)
        .map_err(|_| LocatorError::Config)?;
    Ok(root.to_path_buf())
}

#[cfg(unix)]
fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), LocatorError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                LocatorError::AlreadyExists
            } else {
                LocatorError::Storage
            }
        })?;
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(LocatorError::Storage);
    }
    validate_private_file(&file)
}

#[cfg(not(unix))]
#[cfg(not(windows))]
fn create_private_file(_path: &Path, _bytes: &[u8]) -> Result<(), LocatorError> {
    Err(LocatorError::Storage)
}

#[cfg(windows)]
fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), LocatorError> {
    age_plugin_phone_windows_storage::atomic_create(path, bytes).map_err(|error| match error {
        age_plugin_phone_windows_storage::Error::AlreadyExists => LocatorError::AlreadyExists,
        _ => LocatorError::Storage,
    })
}

#[cfg(unix)]
fn validate_private_file(file: &File) -> Result<(), LocatorError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = file.metadata().map_err(|_| LocatorError::Invalid)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
        return Err(LocatorError::Invalid);
    }
    Ok(())
}

#[cfg(unix)]
fn reject_symlink(path: &Path) -> Result<(), LocatorError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(LocatorError::Invalid),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LocatorError::Invalid),
    }
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> Result<(), LocatorError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| LocatorError::Storage)
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::pairing::DesktopKeyState;
    use age_plugin_phone_protocol::{
        DEFAULT_REPLAY_CAPACITY, FileReplayGuard, PairingRecord, ReplayRole, ReplayScope,
    };
    use age_plugin_phone_recipient_p256::Recipient;
    use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint as _};
    use rand_core::OsRng;

    fn fixture(root: &Path) -> (PublicIdentityStub, PathBuf, PathBuf) {
        let desktop_path = root.join("desktop.key");
        let desktop = DesktopKeyState::open_or_create(&desktop_path, &mut OsRng).unwrap();
        let identity = SecretKey::random(&mut OsRng);
        let recipient = Recipient::from_public_key_bytes(
            identity.public_key().to_encoded_point(true).as_bytes(),
        )
        .unwrap();
        let phone = SigningKey::random(&mut OsRng);
        let stub = PublicIdentityStub {
            desktop_id: desktop.desktop_id,
            identity_id: [3; 16],
            recipient: recipient.to_string().unwrap(),
            desktop_signing_public_key: desktop
                .signing_key()
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            desktop_selection_public_key: desktop
                .selection_key()
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
            offer_digest: [4; 32],
            transcript_fingerprint: [5; 32],
        };
        let replay_path = root.join("replay.cbor");
        let pairing = PairingRecord {
            desktop_id: stub.desktop_id,
            identity_id: stub.identity_id,
            desktop_signing_public_key: stub.desktop_signing_public_key,
            desktop_selection_public_key: stub.desktop_selection_public_key,
            phone_signing_public_key: stub.phone_signing_public_key,
        };
        drop(
            FileReplayGuard::create(
                &replay_path,
                ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing),
                DEFAULT_REPLAY_CAPACITY,
                10,
            )
            .unwrap(),
        );
        (stub, desktop_path, replay_path)
    }

    #[test]
    fn locator_is_private_bound_and_never_overwritten() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!(
            "age-phone-locator-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&root).unwrap();
        let state = root.join("state");
        let (stub, desktop, replay) = fixture(&root);
        let locator_path = create_pairing_locator(&state, &stub, &desktop, &replay).unwrap();
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700,
        );
        assert_eq!(
            std::fs::metadata(&locator_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
        );
        assert_eq!(
            open_pairing_locator(&state, &stub).unwrap(),
            PairingLocator {
                desktop_state: desktop.canonicalize().unwrap(),
                replay_state: replay.canonicalize().unwrap(),
            },
        );
        assert_eq!(
            create_pairing_locator(&state, &stub, &desktop, &replay),
            Err(LocatorError::AlreadyExists),
        );
        let mut wrong = stub.clone();
        wrong.transcript_fingerprint[0] ^= 1;
        assert_eq!(
            open_pairing_locator(&state, &wrong),
            Err(LocatorError::Invalid),
        );
        let mut old_locator = std::fs::read(&locator_path).unwrap();
        old_locator[1] = 1;
        std::fs::write(&locator_path, old_locator).unwrap();
        assert_eq!(
            open_pairing_locator(&state, &stub),
            Err(LocatorError::Invalid),
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
