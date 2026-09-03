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
use crate::transport_policy::TransportChoice;
use age_plugin_phone_protocol::{Id, ProtocolDigest};

const LOCATOR_VERSION: u16 = 3;
const LEGACY_LOCATOR_VERSION: u16 = 2;
const MAX_LOCATOR_BYTES: u64 = 4_096;
const CONFIG_OVERRIDE: &str = "AGE_PLUGIN_PHONE_CONFIG_DIR";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingLocator {
    pub desktop_state: PathBuf,
    pub replay_state: PathBuf,
    pub transport: TransportChoice,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PairingLocatorRecord {
    pub desktop_id: Id,
    pub identity_id: Id,
    pub transcript_fingerprint: ProtocolDigest,
    pub locator: PairingLocator,
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
    #[error("desktop setup is pending for this pairing")]
    SetupPending,
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
    create_pairing_locator_with_transport(
        root,
        stub,
        desktop_state,
        replay_state,
        TransportChoice::Auto,
    )
}

pub fn create_pairing_locator_with_transport(
    root: &Path,
    stub: &PublicIdentityStub,
    desktop_state: &Path,
    replay_state: &Path,
    transport: TransportChoice,
) -> Result<PathBuf, LocatorError> {
    let directory = prepare_directory(root)?;
    ensure_not_pending(&directory, stub)?;
    let path = pairing_locator_path(&directory, stub);
    let locator = PairingLocator {
        desktop_state: absolute_existing(desktop_state)?,
        replay_state: absolute_existing(replay_state)?,
        transport,
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
    open_pairing_locator_record(root, stub).map(|(_, locator)| locator)
}

#[cfg(any(windows, test))]
pub(crate) fn existing_pairing_locator_path(
    root: &Path,
    stub: &PublicIdentityStub,
) -> Result<PathBuf, LocatorError> {
    open_pairing_locator_record(root, stub).map(|(path, _)| path)
}

#[cfg(any(windows, test))]
pub(crate) fn open_pairing_locator_for_cleanup(
    root: &Path,
    supplied_path: &Path,
) -> Result<(PathBuf, PairingLocatorRecord), LocatorError> {
    let directory =
        std::path::absolute(checked_directory(root)?).map_err(|_| LocatorError::Invalid)?;
    let path = std::path::absolute(supplied_path).map_err(|_| LocatorError::Invalid)?;
    if path.parent() != Some(directory.as_path()) {
        return Err(LocatorError::Invalid);
    }
    let record = decode_record(&read_locator_file(&path)?)?;
    if path != locator_path_for_record(&directory, &record)
        && path != legacy_locator_path_for_record(&directory, &record)
    {
        return Err(LocatorError::Invalid);
    }
    Ok((path, record))
}

fn open_pairing_locator_record(
    root: &Path,
    stub: &PublicIdentityStub,
) -> Result<(PathBuf, PairingLocator), LocatorError> {
    let directory = checked_directory(root)?;
    ensure_not_pending(&directory, stub)?;
    crate::setup::ensure_pairing_available(&directory, stub)
        .map_err(|_| LocatorError::SetupPending)?;
    for path in [
        pairing_locator_path(&directory, stub),
        legacy_pairing_locator_path(&directory, stub),
    ] {
        match read_locator_file(&path) {
            Ok(bytes) => return decode(stub, &bytes).map(|locator| (path, locator)),
            Err(LocatorError::Missing) => {}
            Err(error) => return Err(error),
        }
    }
    Err(LocatorError::Missing)
}

#[cfg(windows)]
pub(crate) fn open_pairing_locator_for_setup(
    root: &Path,
    stub: &PublicIdentityStub,
) -> Result<PairingLocator, LocatorError> {
    let directory = checked_directory(root)?;
    ensure_not_pending(&directory, stub)?;
    for path in [
        pairing_locator_path(&directory, stub),
        legacy_pairing_locator_path(&directory, stub),
    ] {
        match read_locator_file(&path) {
            Ok(bytes) => return decode(stub, &bytes),
            Err(LocatorError::Missing) => {}
            Err(error) => return Err(error),
        }
    }
    Err(LocatorError::Missing)
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
    encode_record(&PairingLocatorRecord {
        desktop_id: stub.desktop_id,
        identity_id: stub.identity_id,
        transcript_fingerprint: stub.transcript_fingerprint,
        locator: locator.clone(),
    })
}

fn encode_record(record: &PairingLocatorRecord) -> Result<Vec<u8>, LocatorError> {
    let desktop = record
        .locator
        .desktop_state
        .to_str()
        .filter(|value| !value.contains('\n'))
        .ok_or(LocatorError::Invalid)?;
    let replay = record
        .locator
        .replay_state
        .to_str()
        .filter(|value| !value.contains('\n'))
        .ok_or(LocatorError::Invalid)?;
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(7)
        .map_err(|_| LocatorError::Invalid)?
        .u16(LOCATOR_VERSION)
        .map_err(|_| LocatorError::Invalid)?
        .bytes(&record.desktop_id)
        .map_err(|_| LocatorError::Invalid)?
        .bytes(&record.identity_id)
        .map_err(|_| LocatorError::Invalid)?
        .bytes(&record.transcript_fingerprint)
        .map_err(|_| LocatorError::Invalid)?
        .str(desktop)
        .map_err(|_| LocatorError::Invalid)?
        .str(replay)
        .map_err(|_| LocatorError::Invalid)?
        .str(&record.locator.transport.to_string())
        .map_err(|_| LocatorError::Invalid)?;
    Ok(encoder.into_writer())
}

fn decode(stub: &PublicIdentityStub, bytes: &[u8]) -> Result<PairingLocator, LocatorError> {
    let record = decode_record(bytes)?;
    if record.desktop_id != stub.desktop_id
        || record.identity_id != stub.identity_id
        || record.transcript_fingerprint != stub.transcript_fingerprint
    {
        return Err(LocatorError::Invalid);
    }
    Ok(record.locator)
}

fn decode_record(bytes: &[u8]) -> Result<PairingLocatorRecord, LocatorError> {
    let mut decoder = Decoder::new(bytes);
    let fields = decoder.array().map_err(|_| LocatorError::Invalid)?;
    let version = decoder.u16().map_err(|_| LocatorError::Invalid)?;
    if !matches!(
        (fields, version),
        (Some(7), LOCATOR_VERSION) | (Some(6), LEGACY_LOCATOR_VERSION)
    ) {
        return Err(LocatorError::Invalid);
    }
    let record = PairingLocatorRecord {
        desktop_id: fixed(decoder.bytes().map_err(|_| LocatorError::Invalid)?)?,
        identity_id: fixed(decoder.bytes().map_err(|_| LocatorError::Invalid)?)?,
        transcript_fingerprint: fixed(decoder.bytes().map_err(|_| LocatorError::Invalid)?)?,
        locator: PairingLocator {
            desktop_state: PathBuf::from(decoder.str().map_err(|_| LocatorError::Invalid)?),
            replay_state: PathBuf::from(decoder.str().map_err(|_| LocatorError::Invalid)?),
            transport: if version == LOCATOR_VERSION {
                decoder
                    .str()
                    .map_err(|_| LocatorError::Invalid)?
                    .parse()
                    .map_err(|_| LocatorError::Invalid)?
            } else {
                TransportChoice::Auto
            },
        },
    };
    if decoder.position() != bytes.len()
        || if version == LOCATOR_VERSION {
            encode_record(&record).map_err(|_| LocatorError::Invalid)? != bytes
        } else {
            encode_legacy_record(&record).map_err(|_| LocatorError::Invalid)? != bytes
        }
        || !record.locator.desktop_state.is_absolute()
        || !record.locator.replay_state.is_absolute()
    {
        return Err(LocatorError::Invalid);
    }
    Ok(record)
}

fn encode_legacy_record(record: &PairingLocatorRecord) -> Result<Vec<u8>, LocatorError> {
    let desktop = encoded_locator_path(&record.locator.desktop_state)?;
    let replay = encoded_locator_path(&record.locator.replay_state)?;
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(6)
        .map_err(|_| LocatorError::Invalid)?
        .u16(LEGACY_LOCATOR_VERSION)
        .map_err(|_| LocatorError::Invalid)?
        .bytes(&record.desktop_id)
        .map_err(|_| LocatorError::Invalid)?
        .bytes(&record.identity_id)
        .map_err(|_| LocatorError::Invalid)?
        .bytes(&record.transcript_fingerprint)
        .map_err(|_| LocatorError::Invalid)?
        .str(desktop)
        .map_err(|_| LocatorError::Invalid)?
        .str(replay)
        .map_err(|_| LocatorError::Invalid)?;
    Ok(encoder.into_writer())
}

fn encoded_locator_path(path: &Path) -> Result<&str, LocatorError> {
    path.to_str()
        .filter(|value| !value.contains('\n'))
        .ok_or(LocatorError::Invalid)
}

pub(crate) fn pairing_locator_path(root: &Path, stub: &PublicIdentityStub) -> PathBuf {
    root.join(locator_name(stub))
}

fn locator_name(stub: &PublicIdentityStub) -> String {
    format!("{}-{}.cbor", hex(&stub.identity_id), hex(&stub.desktop_id))
}

fn legacy_pairing_locator_path(root: &Path, stub: &PublicIdentityStub) -> PathBuf {
    root.join(format!("{}.cbor", hex(&stub.identity_id)))
}

#[cfg(any(windows, test))]
fn locator_path_for_record(root: &Path, record: &PairingLocatorRecord) -> PathBuf {
    root.join(format!(
        "{}-{}.cbor",
        hex(&record.identity_id),
        hex(&record.desktop_id)
    ))
}

#[cfg(any(windows, test))]
fn legacy_locator_path_for_record(root: &Path, record: &PairingLocatorRecord) -> PathBuf {
    root.join(format!("{}.cbor", hex(&record.identity_id)))
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], LocatorError> {
    bytes.try_into().map_err(|_| LocatorError::Invalid)
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
        let locator_path = create_pairing_locator_with_transport(
            &state,
            &stub,
            &desktop,
            &replay,
            TransportChoice::Wifi,
        )
        .unwrap();
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
                transport: TransportChoice::Wifi,
            },
        );
        assert_eq!(
            create_pairing_locator(&state, &stub, &desktop, &replay),
            Err(LocatorError::AlreadyExists),
        );

        let mut other = stub.clone();
        other.desktop_id[0] ^= 1;
        other.transcript_fingerprint[0] ^= 1;
        let other_desktop = root.join("other-desktop.key");
        let other_replay = root.join("other-replay.cbor");
        std::fs::write(&other_desktop, b"other desktop").unwrap();
        std::fs::write(&other_replay, b"other replay").unwrap();
        let other_locator =
            create_pairing_locator(&state, &other, &other_desktop, &other_replay).unwrap();
        assert_ne!(locator_path, other_locator);
        assert_eq!(
            open_pairing_locator(&state, &other).unwrap(),
            PairingLocator {
                desktop_state: other_desktop.canonicalize().unwrap(),
                replay_state: other_replay.canonicalize().unwrap(),
                transport: TransportChoice::Auto,
            },
        );
        std::fs::remove_file(other_locator).unwrap();

        let legacy_path = legacy_pairing_locator_path(&state, &stub);
        std::fs::rename(&locator_path, &legacy_path).unwrap();
        assert_eq!(
            existing_pairing_locator_path(&state, &stub).unwrap(),
            legacy_path,
        );
        assert!(open_pairing_locator(&state, &stub).is_ok());
        let mut wrong = stub.clone();
        wrong.transcript_fingerprint[0] ^= 1;
        assert_eq!(
            open_pairing_locator(&state, &wrong),
            Err(LocatorError::Invalid),
        );
        let mut old_locator = std::fs::read(&legacy_path).unwrap();
        old_locator[1] = 1;
        std::fs::write(&legacy_path, old_locator).unwrap();
        assert_eq!(
            open_pairing_locator(&state, &stub),
            Err(LocatorError::Invalid),
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_locator_requires_an_exact_private_canonical_path() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!(
            "age-phone-cleanup-locator-{}-{}",
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

        let (cleanup_path, cleanup_record) =
            open_pairing_locator_for_cleanup(&state, &locator_path).unwrap();
        assert_eq!(cleanup_path, locator_path);
        assert_eq!(cleanup_record.desktop_id, stub.desktop_id);
        assert_eq!(cleanup_record.identity_id, stub.identity_id);
        assert_eq!(
            cleanup_record.transcript_fingerprint,
            stub.transcript_fingerprint
        );

        let wrong_name = state.join("wrong-name.cbor");
        std::fs::copy(&locator_path, &wrong_name).unwrap();
        std::fs::set_permissions(&wrong_name, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            open_pairing_locator_for_cleanup(&state, &wrong_name),
            Err(LocatorError::Invalid)
        );
        std::fs::remove_file(wrong_name).unwrap();
        assert_eq!(
            open_pairing_locator_for_cleanup(&state, &desktop),
            Err(LocatorError::Invalid)
        );

        let legacy_path = legacy_pairing_locator_path(&state, &stub);
        std::fs::rename(&locator_path, &legacy_path).unwrap();
        assert_eq!(
            open_pairing_locator_for_cleanup(&state, &legacy_path)
                .unwrap()
                .1
                .identity_id,
            stub.identity_id
        );

        let modern_hardlink = pairing_locator_path(&state, &stub);
        std::fs::hard_link(&legacy_path, &modern_hardlink).unwrap();
        assert_eq!(
            open_pairing_locator_for_cleanup(&state, &legacy_path),
            Err(LocatorError::Invalid)
        );
        std::fs::remove_file(modern_hardlink).unwrap();
        assert!(open_pairing_locator_for_cleanup(&state, &legacy_path).is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
}
