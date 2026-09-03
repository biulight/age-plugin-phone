//! Crash-safe ownership record for simplified Windows desktop setup.

#![cfg_attr(not(windows), allow(dead_code))]
#![allow(clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};

use age_plugin_phone_protocol::Id;
use minicbor::{Decoder, Encoder, data::Type};
use thiserror::Error;

use crate::pairing::PublicIdentityStub;
use crate::transport_policy::TransportChoice;

const SETUP_VERSION: u16 = 2;
const LEGACY_SETUP_VERSION: u16 = 1;
const JOURNAL_NAME: &str = "desktop-setup.cbor";
#[cfg(windows)]
const MAX_JOURNAL_BYTES: u64 = 32_768;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum SetupStage {
    Provisioning = 1,
    Pairing = 2,
    ResponseVerified = 3,
    Confirmed = 4,
}

impl SetupStage {
    fn decode(value: u16) -> Result<Self, SetupError> {
        match value {
            1 => Ok(Self::Provisioning),
            2 => Ok(Self::Pairing),
            3 => Ok(Self::ResponseVerified),
            4 => Ok(Self::Confirmed),
            _ => Err(SetupError::Invalid),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupJournal {
    pub stage: SetupStage,
    pub setup_code: Id,
    pub desktop_id: Id,
    pub desktop_state: PathBuf,
    pub replay_state: PathBuf,
    pub identity_stub: PathBuf,
    pub transport: TransportChoice,
    pub candidate: Option<PublicIdentityStub>,
}

impl SetupJournal {
    #[must_use]
    pub fn new(root: &Path, setup_code: Id, desktop_id: Id) -> Self {
        let suffix = hex(&desktop_id);
        Self {
            stage: SetupStage::Provisioning,
            setup_code,
            desktop_id,
            desktop_state: root.join(format!("desktop-{suffix}.state")),
            replay_state: root.join(format!("replay-{suffix}.state")),
            identity_stub: root.join(format!("identity-{suffix}.txt")),
            transport: TransportChoice::Auto,
            candidate: None,
        }
    }

    #[must_use]
    pub fn new_with_transport(
        root: &Path,
        setup_code: Id,
        desktop_id: Id,
        transport: TransportChoice,
    ) -> Self {
        Self {
            transport,
            ..Self::new(root, setup_code, desktop_id)
        }
    }

    pub fn set_pairing(&mut self) {
        self.stage = SetupStage::Pairing;
    }

    pub fn set_candidate(&mut self, candidate: PublicIdentityStub) -> Result<(), SetupError> {
        if candidate.desktop_id != self.desktop_id {
            return Err(SetupError::Invalid);
        }
        self.stage = SetupStage::ResponseVerified;
        self.candidate = Some(candidate);
        Ok(())
    }

    pub fn set_confirmed(&mut self, candidate: &PublicIdentityStub) -> Result<(), SetupError> {
        if self.candidate.as_ref() != Some(candidate) || candidate.desktop_id != self.desktop_id {
            return Err(SetupError::Invalid);
        }
        self.stage = SetupStage::Confirmed;
        Ok(())
    }

    #[must_use]
    pub fn confirmation_text(&self) -> String {
        self.candidate.as_ref().map_or_else(
            || hex(&self.setup_code),
            |stub| hex(&stub.transcript_fingerprint),
        )
    }

    #[must_use]
    pub fn targets(&self, stub: &PublicIdentityStub) -> bool {
        self.candidate.as_ref().is_some_and(|candidate| {
            candidate.desktop_id == stub.desktop_id
                && candidate.identity_id == stub.identity_id
                && candidate.transcript_fingerprint == stub.transcript_fingerprint
        })
    }

    fn encode(&self) -> Result<Vec<u8>, SetupError> {
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(9)
            .map_err(|_| SetupError::Invalid)?
            .u16(SETUP_VERSION)
            .map_err(|_| SetupError::Invalid)?
            .u16(self.stage as u16)
            .map_err(|_| SetupError::Invalid)?
            .bytes(&self.setup_code)
            .map_err(|_| SetupError::Invalid)?
            .bytes(&self.desktop_id)
            .map_err(|_| SetupError::Invalid)?
            .str(encoded_path(&self.desktop_state)?)
            .map_err(|_| SetupError::Invalid)?
            .str(encoded_path(&self.replay_state)?)
            .map_err(|_| SetupError::Invalid)?
            .str(encoded_path(&self.identity_stub)?)
            .map_err(|_| SetupError::Invalid)?
            .str(&self.transport.to_string())
            .map_err(|_| SetupError::Invalid)?;
        if let Some(candidate) = &self.candidate {
            encoder
                .bytes(&candidate.encode())
                .map_err(|_| SetupError::Invalid)?;
        } else {
            encoder.null().map_err(|_| SetupError::Invalid)?;
        }
        Ok(encoder.into_writer())
    }

    fn decode(bytes: &[u8]) -> Result<Self, SetupError> {
        let mut decoder = Decoder::new(bytes);
        let fields = decoder.array().map_err(|_| SetupError::Invalid)?;
        let version = decoder.u16().map_err(|_| SetupError::Invalid)?;
        if !matches!(
            (fields, version),
            (Some(9), SETUP_VERSION) | (Some(8), LEGACY_SETUP_VERSION)
        ) {
            return Err(SetupError::Invalid);
        }
        let stage = SetupStage::decode(decoder.u16().map_err(|_| SetupError::Invalid)?)?;
        let setup_code = fixed(decoder.bytes().map_err(|_| SetupError::Invalid)?)?;
        let desktop_id = fixed(decoder.bytes().map_err(|_| SetupError::Invalid)?)?;
        let desktop_state = PathBuf::from(decoder.str().map_err(|_| SetupError::Invalid)?);
        let replay_state = PathBuf::from(decoder.str().map_err(|_| SetupError::Invalid)?);
        let identity_stub = PathBuf::from(decoder.str().map_err(|_| SetupError::Invalid)?);
        let transport = if version == SETUP_VERSION {
            decoder
                .str()
                .map_err(|_| SetupError::Invalid)?
                .parse()
                .map_err(|_| SetupError::Invalid)?
        } else {
            TransportChoice::Auto
        };
        let candidate = match decoder.datatype().map_err(|_| SetupError::Invalid)? {
            Type::Null => {
                decoder.null().map_err(|_| SetupError::Invalid)?;
                None
            }
            Type::Bytes => Some(
                PublicIdentityStub::decode(decoder.bytes().map_err(|_| SetupError::Invalid)?)
                    .map_err(|_| SetupError::Invalid)?,
            ),
            _ => return Err(SetupError::Invalid),
        };
        let value = Self {
            stage,
            setup_code,
            desktop_id,
            desktop_state,
            replay_state,
            identity_stub,
            transport,
            candidate,
        };
        if decoder.position() != bytes.len()
            || if version == SETUP_VERSION {
                value.encode()? != bytes
            } else {
                value.encode_legacy()? != bytes
            }
            || value.candidate.is_some()
                != matches!(stage, SetupStage::ResponseVerified | SetupStage::Confirmed)
            || value
                .candidate
                .as_ref()
                .is_some_and(|candidate| candidate.desktop_id != desktop_id)
        {
            return Err(SetupError::Invalid);
        }
        Ok(value)
    }

    fn encode_legacy(&self) -> Result<Vec<u8>, SetupError> {
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(8)
            .map_err(|_| SetupError::Invalid)?
            .u16(LEGACY_SETUP_VERSION)
            .map_err(|_| SetupError::Invalid)?
            .u16(self.stage as u16)
            .map_err(|_| SetupError::Invalid)?
            .bytes(&self.setup_code)
            .map_err(|_| SetupError::Invalid)?
            .bytes(&self.desktop_id)
            .map_err(|_| SetupError::Invalid)?
            .str(encoded_path(&self.desktop_state)?)
            .map_err(|_| SetupError::Invalid)?
            .str(encoded_path(&self.replay_state)?)
            .map_err(|_| SetupError::Invalid)?
            .str(encoded_path(&self.identity_stub)?)
            .map_err(|_| SetupError::Invalid)?;
        if let Some(candidate) = &self.candidate {
            encoder
                .bytes(&candidate.encode())
                .map_err(|_| SetupError::Invalid)?;
        } else {
            encoder.null().map_err(|_| SetupError::Invalid)?;
        }
        Ok(encoder.into_writer())
    }

    fn validate_root(&self, root: &Path) -> Result<(), SetupError> {
        if !root.is_absolute() {
            return Err(SetupError::Invalid);
        }
        let expected = Self::new(root, self.setup_code, self.desktop_id);
        if self.desktop_state != expected.desktop_state
            || self.replay_state != expected.replay_state
            || self.identity_stub != expected.identity_stub
        {
            return Err(SetupError::Invalid);
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SetupError {
    #[error("simplified setup is supported only on the Windows Alpha platform")]
    Unsupported,
    #[error("a desktop setup attempt is already pending")]
    Pending,
    #[error("the desktop setup journal is missing")]
    Missing,
    #[error("the desktop setup journal is malformed, mismatched, or insecure")]
    Invalid,
    #[error("the desktop setup journal could not be durably stored")]
    Storage,
    #[error("another desktop lifecycle operation is active")]
    Busy,
}

#[must_use]
pub fn journal_path(root: &Path) -> PathBuf {
    root.join(JOURNAL_NAME)
}

#[cfg(windows)]
pub fn ensure_no_cleanup_pending(root: &Path) -> Result<(), SetupError> {
    if crate::cleanup_journal::read(root)
        .map_err(|_| SetupError::Invalid)?
        .is_some()
    {
        return Err(SetupError::Busy);
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn ensure_no_cleanup_pending(_root: &Path) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(windows)]
pub fn acquire_lifecycle_lock(
    root: &Path,
) -> Result<age_plugin_phone_windows_storage::PrivateLock, SetupError> {
    age_plugin_phone_windows_storage::open_private_lock(&crate::cleanup_journal::journal_lock_path(
        root,
    ))
    .map_err(|_| SetupError::Busy)
}

#[cfg(not(windows))]
pub fn acquire_lifecycle_lock(_root: &Path) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(windows)]
pub fn read(root: &Path) -> Result<SetupJournal, SetupError> {
    let bytes =
        age_plugin_phone_windows_storage::read_private_file(&journal_path(root), MAX_JOURNAL_BYTES)
            .map_err(|error| match error {
                age_plugin_phone_windows_storage::Error::Missing => SetupError::Missing,
                _ => SetupError::Invalid,
            })?;
    let value = SetupJournal::decode(&bytes)?;
    value.validate_root(root)?;
    Ok(value)
}

#[cfg(not(windows))]
pub fn read(_root: &Path) -> Result<SetupJournal, SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(windows)]
pub fn read_optional(root: &Path) -> Result<Option<SetupJournal>, SetupError> {
    match read(root) {
        Ok(value) => Ok(Some(value)),
        Err(SetupError::Missing) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(not(windows))]
pub fn read_optional(_root: &Path) -> Result<Option<SetupJournal>, SetupError> {
    Ok(None)
}

#[cfg(windows)]
pub fn create(root: &Path, value: &SetupJournal) -> Result<(), SetupError> {
    value.validate_root(root)?;
    age_plugin_phone_windows_storage::atomic_create(&journal_path(root), &value.encode()?).map_err(
        |error| match error {
            age_plugin_phone_windows_storage::Error::AlreadyExists => SetupError::Pending,
            _ => SetupError::Storage,
        },
    )
}

#[cfg(not(windows))]
pub fn create(_root: &Path, _value: &SetupJournal) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(windows)]
pub fn replace(root: &Path, value: &SetupJournal) -> Result<(), SetupError> {
    value.validate_root(root)?;
    age_plugin_phone_windows_storage::atomic_replace(&journal_path(root), &value.encode()?)
        .map_err(|_| SetupError::Storage)
}

#[cfg(not(windows))]
pub fn replace(_root: &Path, _value: &SetupJournal) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(windows)]
pub fn remove(root: &Path) -> Result<(), SetupError> {
    match age_plugin_phone_windows_storage::remove_private_file(&journal_path(root)) {
        Ok(()) | Err(age_plugin_phone_windows_storage::Error::Missing) => Ok(()),
        Err(_) => Err(SetupError::Storage),
    }
}

#[cfg(not(windows))]
pub fn remove(_root: &Path) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(windows)]
pub fn commit_confirmed(
    root: &Path,
    value: &SetupJournal,
    now_unix: u64,
) -> Result<(), SetupError> {
    use age_plugin_phone_protocol::{
        DEFAULT_REPLAY_CAPACITY, FileReplayGuard, PairingRecord, ReplayRole, ReplayScope,
    };

    value.validate_root(root)?;
    if value.stage != SetupStage::Confirmed {
        return Err(SetupError::Invalid);
    }
    let stub = value.candidate.as_ref().ok_or(SetupError::Invalid)?;
    let desktop = crate::pairing::DesktopKeyState::open(&value.desktop_state)
        .map_err(|_| SetupError::Invalid)?;
    if desktop.desktop_id != stub.desktop_id
        || desktop
            .signing_public_key()
            .map_err(|_| SetupError::Invalid)?
            != stub.desktop_signing_public_key
        || desktop
            .selection_public_key()
            .map_err(|_| SetupError::Invalid)?
            != stub.desktop_selection_public_key
    {
        return Err(SetupError::Invalid);
    }
    let pairing = PairingRecord {
        desktop_id: stub.desktop_id,
        identity_id: stub.identity_id,
        desktop_signing_public_key: stub.desktop_signing_public_key,
        desktop_selection_public_key: stub.desktop_selection_public_key,
        phone_signing_public_key: stub.phone_signing_public_key,
    };
    let scope = ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing);
    match FileReplayGuard::create(
        &value.replay_state,
        scope,
        DEFAULT_REPLAY_CAPACITY,
        now_unix,
    ) {
        Ok(replay) => drop(replay),
        Err(_) => drop(
            FileReplayGuard::open(&value.replay_state, scope, DEFAULT_REPLAY_CAPACITY)
                .map_err(|_| SetupError::Invalid)?,
        ),
    }

    match crate::locator::create_pairing_locator_with_transport(
        root,
        stub,
        &value.desktop_state,
        &value.replay_state,
        value.transport,
    ) {
        Ok(_) => {}
        Err(crate::locator::LocatorError::AlreadyExists) => {
            let locator = crate::locator::open_pairing_locator_for_setup(root, stub)
                .map_err(|_| SetupError::Invalid)?;
            if locator.desktop_state != value.desktop_state
                || locator.replay_state != value.replay_state
                || locator.transport != value.transport
            {
                return Err(SetupError::Invalid);
            }
        }
        Err(_) => return Err(SetupError::Storage),
    }

    if crate::pairing::create_identity_stub_file(&value.identity_stub, stub).is_err() {
        let existing = crate::pairing::read_identity_stub_file(&value.identity_stub)
            .map_err(|_| SetupError::Invalid)?;
        if existing != *stub {
            return Err(SetupError::Invalid);
        }
    }
    remove(root)
}

#[cfg(not(windows))]
pub fn commit_confirmed(
    _root: &Path,
    _value: &SetupJournal,
    _now_unix: u64,
) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(windows)]
pub fn cleanup_owned(root: &Path, value: &SetupJournal) -> Result<(), SetupError> {
    fn remove_private(path: &Path) -> Result<(), SetupError> {
        match age_plugin_phone_windows_storage::remove_private_file(path) {
            Ok(()) | Err(age_plugin_phone_windows_storage::Error::Missing) => Ok(()),
            Err(_) => Err(SetupError::Storage),
        }
    }
    fn remove_public(path: &Path) -> Result<(), SetupError> {
        match age_plugin_phone_windows_storage::remove_regular_file(path) {
            Ok(()) | Err(age_plugin_phone_windows_storage::Error::Missing) => Ok(()),
            Err(_) => Err(SetupError::Storage),
        }
    }

    value.validate_root(root)?;
    remove_private(&value.replay_state)?;
    let mut lock_name = value
        .replay_state
        .file_name()
        .ok_or(SetupError::Invalid)?
        .to_os_string();
    lock_name.push(".lock");
    remove_private(&root.join(lock_name))?;
    if let Some(stub) = &value.candidate {
        remove_private(&crate::locator::pairing_locator_path(root, stub))?;
    }
    remove_private(&value.desktop_state)?;
    age_plugin_phone_windows_cng::remove_key_set(value.desktop_id)
        .map_err(|_| SetupError::Storage)?;
    remove_public(&value.identity_stub)?;
    remove(root)
}

#[cfg(not(windows))]
pub fn cleanup_owned(_root: &Path, _value: &SetupJournal) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

pub(crate) fn ensure_pairing_available(
    root: &Path,
    stub: &PublicIdentityStub,
) -> Result<(), SetupError> {
    if read_optional(root)?.is_some_and(|journal| journal.targets(stub)) {
        return Err(SetupError::Pending);
    }
    Ok(())
}

fn encoded_path(path: &Path) -> Result<&str, SetupError> {
    path.to_str()
        .filter(|value| !value.contains(['\n', '\r', '\0']))
        .ok_or(SetupError::Invalid)
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], SetupError> {
    bytes.try_into().map_err(|_| SetupError::Invalid)
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
    use super::*;
    use age_plugin_phone_recipient_p256::Recipient;
    use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint as _};
    use rand_core::OsRng;

    fn root() -> PathBuf {
        #[cfg(windows)]
        return PathBuf::from(r"C:\private\age-plugin-phone");
        #[cfg(not(windows))]
        return PathBuf::from("/private/age-plugin-phone");
    }

    fn candidate(desktop_id: Id) -> PublicIdentityStub {
        let identity = SecretKey::random(&mut OsRng);
        let signing = SigningKey::random(&mut OsRng);
        let selection = SigningKey::random(&mut OsRng);
        let phone = SigningKey::random(&mut OsRng);
        PublicIdentityStub {
            desktop_id,
            identity_id: [3; 16],
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
            offer_digest: [4; 32],
            transcript_fingerprint: [5; 32],
        }
    }

    #[test]
    fn journal_is_canonical_and_stage_bound() {
        let mut value =
            SetupJournal::new_with_transport(&root(), [1; 16], [2; 16], TransportChoice::Wifi);
        for stage in [SetupStage::Provisioning, SetupStage::Pairing] {
            value.stage = stage;
            let encoded = value.encode().unwrap();
            assert_eq!(SetupJournal::decode(&encoded).unwrap(), value);
        }
        let pending = candidate(value.desktop_id);
        value.set_candidate(pending.clone()).unwrap();
        assert!(value.targets(&pending));
        value.set_confirmed(&pending).unwrap();
        let encoded = value.encode().unwrap();
        assert_eq!(SetupJournal::decode(&encoded).unwrap(), value);

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(SetupJournal::decode(&trailing), Err(SetupError::Invalid));

        let legacy = value.encode_legacy().unwrap();
        let decoded = SetupJournal::decode(&legacy).unwrap();
        assert_eq!(decoded.transport, TransportChoice::Auto);
        assert_eq!(decoded.candidate, value.candidate);
    }

    #[test]
    fn journal_rejects_candidate_and_path_mismatches() {
        let mut value = SetupJournal::new(&root(), [1; 16], [2; 16]);
        assert_eq!(
            value.set_candidate(candidate([9; 16])),
            Err(SetupError::Invalid)
        );
        value.desktop_state = root().join("wrong.state");
        assert_eq!(value.validate_root(&root()), Err(SetupError::Invalid));
    }
}
