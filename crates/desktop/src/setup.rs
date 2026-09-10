//! Crash-safe ownership record for simplified hardware desktop setup.

#![cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
#![allow(clippy::missing_errors_doc)]

use crate::pairing::RecipientType;

use std::path::{Path, PathBuf};

use age_plugin_phone_core::protocol::Id;
use minicbor::{Decoder, Encoder, data::Type};
use thiserror::Error;

use crate::pairing::PublicIdentityStub;
use crate::transport_policy::TransportChoice;

const EXPLICIT_SETUP_VERSION: u16 = 3;
const SETUP_VERSION: u16 = 2;
const LEGACY_SETUP_VERSION: u16 = 1;
const JOURNAL_NAME: &str = "desktop-setup.cbor";
#[cfg(test)]
std::thread_local! { static COMMIT_FAILURE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) }; }

#[cfg(any(windows, target_os = "macos"))]
#[cfg_attr(not(test), allow(clippy::unnecessary_wraps))]
fn commit_checkpoint(stage: &'static str) -> Result<(), SetupError> {
    #[cfg(test)]
    if COMMIT_FAILURE.with(|failure| {
        if failure.get() == Some(stage) {
            failure.set(None);
            true
        } else {
            false
        }
    }) {
        return Err(SetupError::Storage);
    }
    let _ = stage;
    Ok(())
}
#[cfg(any(windows, target_os = "macos"))]
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
    pub explicit_paths: bool,
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
            explicit_paths: false,
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

    /// Explicit macOS pairing owns only newly created caller-selected output paths.
    pub fn new_explicit(
        root: &Path,
        setup_code: Id,
        desktop_id: Id,
        paths: [&Path; 3],
        transport: TransportChoice,
    ) -> Result<Self, SetupError> {
        let value = Self {
            explicit_paths: true,
            desktop_state: paths[0].to_owned(),
            replay_state: paths[1].to_owned(),
            identity_stub: paths[2].to_owned(),
            ..Self::new_with_transport(root, setup_code, desktop_id, transport)
        };
        value.validate_root(root)?;
        Ok(value)
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
            .array(if self.explicit_paths { 10 } else { 9 })
            .map_err(|_| SetupError::Invalid)?
            .u16(if self.explicit_paths {
                EXPLICIT_SETUP_VERSION
            } else {
                SETUP_VERSION
            })
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
        if self.explicit_paths {
            encoder.bool(true).map_err(|_| SetupError::Invalid)?;
        }
        Ok(encoder.into_writer())
    }

    fn decode(bytes: &[u8]) -> Result<Self, SetupError> {
        let mut decoder = Decoder::new(bytes);
        let fields = decoder.array().map_err(|_| SetupError::Invalid)?;
        let version = decoder.u16().map_err(|_| SetupError::Invalid)?;
        if !matches!(
            (fields, version),
            (Some(10), EXPLICIT_SETUP_VERSION)
                | (Some(9), SETUP_VERSION)
                | (Some(8), LEGACY_SETUP_VERSION)
        ) {
            return Err(SetupError::Invalid);
        }
        let stage = SetupStage::decode(decoder.u16().map_err(|_| SetupError::Invalid)?)?;
        let setup_code = fixed(decoder.bytes().map_err(|_| SetupError::Invalid)?)?;
        let desktop_id = fixed(decoder.bytes().map_err(|_| SetupError::Invalid)?)?;
        let desktop_state = PathBuf::from(decoder.str().map_err(|_| SetupError::Invalid)?);
        let replay_state = PathBuf::from(decoder.str().map_err(|_| SetupError::Invalid)?);
        let identity_stub = PathBuf::from(decoder.str().map_err(|_| SetupError::Invalid)?);
        let transport = if version == LEGACY_SETUP_VERSION {
            TransportChoice::Auto
        } else {
            decoder
                .str()
                .map_err(|_| SetupError::Invalid)?
                .parse()
                .map_err(|_| SetupError::Invalid)?
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
        let explicit_paths = version == EXPLICIT_SETUP_VERSION;
        if explicit_paths && !decoder.bool().map_err(|_| SetupError::Invalid)? {
            return Err(SetupError::Invalid);
        }
        let value = Self {
            explicit_paths,
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
            || if version == LEGACY_SETUP_VERSION {
                value.encode_legacy()? != bytes
            } else {
                value.encode()? != bytes
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
        if self.explicit_paths {
            return self.validate_explicit_root(root);
        }
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
    #[cfg(not(target_os = "macos"))]
    // Match the macOS validator's method interface while rejecting this layout.
    #[allow(clippy::unused_self)]
    fn validate_explicit_root(&self, _root: &Path) -> Result<(), SetupError> {
        Err(SetupError::Unsupported)
    }

    #[cfg(target_os = "macos")]
    fn validate_explicit_root(&self, root: &Path) -> Result<(), SetupError> {
        use std::path::Component;
        let canonical = |path: &Path| {
            path.is_absolute()
                && path
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        };
        let paths = [&self.desktop_state, &self.replay_state, &self.identity_stub];
        if !canonical(root)
            || paths.iter().any(|path| !canonical(path))
            || self.desktop_state.parent() != Some(root)
            || self.replay_state.parent() != Some(root)
            || paths[0] == paths[1]
            || paths[0] == paths[2]
            || paths[1] == paths[2]
        {
            return Err(SetupError::Invalid);
        }
        // Reserve all journal/locator and replay-sidecar namespaces even before a phone
        // identity is known. An explicit path must never alias another operation's metadata.
        let mut names = std::collections::BTreeSet::new();
        for path in paths {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(SetupError::Invalid)?;
            // Avoid case-folding/Unicode aliases on ordinary case-insensitive APFS. Public
            // output also reserves these names, including when its parent aliases this root.
            if name.is_empty()
                || !name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'-' | b'_')
                })
                || !names.insert(name)
                || path.extension().is_some_and(|ext| {
                    ["cbor", "lock", "pending"]
                        .iter()
                        .any(|reserved| ext == *reserved)
                })
                || name.starts_with(".replace-")
                || name.starts_with(".state-")
            {
                return Err(SetupError::Invalid);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SetupError {
    #[error("simplified setup requires a supported Windows or macOS hardware desktop")]
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

#[cfg(any(windows, target_os = "macos"))]
pub fn ensure_no_cleanup_pending(root: &Path) -> Result<(), SetupError> {
    if crate::cleanup_journal::read(root)
        .map_err(|_| SetupError::Invalid)?
        .is_some()
    {
        return Err(SetupError::Busy);
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn ensure_no_cleanup_pending(_root: &Path) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(windows)]
pub fn acquire_lifecycle_lock(
    root: &Path,
) -> Result<age_plugin_phone_platform_storage::windows::PrivateLock, SetupError> {
    age_plugin_phone_platform_storage::windows::open_private_lock(
        &crate::cleanup_journal::journal_lock_path(root),
    )
    .map_err(|_| SetupError::Busy)
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn acquire_lifecycle_lock(_root: &Path) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(target_os = "macos")]
pub fn acquire_lifecycle_lock(
    root: &Path,
) -> Result<age_plugin_phone_platform_storage::macos::PrivateLock, SetupError> {
    let directory = age_plugin_phone_platform_storage::macos::Directory::open(root)
        .map_err(|_| SetupError::Invalid)?;
    let path = crate::cleanup_journal::journal_lock_path(root);
    directory
        .lock(Path::new(path.file_name().ok_or(SetupError::Invalid)?))
        .map_err(|_| SetupError::Busy)
}

#[cfg(windows)]
fn create_managed_stub(
    path: &Path,
    stub: &PublicIdentityStub,
    kind: RecipientType,
) -> Result<(), SetupError> {
    crate::pairing::create_identity_stub_file_for(path, stub, kind).map_err(|_| SetupError::Storage)
}

#[cfg(windows)]
fn read_managed_stub(path: &Path) -> Result<PublicIdentityStub, SetupError> {
    crate::pairing::read_identity_stub_file(path).map_err(|_| SetupError::Invalid)
}

#[cfg(target_os = "macos")]
fn create_managed_stub(
    path: &Path,
    stub: &PublicIdentityStub,
    kind: RecipientType,
) -> Result<(), SetupError> {
    let text = stub
        .identity_file_for(kind)
        .map_err(|_| SetupError::Invalid)?;
    age_plugin_phone_platform_storage::macos::create_regular_file(path, text.as_bytes())
        .map_err(|_| SetupError::Storage)
}

#[cfg(target_os = "macos")]
fn read_managed_stub(path: &Path) -> Result<PublicIdentityStub, SetupError> {
    let bytes = age_plugin_phone_platform_storage::macos::read_regular_file(path, 16_384)
        .map_err(|_| SetupError::Invalid)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| SetupError::Invalid)?;
    crate::pairing::decode_identity_stub_text(text).map_err(|_| SetupError::Invalid)
}

#[cfg(windows)]
pub fn read(root: &Path) -> Result<SetupJournal, SetupError> {
    let bytes = age_plugin_phone_platform_storage::windows::read_private_file(
        &journal_path(root),
        MAX_JOURNAL_BYTES,
    )
    .map_err(|error| match error {
        age_plugin_phone_platform_storage::windows::Error::Missing => SetupError::Missing,
        _ => SetupError::Invalid,
    })?;
    let value = SetupJournal::decode(&bytes)?;
    value.validate_root(root)?;
    Ok(value)
}

#[cfg(target_os = "macos")]
pub fn read(root: &Path) -> Result<SetupJournal, SetupError> {
    let bytes = age_plugin_phone_platform_storage::macos::read_private_file(
        &journal_path(root),
        MAX_JOURNAL_BYTES,
    )
    .map_err(|error| match error {
        age_plugin_phone_platform_storage::macos::Error::Missing => SetupError::Missing,
        _ => SetupError::Invalid,
    })?;
    let value = SetupJournal::decode(&bytes)?;
    value.validate_root(root)?;
    Ok(value)
}

#[cfg(not(any(windows, target_os = "macos")))]
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

#[cfg(target_os = "macos")]
pub fn read_optional(root: &Path) -> Result<Option<SetupJournal>, SetupError> {
    match read(root) {
        Ok(value) => Ok(Some(value)),
        Err(SetupError::Missing) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn read_optional(_root: &Path) -> Result<Option<SetupJournal>, SetupError> {
    Ok(None)
}

#[cfg(windows)]
pub fn create(root: &Path, value: &SetupJournal) -> Result<(), SetupError> {
    value.validate_root(root)?;
    age_plugin_phone_platform_storage::windows::atomic_create(&journal_path(root), &value.encode()?)
        .map_err(|error| match error {
            age_plugin_phone_platform_storage::windows::Error::AlreadyExists => SetupError::Pending,
            _ => SetupError::Storage,
        })
}

#[cfg(target_os = "macos")]
pub fn create(root: &Path, value: &SetupJournal) -> Result<(), SetupError> {
    value.validate_root(root)?;
    if value.explicit_paths {
        // Only a new explicit attempt can claim paths. A broken symlink or an uncertain
        // replay sidecar is existing state, never an empty path available for reuse.
        let mut paths = vec![
            value.desktop_state.clone(),
            value.replay_state.clone(),
            value.identity_stub.clone(),
        ];
        for suffix in [".lock", ".pending"] {
            let mut name = value.replay_state.as_os_str().to_os_string();
            name.push(suffix);
            paths.push(PathBuf::from(name));
        }
        for path in paths {
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(SetupError::Invalid),
            }
        }
        crate::locator::ensure_exclusive_cleanup_target(
            root,
            &journal_path(root),
            &value.desktop_state,
            &value.replay_state,
        )
        .map_err(|_| SetupError::Invalid)?;
    }
    age_plugin_phone_platform_storage::macos::atomic_create(&journal_path(root), &value.encode()?)
        .map_err(|error| match error {
            age_plugin_phone_platform_storage::macos::Error::AlreadyExists => SetupError::Pending,
            _ => SetupError::Storage,
        })
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn create(_root: &Path, _value: &SetupJournal) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(windows)]
pub fn replace(root: &Path, value: &SetupJournal) -> Result<(), SetupError> {
    value.validate_root(root)?;
    age_plugin_phone_platform_storage::windows::atomic_replace(
        &journal_path(root),
        &value.encode()?,
    )
    .map_err(|_| SetupError::Storage)
}

#[cfg(target_os = "macos")]
pub fn replace(root: &Path, value: &SetupJournal) -> Result<(), SetupError> {
    value.validate_root(root)?;
    age_plugin_phone_platform_storage::macos::atomic_replace(&journal_path(root), &value.encode()?)
        .map_err(|_| SetupError::Storage)
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn replace(_root: &Path, _value: &SetupJournal) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(windows)]
pub fn remove(root: &Path) -> Result<(), SetupError> {
    match age_plugin_phone_platform_storage::windows::remove_private_file(&journal_path(root)) {
        Ok(()) | Err(age_plugin_phone_platform_storage::windows::Error::Missing) => Ok(()),
        Err(_) => Err(SetupError::Storage),
    }
}

#[cfg(target_os = "macos")]
pub fn remove(root: &Path) -> Result<(), SetupError> {
    match age_plugin_phone_platform_storage::macos::remove_private_file(&journal_path(root)) {
        Ok(()) | Err(age_plugin_phone_platform_storage::macos::Error::Missing) => Ok(()),
        Err(_) => Err(SetupError::Storage),
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn remove(_root: &Path) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(any(windows, target_os = "macos"))]
pub fn commit_confirmed_for(
    root: &Path,
    value: &SetupJournal,
    now_unix: u64,
    kind: RecipientType,
) -> Result<(), SetupError> {
    use age_plugin_phone_core::protocol::{
        DEFAULT_REPLAY_CAPACITY, FileReplayGuard, PairingRecord, ReplayRole, ReplayScope,
    };

    value.validate_root(root)?;
    if value.stage != SetupStage::Confirmed || read(root)? != *value {
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
    commit_checkpoint("before_replay")?;
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
    commit_checkpoint("after_replay")?;

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
    commit_checkpoint("after_locator")?;

    if create_managed_stub(&value.identity_stub, stub, kind).is_err() {
        let existing = read_managed_stub(&value.identity_stub).map_err(|_| SetupError::Invalid)?;
        if existing != *stub {
            return Err(SetupError::Invalid);
        }
        // A crash after the public file was created must not report a different recipient
        // from that file's comment. Resume with the same explicit type; never rewrite a stub.
        #[cfg(windows)]
        let bytes = age_plugin_phone_platform_storage::windows::read_regular_file(
            &value.identity_stub,
            16_384,
        )
        .map_err(|_| SetupError::Invalid)?;
        #[cfg(target_os = "macos")]
        let bytes = age_plugin_phone_platform_storage::macos::read_regular_file(
            &value.identity_stub,
            16_384,
        )
        .map_err(|_| SetupError::Invalid)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| SetupError::Invalid)?;
        let comment = format!(
            "# recipient: {}",
            stub.recipient_for(kind).map_err(|_| SetupError::Invalid)?
        );
        if !text.lines().any(|line| line == comment) {
            return Err(SetupError::Invalid);
        }
    }
    commit_checkpoint("after_stub")?;
    remove(root)
}

/// Compatibility commit using the default phone recipient comment.
pub fn commit_confirmed(
    root: &Path,
    value: &SetupJournal,
    now_unix: u64,
) -> Result<(), SetupError> {
    commit_confirmed_for(root, value, now_unix, RecipientType::Phone)
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn commit_confirmed_for(
    _root: &Path,
    _value: &SetupJournal,
    _now_unix: u64,
    _kind: RecipientType,
) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(windows)]
pub fn cleanup_owned(root: &Path, value: &SetupJournal) -> Result<(), SetupError> {
    fn remove_private(path: &Path) -> Result<(), SetupError> {
        match age_plugin_phone_platform_storage::windows::remove_private_file(path) {
            Ok(()) | Err(age_plugin_phone_platform_storage::windows::Error::Missing) => Ok(()),
            Err(_) => Err(SetupError::Storage),
        }
    }
    fn remove_public(path: &Path) -> Result<(), SetupError> {
        match age_plugin_phone_platform_storage::windows::remove_regular_file(path) {
            Ok(()) | Err(age_plugin_phone_platform_storage::windows::Error::Missing) => Ok(()),
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
    age_plugin_phone_platform_keys::windows::remove_key_set(value.desktop_id)
        .map_err(|_| SetupError::Storage)?;
    remove_public(&value.identity_stub)?;
    remove(root)
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn cleanup_owned(_root: &Path, _value: &SetupJournal) -> Result<(), SetupError> {
    Err(SetupError::Unsupported)
}

#[cfg(target_os = "macos")]
pub fn cleanup_owned(root: &Path, value: &SetupJournal) -> Result<(), SetupError> {
    use age_plugin_phone_platform_storage::macos::{Directory, Error};
    value.validate_root(root)?;
    // Teardown requires the original durable ownership record. Never fabricate ownership from
    // a partial key file or use a missing/corrupt journal as permission to clear replay state.
    if read(root)? != *value {
        return Err(SetupError::Invalid);
    }
    let own_locator = value.candidate.as_ref().map_or_else(
        || journal_path(root),
        |stub| crate::locator::pairing_locator_path(root, stub),
    );
    crate::locator::ensure_exclusive_cleanup_target(
        root,
        &own_locator,
        &value.desktop_state,
        &value.replay_state,
    )
    .map_err(|_| SetupError::Invalid)?;
    let directory = Directory::open(root).map_err(|_| SetupError::Invalid)?;
    let replay_name = value.replay_state.file_name().ok_or(SetupError::Invalid)?;
    let mut lock_name = replay_name.to_os_string();
    lock_name.push(".lock");
    let replay_lock = directory
        .lock(Path::new(&lock_name))
        .map_err(|_| SetupError::Busy)?;
    let remove = |path: &Path| -> Result<(), SetupError> {
        replay_lock
            .validate(&directory)
            .map_err(|_| SetupError::Busy)?;
        let child = Path::new(path.file_name().ok_or(SetupError::Invalid)?);
        match directory.remove(child) {
            Ok(()) | Err(Error::Missing) => {}
            Err(_) => return Err(SetupError::Storage),
        }
        directory
            .remove_replacement_temporaries(child)
            .map_err(|_| SetupError::Storage)
    };
    // These are local reference deletions, not irreversible enclave destruction or phone revocation.
    remove(&value.desktop_state)?;
    remove(&value.replay_state)?;
    let mut pending_name = replay_name.to_os_string();
    pending_name.push(".pending");
    remove(&root.join(pending_name))?;
    if let Some(stub) = &value.candidate {
        remove(&crate::locator::pairing_locator_path(root, stub))?;
    }
    if value.identity_stub.parent() == Some(root) {
        remove(&value.identity_stub)?;
    } else {
        replay_lock
            .validate(&directory)
            .map_err(|_| SetupError::Busy)?;
        match age_plugin_phone_platform_storage::macos::remove_regular_file(&value.identity_stub) {
            Ok(()) | Err(Error::Missing) => {}
            Err(_) => return Err(SetupError::Storage),
        }
    }
    // Keep the journal through all earlier errors, including a failed lock-file deletion.
    remove(&root.join(&lock_name))?;
    drop(replay_lock);
    directory
        .remove_replacement_temporaries(Path::new(JOURNAL_NAME))
        .map_err(|_| SetupError::Storage)?;
    self::remove(root)
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
    use age_plugin_phone_core::recipient::Recipient;
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

    #[cfg(target_os = "macos")]
    #[test]
    fn explicit_journal_is_versioned_and_rejects_aliases_and_reserved_paths() {
        let root = root();
        let desktop = root.join("custom-desktop.state");
        let replay = root.join("custom-replay.state");
        let public = PathBuf::from("/private/public/phone.txt");
        let value = SetupJournal::new_explicit(
            &root,
            [1; 16],
            [2; 16],
            [&desktop, &replay, &public],
            TransportChoice::Qr,
        )
        .unwrap();
        let bytes = value.encode().unwrap();
        assert_eq!(SetupJournal::decode(&bytes).unwrap(), value);
        let mut wrong_marker = bytes.clone();
        *wrong_marker.last_mut().unwrap() = 0xf4; // false cannot disguise version 3 as managed
        assert_eq!(
            SetupJournal::decode(&wrong_marker),
            Err(SetupError::Invalid)
        );
        for name in [
            "desktop-setup.cbor",
            "custom-replay.state.lock",
            ".replace-test",
            "UPPER.state",
        ] {
            assert!(
                SetupJournal::new_explicit(
                    &root,
                    [1; 16],
                    [2; 16],
                    [&root.join(name), &replay, &public],
                    TransportChoice::Qr
                )
                .is_err()
            );
        }
        assert!(
            SetupJournal::new_explicit(
                &root,
                [1; 16],
                [2; 16],
                [&desktop, &desktop, &public],
                TransportChoice::Qr
            )
            .is_err()
        );
        assert!(
            SetupJournal::new_explicit(
                &root,
                [1; 16],
                [2; 16],
                [&public, &replay, &desktop],
                TransportChoice::Qr
            )
            .is_err()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn explicit_ownership_never_claims_existing_or_uncertain_outputs() {
        use age_plugin_phone_platform_storage::macos::Directory;
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "phone-explicit-ownership-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut OsRng)
        ));
        Directory::prepare(&root).unwrap();
        let desktop = root.join("desktop.state");
        let replay = root.join("replay.state");
        let public = root.join("phone.txt");
        let value = SetupJournal::new_explicit(
            &root,
            [1; 16],
            [2; 16],
            [&desktop, &replay, &public],
            TransportChoice::Qr,
        )
        .unwrap();
        for name in [
            "desktop.state",
            "replay.state",
            "phone.txt",
            "replay.state.pending",
            "replay.state.lock",
        ] {
            let path = root.join(name);
            std::fs::write(&path, b"uncertain synthetic state").unwrap();
            assert_eq!(create(&root, &value), Err(SetupError::Invalid));
            assert!(!journal_path(&root).exists());
            assert_eq!(std::fs::read(&path).unwrap(), b"uncertain synthetic state");
            std::fs::remove_file(path).unwrap();
        }
        symlink(root.join("missing"), &desktop).unwrap();
        assert_eq!(create(&root, &value), Err(SetupError::Invalid));
        std::fs::remove_file(&desktop).unwrap();
        create(&root, &value).unwrap();
        assert_eq!(read(&root).unwrap(), value);
        Directory::open(&root)
            .unwrap()
            .create(Path::new("desktop.state"), b"pending")
            .unwrap();
        cleanup_owned(&root, &value).unwrap();
        assert!(!desktop.exists());
        assert!(!journal_path(&root).exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    fn macos_fixture() -> (PathBuf, SetupJournal) {
        macos_fixture_with_paths(false)
    }

    #[cfg(target_os = "macos")]
    fn macos_fixture_with_paths(explicit: bool) -> (PathBuf, SetupJournal) {
        use age_plugin_phone_platform_storage::macos::Directory;
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "phone-setup-test-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut OsRng)
        ));
        Directory::prepare(&root).unwrap();
        // This module's ordinary fixture uses the cfg(test) operation implementation, never
        // the user's Secure Enclave. Native provisioning is a separately invoked test.
        let source = root.join("fixture-key");
        let keys = crate::pairing::DesktopKeyState::open_or_create(&source, &mut OsRng).unwrap();
        let public_root = root.join("public");
        std::fs::create_dir(&public_root).unwrap();
        let mut value = if explicit {
            SetupJournal::new_explicit(
                &root,
                [1; 16],
                keys.desktop_id,
                [
                    &root.join("explicit-desktop.state"),
                    &root.join("explicit-replay.state"),
                    &public_root.join("phone.txt"),
                ],
                TransportChoice::Qr,
            )
            .unwrap()
        } else {
            SetupJournal::new(&root, [1; 16], keys.desktop_id)
        };
        create(&root, &value).unwrap();
        std::fs::rename(source, &value.desktop_state).unwrap();
        let mut stub = candidate(keys.desktop_id);
        stub.desktop_signing_public_key = keys.signing_public_key().unwrap();
        stub.desktop_selection_public_key = keys.selection_public_key().unwrap();
        value.set_candidate(stub.clone()).unwrap();
        value.set_confirmed(&stub).unwrap();
        replace(&root, &value).unwrap();
        (root, value)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_confirmed_commit_resumes_at_every_write_boundary() {
        for kind in [RecipientType::Phone, RecipientType::Tag] {
            for explicit in [false, true] {
                for stage in [
                    "before_replay",
                    "after_replay",
                    "after_locator",
                    "after_stub",
                ] {
                    let (root, value) = macos_fixture_with_paths(explicit);
                    let lock = acquire_lifecycle_lock(&root).unwrap();
                    assert!(acquire_lifecycle_lock(&root).is_err());
                    COMMIT_FAILURE.with(|failure| failure.set(Some(stage)));
                    assert_eq!(
                        commit_confirmed_for(&root, &value, 100, kind),
                        Err(SetupError::Storage)
                    );
                    assert_eq!(read(&root).unwrap(), value);
                    let stub = value.candidate.as_ref().unwrap();
                    assert!(crate::locator::open_pairing_locator(&root, stub).is_err());
                    commit_confirmed_for(&root, &value, 100, kind).unwrap();
                    assert_eq!(read(&root), Err(SetupError::Missing));
                    assert_eq!(read_managed_stub(&value.identity_stub).unwrap(), *stub);
                    assert!(crate::locator::open_pairing_locator(&root, stub).is_ok());
                    drop(lock);
                    std::fs::remove_dir_all(root).unwrap();
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_unconfirmed_wrong_key_and_uncertain_replay_do_not_commit() {
        use age_plugin_phone_platform_storage::macos::Directory;
        let (root, mut value) = macos_fixture();
        for stage in [
            SetupStage::Provisioning,
            SetupStage::Pairing,
            SetupStage::ResponseVerified,
        ] {
            value.stage = stage;
            assert_eq!(
                commit_confirmed(&root, &value, 100),
                Err(SetupError::Invalid)
            );
            assert!(!value.replay_state.exists());
        }
        value.stage = SetupStage::Confirmed;
        let original = value.candidate.clone();
        value.candidate = Some(candidate(value.desktop_id));
        assert_eq!(
            commit_confirmed(&root, &value, 100),
            Err(SetupError::Invalid)
        );
        assert!(!value.replay_state.exists());
        value.candidate = original;
        let directory = Directory::open(&root).unwrap();
        let pending = root.join(format!(
            "{}.pending",
            value.replay_state.file_name().unwrap().to_str().unwrap()
        ));
        directory
            .create(Path::new(pending.file_name().unwrap()), b"uncertain")
            .unwrap();
        assert_eq!(
            commit_confirmed(&root, &value, 100),
            Err(SetupError::Invalid)
        );
        assert_eq!(std::fs::read(pending).unwrap(), b"uncertain");
        assert_eq!(read(&root).unwrap(), value);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_owned_cleanup_is_exact_idempotent_and_rejects_active_replay() {
        use age_plugin_phone_platform_storage::macos::Directory;
        let (root, value) = macos_fixture();
        let directory = Directory::open(&root).unwrap();
        directory.create(Path::new("unrelated"), b"keep").unwrap();
        COMMIT_FAILURE.with(|failure| failure.set(Some("after_stub")));
        assert_eq!(
            commit_confirmed(&root, &value, 100),
            Err(SetupError::Storage)
        );
        let mut wrong = value.clone();
        wrong.setup_code[0] ^= 1;
        assert_eq!(cleanup_owned(&root, &wrong), Err(SetupError::Invalid));
        let lock_name = format!(
            "{}.lock",
            value.replay_state.file_name().unwrap().to_str().unwrap()
        );
        let replay_lock = directory.lock(Path::new(&lock_name)).unwrap();
        assert_eq!(cleanup_owned(&root, &value), Err(SetupError::Busy));
        assert!(value.desktop_state.exists());
        drop(replay_lock);
        // Simulate a process dying after its first deletion; journal remains authoritative.
        directory
            .remove(Path::new(value.desktop_state.file_name().unwrap()))
            .unwrap();
        cleanup_owned(&root, &value).unwrap();
        assert_eq!(directory.read(Path::new("unrelated"), 10).unwrap(), b"keep");
        assert!(!value.replay_state.exists());
        assert!(!value.identity_stub.exists());
        assert!(!journal_path(&root).exists());
        assert_eq!(cleanup_owned(&root, &value), Err(SetupError::Missing));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn explicit_cleanup_resumes_after_rejecting_a_linked_public_output() {
        let (root, value) = macos_fixture_with_paths(true);
        COMMIT_FAILURE.with(|failure| failure.set(Some("after_stub")));
        assert_eq!(
            commit_confirmed(&root, &value, 100),
            Err(SetupError::Storage)
        );
        let alias = root.join("public-alias");
        std::fs::hard_link(&value.identity_stub, &alias).unwrap();
        assert_eq!(cleanup_owned(&root, &value), Err(SetupError::Storage));
        assert!(value.identity_stub.exists());
        assert!(journal_path(&root).exists());
        std::fs::remove_file(alias).unwrap();
        cleanup_owned(&root, &value).unwrap();
        assert!(!value.identity_stub.exists());
        assert!(!journal_path(&root).exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_resume_preserves_existing_consumption_and_rejects_missing_ownership() {
        use age_plugin_phone_core::protocol::{
            DEFAULT_REPLAY_CAPACITY, FileReplayGuard, ReplayRole, ReplayScope, ReplayStore,
        };
        let (root, value) = macos_fixture();
        COMMIT_FAILURE.with(|failure| failure.set(Some("after_replay")));
        assert_eq!(
            commit_confirmed(&root, &value, 100),
            Err(SetupError::Storage)
        );
        let scope = ReplayScope::new(
            ReplayRole::DesktopResponses,
            value.desktop_id,
            value.candidate.as_ref().unwrap().identity_id,
        );
        let mut replay =
            FileReplayGuard::open(&value.replay_state, scope, DEFAULT_REPLAY_CAPACITY).unwrap();
        replay
            .consume_response(
                value.desktop_id,
                value.candidate.as_ref().unwrap().identity_id,
                [9; 32],
                110,
                100,
            )
            .unwrap();
        drop(replay);
        commit_confirmed(&root, &value, 100).unwrap();
        let mut replay =
            FileReplayGuard::open(&value.replay_state, scope, DEFAULT_REPLAY_CAPACITY).unwrap();
        assert!(
            replay
                .consume_response(
                    value.desktop_id,
                    value.candidate.as_ref().unwrap().identity_id,
                    [9; 32],
                    110,
                    100
                )
                .is_err()
        );
        drop(replay);
        // A caller-held copy of a journal cannot reconstruct ownership after commit.
        assert_eq!(
            commit_confirmed(&root, &value, 100),
            Err(SetupError::Missing)
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
