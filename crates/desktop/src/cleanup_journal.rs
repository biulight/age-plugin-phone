//! Crash-safe Windows desktop cleanup journal.

#![cfg_attr(not(windows), allow(dead_code))]

use std::path::{Path, PathBuf};

use minicbor::{Decoder, Encoder};
use thiserror::Error;

use age_plugin_phone_protocol::{Id, ProtocolDigest};

use crate::pairing::PublicIdentityStub;

const LEGACY_JOURNAL_VERSION: u16 = 1;
const JOURNAL_VERSION: u16 = 2;
const PAIRED_TARGET: u16 = 1;
const ORPHAN_TARGET: u16 = 2;
const JOURNAL_NAME: &str = "desktop-cleanup.cbor";
const JOURNAL_LOCK_NAME: &str = "desktop-cleanup.lock";
#[cfg(windows)]
const MAX_JOURNAL_BYTES: u64 = 16_384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CleanupTarget {
    Paired {
        stub: PublicIdentityStub,
        stub_path: PathBuf,
    },
    Orphan {
        desktop_id: Id,
        identity_id: Id,
        transcript_fingerprint: ProtocolDigest,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CleanupJournal {
    pub target: CleanupTarget,
    pub locator_path: PathBuf,
    pub desktop_state: PathBuf,
    pub replay_state: PathBuf,
}

impl CleanupJournal {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, JournalError> {
        let locator_path = encoded_path(&self.locator_path)?;
        let desktop_state = encoded_path(&self.desktop_state)?;
        let replay_state = encoded_path(&self.replay_state)?;
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(6)
            .map_err(|_| JournalError::Invalid)?
            .u16(JOURNAL_VERSION)
            .map_err(|_| JournalError::Invalid)?;
        match &self.target {
            CleanupTarget::Paired { stub, stub_path } => {
                encoder
                    .u16(PAIRED_TARGET)
                    .map_err(|_| JournalError::Invalid)?
                    .array(2)
                    .map_err(|_| JournalError::Invalid)?
                    .bytes(&stub.encode())
                    .map_err(|_| JournalError::Invalid)?
                    .str(encoded_path(stub_path)?)
                    .map_err(|_| JournalError::Invalid)?;
            }
            CleanupTarget::Orphan {
                desktop_id,
                identity_id,
                transcript_fingerprint,
            } => {
                encoder
                    .u16(ORPHAN_TARGET)
                    .map_err(|_| JournalError::Invalid)?
                    .array(3)
                    .map_err(|_| JournalError::Invalid)?
                    .bytes(desktop_id)
                    .map_err(|_| JournalError::Invalid)?
                    .bytes(identity_id)
                    .map_err(|_| JournalError::Invalid)?
                    .bytes(transcript_fingerprint)
                    .map_err(|_| JournalError::Invalid)?;
            }
        }
        encoder
            .str(locator_path)
            .map_err(|_| JournalError::Invalid)?
            .str(desktop_state)
            .map_err(|_| JournalError::Invalid)?
            .str(replay_state)
            .map_err(|_| JournalError::Invalid)?;
        Ok(encoder.into_writer())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| JournalError::Invalid)? != Some(6) {
            return Err(JournalError::Invalid);
        }
        let version = decoder.u16().map_err(|_| JournalError::Invalid)?;
        let value = match version {
            LEGACY_JOURNAL_VERSION => Self::decode_legacy(&mut decoder)?,
            JOURNAL_VERSION => Self::decode_current(&mut decoder)?,
            _ => return Err(JournalError::Invalid),
        };
        let canonical = match version {
            LEGACY_JOURNAL_VERSION => value.encode_legacy()?,
            JOURNAL_VERSION => value.encode()?,
            _ => unreachable!(),
        };
        if decoder.position() != bytes.len() || canonical != bytes || !value.paths_are_valid() {
            return Err(JournalError::Invalid);
        }
        Ok(value)
    }

    fn decode_legacy(decoder: &mut Decoder<'_>) -> Result<Self, JournalError> {
        Ok(Self {
            target: CleanupTarget::Paired {
                stub: PublicIdentityStub::decode(
                    decoder.bytes().map_err(|_| JournalError::Invalid)?,
                )
                .map_err(|_| JournalError::Invalid)?,
                stub_path: PathBuf::from(decoder.str().map_err(|_| JournalError::Invalid)?),
            },
            locator_path: PathBuf::from(decoder.str().map_err(|_| JournalError::Invalid)?),
            desktop_state: PathBuf::from(decoder.str().map_err(|_| JournalError::Invalid)?),
            replay_state: PathBuf::from(decoder.str().map_err(|_| JournalError::Invalid)?),
        })
    }

    fn decode_current(decoder: &mut Decoder<'_>) -> Result<Self, JournalError> {
        let kind = decoder.u16().map_err(|_| JournalError::Invalid)?;
        let target = match kind {
            PAIRED_TARGET => {
                if decoder.array().map_err(|_| JournalError::Invalid)? != Some(2) {
                    return Err(JournalError::Invalid);
                }
                CleanupTarget::Paired {
                    stub: PublicIdentityStub::decode(
                        decoder.bytes().map_err(|_| JournalError::Invalid)?,
                    )
                    .map_err(|_| JournalError::Invalid)?,
                    stub_path: PathBuf::from(decoder.str().map_err(|_| JournalError::Invalid)?),
                }
            }
            ORPHAN_TARGET => {
                if decoder.array().map_err(|_| JournalError::Invalid)? != Some(3) {
                    return Err(JournalError::Invalid);
                }
                CleanupTarget::Orphan {
                    desktop_id: fixed(decoder.bytes().map_err(|_| JournalError::Invalid)?)?,
                    identity_id: fixed(decoder.bytes().map_err(|_| JournalError::Invalid)?)?,
                    transcript_fingerprint: fixed(
                        decoder.bytes().map_err(|_| JournalError::Invalid)?,
                    )?,
                }
            }
            _ => return Err(JournalError::Invalid),
        };
        Ok(Self {
            target,
            locator_path: PathBuf::from(decoder.str().map_err(|_| JournalError::Invalid)?),
            desktop_state: PathBuf::from(decoder.str().map_err(|_| JournalError::Invalid)?),
            replay_state: PathBuf::from(decoder.str().map_err(|_| JournalError::Invalid)?),
        })
    }

    fn encode_legacy(&self) -> Result<Vec<u8>, JournalError> {
        let CleanupTarget::Paired { stub, stub_path } = &self.target else {
            return Err(JournalError::Invalid);
        };
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(6)
            .map_err(|_| JournalError::Invalid)?
            .u16(LEGACY_JOURNAL_VERSION)
            .map_err(|_| JournalError::Invalid)?
            .bytes(&stub.encode())
            .map_err(|_| JournalError::Invalid)?
            .str(encoded_path(stub_path)?)
            .map_err(|_| JournalError::Invalid)?
            .str(encoded_path(&self.locator_path)?)
            .map_err(|_| JournalError::Invalid)?
            .str(encoded_path(&self.desktop_state)?)
            .map_err(|_| JournalError::Invalid)?
            .str(encoded_path(&self.replay_state)?)
            .map_err(|_| JournalError::Invalid)?;
        Ok(encoder.into_writer())
    }

    fn paths_are_valid(&self) -> bool {
        let mut paths = vec![&self.locator_path, &self.desktop_state, &self.replay_state];
        if let CleanupTarget::Paired { stub_path, .. } = &self.target {
            paths.push(stub_path);
        }
        paths
            .into_iter()
            .all(|path| path.is_absolute() && path.file_name().is_some())
    }

    pub(crate) fn targets(&self, stub: &PublicIdentityStub) -> bool {
        self.desktop_id() == stub.desktop_id
            && self.identity_id() == stub.identity_id
            && self.transcript_fingerprint() == stub.transcript_fingerprint
    }

    pub(crate) fn paired(&self) -> Option<(&PublicIdentityStub, &Path)> {
        match &self.target {
            CleanupTarget::Paired { stub, stub_path } => Some((stub, stub_path)),
            CleanupTarget::Orphan { .. } => None,
        }
    }

    pub(crate) const fn desktop_id(&self) -> Id {
        match &self.target {
            CleanupTarget::Paired { stub, .. } => stub.desktop_id,
            CleanupTarget::Orphan { desktop_id, .. } => *desktop_id,
        }
    }

    pub(crate) const fn identity_id(&self) -> Id {
        match &self.target {
            CleanupTarget::Paired { stub, .. } => stub.identity_id,
            CleanupTarget::Orphan { identity_id, .. } => *identity_id,
        }
    }

    pub(crate) const fn transcript_fingerprint(&self) -> ProtocolDigest {
        match &self.target {
            CleanupTarget::Paired { stub, .. } => stub.transcript_fingerprint,
            CleanupTarget::Orphan {
                transcript_fingerprint,
                ..
            } => *transcript_fingerprint,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum JournalError {
    #[error("desktop cleanup journal is malformed or unavailable")]
    Invalid,
    #[error("desktop cleanup is pending for this pairing")]
    Pending,
    #[error("desktop cleanup journal could not be durably created")]
    Storage,
}

pub(crate) fn journal_path(root: &Path) -> PathBuf {
    root.join(JOURNAL_NAME)
}

pub(crate) fn journal_lock_path(root: &Path) -> PathBuf {
    root.join(JOURNAL_LOCK_NAME)
}

#[cfg(windows)]
pub(crate) fn read(root: &Path) -> Result<Option<CleanupJournal>, JournalError> {
    match age_plugin_phone_windows_storage::read_private_file(
        &journal_path(root),
        MAX_JOURNAL_BYTES,
    ) {
        Ok(bytes) => CleanupJournal::decode(&bytes).map(Some),
        Err(age_plugin_phone_windows_storage::Error::Missing) => Ok(None),
        Err(_) => Err(JournalError::Invalid),
    }
}

#[cfg(windows)]
pub(crate) fn create(root: &Path, journal: &CleanupJournal) -> Result<(), JournalError> {
    let encoded = journal.encode()?;
    age_plugin_phone_windows_storage::atomic_create(&journal_path(root), &encoded)
        .map_err(|_| JournalError::Storage)
}

#[cfg(windows)]
pub(crate) fn ensure_pairing_available(
    root: &Path,
    stub: &PublicIdentityStub,
) -> Result<(), JournalError> {
    if read(root)?.is_some_and(|journal| journal.targets(stub)) {
        return Err(JournalError::Pending);
    }
    Ok(())
}

#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn ensure_pairing_available(
    _root: &Path,
    _stub: &PublicIdentityStub,
) -> Result<(), JournalError> {
    Ok(())
}

fn encoded_path(path: &Path) -> Result<&str, JournalError> {
    path.to_str()
        .filter(|value| !value.contains(['\n', '\r', '\0']))
        .ok_or(JournalError::Invalid)
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], JournalError> {
    bytes.try_into().map_err(|_| JournalError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age_plugin_phone_recipient_p256::Recipient;
    use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint as _};
    use rand_core::OsRng;

    fn stub() -> PublicIdentityStub {
        let identity = SecretKey::random(&mut OsRng);
        let signing = SigningKey::random(&mut OsRng);
        let selection = SigningKey::random(&mut OsRng);
        let phone = SigningKey::random(&mut OsRng);
        PublicIdentityStub {
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
        }
    }

    fn absolute(name: &str) -> PathBuf {
        #[cfg(windows)]
        return PathBuf::from(format!(r"C:\private\{name}"));
        #[cfg(not(windows))]
        return PathBuf::from(format!("/private/{name}"));
    }

    fn paired_journal(stub_path: PathBuf) -> CleanupJournal {
        CleanupJournal {
            target: CleanupTarget::Paired {
                stub: stub(),
                stub_path,
            },
            locator_path: absolute("locator.cbor"),
            desktop_state: absolute("desktop.state"),
            replay_state: absolute("replay.state"),
        }
    }

    fn orphan_journal() -> CleanupJournal {
        CleanupJournal {
            target: CleanupTarget::Orphan {
                desktop_id: [1; 16],
                identity_id: [2; 16],
                transcript_fingerprint: [4; 32],
            },
            locator_path: absolute("locator.cbor"),
            desktop_state: absolute("desktop.state"),
            replay_state: absolute("replay.state"),
        }
    }

    #[test]
    fn paired_and_orphan_journals_are_canonical_bound_and_strict() {
        let paired = paired_journal(absolute("identity.txt"));
        let paired_stub = paired.paired().unwrap().0.clone();
        assert!(paired.targets(&paired_stub));
        assert!(orphan_journal().targets(&paired_stub));
        for value in [paired.clone(), orphan_journal()] {
            let encoded = value.encode().unwrap();
            assert_eq!(CleanupJournal::decode(&encoded).unwrap(), value);

            let mut trailing = encoded;
            trailing.push(0);
            assert_eq!(
                CleanupJournal::decode(&trailing),
                Err(JournalError::Invalid)
            );
        }

        let mut unknown_target = orphan_journal().encode().unwrap();
        let mut decoder = Decoder::new(&unknown_target);
        assert_eq!(decoder.array().unwrap(), Some(6));
        assert_eq!(decoder.u16().unwrap(), JOURNAL_VERSION);
        let kind_start = decoder.position();
        assert_eq!(decoder.u16().unwrap(), ORPHAN_TARGET);
        let kind_end = decoder.position();
        unknown_target[kind_end - 1] = 9;
        assert!(kind_end - kind_start <= 3);
        assert_eq!(
            CleanupJournal::decode(&unknown_target),
            Err(JournalError::Invalid)
        );

        let legacy = paired.encode_legacy().unwrap();
        assert_eq!(CleanupJournal::decode(&legacy).unwrap(), paired);
    }

    #[test]
    fn journal_rejects_relative_and_mismatched_targets() {
        let mut value = paired_journal(PathBuf::from("relative.txt"));
        assert_eq!(
            CleanupJournal::decode(&value.encode().unwrap()),
            Err(JournalError::Invalid)
        );
        let CleanupTarget::Paired { stub, stub_path } = &mut value.target else {
            unreachable!();
        };
        *stub_path = absolute("identity.txt");
        let mut other = stub.clone();
        other.desktop_id[0] ^= 1;
        assert!(!value.targets(&other));

        let mut orphan = orphan_journal();
        orphan.locator_path = PathBuf::from("relative.cbor");
        assert_eq!(
            CleanupJournal::decode(&orphan.encode().unwrap()),
            Err(JournalError::Invalid)
        );
    }

    #[cfg(windows)]
    #[test]
    fn persisted_journal_blocks_only_the_bound_pairing() {
        let root = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap()).join(format!(
            "age-phone-cleanup-journal-test-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut OsRng),
        ));
        age_plugin_phone_windows_storage::ensure_private_directory(&root).unwrap();
        let value = CleanupJournal {
            target: CleanupTarget::Paired {
                stub: stub(),
                stub_path: root.join("identity.txt"),
            },
            locator_path: root.join("locator.cbor"),
            desktop_state: root.join("desktop.state"),
            replay_state: root.join("replay.state"),
        };
        create(&root, &value).unwrap();
        let value_stub = value.paired().unwrap().0.clone();
        assert_eq!(
            ensure_pairing_available(&root, &value_stub),
            Err(JournalError::Pending)
        );
        let mut other = value_stub;
        other.desktop_id[0] ^= 1;
        assert_eq!(ensure_pairing_available(&root, &other), Ok(()));
        age_plugin_phone_windows_storage::remove_private_file(&journal_path(&root)).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
}
