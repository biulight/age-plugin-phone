//! Fail-closed desktop half of the pairing confirmation boundary.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use age_plugin_phone_protocol::{
    ALGORITHM_SUITE, EncodedPublicKey, Id, P256Signer, PairingOffer, ProtocolDigest, ProtocolNonce,
    SignedPairingOffer, SignedPairingResponse, pairing_fingerprint,
};
use age_plugin_phone_recipient_p256::{PLUGIN_NAME, PairedRecipient, Recipient};
use bech32::{FromBase32 as _, ToBase32 as _, Variant};
use minicbor::{Decoder, Encoder};
use p256::ecdsa::SigningKey;
use rand_core::{CryptoRng, RngCore};
use std::{
    fs::{File, OpenOptions},
    io::{Read as _, Write as _},
    path::Path,
};
use thiserror::Error;

/// Pairing sessions are deliberately short lived and never resume after a terminal action.
pub const MAX_PAIRING_SESSION_AGE_MS: u64 = 5 * 60 * 1_000;
const STUB_VERSION: u16 = 2;
const DESKTOP_KEY_MAGIC: &[u8; 5] = b"APDK2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentityStub {
    pub desktop_id: Id,
    pub identity_id: Id,
    pub recipient: String,
    pub desktop_signing_public_key: EncodedPublicKey,
    pub desktop_selection_public_key: EncodedPublicKey,
    pub phone_signing_public_key: EncodedPublicKey,
    pub offer_digest: ProtocolDigest,
    pub transcript_fingerprint: ProtocolDigest,
}

impl PublicIdentityStub {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(11)
            .unwrap()
            .u16(STUB_VERSION)
            .unwrap()
            .u16(ALGORITHM_SUITE)
            .unwrap()
            .bytes(&self.desktop_id)
            .unwrap()
            .bytes(&self.identity_id)
            .unwrap()
            .str(&self.recipient)
            .unwrap()
            .bytes(&self.desktop_signing_public_key)
            .unwrap()
            .bytes(&self.desktop_selection_public_key)
            .unwrap()
            .bytes(&self.phone_signing_public_key)
            .unwrap()
            .bytes(&self.offer_digest)
            .unwrap()
            .bytes(&self.transcript_fingerprint)
            .unwrap()
            .str(PLUGIN_NAME)
            .unwrap();
        encoder.into_writer()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| PairingError::MalformedStub)? != Some(11) {
            return Err(PairingError::MalformedStub);
        }
        if decoder.u16().map_err(|_| PairingError::MalformedStub)? != STUB_VERSION {
            return Err(PairingError::UnsupportedStub);
        }
        if decoder.u16().map_err(|_| PairingError::MalformedStub)? != ALGORITHM_SUITE {
            return Err(PairingError::UnsupportedStub);
        }
        let value = Self {
            desktop_id: fixed(decoder.bytes().map_err(|_| PairingError::MalformedStub)?)?,
            identity_id: fixed(decoder.bytes().map_err(|_| PairingError::MalformedStub)?)?,
            recipient: decoder
                .str()
                .map_err(|_| PairingError::MalformedStub)?
                .to_owned(),
            desktop_signing_public_key: fixed(
                decoder.bytes().map_err(|_| PairingError::MalformedStub)?,
            )?,
            desktop_selection_public_key: fixed(
                decoder.bytes().map_err(|_| PairingError::MalformedStub)?,
            )?,
            phone_signing_public_key: fixed(
                decoder.bytes().map_err(|_| PairingError::MalformedStub)?,
            )?,
            offer_digest: fixed(decoder.bytes().map_err(|_| PairingError::MalformedStub)?)?,
            transcript_fingerprint: fixed(
                decoder.bytes().map_err(|_| PairingError::MalformedStub)?,
            )?,
        };
        if decoder.str().map_err(|_| PairingError::MalformedStub)? != PLUGIN_NAME
            || decoder.position() != bytes.len()
            || value.encode() != bytes
            || Recipient::parse(&value.recipient).is_err()
            || p256::ecdsa::VerifyingKey::from_sec1_bytes(&value.desktop_signing_public_key)
                .is_err()
            || p256::PublicKey::from_sec1_bytes(&value.desktop_selection_public_key).is_err()
            || value.desktop_selection_public_key == value.desktop_signing_public_key
            || p256::ecdsa::VerifyingKey::from_sec1_bytes(&value.phone_signing_public_key).is_err()
        {
            return Err(PairingError::MalformedStub);
        }
        Ok(value)
    }

    /// Standard public age recipient corresponding to the phone's non-exportable identity.
    #[must_use]
    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    /// Pairing-specific recipient that enables private desktop stanza selection.
    pub fn paired_recipient(&self) -> Result<PairedRecipient, PairingError> {
        let phone = Recipient::parse(&self.recipient).map_err(|_| PairingError::MalformedStub)?;
        PairedRecipient::from_public_fields(
            &phone.public_key_bytes(),
            &self.desktop_selection_public_key,
            self.identity_id,
        )
        .map_err(|_| PairingError::MalformedStub)
    }

    /// Canonical v2 public recipient for new encryption.
    pub fn selectable_recipient(&self) -> Result<String, PairingError> {
        self.paired_recipient()?
            .to_string()
            .map_err(|_| PairingError::StubEncoding)
    }

    /// Public age-plugin identity stub. It contains no desktop or phone private key.
    pub fn plugin_identity(&self) -> Result<String, PairingError> {
        bech32::encode(
            "age-plugin-phone-",
            self.encode().to_base32(),
            Variant::Bech32,
        )
        .map(|value| value.to_ascii_uppercase())
        .map_err(|_| PairingError::StubEncoding)
    }

    /// Human-readable age identity file containing only public pairing material.
    pub fn identity_file(&self) -> Result<String, PairingError> {
        Ok(format!(
            "# public age-plugin-phone identity stub\n# recipient: {}\n{}\n",
            self.selectable_recipient()?,
            self.plugin_identity()?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingDisplay {
    pub desktop_label: String,
    pub transcript_fingerprint: String,
}

/// Persistent desktop authentication state. This is role-separated from the phone age identity.
pub struct DesktopKeyState {
    pub desktop_id: Id,
    signing_key: SigningKey,
    selection_key: SigningKey,
}

impl DesktopKeyState {
    pub fn open_or_create(
        path: &Path,
        random: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, PairingError> {
        match Self::open(path) {
            Ok(value) => Ok(value),
            Err(PairingError::StateMissing) => Self::create(path, random),
            Err(error) => Err(error),
        }
    }

    pub fn open(path: &Path) -> Result<Self, PairingError> {
        let mut file = File::open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                PairingError::StateMissing
            } else {
                PairingError::State
            }
        })?;
        validate_private_file(&file)?;
        let mut encoded = [0_u8; 85];
        file.read_exact(&mut encoded)
            .map_err(|_| PairingError::State)?;
        let mut trailing = [0_u8; 1];
        if file.read(&mut trailing).map_err(|_| PairingError::State)? != 0
            || &encoded[..5] != DESKTOP_KEY_MAGIC
        {
            return Err(PairingError::State);
        }
        let desktop_id = encoded[5..21].try_into().map_err(|_| PairingError::State)?;
        let signing_key =
            SigningKey::from_slice(&encoded[21..53]).map_err(|_| PairingError::State)?;
        let selection_key =
            SigningKey::from_slice(&encoded[53..]).map_err(|_| PairingError::State)?;
        if signing_key.verifying_key() == selection_key.verifying_key() {
            encoded[21..].fill(0);
            return Err(PairingError::State);
        }
        encoded[21..].fill(0);
        Ok(Self {
            desktop_id,
            signing_key,
            selection_key,
        })
    }

    fn create(path: &Path, random: &mut (impl CryptoRng + RngCore)) -> Result<Self, PairingError> {
        let mut desktop_id = [0; 16];
        random.fill_bytes(&mut desktop_id);
        let signing_key = SigningKey::random(random);
        let selection_key = SigningKey::random(&mut *random);
        if signing_key.verifying_key() == selection_key.verifying_key() {
            return Err(PairingError::State);
        }
        let mut encoded = [0_u8; 85];
        encoded[..5].copy_from_slice(DESKTOP_KEY_MAGIC);
        encoded[5..21].copy_from_slice(&desktop_id);
        encoded[21..53].copy_from_slice(&signing_key.to_bytes());
        encoded[53..].copy_from_slice(&selection_key.to_bytes());
        let result = create_private_file(path, &encoded);
        encoded[21..].fill(0);
        result?;
        Ok(Self {
            desktop_id,
            signing_key,
            selection_key,
        })
    }

    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    #[must_use]
    pub fn selection_key(&self) -> &SigningKey {
        &self.selection_key
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PairingError {
    #[error("pairing session was cancelled or already consumed")]
    SessionClosed,
    #[error("pairing session timed out")]
    Timeout,
    #[error("phone response is malformed, unauthenticated, or bound to another desktop")]
    InvalidResponse,
    #[error("transcript fingerprint confirmation did not match")]
    FingerprintMismatch,
    #[error("malformed public identity stub")]
    MalformedStub,
    #[error("unsupported public identity stub")]
    UnsupportedStub,
    #[error("failed to encode public identity stub")]
    StubEncoding,
    #[error("desktop authentication state does not exist")]
    StateMissing,
    #[error("desktop authentication state is unavailable, malformed, or insecure")]
    State,
    #[error("identity stub already exists or could not be durably created")]
    StubStorage,
}

pub fn create_identity_stub_file(
    path: &Path,
    stub: &PublicIdentityStub,
) -> Result<(), PairingError> {
    let text = stub.identity_file()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| PairingError::StubStorage)?;
    if file.write_all(text.as_bytes()).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(PairingError::StubStorage);
    }
    Ok(())
}

pub fn read_identity_stub_file(path: &Path) -> Result<PublicIdentityStub, PairingError> {
    let text = std::fs::read_to_string(path).map_err(|_| PairingError::StubStorage)?;
    let identity = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or(PairingError::MalformedStub)?;
    let (hrp, data, variant) =
        bech32::decode(&identity.to_ascii_lowercase()).map_err(|_| PairingError::MalformedStub)?;
    if hrp != "age-plugin-phone-" || variant != Variant::Bech32 {
        return Err(PairingError::MalformedStub);
    }
    let bytes = Vec::<u8>::from_base32(&data).map_err(|_| PairingError::MalformedStub)?;
    PublicIdentityStub::decode(&bytes)
}

enum State {
    Waiting,
    Confirming {
        response: Box<SignedPairingResponse>,
        fingerprint: ProtocolDigest,
    },
    Closed,
}

/// One in-memory pairing attempt. Any cancellation, timeout, mismatch, or duplicate action closes it.
pub struct DesktopPairingSession {
    offer: SignedPairingOffer,
    started_at_ms: u64,
    state: State,
}

impl DesktopPairingSession {
    pub fn begin(
        desktop_id: Id,
        desktop_label: String,
        signing_key: &impl P256Signer,
        desktop_selection_public_key: EncodedPublicKey,
        now_ms: u64,
        random: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, PairingError> {
        let mut nonce: ProtocolNonce = [0; 32];
        random.fill_bytes(&mut nonce);
        let public_key = signing_key
            .public_key()
            .map_err(|_| PairingError::InvalidResponse)?;
        let offer = SignedPairingOffer::sign(
            PairingOffer {
                desktop_id,
                desktop_label,
                desktop_signing_public_key: public_key,
                desktop_selection_public_key,
                nonce,
            },
            signing_key,
        )
        .map_err(|_| PairingError::InvalidResponse)?;
        Ok(Self {
            offer,
            started_at_ms: now_ms,
            state: State::Waiting,
        })
    }

    #[must_use]
    pub fn signed_offer(&self) -> Vec<u8> {
        self.offer.encode()
    }

    pub fn receive_response(
        &mut self,
        encoded: &[u8],
        now_ms: u64,
    ) -> Result<PairingDisplay, PairingError> {
        self.ensure_live(now_ms)?;
        if !matches!(self.state, State::Waiting) {
            self.state = State::Closed;
            return Err(PairingError::SessionClosed);
        }
        let response = SignedPairingResponse::decode(encoded)
            .and_then(|response| {
                response.verify(&self.offer)?;
                Ok(response)
            })
            .map_err(|_| {
                self.state = State::Closed;
                PairingError::InvalidResponse
            })?;
        let fingerprint = pairing_fingerprint(&self.offer, &response);
        let display = PairingDisplay {
            desktop_label: self.offer.payload.desktop_label.clone(),
            transcript_fingerprint: hex(&fingerprint),
        };
        self.state = State::Confirming {
            response: Box::new(response),
            fingerprint,
        };
        Ok(display)
    }

    pub fn confirm(
        &mut self,
        displayed_fingerprint: &str,
        now_ms: u64,
    ) -> Result<PublicIdentityStub, PairingError> {
        self.ensure_live(now_ms)?;
        let state = std::mem::replace(&mut self.state, State::Closed);
        let State::Confirming {
            response,
            fingerprint,
        } = state
        else {
            return Err(PairingError::SessionClosed);
        };
        if displayed_fingerprint != hex(&fingerprint) {
            return Err(PairingError::FingerprintMismatch);
        }
        Ok(PublicIdentityStub {
            desktop_id: self.offer.payload.desktop_id,
            identity_id: response.payload.identity_id,
            recipient: response.payload.recipient,
            desktop_signing_public_key: self.offer.payload.desktop_signing_public_key,
            desktop_selection_public_key: self.offer.payload.desktop_selection_public_key,
            phone_signing_public_key: response.payload.phone_signing_public_key,
            offer_digest: self.offer.digest(),
            transcript_fingerprint: fingerprint,
        })
    }

    pub fn cancel(&mut self) {
        self.state = State::Closed;
    }

    fn ensure_live(&mut self, now_ms: u64) -> Result<(), PairingError> {
        if matches!(self.state, State::Closed) {
            return Err(PairingError::SessionClosed);
        }
        if now_ms < self.started_at_ms || now_ms - self.started_at_ms > MAX_PAIRING_SESSION_AGE_MS {
            self.state = State::Closed;
            return Err(PairingError::Timeout);
        }
        Ok(())
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PairingError> {
    bytes.try_into().map_err(|_| PairingError::MalformedStub)
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

#[cfg(unix)]
fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), PairingError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| PairingError::State)?;
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(PairingError::State);
    }
    validate_private_file(&file)
}

#[cfg(not(unix))]
fn create_private_file(_path: &Path, _bytes: &[u8]) -> Result<(), PairingError> {
    Err(PairingError::State)
}

#[cfg(unix)]
fn validate_private_file(file: &File) -> Result<(), PairingError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = file.metadata().map_err(|_| PairingError::State)?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(PairingError::State);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file(_file: &File) -> Result<(), PairingError> {
    Err(PairingError::State)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age_plugin_phone_protocol::{PairingResponse, SignedPairingResponse};
    use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint as _};
    use rand_core::OsRng;

    fn signing(value: u8) -> SigningKey {
        let mut bytes = [0; 32];
        bytes[31] = value;
        SigningKey::from_bytes((&bytes).into()).unwrap()
    }

    fn selection_public() -> EncodedPublicKey {
        signing(9)
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn response(session: &DesktopPairingSession, phone: &SigningKey) -> SignedPairingResponse {
        let identity = SecretKey::random(&mut OsRng);
        SignedPairingResponse::sign(
            PairingResponse {
                identity_id: [2; 16],
                recipient: Recipient::from_public_key_bytes(
                    identity.public_key().to_encoded_point(true).as_bytes(),
                )
                .unwrap()
                .to_string()
                .unwrap(),
                phone_signing_public_key: phone
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                offer_digest: session.offer.digest(),
                nonce: [3; 32],
            },
            phone,
        )
        .unwrap()
    }

    #[test]
    fn verifies_compares_and_creates_public_stub_once() {
        let desktop = signing(1);
        let phone = signing(2);
        let mut session = DesktopPairingSession::begin(
            [1; 16],
            "untrusted desktop".into(),
            &desktop,
            selection_public(),
            100,
            &mut OsRng,
        )
        .unwrap();
        let display = session
            .receive_response(&response(&session, &phone).encode(), 101)
            .unwrap();
        let stub = session
            .confirm(&display.transcript_fingerprint, 102)
            .unwrap();
        assert_eq!(PublicIdentityStub::decode(&stub.encode()).unwrap(), stub);
        assert_eq!(
            stub.plugin_identity().unwrap(),
            stub.plugin_identity().unwrap().to_uppercase()
        );
        let identity_file = stub.identity_file().unwrap();
        assert!(identity_file.contains(&stub.selectable_recipient().unwrap()));
        assert!(identity_file.contains(&stub.plugin_identity().unwrap()));
        assert_eq!(
            session.confirm(&display.transcript_fingerprint, 103),
            Err(PairingError::SessionClosed)
        );
    }

    #[test]
    fn cancellation_timeout_wrong_device_malformed_and_mismatch_fail_closed() {
        let desktop = signing(1);
        let phone = signing(2);
        let mut cancelled = DesktopPairingSession::begin(
            [1; 16],
            "d".into(),
            &desktop,
            selection_public(),
            10,
            &mut OsRng,
        )
        .unwrap();
        cancelled.cancel();
        assert_eq!(
            cancelled.receive_response(&[], 11),
            Err(PairingError::SessionClosed)
        );

        let mut timed = DesktopPairingSession::begin(
            [1; 16],
            "d".into(),
            &desktop,
            selection_public(),
            10,
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(
            timed.receive_response(&[], 10 + MAX_PAIRING_SESSION_AGE_MS + 1),
            Err(PairingError::Timeout)
        );

        let mut target = DesktopPairingSession::begin(
            [1; 16],
            "d".into(),
            &desktop,
            selection_public(),
            10,
            &mut OsRng,
        )
        .unwrap();
        let other = DesktopPairingSession::begin(
            [9; 16],
            "other".into(),
            &desktop,
            selection_public(),
            10,
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(
            target.receive_response(&response(&other, &phone).encode(), 11),
            Err(PairingError::InvalidResponse)
        );
        assert_eq!(
            target.receive_response(&[], 12),
            Err(PairingError::SessionClosed)
        );

        let mut malformed = DesktopPairingSession::begin(
            [1; 16],
            "d".into(),
            &desktop,
            selection_public(),
            10,
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(
            malformed.receive_response(&[0xff], 11),
            Err(PairingError::InvalidResponse)
        );

        let mut mismatch = DesktopPairingSession::begin(
            [1; 16],
            "d".into(),
            &desktop,
            selection_public(),
            10,
            &mut OsRng,
        )
        .unwrap();
        mismatch
            .receive_response(&response(&mismatch, &phone).encode(), 11)
            .unwrap();
        assert_eq!(
            mismatch.confirm(&"0".repeat(64), 12),
            Err(PairingError::FingerprintMismatch)
        );
        assert_eq!(
            mismatch.confirm(&"0".repeat(64), 13),
            Err(PairingError::SessionClosed)
        );
    }

    #[test]
    fn stub_rejects_extra_unknown_and_private_material() {
        let desktop = signing(1);
        let phone = signing(2);
        let mut session = DesktopPairingSession::begin(
            [1; 16],
            "d".into(),
            &desktop,
            selection_public(),
            10,
            &mut OsRng,
        )
        .unwrap();
        let display = session
            .receive_response(&response(&session, &phone).encode(), 11)
            .unwrap();
        let stub = session
            .confirm(&display.transcript_fingerprint, 12)
            .unwrap();
        let mut trailing = stub.encode();
        trailing.push(0);
        assert_eq!(
            PublicIdentityStub::decode(&trailing),
            Err(PairingError::MalformedStub)
        );
        let mut old_stub = stub.encode();
        old_stub[1] = 1;
        assert_eq!(
            PublicIdentityStub::decode(&old_stub),
            Err(PairingError::UnsupportedStub)
        );
        assert!(
            !stub
                .encode()
                .windows(32)
                .any(|window| window == desktop.to_bytes().as_slice())
        );
    }

    #[cfg(unix)]
    #[test]
    fn desktop_authentication_state_reopens_and_files_never_overwrite() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!(
            "age-phone-pairing-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&root).unwrap();
        let key_path = root.join("desktop.key");
        let identity_path = root.join("identity.txt");
        let first = DesktopKeyState::open_or_create(&key_path, &mut OsRng).unwrap();
        let reopened = DesktopKeyState::open(&key_path).unwrap();
        assert_eq!(first.desktop_id, reopened.desktop_id);
        assert_eq!(
            first.signing_key.to_bytes(),
            reopened.signing_key.to_bytes()
        );
        assert_eq!(
            first.selection_key.to_bytes(),
            reopened.selection_key.to_bytes()
        );
        assert_ne!(
            first.signing_key.verifying_key(),
            first.selection_key.verifying_key()
        );
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600,
        );
        let old_key_path = root.join("desktop-v1.key");
        let mut old_state = std::fs::read(&key_path).unwrap();
        old_state[..5].copy_from_slice(b"APDK1");
        old_state.truncate(53);
        create_private_file(&old_key_path, &old_state).unwrap();
        old_state[21..].fill(0);
        assert!(matches!(
            DesktopKeyState::open(&old_key_path),
            Err(PairingError::State)
        ));

        let phone = signing(2);
        let mut session = DesktopPairingSession::begin(
            first.desktop_id,
            "d".into(),
            first.signing_key(),
            first
                .selection_key()
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            10,
            &mut OsRng,
        )
        .unwrap();
        let encoded = response(&session, &phone).encode();
        let display = session.receive_response(&encoded, 11).unwrap();
        let stub = session
            .confirm(&display.transcript_fingerprint, 12)
            .unwrap();
        create_identity_stub_file(&identity_path, &stub).unwrap();
        assert_eq!(read_identity_stub_file(&identity_path).unwrap(), stub);
        assert_eq!(
            create_identity_stub_file(&identity_path, &stub),
            Err(PairingError::StubStorage),
        );

        std::fs::remove_file(identity_path).unwrap();
        std::fs::remove_file(old_key_path).unwrap();
        std::fs::remove_file(key_path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
