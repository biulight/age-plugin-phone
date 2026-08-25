//! Desktop request/response state for one phone-authorized file-key unwrap.

#![allow(clippy::missing_errors_doc)]

use std::time::{SystemTime, UNIX_EPOCH};

use age_plugin_phone_protocol::{
    FileReplayGuard, MAX_REQUEST_LIFETIME_SECS, PairingRecord, ProtocolNonce, SignedUnwrapResponse,
    UnwrapRequest, VerifiedRequest, create_request, open_response,
};
use age_plugin_phone_recipient_p256::TaggedStanza;
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint as _};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::pairing::{DesktopKeyState, PublicIdentityStub};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwrapDisplay {
    pub request_fingerprint: String,
    pub expires_at_unix: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UnwrapError {
    #[error("desktop authentication state does not match the public identity stub")]
    WrongDesktopState,
    #[error("failed to create a bound unwrap request")]
    Request,
    #[error("unwrap session was already consumed or cancelled")]
    SessionClosed,
    #[error("phone response was malformed, expired, replayed, or bound to another request")]
    InvalidResponse,
    #[error("system clock is unavailable")]
    Clock,
}

/// One request with one fresh desktop response-encryption key.
pub struct DesktopUnwrapSession {
    request: VerifiedRequest,
    desktop_session: SecretKey,
    pairing: PairingRecord,
    closed: bool,
}

impl DesktopUnwrapSession {
    pub fn begin(
        stub: &PublicIdentityStub,
        desktop: &DesktopKeyState,
        stanza: TaggedStanza,
        caller_hint: Option<String>,
        now_unix: u64,
        random: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, UnwrapError> {
        if desktop.desktop_id != stub.desktop_id
            || desktop
                .signing_public_key()
                .map_err(|_| UnwrapError::WrongDesktopState)?
                != stub.desktop_signing_public_key
            || desktop
                .selection_public_key()
                .map_err(|_| UnwrapError::WrongDesktopState)?
                != stub.desktop_selection_public_key
        {
            return Err(UnwrapError::WrongDesktopState);
        }
        let pairing = PairingRecord {
            desktop_id: stub.desktop_id,
            identity_id: stub.identity_id,
            desktop_signing_public_key: stub.desktop_signing_public_key,
            desktop_selection_public_key: stub.desktop_selection_public_key,
            phone_signing_public_key: stub.phone_signing_public_key,
        };
        let desktop_session = SecretKey::random(&mut *random);
        let session_public = desktop_session.public_key().to_encoded_point(true);
        let mut request_id = [0; 16];
        let mut nonce: ProtocolNonce = [0; 32];
        random.fill_bytes(&mut request_id);
        random.fill_bytes(&mut nonce);
        let request = create_request(
            UnwrapRequest {
                request_id,
                identity_id: stub.identity_id,
                desktop_id: stub.desktop_id,
                session_public_key: session_public
                    .as_bytes()
                    .try_into()
                    .map_err(|_| UnwrapError::Request)?,
                recipient_stanza: stanza,
                nonce,
                expires_at_unix: now_unix.saturating_add(MAX_REQUEST_LIFETIME_SECS),
                caller_hint,
            },
            desktop.signer(),
            &pairing,
            now_unix,
        )
        .map_err(|_| UnwrapError::Request)?;
        Ok(Self {
            request,
            desktop_session,
            pairing,
            closed: false,
        })
    }

    #[must_use]
    pub fn signed_request(&self) -> Vec<u8> {
        self.request.encode()
    }

    #[must_use]
    pub fn display(&self) -> UnwrapDisplay {
        UnwrapDisplay {
            request_fingerprint: hex(&self.request.digest()),
            expires_at_unix: self.request.payload().expires_at_unix,
        }
    }

    pub fn receive_response(
        &mut self,
        encoded: &[u8],
        replay: &mut FileReplayGuard,
        now_unix: u64,
    ) -> Result<Zeroizing<[u8; 16]>, UnwrapError> {
        if self.closed {
            return Err(UnwrapError::SessionClosed);
        }
        self.closed = true;
        let response =
            SignedUnwrapResponse::decode(encoded).map_err(|_| UnwrapError::InvalidResponse)?;
        open_response(
            &response,
            &self.request,
            &self.pairing,
            &self.desktop_session,
            replay,
            now_unix,
        )
        .map_err(|_| UnwrapError::InvalidResponse)
    }

    pub fn cancel(&mut self) {
        self.closed = true;
    }
}

pub fn now_unix() -> Result<u64, UnwrapError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| UnwrapError::Clock)
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

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use age_plugin_phone_protocol::{
        ReplayGuard, ReplayRole, ReplayScope, SignedUnwrapRequest, seal_response,
    };
    use age_plugin_phone_recipient_p256::{Recipient, unwrap_file_key, wrap_file_key};
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    fn fixture() -> (
        std::path::PathBuf,
        DesktopKeyState,
        PublicIdentityStub,
        SecretKey,
        SigningKey,
        TaggedStanza,
        [u8; 16],
    ) {
        let root = std::env::temp_dir().join(format!(
            "age-phone-unwrap-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&root).unwrap();
        let desktop =
            DesktopKeyState::open_or_create(&root.join("desktop.key"), &mut OsRng).unwrap();
        let identity = SecretKey::random(&mut OsRng);
        let recipient = Recipient::from_public_key_bytes(
            identity.public_key().to_encoded_point(true).as_bytes(),
        )
        .unwrap();
        let phone = SigningKey::random(&mut OsRng);
        let stub = PublicIdentityStub {
            desktop_id: desktop.desktop_id,
            identity_id: [7; 16],
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
            offer_digest: [8; 32],
            transcript_fingerprint: [9; 32],
        };
        let file_key = [0x42; 16];
        let stanza = wrap_file_key(&recipient, &file_key, &mut OsRng).unwrap();
        (root, desktop, stub, identity, phone, stanza, file_key)
    }

    fn pairing(stub: &PublicIdentityStub) -> PairingRecord {
        PairingRecord {
            desktop_id: stub.desktop_id,
            identity_id: stub.identity_id,
            desktop_signing_public_key: stub.desktop_signing_public_key,
            desktop_selection_public_key: stub.desktop_selection_public_key,
            phone_signing_public_key: stub.phone_signing_public_key,
        }
    }

    #[test]
    fn completes_one_bound_response_with_durable_consumption() {
        let (root, desktop, stub, identity, phone, stanza, expected) = fixture();
        let now = 1_000_000;
        let mut session = DesktopUnwrapSession::begin(
            &stub,
            &desktop,
            stanza,
            Some("untrusted caller".into()),
            now,
            &mut OsRng,
        )
        .unwrap();
        let request = SignedUnwrapRequest::decode(&session.signed_request()).unwrap();
        let verified = ReplayGuard::default()
            .verify_request(request, &pairing(&stub), now)
            .unwrap();
        let file_key = unwrap_file_key(&identity, &verified.payload().recipient_stanza).unwrap();
        let response = seal_response(&verified, &file_key, &phone, &mut OsRng).unwrap();
        let replay_path = root.join("responses.cbor");
        let mut replay = FileReplayGuard::create(
            &replay_path,
            ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing(&stub)),
            4,
            now,
        )
        .unwrap();
        assert_eq!(
            *session
                .receive_response(&response.encode(), &mut replay, now)
                .unwrap(),
            expected
        );
        assert_eq!(
            session.receive_response(&response.encode(), &mut replay, now),
            Err(UnwrapError::SessionClosed),
        );
        drop(replay);
        std::fs::remove_file(&replay_path).unwrap();
        std::fs::remove_file(root.join("responses.cbor.lock")).unwrap();
        std::fs::remove_file(root.join("desktop.key")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn rejects_wrong_desktop_and_cancellation() {
        let (root, desktop, stub, _, _, stanza, _) = fixture();
        let mut wrong_stub = stub.clone();
        wrong_stub.desktop_id[0] ^= 1;
        assert!(matches!(
            DesktopUnwrapSession::begin(
                &wrong_stub,
                &desktop,
                stanza.clone(),
                None,
                10,
                &mut OsRng
            ),
            Err(UnwrapError::WrongDesktopState),
        ));
        let mut session =
            DesktopUnwrapSession::begin(&stub, &desktop, stanza, None, 10, &mut OsRng).unwrap();
        session.cancel();
        let replay_path = root.join("responses.cbor");
        let mut replay = FileReplayGuard::create(
            &replay_path,
            ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing(&stub)),
            4,
            10,
        )
        .unwrap();
        assert_eq!(
            session.receive_response(&[0xff], &mut replay, 11),
            Err(UnwrapError::SessionClosed)
        );
        drop(replay);
        std::fs::remove_file(&replay_path).unwrap();
        std::fs::remove_file(root.join("responses.cbor.lock")).unwrap();
        std::fs::remove_file(root.join("desktop.key")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
