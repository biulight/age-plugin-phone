//! Experimental canonical offline protocol described by ADR 0002.

#![allow(clippy::missing_errors_doc)]

use age_plugin_phone_recipient_p256::{Recipient, TaggedStanza, validate_stanza};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit as _, Nonce,
    aead::{Aead as _, Payload},
};
use hkdf::Hkdf;
use minicbor::{Decoder, Encoder, data::Type};
use p256::{
    PublicKey, SecretKey,
    ecdh::{EphemeralSecret, diffie_hellman},
    ecdsa::{Signature, SigningKey, VerifyingKey, signature::Verifier as _},
    elliptic_curve::sec1::ToEncodedPoint as _,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

mod qr;
mod replay;

pub use qr::{
    DEFAULT_QR_CHUNK_BYTES, EncodedQrFrame, MAX_QR_ASSEMBLY_AGE_MS, MAX_QR_FRAGMENTS,
    MAX_QR_MESSAGE_BYTES, QrAssemblyStatus, QrError, QrReassembler, fragment_qr_message,
};
#[cfg(any(unix, windows))]
pub use replay::FileReplayGuard;
pub use replay::{DEFAULT_REPLAY_CAPACITY, ReplayGuard, ReplayRole, ReplayScope, ReplayStore};

pub const PROTOCOL_VERSION: u16 = 2;
pub const ALGORITHM_SUITE: u16 = 1;
pub const MAX_REQUEST_LIFETIME_SECS: u64 = 300;
pub type Id = [u8; 16];
pub type ProtocolNonce = [u8; 32];
pub type ProtocolDigest = [u8; 32];
pub type EncodedPublicKey = [u8; 33];

/// Role-agnostic P-256 signing boundary for software test keys and platform-backed keys.
///
/// Implementations receive an already hashed SHA-256 digest and must return a fixed-width,
/// low-S IEEE P1363 signature. Production desktop implementations must keep the private key in
/// platform hardware; [`SigningKey`] is retained for deterministic vectors and tests.
pub trait P256Signer {
    /// Returns the canonical compressed SEC1 public key.
    fn public_key(&self) -> Result<EncodedPublicKey, Error>;

    /// Signs one SHA-256 digest and returns canonical `r || s` bytes.
    fn sign_prehash(&self, digest: &ProtocolDigest) -> Result<[u8; 64], Error>;
}

impl P256Signer for SigningKey {
    fn public_key(&self) -> Result<EncodedPublicKey, Error> {
        Ok(public_signing(self.verifying_key()))
    }

    fn sign_prehash(&self, digest: &ProtocolDigest) -> Result<[u8; 64], Error> {
        let signature: Signature = <SigningKey as p256::ecdsa::signature::hazmat::PrehashSigner<
            Signature,
        >>::sign_prehash(self, digest)
        .map_err(|_| Error::KeyOperation)?;
        Ok(signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .into())
    }
}

const OFFER: u16 = 1;
const PAIRING_RESPONSE: u16 = 2;
const REQUEST: u16 = 3;
const RESPONSE: u16 = 4;
const OFFER_SIG: &[u8] = b"age-plugin-phone/pairing-offer-signature/v2";
const PAIRING_SIG: &[u8] = b"age-plugin-phone/pairing-response-signature/v2";
const REQUEST_SIG: &[u8] = b"age-plugin-phone/unwrap-request-signature/v2";
const RESPONSE_SIG: &[u8] = b"age-plugin-phone/unwrap-response-signature/v2";
const REQUEST_DIGEST: &[u8] = b"age-plugin-phone/request-digest/v2";
const OFFER_DIGEST: &[u8] = b"age-plugin-phone/pairing-offer-digest/v2";
const FINGERPRINT: &[u8] = b"age-plugin-phone/pairing-fingerprint/v2";
const SESSION_INFO: &[u8] = b"age-plugin-phone/session-response/p256/v2";

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("malformed or non-canonical protocol message")]
    Malformed,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("unsupported algorithm suite")]
    UnsupportedSuite,
    #[error("unexpected message type")]
    UnexpectedMessageType,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("wrong paired desktop")]
    WrongDesktop,
    #[error("wrong phone identity")]
    WrongIdentity,
    #[error("request expired")]
    Expired,
    #[error("request lifetime exceeds policy")]
    LifetimeTooLong,
    #[error("replayed request or response")]
    Replay,
    #[error("wall clock moved backwards relative to replay state")]
    ClockRollback,
    #[error("replay-state capacity exhausted")]
    ReplayCapacity,
    #[error("replay state is unavailable, corrupt, mismatched, or not durable")]
    ReplayState,
    #[error("invalid recipient stanza")]
    InvalidRecipientStanza,
    #[error("response binding mismatch")]
    BindingMismatch,
    #[error("response decryption failed")]
    Decryption,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("platform signing or key-agreement operation failed")]
    KeyOperation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingOffer {
    pub desktop_id: Id,
    pub desktop_label: String,
    pub desktop_signing_public_key: EncodedPublicKey,
    pub desktop_selection_public_key: EncodedPublicKey,
    pub nonce: ProtocolNonce,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPairingOffer {
    pub payload: PairingOffer,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingResponse {
    pub identity_id: Id,
    pub recipient: String,
    pub phone_signing_public_key: EncodedPublicKey,
    pub offer_digest: ProtocolDigest,
    pub nonce: ProtocolNonce,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPairingResponse {
    pub payload: PairingResponse,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwrapRequest {
    pub request_id: Id,
    pub identity_id: Id,
    pub desktop_id: Id,
    pub session_public_key: EncodedPublicKey,
    pub recipient_stanza: TaggedStanza,
    pub nonce: ProtocolNonce,
    pub expires_at_unix: u64,
    pub caller_hint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedUnwrapRequest {
    pub payload: UnwrapRequest,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwrapResponse {
    pub request_id: Id,
    pub request_digest: ProtocolDigest,
    pub identity_id: Id,
    pub desktop_id: Id,
    pub phone_session_public_key: EncodedPublicKey,
    pub nonce: ProtocolNonce,
    pub encrypted_file_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedUnwrapResponse {
    pub payload: UnwrapResponse,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingRecord {
    pub desktop_id: Id,
    pub identity_id: Id,
    pub desktop_signing_public_key: EncodedPublicKey,
    pub desktop_selection_public_key: EncodedPublicKey,
    pub phone_signing_public_key: EncodedPublicKey,
}

#[derive(Clone, Debug)]
pub struct VerifiedRequest {
    signed: SignedUnwrapRequest,
    digest: ProtocolDigest,
}

impl SignedPairingOffer {
    pub fn sign(payload: PairingOffer, key: &(impl P256Signer + ?Sized)) -> Result<Self, Error> {
        label(&payload.desktop_label)?;
        if key.public_key()? != payload.desktop_signing_public_key {
            return Err(Error::InvalidPublicKey);
        }
        public(&payload.desktop_selection_public_key)?;
        if payload.desktop_selection_public_key == payload.desktop_signing_public_key {
            return Err(Error::InvalidPublicKey);
        }
        let signature = sign(key, OFFER_SIG, &encode_offer(&payload))?;
        Ok(Self { payload, signature })
    }
    pub fn verify(&self) -> Result<(), Error> {
        label(&self.payload.desktop_label)?;
        public(&self.payload.desktop_selection_public_key)?;
        if self.payload.desktop_selection_public_key == self.payload.desktop_signing_public_key {
            return Err(Error::InvalidPublicKey);
        }
        verify(
            &verifying(&self.payload.desktop_signing_public_key)?,
            OFFER_SIG,
            &encode_offer(&self.payload),
            &self.signature,
        )
    }
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        signed(&encode_offer(&self.payload), &self.signature)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (p, signature) = decode_signed(bytes)?;
        let value = Self {
            payload: decode_offer(&p)?,
            signature,
        };
        canonical(bytes, &value.encode())?;
        Ok(value)
    }
    #[must_use]
    pub fn digest(&self) -> ProtocolDigest {
        hash(OFFER_DIGEST, &self.encode())
    }
}

impl SignedPairingResponse {
    pub fn sign(payload: PairingResponse, key: &(impl P256Signer + ?Sized)) -> Result<Self, Error> {
        validate_pairing_response(&payload)?;
        if key.public_key()? != payload.phone_signing_public_key {
            return Err(Error::InvalidPublicKey);
        }
        let signature = sign(key, PAIRING_SIG, &encode_pairing_response(&payload))?;
        Ok(Self { payload, signature })
    }
    pub fn verify(&self, offer: &SignedPairingOffer) -> Result<(), Error> {
        offer.verify()?;
        validate_pairing_response(&self.payload)?;
        if self.payload.offer_digest != offer.digest() {
            return Err(Error::BindingMismatch);
        }
        verify(
            &verifying(&self.payload.phone_signing_public_key)?,
            PAIRING_SIG,
            &encode_pairing_response(&self.payload),
            &self.signature,
        )
    }
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        signed(&encode_pairing_response(&self.payload), &self.signature)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (p, signature) = decode_signed(bytes)?;
        let value = Self {
            payload: decode_pairing_response(&p)?,
            signature,
        };
        canonical(bytes, &value.encode())?;
        Ok(value)
    }
}

#[must_use]
pub fn pairing_fingerprint(
    offer: &SignedPairingOffer,
    response: &SignedPairingResponse,
) -> ProtocolDigest {
    let mut transcript = offer.encode();
    transcript.extend(response.encode());
    hash(FINGERPRINT, &transcript)
}

impl SignedUnwrapRequest {
    pub fn sign(payload: UnwrapRequest, key: &(impl P256Signer + ?Sized)) -> Result<Self, Error> {
        validate_request(&payload)?;
        let signature = sign(key, REQUEST_SIG, &encode_request(&payload))?;
        Ok(Self { payload, signature })
    }
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        signed(&encode_request(&self.payload), &self.signature)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (p, signature) = decode_signed(bytes)?;
        let value = Self {
            payload: decode_request(&p)?,
            signature,
        };
        canonical(bytes, &value.encode())?;
        Ok(value)
    }
}

/// Creates a request on the paired desktop and returns its verified transcript representation.
/// This path does not consume phone replay state; the phone must still durably consume it before
/// authorization.
pub fn create_request(
    payload: UnwrapRequest,
    signing_key: &(impl P256Signer + ?Sized),
    pairing: &PairingRecord,
    now: u64,
) -> Result<VerifiedRequest, Error> {
    if payload.desktop_id != pairing.desktop_id {
        return Err(Error::WrongDesktop);
    }
    if payload.identity_id != pairing.identity_id {
        return Err(Error::WrongIdentity);
    }
    if signing_key.public_key()? != pairing.desktop_signing_public_key {
        return Err(Error::InvalidPublicKey);
    }
    if payload.expires_at_unix < now {
        return Err(Error::Expired);
    }
    if payload.expires_at_unix > now.saturating_add(MAX_REQUEST_LIFETIME_SECS) {
        return Err(Error::LifetimeTooLong);
    }
    let signed = SignedUnwrapRequest::sign(payload, signing_key)?;
    let digest = hash(REQUEST_DIGEST, &signed.encode());
    Ok(VerifiedRequest { signed, digest })
}

impl ReplayGuard {
    pub fn verify_request(
        &mut self,
        request: SignedUnwrapRequest,
        pairing: &PairingRecord,
        now: u64,
    ) -> Result<VerifiedRequest, Error> {
        verify_request_with_replay(request, pairing, now, self)
    }
}

pub fn verify_request_with_replay(
    request: SignedUnwrapRequest,
    pairing: &PairingRecord,
    now: u64,
    replay: &mut (impl ReplayStore + ?Sized),
) -> Result<VerifiedRequest, Error> {
    validate_request(&request.payload)?;
    if request.payload.desktop_id != pairing.desktop_id {
        return Err(Error::WrongDesktop);
    }
    if request.payload.identity_id != pairing.identity_id {
        return Err(Error::WrongIdentity);
    }
    if request.payload.expires_at_unix < now {
        return Err(Error::Expired);
    }
    if request.payload.expires_at_unix > now.saturating_add(MAX_REQUEST_LIFETIME_SECS) {
        return Err(Error::LifetimeTooLong);
    }
    verify(
        &verifying(&pairing.desktop_signing_public_key)?,
        REQUEST_SIG,
        &encode_request(&request.payload),
        &request.signature,
    )?;
    let digest = hash(REQUEST_DIGEST, &request.encode());
    replay.consume_request(
        pairing.desktop_id,
        pairing.identity_id,
        request.payload.request_id,
        request.payload.nonce,
        request.payload.expires_at_unix,
        now,
    )?;
    Ok(VerifiedRequest {
        signed: request,
        digest,
    })
}

impl VerifiedRequest {
    #[must_use]
    pub const fn digest(&self) -> ProtocolDigest {
        self.digest
    }
    #[must_use]
    pub const fn payload(&self) -> &UnwrapRequest {
        &self.signed.payload
    }
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.signed.encode()
    }
}

impl SignedUnwrapResponse {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        signed(&encode_response(&self.payload), &self.signature)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (p, signature) = decode_signed(bytes)?;
        let value = Self {
            payload: decode_response(&p)?,
            signature,
        };
        canonical(bytes, &value.encode())?;
        Ok(value)
    }
}

pub fn seal_response(
    request: &VerifiedRequest,
    file_key: &[u8; 16],
    phone_signing: &(impl P256Signer + ?Sized),
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<SignedUnwrapResponse, Error> {
    let ephemeral = EphemeralSecret::random(&mut *rng);
    let phone_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&public(&request.payload().session_public_key)?);
    let mut nonce = [0; 32];
    rng.fill_bytes(&mut nonce);
    seal_shared(
        request,
        file_key,
        phone_signing,
        &phone_public,
        shared.raw_secret_bytes(),
        nonce,
    )
}

pub fn seal_response_with_ephemeral(
    request: &VerifiedRequest,
    file_key: &[u8; 16],
    phone_signing: &(impl P256Signer + ?Sized),
    phone_session: &SecretKey,
    nonce: ProtocolNonce,
) -> Result<SignedUnwrapResponse, Error> {
    let desktop = public(&request.payload().session_public_key)?;
    let shared = diffie_hellman(phone_session.to_nonzero_scalar(), desktop.as_affine());
    seal_shared(
        request,
        file_key,
        phone_signing,
        &phone_session.public_key(),
        shared.raw_secret_bytes(),
        nonce,
    )
}

pub fn open_response(
    response: &SignedUnwrapResponse,
    request: &VerifiedRequest,
    pairing: &PairingRecord,
    desktop_session: &SecretKey,
    replay: &mut (impl ReplayStore + ?Sized),
    now: u64,
) -> Result<Zeroizing<[u8; 16]>, Error> {
    if request.payload().expires_at_unix < now {
        return Err(Error::Expired);
    }
    let p = &response.payload;
    if p.request_id != request.payload().request_id
        || p.request_digest != request.digest()
        || p.identity_id != pairing.identity_id
        || p.desktop_id != pairing.desktop_id
    {
        return Err(Error::BindingMismatch);
    }
    verify(
        &verifying(&pairing.phone_signing_public_key)?,
        RESPONSE_SIG,
        &encode_response(p),
        &response.signature,
    )?;
    let shared = diffie_hellman(
        desktop_session.to_nonzero_scalar(),
        public(&p.phone_session_public_key)?.as_affine(),
    );
    let key = session_key(shared.raw_secret_bytes(), &p.request_digest, &p.nonce)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::KeyDerivation)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&[0; 12]),
                Payload {
                    msg: &p.encrypted_file_key,
                    aad: &response_aad(p),
                },
            )
            .map_err(|_| Error::Decryption)?,
    );
    if plaintext.len() != 16 {
        return Err(Error::Decryption);
    }
    let mut file_key = Zeroizing::new([0; 16]);
    file_key.copy_from_slice(&plaintext);
    replay.consume_response(
        pairing.desktop_id,
        pairing.identity_id,
        hash(RESPONSE_SIG, &response.encode()),
        request.payload().expires_at_unix,
        now,
    )?;
    Ok(file_key)
}

fn seal_shared(
    request: &VerifiedRequest,
    file_key: &[u8; 16],
    phone_signing: &(impl P256Signer + ?Sized),
    phone_public: &PublicKey,
    shared: &[u8],
    nonce: ProtocolNonce,
) -> Result<SignedUnwrapResponse, Error> {
    let mut payload = UnwrapResponse {
        request_id: request.payload().request_id,
        request_digest: request.digest(),
        identity_id: request.payload().identity_id,
        desktop_id: request.payload().desktop_id,
        phone_session_public_key: encode_public(phone_public),
        nonce,
        encrypted_file_key: [0; 32],
    };
    let key = session_key(shared, &payload.request_digest, &payload.nonce)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::KeyDerivation)?;
    payload.encrypted_file_key = cipher
        .encrypt(
            Nonce::from_slice(&[0; 12]),
            Payload {
                msg: file_key,
                aad: &response_aad(&payload),
            },
        )
        .map_err(|_| Error::Decryption)?
        .try_into()
        .map_err(|_| Error::Decryption)?;
    let signature = sign(phone_signing, RESPONSE_SIG, &encode_response(&payload))?;
    Ok(SignedUnwrapResponse { payload, signature })
}

fn validate_request(value: &UnwrapRequest) -> Result<(), Error> {
    public(&value.session_public_key)?;
    validate_stanza(&value.recipient_stanza).map_err(|_| Error::InvalidRecipientStanza)?;
    if let Some(v) = &value.caller_hint {
        label(v)?;
    }
    Ok(())
}
fn validate_pairing_response(value: &PairingResponse) -> Result<(), Error> {
    Recipient::parse(&value.recipient).map_err(|_| Error::InvalidRecipientStanza)?;
    verifying(&value.phone_signing_public_key)?;
    Ok(())
}
fn label(value: &str) -> Result<(), Error> {
    if value.len() <= 64 {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}

fn sign(
    key: &(impl P256Signer + ?Sized),
    domain: &[u8],
    payload: &[u8],
) -> Result<[u8; 64], Error> {
    key.sign_prehash(&hash(domain, payload))
}
fn verify(
    key: &VerifyingKey,
    domain: &[u8],
    payload: &[u8],
    bytes: &[u8; 64],
) -> Result<(), Error> {
    let signature = Signature::from_slice(bytes).map_err(|_| Error::InvalidSignature)?;
    if signature.normalize_s().is_some() {
        return Err(Error::InvalidSignature);
    }
    key.verify(&domain_input(domain, payload), &signature)
        .map_err(|_| Error::InvalidSignature)
}
fn domain_input(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = domain.to_vec();
    v.push(0);
    v.extend(payload);
    v
}
fn hash(domain: &[u8], payload: &[u8]) -> ProtocolDigest {
    let mut h = Sha256::new();
    h.update(domain);
    h.update([0]);
    h.update(payload);
    h.finalize().into()
}
fn session_key(
    shared: &[u8],
    digest: &ProtocolDigest,
    nonce: &ProtocolNonce,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut salt = [0; 64];
    salt[..32].copy_from_slice(digest);
    salt[32..].copy_from_slice(nonce);
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(SESSION_INFO, key.as_mut())
        .map_err(|_| Error::KeyDerivation)?;
    salt.zeroize();
    Ok(key)
}
fn public_signing(key: &VerifyingKey) -> EncodedPublicKey {
    let mut b = [0; 33];
    b.copy_from_slice(key.to_encoded_point(true).as_bytes());
    b
}
fn verifying(bytes: &EncodedPublicKey) -> Result<VerifyingKey, Error> {
    VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidPublicKey)
}
fn encode_public(key: &PublicKey) -> EncodedPublicKey {
    let mut b = [0; 33];
    b.copy_from_slice(key.to_encoded_point(true).as_bytes());
    b
}
fn public(bytes: &EncodedPublicKey) -> Result<PublicKey, Error> {
    if !matches!(bytes[0], 2 | 3) {
        return Err(Error::InvalidPublicKey);
    }
    let k = PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
    if encode_public(&k) == *bytes {
        Ok(k)
    } else {
        Err(Error::InvalidPublicKey)
    }
}

fn enc() -> Encoder<Vec<u8>> {
    Encoder::new(Vec::new())
}
fn done(e: Encoder<Vec<u8>>) -> Vec<u8> {
    e.into_writer()
}
fn header(e: &mut Encoder<Vec<u8>>, len: u64, kind: u16) {
    e.array(len)
        .unwrap()
        .u16(PROTOCOL_VERSION)
        .unwrap()
        .u16(kind)
        .unwrap()
        .u16(ALGORITHM_SUITE)
        .unwrap();
}
fn encode_offer(v: &PairingOffer) -> Vec<u8> {
    let mut e = enc();
    header(&mut e, 8, OFFER);
    e.bytes(&v.desktop_id)
        .unwrap()
        .str(&v.desktop_label)
        .unwrap()
        .bytes(&v.desktop_signing_public_key)
        .unwrap()
        .bytes(&v.desktop_selection_public_key)
        .unwrap()
        .bytes(&v.nonce)
        .unwrap();
    done(e)
}
fn encode_pairing_response(v: &PairingResponse) -> Vec<u8> {
    let mut e = enc();
    header(&mut e, 8, PAIRING_RESPONSE);
    e.bytes(&v.identity_id)
        .unwrap()
        .str(&v.recipient)
        .unwrap()
        .bytes(&v.phone_signing_public_key)
        .unwrap()
        .bytes(&v.offer_digest)
        .unwrap()
        .bytes(&v.nonce)
        .unwrap();
    done(e)
}
fn stanza(e: &mut Encoder<Vec<u8>>, v: &TaggedStanza) {
    e.array(3)
        .unwrap()
        .str(&v.tag)
        .unwrap()
        .array(u64::try_from(v.args.len()).expect("validated stanza argument count"))
        .unwrap();
    for argument in &v.args {
        e.str(argument).unwrap();
    }
    e.bytes(&v.body).unwrap();
}
fn encode_request(v: &UnwrapRequest) -> Vec<u8> {
    let mut e = enc();
    header(&mut e, 11, REQUEST);
    e.bytes(&v.request_id)
        .unwrap()
        .bytes(&v.identity_id)
        .unwrap()
        .bytes(&v.desktop_id)
        .unwrap()
        .bytes(&v.session_public_key)
        .unwrap();
    stanza(&mut e, &v.recipient_stanza);
    e.bytes(&v.nonce).unwrap().u64(v.expires_at_unix).unwrap();
    match &v.caller_hint {
        Some(s) => {
            e.str(s).unwrap();
        }
        None => {
            e.null().unwrap();
        }
    }
    done(e)
}
fn encode_response(v: &UnwrapResponse) -> Vec<u8> {
    let mut e = enc();
    header(&mut e, 10, RESPONSE);
    e.bytes(&v.request_id)
        .unwrap()
        .bytes(&v.request_digest)
        .unwrap()
        .bytes(&v.identity_id)
        .unwrap()
        .bytes(&v.desktop_id)
        .unwrap()
        .bytes(&v.phone_session_public_key)
        .unwrap()
        .bytes(&v.nonce)
        .unwrap()
        .bytes(&v.encrypted_file_key)
        .unwrap();
    done(e)
}
fn response_aad(v: &UnwrapResponse) -> Vec<u8> {
    let mut e = enc();
    header(&mut e, 9, RESPONSE);
    e.bytes(&v.request_id)
        .unwrap()
        .bytes(&v.request_digest)
        .unwrap()
        .bytes(&v.identity_id)
        .unwrap()
        .bytes(&v.desktop_id)
        .unwrap()
        .bytes(&v.phone_session_public_key)
        .unwrap()
        .bytes(&v.nonce)
        .unwrap();
    done(e)
}
fn signed(payload: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut e = enc();
    e.array(2)
        .unwrap()
        .bytes(payload)
        .unwrap()
        .bytes(signature)
        .unwrap();
    done(e)
}

fn arr(d: &mut Decoder<'_>, n: u64) -> Result<(), Error> {
    if d.array().map_err(|_| Error::Malformed)? == Some(n) {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}
fn hdr(d: &mut Decoder<'_>, n: u64, kind: u16) -> Result<(), Error> {
    arr(d, n)?;
    if d.u16().map_err(|_| Error::Malformed)? != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if d.u16().map_err(|_| Error::Malformed)? != kind {
        return Err(Error::UnexpectedMessageType);
    }
    if d.u16().map_err(|_| Error::Malformed)? != ALGORITHM_SUITE {
        return Err(Error::UnsupportedSuite);
    }
    Ok(())
}
fn fixed<const N: usize>(v: &[u8]) -> Result<[u8; N], Error> {
    v.try_into().map_err(|_| Error::Malformed)
}
fn text(d: &mut Decoder<'_>, max: usize) -> Result<String, Error> {
    let s = d.str().map_err(|_| Error::Malformed)?;
    if s.len() > max {
        Err(Error::Malformed)
    } else {
        Ok(s.into())
    }
}
fn end(d: &Decoder<'_>, b: &[u8]) -> Result<(), Error> {
    if d.position() == b.len() {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}
fn canonical(a: &[u8], b: &[u8]) -> Result<(), Error> {
    if a == b {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}
fn decode_signed(b: &[u8]) -> Result<(Vec<u8>, [u8; 64]), Error> {
    let mut d = Decoder::new(b);
    arr(&mut d, 2)?;
    let p = d.bytes().map_err(|_| Error::Malformed)?.to_vec();
    let s = fixed(d.bytes().map_err(|_| Error::Malformed)?)?;
    end(&d, b)?;
    Ok((p, s))
}
fn decode_offer(b: &[u8]) -> Result<PairingOffer, Error> {
    let mut d = Decoder::new(b);
    hdr(&mut d, 8, OFFER)?;
    let v = PairingOffer {
        desktop_id: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
        desktop_label: text(&mut d, 64)?,
        desktop_signing_public_key: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
        desktop_selection_public_key: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
        nonce: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
    };
    end(&d, b)?;
    canonical(b, &encode_offer(&v))?;
    Ok(v)
}
fn decode_pairing_response(b: &[u8]) -> Result<PairingResponse, Error> {
    let mut d = Decoder::new(b);
    hdr(&mut d, 8, PAIRING_RESPONSE)?;
    let v = PairingResponse {
        identity_id: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
        recipient: text(&mut d, 160)?,
        phone_signing_public_key: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
        offer_digest: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
        nonce: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
    };
    end(&d, b)?;
    canonical(b, &encode_pairing_response(&v))?;
    validate_pairing_response(&v)?;
    Ok(v)
}
fn decode_stanza(d: &mut Decoder<'_>) -> Result<TaggedStanza, Error> {
    arr(d, 3)?;
    let tag = text(d, 64)?;
    let argument_count = d.array().map_err(|_| Error::Malformed)?;
    if !matches!(argument_count, Some(1 | 2)) {
        return Err(Error::Malformed);
    }
    let args = (0..argument_count.unwrap_or_default())
        .map(|_| text(d, 128))
        .collect::<Result<Vec<_>, _>>()?;
    let body = d.bytes().map_err(|_| Error::Malformed)?.to_vec();
    Ok(TaggedStanza { tag, args, body })
}
fn decode_request(b: &[u8]) -> Result<UnwrapRequest, Error> {
    let mut d = Decoder::new(b);
    hdr(&mut d, 11, REQUEST)?;
    let request_id = fixed(d.bytes().map_err(|_| Error::Malformed)?)?;
    let identity_id = fixed(d.bytes().map_err(|_| Error::Malformed)?)?;
    let desktop_id = fixed(d.bytes().map_err(|_| Error::Malformed)?)?;
    let session_public_key = fixed(d.bytes().map_err(|_| Error::Malformed)?)?;
    let recipient_stanza = decode_stanza(&mut d)?;
    let nonce = fixed(d.bytes().map_err(|_| Error::Malformed)?)?;
    let expires_at_unix = d.u64().map_err(|_| Error::Malformed)?;
    let caller_hint = match d.datatype().map_err(|_| Error::Malformed)? {
        Type::Null => {
            d.null().map_err(|_| Error::Malformed)?;
            None
        }
        Type::String => Some(text(&mut d, 64)?),
        _ => return Err(Error::Malformed),
    };
    let v = UnwrapRequest {
        request_id,
        identity_id,
        desktop_id,
        session_public_key,
        recipient_stanza,
        nonce,
        expires_at_unix,
        caller_hint,
    };
    end(&d, b)?;
    canonical(b, &encode_request(&v))?;
    validate_request(&v)?;
    Ok(v)
}
fn decode_response(b: &[u8]) -> Result<UnwrapResponse, Error> {
    let mut d = Decoder::new(b);
    hdr(&mut d, 10, RESPONSE)?;
    let v = UnwrapResponse {
        request_id: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
        request_digest: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
        identity_id: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
        desktop_id: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
        phone_session_public_key: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
        nonce: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
        encrypted_file_key: fixed(d.bytes().map_err(|_| Error::Malformed)?)?,
    };
    end(&d, b)?;
    canonical(b, &encode_response(&v))?;
    public(&v.phone_session_public_key)?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age_plugin_phone_recipient_p256::{
        PairedRecipient, Recipient, wrap_file_key_v2_with_ephemeral, wrap_file_key_with_ephemeral,
    };
    const D: Id = [0x11; 16];
    const I: Id = [0x22; 16];
    const R: Id = [0x33; 16];
    const F: [u8; 16] = [0x55; 16];
    fn sk(n: u8) -> SecretKey {
        let mut b = [0; 32];
        b[31] = n;
        SecretKey::from_slice(&b).unwrap()
    }
    fn sig(n: u8) -> SigningKey {
        SigningKey::from_bytes(
            (&{
                let mut b = [0; 32];
                b[31] = n;
                b
            })
                .into(),
        )
        .unwrap()
    }
    fn fixture() -> (SignedUnwrapRequest, PairingRecord, SecretKey, SigningKey) {
        let ds = sig(1);
        let ps = sig(2);
        let identity = sk(3);
        let recipient = Recipient::from_public_key_bytes(
            identity.public_key().to_encoded_point(true).as_bytes(),
        )
        .unwrap();
        let stanza = wrap_file_key_with_ephemeral(&recipient, &F, &sk(4)).unwrap();
        let session = sk(5);
        let request = SignedUnwrapRequest::sign(
            UnwrapRequest {
                request_id: R,
                identity_id: I,
                desktop_id: D,
                session_public_key: encode_public(&session.public_key()),
                recipient_stanza: stanza,
                nonce: [0x44; 32],
                expires_at_unix: 1_000_300,
                caller_hint: Some("test caller".into()),
            },
            &ds,
        )
        .unwrap();
        let pairing = PairingRecord {
            desktop_id: D,
            identity_id: I,
            desktop_signing_public_key: public_signing(ds.verifying_key()),
            desktop_selection_public_key: public_signing(sig(7).verifying_key()),
            phone_signing_public_key: public_signing(ps.verifying_key()),
        };
        (request, pairing, session, ps)
    }
    fn pairing_fixture() -> (
        SignedPairingOffer,
        SignedPairingResponse,
        SigningKey,
        SigningKey,
    ) {
        let desktop = sig(1);
        let phone = sig(2);
        let offer = SignedPairingOffer::sign(
            PairingOffer {
                desktop_id: D,
                desktop_label: "desktop".into(),
                desktop_signing_public_key: public_signing(desktop.verifying_key()),
                desktop_selection_public_key: public_signing(sig(7).verifying_key()),
                nonce: [7; 32],
            },
            &desktop,
        )
        .unwrap();
        let response = SignedPairingResponse::sign(
            PairingResponse {
                identity_id: I,
                recipient: Recipient::from_public_key_bytes(
                    sk(3).public_key().to_encoded_point(true).as_bytes(),
                )
                .unwrap()
                .to_string()
                .unwrap(),
                phone_signing_public_key: public_signing(phone.verifying_key()),
                offer_digest: offer.digest(),
                nonce: [8; 32],
            },
            &phone,
        )
        .unwrap();
        (offer, response, desktop, phone)
    }
    fn make_high_s(signature: &mut [u8; 64]) {
        const ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut borrow = 0_u16;
        for i in (0..32).rev() {
            let minuend = u16::from(ORDER[i]);
            let subtrahend = u16::from(signature[32 + i]) + borrow;
            if minuend >= subtrahend {
                signature[32 + i] = u8::try_from(minuend - subtrahend).unwrap();
                borrow = 0;
            } else {
                signature[32 + i] = u8::try_from(minuend + 256 - subtrahend).unwrap();
                borrow = 1;
            }
        }
        assert_eq!(borrow, 0);
    }
    struct FailingReplayStore;
    impl ReplayStore for FailingReplayStore {
        fn consume_request(
            &mut self,
            _desktop_id: Id,
            _identity_id: Id,
            _request_id: Id,
            _nonce: ProtocolNonce,
            _expires_at_unix: u64,
            _now_unix: u64,
        ) -> Result<(), Error> {
            Err(Error::ReplayState)
        }

        fn consume_response(
            &mut self,
            _desktop_id: Id,
            _identity_id: Id,
            _response_digest: ProtocolDigest,
            _expires_at_unix: u64,
            _now_unix: u64,
        ) -> Result<(), Error> {
            Err(Error::ReplayState)
        }
    }
    #[test]
    fn round_trip_and_replay() {
        use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
        let (r, p, s, ps) = fixture();
        let decoded = SignedUnwrapRequest::decode(&r.encode()).unwrap();
        let mut g = ReplayGuard::default();
        let verified = g.verify_request(decoded, &p, 1_000_000).unwrap();
        let response =
            seal_response_with_ephemeral(&verified, &F, &ps, &sk(6), [0x66; 32]).unwrap();
        let response = SignedUnwrapResponse::decode(&response.encode()).unwrap();
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/test-vectors/offline-envelope-v2.json"
        ))
        .unwrap();
        assert_eq!(
            STANDARD_NO_PAD.encode(r.encode()),
            vector["signed_request_base64"].as_str().unwrap()
        );
        assert_eq!(
            STANDARD_NO_PAD.encode(verified.digest()),
            vector["request_digest_base64"].as_str().unwrap()
        );
        assert_eq!(
            STANDARD_NO_PAD.encode(response.encode()),
            vector["signed_response_base64"].as_str().unwrap()
        );
        let mut rg = ReplayGuard::default();
        assert_eq!(
            *open_response(&response, &verified, &p, &s, &mut rg, 1_000_000).unwrap(),
            F
        );
        assert_eq!(
            open_response(&response, &verified, &p, &s, &mut rg, 1_000_000).unwrap_err(),
            Error::Replay
        );
    }

    #[test]
    fn v2_two_argument_stanza_round_trips_canonically() {
        let desktop = sig(1);
        let phone_identity = sk(3);
        let recipient = PairedRecipient::from_public_fields(
            phone_identity
                .public_key()
                .to_encoded_point(true)
                .as_bytes(),
            desktop.verifying_key().to_encoded_point(true).as_bytes(),
            I,
        )
        .unwrap();
        let stanza = wrap_file_key_v2_with_ephemeral(&recipient, &F, &sk(4)).unwrap();
        let (request, pairing, _, _) = fixture();
        let mut payload = request.payload;
        payload.recipient_stanza = stanza;
        let signed = SignedUnwrapRequest::sign(payload, &desktop).unwrap();
        let decoded = SignedUnwrapRequest::decode(&signed.encode()).unwrap();
        assert_eq!(decoded.payload.recipient_stanza.args.len(), 2);
        ReplayGuard::default()
            .verify_request(decoded, &pairing, 1_000_000)
            .unwrap();
    }
    #[test]
    fn desktop_request_creation_checks_pairing_key_scope_and_lifetime() {
        let (request, pairing, _, _) = fixture();
        let desktop = sig(1);
        let created =
            create_request(request.payload.clone(), &desktop, &pairing, 1_000_000).unwrap();
        assert_eq!(created.digest(), hash(REQUEST_DIGEST, &request.encode()));

        let mut wrong_scope = request.payload.clone();
        wrong_scope.desktop_id[0] ^= 1;
        assert_eq!(
            create_request(wrong_scope, &desktop, &pairing, 1_000_000).unwrap_err(),
            Error::WrongDesktop,
        );
        assert_eq!(
            create_request(request.payload.clone(), &sig(9), &pairing, 1_000_000).unwrap_err(),
            Error::InvalidPublicKey,
        );
        let mut expired = request.payload;
        expired.expires_at_unix = 999_999;
        assert_eq!(
            create_request(expired, &desktop, &pairing, 1_000_000).unwrap_err(),
            Error::Expired,
        );
    }
    #[test]
    fn rejects_wrong_expired_replay_and_tamper() {
        let (r, p, s, ps) = fixture();
        let mut g = ReplayGuard::default();
        let mut wrong = p.clone();
        wrong.desktop_id[0] ^= 1;
        assert_eq!(
            g.verify_request(r.clone(), &wrong, 1_000_000).unwrap_err(),
            Error::WrongDesktop
        );
        wrong = p.clone();
        wrong.identity_id[0] ^= 1;
        assert_eq!(
            g.verify_request(r.clone(), &wrong, 1_000_000).unwrap_err(),
            Error::WrongIdentity
        );
        assert_eq!(
            g.verify_request(r.clone(), &p, 1_000_301).unwrap_err(),
            Error::Expired
        );
        let verified = g.verify_request(r.clone(), &p, 1_000_000).unwrap();
        assert_eq!(
            g.verify_request(r, &p, 1_000_000).unwrap_err(),
            Error::Replay
        );
        let mut response =
            seal_response_with_ephemeral(&verified, &F, &ps, &sk(6), [0x66; 32]).unwrap();
        assert_eq!(
            open_response(
                &response,
                &verified,
                &p,
                &s,
                &mut ReplayGuard::default(),
                1_000_301,
            )
            .unwrap_err(),
            Error::Expired
        );
        response.payload.request_digest[0] ^= 1;
        assert_eq!(
            open_response(
                &response,
                &verified,
                &p,
                &s,
                &mut ReplayGuard::default(),
                1_000_000,
            )
            .unwrap_err(),
            Error::BindingMismatch
        );
    }
    #[test]
    fn replay_storage_failure_never_falls_back() {
        let (request, pairing, desktop_session, phone_signing) = fixture();
        assert_eq!(
            verify_request_with_replay(
                request.clone(),
                &pairing,
                1_000_000,
                &mut FailingReplayStore,
            )
            .unwrap_err(),
            Error::ReplayState
        );

        let verified = ReplayGuard::default()
            .verify_request(request, &pairing, 1_000_000)
            .unwrap();
        let response =
            seal_response_with_ephemeral(&verified, &F, &phone_signing, &sk(6), [0x66; 32])
                .unwrap();
        assert_eq!(
            open_response(
                &response,
                &verified,
                &pairing,
                &desktop_session,
                &mut FailingReplayStore,
                1_000_000,
            )
            .unwrap_err(),
            Error::ReplayState
        );
    }
    #[test]
    fn rejects_noncanonical_and_bad_signature() {
        let (mut r, p, _, _) = fixture();
        r.signature[0] ^= 1;
        assert_eq!(
            ReplayGuard::default()
                .verify_request(r, &p, 1_000_000)
                .unwrap_err(),
            Error::InvalidSignature
        );
        let (r, _, _, _) = fixture();
        let mut b = r.encode();
        b.push(0);
        assert_eq!(
            SignedUnwrapRequest::decode(&b).unwrap_err(),
            Error::Malformed
        );
    }
    #[test]
    fn pairing_transcript() {
        use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};

        let (offer, response, desktop, phone) = pairing_fixture();
        SignedPairingOffer::decode(&offer.encode())
            .unwrap()
            .verify()
            .unwrap();
        SignedPairingResponse::decode(&response.encode())
            .unwrap()
            .verify(&offer)
            .unwrap();
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/test-vectors/pairing-transcript-v2.json"
        ))
        .unwrap();
        assert_eq!(
            STANDARD_NO_PAD.encode(offer.encode()),
            vector["signed_offer_base64"].as_str().unwrap()
        );
        assert_eq!(
            STANDARD_NO_PAD.encode(offer.digest()),
            vector["offer_digest_base64"].as_str().unwrap()
        );
        assert_eq!(
            STANDARD_NO_PAD.encode(response.encode()),
            vector["signed_response_base64"].as_str().unwrap()
        );
        assert_eq!(
            STANDARD_NO_PAD.encode(pairing_fingerprint(&offer, &response)),
            vector["fingerprint_base64"].as_str().unwrap()
        );
        assert_eq!(
            STANDARD_NO_PAD.encode(public_signing(desktop.verifying_key())),
            vector["desktop_signing_public_key_base64"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            STANDARD_NO_PAD.encode(offer.payload.desktop_selection_public_key),
            vector["desktop_selection_public_key_base64"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            STANDARD_NO_PAD.encode(public_signing(phone.verifying_key())),
            vector["phone_signing_public_key_base64"].as_str().unwrap()
        );
        assert_eq!(
            response.payload.recipient,
            vector["recipient"].as_str().unwrap()
        );
    }
    #[test]
    fn rejects_pairing_tamper_wrong_offer_and_malformed_fields() {
        let (offer, response, desktop, phone) = pairing_fixture();

        let mut bad_offer = offer.clone();
        bad_offer.signature[0] ^= 1;
        assert_eq!(bad_offer.verify().unwrap_err(), Error::InvalidSignature);

        let mut high_s_offer = offer.clone();
        make_high_s(&mut high_s_offer.signature);
        assert_eq!(high_s_offer.verify().unwrap_err(), Error::InvalidSignature);

        let mut trailing = offer.encode();
        trailing.push(0);
        assert_eq!(
            SignedPairingOffer::decode(&trailing).unwrap_err(),
            Error::Malformed
        );

        let mut old_version = offer.encode();
        old_version[4] = 1;
        assert_eq!(
            SignedPairingOffer::decode(&old_version).unwrap_err(),
            Error::UnsupportedVersion
        );

        let other_offer = SignedPairingOffer::sign(
            PairingOffer {
                nonce: [9; 32],
                ..offer.payload.clone()
            },
            &desktop,
        )
        .unwrap();
        assert_eq!(
            response.verify(&other_offer).unwrap_err(),
            Error::BindingMismatch
        );

        let mut bad_response = response.clone();
        bad_response.signature[0] ^= 1;
        assert_eq!(
            bad_response.verify(&offer).unwrap_err(),
            Error::InvalidSignature
        );

        let mut high_s_response = response.clone();
        make_high_s(&mut high_s_response.signature);
        assert_eq!(
            high_s_response.verify(&offer).unwrap_err(),
            Error::InvalidSignature
        );

        let mut wrong_digest = response.payload.clone();
        wrong_digest.offer_digest[0] ^= 1;
        assert_eq!(
            SignedPairingResponse::sign(wrong_digest, &phone)
                .unwrap()
                .verify(&offer)
                .unwrap_err(),
            Error::BindingMismatch
        );

        let mut invalid_recipient = response.payload.clone();
        invalid_recipient.recipient.make_ascii_uppercase();
        assert_eq!(
            SignedPairingResponse::sign(invalid_recipient, &phone).unwrap_err(),
            Error::InvalidRecipientStanza
        );

        let mut oversized = offer.payload.clone();
        oversized.desktop_label = "x".repeat(65);
        assert_eq!(
            SignedPairingOffer::sign(oversized, &desktop).unwrap_err(),
            Error::Malformed
        );
    }
}
