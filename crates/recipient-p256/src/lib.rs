//! Experimental P-256 age tagged-recipient construction.
//!
//! This crate implements ADR 0001. Its wire values are not stable until the construction has
//! received independent review.

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use bech32::{FromBase32 as _, ToBase32 as _, Variant};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit as _, Nonce,
    aead::{Aead as _, Payload},
};
use hkdf::Hkdf;
use p256::{
    EncodedPoint, PublicKey, SecretKey,
    ecdh::{EphemeralSecret, diffie_hellman},
    elliptic_curve::{sec1::ToEncodedPoint as _, subtle::ConstantTimeEq as _},
};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

mod plugin;

/// Plugin name used by age recipient dispatch.
pub const PLUGIN_NAME: &str = "phone";
/// Bech32 HRP for the plugin recipient.
pub const RECIPIENT_HRP: &str = "age1phone";
/// Exact age stanza tag for this experimental construction.
pub const STANZA_TAG: &str = "phone-p256-v1";
/// Exact age stanza tag for the privately selectable construction.
pub const STANZA_TAG_V2: &str = "phone-p256-v2";
/// Length of an age file key.
pub const FILE_KEY_BYTES: usize = 16;
/// Length of pairing and identity identifiers.
pub const ID_BYTES: usize = 16;

const PAYLOAD_VERSION: u8 = 1;
const PAYLOAD_VERSION_V2: u8 = 2;
const COMPRESSED_POINT_BYTES: usize = 33;
const RECIPIENT_PAYLOAD_BYTES: usize = 1 + COMPRESSED_POINT_BYTES;
const RECIPIENT_PAYLOAD_V2_BYTES: usize = 1 + COMPRESSED_POINT_BYTES * 2 + ID_BYTES;
const STANZA_BODY_BYTES: usize = FILE_KEY_BYTES + 16;
const KDF_INFO: &[u8] = b"age-plugin-phone/recipient/p256/v1";
const FILE_KEY_KDF_INFO_V2: &[u8] = b"age-plugin-phone/recipient/p256/v2/file-key";
const SELECTION_KDF_INFO_V2: &[u8] = b"age-plugin-phone/recipient/p256/v2/selection";
const NONCE: [u8; 12] = [0; 12];

/// A validated phone recipient public key.
#[derive(Clone, Debug)]
pub struct Recipient(PublicKey);

/// A phone recipient privately selectable by one paired desktop.
#[derive(Clone, Debug)]
pub struct PairedRecipient {
    phone_identity: PublicKey,
    desktop_selection: PublicKey,
    identity_id: [u8; ID_BYTES],
}

/// The owned fields of one P-256 recipient stanza.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaggedStanza {
    /// Exact stanza type.
    pub tag: String,
    /// V1 has one canonical Base64 ephemeral-key argument; v2 adds one selector ciphertext.
    pub args: Vec<String>,
    /// A 16-byte ciphertext followed by a 16-byte Poly1305 tag.
    pub body: Vec<u8>,
}

/// Strict recipient or stanza processing failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// The recipient text was not its canonical lowercase Bech32 representation.
    #[error("non-canonical recipient encoding")]
    NonCanonicalRecipient,
    /// The recipient used a different plugin HRP.
    #[error("unexpected recipient HRP")]
    WrongRecipientHrp,
    /// The recipient payload version is not supported.
    #[error("unsupported recipient version")]
    UnsupportedRecipientVersion,
    /// The recipient payload has the wrong length.
    #[error("invalid recipient payload length")]
    InvalidRecipientLength,
    /// A SEC1 public key is malformed, non-canonical, or not a P-256 point.
    #[error("invalid P-256 public key")]
    InvalidPublicKey,
    /// The stanza tag is not this construction's exact tag.
    #[error("unknown recipient stanza type")]
    UnknownStanzaType,
    /// The stanza does not contain the exact argument count for its version.
    #[error("invalid recipient stanza arguments")]
    InvalidStanzaArguments,
    /// An argument is not canonical unpadded standard Base64 or has the wrong size.
    #[error("invalid stanza argument encoding")]
    InvalidEphemeralEncoding,
    /// The stanza body does not have the exact ciphertext length.
    #[error("invalid recipient stanza body length")]
    InvalidBodyLength,
    /// HKDF could not produce the fixed-size wrapping key.
    #[error("wrapping-key derivation failed")]
    KeyDerivation,
    /// The stanza could not be authenticated and decrypted.
    #[error("file-key unwrap failed")]
    Authentication,
    /// Recipient serialization failed.
    #[error("recipient encoding failed")]
    RecipientEncoding,
    /// The supplied desktop private key does not match the paired recipient.
    #[error("desktop selection key does not match recipient")]
    WrongSelectionKey,
}

impl Recipient {
    /// Parses a canonical compressed SEC1 P-256 public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] for a wrong length, uncompressed point,
    /// non-canonical point, point at infinity, or point outside P-256.
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != COMPRESSED_POINT_BYTES || !matches!(bytes.first(), Some(2 | 3)) {
            return Err(Error::InvalidPublicKey);
        }
        let public_key = PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
        if public_key.to_encoded_point(true).as_bytes() != bytes {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self(public_key))
    }

    /// Parses a canonical age plugin recipient.
    ///
    /// # Errors
    ///
    /// Returns an error for mixed case, wrong HRP or variant, unknown version, trailing data, or an
    /// invalid public key.
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text != text.to_ascii_lowercase() {
            return Err(Error::NonCanonicalRecipient);
        }
        let (hrp, data, variant) =
            bech32::decode(text).map_err(|_| Error::NonCanonicalRecipient)?;
        if hrp != RECIPIENT_HRP || variant != Variant::Bech32 {
            return Err(Error::WrongRecipientHrp);
        }
        let payload = Vec::<u8>::from_base32(&data).map_err(|_| Error::NonCanonicalRecipient)?;
        if payload.len() != RECIPIENT_PAYLOAD_BYTES {
            return Err(Error::InvalidRecipientLength);
        }
        if payload[0] != PAYLOAD_VERSION {
            return Err(Error::UnsupportedRecipientVersion);
        }
        let recipient = Self::from_public_key_bytes(&payload[1..])?;
        if recipient.to_string()? != text {
            return Err(Error::NonCanonicalRecipient);
        }
        Ok(recipient)
    }

    /// Serializes this recipient as canonical lowercase Bech32.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RecipientEncoding`] if Bech32 serialization fails.
    pub fn to_string(&self) -> Result<String, Error> {
        let mut payload = Vec::with_capacity(RECIPIENT_PAYLOAD_BYTES);
        payload.push(PAYLOAD_VERSION);
        payload.extend_from_slice(self.public_key_bytes().as_slice());
        bech32::encode(RECIPIENT_HRP, payload.to_base32(), Variant::Bech32)
            .map_err(|_| Error::RecipientEncoding)
    }

    /// Returns the canonical compressed SEC1 public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; COMPRESSED_POINT_BYTES] {
        let encoded = self.0.to_encoded_point(true);
        let mut output = [0; COMPRESSED_POINT_BYTES];
        output.copy_from_slice(encoded.as_bytes());
        output
    }
}

impl PairedRecipient {
    /// Constructs a pairing-specific recipient from canonical public fields.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if either compressed point is invalid.
    pub fn from_public_fields(
        phone_identity: &[u8],
        desktop_selection: &[u8],
        identity_id: [u8; ID_BYTES],
    ) -> Result<Self, Error> {
        Ok(Self {
            phone_identity: Recipient::from_public_key_bytes(phone_identity)?.0,
            desktop_selection: Recipient::from_public_key_bytes(desktop_selection)?.0,
            identity_id,
        })
    }

    /// Parses a canonical v2 age plugin recipient.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong HRP, encoding, version, length, or public key.
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text != text.to_ascii_lowercase() {
            return Err(Error::NonCanonicalRecipient);
        }
        let (hrp, data, variant) =
            bech32::decode(text).map_err(|_| Error::NonCanonicalRecipient)?;
        if hrp != RECIPIENT_HRP || variant != Variant::Bech32 {
            return Err(Error::WrongRecipientHrp);
        }
        let payload = Vec::<u8>::from_base32(&data).map_err(|_| Error::NonCanonicalRecipient)?;
        let recipient = Self::from_plugin_bytes(&payload)?;
        if recipient.to_string()? != text {
            return Err(Error::NonCanonicalRecipient);
        }
        Ok(recipient)
    }

    /// Parses the decoded fixed-field v2 plugin payload.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong version, length, or public key.
    pub fn from_plugin_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != RECIPIENT_PAYLOAD_V2_BYTES {
            return Err(Error::InvalidRecipientLength);
        }
        if bytes[0] != PAYLOAD_VERSION_V2 {
            return Err(Error::UnsupportedRecipientVersion);
        }
        let phone_end = 1 + COMPRESSED_POINT_BYTES;
        let desktop_end = phone_end + COMPRESSED_POINT_BYTES;
        Self::from_public_fields(
            &bytes[1..phone_end],
            &bytes[phone_end..desktop_end],
            bytes[desktop_end..]
                .try_into()
                .map_err(|_| Error::InvalidRecipientLength)?,
        )
    }

    /// Serializes the pairing-specific recipient as canonical Bech32.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RecipientEncoding`] if Bech32 serialization fails.
    pub fn to_string(&self) -> Result<String, Error> {
        bech32::encode(
            RECIPIENT_HRP,
            self.plugin_bytes().to_base32(),
            Variant::Bech32,
        )
        .map_err(|_| Error::RecipientEncoding)
    }

    /// Returns the decoded fixed-field v2 plugin payload.
    #[must_use]
    pub fn plugin_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECIPIENT_PAYLOAD_V2_BYTES);
        bytes.push(PAYLOAD_VERSION_V2);
        bytes.extend_from_slice(&public_key_bytes(&self.phone_identity));
        bytes.extend_from_slice(&public_key_bytes(&self.desktop_selection));
        bytes.extend_from_slice(&self.identity_id);
        bytes
    }

    /// Returns the phone identity public key.
    #[must_use]
    pub fn phone_identity_public_key(&self) -> [u8; COMPRESSED_POINT_BYTES] {
        public_key_bytes(&self.phone_identity)
    }

    /// Returns the paired desktop selection public key.
    #[must_use]
    pub fn desktop_selection_public_key(&self) -> [u8; COMPRESSED_POINT_BYTES] {
        public_key_bytes(&self.desktop_selection)
    }

    /// Returns the pairing identity identifier encrypted into v2 selectors.
    #[must_use]
    pub fn identity_id(&self) -> [u8; ID_BYTES] {
        self.identity_id
    }
}

/// Wraps a file key using a newly generated ephemeral P-256 key.
///
/// # Errors
///
/// Returns an error only if fixed-size HKDF or AEAD processing fails.
pub fn wrap_file_key(
    recipient: &Recipient,
    file_key: &[u8; FILE_KEY_BYTES],
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<TaggedStanza, Error> {
    let ephemeral = EphemeralSecret::random(rng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&recipient.0);
    wrap_from_shared_secret(
        recipient,
        ephemeral_public.to_encoded_point(true),
        shared.raw_secret_bytes().as_slice(),
        file_key,
    )
}

/// Deterministically wraps a file key with an explicitly supplied test-only ephemeral scalar.
///
/// Callers must never reuse `ephemeral_private` for real encryption. This entry point exists for
/// public interoperability vectors.
///
/// # Errors
///
/// Returns an error only if fixed-size HKDF or AEAD processing fails.
pub fn wrap_file_key_with_ephemeral(
    recipient: &Recipient,
    file_key: &[u8; FILE_KEY_BYTES],
    ephemeral_private: &SecretKey,
) -> Result<TaggedStanza, Error> {
    let ephemeral_public = ephemeral_private.public_key().to_encoded_point(true);
    let shared = diffie_hellman(
        ephemeral_private.to_nonzero_scalar(),
        recipient.0.as_affine(),
    );
    wrap_from_shared_secret(
        recipient,
        ephemeral_public,
        shared.raw_secret_bytes().as_slice(),
        file_key,
    )
}

/// Wraps a file key and a private desktop selector with one fresh ephemeral P-256 key.
///
/// # Errors
///
/// Returns an error only if fixed-size HKDF or AEAD processing fails.
pub fn wrap_file_key_v2(
    recipient: &PairedRecipient,
    file_key: &[u8; FILE_KEY_BYTES],
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<TaggedStanza, Error> {
    let ephemeral = EphemeralSecret::random(rng);
    let ephemeral_public = PublicKey::from(&ephemeral).to_encoded_point(true);
    let phone_shared = ephemeral.diffie_hellman(&recipient.phone_identity);
    let desktop_shared = ephemeral.diffie_hellman(&recipient.desktop_selection);
    wrap_v2_from_shared_secrets(
        recipient,
        ephemeral_public,
        phone_shared.raw_secret_bytes().as_slice(),
        desktop_shared.raw_secret_bytes().as_slice(),
        file_key,
    )
}

/// Deterministically wraps a v2 stanza with a test-only ephemeral scalar.
///
/// Callers must never reuse `ephemeral_private` for real encryption.
///
/// # Errors
///
/// Returns an error only if fixed-size HKDF or AEAD processing fails.
pub fn wrap_file_key_v2_with_ephemeral(
    recipient: &PairedRecipient,
    file_key: &[u8; FILE_KEY_BYTES],
    ephemeral_private: &SecretKey,
) -> Result<TaggedStanza, Error> {
    let ephemeral_public = ephemeral_private.public_key().to_encoded_point(true);
    let phone_shared = diffie_hellman(
        ephemeral_private.to_nonzero_scalar(),
        recipient.phone_identity.as_affine(),
    );
    let desktop_shared = diffie_hellman(
        ephemeral_private.to_nonzero_scalar(),
        recipient.desktop_selection.as_affine(),
    );
    wrap_v2_from_shared_secrets(
        recipient,
        ephemeral_public,
        phone_shared.raw_secret_bytes().as_slice(),
        desktop_shared.raw_secret_bytes().as_slice(),
        file_key,
    )
}

/// Strictly validates and unwraps a stanza with a software P-256 private key.
///
/// Android production code performs the same ECDH operation inside `StrongBox`, then applies the
/// shared-secret half of this construction in native code.
///
/// # Errors
///
/// Returns an error for malformed public structure, the wrong identity, or failed authentication.
pub fn unwrap_file_key(
    identity: &SecretKey,
    stanza: &TaggedStanza,
) -> Result<Zeroizing<[u8; FILE_KEY_BYTES]>, Error> {
    let parsed = ParsedStanza::parse(stanza)?;
    let recipient = Recipient(identity.public_key());
    let shared = diffie_hellman(identity.to_nonzero_scalar(), parsed.ephemeral.as_affine());
    decrypt_with_shared_secret(&recipient, &parsed, shared.raw_secret_bytes().as_slice())
}

/// Privately tests whether a v2 stanza belongs to this pairing.
///
/// This operation uses only the desktop authentication scalar and can recover only the encrypted
/// identity identifier, never the age file key.
///
/// # Errors
///
/// Returns an error for malformed structure, a mismatched desktop key, or key derivation failure.
/// Authentication failure is a non-match and returns `Ok(false)`.
pub fn matches_stanza_v2(
    recipient: &PairedRecipient,
    desktop_selection_private: &p256::ecdsa::SigningKey,
    stanza: &TaggedStanza,
) -> Result<bool, Error> {
    if desktop_selection_private
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        != recipient.desktop_selection_public_key()
    {
        return Err(Error::WrongSelectionKey);
    }
    let parsed = ParsedStanza::parse(stanza)?;
    if parsed.version != StanzaVersion::V2 {
        return Ok(false);
    }
    let shared = diffie_hellman(
        desktop_selection_private.as_nonzero_scalar(),
        parsed.ephemeral.as_affine(),
    );
    let desktop_bytes = recipient.desktop_selection_public_key();
    let phone_bytes = recipient.phone_identity_public_key();
    let selection_key = derive_key(
        shared.raw_secret_bytes().as_slice(),
        &parsed.ephemeral_bytes,
        &desktop_bytes,
        SELECTION_KDF_INFO_V2,
    )?;
    let aad = selection_associated_data(
        &parsed.ephemeral_bytes,
        &phone_bytes,
        &desktop_bytes,
        &parsed.body,
    );
    let Some(selection) = parsed.selection.as_ref() else {
        return Ok(false);
    };
    let cipher = ChaCha20Poly1305::new_from_slice(selection_key.as_slice())
        .map_err(|_| Error::KeyDerivation)?;
    let Ok(mut plaintext) = cipher.decrypt(
        Nonce::from_slice(&NONCE),
        Payload {
            msg: selection,
            aad: &aad,
        },
    ) else {
        return Ok(false);
    };
    let matches = plaintext.len() == ID_BYTES
        && bool::from(plaintext.as_slice().ct_eq(recipient.identity_id.as_slice()));
    plaintext.zeroize();
    Ok(matches)
}

/// Validates all public stanza structure before a private-key operation is requested.
///
/// # Errors
///
/// Returns an error for an unknown tag, wrong argument or body length, non-canonical Base64, or an
/// invalid P-256 ephemeral point.
pub fn validate_stanza(stanza: &TaggedStanza) -> Result<(), Error> {
    ParsedStanza::parse(stanza).map(|_| ())
}

fn wrap_from_shared_secret(
    recipient: &Recipient,
    ephemeral_public: EncodedPoint,
    shared_secret: &[u8],
    file_key: &[u8; FILE_KEY_BYTES],
) -> Result<TaggedStanza, Error> {
    let ephemeral_bytes: [u8; COMPRESSED_POINT_BYTES] = ephemeral_public
        .as_bytes()
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)?;
    let recipient_bytes = recipient.public_key_bytes();
    let wrap_key = derive_key(shared_secret, &ephemeral_bytes, &recipient_bytes, KDF_INFO)?;
    let aad = associated_data(&ephemeral_bytes, &recipient_bytes);
    let cipher =
        ChaCha20Poly1305::new_from_slice(wrap_key.as_slice()).map_err(|_| Error::KeyDerivation)?;
    let body = cipher
        .encrypt(
            Nonce::from_slice(&NONCE),
            Payload {
                msg: file_key,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    debug_assert_eq!(body.len(), STANZA_BODY_BYTES);

    Ok(TaggedStanza {
        tag: STANZA_TAG.to_owned(),
        args: vec![STANDARD_NO_PAD.encode(ephemeral_bytes)],
        body,
    })
}

fn wrap_v2_from_shared_secrets(
    recipient: &PairedRecipient,
    ephemeral_public: EncodedPoint,
    phone_shared_secret: &[u8],
    desktop_shared_secret: &[u8],
    file_key: &[u8; FILE_KEY_BYTES],
) -> Result<TaggedStanza, Error> {
    let ephemeral_bytes: [u8; COMPRESSED_POINT_BYTES] = ephemeral_public
        .as_bytes()
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)?;
    let phone_bytes = recipient.phone_identity_public_key();
    let desktop_bytes = recipient.desktop_selection_public_key();

    let file_key_key = derive_key(
        phone_shared_secret,
        &ephemeral_bytes,
        &phone_bytes,
        FILE_KEY_KDF_INFO_V2,
    )?;
    let cipher = ChaCha20Poly1305::new_from_slice(file_key_key.as_slice())
        .map_err(|_| Error::KeyDerivation)?;
    let body = cipher
        .encrypt(
            Nonce::from_slice(&NONCE),
            Payload {
                msg: file_key,
                aad: &file_key_associated_data_v2(&ephemeral_bytes, &phone_bytes),
            },
        )
        .map_err(|_| Error::Authentication)?;

    let selection_key = derive_key(
        desktop_shared_secret,
        &ephemeral_bytes,
        &desktop_bytes,
        SELECTION_KDF_INFO_V2,
    )?;
    let selection_cipher = ChaCha20Poly1305::new_from_slice(selection_key.as_slice())
        .map_err(|_| Error::KeyDerivation)?;
    let selection = selection_cipher
        .encrypt(
            Nonce::from_slice(&NONCE),
            Payload {
                msg: &recipient.identity_id,
                aad: &selection_associated_data(
                    &ephemeral_bytes,
                    &phone_bytes,
                    &desktop_bytes,
                    &body,
                ),
            },
        )
        .map_err(|_| Error::Authentication)?;
    debug_assert_eq!(body.len(), STANZA_BODY_BYTES);
    debug_assert_eq!(selection.len(), STANZA_BODY_BYTES);
    Ok(TaggedStanza {
        tag: STANZA_TAG_V2.to_owned(),
        args: vec![
            STANDARD_NO_PAD.encode(ephemeral_bytes),
            STANDARD_NO_PAD.encode(selection),
        ],
        body,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StanzaVersion {
    V1,
    V2,
}

struct ParsedStanza {
    version: StanzaVersion,
    ephemeral: PublicKey,
    ephemeral_bytes: [u8; COMPRESSED_POINT_BYTES],
    selection: Option<Vec<u8>>,
    body: Vec<u8>,
}

impl ParsedStanza {
    fn parse(stanza: &TaggedStanza) -> Result<Self, Error> {
        let (version, argument, selection) = match (stanza.tag.as_str(), stanza.args.as_slice()) {
            (STANZA_TAG, [argument]) => (StanzaVersion::V1, argument, None),
            (STANZA_TAG_V2, [argument, selection]) => {
                let decoded = decode_base64_exact(selection, STANZA_BODY_BYTES)?;
                (StanzaVersion::V2, argument, Some(decoded))
            }
            (STANZA_TAG | STANZA_TAG_V2, _) => return Err(Error::InvalidStanzaArguments),
            _ => return Err(Error::UnknownStanzaType),
        };
        if stanza.body.len() != STANZA_BODY_BYTES {
            return Err(Error::InvalidBodyLength);
        }
        let decoded = STANDARD_NO_PAD
            .decode(argument)
            .map_err(|_| Error::InvalidEphemeralEncoding)?;
        if STANDARD_NO_PAD.encode(&decoded) != *argument {
            return Err(Error::InvalidEphemeralEncoding);
        }
        let recipient = Recipient::from_public_key_bytes(&decoded)
            .map_err(|_| Error::InvalidEphemeralEncoding)?;
        Ok(Self {
            version,
            ephemeral: recipient.0,
            ephemeral_bytes: decoded
                .try_into()
                .map_err(|_| Error::InvalidEphemeralEncoding)?,
            selection,
            body: stanza.body.clone(),
        })
    }
}

fn decrypt_with_shared_secret(
    recipient: &Recipient,
    stanza: &ParsedStanza,
    shared_secret: &[u8],
) -> Result<Zeroizing<[u8; FILE_KEY_BYTES]>, Error> {
    let recipient_bytes = recipient.public_key_bytes();
    let (info, aad) = match stanza.version {
        StanzaVersion::V1 => (
            KDF_INFO,
            associated_data(&stanza.ephemeral_bytes, &recipient_bytes),
        ),
        StanzaVersion::V2 => (
            FILE_KEY_KDF_INFO_V2,
            file_key_associated_data_v2(&stanza.ephemeral_bytes, &recipient_bytes),
        ),
    };
    let wrap_key = derive_key(
        shared_secret,
        &stanza.ephemeral_bytes,
        &recipient_bytes,
        info,
    )?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(wrap_key.as_slice()).map_err(|_| Error::KeyDerivation)?;
    let mut plaintext = cipher
        .decrypt(
            Nonce::from_slice(&NONCE),
            Payload {
                msg: &stanza.body,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    if plaintext.len() != FILE_KEY_BYTES {
        plaintext.zeroize();
        return Err(Error::Authentication);
    }
    let mut file_key = Zeroizing::new([0; FILE_KEY_BYTES]);
    file_key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(file_key)
}

fn derive_key(
    shared_secret: &[u8],
    ephemeral_public: &[u8; COMPRESSED_POINT_BYTES],
    recipient_public: &[u8; COMPRESSED_POINT_BYTES],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut salt = [0; COMPRESSED_POINT_BYTES * 2];
    salt[..COMPRESSED_POINT_BYTES].copy_from_slice(ephemeral_public);
    salt[COMPRESSED_POINT_BYTES..].copy_from_slice(recipient_public);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key = Zeroizing::new([0; 32]);
    hkdf.expand(info, key.as_mut())
        .map_err(|_| Error::KeyDerivation)?;
    salt.zeroize();
    Ok(key)
}

fn file_key_associated_data_v2(
    ephemeral_public: &[u8; COMPRESSED_POINT_BYTES],
    phone_identity_public: &[u8; COMPRESSED_POINT_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(STANZA_TAG_V2.len() + 1 + COMPRESSED_POINT_BYTES * 2);
    aad.extend_from_slice(STANZA_TAG_V2.as_bytes());
    aad.push(0);
    aad.extend_from_slice(ephemeral_public);
    aad.extend_from_slice(phone_identity_public);
    aad
}

fn selection_associated_data(
    ephemeral_public: &[u8; COMPRESSED_POINT_BYTES],
    phone_identity_public: &[u8; COMPRESSED_POINT_BYTES],
    desktop_selection_public: &[u8; COMPRESSED_POINT_BYTES],
    body: &[u8],
) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(STANZA_TAG_V2.len() + 1 + COMPRESSED_POINT_BYTES * 3 + body.len());
    aad.extend_from_slice(STANZA_TAG_V2.as_bytes());
    aad.push(0);
    aad.extend_from_slice(b"selection");
    aad.push(0);
    aad.extend_from_slice(ephemeral_public);
    aad.extend_from_slice(phone_identity_public);
    aad.extend_from_slice(desktop_selection_public);
    aad.extend_from_slice(body);
    aad
}

fn decode_base64_exact(value: &str, expected_len: usize) -> Result<Vec<u8>, Error> {
    let decoded = STANDARD_NO_PAD
        .decode(value)
        .map_err(|_| Error::InvalidEphemeralEncoding)?;
    if decoded.len() != expected_len || STANDARD_NO_PAD.encode(&decoded) != value {
        return Err(Error::InvalidEphemeralEncoding);
    }
    Ok(decoded)
}

fn public_key_bytes(key: &PublicKey) -> [u8; COMPRESSED_POINT_BYTES] {
    key.to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed P-256 public keys are fixed width")
}

fn associated_data(
    ephemeral_public: &[u8; COMPRESSED_POINT_BYTES],
    recipient_public: &[u8; COMPRESSED_POINT_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(STANZA_TAG.len() + 1 + COMPRESSED_POINT_BYTES * 2);
    aad.extend_from_slice(STANZA_TAG.as_bytes());
    aad.push(0);
    aad.extend_from_slice(ephemeral_public);
    aad.extend_from_slice(recipient_public);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY_PRIVATE: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ];
    const EPHEMERAL_PRIVATE: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02,
    ];
    const FILE_KEY: [u8; FILE_KEY_BYTES] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn fixture() -> (SecretKey, SecretKey, Recipient) {
        let identity = SecretKey::from_slice(&IDENTITY_PRIVATE).unwrap();
        let ephemeral = SecretKey::from_slice(&EPHEMERAL_PRIVATE).unwrap();
        let recipient = Recipient(identity.public_key());
        (identity, ephemeral, recipient)
    }

    #[test]
    fn deterministic_round_trip() {
        let (identity, ephemeral, recipient) = fixture();
        let stanza = wrap_file_key_with_ephemeral(&recipient, &FILE_KEY, &ephemeral).unwrap();
        assert_eq!(*unwrap_file_key(&identity, &stanza).unwrap(), FILE_KEY);
        assert_eq!(
            Recipient::parse(&recipient.to_string().unwrap())
                .unwrap()
                .public_key_bytes(),
            recipient.public_key_bytes()
        );
        assert_eq!(
            Recipient::from_plugin_bytes(&recipient.plugin_bytes())
                .unwrap()
                .public_key_bytes(),
            recipient.public_key_bytes(),
        );
    }

    #[test]
    fn privately_selectable_v2_round_trip() {
        let (identity, ephemeral, _) = fixture();
        let desktop = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
        let paired = PairedRecipient::from_public_fields(
            identity.public_key().to_encoded_point(true).as_bytes(),
            desktop.verifying_key().to_encoded_point(true).as_bytes(),
            [0x42; ID_BYTES],
        )
        .unwrap();
        let encoded = paired.to_string().unwrap();
        let parsed = PairedRecipient::parse(&encoded).unwrap();
        assert_eq!(parsed.plugin_bytes(), paired.plugin_bytes());

        let stanza = wrap_file_key_v2_with_ephemeral(&paired, &FILE_KEY, &ephemeral).unwrap();
        assert_eq!(stanza.tag, STANZA_TAG_V2);
        assert_eq!(stanza.args.len(), 2);
        assert!(matches_stanza_v2(&paired, &desktop, &stanza).unwrap());
        assert_eq!(*unwrap_file_key(&identity, &stanza).unwrap(), FILE_KEY);
    }

    #[test]
    fn v2_selection_rejects_wrong_pairing_and_tampering() {
        let (identity, ephemeral, _) = fixture();
        let desktop = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
        let wrong_desktop = p256::ecdsa::SigningKey::from_slice(&[4; 32]).unwrap();
        let paired = PairedRecipient::from_public_fields(
            identity.public_key().to_encoded_point(true).as_bytes(),
            desktop.verifying_key().to_encoded_point(true).as_bytes(),
            [0x42; ID_BYTES],
        )
        .unwrap();
        let stanza = wrap_file_key_v2_with_ephemeral(&paired, &FILE_KEY, &ephemeral).unwrap();
        assert_eq!(
            matches_stanza_v2(&paired, &wrong_desktop, &stanza),
            Err(Error::WrongSelectionKey),
        );

        let mut wrong_identity = paired.clone();
        wrong_identity.identity_id[0] ^= 1;
        assert!(!matches_stanza_v2(&wrong_identity, &desktop, &stanza).unwrap());

        let mut modified_selection = stanza.clone();
        modified_selection.args[1].replace_range(0..1, "A");
        assert!(!matches_stanza_v2(&paired, &desktop, &modified_selection).unwrap());

        let mut modified_body = stanza;
        modified_body.body[0] ^= 1;
        assert!(!matches_stanza_v2(&paired, &desktop, &modified_body).unwrap());
        assert_eq!(
            unwrap_file_key(&identity, &modified_body),
            Err(Error::Authentication),
        );
    }

    #[test]
    fn rejects_unknown_fields_before_ecdh() {
        let (_, ephemeral, recipient) = fixture();
        let stanza = wrap_file_key_with_ephemeral(&recipient, &FILE_KEY, &ephemeral).unwrap();

        let mut wrong_tag = stanza.clone();
        wrong_tag.tag.push_str("-future");
        assert_eq!(
            ParsedStanza::parse(&wrong_tag).err(),
            Some(Error::UnknownStanzaType)
        );

        let mut extra_arg = stanza.clone();
        extra_arg.args.push("extra".into());
        assert_eq!(
            ParsedStanza::parse(&extra_arg).err(),
            Some(Error::InvalidStanzaArguments)
        );

        let mut short_body = stanza.clone();
        short_body.body.pop();
        assert_eq!(
            ParsedStanza::parse(&short_body).err(),
            Some(Error::InvalidBodyLength)
        );
    }

    #[test]
    fn rejects_invalid_and_noncanonical_points() {
        assert_eq!(
            Recipient::from_public_key_bytes(&[0; 33]).err(),
            Some(Error::InvalidPublicKey)
        );
        let uncompressed = SecretKey::from_slice(&IDENTITY_PRIVATE)
            .unwrap()
            .public_key()
            .to_encoded_point(false);
        assert_eq!(
            Recipient::from_public_key_bytes(uncompressed.as_bytes()).err(),
            Some(Error::InvalidPublicKey)
        );
    }

    #[test]
    fn rejects_tampering_and_wrong_identity() {
        let (identity, ephemeral, recipient) = fixture();
        let mut stanza = wrap_file_key_with_ephemeral(&recipient, &FILE_KEY, &ephemeral).unwrap();
        stanza.body[0] ^= 1;
        assert_eq!(
            unwrap_file_key(&identity, &stanza).err(),
            Some(Error::Authentication)
        );

        let wrong_identity = SecretKey::from_slice(&[3; 32]).unwrap();
        let stanza = wrap_file_key_with_ephemeral(&recipient, &FILE_KEY, &ephemeral).unwrap();
        assert_eq!(
            unwrap_file_key(&wrong_identity, &stanza).err(),
            Some(Error::Authentication)
        );
    }
}
