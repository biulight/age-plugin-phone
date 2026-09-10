//! Standard C2SP p256tag recipients and RFC 9180 base-mode HPKE.
use super::*;
use sha2::Digest as _;

/// Native age stanza type (requires age 1.3+ for plugin-free encryption).
pub const STANZA_TAG: &str = "p256tag";
const HRP: &str = "age1tag";
const INFO: &[u8] = b"age-encryption.org/p256tag";
const KEM: &[u8] = b"KEM\x00\x10";
const SUITE: &[u8] = b"HPKE\x00\x10\x00\x01\x00\x03";

/// Encode the same phone public key as a native tagged recipient.
/// # Errors
/// Returns an error if encoding fails.
pub fn recipient(recipient: &Recipient) -> Result<String, Error> {
    bech32::encode(
        HRP,
        recipient.public_key_bytes().to_base32(),
        Variant::Bech32,
    )
    .map_err(|_| Error::RecipientEncoding)
}

/// Strictly decode a canonical native tagged recipient.
/// # Errors
/// Rejects noncanonical encodings, incorrect HRPs and invalid public keys.
pub fn parse_recipient(text: &str) -> Result<Recipient, Error> {
    let (hrp, data, variant) = bech32::decode(text).map_err(|_| Error::NonCanonicalRecipient)?;
    if hrp != HRP || variant != Variant::Bech32 {
        return Err(Error::WrongRecipientHrp);
    }
    let bytes = Vec::<u8>::from_base32(&data).map_err(|_| Error::NonCanonicalRecipient)?;
    let key = Recipient::from_public_key_bytes(&bytes)?;
    if recipient(&key)? != text {
        return Err(Error::NonCanonicalRecipient);
    }
    Ok(key)
}

pub(super) fn parse(stanza: &TaggedStanza) -> Result<PublicKey, Error> {
    if stanza.tag != STANZA_TAG {
        return Err(Error::UnknownStanzaType);
    }
    let [tag, enc] = stanza.args.as_slice() else {
        return Err(Error::InvalidStanzaArguments);
    };
    decode_base64_exact(tag, 4)?;
    let enc = decode_base64_exact(enc, 65)?;
    if stanza.body.len() != 32 {
        return Err(Error::InvalidBodyLength);
    }
    if enc[0] != 4 {
        return Err(Error::InvalidPublicKey);
    }
    let key = PublicKey::from_sec1_bytes(&enc).map_err(|_| Error::InvalidPublicKey)?;
    if key.to_encoded_point(false).as_bytes() != enc {
        return Err(Error::InvalidPublicKey);
    }
    Ok(key)
}

fn selection(recipient: &Recipient, enc: &[u8]) -> [u8; 4] {
    let hash = Sha256::digest(recipient.public_key_bytes());
    let (prk, _) = Hkdf::<Sha256>::extract(Some(INFO), &[enc, &hash[..4]].concat());
    prk[..4].try_into().expect("four bytes")
}

/// Public prefilter only; HPKE authentication is still required.
/// # Errors
/// Rejects malformed supported stanzas.
pub fn matches(recipient: &Recipient, stanza: &TaggedStanza) -> Result<bool, Error> {
    let enc = parse(stanza)?.to_encoded_point(false);
    Ok(STANDARD_NO_PAD.encode(selection(recipient, enc.as_bytes())) == stanza.args[0])
}

fn extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    let input = Zeroizing::new([b"HPKE-v1", suite, label, ikm].concat());
    let (mut prk, _) = Hkdf::<Sha256>::extract(Some(salt), &input);
    let result = Zeroizing::new(prk.to_vec());
    prk.zeroize();
    result
}

fn expand(
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: u16,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let input = [len.to_be_bytes().as_slice(), b"HPKE-v1", suite, label, info].concat();
    let mut output = Zeroizing::new(vec![0; usize::from(len)]);
    Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| Error::KeyDerivation)?
        .expand(&input, &mut output)
        .map_err(|_| Error::KeyDerivation)?;
    Ok(output)
}

type KeyAndNonce = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

fn schedule(dh: &[u8], enc: &[u8], recipient: &Recipient) -> Result<KeyAndNonce, Error> {
    let eae = extract(KEM, &[], b"eae_prk", dh);
    let context = [enc, recipient.0.to_encoded_point(false).as_bytes()].concat();
    let shared = expand(KEM, &eae, b"shared_secret", &context, 32)?;
    let psk = extract(SUITE, &[], b"psk_id_hash", &[]);
    let info = extract(SUITE, &[], b"info_hash", INFO);
    let context = [&[0], psk.as_slice(), info.as_slice()].concat();
    let secret = extract(SUITE, &shared, b"secret", &[]);
    Ok((
        expand(SUITE, &secret, b"key", &context, 32)?,
        expand(SUITE, &secret, b"base_nonce", &context, 12)?,
    ))
}

/// Software-key reference open for deterministic tests; mobile production uses native hardware.
/// # Errors
/// Rejects malformed stanzas, wrong recipients and authentication failures.
pub fn unwrap(
    identity: &SecretKey,
    stanza: &TaggedStanza,
) -> Result<Zeroizing<[u8; FILE_KEY_BYTES]>, Error> {
    let enc = parse(stanza)?;
    let recipient = Recipient(identity.public_key());
    if !matches(&recipient, stanza)? {
        return Err(Error::Authentication);
    }
    let dh = diffie_hellman(identity.to_nonzero_scalar(), enc.as_affine());
    let (key, nonce) = schedule(
        dh.raw_secret_bytes(),
        enc.to_encoded_point(false).as_bytes(),
        &recipient,
    )?;
    let plaintext = Zeroizing::new(
        ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| Error::KeyDerivation)?
            .decrypt(Nonce::from_slice(&nonce), stanza.body.as_slice())
            .map_err(|_| Error::Authentication)?,
    );
    let mut output = Zeroizing::new([0; FILE_KEY_BYTES]);
    if plaintext.len() != FILE_KEY_BYTES {
        return Err(Error::Authentication);
    }
    output.copy_from_slice(&plaintext);
    Ok(output)
}

/// Deterministic public-vector helper. Never reuse the supplied ephemeral scalar for real data.
/// # Errors
/// Returns an error on key derivation or encryption failure.
pub fn wrap_with_ephemeral(
    recipient: &Recipient,
    file_key: &[u8; FILE_KEY_BYTES],
    ephemeral: &SecretKey,
) -> Result<TaggedStanza, Error> {
    let enc = ephemeral.public_key().to_encoded_point(false);
    let dh = diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.0.as_affine());
    let (key, nonce) = schedule(dh.raw_secret_bytes(), enc.as_bytes(), recipient)?;
    let body = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::KeyDerivation)?
        .encrypt(Nonce::from_slice(&nonce), file_key.as_slice())
        .map_err(|_| Error::Authentication)?;
    Ok(TaggedStanza {
        tag: STANZA_TAG.into(),
        args: vec![
            STANDARD_NO_PAD.encode(selection(recipient, enc.as_bytes())),
            STANDARD_NO_PAD.encode(enc.as_bytes()),
        ],
        body,
    })
}
