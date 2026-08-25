use std::ptr;

use age_plugin_phone_protocol::{EncodedPublicKey, Error as ProtocolError, P256Signer};
use age_plugin_phone_recipient_p256::{Error as RecipientError, P256KeyAgreement};
use p256::{PublicKey, ecdsa::Signature, elliptic_curve::sec1::ToEncodedPoint as _};
use thiserror::Error;
use windows_sys::Win32::{
    Foundation::{NTE_BAD_KEYSET, NTE_NOT_FOUND},
    Security::Cryptography::{
        BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDH_PUBLIC_P256_MAGIC,
        BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_KDF_RAW_SECRET, MS_PLATFORM_CRYPTO_PROVIDER,
        NCRYPT_ECDH_P256_ALGORITHM, NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_EXPORT_POLICY_PROPERTY,
        NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCryptCreatePersistedKey,
        NCryptDeleteKey, NCryptDeriveKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject,
        NCryptGetProperty, NCryptImportKey, NCryptOpenKey, NCryptOpenStorageProvider,
        NCryptSecretAgreement, NCryptSignHash,
    },
};
use zeroize::{Zeroize as _, Zeroizing};

const ECC_BLOB_HEADER_BYTES: usize = 8;
const P256_COORDINATE_BYTES: usize = 32;
const P256_PUBLIC_BLOB_BYTES: usize = ECC_BLOB_HEADER_BYTES + P256_COORDINATE_BYTES * 2;
const P256_SIGNATURE_BYTES: usize = 64;
const P256_COORDINATE_BYTES_U32: u32 = 32;
const P256_PUBLIC_BLOB_BYTES_U32: u32 = 72;
const P256_SIGNATURE_BYTES_U32: u32 = 64;
const SHA256_BYTES_U32: u32 = 32;
const MAX_KEY_NAME_CHARS: usize = 128;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("Microsoft Platform Crypto Provider is unavailable")]
    ProviderUnavailable,
    #[error("TPM key state is missing or only partially provisioned")]
    PartialState,
    #[error("TPM key creation or opening failed")]
    KeyState,
    #[error("TPM key metadata is invalid or permits private-key export")]
    InsecureKey,
    #[error("TPM signing failed")]
    Signing,
    #[error("TPM key agreement failed")]
    Agreement,
    #[error("invalid P-256 public key")]
    InvalidPublicKey,
}

/// Two distinct, current-user P-256 keys held by the Microsoft Platform Crypto Provider.
///
/// The signing key can only sign request transcripts. The selection key can only perform ECDH for
/// private stanza selection. A partial pair fails closed and is never silently repaired.
pub struct WindowsCngKeySet {
    provider: OwnedHandle,
    signing: OwnedHandle,
    selection: OwnedHandle,
}

impl WindowsCngKeySet {
    /// Opens an existing pair or provisions both keys when neither exists.
    ///
    /// # Errors
    ///
    /// Returns an error when the TPM provider is unavailable, state is partial, or either key is
    /// malformed or exportable.
    pub fn open_or_create(desktop_id: [u8; 16]) -> Result<Self, Error> {
        let provider = open_provider()?;
        let (signing_name, selection_name) = key_names(desktop_id);
        let signing = open_key(provider.raw(), &signing_name)?;
        let selection = open_key(provider.raw(), &selection_name)?;
        let (signing, selection) = match (signing, selection) {
            (Some(signing), Some(selection)) => (signing, selection),
            (None, None) => {
                let signing =
                    create_key(provider.raw(), &signing_name, NCRYPT_ECDSA_P256_ALGORITHM)?;
                match create_key(provider.raw(), &selection_name, NCRYPT_ECDH_P256_ALGORITHM) {
                    Ok(selection) => (signing, selection),
                    Err(error) => {
                        signing.delete();
                        return Err(error);
                    }
                }
            }
            (signing, selection) => {
                drop(signing);
                drop(selection);
                return Err(Error::PartialState);
            }
        };
        validate_non_exportable(signing.raw())?;
        validate_non_exportable(selection.raw())?;
        let value = Self {
            provider,
            signing,
            selection,
        };
        if value.signing_public_key()? == value.selection_public_key()? {
            return Err(Error::InsecureKey);
        }
        Ok(value)
    }

    /// Returns the signing key's compressed SEC1 public point.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider does not return the exact canonical P-256 public blob.
    pub fn signing_public_key(&self) -> Result<EncodedPublicKey, Error> {
        export_public(self.signing.raw(), BCRYPT_ECDSA_PUBLIC_P256_MAGIC)
    }

    /// Returns the selection key's compressed SEC1 public point.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider does not return the exact canonical P-256 public blob.
    pub fn selection_public_key(&self) -> Result<EncodedPublicKey, Error> {
        export_public(self.selection.raw(), BCRYPT_ECDH_PUBLIC_P256_MAGIC)
    }
}

impl P256Signer for WindowsCngKeySet {
    fn public_key(&self) -> Result<EncodedPublicKey, ProtocolError> {
        self.signing_public_key()
            .map_err(|_| ProtocolError::KeyOperation)
    }

    fn sign_prehash(&self, digest: &[u8; 32]) -> Result<[u8; 64], ProtocolError> {
        let mut signature = [0_u8; P256_SIGNATURE_BYTES];
        let mut written = 0_u32;
        let status = unsafe {
            NCryptSignHash(
                self.signing.raw(),
                ptr::null(),
                digest.as_ptr(),
                SHA256_BYTES_U32,
                signature.as_mut_ptr(),
                P256_SIGNATURE_BYTES_U32,
                &raw mut written,
                0,
            )
        };
        if status != 0 || written as usize != signature.len() {
            signature.zeroize();
            return Err(ProtocolError::KeyOperation);
        }
        let parsed = Signature::from_slice(&signature).map_err(|_| ProtocolError::KeyOperation)?;
        let normalized = parsed.normalize_s().unwrap_or(parsed).to_bytes().into();
        signature.zeroize();
        Ok(normalized)
    }
}

impl P256KeyAgreement for WindowsCngKeySet {
    fn public_key(&self) -> Result<EncodedPublicKey, RecipientError> {
        self.selection_public_key()
            .map_err(|_| RecipientError::KeyAgreement)
    }

    fn agree(&self, peer: &EncodedPublicKey) -> Result<Zeroizing<[u8; 32]>, RecipientError> {
        agree(self.provider.raw(), self.selection.raw(), peer)
            .map_err(|_| RecipientError::KeyAgreement)
    }
}

struct OwnedHandle(NCRYPT_HANDLE);

impl OwnedHandle {
    const fn raw(&self) -> NCRYPT_HANDLE {
        self.0
    }

    fn delete(mut self) {
        if self.0 != 0 {
            unsafe {
                NCryptDeleteKey(self.0, 0);
            }
            self.0 = 0;
        }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}

fn open_provider() -> Result<OwnedHandle, Error> {
    let mut provider: NCRYPT_PROV_HANDLE = 0;
    let status =
        unsafe { NCryptOpenStorageProvider(&raw mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
    if status == 0 && provider != 0 {
        Ok(OwnedHandle(provider))
    } else {
        Err(Error::ProviderUnavailable)
    }
}

fn open_key(provider: NCRYPT_PROV_HANDLE, name: &[u16]) -> Result<Option<OwnedHandle>, Error> {
    let mut key: NCRYPT_KEY_HANDLE = 0;
    let status = unsafe { NCryptOpenKey(provider, &raw mut key, name.as_ptr(), 0, 0) };
    if status == 0 && key != 0 {
        Ok(Some(OwnedHandle(key)))
    } else if status == NTE_BAD_KEYSET || status == NTE_NOT_FOUND {
        Ok(None)
    } else {
        Err(Error::KeyState)
    }
}

fn create_key(
    provider: NCRYPT_PROV_HANDLE,
    name: &[u16],
    algorithm: *const u16,
) -> Result<OwnedHandle, Error> {
    let mut key: NCRYPT_KEY_HANDLE = 0;
    let status =
        unsafe { NCryptCreatePersistedKey(provider, &raw mut key, algorithm, name.as_ptr(), 0, 0) };
    if status != 0 || key == 0 {
        return Err(Error::KeyState);
    }
    let key = OwnedHandle(key);
    if unsafe { NCryptFinalizeKey(key.raw(), 0) } != 0 {
        key.delete();
        return Err(Error::KeyState);
    }
    Ok(key)
}

fn validate_non_exportable(key: NCRYPT_KEY_HANDLE) -> Result<(), Error> {
    let mut policy = 0_u32;
    let mut written = 0_u32;
    let status = unsafe {
        NCryptGetProperty(
            key,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            (&raw mut policy).cast(),
            4,
            &raw mut written,
            0,
        )
    };
    if status != 0 || written as usize != size_of::<u32>() || policy != 0 {
        return Err(Error::InsecureKey);
    }
    let mut private_size = 0_u32;
    let private_export = unsafe {
        NCryptExportKey(
            key,
            0,
            BCRYPT_ECCPRIVATE_BLOB,
            ptr::null(),
            ptr::null_mut(),
            0,
            &raw mut private_size,
            0,
        )
    };
    if private_export == 0 {
        return Err(Error::InsecureKey);
    }
    Ok(())
}

fn export_public(key: NCRYPT_KEY_HANDLE, expected_magic: u32) -> Result<EncodedPublicKey, Error> {
    let mut blob = [0_u8; P256_PUBLIC_BLOB_BYTES];
    let mut written = 0_u32;
    let status = unsafe {
        NCryptExportKey(
            key,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            ptr::null(),
            blob.as_mut_ptr(),
            P256_PUBLIC_BLOB_BYTES_U32,
            &raw mut written,
            0,
        )
    };
    if status != 0
        || written as usize != blob.len()
        || u32::from_le_bytes(blob[..4].try_into().map_err(|_| Error::InsecureKey)?)
            != expected_magic
        || u32::from_le_bytes(blob[4..8].try_into().map_err(|_| Error::InsecureKey)?)
            != P256_COORDINATE_BYTES_U32
    {
        return Err(Error::InsecureKey);
    }
    let mut uncompressed = [0_u8; 65];
    uncompressed[0] = 4;
    uncompressed[1..].copy_from_slice(&blob[ECC_BLOB_HEADER_BYTES..]);
    let public = PublicKey::from_sec1_bytes(&uncompressed).map_err(|_| Error::InsecureKey)?;
    public
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| Error::InsecureKey)
}

fn agree(
    provider: NCRYPT_PROV_HANDLE,
    private_key: NCRYPT_KEY_HANDLE,
    peer: &EncodedPublicKey,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let public = PublicKey::from_sec1_bytes(peer).map_err(|_| Error::InvalidPublicKey)?;
    if public.to_encoded_point(true).as_bytes() != peer {
        return Err(Error::InvalidPublicKey);
    }
    let point = public.to_encoded_point(false);
    let mut blob = Zeroizing::new([0_u8; P256_PUBLIC_BLOB_BYTES]);
    blob[..4].copy_from_slice(&BCRYPT_ECDH_PUBLIC_P256_MAGIC.to_le_bytes());
    blob[4..8].copy_from_slice(&P256_COORDINATE_BYTES_U32.to_le_bytes());
    blob[ECC_BLOB_HEADER_BYTES..].copy_from_slice(&point.as_bytes()[1..]);
    let mut imported: NCRYPT_KEY_HANDLE = 0;
    let status = unsafe {
        NCryptImportKey(
            provider,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            ptr::null(),
            &raw mut imported,
            blob.as_ptr(),
            P256_PUBLIC_BLOB_BYTES_U32,
            0,
        )
    };
    if status != 0 || imported == 0 {
        return Err(Error::Agreement);
    }
    let imported = OwnedHandle(imported);
    let mut secret = 0;
    if unsafe { NCryptSecretAgreement(private_key, imported.raw(), &raw mut secret, 0) } != 0
        || secret == 0
    {
        return Err(Error::Agreement);
    }
    let secret = OwnedHandle(secret);
    let mut raw = Zeroizing::new([0_u8; 32]);
    let mut written = 0_u32;
    let status = unsafe {
        NCryptDeriveKey(
            secret.raw(),
            BCRYPT_KDF_RAW_SECRET,
            ptr::null(),
            raw.as_mut_ptr(),
            P256_COORDINATE_BYTES_U32,
            &raw mut written,
            0,
        )
    };
    if status != 0 || written as usize != raw.len() {
        return Err(Error::Agreement);
    }
    raw.reverse();
    Ok(raw)
}

fn key_names(desktop_id: [u8; 16]) -> (Vec<u16>, Vec<u16>) {
    let suffix = desktop_id
        .iter()
        .fold(String::with_capacity(32), |mut value, byte| {
            use std::fmt::Write as _;
            write!(value, "{byte:02x}").expect("writing to String cannot fail");
            value
        });
    (
        wide(&format!("age-plugin-phone-{suffix}-signing")),
        wide(&format!("age-plugin-phone-{suffix}-selection")),
    )
}

fn wide(value: &str) -> Vec<u16> {
    assert!(!value.is_empty() && value.encode_utf16().count() <= MAX_KEY_NAME_CHARS);
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{SecretKey, ecdh::diffie_hellman, ecdsa::signature::hazmat::PrehashVerifier as _};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_id() -> [u8; 16] {
        let mut id = [0_u8; 16];
        id[..4].copy_from_slice(&std::process::id().to_le_bytes());
        id[4..].copy_from_slice(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                .to_le_bytes()[..12],
        );
        id
    }

    struct Cleanup([u8; 16]);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let Ok(provider) = open_provider() else {
                return;
            };
            let (signing_name, selection_name) = key_names(self.0);
            if let Ok(Some(key)) = open_key(provider.raw(), &signing_name) {
                key.delete();
            }
            if let Ok(Some(key)) = open_key(provider.raw(), &selection_name) {
                key.delete();
            }
        }
    }

    #[test]
    fn provisions_distinct_non_exportable_keys_and_reopens_them() {
        let id = unique_id();
        let _cleanup = Cleanup(id);
        let keys = WindowsCngKeySet::open_or_create(id).unwrap();
        let signing_public = keys.signing_public_key().unwrap();
        let selection_public = keys.selection_public_key().unwrap();
        assert_ne!(signing_public, selection_public);

        let digest = [0x42; 32];
        let signature = keys.sign_prehash(&digest).unwrap();
        let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&signing_public).unwrap();
        let parsed = Signature::from_slice(&signature).unwrap();
        verifying.verify_prehash(&digest, &parsed).unwrap();

        let peer = SecretKey::random(&mut rand_core::OsRng);
        let peer_public: EncodedPublicKey = peer
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let platform_shared = keys.agree(&peer_public).unwrap();
        let selection = PublicKey::from_sec1_bytes(&selection_public).unwrap();
        let software_shared = diffie_hellman(peer.to_nonzero_scalar(), selection.as_affine());
        assert_eq!(
            platform_shared.as_slice(),
            software_shared.raw_secret_bytes().as_slice()
        );

        drop(keys);
        let reopened = WindowsCngKeySet::open_or_create(id).unwrap();
        assert_eq!(reopened.signing_public_key().unwrap(), signing_public);
        assert_eq!(reopened.selection_public_key().unwrap(), selection_public);
        drop(reopened);
    }
}
