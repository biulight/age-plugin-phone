//! Operation-only `CryptoKit` Secure Enclave wrappers. No software fallback or persistent Keychain
//! items. Wrapped references remain usable by other builds on this Mac; deletion is not revocation.
#![allow(clippy::missing_errors_doc)]
use age_plugin_phone_core::{protocol, recipient};
use p256::{PublicKey, ecdsa::Signature, elliptic_curve::sec1::ToEncodedPoint as _};
use zeroize::Zeroizing;

const MAX_REFERENCE: usize = 4096;

#[derive(Debug, thiserror::Error)]
#[error("macOS Secure Enclave key operation unavailable or invalid")]
pub struct Error;

unsafe extern "C" {
    fn age_phone_macos_enclave_available() -> i32;
    fn age_phone_macos_key(
        op: i32,
        role: i32,
        reference: *const u8,
        reference_len: usize,
        input: *const u8,
        input_len: usize,
        output: *mut u8,
        capacity: usize,
        length: *mut usize,
    ) -> i32;
}

/// Read-only hardware capability hint; successful key creation/reopening remains authoritative.
#[must_use]
pub fn secure_enclave_available() -> bool {
    // SAFETY: the synchronous Swift function has no arguments, pointers, or retained state.
    unsafe { age_phone_macos_enclave_available() == 1 }
}

fn operation(
    op: i32,
    role: i32,
    reference: &[u8],
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    let mut length = 0;
    // SAFETY: all pointers borrow live slices for this synchronous call. Swift bounds every
    // write by capacity, retains no pointers, and returns only a status and initialized length.
    let status = unsafe {
        age_phone_macos_key(
            op,
            role,
            reference.as_ptr(),
            reference.len(),
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
            &raw mut length,
        )
    };
    if status != 0 || length == 0 || length > output.len() {
        return Err(Error);
    }
    Ok(length)
}

struct Key {
    role: i32,
    reference: Zeroizing<Vec<u8>>,
    public: [u8; 33],
}
impl Key {
    fn create(role: i32) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new(vec![0; MAX_REFERENCE]);
        let len = operation(0, role, &[], &[], &mut bytes)?;
        bytes.truncate(len);
        Self::open(role, &bytes)
    }
    fn open(role: i32, reference: &[u8]) -> Result<Self, Error> {
        if reference.is_empty() || reference.len() > MAX_REFERENCE {
            return Err(Error);
        }
        let mut output = [0; 65];
        if operation(1, role, reference, &[], &mut output)? != 65 {
            return Err(Error);
        }
        let public = PublicKey::from_sec1_bytes(&output)
            .map_err(|_| Error)?
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| Error)?;
        Ok(Self {
            role,
            reference: Zeroizing::new(reference.to_vec()),
            public,
        })
    }
}

/// Only the signing operation is exposed for this role.
pub struct MacosSigner(Key);
/// Only the selection agreement operation is exposed for this role.
pub struct MacosKeyAgreement(Key);

macro_rules! constructors {
    ($name:ident, $role:expr) => {
        impl $name {
            pub fn create() -> Result<Self, Error> {
                Ok(Self(Key::create($role)?))
            }
            pub fn open(reference: &[u8], expected_public: &[u8; 33]) -> Result<Self, Error> {
                let key = Key::open($role, reference)?;
                if &key.public != expected_public {
                    return Err(Error);
                }
                Ok(Self(key))
            }
            /// Opaque hardware-encrypted representation for protected local metadata only.
            #[must_use]
            pub fn wrapped_reference(&self) -> &[u8] {
                &self.0.reference
            }
        }
    };
}
constructors!(MacosSigner, 0);
constructors!(MacosKeyAgreement, 1);

impl protocol::P256Signer for MacosSigner {
    fn public_key(&self) -> Result<[u8; 33], protocol::Error> {
        Ok(self.0.public)
    }
    fn sign_prehash(&self, digest: &[u8; 32]) -> Result<[u8; 64], protocol::Error> {
        let mut output = [0; 64];
        let len = operation(2, self.0.role, &self.0.reference, digest, &mut output)
            .map_err(|_| protocol::Error::KeyOperation)?;
        if len != 64 {
            return Err(protocol::Error::KeyOperation);
        }
        let signature =
            Signature::from_slice(&output).map_err(|_| protocol::Error::KeyOperation)?;
        Ok(signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .into())
    }
}
impl recipient::P256KeyAgreement for MacosKeyAgreement {
    fn public_key(&self) -> Result<[u8; 33], recipient::Error> {
        Ok(self.0.public)
    }
    fn agree(&self, peer: &[u8; 33]) -> Result<Zeroizing<[u8; 32]>, recipient::Error> {
        let peer =
            PublicKey::from_sec1_bytes(peer).map_err(|_| recipient::Error::InvalidPublicKey)?;
        let mut output = Zeroizing::new([0; 32]);
        let len = operation(
            3,
            self.0.role,
            &self.0.reference,
            peer.to_encoded_point(false).as_bytes(),
            output.as_mut(),
        )
        .map_err(|_| recipient::Error::InvalidPublicKey)?;
        if len != 32 {
            return Err(recipient::Error::InvalidPublicKey);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_references_fail_before_native_access() {
        for bytes in [&[][..], &[0; MAX_REFERENCE + 1][..]] {
            assert!(MacosSigner::open(bytes, &[0; 33]).is_err());
            assert!(MacosKeyAgreement::open(bytes, &[0; 33]).is_err());
        }
    }
}

#[cfg(test)]
mod hardware_tests {
    use super::*;
    use p256::ecdsa::{VerifyingKey, signature::hazmat::PrehashVerifier as _};
    use protocol::P256Signer as _;
    use recipient::P256KeyAgreement as _;

    #[test]
    #[ignore = "requires real Secure Enclave; creates only transient isolated test keys"]
    fn native_roles_prehash_ecdh_and_reopen() {
        let signer = MacosSigner::create().unwrap();
        let selection = MacosKeyAgreement::create().unwrap();
        let public = signer.public_key().unwrap();
        let selection_public = selection.public_key().unwrap();
        assert_ne!(public, selection_public);
        let reopened = MacosSigner::open(signer.wrapped_reference(), &public).unwrap();
        let reopened_selection =
            MacosKeyAgreement::open(selection.wrapped_reference(), &selection_public).unwrap();
        let digest = [42; 32];
        let signature = Signature::from_slice(&reopened.sign_prehash(&digest).unwrap()).unwrap();
        assert!(signature.normalize_s().is_none());
        let verifier = VerifyingKey::from_sec1_bytes(&public).unwrap();
        verifier.verify_prehash(&digest, &signature).unwrap();
        assert!(verifier.verify_prehash(&[43; 32], &signature).is_err());
        let peer = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let peer_public = protocol::P256Signer::public_key(&peer).unwrap();
        let actual = reopened_selection.agree(&peer_public).unwrap();
        let expected = recipient::P256KeyAgreement::agree(&peer, &selection_public).unwrap();
        assert!(*actual == *expected, "ECDH mismatch");
        assert!(selection.agree(&[0; 33]).is_err());
        assert!(MacosSigner::open(signer.wrapped_reference(), &selection_public).is_err());
        assert!(MacosKeyAgreement::open(selection.wrapped_reference(), &public).is_err());
        let mut damaged = Zeroizing::new(signer.wrapped_reference().to_vec());
        damaged[0] ^= 1;
        assert!(MacosSigner::open(&damaged, &public).is_err());
    }
}
