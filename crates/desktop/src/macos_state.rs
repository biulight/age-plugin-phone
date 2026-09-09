//! Versioned, signed hardware-reference metadata. Storage hardening is tracked by macOS PR 3.
// Unit fixtures elsewhere use software operations; this module never falls back to them.
#![cfg_attr(test, allow(dead_code))]
use super::{EncodedPublicKey, Id, P256KeyAgreement, P256Signer, PairingError};
use age_plugin_phone_platform_keys::macos::{MacosKeyAgreement, MacosSigner};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier as _};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};
use std::{fs::OpenOptions, io::Write as _, os::unix::fs::OpenOptionsExt as _, path::Path};
use zeroize::Zeroizing;

// APSE2 | suite:u16be | desktop ID | signing public | selection public |
// signing length:u16be | selection length:u16be | signing ref | selection ref | signature.
const MAGIC: &[u8; 5] = b"APSE2";
const HEADER: usize = 89 + 4;
const MAX_REFERENCE: usize = 4096;
const MAX_STATE: usize = HEADER + 2 * MAX_REFERENCE + 64;
const DOMAIN: &[u8] = b"age-plugin-phone/macos-key-metadata/v2\0";

pub struct DesktopKeyState {
    pub desktop_id: Id,
    signing: MacosSigner,
    selection: MacosKeyAgreement,
}
impl DesktopKeyState {
    pub fn open_or_create(
        path: &Path,
        random: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, PairingError> {
        match Self::open(path) {
            Ok(value) => Ok(value),
            Err(PairingError::StateMissing) => {
                let mut id = [0; 16];
                random.fill_bytes(&mut id);
                Self::create_new(path, id)
            }
            Err(error) => Err(error),
        }
    }
    pub fn create_new(path: &Path, desktop_id: Id) -> Result<Self, PairingError> {
        // Reserve before native generation. Failure leaves unavailable state, never an implicit
        // permission to generate replacement roles. Concurrent creators cannot both commit.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| PairingError::State)?;
        let signing = MacosSigner::create().map_err(|_| PairingError::State)?;
        let selection = MacosKeyAgreement::create().map_err(|_| PairingError::State)?;
        let value = Self {
            desktop_id,
            signing,
            selection,
        };
        let _secret = value
            .selection
            .agree(&value.signing_public_key()?)
            .map_err(|_| PairingError::State)?;
        let encoded = value.encode()?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|_| PairingError::State)?;
        age_plugin_phone_platform_storage::unix::private_file::sync_directory(
            path.parent().ok_or(PairingError::State)?,
        )
        .map_err(|_| PairingError::State)?;
        Ok(value)
    }
    pub fn open(path: &Path) -> Result<Self, PairingError> {
        use age_plugin_phone_platform_storage::unix::private_file::{self, Error};
        let bytes = Zeroizing::new(
            private_file::read_private_file(path, MAX_STATE as u64).map_err(|e| match e {
                Error::Missing => PairingError::StateMissing,
                _ => PairingError::State,
            })?,
        );
        let metadata = Metadata::parse(&bytes)?;
        let signing = MacosSigner::open(metadata.signing, &metadata.signing_public)
            .map_err(|_| PairingError::State)?;
        let selection = MacosKeyAgreement::open(metadata.selection, &metadata.selection_public)
            .map_err(|_| PairingError::State)?;
        // Exercise both private operations: merely reading cached public material cannot establish
        // that this enclave can use the references. Neither operation authorizes a phone unwrap.
        let proof = signing
            .sign_prehash(&digest(&bytes))
            .map_err(|_| PairingError::State)?;
        verify(&metadata.signing_public, &digest(&bytes), &proof)?;
        let _secret = selection
            .agree(&metadata.signing_public)
            .map_err(|_| PairingError::State)?;
        Ok(Self {
            desktop_id: metadata.id,
            signing,
            selection,
        })
    }
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, PairingError> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&age_plugin_phone_core::protocol::ALGORITHM_SUITE.to_be_bytes());
        bytes.extend_from_slice(&self.desktop_id);
        bytes.extend_from_slice(&self.signing_public_key()?);
        bytes.extend_from_slice(&self.selection_public_key()?);
        for reference in [
            self.signing.wrapped_reference(),
            self.selection.wrapped_reference(),
        ] {
            bytes.extend_from_slice(
                &u16::try_from(reference.len())
                    .map_err(|_| PairingError::State)?
                    .to_be_bytes(),
            );
        }
        bytes.extend_from_slice(self.signing.wrapped_reference());
        bytes.extend_from_slice(self.selection.wrapped_reference());
        let signature = self
            .signing
            .sign_prehash(&digest(&bytes))
            .map_err(|_| PairingError::State)?;
        bytes.extend_from_slice(&signature);
        Metadata::parse(&bytes)?;
        Ok(bytes)
    }
    #[must_use]
    pub fn signer(&self) -> &dyn P256Signer {
        &self.signing
    }
    #[must_use]
    pub fn agreement(&self) -> &dyn P256KeyAgreement {
        &self.selection
    }
    pub fn signing_public_key(&self) -> Result<EncodedPublicKey, PairingError> {
        self.signer().public_key().map_err(|_| PairingError::State)
    }
    pub fn selection_public_key(&self) -> Result<EncodedPublicKey, PairingError> {
        self.agreement()
            .public_key()
            .map_err(|_| PairingError::State)
    }
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(bytes)
        .finalize()
        .into()
}
fn verify(public: &[u8; 33], digest: &[u8; 32], signature: &[u8]) -> Result<(), PairingError> {
    let signature = Signature::from_slice(signature).map_err(|_| PairingError::State)?;
    if signature.normalize_s().is_some() {
        return Err(PairingError::State);
    }
    VerifyingKey::from_sec1_bytes(public)
        .map_err(|_| PairingError::State)?
        .verify_prehash(digest, &signature)
        .map_err(|_| PairingError::State)
}
struct Metadata<'a> {
    id: Id,
    signing_public: EncodedPublicKey,
    selection_public: EncodedPublicKey,
    signing: &'a [u8],
    selection: &'a [u8],
}
impl<'a> Metadata<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, PairingError> {
        if bytes.len() < HEADER + 66
            || bytes.len() > MAX_STATE
            || &bytes[..5] != MAGIC
            || bytes[5..7] != age_plugin_phone_core::protocol::ALGORITHM_SUITE.to_be_bytes()
        {
            return Err(PairingError::State);
        }
        let signing_len = usize::from(u16::from_be_bytes(bytes[89..91].try_into().unwrap()));
        let selection_len = usize::from(u16::from_be_bytes(bytes[91..93].try_into().unwrap()));
        if signing_len == 0
            || selection_len == 0
            || signing_len > MAX_REFERENCE
            || selection_len > MAX_REFERENCE
            || bytes.len() != HEADER + signing_len + selection_len + 64
        {
            return Err(PairingError::State);
        }
        let value = Self {
            id: bytes[7..23].try_into().unwrap(),
            signing_public: bytes[23..56].try_into().unwrap(),
            selection_public: bytes[56..89].try_into().unwrap(),
            signing: &bytes[HEADER..HEADER + signing_len],
            selection: &bytes[HEADER + signing_len..bytes.len() - 64],
        };
        if value.signing_public == value.selection_public
            || value.signing == value.selection
            || p256::PublicKey::from_sec1_bytes(&value.selection_public).is_err()
        {
            return Err(PairingError::State);
        }
        verify(
            &value.signing_public,
            &digest(&bytes[..bytes.len() - 64]),
            &bytes[bytes.len() - 64..],
        )?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn synthetic_metadata() -> Vec<u8> {
        let signer = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let selection = p256::ecdsa::SigningKey::from_slice(&[8; 32]).unwrap();
        let mut bytes = Vec::from(MAGIC.as_slice());
        bytes.extend_from_slice(&age_plugin_phone_core::protocol::ALGORITHM_SUITE.to_be_bytes());
        bytes.extend_from_slice(&[1; 16]);
        bytes.extend_from_slice(&P256Signer::public_key(&signer).unwrap());
        bytes.extend_from_slice(&P256Signer::public_key(&selection).unwrap());
        bytes.extend_from_slice(&[0, 1, 0, 1, 2, 3]);
        let signature = signer.sign_prehash(&digest(&bytes)).unwrap();
        bytes.extend_from_slice(&signature);
        bytes
    }
    #[test]
    fn signed_metadata_rejects_mutation_truncation_unknown_fields_and_software_state() {
        let bytes = synthetic_metadata();
        assert!(Metadata::parse(&bytes).is_ok());
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(
                Metadata::parse(&changed).is_err(),
                "accepted mutation at {index}"
            );
            assert!(Metadata::parse(&bytes[..index]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Metadata::parse(&extra).is_err());
        let mut old = vec![0; 85];
        old[..5].copy_from_slice(b"APDK2");
        assert!(Metadata::parse(&old).is_err());
    }
    #[test]
    fn missing_partial_and_legacy_state_never_repaired() {
        let root = std::env::temp_dir().join(format!("phone-m1-negative-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("keys");
        assert!(matches!(
            DesktopKeyState::open(&path),
            Err(PairingError::StateMissing)
        ));
        for bytes in [&[][..], &b"APDK2"[..]] {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(bytes).unwrap();
            assert!(DesktopKeyState::open_or_create(&path, &mut OsRng).is_err());
            assert!(DesktopKeyState::create_new(&path, [1; 16]).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires real Secure Enclave; isolated metadata and child process only"]
    fn native_metadata_lifecycle() {
        const CHILD: &str = "AGE_PHONE_M1_TEST_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let key = DesktopKeyState::open(Path::new(&path)).unwrap();
            assert_eq!(key.desktop_id, [19; 16]);
            return;
        }
        let root = std::env::temp_dir().join(format!("phone-m1-native-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("keys");
        let key = DesktopKeyState::create_new(&path, [19; 16]).unwrap();
        let original = Zeroizing::new(std::fs::read(&path).unwrap());
        assert!(DesktopKeyState::create_new(&path, [20; 16]).is_err());
        let reopened = DesktopKeyState::open(&path).unwrap();
        assert_eq!(
            key.signing_public_key().unwrap(),
            reopened.signing_public_key().unwrap()
        );
        assert_eq!(
            key.selection_public_key().unwrap(),
            reopened.selection_public_key().unwrap()
        );
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "pairing::macos_state::tests::native_metadata_lifecycle",
                "--ignored",
                "--exact",
            ])
            .env(CHILD, &path)
            .status()
            .unwrap();
        assert!(status.success());
        // A complete reference loss is unavailable; no partial-key repair or implicit overwrite.
        std::fs::write(&path, &original[..original.len() / 2]).unwrap();
        assert!(DesktopKeyState::open_or_create(&path, &mut OsRng).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            DesktopKeyState::open(&path),
            Err(PairingError::StateMissing)
        ));
        let race = root.join("concurrent");
        let barrier = std::sync::Barrier::new(2);
        let winners = std::thread::scope(|scope| {
            let attempt = || {
                barrier.wait();
                DesktopKeyState::create_new(&race, [21; 16]).is_ok()
            };
            let first = scope.spawn(attempt);
            let second = scope.spawn(attempt);
            usize::from(first.join().unwrap()) + usize::from(second.join().unwrap())
        });
        assert_eq!(winners, 1);
        assert_eq!(DesktopKeyState::open(&race).unwrap().desktop_id, [21; 16]);
        std::fs::remove_file(race).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
