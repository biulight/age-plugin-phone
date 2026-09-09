//! Research harness, deliberately not exported from the platform library.
//! Only synthetic, independent desktop-role keys in a dedicated random namespace.
use core_foundation::{
    base::{CFType, TCFType},
    boolean::CFBoolean,
    dictionary::CFDictionary,
    number::CFNumber,
    string::{CFString, CFStringRef},
};
use p256::{
    PublicKey,
    ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
    elliptic_curve::sec1::ToEncodedPoint,
};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::{ItemClass, ItemSearchOptions, KeyClass, Reference, SearchResult},
    key::{Algorithm, SecKey},
};
use security_framework_sys::{
    access_control::kSecAccessControlPrivateKeyUsage,
    item::{
        kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType,
        kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrSynchronizable, kSecAttrTokenID,
        kSecAttrTokenIDSecureEnclave, kSecPrivateKeyAttrs, kSecUseDataProtectionKeychain,
    },
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, String>;
const ROLES: [&str; 2] = ["signing", "selection"];

fn label(scope: &str, role: &str) -> String {
    format!("org.age-plugin-phone.m0.v1.{scope}.{role}")
}

fn search(scope: &str, role: &str) -> ItemSearchOptions {
    let mut query = ItemSearchOptions::new();
    query
        .ignore_legacy_keychains()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(&label(scope, role))
        .cloud_sync(Some(false))
        .load_refs(true)
        .limit(2);
    query
}

fn lookup(scope: &str, role: &str) -> Result<Option<SecKey>> {
    match search(scope, role).search() {
        Err(error) if error.code() == -25300 => Ok(None),
        Err(error) => Err(format!("lookup_{role}:osstatus={}", error.code())),
        Ok(mut results) if results.len() == 1 => match results.pop() {
            Some(SearchResult::Ref(Reference::Key(key))) => Ok(Some(key)),
            _ => Err("unexpected_key_type".into()),
        },
        Ok(_) => Err("ambiguous_key_reference".into()),
    }
}

// Caller supplies valid static Security.framework string constants.
unsafe fn dictionary(pairs: &[(CFStringRef, CFType)]) -> CFDictionary {
    let owned: Vec<_> = pairs
        .iter()
        .map(|(key, value)| {
            (
                unsafe { CFString::wrap_under_get_rule(*key) },
                value.clone(),
            )
        })
        .collect();
    CFDictionary::from_CFType_pairs(&owned).to_untyped()
}

// GenerateKeyOptions also persists a public item on macOS. Use the narrow
// dictionary API to persist only the private item that this probe can delete.
#[allow(deprecated)]
fn create(scope: &str, role: &str) -> Result<()> {
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlPrivateKeyUsage,
    )
    .map_err(|e| format!("access_control:osstatus={}", e.code()))?;
    // SAFETY: all inputs here are static Security.framework CFString constants;
    // values are retained by the owned dictionary for the duration of generation.
    let attrs = unsafe {
        let private = dictionary(&[
            (kSecAttrIsPermanent, CFBoolean::true_value().as_CFType()),
            (
                kSecAttrLabel,
                CFString::new(&label(scope, role)).as_CFType(),
            ),
            (kSecAttrAccessControl, access.as_CFType()),
        ]);
        dictionary(&[
            (
                kSecAttrKeyType,
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
            ),
            (kSecAttrKeySizeInBits, CFNumber::from(256).as_CFType()),
            (
                kSecAttrTokenID,
                CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType(),
            ),
            (
                kSecUseDataProtectionKeychain,
                CFBoolean::true_value().as_CFType(),
            ),
            (kSecAttrSynchronizable, CFBoolean::false_value().as_CFType()),
            (kSecPrivateKeyAttrs, private.as_CFType()),
        ])
    };
    SecKey::generate(attrs).map_err(|e| format!("create_{role}:cfcode={}", e.code()))?;
    Ok(())
}

fn public(key: &SecKey) -> Result<PublicKey> {
    let bytes = key
        .public_key()
        .and_then(|k| k.external_representation())
        .ok_or("public_key_unavailable")?;
    PublicKey::from_sec1_bytes(bytes.bytes()).map_err(|_| "invalid_p256_public_key".into())
}

fn check_hardware(key: &SecKey) -> Result<()> {
    // SAFETY: Security.framework constants have static lifetime. The owned CFString
    // retains the token; the attribute pointer is borrowed only while dict is alive.
    let enclave = unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) };
    let attributes = key.attributes();
    let token = attributes
        .find(unsafe { kSecAttrTokenID.cast::<std::ffi::c_void>() })
        .ok_or("missing_hardware_token")?;
    if !unsafe { core_foundation::base::CFEqual(*token, enclave.as_CFTypeRef()) != 0 } {
        return Err("not_secure_enclave".into());
    }
    if key.external_representation().is_some() {
        return Err("private_key_exportable".into());
    }
    public(key)?;
    Ok(())
}

fn verify(scope: &str) -> Result<()> {
    let signing = lookup(scope, ROLES[0])?.ok_or("missing_signing")?;
    let selection = lookup(scope, ROLES[1])?.ok_or("missing_selection")?;
    check_hardware(&signing)?;
    check_hardware(&selection)?;
    let signing_public = public(&signing)?;
    let selection_public = public(&selection)?;
    if signing_public == selection_public {
        return Err("roles_not_independent".into());
    }
    let digest = Sha256::digest(b"age-plugin-phone M0 synthetic digest");
    let der = signing
        .create_signature(Algorithm::ECDSASignatureDigestX962SHA256, &digest)
        .map_err(|e| format!("sign:cfcode={}", e.code()))?;
    let signature = Signature::from_der(&der).map_err(|_| "invalid_signature_der")?;
    let signature = signature.normalize_s().unwrap_or(signature);
    let signature =
        Signature::from_slice(&signature.to_bytes()).map_err(|_| "invalid_fixed_signature")?;
    let verifier = VerifyingKey::from(signing_public);
    verifier
        .verify_prehash(&digest, &signature)
        .map_err(|_| "digest_interoperability")?;
    if verifier.verify_prehash(&[0; 32], &signature).is_ok() {
        return Err("wrong_digest_accepted".into());
    }
    // Both directions remain in hardware; only synthetic shared results enter memory.
    let left = Zeroizing::new(
        signing
            .key_exchange(
                Algorithm::ECDHKeyExchangeStandard,
                &selection.public_key().ok_or("missing_public")?,
                32,
                None,
            )
            .map_err(|e| format!("ecdh:cfcode={}", e.code()))?,
    );
    let right = Zeroizing::new(
        selection
            .key_exchange(
                Algorithm::ECDHKeyExchangeStandard,
                &signing.public_key().ok_or("missing_public")?,
                32,
                None,
            )
            .map_err(|e| format!("ecdh:cfcode={}", e.code()))?,
    );
    if left.len() != 32 || *left != *right {
        return Err("ecdh_mismatch".into());
    }
    // A public digest allows cross-process / build comparison, without logging refs.
    let mut binding = Sha256::new();
    binding.update(signing_public.to_encoded_point(true).as_bytes());
    binding.update(selection_public.to_encoded_point(true).as_bytes());
    println!("PASS verify public_binding={:x}", binding.finalize());
    Ok(())
}

fn delete(scope: &str, roles: &[&str]) -> Result<()> {
    for role in roles {
        if let Some(key) = lookup(scope, role)? {
            check_hardware(&key)?;
            // Delete the exact resolved item, never a namespace-wide query.
            key.delete()
                .map_err(|e| format!("delete_{role}:osstatus={}", e.code()))?;
        }
        if lookup(scope, role)?.is_some() {
            return Err("delete_not_effective".into());
        }
    }
    println!("PASS delete");
    Ok(())
}

pub fn run(args: &[String]) -> Result<()> {
    if args.len() != 2
        || args[1].len() != 32
        || !args[1]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("usage: macos-key-probe create|verify|delete|delete-selection <random-32-lowercase-hex-run-id>".into());
    }
    let scope = &args[1];
    match args[0].as_str() {
        "create" => {
            for role in ROLES {
                if lookup(scope, role)?.is_some() {
                    return Err("scope_already_exists".into());
                }
            }
            // Do not erase uncertain partial state on failure. Explicit delete can
            // target this isolated run later, including after process termination.
            for role in ROLES {
                create(scope, role)?;
            }
            verify(scope)
        }
        "verify" => verify(scope),
        "delete" => delete(scope, &ROLES),
        "delete-selection" => delete(scope, &[ROLES[1]]),
        _ => Err("unknown_command".into()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn invalid_arguments_never_reach_keychain() {
        for args in [
            vec![],
            vec!["create".into()],
            vec!["create".into(), "../state".into()],
            vec!["unknown".into(), "a".repeat(32)],
            vec!["verify".into(), "A".repeat(32)],
        ] {
            assert!(super::run(&args).is_err());
        }
    }
}
