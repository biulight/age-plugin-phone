//! Verify public M0 `CryptoKit` evidence using the same Rust crypto library as core.
//! No Keychain or native private-key operations. Input is synthetic public evidence.
#[cfg(target_os = "macos")]
mod verify {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use p256::{
        PublicKey, SecretKey,
        ecdh::diffie_hellman,
        ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
    };
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use std::io::Read;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Report {
        public_binding: String,
        signing_public: String,
        selection_public: String,
        signature_der: String,
        synthetic_ecdh_sha256: String,
    }

    fn decode(value: &str) -> Result<Vec<u8>, &'static str> {
        STANDARD.decode(value).map_err(|_| "base64")
    }

    fn check(bytes: &[u8]) -> Result<(), &'static str> {
        let report: Report = serde_json::from_slice(bytes).map_err(|_| "report_format")?;
        let signing = decode(&report.signing_public)?;
        let selection = decode(&report.selection_public)?;
        if signing.len() != 33 || selection.len() != 33 || signing == selection {
            return Err("public_keys");
        }
        let verifier = VerifyingKey::from_sec1_bytes(&signing).map_err(|_| "signing_key")?;
        let public = PublicKey::from_sec1_bytes(&selection).map_err(|_| "selection_key")?;
        let signature =
            Signature::from_der(&decode(&report.signature_der)?).map_err(|_| "signature_der")?;
        let normalized = signature.normalize_s().unwrap_or(signature);
        let fixed = Signature::from_slice(&normalized.to_bytes()).map_err(|_| "fixed_signature")?;
        let digest = Sha256::digest(b"age-plugin-phone M0 synthetic digest");
        verifier
            .verify_prehash(&digest, &fixed)
            .map_err(|_| "signature_verify")?;
        if verifier.verify_prehash(&[0; 32], &fixed).is_ok()
            || VerifyingKey::from(public)
                .verify_prehash(&digest, &fixed)
                .is_ok()
        {
            return Err("wrong_digest_or_key_accepted");
        }
        // Fixed public test scalar, never a real identity. SecretKey and SharedSecret
        // clear their owned secret storage on drop; no raw result leaves this process.
        let peer = SecretKey::from_slice(&[7; 32]).map_err(|_| "synthetic_peer")?;
        let shared = diffie_hellman(peer.to_nonzero_scalar(), public.as_affine());
        if Sha256::digest(shared.raw_secret_bytes()).as_slice()
            != decode(&report.synthetic_ecdh_sha256)?
        {
            return Err("ecdh_interoperability");
        }
        let mut binding = Sha256::new();
        binding.update(&signing);
        binding.update(&selection);
        if binding.finalize().as_slice() != decode(&report.public_binding)? {
            return Err("binding");
        }
        Ok(())
    }

    pub fn run() -> Result<(), &'static str> {
        let mut input = Vec::new();
        std::io::stdin()
            .take(4097)
            .read_to_end(&mut input)
            .map_err(|_| "read")?;
        if input.len() > 4096 {
            return Err("oversized");
        }
        check(&input)?;
        println!("PASS rust_prehash_low_s_ecdh_binding");
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn malformed_reports_fail_without_native_calls() {
            for input in [b"{}".as_slice(), b"null", b"{\"unknown\":1}"] {
                assert!(super::check(input).is_err());
            }
        }
    }
}

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "macos")]
    let result = verify::run();
    #[cfg(not(target_os = "macos"))]
    let result: Result<(), &str> = Err("unsupported_os");
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FAIL {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
