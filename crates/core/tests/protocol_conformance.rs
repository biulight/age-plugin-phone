//! Public byte expectations, independently consumed by Kotlin and Swift.
use age_plugin_phone_core::{
    protocol::{
        Error, PairingRecord, ReplayGuard, SignedPairingOffer, SignedPairingResponse,
        SignedUnwrapRequest, SignedUnwrapResponse, open_response, pairing_fingerprint,
        seal_response_with_ephemeral,
    },
    recipient::{
        PairedRecipient, matches_stanza_v2, unwrap_file_key, wrap_file_key_v2_with_ephemeral,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as B64};
use p256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, signature::Verifier as _},
    elliptic_curve::sec1::ToEncodedPoint as _,
};
fn key(n: u8) -> SecretKey {
    let mut b = [0; 32];
    b[31] = n;
    SecretKey::from_slice(&b).unwrap()
}
fn public(n: u8) -> [u8; 33] {
    key(n)
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn bytes(v: &serde_json::Value, field: &str) -> Vec<u8> {
    B64.decode(v[field].as_str().unwrap()).unwrap()
}
fn pairing() -> PairingRecord {
    PairingRecord {
        desktop_id: [0x11; 16],
        identity_id: [0x22; 16],
        desktop_signing_public_key: public(1),
        desktop_selection_public_key: public(7),
        phone_signing_public_key: public(2),
    }
}
#[test]
fn complete_phone_v2_vector_and_rejections() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/phone-v2-envelope.json")).unwrap();
    let p: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/pairing-transcript-v2.json")).unwrap();
    let offer = SignedPairingOffer::decode(&bytes(&p, "signed_offer_base64")).unwrap();
    let paired = SignedPairingResponse::decode(&bytes(&p, "signed_response_base64")).unwrap();
    paired.verify(&offer).unwrap();
    assert_eq!(
        pairing_fingerprint(&offer, &paired).as_slice(),
        bytes(&p, "fingerprint_base64")
    );
    let request = SignedUnwrapRequest::decode(&bytes(&v, "signed_request_base64")).unwrap();
    let recipient = PairedRecipient::parse(v["recipient"].as_str().unwrap()).unwrap();
    assert!(
        matches_stanza_v2(
            &recipient,
            &SigningKey::from(key(7)),
            &request.payload.recipient_stanza
        )
        .unwrap()
    );
    assert_eq!(
        *unwrap_file_key(&key(3), &request.payload.recipient_stanza).unwrap(),
        [0x55; 16]
    );
    let stanza = wrap_file_key_v2_with_ephemeral(&recipient, &[0x55; 16], &key(4)).unwrap();
    assert_stanza_fields(&v, &stanza, &request.payload.recipient_stanza);
    assert_eq!(
        SignedUnwrapRequest::sign(request.payload.clone(), &SigningKey::from(key(1)))
            .unwrap()
            .encode(),
        request.encode()
    );
    let verified = ReplayGuard::default()
        .verify_request(request, &pairing(), 1_000_000)
        .unwrap();
    assert_eq!(
        verified.digest().as_slice(),
        bytes(&v, "request_digest_base64")
    );
    let response = SignedUnwrapResponse::decode(&bytes(&v, "signed_response_base64")).unwrap();
    assert_eq!(
        seal_response_with_ephemeral(
            &verified,
            &[0x55; 16],
            &SigningKey::from(key(2)),
            &key(6),
            [0x66; 32]
        )
        .unwrap()
        .encode(),
        response.encode()
    );
    assert_eq!(
        *open_response(
            &response,
            &verified,
            &pairing(),
            &key(5),
            &mut ReplayGuard::default(),
            1_000_000
        )
        .unwrap(),
        [0x55; 16]
    );
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/protocol-rejections-v2.json")).unwrap();
    assert_eq!(cases["cases"].as_array().unwrap().len(), 39);
    for case in cases["cases"].as_array().unwrap() {
        assert_eq!(case["accept"], false);
        let b = bytes(case, "encoded_base64");
        let result = match case["target"].as_str().unwrap() {
            "offer" => SignedPairingOffer::decode(&b).and_then(|x| x.verify()),
            "pairing_response" => SignedPairingResponse::decode(&b).and_then(|x| x.verify(&offer)),
            "request" => SignedUnwrapRequest::decode(&b)
                .and_then(|x| ReplayGuard::default().verify_request(x, &pairing(), 1_000_000))
                .map(|_| ()),
            "response" => SignedUnwrapResponse::decode(&b)
                .and_then(|x| {
                    open_response(
                        &x,
                        &verified,
                        &pairing(),
                        &key(5),
                        &mut ReplayGuard::default(),
                        1_000_000,
                    )
                })
                .map(|_| ()),
            _ => panic!("unknown target"),
        };
        assert_eq!(
            result.unwrap_err(),
            expected_error(case),
            "{}",
            case["name"]
        );
    }
}

// Error names are Rust regression evidence, not a cross-language wire/error-string contract.
fn expected_error(case: &serde_json::Value) -> Error {
    let target = case["target"].as_str().unwrap();
    let name = case["name"]
        .as_str()
        .unwrap()
        .strip_prefix(&format!("{target}_"))
        .unwrap();
    match name {
        "version" => Error::UnsupportedVersion,
        "suite" => Error::UnsupportedSuite,
        "type" => Error::UnexpectedMessageType,
        "extra_field" | "nonminimal" | "trailing" | "malformed_stanza" => Error::Malformed,
        "high_s" => Error::InvalidSignature,
        "reused_roles" => Error::InvalidPublicKey,
        "wrong_identity" if target == "request" => Error::WrongIdentity,
        "wrong_desktop" if target == "request" => Error::WrongDesktop,
        "wrong_offer" | "wrong_request" | "wrong_identity" | "wrong_desktop" | "wrong_digest" => {
            Error::BindingMismatch
        }
        "ciphertext_tamper" => Error::Decryption,
        _ => panic!("unknown case"),
    }
}

#[test]
fn rejection_corpus_has_valid_signatures_before_protocol_policy_checks() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/protocol-rejections-v2.json")).unwrap();
    for case in cases["cases"].as_array().unwrap() {
        let encoded = bytes(case, "encoded_base64");
        let mut decoder = minicbor::Decoder::new(&encoded);
        assert_eq!(decoder.array().unwrap(), Some(2));
        let payload = decoder.bytes().unwrap();
        let raw = decoder.bytes().unwrap();
        let signature = Signature::from_slice(raw).unwrap();
        let name = case["name"].as_str().unwrap();
        let high_s = name.ends_with("_high_s");
        assert_eq!(signature.normalize_s().is_some(), high_s, "{name}");
        let signature = signature.normalize_s().unwrap_or(signature);
        let (domain, scalar) = match case["target"].as_str().unwrap() {
            "offer" => ("pairing-offer", 1),
            "pairing_response" => (
                "pairing-response",
                if name.ends_with("_reused_roles") {
                    7
                } else {
                    2
                },
            ),
            "request" => ("unwrap-request", 1),
            "response" => ("unwrap-response", 2),
            _ => panic!("unknown target"),
        };
        let input = [
            format!("age-plugin-phone/{domain}-signature/v2").as_bytes(),
            &[0],
            payload,
        ]
        .concat();
        SigningKey::from(key(scalar))
            .verifying_key()
            .verify(&input, &signature)
            .unwrap();
        let expected_remaining = usize::from(name.ends_with("_trailing"));
        assert_eq!(encoded.len() - decoder.position(), expected_remaining);
    }
}

fn assert_stanza_fields(
    vector: &serde_json::Value,
    generated: &age_plugin_phone_core::recipient::TaggedStanza,
    signed: &age_plugin_phone_core::recipient::TaggedStanza,
) {
    assert_eq!(generated.tag, signed.tag);
    assert_eq!(generated.args, signed.args);
    assert_eq!(generated.body, signed.body);
    assert_eq!(vector["stanza"]["tag"], signed.tag);
    assert_eq!(vector["stanza"]["args"], serde_json::json!(signed.args));
    assert_eq!(vector["stanza"]["body_base64"], B64.encode(&signed.body));
}
