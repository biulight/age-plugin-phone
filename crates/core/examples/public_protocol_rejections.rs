//! Deterministic, public-only mutations with explicit rejection expectations.
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as B64};
use minicbor::{Decoder, Encoder};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
fn bstr(value: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.bytes(value).unwrap();
    e.into_writer()
}
fn outer(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(2)
        .unwrap()
        .bytes(payload)
        .unwrap()
        .bytes(signature)
        .unwrap();
    e.into_writer()
}
fn replace(payload: &[u8], index: usize, replacement: &[u8]) -> Vec<u8> {
    let mut d = Decoder::new(payload);
    d.array().unwrap();
    for _ in 0..index {
        d.skip().unwrap();
    }
    let start = d.position();
    d.skip().unwrap();
    let end = d.position();
    [&payload[..start], replacement, &payload[end..]].concat()
}
fn sign(payload: &[u8], target: &str) -> Vec<u8> {
    let scalar = if matches!(target, "offer" | "request") {
        1
    } else {
        2
    };
    sign_as(payload, target, scalar)
}
fn sign_as(payload: &[u8], target: &str, scalar: u8) -> Vec<u8> {
    let mut bytes = [0; 32];
    bytes[31] = scalar;
    let key = SigningKey::from_slice(&bytes).unwrap();
    let domain = match target {
        "offer" => "pairing-offer",
        "pairing_response" => "pairing-response",
        "request" => "unwrap-request",
        "response" => "unwrap-response",
        _ => unreachable!(),
    };
    let input = [
        format!("age-plugin-phone/{domain}-signature/v2").as_bytes(),
        &[0],
        payload,
    ]
    .concat();
    let signature: Signature = key.sign(&input);
    let signature = signature.normalize_s().unwrap_or(signature);
    outer(payload, &signature.to_bytes())
}
// Keep the finite mutation inventory together for auditability.
#[allow(clippy::too_many_lines)]
fn main() {
    let pairing: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/pairing-transcript-v2.json")).unwrap();
    let envelope: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/phone-v2-envelope.json")).unwrap();
    let mut cases = Vec::new();
    for (target, source, field) in [
        ("offer", &pairing, "signed_offer_base64"),
        ("pairing_response", &pairing, "signed_response_base64"),
        ("request", &envelope, "signed_request_base64"),
        ("response", &envelope, "signed_response_base64"),
    ] {
        let encoded = B64.decode(source[field].as_str().unwrap()).unwrap();
        let mut d = Decoder::new(&encoded);
        d.array().unwrap();
        let payload = d.bytes().unwrap();
        let signature = d.bytes().unwrap();
        let mut add = |name: &str, bytes: Vec<u8>| {
            cases.push(serde_json::json!({"name": format!("{target}_{name}"), "target":target, "accept":false, "encoded_base64":B64.encode(bytes)}));
        };
        for (name, index, replacement) in [("version", 0, 3), ("type", 1, 9), ("suite", 2, 2)] {
            add(name, sign(&replace(payload, index, &[replacement]), target));
        }
        let mut extra = payload.to_vec();
        extra[0] += 1;
        extra.push(0xf6);
        add("extra_field", sign(&extra, target));
        let mut nonminimal = payload.to_vec();
        nonminimal.splice(1..2, [0x18, 2]);
        add("nonminimal", sign(&nonminimal, target));
        let mut trailing = encoded.clone();
        trailing.push(0);
        add("trailing", trailing);
        let mut high = signature.to_vec();
        let order: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
            0x25, 0x51,
        ];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let value = i16::from(order[i]) - i16::from(signature[32 + i]) - borrow;
            high[32 + i] = u8::try_from(value.rem_euclid(256)).unwrap();
            borrow = i16::from(value < 0);
        }
        add("high_s", outer(payload, &high));
        match target {
            "offer" => {
                let key = B64
                    .decode(
                        pairing["desktop_signing_public_key_base64"]
                            .as_str()
                            .unwrap(),
                    )
                    .unwrap();
                add(
                    "reused_roles",
                    sign(&replace(payload, 6, &bstr(&key)), target),
                );
            }
            "pairing_response" => {
                add(
                    "wrong_offer",
                    sign(&replace(payload, 6, &bstr(&[0; 32])), target),
                );
                let key = B64
                    .decode(
                        pairing["desktop_selection_public_key_base64"]
                            .as_str()
                            .unwrap(),
                    )
                    .unwrap();
                add(
                    "reused_roles",
                    sign_as(&replace(payload, 5, &bstr(&key)), target, 7),
                );
            }
            "request" => {
                let mut cursor = Decoder::new(payload);
                cursor.array().unwrap();
                for _ in 0..7 {
                    cursor.skip().unwrap();
                }
                let start = cursor.position();
                cursor.skip().unwrap();
                let stanza = &payload[start..cursor.position()];
                let malformed = replace(stanza, 2, &bstr(&[0; 31]));
                add(
                    "malformed_stanza",
                    sign(&replace(payload, 7, &malformed), target),
                );
                for (name, index) in [("wrong_identity", 4), ("wrong_desktop", 5)] {
                    add(
                        name,
                        sign(&replace(payload, index, &bstr(&[0; 16])), target),
                    );
                }
            }
            "response" => {
                for (name, index) in [
                    ("wrong_request", 3),
                    ("wrong_identity", 5),
                    ("wrong_desktop", 6),
                ] {
                    add(
                        name,
                        sign(&replace(payload, index, &bstr(&[0; 16])), target),
                    );
                }
                add(
                    "wrong_digest",
                    sign(&replace(payload, 4, &bstr(&[0; 32])), target),
                );
                add(
                    "ciphertext_tamper",
                    sign(&replace(payload, 9, &bstr(&[0; 32])), target),
                );
            }
            _ => unreachable!(),
        }
    }
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({"schema":"age-plugin-phone/protocol-rejections/v2","warning":"Public synthetic bytes only. Mutations are re-signed except high-S and trailing-byte cases.","pairing_fixture":"pairing-transcript-v2.json","envelope_fixture":"phone-v2-envelope.json","cases":cases})).unwrap());
}
