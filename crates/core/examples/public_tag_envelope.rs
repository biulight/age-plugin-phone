//! Regenerate the public p256tag request/response vector without changing protocol v2.
use age_plugin_phone_core::{
    protocol::{PairingRecord, ReplayGuard, SignedUnwrapRequest, seal_response_with_ephemeral},
    recipient::{Recipient, tag},
};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as B64};
use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint as _};

fn key(n: u8) -> SecretKey {
    let mut scalar = [0; 32];
    scalar[31] = n;
    SecretKey::from_slice(&scalar).unwrap()
}
fn public(n: u8) -> [u8; 33] {
    key(n)
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn main() {
    let mut vector: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/offline-envelope-v2.json")).unwrap();
    let original = SignedUnwrapRequest::decode(
        &B64.decode(vector["signed_request_base64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let mut payload = original.payload;
    payload.recipient_stanza = tag::wrap_with_ephemeral(
        &Recipient::from_public_key_bytes(&public(3)).unwrap(),
        &[0x55; 16],
        &key(4),
    )
    .unwrap();
    let request = SignedUnwrapRequest::sign(payload, &SigningKey::from(key(1))).unwrap();
    let pairing = PairingRecord {
        desktop_id: [0x11; 16],
        identity_id: [0x22; 16],
        desktop_signing_public_key: public(1),
        desktop_selection_public_key: public(7),
        phone_signing_public_key: public(2),
    };
    let verified = ReplayGuard::default()
        .verify_request(request.clone(), &pairing, 1_000_000)
        .unwrap();
    let response = seal_response_with_ephemeral(
        &verified,
        &[0x55; 16],
        &SigningKey::from(key(2)),
        &key(6),
        [0x66; 32],
    )
    .unwrap();
    vector["schema"] = "age-plugin-phone/p256tag-envelope-test-vector/v2".into();
    vector["signed_request_base64"] = B64.encode(request.encode()).into();
    vector["request_digest_base64"] = B64.encode(verified.digest()).into();
    vector["signed_response_base64"] = B64.encode(response.encode()).into();
    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}
