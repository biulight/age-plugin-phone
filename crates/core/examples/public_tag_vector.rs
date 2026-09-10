use age_plugin_phone_core::recipient::{Recipient, tag};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint as _};

const IDENTITY_SCALAR: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
const EPHEMERAL_SCALAR: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];
const FILE_KEY: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn main() {
    let identity = SecretKey::from_slice(&IDENTITY_SCALAR).unwrap();
    let ephemeral = SecretKey::from_slice(&EPHEMERAL_SCALAR).unwrap();
    let recipient =
        Recipient::from_public_key_bytes(identity.public_key().to_encoded_point(true).as_bytes())
            .unwrap();
    let stanza = tag::wrap_with_ephemeral(&recipient, &FILE_KEY, &ephemeral).unwrap();

    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "warning": "PUBLIC TEST KEYS ONLY. Never use for real data.",
        "spec": "https://c2sp.org/age@v1.1.0",
        "identity_scalar_hex": "0000000000000000000000000000000000000000000000000000000000000001",
        "ephemeral_scalar_hex": "0000000000000000000000000000000000000000000000000000000000000002",
        "file_key_hex": "00112233445566778899aabbccddeeff",
        "recipient": tag::recipient(&recipient).unwrap(),
        "recipient_public_key_base64": STANDARD_NO_PAD.encode(recipient.public_key_bytes()),
        "stanza": {"tag": stanza.tag, "args": stanza.args, "body_base64": STANDARD_NO_PAD.encode(stanza.body)}
    })).unwrap());
}
