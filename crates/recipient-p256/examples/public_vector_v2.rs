use age_plugin_phone_recipient_p256::{PairedRecipient, wrap_file_key_v2_with_ephemeral};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint as _};

const IDENTITY_SCALAR: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
const EPHEMERAL_SCALAR: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];
const DESKTOP_SCALAR: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
];
const IDENTITY_ID: [u8; 16] = [0x42; 16];
const FILE_KEY: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn main() {
    let identity = SecretKey::from_slice(&IDENTITY_SCALAR).unwrap();
    let ephemeral = SecretKey::from_slice(&EPHEMERAL_SCALAR).unwrap();
    let desktop = SigningKey::from_slice(&DESKTOP_SCALAR).unwrap();
    let recipient = PairedRecipient::from_public_fields(
        identity.public_key().to_encoded_point(true).as_bytes(),
        desktop.verifying_key().to_encoded_point(true).as_bytes(),
        IDENTITY_ID,
    )
    .unwrap();
    let stanza = wrap_file_key_v2_with_ephemeral(&recipient, &FILE_KEY, &ephemeral).unwrap();
    println!("recipient={}", recipient.to_string().unwrap());
    println!(
        "phone_public={}",
        STANDARD_NO_PAD.encode(recipient.phone_identity_public_key())
    );
    println!(
        "desktop_public={}",
        STANDARD_NO_PAD.encode(recipient.desktop_selection_public_key())
    );
    println!("ephemeral_public={}", stanza.args[0]);
    println!("selection={}", stanza.args[1]);
    println!("body={}", STANDARD_NO_PAD.encode(stanza.body));
}
