use age_plugin_phone_recipient_p256::{Recipient, wrap_file_key_with_ephemeral};
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
    let stanza = wrap_file_key_with_ephemeral(&recipient, &FILE_KEY, &ephemeral).unwrap();

    println!("recipient={}", recipient.to_string().unwrap());
    println!(
        "recipient_public_key={}",
        STANDARD_NO_PAD.encode(recipient.public_key_bytes())
    );
    println!("ephemeral_public_key={}", stanza.args[0]);
    println!("stanza_body={}", STANDARD_NO_PAD.encode(stanza.body));
}
