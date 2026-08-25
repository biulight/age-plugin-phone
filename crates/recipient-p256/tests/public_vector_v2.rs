use age_plugin_phone_recipient_p256::{
    PairedRecipient, TaggedStanza, matches_stanza_v2, unwrap_file_key,
    wrap_file_key_v2_with_ephemeral,
};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint as _};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    schema: String,
    identity_scalar_hex: String,
    desktop_scalar_hex: String,
    ephemeral_scalar_hex: String,
    identity_id_hex: String,
    file_key_hex: String,
    phone_public_key_base64: String,
    desktop_public_key_base64: String,
    recipient: String,
    stanza: VectorStanza,
}

#[derive(Deserialize)]
struct VectorStanza {
    tag: String,
    args: Vec<String>,
    body_base64: String,
}

#[test]
fn rust_matches_private_selection_vector() {
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../docs/test-vectors/p256-recipient-v2.json"
    ))
    .unwrap();
    assert_eq!(
        vector.schema,
        "age-plugin-phone/p256-recipient-test-vector/v2"
    );
    let identity = SecretKey::from_slice(&decode_hex::<32>(&vector.identity_scalar_hex)).unwrap();
    let desktop = SigningKey::from_slice(&decode_hex::<32>(&vector.desktop_scalar_hex)).unwrap();
    let ephemeral = SecretKey::from_slice(&decode_hex::<32>(&vector.ephemeral_scalar_hex)).unwrap();
    let identity_id = decode_hex::<16>(&vector.identity_id_hex);
    let file_key = decode_hex::<16>(&vector.file_key_hex);
    let recipient = PairedRecipient::from_public_fields(
        identity.public_key().to_encoded_point(true).as_bytes(),
        desktop.verifying_key().to_encoded_point(true).as_bytes(),
        identity_id,
    )
    .unwrap();
    assert_eq!(recipient.to_string().unwrap(), vector.recipient);
    assert_eq!(
        STANDARD_NO_PAD.encode(recipient.phone_identity_public_key()),
        vector.phone_public_key_base64
    );
    assert_eq!(
        STANDARD_NO_PAD.encode(recipient.desktop_selection_public_key()),
        vector.desktop_public_key_base64
    );
    let stanza = wrap_file_key_v2_with_ephemeral(&recipient, &file_key, &ephemeral).unwrap();
    assert_eq!(stanza.tag, vector.stanza.tag);
    assert_eq!(stanza.args, vector.stanza.args);
    assert_eq!(
        STANDARD_NO_PAD.encode(&stanza.body),
        vector.stanza.body_base64
    );
    let vector_stanza = TaggedStanza {
        tag: vector.stanza.tag,
        args: vector.stanza.args,
        body: STANDARD_NO_PAD.decode(vector.stanza.body_base64).unwrap(),
    };
    assert!(matches_stanza_v2(&recipient, &desktop, &vector_stanza).unwrap());
    assert_eq!(
        *unwrap_file_key(&identity, &vector_stanza).unwrap(),
        file_key
    );
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut output = [0; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}
