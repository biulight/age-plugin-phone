//! Generate or check public stub expectations from a verified public pairing transcript.
use age_plugin_phone::pairing::PublicIdentityStub;
use age_plugin_phone_core::protocol::{
    SignedPairingOffer, SignedPairingResponse, pairing_fingerprint,
};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as B64};
use std::io::Write as _;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pairing: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&args[1]).unwrap()).unwrap();
    let offer = SignedPairingOffer::decode(
        &B64.decode(pairing["signed_offer_base64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let response = SignedPairingResponse::decode(
        &B64.decode(pairing["signed_response_base64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    response.verify(&offer).unwrap();
    let stub = PublicIdentityStub {
        desktop_id: offer.payload.desktop_id,
        identity_id: response.payload.identity_id,
        recipient: response.payload.recipient.clone(),
        desktop_signing_public_key: offer.payload.desktop_signing_public_key,
        desktop_selection_public_key: offer.payload.desktop_selection_public_key,
        phone_signing_public_key: response.payload.phone_signing_public_key,
        offer_digest: offer.digest(),
        transcript_fingerprint: pairing_fingerprint(&offer, &response),
    };
    assert_eq!(PublicIdentityStub::decode(&stub.encode()).unwrap(), stub);
    let value = serde_json::json!({
        "schema": "age-plugin-phone/public-identity-stub-test-vector/v2",
        "warning": "Public synthetic pairing metadata only; never use these identities for real data.",
        "pairing_fixture": "pairing-transcript-v2.json",
        "stub_cbor_base64": B64.encode(stub.encode()),
        "plugin_identity": stub.plugin_identity().unwrap(),
        "phone_recipient": stub.phone_recipient().unwrap(),
        "tag_recipient": stub.tag_recipient().unwrap(),
        "identity_file": stub.identity_file().unwrap(),
    });
    if let Some(path) = args.get(2) {
        let expected: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(value, expected);
        // Exercise the owning desktop text parser as well as serialization.
        let root = std::env::temp_dir().join(format!("phone-public-stub-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&root)
            .unwrap();
        file.write_all(expected["identity_file"].as_str().unwrap().as_bytes())
            .unwrap();
        drop(file);
        assert_eq!(
            age_plugin_phone::pairing::read_identity_stub_file(&root).unwrap(),
            stub
        );
        std::fs::remove_file(root).unwrap();
        println!("Public stub production serialization and parsing match the vector");
    } else {
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
    }
}
