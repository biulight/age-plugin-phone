use age_plugin_phone_core::recipient::{
    Recipient, TaggedStanza, tag, unwrap_file_key, validate_stanza,
};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as B64};
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint as _};

fn scalar(n: u8) -> SecretKey {
    let mut bytes = [0; 32];
    bytes[31] = n;
    SecretKey::from_slice(&bytes).unwrap()
}

fn fixture() -> (SecretKey, Recipient, TaggedStanza) {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/p256tag.json")).unwrap();
    let identity = scalar(1);
    let recipient = tag::parse_recipient(vector["recipient"].as_str().unwrap()).unwrap();
    let stanza = TaggedStanza {
        tag: "p256tag".into(),
        args: vector["stanza"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().into())
            .collect(),
        body: B64
            .decode(vector["stanza"]["body_base64"].as_str().unwrap())
            .unwrap(),
    };
    (identity, recipient, stanza)
}

#[test]
fn shared_vector_and_legacy_dispatch() {
    let (identity, recipient, stanza) = fixture();
    let key = [
        0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    assert_eq!(
        tag::wrap_with_ephemeral(&recipient, &key, &scalar(2)).unwrap(),
        stanza
    );
    assert_eq!(*unwrap_file_key(&identity, &stanza).unwrap(), key);
    assert!(tag::matches(&recipient, &stanza).unwrap());
    assert!(Recipient::parse(&tag::recipient(&recipient).unwrap()).is_err());
    assert!(Recipient::from_plugin_bytes(&recipient.public_key_bytes()).is_err());
}

#[test]
fn strict_public_validation_and_authenticated_open() {
    let (identity, recipient, stanza) = fixture();
    for len in [0, 1, 31, 33, 64] {
        let mut bad = stanza.clone();
        bad.body.resize(len, 0);
        assert!(validate_stanza(&bad).is_err());
    }
    for args in [
        vec![],
        vec![stanza.args[0].clone()],
        [stanza.args.clone(), vec!["extra".into()]].concat(),
    ] {
        let mut bad = stanza.clone();
        bad.args = args;
        assert!(validate_stanza(&bad).is_err());
    }
    for index in 0..2 {
        for value in [
            "=".into(),
            format!("{}=", stanza.args[index]),
            B64.encode([0; 65]),
            B64.encode([0; 4]),
            "____".into(),
        ] {
            let mut bad = stanza.clone();
            bad.args[index] = value;
            if validate_stanza(&bad).is_ok() {
                assert!(tag::unwrap(&identity, &bad).is_err());
            }
        }
    }
    let mut body = stanza.clone();
    body.body[0] ^= 1;
    assert!(tag::matches(&recipient, &body).unwrap());
    assert!(tag::unwrap(&identity, &body).is_err());
    let mut enc = stanza.clone();
    enc.args[1] = B64.encode(scalar(3).public_key().to_encoded_point(false));
    assert!(tag::unwrap(&identity, &enc).is_err());
    assert!(tag::unwrap(&scalar(4), &stanza).is_err());
    let canonical = tag::recipient(&recipient).unwrap();
    for text in [
        canonical.to_uppercase(),
        format!("{canonical}x"),
        recipient.to_string().unwrap(),
    ] {
        assert!(tag::parse_recipient(&text).is_err());
    }
}

/// Explicit external-client acceptance, never silently skipped as a passing check.
#[test]
#[ignore = "requires P256TAG_AGE_CLIENT set to an absolute age 1.3+ or tagged-capable rage binary"]
fn native_client_without_plugin_encrypts_and_payload_authenticates() {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce, aead::Aead as _};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use std::{
        io::Write as _,
        process::{Command, Stdio},
    };
    let client = std::env::var("P256TAG_AGE_CLIENT").expect("explicit client path required");
    assert!(std::path::Path::new(&client).is_absolute());
    let (identity, recipient, _) = fixture();
    let second =
        Recipient::from_public_key_bytes(scalar(3).public_key().to_encoded_point(true).as_bytes())
            .unwrap();
    let mut child = Command::new(client)
        .env("PATH", "")
        .env("RUST_LOG", "off")
        .args([
            "-e",
            "-r",
            &tag::recipient(&recipient).unwrap(),
            "-r",
            &tag::recipient(&second).unwrap(),
            "-r",
            "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let plaintext = b"synthetic p256tag interoperability input";
    child.stdin.take().unwrap().write_all(plaintext).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "client encryption failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ciphertext = output.stdout;
    let mac_start = ciphertext.windows(4).position(|w| w == b"--- ").unwrap();
    let header_end = mac_start
        + ciphertext[mac_start..]
            .iter()
            .position(|b| *b == b'\n')
            .unwrap()
        + 1;
    let header = std::str::from_utf8(&ciphertext[..mac_start]).unwrap();
    let mut lines = header.lines().peekable();
    assert_eq!(lines.next(), Some("age-encryption.org/v1"));
    let mut stanzas = Vec::new();
    while let Some(line) = lines.next() {
        let Some(args) = line.strip_prefix("-> ") else {
            panic!("invalid stanza header")
        };
        let mut args = args.split(' ');
        let name = args.next().unwrap();
        let mut body = String::new();
        while lines.peek().is_some_and(|l| !l.starts_with("-> ")) {
            body.push_str(lines.next().unwrap());
        }
        if name == "p256tag" {
            stanzas.push(TaggedStanza {
                tag: name.into(),
                args: args.map(str::to_owned).collect(),
                body: B64.decode(body).unwrap(),
            });
        }
    }
    assert_eq!(stanzas.len(), 2);
    for key in [identity, scalar(3)] {
        let public =
            Recipient::from_public_key_bytes(key.public_key().to_encoded_point(true).as_bytes())
                .unwrap();
        let stanza = stanzas
            .iter()
            .find(|s| tag::matches(&public, s).unwrap())
            .unwrap();
        let file_key = tag::unwrap(&key, stanza).unwrap();
        let mut mac_key = [0; 32];
        Hkdf::<Sha256>::new(None, &*file_key)
            .expand(b"header", &mut mac_key)
            .unwrap();
        let (mac, _) = Hkdf::<Sha256>::extract(Some(&mac_key), &ciphertext[..mac_start + 3]);
        assert_eq!(
            B64.encode(mac),
            std::str::from_utf8(&ciphertext[mac_start + 4..header_end - 1]).unwrap()
        );
        let mut payload_key = [0; 32];
        Hkdf::<Sha256>::new(Some(&ciphertext[header_end..header_end + 16]), &*file_key)
            .expand(b"payload", &mut payload_key)
            .unwrap();
        let mut nonce = [0; 12];
        nonce[11] = 1;
        let opened = ChaCha20Poly1305::new_from_slice(&payload_key)
            .unwrap()
            .decrypt(Nonce::from_slice(&nonce), &ciphertext[header_end + 16..])
            .unwrap();
        assert_eq!(opened, plaintext);
    }
}

#[test]
fn real_public_tag_collision_never_authenticates_the_wrong_key() {
    fn key(v: &serde_json::Value, field: &str) -> SecretKey {
        let text = v[field].as_str().unwrap();
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect();
        SecretKey::from_slice(&bytes).unwrap()
    }
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/p256tag-collision.json")).unwrap();
    let first = key(&v, "first_scalar_hex");
    let second = key(&v, "second_scalar_hex");
    let public = |key: &SecretKey| {
        Recipient::from_public_key_bytes(key.public_key().to_encoded_point(true).as_bytes())
            .unwrap()
    };
    let stanza = tag::wrap_with_ephemeral(&public(&first), &[4; 16], &scalar(2)).unwrap();
    assert_eq!(stanza.args[0], v["tag_base64"].as_str().unwrap());
    assert_eq!(stanza.args[1], v["enc_base64"].as_str().unwrap());
    assert_eq!(B64.encode(&stanza.body), v["body_base64"].as_str().unwrap());
    assert!(tag::matches(&public(&first), &stanza).unwrap());
    assert!(tag::matches(&public(&second), &stanza).unwrap());
    assert_eq!(*tag::unwrap(&first, &stanza).unwrap(), [4; 16]);
    assert!(tag::unwrap(&second, &stanza).is_err());
}
