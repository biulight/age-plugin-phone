//! Public-only CLI acceptance: no private locator, hardware key, replay file or phone exists.
use age_plugin_phone::pairing::{PublicIdentityStub, RecipientType};
use age_plugin_phone_core::recipient::Recipient;
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint as _};
use std::process::Command;

fn public(n: u8) -> [u8; 33] {
    let mut scalar = [0; 32];
    scalar[31] = n;
    SecretKey::from_slice(&scalar)
        .unwrap()
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

#[test]
fn exports_exactly_one_recipient_with_no_private_state_and_strict_input() {
    let root = std::env::temp_dir().join(format!("phone-recipients-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let stub = PublicIdentityStub {
        desktop_id: [1; 16],
        identity_id: [2; 16],
        recipient: Recipient::from_public_key_bytes(&public(1))
            .unwrap()
            .to_string()
            .unwrap(),
        desktop_signing_public_key: public(2),
        desktop_selection_public_key: public(3),
        phone_signing_public_key: public(4),
        offer_digest: [5; 32],
        transcript_fingerprint: [6; 32],
    };
    let path = root.join("public.txt");
    let private = root.join("private-must-not-exist");
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_age-plugin-phone"))
            .env("AGE_PLUGIN_PHONE_CONFIG_DIR", &private)
            .env("AGE_PLUGIN_PHONE_TRANSPORT", "invalid-must-not-be-read")
            .args(["recipients", "-i"])
            .arg(&path)
            .args(args)
            .output()
            .unwrap()
    };
    for kind in [RecipientType::Phone, RecipientType::Tag] {
        std::fs::write(&path, stub.identity_file_for(kind).unwrap()).unwrap();
        let output = invoke(&["--recipient-type", &kind.to_string()]);
        assert!(output.status.success());
        assert_eq!(
            output.stdout,
            format!("{}\n", stub.recipient_for(kind).unwrap()).as_bytes()
        );
        assert!(output.stderr.is_empty());
    }
    assert_eq!(
        invoke(&[]).stdout,
        format!("{}\n", stub.phone_recipient().unwrap()).as_bytes()
    );
    let canonical = stub.identity_file().unwrap();
    for bad in [
        String::new(),
        "not an identity".into(),
        canonical.to_lowercase(),
        format!("{canonical}extra\n"),
        format!("{canonical}{canonical}"),
    ] {
        std::fs::write(&path, bad).unwrap();
        let output = invoke(&[]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    std::fs::remove_file(&path).unwrap();
    assert!(!invoke(&[]).status.success());
    assert!(!private.exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn help_and_option_validation_explain_explicit_modes() {
    for command in ["setup", "pair", "recipients"] {
        let output = Command::new(env!("CARGO_BIN_EXE_age-plugin-phone"))
            .args([command, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--recipient-type"));
        assert!(help.contains("age 1.3+"));
        assert!(help.contains("public testable tag"));
        assert!(help.contains("default: phone"));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_age-plugin-phone"))
        .args(["recipients", "-i", "missing", "--recipient-type", "tagpq"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
