//! Explicit native acceptance using synthetic pairing metadata, never a real phone peer.
#![cfg(target_os = "macos")]

use std::{
    io::Write as _,
    process::{Command, Stdio},
};

use age_plugin_phone::{
    locator::open_pairing_locator,
    pairing::{DesktopKeyState, PublicIdentityStub},
    setup::{self, SetupJournal},
};
use age_plugin_phone_core::{protocol::P256Signer, recipient::Recipient};
use age_plugin_phone_platform_storage::macos::Directory;
use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint as _};
use rand_core::{OsRng, RngCore as _};

#[test]
#[ignore = "requires real Secure Enclave; creates isolated synthetic setup state, no phone pairing"]
fn native_confirmed_setup_reopens_and_commits_hardware_roles() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "phone-m3-native-{}-{}",
        std::process::id(),
        OsRng.next_u64()
    ));
    Directory::prepare(&root).unwrap();
    let mut value = SetupJournal::new(&root, [61; 16], [62; 16]);
    setup::create(&root, &value).unwrap();
    let desktop = DesktopKeyState::create_new(&value.desktop_state, value.desktop_id).unwrap();
    let phone_identity = SecretKey::random(&mut OsRng);
    let phone_signer = SigningKey::random(&mut OsRng);
    let stub = PublicIdentityStub {
        desktop_id: value.desktop_id,
        identity_id: [63; 16],
        recipient: Recipient::from_public_key_bytes(
            phone_identity
                .public_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap()
        .to_string()
        .unwrap(),
        desktop_signing_public_key: desktop.signing_public_key().unwrap(),
        desktop_selection_public_key: desktop.selection_public_key().unwrap(),
        phone_signing_public_key: phone_signer.public_key().unwrap(),
        offer_digest: [64; 32],
        transcript_fingerprint: [65; 32],
    };
    value.set_candidate(stub.clone()).unwrap();
    setup::replace(&root, &value).unwrap();
    assert!(setup::commit_confirmed(&root, &value, 100).is_err());
    assert!(!value.replay_state.exists());
    value.set_confirmed(&stub).unwrap();
    setup::replace(&root, &value).unwrap();
    drop(desktop);
    setup::commit_confirmed(&root, &value, 100).unwrap();
    let locator = open_pairing_locator(&root, &stub).unwrap();
    let reopened = DesktopKeyState::open(&locator.desktop_state).unwrap();
    assert_eq!(
        reopened.signing_public_key().unwrap(),
        stub.desktop_signing_public_key
    );
    assert_eq!(
        reopened.selection_public_key().unwrap(),
        stub.desktop_selection_public_key
    );
    assert!(value.identity_stub.exists());
    drop(reopened);
    for (entered, success) in [
        ("wrong\n".to_owned(), false),
        (format!("{}\n", "41".repeat(32)), true),
    ] {
        // Feed only the synthetic fixture's confirmation. Never use this harness to automate
        // a real user's fingerprint comparison or native destructive-action confirmation.
        let mut child = Command::new(env!("CARGO_BIN_EXE_age-plugin-phone"))
            .env("AGE_PLUGIN_PHONE_CONFIG_DIR", &root)
            .args(["remove-desktop-state", "--identity-stub"])
            .arg(&value.identity_stub)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(entered.as_bytes())
            .unwrap();
        assert_eq!(child.wait().unwrap().success(), success);
        assert_eq!(value.desktop_state.exists(), !success);
        assert_eq!(value.identity_stub.exists(), !success);
        assert_eq!(value.replay_state.exists(), !success);
    }
    // The whole root belongs to this synthetic fixture. Removing references is local cleanup,
    // not a claim of hardware destruction or of exercising product fingerprint confirmation.
    std::fs::remove_dir_all(root).unwrap();
}
