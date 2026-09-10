use age_plugin_phone_core::{
    protocol::{
        Error, FileReplayGuard, PairingRecord, ReplayRole, ReplayScope, SignedUnwrapRequest,
        SignedUnwrapResponse, open_response, verify_request_with_replay,
    },
    recipient::unwrap_file_key,
};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as B64};
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint as _};

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

#[test]
fn tag_consumption_survives_cancellation_restart_and_authenticated_response() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/p256tag-envelope-v2.json")).unwrap();
    let request = SignedUnwrapRequest::decode(
        &B64.decode(vector["signed_request_base64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let pairing = PairingRecord {
        desktop_id: [0x11; 16],
        identity_id: [0x22; 16],
        desktop_signing_public_key: public(1),
        desktop_selection_public_key: public(7),
        phone_signing_public_key: public(2),
    };
    #[cfg(windows)]
    let base = std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
    #[cfg(not(windows))]
    let base = std::env::temp_dir();
    let root = base
        .canonicalize()
        .unwrap()
        .join(format!("phone-tag-replay-{}", std::process::id()));
    #[cfg(windows)]
    age_plugin_phone_platform_storage::windows::ensure_private_directory(&root).unwrap();
    #[cfg(not(windows))]
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let scope = ReplayScope::for_pairing(ReplayRole::PhoneRequests, &pairing);
    let path = root.join("requests");
    let mut replay = FileReplayGuard::create(&path, scope, 4, 1_000_000).unwrap();
    let verified =
        verify_request_with_replay(request.clone(), &pairing, 1_000_000, &mut replay).unwrap();
    assert_eq!(
        B64.encode(verified.digest()),
        vector["request_digest_base64"].as_str().unwrap()
    );
    // Cancellation or native HPKE/authentication failure ends here without a response.
    drop(replay);
    let mut reopened = FileReplayGuard::open(&path, scope, 4).unwrap();
    assert_eq!(
        verify_request_with_replay(request, &pairing, 1_000_000, &mut reopened).unwrap_err(),
        Error::Replay
    );
    assert_eq!(
        *unwrap_file_key(&key(3), &verified.payload().recipient_stanza).unwrap(),
        [0x55; 16]
    );
    let response = SignedUnwrapResponse::decode(
        &B64.decode(vector["signed_response_base64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let response_scope = ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing);
    let response_path = root.join("responses");
    let mut responses =
        FileReplayGuard::create(&response_path, response_scope, 4, 1_000_000).unwrap();
    assert_eq!(
        *open_response(
            &response,
            &verified,
            &pairing,
            &key(5),
            &mut responses,
            1_000_000
        )
        .unwrap(),
        [0x55; 16]
    );
    drop(responses);
    let mut responses = FileReplayGuard::open(&response_path, response_scope, 4).unwrap();
    assert_eq!(
        open_response(
            &response,
            &verified,
            &pairing,
            &key(5),
            &mut responses,
            1_000_000
        )
        .unwrap_err(),
        Error::Replay
    );
    drop(responses);
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}
