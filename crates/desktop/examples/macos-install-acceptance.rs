//! Explicit synthetic hardware/replay fixture for installation acceptance. No real phone pairing.
#[cfg(target_os = "macos")]
mod native {
    use age_plugin_phone::{
        pairing::{DesktopKeyState, PublicIdentityStub},
        setup::{self, SetupJournal},
    };
    use age_plugin_phone_core::{
        protocol::{
            DEFAULT_REPLAY_CAPACITY, Error, FileReplayGuard, P256Signer, ReplayRole, ReplayScope,
            ReplayStore,
        },
        recipient::Recipient,
    };
    use age_plugin_phone_platform_storage::macos::{self, Directory};
    use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint as _};
    use rand_core::OsRng;
    use std::path::Path;

    const DESKTOP: [u8; 16] = [0xa5; 16];
    const PHONE: [u8; 16] = [0xb6; 16];
    const MARKER: &[u8] = b"age-phone-m5-synthetic-fixture-v1";
    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    pub fn run(command: &str, root: &Path) -> Result<()> {
        let value = SetupJournal::new(root, [0xc7; 16], DESKTOP);
        let scope = ReplayScope::new(ReplayRole::DesktopResponses, DESKTOP, PHONE);
        match command {
            "seed" => {
                if root.exists() {
                    return Err("fixture must not exist".into());
                }
                let directory = Directory::prepare(root)?;
                directory.create(Path::new("synthetic-fixture"), MARKER)?;
                let mut value = value;
                setup::create(root, &value)?;
                let desktop = DesktopKeyState::create_new(&value.desktop_state, DESKTOP)?;
                let identity = SecretKey::random(&mut OsRng);
                let signer = SigningKey::random(&mut OsRng);
                let stub = PublicIdentityStub {
                    desktop_id: DESKTOP,
                    identity_id: PHONE,
                    recipient: Recipient::from_public_key_bytes(
                        identity.public_key().to_encoded_point(true).as_bytes(),
                    )?
                    .to_string()?,
                    desktop_signing_public_key: desktop.signing_public_key()?,
                    desktop_selection_public_key: desktop.selection_public_key()?,
                    phone_signing_public_key: signer.public_key()?,
                    offer_digest: [0xd8; 32],
                    transcript_fingerprint: [0xe9; 32],
                };
                value.set_candidate(stub.clone())?;
                value.set_confirmed(&stub)?;
                setup::replace(root, &value)?;
                drop(desktop);
                setup::commit_confirmed(root, &value, 100)?;
                let mut replay =
                    FileReplayGuard::open(&value.replay_state, scope, DEFAULT_REPLAY_CAPACITY)?;
                replay.consume_response(DESKTOP, PHONE, [0xfa; 32], 110, 100)?;
                println!("synthetic_fixture_seeded");
            }
            "verify" => {
                if macos::read_private_file(&root.join("synthetic-fixture"), 128)? != MARKER {
                    return Err("not this synthetic fixture".into());
                }
                let stub =
                    age_plugin_phone::pairing::read_identity_stub_file(&value.identity_stub)?;
                if stub.desktop_id != DESKTOP
                    || stub.identity_id != PHONE
                    || stub.transcript_fingerprint != [0xe9; 32]
                {
                    return Err("synthetic fixture binding mismatch".into());
                }
                let desktop = DesktopKeyState::open(&value.desktop_state)?;
                if desktop.signing_public_key()? != stub.desktop_signing_public_key
                    || desktop.selection_public_key()? != stub.desktop_selection_public_key
                {
                    return Err("hardware key continuity failed".into());
                }
                let mut replay =
                    FileReplayGuard::open(&value.replay_state, scope, DEFAULT_REPLAY_CAPACITY)?;
                if replay.consume_response(DESKTOP, PHONE, [0xfa; 32], 110, 100)
                    != Err(Error::Replay)
                {
                    return Err("previous consumption was lost".into());
                }
                println!("hardware_reopened_replay_rejected");
            }
            _ => return Err("expected seed or verify".into()),
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err("expected command and isolated fixture root".into());
    }
    native::run(
        args[1].to_str().ok_or("invalid command")?,
        std::path::Path::new(&args[2]),
    )
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("macOS installation acceptance only");
    std::process::exit(1);
}
