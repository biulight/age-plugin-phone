//! Standard age `identity-v1` adapter for one-shot phone unwraps.

use std::{collections::HashMap, io, path::PathBuf};

use age_core::format::{FileKey, Stanza};
use age_plugin::{
    Callbacks,
    identity::{self, IdentityPluginV1},
};
use age_plugin_phone_protocol::{
    DEFAULT_REPLAY_CAPACITY, FileReplayGuard, PairingRecord, ReplayRole, ReplayScope,
    fragment_qr_message,
};
use age_plugin_phone_recipient_p256::{STANZA_TAG, TaggedStanza, validate_stanza};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use rand_core::OsRng;

use crate::{
    locator::{default_config_root, open_pairing_locator},
    pairing::{DesktopKeyState, PublicIdentityStub},
    qr_terminal::render_terminal_frame,
    unwrap::{DesktopUnwrapSession, UnwrapDisplay, now_unix},
};

const QR_CHUNK_BYTES: usize = 600;

#[derive(Default)]
pub struct PhoneIdentityPlugin {
    identities: Vec<(usize, PublicIdentityStub)>,
    config_root: Option<PathBuf>,
}

impl PhoneIdentityPlugin {
    #[cfg(test)]
    fn with_config_root(config_root: PathBuf) -> Self {
        Self {
            identities: Vec::new(),
            config_root: Some(config_root),
        }
    }

    fn config_root(&self) -> Result<PathBuf, identity::Error> {
        self.config_root.clone().map_or_else(
            || default_config_root().map_err(|_| internal("configuration unavailable")),
            Ok,
        )
    }
}

impl IdentityPluginV1 for PhoneIdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        if plugin_name != age_plugin_phone_recipient_p256::PLUGIN_NAME {
            return Err(identity::Error::Identity {
                index,
                message: "identity was routed to the wrong plugin".into(),
            });
        }
        let stub = PublicIdentityStub::decode(bytes).map_err(|_| identity::Error::Identity {
            index,
            message: "malformed or unsupported public phone identity stub".into(),
        })?;
        self.identities.push((index, stub));
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let root = match self.config_root() {
            Ok(root) => root,
            Err(error) => return Ok(all_supported_files_error(&files, error)),
        };
        unwrap_with_exchange(&self.identities, files, &root, |request, display| {
            let prompt = match render_request_prompt(request, display) {
                Ok(prompt) => prompt,
                Err(error) => return Ok(Err(error)),
            };
            let Ok(input) = callbacks.request_public(&prompt)? else {
                return Ok(Err(ExchangeError::Cancelled));
            };
            let input = input.trim();
            let response = STANDARD_NO_PAD
                .decode(input)
                .ok()
                .filter(|decoded| STANDARD_NO_PAD.encode(decoded) == input)
                .ok_or(ExchangeError::InvalidResponse);
            Ok(response)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExchangeError {
    Cancelled,
    InvalidResponse,
    Failed,
}

fn render_request_prompt(request: &[u8], display: &UnwrapDisplay) -> Result<String, ExchangeError> {
    let frames = fragment_qr_message(request, QR_CHUNK_BYTES, &mut OsRng)
        .map_err(|_| ExchangeError::Failed)?;
    let [frame] = frames.as_slice() else {
        return Err(ExchangeError::Failed);
    };
    let qr = render_terminal_frame(frame).map_err(|_| ExchangeError::Failed)?;
    Ok(format!(
        "Scan this one-time request with the paired phone.\n\n{qr}\nRequest fingerprint: {}\n\nAfter scanning the phone response with the desktop capture helper, paste its unpadded Base64 value:",
        display.request_fingerprint,
    ))
}

#[allow(clippy::too_many_lines)]
fn unwrap_with_exchange<F>(
    identities: &[(usize, PublicIdentityStub)],
    files: Vec<Vec<Stanza>>,
    root: &std::path::Path,
    mut exchange: F,
) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>>
where
    F: FnMut(&[u8], &UnwrapDisplay) -> io::Result<Result<Vec<u8>, ExchangeError>>,
{
    let mut results = HashMap::new();
    for (file_index, stanzas) in files.into_iter().enumerate() {
        let mut errors = Vec::new();
        let mut candidates = Vec::new();
        for (stanza_index, stanza) in stanzas.into_iter().enumerate() {
            if stanza.tag != STANZA_TAG {
                continue;
            }
            let tagged = TaggedStanza {
                tag: stanza.tag,
                args: stanza.args,
                body: stanza.body,
            };
            if validate_stanza(&tagged).is_err() {
                errors.push(stanza_error(
                    file_index,
                    stanza_index,
                    "malformed phone stanza",
                ));
            } else {
                candidates.push((stanza_index, tagged));
            }
        }
        if candidates.is_empty() {
            if !errors.is_empty() {
                results.insert(file_index, Err(errors));
            }
            continue;
        }

        let Some((identity_index, stub)) = identities.first() else {
            errors.push(internal("no phone identity was provided"));
            results.insert(file_index, Err(errors));
            continue;
        };
        // Version 1 stanzas intentionally contain no recipient identifier. Trying several phone
        // identities would create ambiguous prompts, so this prototype uses the first identity.
        let (stanza_index, stanza) = candidates.remove(0);
        let Ok(locator) = open_pairing_locator(root, stub) else {
            errors.push(identity_error(
                *identity_index,
                "paired desktop state is unavailable",
            ));
            results.insert(file_index, Err(errors));
            continue;
        };
        let Ok(desktop) = DesktopKeyState::open(&locator.desktop_state) else {
            errors.push(identity_error(
                *identity_index,
                "desktop authentication state is unavailable",
            ));
            results.insert(file_index, Err(errors));
            continue;
        };
        let pairing = PairingRecord {
            desktop_id: stub.desktop_id,
            identity_id: stub.identity_id,
            desktop_signing_public_key: stub.desktop_signing_public_key,
            phone_signing_public_key: stub.phone_signing_public_key,
        };
        let Ok(mut replay) = FileReplayGuard::open(
            &locator.replay_state,
            ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing),
            DEFAULT_REPLAY_CAPACITY,
        ) else {
            errors.push(identity_error(
                *identity_index,
                "response replay state is unavailable",
            ));
            results.insert(file_index, Err(errors));
            continue;
        };
        let Ok(now) = now_unix() else {
            return Err(io::Error::other("system clock is unavailable"));
        };
        let Ok(mut session) = DesktopUnwrapSession::begin(
            stub,
            &desktop,
            stanza,
            Some("reference age identity-v1".into()),
            now,
            &mut OsRng,
        ) else {
            errors.push(stanza_error(
                file_index,
                stanza_index,
                "failed to create unwrap request",
            ));
            results.insert(file_index, Err(errors));
            continue;
        };
        let response = match exchange(&session.signed_request(), &session.display())? {
            Ok(response) => response,
            Err(ExchangeError::Cancelled) => {
                session.cancel();
                errors.push(identity_error(*identity_index, "phone unwrap cancelled"));
                results.insert(file_index, Err(errors));
                return Ok(results);
            }
            Err(ExchangeError::InvalidResponse | ExchangeError::Failed) => {
                session.cancel();
                errors.push(stanza_error(
                    file_index,
                    stanza_index,
                    "phone response unavailable or malformed",
                ));
                results.insert(file_index, Err(errors));
                continue;
            }
        };
        if let Ok(file_key) =
            session.receive_response(&response, &mut replay, now_unix().unwrap_or(u64::MAX))
        {
            results.insert(
                file_index,
                Ok(FileKey::init_with_mut(|value| {
                    value.copy_from_slice(&file_key[..]);
                })),
            );
        } else {
            errors.push(stanza_error(
                file_index,
                stanza_index,
                "phone response rejected",
            ));
            results.insert(file_index, Err(errors));
        }
    }
    Ok(results)
}

fn all_supported_files_error(
    files: &[Vec<Stanza>],
    error: identity::Error,
) -> HashMap<usize, Result<FileKey, Vec<identity::Error>>> {
    let mut error = Some(error);
    files
        .iter()
        .enumerate()
        .filter(|(_, stanzas)| stanzas.iter().any(|stanza| stanza.tag == STANZA_TAG))
        .map(|(index, _)| {
            let value = error
                .take()
                .unwrap_or_else(|| internal("configuration unavailable"));
            (index, Err(vec![value]))
        })
        .collect()
}

fn identity_error(index: usize, message: &str) -> identity::Error {
    identity::Error::Identity {
        index,
        message: message.into(),
    }
}

fn stanza_error(file_index: usize, stanza_index: usize, message: &str) -> identity::Error {
    identity::Error::Stanza {
        file_index,
        stanza_index,
        message: message.into(),
    }
}

fn internal(message: &str) -> identity::Error {
    identity::Error::Internal {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        locator::create_pairing_locator,
        pairing::{DesktopKeyState, PublicIdentityStub},
    };
    use age_plugin_phone_protocol::{ReplayGuard, SignedUnwrapRequest, seal_response};
    use age_plugin_phone_recipient_p256::{Recipient, unwrap_file_key, wrap_file_key};
    use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint as _};

    struct Fixture {
        root: PathBuf,
        config: PathBuf,
        stub: PublicIdentityStub,
        identity: SecretKey,
        phone: SigningKey,
        pairing: PairingRecord,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "age-phone-identity-v1-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            std::fs::create_dir(&root).unwrap();
            let desktop_path = root.join("desktop.key");
            let desktop = DesktopKeyState::open_or_create(&desktop_path, &mut OsRng).unwrap();
            let identity = SecretKey::random(&mut OsRng);
            let recipient = Recipient::from_public_key_bytes(
                identity.public_key().to_encoded_point(true).as_bytes(),
            )
            .unwrap();
            let phone = SigningKey::random(&mut OsRng);
            let stub = PublicIdentityStub {
                desktop_id: desktop.desktop_id,
                identity_id: [0x31; 16],
                recipient: recipient.to_string().unwrap(),
                desktop_signing_public_key: desktop
                    .signing_key()
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                phone_signing_public_key: phone
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                offer_digest: [0x32; 32],
                transcript_fingerprint: [0x33; 32],
            };
            let pairing = PairingRecord {
                desktop_id: stub.desktop_id,
                identity_id: stub.identity_id,
                desktop_signing_public_key: stub.desktop_signing_public_key,
                phone_signing_public_key: stub.phone_signing_public_key,
            };
            let replay_path = root.join("responses.cbor");
            drop(
                FileReplayGuard::create(
                    &replay_path,
                    ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing),
                    DEFAULT_REPLAY_CAPACITY,
                    1,
                )
                .unwrap(),
            );
            let config = root.join("config");
            create_pairing_locator(&config, &stub, &desktop_path, &replay_path).unwrap();
            Self {
                root,
                config,
                stub,
                identity,
                phone,
                pairing,
            }
        }

        fn stanza(&self, file_key: [u8; 16]) -> Stanza {
            let recipient = Recipient::parse(self.stub.recipient()).unwrap();
            let stanza = wrap_file_key(&recipient, &file_key, &mut OsRng).unwrap();
            Stanza {
                tag: stanza.tag,
                args: stanza.args,
                body: stanza.body,
            }
        }

        fn respond(&self, encoded: &[u8], now: u64) -> Vec<u8> {
            let request = SignedUnwrapRequest::decode(encoded).unwrap();
            let verified = ReplayGuard::default()
                .verify_request(request, &self.pairing, now)
                .unwrap();
            let file_key =
                unwrap_file_key(&self.identity, &verified.payload().recipient_stanza).unwrap();
            seal_response(&verified, &file_key, &self.phone, &mut OsRng)
                .unwrap()
                .encode()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn unwraps_multiple_files_and_ignores_unknown_stanzas() {
        use age_core::secrecy::ExposeSecret as _;

        let fixture = Fixture::new();
        let identities = vec![(0, fixture.stub.clone())];
        let files = vec![
            vec![
                Stanza {
                    tag: "X25519".into(),
                    args: vec!["ignored".into()],
                    body: vec![0; 32],
                },
                fixture.stanza([1; 16]),
            ],
            vec![fixture.stanza([2; 16])],
        ];
        let results =
            unwrap_with_exchange(&identities, files, &fixture.config, |request, display| {
                let prompt = render_request_prompt(request, display).unwrap();
                assert!(!prompt.contains("age-phone:qr1:"));
                assert!(prompt.contains(&display.request_fingerprint));
                Ok(Ok(fixture.respond(request, now_unix().unwrap())))
            })
            .unwrap();
        assert_eq!(results.len(), 2);
        let Ok(first) = results.get(&0).unwrap() else {
            panic!("first file must unwrap");
        };
        assert_eq!(first.expose_secret(), &[1; 16]);
        let Ok(second) = results.get(&1).unwrap() else {
            panic!("second file must unwrap");
        };
        assert_eq!(second.expose_secret(), &[2; 16]);
    }

    #[test]
    fn malformed_cancelled_and_unknown_inputs_fail_without_fallback() {
        let fixture = Fixture::new();
        let identities = vec![(0, fixture.stub.clone())];
        let mut malformed = fixture.stanza([3; 16]);
        malformed.args.push("unknown".into());
        let files = vec![
            vec![Stanza {
                tag: "future".into(),
                args: vec![],
                body: vec![],
            }],
            vec![malformed],
            vec![fixture.stanza([4; 16])],
            vec![fixture.stanza([5; 16])],
        ];
        let mut exchanges = 0;
        let results = unwrap_with_exchange(&identities, files, &fixture.config, |_, _| {
            exchanges += 1;
            Ok(Err(ExchangeError::Cancelled))
        })
        .unwrap();
        assert!(!results.contains_key(&0));
        assert!(matches!(results.get(&1), Some(Err(_))));
        assert!(matches!(results.get(&2), Some(Err(_))));
        assert!(!results.contains_key(&3));
        assert_eq!(exchanges, 1);
    }

    #[test]
    fn wrong_response_is_rejected_and_consumes_the_session() {
        let fixture = Fixture::new();
        let identities = vec![(0, fixture.stub.clone())];
        let results = unwrap_with_exchange(
            &identities,
            vec![vec![fixture.stanza([6; 16])]],
            &fixture.config,
            |request, _| {
                let mut response = fixture.respond(request, now_unix().unwrap());
                let last = response.last_mut().unwrap();
                *last ^= 1;
                Ok(Ok(response))
            },
        )
        .unwrap();
        assert!(matches!(results.get(&0), Some(Err(_))));
    }

    #[test]
    fn test_constructor_uses_explicit_config_root() {
        let plugin = PhoneIdentityPlugin::with_config_root(PathBuf::from("/tmp/test-only"));
        assert_eq!(plugin.config_root.unwrap(), PathBuf::from("/tmp/test-only"));
    }
}
