//! Standard age `identity-v1` adapter for one-shot phone unwraps.

use std::{collections::HashMap, io, net::SocketAddr, path::PathBuf};

use age_core::format::{FileKey, Stanza};
use age_plugin::{
    Callbacks,
    identity::{self, IdentityPluginV1},
};
use age_plugin_phone_protocol::{
    DEFAULT_REPLAY_CAPACITY, FileReplayGuard, PairingRecord, ReplayRole, ReplayScope,
    fragment_qr_message,
};
use age_plugin_phone_recipient_p256::{
    PairedRecipient, STANZA_TAG, STANZA_TAG_V2, TaggedStanza, matches_stanza_v2, validate_stanza,
};
use age_plugin_phone_transport::{DesktopTransport, SessionPurpose, TransportLimits};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::{
    adb::{AdbReverseSession, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MESSAGE_TIMEOUT, SystemAdb},
    locator::{PairingLocator, default_config_root, open_pairing_locator},
    pairing::{DesktopKeyState, PublicIdentityStub},
    qr_scanner::{DEFAULT_SCAN_TIMEOUT, ScanError, ScannerHandle},
    qr_terminal::render_terminal_frame,
    unwrap::{DesktopUnwrapSession, UnwrapDisplay, now_unix},
    wifi::WifiSession,
};

const QR_CHUNK_BYTES: usize = 600;

#[derive(Default)]
pub struct PhoneIdentityPlugin {
    identities: Vec<(usize, PublicIdentityStub)>,
    config_root: Option<PathBuf>,
}

impl PhoneIdentityPlugin {
    #[cfg(all(test, not(windows)))]
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
        let Some(transport) = identity_transport() else {
            return Ok(all_supported_files_error(
                &files,
                internal("unsupported phone transport selection"),
            ));
        };
        let route = match identity_route_options(transport) {
            Ok(route) => route,
            Err(error) => return Ok(all_supported_files_error(&files, error)),
        };
        unwrap_with_exchange(&self.identities, files, &root, |request, display| {
            exchange_identity_transport(&route, request, display, &mut callbacks)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdentityTransport {
    Adb,
    Qr,
    Wifi,
}

struct IdentityRoute {
    transport: IdentityTransport,
    adb_serial: Option<String>,
    wifi_address: Option<SocketAddr>,
}

fn identity_transport() -> Option<IdentityTransport> {
    match std::env::var("AGE_PLUGIN_PHONE_TRANSPORT").as_deref() {
        Ok("adb") => Some(IdentityTransport::Adb),
        Ok("qr") => Some(IdentityTransport::Qr),
        Ok("wifi") => Some(IdentityTransport::Wifi),
        Err(std::env::VarError::NotPresent) => Some(if cfg!(windows) {
            IdentityTransport::Adb
        } else {
            IdentityTransport::Qr
        }),
        Ok(_) | Err(std::env::VarError::NotUnicode(_)) => None,
    }
}

fn valid_identity_route_options(
    transport: IdentityTransport,
    adb_serial: Option<&str>,
    wifi_address: Option<SocketAddr>,
) -> bool {
    match transport {
        IdentityTransport::Adb => wifi_address.is_none(),
        IdentityTransport::Qr => adb_serial.is_none() && wifi_address.is_none(),
        IdentityTransport::Wifi => adb_serial.is_none() && wifi_address.is_some(),
    }
}

fn identity_route_options(transport: IdentityTransport) -> Result<IdentityRoute, identity::Error> {
    let adb_serial = optional_env("AGE_PLUGIN_PHONE_ADB_SERIAL")
        .map_err(|_| internal("ADB device selection is malformed"))?;
    let wifi_address = optional_env("AGE_PLUGIN_PHONE_WIFI_ADDRESS")?
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .map_err(|_| internal("Wi-Fi endpoint selection is malformed"))
        })
        .transpose()?;
    if !valid_identity_route_options(transport, adb_serial.as_deref(), wifi_address) {
        return Err(internal("phone transport options are inconsistent"));
    }
    Ok(IdentityRoute {
        transport,
        adb_serial,
        wifi_address,
    })
}

fn optional_env(name: &str) -> Result<Option<String>, identity::Error> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(internal("environment value is malformed")),
    }
}

fn exchange_identity_transport(
    route: &IdentityRoute,
    request: &[u8],
    display: &UnwrapDisplay,
    callbacks: &mut impl Callbacks<identity::Error>,
) -> io::Result<Result<Zeroizing<Vec<u8>>, ExchangeError>> {
    match route.transport {
        IdentityTransport::Adb => exchange_identity_adb(route, request, display, callbacks),
        IdentityTransport::Wifi => exchange_identity_wifi(route, request, display, callbacks),
        IdentityTransport::Qr => exchange_identity_qr(request, display, callbacks),
    }
}

fn exchange_identity_adb(
    route: &IdentityRoute,
    request: &[u8],
    display: &UnwrapDisplay,
    callbacks: &mut impl Callbacks<identity::Error>,
) -> io::Result<Result<Zeroizing<Vec<u8>>, ExchangeError>> {
    let prompt = format!(
        "The paired phone app will open for Developer USB approval.\nRequest fingerprint: {}\nADB is an untrusted transport; phone verification and protocol authentication remain required.",
        display.request_fingerprint,
    );
    let Ok(()) = callbacks.message(&prompt)? else {
        return Ok(Err(ExchangeError::Cancelled));
    };
    let Ok(mut session) = AdbReverseSession::connect(
        SystemAdb::default(),
        route.adb_serial.as_deref(),
        SessionPurpose::Unwrap,
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_MESSAGE_TIMEOUT,
        TransportLimits::default(),
        &mut OsRng,
    ) else {
        return Ok(Err(ExchangeError::Failed));
    };
    Ok(session
        .exchange(SessionPurpose::Unwrap, request)
        .map_err(|_| ExchangeError::Failed))
}

fn exchange_identity_wifi(
    route: &IdentityRoute,
    request: &[u8],
    display: &UnwrapDisplay,
    callbacks: &mut impl Callbacks<identity::Error>,
) -> io::Result<Result<Zeroizing<Vec<u8>>, ExchangeError>> {
    let prompt = format!(
        "Enable Wi-Fi auto-listen and keep the paired phone app in the foreground before continuing.\nRequest fingerprint: {}\nThe LAN route is untrusted; phone verification and protocol authentication remain required.",
        display.request_fingerprint,
    );
    let Ok(()) = callbacks.message(&prompt)? else {
        return Ok(Err(ExchangeError::Cancelled));
    };
    let Ok(mut session) = WifiSession::connect(
        route.wifi_address.expect("validated Wi-Fi endpoint"),
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_MESSAGE_TIMEOUT,
        TransportLimits::default(),
        &mut OsRng,
    ) else {
        return Ok(Err(ExchangeError::Failed));
    };
    Ok(session
        .exchange(SessionPurpose::Unwrap, request)
        .map_err(|_| ExchangeError::Failed))
}

fn exchange_identity_qr(
    request: &[u8],
    display: &UnwrapDisplay,
    callbacks: &mut impl Callbacks<identity::Error>,
) -> io::Result<Result<Zeroizing<Vec<u8>>, ExchangeError>> {
    let prompt = match render_request_prompt(request, display) {
        Ok(prompt) => prompt,
        Err(error) => return Ok(Err(error)),
    };
    let Ok(()) = callbacks.message(&prompt)? else {
        return Ok(Err(ExchangeError::Cancelled));
    };
    let scanner = ScannerHandle::start_default_camera(DEFAULT_SCAN_TIMEOUT);
    Ok(scanner.wait().map_err(|error| match error {
        ScanError::Cancelled => ExchangeError::Cancelled,
        ScanError::InvalidTransfer => ExchangeError::InvalidResponse,
        ScanError::CameraUnavailable | ScanError::UnsupportedFrame | ScanError::Timeout => {
            ExchangeError::Failed
        }
    }))
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
        "Scan this one-time request with the paired phone.\n\n{qr}\nRequest fingerprint: {}\n\nThe desktop camera is waiting for the phone response QR. Press Ctrl-C to cancel.",
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
    F: FnMut(&[u8], &UnwrapDisplay) -> io::Result<Result<Zeroizing<Vec<u8>>, ExchangeError>>,
{
    let mut results = HashMap::new();
    for (file_index, stanzas) in files.into_iter().enumerate() {
        let mut errors = Vec::new();
        let mut candidates = Vec::new();
        for (stanza_index, stanza) in stanzas.into_iter().enumerate() {
            if stanza.tag != STANZA_TAG && stanza.tag != STANZA_TAG_V2 {
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

        let SelectedCandidate {
            identity_index,
            stub,
            stanza_index,
            stanza,
            locator,
            desktop,
        } = match select_candidate(identities, candidates, root, file_index) {
            Ok(selected) => selected,
            Err(selection_errors) => {
                errors.extend(selection_errors);
                results.insert(file_index, Err(errors));
                continue;
            }
        };
        let pairing = PairingRecord {
            desktop_id: stub.desktop_id,
            identity_id: stub.identity_id,
            desktop_signing_public_key: stub.desktop_signing_public_key,
            desktop_selection_public_key: stub.desktop_selection_public_key,
            phone_signing_public_key: stub.phone_signing_public_key,
        };
        let Ok(mut replay) = FileReplayGuard::open(
            &locator.replay_state,
            ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing),
            DEFAULT_REPLAY_CAPACITY,
        ) else {
            errors.push(identity_error(
                identity_index,
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
                errors.push(identity_error(identity_index, "phone unwrap cancelled"));
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

struct SelectedCandidate<'a> {
    identity_index: usize,
    stub: &'a PublicIdentityStub,
    stanza_index: usize,
    stanza: TaggedStanza,
    locator: PairingLocator,
    desktop: DesktopKeyState,
}

struct OpenedIdentity {
    position: usize,
    locator: PairingLocator,
    desktop: DesktopKeyState,
    recipient: PairedRecipient,
}

fn select_candidate<'a>(
    identities: &'a [(usize, PublicIdentityStub)],
    mut candidates: Vec<(usize, TaggedStanza)>,
    root: &std::path::Path,
    file_index: usize,
) -> Result<SelectedCandidate<'a>, Vec<identity::Error>> {
    if identities.is_empty() {
        return Err(vec![internal("no phone identity was provided")]);
    }

    if candidates
        .iter()
        .any(|(_, stanza)| stanza.tag == STANZA_TAG)
    {
        if identities.len() != 1 || candidates.len() != 1 {
            return Err(candidates
                .iter()
                .map(|(stanza_index, _)| {
                    stanza_error(
                        file_index,
                        *stanza_index,
                        "anonymous v1 phone stanza cannot be selected safely",
                    )
                })
                .collect());
        }
        let (identity_index, stub) = &identities[0];
        let locator = open_pairing_locator(root, stub).map_err(|_| {
            vec![identity_error(
                *identity_index,
                "paired desktop state is unavailable",
            )]
        })?;
        let desktop = DesktopKeyState::open(&locator.desktop_state).map_err(|_| {
            vec![identity_error(
                *identity_index,
                "desktop authentication state is unavailable",
            )]
        })?;
        let (stanza_index, stanza) = candidates.remove(0);
        return Ok(SelectedCandidate {
            identity_index: *identity_index,
            stub,
            stanza_index,
            stanza,
            locator,
            desktop,
        });
    }

    let (mut opened, mut errors) = open_identities(identities, root);
    let mut selected = None;
    'identities: for (opened_position, identity) in opened.iter().enumerate() {
        for (candidate_position, (_, stanza)) in candidates.iter().enumerate() {
            match matches_stanza_v2(&identity.recipient, identity.desktop.agreement(), stanza) {
                Ok(true) => {
                    selected = Some((opened_position, candidate_position));
                    break 'identities;
                }
                Ok(false) => {}
                Err(_) => {
                    return Err(vec![internal("private phone stanza selection failed")]);
                }
            }
        }
    }
    if let Some((opened_position, candidate_position)) = selected {
        let identity = opened.swap_remove(opened_position);
        let (identity_index, stub) = &identities[identity.position];
        let (stanza_index, stanza) = candidates.swap_remove(candidate_position);
        return Ok(SelectedCandidate {
            identity_index: *identity_index,
            stub,
            stanza_index,
            stanza,
            locator: identity.locator,
            desktop: identity.desktop,
        });
    }
    errors.extend(candidates.iter().map(|(stanza_index, _)| {
        stanza_error(
            file_index,
            *stanza_index,
            "phone stanza did not match an available paired identity",
        )
    }));
    Err(errors)
}

fn open_identities(
    identities: &[(usize, PublicIdentityStub)],
    root: &std::path::Path,
) -> (Vec<OpenedIdentity>, Vec<identity::Error>) {
    let mut opened = Vec::with_capacity(identities.len());
    let mut errors = Vec::new();
    for (position, (identity_index, stub)) in identities.iter().enumerate() {
        let Ok(locator) = open_pairing_locator(root, stub) else {
            errors.push(identity_error(
                *identity_index,
                "paired desktop state is unavailable",
            ));
            continue;
        };
        let Ok(desktop) = DesktopKeyState::open(&locator.desktop_state) else {
            errors.push(identity_error(
                *identity_index,
                "desktop authentication state is unavailable",
            ));
            continue;
        };
        let Ok(recipient) = stub.paired_recipient() else {
            errors.push(identity_error(
                *identity_index,
                "phone identity is malformed",
            ));
            continue;
        };
        opened.push(OpenedIdentity {
            position,
            locator,
            desktop,
            recipient,
        });
    }
    (opened, errors)
}

fn all_supported_files_error(
    files: &[Vec<Stanza>],
    error: identity::Error,
) -> HashMap<usize, Result<FileKey, Vec<identity::Error>>> {
    let mut error = Some(error);
    files
        .iter()
        .enumerate()
        .filter(|(_, stanzas)| {
            stanzas
                .iter()
                .any(|stanza| stanza.tag == STANZA_TAG || stanza.tag == STANZA_TAG_V2)
        })
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

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::{
        locator::create_pairing_locator,
        pairing::{DesktopKeyState, PublicIdentityStub},
    };
    use age_plugin_phone_protocol::{ReplayGuard, SignedUnwrapRequest, seal_response};
    use age_plugin_phone_recipient_p256::{
        PairedRecipient, Recipient, unwrap_file_key, wrap_file_key, wrap_file_key_v2,
    };
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
            Self::with_identity_id([0x31; 16])
        }

        fn with_identity_id(identity_id: [u8; 16]) -> Self {
            let root = std::env::temp_dir().join(format!(
                "age-phone-identity-v1-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                rand_core::RngCore::next_u64(&mut OsRng),
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
                identity_id,
                recipient: recipient.to_string().unwrap(),
                desktop_signing_public_key: desktop
                    .signing_key()
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                desktop_selection_public_key: desktop
                    .selection_key()
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
                desktop_selection_public_key: stub.desktop_selection_public_key,
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

        fn selectable_stanza(&self, file_key: [u8; 16]) -> Stanza {
            let stanza = wrap_file_key_v2(
                &self.stub.paired_recipient().unwrap(),
                &file_key,
                &mut OsRng,
            )
            .unwrap();
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
                Ok(Ok(Zeroizing::new(
                    fixture.respond(request, now_unix().unwrap()),
                )))
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
                Ok(Ok(Zeroizing::new(response)))
            },
        )
        .unwrap();
        assert!(matches!(results.get(&0), Some(Err(_))));
    }

    #[test]
    fn ambiguous_identities_and_stanzas_fail_before_authorization() {
        let fixture = Fixture::new();
        let mut other_stub = fixture.stub.clone();
        other_stub.identity_id = [0x91; 16];
        let identities = vec![(0, fixture.stub.clone()), (1, other_stub)];
        let files = vec![
            vec![fixture.stanza([7; 16])],
            vec![fixture.stanza([8; 16]), fixture.stanza([9; 16])],
        ];
        let mut exchanges = 0;
        let results = unwrap_with_exchange(&identities, files, &fixture.config, |_, _| {
            exchanges += 1;
            Ok(Err(ExchangeError::Failed))
        })
        .unwrap();
        assert_eq!(exchanges, 0);
        for file_index in [0, 1] {
            assert!(matches!(results.get(&file_index), Some(Err(_))));
        }

        let single_identity = vec![(0, fixture.stub.clone())];
        let mut exchanges = 0;
        let results = unwrap_with_exchange(
            &single_identity,
            vec![vec![fixture.stanza([10; 16]), fixture.stanza([11; 16])]],
            &fixture.config,
            |_, _| {
                exchanges += 1;
                Ok(Err(ExchangeError::Failed))
            },
        )
        .unwrap();
        assert_eq!(exchanges, 0);
        let Some(Err(errors)) = results.get(&0) else {
            panic!("ambiguous stanzas must fail");
        };
        assert_eq!(errors.len(), 2);
    }

    #[test]
    fn privately_selects_one_v2_stanza_without_phone_trial() {
        use age_core::secrecy::ExposeSecret as _;

        let fixture = Fixture::new();
        let wrong_desktop = SigningKey::random(&mut OsRng);
        let wrong_recipient = PairedRecipient::from_public_fields(
            fixture
                .identity
                .public_key()
                .to_encoded_point(true)
                .as_bytes(),
            wrong_desktop
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
            [0x92; 16],
        )
        .unwrap();
        let wrong = wrap_file_key_v2(&wrong_recipient, &[13; 16], &mut OsRng).unwrap();
        let files = vec![vec![
            Stanza {
                tag: wrong.tag,
                args: wrong.args,
                body: wrong.body,
            },
            fixture.selectable_stanza([12; 16]),
        ]];
        let mut exchanges = 0;
        let results = unwrap_with_exchange(
            &[(0, fixture.stub.clone())],
            files,
            &fixture.config,
            |request, _| {
                exchanges += 1;
                Ok(Ok(Zeroizing::new(
                    fixture.respond(request, now_unix().unwrap()),
                )))
            },
        )
        .unwrap();
        assert_eq!(exchanges, 1);
        let Ok(file_key) = results.get(&0).unwrap() else {
            panic!("matching v2 stanza must unwrap");
        };
        assert_eq!(file_key.expose_secret(), &[12; 16]);
    }

    #[test]
    fn v2_selection_respects_identity_order_without_mismatched_prompt() {
        use age_core::secrecy::ExposeSecret as _;

        let first = Fixture::new();
        let second = Fixture::with_identity_id([0x41; 16]);
        create_pairing_locator(
            &first.config,
            &second.stub,
            &second.root.join("desktop.key"),
            &second.root.join("responses.cbor"),
        )
        .unwrap();
        let identities = vec![(0, second.stub.clone()), (1, first.stub.clone())];
        let files = vec![vec![
            first.selectable_stanza([14; 16]),
            second.selectable_stanza([15; 16]),
        ]];
        let mut selected_identity = None;
        let results = unwrap_with_exchange(&identities, files, &first.config, |request, _| {
            let decoded = SignedUnwrapRequest::decode(request).unwrap();
            selected_identity = Some(decoded.payload.identity_id);
            Ok(Ok(Zeroizing::new(
                second.respond(request, now_unix().unwrap()),
            )))
        })
        .unwrap();
        assert_eq!(selected_identity, Some(second.stub.identity_id));
        let Ok(file_key) = results.get(&0).unwrap() else {
            panic!("preferred matching identity must unwrap");
        };
        assert_eq!(file_key.expose_secret(), &[15; 16]);
    }

    #[test]
    fn test_constructor_uses_explicit_config_root() {
        let plugin = PhoneIdentityPlugin::with_config_root(PathBuf::from("/tmp/test-only"));
        assert_eq!(plugin.config_root.unwrap(), PathBuf::from("/tmp/test-only"));
    }

    #[test]
    fn route_options_require_one_explicit_transport() {
        let wifi = SocketAddr::from(([192, 168, 1, 20], crate::wifi::WIFI_UNWRAP_PORT));
        assert!(valid_identity_route_options(
            IdentityTransport::Adb,
            None,
            None
        ));
        assert!(valid_identity_route_options(
            IdentityTransport::Adb,
            Some("phone"),
            None,
        ));
        assert!(!valid_identity_route_options(
            IdentityTransport::Adb,
            None,
            Some(wifi),
        ));
        assert!(valid_identity_route_options(
            IdentityTransport::Wifi,
            None,
            Some(wifi),
        ));
        assert!(!valid_identity_route_options(
            IdentityTransport::Wifi,
            Some("phone"),
            Some(wifi),
        ));
        assert!(!valid_identity_route_options(
            IdentityTransport::Qr,
            None,
            Some(wifi),
        ));
    }
}
