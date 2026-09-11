//! Standard age `identity-v1` adapter for one-shot phone unwraps.

use std::{collections::HashMap, io, net::SocketAddr, path::PathBuf};

use crate::transport::{DesktopTransport, SessionPurpose, TransportLimits};
use age_core::format::{FileKey, Stanza};
use age_plugin::{
    Callbacks,
    identity::{self, IdentityPluginV1},
};
use age_plugin_phone_core::protocol::{
    DEFAULT_REPLAY_CAPACITY, FileReplayGuard, PairingRecord, ReplayRole, ReplayScope,
    fragment_qr_message,
};
use age_plugin_phone_core::recipient::{
    PairedRecipient, Recipient, STANZA_TAG, STANZA_TAG_V2, TaggedStanza, matches_stanza_v2, tag,
    validate_stanza,
};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::{
    adb::{AdbReverseSession, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MESSAGE_TIMEOUT, SystemAdb},
    locator::{PairingLocator, default_config_root, open_pairing_locator},
    pairing::{DesktopKeyState, PublicIdentityStub},
    qr_scanner::{DEFAULT_SCAN_TIMEOUT, ScanError, ScannerHandle},
    qr_terminal::render_terminal_frame,
    transport_policy::{
        TransportChoice, TransportHints, TransportKind, TransportOperation, TransportRoute,
        resolve_transport,
    },
    unwrap::{DesktopUnwrapSession, UnwrapDisplay, now_unix},
    wifi::{DEFAULT_DISCOVERY_TIMEOUT, WifiError, WifiSession, discover_unwrap_endpoint},
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
        if plugin_name != age_plugin_phone_core::recipient::PLUGIN_NAME {
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
        let messages_enabled = identity_messages_enabled();
        unwrap_with_prepared_exchange(
            &self.identities,
            files,
            || self.config_root(),
            |stub, locator| {
                let transport_override = identity_transport_override()
                    .map_err(|()| internal("unsupported phone transport selection"))?;
                identity_route_options(transport_override.unwrap_or(locator.transport), stub)
            },
            |route, request, display| {
                exchange_identity_transport(
                    route,
                    request,
                    display,
                    messages_enabled,
                    &mut callbacks,
                )
            },
        )
    }
}

fn identity_transport_override() -> Result<Option<TransportChoice>, ()> {
    match std::env::var("AGE_PLUGIN_PHONE_TRANSPORT") {
        Ok(value) => value.parse().map(Some).map_err(|_| ()),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(()),
    }
}

fn identity_messages_enabled() -> bool {
    std::env::var("AGE_PLUGIN_PHONE_MESSAGES")
        .ok()
        .is_some_and(|value| parse_message_setting(&value))
}

fn parse_message_setting(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn identity_route_options(
    transport: TransportChoice,
    stub: &PublicIdentityStub,
) -> Result<TransportRoute, identity::Error> {
    let adb_serial = optional_env("AGE_PLUGIN_PHONE_ADB_SERIAL")
        .map_err(|_| internal("ADB device selection is malformed"))?;
    let mut wifi_address = optional_env("AGE_PLUGIN_PHONE_WIFI_ADDRESS")?
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .map_err(|_| internal("Wi-Fi endpoint selection is malformed"))
        })
        .transpose()?;
    if adb_serial.is_none()
        && wifi_address.is_none()
        && matches!(transport, TransportChoice::Auto | TransportChoice::Wifi)
    {
        match discover_unwrap_endpoint(
            stub.desktop_id,
            stub.identity_id,
            &stub.phone_signing_public_key,
            DEFAULT_DISCOVERY_TIMEOUT,
            &mut OsRng,
        ) {
            Ok(discovered) => wifi_address = Some(discovered),
            Err(WifiError::DiscoveryUnavailable) if transport == TransportChoice::Auto => {}
            Err(error) => return Err(internal(&format!("phone Wi-Fi discovery failed: {error}"))),
        }
    }
    resolve_transport(
        transport,
        TransportOperation::Unwrap,
        TransportHints {
            adb_serial,
            wifi_address,
        },
    )
    .map_err(|_| internal("phone transport selection is unavailable or inconsistent"))
}

fn optional_env(name: &str) -> Result<Option<String>, identity::Error> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(internal("environment value is malformed")),
    }
}

fn exchange_identity_transport(
    route: &TransportRoute,
    request: &[u8],
    display: &UnwrapDisplay,
    messages_enabled: bool,
    callbacks: &mut impl Callbacks<identity::Error>,
) -> io::Result<Result<Zeroizing<Vec<u8>>, ExchangeError>> {
    match route.kind() {
        TransportKind::Adb => {
            exchange_identity_adb(route, request, display, messages_enabled, callbacks)
        }
        TransportKind::Wifi => {
            exchange_identity_wifi(route, request, display, messages_enabled, callbacks)
        }
        TransportKind::Qr => exchange_identity_qr(request, display, callbacks),
        TransportKind::Ble => {
            unreachable!("unimplemented BLE is rejected before request creation")
        }
    }
}

fn exchange_identity_adb(
    route: &TransportRoute,
    request: &[u8],
    display: &UnwrapDisplay,
    messages_enabled: bool,
    callbacks: &mut impl Callbacks<identity::Error>,
) -> io::Result<Result<Zeroizing<Vec<u8>>, ExchangeError>> {
    if messages_enabled {
        let prompt = format!(
            "The paired phone app will open for Developer USB approval.\nRequest fingerprint: {}\nADB is an untrusted transport; phone verification and protocol authentication remain required.",
            display.request_fingerprint,
        );
        let Ok(()) = callbacks.message(&prompt)? else {
            return Ok(Err(ExchangeError::Cancelled));
        };
    }
    let Ok(mut session) = AdbReverseSession::connect(
        SystemAdb::default(),
        route.adb_serial(),
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
    route: &TransportRoute,
    request: &[u8],
    display: &UnwrapDisplay,
    messages_enabled: bool,
    callbacks: &mut impl Callbacks<identity::Error>,
) -> io::Result<Result<Zeroizing<Vec<u8>>, ExchangeError>> {
    if messages_enabled {
        let prompt = format!(
            "Enable Wi-Fi auto-listen and keep the paired phone app in the foreground before continuing.\nRequest fingerprint: {}\nThe LAN route is untrusted; phone verification and protocol authentication remain required.",
            display.request_fingerprint,
        );
        let Ok(()) = callbacks.message(&prompt)? else {
            return Ok(Err(ExchangeError::Cancelled));
        };
    }
    let Ok(mut session) = WifiSession::connect(
        route.wifi_address().expect("validated Wi-Fi endpoint"),
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_MESSAGE_TIMEOUT,
        TransportLimits::default(),
        &mut OsRng,
    ) else {
        return Ok(Err(ExchangeError::ConnectionFailed));
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
    ConnectionFailed,
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

#[cfg(all(test, not(windows)))]
fn unwrap_with_exchange<F>(
    identities: &[(usize, PublicIdentityStub)],
    files: Vec<Vec<Stanza>>,
    root: &std::path::Path,
    mut exchange: F,
) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>>
where
    F: FnMut(&[u8], &UnwrapDisplay) -> io::Result<Result<Zeroizing<Vec<u8>>, ExchangeError>>,
{
    unwrap_with_prepared_exchange(
        identities,
        files,
        || Ok(root.to_path_buf()),
        |_, _| Ok(()),
        |(), request, display| exchange(request, display),
    )
}

#[allow(clippy::too_many_lines)]
fn unwrap_with_prepared_exchange<R, P, F>(
    identities: &[(usize, PublicIdentityStub)],
    files: Vec<Vec<Stanza>>,
    mut resolve_root: impl FnMut() -> Result<PathBuf, identity::Error>,
    mut prepare: P,
    mut exchange: F,
) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>>
where
    P: FnMut(&PublicIdentityStub, &PairingLocator) -> Result<R, identity::Error>,
    F: FnMut(&R, &[u8], &UnwrapDisplay) -> io::Result<Result<Zeroizing<Vec<u8>>, ExchangeError>>,
{
    let mut results = HashMap::new();
    for (file_index, stanzas) in files.into_iter().enumerate() {
        let mut errors = Vec::new();
        let mut candidates = Vec::new();
        for (stanza_index, stanza) in stanzas.into_iter().enumerate() {
            if stanza.tag != STANZA_TAG
                && stanza.tag != STANZA_TAG_V2
                && stanza.tag != tag::STANZA_TAG
            {
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
        if candidates.is_empty() || !errors.is_empty() {
            if !errors.is_empty() {
                results.insert(file_index, Err(errors));
            }
            continue;
        }

        let mut public_match = None;
        for (position, (_, stanza)) in candidates.iter().enumerate() {
            if stanza.tag != tag::STANZA_TAG {
                continue;
            }
            let mut matched_key = None;
            for (identity_position, (_, stub)) in identities.iter().enumerate() {
                let recipient = Recipient::parse(stub.recipient()).expect("validated stub");
                if tag::matches(&recipient, stanza).expect("validated stanza") {
                    let key = recipient.public_key_bytes();
                    if matched_key.is_some_and(|previous| previous != key) {
                        errors.push(internal("ambiguous p256tag recipient"));
                    }
                    if matched_key.is_none() {
                        matched_key = Some(key);
                        if public_match.is_none() {
                            public_match = Some((identity_position, position));
                        }
                    }
                }
            }
        }
        if !errors.is_empty() {
            results.insert(file_index, Err(errors));
            continue;
        }
        if public_match.is_none() {
            candidates.retain(|(_, stanza)| stanza.tag != tag::STANZA_TAG);
            if candidates.is_empty() {
                continue;
            }
        }
        let root = match resolve_root() {
            Ok(root) => root,
            Err(error) => {
                results.insert(file_index, Err(vec![error]));
                continue;
            }
        };
        let selected = if let Some((identity_position, position)) = public_match {
            select_candidate(
                &identities[identity_position..=identity_position],
                vec![candidates.remove(position)],
                &root,
                file_index,
            )
        } else {
            select_candidate(identities, candidates, &root, file_index)
        };

        let selected = match selected {
            Ok(Some(selected)) => selected,
            Ok(None) => continue,
            Err(selection_errors) => {
                errors.extend(selection_errors);
                results.insert(file_index, Err(errors));
                continue;
            }
        };
        let SelectedCandidate {
            identity_index,
            stub,
            stanza_index,
            stanza,
            locator,
            desktop,
        } = selected;
        let pairing = PairingRecord {
            desktop_id: stub.desktop_id,
            identity_id: stub.identity_id,
            desktop_signing_public_key: stub.desktop_signing_public_key,
            desktop_selection_public_key: stub.desktop_selection_public_key,
            phone_signing_public_key: stub.phone_signing_public_key,
        };
        let prepared = match prepare(stub, &locator) {
            Ok(prepared) => prepared,
            Err(error) => {
                errors.push(error);
                results.insert(file_index, Err(errors));
                continue;
            }
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
        let response = match exchange(&prepared, &session.signed_request(), &session.display())? {
            Ok(response) => response,
            Err(ExchangeError::Cancelled) => {
                session.cancel();
                errors.push(identity_error(identity_index, "phone unwrap cancelled"));
                results.insert(file_index, Err(errors));
                return Ok(results);
            }
            Err(ExchangeError::ConnectionFailed) => {
                session.cancel();
                errors.push(stanza_error(
                    file_index,
                    stanza_index,
                    "phone Wi-Fi connection unavailable after discovery",
                ));
                results.insert(file_index, Err(errors));
                continue;
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
) -> Result<Option<SelectedCandidate<'a>>, Vec<identity::Error>> {
    if identities.is_empty() {
        return Err(vec![internal("no phone identity was provided")]);
    }

    if candidates
        .iter()
        .any(|(_, stanza)| stanza.tag == STANZA_TAG || stanza.tag == tag::STANZA_TAG)
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
        return Ok(Some(SelectedCandidate {
            identity_index: *identity_index,
            stub,
            stanza_index,
            stanza,
            locator,
            desktop,
        }));
    }

    let (mut opened, errors) = open_identities(identities, root);
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
        return Ok(Some(SelectedCandidate {
            identity_index: *identity_index,
            stub,
            stanza_index,
            stanza,
            locator: identity.locator,
            desktop: identity.desktop,
        }));
    }
    if errors.is_empty() {
        // A valid stanza for another pairing is an ordinary identity miss. Returning no
        // result lets the age client classify this invocation as ErrIncorrectIdentity and
        // continue with the next configured plugin identity.
        Ok(None)
    } else {
        Err(errors)
    }
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
    use age_plugin_phone_core::protocol::{ReplayGuard, SignedUnwrapRequest, seal_response};
    use age_plugin_phone_core::recipient::{
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
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "age-phone-identity-v1-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                rand_core::RngCore::next_u64(&mut OsRng),
            ));
            std::fs::create_dir(&root).unwrap();
            #[cfg(unix)]
            std::fs::set_permissions(
                &root,
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .unwrap();
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
            let config = root.clone();
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

        fn tag_stanza(&self, file_key: [u8; 16]) -> Stanza {
            let recipient = Recipient::parse(self.stub.recipient()).unwrap();
            let stanza =
                tag::wrap_with_ephemeral(&recipient, &file_key, &SecretKey::random(&mut OsRng))
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
    fn tag_unmatched_and_malformed_never_prepare_or_exchange() {
        let fixture = Fixture::new();
        let other = Fixture::new();
        let missing = fixture.root.join("unavailable-private-state");
        let identities = [(0, fixture.stub.clone())];
        let mut malformed = fixture.tag_stanza([1; 16]);
        malformed.args.push("extra".into());
        let results = unwrap_with_prepared_exchange(
            &identities,
            vec![
                vec![other.tag_stanza([2; 16])],
                vec![fixture.tag_stanza([3; 16]), malformed],
            ],
            || panic!("must not resolve private configuration"),
            |_, _| -> Result<(), identity::Error> { panic!("must not prepare transport") },
            |(), _, _| panic!("must not contact phone"),
        )
        .unwrap();
        assert!(!results.contains_key(&0));
        assert!(results[&1].is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn unmatched_v2_stanza_is_an_ordinary_identity_miss() {
        let configured = Fixture::new();
        let target = Fixture::new();
        let results = unwrap_with_exchange(
            &[(0, configured.stub.clone())],
            vec![vec![target.selectable_stanza([2; 16])]],
            &configured.config,
            |_, _| panic!("an unmatched identity must not contact the phone"),
        )
        .unwrap();

        // The identity-v1 framework turns an absent result into a normal no-match so the
        // reference age client can continue with the next configured plugin identity.
        assert!(results.is_empty());
    }

    #[test]
    fn tag_first_pairing_is_final_even_when_private_state_or_exchange_fails() {
        let fixture = Fixture::new();
        let mut missing = fixture.stub.clone();
        missing.desktop_id[0] ^= 1;
        let results = unwrap_with_exchange(
            &[(1, missing.clone()), (0, fixture.stub.clone())],
            vec![vec![fixture.tag_stanza([7; 16])]],
            &fixture.config,
            |_, _| panic!("missing first pairing must not fall through"),
        )
        .unwrap();
        assert!(results[&0].is_err());
        for error in [
            ExchangeError::Cancelled,
            ExchangeError::Failed,
            ExchangeError::ConnectionFailed,
            ExchangeError::InvalidResponse,
        ] {
            let mut calls = 0;
            let results = unwrap_with_exchange(
                &[(0, fixture.stub.clone()), (1, missing.clone())],
                vec![vec![
                    fixture.tag_stanza([7; 16]),
                    fixture.selectable_stanza([7; 16]),
                ]],
                &fixture.config,
                |_, _| {
                    calls += 1;
                    Ok(Err(error))
                },
            )
            .unwrap();
            assert!(results[&0].is_err());
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn tag_and_old_phone_use_same_signed_response_boundary() {
        let fixture = Fixture::new();
        let files = vec![
            vec![fixture.tag_stanza([1; 16])],
            vec![fixture.selectable_stanza([2; 16])],
            vec![fixture.stanza([3; 16])],
        ];
        let mut calls = 0;
        let results = unwrap_with_exchange(
            &[(0, fixture.stub.clone())],
            files,
            &fixture.config,
            |request, _| {
                calls += 1;
                Ok(Ok(Zeroizing::new(
                    fixture.respond(request, now_unix().unwrap()),
                )))
            },
        )
        .unwrap();
        assert_eq!(calls, 3);
        for (index, key) in [[1; 16], [2; 16], [3; 16]].iter().enumerate() {
            use age_core::secrecy::ExposeSecret as _;
            let Ok(opened) = &results[&index] else {
                panic!("expected authenticated file key")
            };
            assert_eq!(opened.expose_secret(), key);
        }
    }

    #[test]
    fn real_tag_collision_fails_before_private_state() {
        use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as B64};
        // Public-only bytes from core/test-vectors/p256tag-collision.json. Keep the desktop
        // package test independent of another package's filesystem layout and private scalars.
        let fixture = Fixture::new();
        let mut identities = Vec::new();
        for (index, encoded) in [
            "0393c9db8de26d0c2e47f25721f68f53c58d4afc153d222769e591f9a0b1c61b05",
            "0216a58b99bc15d7d705c667fb22eb07c29ae7875c768ae7260c086fd7d662a7db",
        ]
        .iter()
        .enumerate()
        {
            let bytes: Vec<u8> = (0..encoded.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
                .collect();
            let mut stub = fixture.stub.clone();
            stub.recipient = Recipient::from_public_key_bytes(&bytes)
                .unwrap()
                .to_string()
                .unwrap();
            identities.push((index, stub));
        }
        let stanza = TaggedStanza {
            tag: "p256tag".into(),
            args: vec!["3/obTQ".into(), "BHzyexiNA09+ilI4AwS1GsPAiWnid/IbNaYLSPxHZpl4B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E".into()],
            body: B64.decode("NfMzIBYZv9oCrYcadr2EsJj2eap9I3Lv8lq8tR1xtZA").unwrap(),
        };
        for (_, stub) in &identities {
            assert!(tag::matches(&Recipient::parse(stub.recipient()).unwrap(), &stanza).unwrap());
        }
        let stanza = Stanza {
            tag: stanza.tag,
            args: stanza.args,
            body: stanza.body,
        };
        let results = unwrap_with_prepared_exchange(
            &identities,
            vec![vec![stanza]],
            || panic!("ambiguity must not resolve private configuration"),
            |_, _| -> Result<(), identity::Error> { panic!("ambiguous tag must not prepare") },
            |(), _, _| panic!("ambiguous tag must not exchange"),
        )
        .unwrap();
        let errors = results[&0].as_ref().err().unwrap();
        assert!(
            matches!(&errors[0], identity::Error::Internal { message } if message == "ambiguous p256tag recipient")
        );
    }

    #[test]
    fn desktop_message_setting_is_explicit() {
        for enabled in ["1", "true", "TRUE", "yes", "on", " on "] {
            assert!(parse_message_setting(enabled));
        }
        for disabled in ["", "0", "false", "no", "off", "unexpected"] {
            assert!(!parse_message_setting(disabled));
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
        let second_desktop = first.config.join("second-desktop.key");
        let second_replay = first.config.join("second-responses.cbor");
        std::fs::copy(second.root.join("desktop.key"), &second_desktop).unwrap();
        std::fs::copy(second.root.join("responses.cbor"), &second_replay).unwrap();
        create_pairing_locator(&first.config, &second.stub, &second_desktop, &second_replay)
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
}
