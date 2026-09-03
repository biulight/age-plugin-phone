//! Foreground Wi-Fi discovery and one-shot stream transport.
//!
//! Discovery produces an untrusted private IPv4 route hint. Existing-pairing responses are signed
//! by the paired phone key; pairing discovery is intentionally unauthenticated until the existing
//! signed transcript flow completes. The protocol above this boundary still verifies the paired
//! desktop, request digest, nonce, expiry, and response bindings.

#![allow(clippy::missing_errors_doc)]

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    time::{Duration, Instant},
};

use age_plugin_phone_transport::{
    DesktopStreamSession, DesktopTransport, SessionPurpose, TransportError, TransportLimits,
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

pub const WIFI_UNWRAP_PORT: u16 = 47_140;
pub const WIFI_DISCOVERY_PORT: u16 = 47_141;
pub const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);

const DISCOVERY_MAGIC: &[u8; 4] = b"APWD";
const DISCOVERY_VERSION: u16 = 1;
const DISCOVERY_QUERY: u8 = 1;
const DISCOVERY_RESPONSE: u8 = 2;
const DISCOVERY_PAIRING: u8 = 1;
const DISCOVERY_UNWRAP: u8 = 2;
const DISCOVERY_QUERY_BYTES: usize = 72;
const DISCOVERY_SIGNATURE_BYTES: usize = 64;
const DISCOVERY_RESPONSE_BYTES: usize = DISCOVERY_QUERY_BYTES + DISCOVERY_SIGNATURE_BYTES;
const DISCOVERY_SIGNATURE_DOMAIN: &[u8] = b"age-plugin-phone/wifi-discovery-response/v1";
const DISCOVERY_RETRY_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WifiError {
    #[error("the Wi-Fi endpoint must be an explicit private IPv4 address on the fixed PoC port")]
    InvalidEndpoint,
    #[error("the phone Wi-Fi listener was unavailable")]
    Unavailable,
    #[error("the phone Wi-Fi listener did not connect before the hard deadline")]
    ConnectionTimeout,
    #[error("the bounded Wi-Fi transport session could not be created")]
    Transport,
    #[error("no matching foreground Wi-Fi listener was discovered")]
    DiscoveryUnavailable,
    #[error("multiple matching foreground Wi-Fi listeners were discovered")]
    DiscoveryAmbiguous,
    #[error("the Wi-Fi discovery socket was unavailable")]
    Discovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiscoveryPurpose {
    Pairing,
    Unwrap,
}

impl DiscoveryPurpose {
    const fn code(self) -> u8 {
        match self {
            Self::Pairing => DISCOVERY_PAIRING,
            Self::Unwrap => DISCOVERY_UNWRAP,
        }
    }
}

struct DiscoveryQuery {
    purpose: DiscoveryPurpose,
    nonce: [u8; 32],
    desktop_id: [u8; 16],
    identity_id: [u8; 16],
}

/// Discovers the one foreground listener belonging to an existing pairing.
///
/// The returned address is still only a route hint. The response signature limits selection to
/// the paired phone key, while the signed unwrap request and response remain the authorization and
/// file-key security boundary.
pub fn discover_unwrap_endpoint(
    desktop_id: [u8; 16],
    identity_id: [u8; 16],
    phone_signing_public_key: &[u8; 33],
    timeout: Duration,
    random: &mut (impl CryptoRng + RngCore),
) -> Result<SocketAddr, WifiError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(phone_signing_public_key)
        .map_err(|_| WifiError::Discovery)?;
    discover_endpoint(
        &DiscoveryQuery {
            purpose: DiscoveryPurpose::Unwrap,
            nonce: random_nonce(random),
            desktop_id,
            identity_id,
        },
        Some(&verifying_key),
        timeout,
        SocketAddr::from((Ipv4Addr::BROADCAST, WIFI_DISCOVERY_PORT)),
    )
}

/// Discovers a phone that is in an explicit one-shot Wi-Fi pairing mode.
///
/// This pre-pairing route cannot yet be authenticated. Exactly one response is required, and the
/// existing signed pairing response plus full transcript comparison authenticate the peer later.
pub fn discover_pairing_endpoint(
    desktop_id: [u8; 16],
    timeout: Duration,
    random: &mut (impl CryptoRng + RngCore),
) -> Result<SocketAddr, WifiError> {
    discover_endpoint(
        &DiscoveryQuery {
            purpose: DiscoveryPurpose::Pairing,
            nonce: random_nonce(random),
            desktop_id,
            identity_id: [0; 16],
        },
        None,
        timeout,
        SocketAddr::from((Ipv4Addr::BROADCAST, WIFI_DISCOVERY_PORT)),
    )
}

fn random_nonce(random: &mut (impl CryptoRng + RngCore)) -> [u8; 32] {
    let mut nonce = [0; 32];
    random.fill_bytes(&mut nonce);
    nonce
}

fn discover_endpoint(
    query: &DiscoveryQuery,
    verifying_key: Option<&VerifyingKey>,
    timeout: Duration,
    target: SocketAddr,
) -> Result<SocketAddr, WifiError> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|_| WifiError::Discovery)?;
    socket
        .set_broadcast(true)
        .map_err(|_| WifiError::Discovery)?;
    let mut targets = discovery_targets();
    targets.insert(target);
    discover_with_socket(&socket, query, verifying_key, timeout, &targets)
}

fn discover_with_socket(
    socket: &UdpSocket,
    query: &DiscoveryQuery,
    verifying_key: Option<&VerifyingKey>,
    timeout: Duration,
    targets: &BTreeSet<SocketAddr>,
) -> Result<SocketAddr, WifiError> {
    let encoded = encode_discovery(query, DISCOVERY_QUERY);
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(WifiError::Discovery)?;
    let mut next_send = Instant::now();
    let mut candidates = BTreeSet::new();
    let mut buffer = [0_u8; DISCOVERY_RESPONSE_BYTES + 1];
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if now >= next_send {
            let mut sent = false;
            for target in targets {
                sent |= socket.send_to(&encoded, target).is_ok();
            }
            if !sent {
                return Err(WifiError::Discovery);
            }
            next_send = now + DISCOVERY_RETRY_INTERVAL;
        }
        let wait_until = deadline.min(next_send);
        let wait = wait_until.saturating_duration_since(Instant::now());
        socket
            .set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .map_err(|_| WifiError::Discovery)?;
        match socket.recv_from(&mut buffer) {
            Ok((length, source)) => {
                let IpAddr::V4(source_ip) = source.ip() else {
                    continue;
                };
                let endpoint = SocketAddr::from((source_ip, WIFI_UNWRAP_PORT));
                if validate_endpoint(endpoint).is_err()
                    || !valid_discovery_response(&buffer[..length], query, verifying_key)
                {
                    continue;
                }
                record_discovery_candidate(&mut candidates, endpoint)?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                ) => {}
            Err(_) => return Err(WifiError::Discovery),
        }
    }
    match candidates.len() {
        0 => Err(WifiError::DiscoveryUnavailable),
        1 => Ok(*candidates.first().expect("one discovery candidate")),
        _ => Err(WifiError::DiscoveryAmbiguous),
    }
}

#[cfg(not(windows))]
fn discovery_targets() -> BTreeSet<SocketAddr> {
    BTreeSet::from([SocketAddr::from((Ipv4Addr::BROADCAST, WIFI_DISCOVERY_PORT))])
}

#[cfg(windows)]
fn discovery_targets() -> BTreeSet<SocketAddr> {
    let mut targets =
        BTreeSet::from([SocketAddr::from((Ipv4Addr::BROADCAST, WIFI_DISCOVERY_PORT))]);
    targets.extend(
        windows_directed_broadcasts()
            .into_iter()
            .map(|address| SocketAddr::from((address, WIFI_DISCOVERY_PORT))),
    );
    targets
}

#[cfg(any(windows, test))]
fn directed_broadcast(address: Ipv4Addr, mask: Ipv4Addr) -> Option<Ipv4Addr> {
    if !private_route(address) {
        return None;
    }
    let mask = u32::from(mask);
    if mask == 0 || mask == u32::MAX || (!mask).checked_add(1)?.count_ones() != 1 {
        return None;
    }
    let broadcast = Ipv4Addr::from(u32::from(address) | !mask);
    (broadcast != address && broadcast != Ipv4Addr::BROADCAST).then_some(broadcast)
}

#[cfg(windows)]
fn windows_directed_broadcasts() -> BTreeSet<Ipv4Addr> {
    age_plugin_phone_windows_storage::ipv4_interface_subnets()
        .into_iter()
        .filter_map(|(address, mask)| directed_broadcast(address, mask))
        .collect()
}

fn record_discovery_candidate(
    candidates: &mut BTreeSet<SocketAddr>,
    endpoint: SocketAddr,
) -> Result<(), WifiError> {
    candidates.insert(endpoint);
    if candidates.len() > 1 {
        Err(WifiError::DiscoveryAmbiguous)
    } else {
        Ok(())
    }
}

fn encode_discovery(query: &DiscoveryQuery, kind: u8) -> [u8; DISCOVERY_QUERY_BYTES] {
    let mut encoded = [0_u8; DISCOVERY_QUERY_BYTES];
    encoded[..4].copy_from_slice(DISCOVERY_MAGIC);
    encoded[4..6].copy_from_slice(&DISCOVERY_VERSION.to_be_bytes());
    encoded[6] = kind;
    encoded[7] = query.purpose.code();
    encoded[8..40].copy_from_slice(&query.nonce);
    encoded[40..56].copy_from_slice(&query.desktop_id);
    encoded[56..72].copy_from_slice(&query.identity_id);
    encoded
}

fn valid_discovery_response(
    encoded: &[u8],
    query: &DiscoveryQuery,
    verifying_key: Option<&VerifyingKey>,
) -> bool {
    let expected = encode_discovery(query, DISCOVERY_RESPONSE);
    match (query.purpose, verifying_key) {
        (DiscoveryPurpose::Pairing, None) => encoded == expected,
        (DiscoveryPurpose::Unwrap, Some(key)) => {
            if encoded.len() != DISCOVERY_RESPONSE_BYTES
                || encoded[..DISCOVERY_QUERY_BYTES] != expected
            {
                return false;
            }
            let Ok(signature) = Signature::from_slice(&encoded[DISCOVERY_QUERY_BYTES..]) else {
                return false;
            };
            if signature.normalize_s().is_some() {
                return false;
            }
            let mut message =
                Vec::with_capacity(DISCOVERY_SIGNATURE_DOMAIN.len() + 1 + DISCOVERY_QUERY_BYTES);
            message.extend_from_slice(DISCOVERY_SIGNATURE_DOMAIN);
            message.push(0);
            message.extend_from_slice(&expected);
            key.verify(&message, &signature).is_ok()
        }
        (DiscoveryPurpose::Pairing | DiscoveryPurpose::Unwrap, _) => false,
    }
}

pub struct WifiSession {
    stream: DesktopStreamSession<TcpStream>,
    closed: bool,
}

impl WifiSession {
    pub fn connect(
        endpoint: SocketAddr,
        connect_timeout: Duration,
        message_timeout: Duration,
        limits: TransportLimits,
        random: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, WifiError> {
        validate_endpoint(endpoint)?;
        let stream = TcpStream::connect_timeout(&endpoint, connect_timeout).map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut {
                WifiError::ConnectionTimeout
            } else {
                WifiError::Unavailable
            }
        })?;
        Self::from_connected_stream(stream, message_timeout, limits, random)
    }

    fn from_connected_stream(
        stream: TcpStream,
        message_timeout: Duration,
        limits: TransportLimits,
        random: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, WifiError> {
        stream
            .set_read_timeout(Some(message_timeout))
            .map_err(|_| WifiError::Unavailable)?;
        stream
            .set_write_timeout(Some(message_timeout))
            .map_err(|_| WifiError::Unavailable)?;
        stream
            .set_nodelay(true)
            .map_err(|_| WifiError::Unavailable)?;
        let stream =
            DesktopStreamSession::new(stream, limits, random).map_err(|_| WifiError::Transport)?;
        Ok(Self {
            stream,
            closed: false,
        })
    }
}

impl DesktopTransport for WifiSession {
    fn exchange(
        &mut self,
        purpose: SessionPurpose,
        request: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        if self.closed {
            return Err(TransportError::SessionClosed);
        }
        self.closed = true;
        self.stream.exchange(purpose, request)
    }

    fn cancel(&mut self) {
        self.closed = true;
        self.stream.cancel();
    }
}

impl Drop for WifiSession {
    fn drop(&mut self) {
        self.stream.cancel();
    }
}

pub(crate) fn validate_endpoint(endpoint: SocketAddr) -> Result<(), WifiError> {
    let IpAddr::V4(address) = endpoint.ip() else {
        return Err(WifiError::InvalidEndpoint);
    };
    if endpoint.port() != WIFI_UNWRAP_PORT || !private_route(address) {
        return Err(WifiError::InvalidEndpoint);
    }
    Ok(())
}

fn private_route(address: Ipv4Addr) -> bool {
    (address.is_private() || address.is_link_local())
        && !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && address != Ipv4Addr::BROADCAST
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read as _, Write as _},
        net::{TcpListener, TcpStream},
        thread,
    };

    use p256::ecdsa::{SigningKey, signature::Signer as _};
    use rand_core::OsRng;

    #[derive(Clone, Copy)]
    enum PhoneBehavior {
        Valid,
        WrongSession,
        Disconnect,
    }

    fn connected_session(behavior: PhoneBehavior) -> (WifiSession, thread::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let endpoint = listener.local_addr().unwrap();
        let phone = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = [0_u8; 28];
            stream.read_exact(&mut header).unwrap();
            let length = u32::from_be_bytes(header[24..].try_into().unwrap()) as usize;
            let mut request = vec![0_u8; length];
            stream.read_exact(&mut request).unwrap();
            if matches!(behavior, PhoneBehavior::Disconnect) {
                return;
            }
            header[7] = 2;
            if matches!(behavior, PhoneBehavior::WrongSession) {
                header[8] ^= 1;
            }
            let response = b"wifi response";
            header[24..].copy_from_slice(&u32::try_from(response.len()).unwrap().to_be_bytes());
            stream.write_all(&header).unwrap();
            stream.write_all(response).unwrap();
            stream.flush().unwrap();
            request.fill(0);
        });
        let stream = TcpStream::connect(endpoint).unwrap();
        let session = WifiSession::from_connected_stream(
            stream,
            Duration::from_millis(250),
            TransportLimits::default(),
            &mut OsRng,
        )
        .unwrap();
        (session, phone)
    }

    #[test]
    fn accepts_only_fixed_port_private_ipv4_routes() {
        assert_eq!(
            validate_endpoint(SocketAddr::from(([192, 168, 1, 20], WIFI_UNWRAP_PORT))),
            Ok(())
        );
        assert_eq!(
            validate_endpoint(SocketAddr::from(([10, 0, 0, 3], WIFI_UNWRAP_PORT))),
            Ok(())
        );
        assert_eq!(
            validate_endpoint(SocketAddr::from(([169, 254, 4, 2], WIFI_UNWRAP_PORT))),
            Ok(())
        );
        for endpoint in [
            SocketAddr::from(([127, 0, 0, 1], WIFI_UNWRAP_PORT)),
            SocketAddr::from(([8, 8, 8, 8], WIFI_UNWRAP_PORT)),
            SocketAddr::from(([192, 168, 1, 20], WIFI_UNWRAP_PORT + 1)),
            SocketAddr::from(([224, 0, 0, 1], WIFI_UNWRAP_PORT)),
            SocketAddr::from(([0, 0, 0, 0], WIFI_UNWRAP_PORT)),
            SocketAddr::from(([255, 255, 255, 255], WIFI_UNWRAP_PORT)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], WIFI_UNWRAP_PORT)),
        ] {
            assert_eq!(validate_endpoint(endpoint), Err(WifiError::InvalidEndpoint));
        }
    }

    fn discovery_query(purpose: DiscoveryPurpose) -> DiscoveryQuery {
        DiscoveryQuery {
            purpose,
            nonce: [0x31; 32],
            desktop_id: [0x32; 16],
            identity_id: if purpose == DiscoveryPurpose::Pairing {
                [0; 16]
            } else {
                [0x33; 16]
            },
        }
    }

    #[test]
    fn discovery_encoding_is_fixed_and_strict() {
        let pairing = discovery_query(DiscoveryPurpose::Pairing);
        let query = encode_discovery(&pairing, DISCOVERY_QUERY);
        assert_eq!(query.len(), DISCOVERY_QUERY_BYTES);
        assert_eq!(&query[..4], DISCOVERY_MAGIC);
        assert_eq!(&query[4..6], &DISCOVERY_VERSION.to_be_bytes());
        assert_eq!(query[6], DISCOVERY_QUERY);
        assert_eq!(query[7], DISCOVERY_PAIRING);

        let response = encode_discovery(&pairing, DISCOVERY_RESPONSE);
        assert!(valid_discovery_response(&response, &pairing, None));
        let mut malformed = response.to_vec();
        malformed.push(0);
        assert!(!valid_discovery_response(&malformed, &pairing, None));
        malformed.pop();
        malformed[7] = DISCOVERY_UNWRAP;
        assert!(!valid_discovery_response(&malformed, &pairing, None));
    }

    #[test]
    fn unwrap_discovery_requires_the_paired_phone_signature() {
        let query = discovery_query(DiscoveryPurpose::Unwrap);
        let response = encode_discovery(&query, DISCOVERY_RESPONSE);
        let phone = SigningKey::random(&mut OsRng);
        let mut message = Vec::new();
        message.extend_from_slice(DISCOVERY_SIGNATURE_DOMAIN);
        message.push(0);
        message.extend_from_slice(&response);
        let signature: Signature = phone.sign(&message);
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut signed = response.to_vec();
        signed.extend_from_slice(signature.to_bytes().as_slice());
        assert!(valid_discovery_response(
            &signed,
            &query,
            Some(phone.verifying_key())
        ));

        let wrong_phone = SigningKey::random(&mut OsRng);
        assert!(!valid_discovery_response(
            &signed,
            &query,
            Some(wrong_phone.verifying_key())
        ));
        signed[8] ^= 1;
        assert!(!valid_discovery_response(
            &signed,
            &query,
            Some(phone.verifying_key())
        ));
    }

    #[test]
    fn discovery_rejects_replay_high_s_and_multiple_phones() {
        let query = discovery_query(DiscoveryPurpose::Unwrap);
        let response = encode_discovery(&query, DISCOVERY_RESPONSE);
        let phone = SigningKey::random(&mut OsRng);
        let mut message = Vec::from(DISCOVERY_SIGNATURE_DOMAIN);
        message.push(0);
        message.extend_from_slice(&response);
        let signature: Signature = phone.sign(&message);
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut signed = response.to_vec();
        signed.extend_from_slice(signature.to_bytes().as_slice());

        let mut replayed_query = discovery_query(DiscoveryPurpose::Unwrap);
        replayed_query.nonce[0] ^= 1;
        assert!(!valid_discovery_response(
            &signed,
            &replayed_query,
            Some(phone.verifying_key())
        ));

        let high_s = Signature::from_scalars(signature.r().to_bytes(), (-signature.s()).to_bytes())
            .expect("valid high-S twin");
        signed[DISCOVERY_QUERY_BYTES..].copy_from_slice(high_s.to_bytes().as_slice());
        assert!(!valid_discovery_response(
            &signed,
            &query,
            Some(phone.verifying_key())
        ));

        let mut candidates = BTreeSet::new();
        let first = SocketAddr::from(([192, 168, 1, 20], WIFI_UNWRAP_PORT));
        let second = SocketAddr::from(([192, 168, 1, 21], WIFI_UNWRAP_PORT));
        assert_eq!(record_discovery_candidate(&mut candidates, first), Ok(()));
        assert_eq!(record_discovery_candidate(&mut candidates, first), Ok(()));
        assert_eq!(
            record_discovery_candidate(&mut candidates, second),
            Err(WifiError::DiscoveryAmbiguous)
        );
    }

    #[test]
    fn discovery_timeout_fails_closed() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let unused = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = unused.local_addr().unwrap();
        drop(unused);
        let targets = BTreeSet::from([target]);
        assert_eq!(
            discover_with_socket(
                &socket,
                &discovery_query(DiscoveryPurpose::Pairing),
                None,
                Duration::from_millis(5),
                &targets,
            ),
            Err(WifiError::DiscoveryUnavailable)
        );
    }

    #[test]
    fn derives_only_private_subnet_broadcasts() {
        assert_eq!(
            directed_broadcast(
                Ipv4Addr::new(192, 168, 50, 53),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
            Some(Ipv4Addr::new(192, 168, 50, 255))
        );
        assert_eq!(
            directed_broadcast(
                Ipv4Addr::new(10, 43, 133, 69),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
            Some(Ipv4Addr::new(10, 43, 133, 255))
        );
        for (address, mask) in [
            ([8, 8, 8, 8], [255, 255, 255, 0]),
            ([192, 168, 50, 53], [255, 255, 255, 255]),
            ([192, 168, 50, 53], [0, 0, 0, 0]),
            ([192, 168, 50, 53], [255, 0, 255, 0]),
        ] {
            assert_eq!(
                directed_broadcast(Ipv4Addr::from(address), Ipv4Addr::from(mask)),
                None
            );
        }
    }

    #[test]
    fn exchanges_one_bounded_unwrap_message() {
        let (mut session, phone) = connected_session(PhoneBehavior::Valid);
        assert_eq!(
            session
                .exchange(SessionPurpose::Unwrap, b"signed request")
                .unwrap()
                .as_slice(),
            b"wifi response"
        );
        assert_eq!(
            session.exchange(SessionPurpose::Unwrap, b"second request"),
            Err(TransportError::SessionClosed)
        );
        phone.join().unwrap();
    }

    #[test]
    fn rejects_wrong_session_and_disconnect() {
        for behavior in [PhoneBehavior::WrongSession, PhoneBehavior::Disconnect] {
            let (mut session, phone) = connected_session(behavior);
            let error = session
                .exchange(SessionPurpose::Unwrap, b"signed request")
                .unwrap_err();
            assert!(matches!(
                error,
                TransportError::InvalidFrame | TransportError::Io
            ));
            phone.join().unwrap();
        }
    }
}
