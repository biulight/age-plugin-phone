//! Owner-only foreground Wi-Fi proof of concept.
//!
//! The route is an explicitly supplied private IPv4 socket address. It is never an
//! authentication input: the protocol above this boundary still verifies the paired desktop,
//! request digest, nonce, expiry, and response bindings.

#![allow(clippy::missing_errors_doc)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    time::Duration,
};

use age_plugin_phone_transport::{
    DesktopStreamSession, DesktopTransport, SessionPurpose, TransportError, TransportLimits,
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

pub const WIFI_UNWRAP_PORT: u16 = 47_140;

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

fn validate_endpoint(endpoint: SocketAddr) -> Result<(), WifiError> {
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
