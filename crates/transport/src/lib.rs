//! Bounded one-request/one-response transport sessions.
//!
//! This crate deliberately knows nothing about pairing records, age stanzas, signatures, or user
//! authorization. Transports carry opaque canonical protocol messages; authentication remains in
//! the protocol layer above this boundary.

#![allow(clippy::missing_errors_doc)]

use std::io::{Read, Write};

use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"APTS";
const HEADER_LEN: usize = 28;
pub const STREAM_VERSION: u16 = 1;
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionPurpose {
    Pairing = 1,
    Unwrap = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Direction {
    DesktopRequest = 1,
    PhoneResponse = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportLimits {
    pub max_message_bytes: usize,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransportError {
    #[error("transport session is already closed")]
    SessionClosed,
    #[error("transport message exceeds the configured bound")]
    MessageTooLarge,
    #[error("transport stream ended or failed")]
    Io,
    #[error("transport frame is malformed or belongs to another session")]
    InvalidFrame,
}

/// A one-shot desktop transport. Implementations must return at most one opaque response.
pub trait DesktopTransport {
    fn exchange(
        &mut self,
        purpose: SessionPurpose,
        request: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TransportError>;

    fn cancel(&mut self);
}

/// Length-delimited stream implementation used by loopback transports such as ADB reverse.
pub struct DesktopStreamSession<S> {
    stream: S,
    limits: TransportLimits,
    session_id: [u8; 16],
    closed: bool,
}

impl<S: Read + Write> DesktopStreamSession<S> {
    pub fn new(
        stream: S,
        limits: TransportLimits,
        random: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, TransportError> {
        if limits.max_message_bytes == 0 || limits.max_message_bytes > u32::MAX as usize {
            return Err(TransportError::MessageTooLarge);
        }
        let mut session_id = [0_u8; 16];
        random.fill_bytes(&mut session_id);
        Ok(Self {
            stream,
            limits,
            session_id,
            closed: false,
        })
    }

    #[must_use]
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }
}

impl<S: Read + Write> DesktopTransport for DesktopStreamSession<S> {
    fn exchange(
        &mut self,
        purpose: SessionPurpose,
        request: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        if self.closed {
            return Err(TransportError::SessionClosed);
        }
        self.closed = true;
        write_message(
            &mut self.stream,
            purpose,
            Direction::DesktopRequest,
            &self.session_id,
            request,
            self.limits,
        )?;
        self.stream.flush().map_err(|_| TransportError::Io)?;
        read_message(
            &mut self.stream,
            purpose,
            Direction::PhoneResponse,
            &self.session_id,
            self.limits,
        )
    }

    fn cancel(&mut self) {
        self.closed = true;
    }
}

fn write_message(
    writer: &mut impl Write,
    purpose: SessionPurpose,
    direction: Direction,
    session_id: &[u8; 16],
    message: &[u8],
    limits: TransportLimits,
) -> Result<(), TransportError> {
    if message.len() > limits.max_message_bytes {
        return Err(TransportError::MessageTooLarge);
    }
    let length = u32::try_from(message.len()).map_err(|_| TransportError::MessageTooLarge)?;
    let mut header = [0_u8; HEADER_LEN];
    header[..4].copy_from_slice(MAGIC);
    header[4..6].copy_from_slice(&STREAM_VERSION.to_be_bytes());
    header[6] = purpose as u8;
    header[7] = direction as u8;
    header[8..24].copy_from_slice(session_id);
    header[24..].copy_from_slice(&length.to_be_bytes());
    writer.write_all(&header).map_err(|_| TransportError::Io)?;
    writer.write_all(message).map_err(|_| TransportError::Io)
}

fn read_message(
    reader: &mut impl Read,
    purpose: SessionPurpose,
    direction: Direction,
    session_id: &[u8; 16],
    limits: TransportLimits,
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let mut header = [0_u8; HEADER_LEN];
    reader
        .read_exact(&mut header)
        .map_err(|_| TransportError::Io)?;
    if &header[..4] != MAGIC
        || header[4..6] != STREAM_VERSION.to_be_bytes()
        || header[6] != purpose as u8
        || header[7] != direction as u8
        || header[8..24] != session_id[..]
    {
        return Err(TransportError::InvalidFrame);
    }
    let length = u32::from_be_bytes(
        header[24..]
            .try_into()
            .map_err(|_| TransportError::InvalidFrame)?,
    ) as usize;
    if length > limits.max_message_bytes {
        return Err(TransportError::MessageTooLarge);
    }
    let mut message = vec![0_u8; length];
    reader
        .read_exact(&mut message)
        .map_err(|_| TransportError::Io)?;
    Ok(Zeroizing::new(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use std::io::Cursor;

    struct ScriptedStream {
        incoming: Cursor<Vec<u8>>,
        outgoing: Vec<u8>,
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.incoming.read(buffer)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.outgoing.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn response(
        purpose: SessionPurpose,
        direction: Direction,
        session_id: [u8; 16],
        body: &[u8],
    ) -> Vec<u8> {
        let mut encoded = Vec::new();
        write_message(
            &mut encoded,
            purpose,
            direction,
            &session_id,
            body,
            TransportLimits::default(),
        )
        .unwrap();
        encoded
    }

    #[test]
    fn exchanges_one_bounded_opaque_message() {
        let mut session = DesktopStreamSession::new(
            ScriptedStream {
                incoming: Cursor::new(Vec::new()),
                outgoing: Vec::new(),
            },
            TransportLimits::default(),
            &mut OsRng,
        )
        .unwrap();
        let id = session.session_id();
        session.stream.incoming = Cursor::new(response(
            SessionPurpose::Pairing,
            Direction::PhoneResponse,
            id,
            b"response",
        ));
        let received = session
            .exchange(SessionPurpose::Pairing, b"request")
            .unwrap();
        assert_eq!(received.as_slice(), b"response");
        assert_eq!(
            session.exchange(SessionPurpose::Pairing, b"request"),
            Err(TransportError::SessionClosed)
        );
    }

    #[test]
    fn rejects_wrong_session_purpose_direction_and_truncation() {
        for bytes in [
            response(
                SessionPurpose::Unwrap,
                Direction::PhoneResponse,
                [1; 16],
                b"x",
            ),
            response(
                SessionPurpose::Pairing,
                Direction::DesktopRequest,
                [1; 16],
                b"x",
            ),
            vec![0; HEADER_LEN - 1],
        ] {
            let error = read_message(
                &mut Cursor::new(bytes),
                SessionPurpose::Pairing,
                Direction::PhoneResponse,
                &[1; 16],
                TransportLimits::default(),
            )
            .unwrap_err();
            assert!(matches!(
                error,
                TransportError::InvalidFrame | TransportError::Io
            ));
        }
    }

    #[test]
    fn rejects_wrong_session_and_oversize_before_allocating() {
        let wrong = response(
            SessionPurpose::Pairing,
            Direction::PhoneResponse,
            [2; 16],
            b"x",
        );
        assert_eq!(
            read_message(
                &mut Cursor::new(wrong),
                SessionPurpose::Pairing,
                Direction::PhoneResponse,
                &[1; 16],
                TransportLimits::default(),
            ),
            Err(TransportError::InvalidFrame)
        );

        let mut oversized = response(
            SessionPurpose::Pairing,
            Direction::PhoneResponse,
            [1; 16],
            b"",
        );
        oversized[24..].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            read_message(
                &mut Cursor::new(oversized),
                SessionPurpose::Pairing,
                Direction::PhoneResponse,
                &[1; 16],
                TransportLimits::default(),
            ),
            Err(TransportError::MessageTooLarge)
        );
    }

    #[test]
    fn cancellation_is_terminal() {
        let mut session = DesktopStreamSession::new(
            Cursor::new(Vec::new()),
            TransportLimits::default(),
            &mut OsRng,
        )
        .unwrap();
        session.cancel();
        assert_eq!(
            session.exchange(SessionPurpose::Unwrap, b"request"),
            Err(TransportError::SessionClosed)
        );
    }
}
