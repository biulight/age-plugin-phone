use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use minicbor::{Decoder, Encoder};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const TEXT_PREFIX: &str = "age-phone:qr1:";
const FRAME_VERSION: u16 = 1;
const FRAME_TYPE: u16 = 1;
const TRANSFER_ID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const MAX_ENCODED_FRAME_CHARS: usize = 2_048;
const MESSAGE_DIGEST_DOMAIN: &[u8] = b"age-plugin-phone/qr-message-digest/v1";

pub const DEFAULT_QR_CHUNK_BYTES: usize = 600;
pub const MAX_QR_MESSAGE_BYTES: usize = 65_536;
pub const MAX_QR_FRAGMENTS: usize = 128;
pub const MAX_QR_ASSEMBLY_AGE_MS: u64 = 30_000;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QrError {
    #[error("empty or oversized QR message")]
    MessageSize,
    #[error("unsupported QR chunk size")]
    ChunkSize,
    #[error("too many QR fragments")]
    TooManyFragments,
    #[error("malformed or non-canonical QR frame")]
    MalformedFrame,
    #[error("unsupported QR frame version")]
    UnsupportedVersion,
    #[error("unsupported QR frame type")]
    UnsupportedType,
    #[error("frame belongs to a different QR transfer")]
    DifferentTransfer,
    #[error("conflicting duplicate QR fragment")]
    ConflictingFragment,
    #[error("QR assembly timed out")]
    Timeout,
    #[error("clock moved backwards during QR assembly")]
    ClockRollback,
    #[error("QR message digest mismatch")]
    DigestMismatch,
    #[error("QR assembly is poisoned and must be reset")]
    Poisoned,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncodedQrFrame(String);

impl EncodedQrFrame {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for EncodedQrFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncodedQrFrame([REDACTED])")
    }
}

pub enum QrAssemblyStatus {
    InProgress { received: usize, total: usize },
    Complete(Zeroizing<Vec<u8>>),
}

impl fmt::Debug for QrAssemblyStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InProgress { received, total } => formatter
                .debug_struct("InProgress")
                .field("received", received)
                .field("total", total)
                .finish(),
            Self::Complete(message) => formatter
                .debug_struct("Complete")
                .field("message_bytes", &message.len())
                .finish(),
        }
    }
}

pub fn fragment_qr_message(
    message: &[u8],
    chunk_bytes: usize,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<Vec<EncodedQrFrame>, QrError> {
    if message.is_empty() || message.len() > MAX_QR_MESSAGE_BYTES {
        return Err(QrError::MessageSize);
    }
    if !(1..=DEFAULT_QR_CHUNK_BYTES).contains(&chunk_bytes) {
        return Err(QrError::ChunkSize);
    }
    let fragment_count = message.len().div_ceil(chunk_bytes);
    if fragment_count > MAX_QR_FRAGMENTS {
        return Err(QrError::TooManyFragments);
    }

    let mut transfer_id = [0_u8; TRANSFER_ID_BYTES];
    rng.fill_bytes(&mut transfer_id);
    let digest = message_digest(message);
    message
        .chunks(chunk_bytes)
        .enumerate()
        .map(|(index, chunk)| {
            Frame {
                transfer_id,
                digest,
                index: u16::try_from(index).map_err(|_| QrError::TooManyFragments)?,
                count: u16::try_from(fragment_count).map_err(|_| QrError::TooManyFragments)?,
                total_len: message.len(),
                chunk: Zeroizing::new(chunk.to_vec()),
            }
            .encode_text()
        })
        .collect()
}

#[derive(Default)]
pub struct QrReassembler {
    active: Option<ActiveAssembly>,
    poisoned: bool,
}

impl QrReassembler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, encoded: &str, now_ms: u64) -> Result<QrAssemblyStatus, QrError> {
        if self.poisoned {
            return Err(QrError::Poisoned);
        }
        let frame = Frame::decode_text(encoded)?;
        if self.active.is_none() {
            self.active = Some(ActiveAssembly::new(&frame, now_ms));
        }

        let active = self.active.as_mut().ok_or(QrError::MalformedFrame)?;
        if now_ms < active.started_at_ms {
            self.active = None;
            self.poisoned = true;
            return Err(QrError::ClockRollback);
        }
        if now_ms - active.started_at_ms > MAX_QR_ASSEMBLY_AGE_MS {
            self.active = None;
            self.poisoned = true;
            return Err(QrError::Timeout);
        }
        if frame.transfer_id != active.transfer_id
            || frame.digest != active.digest
            || frame.count != active.count
            || frame.total_len != active.total_len
        {
            return Err(QrError::DifferentTransfer);
        }

        let slot = &mut active.chunks[usize::from(frame.index)];
        if let Some(existing) = slot {
            if existing.as_slice() != frame.chunk.as_slice() {
                self.active = None;
                self.poisoned = true;
                return Err(QrError::ConflictingFragment);
            }
        } else {
            let Some(received_bytes) = active.received_bytes.checked_add(frame.chunk.len()) else {
                self.active = None;
                self.poisoned = true;
                return Err(QrError::MalformedFrame);
            };
            active.received_bytes = received_bytes;
            if active.received_bytes > active.total_len {
                self.active = None;
                self.poisoned = true;
                return Err(QrError::MalformedFrame);
            }
            *slot = Some(frame.chunk);
            active.received += 1;
        }

        if active.received != usize::from(active.count) {
            return Ok(QrAssemblyStatus::InProgress {
                received: active.received,
                total: usize::from(active.count),
            });
        }

        let completed = self.active.take().ok_or(QrError::MalformedFrame)?;
        match completed.assemble() {
            Ok(message) => Ok(QrAssemblyStatus::Complete(message)),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    pub fn reset(&mut self) {
        self.active = None;
        self.poisoned = false;
    }
}

struct ActiveAssembly {
    transfer_id: [u8; TRANSFER_ID_BYTES],
    digest: [u8; DIGEST_BYTES],
    count: u16,
    total_len: usize,
    started_at_ms: u64,
    chunks: Vec<Option<Zeroizing<Vec<u8>>>>,
    received: usize,
    received_bytes: usize,
}

impl ActiveAssembly {
    fn new(frame: &Frame, now_ms: u64) -> Self {
        Self {
            transfer_id: frame.transfer_id,
            digest: frame.digest,
            count: frame.count,
            total_len: frame.total_len,
            started_at_ms: now_ms,
            chunks: (0..frame.count).map(|_| None).collect(),
            received: 0,
            received_bytes: 0,
        }
    }

    fn assemble(self) -> Result<Zeroizing<Vec<u8>>, QrError> {
        let mut chunks = self
            .chunks
            .into_iter()
            .map(|chunk| chunk.ok_or(QrError::MalformedFrame))
            .collect::<Result<Vec<_>, _>>()?;
        let chunk_size = chunks.first().ok_or(QrError::MalformedFrame)?.len();
        if chunk_size == 0
            || chunks[..chunks.len().saturating_sub(1)]
                .iter()
                .any(|chunk| chunk.len() != chunk_size)
            || chunks
                .last()
                .is_none_or(|chunk| chunk.is_empty() || chunk.len() > chunk_size)
        {
            return Err(QrError::MalformedFrame);
        }

        let mut message = Zeroizing::new(Vec::with_capacity(self.total_len));
        for chunk in &mut chunks {
            message.extend_from_slice(chunk);
        }
        if message.len() != self.total_len {
            return Err(QrError::MalformedFrame);
        }
        if message_digest(&message) != self.digest {
            return Err(QrError::DigestMismatch);
        }
        Ok(message)
    }
}

struct Frame {
    transfer_id: [u8; TRANSFER_ID_BYTES],
    digest: [u8; DIGEST_BYTES],
    index: u16,
    count: u16,
    total_len: usize,
    chunk: Zeroizing<Vec<u8>>,
}

impl Frame {
    fn encode_text(&self) -> Result<EncodedQrFrame, QrError> {
        let encoded = self.encode_cbor()?;
        let text = format!("{TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(encoded));
        if text.len() > MAX_ENCODED_FRAME_CHARS {
            return Err(QrError::ChunkSize);
        }
        Ok(EncodedQrFrame(text))
    }

    fn encode_cbor(&self) -> Result<Vec<u8>, QrError> {
        let mut encoded = Vec::new();
        let total_len = u32::try_from(self.total_len).map_err(|_| QrError::MessageSize)?;
        Encoder::new(&mut encoded)
            .array(8)
            .and_then(|encoder| encoder.u16(FRAME_VERSION))
            .and_then(|encoder| encoder.u16(FRAME_TYPE))
            .and_then(|encoder| encoder.bytes(&self.transfer_id))
            .and_then(|encoder| encoder.bytes(&self.digest))
            .and_then(|encoder| encoder.u16(self.index))
            .and_then(|encoder| encoder.u16(self.count))
            .and_then(|encoder| encoder.u32(total_len))
            .and_then(|encoder| encoder.bytes(&self.chunk))
            .map_err(|_| QrError::MalformedFrame)?;
        Ok(encoded)
    }

    fn decode_text(text: &str) -> Result<Self, QrError> {
        if text.len() > MAX_ENCODED_FRAME_CHARS || !text.starts_with(TEXT_PREFIX) {
            return Err(QrError::MalformedFrame);
        }
        let payload = &text[TEXT_PREFIX.len()..];
        if payload.is_empty() || payload.contains('=') {
            return Err(QrError::MalformedFrame);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| QrError::MalformedFrame)?;
        if URL_SAFE_NO_PAD.encode(&decoded) != payload {
            return Err(QrError::MalformedFrame);
        }
        Self::decode_cbor(&decoded)
    }

    fn decode_cbor(encoded: &[u8]) -> Result<Self, QrError> {
        let mut decoder = Decoder::new(encoded);
        if decoder.array().map_err(|_| QrError::MalformedFrame)? != Some(8) {
            return Err(QrError::MalformedFrame);
        }
        let version = decoder.u16().map_err(|_| QrError::MalformedFrame)?;
        if version != FRAME_VERSION {
            return Err(QrError::UnsupportedVersion);
        }
        let frame_type = decoder.u16().map_err(|_| QrError::MalformedFrame)?;
        if frame_type != FRAME_TYPE {
            return Err(QrError::UnsupportedType);
        }
        let transfer_id = fixed_bytes::<TRANSFER_ID_BYTES>(&mut decoder)?;
        let digest = fixed_bytes::<DIGEST_BYTES>(&mut decoder)?;
        let index = decoder.u16().map_err(|_| QrError::MalformedFrame)?;
        let count = decoder.u16().map_err(|_| QrError::MalformedFrame)?;
        let total_len = usize::try_from(decoder.u32().map_err(|_| QrError::MalformedFrame)?)
            .map_err(|_| QrError::MalformedFrame)?;
        let chunk = decoder.bytes().map_err(|_| QrError::MalformedFrame)?;
        if decoder.position() != encoded.len()
            || count == 0
            || usize::from(count) > MAX_QR_FRAGMENTS
            || index >= count
            || !(1..=MAX_QR_MESSAGE_BYTES).contains(&total_len)
            || chunk.is_empty()
            || chunk.len() > DEFAULT_QR_CHUNK_BYTES
            || chunk.len() > total_len
        {
            return Err(QrError::MalformedFrame);
        }
        let frame = Self {
            transfer_id,
            digest,
            index,
            count,
            total_len,
            chunk: Zeroizing::new(chunk.to_vec()),
        };
        if frame.encode_cbor()? != encoded {
            return Err(QrError::MalformedFrame);
        }
        Ok(frame)
    }
}

fn fixed_bytes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], QrError> {
    decoder
        .bytes()
        .map_err(|_| QrError::MalformedFrame)?
        .try_into()
        .map_err(|_| QrError::MalformedFrame)
}

fn message_digest(message: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(MESSAGE_DIGEST_DOMAIN);
    hasher.update([0]);
    hasher.update(message);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRng(u8);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            u32::from_le_bytes(self.next_u64().to_le_bytes()[..4].try_into().unwrap())
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            for byte in destination {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

    #[test]
    fn fragments_and_reassembles_out_of_order_with_duplicates() {
        let message = (0_u8..=u8::MAX).cycle().take(3_002).collect::<Vec<_>>();
        let frames = fragment_qr_message(&message, 600, &mut TestRng(1)).unwrap();
        assert_eq!(frames.len(), 6);
        assert_eq!(format!("{:?}", frames[0]), "EncodedQrFrame([REDACTED])");
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(frames[0].as_str().as_bytes())),
            "5UAyIsE2JJ6HduQeKO9Ol_dIKe_qDfYinJPY9oJwiqQ"
        );

        let mut reassembler = QrReassembler::new();
        for (arrival, &index) in [4, 1, 1, 0, 5, 3].iter().enumerate() {
            assert!(matches!(
                reassembler.push(frames[index].as_str(), 1_000 + arrival as u64),
                Ok(QrAssemblyStatus::InProgress { .. })
            ));
        }
        let QrAssemblyStatus::Complete(completed) =
            reassembler.push(frames[2].as_str(), 1_010).unwrap()
        else {
            panic!("expected complete assembly");
        };
        assert_eq!(completed.as_slice(), message);
        assert_eq!(
            format!("{:?}", QrAssemblyStatus::Complete(completed)),
            "Complete { message_bytes: 3002 }"
        );
    }

    #[test]
    fn rejects_sizes_conflicts_cross_transfer_timeout_and_rollback() {
        assert_eq!(
            fragment_qr_message(&[], 600, &mut TestRng(0)).unwrap_err(),
            QrError::MessageSize
        );
        assert_eq!(
            fragment_qr_message(&[1], 601, &mut TestRng(0)).unwrap_err(),
            QrError::ChunkSize
        );
        assert_eq!(
            fragment_qr_message(&vec![1; MAX_QR_MESSAGE_BYTES], 1, &mut TestRng(0)).unwrap_err(),
            QrError::TooManyFragments
        );

        let first = fragment_qr_message(&vec![1; 700], 600, &mut TestRng(1)).unwrap();
        let other = fragment_qr_message(&vec![2; 700], 600, &mut TestRng(2)).unwrap();
        let mut reassembler = QrReassembler::new();
        reassembler.push(first[0].as_str(), 100).unwrap();
        assert_eq!(
            reassembler.push(other[0].as_str(), 101).unwrap_err(),
            QrError::DifferentTransfer
        );
        assert_eq!(
            reassembler.push(first[1].as_str(), 99).unwrap_err(),
            QrError::ClockRollback
        );
        assert_eq!(
            reassembler.push(first[1].as_str(), 102).unwrap_err(),
            QrError::Poisoned
        );
        reassembler.reset();
        reassembler.push(first[0].as_str(), 100).unwrap();
        assert_eq!(
            reassembler
                .push(first[1].as_str(), 100 + MAX_QR_ASSEMBLY_AGE_MS + 1)
                .unwrap_err(),
            QrError::Timeout
        );
    }

    #[test]
    fn rejects_noncanonical_text_metadata_and_digest_tamper() {
        let frames = fragment_qr_message(&vec![7; 700], 600, &mut TestRng(1)).unwrap();
        let padded = format!("{}=", frames[0].as_str());
        assert_eq!(
            QrReassembler::new().push(&padded, 0).unwrap_err(),
            QrError::MalformedFrame
        );

        let mut raw = URL_SAFE_NO_PAD
            .decode(&frames[0].as_str()[TEXT_PREFIX.len()..])
            .unwrap();
        raw.push(0);
        let trailing = format!("{TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
        assert_eq!(
            QrReassembler::new().push(&trailing, 0).unwrap_err(),
            QrError::MalformedFrame
        );

        let canonical = URL_SAFE_NO_PAD
            .decode(&frames[0].as_str()[TEXT_PREFIX.len()..])
            .unwrap();
        for (offset, expected) in [
            (1, QrError::UnsupportedVersion),
            (2, QrError::UnsupportedType),
        ] {
            let mut unknown = canonical.clone();
            unknown[offset] = 2;
            let unknown = format!("{TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(unknown));
            assert_eq!(
                QrReassembler::new().push(&unknown, 0).unwrap_err(),
                expected
            );
        }
        let mut extra_field = canonical.clone();
        extra_field[0] = 0x89;
        let extra_field = format!("{TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(extra_field));
        assert_eq!(
            QrReassembler::new().push(&extra_field, 0).unwrap_err(),
            QrError::MalformedFrame
        );
        let mut noncanonical = canonical.clone();
        noncanonical.splice(1..2, [0x18, 0x01]);
        let noncanonical = format!("{TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(noncanonical));
        assert_eq!(
            QrReassembler::new().push(&noncanonical, 0).unwrap_err(),
            QrError::MalformedFrame
        );

        let mut tampered = Frame::decode_text(frames[1].as_str()).unwrap();
        tampered.chunk[0] ^= 1;
        let tampered = tampered.encode_text().unwrap();
        let mut reassembler = QrReassembler::new();
        reassembler.push(frames[0].as_str(), 0).unwrap();
        assert_eq!(
            reassembler.push(tampered.as_str(), 1).unwrap_err(),
            QrError::DigestMismatch
        );
        assert_eq!(
            reassembler.push(frames[1].as_str(), 2).unwrap_err(),
            QrError::Poisoned
        );
    }

    #[test]
    fn conflicting_duplicate_poison_requires_explicit_reset() {
        let frames = fragment_qr_message(&vec![4; 1_000], 600, &mut TestRng(1)).unwrap();
        let mut conflict = Frame::decode_text(frames[0].as_str()).unwrap();
        conflict.chunk[0] ^= 1;
        let conflict = conflict.encode_text().unwrap();
        let mut reassembler = QrReassembler::new();
        reassembler.push(frames[0].as_str(), 0).unwrap();
        assert_eq!(
            reassembler.push(conflict.as_str(), 1).unwrap_err(),
            QrError::ConflictingFragment
        );
        assert_eq!(
            reassembler.push(frames[1].as_str(), 2).unwrap_err(),
            QrError::Poisoned
        );
        reassembler.reset();
        reassembler.push(frames[0].as_str(), 3).unwrap();
        assert!(matches!(
            reassembler.push(frames[1].as_str(), 4),
            Ok(QrAssemblyStatus::Complete(_))
        ));
    }
}
