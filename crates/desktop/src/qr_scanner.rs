//! Bounded, in-memory desktop QR response scanning.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};

use age_plugin_phone_protocol::{QrAssemblyStatus, QrError, QrReassembler};
#[cfg(target_os = "macos")]
use nokhwa::utils::{CameraFormat, FrameFormat};
use nokhwa::{
    Camera,
    pixel_format::LumaFormat,
    utils::{CameraIndex, RequestedFormat, RequestedFormatType},
};
use rqrr::PreparedImage;
use thiserror::Error;
use zeroize::Zeroizing;

const TRANSPORT_PREFIX: &str = "age-phone:qr1:";
const MAX_FRAME_PIXELS: u64 = 16_000_000;
pub const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ScanError {
    #[error("desktop camera is unavailable")]
    CameraUnavailable,
    #[error("desktop camera frame is unsupported")]
    UnsupportedFrame,
    #[error("QR response scan timed out")]
    Timeout,
    #[error("QR response scan was cancelled")]
    Cancelled,
    #[error("QR response fragments were rejected")]
    InvalidTransfer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanProgress {
    Waiting,
    Receiving { received: usize, total: usize },
}

type ScanUpdate = Result<(ScanProgress, Option<Zeroizing<Vec<u8>>>), ScanError>;

/// Pure framing state used by the camera scanner and negative tests.
pub struct ScanSession {
    assembly: QrReassembler,
    started_at_ms: u64,
    deadline_ms: u64,
    cancelled: bool,
}

impl ScanSession {
    #[must_use]
    pub fn new(started_at_ms: u64, timeout: Duration) -> Self {
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        Self {
            assembly: QrReassembler::new(),
            started_at_ms,
            deadline_ms: started_at_ms.saturating_add(timeout_ms),
            cancelled: false,
        }
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Checks cancellation, monotonic time, and the overall scan deadline.
    ///
    /// # Errors
    ///
    /// Returns [`ScanError::Cancelled`] after cancellation or [`ScanError::Timeout`] when the
    /// deadline has elapsed or the supplied monotonic clock moves backwards.
    pub fn tick(&self, now_ms: u64) -> Result<ScanProgress, ScanError> {
        if self.cancelled {
            return Err(ScanError::Cancelled);
        }
        if now_ms < self.started_at_ms || now_ms > self.deadline_ms {
            return Err(ScanError::Timeout);
        }
        Ok(ScanProgress::Waiting)
    }

    /// Offers one decoded QR text value to the bounded reassembler.
    ///
    /// # Errors
    ///
    /// Returns an error for cancellation, overall timeout, clock rollback, conflicting fragments,
    /// a poisoned assembly, or a completed-message digest failure.
    pub fn push(&mut self, decoded_text: &str, now_ms: u64) -> ScanUpdate {
        self.tick(now_ms)?;
        if !decoded_text.starts_with(TRANSPORT_PREFIX) {
            return Ok((ScanProgress::Waiting, None));
        }

        let status = match self.assembly.push(decoded_text, now_ms) {
            Ok(status) => status,
            Err(
                QrError::MalformedFrame | QrError::UnsupportedVersion | QrError::UnsupportedType,
            ) => {
                return Ok((ScanProgress::Waiting, None));
            }
            Err(QrError::DifferentTransfer) => return Ok((ScanProgress::Waiting, None)),
            Err(QrError::Timeout) => {
                self.assembly.reset();
                match self.assembly.push(decoded_text, now_ms) {
                    Ok(status) => status,
                    Err(_) => return Err(ScanError::InvalidTransfer),
                }
            }
            Err(
                QrError::ConflictingFragment
                | QrError::ClockRollback
                | QrError::DigestMismatch
                | QrError::Poisoned
                | QrError::MessageSize
                | QrError::ChunkSize
                | QrError::TooManyFragments,
            ) => return Err(ScanError::InvalidTransfer),
        };
        match status {
            QrAssemblyStatus::InProgress { received, total } => {
                Ok((ScanProgress::Receiving { received, total }, None))
            }
            QrAssemblyStatus::Complete(message) => Ok((ScanProgress::Waiting, Some(message))),
        }
    }
}

/// A scanner worker. Dropping it requests cancellation without waiting on a blocked camera driver.
pub struct ScannerHandle {
    receiver: Receiver<Result<Zeroizing<Vec<u8>>, ScanError>>,
    cancelled: Arc<AtomicBool>,
    timeout: Duration,
}

impl ScannerHandle {
    #[must_use]
    pub fn start_default_camera(timeout: Duration) -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        thread::spawn(move || {
            let result = scan_default_camera(timeout, &worker_cancelled);
            let _ = sender.send(result);
        });
        Self {
            receiver,
            cancelled,
            timeout,
        }
    }

    /// Polls the camera worker without blocking.
    ///
    /// # Errors
    ///
    /// Returns the worker's scan error, or [`ScanError::CameraUnavailable`] if it terminated
    /// unexpectedly.
    pub fn try_result(&self) -> Result<Option<Zeroizing<Vec<u8>>>, ScanError> {
        match self.receiver.try_recv() {
            Ok(result) => result.map(Some),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(ScanError::CameraUnavailable),
        }
    }

    /// Waits for one complete response or a terminal scanner error.
    ///
    /// # Errors
    ///
    /// Returns the worker's scan error, or [`ScanError::CameraUnavailable`] if it terminated
    /// unexpectedly.
    pub fn wait(self) -> Result<Zeroizing<Vec<u8>>, ScanError> {
        match self.receiver.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                self.cancel();
                Err(ScanError::Timeout)
            }
            Err(RecvTimeoutError::Disconnected) => Err(ScanError::CameraUnavailable),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl Drop for ScannerHandle {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn scan_default_camera(
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<Zeroizing<Vec<u8>>, ScanError> {
    let mut camera = open_default_camera_stream()?;
    let resolution = camera.resolution();
    let pixels = u64::from(resolution.width_x).saturating_mul(u64::from(resolution.height_y));
    if pixels == 0 || pixels > MAX_FRAME_PIXELS {
        return Err(ScanError::UnsupportedFrame);
    }

    let started = Instant::now();
    let mut session = ScanSession::new(0, timeout);
    loop {
        if cancelled.load(Ordering::Acquire) {
            session.cancel();
        }
        let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        session.tick(now_ms)?;
        let frame = camera.frame().map_err(|_| ScanError::CameraUnavailable)?;
        let image = frame
            .decode_image::<LumaFormat>()
            .map_err(|_| ScanError::UnsupportedFrame)?;
        let width = usize::try_from(image.width()).map_err(|_| ScanError::UnsupportedFrame)?;
        let height = usize::try_from(image.height()).map_err(|_| ScanError::UnsupportedFrame)?;
        for decoded in decode_qr_texts(width, height, image.as_raw()) {
            let (_, complete) = session.push(&decoded, now_ms)?;
            if let Some(message) = complete {
                return Ok(message);
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn open_default_camera_stream() -> Result<Camera, ScanError> {
    // `RequestedFormatType::None` currently selects a rejected 1080p/15fps YUYV mode on some
    // FaceTime cameras. Keep AVFoundation negotiation explicit and bounded instead.
    let candidates = [
        CameraFormat::new_from(1280, 720, FrameFormat::NV12, 30),
        CameraFormat::new_from(640, 480, FrameFormat::NV12, 30),
        CameraFormat::new_from(1920, 1080, FrameFormat::NV12, 30),
        CameraFormat::new_from(1280, 720, FrameFormat::YUYV, 30),
        CameraFormat::new_from(640, 480, FrameFormat::YUYV, 30),
    ];
    for format in candidates {
        let requested = RequestedFormat::new::<LumaFormat>(RequestedFormatType::Exact(format));
        let Ok(mut camera) = Camera::new(CameraIndex::Index(0), requested) else {
            continue;
        };
        if camera.open_stream().is_ok() {
            return Ok(camera);
        }
    }
    Err(ScanError::CameraUnavailable)
}

#[cfg(not(target_os = "macos"))]
fn open_default_camera_stream() -> Result<Camera, ScanError> {
    let requested = RequestedFormat::new::<LumaFormat>(RequestedFormatType::None);
    let mut camera =
        Camera::new(CameraIndex::Index(0), requested).map_err(|_| ScanError::CameraUnavailable)?;
    camera
        .open_stream()
        .map_err(|_| ScanError::CameraUnavailable)?;
    Ok(camera)
}

fn decode_qr_texts(width: usize, height: usize, greyscale: &[u8]) -> Vec<Zeroizing<String>> {
    if width
        .checked_mul(height)
        .is_none_or(|pixels| pixels != greyscale.len())
    {
        return Vec::new();
    }
    let mut prepared =
        PreparedImage::prepare_from_greyscale(width, height, |x, y| greyscale[y * width + x]);
    prepared
        .detect_grids()
        .into_iter()
        .filter_map(|grid| {
            grid.decode()
                .ok()
                .map(|(_, decoded)| Zeroizing::new(decoded))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use age_plugin_phone_protocol::{MAX_QR_ASSEMBLY_AGE_MS, fragment_qr_message};
    use qrcode::{QrCode, types::Color};
    use rand_core::OsRng;

    #[test]
    fn reassembles_out_of_order_frames_and_duplicates() {
        let frames = fragment_qr_message(&vec![0x5a; 1_300], 600, &mut OsRng).unwrap();
        let mut session = ScanSession::new(100, Duration::from_secs(60));
        assert!(session.push(frames[2].as_str(), 101).unwrap().1.is_none());
        assert!(session.push(frames[2].as_str(), 102).unwrap().1.is_none());
        assert!(session.push(frames[0].as_str(), 103).unwrap().1.is_none());
        let complete = session.push(frames[1].as_str(), 104).unwrap().1.unwrap();
        assert_eq!(complete.as_slice(), &[0x5a; 1_300]);
    }

    #[test]
    fn decodes_a_transport_frame_from_greyscale_pixels() {
        let frames = fragment_qr_message(b"camera decoder probe", 600, &mut OsRng).unwrap();
        let code = QrCode::new(frames[0].as_str()).unwrap();
        let modules = code.width();
        let quiet_modules = 4;
        let scale = 6;
        let width = (modules + quiet_modules * 2) * scale;
        let mut pixels = vec![255_u8; width * width];
        for module_y in 0..modules {
            for module_x in 0..modules {
                if code[(module_x, module_y)] != Color::Dark {
                    continue;
                }
                let left = (module_x + quiet_modules) * scale;
                let top = (module_y + quiet_modules) * scale;
                for y in top..top + scale {
                    pixels[y * width + left..y * width + left + scale].fill(0);
                }
            }
        }
        let decoded = decode_qr_texts(width, width, &pixels);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].as_str(), frames[0].as_str());
    }

    #[test]
    fn ignores_unrelated_malformed_and_wrong_transfer_frames() {
        let first = fragment_qr_message(&vec![1; 700], 600, &mut OsRng).unwrap();
        let other = fragment_qr_message(&vec![2; 700], 600, &mut OsRng).unwrap();
        let mut session = ScanSession::new(0, Duration::from_secs(60));
        assert!(
            session
                .push("https://example.invalid", 1)
                .unwrap()
                .1
                .is_none()
        );
        assert!(
            session
                .push("age-phone:qr1:not-valid", 2)
                .unwrap()
                .1
                .is_none()
        );
        assert!(session.push(first[0].as_str(), 3).unwrap().1.is_none());
        assert!(session.push(other[1].as_str(), 4).unwrap().1.is_none());
        let complete = session.push(first[1].as_str(), 5).unwrap().1.unwrap();
        assert_eq!(complete.as_slice(), &[1; 700]);
    }

    #[test]
    fn incomplete_transfer_can_restart_after_assembly_timeout() {
        let first = fragment_qr_message(&vec![1; 700], 600, &mut OsRng).unwrap();
        let second = fragment_qr_message(&vec![2; 700], 600, &mut OsRng).unwrap();
        let mut session = ScanSession::new(0, Duration::from_secs(90));
        session.push(first[0].as_str(), 1).unwrap();
        session
            .push(second[0].as_str(), MAX_QR_ASSEMBLY_AGE_MS + 2)
            .unwrap();
        let complete = session
            .push(second[1].as_str(), MAX_QR_ASSEMBLY_AGE_MS + 3)
            .unwrap()
            .1
            .unwrap();
        assert_eq!(complete.as_slice(), &[2; 700]);
    }

    #[test]
    fn cancellation_timeout_and_clock_rollback_fail_closed() {
        let mut cancelled = ScanSession::new(10, Duration::from_secs(1));
        cancelled.cancel();
        assert_eq!(cancelled.tick(10), Err(ScanError::Cancelled));

        let timed = ScanSession::new(10, Duration::from_millis(5));
        assert_eq!(timed.tick(16), Err(ScanError::Timeout));
        assert_eq!(timed.tick(9), Err(ScanError::Timeout));
    }

    #[test]
    fn blocking_wait_has_an_independent_supervisor_deadline() {
        let (_sender, receiver) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&cancelled);
        let scanner = ScannerHandle {
            receiver,
            cancelled,
            timeout: Duration::from_millis(1),
        };
        assert_eq!(scanner.wait(), Err(ScanError::Timeout));
        assert!(observed.load(Ordering::Acquire));
    }
}
