use std::fmt;

use age_plugin_phone_protocol::EncodedQrFrame;
use qrcode::{
    QrCode,
    render::{svg, unicode::Dense1x2},
    types::EcLevel,
};
use thiserror::Error;

pub const DEFAULT_FRAME_INTERVAL_MS: u64 = 250;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TerminalQrError {
    #[error("QR frame cannot be encoded at the selected error-correction level")]
    Encoding,
    #[error("animation needs at least one frame")]
    EmptyAnimation,
    #[error("animation frame interval must be non-zero")]
    InvalidInterval,
    #[error("animation clock moved backwards")]
    ClockRollback,
}

/// Renders one transport frame without ever writing its textual representation.
///
/// # Errors
///
/// Returns [`TerminalQrError::Encoding`] if the frame does not fit a QR symbol.
pub fn render_terminal_frame(frame: &EncodedQrFrame) -> Result<String, TerminalQrError> {
    let code = QrCode::with_error_correction_level(frame.as_str().as_bytes(), EcLevel::M)
        .map_err(|_| TerminalQrError::Encoding)?;
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Dark)
        .light_color(Dense1x2::Light)
        .quiet_zone(true)
        .build())
}

/// Builds a self-contained offline SVG animation without embedding frame text.
///
/// # Errors
///
/// Returns [`TerminalQrError::EmptyAnimation`] for no frames, or
/// [`TerminalQrError::Encoding`] if any frame does not fit a QR symbol.
pub fn render_offline_html(
    frames: &[EncodedQrFrame],
    offer_digest: &[u8; 32],
) -> Result<String, TerminalQrError> {
    use fmt::Write as _;

    if frames.is_empty() {
        return Err(TerminalQrError::EmptyAnimation);
    }
    let safe_digest = offer_digest.iter().fold(
        String::with_capacity(offer_digest.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        },
    );
    let frame_count = frames.len();
    let mut rendered_frames = String::new();
    for (index, frame) in frames.iter().enumerate() {
        let code = QrCode::with_error_correction_level(frame.as_str().as_bytes(), EcLevel::M)
            .map_err(|_| TerminalQrError::Encoding)?;
        let svg = code
            .render::<svg::Color>()
            .min_dimensions(900, 900)
            .quiet_zone(true)
            .build();
        write!(
            rendered_frames,
            "<div class=\"frame{}\">{svg}</div>",
            if index == 0 { " active" } else { "" },
        )
        .expect("writing to a String cannot fail");
    }
    Ok(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>QR capture probe</title>\
         <style>html,body{{margin:0;height:100%;background:#fff;font-family:system-ui}}\
         body{{display:grid;place-items:center}}main{{text-align:center}}\
         .frame{{display:none}}.frame.active{{display:block}}svg{{width:min(82vh,82vw);height:min(82vh,82vw)}}\
         p{{margin:.25rem;color:#111}}</style><main><p>QR capture probe · {frame_count}-frame animation</p>\
         <p>Offer digest: {safe_digest}</p>{rendered_frames}</main>\
         <script>const f=[...document.querySelectorAll('.frame')];let i=0;\
         setInterval(()=>{{f[i].classList.remove('active');i=(i+1)%f.length;f[i].classList.add('active')}},250)</script>"
    ))
}

/// Selects animation frames from a monotonic clock without retaining frame contents.
pub struct FrameScheduler<'a> {
    frames: &'a [EncodedQrFrame],
    interval_ms: u64,
    started_at_ms: Option<u64>,
    last_now_ms: Option<u64>,
}

impl<'a> FrameScheduler<'a> {
    /// Creates a scheduler over borrowed frames.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty animation or zero interval.
    pub fn new(frames: &'a [EncodedQrFrame], interval_ms: u64) -> Result<Self, TerminalQrError> {
        if frames.is_empty() {
            return Err(TerminalQrError::EmptyAnimation);
        }
        if interval_ms == 0 {
            return Err(TerminalQrError::InvalidInterval);
        }
        Ok(Self {
            frames,
            interval_ms,
            started_at_ms: None,
            last_now_ms: None,
        })
    }

    /// Selects the frame for a monotonic timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`TerminalQrError::ClockRollback`] if `now_ms` precedes the last timestamp.
    pub fn frame_at(
        &mut self,
        now_ms: u64,
    ) -> Result<(usize, &'a EncodedQrFrame), TerminalQrError> {
        if self.last_now_ms.is_some_and(|last| now_ms < last) {
            return Err(TerminalQrError::ClockRollback);
        }
        let started_at_ms = *self.started_at_ms.get_or_insert(now_ms);
        self.last_now_ms = Some(now_ms);
        let elapsed = now_ms - started_at_ms;
        let ticks = elapsed / self.interval_ms;
        let frame_count =
            u64::try_from(self.frames.len()).map_err(|_| TerminalQrError::EmptyAnimation)?;
        let index =
            usize::try_from(ticks % frame_count).map_err(|_| TerminalQrError::ClockRollback)?;
        Ok((index, &self.frames[index]))
    }
}

impl fmt::Debug for FrameScheduler<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameScheduler")
            .field("frame_count", &self.frames.len())
            .field("interval_ms", &self.interval_ms)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use age_plugin_phone_protocol::fragment_qr_message;
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn renderer_does_not_emit_raw_frame_text() {
        let frames = fragment_qr_message(&vec![7_u8; 1_300], 600, &mut OsRng).unwrap();
        let rendered = render_terminal_frame(&frames[0]).unwrap();
        assert!(!rendered.contains("age-phone:qr1:"));
        assert!(rendered.lines().count() > 20);
        let html = render_offline_html(&frames, &[0_u8; 32]).unwrap();
        assert!(!html.contains("age-phone:qr1:"));
        assert_eq!(html.matches("<svg").count(), frames.len());
    }

    #[test]
    fn scheduler_cycles_without_copying_or_extending_deadlines() {
        let frames = fragment_qr_message(&vec![9_u8; 1_300], 600, &mut OsRng).unwrap();
        let mut scheduler = FrameScheduler::new(&frames, 250).unwrap();
        assert_eq!(scheduler.frame_at(1_000).unwrap().0, 0);
        assert_eq!(scheduler.frame_at(1_249).unwrap().0, 0);
        assert_eq!(scheduler.frame_at(1_250).unwrap().0, 1);
        assert_eq!(scheduler.frame_at(1_500).unwrap().0, 2);
        assert_eq!(scheduler.frame_at(1_750).unwrap().0, 0);
        assert_eq!(
            scheduler.frame_at(1_749),
            Err(TerminalQrError::ClockRollback)
        );
    }

    #[test]
    fn empty_and_zero_interval_animations_are_rejected() {
        assert_eq!(
            FrameScheduler::new(&[], 250).unwrap_err(),
            TerminalQrError::EmptyAnimation
        );
        let frames = fragment_qr_message(b"x", 1, &mut OsRng).unwrap();
        assert_eq!(
            FrameScheduler::new(&frames, 0).unwrap_err(),
            TerminalQrError::InvalidInterval
        );
    }
}
