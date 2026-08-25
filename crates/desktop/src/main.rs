use std::{
    io::{self, Write as _},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use age_plugin::{PluginHandler, run_state_machine};
use age_plugin_phone::adb::{
    AdbReverseSession, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MESSAGE_TIMEOUT, SystemAdb,
    run_cleanup_guard,
};
use age_plugin_phone::age_identity::PhoneIdentityPlugin;
use age_plugin_phone::age_recipient::PhoneRecipientPlugin;
use age_plugin_phone::locator::{create_pairing_locator, default_config_root, prepare_config_root};
use age_plugin_phone::pairing::{
    DesktopKeyState, DesktopPairingSession, MAX_PAIRING_SESSION_AGE_MS, create_identity_stub_file,
    read_identity_stub_file,
};
use age_plugin_phone::qr_scanner::{DEFAULT_SCAN_TIMEOUT, ScannerHandle};
use age_plugin_phone::qr_terminal::{
    DEFAULT_FRAME_INTERVAL_MS, FrameScheduler, render_offline_html, render_terminal_frame,
};
use age_plugin_phone::unwrap::{DesktopUnwrapSession, now_unix};
use age_plugin_phone_protocol::{
    DEFAULT_REPLAY_CAPACITY, FileReplayGuard, PROTOCOL_VERSION, PairingOffer, ReplayRole,
    ReplayScope, SignedPairingOffer, fragment_qr_message,
};
use age_plugin_phone_recipient_p256::{STANZA_TAG, TaggedStanza};
use age_plugin_phone_transport::{DesktopTransport, SessionPurpose, TransportLimits};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use clap::{Parser, Subcommand, ValueEnum};
use p256::ecdsa::SigningKey;
use rand_core::{OsRng, RngCore as _};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(name = "age-plugin-phone", version, about)]
struct Options {
    /// Run an age plugin state machine. This is invoked by age clients.
    #[arg(long, hide = true)]
    age_plugin: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(name = "__adb-cleanup-guard", hide = true)]
    AdbCleanupGuard {
        #[arg(long)]
        serial: String,
    },
    /// Report scaffold and protocol status without probing devices.
    Status,
    /// Complete an authenticated pairing over Developer USB or QR.
    Pair {
        /// Untrusted desktop label shown on both endpoints.
        #[arg(long)]
        label: String,
        /// Persistent desktop authentication state (contains no age identity key).
        #[arg(long)]
        desktop_state: PathBuf,
        /// New public age identity stub; an existing file is never overwritten.
        #[arg(long)]
        identity_output: PathBuf,
        /// Durable desktop response-replay state; must be an absolute path.
        #[arg(long)]
        replay_state: PathBuf,
        /// Bidirectional message transport. ADB is the Windows Alpha default; QR remains fallback.
        #[arg(long, value_enum, default_value_t = TransportChoice::default())]
        transport: TransportChoice,
        /// Explicit ADB device serial. Required when multiple devices are listed by ADB.
        #[arg(long, requires = "transport")]
        adb_serial: Option<String>,
    },
    /// Exercise one real paired unwrap over Developer USB or QR.
    Unwrap {
        #[arg(long)]
        identity_stub: PathBuf,
        #[arg(long)]
        desktop_state: PathBuf,
        /// Durable response-replay state created during pairing.
        #[arg(long)]
        replay_state: PathBuf,
        /// The single Base64 stanza argument from the age header.
        #[arg(long)]
        stanza_arg: String,
        /// Unpadded Base64 stanza body from the age header.
        #[arg(long)]
        stanza_body: String,
        /// Untrusted application/caller display hint shown on the phone.
        #[arg(long)]
        caller_hint: Option<String>,
        /// Bidirectional message transport. ADB is the Windows Alpha default; QR remains fallback.
        #[arg(long, value_enum, default_value_t = TransportChoice::default())]
        transport: TransportChoice,
        /// Explicit ADB device serial. Required when multiple devices are listed by ADB.
        #[arg(long, requires = "transport")]
        adb_serial: Option<String>,
    },
    /// Display a signed, disposable pairing offer to exercise QR capture only.
    QrCaptureProbe {
        /// Untrusted label shown by the phone after signature verification.
        #[arg(long, default_value = "Desktop QR capture probe")]
        label: String,
        /// Number of complete animation cycles before the probe exits.
        #[arg(long, default_value_t = 12)]
        cycles: u16,
        /// Write a self-contained SVG animation instead of rendering in the terminal.
        #[arg(long)]
        html_output: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum TransportChoice {
    Adb,
    Qr,
}

impl Default for TransportChoice {
    fn default() -> Self {
        if cfg!(windows) { Self::Adb } else { Self::Qr }
    }
}

struct Handler;

impl PluginHandler for Handler {
    type RecipientV1 = PhoneRecipientPlugin;
    type IdentityV1 = PhoneIdentityPlugin;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Ok(PhoneRecipientPlugin::default())
    }

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(PhoneIdentityPlugin::default())
    }
}

fn main() -> io::Result<()> {
    let options = Options::parse();

    if let Some(state_machine) = options.age_plugin {
        return run_state_machine(&state_machine, Handler);
    }

    match options.command.unwrap_or(Command::Status) {
        Command::AdbCleanupGuard { serial } => run_cleanup_guard(&serial),
        Command::Status => {
            println!("status: common-transport-adb-alpha");
            println!("protocol_version: {PROTOCOL_VERSION}");
            println!("qr_capture_probe: available");
            println!("pairing_transport: adb_reverse_or_desktop_camera_qr");
            println!("unwrap_transport: adb_reverse_or_desktop_camera_qr");
            println!("ble_transport: not_implemented");
            println!("mobile_identity: android_strongbox_pairing");
            println!("age_recipient_v1: available");
            println!("age_identity_v1: available");
            Ok(())
        }
        Command::Pair {
            label,
            desktop_state,
            identity_output,
            replay_state,
            transport,
            adb_serial,
        } => run_pair(
            label,
            &desktop_state,
            &identity_output,
            &replay_state,
            transport,
            adb_serial.as_deref(),
        ),
        Command::Unwrap {
            identity_stub,
            desktop_state,
            replay_state,
            stanza_arg,
            stanza_body,
            caller_hint,
            transport,
            adb_serial,
        } => run_unwrap(
            &identity_stub,
            &desktop_state,
            &replay_state,
            stanza_arg,
            &stanza_body,
            caller_hint,
            transport,
            adb_serial.as_deref(),
        ),
        Command::QrCaptureProbe {
            label,
            cycles,
            html_output,
        } => run_qr_capture_probe(label, cycles, html_output),
    }
}

fn run_pair(
    label: String,
    desktop_state: &std::path::Path,
    identity_output: &std::path::Path,
    replay_state: &std::path::Path,
    transport: TransportChoice,
    adb_serial: Option<&str>,
) -> io::Result<()> {
    validate_transport_options(transport, adb_serial)?;
    ensure_pairing_outputs_available(identity_output, replay_state)?;
    let config_root = default_config_root()
        .map_err(|_| io::Error::other("phone plugin configuration is unavailable"))?;
    prepare_config_root(&config_root)
        .map_err(|_| io::Error::other("phone plugin configuration is unavailable"))?;
    #[cfg(windows)]
    {
        ensure_windows_private_state_path(&config_root, desktop_state)?;
        ensure_windows_private_state_path(&config_root, replay_state)?;
    }
    let state = DesktopKeyState::open_or_create(desktop_state, &mut OsRng)
        .map_err(|_| io::Error::other("desktop authentication state is unavailable"))?;
    let selection_public = state
        .selection_public_key()
        .map_err(|_| io::Error::other("desktop selection key is unavailable"))?;
    let mut session = DesktopPairingSession::begin(
        state.desktop_id,
        label,
        state.signer(),
        selection_public,
        0,
        &mut OsRng,
    )
    .map_err(|_| io::Error::other("failed to create pairing offer"))?;
    let started = Instant::now();
    let mut stdout = io::stdout().lock();
    let response = match transport {
        TransportChoice::Adb => {
            exchange_adb(SessionPurpose::Pairing, &session.signed_offer(), adb_serial)
        }
        TransportChoice::Qr => exchange_pairing_qr(&session.signed_offer(), started, &mut stdout),
    };
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            session.cancel();
            return Err(error);
        }
    };
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let display = session
        .receive_response(&response, elapsed_ms)
        .map_err(|_| {
            io::Error::new(io::ErrorKind::PermissionDenied, "pairing response rejected")
        })?;
    writeln!(
        stdout,
        "\x1b[2J\x1b[HCompare this full fingerprint with the phone:\n{}\n\nType the full fingerprint to confirm:",
        display.transcript_fingerprint,
    )?;
    stdout.flush()?;
    drop(stdout);
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let stub = session
        .confirm(confirmation.trim(), elapsed_ms)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "pairing not confirmed"))?;
    let pairing = age_plugin_phone_protocol::PairingRecord {
        desktop_id: stub.desktop_id,
        identity_id: stub.identity_id,
        desktop_signing_public_key: stub.desktop_signing_public_key,
        desktop_selection_public_key: stub.desktop_selection_public_key,
        phone_signing_public_key: stub.phone_signing_public_key,
    };
    FileReplayGuard::create(
        replay_state,
        ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing),
        DEFAULT_REPLAY_CAPACITY,
        now_unix().map_err(|_| io::Error::other("system clock is unavailable"))?,
    )
    .map_err(|_| io::Error::other("failed to create durable response replay state"))?;
    let locator_path = create_pairing_locator(&config_root, &stub, desktop_state, replay_state)
        .map_err(|_| io::Error::other("failed to create private pairing locator"))?;
    if create_identity_stub_file(identity_output, &stub).is_err() {
        let _ = std::fs::remove_file(locator_path);
        return Err(io::Error::other("failed to create public identity stub"));
    }
    print_pairing_outputs(identity_output, &stub)
}

#[cfg(windows)]
fn ensure_windows_private_state_path(
    root: &std::path::Path,
    path: &std::path::Path,
) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("private state path is unavailable"))?;
    let root = root
        .canonicalize()
        .map_err(|_| io::Error::other("private configuration root is unavailable"))?;
    let parent = parent
        .canonicalize()
        .map_err(|_| io::Error::other("private state parent is unavailable"))?;
    if !path.is_absolute() || parent != root || path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows private state must be directly under the selected private configuration root",
        ));
    }
    Ok(())
}

fn print_pairing_outputs(
    identity_output: &std::path::Path,
    stub: &age_plugin_phone::pairing::PublicIdentityStub,
) -> io::Result<()> {
    println!(
        "Public identity stub created: {}",
        identity_output.display()
    );
    println!(
        "Recipient: {}",
        stub.selectable_recipient()
            .map_err(|_| io::Error::other("failed to encode selectable recipient"))?
    );
    Ok(())
}

fn ensure_pairing_outputs_available(
    identity_output: &std::path::Path,
    replay_state: &std::path::Path,
) -> io::Result<()> {
    if identity_output.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "identity output already exists",
        ));
    }
    if replay_state.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "response replay state already exists",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_unwrap(
    identity_stub: &std::path::Path,
    desktop_state: &std::path::Path,
    replay_state: &std::path::Path,
    stanza_arg: String,
    stanza_body: &str,
    caller_hint: Option<String>,
    transport: TransportChoice,
    adb_serial: Option<&str>,
) -> io::Result<()> {
    validate_transport_options(transport, adb_serial)?;
    let stub = read_identity_stub_file(identity_stub)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid public identity stub"))?;
    let desktop = DesktopKeyState::open(desktop_state)
        .map_err(|_| io::Error::other("desktop authentication state is unavailable"))?;
    let body = STANDARD_NO_PAD
        .decode(stanza_body.trim())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed stanza body"))?;
    let now = now_unix().map_err(|_| io::Error::other("system clock is unavailable"))?;
    let mut session = DesktopUnwrapSession::begin(
        &stub,
        &desktop,
        TaggedStanza {
            tag: STANZA_TAG.to_owned(),
            args: vec![stanza_arg],
            body,
        },
        caller_hint,
        now,
        &mut OsRng,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "unwrap request rejected"))?;
    let started = Instant::now();
    let display = session.display();
    let mut stdout = io::stdout().lock();
    let response = match transport {
        TransportChoice::Adb => exchange_adb(
            SessionPurpose::Unwrap,
            &session.signed_request(),
            adb_serial,
        ),
        TransportChoice::Qr => {
            exchange_unwrap_qr(&session.signed_request(), &display, started, &mut stdout)
        }
    };
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            session.cancel();
            return Err(error);
        }
    };
    let pairing = age_plugin_phone_protocol::PairingRecord {
        desktop_id: stub.desktop_id,
        identity_id: stub.identity_id,
        desktop_signing_public_key: stub.desktop_signing_public_key,
        desktop_selection_public_key: stub.desktop_selection_public_key,
        phone_signing_public_key: stub.phone_signing_public_key,
    };
    let mut replay = FileReplayGuard::open(
        replay_state,
        ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing),
        DEFAULT_REPLAY_CAPACITY,
    )
    .map_err(|_| io::Error::other("durable response replay state is unavailable"))?;
    let file_key = session
        .receive_response(
            &response,
            &mut replay,
            now_unix().map_err(|_| io::Error::other("system clock is unavailable"))?,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "unwrap response rejected"))?;
    drop(file_key);
    writeln!(
        stdout,
        "\x1b[2J\x1b[HAuthenticated one-time unwrap completed."
    )?;
    Ok(())
}

fn validate_transport_options(
    transport: TransportChoice,
    adb_serial: Option<&str>,
) -> io::Result<()> {
    if transport == TransportChoice::Qr && adb_serial.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--adb-serial is valid only with --transport adb",
        ));
    }
    Ok(())
}

fn exchange_adb(
    purpose: SessionPurpose,
    request: &[u8],
    serial: Option<&str>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut transport = AdbReverseSession::connect(
        SystemAdb::default(),
        serial,
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_MESSAGE_TIMEOUT,
        TransportLimits::default(),
        &mut OsRng,
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    transport
        .exchange(purpose, request)
        .map_err(|_| io::Error::other("ADB transport session failed closed"))
}

fn exchange_pairing_qr(
    request: &[u8],
    started: Instant,
    output: &mut impl io::Write,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let frames = fragment_qr_message(request, 120, &mut OsRng)
        .map_err(|_| io::Error::other("failed to fragment pairing offer"))?;
    let mut scheduler = FrameScheduler::new(&frames, DEFAULT_FRAME_INTERVAL_MS)
        .map_err(|_| io::Error::other("failed to schedule pairing QR"))?;
    let scanner = ScannerHandle::start_default_camera(DEFAULT_SCAN_TIMEOUT);
    loop {
        match scanner.try_result() {
            Ok(Some(response)) => return Ok(response),
            Ok(None) => {}
            Err(_) => return Err(io::Error::other("desktop QR scanner is unavailable")),
        }
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if elapsed_ms > MAX_PAIRING_SESSION_AGE_MS {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "pairing timed out"));
        }
        let (index, frame) = scheduler
            .frame_at(elapsed_ms)
            .map_err(|_| io::Error::other("pairing QR clock failed"))?;
        let rendered = render_terminal_frame(frame)
            .map_err(|_| io::Error::other("failed to render pairing QR"))?;
        write!(
            output,
            "\x1b[2J\x1b[HPair phone · offer frame {}/{}\nWaiting for captured phone response…\n\n{rendered}",
            index + 1,
            frames.len(),
        )?;
        output.flush()?;
        thread::sleep(Duration::from_millis(DEFAULT_FRAME_INTERVAL_MS));
    }
}

fn exchange_unwrap_qr(
    request: &[u8],
    display: &age_plugin_phone::unwrap::UnwrapDisplay,
    started: Instant,
    output: &mut impl io::Write,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let frames = fragment_qr_message(request, 120, &mut OsRng)
        .map_err(|_| io::Error::other("failed to fragment unwrap request"))?;
    let mut scheduler = FrameScheduler::new(&frames, DEFAULT_FRAME_INTERVAL_MS)
        .map_err(|_| io::Error::other("failed to schedule unwrap QR"))?;
    let scanner = ScannerHandle::start_default_camera(DEFAULT_SCAN_TIMEOUT);
    loop {
        match scanner.try_result() {
            Ok(Some(response)) => return Ok(response),
            Ok(None) => {}
            Err(_) => return Err(io::Error::other("desktop QR scanner is unavailable")),
        }
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if now_unix().unwrap_or(u64::MAX) > display.expires_at_unix {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "unwrap timed out"));
        }
        let (index, frame) = scheduler
            .frame_at(elapsed_ms)
            .map_err(|_| io::Error::other("unwrap QR clock failed"))?;
        let rendered = render_terminal_frame(frame)
            .map_err(|_| io::Error::other("failed to render unwrap QR"))?;
        write!(
            output,
            "\x1b[2J\x1b[HApprove phone unwrap · request frame {}/{}\nRequest fingerprint: {}\nWaiting for captured phone response…\n\n{rendered}",
            index + 1,
            frames.len(),
            display.request_fingerprint,
        )?;
        output.flush()?;
        thread::sleep(Duration::from_millis(DEFAULT_FRAME_INTERVAL_MS));
    }
}

fn encoded_public_key(key: &SigningKey) -> io::Result<[u8; 33]> {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| io::Error::other("invalid desktop P-256 public key"))
}

fn run_qr_capture_probe(
    label: String,
    cycles: u16,
    html_output: Option<PathBuf>,
) -> io::Result<()> {
    if cycles == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QR capture probe needs at least one animation cycle",
        ));
    }
    let signing_key = SigningKey::random(&mut OsRng);
    let desktop_signing_public_key = encoded_public_key(&signing_key)?;
    let selection_key = SigningKey::random(&mut OsRng);
    let desktop_selection_public_key = encoded_public_key(&selection_key)?;
    let mut desktop_id = [0_u8; 16];
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut desktop_id);
    OsRng.fill_bytes(&mut nonce);
    let offer = SignedPairingOffer::sign(
        PairingOffer {
            desktop_id,
            desktop_label: label,
            desktop_signing_public_key,
            desktop_selection_public_key,
            nonce,
        },
        &signing_key,
    )
    .map_err(|_| io::Error::other("failed to create disposable signed pairing offer"))?;
    let digest = offer.digest();
    let frames = fragment_qr_message(&offer.encode(), 80, &mut OsRng)
        .map_err(|_| io::Error::other("failed to fragment disposable pairing offer"))?;
    let mut scheduler = FrameScheduler::new(&frames, DEFAULT_FRAME_INTERVAL_MS)
        .map_err(|_| io::Error::other("failed to schedule QR animation"))?;
    let frame_count =
        u64::try_from(frames.len()).map_err(|_| io::Error::other("invalid QR frame count"))?;
    let ticks = frame_count
        .checked_mul(u64::from(cycles))
        .ok_or_else(|| io::Error::other("QR animation is too long"))?;
    let digest_hex = hex(&digest);
    if let Some(path) = html_output {
        let html = render_offline_html(&frames, &digest)
            .map_err(|_| io::Error::other("failed to render offline QR animation"))?;
        std::fs::write(&path, html)?;
        println!("QR capture probe written: {}", path.display());
        println!("offer_digest: {digest_hex}");
        return Ok(());
    }
    let mut stdout = io::stdout().lock();

    for tick in 0..ticks {
        let now_ms = tick
            .checked_mul(DEFAULT_FRAME_INTERVAL_MS)
            .ok_or_else(|| io::Error::other("QR animation clock overflow"))?;
        let (index, frame) = scheduler
            .frame_at(now_ms)
            .map_err(|_| io::Error::other("QR animation clock failed"))?;
        let rendered = render_terminal_frame(frame)
            .map_err(|_| io::Error::other("failed to render QR frame"))?;
        write!(
            stdout,
            "\x1b[2J\x1b[HQR capture probe · frame {}/{}\nOffer digest: {digest_hex}\n\n{rendered}",
            index + 1,
            frames.len(),
        )?;
        stdout.flush()?;
        thread::sleep(Duration::from_millis(DEFAULT_FRAME_INTERVAL_MS));
    }
    writeln!(stdout, "\x1b[2J\x1b[HQR capture probe finished.")?;
    stdout.flush()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        },
    )
}
