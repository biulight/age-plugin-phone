use std::{
    io::{self, Write as _},
    net::SocketAddr,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use age_plugin::{PluginHandler, run_state_machine};
#[cfg(any(windows, target_os = "macos"))]
use age_plugin_phone::adb::preflight_device;
use age_plugin_phone::adb::{
    AdbReverseSession, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MESSAGE_TIMEOUT, SystemAdb,
    run_cleanup_guard,
};
use age_plugin_phone::age_identity::PhoneIdentityPlugin;
use age_plugin_phone::age_recipient::PhoneRecipientPlugin;
#[cfg(not(target_os = "macos"))]
use age_plugin_phone::locator::create_pairing_locator_with_transport;
use age_plugin_phone::locator::{default_config_root, prepare_config_root};
use age_plugin_phone::pairing::RecipientType;
use age_plugin_phone::pairing::{
    DesktopKeyState, DesktopPairingSession, MAX_PAIRING_SESSION_AGE_MS, read_identity_stub_file,
};
use age_plugin_phone::qr_scanner::{DEFAULT_SCAN_TIMEOUT, ScannerHandle};
use age_plugin_phone::qr_terminal::{
    DEFAULT_FRAME_INTERVAL_MS, FrameScheduler, render_offline_html, render_terminal_frame,
};
use age_plugin_phone::setup;
#[cfg(any(windows, target_os = "macos"))]
use age_plugin_phone::setup::{SetupJournal, SetupStage};
use age_plugin_phone::transport::{DesktopTransport, SessionPurpose, TransportLimits};
use age_plugin_phone::transport_policy::{
    TransportChoice, TransportHints, TransportKind, TransportOperation, TransportRoute,
    resolve_transport,
};
use age_plugin_phone::unwrap::{DesktopUnwrapSession, now_unix};
use age_plugin_phone::wifi::{
    DEFAULT_DISCOVERY_TIMEOUT, WIFI_UNWRAP_PORT, WifiError, WifiSession, discover_pairing_endpoint,
    discover_unwrap_endpoint,
};
use age_plugin_phone_core::protocol::{
    DEFAULT_REPLAY_CAPACITY, FileReplayGuard, PROTOCOL_VERSION, PairingOffer, ReplayRole,
    ReplayScope, SignedPairingOffer, fragment_qr_message,
};
use age_plugin_phone_core::recipient::{STANZA_TAG, TaggedStanza};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use clap::{Parser, Subcommand};
use p256::ecdsa::SigningKey;
use rand_core::{OsRng, RngCore as _};
#[cfg(any(windows, target_os = "macos", test))]
use serde::Serialize;
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
    /// Report implementation status and read-only platform capabilities.
    Status,
    /// Diagnose one bounded Wi-Fi discovery window without pairing or requesting an unwrap.
    WifiDoctor {
        /// Check authenticated discovery for this public stub; omit for explicit phone pairing mode.
        #[arg(long)]
        identity_stub: Option<PathBuf>,
    },
    /// Create one phone-backed identity using managed hardware desktop paths.
    Setup {
        /// phone: plugin required, private selection (default); tag: age 1.3+, public testable tag, no encryption plugin.
        #[arg(long, default_value_t = RecipientType::Phone)]
        recipient_type: RecipientType,
        /// Untrusted desktop label shown on both endpoints.
        #[arg(
            long,
            required_unless_present_any = ["resume", "cleanup"],
            conflicts_with_all = ["resume", "cleanup"]
        )]
        label: Option<String>,
        /// Resume the exact locally confirmed setup recorded in the setup journal.
        #[arg(
            long,
            conflicts_with_all = ["cleanup", "label", "transport", "adb_serial"]
        )]
        resume: bool,
        /// Remove the exact incomplete setup recorded in the setup journal.
        #[arg(
            long,
            conflicts_with_all = ["resume", "label", "transport", "adb_serial"]
        )]
        cleanup: bool,
        /// Bidirectional message transport: auto, adb, ble, wifi, or qr.
        #[arg(long, default_value_t = TransportChoice::default())]
        transport: TransportChoice,
        /// Explicit ADB device serial. Required when multiple devices are listed by ADB.
        #[arg(long)]
        adb_serial: Option<String>,
        /// Emit one versioned public setup result as JSON on stdout.
        #[arg(long, conflicts_with = "cleanup")]
        json: bool,
    },
    /// Complete an authenticated pairing over Developer USB or QR.
    Pair {
        /// phone: plugin required, private selection (default); tag: age 1.3+, public testable tag, no encryption plugin.
        #[arg(long, default_value_t = RecipientType::Phone)]
        recipient_type: RecipientType,
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
        /// Bidirectional message transport: auto, adb, ble, wifi, or qr.
        #[arg(long, default_value_t = TransportChoice::default())]
        transport: TransportChoice,
        /// Explicit ADB device serial. Required when multiple devices are listed by ADB.
        #[arg(long)]
        adb_serial: Option<String>,
    },
    /// Export one public recipient without private state or phone access.
    Recipients {
        #[arg(short = 'i', long = "identity")]
        identity_stub: PathBuf,
        /// phone: plugin required, private selection (default); tag: age 1.3+, public testable tag, no encryption plugin.
        #[arg(long, default_value_t = RecipientType::Phone)]
        recipient_type: RecipientType,
    },
    /// Exercise one real paired unwrap over Developer USB, foreground Wi-Fi, or QR.
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
        /// Bidirectional message transport: auto, adb, ble, wifi, or qr.
        #[arg(long, default_value_t = TransportChoice::default())]
        transport: TransportChoice,
        /// Explicit ADB device serial. Required when multiple devices are listed by ADB.
        #[arg(long)]
        adb_serial: Option<String>,
        /// Explicit private IPv4 phone endpoint for the foreground Wi-Fi proof of concept.
        #[arg(long)]
        wifi_address: Option<SocketAddr>,
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
    /// Remove one revoked pairing's exact private hardware desktop state.
    RemoveDesktopState {
        /// Public identity stub for the exact pairing to remove.
        #[arg(long)]
        identity_stub: PathBuf,
    },
    /// Remove orphaned private hardware desktop state when its public stub is unavailable.
    RemoveOrphanedDesktopState {
        /// Canonical private locator in the age-plugin-phone configuration root.
        #[arg(long)]
        locator: PathBuf,
    },
}

struct Handler;

impl PluginHandler for Handler {
    type RecipientV1 = PhoneRecipientPlugin;
    type IdentityV1 = PhoneIdentityPlugin;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Ok(PhoneRecipientPlugin::default())
    }

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        ensure_desktop_platform_supported()?;
        Ok(PhoneIdentityPlugin::default())
    }
}

#[allow(clippy::too_many_lines)]
fn main() -> io::Result<()> {
    let options = Options::parse();

    if let Some(state_machine) = options.age_plugin {
        return run_state_machine(&state_machine, Handler);
    }

    match options.command.unwrap_or(Command::Status) {
        Command::AdbCleanupGuard { serial } => run_cleanup_guard(&serial),
        Command::WifiDoctor { identity_stub } => run_wifi_doctor(identity_stub.as_deref()),
        Command::Status => {
            println!("status: common-transport-adb-alpha");
            println!("protocol_version: {PROTOCOL_VERSION}");
            #[cfg(not(target_os = "macos"))]
            println!("qr_capture_probe: available");
            println!("pairing_transport: adb_reverse_or_foreground_wifi_or_desktop_camera_qr");
            println!("unwrap_transport: adb_reverse_or_foreground_wifi_or_desktop_camera_qr");
            println!("transport_policy: wifi_discovery_then_explicit_single_route");
            println!(
                "wifi_transport: foreground_discovery_port_47141_stream_port_{WIFI_UNWRAP_PORT}"
            );
            println!("ble_transport: not_implemented");
            println!("mobile_identity: android_strongbox_or_ios_secure_enclave");
            println!("age_recipient_v1: available");
            println!(
                "tagged_recipient: p256tag; encryption requires age 1.3+; public testable tag; phone remains default"
            );
            println!(
                "age_identity_v1: implemented_requires_paired_hardware_and_fresh_phone_verification"
            );
            #[cfg(windows)]
            print_windows_platform_status();
            #[cfg(target_os = "macos")]
            print_macos_platform_status();
            Ok(())
        }
        Command::Recipients {
            identity_stub,
            recipient_type,
        } => {
            let stub = read_identity_stub_file(&identity_stub)
                .map_err(|_| io::Error::other("invalid public identity stub"))?;
            let recipient = stub
                .recipient_for(recipient_type)
                .map_err(|_| io::Error::other("invalid recipient"))?;
            println!("{recipient}");
            Ok(())
        }
        Command::Setup {
            recipient_type,
            label,
            resume,
            cleanup,
            transport,
            adb_serial,
            json,
        } => run_setup(
            label,
            resume,
            cleanup,
            transport,
            adb_serial.as_deref(),
            json,
            recipient_type,
        ),
        Command::Pair {
            recipient_type,
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
            recipient_type,
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
            wifi_address,
        } => run_unwrap(
            &identity_stub,
            &desktop_state,
            &replay_state,
            stanza_arg,
            &stanza_body,
            caller_hint,
            transport,
            adb_serial.as_deref(),
            wifi_address,
        ),
        Command::QrCaptureProbe {
            label,
            cycles,
            html_output,
        } => run_qr_capture_probe(label, cycles, html_output),
        Command::RemoveDesktopState { identity_stub } => run_remove_desktop_state(&identity_stub),
        Command::RemoveOrphanedDesktopState { locator } => {
            run_remove_orphaned_desktop_state(&locator)
        }
    }
}

fn run_remove_desktop_state(identity_stub: &std::path::Path) -> io::Result<()> {
    let fingerprint = age_plugin_phone::desktop_cleanup::confirmation_fingerprint(identity_stub)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "Remove private desktop state only after revoking this pairing on the phone.\nIf the phone is lost, local removal does not claim phone-side revocation.\nFull transcript fingerprint: {fingerprint}\nType the full fingerprint to remove this exact pairing:"
    )?;
    stdout.flush()?;
    drop(stdout);
    let mut entered = String::new();
    io::stdin().read_line(&mut entered)?;
    age_plugin_phone::desktop_cleanup::remove_desktop_state(identity_stub, entered.trim_end())
        .map_err(|error| {
            io::Error::new(
                if matches!(
                    error,
                    age_plugin_phone::desktop_cleanup::CleanupError::ConfirmationMismatch
                ) {
                    io::ErrorKind::PermissionDenied
                } else {
                    io::ErrorKind::Other
                },
                error.to_string(),
            )
        })?;
    println!("Private desktop state removed. Phone-side revocation is a separate operation.");
    Ok(())
}

fn run_remove_orphaned_desktop_state(locator: &std::path::Path) -> io::Result<()> {
    let fingerprint = age_plugin_phone::desktop_cleanup::orphan_confirmation_fingerprint(locator)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "Remove orphaned private desktop state only after revoking its pairing on the phone.\n\
         This command does not discover or remove public identity stubs.\n\
         Full transcript fingerprint: {fingerprint}\n\
         Type the full fingerprint to remove this exact orphaned pairing:"
    )?;
    stdout.flush()?;
    drop(stdout);
    let mut entered = String::new();
    io::stdin().read_line(&mut entered)?;
    age_plugin_phone::desktop_cleanup::remove_orphaned_desktop_state(locator, entered.trim_end())
        .map_err(|error| {
        io::Error::new(
            if matches!(
                error,
                age_plugin_phone::desktop_cleanup::CleanupError::ConfirmationMismatch
            ) {
                io::ErrorKind::PermissionDenied
            } else {
                io::ErrorKind::Other
            },
            error.to_string(),
        )
    })?;
    println!(
        "Orphaned private desktop state removed. Public stubs and phone-side revocation are separate operations."
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_pair(
    label: String,
    desktop_state: &std::path::Path,
    identity_output: &std::path::Path,
    replay_state: &std::path::Path,
    transport: TransportChoice,
    adb_serial: Option<&str>,
    recipient_type: RecipientType,
) -> io::Result<()> {
    run_setup_impl(
        Some(label),
        false,
        false,
        transport,
        adb_serial,
        false,
        Some([desktop_state, replay_state, identity_output]),
        recipient_type,
    )
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::too_many_lines)]
fn run_pair(
    label: String,
    desktop_state: &std::path::Path,
    identity_output: &std::path::Path,
    replay_state: &std::path::Path,
    transport: TransportChoice,
    adb_serial: Option<&str>,
    recipient_type: RecipientType,
) -> io::Result<()> {
    validate_setup_label(&label)?;
    ensure_desktop_platform_supported()?;
    ensure_pairing_outputs_available(identity_output, replay_state)?;
    // Reopening existing state is read-only. A new identity is selected for discovery before
    // any configuration directory, journal, replay file or hardware role is created.
    let desktop_state_existed = desktop_state.exists();
    #[cfg(target_os = "macos")]
    if desktop_state_existed {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "macOS explicit pair requires unused desktop state; existing or partial state must not be reused for another pairing",
        ));
    }
    if desktop_state == replay_state
        || desktop_state == identity_output
        || replay_state == identity_output
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pairing output paths must be distinct",
        ));
    }
    #[cfg(any(windows, target_os = "macos"))]
    let existing = if desktop_state_existed {
        Some(
            DesktopKeyState::open(desktop_state)
                .map_err(|_| io::Error::other("desktop authentication state is unavailable"))?,
        )
    } else {
        None
    };
    #[cfg(not(any(windows, target_os = "macos")))]
    let existing = Some(
        DesktopKeyState::open_or_create(desktop_state, &mut OsRng)
            .map_err(|_| io::Error::other("desktop authentication state is unavailable"))?,
    );
    let desktop_id = existing.as_ref().map_or_else(
        || {
            let mut id = [0_u8; 16];
            OsRng.fill_bytes(&mut id);
            id
        },
        |state| state.desktop_id,
    );
    let wifi_address = discover_pairing_wifi(desktop_id, transport, adb_serial)?;
    let route = resolve_transport(
        transport,
        TransportOperation::Pairing,
        TransportHints {
            adb_serial: adb_serial.map(str::to_owned),
            wifi_address,
        },
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    #[cfg(any(windows, target_os = "macos"))]
    let prepared_transport = prepare_pairing_transport(&route)?;
    let config_root = prepare_pairing_config_root()?;
    #[cfg(target_os = "macos")]
    let _lifecycle_lock = acquire_explicit_pair_lock(&config_root)?;
    #[cfg(any(windows, target_os = "macos"))]
    {
        ensure_managed_private_state_path(&config_root, desktop_state)?;
        ensure_managed_private_state_path(&config_root, replay_state)?;
    }
    #[cfg(any(windows, target_os = "macos"))]
    let state = match existing {
        Some(state) => state,
        None => DesktopKeyState::create_new(desktop_state, desktop_id).map_err(|_| {
            io::Error::other(
                "desktop authentication state is unavailable; partial state must be retained",
            )
        })?,
    };
    #[cfg(not(any(windows, target_os = "macos")))]
    let Some(state) = existing else {
        unreachable!("experimental software state is already open")
    };
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
    #[cfg(any(windows, target_os = "macos"))]
    let response = prepared_transport.exchange(&session.signed_offer(), started, &mut stdout);
    #[cfg(not(any(windows, target_os = "macos")))]
    let response = exchange_pairing_route(&route, &session.signed_offer(), started, &mut stdout);
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            session.cancel();
            drop(session);
            drop(state);
            if !rollback_failed_pairing(
                desktop_state,
                replay_state,
                None,
                !desktop_state_existed,
                desktop_id,
            ) {
                return Err(io::Error::other(
                    "pairing transport failed and local rollback is incomplete",
                ));
            }
            return Err(error);
        }
    };
    let stub =
        complete_pairing_interaction(&mut session, &response, started, &mut stdout, |_| Ok(()))?;
    drop(stdout);
    drop(session);
    drop(state);
    commit_pairing_state(
        &config_root,
        &stub,
        desktop_state,
        identity_output,
        replay_state,
        !desktop_state_existed,
        transport,
        recipient_type,
    )?;
    print_pairing_outputs(identity_output, &stub, recipient_type)
}

#[cfg(not(target_os = "macos"))]
fn prepare_pairing_config_root() -> io::Result<PathBuf> {
    let config_root = default_config_root()
        .map_err(|_| io::Error::other("phone plugin configuration is unavailable"))?;
    prepare_config_root(&config_root)
        .map_err(|_| io::Error::other("phone plugin configuration is unavailable"))?;
    ensure_no_setup_pending_for_pair(&config_root)?;
    Ok(config_root)
}

#[cfg(not(target_os = "macos"))]
fn discover_pairing_wifi(
    desktop_id: [u8; 16],
    transport: TransportChoice,
    adb_serial: Option<&str>,
) -> io::Result<Option<SocketAddr>> {
    if adb_serial.is_some() || !matches!(transport, TransportChoice::Auto | TransportChoice::Wifi) {
        return Ok(None);
    }
    match discover_pairing_endpoint(desktop_id, DEFAULT_DISCOVERY_TIMEOUT, &mut OsRng) {
        Ok(address) => Ok(Some(address)),
        Err(WifiError::DiscoveryUnavailable) if transport == TransportChoice::Auto => Ok(None),
        Err(error) => Err(io::Error::other(error.to_string())),
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn exchange_pairing_route(
    route: &TransportRoute,
    offer: &[u8],
    started: Instant,
    output: &mut impl io::Write,
) -> io::Result<Zeroizing<Vec<u8>>> {
    match route.kind() {
        TransportKind::Adb => exchange_adb(SessionPurpose::Pairing, offer, route.adb_serial()),
        TransportKind::Qr => exchange_pairing_qr(offer, started, output),
        TransportKind::Wifi => exchange_wifi(
            SessionPurpose::Pairing,
            offer,
            route
                .wifi_address()
                .expect("validated Wi-Fi pairing endpoint"),
        ),
        TransportKind::Ble => {
            unreachable!("unsupported pairing transports are rejected before session creation")
        }
    }
}

#[cfg(windows)]
fn ensure_managed_private_state_path(
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
            "Hardware desktop private state must be directly under the selected private configuration root",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn ensure_no_setup_pending_for_pair(config_root: &std::path::Path) -> io::Result<()> {
    if setup::read_optional(config_root)
        .map_err(|_| io::Error::other("desktop setup recovery state is unavailable"))?
        .is_some()
    {
        return Err(io::Error::other(
            "an incomplete managed setup must be resumed or cleaned before explicit pairing",
        ));
    }
    Ok(())
}

fn validate_setup_label(label: &str) -> io::Result<()> {
    if label.len() > 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "desktop label must be at most 64 UTF-8 bytes",
        ));
    }
    Ok(())
}

fn complete_pairing_interaction(
    session: &mut DesktopPairingSession,
    response: &[u8],
    started: Instant,
    output: &mut impl io::Write,
    mut on_verified: impl FnMut(&age_plugin_phone::pairing::PublicIdentityStub) -> io::Result<()>,
) -> io::Result<age_plugin_phone::pairing::PublicIdentityStub> {
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let display = session
        .receive_response(response, elapsed_ms)
        .map_err(|_| {
            io::Error::new(io::ErrorKind::PermissionDenied, "pairing response rejected")
        })?;
    let candidate = session
        .pending_stub()
        .map_err(|_| io::Error::other("verified pairing candidate is unavailable"))?;
    on_verified(&candidate)?;

    writeln!(
        output,
        "\x1b[2J\x1b[HCompare this full fingerprint with the phone:\n{}\n\nType the full fingerprint to confirm:",
        display.transcript_fingerprint,
    )?;
    output.flush()?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    session
        .confirm(confirmation.trim(), elapsed_ms)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "pairing not confirmed"))
}

#[cfg(not(target_os = "macos"))]
fn print_pairing_outputs(
    identity_output: &std::path::Path,
    stub: &age_plugin_phone::pairing::PublicIdentityStub,
    recipient_type: RecipientType,
) -> io::Result<()> {
    println!(
        "Public identity stub created: {}",
        identity_output.display()
    );
    println!(
        "Recipient: {}",
        stub.recipient_for(recipient_type)
            .map_err(|_| io::Error::other("failed to encode selectable recipient"))?
    );
    Ok(())
}

#[cfg(any(windows, target_os = "macos"))]
enum PreparedSetupTransport {
    Adb(String),
    Wifi(SocketAddr),
    Qr(ScannerHandle),
}

#[cfg(any(windows, target_os = "macos"))]
fn prepare_pairing_transport(route: &TransportRoute) -> io::Result<PreparedSetupTransport> {
    Ok(match route.kind() {
        TransportKind::Adb => {
            let mut adb = SystemAdb::default();
            let serial = preflight_device(&mut adb, route.adb_serial()).map_err(|error| {
                let message = if matches!(
                    error,
                    age_plugin_phone::adb::AdbError::DeviceSelectionRequired
                ) {
                    "multiple Android devices require --adb-serial SERIAL; no pairing state was created"
                        .to_owned()
                } else {
                    format!("Developer USB preflight failed: {error}; no pairing state was created")
                };
                io::Error::other(message)
            })?;
            PreparedSetupTransport::Adb(serial)
        }
        TransportKind::Qr => PreparedSetupTransport::Qr(
            ScannerHandle::start_default_camera_checked(DEFAULT_SCAN_TIMEOUT).map_err(|error| {
                io::Error::other(format!(
                    "QR camera preflight failed: {error}; no pairing state was created"
                ))
            })?,
        ),
        TransportKind::Wifi => PreparedSetupTransport::Wifi(
            route
                .wifi_address()
                .expect("validated Wi-Fi pairing endpoint"),
        ),
        TransportKind::Ble => {
            unreachable!("unsupported setup transports are rejected by policy")
        }
    })
}

#[cfg(any(windows, target_os = "macos"))]
impl PreparedSetupTransport {
    fn exchange(
        self,
        offer: &[u8],
        started: Instant,
        output: &mut impl io::Write,
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        match self {
            PreparedSetupTransport::Adb(serial) => {
                exchange_adb(SessionPurpose::Pairing, offer, Some(&serial))
            }
            PreparedSetupTransport::Wifi(endpoint) => {
                exchange_wifi(SessionPurpose::Pairing, offer, endpoint)
            }
            PreparedSetupTransport::Qr(scanner) => {
                exchange_pairing_qr_with_scanner(offer, started, output, &scanner)
            }
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn run_setup(
    label: Option<String>,
    resume: bool,
    cleanup: bool,
    transport: TransportChoice,
    adb_serial: Option<&str>,
    json: bool,
    recipient_type: RecipientType,
) -> io::Result<()> {
    run_setup_impl(
        label,
        resume,
        cleanup,
        transport,
        adb_serial,
        json,
        None,
        recipient_type,
    )
}

#[cfg(any(windows, target_os = "macos"))]
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn run_setup_impl(
    label: Option<String>,
    resume: bool,
    cleanup: bool,
    transport: TransportChoice,
    adb_serial: Option<&str>,
    json: bool,
    explicit_paths: Option<[&std::path::Path; 3]>,
    recipient_type: RecipientType,
) -> io::Result<()> {
    if resume || cleanup {
        if label.is_some() || transport != TransportChoice::Auto || adb_serial.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "setup recovery modes do not accept label or transport options",
            ));
        }
        ensure_desktop_platform_supported()?;
        return if resume {
            resume_setup(json, recipient_type)
        } else {
            cleanup_setup()
        };
    }

    let label = label
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "new setup requires --label"))?;
    validate_setup_label(&label)?;
    ensure_desktop_platform_supported()?;
    let mut desktop_id = [0_u8; 16];
    OsRng.fill_bytes(&mut desktop_id);
    let mut wifi_address = None;
    if adb_serial.is_none() && matches!(transport, TransportChoice::Auto | TransportChoice::Wifi) {
        match discover_pairing_endpoint(desktop_id, DEFAULT_DISCOVERY_TIMEOUT, &mut OsRng) {
            Ok(discovered) => wifi_address = Some(discovered),
            Err(WifiError::DiscoveryUnavailable) if transport == TransportChoice::Auto => {}
            Err(error) => {
                return Err(io::Error::other(format!(
                    "Wi-Fi pairing discovery failed: {error}; no setup state was created"
                )));
            }
        }
    }
    let route = resolve_transport(
        transport,
        TransportOperation::Pairing,
        TransportHints {
            adb_serial: adb_serial.map(str::to_owned),
            wifi_address,
        },
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    ensure_desktop_platform_supported()?;
    let prepared_transport = prepare_pairing_transport(&route)?;

    let root = default_config_root()
        .map_err(|_| io::Error::other("phone plugin configuration is unavailable"))?;
    prepare_config_root(&root)
        .map_err(|_| io::Error::other("phone plugin configuration is unavailable"))?;
    let _lifecycle_lock = setup::acquire_lifecycle_lock(&root)
        .map_err(|error| io::Error::other(error.to_string()))?;
    setup::ensure_no_cleanup_pending(&root).map_err(|error| io::Error::other(error.to_string()))?;
    if setup::read_optional(&root)
        .map_err(|error| io::Error::other(error.to_string()))?
        .is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "an incomplete setup exists; use setup --resume or setup --cleanup",
        ));
    }

    let mut setup_code = [0_u8; 16];
    OsRng.fill_bytes(&mut setup_code);
    let mut journal = if let Some(paths) = explicit_paths {
        SetupJournal::new_explicit(&root, setup_code, desktop_id, paths, transport).map_err(
            |_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "explicit pairing paths are invalid or overlap reserved state",
                )
            },
        )?
    } else {
        SetupJournal::new_with_transport(&root, setup_code, desktop_id, transport)
    };
    if [
        &journal.desktop_state,
        &journal.replay_state,
        &journal.identity_stub,
    ]
    .into_iter()
    .any(|path| path.exists())
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "pairing output already exists; no existing state was modified",
        ));
    }
    setup::create(&root, &journal).map_err(|error| io::Error::other(error.to_string()))?;

    let Ok(state) = DesktopKeyState::create_new(&journal.desktop_state, desktop_id) else {
        return rollback_setup_error(
            &root,
            &journal,
            "failed to create new hardware desktop state; no existing key was reused",
            false,
        );
    };
    journal.set_pairing();
    if let Err(error) = setup::replace(&root, &journal) {
        drop(state);
        return rollback_setup_error(&root, &journal, &error.to_string(), false);
    }

    let Ok(selection_public) = state.selection_public_key() else {
        drop(state);
        return rollback_setup_error(
            &root,
            &journal,
            "desktop selection key is unavailable",
            false,
        );
    };
    let Ok(mut session) = DesktopPairingSession::begin(
        state.desktop_id,
        label,
        state.signer(),
        selection_public,
        0,
        &mut OsRng,
    ) else {
        drop(state);
        return rollback_setup_error(&root, &journal, "failed to create pairing offer", false);
    };
    let started = Instant::now();
    let mut interaction: Box<dyn io::Write> = if json {
        Box::new(io::stderr())
    } else {
        Box::new(io::stdout())
    };
    let response = prepared_transport.exchange(&session.signed_offer(), started, &mut interaction);
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            session.cancel();
            drop(session);
            drop(state);
            return rollback_setup_error(&root, &journal, &error.to_string(), false);
        }
    };
    let stub = match complete_pairing_interaction(
        &mut session,
        &response,
        started,
        &mut interaction,
        |candidate| {
            journal
                .set_candidate(candidate.clone())
                .map_err(|_| io::Error::other("verified pairing candidate is invalid"))?;
            setup::replace(&root, &journal)
                .map_err(|_| io::Error::other("failed to journal the verified phone response"))
        },
    ) {
        Ok(stub) => stub,
        Err(error) => {
            drop(session);
            drop(state);
            return rollback_setup_error(&root, &journal, &error.to_string(), true);
        }
    };
    if journal.set_confirmed(&stub).is_err() || setup::replace(&root, &journal).is_err() {
        drop(session);
        drop(state);
        return rollback_setup_error(&root, &journal, "failed to journal confirmed setup", true);
    }
    drop(session);
    drop(state);
    setup::commit_confirmed_for(
        &root,
        &journal,
        now_unix().map_err(|_| io::Error::other("system clock is unavailable"))?,
        recipient_type,
    )
    .map_err(|_| {
        io::Error::other(
            "confirmed setup commit is incomplete; use setup --resume or setup --cleanup",
        )
    })?;
    print_setup_outputs(
        &journal.identity_stub,
        &stub,
        json,
        recipient_type,
        &mut interaction,
    )
}

#[cfg(not(any(windows, target_os = "macos")))]
fn run_setup(
    _label: Option<String>,
    _resume: bool,
    _cleanup: bool,
    _transport: TransportChoice,
    _adb_serial: Option<&str>,
    _json: bool,
    _recipient_type: RecipientType,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "simplified setup requires a supported Windows or macOS hardware desktop; use explicit pair for diagnostics",
    ))
}

#[cfg(any(windows, target_os = "macos"))]
fn resume_setup(json: bool, recipient_type: RecipientType) -> io::Result<()> {
    let root = default_config_root()
        .map_err(|_| io::Error::other("phone plugin configuration is unavailable"))?;
    let _lifecycle_lock = setup::acquire_lifecycle_lock(&root)
        .map_err(|error| io::Error::other(error.to_string()))?;
    setup::ensure_no_cleanup_pending(&root).map_err(|error| io::Error::other(error.to_string()))?;
    let journal = setup::read(&root).map_err(|error| io::Error::other(error.to_string()))?;
    if journal.stage != SetupStage::Confirmed {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "this setup was not fully confirmed and may only be removed with setup --cleanup",
        ));
    }
    let fingerprint = journal.confirmation_text();
    let mut interaction: Box<dyn io::Write> = if json {
        Box::new(io::stderr())
    } else {
        Box::new(io::stdout())
    };
    writeln!(
        interaction,
        "Resume only this confirmed setup.\nFull transcript fingerprint: {fingerprint}\nType the full fingerprint to continue:"
    )?;
    interaction.flush()?;
    let mut entered = String::new();
    io::stdin().read_line(&mut entered)?;
    if entered.trim_end() != fingerprint {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "setup resume confirmation did not match",
        ));
    }
    setup::commit_confirmed_for(
        &root,
        &journal,
        now_unix().map_err(|_| io::Error::other("system clock is unavailable"))?,
        recipient_type,
    )
    .map_err(|_| io::Error::other("confirmed setup remains incomplete"))?;
    print_setup_outputs(
        &journal.identity_stub,
        journal
            .candidate
            .as_ref()
            .expect("confirmed journal candidate"),
        json,
        recipient_type,
        &mut interaction,
    )
}

#[cfg(any(windows, target_os = "macos"))]
fn cleanup_setup() -> io::Result<()> {
    let root = default_config_root()
        .map_err(|_| io::Error::other("phone plugin configuration is unavailable"))?;
    let _lifecycle_lock = setup::acquire_lifecycle_lock(&root)
        .map_err(|error| io::Error::other(error.to_string()))?;
    setup::ensure_no_cleanup_pending(&root).map_err(|error| io::Error::other(error.to_string()))?;
    let journal = setup::read(&root).map_err(|error| io::Error::other(error.to_string()))?;
    let confirmation = journal.confirmation_text();
    println!(
        "Remove only the incomplete setup recorded by the private journal.\nConfirmation: {confirmation}\nType the complete value to remove it:"
    );
    let mut entered = String::new();
    io::stdin().read_line(&mut entered)?;
    if entered.trim_end() != confirmation {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "setup cleanup confirmation did not match",
        ));
    }
    let phone_may_be_paired =
        journal.candidate.is_some() || journal.stage != SetupStage::Provisioning;
    setup::cleanup_owned(&root, &journal)
        .map_err(|_| io::Error::other("incomplete setup cleanup remains pending"))?;
    if phone_may_be_paired {
        println!(
            "Incomplete desktop setup removed. Revoke the matching full fingerprint on the phone; local cleanup is not phone-side revocation."
        );
    } else {
        println!("Incomplete desktop setup removed.");
    }
    Ok(())
}

#[cfg(windows)]
fn rollback_setup_error(
    root: &std::path::Path,
    journal: &SetupJournal,
    message: &str,
    phone_may_be_paired: bool,
) -> io::Result<()> {
    match setup::cleanup_owned(root, journal) {
        Ok(()) => {
            let suffix = if phone_may_be_paired {
                "; local state was removed, but the matching phone pairing must be revoked"
            } else {
                "; local setup state was removed"
            };
            Err(io::Error::other(format!("{message}{suffix}")))
        }
        Err(_) => Err(io::Error::other(format!(
            "{message}; rollback is incomplete, use setup --cleanup"
        ))),
    }
}

#[cfg(target_os = "macos")]
fn rollback_setup_error(
    _root: &std::path::Path,
    _journal: &SetupJournal,
    message: &str,
    phone_may_be_paired: bool,
) -> io::Result<()> {
    let revocation = if phone_may_be_paired {
        "; revoke the matching full fingerprint on the phone if it was committed there"
    } else {
        ""
    };
    Err(io::Error::other(format!(
        "{message}; setup state was retained; use setup --cleanup{revocation}"
    )))
}

#[cfg(any(windows, target_os = "macos", test))]
#[derive(Serialize)]
struct SetupResult<'a> {
    schema_version: u16,
    identity_path: &'a std::path::Path,
    recipient: &'a str,
}

#[cfg(any(windows, target_os = "macos", test))]
fn write_setup_result_json(
    mut output: impl io::Write,
    identity_path: &std::path::Path,
    recipient: &str,
) -> io::Result<()> {
    serde_json::to_writer(
        &mut output,
        &SetupResult {
            schema_version: 1,
            identity_path,
            recipient,
        },
    )
    .map_err(|_| io::Error::other("failed to encode public setup result"))?;
    writeln!(output)
}

#[cfg(any(windows, target_os = "macos"))]
fn print_setup_outputs(
    identity_output: &std::path::Path,
    stub: &age_plugin_phone::pairing::PublicIdentityStub,
    json: bool,
    recipient_type: RecipientType,
    interaction: &mut impl io::Write,
) -> io::Result<()> {
    let recipient = stub
        .recipient_for(recipient_type)
        .map_err(|_| io::Error::other("failed to encode selectable recipient"))?;
    if json {
        writeln!(
            interaction,
            "Pairing success is not a recovery drill. Retained data also needs an independently verified recovery recipient."
        )?;
        interaction.flush()?;
        write_setup_result_json(io::stdout().lock(), identity_output, &recipient)?;
    } else {
        writeln!(interaction, "Recipient: {recipient}")?;
        writeln!(
            interaction,
            "Public identity stub: {}",
            identity_output.display()
        )?;
        writeln!(
            interaction,
            "Encrypt with a standard age client: age -e -r {recipient} ..."
        )?;
        writeln!(
            interaction,
            "Decrypt with a standard age client: age -d -i \"{}\" ...",
            identity_output.display()
        )?;
        writeln!(
            interaction,
            "Pairing success is not a recovery drill. Retained data also needs an independently verified recovery recipient."
        )?;
        interaction.flush()?;
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
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

#[cfg(not(target_os = "macos"))]
#[allow(clippy::too_many_arguments)]
fn commit_pairing_state(
    config_root: &std::path::Path,
    stub: &age_plugin_phone::pairing::PublicIdentityStub,
    desktop_state: &std::path::Path,
    identity_output: &std::path::Path,
    replay_state: &std::path::Path,
    desktop_state_created: bool,
    transport: TransportChoice,
    recipient_type: RecipientType,
) -> io::Result<()> {
    let pairing = age_plugin_phone_core::protocol::PairingRecord {
        desktop_id: stub.desktop_id,
        identity_id: stub.identity_id,
        desktop_signing_public_key: stub.desktop_signing_public_key,
        desktop_selection_public_key: stub.desktop_selection_public_key,
        phone_signing_public_key: stub.phone_signing_public_key,
    };
    let Ok(replay) = FileReplayGuard::create(
        replay_state,
        ReplayScope::for_pairing(ReplayRole::DesktopResponses, &pairing),
        DEFAULT_REPLAY_CAPACITY,
        now_unix().map_err(|_| io::Error::other("system clock is unavailable"))?,
    ) else {
        let rolled_back = rollback_failed_pairing(
            desktop_state,
            replay_state,
            None,
            desktop_state_created,
            stub.desktop_id,
        );
        return Err(pairing_commit_error(
            "failed to create durable response replay state",
            rolled_back,
        ));
    };
    drop(replay);
    let Ok(locator_path) = create_pairing_locator_with_transport(
        config_root,
        stub,
        desktop_state,
        replay_state,
        transport,
    ) else {
        let rolled_back = rollback_failed_pairing(
            desktop_state,
            replay_state,
            None,
            desktop_state_created,
            stub.desktop_id,
        );
        return Err(pairing_commit_error(
            "failed to create private pairing locator",
            rolled_back,
        ));
    };
    if age_plugin_phone::pairing::create_identity_stub_file_for(
        identity_output,
        stub,
        recipient_type,
    )
    .is_err()
    {
        let rolled_back = rollback_failed_pairing(
            desktop_state,
            replay_state,
            Some(&locator_path),
            desktop_state_created,
            stub.desktop_id,
        );
        return Err(pairing_commit_error(
            "failed to create public identity stub",
            rolled_back,
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn pairing_commit_error(message: &'static str, rolled_back: bool) -> io::Error {
    if rolled_back {
        io::Error::other(format!(
            "{message}; local partial state was removed, but the phone pairing must be revoked"
        ))
    } else {
        io::Error::other(format!(
            "{message}; local rollback is incomplete and the phone pairing must be revoked"
        ))
    }
}

#[cfg(not(target_os = "macos"))]
fn rollback_failed_pairing(
    desktop_state: &std::path::Path,
    replay_state: &std::path::Path,
    locator_path: Option<&std::path::Path>,
    desktop_state_created: bool,
    desktop_id: [u8; 16],
) -> bool {
    let mut complete = true;
    if let Some(path) = locator_path {
        complete &= remove_private_pairing_file(path);
    }
    complete &= remove_private_pairing_file(replay_state);
    if let Some(lock_path) = replay_lock_path(replay_state) {
        complete &= remove_private_pairing_file(&lock_path);
    } else {
        complete = false;
    }
    if desktop_state_created {
        #[cfg(windows)]
        {
            if age_plugin_phone_platform_keys::windows::remove_key_set(desktop_id).is_ok() {
                complete &= remove_private_pairing_file(desktop_state);
            } else {
                complete = false;
            }
        }
        #[cfg(not(windows))]
        {
            let _ = desktop_id;
            complete &= remove_private_pairing_file(desktop_state);
        }
    }
    complete
}

#[cfg(not(target_os = "macos"))]
fn replay_lock_path(path: &std::path::Path) -> Option<PathBuf> {
    let mut name = path.file_name()?.to_os_string();
    name.push(".lock");
    Some(path.parent()?.join(name))
}

#[cfg(windows)]
fn remove_private_pairing_file(path: &std::path::Path) -> bool {
    matches!(
        age_plugin_phone_platform_storage::windows::remove_private_file(path),
        Ok(()) | Err(age_plugin_phone_platform_storage::windows::Error::Missing)
    )
}

#[cfg(not(any(windows, target_os = "macos")))]
fn remove_private_pairing_file(path: &std::path::Path) -> bool {
    match std::fs::remove_file(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

#[cfg(target_os = "macos")]
fn ensure_macos_unwrap_locator(
    stub: &age_plugin_phone::pairing::PublicIdentityStub,
    desktop_state: &std::path::Path,
    replay_state: &std::path::Path,
) -> io::Result<()> {
    let root = default_config_root()
        .map_err(|_| io::Error::other("phone plugin configuration is unavailable"))?;
    let locator = age_plugin_phone::locator::open_pairing_locator(&root, stub)
        .map_err(|_| io::Error::other("paired state is unavailable or pending setup/cleanup"))?;
    if std::path::absolute(desktop_state)? != locator.desktop_state
        || std::path::absolute(replay_state)? != locator.replay_state
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "explicit state does not match the paired locator",
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
    wifi_address: Option<SocketAddr>,
) -> io::Result<()> {
    ensure_desktop_platform_supported()?;
    let stub = read_identity_stub_file(identity_stub)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid public identity stub"))?;
    #[cfg(target_os = "macos")]
    ensure_macos_unwrap_locator(&stub, desktop_state, replay_state)?;
    let wifi_address = discover_unwrap_wifi(&stub, transport, adb_serial, wifi_address)?;
    let route = resolve_transport(
        transport,
        TransportOperation::Unwrap,
        TransportHints {
            adb_serial: adb_serial.map(str::to_owned),
            wifi_address,
        },
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
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
    let response = match route.kind() {
        TransportKind::Adb => exchange_adb(
            SessionPurpose::Unwrap,
            &session.signed_request(),
            route.adb_serial(),
        ),
        TransportKind::Qr => {
            exchange_unwrap_qr(&session.signed_request(), &display, started, &mut stdout)
        }
        TransportKind::Wifi => exchange_wifi(
            SessionPurpose::Unwrap,
            &session.signed_request(),
            route.wifi_address().expect("validated Wi-Fi endpoint"),
        ),
        TransportKind::Ble => {
            unreachable!("unimplemented BLE is rejected before session creation")
        }
    };
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            session.cancel();
            return Err(error);
        }
    };
    let pairing = age_plugin_phone_core::protocol::PairingRecord {
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

fn discover_unwrap_wifi(
    stub: &age_plugin_phone::pairing::PublicIdentityStub,
    transport: TransportChoice,
    adb_serial: Option<&str>,
    wifi_address: Option<SocketAddr>,
) -> io::Result<Option<SocketAddr>> {
    if adb_serial.is_some()
        || wifi_address.is_some()
        || !matches!(transport, TransportChoice::Auto | TransportChoice::Wifi)
    {
        return Ok(wifi_address);
    }
    match discover_unwrap_endpoint(
        stub.desktop_id,
        stub.identity_id,
        &stub.phone_signing_public_key,
        DEFAULT_DISCOVERY_TIMEOUT,
        &mut OsRng,
    ) {
        Ok(address) => Ok(Some(address)),
        Err(WifiError::DiscoveryUnavailable) if transport == TransportChoice::Auto => Ok(None),
        Err(error) => Err(io::Error::other(error.to_string())),
    }
}

fn run_wifi_doctor(identity_stub: Option<&std::path::Path>) -> io::Result<()> {
    // No private locator, TPM key, replay store, signed session, or TCP connection is opened.
    // In particular, a TCP reachability probe would consume the phone's one-shot listener.
    let stub = identity_stub
        .map(read_identity_stub_file)
        .transpose()
        .map_err(|_| {
            io::Error::other(
                "wifi_doctor: public_stub_unavailable; check the selected public identity stub",
            )
        })?;
    let purpose = if stub.is_some() { "unwrap" } else { "pairing" };
    println!("stage=discovery purpose={purpose} timeout_ms=3000");
    let started = Instant::now();
    let result = if let Some(stub) = stub {
        discover_unwrap_endpoint(
            stub.desktop_id,
            stub.identity_id,
            &stub.phone_signing_public_key,
            DEFAULT_DISCOVERY_TIMEOUT,
            &mut OsRng,
        )
    } else {
        let mut desktop_id = [0; 16];
        OsRng.fill_bytes(&mut desktop_id);
        discover_pairing_endpoint(desktop_id, DEFAULT_DISCOVERY_TIMEOUT, &mut OsRng)
    };
    let elapsed = started.elapsed().as_millis();
    match result {
        Ok(_) => {
            println!("stage=discovery elapsed_ms={elapsed} result=one_candidate");
            println!("next=run_a_fresh_operation; discovery_does_not_authorize_pairing_or_unwrap");
            Ok(())
        }
        Err(error) => {
            let (reason, next) = match error {
                WifiError::DiscoveryUnavailable => (
                    "no_matching_response",
                    "check_phone_foreground_mode_same_subnet_listener_then_firewall",
                ),
                WifiError::DiscoveryAmbiguous => (
                    "multiple_candidates",
                    "leave_only_the_intended_phone_listener_active",
                ),
                _ => (
                    "local_socket_unavailable",
                    "check_local_network_interfaces_and_endpoint_security_policy",
                ),
            };
            println!("stage=discovery elapsed_ms={elapsed} result={reason}");
            println!("next={next}; timeout_alone_does_not_identify_a_firewall_fault");
            Err(io::Error::other("Wi-Fi discovery diagnostic failed"))
        }
    }
}

#[cfg(windows)]
fn ensure_desktop_platform_supported() -> io::Result<()> {
    age_plugin_phone_platform_keys::windows::ensure_supported_platform().map_err(|error| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported Windows Alpha platform: {error}"),
        )
    })
}

#[cfg(target_os = "macos")]
fn ensure_desktop_platform_supported() -> io::Result<()> {
    if age_plugin_phone_platform_keys::macos::secure_enclave_available() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "macOS Secure Enclave is unavailable; desktop private operations require hardware keys",
        ))
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
// Keep command paths identical to Windows while the actual capability gate is platform-specific.
#[allow(clippy::unnecessary_wraps)]
fn ensure_desktop_platform_supported() -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn print_macos_platform_status() {
    // Status deliberately does not open cameras, request permissions, discover phones,
    // or create/reopen persistent keys. Compilation is not a hardware acceptance result.
    println!("desktop_os: macos");
    println!("desktop_arch: {}", std::env::consts::ARCH);
    println!("macos_support: experimental_acceptance_incomplete");
    println!("desktop_key_backend: cryptokit_secure_enclave_dual_p256");
    println!("secure_enclave_usability: unverified_no_key_operation_performed");
    println!("qr_capture_probe: unverified_camera_not_opened");
    println!("camera_permission: unverified_for_current_caller");
    println!("local_network_permission: unverified_for_current_caller");
    println!("wifi_discovery_interfaces: active_ipv4_broadcast_snapshot_per_attempt");
    println!("developer_usb: explicit_android_adb_only_device_authorization_unverified");
    println!("macos_setup: implemented_acceptance_incomplete");
    println!("macos_snapshot_rollback_protection: unresolved");
}

#[cfg(windows)]
fn print_windows_platform_status() {
    let report = age_plugin_phone_platform_keys::windows::probe_windows_platform();
    println!(
        "windows_alpha_support: {}",
        if report.is_supported() {
            "supported"
        } else {
            "unsupported"
        }
    );
    println!(
        "windows_version: {}.{}.{}",
        report.version_major, report.version_minor, report.version_build
    );
    println!("windows_client_edition: {}", report.client_edition.as_str());
    println!("windows_x64: {}", report.x64.as_str());
    println!("tpm_2_0: {}", report.tpm20.as_str());
    println!(
        "microsoft_platform_crypto_provider: {}",
        report.platform_provider.as_str()
    );
}

fn exchange_adb(
    purpose: SessionPurpose,
    request: &[u8],
    serial: Option<&str>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut transport = AdbReverseSession::connect(
        SystemAdb::default(),
        serial,
        purpose,
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

fn exchange_wifi(
    purpose: SessionPurpose,
    request: &[u8],
    endpoint: SocketAddr,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut transport = WifiSession::connect(
        endpoint,
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_MESSAGE_TIMEOUT,
        TransportLimits::default(),
        &mut OsRng,
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    transport
        .exchange(purpose, request)
        .map_err(|_| io::Error::other("Wi-Fi transport session failed closed"))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn exchange_pairing_qr(
    request: &[u8],
    started: Instant,
    output: &mut impl io::Write,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let scanner = ScannerHandle::start_default_camera(DEFAULT_SCAN_TIMEOUT);
    exchange_pairing_qr_with_scanner(request, started, output, &scanner)
}

fn exchange_pairing_qr_with_scanner(
    request: &[u8],
    started: Instant,
    output: &mut impl io::Write,
    scanner: &ScannerHandle,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let frames = fragment_qr_message(request, 120, &mut OsRng)
        .map_err(|_| io::Error::other("failed to fragment pairing offer"))?;
    let mut scheduler = FrameScheduler::new(&frames, DEFAULT_FRAME_INTERVAL_MS)
        .map_err(|_| io::Error::other("failed to schedule pairing QR"))?;
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

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn wifi_doctor_rejects_session_options_and_bad_stub_before_discovery() {
        assert!(matches!(
            Options::try_parse_from(["age-plugin-phone", "wifi-doctor"])
                .unwrap()
                .command,
            Some(Command::WifiDoctor {
                identity_stub: None
            })
        ));
        for option in [
            "--transport",
            "--wifi-address",
            "--desktop-state",
            "--replay-state",
        ] {
            assert!(
                Options::try_parse_from(["age-plugin-phone", "wifi-doctor", option, "value"])
                    .is_err()
            );
        }
        let root = std::env::temp_dir().join(format!(
            "age-phone-wifi-doctor-{}-{}",
            std::process::id(),
            now_unix().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("public-stub.txt");
        assert!(run_wifi_doctor(Some(&path)).is_err());
        assert!(!path.exists());
        std::fs::write(&path, b"malformed public stub").unwrap();
        assert!(run_wifi_doctor(Some(&path)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"malformed public stub");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn auto_accepts_one_route_hint_without_an_explicit_transport_option() {
        let options = Options::try_parse_from([
            "age-plugin-phone",
            "unwrap",
            "--identity-stub",
            "/tmp/identity",
            "--desktop-state",
            "/tmp/desktop",
            "--replay-state",
            "/tmp/replay",
            "--stanza-arg",
            "arg",
            "--stanza-body",
            "body",
            "--wifi-address",
            "192.168.1.20:47140",
        ])
        .unwrap();
        let Some(Command::Unwrap {
            transport,
            adb_serial,
            wifi_address,
            ..
        }) = options.command
        else {
            panic!("unwrap command must parse");
        };
        assert_eq!(transport, TransportChoice::Auto);
        assert_eq!(adb_serial, None);
        assert_eq!(
            wifi_address,
            Some(SocketAddr::from(([192, 168, 1, 20], WIFI_UNWRAP_PORT)))
        );
    }

    #[test]
    fn setup_cli_separates_new_resume_and_cleanup_modes() {
        let options = Options::try_parse_from([
            "age-plugin-phone",
            "setup",
            "--label",
            "Work laptop",
            "--adb-serial",
            "phone-a",
        ])
        .unwrap();
        let Some(Command::Setup {
            label,
            resume,
            cleanup,
            transport,
            adb_serial,
            json,
            recipient_type,
        }) = options.command
        else {
            panic!("setup command must parse");
        };
        assert_eq!(label.as_deref(), Some("Work laptop"));
        assert!(!resume && !cleanup);
        assert_eq!(transport, TransportChoice::Auto);
        assert_eq!(adb_serial.as_deref(), Some("phone-a"));
        assert_eq!(recipient_type, RecipientType::Phone);
        assert!(!json);

        assert!(
            Options::try_parse_from(["age-plugin-phone", "setup", "--resume", "--json"]).is_ok()
        );
        assert!(Options::try_parse_from(["age-plugin-phone", "setup", "--cleanup"]).is_ok());
        assert!(
            Options::try_parse_from(["age-plugin-phone", "setup", "--cleanup", "--json"]).is_err()
        );
        assert!(Options::try_parse_from(["age-plugin-phone", "setup"]).is_err());
        assert!(
            Options::try_parse_from(["age-plugin-phone", "setup", "--resume", "--cleanup",])
                .is_err()
        );
        assert!(
            Options::try_parse_from([
                "age-plugin-phone",
                "setup",
                "--resume",
                "--label",
                "desktop",
            ])
            .is_err()
        );
        assert!(
            Options::try_parse_from([
                "age-plugin-phone",
                "setup",
                "--cleanup",
                "--adb-serial",
                "phone-a",
            ])
            .is_err()
        );
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    #[test]
    fn simplified_setup_is_explicitly_unsupported_off_windows() {
        let error = run_setup(
            Some("desktop".to_owned()),
            false,
            false,
            TransportChoice::Auto,
            None,
            false,
            RecipientType::Phone,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn setup_label_uses_the_protocol_byte_limit() {
        assert!(validate_setup_label(&"x".repeat(64)).is_ok());
        assert_eq!(
            validate_setup_label(&"x".repeat(65)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            validate_setup_label(&"桌".repeat(22)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn rejected_explicit_pair_preflight_creates_no_state() {
        let root = std::env::temp_dir().join(format!(
            "phone-pair-preflight-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        for label in ["x".repeat(65), "synthetic preflight".to_owned()] {
            // BLE is deliberately unsupported. On machines without hardware, the earlier
            // capability gate also fails; neither rejection may create the requested state.
            assert!(
                run_pair(
                    label,
                    &root.join("desktop.state"),
                    &root.join("identity.txt"),
                    &root.join("replay.state"),
                    TransportChoice::Ble,
                    None,
                    RecipientType::Phone,
                )
                .is_err()
            );
            assert!(!root.exists());
        }
    }

    #[test]
    fn setup_json_contains_only_versioned_public_fields() {
        for recipient in ["age1phone1example", "age1tag1example"] {
            let mut output = Vec::new();
            write_setup_result_json(
                &mut output,
                std::path::Path::new("C:/Users/example/identity.txt"),
                recipient,
            )
            .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(
                value,
                serde_json::json!({
                    "schema_version": 1,
                    "identity_path": "C:/Users/example/identity.txt",
                    "recipient": recipient,
                })
            );
        }
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn failed_pairing_rollback_removes_only_new_local_state() {
        let root = std::env::temp_dir().join(format!(
            "age-phone-pairing-rollback-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&root).unwrap();
        let desktop = root.join("desktop.state");
        let replay = root.join("replay.state");
        let replay_lock = replay_lock_path(&replay).unwrap();
        let locator = root.join("locator.cbor");
        let unrelated = root.join("unrelated.state");
        for path in [&desktop, &replay, &replay_lock, &locator, &unrelated] {
            std::fs::write(path, b"synthetic").unwrap();
        }

        assert!(rollback_failed_pairing(
            &desktop,
            &replay,
            Some(&locator),
            true,
            [7; 16],
        ));
        for path in [&desktop, &replay, &replay_lock, &locator] {
            assert!(!path.exists());
        }
        assert!(unrelated.exists());
        std::fs::remove_file(unrelated).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
