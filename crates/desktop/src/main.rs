use std::{
    collections::HashMap,
    convert::Infallible,
    io::{self, Write as _},
    path::PathBuf,
    thread,
    time::Duration,
};

use age_core::format::{FileKey, Stanza};
use age_plugin::{
    Callbacks, PluginHandler,
    identity::{self, IdentityPluginV1},
    run_state_machine,
};
use age_plugin_phone::qr_terminal::{
    DEFAULT_FRAME_INTERVAL_MS, FrameScheduler, render_offline_html, render_terminal_frame,
};
use age_plugin_phone_protocol::{
    PROTOCOL_VERSION, PairingOffer, SignedPairingOffer, fragment_qr_message,
};
use clap::{Parser, Subcommand};
use p256::ecdsa::SigningKey;
use rand_core::{OsRng, RngCore as _};

const NOT_IMPLEMENTED: &str =
    "phone transport is not implemented; refusing to release an age file key";

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
    /// Report scaffold and protocol status without probing devices.
    Status,
    /// Start offline phone pairing once a transport backend is implemented.
    Pair,
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

struct Handler;

impl PluginHandler for Handler {
    type RecipientV1 = Infallible;
    type IdentityV1 = PhoneIdentityPlugin;

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(PhoneIdentityPlugin::default())
    }
}

#[derive(Default)]
struct PhoneIdentityPlugin {
    identities: Vec<(usize, String, Vec<u8>)>,
}

impl IdentityPluginV1 for PhoneIdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        self.identities
            .push((index, plugin_name.to_owned(), bytes.to_vec()));
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        _files: Vec<Vec<Stanza>>,
        _callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, NOT_IMPLEMENTED))
    }
}

fn main() -> io::Result<()> {
    let options = Options::parse();

    if let Some(state_machine) = options.age_plugin {
        return run_state_machine(&state_machine, Handler);
    }

    match options.command.unwrap_or(Command::Status) {
        Command::Status => {
            println!("status: scaffold-only");
            println!("protocol_version: {PROTOCOL_VERSION}");
            println!("qr_capture_probe: available");
            println!("pairing_transport: not_implemented");
            println!("ble_transport: not_implemented");
            println!("mobile_identity: not_implemented");
            println!("secret_operations: fail_closed");
            Ok(())
        }
        Command::Pair => Err(io::Error::new(io::ErrorKind::Unsupported, NOT_IMPLEMENTED)),
        Command::QrCaptureProbe {
            label,
            cycles,
            html_output,
        } => run_qr_capture_probe(label, cycles, html_output),
    }
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
    let encoded_public = signing_key.verifying_key().to_encoded_point(true);
    let desktop_signing_public_key = encoded_public
        .as_bytes()
        .try_into()
        .map_err(|_| io::Error::other("failed to encode disposable signing public key"))?;
    let mut desktop_id = [0_u8; 16];
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut desktop_id);
    OsRng.fill_bytes(&mut nonce);
    let offer = SignedPairingOffer::sign(
        PairingOffer {
            desktop_id,
            desktop_label: label,
            desktop_signing_public_key,
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
