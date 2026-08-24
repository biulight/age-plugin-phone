use std::{collections::HashMap, convert::Infallible, io};

use age_core::format::{FileKey, Stanza};
use age_plugin::{
    Callbacks, PluginHandler,
    identity::{self, IdentityPluginV1},
    run_state_machine,
};
use age_plugin_phone_protocol::PROTOCOL_VERSION;
use clap::{Parser, Subcommand};

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
            println!("qr_transport: not_implemented");
            println!("ble_transport: not_implemented");
            println!("mobile_identity: not_implemented");
            println!("secret_operations: fail_closed");
            Ok(())
        }
        Command::Pair => Err(io::Error::new(io::ErrorKind::Unsupported, NOT_IMPLEMENTED)),
    }
}
