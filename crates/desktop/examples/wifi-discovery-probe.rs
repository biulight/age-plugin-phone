//! Diagnose authenticated discovery without opening a stream or requesting identity use.

use age_plugin_phone::{
    pairing::read_identity_stub_file,
    wifi::{DEFAULT_DISCOVERY_TIMEOUT, discover_unwrap_endpoint},
};
use rand_core::OsRng;
use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(path) = arguments.next() else {
        eprintln!("usage: wifi-discovery-probe IDENTITY_FILE");
        return ExitCode::FAILURE;
    };
    if arguments.next().is_some() {
        eprintln!("usage: wifi-discovery-probe IDENTITY_FILE");
        return ExitCode::FAILURE;
    }
    let Ok(stub) = read_identity_stub_file(&PathBuf::from(path)) else {
        eprintln!("public identity reference unavailable or malformed");
        return ExitCode::FAILURE;
    };
    let mut success = true;
    for attempt in 1..=3 {
        match discover_unwrap_endpoint(
            stub.desktop_id,
            stub.identity_id,
            &stub.phone_signing_public_key,
            DEFAULT_DISCOVERY_TIMEOUT,
            &mut OsRng,
        ) {
            Ok(_) => println!("attempt {attempt}: one authenticated listener"),
            Err(error) => {
                println!("attempt {attempt}: {error}");
                success = false;
            }
        }
    }
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
