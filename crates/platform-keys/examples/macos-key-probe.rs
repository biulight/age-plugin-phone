//! Explicit M0 experiment. Never invoked by status, setup, or ordinary tests.
#[cfg(target_os = "macos")]
#[path = "../src/macos/probe.rs"]
mod probe;

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "macos")]
    let result = probe::run(&std::env::args().skip(1).collect::<Vec<_>>());
    #[cfg(not(target_os = "macos"))]
    let result: Result<(), String> = Err("unsupported_os".into());
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FAIL {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
