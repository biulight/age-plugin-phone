//! Explicit synthetic macOS persistence acceptance. Never processes protocol payloads or keys.
#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use age_plugin_phone_core::protocol::{
        Error, FileReplayGuard, ReplayRole, ReplayScope, ReplayStore,
    };
    use age_plugin_phone_platform_storage::macos::Directory;
    use std::{
        io::Write as _,
        path::{Path, PathBuf},
    };
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err("expected command and isolated synthetic state path".into());
    }
    let command = args[1].to_str().ok_or("invalid command")?;
    let path = PathBuf::from(&args[2]);
    let scope = ReplayScope::new(ReplayRole::DesktopResponses, [0xa1; 16], [0xb2; 16]);
    let consume = |guard: &mut FileReplayGuard, token| {
        guard.consume_response([0xa1; 16], [0xb2; 16], [token; 32], 110, 100)
    };
    match command {
        "seed" => {
            let mut guard = FileReplayGuard::create(&path, scope, 8, 100)?;
            consume(&mut guard, 1)?;
            println!("seeded");
        }
        "verify" | "verify-three" => {
            let mut guard = FileReplayGuard::open(&path, scope, 8)?;
            if consume(&mut guard, if command == "verify" { 1 } else { 3 }) != Err(Error::Replay) {
                return Err("consumed token accepted".into());
            }
            println!("replay_rejected");
        }
        "consume-two" => {
            let mut guard = FileReplayGuard::open(&path, scope, 8)?;
            consume(&mut guard, 2)?;
            println!("consumed");
        }
        "consume-fails" => {
            let mut guard = FileReplayGuard::open(&path, scope, 8)?;
            if consume(&mut guard, 2) != Err(Error::ReplayState)
                || consume(&mut guard, 2) != Err(Error::ReplayState)
            {
                return Err("full-volume commit or poisoned-guard retry succeeded".into());
            }
            println!("commit_unavailable");
        }
        "verify-closed" => {
            if let Ok(mut guard) = FileReplayGuard::open(&path, scope, 8) {
                if consume(&mut guard, 1) != Err(Error::Replay) {
                    return Err("baseline replay restored".into());
                }
                println!("replay_rejected");
            } else {
                println!("state_unavailable");
            }
        }
        "verify-pending" => {
            if FileReplayGuard::open(&path, scope, 8).is_ok()
                || FileReplayGuard::create(&path, scope, 8, 100).is_ok()
            {
                return Err("uncertain state opened or recreated".into());
            }
            println!("pending_rejected");
        }
        "hold-committed" | "hold-pending" => {
            let mut guard = FileReplayGuard::open(&path, scope, 8)?;
            if command == "hold-committed" {
                consume(&mut guard, 3)?;
            } else {
                let directory = Directory::open(path.parent().ok_or("missing parent")?)?;
                let mut pending = path.file_name().ok_or("missing name")?.to_os_string();
                pending.push(".pending");
                directory.create(Path::new(&pending), b"pending")?;
            }
            println!("ready");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            return Err("holder must be terminated by acceptance runner".into());
        }
        _ => return Err("unknown command".into()),
    }
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("macOS acceptance only");
    std::process::exit(1);
}
