#![cfg(unix)]

use age_plugin_phone_core::protocol::{
    Error, FileReplayGuard, ReplayRole, ReplayScope, ReplayStore,
};
use std::{fs, os::unix::fs::PermissionsExt as _};

#[test]
fn pre_refactor_states_preserve_consumption_clock_and_later_commits() {
    let directory = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("phone-old-replay-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    for (name, role, bytes) in [
        (
            "requests",
            ReplayRole::PhoneRequests,
            include_bytes!("fixtures/requests.cbor").as_slice(),
        ),
        (
            "responses",
            ReplayRole::DesktopResponses,
            include_bytes!("fixtures/responses.cbor").as_slice(),
        ),
    ] {
        let path = directory.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let scope = ReplayScope::new(role, [1; 16], [2; 16]);
        let mut guard = FileReplayGuard::open(&path, scope, 4).unwrap();
        let consume = |guard: &mut FileReplayGuard, fresh: bool, now| match role {
            ReplayRole::PhoneRequests => guard.consume_request(
                [1; 16],
                [2; 16],
                [if fresh { 6 } else { 3 }; 16],
                [if fresh { 7 } else { 4 }; 32],
                200,
                now,
            ),
            ReplayRole::DesktopResponses => {
                guard.consume_response([1; 16], [2; 16], [if fresh { 8 } else { 5 }; 32], 200, now)
            }
        };
        assert_eq!(consume(&mut guard, false, 110), Err(Error::Replay));
        assert_eq!(consume(&mut guard, true, 109), Err(Error::ClockRollback));
        consume(&mut guard, true, 120).unwrap();
        drop(guard);
        let mut guard = FileReplayGuard::open(&path, scope, 4).unwrap();
        assert_eq!(consume(&mut guard, false, 120), Err(Error::Replay));
        assert_eq!(consume(&mut guard, true, 120), Err(Error::Replay));
        assert_eq!(consume(&mut guard, true, 119), Err(Error::ClockRollback));
    }
    fs::remove_dir_all(directory).unwrap();
}
