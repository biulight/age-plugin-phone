//! Separate owner-assisted adversarial probe for synthetic pairings only.
//! Never logs or persists protocol bytes or keys; replay bytes remain in memory.
use age_plugin_phone::{
    adb::{AdbReverseSession, SystemAdb, run_cleanup_guard},
    locator::open_pairing_locator,
    pairing::{DesktopKeyState, read_identity_stub_file},
    transport::{DesktopTransport, SessionPurpose, TransportLimits},
    unwrap::{DesktopUnwrapSession, now_unix},
};
use age_plugin_phone_core::{
    protocol::{
        DEFAULT_REPLAY_CAPACITY, Error, FileReplayGuard, ReplayRole, ReplayScope, ReplayStore,
    },
    recipient::wrap_file_key_v2,
};
use rand_core::{OsRng, RngCore};
use std::{
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn connect() -> Result<AdbReverseSession<SystemAdb>, &'static str> {
    AdbReverseSession::connect(
        SystemAdb::default(),
        None,
        SessionPurpose::Unwrap,
        Duration::from_secs(20),
        Duration::from_secs(60),
        TransportLimits::default(),
        &mut OsRng,
    )
    .map_err(|_| "transport_connection_failed")
}

fn probe(args: &[String]) -> Result<(), &'static str> {
    if args.len() != 4 {
        return Err("expected_action_config_root_stub");
    }
    let stub = read_identity_stub_file(Path::new(&args[3])).map_err(|_| "stub_failed")?;
    let locator = open_pairing_locator(Path::new(&args[2]), &stub).map_err(|_| "locator_failed")?;
    let desktop =
        DesktopKeyState::open(&locator.desktop_state).map_err(|_| "existing_tpm_keys_failed")?;
    if desktop
        .signing_public_key()
        .map_err(|_| "signing_key_failed")?
        != stub.desktop_signing_public_key
        || desktop
            .selection_public_key()
            .map_err(|_| "selection_key_failed")?
            != stub.desktop_selection_public_key
    {
        return Err("key_binding_failed");
    }
    let scope = ReplayScope::new(
        ReplayRole::DesktopResponses,
        stub.desktop_id,
        stub.identity_id,
    );
    if args[1] == "stored-response" {
        #[cfg(windows)]
        {
            use age_plugin_phone_platform_storage::windows::read_private_file;
            let mut guard =
                FileReplayGuard::open(&locator.replay_state, scope, DEFAULT_REPLAY_CAPACITY)
                    .map_err(|_| "existing_replay_open_failed")?;
            let before = read_private_file(&locator.replay_state, 1_048_576)
                .map_err(|_| "state_read_failed")?;
            let mut d = minicbor::Decoder::new(&before);
            if d.array().ok() != Some(Some(6))
                || d.u16().ok() != Some(2)
                || d.u16().ok() != Some(2)
                || d.bytes().ok() != Some(stub.desktop_id.as_slice())
                || d.bytes().ok() != Some(stub.identity_id.as_slice())
            {
                return Err("state_header_failed");
            }
            let clock = d.u64().map_err(|_| "clock_missing")?;
            let count = d
                .array()
                .map_err(|_| "entries_missing")?
                .ok_or("indefinite_entries")?;
            if count == 0 {
                return Err("no_consumed_response");
            }
            if d.array().ok() != Some(Some(3)) || d.u16().ok() != Some(2) {
                return Err("entry_invalid");
            }
            let digest: [u8; 32] = d
                .bytes()
                .map_err(|_| "digest_invalid")?
                .try_into()
                .map_err(|_| "digest_length")?;
            let expiry = d.u64().map_err(|_| "expiry_invalid")?;
            if expiry <= clock {
                return Err("expired_at_test_clock");
            }
            if guard.consume_response(stub.desktop_id, stub.identity_id, digest, expiry, clock)
                != Err(Error::Replay)
            {
                return Err("durable_replay_not_rejected");
            }
            if guard.consume_response(
                stub.desktop_id,
                stub.identity_id,
                digest,
                expiry,
                clock.checked_sub(1).ok_or("zero_clock")?,
            ) != Err(Error::ClockRollback)
            {
                return Err("clock_rollback_not_rejected");
            }
            if read_private_file(&locator.replay_state, 1_048_576)
                .map_err(|_| "state_reread_failed")?
                != before
            {
                return Err("rejected_probe_changed_state");
            }
            println!(
                "stored_response_replay=PASS clock_rollback=PASS state_unchanged=PASS existing_key_binding=PASS"
            );
            return Ok(());
        }
        #[cfg(not(windows))]
        return Err("windows_required");
    }
    let approve = match args[1].as_str() {
        "approve-replay" => true,
        "cancel-replay" => false,
        _ => return Err("unknown_action"),
    };
    let mut key = Zeroizing::new([0u8; 16]);
    OsRng.fill_bytes(key.as_mut());
    let stanza = wrap_file_key_v2(
        &stub.paired_recipient().map_err(|_| "recipient_failed")?,
        &key,
        &mut OsRng,
    )
    .map_err(|_| "wrap_failed")?;
    let mut session = DesktopUnwrapSession::begin(
        &stub,
        &desktop,
        stanza,
        None,
        now_unix().map_err(|_| "clock_failed")?,
        &mut OsRng,
    )
    .map_err(|_| "session_failed")?;
    let request = Zeroizing::new(session.signed_request());
    println!(
        "owner_action={}",
        if approve {
            "APPROVE_ON_PHONE"
        } else {
            "CANCEL_ON_PHONE"
        }
    );
    let mut transport = connect()?;
    let response = transport.exchange(SessionPurpose::Unwrap, &request);
    drop(transport);
    if approve {
        let response = response.map_err(|_| "approved_response_missing")?;
        let mut guard =
            FileReplayGuard::open(&locator.replay_state, scope, DEFAULT_REPLAY_CAPACITY)
                .map_err(|_| "replay_open_failed")?;
        let opened = session
            .receive_response(
                &response,
                &mut guard,
                now_unix().map_err(|_| "clock_failed")?,
            )
            .map_err(|_| "response_verification_failed")?;
        if *opened != *key {
            return Err("synthetic_key_mismatch");
        }
        println!("first_authorized_unwrap=PASS");
    } else {
        if response.is_ok() {
            return Err("cancel_returned_response");
        }
        session.cancel();
        println!("first_attempt_no_response=PASS owner_cancellation_observation_required=true");
    }
    println!("wait_for_phone_idle_then_type_READY=true");
    let mut ready = String::new();
    std::io::stdin()
        .read_line(&mut ready)
        .map_err(|_| "owner_input_failed")?;
    if ready.trim() != "READY" {
        return Err("owner_readiness_not_confirmed");
    }
    if now_unix().map_err(|_| "clock_failed")?.saturating_add(25)
        >= session.display().expires_at_unix
    {
        return Err("insufficient_unexpired_replay_window");
    }
    println!("replaying_identical_unexpired_request=true observe_no_native_prompt=true");
    let mut transport = connect()?;
    let started = Instant::now();
    let replay = transport.exchange(SessionPurpose::Unwrap, &request);
    drop(transport);
    if replay.is_ok() {
        return Err("replayed_request_returned_response");
    }
    if started.elapsed() > Duration::from_secs(10) {
        return Err("replay_rejection_not_prompt_unavailable_or_timeout");
    }
    println!(
        "identical_request_rejected_after_connection=PASS within_expiry=true owner_no_prompt_observation_required=true"
    );
    Ok(())
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 4 && args[1] == "__adb-cleanup-guard" && args[2] == "--serial" {
        std::process::exit(if run_cleanup_guard(&args[3]).is_ok() {
            0
        } else {
            1
        });
    }
    if let Err(category) = probe(&args) {
        eprintln!("probe_failed={category}");
        std::process::exit(1);
    }
}
