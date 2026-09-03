mod models;

pub use models::{
    AgreementReport, CapabilityReport, CleanupReport, IdentityCustodyReport, IdentityStatusReport,
    LifecycleReport, PairedDesktopSummary, PairingOfferScanReport, PairingStorageReport,
    PhonePairingReport, PhoneUnwrapReport, ProbeKeyReport, WifiAutoListenStatusReport,
};

#[cfg(not(target_os = "android"))]
use std::marker::PhantomData;

use tauri::{
    AppHandle, Manager, Runtime, State,
    plugin::{Builder, TauriPlugin},
};
use thiserror::Error;

#[cfg(target_os = "android")]
mod mobile;

#[derive(Debug, Error)]
pub enum Error {
    #[cfg(target_os = "android")]
    #[error("native phone identity bridge failed")]
    Mobile(#[from] tauri::plugin::mobile::PluginInvokeError),
    #[error("phone identity is only available on Android")]
    Unsupported,
}

impl serde::Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("phone_identity_unavailable")
    }
}

#[cfg(target_os = "android")]
type PhoneIdentity<R> = mobile::PhoneIdentity<R>;

#[cfg(not(target_os = "android"))]
struct PhoneIdentity<R: Runtime>(PhantomData<fn() -> R>);

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn doctor_capabilities<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<CapabilityReport, Error> {
    if !cfg!(debug_assertions) {
        return Err(Error::Unsupported);
    }
    #[cfg(target_os = "android")]
    return _identity.doctor_capabilities();

    #[cfg(not(target_os = "android"))]
    Ok(CapabilityReport {
        android_release: "not-android".into(),
        api_level: 0,
        sdk_extension_level: 0,
        strongbox_feature: false,
        strong_biometric: "unsupported".into(),
        secure_lock_screen: false,
        key_agreement_crypto_object: false,
        leftover_probe_key: false,
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn doctor_identity_custody<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<IdentityCustodyReport, Error> {
    if !cfg!(debug_assertions) {
        return Err(Error::Unsupported);
    }
    #[cfg(target_os = "android")]
    return _identity.doctor_identity_custody();

    #[cfg(not(target_os = "android"))]
    Ok(IdentityCustodyReport {
        no_backup_storage: false,
        identity_strong_box: false,
        identity_agree_only: false,
        identity_auth_per_use: false,
        identity_biometric_strong: false,
        signing_strong_box: false,
        signing_purpose_sign_only: false,
        signing_no_user_auth: false,
        private_keys_non_exportable: false,
        keys_distinct: false,
        metadata_bound: false,
        reopened: false,
        duplicate_rejected: false,
        preparing_recovered: false,
        cleanup_complete: true,
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn doctor_create_probe<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<ProbeKeyReport, Error> {
    if !cfg!(debug_assertions) {
        return Err(Error::Unsupported);
    }
    #[cfg(target_os = "android")]
    return _identity.doctor_create_probe();

    #[cfg(not(target_os = "android"))]
    Ok(ProbeKeyReport {
        generated: false,
        security_level: "unsupported".into(),
        origin_generated: false,
        purpose_agree_key: false,
        user_authentication_required: false,
        auth_per_use: false,
        authentication_type: "none".into(),
        auth_enforced_by_secure_hardware: false,
        private_key_format_is_null: false,
        private_key_encoded_is_null: false,
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn doctor_run_agreement<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<AgreementReport, Error> {
    if !cfg!(debug_assertions) {
        return Err(Error::Unsupported);
    }
    #[cfg(target_os = "android")]
    return _identity.doctor_run_agreement();

    #[cfg(not(target_os = "android"))]
    Ok(AgreementReport {
        recipient_protocol: "phone-p256-v2".into(),
        authenticated: false,
        agreement_match: false,
        response_envelope_match: false,
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn doctor_cleanup<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<CleanupReport, Error> {
    if !cfg!(debug_assertions) {
        return Err(Error::Unsupported);
    }
    #[cfg(target_os = "android")]
    return _identity.doctor_cleanup();

    #[cfg(not(target_os = "android"))]
    Ok(CleanupReport {
        probe_key_existed: false,
        probe_key_deleted: false,
        probe_key_absent_after_delete: true,
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn doctor_pairing_storage<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<PairingStorageReport, Error> {
    if !cfg!(debug_assertions) {
        return Err(Error::Unsupported);
    }
    #[cfg(target_os = "android")]
    return _identity.doctor_pairing_storage();

    #[cfg(not(target_os = "android"))]
    Ok(PairingStorageReport {
        no_backup_storage: false,
        qr_fragmented: false,
        qr_out_of_order_reassembled: false,
        qr_corruption_rejected: false,
        qr_timeout_rejected: false,
        transcript_verified: false,
        fingerprint_mismatch_rejected: false,
        cancellation_rejected: false,
        confirmation_committed: false,
        duplicate_confirmation_rejected: false,
        atomic_state_created: false,
        verified_before_consume: false,
        replay_rejected_after_reopen: false,
        wrong_scope_rejected: false,
        missing_state_rejected_after_delete: false,
        cleanup_complete: true,
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn scan_pairing_offer<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<PairingOfferScanReport, Error> {
    #[cfg(target_os = "android")]
    return _identity.scan_pairing_offer();

    #[cfg(not(target_os = "android"))]
    Ok(PairingOfferScanReport {
        scanner_started: false,
        message_verified: false,
        desktop_label: None,
        offer_fingerprint: None,
        frames_accepted: 0,
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn pair_phone<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<PhonePairingReport, Error> {
    #[cfg(target_os = "android")]
    return _identity.pair_phone();

    #[cfg(not(target_os = "android"))]
    Ok(PhonePairingReport {
        paired: false,
        desktop_label: None,
        transcript_fingerprint: None,
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn unwrap_phone<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<PhoneUnwrapReport, Error> {
    #[cfg(target_os = "android")]
    return _identity.unwrap_phone();

    #[cfg(not(target_os = "android"))]
    Ok(PhoneUnwrapReport {
        authenticated: false,
        response_displayed: false,
        request_fingerprint: None,
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn set_wifi_auto_listen<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
    enabled: bool,
) -> Result<WifiAutoListenStatusReport, Error> {
    #[cfg(target_os = "android")]
    return _identity.set_wifi_auto_listen(enabled);

    #[cfg(not(target_os = "android"))]
    let _ = enabled;

    #[cfg(not(target_os = "android"))]
    Ok(WifiAutoListenStatusReport {
        enabled: false,
        state: "disabled".into(),
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn wifi_auto_listen_status<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<WifiAutoListenStatusReport, Error> {
    #[cfg(target_os = "android")]
    return _identity.wifi_auto_listen_status();

    #[cfg(not(target_os = "android"))]
    Ok(WifiAutoListenStatusReport {
        enabled: false,
        state: "disabled".into(),
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn pair_phone_usb<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<PhonePairingReport, Error> {
    #[cfg(target_os = "android")]
    return _identity.pair_phone_usb();

    #[cfg(not(target_os = "android"))]
    Ok(PhonePairingReport {
        paired: false,
        desktop_label: None,
        transcript_fingerprint: None,
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn pair_phone_wifi<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<PhonePairingReport, Error> {
    #[cfg(target_os = "android")]
    return _identity.pair_phone_wifi();

    #[cfg(not(target_os = "android"))]
    Ok(PhonePairingReport {
        paired: false,
        desktop_label: None,
        transcript_fingerprint: None,
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn identity_status<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<IdentityStatusReport, Error> {
    #[cfg(target_os = "android")]
    return _identity.identity_status();

    #[cfg(not(target_os = "android"))]
    Ok(IdentityStatusReport {
        state: "unsupported".into(),
        public_recipient: None,
        paired_desktops: Vec::new(),
        recovery_required: true,
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
#[allow(clippy::used_underscore_binding)]
fn provision_identity<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<IdentityStatusReport, Error> {
    #[cfg(target_os = "android")]
    return _identity.provision_identity();

    #[cfg(not(target_os = "android"))]
    identity_status(_app, _identity)
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn revoke_pairing<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
    _handle: String,
) -> Result<LifecycleReport, Error> {
    #[cfg(target_os = "android")]
    return _identity.revoke_pairing(_handle);

    #[cfg(not(target_os = "android"))]
    Ok(LifecycleReport {
        completed: false,
        state: "unsupported".into(),
        error_category: Some("unsupported_api".into()),
    })
}

#[tauri::command]
#[allow(clippy::unnecessary_wraps)]
fn delete_identity<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<LifecycleReport, Error> {
    #[cfg(target_os = "android")]
    return _identity.delete_identity();

    #[cfg(not(target_os = "android"))]
    Ok(LifecycleReport {
        completed: false,
        state: "unsupported".into(),
        error_category: Some("unsupported_api".into()),
    })
}

#[must_use]
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("phone-identity")
        .invoke_handler(tauri::generate_handler![
            doctor_capabilities,
            doctor_identity_custody,
            doctor_create_probe,
            doctor_run_agreement,
            doctor_cleanup,
            doctor_pairing_storage,
            scan_pairing_offer,
            pair_phone,
            pair_phone_usb,
            pair_phone_wifi,
            unwrap_phone,
            set_wifi_auto_listen,
            wifi_auto_listen_status,
            identity_status,
            provision_identity,
            revoke_pairing,
            delete_identity
        ])
        .setup(|app, _api| {
            #[cfg(target_os = "android")]
            let identity = mobile::init(app, _api)?;
            #[cfg(not(target_os = "android"))]
            let identity = PhoneIdentity::<R>(PhantomData);
            app.manage(identity);
            Ok(())
        })
        .build()
}
