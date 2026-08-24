mod models;

pub use models::{
    AgreementReport, CapabilityReport, CleanupReport, PairingStorageReport, ProbeKeyReport,
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
    #[cfg(not(target_os = "android"))]
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
fn doctor_create_probe<R: Runtime>(
    _app: AppHandle<R>,
    _identity: State<'_, PhoneIdentity<R>>,
) -> Result<ProbeKeyReport, Error> {
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
    #[cfg(target_os = "android")]
    return _identity.doctor_run_agreement();

    #[cfg(not(target_os = "android"))]
    Ok(AgreementReport {
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
    #[cfg(target_os = "android")]
    return _identity.doctor_pairing_storage();

    #[cfg(not(target_os = "android"))]
    Ok(PairingStorageReport {
        no_backup_storage: false,
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

#[must_use]
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("phone-identity")
        .invoke_handler(tauri::generate_handler![
            doctor_capabilities,
            doctor_create_probe,
            doctor_run_agreement,
            doctor_cleanup,
            doctor_pairing_storage
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
