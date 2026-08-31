use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedDesktopSummary {
    pub handle: String,
    pub display_label: String,
    pub transcript_fingerprint: String,
    pub deletion_pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityStatusReport {
    pub state: String,
    pub public_recipient: Option<String>,
    pub paired_desktops: Vec<PairedDesktopSummary>,
    pub recovery_required: bool,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleReport {
    pub completed: bool,
    pub state: String,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WifiAutoListenStatusReport {
    pub enabled: bool,
    pub state: String,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
// The doctor intentionally reports each independently audited platform claim.
#[allow(clippy::struct_excessive_bools)]
pub struct CapabilityReport {
    pub android_release: String,
    pub api_level: u32,
    pub sdk_extension_level: u32,
    pub strongbox_feature: bool,
    pub strong_biometric: String,
    pub secure_lock_screen: bool,
    pub key_agreement_crypto_object: bool,
    pub leftover_probe_key: bool,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct IdentityCustodyReport {
    pub no_backup_storage: bool,
    pub identity_strong_box: bool,
    pub identity_agree_only: bool,
    pub identity_auth_per_use: bool,
    pub identity_biometric_strong: bool,
    pub signing_strong_box: bool,
    pub signing_purpose_sign_only: bool,
    pub signing_no_user_auth: bool,
    pub private_keys_non_exportable: bool,
    pub keys_distinct: bool,
    pub metadata_bound: bool,
    pub reopened: bool,
    pub duplicate_rejected: bool,
    pub preparing_recovered: bool,
    pub cleanup_complete: bool,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
// These booleans mirror distinct KeyInfo assertions; collapsing them would hide evidence.
#[allow(clippy::struct_excessive_bools)]
pub struct ProbeKeyReport {
    pub generated: bool,
    pub security_level: String,
    pub origin_generated: bool,
    pub purpose_agree_key: bool,
    pub user_authentication_required: bool,
    pub auth_per_use: bool,
    pub authentication_type: String,
    pub auth_enforced_by_secure_hardware: bool,
    pub private_key_format_is_null: bool,
    pub private_key_encoded_is_null: bool,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgreementReport {
    pub recipient_protocol: String,
    pub authenticated: bool,
    pub agreement_match: bool,
    pub response_envelope_match: bool,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupReport {
    pub probe_key_existed: bool,
    pub probe_key_deleted: bool,
    pub probe_key_absent_after_delete: bool,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct PairingStorageReport {
    pub no_backup_storage: bool,
    pub qr_fragmented: bool,
    pub qr_out_of_order_reassembled: bool,
    pub qr_corruption_rejected: bool,
    pub qr_timeout_rejected: bool,
    pub transcript_verified: bool,
    pub fingerprint_mismatch_rejected: bool,
    pub cancellation_rejected: bool,
    pub confirmation_committed: bool,
    pub duplicate_confirmation_rejected: bool,
    pub atomic_state_created: bool,
    pub verified_before_consume: bool,
    pub replay_rejected_after_reopen: bool,
    pub wrong_scope_rejected: bool,
    pub missing_state_rejected_after_delete: bool,
    pub cleanup_complete: bool,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingOfferScanReport {
    pub scanner_started: bool,
    pub message_verified: bool,
    pub desktop_label: Option<String>,
    pub offer_fingerprint: Option<String>,
    pub frames_accepted: u32,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhonePairingReport {
    pub paired: bool,
    pub desktop_label: Option<String>,
    pub transcript_fingerprint: Option<String>,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhoneUnwrapReport {
    pub authenticated: bool,
    pub response_displayed: bool,
    pub request_fingerprint: Option<String>,
    pub error_category: Option<String>,
}
