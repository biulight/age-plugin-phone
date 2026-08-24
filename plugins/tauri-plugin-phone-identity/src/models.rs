use serde::{Deserialize, Serialize};

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
