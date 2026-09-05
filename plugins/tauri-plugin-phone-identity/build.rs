const COMMANDS: &[&str] = &[
    "doctor_capabilities",
    "doctor_identity_custody",
    "doctor_create_probe",
    "doctor_run_agreement",
    "doctor_cleanup",
    "doctor_pairing_storage",
    "scan_pairing_offer",
    "pair_phone",
    "pair_phone_usb",
    "pair_phone_wifi",
    "unwrap_phone",
    "set_wifi_auto_listen",
    "wifi_auto_listen_status",
    "identity_status",
    "provision_identity",
    "revoke_pairing",
    "delete_identity",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
