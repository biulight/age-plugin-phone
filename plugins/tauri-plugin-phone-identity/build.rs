const COMMANDS: &[&str] = &[
    "doctor_capabilities",
    "doctor_identity_custody",
    "doctor_create_probe",
    "doctor_run_agreement",
    "doctor_cleanup",
    "doctor_pairing_storage",
    "scan_pairing_offer",
    "pair_phone",
    "unwrap_phone",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .try_build()
        .expect("failed to build phone identity plugin");
}
