const COMMANDS: &[&str] = &[
    "doctor_capabilities",
    "doctor_create_probe",
    "doctor_run_agreement",
    "doctor_cleanup",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .try_build()
        .expect("failed to build phone identity plugin");
}
