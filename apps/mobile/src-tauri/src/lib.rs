use age_plugin_phone_protocol::PROTOCOL_VERSION;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectStatus {
    stage: &'static str,
    protocol_version: u16,
    qr_transport: &'static str,
    usb_transport: &'static str,
    wifi_transport: &'static str,
    ble_transport: &'static str,
    key_backend: &'static str,
    doctor_enabled: bool,
}

#[tauri::command]
fn project_status() -> ProjectStatus {
    ProjectStatus {
        stage: "windows-android-product-alpha",
        protocol_version: PROTOCOL_VERSION,
        qr_transport: "native bidirectional pairing prototype",
        usb_transport: "Developer USB ADB reverse Alpha",
        wifi_transport: "opt-in foreground auto-listen PoC",
        ble_transport: "not implemented",
        key_backend: "StrongBox dual-key custody validated",
        doctor_enabled: cfg!(debug_assertions),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Starts the Tauri mobile application.
///
/// # Panics
///
/// Panics if Tauri cannot create or run the application context.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_phone_identity::init())
        .invoke_handler(tauri::generate_handler![project_status])
        .run(tauri::generate_context!())
        .expect("error while running age-plugin-phone mobile application");
}
