use age_plugin_phone_protocol::PROTOCOL_VERSION;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectStatus {
    stage: &'static str,
    protocol_version: u16,
    qr_transport: &'static str,
    ble_transport: &'static str,
    key_backend: &'static str,
}

#[tauri::command]
fn project_status() -> ProjectStatus {
    ProjectStatus {
        stage: "scaffold-only",
        protocol_version: PROTOCOL_VERSION,
        qr_transport: "not implemented",
        ble_transport: "not implemented",
        key_backend: "not implemented",
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
        .invoke_handler(tauri::generate_handler![project_status])
        .run(tauri::generate_context!())
        .expect("error while running age-plugin-phone mobile application");
}
