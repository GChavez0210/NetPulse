mod commands;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub struct AppState {
    pub flood_cancel: Arc<AtomicBool>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            flood_cancel: Arc::new(AtomicBool::new(false)),
        })
        .invoke_handler(tauri::generate_handler![
            commands::ping::ping_run,
            commands::ping::ping_sample,
            commands::flood::flood_start,
            commands::flood::flood_cancel,
            commands::trace::trace_run,
            commands::tcp::tcp_ping,
            commands::tcp::port_scan,
            commands::dns::dns_query,
            commands::dns::dns_validate,
            commands::dns::dns_health,
            commands::dns::dns_dmarc,
            commands::dns::mtr_run,
            commands::whois::whois_lookup,
            commands::oui::mac_lookup,
            commands::settings::settings_read,
            commands::settings::settings_write,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
