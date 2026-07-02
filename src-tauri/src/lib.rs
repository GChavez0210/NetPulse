mod commands;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tauri::Manager;

pub struct AppState {
    pub flood_cancel: Arc<AtomicBool>,
    /// Set while a flood job is active so a second flood_start can't spawn a
    /// concurrent job that would race the single shared cancel flag.
    pub flood_running: Arc<AtomicBool>,
    /// Shared SQLite connection for OUI MAC lookups (initialized in setup).
    pub oui_conn: Arc<std::sync::Mutex<Option<rusqlite::Connection>>>,
    /// Unix-epoch milliseconds of the last WHOIS query (for rate limiting).
    /// Held across the throttle check+sleep+update so concurrent calls can't
    /// both read a stale timestamp and bypass the gap.
    pub last_whois_ms: Arc<tokio::sync::Mutex<u64>>,
    /// Lazily-built, shared DNS resolvers (system/Google/Cloudflare) reused
    /// across dns_query/dns_validate/dns_health/dns_dmarc/dnsbl_check instead
    /// of rebuilding a resolver (and losing its lookup cache) on every call.
    pub dns_resolvers: Arc<tokio::sync::OnceCell<commands::dns::DnsResolvers>>,
    /// Shared reqwest client reused by simple single-shot HTTP callers
    /// (GeoIP, RDAP) instead of paying connection-pool/TLS setup per call.
    pub http_client: reqwest::Client,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            flood_cancel: Arc::new(AtomicBool::new(false)),
            flood_running: Arc::new(AtomicBool::new(false)),
            oui_conn: Arc::new(std::sync::Mutex::new(None)),
            last_whois_ms: Arc::new(tokio::sync::Mutex::new(0)),
            dns_resolvers: Arc::new(tokio::sync::OnceCell::new()),
            http_client: reqwest::Client::new(),
        })
        .setup(|app| {
            // Open the OUI SQLite database once at startup and keep it in AppState.
            // Clone the Arc first so the State guard drops before we lock the Mutex.
            let oui_conn = app.state::<AppState>().oui_conn.clone();
            match app
                .path()
                .resolve("oui-database.sqlite", tauri::path::BaseDirectory::Resource)
            {
                Ok(db_path) => {
                    eprintln!("[setup] OUI database path: {}", db_path.display());
                    if !db_path.exists() {
                        eprintln!("[setup] OUI database file not found at that path");
                    } else {
                        match rusqlite::Connection::open_with_flags(
                            &db_path,
                            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                        ) {
                            Ok(conn) => {
                                eprintln!("[setup] OUI database opened successfully");
                                if let Ok(mut guard) = oui_conn.lock() {
                                    *guard = Some(conn);
                                }
                            }
                            Err(e) => eprintln!("[setup] Failed to open OUI database: {e}"),
                        }
                    }
                }
                Err(e) => eprintln!("[setup] Could not resolve OUI database path: {e}"),
            }
            Ok(())
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
            commands::dnsbl::dnsbl_check,
            commands::whois::whois_lookup,
            commands::oui::mac_lookup,
            commands::geoip::geoip_lookup,
            commands::settings::settings_read,
            commands::settings::settings_write,
            commands::recon::ssl_inspect,
            commands::recon::http_headers,
            commands::recon::subdomains_lookup,
            commands::recon::tech_detect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
