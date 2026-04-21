use serde::Serialize;
use tauri::Manager;

#[derive(Serialize)]
pub struct MacResult {
    pub ok: bool,
    pub mac: String,
    pub oui: String,
    pub vendor: Option<String>,
    pub raw_output: String,
    pub error: Option<String>,
}

#[tauri::command]
pub async fn mac_lookup(mac: String, app_handle: tauri::AppHandle) -> Result<MacResult, String> {
    // Strip non-hex characters
    let hex_only: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();

    if hex_only.len() < 6 {
        return Ok(MacResult {
            ok: false,
            mac: mac.clone(),
            oui: String::new(),
            vendor: None,
            raw_output: String::new(),
            error: Some("MAC address must have at least 6 hex digits".to_string()),
        });
    }

    let oui_hex = hex_only[..6].to_string();

    // Parse OUI hex string to u64
    let oui_int = match u64::from_str_radix(&oui_hex, 16) {
        Ok(v) => v,
        Err(e) => {
            return Ok(MacResult {
                ok: false,
                mac: mac.clone(),
                oui: oui_hex,
                vendor: None,
                raw_output: String::new(),
                error: Some(format!("Failed to parse OUI: {e}")),
            });
        }
    };

    // Resolve database path from app resources
    let db_path = app_handle
        .path()
        .resolve("oui-database.sqlite", tauri::path::BaseDirectory::Resource)
        .map_err(|e| format!("Failed to resolve resource path: {e}"))?;

    let oui_display = format!(
        "{:02X}:{:02X}:{:02X}",
        (oui_int >> 16) & 0xFF,
        (oui_int >> 8) & 0xFF,
        oui_int & 0xFF
    );

    let result = tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| format!("Failed to open database: {e}"))?;

        let mut stmt = conn
            .prepare("SELECT vendor FROM vendordb WHERE mac = ?1")
            .map_err(|e| format!("Failed to prepare query: {e}"))?;

        let vendor: Option<String> = stmt
            .query_row(rusqlite::params![oui_int], |row| row.get(0))
            .ok();

        Ok::<Option<String>, String>(vendor)
    })
    .await
    .map_err(|e| format!("Database task failed: {e}"))??;

    let raw_output = match &result {
        Some(v) => format!("OUI: {oui_display}\nVendor: {v}"),
        None => format!("OUI: {oui_display}\nVendor: Unknown"),
    };

    Ok(MacResult {
        ok: true,
        mac,
        oui: oui_display,
        vendor: result,
        raw_output,
        error: None,
    })
}
