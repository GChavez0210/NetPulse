use serde::Serialize;

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
pub async fn mac_lookup(
    mac: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<MacResult, String> {
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

    let oui_display = format!(
        "{:02X}:{:02X}:{:02X}",
        (oui_int >> 16) & 0xFF,
        (oui_int >> 8) & 0xFF,
        oui_int & 0xFF
    );

    let conn_arc = state.oui_conn.clone();
    let result = tokio::task::spawn_blocking(move || {
        let guard = conn_arc
            .lock()
            .map_err(|_| "OUI database lock is poisoned".to_string())?;
        let conn = guard
            .as_ref()
            .ok_or("OUI database is not available (startup initialization failed)".to_string())?;

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
