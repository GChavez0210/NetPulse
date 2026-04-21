use tauri::Manager;

#[tauri::command]
pub async fn settings_read(app_handle: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))?;

    let settings_path = data_dir.join("settings.json");

    if !settings_path.exists() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }

    let contents = tokio::fs::read_to_string(&settings_path)
        .await
        .map_err(|e| format!("Failed to read settings.json: {e}"))?;

    let value: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse settings.json: {e}"))?;

    Ok(value)
}

#[tauri::command]
pub async fn settings_write(
    app_handle: tauri::AppHandle,
    data: serde_json::Value,
) -> Result<(), String> {
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))?;

    tokio::fs::create_dir_all(&data_dir)
        .await
        .map_err(|e| format!("Failed to create app data directory: {e}"))?;

    let settings_path = data_dir.join("settings.json");

    let pretty = serde_json::to_string_pretty(&data)
        .map_err(|e| format!("Failed to serialize settings: {e}"))?;

    tokio::fs::write(&settings_path, pretty.as_bytes())
        .await
        .map_err(|e| format!("Failed to write settings.json: {e}"))?;

    Ok(())
}
