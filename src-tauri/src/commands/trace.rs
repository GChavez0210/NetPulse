use serde::Serialize;
use std::time::Duration;
use tokio::process::Command;

#[derive(Serialize)]
pub struct TraceResult {
    pub ok: bool,
    pub output: String,
    pub error: Option<String>,
}

#[tauri::command]
pub async fn trace_run(host: String) -> Result<TraceResult, String> {
    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = Command::new("tracert");
        c.args(["-h", "20", &host]);
        c
    } else {
        let mut c = Command::new("traceroute");
        c.args(["-m", "20", &host]);
        c
    };

    cmd.kill_on_drop(true);

    let result = tokio::time::timeout(Duration::from_secs(30), cmd.output()).await;

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = format!("{stdout}{stderr}");
            Ok(TraceResult {
                ok: true,
                output: combined,
                error: None,
            })
        }
        Ok(Err(e)) => Ok(TraceResult {
            ok: false,
            output: String::new(),
            error: Some(format!("Failed to spawn traceroute: {e}")),
        }),
        Err(_) => Ok(TraceResult {
            ok: false,
            output: String::new(),
            error: Some("Traceroute timed out after 30 seconds".to_string()),
        }),
    }
}
