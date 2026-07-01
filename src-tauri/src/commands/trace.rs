use serde::Serialize;
use std::time::Duration;
use tokio::process::Command;

use super::validation::validate_host;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Serialize)]
pub struct TraceResult {
    pub ok: bool,
    pub output: String,
    pub error: Option<String>,
}

#[tauri::command]
pub async fn trace_run(host: String) -> Result<TraceResult, String> {
    validate_host(&host)?;

    let mut cmd = if cfg!(target_os = "windows") {
        // cmd /c gives tracert a proper console context from a GUI (windowless) process.
        // -w 2000 caps per-hop wait to 2 s → 20 hops × 2 s = 40 s max, under the 60 s limit.
        let mut c = Command::new("cmd");
        c.args(["/c", "tracert", "-d", "-h", "20", "-w", "1000", &host]);
        c
    } else {
        let mut c = Command::new("traceroute");
        c.args(["-m", "20", &host]);
        c
    };

    cmd.kill_on_drop(true);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let result = tokio::time::timeout(Duration::from_secs(90), cmd.output()).await;

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = format!("{stdout}{stderr}");
            eprintln!("[trace] exit={} stdout={}b stderr={}b", output.status, stdout.len(), stderr.len());
            Ok(TraceResult {
                ok: true,
                output: combined,
                error: None,
            })
        }
        Ok(Err(e)) => {
            eprintln!("[trace] spawn error: {e}");
            Ok(TraceResult {
                ok: false,
                output: String::new(),
                error: Some(format!("Failed to spawn: {e}")),
            })
        }
        Err(_) => {
            eprintln!("[trace] timed out after 60 s");
            Ok(TraceResult {
                ok: false,
                output: String::new(),
                error: Some("Traceroute timed out after 90 seconds".to_string()),
            })
        }
    }
}
