use serde::Serialize;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::Emitter;
use tokio::process::Command;

#[derive(Serialize, Clone)]
pub struct FloodSample {
    pub seq: u32,
    pub timeout: bool,
    pub rtt_ms: Option<f64>,
    pub timestamp: String,
}

#[derive(Serialize, Clone)]
pub struct FloodSummary {
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub avg_rtt_ms: Option<f64>,
    pub min_rtt_ms: Option<f64>,
    pub max_rtt_ms: Option<f64>,
    pub p95_rtt_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss_streak_max: u32,
    pub status: String,
}

#[derive(Serialize)]
pub struct FloodStartResult {
    pub ok: bool,
    pub status: String,
}

/// Format current local time as "HH:MM:SS.mmm"
fn format_time() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let total_secs = now.as_secs();
    let millis = now.subsec_millis();
    // Local time offset is not trivial without external crates; use UTC for now
    let secs_in_day = total_secs % 86400;
    let h = secs_in_day / 3600;
    let m = (secs_in_day % 3600) / 60;
    let s = secs_in_day % 60;
    format!("{h:02}:{m:02}:{s:02}.{millis:03}")
}

/// Parse RTT from a single ping reply line (same logic as ping.rs helper).
fn parse_single_rtt(output: &str) -> Option<f64> {
    if output.contains("time<1ms") || output.contains("time<1 ms") {
        return Some(0.5);
    }
    if let Some(pos) = output.find("time=") {
        let after = &output[pos + 5..];
        let num_str: String = after
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if let Ok(v) = num_str.parse::<f64>() {
            return Some(v);
        }
    }
    None
}

/// Spawn a single ping and return the RTT if replied.
async fn do_single_icmp_ping(host: &str) -> Option<f64> {
    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = Command::new("ping");
        c.args(["-n", "1", "-w", "1000", host]);
        c
    } else {
        let mut c = Command::new("ping");
        c.args(["-c", "1", "-W", "1", host]);
        c
    };
    cmd.kill_on_drop(true);

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(_) => return None,
    };

    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    parse_single_rtt(&text)
}

fn build_flood_summary(
    rtts: &[f64],
    sent: u32,
    received: u32,
    max_streak: u32,
    status: &str,
) -> FloodSummary {
    let loss_pct = if sent == 0 {
        0.0
    } else {
        (sent - received) as f64 / sent as f64 * 100.0
    };

    if rtts.is_empty() {
        return FloodSummary {
            sent,
            received,
            loss_pct,
            avg_rtt_ms: None,
            min_rtt_ms: None,
            max_rtt_ms: None,
            p95_rtt_ms: None,
            jitter_ms: None,
            loss_streak_max: max_streak,
            status: status.to_string(),
        };
    }

    let avg_rtt_ms = Some(rtts.iter().sum::<f64>() / rtts.len() as f64);
    let min_rtt_ms = rtts.iter().cloned().reduce(f64::min);
    let max_rtt_ms = rtts.iter().cloned().reduce(f64::max);

    let p95_rtt_ms = {
        let mut sorted = rtts.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((0.95 * sorted.len() as f64).ceil() as usize).saturating_sub(1);
        Some(sorted[idx.min(sorted.len() - 1)])
    };

    let jitter_ms = if rtts.len() < 2 {
        None
    } else {
        let diffs: Vec<f64> = rtts
            .windows(2)
            .map(|w| (w[1] - w[0]).abs())
            .collect();
        Some(diffs.iter().sum::<f64>() / diffs.len() as f64)
    };

    FloodSummary {
        sent,
        received,
        loss_pct,
        avg_rtt_ms,
        min_rtt_ms,
        max_rtt_ms,
        p95_rtt_ms,
        jitter_ms,
        loss_streak_max: max_streak,
        status: status.to_string(),
    }
}

#[tauri::command]
pub async fn flood_start(
    host: String,
    mode: String,
    count: u32,
    state: tauri::State<'_, crate::AppState>,
    app_handle: tauri::AppHandle,
) -> Result<FloodStartResult, String> {
    // Validate inputs
    if host.is_empty() || host.len() > 253 {
        return Err("Invalid host: must be 1–253 characters".to_string());
    }
    if count != 100 && count != 1000 {
        return Err("Count must be 100 or 1000".to_string());
    }
    let _ = mode; // only ICMP supported for now

    // Reset cancel flag
    state.flood_cancel.store(false, Ordering::SeqCst);
    let cancel_flag = state.flood_cancel.clone();

    tokio::spawn(async move {
        // Emit starting status
        let _ = app_handle.emit(
            "ping:flood-status",
            serde_json::json!({ "status": "running", "message": "Starting flood test..." }),
        );

        let mut rtts: Vec<f64> = Vec::new();
        let mut received: u32 = 0;
        let mut loss_streak: u32 = 0;
        let mut max_streak: u32 = 0;

        for seq in 1..=count {
            if cancel_flag.load(Ordering::SeqCst) {
                let _ = app_handle.emit(
                    "ping:flood-status",
                    serde_json::json!({ "status": "cancelled" }),
                );
                break;
            }

            let rtt = do_single_icmp_ping(&host).await;
            let timeout = rtt.is_none();

            if let Some(r) = rtt {
                rtts.push(r);
                received += 1;
                loss_streak = 0;
            } else {
                loss_streak += 1;
                if loss_streak > max_streak {
                    max_streak = loss_streak;
                }
            }

            let sample = FloodSample {
                seq,
                timeout,
                rtt_ms: rtt,
                timestamp: format_time(),
            };

            let _ = app_handle.emit("ping:flood-sample", &sample);

            // Adaptive sleep
            let delay_ms = match rtt {
                Some(r) if r < 20.0 => 200,
                Some(r) if r < 100.0 => 300,
                _ => 500,
            };
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        let summary = build_flood_summary(&rtts, count, received, max_streak, "done");
        let _ = app_handle.emit("ping:flood-done", serde_json::json!({ "summary": summary }));
        let _ = app_handle.emit(
            "ping:flood-status",
            serde_json::json!({ "status": "done" }),
        );
    });

    Ok(FloodStartResult {
        ok: true,
        status: "running".to_string(),
    })
}

#[tauri::command]
pub async fn flood_cancel(
    state: tauri::State<'_, crate::AppState>,
) -> Result<(), String> {
    state.flood_cancel.store(true, Ordering::SeqCst);
    Ok(())
}
