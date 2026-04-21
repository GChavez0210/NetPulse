use serde::Serialize;
use tokio::process::Command;

#[derive(Serialize)]
pub struct PingResult {
    pub ok: bool,
    pub host: String,
    pub latency_ms: Option<f64>,
    pub output: String,
    pub error: Option<String>,
}

/// Parse a single-reply RTT from ping output (used by ping_sample and flood helper).
/// Returns Some(ms) if a valid time was found, None if timeout.
fn parse_single_rtt(output: &str) -> Option<f64> {
    // Windows "time<1ms" → 0.5
    if output.contains("time<1ms") || output.contains("time<1 ms") {
        return Some(0.5);
    }
    // Windows "time=14ms" or "time=14 ms"  / Unix "time=1.234 ms"
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

/// Parse the average RTT from a multi-ping summary block.
fn parse_avg_rtt(output: &str) -> Option<f64> {
    // Windows: "Average = 14ms"
    for line in output.lines() {
        let line = line.trim();
        if line.to_lowercase().contains("average") && line.contains('=') {
            if let Some(pos) = line.rfind('=') {
                let after = line[pos + 1..].trim();
                let num_str: String = after
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if let Ok(v) = num_str.parse::<f64>() {
                    return Some(v);
                }
            }
        }
        // Unix: "rtt min/avg/max/mdev = 1.1/2.2/3.3/0.4 ms"
        if line.starts_with("rtt ") && line.contains('/') {
            if let Some(eq) = line.find('=') {
                let values = line[eq + 1..].trim();
                let parts: Vec<&str> = values.split('/').collect();
                if parts.len() >= 2 {
                    let avg_str: String = parts[1]
                        .trim()
                        .chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '.')
                        .collect();
                    if let Ok(v) = avg_str.parse::<f64>() {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

/// Returns true if the output indicates at least one reply was received.
fn has_reply(output: &str) -> bool {
    if cfg!(target_os = "windows") {
        output.contains("Reply from") || output.contains("time=") || output.contains("time<1ms")
    } else {
        output.contains("time=") && !output.contains("100% packet loss")
    }
}

#[tauri::command]
pub async fn ping_run(host: String) -> Result<PingResult, String> {
    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = Command::new("ping");
        c.args(["-n", "4", &host]);
        c
    } else {
        let mut c = Command::new("ping");
        c.args(["-c", "4", &host]);
        c
    };

    cmd.kill_on_drop(true);

    let output = cmd
        .output()
        .await
        .map_err(|e| format!("Failed to spawn ping: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    let ok = has_reply(&combined);
    let latency_ms = if ok { parse_avg_rtt(&combined) } else { None };

    Ok(PingResult {
        ok,
        host,
        latency_ms,
        output: combined,
        error: if ok { None } else { Some("No reply received".to_string()) },
    })
}

#[tauri::command]
pub async fn ping_sample(
    host: String,
    packet_size: Option<u32>,
    dont_fragment: Option<bool>,
) -> Result<PingResult, String> {
    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = Command::new("ping");
        c.args(["-n", "1", "-w", "1000"]);
        if dont_fragment.unwrap_or(false) {
            c.arg("-f");
        }
        if let Some(size) = packet_size {
            c.args(["-l", &size.to_string()]);
        }
        c.arg(&host);
        c
    } else {
        let mut c = Command::new("ping");
        c.args(["-c", "1", "-W", "1"]);
        if let Some(size) = packet_size {
            c.args(["-s", &size.to_string()]);
        }
        if dont_fragment.unwrap_or(false) {
            c.args(["-M", "do"]);
        }
        c.arg(&host);
        c
    };

    cmd.kill_on_drop(true);

    let output = cmd
        .output()
        .await
        .map_err(|e| format!("Failed to spawn ping: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    let rtt = parse_single_rtt(&combined);
    let ok = rtt.is_some();

    Ok(PingResult {
        ok,
        host,
        latency_ms: rtt,
        output: combined,
        error: if ok { None } else { Some("Request timed out".to_string()) },
    })
}
