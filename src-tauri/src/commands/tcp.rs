use serde::Serialize;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

#[derive(Serialize)]
pub struct TcpPingResult {
    pub ok: bool,
    pub status: String, // "open", "closed", "filtered", "error"
    pub rtt_ms: Option<f64>,
    pub port: u16,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct PortEntry {
    pub port: u16,
    pub status: String,
    pub rtt_ms: Option<f64>,
}

#[derive(Serialize)]
pub struct PortScanResult {
    pub ok: bool,
    pub host: String,
    pub ports: Vec<PortEntry>,
    pub error: Option<String>,
}

async fn probe_port(host: &str, port: u16, timeout_ms: u64) -> TcpPingResult {
    let addr = format!("{host}:{port}");
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => {
            let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
            TcpPingResult {
                ok: true,
                status: "open".to_string(),
                rtt_ms: Some(rtt_ms),
                port,
                error: None,
            }
        }
        Ok(Err(e)) => {
            // Check for connection refused
            let status = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                "closed"
            } else {
                "error"
            };
            TcpPingResult {
                ok: false,
                status: status.to_string(),
                rtt_ms: None,
                port,
                error: Some(e.to_string()),
            }
        }
        Err(_) => {
            // Timeout → filtered
            TcpPingResult {
                ok: false,
                status: "filtered".to_string(),
                rtt_ms: None,
                port,
                error: Some("Connection timed out".to_string()),
            }
        }
    }
}

#[tauri::command]
pub async fn tcp_ping(host: String, port: u16, timeout_ms: u64) -> Result<TcpPingResult, String> {
    Ok(probe_port(&host, port, timeout_ms).await)
}

#[tauri::command]
pub async fn port_scan(
    host: String,
    ports: Vec<u16>,
    timeout_ms: u64,
) -> Result<PortScanResult, String> {
    if host.is_empty() {
        return Err("Host must not be empty".to_string());
    }

    // Deduplicate and cap at 32
    let mut deduped: Vec<u16> = {
        let mut seen = std::collections::HashSet::new();
        ports.into_iter().filter(|p| seen.insert(*p)).collect()
    };
    deduped.truncate(32);

    // Run all probes concurrently
    let futures: Vec<_> = deduped
        .iter()
        .map(|&port| {
            let h = host.clone();
            async move {
                let result = probe_port(&h, port, timeout_ms).await;
                PortEntry {
                    port: result.port,
                    status: result.status,
                    rtt_ms: result.rtt_ms,
                }
            }
        })
        .collect();

    let entries = futures::future::join_all(futures).await;

    Ok(PortScanResult {
        ok: true,
        host,
        ports: entries,
        error: None,
    })
}
