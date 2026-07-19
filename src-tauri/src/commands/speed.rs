use futures::StreamExt;
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Serialize)]
pub struct SpeedTestResult {
    pub ok: bool,
    pub download_mbps: Option<f64>,
    pub upload_mbps: Option<f64>,
    pub latency_ms: Option<f64>,
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub server_colo: Option<String>,
    pub server_country: Option<String>,
    pub raw_output: String,
    pub error: Option<String>,
}

// A single TCP stream is capped by window-size / RTT and can't saturate fast
// links no matter how long it runs — Ookla, Fast.com, and Cloudflare's own
// frontend all measure with several parallel connections instead, so we do
// the same rather than just running one stream longer.
const PARALLEL_STREAMS: usize = 4;

// Cloudflare rate-limits __down based on aggregate concurrent bytes in flight
// across a client's connections, not just a single request's size — confirmed
// empirically: 4 streams x 8MB (32MB aggregate) is reliably safe even sustained
// over several seconds, while 4x15MB (60MB aggregate) or even 2x20MB (40MB
// aggregate) gets rejected with 403/429. Stay comfortably under that.
const DOWNLOAD_CHUNK_BYTES: u64 = 8 * 1024 * 1024;
const DOWNLOAD_MAX_SECS: u64 = 8;
const UPLOAD_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const UPLOAD_MAX_SECS: u64 = 8;

fn fail(msg: impl Into<String>) -> SpeedTestResult {
    SpeedTestResult {
        ok: false,
        download_mbps: None,
        upload_mbps: None,
        latency_ms: None,
        download_bytes: 0,
        upload_bytes: 0,
        server_colo: None,
        server_country: None,
        raw_output: String::new(),
        error: Some(msg.into()),
    }
}

/// Cloudflare's `server-timing` response header carries the TCP-level RTT
/// observed by their edge for this connection, e.g.
/// `cfL4;desc="?proto=TCP&rtt=26415&min_rtt=23608&..."` (microseconds).
fn parse_rtt_ms(header: Option<&reqwest::header::HeaderValue>) -> Option<f64> {
    let val = header?.to_str().ok()?;
    let idx = val.find("rtt=")?;
    let digits: String = val[idx + 4..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<f64>().ok().map(|micros| micros / 1000.0)
}

fn format_mbps(v: Option<f64>) -> String {
    v.map(|m| format!("{m:.1} Mbps")).unwrap_or_else(|| "-".to_string())
}

struct DownloadStreamResult {
    bytes: u64,
    latency_ms: Option<f64>,
    colo: Option<String>,
    country: Option<String>,
    error: Option<String>,
}

/// Runs one download stream: repeatedly requests `DOWNLOAD_CHUNK_BYTES` and
/// reads it until the shared deadline passes, reusing the pooled keep-alive
/// connection across requests within this stream.
async fn run_download_stream(client: reqwest::Client, url: String, deadline: Instant) -> DownloadStreamResult {
    let mut bytes: u64 = 0;
    let mut latency_ms = None;
    let mut colo = None;
    let mut country = None;
    let mut error = None;

    'requests: loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }

        let resp = match tokio::time::timeout(remaining, client.get(&url).send()).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                if bytes == 0 {
                    error = Some(format!("Download request failed: {e}"));
                }
                break;
            }
            Err(_) => break,
        };

        if !resp.status().is_success() {
            if bytes == 0 {
                error = Some(format!("Download request returned HTTP {}", resp.status()));
            }
            break;
        }

        if latency_ms.is_none() {
            latency_ms = parse_rtt_ms(resp.headers().get("server-timing"));
            colo = resp.headers().get("colo").and_then(|v| v.to_str().ok()).map(String::from);
            country = resp.headers().get("country").and_then(|v| v.to_str().ok()).map(String::from);
        }

        let mut stream = resp.bytes_stream();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break 'requests;
            }
            match tokio::time::timeout(remaining, stream.next()).await {
                Ok(Some(Ok(chunk))) => bytes += chunk.len() as u64,
                // This chunk's stream ended/errored — loop back for another request.
                Ok(Some(Err(_))) | Ok(None) => break,
                // Deadline hit mid-read — stop entirely, keep what we have.
                Err(_) => break 'requests,
            }
        }
    }

    DownloadStreamResult { bytes, latency_ms, colo, country, error }
}

/// Runs one upload stream: repeatedly POSTs a fixed-size body until the
/// shared deadline passes.
async fn run_upload_stream(client: reqwest::Client, deadline: Instant) -> u64 {
    let mut bytes: u64 = 0;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let body = vec![0u8; UPLOAD_CHUNK_BYTES];
        match tokio::time::timeout(
            remaining,
            client.post("https://speed.cloudflare.com/__up").body(body).send(),
        )
        .await
        {
            Ok(Ok(r)) if r.status().is_success() => bytes += UPLOAD_CHUNK_BYTES as u64,
            _ => break,
        }
    }
    bytes
}

/// Runs a download + upload throughput test against Cloudflare's public,
/// keyless speed-test backend (the same endpoints speed.cloudflare.com uses),
/// using several parallel streams per phase to avoid under-reporting fast
/// links that a single TCP stream can't saturate.
#[tauri::command]
pub async fn speed_test(state: tauri::State<'_, crate::AppState>) -> Result<SpeedTestResult, String> {
    let client = state.http_client.clone();

    let download_url = format!("https://speed.cloudflare.com/__down?bytes={DOWNLOAD_CHUNK_BYTES}");
    let dl_start = Instant::now();
    let dl_deadline = dl_start + Duration::from_secs(DOWNLOAD_MAX_SECS);

    let download_handles: Vec<_> = (0..PARALLEL_STREAMS)
        .map(|_| tokio::spawn(run_download_stream(client.clone(), download_url.clone(), dl_deadline)))
        .collect();

    let mut download_bytes: u64 = 0;
    let mut latency_ms: Option<f64> = None;
    let mut server_colo: Option<String> = None;
    let mut server_country: Option<String> = None;
    let mut first_error: Option<String> = None;
    for handle in download_handles {
        if let Ok(r) = handle.await {
            download_bytes += r.bytes;
            if latency_ms.is_none() && r.latency_ms.is_some() {
                latency_ms = r.latency_ms;
                server_colo = r.colo;
                server_country = r.country;
            }
            if first_error.is_none() && r.error.is_some() {
                first_error = r.error;
            }
        }
    }
    let download_secs = dl_start.elapsed().as_secs_f64().max(0.05);

    if download_bytes == 0 {
        return Ok(fail(first_error.unwrap_or_else(|| "Download test received no data".to_string())));
    }
    let download_mbps = (download_bytes as f64 * 8.0) / download_secs / 1_000_000.0;

    let up_start = Instant::now();
    let up_deadline = up_start + Duration::from_secs(UPLOAD_MAX_SECS);
    let upload_handles: Vec<_> = (0..PARALLEL_STREAMS)
        .map(|_| tokio::spawn(run_upload_stream(client.clone(), up_deadline)))
        .collect();

    let mut upload_bytes: u64 = 0;
    for handle in upload_handles {
        if let Ok(bytes) = handle.await {
            upload_bytes += bytes;
        }
    }
    let upload_secs = up_start.elapsed().as_secs_f64().max(0.05);
    let upload_mbps = if upload_bytes > 0 {
        Some((upload_bytes as f64 * 8.0) / upload_secs / 1_000_000.0)
    } else {
        None
    };

    let mut lines = Vec::new();
    if let Some(l) = latency_ms {
        lines.push(format!("Latency:   {l:.1} ms"));
    }
    if let (Some(colo), Some(country)) = (&server_colo, &server_country) {
        lines.push(format!("Server:    Cloudflare {colo} ({country})"));
    }
    lines.push(format!(
        "Download:  {}  ({:.1} MB across {PARALLEL_STREAMS} streams in {download_secs:.1}s)",
        format_mbps(Some(download_mbps)),
        download_bytes as f64 / 1_048_576.0
    ));
    lines.push(if let Some(mbps) = upload_mbps {
        format!(
            "Upload:    {}  ({:.1} MB across {PARALLEL_STREAMS} streams in {upload_secs:.1}s)",
            format_mbps(Some(mbps)),
            upload_bytes as f64 / 1_048_576.0
        )
    } else {
        "Upload:    - (upload test failed)".to_string()
    });

    Ok(SpeedTestResult {
        ok: true,
        download_mbps: Some(download_mbps),
        upload_mbps,
        latency_ms,
        download_bytes,
        upload_bytes,
        server_colo,
        server_country,
        raw_output: lines.join("\n"),
        error: None,
    })
}
