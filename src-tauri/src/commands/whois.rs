use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Serialize)]
pub struct WhoisResult {
    pub ok: bool,
    pub query: String,
    pub source: String,
    pub normalized: Option<serde_json::Value>,
    pub raw: Option<String>,
    pub error: Option<String>,
}

/// Returns true if the string is a valid IPv4 address.
fn is_ipv4(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}

/// Returns true if the string is a valid IPv6 address.
fn is_ipv6(s: &str) -> bool {
    s.contains(':') && s.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Perform a raw TCP WHOIS query against host:43.
async fn raw_tcp_whois(server: &str, query: &str) -> Result<String, String> {
    let addr = format!("{server}:43");
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| format!("Connection to {server}:43 timed out"))?
    .map_err(|e| format!("Failed to connect to {server}:43: {e}"))?;

    let request = format!("{query}\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("Write error: {e}"))?;

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    // Distinguish a clean EOF (server finished sending) from a read timeout,
    // read error, or hitting the size cap — all of which mean the response
    // may be incomplete, unlike Ok(Ok(0)) which means it's genuinely done.
    let mut truncated = false;
    loop {
        match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() >= 51_200 {
                    truncated = true;
                    break;
                }
            }
            Ok(Err(_)) => {
                truncated = true;
                break;
            }
            Err(_) => {
                truncated = true;
                break;
            }
        }
    }

    let mut text = String::from_utf8_lossy(&response).to_string();
    if truncated {
        text.push_str(
            "\n\n[NetPulse] Warning: this response may be incomplete — the connection \
             timed out or was cut off before the server finished sending data.\n",
        );
    }
    Ok(text)
}

/// Parse a "refer: server" or "whois: server" line from an IANA response.
fn parse_referral(response: &str) -> Option<String> {
    for line in response.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("refer:") || lower.starts_with("whois:") {
            let server = line
                .splitn(2, ':')
                .nth(1)
                .map(|s| s.trim().to_string());
            if let Some(s) = server {
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }
    None
}

/// Map an RIR WHOIS hostname to its RDAP base URL.
fn whois_to_rdap_base(whois_host: &str) -> Option<&'static str> {
    match whois_host.trim() {
        "whois.arin.net"    => Some("https://rdap.arin.net/registry"),
        "whois.ripe.net"    => Some("https://rdap.ripe.net"),
        "whois.apnic.net"   => Some("https://rdap.apnic.net"),
        "whois.lacnic.net"  => Some("https://rdap.lacnic.net"),
        "whois.afrinic.net" => Some("https://rdap.afrinic.net"),
        _                   => None,
    }
}

/// Handle RDAP lookup for IP addresses, bootstrapping the correct RIR via IANA WHOIS.
async fn rdap_lookup(ip: &str, http_client: &reqwest::Client) -> WhoisResult {
    // Step 1: Ask IANA WHOIS which RIR handles this IP.
    let iana_response = raw_tcp_whois("whois.iana.org", ip)
        .await
        .unwrap_or_default();
    let whois_server = parse_referral(&iana_response)
        .unwrap_or_else(|| "whois.arin.net".to_string());

    // Step 2: Resolve the RDAP base URL for that RIR.
    let rdap_base = match whois_to_rdap_base(&whois_server) {
        Some(base) => base,
        None => {
            return WhoisResult {
                ok: false,
                query: ip.to_string(),
                source: format!("RDAP ({whois_server})"),
                normalized: None,
                raw: Some(iana_response),
                error: Some(format!("No RDAP endpoint known for {whois_server}")),
            };
        }
    };

    // Step 3: Query the RIR RDAP server directly.
    let url = format!("{rdap_base}/ip/{ip}");

    let response = match http_client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return WhoisResult {
                ok: false,
                query: ip.to_string(),
                source: "RDAP".to_string(),
                normalized: None,
                raw: Some(iana_response),
                error: Some(format!("RDAP request failed: {e}")),
            };
        }
    };

    let raw_text = match response.text().await {
        Ok(t) => t,
        Err(e) => {
            return WhoisResult {
                ok: false,
                query: ip.to_string(),
                source: "RDAP".to_string(),
                normalized: None,
                raw: Some(iana_response),
                error: Some(format!("Failed to read RDAP response: {e}")),
            };
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&raw_text) {
        Ok(v) => v,
        Err(e) => {
            return WhoisResult {
                ok: false,
                query: ip.to_string(),
                source: "RDAP".to_string(),
                normalized: None,
                raw: Some(raw_text),
                error: Some(format!("Failed to parse RDAP JSON: {e}")),
            };
        }
    };

    // Extract useful fields
    let name = json
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let country = json
        .get("country")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let r#type = json
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let start_address = json
        .get("startAddress")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let end_address = json
        .get("endAddress")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // cidr from cidr0_cidrs — check v4prefix first, then v6prefix
    let cidr = json
        .get("cidr0_cidrs")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|c| {
            let prefix = c
                .get("v4prefix")
                .or_else(|| c.get("v6prefix"))
                .and_then(|p| p.as_str());
            let len = c.get("length").and_then(|l| l.as_u64());
            match (prefix, len) {
                (Some(p), Some(l)) => Some(format!("{p}/{l}")),
                _ => None,
            }
        })
        .unwrap_or_default();

    // owner from entities vcard (registrant role)
    let owner = json
        .get("entities")
        .and_then(|e| e.as_array())
        .and_then(|arr| {
            arr.iter().find(|e| {
                e.get("roles")
                    .and_then(|r| r.as_array())
                    .map(|roles| roles.iter().any(|r| r.as_str() == Some("registrant")))
                    .unwrap_or(false)
            })
        })
        .and_then(|entity| entity.get("vcardArray"))
        .and_then(|vc| vc.as_array())
        .and_then(|vc| vc.get(1))
        .and_then(|fields| fields.as_array())
        .and_then(|fields| {
            fields.iter().find(|f| {
                f.as_array()
                    .and_then(|fa| fa.first())
                    .and_then(|v| v.as_str())
                    == Some("fn")
            })
        })
        .and_then(|f| f.as_array())
        .and_then(|f| f.last())
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let normalized = serde_json::json!({
        "name": name,
        "country": country,
        "type": r#type,
        "cidr": cidr,
        "owner": owner,
        "start_address": start_address,
        "end_address": end_address,
        "rdap_server": rdap_base,
    });

    WhoisResult {
        ok: true,
        query: ip.to_string(),
        source: "RDAP".to_string(),
        normalized: Some(normalized),
        raw: Some(raw_text),
        error: None,
    }
}

/// Handle raw WHOIS lookup for domain names.
async fn raw_whois_lookup(domain: &str) -> WhoisResult {
    // Step 1: query IANA to find referral
    let iana_response = match raw_tcp_whois("whois.iana.org", domain).await {
        Ok(r) => r,
        Err(e) => {
            return WhoisResult {
                ok: false,
                query: domain.to_string(),
                source: "WHOIS".to_string(),
                normalized: None,
                raw: None,
                error: Some(e),
            };
        }
    };

    let server = parse_referral(&iana_response).unwrap_or_else(|| "whois.iana.org".to_string());

    // Step 2: query the actual WHOIS server
    let source_label = format!("WHOIS ({server})");
    if server == "whois.iana.org" {
        return WhoisResult {
            ok: true,
            query: domain.to_string(),
            source: source_label,
            normalized: None,
            raw: Some(iana_response),
            error: None,
        };
    }

    let response = match raw_tcp_whois(&server, domain).await {
        Ok(r) => r,
        Err(e) => {
            return WhoisResult {
                ok: false,
                query: domain.to_string(),
                source: source_label,
                normalized: None,
                raw: Some(iana_response),
                error: Some(e),
            };
        }
    };

    WhoisResult {
        ok: true,
        query: domain.to_string(),
        source: source_label,
        normalized: None,
        raw: Some(response),
        error: None,
    }
}

#[tauri::command]
pub async fn whois_lookup(
    query: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<WhoisResult, String> {
    if query.is_empty() {
        return Err("Query must not be empty".to_string());
    }

    // Enforce a 2-second minimum gap between WHOIS queries to avoid getting blocked.
    // The mutex is held across the check+sleep+update so two concurrent calls
    // can't both read the same last_ms and both slip through the gap.
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
    {
        let mut last_ms = state.last_whois_ms.lock().await;
        let min_gap_ms = 2_000u64;
        let elapsed = now_ms().saturating_sub(*last_ms);
        if elapsed < min_gap_ms {
            tokio::time::sleep(Duration::from_millis(min_gap_ms - elapsed)).await;
        }
        *last_ms = now_ms();
    }

    if is_ipv4(&query) || is_ipv6(&query) {
        Ok(rdap_lookup(&query, &state.http_client).await)
    } else {
        Ok(raw_whois_lookup(&query).await)
    }
}
