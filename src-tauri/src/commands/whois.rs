use serde::Serialize;
use std::time::Duration;
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

/// Returns true if the string looks like an IPv4 address.
fn is_ipv4(s: &str) -> bool {
    let re_parts: Vec<&str> = s.split('.').collect();
    if re_parts.len() != 4 {
        return false;
    }
    re_parts.iter().all(|p| p.parse::<u8>().is_ok())
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
    loop {
        match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() >= 51_200 {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }

    Ok(String::from_utf8_lossy(&response).to_string())
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

/// Handle RDAP lookup for IP addresses.
async fn rdap_lookup(ip: &str) -> WhoisResult {
    let url = format!("https://rdap.org/ip/{ip}");
    let client = reqwest::Client::new();

    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return WhoisResult {
                ok: false,
                query: ip.to_string(),
                source: "RDAP".to_string(),
                normalized: None,
                raw: None,
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
                raw: None,
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

    // cidr from cidr0CidrsV4 or cidr0CidrsV6
    let cidr = json
        .get("cidr0_cidrs")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|c| {
            let v4 = c.get("v4prefix").and_then(|p| p.as_str());
            let len = c.get("length").and_then(|l| l.as_u64());
            match (v4, len) {
                (Some(p), Some(l)) => Some(format!("{p}/{l}")),
                _ => None,
            }
        })
        .unwrap_or_default();

    // owner from entities vcard
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
pub async fn whois_lookup(query: String) -> Result<WhoisResult, String> {
    if query.is_empty() {
        return Err("Query must not be empty".to_string());
    }

    if is_ipv4(&query) {
        Ok(rdap_lookup(&query).await)
    } else {
        Ok(raw_whois_lookup(&query).await)
    }
}
