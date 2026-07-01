use serde::Serialize;
use std::time::Duration;

#[derive(Serialize)]
pub struct GeoIpResult {
    pub ok: bool,
    pub ip: String,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub org: Option<String>,
    pub as_info: Option<String>,
    pub error: Option<String>,
}

fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
        return match addr {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => v6.is_loopback(),
        };
    }
    false
}

#[tauri::command]
pub async fn geoip_lookup(
    ip: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<GeoIpResult, String> {
    if is_private_ip(&ip) {
        return Ok(GeoIpResult {
            ok: false,
            ip,
            country: None,
            country_code: None,
            city: None,
            org: None,
            as_info: None,
            error: Some("Private/loopback address".to_string()),
        });
    }

    let url = format!(
        "http://ip-api.com/json/{}?fields=status,country,countryCode,city,org,as",
        ip
    );

    let response = match tokio::time::timeout(Duration::from_secs(5), state.http_client.get(&url).send()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return Ok(GeoIpResult {
                ok: false,
                ip,
                country: None,
                country_code: None,
                city: None,
                org: None,
                as_info: None,
                error: Some(format!("Request failed: {e}")),
            })
        }
        Err(_) => {
            return Ok(GeoIpResult {
                ok: false,
                ip,
                country: None,
                country_code: None,
                city: None,
                org: None,
                as_info: None,
                error: Some("Request timed out".to_string()),
            })
        }
    };

    let text = match response.text().await {
        Ok(t) => t,
        Err(e) => {
            return Ok(GeoIpResult {
                ok: false,
                ip,
                country: None,
                country_code: None,
                city: None,
                org: None,
                as_info: None,
                error: Some(format!("Failed to read response: {e}")),
            })
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            return Ok(GeoIpResult {
                ok: false,
                ip,
                country: None,
                country_code: None,
                city: None,
                org: None,
                as_info: None,
                error: Some(format!("Failed to parse response: {e}")),
            })
        }
    };

    if json.get("status").and_then(|s| s.as_str()) != Some("success") {
        return Ok(GeoIpResult {
            ok: false,
            ip,
            country: None,
            country_code: None,
            city: None,
            org: None,
            as_info: None,
            error: Some("GeoIP lookup failed for this address".to_string()),
        });
    }

    let str_field = |key: &str| json.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from);

    Ok(GeoIpResult {
        ok: true,
        ip,
        country: str_field("country"),
        country_code: str_field("countryCode"),
        city: str_field("city"),
        org: str_field("org"),
        as_info: str_field("as"),
        error: None,
    })
}
