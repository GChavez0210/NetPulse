use serde::Serialize;
use std::collections::BTreeSet;
use std::time::Duration;

#[derive(Serialize)]
pub struct LookingGlassEntry {
    pub rrc: String,
    pub peer: String,
    pub origin_asn: String,
    pub as_path: String,
}

#[derive(Serialize)]
pub struct LookingGlassResult {
    pub ok: bool,
    pub resource: String,
    pub peer_count: usize,
    pub rrc_count: usize,
    pub distinct_origins: Vec<String>,
    pub entries: Vec<LookingGlassEntry>,
    pub raw_output: String,
    pub error: Option<String>,
}

const MAX_SAMPLE_ENTRIES: usize = 20;

fn fail(resource: &str, msg: impl Into<String>) -> LookingGlassResult {
    LookingGlassResult {
        ok: false,
        resource: resource.to_string(),
        peer_count: 0,
        rrc_count: 0,
        distinct_origins: Vec::new(),
        entries: Vec::new(),
        raw_output: String::new(),
        error: Some(msg.into()),
    }
}

/// Queries RIPEstat's public "looking glass" data call, which surfaces what
/// RIPE RIS's global BGP route-collector peers actually see announced for a
/// resource right now — real-time route visibility rather than a registry
/// record, useful for confirming a prefix is correctly propagated or
/// spotting a conflicting/unexpected origin ASN (a route leak or hijack
/// signal).
#[tauri::command]
pub async fn bgp_looking_glass(
    resource: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<LookingGlassResult, String> {
    let resource = resource.trim().to_string();
    if resource.is_empty() {
        return Ok(fail(&resource, "Enter an IP address or CIDR prefix"));
    }

    let response = match tokio::time::timeout(
        Duration::from_secs(15),
        state
            .http_client
            .get("https://stat.ripe.net/data/looking-glass/data.json")
            .query(&[("resource", resource.as_str())])
            .send(),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Ok(fail(&resource, format!("Request failed: {e}"))),
        Err(_) => return Ok(fail(&resource, "Request timed out")),
    };

    let json: serde_json::Value = match response.json().await {
        Ok(v) => v,
        Err(e) => return Ok(fail(&resource, format!("Failed to parse response: {e}"))),
    };

    if json.get("status").and_then(|s| s.as_str()) != Some("ok") {
        let msg = json
            .get("status_message")
            .and_then(|s| s.as_str())
            .unwrap_or("RIPEstat lookup failed");
        return Ok(fail(&resource, msg));
    }

    let rrcs = json
        .get("data")
        .and_then(|d| d.get("rrcs"))
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();

    let mut entries: Vec<LookingGlassEntry> = Vec::new();
    let mut origins: BTreeSet<String> = BTreeSet::new();
    let mut peer_count = 0usize;
    let mut rrc_count = 0usize;

    for rrc in &rrcs {
        let rrc_name = rrc.get("rrc").and_then(|v| v.as_str()).unwrap_or("?").to_string();
        let peers = rrc.get("peers").and_then(|p| p.as_array()).cloned().unwrap_or_default();
        if peers.is_empty() {
            continue;
        }
        rrc_count += 1;
        for peer in &peers {
            peer_count += 1;
            let origin_asn = peer
                .get("asn_origin")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            origins.insert(origin_asn.clone());
            if entries.len() < MAX_SAMPLE_ENTRIES {
                entries.push(LookingGlassEntry {
                    rrc: rrc_name.clone(),
                    peer: peer.get("peer").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
                    origin_asn,
                    as_path: peer.get("as_path").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
                });
            }
        }
    }

    let distinct_origins: Vec<String> = origins.into_iter().collect();

    let mut lines = Vec::new();
    lines.push(format!("Resource: {resource}"));

    if peer_count == 0 {
        lines.push(String::new());
        lines.push(
            "Not currently visible in the global routing table — no BGP announcements observed by any RIPE RIS route collector.".to_string(),
        );
        return Ok(LookingGlassResult {
            ok: true,
            resource,
            peer_count: 0,
            rrc_count: 0,
            distinct_origins,
            entries,
            raw_output: lines.join("\n"),
            error: None,
        });
    }

    lines.push(format!("Seen by:  {peer_count} peer(s) across {rrc_count} route collector(s)"));
    lines.push(format!(
        "Origin(s): {}",
        distinct_origins.iter().map(|a| format!("AS{a}")).collect::<Vec<_>>().join(", ")
    ));
    if distinct_origins.len() > 1 {
        lines.push(String::new());
        lines.push(
            "WARNING: multiple distinct origin ASNs observed for this resource — possible route leak or hijack.".to_string(),
        );
    }
    lines.push(String::new());
    lines.push(format!(
        "Sample observations (showing {} of {peer_count}):",
        entries.len()
    ));
    lines.push("  RRC     PEER               ORIGIN    AS PATH".to_string());
    for e in &entries {
        lines.push(format!(
            "  {:<7} {:<18} AS{:<7} {}",
            e.rrc, e.peer, e.origin_asn, e.as_path
        ));
    }

    Ok(LookingGlassResult {
        ok: true,
        resource,
        peer_count,
        rrc_count,
        distinct_origins,
        entries,
        raw_output: lines.join("\n"),
        error: None,
    })
}
