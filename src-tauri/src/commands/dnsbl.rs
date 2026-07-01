use hickory_resolver::TokioResolver;
use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Serialize)]
pub struct DnsblResult {
    pub ok: bool,
    pub ip: String,
    pub listed_count: usize,
    pub total_checked: usize,
    pub listings: Vec<DnsblListing>,
    pub raw_output: String,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct DnsblListing {
    pub zone: String,
    pub name: String,
    pub listed: bool,
    pub response: Option<String>,
    pub inconclusive: bool,
}

// Spamhaus reserves 127.255.255.254/.255 to signal "query blocked / rate limit
// exceeded" (typically hit when querying via a public resolver like 8.8.8.8 or
// 1.1.1.1 instead of a dedicated one). These are not real listings.
const SPAMHAUS_ERROR_CODES: &[&str] = &["127.255.255.254", "127.255.255.255"];

struct DnsblZone {
    zone: &'static str,
    name: &'static str,
}

// Well-known public DNSBL zones queried via reversed-IP DNS lookup
// (e.g. 4.3.2.1.zen.spamhaus.org). No API key required.
const DNSBL_ZONES: &[DnsblZone] = &[
    DnsblZone { zone: "zen.spamhaus.org", name: "Spamhaus ZEN" },
    DnsblZone { zone: "bl.spamcop.net", name: "SpamCop" },
    DnsblZone { zone: "b.barracudacentral.org", name: "Barracuda Reputation" },
    DnsblZone { zone: "dnsbl.sorbs.net", name: "SORBS" },
    DnsblZone { zone: "dnsbl-1.uceprotect.net", name: "UCEPROTECT Level 1" },
];

fn reverse_ipv4(ip: &Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
}

async fn query_zone(resolver: &TokioResolver, reversed: &str, zone: &DnsblZone) -> DnsblListing {
    let query = format!("{reversed}.{}", zone.zone);
    match resolver.lookup_ip(query.as_str()).await {
        Ok(r) => {
            let ips: Vec<String> = r.iter().map(|ip| ip.to_string()).collect();
            if ips.is_empty() {
                DnsblListing {
                    zone: zone.zone.to_string(),
                    name: zone.name.to_string(),
                    listed: false,
                    response: None,
                    inconclusive: false,
                }
            } else if ips.iter().any(|ip| SPAMHAUS_ERROR_CODES.contains(&ip.as_str())) {
                // The querying resolver was rate-limited or blocked by the DNSBL
                // provider; this is not a real listing result either way.
                DnsblListing {
                    zone: zone.zone.to_string(),
                    name: zone.name.to_string(),
                    listed: false,
                    response: Some(format!(
                        "Query blocked/rate-limited by provider (response: {}). Try a different DNS resolver.",
                        ips.join(", ")
                    )),
                    inconclusive: true,
                }
            } else {
                DnsblListing {
                    zone: zone.zone.to_string(),
                    name: zone.name.to_string(),
                    listed: true,
                    response: Some(ips.join(", ")),
                    inconclusive: false,
                }
            }
        }
        // NXDOMAIN (no records found) genuinely means "not listed" in DNSBL
        // semantics. Any other failure (timeout, SERVFAIL, network error) is
        // a transient resolver problem, not a real answer — mark inconclusive
        // rather than silently reporting a false "not listed".
        Err(e) => DnsblListing {
            zone: zone.zone.to_string(),
            name: zone.name.to_string(),
            listed: false,
            response: if e.is_no_records_found() {
                None
            } else {
                Some(format!("Lookup failed: {e}"))
            },
            inconclusive: !e.is_no_records_found(),
        },
    }
}

#[tauri::command]
pub async fn dnsbl_check(
    ip: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<DnsblResult, String> {
    let ip = ip.trim().to_string();

    let parsed: Ipv4Addr = match ip.parse() {
        Ok(v) => v,
        Err(_) => {
            return Ok(DnsblResult {
                ok: false,
                ip,
                listed_count: 0,
                total_checked: 0,
                listings: vec![],
                raw_output: String::new(),
                error: Some(
                    "Enter a valid IPv4 address. Public DNSBL zones do not support IPv6."
                        .to_string(),
                ),
            });
        }
    };

    let resolvers = super::dns::get_resolvers(&state).await?;
    let reversed = reverse_ipv4(&parsed);

    let queries = DNSBL_ZONES
        .iter()
        .map(|zone| query_zone(&resolvers.system, &reversed, zone));
    let listings: Vec<DnsblListing> = futures::future::join_all(queries).await;

    let listed_count = listings.iter().filter(|l| l.listed).count();
    let inconclusive_count = listings.iter().filter(|l| l.inconclusive).count();
    let total_checked = listings.len();

    let mut raw_lines = vec![format!("DNSBL Check: {ip}")];
    for l in &listings {
        let tag = if l.listed {
            "LISTED"
        } else if l.inconclusive {
            "BLOCKED"
        } else {
            "clean"
        };
        raw_lines.push(format!(
            "[{tag}] {}: {}",
            l.name,
            l.response.as_deref().unwrap_or("-"),
        ));
    }
    raw_lines.push(String::new());
    raw_lines.push(if listed_count == 0 {
        format!("Not listed on any of {total_checked} checked blacklists.")
    } else {
        format!("Listed on {listed_count} of {total_checked} checked blacklists.")
    });
    if inconclusive_count > 0 {
        raw_lines.push(format!(
            "{inconclusive_count} check(s) were inconclusive (provider rate-limited this DNS resolver)."
        ));
    }

    Ok(DnsblResult {
        ok: true,
        ip,
        listed_count,
        total_checked,
        listings,
        raw_output: raw_lines.join("\n"),
        error: None,
    })
}
