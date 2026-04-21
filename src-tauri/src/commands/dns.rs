use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use serde::Serialize;

#[derive(Serialize)]
pub struct DnsResult {
    pub ok: bool,
    pub domain: String,
    pub record_type: String,
    pub local: Vec<String>,
    pub google: Vec<String>,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct DnsValidateResult {
    pub ok: bool,
    pub domain: String,
    pub score: i32,
    pub findings: Vec<DnsFinding>,
    pub raw_output: String,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct DnsFinding {
    pub severity: String, // "info", "success", "warn", "error"
    pub check: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct DnsHealthResult {
    pub ok: bool,
    pub domain: String,
    pub resolvers: Vec<ResolverComparison>,
    pub consistent: bool,
    pub raw_output: String,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct ResolverComparison {
    pub resolver: String,
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub ns_records: Vec<String>,
}

#[derive(Serialize)]
pub struct DmarcResult {
    pub ok: bool,
    pub domain: String,
    pub record: Option<String>,
    pub tags: Vec<DmarcTag>,
    pub issues: Vec<String>,
    pub raw_output: String,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct DmarcTag {
    pub name: String,
    pub value: String,
}

#[derive(Serialize)]
pub struct MtrResult {
    pub ok: bool,
    pub host: String,
    pub rounds: u32,
    pub hops: Vec<MtrHop>,
    pub worst_hop: Option<u32>,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct MtrHop {
    pub hop: u32,
    pub ip: String,
    pub loss_pct: f64,
    pub avg_rtt: Option<f64>,
    pub worst_rtt: Option<f64>,
    pub best_rtt: Option<f64>,
}

// ---------------------------------------------------------------------------
// Resolver helpers
// ---------------------------------------------------------------------------

fn make_custom_resolver(ip: &str) -> TokioAsyncResolver {
    let mut config = ResolverConfig::new();
    config.add_name_server(NameServerConfig {
        socket_addr: format!("{ip}:53").parse().unwrap(),
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    });
    TokioAsyncResolver::tokio(config, ResolverOpts::default())
}

fn make_system_resolver() -> Result<TokioAsyncResolver, String> {
    TokioAsyncResolver::tokio_from_system_conf().map_err(|e| e.to_string())
}

/// Resolve a record type with a given resolver, returning strings.
async fn resolve_record(
    resolver: &TokioAsyncResolver,
    domain: &str,
    record_type: &str,
) -> Vec<String> {
    match record_type.to_uppercase().as_str() {
        "A" => resolver
            .lookup_ip(domain)
            .await
            .map(|r| {
                r.iter()
                    .filter(|ip| ip.is_ipv4())
                    .map(|ip| ip.to_string())
                    .collect()
            })
            .unwrap_or_default(),
        "AAAA" => resolver
            .lookup_ip(domain)
            .await
            .map(|r| {
                r.iter()
                    .filter(|ip| ip.is_ipv6())
                    .map(|ip| ip.to_string())
                    .collect()
            })
            .unwrap_or_default(),
        "MX" => resolver
            .mx_lookup(domain)
            .await
            .map(|r| r.iter().map(|mx| format!("{} {}", mx.preference(), mx.exchange())).collect())
            .unwrap_or_default(),
        "NS" => resolver
            .ns_lookup(domain)
            .await
            .map(|r| r.iter().map(|ns| ns.to_string()).collect())
            .unwrap_or_default(),
        "CNAME" => resolver
            .lookup(domain, hickory_resolver::proto::rr::RecordType::CNAME)
            .await
            .map(|r| r.iter().map(|rdata| rdata.to_string()).collect())
            .unwrap_or_default(),
        "PTR" => resolver
            .reverse_lookup(domain.parse().unwrap_or([0, 0, 0, 0].into()))
            .await
            .map(|r| r.iter().map(|ptr| ptr.to_string()).collect())
            .unwrap_or_default(),
        "SOA" => resolver
            .lookup(domain, hickory_resolver::proto::rr::RecordType::SOA)
            .await
            .map(|r| r.iter().map(|rdata| rdata.to_string()).collect())
            .unwrap_or_default(),
        "TXT" => resolver
            .txt_lookup(domain)
            .await
            .map(|r| {
                r.iter()
                    .map(|txt| {
                        txt.iter()
                            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                            .collect::<Vec<_>>()
                            .join("")
                    })
                    .collect()
            })
            .unwrap_or_default(),
        "CAA" => resolver
            .lookup(domain, hickory_resolver::proto::rr::RecordType::CAA)
            .await
            .map(|r| r.iter().map(|rdata| rdata.to_string()).collect())
            .unwrap_or_default(),
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn dns_query(domain: String, record_type: String) -> Result<DnsResult, String> {
    let system_resolver = make_system_resolver().map_err(|e| e.to_string())?;
    let google_resolver = make_custom_resolver("8.8.8.8");

    let (local, google) = tokio::join!(
        resolve_record(&system_resolver, &domain, &record_type),
        resolve_record(&google_resolver, &domain, &record_type),
    );

    Ok(DnsResult {
        ok: true,
        domain,
        record_type,
        local,
        google,
        error: None,
    })
}

#[tauri::command]
pub async fn dns_validate(domain: String) -> Result<DnsValidateResult, String> {
    let resolver = make_system_resolver().map_err(|e| e.to_string())?;

    let a_records = resolve_record(&resolver, &domain, "A").await;
    let aaaa_records = resolve_record(&resolver, &domain, "AAAA").await;
    let ns_records = resolve_record(&resolver, &domain, "NS").await;
    let soa_records = resolve_record(&resolver, &domain, "SOA").await;
    let caa_records = resolve_record(&resolver, &domain, "CAA").await;

    let mut findings: Vec<DnsFinding> = Vec::new();
    let mut score: i32 = 100;

    // A records
    if a_records.is_empty() {
        score -= 30;
        findings.push(DnsFinding {
            severity: "error".to_string(),
            check: "A Records".to_string(),
            message: "No A records found. Domain may not resolve.".to_string(),
        });
    } else {
        findings.push(DnsFinding {
            severity: "success".to_string(),
            check: "A Records".to_string(),
            message: format!("Found {} A record(s): {}", a_records.len(), a_records.join(", ")),
        });
    }

    // AAAA records
    if aaaa_records.is_empty() {
        findings.push(DnsFinding {
            severity: "info".to_string(),
            check: "AAAA Records".to_string(),
            message: "No AAAA records (IPv6 not configured).".to_string(),
        });
    } else {
        findings.push(DnsFinding {
            severity: "success".to_string(),
            check: "AAAA Records".to_string(),
            message: format!("Found {} AAAA record(s).", aaaa_records.len()),
        });
    }

    // NS records
    if ns_records.len() < 2 {
        score -= 10;
        findings.push(DnsFinding {
            severity: "warn".to_string(),
            check: "NS Records".to_string(),
            message: format!(
                "Only {} NS record(s) found. At least 2 recommended.",
                ns_records.len()
            ),
        });
    } else {
        findings.push(DnsFinding {
            severity: "success".to_string(),
            check: "NS Records".to_string(),
            message: format!("Found {} NS record(s).", ns_records.len()),
        });
    }

    // SOA
    if soa_records.is_empty() {
        score -= 20;
        findings.push(DnsFinding {
            severity: "error".to_string(),
            check: "SOA Record".to_string(),
            message: "No SOA record found.".to_string(),
        });
    } else {
        findings.push(DnsFinding {
            severity: "success".to_string(),
            check: "SOA Record".to_string(),
            message: "SOA record present.".to_string(),
        });
    }

    // CAA
    if caa_records.is_empty() {
        score -= 5;
        findings.push(DnsFinding {
            severity: "warn".to_string(),
            check: "CAA Records".to_string(),
            message: "No CAA records found. Consider adding CAA to restrict certificate issuance."
                .to_string(),
        });
    } else {
        findings.push(DnsFinding {
            severity: "success".to_string(),
            check: "CAA Records".to_string(),
            message: format!("Found {} CAA record(s).", caa_records.len()),
        });
    }

    let raw_output = findings
        .iter()
        .map(|f| format!("[{}] {}: {}", f.severity.to_uppercase(), f.check, f.message))
        .collect::<Vec<_>>()
        .join("\n");

    Ok(DnsValidateResult {
        ok: true,
        domain,
        score: score.max(0),
        findings,
        raw_output,
        error: None,
    })
}

#[tauri::command]
pub async fn dns_health(domain: String) -> Result<DnsHealthResult, String> {
    let system_resolver = make_system_resolver().map_err(|e| e.to_string())?;
    let cloudflare_resolver = make_custom_resolver("1.1.1.1");
    let google_resolver = make_custom_resolver("8.8.8.8");

    let (sys_a, sys_aaaa, sys_ns) = tokio::join!(
        resolve_record(&system_resolver, &domain, "A"),
        resolve_record(&system_resolver, &domain, "AAAA"),
        resolve_record(&system_resolver, &domain, "NS"),
    );
    let (cf_a, cf_aaaa, cf_ns) = tokio::join!(
        resolve_record(&cloudflare_resolver, &domain, "A"),
        resolve_record(&cloudflare_resolver, &domain, "AAAA"),
        resolve_record(&cloudflare_resolver, &domain, "NS"),
    );
    let (goog_a, goog_aaaa, goog_ns) = tokio::join!(
        resolve_record(&google_resolver, &domain, "A"),
        resolve_record(&google_resolver, &domain, "AAAA"),
        resolve_record(&google_resolver, &domain, "NS"),
    );

    let mut sys_a_sorted = sys_a.clone();
    let mut cf_a_sorted = cf_a.clone();
    let mut goog_a_sorted = goog_a.clone();
    sys_a_sorted.sort();
    cf_a_sorted.sort();
    goog_a_sorted.sort();
    let consistent = sys_a_sorted == cf_a_sorted && cf_a_sorted == goog_a_sorted;

    let resolvers = vec![
        ResolverComparison {
            resolver: "System".to_string(),
            a_records: sys_a,
            aaaa_records: sys_aaaa,
            ns_records: sys_ns,
        },
        ResolverComparison {
            resolver: "Cloudflare (1.1.1.1)".to_string(),
            a_records: cf_a,
            aaaa_records: cf_aaaa,
            ns_records: cf_ns,
        },
        ResolverComparison {
            resolver: "Google (8.8.8.8)".to_string(),
            a_records: goog_a,
            aaaa_records: goog_aaaa,
            ns_records: goog_ns,
        },
    ];

    let mut raw_lines = vec![format!("DNS Health Check: {domain}")];
    for r in &resolvers {
        raw_lines.push(format!(
            "\n[{}]\n  A:    {}\n  AAAA: {}\n  NS:   {}",
            r.resolver,
            if r.a_records.is_empty() { "(none)".to_string() } else { r.a_records.join(", ") },
            if r.aaaa_records.is_empty() { "(none)".to_string() } else { r.aaaa_records.join(", ") },
            if r.ns_records.is_empty() { "(none)".to_string() } else { r.ns_records.join(", ") },
        ));
    }
    raw_lines.push(format!(
        "\nConsistency: {}",
        if consistent { "PASS - all resolvers agree on A records" } else { "FAIL - A records differ across resolvers" }
    ));

    Ok(DnsHealthResult {
        ok: true,
        domain,
        resolvers,
        consistent,
        raw_output: raw_lines.join("\n"),
        error: None,
    })
}

#[tauri::command]
pub async fn dns_dmarc(domain: String) -> Result<DmarcResult, String> {
    let resolver = make_system_resolver().map_err(|e| e.to_string())?;
    let dmarc_domain = format!("_dmarc.{domain}");

    let txt_records = resolve_record(&resolver, &dmarc_domain, "TXT").await;
    let raw_output = txt_records.join("\n");

    let dmarc_record = txt_records
        .iter()
        .find(|r| r.starts_with("v=DMARC1"))
        .cloned();

    let Some(ref record) = dmarc_record else {
        return Ok(DmarcResult {
            ok: false,
            domain,
            record: None,
            tags: vec![],
            issues: vec!["No DMARC record found".to_string()],
            raw_output,
            error: None,
        });
    };

    let mut tags: Vec<DmarcTag> = Vec::new();
    let mut issues: Vec<String> = Vec::new();

    for part in record.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(eq) = part.find('=') {
            let name = part[..eq].trim().to_string();
            let value = part[eq + 1..].trim().to_string();
            tags.push(DmarcTag {
                name: name.clone(),
                value: value.clone(),
            });

            match name.as_str() {
                "p" | "sp" => {
                    if !matches!(value.as_str(), "none" | "quarantine" | "reject") {
                        issues.push(format!(
                            "Invalid '{}' value '{}'. Must be none, quarantine, or reject.",
                            name, value
                        ));
                    }
                }
                "pct" => {
                    match value.parse::<u8>() {
                        Ok(n) if n <= 100 => {}
                        _ => issues.push(format!(
                            "Invalid 'pct' value '{}'. Must be 0–100.",
                            value
                        )),
                    }
                }
                _ => {}
            }
        }
    }

    Ok(DmarcResult {
        ok: true,
        domain,
        record: Some(record.clone()),
        tags,
        issues,
        raw_output,
        error: None,
    })
}

#[tauri::command]
pub async fn mtr_run(host: String, rounds: u32) -> Result<MtrResult, String> {
    let rounds = rounds.clamp(2, 30);

    use std::collections::HashMap;

    // hop_number → list of (ip, rtt_ms) per round
    let mut hop_data: HashMap<u32, Vec<(String, Option<f64>)>> = HashMap::new();

    for _ in 0..rounds {
        let trace = super::trace::trace_run(host.clone()).await?;
        if !trace.ok {
            continue;
        }

        for line in trace.output.lines() {
            // Match lines like "  1   192.168.1.1  1.234 ms" or Windows "  1    192.168.1.1   1ms"
            let trimmed = line.trim();
            // Extract leading hop number
            let mut parts = trimmed.split_whitespace();
            let hop_num = match parts.next().and_then(|s| s.trim_matches('*').parse::<u32>().ok()) {
                Some(n) if n > 0 && n <= 64 => n,
                _ => continue,
            };

            let ip = match parts.next() {
                Some(s) if !s.starts_with('*') => s.to_string(),
                _ => "*".to_string(),
            };

            let rtt = if ip == "*" {
                None
            } else {
                // Look for a number followed by ms
                let text = trimmed;
                let mut found: Option<f64> = None;
                for token in text.split_whitespace() {
                    let clean: String = token.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
                    if let Ok(v) = clean.parse::<f64>() {
                        found = Some(v);
                        break;
                    }
                }
                found
            };

            hop_data.entry(hop_num).or_default().push((ip, rtt));
        }
    }

    let mut hops: Vec<MtrHop> = Vec::new();
    let mut worst_hop: Option<u32> = None;
    let mut worst_avg: f64 = 0.0;

    let mut hop_nums: Vec<u32> = hop_data.keys().cloned().collect();
    hop_nums.sort();

    for hop_num in hop_nums {
        let samples = &hop_data[&hop_num];
        let total = samples.len() as u32;
        let mut ips: Vec<&str> = samples.iter().map(|(ip, _)| ip.as_str()).collect();
        ips.dedup();
        let ip = ips.first().copied().unwrap_or("*").to_string();

        let rtts: Vec<f64> = samples.iter().filter_map(|(_, r)| *r).collect();
        let received = rtts.len() as u32;
        let loss_pct = if total == 0 {
            100.0
        } else {
            (total - received) as f64 / total as f64 * 100.0
        };

        let avg_rtt = if rtts.is_empty() {
            None
        } else {
            Some(rtts.iter().sum::<f64>() / rtts.len() as f64)
        };
        let best_rtt = rtts.iter().cloned().reduce(f64::min);
        let worst_rtt = rtts.iter().cloned().reduce(f64::max);

        if let Some(avg) = avg_rtt {
            if avg > worst_avg {
                worst_avg = avg;
                worst_hop = Some(hop_num);
            }
        }

        hops.push(MtrHop {
            hop: hop_num,
            ip,
            loss_pct,
            avg_rtt,
            worst_rtt,
            best_rtt,
        });
    }

    Ok(MtrResult {
        ok: true,
        host,
        rounds,
        hops,
        worst_hop,
        error: None,
    })
}
