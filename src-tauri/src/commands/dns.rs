use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
    proto::rr::{domain::Name, RecordType},
    TokioResolver,
};
use serde::Serialize;
use std::time::Duration;

#[derive(Serialize)]
pub struct DnsResult {
    pub ok: bool,
    pub domain: String,
    pub record_type: String,
    pub local: Vec<String>,
    pub google: Vec<String>,
    /// Set when the *local* resolver genuinely failed (timeout/network/SERVFAIL),
    /// as opposed to `local` simply being empty because no records exist.
    pub local_error: Option<String>,
    /// Same distinction for the Google (8.8.8.8) resolver.
    pub google_error: Option<String>,
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

fn make_custom_resolver(ip: &str) -> Result<TokioResolver, String> {
    let addr: std::net::IpAddr = ip.parse().map_err(|_| format!("Invalid DNS server address: {ip}"))?;
    let config = ResolverConfig::from_parts(None, vec![], vec![NameServerConfig::udp(addr)]);
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .map_err(|e| e.to_string())
}

fn make_system_resolver() -> Result<TokioResolver, String> {
    let builder = TokioResolver::builder_tokio().map_err(|e| e.to_string())?;
    builder.build().map_err(|e| e.to_string())
}

/// Shared set of resolvers, built once and reused across all DNS-related
/// commands instead of re-resolving system config / rebuilding a UDP
/// resolver (and discarding its lookup cache) on every invocation.
pub struct DnsResolvers {
    pub system: TokioResolver,
    pub google: TokioResolver,
    pub cloudflare: TokioResolver,
}

pub async fn get_resolvers<'a>(
    state: &'a tauri::State<'_, crate::AppState>,
) -> Result<&'a DnsResolvers, String> {
    state
        .dns_resolvers
        .get_or_try_init(|| async {
            Ok::<DnsResolvers, String>(DnsResolvers {
                system: make_system_resolver()?,
                google: make_custom_resolver("8.8.8.8")?,
                cloudflare: make_custom_resolver("1.1.1.1")?,
            })
        })
        .await
}

/// Resolve a record type with a given resolver.
///
/// Returns `Ok(vec![])` when the domain genuinely has no records of this
/// type (NXDOMAIN / NoRecordsFound — a legitimate, successful DNS answer),
/// and `Err(...)` only for real failures (timeout, network error, SERVFAIL,
/// refused, etc.) so callers can tell "no records" apart from "lookup failed".
async fn resolve_record(
    resolver: &TokioResolver,
    domain: &str,
    record_type: &str,
) -> Result<Vec<String>, String> {
    fn ok_or_no_records<T, E>(result: Result<T, hickory_resolver::net::NetError>, map: impl FnOnce(T) -> Vec<E>) -> Result<Vec<E>, String> {
        match result {
            Ok(v) => Ok(map(v)),
            Err(e) if e.is_no_records_found() => Ok(vec![]),
            Err(e) => Err(e.to_string()),
        }
    }

    // MX/NS/CNAME/SOA/TXT/CAA no longer have dedicated typed lookup methods;
    // use the generic lookup and format each answer's RData via its Display
    // impl (e.g. MX's Display already renders as "{preference} {exchange}").
    let generic_lookup = |rtype: RecordType| async move {
        ok_or_no_records(resolver.lookup(domain, rtype).await, |r| {
            r.answers().iter().map(|rec| rec.data.to_string()).collect()
        })
    };

    match record_type.to_uppercase().as_str() {
        "A" => ok_or_no_records(resolver.lookup_ip(domain).await, |r| {
            r.iter().filter(|ip| ip.is_ipv4()).map(|ip| ip.to_string()).collect()
        }),
        "AAAA" => ok_or_no_records(resolver.lookup_ip(domain).await, |r| {
            r.iter().filter(|ip| ip.is_ipv6()).map(|ip| ip.to_string()).collect()
        }),
        "MX" => generic_lookup(RecordType::MX).await,
        "NS" => generic_lookup(RecordType::NS).await,
        "CNAME" => generic_lookup(RecordType::CNAME).await,
        "PTR" => match domain.parse::<std::net::IpAddr>() {
            Ok(ip) => {
                let reverse_name = Name::from(ip);
                ok_or_no_records(resolver.lookup(reverse_name, RecordType::PTR).await, |r| {
                    r.answers().iter().map(|rec| rec.data.to_string()).collect()
                })
            }
            Err(_) => Err(format!("Invalid IP address for PTR lookup: {domain}")),
        },
        "SOA" => generic_lookup(RecordType::SOA).await,
        "TXT" => generic_lookup(RecordType::TXT).await,
        "CAA" => generic_lookup(RecordType::CAA).await,
        _ => Ok(vec![]),
    }
}

/// Convenience wrapper for callers (validate/health/dmarc) that don't
/// distinguish "no records" from "lookup failed" and just want a Vec.
async fn resolve_record_lenient(resolver: &TokioResolver, domain: &str, record_type: &str) -> Vec<String> {
    resolve_record(resolver, domain, record_type).await.unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn dns_query(
    domain: String,
    record_type: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<DnsResult, String> {
    let resolvers = get_resolvers(&state).await?;

    let (local_result, google_result) = tokio::join!(
        resolve_record(&resolvers.system, &domain, &record_type),
        resolve_record(&resolvers.google, &domain, &record_type),
    );

    let (local, local_error) = match local_result {
        Ok(v) => (v, None),
        Err(e) => (vec![], Some(e)),
    };
    let (google, google_error) = match google_result {
        Ok(v) => (v, None),
        Err(e) => (vec![], Some(e)),
    };

    Ok(DnsResult {
        ok: local_error.is_none() || google_error.is_none(),
        domain,
        record_type,
        local,
        google,
        local_error,
        google_error,
        error: None,
    })
}

#[tauri::command]
pub async fn dns_validate(
    domain: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<DnsValidateResult, String> {
    let resolvers = get_resolvers(&state).await?;
    let resolver = &resolvers.system;

    let a_records = resolve_record_lenient(resolver, &domain, "A").await;
    let aaaa_records = resolve_record_lenient(resolver, &domain, "AAAA").await;
    let ns_records = resolve_record_lenient(resolver, &domain, "NS").await;
    let soa_records = resolve_record_lenient(resolver, &domain, "SOA").await;
    let caa_records = resolve_record_lenient(resolver, &domain, "CAA").await;

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
pub async fn dns_health(
    domain: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<DnsHealthResult, String> {
    let resolvers = get_resolvers(&state).await?;

    let (sys_a, sys_aaaa, sys_ns) = tokio::join!(
        resolve_record_lenient(&resolvers.system, &domain, "A"),
        resolve_record_lenient(&resolvers.system, &domain, "AAAA"),
        resolve_record_lenient(&resolvers.system, &domain, "NS"),
    );
    let (cf_a, cf_aaaa, cf_ns) = tokio::join!(
        resolve_record_lenient(&resolvers.cloudflare, &domain, "A"),
        resolve_record_lenient(&resolvers.cloudflare, &domain, "AAAA"),
        resolve_record_lenient(&resolvers.cloudflare, &domain, "NS"),
    );
    let (goog_a, goog_aaaa, goog_ns) = tokio::join!(
        resolve_record_lenient(&resolvers.google, &domain, "A"),
        resolve_record_lenient(&resolvers.google, &domain, "AAAA"),
        resolve_record_lenient(&resolvers.google, &domain, "NS"),
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
pub async fn dns_dmarc(
    domain: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<DmarcResult, String> {
    let resolvers = get_resolvers(&state).await?;
    let dmarc_domain = format!("_dmarc.{domain}");

    let txt_records = resolve_record_lenient(&resolvers.system, &dmarc_domain, "TXT").await;
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
    use futures::StreamExt;
    use std::collections::HashMap;

    let rounds = rounds.clamp(2, 30);

    // Run up to 5 traceroute rounds concurrently instead of sequentially, but
    // bound the whole operation to a wall-clock deadline — each round is a
    // full external tracert/traceroute process (up to 90s), so an unbounded
    // 30-round run could otherwise tie up the machine for several minutes.
    // Whatever rounds finish before the deadline are still used; a slow
    // target just yields a result built from fewer samples.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let trace_host = host.clone();
    let mut stream = futures::stream::iter(
        (0..rounds).map(move |_| super::trace::trace_run(trace_host.clone())),
    )
    .buffer_unordered(5);
    let mut trace_results = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(r)) => trace_results.push(r),
            Ok(None) => break, // all rounds finished
            Err(_) => break,   // deadline reached with rounds still in flight
        }
    }
    drop(stream);

    // hop_number → list of (ip, rtt_ms) per round
    let mut hop_data: HashMap<u32, Vec<(String, Option<f64>)>> = HashMap::new();

    for trace_result in trace_results {
        let trace = match trace_result {
            Ok(t) if t.ok => t,
            _ => continue,
        };

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
