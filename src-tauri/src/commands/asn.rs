use serde::Serialize;

use super::whois::raw_tcp_whois;

#[derive(Serialize)]
pub struct AsnResult {
    pub ok: bool,
    pub query: String,
    pub asn: Option<String>,
    pub as_name: Option<String>,
    pub bgp_prefix: Option<String>,
    pub country_code: Option<String>,
    pub registry: Option<String>,
    pub allocated: Option<String>,
    pub raw_output: String,
    pub error: Option<String>,
}

fn empty_result(query: &str, error: &str, raw_output: String) -> AsnResult {
    AsnResult {
        ok: false,
        query: query.to_string(),
        asn: None,
        as_name: None,
        bgp_prefix: None,
        country_code: None,
        registry: None,
        allocated: None,
        raw_output,
        error: Some(error.to_string()),
    }
}

/// Looks up the announcing ASN / BGP origin for an IP address via Team Cymru's
/// public whois service (whois.cymru.com), which mirrors real-time BGP table
/// data rather than registry allocation records — the same source ISPs use to
/// answer "who is originating this route right now".
#[tauri::command]
pub async fn asn_lookup(query: String) -> Result<AsnResult, String> {
    let ip = query.trim().to_string();
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Ok(empty_result(&ip, "Enter a valid IPv4 or IPv6 address", String::new()));
    }

    // " -v <ip>" is Team Cymru's documented raw-TCP verbose query syntax; it
    // returns AS number, BGP prefix, country, registry, and AS name in one row.
    let request = format!(" -v {ip}");
    let response = match raw_tcp_whois("whois.cymru.com", &request).await {
        Ok(r) => r,
        Err(e) => return Ok(empty_result(&ip, &e, String::new())),
    };

    let data_line = response
        .lines()
        .map(|l| l.trim())
        .find(|l| !l.is_empty() && !l.starts_with("AS "));

    let Some(line) = data_line else {
        return Ok(empty_result(&ip, "No ASN data returned for this address", response));
    };

    // Columns: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    let fields: Vec<Option<String>> = line
        .split('|')
        .map(|f| {
            let t = f.trim();
            if t.is_empty() || t.eq_ignore_ascii_case("NA") {
                None
            } else {
                Some(t.to_string())
            }
        })
        .collect();
    let field = |i: usize| fields.get(i).cloned().flatten();

    let asn = field(0);
    let bgp_prefix = field(2);
    let country_code = field(3);
    let registry = field(4);
    let allocated = field(5);
    let as_name = field(6);

    let Some(asn) = asn else {
        return Ok(empty_result(
            &ip,
            "Address has no announced ASN (private, unallocated, or not currently routed)",
            response,
        ));
    };

    let mut lines = Vec::new();
    lines.push(format!("Query:      {ip}"));
    lines.push(format!("ASN:        AS{asn}"));
    if let Some(name) = &as_name {
        lines.push(format!("AS Name:    {name}"));
    }
    if let Some(p) = &bgp_prefix {
        lines.push(format!("BGP Prefix: {p}"));
    }
    if let Some(cc) = &country_code {
        lines.push(format!("Country:    {cc}"));
    }
    if let Some(r) = &registry {
        lines.push(format!("Registry:   {r}"));
    }
    if let Some(a) = &allocated {
        lines.push(format!("Allocated:  {a}"));
    }

    Ok(AsnResult {
        ok: true,
        query: ip,
        asn: Some(asn),
        as_name,
        bgp_prefix,
        country_code,
        registry,
        allocated,
        raw_output: lines.join("\n"),
        error: None,
    })
}
