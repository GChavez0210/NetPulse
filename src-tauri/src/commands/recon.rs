use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ── SSL / TLS Inspection ──────────────────────────────────────────────────────
// Uses rustls sync I/O on a blocking thread so the async timeout is
// always respected — avoids the async TLS handshake freeze on filtered ports.

#[derive(Serialize, Default)]
pub struct SslInspectResult {
    pub ok: bool,
    pub host: String,
    pub port: u16,
    pub tls_version: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub sans: Vec<String>,
    pub serial: Option<String>,
    pub chain_depth: usize,
    pub expired: Option<bool>,
    pub days_until_expiry: Option<i64>,
    pub raw_output: Option<String>,
    pub error: Option<String>,
}

/// Blocking implementation — runs on a dedicated thread via spawn_blocking.
fn ssl_inspect_sync(host: String, port: u16) -> SslInspectResult {
    use std::net::TcpStream;
    use std::time::Duration;

    let mut res = SslInspectResult {
        host: host.clone(),
        port,
        ..Default::default()
    };

    // Build rustls config with trusted web roots
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    // Resolve ServerName (supports both hostnames and bare IPs)
    let server_name: rustls::pki_types::ServerName<'static> =
        match host.parse::<std::net::IpAddr>() {
            Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
            Err(_) => match rustls::pki_types::ServerName::try_from(host.as_str()) {
                Ok(n) => n.to_owned(),
                Err(e) => {
                    res.error = Some(format!("Invalid hostname: {e}"));
                    return res;
                }
            },
        };

    // Blocking TCP connect — std::net handles DNS resolution here
    let addr = format!("{host}:{port}");
    let mut tcp = match TcpStream::connect(addr.as_str()) {
        Ok(s) => s,
        Err(e) => {
            res.error = Some(format!("TCP connect error: {e}"));
            return res;
        }
    };

    // Per-operation timeouts so a stalled server doesn't hang forever
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(10)));

    // Initialise the TLS client connection
    let mut conn = match rustls::ClientConnection::new(config, server_name) {
        Ok(c) => c,
        Err(e) => {
            res.error = Some(format!("TLS init error: {e}"));
            return res;
        }
    };

    // Drive the TLS handshake to completion
    while conn.is_handshaking() {
        match conn.complete_io(&mut tcp) {
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                res.error = Some("TLS handshake timed out (10 s)".into());
                return res;
            }
            Err(e) => {
                res.error = Some(format!("TLS handshake error: {e}"));
                return res;
            }
        }
    }

    // TLS protocol version
    res.tls_version = conn.protocol_version().map(|v| match v {
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
        other => format!("{other:?}"),
    });

    // Extract peer certificates (copy bytes before conn is dropped)
    let cert_bytes: Vec<Vec<u8>> = match conn.peer_certificates() {
        Some(c) if !c.is_empty() => c.iter().map(|der| der.as_ref().to_vec()).collect(),
        _ => {
            res.error = Some("No peer certificates received".into());
            return res;
        }
    };
    res.chain_depth = cert_bytes.len();

    // Parse the leaf certificate with x509-parser
    use x509_parser::prelude::*;
    match X509Certificate::from_der(&cert_bytes[0]) {
        Ok((_, cert)) => {
            res.subject = Some(cert.subject().to_string());
            res.issuer = Some(cert.issuer().to_string());

            res.serial = Some(
                cert.raw_serial()
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":"),
            );

            res.not_before = Some(cert.validity().not_before.to_string());
            res.not_after = Some(cert.validity().not_after.to_string());

            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let expiry_ts = cert.validity().not_after.timestamp();
            res.expired = Some(now_ts > expiry_ts);
            res.days_until_expiry = Some((expiry_ts - now_ts) / 86400);

            for ext in cert.extensions() {
                if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                    for gn in &san.general_names {
                        match gn {
                            GeneralName::DNSName(name) => res.sans.push(name.to_string()),
                            GeneralName::IPAddress(ip) if ip.len() == 4 => {
                                res.sans
                                    .push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                            }
                            _ => {}
                        }
                    }
                }
            }

            let expiry_label = if res.expired == Some(true) {
                format!("EXPIRED ({} days ago)", -res.days_until_expiry.unwrap_or(0))
            } else {
                format!("{} days remaining", res.days_until_expiry.unwrap_or(0))
            };

            let mut lines = vec![
                format!("Host:        {host}"),
                format!("Port:        {port}"),
                format!(
                    "TLS:         {}",
                    res.tls_version.as_deref().unwrap_or("Unknown")
                ),
                format!("Subject:     {}", cert.subject()),
                format!("Issuer:      {}", cert.issuer()),
                format!("Serial:      {}", res.serial.as_deref().unwrap_or("-")),
                format!("Not Before:  {}", res.not_before.as_deref().unwrap_or("-")),
                format!("Not After:   {}", res.not_after.as_deref().unwrap_or("-")),
                format!("Expiry:      {expiry_label}"),
                format!("Chain Depth: {}", res.chain_depth),
            ];
            if !res.sans.is_empty() {
                lines.push(format!("SANs ({}):", res.sans.len()));
                for san in &res.sans {
                    lines.push(format!("  {san}"));
                }
            }
            res.raw_output = Some(lines.join("\n"));
            res.ok = true;
        }
        Err(e) => {
            res.error = Some(format!("Failed to parse certificate: {e}"));
        }
    }

    res
}

#[tauri::command]
pub async fn ssl_inspect(host: String, port: Option<u16>) -> SslInspectResult {
    let port = port.unwrap_or(443);
    let host_c = host.clone();

    // Run on a blocking thread with a hard 20-second outer timeout.
    // spawn_blocking ensures the sync DNS + TCP + TLS work never blocks
    // the async runtime, and the timeout guarantees the frontend always
    // receives a response even if the underlying operation hangs.
    match tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tokio::task::spawn_blocking(move || ssl_inspect_sync(host_c, port)),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => SslInspectResult {
            ok: false,
            host,
            port,
            error: Some(format!("Internal task error: {e}")),
            ..Default::default()
        },
        Err(_) => SslInspectResult {
            ok: false,
            host,
            port,
            error: Some("Operation timed out after 20 s".into()),
            ..Default::default()
        },
    }
}

// ── HTTP Headers ──────────────────────────────────────────────────────────────

#[derive(Serialize, Default)]
pub struct HttpHeadersResult {
    pub ok: bool,
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<[String; 2]>,
    pub raw_output: Option<String>,
    pub error: Option<String>,
}

#[tauri::command]
pub async fn http_headers(url: String) -> HttpHeadersResult {
    let url_str = if url.starts_with("http://") || url.starts_with("https://") {
        url.clone()
    } else {
        format!("https://{url}")
    };

    let mut res = HttpHeadersResult {
        url: url.clone(),
        ..Default::default()
    };

    let client = match reqwest::Client::builder()
        .redirect(Policy::limited(10))
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("Mozilla/5.0 NetPulse/1.0")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            res.error = Some(format!("Client build error: {e}"));
            return res;
        }
    };

    // Try HEAD first; fall back to GET if the server rejects it
    let resp = match client.head(&url_str).send().await {
        Ok(r) if r.status().as_u16() != 405 => r,
        _ => match client.get(&url_str).send().await {
            Ok(r) => r,
            Err(e) => {
                res.error = Some(format!("Request failed: {e}"));
                return res;
            }
        },
    };

    res.status = resp.status().as_u16();
    res.status_text = resp
        .status()
        .canonical_reason()
        .unwrap_or("Unknown")
        .to_string();
    res.final_url = resp.url().to_string();

    let mut lines = vec![
        format!("URL:    {url_str}"),
        format!("Final:  {}", res.final_url),
        format!("Status: {} {}", res.status, res.status_text),
        String::new(),
        "── Response Headers ──────────────────────────────".to_string(),
    ];

    for (name, value) in resp.headers() {
        let n = name.as_str().to_string();
        let v = value.to_str().unwrap_or("(binary)").to_string();
        lines.push(format!("{n}: {v}"));
        res.headers.push([n, v]);
    }

    res.raw_output = Some(lines.join("\n"));
    res.ok = true;
    res
}

// ── Subdomain Enumeration (crt.sh) ───────────────────────────────────────────

#[derive(Serialize, Default)]
pub struct SubdomainsResult {
    pub ok: bool,
    pub domain: String,
    pub subdomains: Vec<String>,
    pub count: usize,
    pub raw_output: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
struct CrtShEntry {
    name_value: String,
}

#[tauri::command]
pub async fn subdomains_lookup(domain: String) -> SubdomainsResult {
    let mut res = SubdomainsResult {
        domain: domain.clone(),
        ..Default::default()
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("Mozilla/5.0 NetPulse/1.0")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            res.error = Some(format!("Client build error: {e}"));
            return res;
        }
    };

    let url = format!("https://crt.sh/?q=%.{domain}&output=json");

    // Attempt the request up to 2 times — crt.sh 502s are occasionally transient.
    let http_res = {
        let mut last_err: Option<String> = None;
        let mut result = None;
        for attempt in 0..2u8 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            match client.get(&url).send().await {
                Ok(r) => { result = Some(r); break; }
                Err(e) => { last_err = Some(format!("crt.sh request failed: {e}")); }
            }
        }
        match result {
            Some(r) => r,
            None => {
                res.error = last_err;
                return res;
            }
        }
    };

    let status = http_res.status();
    if !status.is_success() {
        res.error = Some(match status.as_u16() {
            502 | 503 | 504 => format!(
                "crt.sh returned {status} — the domain likely has too many \
                 Certificate Transparency entries for crt.sh to handle in one \
                 query (common for high-traffic domains like google.com). \
                 Try a more specific subdomain, e.g. \"mail.{domain}\"."
            ),
            429 => "crt.sh rate-limited this request. Wait a moment and try again.".to_string(),
            _ => format!("crt.sh returned HTTP {status}"),
        });
        return res;
    }

    // Read as text first — avoids opaque "error decoding response body" from
    // .json() when the server sends gzip or an unexpected content type.
    let body = match http_res.text().await {
        Ok(b) => b,
        Err(e) => {
            res.error = Some(format!("Failed to read crt.sh response: {e}"));
            return res;
        }
    };

    let trimmed = body.trim();

    // crt.sh returns null or [] when no entries exist
    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        let lines = vec![
            format!("Domain: {domain}"),
            "Found:  0 subdomains (via crt.sh CT logs)".to_string(),
            String::new(),
            "── Subdomains ────────────────────────────────────".to_string(),
            "No subdomains found in Certificate Transparency logs.".to_string(),
        ];
        res.raw_output = Some(lines.join("\n"));
        res.ok = true;
        return res;
    }

    let entries: Vec<CrtShEntry> = match serde_json::from_str(trimmed) {
        Ok(e) => e,
        Err(e) => {
            // Surface a response preview so the user can see what came back
            let preview = &trimmed[..trimmed.len().min(300)];
            res.error = Some(format!("Failed to parse crt.sh response: {e}\n\nResponse preview:\n{preview}"));
            return res;
        }
    };

    let mut seen = std::collections::HashSet::new();
    let mut subdomains: Vec<String> = Vec::new();
    let suffix = format!(".{domain}");

    for entry in entries {
        for raw in entry.name_value.split('\n') {
            let name = raw.trim().to_lowercase();
            if name.is_empty() || name.starts_with("*.") {
                continue;
            }
            if (name == domain || name.ends_with(&suffix)) && seen.insert(name.clone()) {
                subdomains.push(name);
            }
        }
    }
    subdomains.sort();

    res.count = subdomains.len();
    let mut lines = vec![
        format!("Domain: {domain}"),
        format!("Found:  {} subdomains (via crt.sh CT logs)", res.count),
        String::new(),
        "── Subdomains ────────────────────────────────────".to_string(),
    ];
    for sub in &subdomains {
        lines.push(sub.clone());
    }
    if subdomains.is_empty() {
        lines.push("No subdomains found in Certificate Transparency logs.".into());
    }

    res.raw_output = Some(lines.join("\n"));
    res.subdomains = subdomains;
    res.ok = true;
    res
}

// ── Technology Detection ──────────────────────────────────────────────────────

#[derive(Serialize, Default, Clone)]
pub struct TechEntry {
    pub name: String,
    pub category: String,
    pub evidence: String,
}

#[derive(Serialize, Default)]
pub struct TechDetectResult {
    pub ok: bool,
    pub url: String,
    pub technologies: Vec<TechEntry>,
    pub raw_output: Option<String>,
    pub error: Option<String>,
}

fn add_tech(techs: &mut Vec<TechEntry>, name: &str, category: &str, evidence: String) {
    if !techs.iter().any(|t| t.name == name) {
        techs.push(TechEntry {
            name: name.to_string(),
            category: category.to_string(),
            evidence,
        });
    }
}

fn extract_meta_generator(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let search = &lower[..lower.len().min(15_000)];
    let pos = search
        .find("name=\"generator\"")
        .or_else(|| search.find("name='generator'"))?;
    let window = &html[pos.saturating_sub(50)..pos.saturating_add(300).min(html.len())];
    let wl = window.to_lowercase();
    if let Some(ci) = wl.find("content=\"") {
        let s = ci + 9;
        if let Some(e) = window[s..].find('"') {
            let v = window[s..s + e].trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    } else if let Some(ci) = wl.find("content='") {
        let s = ci + 9;
        if let Some(e) = window[s..].find('\'') {
            let v = window[s..s + e].trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

#[tauri::command]
pub async fn tech_detect(url: String) -> TechDetectResult {
    let url_str = if url.starts_with("http://") || url.starts_with("https://") {
        url.clone()
    } else {
        format!("https://{url}")
    };

    let mut res = TechDetectResult {
        url: url.clone(),
        ..Default::default()
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .redirect(Policy::limited(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            res.error = Some(format!("Client build error: {e}"));
            return res;
        }
    };

    let resp = match client.get(&url_str).send().await {
        Ok(r) => r,
        Err(e) => {
            res.error = Some(format!("Request failed: {e}"));
            return res;
        }
    };

    let mut techs: Vec<TechEntry> = Vec::new();
    let headers = resp.headers().clone();

    let header_rules: &[(&str, &str, &str)] = &[
        ("server", "", "Web Server"),
        ("x-powered-by", "", "Runtime"),
        ("x-generator", "", "CMS/Generator"),
        ("x-drupal-cache", "Drupal", "CMS"),
        ("x-drupal-dynamic-cache", "Drupal", "CMS"),
        ("x-wp-total", "WordPress REST API", "CMS"),
        ("x-shopify-stage", "Shopify", "E-Commerce"),
        ("x-ghost-cache-status", "Ghost", "CMS"),
        ("cf-ray", "Cloudflare", "CDN/Proxy"),
        ("x-varnish", "Varnish", "Cache"),
        ("x-amz-request-id", "Amazon AWS", "Cloud"),
        ("x-amzn-requestid", "Amazon AWS", "Cloud"),
        ("x-azure-ref", "Microsoft Azure", "Cloud"),
        ("x-cache", "", "Cache"),
        ("via", "", "Proxy/CDN"),
    ];

    for (header_name, override_name, category) in header_rules {
        if let Some(val) = headers.get(*header_name) {
            let val_str = val.to_str().unwrap_or("").to_string();
            let name = if override_name.is_empty() {
                val_str.split('/').next().unwrap_or(&val_str).trim().to_string()
            } else {
                override_name.to_string()
            };
            if !name.is_empty() {
                add_tech(
                    &mut techs,
                    &name,
                    category,
                    format!("{header_name}: {val_str}"),
                );
            }
        }
    }

    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => String::new(),
    };

    if let Some(gen) = extract_meta_generator(&body) {
        add_tech(&mut techs, &gen, "CMS/Generator", "<meta generator>".into());
    }

    let body_lower = body.to_lowercase();
    let body_rules: &[(&str, &str, &str)] = &[
        ("/wp-content/", "WordPress", "CMS"),
        ("/wp-includes/", "WordPress", "CMS"),
        ("wp-json", "WordPress REST API", "CMS"),
        ("/sites/default/files/", "Drupal", "CMS"),
        ("joomla!", "Joomla", "CMS"),
        ("/media/jui/", "Joomla", "CMS"),
        ("prestashop", "PrestaShop", "E-Commerce"),
        ("shopify.com/s/files", "Shopify", "E-Commerce"),
        ("woocommerce", "WooCommerce", "E-Commerce"),
        ("jquery", "jQuery", "JS Library"),
        ("bootstrap", "Bootstrap", "CSS Framework"),
        ("/react", "React", "JS Framework"),
        ("vue.js", "Vue.js", "JS Framework"),
        ("angular", "Angular", "JS Framework"),
        ("next.js", "Next.js", "JS Framework"),
        ("nuxt", "Nuxt.js", "JS Framework"),
        ("svelte", "Svelte", "JS Framework"),
        ("tailwind", "Tailwind CSS", "CSS Framework"),
        (
            "google-analytics.com/analytics.js",
            "Google Analytics UA",
            "Analytics",
        ),
        (
            "googletagmanager.com/gtm.js",
            "Google Tag Manager",
            "Analytics",
        ),
        ("gtag/js", "Google Analytics 4", "Analytics"),
        ("cdn.matomo", "Matomo", "Analytics"),
        ("cdnjs.cloudflare.com", "cdnjs", "CDN"),
        ("fonts.googleapis.com", "Google Fonts", "Fonts"),
    ];

    for (pattern, tech, category) in body_rules {
        if body_lower.contains(pattern) {
            add_tech(&mut techs, tech, category, format!("body: '{pattern}'"));
        }
    }

    let mut lines = vec![
        format!("URL: {url_str}"),
        format!("Detected: {} technologies", techs.len()),
        String::new(),
    ];

    let mut seen_cats: Vec<&str> = Vec::new();
    for t in &techs {
        if !seen_cats.contains(&t.category.as_str()) {
            seen_cats.push(&t.category);
        }
    }
    for cat in seen_cats {
        lines.push(format!("── {cat}"));
        for t in techs.iter().filter(|t| t.category == cat) {
            lines.push(format!("  {} ({})", t.name, t.evidence));
        }
        lines.push(String::new());
    }
    if techs.is_empty() {
        lines.push("No technologies identified.".into());
    }

    res.raw_output = Some(lines.join("\n"));
    res.technologies = techs;
    res.ok = true;
    res
}
