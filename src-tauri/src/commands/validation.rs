#[allow(dead_code)]
pub fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("Host must not be empty".to_string());
    }
    if host.len() > 253 {
        return Err("Host must be 253 characters or fewer".to_string());
    }
    // Allow alphanumeric, dots, hyphens, underscores, colons (IPv6), brackets (IPv6 literal), percent (zone ID)
    if !host.chars().all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']' | '%')) {
        return Err(format!("Host '{host}' contains invalid characters"));
    }
    Ok(())
}

#[allow(dead_code)]
pub fn validate_ip(ip: &str) -> Result<(), String> {
    ip.parse::<std::net::IpAddr>()
        .map(|_| ())
        .map_err(|_| format!("'{ip}' is not a valid IP address"))
}
