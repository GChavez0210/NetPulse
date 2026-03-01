const dns = require('dns');

function isValidHost(host) {
    if (typeof host !== 'string') return false;
    if (host.length < 1 || host.length > 253) return false;
    return /^[a-zA-Z0-9.-]+$/.test(host);
}

async function validateDns(domain) {
    if (!isValidHost(domain)) {
        return { ok: false, error: 'Invalid domain.' };
    }

    const resolver = new dns.promises.Resolver();
    const summary = { score: 100, overallStatus: 'PASS' };
    const findings = [];
    const reportLines = [];

    try {
        reportLines.push(`DNS Validation Report for: ${domain}\n`);

        // 1. A/AAAA resolution
        let ipv4 = [];
        let ipv6 = [];
        try {
            ipv4 = await resolver.resolve4(domain);
            reportLines.push(`[A] Resolved to: ${ipv4.join(', ')}`);
            findings.push({ severity: 'info', check: 'A Record', message: `Found ${ipv4.length} IPv4 addresses.` });
        } catch (err) {
            reportLines.push(`[A] No A records found (${err.code}).`);
        }

        try {
            ipv6 = await resolver.resolve6(domain);
            reportLines.push(`[AAAA] Resolved to: ${ipv6.join(', ')}`);
            findings.push({ severity: 'info', check: 'AAAA Record', message: `Found ${ipv6.length} IPv6 addresses.` });
        } catch (err) {
            reportLines.push(`[AAAA] No AAAA records found.`);
        }

        if (ipv4.length === 0 && ipv6.length === 0) {
            summary.score -= 50;
            summary.overallStatus = 'FAIL';
            findings.push({ severity: 'error', check: 'Resolution', message: 'Domain does not resolve to any IP.' });
            reportLines.push(`\nERROR: Domain does not resolve to any IP address.`);
        }

        // Detect Private IPs
        const allIps = [...ipv4, ...ipv6];
        const isPrivate = allIps.some(ip => {
            // Basic IPv4 private space check
            if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
            if (ip.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)) return true;
            if (ip === '127.0.0.1' || ip === '::1') return true;
            return false;
        });

        if (isPrivate) {
            summary.score -= 20;
            summary.overallStatus = summary.overallStatus === 'FAIL' ? 'FAIL' : 'WARN';
            findings.push({ severity: 'warn', check: 'Routability', message: 'Domain resolves to a private/loopback IP address.' });
            reportLines.push(`\nWARNING: Resolves to private/loopback IP.`);
        }

        // 2. NS validation
        try {
            const ns = await resolver.resolveNs(domain);
            reportLines.push(`\n[NS] Nameservers:`);
            ns.forEach(n => reportLines.push(`  - ${n}`));
            if (ns.length < 2) {
                summary.score -= 10;
                summary.overallStatus = summary.overallStatus === 'FAIL' ? 'FAIL' : 'WARN';
                findings.push({ severity: 'warn', check: 'Nameservers', message: 'Less than 2 nameservers configured. Redundancy risk.' });
            } else {
                findings.push({ severity: 'success', check: 'Nameservers', message: `Found ${ns.length} nameservers.` });
            }
        } catch (err) {
            reportLines.push(`\n[NS] Failed to resolve nameservers.`);
            findings.push({ severity: 'error', check: 'Nameservers', message: 'Could not fetch NS records.' });
        }

        // 3. SOA Validation
        try {
            const soa = await resolver.resolveSoa(domain);
            reportLines.push(`\n[SOA] Primary: ${soa.nsname}, Admin: ${soa.hostmaster}, Serial: ${soa.serial}`);
            findings.push({ severity: 'success', check: 'SOA Record', message: 'SOA record is valid.' });
        } catch (err) {
            reportLines.push(`\n[SOA] Failed to resolve SOA (${err.code}).`);
            findings.push({ severity: 'warn', check: 'SOA Record', message: 'Missing or inaccessible SOA record.' });
        }

        // 4. CAA Validation
        try {
            const caa = await resolver.resolveCaa(domain);
            if (caa && caa.length > 0) {
                reportLines.push(`\n[CAA] Records found:`);
                caa.forEach(c => reportLines.push(`  - ${c.issue || c.issuewild || c.iodef || JSON.stringify(c)}`));
                findings.push({ severity: 'success', check: 'CAA Record', message: 'CAA security records are present.' });
            }
        } catch (err) {
            reportLines.push(`\n[CAA] No CAA records found.`);
            findings.push({ severity: 'info', check: 'CAA Record', message: 'No CAA records configured (optional but recommended).' });
        }

        return {
            ok: true,
            summary,
            findings,
            rawOutput: reportLines.join('\n')
        };

    } catch (err) {
        return { ok: false, error: err.message || 'Validation failed.' };
    }
}

async function healthCheckDns(domain) {
    if (!isValidHost(domain)) {
        return { ok: false, error: 'Invalid domain.' };
    }

    const resolvers = [
        { name: 'System Local', ips: undefined }, // uses default
        { name: 'Cloudflare (1.1.1.1)', ips: ['1.1.1.1', '1.0.0.1'] },
        { name: 'Google (8.8.8.8)', ips: ['8.8.8.8', '8.8.4.4'] }
    ];

    const results = {};
    const diffs = [];
    const reportLines = [`Multi-Resolver DNS Health Check for: ${domain}\n`];

    for (const res of resolvers) {
        const r = new dns.promises.Resolver();
        if (res.ips) r.setServers(res.ips);

        results[res.name] = { A: [], AAAA: [], NS: [] };

        // Check A
        try {
            const ips = await r.resolve4(domain);
            results[res.name].A = ips.sort();
        } catch (e) { /* empty */ }

        // Check AAAA
        try {
            const ips = await r.resolve6(domain);
            results[res.name].AAAA = ips.sort();
        } catch (e) { /* empty */ }

        // Check NS
        try {
            const ns = await r.resolveNs(domain);
            results[res.name].NS = ns.sort();
        } catch (e) { /* empty */ }

        reportLines.push(`[${res.name}]`);
        reportLines.push(`  IPv4: ${results[res.name].A.length ? results[res.name].A.join(', ') : 'None'}`);
        reportLines.push(`  IPv6: ${results[res.name].AAAA.length ? results[res.name].AAAA.join(', ') : 'None'}`);
        reportLines.push(`  NS:   ${results[res.name].NS.length ? results[res.name].NS.join(', ') : 'None'}\n`);
    }

    // Compare A records
    const cfA = results['Cloudflare (1.1.1.1)'].A.join(',');
    const ggA = results['Google (8.8.8.8)'].A.join(',');
    const loA = results['System Local'].A.join(',');

    if (cfA !== ggA || cfA !== loA) {
        diffs.push('A records differ across resolvers! Possible Split-Horizon DNS, load balancing, or propagation delay.');
    }

    const cfNS = results['Cloudflare (1.1.1.1)'].NS.join(',');
    const ggNS = results['Google (8.8.8.8)'].NS.join(',');
    const loNS = results['System Local'].NS.join(',');

    if (cfNS !== ggNS || cfNS !== loNS) {
        diffs.push('Nameservers differ across resolvers! Highly indicative of recent DNS delegation changes propagating.');
    }

    if (diffs.length > 0) {
        reportLines.push(`--- INCONSISTENCIES DETECTED ---`);
        diffs.forEach(d => reportLines.push(`! ${d}`));
    } else {
        reportLines.push(`--- HEALTHY ---`);
        reportLines.push(`All resolvers returned consistent critical records.`);
    }

    return {
        ok: true,
        perResolverResults: results,
        diffs,
        rawOutput: reportLines.join('\n')
    };
}

async function validateDmarc(domain) {
    if (!isValidHost(domain)) {
        return { ok: false, error: 'Invalid domain.' };
    }

    const resolver = new dns.promises.Resolver();
    const dmarcDomain = `_dmarc.${domain}`;
    const issues = [];
    const parsed = {};
    let rawRecord = '';
    const reportLines = [`DMARC Validation for: ${domain}\n`];

    try {
        const txtRecords = await resolver.resolveTxt(dmarcDomain);

        // Find the actual DMARC record (starts with v=DMARC1)
        let dmarcString = null;
        for (const chunkGroup of txtRecords) {
            const fullString = chunkGroup.join('');
            if (fullString.startsWith('v=DMARC1')) {
                dmarcString = fullString;
                break;
            }
        }

        if (!dmarcString) {
            return {
                ok: true,
                parsed: null,
                issues: ['No valid v=DMARC1 record found.'],
                rawOutput: `Failed to find v=DMARC1 TXT record at ${dmarcDomain}.`
            };
        }

        rawRecord = dmarcString;
        reportLines.push(`Raw Record: ${rawRecord}\n`);

        const parts = dmarcString.split(';').map(p => p.trim()).filter(Boolean);

        parts.forEach(part => {
            const [key, ...valArr] = part.split('=');
            const val = valArr.join('=').trim();
            parsed[key.toLowerCase()] = val;
        });

        // Validate
        if (parsed.v !== 'DMARC1') {
            issues.push('Version (v) must be exactly "DMARC1".');
        }

        if (!parsed.p) {
            issues.push('Policy (p) tag is missing but required.');
        } else if (!['none', 'quarantine', 'reject'].includes(parsed.p.toLowerCase())) {
            issues.push(`Invalid policy (p): ${parsed.p}. Must be none, quarantine, or reject.`);
        }

        if (parsed.sp && !['none', 'quarantine', 'reject'].includes(parsed.sp.toLowerCase())) {
            issues.push(`Invalid subdomain policy (sp): ${parsed.sp}.`);
        }

        if (parsed.pct) {
            const pct = parseInt(parsed.pct, 10);
            if (isNaN(pct) || pct < 0 || pct > 100) {
                issues.push(`Invalid percentage (pct): ${parsed.pct}. Must be 0-100.`);
            }
        }

        if (!parsed.rua) {
            issues.push('Aggregate reporting URI (rua) is missing. You will not receive reports.');
        }

        reportLines.push(`Parsed Configuration:`);
        reportLines.push(`- Version (v): ${parsed.v || 'MISSING'}`);
        reportLines.push(`- Policy (p): ${parsed.p || 'MISSING'}`);
        if (parsed.sp) reportLines.push(`- Subdomain Policy (sp): ${parsed.sp}`);
        if (parsed.pct) reportLines.push(`- Percentage (pct): ${parsed.pct}%`);
        if (parsed.rua) reportLines.push(`- Aggregate Reports (rua): ${parsed.rua}`);
        if (parsed.ruf) reportLines.push(`- Forensic Reports (ruf): ${parsed.ruf}`);

        if (issues.length > 0) {
            reportLines.push(`\n--- DMARC ISSUES ---`);
            issues.forEach(i => reportLines.push(`! ${i}`));
        } else {
            reportLines.push(`\n--- SYNTAX VALID ---`);
            reportLines.push(`DMARC record syntax meets basic standard requirements.`);
            if (parsed.p && parsed.p.toLowerCase() === 'none') {
                reportLines.push(`Note: Policy is 'none', meaning no enforcement is active.`);
            }
        }

        return {
            ok: true,
            parsed,
            issues,
            rawOutput: reportLines.join('\n')
        };

    } catch (err) {
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
            return {
                ok: true,
                parsed: null,
                issues: ['No DMARC record found (ENODATA/ENOTFOUND).'],
                rawOutput: `No DMARC record found at ${dmarcDomain}.`
            };
        }
        return { ok: false, error: err.message || 'DMARC validation failed.' };
    }
}

module.exports = {
    validateDns,
    healthCheckDns,
    validateDmarc
};
