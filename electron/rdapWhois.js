const https = require('https');
const net = require('net');

function lookupRdap(ip) {
    return new Promise((resolve) => {
        const req = https.get(`https://rdap.org/ip/${ip}`, { timeout: 4000 }, (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try {
                        const parsed = JSON.parse(data);
                        const normalized = {
                            name: parsed.name || '',
                            country: parsed.country || '',
                            type: parsed.type || '',
                            cidr: '',
                            owner: '',
                            contacts: []
                        };

                        // Extract CIDR if available
                        if (parsed.network && parsed.network.cidr) {
                            normalized.cidr = parsed.network.cidr;
                        } else if (parsed.cidr0_cidrs && parsed.cidr0_cidrs.length > 0) {
                            const c = parsed.cidr0_cidrs[0];
                            if (c.v4prefix && c.length) {
                                normalized.cidr = `${c.v4prefix}/${c.length}`;
                            }
                        }

                        if (parsed.entities && parsed.entities.length > 0) {
                            const primary = parsed.entities[0];
                            if (primary.vcardArray && primary.vcardArray.length > 1) {
                                const orgCard = primary.vcardArray[1].find(c => c[0] === 'fn');
                                if (orgCard) normalized.owner = orgCard[3];
                            }
                        }

                        resolve({ ok: true, source: 'RDAP', normalized, raw: JSON.stringify(parsed, null, 2) });
                    } catch (e) {
                        resolve({ ok: false, error: 'RDAP Parse Error', output: data });
                    }
                } else {
                    resolve({ ok: false, error: `RDAP HTTP ${res.statusCode}`, output: data });
                }
            });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({ ok: false, error: 'RDAP Timeout' });
        });

        req.on('error', (e) => {
            resolve({ ok: false, error: `RDAP Error: ${e.message}` });
        });
    });
}

function lookupRawWhois(query, server = 'whois.iana.org') {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        let data = '';
        let settled = false;

        socket.setTimeout(5000);

        const finish = (result) => {
            if (settled) return;
            settled = true;
            socket.destroy();
            resolve(result);
        };

        socket.connect(43, server, () => {
            socket.write(`${query}\r\n`);
        });

        socket.on('data', chunk => {
            data += chunk.toString();
            if (data.length > 50000) finish({ ok: false, error: 'WHOIS output too large' }); // limit
        });

        socket.on('timeout', () => {
            finish({ ok: false, error: 'WHOIS Timeout' });
        });

        socket.on('error', (err) => {
            finish({ ok: false, error: `WHOIS Error: ${err.message}` });
        });

        socket.on('end', () => {
            finish({ ok: true, source: `WHOIS (${server})`, raw: data });
        });
    });
}

async function orchestrateWhoisFallback(query) {
    // If IP, try RDAP first
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(query); // Basic IPv4 check

    if (isIp) {
        const rdapResult = await lookupRdap(query);
        if (rdapResult.ok) {
            return rdapResult;
        }
    }

    // Fallback to WHOIS port 43
    // First query iana wrapper
    const referralResult = await lookupRawWhois(query, 'whois.iana.org');

    if (referralResult.ok && referralResult.raw) {
        const lines = referralResult.raw.split('\n');
        let referServer = null;
        for (const line of lines) {
            if (line.toLowerCase().startsWith('refer:')) {
                referServer = line.split(':')[1].trim();
                break;
            }
            if (line.toLowerCase().startsWith('whois:')) {
                referServer = line.split(':')[1].trim();
                break;
            }
        }

        if (referServer) {
            // Query the referred server
            const finalResult = await lookupRawWhois(query, referServer);
            if (finalResult.ok) {
                return { ok: true, source: `WHOIS (${referServer})`, normalized: { name: query }, raw: finalResult.raw };
            }
        }

        // Return IANA result if no referral
        return { ok: true, source: 'WHOIS (IANA)', normalized: { name: query }, raw: referralResult.raw };
    }

    return { ok: false, error: 'All WHOIS fallbacks failed.' };
}

module.exports = {
    orchestrateWhoisFallback
};
