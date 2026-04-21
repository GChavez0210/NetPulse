export const MAX_POINTS = 60;
export const DOWN_THRESHOLD = 3;
export const MAX_ACTIVE_SESSIONS = 8;

export const HEALTH = {
  NORMAL: 'normal',
  DEGRADED: 'degraded',
  DOWN: 'down',
  UNKNOWN: 'unknown'
};

export function getHealth(test) {
  if (test.reachable === false) return HEALTH.DOWN;

  const lossPct = test.sent > 0 ? ((test.sent - test.received) * 100) / test.sent : 0;
  if (test.failureStreak > 0 || lossPct > 0) return HEALTH.DEGRADED;

  if (test.reachable === true) return HEALTH.NORMAL;
  return HEALTH.UNKNOWN;
}

export function formatHealthLabel(health) {
  if (health === HEALTH.NORMAL) return 'Normal';
  if (health === HEALTH.DEGRADED) return 'Degraded';
  if (health === HEALTH.DOWN) return 'Down';
  return 'No data';
}

export function getQueryType(text = '') {
  const lower = text.toLowerCase();
  if (lower.includes('traceroute')) return 'Traceroute';
  if (lower.includes('whois')) return 'WHOIS';
  return 'Ping';
}

export function getLatencyStatus(latencyMs) {
  if (latencyMs == null) return 'bad';
  if (latencyMs <= 60) return 'good';
  if (latencyMs <= 140) return 'warn';
  return 'bad';
}

export function getTestMetrics(test) {
  const latencies = test.points.map((p) => p.latency).filter((v) => v != null);
  const current = test.lastLatency;
  const avg = latencies.length > 0 ? latencies.reduce((a, b) => a + b, 0) / latencies.length : null;
  const max = latencies.length > 0 ? Math.max(...latencies) : null;
  const sorted = [...latencies].sort((a, b) => a - b);
  const percentile = (p) => {
    if (sorted.length === 0) return null;
    const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
    return sorted[idx];
  };
  const stddev =
    latencies.length > 1
      ? Math.sqrt(latencies.reduce((acc, v) => acc + Math.pow(v - avg, 2), 0) / latencies.length)
      : 0;
  return {
    current,
    avg,
    max,
    p50: percentile(50),
    p95: percentile(95),
    p99: percentile(99),
    stddev
  };
}

export function pickValue(source, keys, fallback = 'N/A') {
  for (const key of keys) {
    const value = source?.[key];
    if (value != null && value !== '') return value;
  }
  return fallback;
}

export function listValue(value) {
  if (Array.isArray(value)) return value.filter(Boolean);
  if (typeof value === 'string') {
    return value
      .split(/[,\n]/)
      .map((v) => v.trim())
      .filter(Boolean);
  }
  return [];
}

export function buildWhoisPresentation(dataWrapper, domain) {
  const isRawFallback = dataWrapper?.source && dataWrapper?.source.startsWith('WHOIS (');
  if (isRawFallback && dataWrapper.raw) {
    return {
      text: dataWrapper.raw,
      queryDomain: domain || 'unknown'
    };
  }

  const payload = dataWrapper?.data || dataWrapper?.normalized || dataWrapper || {};
  const queryDomain = pickValue(payload, ['domain_name', 'domain', 'domainName', 'name'], domain || 'unknown');

  const domainInfo = [
    ['Domain Name', queryDomain],
    ['Registry Domain ID', pickValue(payload, ['domain_id', 'registry_domain_id', 'id'])],
    ['Registrar WHOIS', pickValue(payload, ['whois_server', 'whoisServer'])],
    ['Registrar URL', pickValue(payload, ['registrar_url', 'url'])],
    ['Updated Date', pickValue(payload, ['updated_date', 'updatedDate'])],
    ['Creation Date', pickValue(payload, ['creation_date', 'creationDate'])],
    ['Registry Expiry Date', pickValue(payload, ['expiration_date', 'expiry_date', 'expiresDate'])],
    ['Registrar', pickValue(payload, ['registrar', 'registrar_name'])]
  ];

  const statuses = listValue(pickValue(payload, ['status', 'domain_status'], []));
  const nameServers = listValue(pickValue(payload, ['name_servers', 'nameServers', 'name_server'], []));

  const registrant = [
    ['Registrant Org', pickValue(payload, ['registrant_organization', 'registrant_org'])],
    ['Registrant Name', pickValue(payload, ['registrant_name', 'registrant'])],
    ['Registrant State', pickValue(payload, ['registrant_state', 'state'])],
    ['Registrant Country', pickValue(payload, ['registrant_country', 'country'])],
    ['Registrant Email', pickValue(payload, ['registrant_email', 'email'])]
  ];

  const lines = [];
  const pushKV = (label, value) => {
    lines.push({ type: 'kv', label, value: String(value || 'N/A') });
  };

  lines.push({ type: 'comment', value: `# WHOIS Lookup results for ${queryDomain}` });
  lines.push({ type: 'comment', value: `# Requested at: ${new Date().toISOString().replace('T', ' ').replace('Z', ' UTC')}` });
  lines.push({ type: 'blank' });

  lines.push({ type: 'section', value: '// Domain Information' });
  domainInfo.forEach(([k, v]) => pushKV(k, v));
  lines.push({ type: 'blank' });

  lines.push({ type: 'section', value: '// Domain Status' });
  if (statuses.length === 0) {
    pushKV('Status', 'N/A');
  } else {
    statuses.forEach((statusItem) => pushKV('Status', statusItem));
  }
  lines.push({ type: 'blank' });

  lines.push({ type: 'section', value: '// Name Servers' });
  if (nameServers.length === 0) {
    pushKV('Name Server', 'N/A');
  } else {
    nameServers.forEach((ns) => pushKV('Name Server', ns));
  }
  lines.push({ type: 'blank' });

  lines.push({ type: 'section', value: '// Registrant Contact Information' });
  registrant.forEach(([k, v]) => pushKV(k, v));

  const text = lines
    .map((line) => {
      if (line.type === 'kv') return `${line.label.padEnd(25)}: ${line.value}`;
      if (line.type === 'blank') return '';
      return line.value;
    })
    .join('\n');

  return { lines, text, queryDomain };
}

export function getFloodPacketState(sample) {
  if (!sample || sample.timeout) return 'failed';
  if (sample.rtt_ms != null && sample.rtt_ms > 80) return 'jitter';
  return 'success';
}

export function createTest(host) {
  return {
    id: `${host}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    host,
    phase: 'running',
    reachable: null,
    failureStreak: 0,
    points: [],
    sent: 0,
    received: 0,
    lastLatency: null,
    lastOutput: 'Initializing extended ping test...',
    viewMode: 'graph',
    events: []
  };
}
