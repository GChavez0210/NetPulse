export const MAX_POINTS = 60;
export const DOWN_THRESHOLD = 3;
export const MAX_ACTIVE_SESSIONS = 16;
export const HEALTH_WINDOW = 100;

// Parses a numeric input value, falling back to `fallback` when the input is
// empty, non-numeric, or out of [min, max] — guards against NaN slipping
// through to invoke() when a number field is cleared or mid-edit.
export function parseIntOrDefault(value, fallback, min = -Infinity, max = Infinity) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) return fallback;
  return parsed;
}

export const HEALTH = {
  NORMAL: 'normal',
  DEGRADED: 'degraded',
  DOWN: 'down',
  UNKNOWN: 'unknown'
};

// Why a target is degraded, as distinct from how badly. Both LOSS and JITTER
// are the same severity — they differ in what's actually wrong, which is what
// the card label needs to say.
export const HEALTH_REASON = {
  UNREACHABLE: 'unreachable',
  LOSS: 'loss',
  JITTER: 'jitter'
};

// Jitter measured as spread relative to the average, so the rule holds on a
// 2 ms LAN and a 600 ms satellite link alike; the floor keeps sub-millisecond
// wobble on fast links from tripping it. Mirrors the flood tab's spike rule.
export const JITTER_RATIO = 0.3;
export const JITTER_FLOOR_MS = 5;

export function isJittery(metrics) {
  if (!metrics || metrics.avg == null || metrics.stddev == null) return false;
  return metrics.stddev >= JITTER_FLOOR_MS && metrics.stddev > JITTER_RATIO * metrics.avg;
}

// `metrics` is optional — callers that already computed it can pass it in
// rather than paying for getTestMetrics twice per render.
export function getHealthReason(test, metrics) {
  if (test.reachable === false) return HEALTH_REASON.UNREACHABLE;

  const recent = test.recentResults || [];
  const lossPct =
    recent.length > 0 ? (recent.filter((ok) => !ok).length * 100) / recent.length : 0;
  // Loss outranks jitter: a dropped packet is the more serious finding, and
  // reporting it as jitter is what made the old label wrong.
  if (test.failureStreak > 0 || lossPct > 0) return HEALTH_REASON.LOSS;

  if (isJittery(metrics ?? getTestMetrics(test))) return HEALTH_REASON.JITTER;
  return null;
}

export function getHealth(test, metrics) {
  const reason = getHealthReason(test, metrics);
  if (reason === HEALTH_REASON.UNREACHABLE) return HEALTH.DOWN;
  if (reason) return HEALTH.DEGRADED;
  if (test.reachable === true) return HEALTH.NORMAL;
  return HEALTH.UNKNOWN;
}

export function formatHealthReason(reason) {
  if (reason === HEALTH_REASON.UNREACHABLE) return 'TIMEOUT';
  if (reason === HEALTH_REASON.LOSS) return 'LOSS';
  if (reason === HEALTH_REASON.JITTER) return 'JITTER';
  return 'STABLE';
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
  // Match on the source label the backend uses today, but fall back to a
  // structural check (rdap_server is only ever populated by the RDAP path)
  // so a future label change on either side can't silently misroute this
  // into the domain-WHOIS formatting branch below.
  const isRdap =
    dataWrapper?.source === 'RDAP' ||
    dataWrapper?.source?.startsWith?.('RDAP') ||
    typeof dataWrapper?.normalized?.rdap_server === 'string';
  if (isRdap) {
    const payload = dataWrapper?.normalized || {};
    const ip = dataWrapper?.query || domain || 'unknown';
    const lines = [];
    const pushKV = (label, value) => {
      if (value && value !== '') lines.push({ type: 'kv', label, value: String(value) });
    };

    lines.push({ type: 'comment', value: `# RDAP IP Lookup results for ${ip}` });
    lines.push({ type: 'comment', value: `# Source: ${payload.rdap_server || 'RDAP'}` });
    lines.push({ type: 'comment', value: `# Requested at: ${new Date().toISOString().replace('T', ' ').replace('Z', ' UTC')}` });
    lines.push({ type: 'blank' });

    lines.push({ type: 'section', value: '// Network Information' });
    lines.push({ type: 'kv', label: 'IP Address', value: ip });
    pushKV('Network Name', payload.name);
    pushKV('CIDR Block', payload.cidr);
    pushKV('Start Address', payload.start_address);
    pushKV('End Address', payload.end_address);
    pushKV('Network Type', payload.type);
    pushKV('Country', payload.country);
    lines.push({ type: 'blank' });

    lines.push({ type: 'section', value: '// Registration' });
    pushKV('Owner / Registrant', payload.owner);
    pushKV('RDAP Server', payload.rdap_server);

    const text = lines
      .map((line) => {
        if (line.type === 'kv') return `${line.label.padEnd(25)}: ${line.value}`;
        if (line.type === 'blank') return '';
        return line.value;
      })
      .join('\n');

    return { lines, text, queryDomain: ip };
  }

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

// A packet is a spike when it is well above this run's own baseline, not above
// a fixed millisecond count: 80 ms is unremarkable on a satellite link and a
// serious excursion on a LAN. The ratio makes the rule scale-free; the floor
// stops sub-millisecond wobble on very fast links from flagging constantly.
export const SPIKE_RATIO = 2;
export const SPIKE_FLOOR_MS = 5;
// Replies sampled before the baseline is fixed. Frozen rather than rolling so
// a long degradation can't drag the baseline up to meet itself.
export const SPIKE_BASELINE_SAMPLES = 20;

export function medianOf(values) {
  if (!values || values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

/// Classify one reply against the run baseline. Until the baseline exists there
/// is nothing to compare against, so replies read as normal.
export function classifyRtt(rtt, baseline) {
  if (rtt == null) return 'success';
  if (baseline == null) return 'success';
  return rtt > baseline * SPIKE_RATIO && rtt - baseline >= SPIKE_FLOOR_MS ? 'jitter' : 'success';
}

export function getFloodPacketState(sample, baseline) {
  if (!sample || sample.timeout) return 'failed';
  return classifyRtt(sample.rtt_ms, baseline);
}

export function createTest(host) {
  return {
    id: `${host}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    host,
    alias: '',
    interval: 1000,
    phase: 'running',
    reachable: null,
    failureStreak: 0,
    points: [],
    recentResults: [],
    sent: 0,
    received: 0,
    lastLatency: null,
    lastTtl: null,
    // Retained across samples so a change in path length can be flagged.
    prevTtl: null,
    ttlChanges: 0,
    lastOutput: 'Initializing extended ping test...',
    viewMode: 'graph',
    events: []
  };
}
