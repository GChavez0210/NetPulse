import { useEffect, useMemo, useRef, useState } from 'react';
import netPulseLogo from '../../NetPulse-logo.png';

const MAX_POINTS = 60;
const DOWN_THRESHOLD = 3;
const MAX_ACTIVE_SESSIONS = 8;

const HEALTH = {
  NORMAL: 'normal',
  DEGRADED: 'degraded',
  DOWN: 'down',
  UNKNOWN: 'unknown'
};
const TABS = [
  {
    id: 'ping',
    label: 'Multi-Target Ping',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--warning)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
    )
  },
  {
    id: 'trace',
    label: 'Topology (Trace)',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="18" cy="18" r="3"></circle><circle cx="6" cy="6" r="3"></circle><path d="M13 6h3a2 2 0 0 1 2 2v7"></path><path d="M6 9v2a2 2 0 0 0 2 2h3"></path></svg>
    )
  },
  {
    id: 'packetloss',
    label: 'Flood Test',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
    )
  },
  {
    id: 'diagnostics',
    label: 'Analytics',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
    )
  },
  {
    id: 'whois',
    label: 'Identity (WHOIS)',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#a855f7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
    )
  }
];

function getHealth(test) {
  if (test.reachable === false) return HEALTH.DOWN;

  const lossPct = test.sent > 0 ? ((test.sent - test.received) * 100) / test.sent : 0;
  if (test.failureStreak > 0 || lossPct > 0) return HEALTH.DEGRADED;

  if (test.reachable === true) return HEALTH.NORMAL;
  return HEALTH.UNKNOWN;
}

function formatHealthLabel(health) {
  if (health === HEALTH.NORMAL) return 'Normal';
  if (health === HEALTH.DEGRADED) return 'Degraded';
  if (health === HEALTH.DOWN) return 'Down';
  return 'No data';
}

function getQueryType(text = '') {
  const lower = text.toLowerCase();
  if (lower.includes('traceroute')) return 'Traceroute';
  if (lower.includes('whois')) return 'WHOIS';
  return 'Ping';
}

function getLatencyStatus(latencyMs) {
  if (latencyMs == null) return 'bad';
  if (latencyMs <= 60) return 'good';
  if (latencyMs <= 140) return 'warn';
  return 'bad';
}

function getTestMetrics(test) {
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

function parseTracerouteLine(rawLine) {
  const line = rawLine.trim();
  if (!line) return null;
  if (/^tracing route/i.test(line)) return null;
  if (/^trace complete/i.test(line)) return null;
  if (/^over a maximum/i.test(line)) return null;

  const hopMatch = line.match(/^(\d+)\s+(.*)$/);
  if (!hopMatch) return null;

  const hop = Number.parseInt(hopMatch[1], 10);
  const rest = hopMatch[2];
  const latencyMatches = [...rest.matchAll(/<?\s*(\d+(?:\.\d+)?)\s*ms/gi)];
  const latencies = latencyMatches.map((m) => Number.parseFloat(m[1])).filter((v) => Number.isFinite(v));
  const avgLatency = latencies.length > 0 ? latencies.reduce((a, b) => a + b, 0) / latencies.length : null;

  const ipv4Match = rest.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
  const ipv6Match = rest.match(/([a-fA-F0-9:]{2,})/);
  const ip = ipv4Match?.[1] || ipv6Match?.[1] || 'Unknown';

  let hostname = 'Unknown';
  if (ipv4Match?.[1]) {
    const beforeIp = rest.slice(0, rest.indexOf(ipv4Match[1])).trim();
    if (beforeIp && !beforeIp.includes('ms') && !beforeIp.includes('*')) {
      hostname = beforeIp;
    }
  }

  return {
    hop,
    ip,
    hostname,
    latencies,
    avgLatency,
    status: getLatencyStatus(avgLatency),
    timedOut: rest.includes('*')
  };
}

function parseTracerouteOutput(output) {
  const lines = String(output || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const hops = lines.map(parseTracerouteLine).filter(Boolean);
  const avgCandidates = hops.map((h) => h.avgLatency).filter((v) => v != null);
  const avgRtt = avgCandidates.length > 0 ? avgCandidates.reduce((a, b) => a + b, 0) / avgCandidates.length : null;

  return {
    hops,
    totalHops: hops.length,
    avgRtt
  };
}

function pickValue(source, keys, fallback = 'N/A') {
  for (const key of keys) {
    const value = source?.[key];
    if (value != null && value !== '') return value;
  }
  return fallback;
}

function listValue(value) {
  if (Array.isArray(value)) return value.filter(Boolean);
  if (typeof value === 'string') {
    return value
      .split(/[,\n]/)
      .map((v) => v.trim())
      .filter(Boolean);
  }
  return [];
}

function buildWhoisPresentation(dataWrapper, domain) {
  // If this is a raw text fallback (like Port 43 WHOIS), just dump the raw text directly.
  const isRawFallback = dataWrapper?.source && dataWrapper?.source.startsWith('WHOIS (');
  if (isRawFallback && dataWrapper.raw) {
    return {
      text: dataWrapper.raw,
      queryDomain: domain || 'unknown'
    };
  }

  // Extract the actual payload from our Phase 6 wrapper, or use the wrapper itself if old format
  const payload = dataWrapper?.data || dataWrapper?.normalized || dataWrapper || {};
  const isFallback = !!dataWrapper?.normalized;

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

function getFloodPacketState(sample) {
  if (!sample || sample.timeout) return 'failed';
  if (sample.rtt_ms != null && sample.rtt_ms > 80) return 'jitter';
  return 'success';
}

function LineChart({ points, health, liveLabel, events = [] }) {
  const width = 900;
  const height = 250;
  const padding = 26;

  const valid = useMemo(() => points.filter((p) => p.latency != null), [points]);

  const maxY = useMemo(() => {
    const rawMax = Math.max(...valid.map((p) => p.latency), 1);
    const step = 25;
    return Math.ceil(rawMax / step) * step;
  }, [valid]);

  const markers = useMemo(() => {
    if (valid.length === 0) return [];

    return valid.map((point, index) => {
      const x = padding + (index * (width - padding * 2)) / Math.max(valid.length - 1, 1);
      const normalized = point.latency / (maxY || 1);
      const y = height - padding - normalized * (height - padding * 2);
      return { x, y, latency: point.latency };
    });
  }, [maxY, valid]);

  const plotted = useMemo(() => markers.map((m) => `${m.x},${m.y}`).join(' '), [markers]);
  const lastMarker = markers.length > 0 ? markers[markers.length - 1] : null;
  const latestLabelX = lastMarker ? Math.max(lastMarker.x - 20, padding + 88) : 0;
  const yTicks = 5;
  const grid = Array.from({ length: yTicks + 1 }, (_, i) => {
    const ratio = i / yTicks;
    return {
      y: height - padding - ratio * (height - padding * 2),
      value: Math.round(ratio * maxY)
    };
  });

  const eventMarkers = useMemo(() => {
    if (markers.length === 0 || events.length === 0) return [];
    return events
      .map((event) => {
        const idx = points.findIndex((point) => point.ts >= event.ts && point.latency != null);
        if (idx < 0 || idx >= markers.length) return null;
        return { ...event, x: markers[idx].x };
      })
      .filter(Boolean);
  }, [events, markers, points]);

  return (
    <div className={`chart-wrap chart-${health}`}>
      <span className={`live-badge ${health}`}>{liveLabel}</span>
      <svg viewBox={`0 0 ${width} ${height}`} className="line-chart" role="img" aria-label="Live ping latency graph">
        <rect x="0" y="0" width={width} height={height} className="chart-bg" />
        {grid.map((tick) => (
          <g key={tick.value}>
            <line x1={padding} y1={tick.y} x2={width - padding} y2={tick.y} className="grid-line" />
            <text x={padding + 4} y={tick.y - 4} className="grid-label">
              {tick.value} ms
            </text>
          </g>
        ))}
        <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} className="axis" />
        <line x1={padding} y1={padding} x2={padding} y2={height - padding} className="axis" />
        {plotted ? (
          <>
            <polyline points={plotted} className="line" />
            {markers.map((marker, index) => (
              <circle key={`${marker.x}-${marker.y}-${index}`} cx={marker.x} cy={marker.y} r="3.3" className="point-marker" />
            ))}
            {lastMarker ? (
              <text
                x={latestLabelX}
                y={Math.max(lastMarker.y - 8, padding + 10)}
                textAnchor="end"
                className="latest-label"
              >
                {lastMarker.latency.toFixed(1)} ms
              </text>
            ) : null}
            {eventMarkers.map((event) => (
              <g key={event.id}>
                <line x1={event.x} y1={padding} x2={event.x} y2={height - padding} className={`event-marker ${event.kind}`} />
              </g>
            ))}
          </>
        ) : null}
      </svg>
      {plotted ? null : <p className="chart-empty">No successful ping samples yet.</p>}
    </div>
  );
}

function createTest(host) {
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

function App() {
  const [activeTab, setActiveTab] = useState('ping');
  const [hostInput, setHostInput] = useState('');
  const [pingEntryMode, setPingEntryMode] = useState('single');

  // Isolated Analytics Input States
  const [tcpHostInput, setTcpHostInput] = useState('');
  const [mtrHostInput, setMtrHostInput] = useState('');
  const [dnsHostInput, setDnsHostInput] = useState('');
  const [portScanHostInput, setPortScanHostInput] = useState('');
  const [floodHostInput, setFloodHostInput] = useState('');

  const [bulkHostsInput, setBulkHostsInput] = useState('');
  const [whoisInput, setWhoisInput] = useState('');
  const [tests, setTests] = useState([]);
  const [rapidCount, setRapidCount] = useState(100);
  const [rapidRunning, setRapidRunning] = useState(false);
  const [rapidDetails, setRapidDetails] = useState({
    host: '',
    mode: 'ICMP',
    sent: 0,
    received: 0,
    lost: 0,
    lossPct: 0,
    jitterCount: 0,
    avgLatency: null,
    minRtt: null,
    maxRtt: null,
    p95Rtt: null,
    jitterMs: null,
    lossStreakMax: 0,
    status: 'idle',
    packetStates: [],
    logLines: [{ type: 'meta', text: '[init] Ready for packet loss diagnostics.' }]
  });
  const [notifications, setNotifications] = useState([]);
  const [traceOutput, setTraceOutput] = useState('No traceroute execution yet.');
  const [traceHops, setTraceHops] = useState([]);
  const [traceSummary, setTraceSummary] = useState({ totalHops: 0, avgRtt: null });
  const [traceHost, setTraceHost] = useState('');
  const [traceLoading, setTraceLoading] = useState(false);
  const [mtrRounds, setMtrRounds] = useState(5);
  const [mtrLoading, setMtrLoading] = useState(false);
  const [mtrResult, setMtrResult] = useState(null);
  const [tcpPort, setTcpPort] = useState(443);
  const [tcpResult, setTcpResult] = useState(null);
  const [dnsType, setDnsType] = useState('A');
  const [dnsResult, setDnsResult] = useState(null);
  const [portListInput, setPortListInput] = useState('22,80,443,3389');
  const [portScanResult, setPortScanResult] = useState(null);
  const [packetSize, setPacketSize] = useState(56);
  const [dontFragment, setDontFragment] = useState(false);
  const [whoisData, setWhoisData] = useState(null);
  const [whoisLoading, setWhoisLoading] = useState(false);
  const [status, setStatus] = useState('Ready.');

  // Phase 6 Tools State
  const [dnsValInput, setDnsValInput] = useState('');
  const [dnsValLoading, setDnsValLoading] = useState(false);
  const [dnsValResult, setDnsValResult] = useState(null);

  const [dnsHealthInput, setDnsHealthInput] = useState('');
  const [dnsHealthLoading, setDnsHealthLoading] = useState(false);
  const [dnsHealthResult, setDnsHealthResult] = useState(null);

  const [dmarcInput, setDmarcInput] = useState('');
  const [dmarcLoading, setDmarcLoading] = useState(false);
  const [dmarcResult, setDmarcResult] = useState(null);

  const [macInput, setMacInput] = useState('');
  const [macLoading, setMacLoading] = useState(false);
  const [macResult, setMacResult] = useState(null);

  const timersRef = useRef(new Map());
  const inFlightRef = useRef(new Set());
  const testsRef = useRef(tests);
  const whoisPresentation = useMemo(() => buildWhoisPresentation(whoisData, whoisInput.trim()), [whoisData, whoisInput]);

  useEffect(() => {
    testsRef.current = tests;
  }, [tests]);

  useEffect(() => {
    if (typeof Notification !== 'undefined' && Notification.permission === 'default') {
      Notification.requestPermission().catch(() => { });
    }

    return () => {
      for (const timer of timersRef.current.values()) {
        clearInterval(timer);
      }
      timersRef.current.clear();
      inFlightRef.current.clear();
      window.networkAPI.cancelFloodPing().catch(() => { });
    };
  }, []);

  useEffect(() => {
    const unsubscribeSample = window.networkAPI.onFloodPingSample((sample) => {
      if (!sample || typeof sample.seq !== 'number') return;
      setRapidDetails((prev) => {
        const nextStates = [...prev.packetStates];
        const index = sample.seq - 1;
        if (index >= 0 && index < nextStates.length) {
          nextStates[index] = getFloodPacketState(sample);
        }

        const received = nextStates.filter((state) => state !== 'failed' && state !== 'pending').length;
        const sent = nextStates.filter((state) => state !== 'pending').length;
        const lost = Math.max(sent - received, 0);
        const lossPct = sent > 0 ? Number(((lost * 100) / sent).toFixed(2)) : 0;
        const jitterCount = nextStates.filter((state) => state === 'jitter').length;
        const logType = sample.timeout ? 'failed' : sample.rtt_ms > 80 ? 'jitter' : 'success';
        const logText = sample.timeout
          ? `[${sample.timestamp}] seq=${sample.seq} timeout`
          : `[${sample.timestamp}] seq=${sample.seq} rtt=${sample.rtt_ms}ms`;

        return {
          ...prev,
          sent,
          received,
          lost,
          lossPct,
          jitterCount,
          packetStates: nextStates,
          logLines: [...prev.logLines, { type: logType, text: logText }].slice(-700)
        };
      });
    });

    const unsubscribeDone = window.networkAPI.onFloodPingDone((payload) => {
      const summary = payload?.summary;
      if (!summary) return;
      setRapidDetails((prev) => ({
        ...prev,
        sent: summary.sent ?? prev.sent,
        received: summary.received ?? prev.received,
        lost: Math.max((summary.sent ?? prev.sent) - (summary.received ?? prev.received), 0),
        lossPct: summary.loss_pct ?? prev.lossPct,
        avgLatency: summary.avg_rtt_ms ?? null,
        minRtt: summary.min_rtt_ms ?? null,
        maxRtt: summary.max_rtt_ms ?? null,
        p95Rtt: summary.p95_rtt_ms ?? null,
        jitterMs: summary.jitter_ms ?? null,
        lossStreakMax: summary.lossStreakMax ?? 0,
        status: summary.status || 'done',
        logLines: [
          ...prev.logLines,
          {
            type: 'meta',
            text: `[${new Date().toISOString()}] Flood ${summary.status || 'done'}: sent=${summary.sent}, recv=${summary.received}, loss=${summary.loss_pct}%`
          }
        ].slice(-700)
      }));
      setRapidRunning(false);
    });

    const unsubscribeStatus = window.networkAPI.onFloodPingStatus((payload) => {
      if (!payload) return;
      if (payload.message) setStatus(payload.message);
      if (payload.status === 'error' || payload.status === 'done' || payload.status === 'cancelled') {
        setRapidRunning(false);
      }
      setRapidDetails((prev) => ({
        ...prev,
        status: payload.status || prev.status,
        logLines: payload.message
          ? [...prev.logLines, { type: payload.status === 'error' ? 'failed' : 'meta', text: payload.message }].slice(-700)
          : prev.logLines
      }));
    });

    return () => {
      if (typeof unsubscribeSample === 'function') unsubscribeSample();
      if (typeof unsubscribeDone === 'function') unsubscribeDone();
      if (typeof unsubscribeStatus === 'function') unsubscribeStatus();
    };
  }, []);

  const pushNotification = (host, type, text) => {
    const note = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      host,
      type,
      text,
      time: new Date().toLocaleTimeString('en-US')
    };

    setNotifications((prev) => [note, ...prev].slice(0, 20));

    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      new Notification(`Ping status changed: ${host}`, { body: text });
    }
  };

  const stopTimer = (id) => {
    const timer = timersRef.current.get(id);
    if (timer) {
      clearInterval(timer);
      timersRef.current.delete(id);
    }
  };

  const applyPingSample = (id, result) => {
    let emitted = null;

    setTests((prev) =>
      prev.map((test) => {
        if (test.id !== id) return test;

        const isSuccess = result.ok && result.latencyMs != null;
        const failureStreak = isSuccess ? 0 : test.failureStreak + 1;

        let reachable = test.reachable;
        if (isSuccess) {
          if (test.reachable !== true) {
            emitted = { type: 'up', text: 'Host recovered and is responding again.' };
          }
          reachable = true;
        } else if (failureStreak >= DOWN_THRESHOLD && test.reachable !== false) {
          emitted = {
            type: 'down',
            text: `Host is down after ${failureStreak} consecutive failed pings.`
          };
          reachable = false;
        }

        const nextPoints = isSuccess
          ? [...test.points, { ts: Date.now(), latency: result.latencyMs }].slice(-MAX_POINTS)
          : test.points;
        const nowTs = Date.now();
        const nextEvents = [...test.events];
        if (emitted?.type === 'up') {
          nextEvents.push({ id: `${nowTs}-up`, ts: nowTs, kind: 'up' });
        } else if (emitted?.type === 'down') {
          nextEvents.push({ id: `${nowTs}-down`, ts: nowTs, kind: 'down' });
        }

        return {
          ...test,
          reachable,
          failureStreak,
          points: nextPoints,
          events: nextEvents.slice(-20),
          sent: test.sent + 1,
          received: test.received + (isSuccess ? 1 : 0),
          lastLatency: isSuccess ? result.latencyMs : null,
          lastOutput: result.output || 'No output.'
        };
      })
    );

    if (emitted) {
      const target = testsRef.current.find((t) => t.id === id);
      if (target) {
        pushNotification(target.host, emitted.type, emitted.text);
      }
    }
  };

  const samplePing = async (id) => {
    if (inFlightRef.current.has(id)) return;

    const target = testsRef.current.find((t) => t.id === id);
    if (!target || target.phase !== 'running') return;

    inFlightRef.current.add(id);
    try {
      const result = await window.networkAPI.pingSample(target.host, { packetSize, dontFragment });
      applyPingSample(id, result);
    } catch (error) {
      applyPingSample(id, {
        ok: false,
        latencyMs: null,
        output: String(error?.message || error || 'Ping request failed')
      });
    } finally {
      inFlightRef.current.delete(id);
    }
  };

  const startTest = (id) => {
    const target = testsRef.current.find((t) => t.id === id);
    const running = testsRef.current.filter((t) => t.phase === 'running').length;
    if (target && target.phase !== 'running' && running >= MAX_ACTIVE_SESSIONS) {
      setStatus(`Cannot start more than ${MAX_ACTIVE_SESSIONS} active sessions.`);
      return;
    }

    stopTimer(id);
    setTests((prev) => prev.map((t) => (t.id === id ? { ...t, phase: 'running' } : t)));

    samplePing(id);
    const timer = setInterval(() => {
      samplePing(id);
    }, 1000);

    timersRef.current.set(id, timer);
  };

  const pauseTest = (id) => {
    stopTimer(id);
    setTests((prev) => prev.map((t) => (t.id === id ? { ...t, phase: 'paused' } : t)));
  };

  const stopTest = (id) => {
    stopTimer(id);
    setTests((prev) => prev.map((t) => (t.id === id ? { ...t, phase: 'stopped' } : t)));
  };

  const removeTest = (id) => {
    stopTimer(id);
    inFlightRef.current.delete(id);
    setTests((prev) => prev.filter((t) => t.id !== id));
  };

  const toggleTestViewMode = (id) => {
    setTests((prev) =>
      prev.map((test) =>
        test.id === id ? { ...test, viewMode: test.viewMode === 'graph' ? 'cli' : 'graph' } : test
      )
    );
  };

  const addTest = () => {
    const host = hostInput.trim();
    if (!host) {
      setStatus('Enter a valid host or IP address.');
      return;
    }

    if (testsRef.current.some((t) => t.host.toLowerCase() === host.toLowerCase())) {
      setStatus(`Target ${host} already exists.`);
      return;
    }

    const currentlyRunning = testsRef.current.filter((t) => t.phase === 'running').length;
    if (currentlyRunning >= MAX_ACTIVE_SESSIONS) {
      setStatus(`Active session limit reached (${MAX_ACTIVE_SESSIONS}). Pause/stop one first.`);
      return;
    }

    const test = createTest(host);
    setTests((prev) => [test, ...prev]);
    setStatus(`Created new extended ping test for ${host}.`);
    setHostInput('');

    setTimeout(() => startTest(test.id), 0);
  };

  const addBulkTests = () => {
    const hosts = Array.from(
      new Set(
        bulkHostsInput
          .split(/[\n,;\t ]+/)
          .map((value) => value.trim())
          .filter(Boolean)
      )
    );

    if (hosts.length === 0) {
      setStatus('Enter at least one valid host in the bulk input.');
      return;
    }

    const existing = new Set(testsRef.current.map((t) => t.host.toLowerCase()));
    const filtered = hosts.filter((h) => !existing.has(h.toLowerCase()));
    const currentlyRunning = testsRef.current.filter((t) => t.phase === 'running').length;
    const availableSlots = Math.max(MAX_ACTIVE_SESSIONS - currentlyRunning, 0);
    const allowed = filtered.slice(0, availableSlots);

    if (allowed.length === 0) {
      setStatus('No bulk targets added (duplicates or active session limit reached).');
      return;
    }

    const newTests = allowed.map((host) => createTest(host));
    setTests((prev) => [...newTests, ...prev]);
    setStatus(`Created ${newTests.length} ping sessions from bulk input.`);
    setBulkHostsInput('');

    setTimeout(() => {
      newTests.forEach((test) => startTest(test.id));
    }, 0);
  };

  const startAll = () => {
    if (pingEntryMode === 'bulk' && bulkHostsInput.trim()) {
      addBulkTests();
      return;
    }

    let started = 0;
    const running = testsRef.current.filter((t) => t.phase === 'running').length;
    const slots = Math.max(MAX_ACTIVE_SESSIONS - running, 0);
    testsRef.current.forEach((t) => {
      if (started >= slots) return;
      if (t.phase !== 'running') {
        startTest(t.id);
        started += 1;
      }
    });
    setStatus(
      started > 0
        ? `Started ${started} sessions (limit ${MAX_ACTIVE_SESSIONS}).`
        : `No sessions started. Active limit is ${MAX_ACTIVE_SESSIONS}.`
    );
  };

  const pauseAll = () => {
    testsRef.current.forEach((t) => pauseTest(t.id));
    setStatus('All tests are paused.');
  };

  const stopAll = () => {
    testsRef.current.forEach((t) => stopTest(t.id));
    setStatus('All tests are stopped.');
  };

  const clearNotifications = () => {
    setNotifications([]);
  };

  const runOnEnter = (event, action) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    action();
  };

  const handleRapidPing = async () => {
    const host = floodHostInput.trim();
    if (!host) {
      setStatus('Enter a host for flood packet loss test.');
      return;
    }

    const count = Number.parseInt(String(rapidCount), 10);
    if (count !== 100 && count !== 1000) {
      setStatus('Flood test count must be 100 or 1000.');
      return;
    }

    setRapidRunning(true);
    setRapidDetails({
      host,
      mode: 'ICMP',
      sent: 0,
      received: 0,
      lost: 0,
      lossPct: 0,
      jitterCount: 0,
      avgLatency: null,
      minRtt: null,
      maxRtt: null,
      p95Rtt: null,
      jitterMs: null,
      lossStreakMax: 0,
      status: 'working',
      packetStates: Array.from({ length: count }, () => 'pending'),
      logLines: [{ type: 'meta', text: `[init] Starting rapid ICMP test for ${host} (${count} pings)...` }]
    });
    setStatus(`Running fixed-count flood test (${count}) for ${host}...`);

    try {
      const startResult = await window.networkAPI.startFloodPing({
        target: host,
        count,
        mode: 'ICMP',
        timeoutMs: 1000
      });

      if (!startResult?.ok) {
        setRapidRunning(false);
        setStatus(startResult?.error || 'Flood test could not start.');
        setRapidDetails((prev) => ({
          ...prev,
          status: 'error',
          logLines: [...prev.logLines, { type: 'failed', text: startResult?.error || 'Flood test start failed.' }]
        }));
      } else {
        setFloodHostInput('');
      }
    } catch (error) {
      setRapidRunning(false);
      setRapidDetails((prev) => ({
        ...prev,
        status: 'error',
        logLines: [...prev.logLines, { type: 'failed', text: String(error?.message || error || 'Flood test failed.') }]
      }));
      setStatus('Flood test failed.');
    }
  };

  const handleRapidCancel = async () => {
    if (!rapidRunning) return;
    try {
      const response = await window.networkAPI.cancelFloodPing();
      if (!response?.ok && response?.error) {
        setStatus(response.error);
      } else {
        setStatus('Cancelling flood test...');
      }
    } catch (error) {
      setStatus(String(error?.message || error || 'Flood cancel failed.'));
    }
  };

  const handleTraceroute = async () => {
    const host = traceHost.trim();
    if (!host) {
      setStatus('Enter a hostname or IP for traceroute.');
      return;
    }
    setTraceLoading(true);
    setTraceHops([]);
    setTraceOutput('Initializing tracing route...');
    setStatus(`Running traceroute to ${host}...`);
    setTraceSummary({ totalHops: 0, avgRtt: null });

    try {
      const output = await window.networkAPI.runTraceroute(host);
      setTraceOutput(output);
      const parsed = parseTracerouteOutput(output);
      setTraceHops(parsed.hops);
      setTraceSummary({ totalHops: parsed.totalHops, avgRtt: parsed.avgRtt });
      setStatus(`Traceroute complete to ${host}.`);
      setTraceHost('');
    } catch (error) {
      setTraceOutput(String(error?.message || error));
      setStatus(`Traceroute failed to ${host}.`);
    } finally {
      setTraceLoading(false);
    }
  };

  const handleExportTraceCsv = () => {
    if (traceHops.length === 0) {
      setStatus('Run traceroute first before exporting.');
      return;
    }

    const payload = {
      host: traceHost.trim(),
      createdAt: new Date().toISOString(),
      summary: traceSummary
    };
    const escapeCsv = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;
    const rows = [
      [
        'targetHost',
        'createdAt',
        'totalHops',
        'avgRttMs',
        'hop',
        'hostname',
        'ip',
        'status',
        'avgLatencyMs',
        'timedOut',
        'latenciesMs'
      ].join(',')
    ];
    traceHops.forEach((hop) => {
      rows.push(
        [
          escapeCsv(payload.host || ''),
          escapeCsv(payload.createdAt),
          escapeCsv(payload.summary.totalHops),
          escapeCsv(payload.summary.avgRtt != null ? payload.summary.avgRtt.toFixed(2) : ''),
          escapeCsv(hop.hop),
          escapeCsv(hop.hostname),
          escapeCsv(hop.ip),
          escapeCsv(hop.status),
          escapeCsv(hop.avgLatency != null ? hop.avgLatency.toFixed(2) : ''),
          escapeCsv(Boolean(hop.timedOut)),
          escapeCsv((hop.latencies || []).join('|'))
        ].join(',')
      );
    });

    const blob = new Blob([rows.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `traceroute-${payload.host || 'report'}-${Date.now()}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setStatus('Traceroute CSV exported.');
  };

  const handleTcpPing = async () => {
    const host = tcpHostInput.trim();
    if (!host) {
      setStatus('Enter a hostname or IP for TCP ping.');
      return;
    }
    setStatus(`Pinging TCP port ${tcpPort} on ${host}...`);
    setTcpResult(null);
    try {
      const result = await window.networkAPI.runTcpPing(host, tcpPort, 1500);
      setTcpResult(result);
      setStatus(`TCP ping to ${host}:${tcpPort} complete.`);
      setTcpHostInput('');
    } catch (error) {
      setTcpResult({ error: String(error?.message || error) });
      setStatus('TCP ping failed.');
    }
  };

  const handleMtrRun = async () => {
    const host = mtrHostInput.trim();
    if (!host) {
      setStatus('Enter a hostname or IP for MTR.');
      return;
    }
    setMtrLoading(true);
    setStatus(`Running MTR-style diagnostic to ${host} (rounds: ${mtrRounds})...`);
    setMtrResult(null);
    try {
      const result = await window.networkAPI.runMtr(host, mtrRounds);
      setMtrResult(result);
      setStatus(`MTR diagnostic complete to ${host}.`);
      setMtrHostInput('');
    } finally {
      setMtrLoading(false);
    }
  };

  const handleDnsQuery = async () => {
    const host = dnsHostInput.trim();
    if (!host) {
      setStatus('Enter a domain for DNS lookup.');
      return;
    }
    setStatus(`Running DNS query (${dnsType}) for ${host}...`);
    setDnsResult(null);
    try {
      const result = await window.networkAPI.queryDns(host, dnsType);
      setDnsResult(result);
      setStatus(`DNS query for ${host} complete.`);
      setDnsHostInput('');
    } catch (error) {
      setDnsResult({ error: String(error?.message || error) });
      setStatus('DNS query failed.');
    }
  };

  const handlePortScan = async () => {
    const host = portScanHostInput.trim();
    if (!host) {
      setStatus('Enter a host for port scan.');
      return;
    }
    const ports = portListInput
      .split(/[,\s]+/)
      .map((v) => Number.parseInt(v, 10))
      .filter((v) => Number.isFinite(v) && v > 0 && v <= 65535)
      .slice(0, 32);
    if (ports.length === 0) {
      setStatus('Enter at least one valid port.');
      return;
    }
    setStatus(`Scanning ${ports.length} ports on ${host}...`);
    setPortScanResult(null);
    try {
      const result = await window.networkAPI.runPortScan(host, ports, 900);
      setPortScanResult(result);
      setStatus(`Port scan complete on ${host}.`);
      setPortScanHostInput('');
    } catch (error) {
      setPortScanResult({ error: String(error?.message || error) });
      setStatus('Port scan failed.');
    }
  };



  const handleWhoisLookup = async () => {
    const domain = whoisInput.trim();
    if (!domain) {
      setStatus('Enter a domain or IP for WHOIS.');
      return;
    }

    setWhoisLoading(true);
    setWhoisData(null);
    setStatus(`Running WHOIS lookup for ${domain}...`);

    try {
      const result = await window.networkAPI.lookupIdentity(domain);
      if (result.ok) {
        setWhoisData({
          normalized: result.normalized,
          raw: result.raw,
          source: result.source || 'Apilayer',
          data: result.data // Preserve original apilayer data if present
        });
        setStatus(`WHOIS lookup complete for ${domain} via ${result.source || 'Apilayer'}.`);
        setWhoisInput('');
      } else {
        setWhoisData(result.data ?? { error: result.error });
        setStatus(result.error || 'WHOIS lookup failed.');
      }
    } catch (error) {
      setWhoisData({ error: String(error?.message || error) });
      setStatus('WHOIS lookup failed.');
    } finally {
      setWhoisLoading(false);
    }
  };

  const handleCopyWhois = async () => {
    if (!whoisData) {
      setStatus('Run WHOIS lookup first.');
      return;
    }
    try {
      await navigator.clipboard.writeText(whoisPresentation.text);
      setStatus('WHOIS results copied to clipboard.');
    } catch {
      setStatus('Could not copy WHOIS results.');
    }
  };

  const handleExportWhoisTxt = () => {
    if (!whoisData) {
      setStatus('Run WHOIS lookup first.');
      return;
    }
    const blob = new Blob([whoisPresentation.text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `whois-${whoisPresentation.queryDomain || 'lookup'}-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setStatus('WHOIS TXT exported.');
  };

  // --- Phase 6 Specific Handlers ---
  const handleDnsValidate = async () => {
    const target = dnsValInput.trim();
    if (!target) return;
    setDnsValLoading(true);
    setDnsValResult(null);
    setStatus(`Validating DNS configuration for ${target}...`);
    try {
      const res = await window.networkAPI.validateDns(target);
      setDnsValResult(res);
      setStatus(res.ok ? 'DNS Validation complete.' : 'DNS Validation failed.');
      if (res.ok) setDnsValInput('');
    } catch (e) {
      setDnsValResult({ ok: false, error: e.message });
      setStatus('DNS Validation runtime error.');
    } finally {
      setDnsValLoading(false);
    }
  };

  const handleDnsHealth = async () => {
    const target = dnsHealthInput.trim();
    if (!target) return;
    setDnsHealthLoading(true);
    setDnsHealthResult(null);
    setStatus(`Running Multi-Resolver check for ${target}...`);
    try {
      const res = await window.networkAPI.healthCheckDns(target);
      setDnsHealthResult(res);
      setStatus(res.ok ? 'Multi-Resolver Health Check complete.' : 'Health check failed.');
      if (res.ok) setDnsHealthInput('');
    } catch (e) {
      setDnsHealthResult({ ok: false, error: e.message });
      setStatus('Health Check runtime error.');
    } finally {
      setDnsHealthLoading(false);
    }
  };

  const handleDmarcValidate = async () => {
    const target = dmarcInput.trim();
    if (!target) return;
    setDmarcLoading(true);
    setDmarcResult(null);
    setStatus(`Validating DMARC records for ${target}...`);
    try {
      const res = await window.networkAPI.validateDmarc(target);
      setDmarcResult(res);
      setStatus(res.ok ? 'DMARC validation complete.' : 'DMARC validation failed.');
      if (res.ok) setDmarcInput('');
    } catch (e) {
      setDmarcResult({ ok: false, error: e.message });
      setStatus('DMARC validation runtime error.');
    } finally {
      setDmarcLoading(false);
    }
  };

  const handleMacLookup = async () => {
    const target = macInput.trim();
    if (!target) return;
    setMacLoading(true);
    setMacResult(null);
    setStatus('Looking up hardware database...');
    try {
      const res = await window.networkAPI.lookupMac(target);
      setMacResult(res);
      setStatus(res.ok ? 'MAC lookup complete.' : 'MAC lookup failed.');
      if (res.ok) setMacInput('');
    } catch (e) {
      setMacResult({ ok: false, error: e.message });
      setStatus('MAC lookup runtime error.');
    } finally {
      setMacLoading(false);
    }
  };

  const handleCopyPhase6Raw = async (text) => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setStatus('Raw output copied to clipboard.');
    } catch {
      setStatus('Failed to copy text.');
    }
  };

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-wrap">
          <div className="brand-logo-row">
            <img className="brand-logo" src={netPulseLogo} alt="NetPulse" />
            <span className="version-badge">v0.1.2</span>
          </div>
        </div>
        <div className="tabs-bar">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <span className="tab-icon">{tab.icon}</span>
              <span>{tab.label}</span>
            </button>
          ))}
        </div>
      </aside>

      <div className="app-container">
        {activeTab === 'ping' ? (
          <section className="ping-dashboard">
            <section className="ping-topbar">
              <div>
                <h2>Multi-Target Ping</h2>
              </div>
              <div className="ping-actions">
                <div className="entry-toggle">
                  <button
                    className={pingEntryMode === 'single' ? 'active' : ''}
                    onClick={() => setPingEntryMode('single')}
                  >
                    Single IP
                  </button>
                  <button className={pingEntryMode === 'bulk' ? 'active' : ''} onClick={() => setPingEntryMode('bulk')}>
                    Bulk IPs
                  </button>
                </div>
                {pingEntryMode === 'single' ? (
                  <>
                    <input
                      id="host"
                      value={hostInput}
                      onChange={(e) => setHostInput(e.target.value)}
                      onKeyDown={(e) => runOnEnter(e, addTest)}
                      placeholder="Enter a hostname"
                    />
                    <button onClick={addTest}>Add Target</button>
                  </>
                ) : null}
              </div>
            </section>

            <section className="card command-panel compact">
              {pingEntryMode === 'bulk' ? (
                <>
                  <label htmlFor="bulkHosts">Bulk Hosts (one per line or comma separated)</label>
                  <textarea
                    id="bulkHosts"
                    value={bulkHostsInput}
                    onChange={(e) => setBulkHostsInput(e.target.value)}
                    placeholder={'Enter a hostname\nexample.com\nweb-server.local'}
                  />
                  <p className="empty">Bulk mode: paste targets here, then click Start All to add and run them.</p>
                </>
              ) : (
                <p className="empty">Single IP mode enabled. Switch to Bulk IPs to paste multiple targets.</p>
              )}
              <div>
                <button className="secondary" onClick={startAll} disabled={tests.length === 0}>
                  Start All
                </button>
                <button className="secondary" onClick={pauseAll} disabled={tests.length === 0}>
                  Pause All
                </button>
                <button className="danger" onClick={stopAll} disabled={tests.length === 0}>
                  Stop All
                </button>
              </div>
              <div className="ping-options-row">
                <label htmlFor="packetSize">Packet Size (bytes)</label>
                <input
                  id="packetSize"
                  type="number"
                  min="1"
                  max="65000"
                  value={packetSize}
                  onChange={(e) => setPacketSize(Number.parseInt(e.target.value || '56', 10))}
                />
                <label className="checkbox-inline">
                  <input
                    type="checkbox"
                    checked={dontFragment}
                    onChange={(e) => setDontFragment(e.target.checked)}
                  />
                  Don't Fragment (DF)
                </label>
              </div>
            </section>

            <section className="tests-grid monitor-grid ping-grid">
              {tests.length === 0 ? <p className="empty">No active monitors. Add a target to begin.</p> : null}
              {tests.map((test) => {
                const health = getHealth(test);
                const uptime = test.sent > 0 ? ((test.received / test.sent) * 100).toFixed(1) : '0.0';
                const m = getTestMetrics(test);
                const liveLabel = health === HEALTH.DOWN ? 'OFFLINE' : health === HEALTH.DEGRADED ? 'UNSTABLE' : 'LIVE';

                return (
                  <article key={test.id} className={`test-card monitor-card ping-card health-${health}`}>
                    <div className="test-head">
                      <div>
                        <div className="target-title">
                          <span className={`status-light ${health}`} />
                          <h3>{test.host}</h3>
                        </div>
                        <p className="target-sub">{test.host}</p>
                      </div>
                      <span className="uptime-pill">UPTIME {uptime}%</span>
                    </div>

                    {test.viewMode === 'graph' ? (
                      <LineChart points={test.points} health={health} liveLabel={liveLabel} events={test.events} />
                    ) : (
                      <pre>{test.lastOutput}</pre>
                    )}

                    <div className="metric-row stats-grid">
                      <article className="metric-box">
                        <span>Current</span>
                        <strong>{m.current != null ? `${m.current.toFixed(0)}ms` : '--'}</strong>
                      </article>
                      <article className="metric-box">
                        <span>Average</span>
                        <strong>{m.avg != null ? `${m.avg.toFixed(0)}ms` : '--'}</strong>
                      </article>
                      <article className="metric-box">
                        <span>Max</span>
                        <strong>{m.max != null ? `${m.max.toFixed(0)}ms` : '--'}</strong>
                      </article>
                    </div>
                    <div className="metric-row metric-row-secondary stats-grid">
                      <article className="metric-box">
                        <span>p50</span>
                        <strong>{m.p50 != null ? `${m.p50.toFixed(0)}ms` : '--'}</strong>
                      </article>
                      <article className="metric-box">
                        <span>p95</span>
                        <strong>{m.p95 != null ? `${m.p95.toFixed(0)}ms` : '--'}</strong>
                      </article>
                      <article className="metric-box">
                        <span>p99</span>
                        <strong>{m.p99 != null ? `${m.p99.toFixed(0)}ms` : '--'}</strong>
                      </article>
                      <article className="metric-box">
                        <span>StdDev</span>
                        <strong>{m.stddev != null ? `${m.stddev.toFixed(1)}ms` : '--'}</strong>
                      </article>
                    </div>

                    <div className="card-actions">
                      <button className="secondary" onClick={() => toggleTestViewMode(test.id)}>
                        {test.viewMode === 'graph' ? 'CLI View' : 'Graph View'}
                      </button>
                      <button onClick={() => startTest(test.id)} disabled={test.phase === 'running'}>
                        Resume
                      </button>
                      <button className="secondary" onClick={() => pauseTest(test.id)} disabled={test.phase !== 'running'}>
                        Pause
                      </button>
                      <button className="danger" onClick={() => stopTest(test.id)} disabled={test.phase === 'stopped'}>
                        Stop
                      </button>
                      <button className="danger" onClick={() => removeTest(test.id)}>
                        Remove
                      </button>
                    </div>
                  </article>
                );
              })}
            </section>

            <section className="global-health">
              {(() => {
                const combined = tests.flatMap((t) => t.points.map((p) => p.latency).filter((v) => v != null));
                const totalSent = tests.reduce((acc, t) => acc + t.sent, 0);
                const totalReceived = tests.reduce((acc, t) => acc + t.received, 0);
                const totalAvg = combined.length > 0 ? combined.reduce((a, b) => a + b, 0) / combined.length : null;
                const packetLoss = totalSent > 0 ? ((totalSent - totalReceived) * 100) / totalSent : 0;
                const online = tests.filter((t) => getHealth(t) !== HEALTH.DOWN).length;
                return (
                  <>
                    <article className="global-card">
                      <span>Total Avg Latency</span>
                      <strong>{totalAvg != null ? `${totalAvg.toFixed(1)} ms` : '--'}</strong>
                    </article>
                    <article className="global-card">
                      <span>Global Packet Loss</span>
                      <strong>{packetLoss.toFixed(2)}%</strong>
                    </article>
                    <article className="global-card">
                      <span>Active Monitors</span>
                      <strong>
                        {online}/{tests.length || 0}
                      </strong>
                    </article>
                  </>
                );
              })()}
            </section>

            <section className="card latency-matrix">
              <h3>Multi-Target Latency Matrix</h3>
              <table>
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Avg</th>
                    <th>Loss</th>
                    <th>Jitter</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {tests.map((test) => {
                    const m = getTestMetrics(test);
                    const loss = test.sent > 0 ? (((test.sent - test.received) * 100) / test.sent).toFixed(1) : '0.0';
                    const health = getHealth(test);
                    return (
                      <tr key={`mx-${test.id}`} className={`matrix-${health}`}>
                        <td>{test.host}</td>
                        <td>{m.avg != null ? `${m.avg.toFixed(1)} ms` : '--'}</td>
                        <td>{loss}%</td>
                        <td>{m.stddev != null ? `${m.stddev.toFixed(1)} ms` : '--'}</td>
                        <td>{formatHealthLabel(health)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </section>
          </section>
        ) : null}

        {activeTab === 'trace' ? (
          <section className="card trace-panel">
            <div className="panel-head">
              <h2>Traceroute</h2>
              <div className="run-state">
                <span className={`status-light ${traceLoading ? 'running' : 'idle'}`} />
                <span>{traceLoading ? 'Running' : 'Idle'}</span>
              </div>
            </div>
            <label htmlFor="traceHost">Target Host / IP</label>
            <input
              id="traceHost"
              value={traceHost}
              onChange={(e) => setTraceHost(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleTraceroute)}
              placeholder="Enter a hostname"
            />
            <button onClick={handleTraceroute} disabled={traceLoading}>
              {traceLoading ? 'Running traceroute...' : 'Run traceroute'}
            </button>
            <div className="trace-actions">
              <button className="secondary" onClick={handleTraceroute} disabled={traceLoading}>
                Rerun
              </button>
              <button className="secondary" onClick={handleExportTraceCsv} disabled={traceHops.length === 0}>
                Export CSV
              </button>
            </div>

            <section className="trace-summary">
              <article className="trace-stat">
                <span>Total Hops</span>
                <strong>{traceSummary.totalHops}</strong>
              </article>
              <article className="trace-stat">
                <span>Average RTT</span>
                <strong>{traceSummary.avgRtt != null ? `${traceSummary.avgRtt.toFixed(1)} ms` : 'n/a'}</strong>
              </article>
            </section>

            <div className="trace-list">
              {traceHops.length === 0 ? <p className="empty">No hop analysis yet. Run traceroute to populate details.</p> : null}
              {traceHops.map((hop) => (
                <article key={`${hop.hop}-${hop.ip}`} className="trace-hop">
                  <div className="trace-hop-head">
                    <strong>Hop {hop.hop}</strong>
                    <span className={`trace-pill ${hop.status}`}>
                      {hop.avgLatency != null ? `${hop.avgLatency.toFixed(1)} ms` : 'timeout'}
                    </span>
                  </div>
                  <p className="trace-host">
                    {hop.hostname} <span>{hop.ip}</span>
                  </p>
                  <div className="latency-bar-glass">
                    <div
                      className={`latency-bar-fill ${hop.status}`}
                      style={{ width: `${Math.min(((hop.avgLatency || 180) / 180) * 100, 100)}%` }}
                    />
                  </div>
                </article>
              ))}
            </div>

            <pre>{traceOutput}</pre>
          </section>
        ) : null}

        {activeTab === 'packetloss' ? (
          <section className="packetloss-page">
            <div className="packetloss-head">
              <h2>Packet Loss Test</h2>
            </div>
            <section className="packetloss-controls">
              <input
                id="packetLossHost"
                value={floodHostInput}
                onChange={(e) => setFloodHostInput(e.target.value)}
                onKeyDown={(e) => runOnEnter(e, handleRapidPing)}
                placeholder="Enter a hostname"
              />
              <div className="count-toggle">
                <button className={rapidCount === 100 ? 'active' : ''} onClick={() => setRapidCount(100)}>
                  100 Pings
                </button>
                <button className={rapidCount === 1000 ? 'active' : ''} onClick={() => setRapidCount(1000)}>
                  1000 Pings
                </button>
              </div>
              <button className="packetloss-start" onClick={handleRapidPing} disabled={rapidRunning}>
                ▶ {rapidRunning ? 'RUNNING TEST...' : 'START TEST'}
              </button>
              <button className="secondary" onClick={handleRapidCancel} disabled={!rapidRunning}>
                Cancel
              </button>
            </section>

            <section className="packetloss-layout">
              <aside className="packetloss-left">
                <article className="loss-donut-card">
                  <div
                    className="loss-donut"
                    style={{
                      background:
                        Number(rapidDetails.lossPct || 0) === 0
                          ? `rgba(40,50,72,0.85)`
                          : `conic-gradient(#ff5b36 0 ${Math.max(
                            3,
                            Number(rapidDetails.lossPct || 0) * 3.6
                          )}deg, rgba(40,50,72,0.85) ${Math.max(3, Number(rapidDetails.lossPct || 0) * 3.6)}deg 360deg)`
                    }}
                  >
                    <div>
                      <strong>{Number(rapidDetails.lossPct || 0).toFixed(1)}%</strong>
                      <span>Loss Rate</span>
                    </div>
                  </div>
                </article>
                <article className="diag-metric">Total Sent <strong>{rapidDetails.sent}</strong></article>
                <article className="diag-metric">
                  Received <strong>{rapidDetails.received}</strong>
                </article>
                <article className="diag-metric">
                  Lost <strong>{rapidDetails.lost}</strong>
                </article>
                <article className="diag-metric">
                  Avg RTT <strong>{rapidDetails.avgLatency != null ? `${rapidDetails.avgLatency} ms` : 'n/a'}</strong>
                </article>
                <article className="diag-metric">
                  Min/Max RTT{' '}
                  <strong>
                    {rapidDetails.minRtt != null ? `${rapidDetails.minRtt} / ${rapidDetails.maxRtt} ms` : 'n/a'}
                  </strong>
                </article>
                <article className="diag-metric">
                  Jitter / P95{' '}
                  <strong>
                    {rapidDetails.jitterMs != null ? `${rapidDetails.jitterMs} / ${rapidDetails.p95Rtt ?? 'n/a'} ms` : 'n/a'}
                  </strong>
                </article>
                <article className="diag-metric">
                  Max Loss Streak <strong>{rapidDetails.lossStreakMax}</strong>
                </article>
                <article className="diag-metric">
                  Error Rate{' '}
                  <strong className={rapidDetails.lossPct >= 5 ? 'critical' : rapidDetails.lossPct >= 1 ? 'warn' : 'healthy'}>
                    {rapidDetails.lossPct >= 5 ? 'Critical' : rapidDetails.lossPct >= 1 ? 'Warning' : 'Stable'}
                  </strong>
                </article>
              </aside>

              <section className="packetloss-right card">
                <div className="sequence-head">
                  <h3>Sequence Analysis (Pings 1-{rapidCount})</h3>
                  <div className="sequence-legend">
                    <span className="success">Success</span>
                    <span className="jitter">Jitter</span>
                    <span className="failed">Failed</span>
                  </div>
                </div>
                <div className="sequence-grid">
                  {rapidDetails.packetStates.map((state, index) => (
                    <span key={`pkt-${index}`} className={`pkt ${state}`} />
                  ))}
                </div>

                <section className="diag-log">
                  <h4>Diagnostic Log</h4>
                  <pre className="diag-log-pre">
                    {rapidDetails.logLines.map((line, index) => (
                      <div key={`log-${index}`} className={`diag-line ${line.type}`}>
                        {line.text}
                      </div>
                    ))}
                  </pre>
                </section>
              </section>
            </section>
          </section>
        ) : null}

        {activeTab === 'diagnostics' ? (
          <section className="diagnostics-hub">
            <section className="card diagnostics-grid">
              <article className="diag-card">
                <h3>TCP Ping (SYN Reachability)</h3>
                <div className="diag-controls">
                  <input
                    value={tcpHostInput}
                    onChange={(e) => setTcpHostInput(e.target.value)}
                    onKeyDown={(e) => runOnEnter(e, handleTcpPing)}
                    placeholder="Enter a hostname"
                  />
                  <input
                    id="tcpPort"
                    type="number"
                    min="1"
                    max="65535"
                    value={tcpPort}
                    onChange={(e) => setTcpPort(Number.parseInt(e.target.value || '443', 10))}
                    placeholder="443"
                  />
                </div>
                <button className="diag-run-btn" onClick={handleTcpPing}>
                  ⚡ Run TCP Ping
                </button>
                <pre className="diag-log-pre">{tcpResult ? JSON.stringify(tcpResult, null, 2) : 'No TCP ping result yet.'}</pre>
              </article>

              <article className="diag-card">
                <h3>MTR-style (Ping + Trace)</h3>
                <div className="diag-controls">
                  <input
                    value={mtrHostInput}
                    onChange={(e) => setMtrHostInput(e.target.value)}
                    onKeyDown={(e) => runOnEnter(e, handleMtrRun)}
                    placeholder="Enter a hostname"
                  />
                  <input
                    id="mtrRounds"
                    type="number"
                    min="2"
                    max="30"
                    value={mtrRounds}
                    onChange={(e) => setMtrRounds(Number.parseInt(e.target.value || '5', 10))}
                    placeholder="Rounds"
                  />
                </div>
                <button className="diag-run-btn" onClick={handleMtrRun} disabled={mtrLoading}>
                  {mtrLoading ? 'Running...' : '▶ Run MTR-style'}
                </button>
                <pre className="diag-log-pre">{mtrResult ? JSON.stringify(mtrResult, null, 2) : 'No MTR result yet.'}</pre>
              </article>

              <article className="diag-card">
                <h3>DNS Toolkit</h3>
                <div className="diag-controls">
                  <input
                    value={dnsHostInput}
                    onChange={(e) => setDnsHostInput(e.target.value)}
                    onKeyDown={(e) => runOnEnter(e, handleDnsQuery)}
                    placeholder="Enter a hostname"
                  />
                  <select id="dnsType" value={dnsType} onChange={(e) => setDnsType(e.target.value)}>
                    <option value="A">Type: A</option>
                    <option value="AAAA">Type: AAAA</option>
                    <option value="MX">Type: MX</option>
                    <option value="NS">Type: NS</option>
                    <option value="CNAME">Type: CNAME</option>
                    <option value="PTR">Type: PTR</option>
                  </select>
                </div>
                <button className="diag-run-btn" onClick={handleDnsQuery}>
                  ⌕ Run DNS Query
                </button>
                <pre className="diag-log-pre">{dnsResult ? JSON.stringify(dnsResult, null, 2) : 'No DNS result yet.'}</pre>
              </article>

              <article className="diag-card">
                <h3>Port Scanner Lite</h3>
                <div className="diag-controls">
                  <input
                    value={portScanHostInput}
                    onChange={(e) => setPortScanHostInput(e.target.value)}
                    onKeyDown={(e) => runOnEnter(e, handlePortScan)}
                    placeholder="Enter a hostname"
                  />
                  <input
                    id="portList"
                    value={portListInput}
                    onChange={(e) => setPortListInput(e.target.value)}
                    placeholder="Ports (e.g. 80,443,3389)"
                  />
                </div>
                <button className="diag-run-btn" onClick={handlePortScan}>
                  ◎ Run Port Scan
                </button>
                <pre className="diag-log-pre">{portScanResult ? JSON.stringify(portScanResult, null, 2) : 'No port scan result yet.'}</pre>
              </article>

              {/* PHASE 6 ADDITIONS */}
              <article className="diag-card">
                <h3>DNS Validation</h3>
                <div className="diag-controls">
                  <input
                    value={dnsValInput}
                    onChange={(e) => setDnsValInput(e.target.value)}
                    onKeyDown={(e) => runOnEnter(e, handleDnsValidate)}
                    placeholder="Enter a hostname"
                  />
                </div>
                <button className="diag-run-btn" onClick={handleDnsValidate} disabled={dnsValLoading}>
                  {dnsValLoading ? 'Validating...' : '✓ Validate Configuration'}
                </button>
                <div className="diag-result-container" style={{ position: 'relative' }}>
                  <pre className="diag-log-pre">
                    {dnsValResult ? (
                      dnsValResult.rawOutput || JSON.stringify(dnsValResult, null, 2)
                    ) : (
                      'No DNS Validation result yet.'
                    )}
                  </pre>
                  {dnsValResult && dnsValResult.rawOutput && (
                    <button className="copy-sm-btn" onClick={() => handleCopyPhase6Raw(dnsValResult.rawOutput)}>
                      Copy
                    </button>
                  )}
                </div>
              </article>

              <article className="diag-card">
                <h3>Multi-Resolver Health (Split DNS)</h3>
                <div className="diag-controls">
                  <input
                    value={dnsHealthInput}
                    onChange={(e) => setDnsHealthInput(e.target.value)}
                    onKeyDown={(e) => runOnEnter(e, handleDnsHealth)}
                    placeholder="Enter a hostname"
                  />
                </div>
                <button className="diag-run-btn" onClick={handleDnsHealth} disabled={dnsHealthLoading}>
                  {dnsHealthLoading ? 'Checking...' : '✓ Compare Resolvers'}
                </button>
                <div className="diag-result-container" style={{ position: 'relative' }}>
                  <pre className="diag-log-pre">
                    {dnsHealthResult ? (
                      dnsHealthResult.rawOutput || JSON.stringify(dnsHealthResult, null, 2)
                    ) : (
                      'No Multi-Resolver result yet.'
                    )}
                  </pre>
                  {dnsHealthResult && dnsHealthResult.rawOutput && (
                    <button className="copy-sm-btn" onClick={() => handleCopyPhase6Raw(dnsHealthResult.rawOutput)}>
                      Copy
                    </button>
                  )}
                </div>
              </article>

              <article className="diag-card">
                <h3>DMARC Inspector</h3>
                <div className="diag-controls">
                  <input
                    value={dmarcInput}
                    onChange={(e) => setDmarcInput(e.target.value)}
                    onKeyDown={(e) => runOnEnter(e, handleDmarcValidate)}
                    placeholder="Enter a hostname"
                  />
                </div>
                <button className="diag-run-btn" onClick={handleDmarcValidate} disabled={dmarcLoading}>
                  {dmarcLoading ? 'Inspecting...' : '✓ Inspect Records'}
                </button>
                <div className="diag-result-container" style={{ position: 'relative' }}>
                  <pre className="diag-log-pre">
                    {dmarcResult ? (
                      dmarcResult.rawOutput || JSON.stringify(dmarcResult, null, 2)
                    ) : (
                      'No DMARC validation result yet.'
                    )}
                  </pre>
                  {dmarcResult && dmarcResult.rawOutput && (
                    <button className="copy-sm-btn" onClick={() => handleCopyPhase6Raw(dmarcResult.rawOutput)}>
                      Copy
                    </button>
                  )}
                </div>
              </article>
            </section>
          </section>
        ) : null}
        {activeTab === 'whois' ? (
          <section className="whois-page">
            <div className="whois-head">
              <p className="whois-breadcrumb">Tools &gt; Identity & WHOIS</p>
              <h2>Registry & Hardware Identity</h2>
            </div>

            <div className="identity-grid">
              <section className="card whois-search-card" style={{ flex: 1 }}>
                <h3>WHOIS Lookup (Multi-Tier)</h3>
                <br />
                <div className="whois-search-wrap">
                  <span className="whois-icon" aria-hidden="true">
                    ⌕
                  </span>
                  <input
                    id="whoisDomain"
                    value={whoisInput}
                    onChange={(e) => setWhoisInput(e.target.value)}
                    onKeyDown={(e) => runOnEnter(e, handleWhoisLookup)}
                    placeholder="Enter a hostname or IP"
                  />
                  <button className="whois-primary" onClick={handleWhoisLookup} disabled={whoisLoading}>
                    {whoisLoading ? 'Running...' : 'WHOIS Lookup'}
                  </button>
                </div>
                {whoisData && (
                  <div className="whois-result-inline" style={{ marginTop: '16px', background: 'var(--surface-recessed)', padding: '12px', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)' }}>
                    <div className="whois-inline-actions" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Query: {whoisPresentation.queryDomain}</span>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button className="copy-sm-btn" onClick={handleCopyWhois}>Copy</button>
                        <button className="copy-sm-btn" onClick={handleExportWhoisTxt}>Export</button>
                      </div>
                    </div>
                    <pre className="diag-log-pre" style={{ margin: 0, minHeight: 'auto', fontSize: '0.8rem' }}>
                      {whoisPresentation.lines && whoisPresentation.lines.length > 0 ? (
                        whoisPresentation.lines.map((line, index) => {
                          if (line.type === 'blank') return <div key={`line-${index}`}>&nbsp;</div>;
                          if (line.type === 'comment') return <div key={`line-${index}`} className="whois-comment">{line.value}</div>;
                          if (line.type === 'section') return <div key={`line-${index}`} className="whois-section">{line.value}</div>;
                          const isLink = /^https?:\/\//i.test(line.value);
                          return (
                            <div key={`line-${index}`}>
                              <span className="whois-label">{line.label}:</span>{' '}
                              <span className={isLink ? 'whois-link' : 'whois-value'}>{line.value}</span>
                            </div>
                          );
                        })
                      ) : (
                        <div className="whois-raw-text">{whoisPresentation.text}</div>
                      )}
                    </pre>
                  </div>
                )}
              </section>

              <section className="card whois-search-card" style={{ flex: 1 }}>
                <h3>MAC Address OUI Matcher</h3>
                <br />
                <div className="whois-search-wrap">
                  <span className="whois-icon" aria-hidden="true">
                    ⌕
                  </span>
                  <input
                    id="macTarget"
                    value={macInput}
                    onChange={(e) => setMacInput(e.target.value)}
                    onKeyDown={(e) => runOnEnter(e, handleMacLookup)}
                    placeholder="Enter MAC Address (00:1A:2B:...)"
                  />
                  <button className="whois-primary" onClick={handleMacLookup} disabled={macLoading}>
                    {macLoading ? 'Looking up...' : 'Lookup Vendor'}
                  </button>
                </div>
                {macResult && (
                  <div className="mac-result" style={{ marginTop: '16px', background: 'var(--surface-recessed)', padding: '12px', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)' }}>
                    <pre className="diag-log-pre" style={{ margin: 0, minHeight: 'auto' }}>
                      {macResult.rawOutput || JSON.stringify(macResult, null, 2)}
                    </pre>
                  </div>
                )}
              </section>
            </div>
          </section>
        ) : null}



        <footer className="attribution-footer">
          NetPulse by Gabriel Chavez • Developed in Mexico with love
        </footer>
      </div>
    </main>
  );
}

export default App;
