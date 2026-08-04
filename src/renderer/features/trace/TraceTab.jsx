import React, { useState, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { exportStatusMessage, saveTextFile } from '../../utils/exportFile';

export const runOnEnter = (event, action) => {
  if (event.key !== 'Enter') return;
  event.preventDefault();
  action();
};

function getLatencyStatus(ms) {
  if (ms == null) return 'bad';
  if (ms <= 60) return 'good';
  if (ms <= 140) return 'warn';
  return 'bad';
}

// Parse a single traceroute line. Handles Windows (tracert) and Unix (traceroute) formats.
function parseTracerouteLine(rawLine) {
  const line = rawLine.trim();
  if (!line) return null;

  // Skip header/footer lines
  if (/^(tracing route|trace complete|over a maximum|traceroute to)/i.test(line)) return null;

  // Line must begin with a hop number
  const hopMatch = line.match(/^(\d+)\s+(.*)/);
  if (!hopMatch) return null;

  const hop = parseInt(hopMatch[1], 10);
  const rest = hopMatch[2].trim();

  // Timeout detection: two or more * markers
  const starCount = (rest.match(/\*/g) || []).length;
  const isTimeout = starCount >= 2;

  // Latency values: handles "<1 ms", "1.5 ms", "10ms", "<1ms"
  const latencyMatches = [...rest.matchAll(/<?\s*(\d+(?:\.\d+)?)\s*ms/gi)];
  const latencies = latencyMatches
    .map((m) => parseFloat(m[1]))
    .filter((v) => Number.isFinite(v));

  // IPv4 address (strict octet match)
  const ipv4Match = rest.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);

  // IPv6 address — only look if no IPv4 found, and use a tight pattern
  const ipv6Match =
    !ipv4Match &&
    rest.match(/\b([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){3,7})\b/);

  const ip = ipv4Match?.[1] || ipv6Match?.[1] || null;

  // Hostname — Unix format: "hostname (IP)  ms..."
  let hostname = null;
  if (ip && ipv4Match) {
    const parenMatch = rest.match(/^([a-zA-Z][^\s(*]+)\s*\(/);
    if (parenMatch) {
      hostname = parenMatch[1].trim();
    }
  }

  // Destination unreachable / administratively prohibited
  const isUnreachable =
    /unreachable|prohibited|administratively/i.test(rest) && starCount === 0;

  if (isTimeout && latencies.length === 0) {
    return {
      hop,
      ip: ip || '*',
      hostname,
      latencies: [],
      avgLatency: null,
      status: 'bad',
      timedOut: true,
      unreachable: false,
    };
  }

  const avgLatency =
    latencies.length > 0
      ? latencies.reduce((a, b) => a + b, 0) / latencies.length
      : null;

  return {
    hop,
    ip: ip || 'Unknown',
    hostname,
    latencies,
    avgLatency,
    status: isUnreachable ? 'bad' : getLatencyStatus(avgLatency),
    timedOut: isTimeout,
    unreachable: isUnreachable,
  };
}

// Traceroute RTTs are cumulative from the source, so the useful per-hop figure
// is the delta against the previous *responding* hop — that's where latency was
// actually introduced. A delta spanning a timeout covers both hops together.
function withHopDeltas(hops) {
  let prevRtt = null;
  return hops.map((hop) => {
    if (hop.avgLatency == null) return { ...hop, delta: null };
    const delta = prevRtt == null ? hop.avgLatency : hop.avgLatency - prevRtt;
    prevRtt = hop.avgLatency;
    return { ...hop, delta };
  });
}

function parseTracerouteOutput(output) {
  const lines = String(output || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const hops = withHopDeltas(lines.map(parseTracerouteLine).filter(Boolean));

  const responding = hops.filter((h) => h.avgLatency != null);
  // End-to-end latency is the last hop that answered, not an average of all of
  // them — averaging cumulative RTTs understates the real distance to target.
  const destRtt = responding.length > 0 ? responding[responding.length - 1].avgLatency : null;
  // Bars scale to the slowest hop in this trace so the shape stays readable
  // whether the route is 5 ms across town or 300 ms intercontinental.
  const maxRtt = responding.length > 0 ? Math.max(...responding.map((h) => h.avgLatency)) : null;

  let worstJump = null;
  let worstJumpHop = null;
  hops.forEach((h) => {
    if (h.delta != null && h.delta > 0 && (worstJump == null || h.delta > worstJump)) {
      worstJump = h.delta;
      worstJumpHop = h.hop;
    }
  });

  return { hops, totalHops: hops.length, destRtt, maxRtt, worstJump, worstJumpHop };
}

export default function TraceTab({ addNotification }) {
  const [traceHost, setTraceHost] = useState('');
  const [traceLoading, setTraceLoading] = useState(false);
  const [traceHops, setTraceHops] = useState([]);
  const [traceOutput, setTraceOutput] = useState('No traceroute execution yet.');
  const [traceSummary, setTraceSummary] = useState({
    totalHops: 0,
    destRtt: null,
    maxRtt: null,
    worstJump: null,
    worstJumpHop: null,
  });
  const [geoData, setGeoData] = useState({});
  const [geoLoading, setGeoLoading] = useState(false);
  const [status, setStatus] = useState('Ready.');
  // Bumped on every new traceroute run; lets a slow, superseded GeoIP batch
  // detect it's stale and avoid overwriting a newer trace's results.
  const traceGenRef = useRef(0);

  const fetchGeoData = async (hops, generation) => {
    const uniqueIps = [
      ...new Set(
        hops
          .map((h) => h.ip)
          .filter((ip) => ip && ip !== '*' && ip !== 'Unknown')
      ),
    ];
    if (uniqueIps.length === 0) return;

    setGeoLoading(true);
    const results = await Promise.allSettled(
      uniqueIps.map((ip) =>
        invoke('geoip_lookup', { ip }).then((result) => ({ ip, result }))
      )
    );
    if (generation !== traceGenRef.current) return; // a newer trace superseded this one
    const geoMap = {};
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value.result.ok) {
        geoMap[r.value.ip] = r.value.result;
      }
    }
    setGeoData(geoMap);
    setGeoLoading(false);
  };

  const handleTraceroute = async () => {
    const host = traceHost.trim();
    if (!host) {
      setStatus('Enter a hostname or IP for traceroute.');
      return;
    }
    const generation = ++traceGenRef.current;
    setTraceLoading(true);
    setTraceHops([]);
    setGeoData({});
    setGeoLoading(false);
    setTraceOutput('Initializing trace route...');
    setStatus(`Running traceroute to ${host}...`);
    setTraceSummary({ totalHops: 0, destRtt: null, maxRtt: null, worstJump: null, worstJumpHop: null });

    try {
      const result = await invoke('trace_run', { host });
      if (!result.ok) throw new Error(result.error || 'Traceroute failed');
      const output = result.output;
      setTraceOutput(output);
      const parsed = parseTracerouteOutput(output);
      setTraceHops(parsed.hops);
      setTraceSummary({
        totalHops: parsed.totalHops,
        destRtt: parsed.destRtt,
        maxRtt: parsed.maxRtt,
        worstJump: parsed.worstJump,
        worstJumpHop: parsed.worstJumpHop,
      });
      setStatus(`Traceroute complete to ${host}.`);
      addNotification?.(
        'trace_complete',
        `Traceroute to ${host} complete — ${parsed.totalHops} hops, ${
          parsed.destRtt != null ? `${parsed.destRtt.toFixed(1)} ms to destination` : 'destination did not respond'
        }`
      );
      // The host stays in the box so Rerun works and CSV export can name the target.
      // Fetch GeoIP in background after results are shown
      fetchGeoData(parsed.hops, generation);
    } catch (error) {
      const msg = String(error?.message || error);
      setTraceOutput(msg);
      setStatus(`Traceroute failed: ${msg}`);
    } finally {
      setTraceLoading(false);
    }
  };

  const handleExportTraceCsv = async () => {
    if (traceHops.length === 0) return;

    const escapeCsv = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;
    const rows = [
      [
        'targetHost',
        'createdAt',
        'totalHops',
        'destRttMs',
        'worstJumpMs',
        'worstJumpHop',
        'hop',
        'hostname',
        'ip',
        'country',
        'asn',
        'status',
        'avgLatencyMs',
        'deltaMs',
        'timedOut',
        'latenciesMs',
      ].join(','),
    ];
    traceHops.forEach((hop) => {
      const geo = geoData[hop.ip];
      rows.push(
        [
          escapeCsv(traceHost || ''),
          escapeCsv(new Date().toISOString()),
          escapeCsv(traceSummary.totalHops),
          escapeCsv(traceSummary.destRtt != null ? traceSummary.destRtt.toFixed(2) : ''),
          escapeCsv(traceSummary.worstJump != null ? traceSummary.worstJump.toFixed(2) : ''),
          escapeCsv(traceSummary.worstJumpHop ?? ''),
          escapeCsv(hop.hop),
          escapeCsv(hop.hostname || ''),
          escapeCsv(hop.ip),
          escapeCsv(geo?.country || ''),
          escapeCsv(geo?.as_info || ''),
          escapeCsv(hop.status),
          escapeCsv(hop.avgLatency != null ? hop.avgLatency.toFixed(2) : ''),
          escapeCsv(hop.delta != null ? hop.delta.toFixed(2) : ''),
          escapeCsv(Boolean(hop.timedOut)),
          escapeCsv((hop.latencies || []).join('|')),
        ].join(',')
      );
    });

    const fileName = `traceroute-${traceHost || 'report'}-${Date.now()}.csv`;
    const result = await saveTextFile(fileName, rows.join('\n'), 'text/csv;charset=utf-8;');
    setStatus(exportStatusMessage(result, 'Traceroute CSV'));
  };

  return (
    <section className="trace-panel">
      {/* Header */}
      <div className="page-header" style={{ marginBottom: 0 }}>
        <div className="page-title-block">
          <span className="page-tag">
            <span className="page-tag-dot" />
            TOPOLOGY ANALYSIS
          </span>
          <h1>Traceroute</h1>
        </div>
        <div className="page-header-actions" style={{ alignItems: 'center', gap: 8 }}>
          <span className="run-state" style={{ marginRight: 8 }}>
            <span className={`status-light ${traceLoading ? 'running' : 'idle'}`} />
            {traceLoading ? 'Running' : geoLoading ? 'Fetching GeoIP...' : 'Idle'}
          </span>
          <button
            className="secondary"
            onClick={handleExportTraceCsv}
            disabled={traceHops.length === 0}
          >
            Export CSV
          </button>
        </div>
      </div>

      {/* Input */}
      <div className="card" style={{ marginBottom: 0 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input
            id="traceHost"
            value={traceHost}
            onChange={(e) => setTraceHost(e.target.value)}
            onKeyDown={(e) => runOnEnter(e, handleTraceroute)}
            placeholder="Enter a hostname or IP"
            style={{ flex: 1 }}
          />
          <button onClick={handleTraceroute} disabled={traceLoading}>
            {traceLoading ? 'Running...' : 'Run Traceroute'}
          </button>
          <button className="secondary" onClick={handleTraceroute} disabled={traceLoading}>
            Rerun
          </button>
        </div>
      </div>

      {/* Summary KPIs */}
      <div className="trace-summary">
        <article className="trace-stat">
          <span>Total Hops</span>
          <strong>{traceSummary.totalHops}</strong>
        </article>
        <article className="trace-stat">
          <span>To Destination</span>
          <strong>
            {traceSummary.destRtt != null
              ? `${traceSummary.destRtt.toFixed(1)} ms`
              : 'n/a'}
          </strong>
        </article>
        <article className="trace-stat">
          <span>Worst Jump</span>
          <strong className={traceSummary.worstJump != null ? 'warn' : undefined}>
            {traceSummary.worstJump != null
              ? `+${traceSummary.worstJump.toFixed(1)} ms`
              : 'n/a'}
            {traceSummary.worstJumpHop != null && (
              <em className="trace-stat-note">hop {traceSummary.worstJumpHop}</em>
            )}
          </strong>
        </article>
      </div>

      {/* Hop list */}
      <div className="trace-list">
        {traceHops.length === 0 ? (
          <p className="empty">No hop analysis yet. Run traceroute to populate details.</p>
        ) : null}
        {traceHops.map((hop) => {
          const geo = geoData[hop.ip];
          const noResponse = hop.avgLatency == null;
          const isWorstJump = traceSummary.worstJumpHop != null && hop.hop === traceSummary.worstJumpHop;
          // Scale against the slowest hop in this trace, not a fixed ceiling.
          const barPct =
            noResponse || !traceSummary.maxRtt
              ? 0
              : Math.max(2, (hop.avgLatency / traceSummary.maxRtt) * 100);
          return (
            <article
              key={`${hop.hop}-${hop.ip}`}
              className={`trace-hop${noResponse ? ' no-response' : ''}${isWorstJump ? ' worst-jump' : ''}`}
            >
              <div className="trace-hop-head">
                <strong>Hop {hop.hop}</strong>
                <div className="trace-hop-metrics">
                  {hop.delta != null && (
                    <span className={`trace-delta${hop.delta > 0 ? ' up' : ' down'}`}>
                      {hop.delta > 0 ? '+' : '−'}
                      {Math.abs(hop.delta).toFixed(1)}
                    </span>
                  )}
                  <span className={`trace-pill ${hop.status}`}>
                    {hop.unreachable
                      ? 'unreachable'
                      : hop.avgLatency != null
                      ? `${hop.avgLatency.toFixed(1)} ms`
                      : 'no response'}
                  </span>
                </div>
              </div>
              <p className="trace-host">
                {hop.hostname ? `${hop.hostname} ` : ''}
                <span>{noResponse && hop.ip === '*' ? 'no response' : hop.ip}</span>
                {geo && (
                  <span
                    className="geo-tag"
                    title={`${geo.country || ''}${geo.city ? ` · ${geo.city}` : ''}${geo.as_info ? ` · ${geo.as_info}` : ''}`}
                  >
                    {geo.country_code ? ` · ${geo.country_code}` : ''}
                    {geo.org ? ` · ${geo.org}` : ''}
                  </span>
                )}
              </p>
              {noResponse ? (
                // A timeout is missing data, not slow data — never draw a filled bar,
                // which would read as the worst latency in the route.
                <div className="latency-bar-glass empty" title="Hop did not respond" />
              ) : (
                <div className="latency-bar-glass">
                  <div
                    className={`latency-bar-fill ${hop.status}`}
                    style={{ width: `${Math.min(barPct, 100)}%` }}
                  />
                </div>
              )}
            </article>
          );
        })}
      </div>

      {/* Raw output */}
      <div className="card" style={{ marginBottom: 0 }}>
        <pre className="diag-log-pre" style={{ margin: 0 }}>
          {traceOutput}
        </pre>
      </div>

      {status && status !== 'Ready.' && <div className="status-toast">{status}</div>}
    </section>
  );
}
