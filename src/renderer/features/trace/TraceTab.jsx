import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

export const runOnEnter = (event, action) => {
  if (event.key !== 'Enter') return;
  event.preventDefault();
  action();
};

export default function TraceTab() {
  const [traceHost, setTraceHost] = useState('');
  const [traceLoading, setTraceLoading] = useState(false);
  const [traceHops, setTraceHops] = useState([]);
  const [traceOutput, setTraceOutput] = useState('No traceroute execution yet.');
  const [traceSummary, setTraceSummary] = useState({ totalHops: 0, avgRtt: null });
  const [status, setStatus] = useState('Ready.');

  const parseTracerouteLine = (rawLine) => {
    const line = rawLine.trim();
    if (!line) return null;
    if (
      /^tracing route/i.test(line) ||
      /^trace complete/i.test(line) ||
      /^over a maximum/i.test(line)
    ) return null;

    const hopMatch = line.match(/^(\d+)\s+(.*)$/);
    if (!hopMatch) return null;

    const hop = Number.parseInt(hopMatch[1], 10);
    const rest = hopMatch[2];
    const latencyMatches = [...rest.matchAll(/<?\s*(\d+(?:\.\d+)?)\s*ms/gi)];
    const latencies = latencyMatches
      .map((m) => Number.parseFloat(m[1]))
      .filter((v) => Number.isFinite(v));
    const avgLatency =
      latencies.length > 0 ? latencies.reduce((a, b) => a + b, 0) / latencies.length : null;

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

    const getLatencyStatus = (latencyMs) => {
      if (latencyMs == null) return 'bad';
      if (latencyMs <= 60) return 'good';
      if (latencyMs <= 140) return 'warn';
      return 'bad';
    };

    return {
      hop,
      ip,
      hostname,
      latencies,
      avgLatency,
      status: getLatencyStatus(avgLatency),
      timedOut: rest.includes('*')
    };
  };

  const parseTracerouteOutput = (output) => {
    const lines = String(output || '')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    const hops = lines.map(parseTracerouteLine).filter(Boolean);
    const avgCandidates = hops.map((h) => h.avgLatency).filter((v) => v != null);
    const avgRtt =
      avgCandidates.length > 0
        ? avgCandidates.reduce((a, b) => a + b, 0) / avgCandidates.length
        : null;
    return { hops, totalHops: hops.length, avgRtt };
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
      const result = await invoke('trace_run', { host });
      if (!result.ok) throw new Error(result.error || 'Traceroute failed');
      const output = result.output;
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
    if (traceHops.length === 0) return;

    const escapeCsv = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;
    const rows = [
      ['targetHost', 'createdAt', 'totalHops', 'avgRttMs', 'hop', 'hostname', 'ip', 'status', 'avgLatencyMs', 'timedOut', 'latenciesMs'].join(',')
    ];
    traceHops.forEach((hop) => {
      rows.push(
        [
          escapeCsv(traceHost || ''),
          escapeCsv(new Date().toISOString()),
          escapeCsv(traceSummary.totalHops),
          escapeCsv(traceSummary.avgRtt != null ? traceSummary.avgRtt.toFixed(2) : ''),
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
    a.download = `traceroute-${traceHost || 'report'}-${Date.now()}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setStatus('Traceroute CSV exported.');
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
          <p className="page-desc">
            Visualize network path hops with per-hop latency and status classification.
          </p>
        </div>
        <div className="page-header-actions" style={{ alignItems: 'center', gap: 8 }}>
          <span
            className="run-state"
            style={{ marginRight: 8 }}
          >
            <span className={`status-light ${traceLoading ? 'running' : 'idle'}`} />
            {traceLoading ? 'Running' : 'Idle'}
          </span>
          <button className="secondary" onClick={handleExportTraceCsv} disabled={traceHops.length === 0}>
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
          <span>Average RTT</span>
          <strong>
            {traceSummary.avgRtt != null ? `${traceSummary.avgRtt.toFixed(1)} ms` : 'n/a'}
          </strong>
        </article>
      </div>

      {/* Hop list */}
      <div className="trace-list">
        {traceHops.length === 0 ? (
          <p className="empty">No hop analysis yet. Run traceroute to populate details.</p>
        ) : null}
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

      {/* Raw output */}
      <div className="card" style={{ marginBottom: 0 }}>
        <pre className="diag-log-pre" style={{ margin: 0 }}>{traceOutput}</pre>
      </div>

      {status && status !== 'Ready.' && <div className="status-toast">{status}</div>}
    </section>
  );
}
