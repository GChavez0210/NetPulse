import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { runOnEnter } from '../trace/TraceTab';
import { getFloodPacketState } from '../../utils/networkUtils';

export default function FloodTestTab() {
  const [floodHostInput, setFloodHostInput] = useState('');
  const [rapidCount, setRapidCount] = useState(100);
  const [rapidRunning, setRapidRunning] = useState(false);
  const [status, setStatus] = useState('Ready.');
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

  useEffect(() => {
    let unlistenSample;
    let unlistenDone;
    let unlistenStatus;

    const setup = async () => {
      unlistenSample = await listen('ping:flood-sample', (e) => {
        const sample = e.payload;
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

      unlistenDone = await listen('ping:flood-done', (e) => {
        const payload = e.payload;
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
          lossStreakMax: summary.loss_streak_max ?? 0,
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

      unlistenStatus = await listen('ping:flood-status', (e) => {
        const payload = e.payload;
        if (!payload) return;
        if (
          payload.status === 'error' ||
          payload.status === 'done' ||
          payload.status === 'cancelled'
        ) {
          setRapidRunning(false);
        }
        setRapidDetails((prev) => ({
          ...prev,
          status: payload.status || prev.status,
          logLines: payload.message
            ? [
                ...prev.logLines,
                {
                  type: payload.status === 'error' ? 'failed' : 'meta',
                  text: payload.message
                }
              ].slice(-700)
            : prev.logLines
        }));
      });
    };

    setup();

    return () => {
      unlistenSample?.();
      unlistenDone?.();
      unlistenStatus?.();
      invoke('flood_cancel').catch(() => {});
    };
  }, []);

  const handleRapidPing = async () => {
    const host = floodHostInput.trim();
    if (!host) return;
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
      packetStates: Array.from({ length: rapidCount }, () => 'pending'),
      logLines: [
        { type: 'meta', text: `[init] Starting rapid ICMP test for ${host} (${rapidCount} pings)...` }
      ]
    });

    try {
      const startResult = await invoke('flood_start', {
        host,
        mode: 'ICMP',
        count: rapidCount
      });
      if (!startResult?.ok) {
        setRapidRunning(false);
        setRapidDetails((prev) => ({
          ...prev,
          status: 'error',
          logLines: [
            ...prev.logLines,
            { type: 'failed', text: startResult?.error || 'Start failed.' }
          ]
        }));
      } else {
        setFloodHostInput('');
      }
    } catch (error) {
      setRapidRunning(false);
      setRapidDetails((prev) => ({
        ...prev,
        status: 'error',
        logLines: [
          ...prev.logLines,
          { type: 'failed', text: String(error?.message || error) }
        ]
      }));
    }
  };

  const handleRapidCancel = async () => {
    if (!rapidRunning) return;
    try { await invoke('flood_cancel'); } catch (_) {}
  };

  const lossPct = Number(rapidDetails.lossPct || 0);
  const donutBg =
    lossPct === 0
      ? 'rgba(12,16,28,0.85)'
      : `conic-gradient(#ff4444 0 ${Math.max(3, lossPct * 3.6)}deg, rgba(12,16,28,0.85) ${Math.max(3, lossPct * 3.6)}deg 360deg)`;

  return (
    <section className="packetloss-page">
      {/* Header */}
      <div className="page-header" style={{ marginBottom: 0 }}>
        <div className="page-title-block">
          <span className="page-tag">
            <span className="page-tag-dot" />
            FLOOD DIAGNOSTICS
          </span>
          <h1>Packet Loss Test</h1>
          <p className="page-desc">
            Rapid ICMP flood analysis with per-packet sequencing, jitter classification, and loss rate visualization.
          </p>
        </div>
      </div>

      {/* Controls */}
      <div className="card" style={{ marginBottom: 0 }}>
        <div className="packetloss-controls">
          <input
            id="packetLossHost"
            value={floodHostInput}
            onChange={(e) => setFloodHostInput(e.target.value)}
            onKeyDown={(e) => runOnEnter(e, handleRapidPing)}
            placeholder="Enter a hostname or IP"
            style={{ width: 240 }}
          />
          <div className="count-toggle">
            <button
              className={rapidCount === 100 ? 'active' : ''}
              onClick={() => setRapidCount(100)}
            >
              100 Pings
            </button>
            <button
              className={rapidCount === 1000 ? 'active' : ''}
              onClick={() => setRapidCount(1000)}
            >
              1000 Pings
            </button>
          </div>
          <button onClick={handleRapidPing} disabled={rapidRunning}>
            {rapidRunning ? 'Running Test...' : 'Start Test'}
          </button>
          <button className="secondary" onClick={handleRapidCancel} disabled={!rapidRunning}>
            Cancel
          </button>
        </div>
      </div>

      {/* Layout */}
      <div className="packetloss-layout">
        {/* Left: Stats */}
        <aside className="packetloss-left">
          <article className="loss-donut-card">
            <div className="loss-donut" style={{ background: donutBg }}>
              <div>
                <strong>{lossPct.toFixed(1)}%</strong>
                <span>Loss Rate</span>
              </div>
            </div>
          </article>

          <article className="diag-metric">Total Sent <strong>{rapidDetails.sent}</strong></article>
          <article className="diag-metric">Received <strong>{rapidDetails.received}</strong></article>
          <article className="diag-metric">Lost <strong>{rapidDetails.lost}</strong></article>
          <article className="diag-metric">
            Avg RTT{' '}
            <strong>{rapidDetails.avgLatency != null ? `${rapidDetails.avgLatency} ms` : 'n/a'}</strong>
          </article>
          <article className="diag-metric">
            Min/Max RTT{' '}
            <strong>
              {rapidDetails.minRtt != null
                ? `${rapidDetails.minRtt}/${rapidDetails.maxRtt} ms`
                : 'n/a'}
            </strong>
          </article>
          <article className="diag-metric">
            Jitter/P95{' '}
            <strong>
              {rapidDetails.jitterMs != null
                ? `${rapidDetails.jitterMs}/${rapidDetails.p95Rtt ?? 'n/a'} ms`
                : 'n/a'}
            </strong>
          </article>
          <article className="diag-metric">
            Max Loss Streak <strong>{rapidDetails.lossStreakMax}</strong>
          </article>
          <article className="diag-metric">
            Error Rate{' '}
            <strong
              className={
                rapidDetails.lossPct >= 5
                  ? 'critical'
                  : rapidDetails.lossPct >= 1
                  ? 'warn'
                  : 'healthy'
              }
            >
              {rapidDetails.lossPct >= 5
                ? 'Critical'
                : rapidDetails.lossPct >= 1
                ? 'Warning'
                : 'Stable'}
            </strong>
          </article>
        </aside>

        {/* Right: Sequence + Log */}
        <section className="packetloss-right">
          <div className="sequence-head">
            <h3>Sequence Analysis (Pings 1–{rapidCount})</h3>
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
      </div>

      {status !== 'Ready.' && <div className="status-toast">{status}</div>}
    </section>
  );
}
