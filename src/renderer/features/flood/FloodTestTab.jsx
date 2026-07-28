import React, { useState, useEffect, useRef, useMemo, memo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import {
  LineChart as ReLineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { runOnEnter } from '../trace/TraceTab';
import {
  getFloodPacketState,
  classifyRtt,
  medianOf,
  SPIKE_BASELINE_SAMPLES,
  SPIKE_RATIO,
} from '../../utils/networkUtils';

// Memoized so React can bail out of re-rendering the ~999 unchanged cells
// on every single-packet sample update instead of re-diffing all of them.
// The title is built in here rather than in the parent's map so it costs
// nothing for cells whose props didn't change.
const PacketCell = memo(function PacketCell({ state, seq, rtt }) {
  const title =
    state === 'pending'
      ? `seq ${seq} — not sent yet`
      : state === 'failed'
      ? `seq ${seq} — timeout`
      : `seq ${seq} — ${rtt != null ? `${rtt.toFixed(1)} ms` : 'no RTT'}`;
  return <span className={`pkt ${state}`} title={title} />;
});

const SequenceGrid = memo(function SequenceGrid({ packetStates, rtts }) {
  return (
    <div className="sequence-grid">
      {packetStates.map((state, index) => (
        <PacketCell key={index} state={state} seq={index + 1} rtt={rtts[index]} />
      ))}
    </div>
  );
});

// Timeouts are left as null so recharts breaks the line rather than drawing
// through the gap — a dropped packet isn't a latency reading of zero.
const FloodChart = memo(function FloodChart({ samples }) {
  const data = useMemo(
    () => samples.map((s) => ({ seq: s.seq, rtt: s.timeout ? null : s.rtt })),
    [samples]
  );

  if (data.length === 0) {
    return <div className="flood-chart empty">Awaiting samples...</div>;
  }

  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;
    const point = payload[0].payload;
    return (
      <div className="flood-chart-tip">
        <div>seq {point.seq}</div>
        <div style={{ color: point.rtt == null ? 'var(--color-danger)' : 'var(--color-success)' }}>
          {point.rtt == null ? 'timeout' : `${point.rtt.toFixed(1)} ms`}
        </div>
      </div>
    );
  };

  return (
    <div className="flood-chart">
      <ResponsiveContainer width="100%" height="100%">
        <ReLineChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -26 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
          <XAxis
            dataKey="seq"
            tick={{ fontSize: 10, fontFamily: 'monospace', fill: 'var(--color-text-muted)' }}
            interval="preserveStartEnd"
            minTickGap={40}
          />
          <YAxis
            domain={['auto', 'auto']}
            tick={{ fontSize: 10, fontFamily: 'monospace', fill: 'var(--color-text-muted)' }}
          />
          <Tooltip content={<CustomTooltip />} />
          <Line
            type="monotone"
            dataKey="rtt"
            stroke="var(--color-success)"
            strokeWidth={1.5}
            dot={false}
            connectNulls={false}
            isAnimationActive={false}
          />
        </ReLineChart>
      </ResponsiveContainer>
    </div>
  );
});

const DiagLog = memo(function DiagLog({ logLines }) {
  return (
    <pre className="diag-log-pre">
      {logLines.map((line) => (
        <div key={line.id} className={`diag-line ${line.type}`}>
          {line.text}
        </div>
      ))}
    </pre>
  );
});

export default function FloodTestTab({ addNotification }) {
  const [floodHostInput, setFloodHostInput] = useState('');
  const [rapidCount, setRapidCount] = useState(100);
  const hostRef = useRef('');
  const [rapidRunning, setRapidRunning] = useState(false);
  // Mirrors rapidRunning for the unmount-cleanup effect below, which only
  // needs the latest value and shouldn't itself be a dependency of that effect.
  const rapidRunningRef = useRef(false);
  useEffect(() => { rapidRunningRef.current = rapidRunning; }, [rapidRunning]);
  const [status, setStatus] = useState('Ready.');
  // Stable, ever-increasing ids for log lines so React keys stay stable across
  // the .slice(-700) trim (index-based keys would shift and force full remounts).
  const logIdRef = useRef(0);
  const makeLine = (type, text) => ({ id: ++logIdRef.current, type, text });
  const [rapidDetails, setRapidDetails] = useState(() => ({
    host: '',
    mode: 'ICMP',
    sent: 0,
    received: 0,
    lost: 0,
    lossPct: 0,
    avgLatency: null,
    minRtt: null,
    maxRtt: null,
    p95Rtt: null,
    jitterMs: null,
    lossStreakMax: 0,
    status: 'idle',
    // Frozen reference RTT for spike detection, plus the replies it's built from.
    baseline: null,
    baselineRtts: [],
    packetStates: [],
    // Per-packet RTTs, retained so the run can be charted and exported.
    rtts: [],
    samples: [],
    logLines: [makeLine('meta', '[init] Ready for packet loss diagnostics.')]
  }));

  useEffect(() => {
    let cancelled = false;
    const unlisteners = [];

    const setup = async () => {
      const unlistenSample = await listen('ping:flood-sample', (e) => {
        if (cancelled) return;
        const sample = e.payload;
        if (!sample || typeof sample.seq !== 'number') return;
        setRapidDetails((prev) => {
          const nextStates = [...prev.packetStates];
          const nextRtts = [...prev.rtts];
          const index = sample.seq - 1;

          // Accumulate the first N replies, then freeze a median as this run's
          // reference point. Everything before that can't be judged yet.
          let baseline = prev.baseline;
          let baselineRtts = prev.baselineRtts;
          if (baseline == null && !sample.timeout && sample.rtt_ms != null) {
            baselineRtts = [...baselineRtts, sample.rtt_ms];
            if (baselineRtts.length >= SPIKE_BASELINE_SAMPLES) {
              baseline = medianOf(baselineRtts);
            }
          }

          if (index >= 0 && index < nextStates.length) {
            nextStates[index] = getFloodPacketState(sample, baseline);
            nextRtts[index] = sample.timeout ? null : sample.rtt_ms ?? null;
          }

          // The packets that arrived before the baseline existed were all
          // recorded as normal; once there's something to compare against,
          // score them properly. One-time pass on the sample that fixes it.
          if (baseline != null && prev.baseline == null) {
            for (let i = 0; i < nextStates.length; i += 1) {
              if (nextStates[i] === 'pending' || nextStates[i] === 'failed') continue;
              nextStates[i] = classifyRtt(nextRtts[i], baseline);
            }
          }

          const received = nextStates.filter((state) => state !== 'failed' && state !== 'pending').length;
          const sent = nextStates.filter((state) => state !== 'pending').length;
          const lost = Math.max(sent - received, 0);
          const lossPct = sent > 0 ? Number(((lost * 100) / sent).toFixed(2)) : 0;
          const logType = sample.timeout
            ? 'failed'
            : classifyRtt(sample.rtt_ms, baseline) === 'jitter'
            ? 'jitter'
            : 'success';
          const logText = sample.timeout
            ? `[${sample.timestamp}] seq=${sample.seq} timeout`
            : `[${sample.timestamp}] seq=${sample.seq} rtt=${sample.rtt_ms}ms`;

          return {
            ...prev,
            sent,
            received,
            lost,
            lossPct,
            baseline,
            baselineRtts,
            packetStates: nextStates,
            rtts: nextRtts,
            samples: [
              ...prev.samples,
              {
                seq: sample.seq,
                rtt: sample.timeout ? null : sample.rtt_ms ?? null,
                timeout: Boolean(sample.timeout),
                timestamp: sample.timestamp,
              },
            ],
            logLines: [...prev.logLines, makeLine(logType, logText)].slice(-700)
          };
        });
      });
      if (cancelled) { unlistenSample(); return; }
      unlisteners.push(unlistenSample);

      const unlistenDone = await listen('ping:flood-done', (e) => {
        if (cancelled) return;
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
            makeLine(
              'meta',
              `[${new Date().toISOString()}] Flood ${summary.status || 'done'}: sent=${summary.sent}, recv=${summary.received}, loss=${summary.loss_pct}%`
            )
          ].slice(-700)
        }));
        addNotification?.(
          'flood_complete',
          `Flood test to ${hostRef.current} complete — sent=${summary.sent}, recv=${summary.received}, loss=${summary.loss_pct}%`
        );
        setStatus(
          `Flood test ${summary.status || 'complete'} — ${summary.loss_pct}% loss over ${summary.sent} pings.`
        );
        setRapidRunning(false);
      });
      if (cancelled) { unlistenDone(); return; }
      unlisteners.push(unlistenDone);

      const unlistenStatus = await listen('ping:flood-status', (e) => {
        if (cancelled) return;
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
                makeLine(payload.status === 'error' ? 'failed' : 'meta', payload.message)
              ].slice(-700)
            : prev.logLines
        }));
      });
      if (cancelled) { unlistenStatus(); return; }
      unlisteners.push(unlistenStatus);
    };

    setup();

    return () => {
      cancelled = true;
      unlisteners.forEach((u) => u());
      if (rapidRunningRef.current) invoke('flood_cancel').catch(() => {});
    };
  }, []);

  const handleRapidPing = async () => {
    const host = floodHostInput.trim();
    if (!host) {
      setStatus('Enter a hostname or IP for the flood test.');
      return;
    }
    hostRef.current = host;
    setRapidRunning(true);
    setStatus(`Running ${rapidCount}-ping flood test against ${host}...`);
    setRapidDetails({
      host,
      mode: 'ICMP',
      sent: 0,
      received: 0,
      lost: 0,
      lossPct: 0,
      avgLatency: null,
      minRtt: null,
      maxRtt: null,
      p95Rtt: null,
      jitterMs: null,
      lossStreakMax: 0,
      status: 'working',
      baseline: null,
      baselineRtts: [],
      packetStates: Array.from({ length: rapidCount }, () => 'pending'),
      rtts: Array.from({ length: rapidCount }, () => null),
      samples: [],
      logLines: [
        makeLine('meta', `[init] Starting rapid ICMP test for ${host} (${rapidCount} pings)...`)
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
        setStatus(startResult?.error || 'Flood test failed to start.');
        setRapidDetails((prev) => ({
          ...prev,
          status: 'error',
          logLines: [
            ...prev.logLines,
            makeLine('failed', startResult?.error || 'Start failed.')
          ]
        }));
      }
      // The host stays in the box so the test can be re-run without retyping.
    } catch (error) {
      const msg = String(error?.message || error);
      setRapidRunning(false);
      setStatus(`Flood test error: ${msg}`);
      setRapidDetails((prev) => ({
        ...prev,
        status: 'error',
        logLines: [...prev.logLines, makeLine('failed', msg)]
      }));
    }
  };

  const handleRapidCancel = async () => {
    if (!rapidRunning) return;
    try {
      await invoke('flood_cancel');
      setStatus('Cancelling flood test...');
    } catch (_) {
      setStatus('Could not cancel the flood test.');
    }
  };

  const handleExportCsv = () => {
    const { samples, host } = rapidDetails;
    if (samples.length === 0) return;

    const escapeCsv = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;
    const summaryCols = [
      escapeCsv(host),
      escapeCsv(new Date().toISOString()),
      escapeCsv(rapidDetails.sent),
      escapeCsv(rapidDetails.received),
      escapeCsv(rapidDetails.lossPct),
      escapeCsv(rapidDetails.avgLatency != null ? rapidDetails.avgLatency.toFixed(2) : ''),
      escapeCsv(rapidDetails.minRtt != null ? rapidDetails.minRtt.toFixed(2) : ''),
      escapeCsv(rapidDetails.maxRtt != null ? rapidDetails.maxRtt.toFixed(2) : ''),
      escapeCsv(rapidDetails.p95Rtt != null ? rapidDetails.p95Rtt.toFixed(2) : ''),
      escapeCsv(rapidDetails.jitterMs != null ? rapidDetails.jitterMs.toFixed(2) : ''),
      escapeCsv(rapidDetails.lossStreakMax),
    ];

    const rows = [
      [
        'targetHost', 'exportedAt', 'sent', 'received', 'lossPct',
        'avgRttMs', 'minRttMs', 'maxRttMs', 'p95RttMs', 'jitterMs', 'maxLossStreak',
        'seq', 'timestamp', 'rttMs', 'timedOut',
      ].join(','),
    ];
    samples.forEach((s) => {
      rows.push(
        [
          ...summaryCols,
          escapeCsv(s.seq),
          escapeCsv(s.timestamp),
          escapeCsv(s.rtt != null ? s.rtt.toFixed(2) : ''),
          escapeCsv(s.timeout),
        ].join(',')
      );
    });

    const blob = new Blob([rows.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netpulse-flood-${host || 'test'}-${Date.now()}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setStatus(`Flood CSV exported — ${samples.length} samples.`);
  };

  const lossPct = Number(rapidDetails.lossPct || 0);
  // Loss that matters lives in the 0.5–5% band, which a donut renders as an
  // indistinguishable sliver — so the figure is the visual.
  const lossSeverity = lossPct >= 5 ? 'critical' : lossPct >= 1 ? 'warn' : 'healthy';
  const lossLabel = lossPct >= 5 ? 'Critical' : lossPct >= 1 ? 'Warning' : 'Stable';

  const spikeRuleLabel =
    rapidDetails.baseline != null
      ? `Over ${SPIKE_RATIO}× this run's baseline of ${rapidDetails.baseline.toFixed(1)} ms`
      : `Set once ${SPIKE_BASELINE_SAMPLES} replies have arrived — spikes are measured against this run's own baseline, not a fixed threshold`;

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
        </div>
        <div className="page-header-actions" style={{ alignItems: 'center', gap: 8 }}>
          {rapidDetails.host && (
            <span className="run-state">
              <span className={`status-light ${rapidRunning ? 'running' : 'idle'}`} />
              {rapidDetails.host}
            </span>
          )}
          <button
            className="secondary"
            onClick={handleExportCsv}
            disabled={rapidDetails.samples.length === 0}
          >
            Export CSV
          </button>
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
          <article className="loss-headline">
            <span className="loss-headline-label">Loss Rate</span>
            <strong className={lossSeverity}>{lossPct.toFixed(1)}%</strong>
            <span className={`loss-headline-status ${lossSeverity}`}>{lossLabel}</span>
          </article>

          <article className="diag-metric">Total Sent <strong>{rapidDetails.sent}</strong></article>
          <article className="diag-metric">Received <strong>{rapidDetails.received}</strong></article>
          <article className="diag-metric">Lost <strong>{rapidDetails.lost}</strong></article>
          <article className="diag-metric">
            Avg RTT{' '}
            <strong>{rapidDetails.avgLatency != null ? `${rapidDetails.avgLatency.toFixed(2)} ms` : 'n/a'}</strong>
          </article>
          <article className="diag-metric">
            Min/Max RTT{' '}
            <strong>
              {rapidDetails.minRtt != null
                ? `${rapidDetails.minRtt.toFixed(2)}/${rapidDetails.maxRtt.toFixed(2)} ms`
                : 'n/a'}
            </strong>
          </article>
          <article className="diag-metric">
            Jitter/P95{' '}
            <strong>
              {rapidDetails.jitterMs != null
                ? `${rapidDetails.jitterMs.toFixed(2)}/${
                    rapidDetails.p95Rtt != null ? rapidDetails.p95Rtt.toFixed(2) : 'n/a'
                  } ms`
                : 'n/a'}
            </strong>
          </article>
          <article className="diag-metric" title={spikeRuleLabel}>
            Spike Baseline{' '}
            <strong>
              {rapidDetails.baseline != null ? `${rapidDetails.baseline.toFixed(1)} ms` : 'n/a'}
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
            <h3>RTT Over Sequence</h3>
            <div className="sequence-legend">
              <span className="failed">Gaps = timeouts</span>
            </div>
          </div>

          <FloodChart samples={rapidDetails.samples} />

          <div className="sequence-head" style={{ marginTop: 16 }}>
            <h3>Sequence Analysis (Pings 1–{rapidCount})</h3>
            <div className="sequence-legend">
              <span className="success">Normal</span>
              <span className="jitter" title={spikeRuleLabel}>Spike</span>
              <span className="failed">Failed</span>
            </div>
          </div>

          <SequenceGrid packetStates={rapidDetails.packetStates} rtts={rapidDetails.rtts} />

          <section className="diag-log">
            <h4>Diagnostic Log</h4>
            <DiagLog logLines={rapidDetails.logLines} />
          </section>
        </section>
      </div>

      {status !== 'Ready.' && <div className="status-toast">{status}</div>}
    </section>
  );
}
