import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import LineChart from '../../components/LineChart';
import { runOnEnter } from '../trace/TraceTab';
import {
  HEALTH,
  MAX_ACTIVE_SESSIONS,
  DOWN_THRESHOLD,
  MAX_POINTS,
  getHealth,
  getTestMetrics,
  createTest
} from '../../utils/networkUtils';

function latencyColor(ms) {
  if (ms == null) return undefined;
  if (ms <= 50) return 'var(--accent)';
  if (ms <= 150) return 'var(--warn)';
  return 'var(--danger)';
}

function healthPill(health) {
  if (health === HEALTH.DOWN) return { label: 'TIMEOUT', cls: 'pill-timeout' };
  if (health === HEALTH.DEGRADED) return { label: 'JITTER', cls: 'pill-jitter' };
  return { label: 'STABLE', cls: 'pill-stable' };
}

export default function PingTab() {
  const [hostInput, setHostInput] = useState('');
  const [pingEntryMode, setPingEntryMode] = useState('single');
  const [bulkHostsInput, setBulkHostsInput] = useState('');
  const [tests, setTests] = useState([]);
  const [packetSize, setPacketSize] = useState(56);
  const [dontFragment, setDontFragment] = useState(false);
  const [status, setStatus] = useState('Ready.');

  const timersRef = useRef(new Map());
  const inFlightRef = useRef(new Set());
  const testsRef = useRef(tests);

  useEffect(() => {
    testsRef.current = tests;
  }, [tests]);

  useEffect(() => {
    if (typeof Notification !== 'undefined' && Notification.permission === 'default') {
      Notification.requestPermission().catch(() => {});
    }
    return () => {
      for (const timer of timersRef.current.values()) clearInterval(timer);
      timersRef.current.clear();
      inFlightRef.current.clear();
    };
  }, []);

  const pushNotification = (host, type, text) => {
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
        const isSuccess = result.ok && result.latency_ms != null;
        const failureStreak = isSuccess ? 0 : test.failureStreak + 1;
        let reachable = test.reachable;
        if (isSuccess) {
          if (test.reachable !== true) emitted = { type: 'up', text: 'Host recovered and is responding again.' };
          reachable = true;
        } else if (failureStreak >= DOWN_THRESHOLD && test.reachable !== false) {
          emitted = { type: 'down', text: `Host is down after ${failureStreak} consecutive failed pings.` };
          reachable = false;
        }

        const nextPoints = isSuccess
          ? [...test.points, { ts: Date.now(), latency: result.latency_ms }].slice(-MAX_POINTS)
          : test.points;
        const nowTs = Date.now();
        const nextEvents = [...test.events];
        if (emitted?.type === 'up') nextEvents.push({ id: `${nowTs}-up`, ts: nowTs, kind: 'up' });
        else if (emitted?.type === 'down') nextEvents.push({ id: `${nowTs}-down`, ts: nowTs, kind: 'down' });

        return {
          ...test,
          reachable,
          failureStreak,
          points: nextPoints,
          events: nextEvents.slice(-20),
          sent: test.sent + 1,
          received: test.received + (isSuccess ? 1 : 0),
          lastLatency: isSuccess ? result.latency_ms : null,
          lastOutput: result.output || 'No output.'
        };
      })
    );
    if (emitted) {
      const target = testsRef.current.find((t) => t.id === id);
      if (target) pushNotification(target.host, emitted.type, emitted.text);
    }
  };

  const samplePing = async (id) => {
    if (inFlightRef.current.has(id)) return;
    const target = testsRef.current.find((t) => t.id === id);
    if (!target || target.phase !== 'running') return;
    inFlightRef.current.add(id);
    try {
      const result = await invoke('ping_sample', {
        host: target.host,
        packetSize,
        dontFragment
      });
      applyPingSample(id, result);
    } catch (error) {
      applyPingSample(id, {
        ok: false,
        latency_ms: null,
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
    const timer = setInterval(() => samplePing(id), 1000);
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
        test.id === id
          ? { ...test, viewMode: test.viewMode === 'graph' ? 'cli' : 'graph' }
          : test
      )
    );
  };

  const addTest = () => {
    const host = hostInput.trim();
    if (!host) { setStatus('Enter a valid host or IP address.'); return; }
    if (testsRef.current.some((t) => t.host.toLowerCase() === host.toLowerCase())) {
      setStatus(`Target ${host} already exists.`);
      return;
    }
    if (testsRef.current.filter((t) => t.phase === 'running').length >= MAX_ACTIVE_SESSIONS) {
      setStatus(`Active session limit reached (${MAX_ACTIVE_SESSIONS}).`);
      return;
    }
    const test = createTest(host);
    setTests((prev) => [test, ...prev]);
    setStatus(`Created new ping test for ${host}.`);
    setHostInput('');
    setTimeout(() => startTest(test.id), 0);
  };

  const addBulkTests = () => {
    const hosts = Array.from(
      new Set(
        bulkHostsInput
          .split(/[\n,;\t ]+/)
          .map((v) => v.trim())
          .filter(Boolean)
      )
    );
    if (hosts.length === 0) { setStatus('Enter at least one valid host.'); return; }
    const existing = new Set(testsRef.current.map((t) => t.host.toLowerCase()));
    const allowed = hosts
      .filter((h) => !existing.has(h.toLowerCase()))
      .slice(0, Math.max(MAX_ACTIVE_SESSIONS - testsRef.current.filter((t) => t.phase === 'running').length, 0));
    if (allowed.length === 0) {
      setStatus('No bulk targets added (limit reached or duplicates).');
      return;
    }
    const newTests = allowed.map((host) => createTest(host));
    setTests((prev) => [...newTests, ...prev]);
    setStatus(`Created ${newTests.length} sessions.`);
    setBulkHostsInput('');
    setTimeout(() => newTests.forEach((t) => startTest(t.id)), 0);
  };

  const startAll = () => {
    if (pingEntryMode === 'bulk' && bulkHostsInput.trim()) { addBulkTests(); return; }
    let started = 0;
    const slots = Math.max(
      MAX_ACTIVE_SESSIONS - testsRef.current.filter((t) => t.phase === 'running').length,
      0
    );
    testsRef.current.forEach((t) => {
      if (started < slots && t.phase !== 'running') { startTest(t.id); started++; }
    });
    setStatus(started > 0 ? `Started ${started} sessions.` : 'No sessions started.');
  };

  const pauseAll = () => { testsRef.current.forEach((t) => pauseTest(t.id)); setStatus('All tests paused.'); };
  const stopAll = () => { testsRef.current.forEach((t) => stopTest(t.id)); setStatus('All tests stopped.'); };

  const exportSession = () => {
    const rows = tests.map((t) => {
      const m = getTestMetrics(t);
      const { label } = healthPill(getHealth(t));
      const loss = t.sent > 0 ? ((t.sent - t.received) / t.sent * 100).toFixed(2) : '0.00';
      return [t.host, m.avg?.toFixed(1) ?? '--', m.max?.toFixed(1) ?? '--', loss, label].join(',');
    });
    const csv = ['Host,Avg RTT (ms),Max RTT (ms),Loss %,Status', ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netpulse-session-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // KPI computations
  const activeCount = tests.filter((t) => t.phase === 'running').length;
  const allRtts = tests.flatMap((t) => t.points.map((p) => p.latency));
  const globalAvgRtt =
    allRtts.length > 0
      ? (allRtts.reduce((a, b) => a + b, 0) / allRtts.length).toFixed(1)
      : null;
  const activeSent = tests.filter((t) => t.sent > 0);
  const globalLoss =
    activeSent.length > 0
      ? (
          activeSent.reduce((acc, t) => acc + ((t.sent - t.received) / t.sent * 100), 0) /
          activeSent.length
        ).toFixed(2)
      : null;

  return (
    <section className="ping-dashboard">

      {/* Page Header */}
      <div className="page-header">
        <div className="page-title-block">
          <span className="page-tag">
            <span className="page-tag-dot" />
            MONITOR ACTIVE
          </span>
          <h1>Multi-Target Ping</h1>
          <p className="page-desc">
            High-precision diagnostic array for global infrastructure interrogation. Real-time latency tracking and resolver validation.
          </p>
        </div>
        <div className="page-header-actions">
          <button className="secondary" onClick={exportSession} disabled={tests.length === 0}>
            Export Session
          </button>
          <button onClick={startAll}>Run Global Array</button>
        </div>
      </div>

      {/* KPI Row */}
      <div className="kpi-row">
        <div className="kpi-card">
          <span className="kpi-label">Active Monitors</span>
          <strong className="kpi-value">
            {activeCount}
            <span className="kpi-unit"> Running</span>
          </strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Global Avg RTT</span>
          <strong className="kpi-value">
            {globalAvgRtt != null ? (
              <>{globalAvgRtt}<span className="kpi-unit">ms</span></>
            ) : '—'}
          </strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Avg Packet Loss</span>
          <strong className="kpi-value">
            {globalLoss != null ? (
              <>{globalLoss}<span className="kpi-unit">%</span></>
            ) : '—'}
          </strong>
        </div>
      </div>

      {/* Controls */}
      <div className="card command-panel">
        <section className="ping-topbar">
          <div className="ping-actions">
            <div className="entry-toggle">
              <button
                className={pingEntryMode === 'single' ? 'active' : ''}
                onClick={() => setPingEntryMode('single')}
              >
                Single IP
              </button>
              <button
                className={pingEntryMode === 'bulk' ? 'active' : ''}
                onClick={() => setPingEntryMode('bulk')}
              >
                Bulk IPs
              </button>
            </div>
            {pingEntryMode === 'single' && (
              <>
                <input
                  id="host"
                  value={hostInput}
                  onChange={(e) => setHostInput(e.target.value)}
                  onKeyDown={(e) => runOnEnter(e, addTest)}
                  placeholder="Enter a hostname or IP"
                  style={{ width: 240 }}
                />
                <button onClick={addTest}>Add Target</button>
              </>
            )}
          </div>
        </section>

        {pingEntryMode === 'bulk' ? (
          <>
            <label htmlFor="bulkHosts">Bulk Hosts (one per line or comma separated)</label>
            <textarea
              id="bulkHosts"
              value={bulkHostsInput}
              onChange={(e) => setBulkHostsInput(e.target.value)}
              placeholder={'Enter a hostname\nexample.com\n192.168.1.1'}
            />
            <p className="empty" style={{ textAlign: 'left', padding: 0, marginBottom: 8 }}>
              Bulk mode: paste targets here, then click Run Global Array or Start All.
            </p>
          </>
        ) : (
          <p className="empty" style={{ textAlign: 'left', padding: 0, marginBottom: 8 }}>
            Single IP mode enabled. Switch to Bulk IPs to paste multiple targets.
          </p>
        )}

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
          <button className="secondary" onClick={startAll}>Start All</button>
          <button className="secondary" onClick={pauseAll} disabled={tests.length === 0}>Pause All</button>
          <button className="danger" onClick={stopAll} disabled={tests.length === 0}>Stop All</button>
        </div>

        <div className="ping-options-row">
          <label htmlFor="packetSize" style={{ margin: 0, marginRight: 4 }}>
            Packet Size (bytes)
          </label>
          <input
            id="packetSize"
            type="number"
            min="1"
            max="65000"
            value={packetSize}
            onChange={(e) => setPacketSize(Number.parseInt(e.target.value || '56', 10))}
            style={{ width: 120 }}
          />
          <label className="checkbox-inline" style={{ margin: 0 }}>
            <input
              type="checkbox"
              checked={dontFragment}
              onChange={(e) => setDontFragment(e.target.checked)}
            />
            Don't Fragment (DF)
          </label>
        </div>
      </div>

      {/* Monitor Grid */}
      <section className="tests-grid ping-grid">
        {tests.length === 0 && (
          <p className="empty" style={{ gridColumn: '1 / -1' }}>
            No active monitors. Add a target to begin.
          </p>
        )}
        {tests.map((test) => {
          const health = getHealth(test);
          const uptime = test.sent > 0 ? ((test.received / test.sent) * 100).toFixed(1) : '0.0';
          const m = getTestMetrics(test);
          const { label: pillLabel, cls: pillCls } = healthPill(health);

          return (
            <article key={test.id} className={`test-card ping-card`}>
              <div className="test-head">
                <div>
                  <div className="target-title">
                    <span className={`status-light ${health}`} />
                    <h3 style={{ color: health === 'normal' ? 'var(--accent)' : health === 'degraded' ? 'var(--warn)' : health === 'down' ? 'var(--danger)' : 'var(--text)' }}>
                      {test.host}
                    </h3>
                  </div>
                  <p className="target-sub">
                    {test.phase.toUpperCase()} &bull; UPTIME {uptime}%
                  </p>
                </div>
                <span className={`status-pill ${pillCls}`}>{pillLabel}</span>
              </div>

              {test.viewMode === 'graph' ? (
                <LineChart points={test.points} health={health} liveLabel={pillLabel} events={test.events} />
              ) : (
                <pre style={{ marginBottom: 8 }}>{test.lastOutput}</pre>
              )}

              <div className="metric-row">
                <article className="metric-box">
                  <span>Current</span>
                  <strong style={{ color: latencyColor(m.current) }}>
                    {m.current != null ? `${m.current.toFixed(0)}ms` : '--'}
                  </strong>
                </article>
                <article className="metric-box">
                  <span>Average</span>
                  <strong style={{ color: latencyColor(m.avg) }}>
                    {m.avg != null ? `${m.avg.toFixed(0)}ms` : '--'}
                  </strong>
                </article>
                <article className="metric-box">
                  <span>Max</span>
                  <strong style={{ color: latencyColor(m.max) }}>
                    {m.max != null ? `${m.max.toFixed(0)}ms` : '--'}
                  </strong>
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

      {status !== 'Ready.' && <div className="status-toast">{status}</div>}
    </section>
  );
}
