import React, { useState, useEffect, useRef, useReducer, useMemo, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { DndContext, closestCenter, PointerSensor, useSensor, useSensors } from '@dnd-kit/core';
import { SortableContext, rectSortingStrategy, arrayMove } from '@dnd-kit/sortable';
import { runOnEnter } from '../trace/TraceTab';
import PingCard from './PingCard';
import FavoritesPanel from './FavoritesPanel';
import {
  MAX_ACTIVE_SESSIONS,
  DOWN_THRESHOLD,
  MAX_POINTS,
  HEALTH_WINDOW,
  getHealthReason,
  formatHealthReason,
  getTestMetrics,
  createTest,
  parseIntOrDefault,
} from '../../utils/networkUtils';

function playAlert(type) {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.type = 'sine';
    const t = ctx.currentTime;
    if (type === 'down') {
      osc.frequency.setValueAtTime(660, t);
      osc.frequency.exponentialRampToValueAtTime(220, t + 0.45);
    } else {
      osc.frequency.setValueAtTime(330, t);
      osc.frequency.exponentialRampToValueAtTime(880, t + 0.45);
    }
    gain.gain.setValueAtTime(0.25, t);
    gain.gain.exponentialRampToValueAtTime(0.001, t + 0.5);
    osc.start(t);
    osc.stop(t + 0.5);
    setTimeout(() => ctx.close().catch(() => {}), 600);
  } catch {}
}

// ---------------------------------------------------------------------------
// Reducer — pure state transitions, no side effects
// ---------------------------------------------------------------------------

function pingReducer(tests, action) {
  switch (action.type) {
    case 'ADD':
      return [action.test, ...tests];

    case 'REMOVE':
      return tests.filter((t) => t.id !== action.id);

    case 'SET_PHASE':
      return tests.map((t) => (t.id === action.id ? { ...t, phase: action.phase } : t));

    case 'TOGGLE_VIEW':
      return tests.map((t) =>
        t.id === action.id ? { ...t, viewMode: t.viewMode === 'graph' ? 'cli' : 'graph' } : t
      );

    case 'SET_ALIAS':
      return tests.map((t) => (t.id === action.id ? { ...t, alias: action.alias } : t));

    case 'SET_INTERVAL':
      return tests.map((t) => (t.id === action.id ? { ...t, interval: action.interval } : t));

    case 'REORDER': {
      const { activeId, overId } = action;
      const oldIdx = tests.findIndex((t) => t.id === activeId);
      const newIdx = tests.findIndex((t) => t.id === overId);
      if (oldIdx === -1 || newIdx === -1) return tests;
      return arrayMove(tests, oldIdx, newIdx);
    }

    case 'APPLY_SAMPLE': {
      const { id, result } = action;
      return tests.map((test) => {
        if (test.id !== id) return test;
        const isSuccess = result.ok && result.latency_ms != null;
        const failureStreak = isSuccess ? 0 : test.failureStreak + 1;
        const becameDown =
          !isSuccess && failureStreak >= DOWN_THRESHOLD && test.reachable !== false;
        const becameUp = isSuccess && test.reachable === false;
        const reachable = isSuccess ? true : becameDown ? false : test.reachable;
        const nextPoints = isSuccess
          ? [...test.points, { ts: Date.now(), latency: result.latency_ms }].slice(-MAX_POINTS)
          : test.points;
        const nextRecentResults = [...(test.recentResults || []), isSuccess].slice(-HEALTH_WINDOW);
        const nowTs = Date.now();
        const nextEvents = [...test.events];
        if (becameUp) nextEvents.push({ id: `${nowTs}-up`, ts: nowTs, kind: 'up' });
        if (becameDown) nextEvents.push({ id: `${nowTs}-down`, ts: nowTs, kind: 'down' });
        // A reply TTL that shifts means the packet took a different-length path.
        // Only compare successful replies — a timeout has no TTL to speak of.
        const ttl = isSuccess && result.ttl != null ? result.ttl : null;
        const ttlChanged = ttl != null && test.lastTtl != null && ttl !== test.lastTtl;
        return {
          ...test,
          reachable,
          failureStreak,
          points: nextPoints,
          recentResults: nextRecentResults,
          events: nextEvents.slice(-20),
          sent: test.sent + 1,
          received: test.received + (isSuccess ? 1 : 0),
          lastLatency: isSuccess ? result.latency_ms : null,
          lastTtl: ttl ?? test.lastTtl,
          prevTtl: ttlChanged ? test.lastTtl : test.prevTtl,
          ttlChanges: test.ttlChanges + (ttlChanged ? 1 : 0),
          lastOutput: result.output || 'No output.',
        };
      });
    }

    default:
      return tests;
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function PingTab({ addNotification, settings, saveSettings }) {
  const [tests, dispatch] = useReducer(pingReducer, []);
  const [hostInput, setHostInput] = useState('');
  const [pingEntryMode, setPingEntryMode] = useState('single');
  const [bulkHostsInput, setBulkHostsInput] = useState('');
  const [packetSize, setPacketSize] = useState(56);
  const [dontFragment, setDontFragment] = useState(false);
  const [status, setStatus] = useState('Ready.');
  const [showFavorites, setShowFavorites] = useState(false);
  const [netStatus, setNetStatus] = useState('checking'); // 'checking' | 'online' | 'offline'

  const audioEnabled = settings?.audio_alerts ?? true;
  const favorites = settings?.ping_favorites ?? [];

  const timersRef = useRef(new Map());
  const inFlightRef = useRef(new Set());
  const testsRef = useRef(tests);
  const packetSizeRef = useRef(packetSize);
  const dontFragmentRef = useRef(dontFragment);
  const audioEnabledRef = useRef(audioEnabled);

  useEffect(() => { testsRef.current = tests; }, [tests]);
  useEffect(() => { packetSizeRef.current = packetSize; }, [packetSize]);
  useEffect(() => { dontFragmentRef.current = dontFragment; }, [dontFragment]);
  useEffect(() => { audioEnabledRef.current = audioEnabled; }, [audioEnabled]);

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

  // Quick reachability check against 8.8.8.8, used to show whether the app
  // has an internet path at all — independent of any user-configured targets.
  useEffect(() => {
    let cancelled = false;
    const checkConnectivity = async () => {
      try {
        const result = await invoke('ping_sample', { host: '8.8.8.8' });
        if (!cancelled) setNetStatus(result.ok ? 'online' : 'offline');
      } catch {
        if (!cancelled) setNetStatus('offline');
      }
    };
    checkConnectivity();
    const interval = setInterval(checkConnectivity, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } })
  );

  const handleDragEnd = ({ active, over }) => {
    if (over && active.id !== over.id) {
      dispatch({ type: 'REORDER', activeId: active.id, overId: over.id });
    }
  };

  const pushNotification = useCallback((host, text) => {
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      new Notification(`Ping: ${host}`, { body: text });
    }
  }, []);

  const stopTimer = useCallback((id) => {
    const timer = timersRef.current.get(id);
    if (timer) {
      clearInterval(timer);
      timersRef.current.delete(id);
    }
  }, []);

  const samplePing = useCallback(async (id) => {
    if (inFlightRef.current.has(id)) return;
    const target = testsRef.current.find((t) => t.id === id);
    if (!target || target.phase !== 'running') return;

    inFlightRef.current.add(id);
    try {
      const result = await invoke('ping_sample', {
        host: target.host,
        packetSize: packetSizeRef.current,
        dontFragment: dontFragmentRef.current,
      });

      const freshTarget = testsRef.current.find((t) => t.id === id) ?? target;
      const isSuccess = result.ok && result.latency_ms != null;
      const newStreak = isSuccess ? 0 : freshTarget.failureStreak + 1;
      let notification = null;

      if (isSuccess && freshTarget.reachable === false) {
        notification = { type: 'up', text: 'Host recovered and is responding again.' };
      } else if (!isSuccess && newStreak >= DOWN_THRESHOLD && freshTarget.reachable !== false) {
        notification = {
          type: 'down',
          text: `Host is down after ${newStreak} consecutive failed pings.`,
        };
      }

      dispatch({ type: 'APPLY_SAMPLE', id, result });

      if (notification) {
        const label = freshTarget.alias || freshTarget.host;
        pushNotification(label, notification.text);
        addNotification?.(notification.type, `${label}: ${notification.text}`);
        if (audioEnabledRef.current) playAlert(notification.type);
      }
    } catch (error) {
      dispatch({
        type: 'APPLY_SAMPLE',
        id,
        result: {
          ok: false,
          latency_ms: null,
          output: String(error?.message || error || 'Ping request failed'),
        },
      });
    } finally {
      inFlightRef.current.delete(id);
    }
  }, [addNotification, pushNotification]);

  const startTest = useCallback((id) => {
    const target = testsRef.current.find((t) => t.id === id);
    const running = testsRef.current.filter((t) => t.phase === 'running').length;
    if (target && target.phase !== 'running' && running >= MAX_ACTIVE_SESSIONS) {
      setStatus(`Cannot start more than ${MAX_ACTIVE_SESSIONS} active sessions.`);
      return;
    }
    stopTimer(id);
    dispatch({ type: 'SET_PHASE', id, phase: 'running' });
    samplePing(id);
    const interval = target?.interval ?? 1000;
    const timer = setInterval(() => samplePing(id), interval);
    timersRef.current.set(id, timer);
  }, [stopTimer, samplePing]);

  const pauseTest = useCallback((id) => {
    stopTimer(id);
    dispatch({ type: 'SET_PHASE', id, phase: 'paused' });
  }, [stopTimer]);

  const stopTest = useCallback((id) => {
    stopTimer(id);
    dispatch({ type: 'SET_PHASE', id, phase: 'stopped' });
  }, [stopTimer]);

  const removeTest = useCallback((id) => {
    stopTimer(id);
    inFlightRef.current.delete(id);
    dispatch({ type: 'REMOVE', id });
  }, [stopTimer]);

  const setTestAlias = useCallback((id, alias) => {
    dispatch({ type: 'SET_ALIAS', id, alias });
  }, []);

  const setTestInterval = useCallback((id, intervalMs) => {
    dispatch({ type: 'SET_INTERVAL', id, interval: intervalMs });
    // testsRef only syncs to the new `tests` state via an effect after the
    // next render/commit. Patch it synchronously too so a startTest() call
    // for this id in the same tick (e.g. change interval while paused, then
    // immediately click Resume) can't read the stale pre-change interval.
    testsRef.current = testsRef.current.map((t) =>
      t.id === id ? { ...t, interval: intervalMs } : t
    );
    const target = testsRef.current.find((t) => t.id === id);
    if (target?.phase === 'running') {
      stopTimer(id);
      const timer = setInterval(() => samplePing(id), intervalMs);
      timersRef.current.set(id, timer);
    }
  }, [stopTimer, samplePing]);

  const toggleTestView = useCallback((id) => {
    dispatch({ type: 'TOGGLE_VIEW', id });
  }, []);

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
    dispatch({ type: 'ADD', test });
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
    const slots = Math.max(
      MAX_ACTIVE_SESSIONS - testsRef.current.filter((t) => t.phase === 'running').length,
      0
    );
    const allowed = hosts.filter((h) => !existing.has(h.toLowerCase())).slice(0, slots);
    if (allowed.length === 0) {
      setStatus('No bulk targets added (limit reached or duplicates).');
      return;
    }
    const newTests = allowed.map((host) => createTest(host));
    for (const test of newTests) dispatch({ type: 'ADD', test });
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

  const pauseAll = () => {
    testsRef.current.forEach((t) => pauseTest(t.id));
    setStatus('All tests paused.');
  };

  const stopAll = () => {
    testsRef.current.forEach((t) => stopTest(t.id));
    setStatus('All tests stopped.');
  };

  const exportSession = () => {
    const rows = tests.map((t) => {
      const m = getTestMetrics(t);
      const loss = t.sent > 0 ? ((t.sent - t.received) / t.sent * 100).toFixed(2) : '0.00';
      const healthLabel = formatHealthReason(getHealthReason(t, m));
      return [
        t.alias || t.host,
        t.host,
        m.avg?.toFixed(1) ?? '--',
        m.max?.toFixed(1) ?? '--',
        loss,
        healthLabel,
        t.lastTtl ?? '--',
        t.ttlChanges ?? 0,
      ].join(',');
    });
    const csv = [
      'Alias,Host,Avg RTT (ms),Max RTT (ms),Loss %,Status,Reply TTL,TTL Changes',
      ...rows,
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netpulse-session-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const saveFavoriteGroup = (name) => {
    const hosts = testsRef.current.map((t) => t.host);
    saveSettings?.({ ping_favorites: [...favorites, { name, hosts }] });
  };

  const loadFavoriteGroup = (hosts) => {
    const existing = new Set(testsRef.current.map((t) => t.host.toLowerCase()));
    const toAdd = hosts.filter((h) => !existing.has(h.toLowerCase()));
    const newTests = toAdd.map((host) => createTest(host));
    for (const test of newTests) dispatch({ type: 'ADD', test });
    setTimeout(() => newTests.forEach((t) => startTest(t.id)), 0);
    setStatus(
      newTests.length > 0
        ? `Loaded ${newTests.length} host(s) from group.`
        : 'All hosts from this group are already active.'
    );
  };

  const deleteFavoriteGroup = (idx) => {
    saveSettings?.({ ping_favorites: favorites.filter((_, i) => i !== idx) });
  };

  // KPI computations — memoized so a sample landing on one monitor doesn't
  // re-scan every point of every monitor on every render.
  const { activeCount, globalAvgRtt, globalLoss } = useMemo(() => {
    const active = tests.filter((t) => t.phase === 'running').length;
    const allRtts = tests.flatMap((t) => t.points.map((p) => p.latency));
    const avgRtt =
      allRtts.length > 0
        ? (allRtts.reduce((a, b) => a + b, 0) / allRtts.length).toFixed(1)
        : null;
    const activeSent = tests.filter((t) => t.sent > 0);
    const loss =
      activeSent.length > 0
        ? (
            activeSent.reduce((acc, t) => acc + ((t.sent - t.received) / t.sent * 100), 0) /
            activeSent.length
          ).toFixed(2)
        : null;
    return { activeCount: active, globalAvgRtt: avgRtt, globalLoss: loss };
  }, [tests]);

  return (
    <section className="ping-dashboard">

      {/* Page Header */}
      <div className="page-header">
        <div className="page-title-block">
          <span className={`page-tag page-tag--${netStatus}`}>
            <span className="page-tag-dot" />
            {netStatus === 'online' && 'ALL SYSTEMS READY'}
            {netStatus === 'offline' && 'NO INTERNET CONNECTION'}
            {netStatus === 'checking' && 'CHECKING CONNECTIVITY'}
          </span>
          <h1>Multi-Target Ping</h1>
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
              Bulk mode: paste targets here, then click Start All.
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
          <button className="secondary" onClick={exportSession} disabled={tests.length === 0}>Export CSV</button>
          <button
            className={`secondary${showFavorites ? ' btn-active' : ''}`}
            onClick={() => setShowFavorites((v) => !v)}
          >
            Groups{favorites.length > 0 ? ` (${favorites.length})` : ''}
          </button>
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
            onChange={(e) => setPacketSize(parseIntOrDefault(e.target.value, 56, 1, 65000))}
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

      {/* Favorites Panel */}
      {showFavorites && (
        <FavoritesPanel
          favorites={favorites}
          currentHosts={tests.map((t) => t.host)}
          onLoad={loadFavoriteGroup}
          onSave={saveFavoriteGroup}
          onDelete={deleteFavoriteGroup}
          onClose={() => setShowFavorites(false)}
        />
      )}

      {/* Monitor Grid */}
      <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
        <SortableContext items={tests.map((t) => t.id)} strategy={rectSortingStrategy}>
          <section className="tests-grid ping-grid">
            {tests.length === 0 && (
              <p className="empty" style={{ gridColumn: '1 / -1' }}>
                No active monitors. Add a target to begin.
              </p>
            )}
            {tests.map((test) => (
              <PingCard
                key={test.id}
                test={test}
                onStart={startTest}
                onPause={pauseTest}
                onStop={stopTest}
                onRemove={removeTest}
                onToggleView={toggleTestView}
                onSetAlias={setTestAlias}
                onSetInterval={setTestInterval}
              />
            ))}
          </section>
        </SortableContext>
      </DndContext>

      {status !== 'Ready.' && <div className="status-toast">{status}</div>}
    </section>
  );
}
