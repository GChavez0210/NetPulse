import React, { useState, useRef, useEffect } from 'react';
import { useSortable } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import LineChart from '../../components/LineChart';
import {
  HEALTH,
  HEALTH_REASON,
  getHealth,
  getHealthReason,
  getTestMetrics,
} from '../../utils/networkUtils';

const INTERVAL_OPTIONS = [
  { value: 500, label: '0.5s' },
  { value: 1000, label: '1s' },
  { value: 2000, label: '2s' },
  { value: 5000, label: '5s' },
  { value: 10000, label: '10s' },
];

function latencyColor(ms) {
  if (ms == null) return undefined;
  if (ms <= 50) return 'var(--color-success)';
  if (ms <= 150) return 'var(--color-warning)';
  return 'var(--color-danger)';
}

// LOSS and JITTER share the degraded (amber) treatment because they share a
// severity — only the wording differs, so the pill matches the status light.
function healthPill(health, reason) {
  if (health === HEALTH.DOWN) return { label: 'TIMEOUT', cls: 'pill-timeout' };
  if (reason === HEALTH_REASON.LOSS) return { label: 'LOSS', cls: 'pill-loss' };
  if (reason === HEALTH_REASON.JITTER) return { label: 'JITTER', cls: 'pill-jitter' };
  return { label: 'STABLE', cls: 'pill-stable' };
}

// Senders start at a round TTL — 64 (Linux/BSD/macOS), 128 (Windows), or 255
// (network gear). The next one up from what we saw is the likely origin, so
// the difference approximates the hop count.
const INITIAL_TTLS = [64, 128, 255];

function guessHopCount(ttl) {
  if (ttl == null) return null;
  const initial = INITIAL_TTLS.find((v) => ttl <= v);
  if (initial == null) return null;
  const hops = initial - ttl;
  return hops >= 0 && hops < 64 ? hops : null;
}

function PingCard({
  test,
  onStart,
  onPause,
  onStop,
  onRemove,
  onToggleView,
  onSetAlias,
  onSetInterval,
}) {
  const [editingAlias, setEditingAlias] = useState(false);
  const [aliasInput, setAliasInput] = useState(test.alias || '');
  const aliasInputRef = useRef(null);

  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: test.id,
  });

  const dragStyle = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.45 : 1,
    position: 'relative',
    zIndex: isDragging ? 999 : undefined,
  };

  const uptime = test.sent > 0 ? ((test.received / test.sent) * 100).toFixed(1) : '0.0';
  const m = getTestMetrics(test);
  const reason = getHealthReason(test, m);
  const health = getHealth(test, m);
  const { label: pillLabel, cls: pillCls } = healthPill(health, reason);
  const displayName = test.alias || test.host;

  const lossPct = test.sent > 0 ? ((test.sent - test.received) / test.sent) * 100 : 0;
  const pillTitle =
    reason === HEALTH_REASON.UNREACHABLE
      ? 'No replies — target is unreachable'
      : reason === HEALTH_REASON.LOSS
      ? `${lossPct.toFixed(1)}% of pings lost (${test.sent - test.received} of ${test.sent})`
      : reason === HEALTH_REASON.JITTER
      ? `Latency varies by ±${m.stddev.toFixed(1)} ms around a ${m.avg.toFixed(0)} ms average`
      : 'No loss, latency steady';

  const hops = guessHopCount(test.lastTtl);
  const ttlTitle =
    test.lastTtl == null
      ? 'Reply TTL — no reply yet'
      : [
          `Reply TTL ${test.lastTtl}`,
          hops != null ? `≈ ${hops} hops away` : null,
          test.ttlChanges > 0
            ? `TTL changed ${test.ttlChanges}× (was ${test.prevTtl}) — the path length shifted, which can mean route flapping or an anycast change`
            : null,
        ]
          .filter(Boolean)
          .join(' · ');

  const hostColor =
    health === 'normal'
      ? 'var(--color-success)'
      : health === 'degraded'
      ? 'var(--color-warning)'
      : health === 'down'
      ? 'var(--color-danger)'
      : 'var(--color-text-primary)';

  useEffect(() => {
    if (editingAlias && aliasInputRef.current) {
      aliasInputRef.current.focus();
      aliasInputRef.current.select();
    }
  }, [editingAlias]);

  const commitAlias = () => {
    onSetAlias(test.id, aliasInput.trim());
    setEditingAlias(false);
  };

  const cancelAlias = () => {
    setAliasInput(test.alias || '');
    setEditingAlias(false);
  };

  return (
    <article ref={setNodeRef} style={dragStyle} className="test-card ping-card">
      <div className="test-head">
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="target-title">
            <button
              className="drag-handle"
              {...attributes}
              {...listeners}
              title="Drag to reorder"
              tabIndex={-1}
            >
              ⠿
            </button>
            <span className={`status-light ${health}`} />
            {editingAlias ? (
              <input
                ref={aliasInputRef}
                className="alias-input"
                value={aliasInput}
                onChange={(e) => setAliasInput(e.target.value)}
                onBlur={commitAlias}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') commitAlias();
                  if (e.key === 'Escape') cancelAlias();
                }}
                placeholder={test.host}
                maxLength={40}
              />
            ) : (
              <h3
                style={{ color: hostColor }}
                onDoubleClick={() => {
                  setAliasInput(test.alias || '');
                  setEditingAlias(true);
                }}
                title={test.alias ? test.host : 'Double-click to set alias'}
              >
                {displayName}
              </h3>
            )}
            {!editingAlias && (
              <button
                className="alias-edit-btn"
                title={test.alias ? `Alias: "${test.alias}" — click to edit` : 'Set display alias'}
                onClick={() => {
                  setAliasInput(test.alias || '');
                  setEditingAlias(true);
                }}
              >
                ✎
              </button>
            )}
          </div>
          <p className="target-sub">
            {test.alias && (
              <span style={{ marginRight: 6, opacity: 0.55 }}>{test.host} •</span>
            )}
            {test.phase.toUpperCase()} • UPTIME {uptime}%
          </p>
        </div>
        <span className={`status-pill ${pillCls}`} title={pillTitle}>{pillLabel}</span>
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
        <article className="metric-box" title={ttlTitle}>
          <span>TTL{test.ttlChanges > 0 ? ' ⚠' : ''}</span>
          <strong style={{ color: test.ttlChanges > 0 ? 'var(--color-warning)' : undefined }}>
            {test.lastTtl != null ? test.lastTtl : '--'}
            {hops != null && <em className="metric-sub">{hops}h</em>}
          </strong>
        </article>
      </div>

      <div className="card-actions">
        <select
          className="interval-select"
          value={test.interval ?? 1000}
          onChange={(e) => onSetInterval(test.id, Number(e.target.value))}
          title="Ping interval"
        >
          {INTERVAL_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <button className="secondary" onClick={() => onToggleView(test.id)}>
          {test.viewMode === 'graph' ? 'CLI' : 'Graph'}
        </button>
        <button onClick={() => onStart(test.id)} disabled={test.phase === 'running'}>
          Resume
        </button>
        <button
          className="secondary"
          onClick={() => onPause(test.id)}
          disabled={test.phase !== 'running'}
        >
          Pause
        </button>
        <button
          className="danger"
          onClick={() => onStop(test.id)}
          disabled={test.phase === 'stopped'}
        >
          Stop
        </button>
        <button className="danger" onClick={() => onRemove(test.id)}>
          Remove
        </button>
      </div>
    </article>
  );
}

// Memoized so a sample landing on one monitor only re-renders that card,
// not every card in the grid — requires callers to pass stable callback refs.
export default React.memo(PingCard);
