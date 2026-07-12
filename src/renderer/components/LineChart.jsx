import React, { useMemo } from 'react';
import {
  LineChart as ReLineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine
} from 'recharts';

function LineChart({ points, health, liveLabel, events }) {
  const data = useMemo(
    () => points.map((p, i) => ({ index: i, latency: p.latency, ts: p.ts })),
    [points]
  );

  const color =
    health === 'down' ? 'var(--color-danger)' : health === 'degraded' ? 'var(--color-warning)' : 'var(--color-success)';

  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;
    return (
      <div
        style={{
          background: 'var(--color-bg-elevated)',
          border: '1px solid var(--color-border)',
          padding: '6px 10px',
          borderRadius: 4,
          fontFamily: 'monospace',
          fontSize: 12
        }}
      >
        <span style={{ color }}>{payload[0].value?.toFixed(1)}ms</span>
      </div>
    );
  };

  if (data.length === 0) {
    return (
      <div
        style={{
          height: 100,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontFamily: 'monospace',
          fontSize: '0.75rem',
          color: 'var(--color-text-muted)'
        }}
      >
        Awaiting data...
      </div>
    );
  }

  return (
    <div style={{ height: 100, marginBottom: 8 }}>
      <ResponsiveContainer width="100%" height="100%">
        <ReLineChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -32 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
          <XAxis dataKey="index" hide />
          <YAxis
            domain={['auto', 'auto']}
            tick={{ fontSize: 10, fontFamily: 'monospace', fill: 'var(--color-text-muted)' }}
          />
          <Tooltip content={<CustomTooltip />} />
          {events?.map(ev => (
            <ReferenceLine
              key={ev.id}
              x={data.findIndex(d => d.ts >= ev.ts)}
              stroke={ev.kind === 'up' ? 'var(--color-success)' : 'var(--color-danger)'}
              strokeDasharray="3 3"
            />
          ))}
          <Line
            type="monotone"
            dataKey="latency"
            stroke={color}
            strokeWidth={1.5}
            dot={false}
            isAnimationActive={false}
          />
        </ReLineChart>
      </ResponsiveContainer>
    </div>
  );
}

export default React.memo(LineChart);
