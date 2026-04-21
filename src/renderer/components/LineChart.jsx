import React from 'react';
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

export default function LineChart({ points, health, liveLabel, events }) {
  const data = points.map((p, i) => ({
    index: i,
    latency: p.latency,
    ts: p.ts
  }));

  const color =
    health === 'down' ? '#ff4444' : health === 'degraded' ? '#ffaa00' : '#00ff88';

  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;
    return (
      <div
        style={{
          background: 'rgba(12,16,28,0.95)',
          border: '1px solid rgba(255,255,255,0.08)',
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
          color: '#3a4a62'
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
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
          <XAxis dataKey="index" hide />
          <YAxis
            domain={['auto', 'auto']}
            tick={{ fontSize: 10, fontFamily: 'monospace', fill: '#3a4a62' }}
          />
          <Tooltip content={<CustomTooltip />} />
          {events?.map(ev => (
            <ReferenceLine
              key={ev.id}
              x={data.findIndex(d => d.ts >= ev.ts)}
              stroke={ev.kind === 'up' ? '#00ff88' : '#ff4444'}
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
