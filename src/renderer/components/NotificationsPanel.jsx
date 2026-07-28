import React from 'react';

const TYPE_META = {
  up:             { label: 'UP',    cls: 'notif-type-up' },
  down:           { label: 'DOWN',  cls: 'notif-type-down' },
  trace_complete: { label: 'TRACE', cls: 'notif-type-trace' },
  flood_complete: { label: 'FLOOD', cls: 'notif-type-flood' },
};

function formatTs(ts) {
  return new Date(ts).toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

export default function NotificationsPanel({ notifications, onClose, onClear, onDismiss }) {
  return (
    <div className="notif-overlay" onClick={onClose}>
      <aside className="notif-panel" onClick={(e) => e.stopPropagation()}>
        <div className="notif-panel-header">
          <h2>Notifications</h2>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            {notifications.length > 0 && (
              <button className="secondary notif-clear-btn" onClick={onClear}>
                Clear All
              </button>
            )}
            <button className="nav-icon-btn" onClick={onClose} title="Close">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 6L6 18M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {notifications.length === 0 ? (
          <div className="notif-empty">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.3, marginBottom: 10 }}>
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
              <path d="M13.73 21a2 2 0 0 1-3.46 0" />
            </svg>
            <p>No notifications yet.</p>
            <p style={{ fontSize: '0.75rem', marginTop: 4 }}>IP status changes, traceroutes, and flood tests will appear here.</p>
          </div>
        ) : (
          <ul className="notif-list">
            {notifications.map((n) => {
              const meta = TYPE_META[n.type] || { label: 'INFO', cls: 'notif-type-info' };
              return (
                <li key={n.id} className="notif-item">
                  <span className={`notif-type-badge ${meta.cls}`}>{meta.label}</span>
                  <div className="notif-body">
                    <span className="notif-text">{n.text}</span>
                    <span className="notif-ts">{formatTs(n.ts)}</span>
                  </div>
                  <button
                    type="button"
                    className="notif-dismiss-btn"
                    onClick={() => onDismiss?.(n.id)}
                    title="Dismiss"
                    aria-label="Dismiss notification"
                  >
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M18 6L6 18M6 6l12 12" />
                    </svg>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </aside>
    </div>
  );
}
