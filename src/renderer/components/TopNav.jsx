import React from 'react';

const TABS = [
  { id: 'ping', label: 'Multi-Target Ping' },
  { id: 'trace', label: 'Topology' },
  { id: 'packetloss', label: 'Flood Test' },
  { id: 'diagnostics', label: 'Analytics' },
  { id: 'whois', label: 'Identity' }
];

export default function TopNav({ activeTab, setActiveTab, notificationCount, onToggleNotifications }) {
  return (
    <header className="top-nav">
      <div className="nav-brand">
        <span className="brand-text">
          NET<span className="brand-accent">PULSE</span>
        </span>
      </div>

      <nav className="nav-tabs">
        {TABS.map(tab => (
          <button
            key={tab.id}
            className={`nav-tab${activeTab === tab.id ? ' active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className="nav-utilities">
        <button
          className="nav-icon-btn notif-btn"
          title="Notifications"
          onClick={onToggleNotifications}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
            <path d="M13.73 21a2 2 0 0 1-3.46 0" />
          </svg>
          {notificationCount > 0 && (
            <span className="notif-count-badge">
              {notificationCount > 99 ? '99+' : notificationCount}
            </span>
          )}
        </button>
      </div>
    </header>
  );
}
