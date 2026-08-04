import React from 'react';

const TABS = [
  { id: 'ping', label: 'Multi-Target Ping' },
  { id: 'trace', label: 'Topology' },
  { id: 'packetloss', label: 'Flood Test' },
  { id: 'diagnostics', label: 'Diagnostics' },
  { id: 'recon', label: 'Recon' },
  { id: 'console', label: 'Console' },
];

export default function TopNav({
  activeTab,
  setActiveTab,
  notificationCount,
  onToggleNotifications,
  alwaysOnTop,
  onToggleAlwaysOnTop,
  audioEnabled,
  onToggleAudio,
}) {
  return (
    <header className="top-nav">
      <div className="nav-brand">
        <span className="brand-text">
          NET<span className="brand-accent">PULSE</span>
        </span>
      </div>

      <nav className="nav-tabs">
        {TABS.map((tab) => (
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
        {/* Audio alerts toggle */}
        <button
          className={`nav-icon-btn${audioEnabled ? ' nav-icon-btn--active' : ''}`}
          title={audioEnabled ? 'Audio alerts: ON' : 'Audio alerts: OFF'}
          onClick={onToggleAudio}
        >
          {audioEnabled ? (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
              <path d="M19.07 4.93a10 10 0 0 1 0 14.14" />
              <path d="M15.54 8.46a5 5 0 0 1 0 7.07" />
            </svg>
          ) : (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
              <line x1="23" y1="9" x2="17" y2="15" />
              <line x1="17" y1="9" x2="23" y2="15" />
            </svg>
          )}
        </button>

        {/* Always-on-top toggle */}
        <button
          className={`nav-icon-btn${alwaysOnTop ? ' nav-icon-btn--active' : ''}`}
          title={alwaysOnTop ? 'Always on top: ON' : 'Always on top: OFF'}
          onClick={onToggleAlwaysOnTop}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="12" y1="17" x2="12" y2="22" />
            <path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z" />
          </svg>
        </button>

        {/* Notifications */}
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
