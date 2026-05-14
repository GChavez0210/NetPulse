import React, { useState, useCallback, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import TopNav from './components/TopNav';
import NotificationsPanel from './components/NotificationsPanel';
import PingTab from './features/ping/PingTab';
import TraceTab from './features/trace/TraceTab';
import FloodTestTab from './features/flood/FloodTestTab';
import DiagnosticsTab from './features/diagnostics/DiagnosticsTab';
import ReconTab from './features/recon/ReconTab';

function App() {
  const [activeTab, setActiveTab] = useState('ping');
  const [notifications, setNotifications] = useState([]);
  const [showNotifications, setShowNotifications] = useState(false);
  const [settings, setSettings] = useState({});

  // Load persisted settings on mount
  useEffect(() => {
    invoke('settings_read')
      .then((data) => {
        if (data && typeof data === 'object') setSettings(data);
      })
      .catch(() => {});
  }, []);

  // Apply always-on-top from loaded settings
  useEffect(() => {
    if (settings.always_on_top != null) {
      getCurrentWindow().setAlwaysOnTop(settings.always_on_top).catch(() => {});
    }
  }, [settings.always_on_top]);

  const saveSettings = useCallback((updates) => {
    setSettings((prev) => {
      const next = { ...prev, ...updates };
      invoke('settings_write', { data: next }).catch(() => {});
      return next;
    });
  }, []);

  const alwaysOnTop = settings.always_on_top ?? false;
  const audioEnabled = settings.audio_alerts ?? true;

  const toggleAlwaysOnTop = useCallback(() => {
    const next = !alwaysOnTop;
    getCurrentWindow().setAlwaysOnTop(next).catch(() => {});
    saveSettings({ always_on_top: next });
  }, [alwaysOnTop, saveSettings]);

  const toggleAudio = useCallback(() => {
    saveSettings({ audio_alerts: !audioEnabled });
  }, [audioEnabled, saveSettings]);

  const addNotification = useCallback((type, text) => {
    setNotifications((prev) =>
      [
        { id: `${Date.now()}-${Math.random().toString(36).slice(2)}`, type, text, ts: Date.now() },
        ...prev,
      ].slice(0, 100)
    );
  }, []);

  const clearNotifications = useCallback(() => setNotifications([]), []);

  return (
    <div className="app-shell">
      <TopNav
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        notificationCount={notifications.length}
        onToggleNotifications={() => setShowNotifications((v) => !v)}
        alwaysOnTop={alwaysOnTop}
        onToggleAlwaysOnTop={toggleAlwaysOnTop}
        audioEnabled={audioEnabled}
        onToggleAudio={toggleAudio}
      />
      <main className="app-main">
        <div className="app-container">
          {/* All tabs stay mounted to preserve state; inactive ones are hidden via CSS */}
          <div className={activeTab !== 'ping' ? 'tab-hidden' : undefined}>
            <PingTab
              addNotification={addNotification}
              settings={settings}
              saveSettings={saveSettings}
            />
          </div>
          <div className={activeTab !== 'trace' ? 'tab-hidden' : undefined}>
            <TraceTab addNotification={addNotification} />
          </div>
          <div className={activeTab !== 'packetloss' ? 'tab-hidden' : undefined}>
            <FloodTestTab addNotification={addNotification} />
          </div>
          <div className={activeTab !== 'diagnostics' ? 'tab-hidden' : undefined}>
            <DiagnosticsTab />
          </div>
          <div className={activeTab !== 'recon' ? 'tab-hidden' : undefined}>
            <ReconTab />
          </div>

          <footer className="attribution-footer">
            NetPulse by Gabriel Chavez &bull; Developed in Mexico with love
          </footer>
        </div>
      </main>

      {showNotifications && (
        <NotificationsPanel
          notifications={notifications}
          onClose={() => setShowNotifications(false)}
          onClear={clearNotifications}
        />
      )}
    </div>
  );
}

export default App;
