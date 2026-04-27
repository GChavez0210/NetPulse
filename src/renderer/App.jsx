import React, { useState, useCallback } from 'react';
import TopNav from './components/TopNav';
import NotificationsPanel from './components/NotificationsPanel';
import PingTab from './features/ping/PingTab';
import TraceTab from './features/trace/TraceTab';
import FloodTestTab from './features/flood/FloodTestTab';
import DiagnosticsTab from './features/diagnostics/DiagnosticsTab';
import WhoisTab from './features/whois/WhoisTab';

function App() {
  const [activeTab, setActiveTab] = useState('ping');
  const [notifications, setNotifications] = useState([]);
  const [showNotifications, setShowNotifications] = useState(false);

  const addNotification = useCallback((type, text) => {
    setNotifications((prev) => [
      { id: `${Date.now()}-${Math.random().toString(36).slice(2)}`, type, text, ts: Date.now() },
      ...prev,
    ].slice(0, 100));
  }, []);

  const clearNotifications = useCallback(() => setNotifications([]), []);

  return (
    <div className="app-shell">
      <TopNav
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        notificationCount={notifications.length}
        onToggleNotifications={() => setShowNotifications((v) => !v)}
      />
      <main className="app-main">
        <div className="app-container">
          {/* All tabs stay mounted to preserve state; inactive ones are hidden via CSS */}
          <div className={activeTab !== 'ping' ? 'tab-hidden' : undefined}>
            <PingTab addNotification={addNotification} />
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
          <div className={activeTab !== 'whois' ? 'tab-hidden' : undefined}>
            <WhoisTab />
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
