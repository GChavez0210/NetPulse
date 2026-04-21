import React, { useState } from 'react';
import TopNav from './components/TopNav';
import PingTab from './features/ping/PingTab';
import TraceTab from './features/trace/TraceTab';
import FloodTestTab from './features/flood/FloodTestTab';
import DiagnosticsTab from './features/diagnostics/DiagnosticsTab';
import WhoisTab from './features/whois/WhoisTab';

function App() {
  const [activeTab, setActiveTab] = useState('ping');

  return (
    <div className="app-shell">
      <TopNav activeTab={activeTab} setActiveTab={setActiveTab} />
      <main className="app-main">
        <div className="app-container">
          {activeTab === 'ping' && <PingTab />}
          {activeTab === 'trace' && <TraceTab />}
          {activeTab === 'packetloss' && <FloodTestTab />}
          {activeTab === 'diagnostics' && <DiagnosticsTab />}
          {activeTab === 'whois' && <WhoisTab />}

          <footer className="attribution-footer">
            NetPulse by Gabriel Chavez &bull; Developed in Mexico with love
          </footer>
        </div>
      </main>
    </div>
  );
}

export default App;
