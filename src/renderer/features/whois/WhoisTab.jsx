import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { runOnEnter } from '../trace/TraceTab';
import { buildWhoisPresentation } from '../../utils/networkUtils';

export default function WhoisTab() {
  const [whoisInput, setWhoisInput] = useState('');
  const [whoisData, setWhoisData] = useState(null);
  const [whoisLoading, setWhoisLoading] = useState(false);
  const [macInput, setMacInput] = useState('');
  const [macLoading, setMacLoading] = useState(false);
  const [macResult, setMacResult] = useState(null);
  const [status, setStatus] = useState('Ready.');

  const whoisPresentation = buildWhoisPresentation(whoisData, whoisInput.trim());

  const handleWhoisLookup = async () => {
    const domain = whoisInput.trim();
    if (!domain) return;
    setWhoisLoading(true);
    setWhoisData(null);
    setStatus(`Running WHOIS lookup for ${domain}...`);

    try {
      const result = await invoke('whois_lookup', { query: domain });
      if (result.ok) {
        setWhoisData({
          normalized: result.normalized,
          raw: result.raw,
          source: result.source || 'Apilayer',
          data: result.normalized
        });
        setStatus(`WHOIS lookup complete via ${result.source || 'Apilayer'}.`);
        setWhoisInput('');
      } else {
        setWhoisData(result.normalized ?? { error: result.error });
        setStatus(result.error || 'WHOIS lookup failed.');
      }
    } catch (error) {
      setWhoisData({ error: String(error?.message || error) });
      setStatus('WHOIS lookup failed.');
    } finally {
      setWhoisLoading(false);
    }
  };

  const handleCopyWhois = async () => {
    if (!whoisData) return;
    try {
      await navigator.clipboard.writeText(whoisPresentation.text);
      setStatus('WHOIS results copied.');
    } catch {
      setStatus('Could not copy WHOIS results.');
    }
  };

  const handleExportWhoisTxt = () => {
    if (!whoisData) return;
    const blob = new Blob([whoisPresentation.text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `whois-${whoisPresentation.queryDomain || 'lookup'}-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setStatus('WHOIS TXT exported.');
  };

  const handleMacLookup = async () => {
    const target = macInput.trim();
    if (!target) return;
    setMacLoading(true);
    setMacResult(null);
    setStatus('Looking up hardware database...');
    try {
      const res = await invoke('mac_lookup', { mac: target });
      setMacResult(res);
      setStatus(res.ok ? 'MAC lookup complete.' : 'MAC lookup failed.');
      if (res.ok) setMacInput('');
    } catch (e) {
      setMacResult({ ok: false, error: e.message });
      setStatus('MAC lookup runtime error.');
    } finally {
      setMacLoading(false);
    }
  };

  return (
    <section className="whois-page">
      {/* Header */}
      <div className="page-header">
        <div className="page-title-block">
          <span className="page-tag">
            <span className="page-tag-dot" />
            IDENTITY MODULE
          </span>
          <h1>Registry &amp; Hardware Identity</h1>
          <p className="page-desc">
            Multi-tier WHOIS lookups and OUI-based hardware vendor identification.
          </p>
        </div>
      </div>

      <div className="identity-grid">
        {/* WHOIS Card */}
        <section className="whois-search-card">
          <h3>WHOIS Lookup (Multi-Tier)</h3>

          <div className="whois-search-wrap" style={{ marginBottom: 12 }}>
            <span className="whois-icon" aria-hidden="true">⌕</span>
            <input
              id="whoisDomain"
              value={whoisInput}
              onChange={(e) => setWhoisInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleWhoisLookup)}
              placeholder="Enter a hostname or IP"
            />
            <button className="whois-primary" onClick={handleWhoisLookup} disabled={whoisLoading}>
              {whoisLoading ? 'Running...' : 'WHOIS Lookup'}
            </button>
          </div>

          {whoisData && (
            <div
              className="whois-result-inline"
              style={{
                background: 'var(--surface-recessed)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                padding: 12
              }}
            >
              <div className="whois-inline-actions">
                <span>Query: {whoisPresentation.queryDomain}</span>
                <div className="whois-result-actions">
                  <button className="secondary" onClick={handleCopyWhois}>Copy</button>
                  <button className="secondary" onClick={handleExportWhoisTxt}>Export</button>
                </div>
              </div>
              <pre className="diag-log-pre" style={{ margin: 0, minHeight: 'auto', fontSize: '0.8rem' }}>
                {whoisPresentation.lines && whoisPresentation.lines.length > 0 ? (
                  whoisPresentation.lines.map((line, index) => {
                    if (line.type === 'blank') return <div key={`line-${index}`}>&nbsp;</div>;
                    if (line.type === 'comment')
                      return <div key={`line-${index}`} className="whois-comment">{line.value}</div>;
                    if (line.type === 'section')
                      return <div key={`line-${index}`} className="whois-section">{line.value}</div>;
                    const isLink = /^https?:\/\//i.test(line.value);
                    return (
                      <div key={`line-${index}`}>
                        <span className="whois-label">{line.label}:</span>{' '}
                        <span className={isLink ? 'whois-link' : 'whois-value'}>{line.value}</span>
                      </div>
                    );
                  })
                ) : (
                  <div className="whois-value">{whoisPresentation.text}</div>
                )}
              </pre>
            </div>
          )}
        </section>

        {/* MAC OUI Card */}
        <section className="whois-search-card">
          <h3>MAC Address OUI Matcher</h3>

          <div className="whois-search-wrap" style={{ marginBottom: 12 }}>
            <span className="whois-icon" aria-hidden="true">⌕</span>
            <input
              id="macTarget"
              value={macInput}
              onChange={(e) => setMacInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleMacLookup)}
              placeholder="Enter MAC Address (00:1A:2B:...)"
            />
            <button className="whois-primary" onClick={handleMacLookup} disabled={macLoading}>
              {macLoading ? 'Looking up...' : 'Lookup Vendor'}
            </button>
          </div>

          {macResult && (
            <div
              style={{
                background: 'var(--surface-recessed)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                padding: 12
              }}
            >
              <pre className="diag-log-pre" style={{ margin: 0, minHeight: 'auto' }}>
                {macResult.rawOutput || JSON.stringify(macResult, null, 2)}
              </pre>
            </div>
          )}
        </section>
      </div>

      {status !== 'Ready.' && <div className="status-toast">{status}</div>}
    </section>
  );
}
