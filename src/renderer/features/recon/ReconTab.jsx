import React, { useState, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { runOnEnter } from '../trace/TraceTab';
import { buildWhoisPresentation, parseIntOrDefault } from '../../utils/networkUtils';

export default function ReconTab() {
  // SSL / TLS
  const [sslHost, setSslHost] = useState('');
  const [sslPort, setSslPort] = useState(443);
  const [sslLoading, setSslLoading] = useState(false);
  const [sslResult, setSslResult] = useState(null);

  // HTTP Headers
  const [headersUrl, setHeadersUrl] = useState('');
  const [headersLoading, setHeadersLoading] = useState(false);
  const [headersResult, setHeadersResult] = useState(null);

  // Tech Detect
  const [techUrl, setTechUrl] = useState('');
  const [techLoading, setTechLoading] = useState(false);
  const [techResult, setTechResult] = useState(null);

  // MAC OUI
  const [macInput, setMacInput] = useState('');
  const [macLoading, setMacLoading] = useState(false);
  const [macResult, setMacResult] = useState(null);

  // DMARC Inspector
  const [dmarcInput, setDmarcInput] = useState('');
  const [dmarcLoading, setDmarcLoading] = useState(false);
  const [dmarcResult, setDmarcResult] = useState(null);

  // WHOIS
  const [whoisInput, setWhoisInput] = useState('');
  const [whoisData, setWhoisData] = useState(null);
  const [whoisLoading, setWhoisLoading] = useState(false);

  const [status, setStatus] = useState('Ready.');

  const whoisPresentation = useMemo(
    () => buildWhoisPresentation(whoisData, whoisInput.trim()),
    [whoisData, whoisInput]
  );

  const copyText = async (text) => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setStatus('Copied to clipboard.');
    } catch {
      setStatus('Failed to copy.');
    }
  };

  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleSslInspect = async () => {
    const host = sslHost.trim();
    if (!host) { setStatus('Enter a hostname or IP.'); return; }
    setSslLoading(true);
    setSslResult(null);
    setStatus(`Inspecting TLS certificate for ${host}:${sslPort}...`);
    try {
      const res = await invoke('ssl_inspect', { host, port: sslPort });
      setSslResult(res);
      setStatus(res.ok ? `Certificate inspection complete for ${host}.` : `SSL error: ${res.error}`);
      if (res.ok) setSslHost('');
    } catch (e) {
      setSslResult({ ok: false, error: String(e?.message || e) });
      setStatus('SSL inspection failed.');
    } finally {
      setSslLoading(false);
    }
  };

  const handleHttpHeaders = async () => {
    const url = headersUrl.trim();
    if (!url) { setStatus('Enter a URL or hostname.'); return; }
    setHeadersLoading(true);
    setHeadersResult(null);
    setStatus(`Fetching HTTP headers for ${url}...`);
    try {
      const res = await invoke('http_headers', { url });
      setHeadersResult(res);
      setStatus(res.ok ? `Headers retrieved (${res.status} ${res.status_text}).` : `Headers error: ${res.error}`);
      if (res.ok) setHeadersUrl('');
    } catch (e) {
      setHeadersResult({ ok: false, error: String(e?.message || e) });
      setStatus('HTTP headers fetch failed.');
    } finally {
      setHeadersLoading(false);
    }
  };

  const handleTechDetect = async () => {
    const url = techUrl.trim();
    if (!url) { setStatus('Enter a URL or hostname.'); return; }
    setTechLoading(true);
    setTechResult(null);
    setStatus(`Fingerprinting technologies on ${url}...`);
    try {
      const res = await invoke('tech_detect', { url });
      setTechResult(res);
      setStatus(res.ok ? `Detected ${res.technologies?.length ?? 0} technologies.` : `Tech detect error: ${res.error}`);
      if (res.ok) setTechUrl('');
    } catch (e) {
      setTechResult({ ok: false, error: String(e?.message || e) });
      setStatus('Technology detection failed.');
    } finally {
      setTechLoading(false);
    }
  };

  const handleMacLookup = async () => {
    const target = macInput.trim();
    if (!target) { setStatus('Enter a MAC address.'); return; }
    setMacLoading(true);
    setMacResult(null);
    setStatus('Looking up hardware database...');
    try {
      const res = await invoke('mac_lookup', { mac: target });
      setMacResult(res);
      setStatus(res.ok ? 'MAC lookup complete.' : 'MAC lookup failed.');
      if (res.ok) setMacInput('');
    } catch (e) {
      const msg = String(e?.message || e);
      setMacResult({ ok: false, error: msg });
      setStatus(`MAC lookup error: ${msg}`);
    } finally {
      setMacLoading(false);
    }
  };

  const handleDmarcValidate = async () => {
    const target = dmarcInput.trim();
    if (!target) return;
    setDmarcLoading(true);
    setDmarcResult(null);
    setStatus(`Validating DMARC records for ${target}...`);
    try {
      const res = await invoke('dns_dmarc', { domain: target });
      setDmarcResult(res);
      setStatus(res.ok ? 'DMARC validation complete.' : 'DMARC validation failed.');
      if (res.ok) setDmarcInput('');
    } catch (e) {
      setDmarcResult({ ok: false, error: String(e?.message || e) });
      setStatus('DMARC validation error.');
    } finally {
      setDmarcLoading(false);
    }
  };

  const handleWhoisLookup = async () => {
    const domain = whoisInput.trim();
    if (!domain) return;
    setWhoisLoading(true);
    setWhoisData(null);
    setStatus(`Running WHOIS lookup for ${domain}...`);
    try {
      const result = await invoke('whois_lookup', { query: domain });
      if (result.ok) {
        setWhoisData({ normalized: result.normalized, raw: result.raw, source: result.source || 'Apilayer', data: result.normalized });
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

  // ── Render helpers ─────────────────────────────────────────────────────────

  const sslExpiredClass =
    sslResult?.expired === true ? 'pill-timeout' : sslResult?.expired === false ? 'pill-stable' : '';

  return (
    <section className="diagnostics-hub">
      <div className="page-header">
        <div className="page-title-block">
          <span className="page-tag">
            <span className="page-tag-dot" />
            RECON TOOLKIT
          </span>
          <h1>Reconnaissance &amp; Analysis</h1>
        </div>
      </div>

      <div className="diagnostics-grid">

        {/* ── SSL / TLS Inspector ─────────────────────────────────────────── */}
        <article className="diag-card">
          <h3>SSL / TLS Inspector</h3>
          <p className="diag-card-desc">
            Certificate chain, expiry, SANs, and TLS version.
          </p>
          <div className="diag-controls">
            <input
              value={sslHost}
              onChange={(e) => setSslHost(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleSslInspect)}
              placeholder="hostname or IP"
            />
            <input
              type="number"
              min="1"
              max="65535"
              value={sslPort}
              onChange={(e) => setSslPort(parseIntOrDefault(e.target.value, 443, 1, 65535))}
              placeholder="443"
              style={{ width: 80, flex: '0 0 80px' }}
            />
          </div>
          <button className="diag-run-btn" onClick={handleSslInspect} disabled={sslLoading}>
            {sslLoading ? 'Inspecting...' : 'Inspect Certificate'}
          </button>

          {sslResult ? (
            <div className="diag-result-container">
              {sslResult.ok && (
                <div style={{ display: 'flex', gap: 6, marginBottom: 6, flexWrap: 'wrap' }}>
                  {sslResult.tls_version && (
                    <span className="pill-stable">{sslResult.tls_version}</span>
                  )}
                  {sslResult.expired != null && (
                    <span className={sslExpiredClass}>
                      {sslResult.expired ? 'EXPIRED' : `${sslResult.days_until_expiry}d left`}
                    </span>
                  )}
                  {sslResult.chain_depth > 0 && (
                    <span className="pill-jitter">chain: {sslResult.chain_depth}</span>
                  )}
                </div>
              )}
              <pre className="diag-log-pre">
                {sslResult.raw_output || (sslResult.error ? `Error: ${sslResult.error}` : '')}
              </pre>
              {sslResult.raw_output && (
                <button className="copy-sm-btn secondary" onClick={() => copyText(sslResult.raw_output)}>
                  Copy
                </button>
              )}
            </div>
          ) : (
            <pre className="diag-log-pre">No result yet.</pre>
          )}
        </article>

        {/* ── HTTP Headers ────────────────────────────────────────────────── */}
        <article className="diag-card">
          <h3>HTTP Headers</h3>
          <p className="diag-card-desc">
            Response headers, status, and redirect chain.
          </p>
          <div className="diag-controls">
            <input
              value={headersUrl}
              onChange={(e) => setHeadersUrl(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleHttpHeaders)}
              placeholder="URL or hostname"
            />
          </div>
          <button className="diag-run-btn" onClick={handleHttpHeaders} disabled={headersLoading}>
            {headersLoading ? 'Fetching...' : 'Fetch Headers'}
          </button>

          {headersResult ? (
            <div className="diag-result-container">
              {headersResult.ok && headersResult.status && (
                <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
                  <span
                    className={
                      headersResult.status < 300
                        ? 'pill-stable'
                        : headersResult.status < 400
                        ? 'pill-jitter'
                        : 'pill-timeout'
                    }
                  >
                    {headersResult.status} {headersResult.status_text}
                  </span>
                </div>
              )}
              <pre className="diag-log-pre">
                {headersResult.raw_output || (headersResult.error ? `Error: ${headersResult.error}` : '')}
              </pre>
              {headersResult.raw_output && (
                <button className="copy-sm-btn secondary" onClick={() => copyText(headersResult.raw_output)}>
                  Copy
                </button>
              )}
            </div>
          ) : (
            <pre className="diag-log-pre">No result yet.</pre>
          )}
        </article>

        {/* ── Technology Detection ────────────────────────────────────────── */}
        <article className="diag-card">
          <h3>Tech Detect</h3>
          <p className="diag-card-desc">
            Fingerprint web technologies from headers and HTML.
          </p>
          <div className="diag-controls">
            <input
              value={techUrl}
              onChange={(e) => setTechUrl(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleTechDetect)}
              placeholder="URL or hostname"
            />
          </div>
          <button className="diag-run-btn" onClick={handleTechDetect} disabled={techLoading}>
            {techLoading ? 'Detecting...' : 'Detect Technologies'}
          </button>

          {techResult ? (
            <div className="diag-result-container">
              {techResult.ok && techResult.technologies?.length > 0 && (
                <div style={{ display: 'flex', gap: 6, marginBottom: 6, flexWrap: 'wrap' }}>
                  {techResult.technologies.slice(0, 4).map((t) => (
                    <span key={t.name} className="pill-jitter">{t.name}</span>
                  ))}
                  {techResult.technologies.length > 4 && (
                    <span className="pill-jitter">+{techResult.technologies.length - 4} more</span>
                  )}
                </div>
              )}
              <pre className="diag-log-pre">
                {techResult.raw_output || (techResult.error ? `Error: ${techResult.error}` : '')}
              </pre>
              {techResult.raw_output && (
                <button className="copy-sm-btn secondary" onClick={() => copyText(techResult.raw_output)}>
                  Copy
                </button>
              )}
            </div>
          ) : (
            <pre className="diag-log-pre">No result yet.</pre>
          )}
        </article>

        {/* ── MAC Address OUI Matcher ─────────────────────────────────────── */}
        <article className="diag-card">
          <h3>MAC Address OUI Matcher</h3>
          <p className="diag-card-desc">
            Identify hardware vendor from a MAC address.
          </p>
          <div className="diag-controls">
            <input
              value={macInput}
              onChange={(e) => setMacInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleMacLookup)}
              placeholder="00:1A:2B:3C:4D:5E"
            />
          </div>
          <button className="diag-run-btn" onClick={handleMacLookup} disabled={macLoading}>
            {macLoading ? 'Looking up...' : 'Lookup Vendor'}
          </button>

          {macResult ? (
            <pre className="diag-log-pre">
              {macResult.ok
                ? (macResult.raw_output || macResult.rawOutput)
                : `Error: ${macResult.error || 'Unknown error'}`}
            </pre>
          ) : (
            <pre className="diag-log-pre">No result yet.</pre>
          )}
        </article>

        {/* ── DMARC Inspector ─────────────────────────────────────────────── */}
        <article className="diag-card">
          <h3>DMARC Inspector</h3>
          <p className="diag-card-desc">
            Validates DMARC policy tags for a domain.
          </p>
          <div className="diag-controls">
            <input
              value={dmarcInput}
              onChange={(e) => setDmarcInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleDmarcValidate)}
              placeholder="Enter a domain"
            />
          </div>
          <button className="diag-run-btn" onClick={handleDmarcValidate} disabled={dmarcLoading}>
            {dmarcLoading ? 'Inspecting...' : 'Inspect Records'}
          </button>
          <div className="diag-result-container">
            <pre className="diag-log-pre">
              {dmarcResult
                ? dmarcResult.rawOutput || JSON.stringify(dmarcResult, null, 2)
                : 'No DMARC validation result yet.'}
            </pre>
            {dmarcResult?.rawOutput && (
              <button className="copy-sm-btn secondary" onClick={() => copyText(dmarcResult.rawOutput)}>
                Copy
              </button>
            )}
          </div>
        </article>

        {/* ── WHOIS Lookup ─────────────────────────────────────────────────── */}
        <article className="diag-card">
          <h3>WHOIS Lookup</h3>
          <p className="diag-card-desc">
            Registry ownership and RDAP details for a hostname or IP.
          </p>
          <div className="diag-controls">
            <input
              value={whoisInput}
              onChange={(e) => setWhoisInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleWhoisLookup)}
              placeholder="hostname or IP"
            />
          </div>
          <button className="diag-run-btn" onClick={handleWhoisLookup} disabled={whoisLoading}>
            {whoisLoading ? 'Running...' : 'WHOIS Lookup'}
          </button>

          {whoisData ? (
            <div className="diag-result-container">
              <div className="whois-inline-actions" style={{ marginBottom: 6 }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                  Query: {whoisPresentation.queryDomain}
                </span>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button className="copy-sm-btn secondary" onClick={handleCopyWhois}>Copy</button>
                  <button className="copy-sm-btn secondary" onClick={handleExportWhoisTxt}>Export</button>
                </div>
              </div>
              <pre className="diag-log-pre" style={{ fontSize: '0.78rem' }}>
                {whoisPresentation.lines && whoisPresentation.lines.length > 0
                  ? whoisPresentation.lines.map((line, i) => {
                      if (line.type === 'blank') return <div key={i}>&nbsp;</div>;
                      if (line.type === 'comment') return <div key={i} className="whois-comment">{line.value}</div>;
                      if (line.type === 'section') return <div key={i} className="whois-section">{line.value}</div>;
                      return (
                        <div key={i}>
                          <span className="whois-label">{line.label}:</span>{' '}
                          <span className="whois-value">{line.value}</span>
                        </div>
                      );
                    })
                  : <div className="whois-value">{whoisPresentation.text}</div>}
              </pre>
            </div>
          ) : (
            <pre className="diag-log-pre">No WHOIS result yet.</pre>
          )}
        </article>

      </div>

      {status !== 'Ready.' && <div className="status-toast">{status}</div>}
    </section>
  );
}
