import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { runOnEnter } from '../trace/TraceTab';

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

  // Subdomains
  const [subDomain, setSubDomain] = useState('');
  const [subLoading, setSubLoading] = useState(false);
  const [subResult, setSubResult] = useState(null);

  // Tech Detect
  const [techUrl, setTechUrl] = useState('');
  const [techLoading, setTechLoading] = useState(false);
  const [techResult, setTechResult] = useState(null);

  const [status, setStatus] = useState('Ready.');

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

  const handleSubdomains = async () => {
    const domain = subDomain.trim();
    if (!domain) { setStatus('Enter a domain name.'); return; }
    setSubLoading(true);
    setSubResult(null);
    setStatus(`Querying Certificate Transparency logs for ${domain}...`);
    try {
      const res = await invoke('subdomains_lookup', { domain });
      setSubResult(res);
      setStatus(res.ok ? `Found ${res.count} subdomains for ${domain}.` : `Subdomain error: ${res.error}`);
      if (res.ok) setSubDomain('');
    } catch (e) {
      setSubResult({ ok: false, error: String(e?.message || e) });
      setStatus('Subdomain enumeration failed.');
    } finally {
      setSubLoading(false);
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
              onChange={(e) => setSslPort(Number.parseInt(e.target.value || '443', 10))}
              placeholder="443"
              style={{ width: 80, flex: '0 0 80px' }}
            />
          </div>
          <button className="diag-run-btn" onClick={handleSslInspect} disabled={sslLoading}>
            {sslLoading ? 'Inspecting...' : 'Inspect Certificate'}
          </button>

          {sslResult && (
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
          )}
          {!sslResult && (
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

          {headersResult && (
            <div className="diag-result-container">
              {headersResult.ok && headersResult.status && (
                <div style={{ display: 'flex', gap: 6, marginBottom: 6, flexWrap: 'wrap' }}>
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
          )}
          {!headersResult && (
            <pre className="diag-log-pre">No result yet.</pre>
          )}
        </article>

        {/* ── Subdomain Enumeration ───────────────────────────────────────── */}
        <article className="diag-card">
          <h3>Subdomain Enumeration</h3>
          <p className="diag-card-desc">
            Certificate Transparency logs via crt.sh.
          </p>
          <div className="diag-controls">
            <input
              value={subDomain}
              onChange={(e) => setSubDomain(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleSubdomains)}
              placeholder="example.com"
            />
          </div>
          <button className="diag-run-btn" onClick={handleSubdomains} disabled={subLoading}>
            {subLoading ? 'Querying CT logs...' : 'Enumerate Subdomains'}
          </button>

          {subResult && (
            <div className="diag-result-container">
              {subResult.ok && (
                <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
                  <span className="pill-stable">{subResult.count} found</span>
                </div>
              )}
              <pre className="diag-log-pre">
                {subResult.raw_output || (subResult.error ? `Error: ${subResult.error}` : '')}
              </pre>
              {subResult.raw_output && (
                <button className="copy-sm-btn secondary" onClick={() => copyText(subResult.raw_output)}>
                  Copy
                </button>
              )}
            </div>
          )}
          {!subResult && (
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

          {techResult && (
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
          )}
          {!techResult && (
            <pre className="diag-log-pre">No result yet.</pre>
          )}
        </article>

      </div>

      {status !== 'Ready.' && <div className="status-toast">{status}</div>}
    </section>
  );
}
