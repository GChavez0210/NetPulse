import React, { useState, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { runOnEnter } from '../trace/TraceTab';
import { buildWhoisPresentation, parseIntOrDefault } from '../../utils/networkUtils';
import ClearButton from '../../components/ClearButton';

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

  // ASN / Network Lookup
  const [asnInput, setAsnInput] = useState('');
  const [asnLoading, setAsnLoading] = useState(false);
  const [asnResult, setAsnResult] = useState(null);

  // BGP Looking Glass
  const [lgInput, setLgInput] = useState('');
  const [lgLoading, setLgLoading] = useState(false);
  const [lgResult, setLgResult] = useState(null);

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

  const handleAsnLookup = async () => {
    const ip = asnInput.trim();
    if (!ip) { setStatus('Enter an IPv4 or IPv6 address.'); return; }
    setAsnLoading(true);
    setAsnResult(null);
    setStatus(`Looking up announcing ASN for ${ip}...`);
    try {
      const res = await invoke('asn_lookup', { query: ip });
      setAsnResult(res);
      setStatus(res.ok ? `ASN lookup complete: AS${res.asn}.` : (res.error || 'ASN lookup failed.'));
    } catch (e) {
      setAsnResult({ ok: false, error: String(e?.message || e) });
      setStatus('ASN lookup error.');
    } finally {
      setAsnLoading(false);
    }
  };

  const handleLookingGlass = async () => {
    const resource = lgInput.trim();
    if (!resource) { setStatus('Enter an IP address or CIDR prefix.'); return; }
    setLgLoading(true);
    setLgResult(null);
    setStatus(`Querying BGP looking glass for ${resource}...`);
    try {
      const res = await invoke('bgp_looking_glass', { resource });
      setLgResult(res);
      setStatus(res.ok ? `Looking glass complete: seen by ${res.peer_count} peer(s).` : (res.error || 'Looking glass failed.'));
    } catch (e) {
      setLgResult({ ok: false, error: String(e?.message || e) });
      setStatus('Looking glass error.');
    } finally {
      setLgLoading(false);
    }
  };

  // ── Per-tool reset ────────────────────────────────────────────────────────
  // Inputs and results otherwise stick around for the lifetime of the app, so
  // each card gets its own trash button to wipe just that tool.

  const resetWhois = () => {
    setWhoisInput('');
    setWhoisData(null);
    setStatus('WHOIS Lookup cleared.');
  };

  const resetAsn = () => {
    setAsnInput('');
    setAsnResult(null);
    setStatus('ASN Lookup cleared.');
  };

  const resetLookingGlass = () => {
    setLgInput('');
    setLgResult(null);
    setStatus('BGP Looking Glass cleared.');
  };

  const resetDmarc = () => {
    setDmarcInput('');
    setDmarcResult(null);
    setStatus('DMARC Inspector cleared.');
  };

  const resetSsl = () => {
    setSslHost('');
    setSslPort(443);
    setSslResult(null);
    setStatus('SSL / TLS Inspector cleared.');
  };

  const resetHeaders = () => {
    setHeadersUrl('');
    setHeadersResult(null);
    setStatus('HTTP Headers cleared.');
  };

  const resetTech = () => {
    setTechUrl('');
    setTechResult(null);
    setStatus('Tech Detect cleared.');
  };

  const resetMac = () => {
    setMacInput('');
    setMacResult(null);
    setStatus('MAC OUI Matcher cleared.');
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

        {/* ── WHOIS Lookup ─────────────────────────────────────────────────── */}
        <article className="diag-card">
          <div className="diag-card-head">
            <h3>WHOIS Lookup</h3>
            <ClearButton
              onClear={resetWhois}
              disabled={whoisLoading || (!whoisInput && !whoisData)}
              title="Clear WHOIS Lookup"
            />
          </div>
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
                <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
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

        {/* ── ASN / Network Lookup ─────────────────────────────────────────── */}
        <article className="diag-card">
          <div className="diag-card-head">
            <h3>ASN / Network Lookup</h3>
            <ClearButton
              onClear={resetAsn}
              disabled={asnLoading || (!asnInput && !asnResult)}
              title="Clear ASN Lookup"
            />
          </div>
          <p className="diag-card-desc">
            Who is currently announcing this IP on the internet — ASN, BGP prefix, and origin network.
          </p>
          <div className="diag-controls">
            <input
              value={asnInput}
              onChange={(e) => setAsnInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleAsnLookup)}
              placeholder="IPv4 or IPv6 address"
            />
          </div>
          <button className="diag-run-btn" onClick={handleAsnLookup} disabled={asnLoading}>
            {asnLoading ? 'Looking up...' : 'Lookup ASN'}
          </button>

          {asnResult ? (
            <div className="diag-result-container">
              {asnResult.ok && (
                <div style={{ display: 'flex', gap: 6, marginBottom: 6, flexWrap: 'wrap' }}>
                  <span className="pill-stable">AS{asnResult.asn}</span>
                  {asnResult.country_code && <span className="pill-jitter">{asnResult.country_code}</span>}
                </div>
              )}
              <pre className="diag-log-pre">
                {asnResult.raw_output || (asnResult.error ? `Error: ${asnResult.error}` : '')}
              </pre>
              {asnResult.raw_output && (
                <button className="copy-sm-btn secondary" onClick={() => copyText(asnResult.raw_output)}>
                  Copy
                </button>
              )}
            </div>
          ) : (
            <pre className="diag-log-pre">No ASN result yet.</pre>
          )}
        </article>

        {/* ── BGP Looking Glass ────────────────────────────────────────────── */}
        <article className="diag-card">
          <div className="diag-card-head">
            <h3>BGP Looking Glass</h3>
            <ClearButton
              onClear={resetLookingGlass}
              disabled={lgLoading || (!lgInput && !lgResult)}
              title="Clear BGP Looking Glass"
            />
          </div>
          <p className="diag-card-desc">
            Real-time route visibility from RIPE RIS route collectors — confirms propagation and flags conflicting origins.
          </p>
          <div className="diag-controls">
            <input
              value={lgInput}
              onChange={(e) => setLgInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleLookingGlass)}
              placeholder="IP address or CIDR prefix"
            />
          </div>
          <button className="diag-run-btn" onClick={handleLookingGlass} disabled={lgLoading}>
            {lgLoading ? 'Querying...' : 'Query Looking Glass'}
          </button>

          {lgResult ? (
            <div className="diag-result-container">
              {lgResult.ok && lgResult.peer_count > 0 && (
                <div style={{ display: 'flex', gap: 6, marginBottom: 6, flexWrap: 'wrap' }}>
                  <span className="pill-stable">{lgResult.peer_count} peers</span>
                  <span
                    className={lgResult.distinct_origins.length > 1 ? 'pill-timeout' : 'pill-jitter'}
                  >
                    {lgResult.distinct_origins.length > 1
                      ? `${lgResult.distinct_origins.length} conflicting origins`
                      : `AS${lgResult.distinct_origins[0]}`}
                  </span>
                </div>
              )}
              <pre className="diag-log-pre">
                {lgResult.raw_output || (lgResult.error ? `Error: ${lgResult.error}` : '')}
              </pre>
              {lgResult.raw_output && (
                <button className="copy-sm-btn secondary" onClick={() => copyText(lgResult.raw_output)}>
                  Copy
                </button>
              )}
            </div>
          ) : (
            <pre className="diag-log-pre">No looking glass result yet.</pre>
          )}
        </article>

        {/* ── DMARC Inspector ─────────────────────────────────────────────── */}
        <article className="diag-card">
          <div className="diag-card-head">
            <h3>DMARC Inspector</h3>
            <ClearButton
              onClear={resetDmarc}
              disabled={dmarcLoading || (!dmarcInput && !dmarcResult)}
              title="Clear DMARC Inspector"
            />
          </div>
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
                ? dmarcResult.raw_output || JSON.stringify(dmarcResult, null, 2)
                : 'No DMARC validation result yet.'}
            </pre>
            {dmarcResult?.rawOutput && (
              <button className="copy-sm-btn secondary" onClick={() => copyText(dmarcResult.raw_output)}>
                Copy
              </button>
            )}
          </div>
        </article>

        {/* ── SSL / TLS Inspector ─────────────────────────────────────────── */}
        <article className="diag-card">
          <div className="diag-card-head">
            <h3>SSL / TLS Inspector</h3>
            <ClearButton
              onClear={resetSsl}
              disabled={sslLoading || (!sslHost && sslPort === 443 && !sslResult)}
              title="Clear SSL / TLS Inspector"
            />
          </div>
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
          <div className="diag-card-head">
            <h3>HTTP Headers</h3>
            <ClearButton
              onClear={resetHeaders}
              disabled={headersLoading || (!headersUrl && !headersResult)}
              title="Clear HTTP Headers"
            />
          </div>
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
          <div className="diag-card-head">
            <h3>Tech Detect</h3>
            <ClearButton
              onClear={resetTech}
              disabled={techLoading || (!techUrl && !techResult)}
              title="Clear Tech Detect"
            />
          </div>
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
          <div className="diag-card-head">
            <h3>MAC Address OUI Matcher</h3>
            <ClearButton
              onClear={resetMac}
              disabled={macLoading || (!macInput && !macResult)}
              title="Clear MAC OUI Matcher"
            />
          </div>
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
                ? macResult.raw_output
                : `Error: ${macResult.error || 'Unknown error'}`}
            </pre>
          ) : (
            <pre className="diag-log-pre">No result yet.</pre>
          )}
        </article>

      </div>

      {status !== 'Ready.' && <div className="status-toast">{status}</div>}
    </section>
  );
}
