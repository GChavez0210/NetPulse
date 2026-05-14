import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { runOnEnter } from '../trace/TraceTab';
import { buildWhoisPresentation } from '../../utils/networkUtils';

export default function DiagnosticsTab() {
  // TCP Ping
  const [tcpHostInput, setTcpHostInput] = useState('');
  const [tcpPort, setTcpPort] = useState(443);
  const [tcpResult, setTcpResult] = useState(null);

  // MTR
  const [mtrHostInput, setMtrHostInput] = useState('');
  const [mtrRounds, setMtrRounds] = useState(5);
  const [mtrLoading, setMtrLoading] = useState(false);
  const [mtrResult, setMtrResult] = useState(null);

  // DNS Toolkit
  const [dnsHostInput, setDnsHostInput] = useState('');
  const [dnsType, setDnsType] = useState('A');
  const [dnsResult, setDnsResult] = useState(null);

  // Port Scanner
  const [portScanHostInput, setPortScanHostInput] = useState('');
  const [portListInput, setPortListInput] = useState('22,80,443,3389');
  const [portScanResult, setPortScanResult] = useState(null);

  // DNS Validation
  const [dnsValInput, setDnsValInput] = useState('');
  const [dnsValLoading, setDnsValLoading] = useState(false);
  const [dnsValResult, setDnsValResult] = useState(null);

  // Multi-Resolver Health
  const [dnsHealthInput, setDnsHealthInput] = useState('');
  const [dnsHealthLoading, setDnsHealthLoading] = useState(false);
  const [dnsHealthResult, setDnsHealthResult] = useState(null);

  // DMARC Inspector
  const [dmarcInput, setDmarcInput] = useState('');
  const [dmarcLoading, setDmarcLoading] = useState(false);
  const [dmarcResult, setDmarcResult] = useState(null);

  // WHOIS
  const [whoisInput, setWhoisInput] = useState('');
  const [whoisData, setWhoisData] = useState(null);
  const [whoisLoading, setWhoisLoading] = useState(false);

  // MAC OUI
  const [macInput, setMacInput] = useState('');
  const [macLoading, setMacLoading] = useState(false);
  const [macResult, setMacResult] = useState(null);

  const [status, setStatus] = useState('Ready.');

  const whoisPresentation = buildWhoisPresentation(whoisData, whoisInput.trim());

  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleTcpPing = async () => {
    const host = tcpHostInput.trim();
    if (!host) { setStatus('Enter a hostname or IP for TCP ping.'); return; }
    setStatus(`Pinging TCP port ${tcpPort} on ${host}...`);
    setTcpResult(null);
    try {
      const result = await invoke('tcp_ping', { host, port: tcpPort, timeoutMs: 1500 });
      setTcpResult(result);
      setStatus(`TCP ping to ${host}:${tcpPort} complete.`);
      setTcpHostInput('');
    } catch (error) {
      setTcpResult({ error: String(error?.message || error) });
      setStatus('TCP ping failed.');
    }
  };

  const handleMtrRun = async () => {
    const host = mtrHostInput.trim();
    if (!host) { setStatus('Enter a hostname or IP for MTR.'); return; }
    setMtrLoading(true);
    setStatus(`Running MTR-style diagnostic to ${host} (rounds: ${mtrRounds})...`);
    setMtrResult(null);
    try {
      const result = await invoke('mtr_run', { host, rounds: mtrRounds });
      setMtrResult(result);
      setStatus(`MTR diagnostic complete to ${host}.`);
      setMtrHostInput('');
    } finally {
      setMtrLoading(false);
    }
  };

  const handleDnsQuery = async () => {
    const host = dnsHostInput.trim();
    if (!host) { setStatus('Enter a domain for DNS lookup.'); return; }
    setStatus(`Running DNS query (${dnsType}) for ${host}...`);
    setDnsResult(null);
    try {
      const result = await invoke('dns_query', { domain: host, recordType: dnsType });
      setDnsResult(result);
      setStatus(`DNS query for ${host} complete.`);
      setDnsHostInput('');
    } catch (error) {
      setDnsResult({ error: String(error?.message || error) });
      setStatus('DNS query failed.');
    }
  };

  const handlePortScan = async () => {
    const host = portScanHostInput.trim();
    if (!host) { setStatus('Enter a host for port scan.'); return; }
    const ports = portListInput
      .split(/[,\s]+/)
      .map((v) => Number.parseInt(v, 10))
      .filter((v) => Number.isFinite(v) && v > 0 && v <= 65535)
      .slice(0, 32);
    if (ports.length === 0) { setStatus('Enter at least one valid port.'); return; }
    setStatus(`Scanning ${ports.length} ports on ${host}...`);
    setPortScanResult(null);
    try {
      const result = await invoke('port_scan', { host, ports, timeoutMs: 900 });
      setPortScanResult(result);
      setStatus(`Port scan complete on ${host}.`);
      setPortScanHostInput('');
    } catch (error) {
      setPortScanResult({ error: String(error?.message || error) });
      setStatus('Port scan failed.');
    }
  };

  const handleDnsValidate = async () => {
    const target = dnsValInput.trim();
    if (!target) return;
    setDnsValLoading(true);
    setDnsValResult(null);
    setStatus(`Validating DNS configuration for ${target}...`);
    try {
      const res = await invoke('dns_validate', { domain: target });
      setDnsValResult(res);
      setStatus(res.ok ? 'DNS Validation complete.' : 'DNS Validation failed.');
      if (res.ok) setDnsValInput('');
    } catch (e) {
      setDnsValResult({ ok: false, error: e.message });
      setStatus('DNS Validation runtime error.');
    } finally {
      setDnsValLoading(false);
    }
  };

  const handleDnsHealth = async () => {
    const target = dnsHealthInput.trim();
    if (!target) return;
    setDnsHealthLoading(true);
    setDnsHealthResult(null);
    setStatus(`Running Multi-Resolver check for ${target}...`);
    try {
      const res = await invoke('dns_health', { domain: target });
      setDnsHealthResult(res);
      setStatus(res.ok ? 'Multi-Resolver Check complete.' : 'Health check failed.');
      if (res.ok) setDnsHealthInput('');
    } catch (e) {
      setDnsHealthResult({ ok: false, error: e.message });
      setStatus('Health Check runtime error.');
    } finally {
      setDnsHealthLoading(false);
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
      setDmarcResult({ ok: false, error: e.message });
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
      const msg = String(e?.message || e);
      setMacResult({ ok: false, error: msg });
      setStatus(`MAC lookup error: ${msg}`);
    } finally {
      setMacLoading(false);
    }
  };

  const handleCopyRaw = async (text) => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setStatus('Raw output copied to clipboard.');
    } catch {
      setStatus('Failed to copy text.');
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

  const formatDnsResult = (result) => {
    if (!result) return 'No DNS result yet.';
    if (result.error) return `Error: ${result.error}`;
    const lines = [];
    if (result.domain) lines.push(`Domain:      ${result.domain}`);
    if (result.record_type) lines.push(`Record Type: ${result.record_type}`);
    if (result.local?.length) {
      lines.push('');
      lines.push('Local Resolver:');
      result.local.forEach((r) => lines.push(`  ${r}`));
    }
    if (result.google?.length) {
      lines.push('');
      lines.push('Google (8.8.8.8):');
      result.google.forEach((r) => lines.push(`  ${r}`));
    }
    if (lines.length === 0) return JSON.stringify(result, null, 2);
    return lines.join('\n');
  };

  return (
    <section className="diagnostics-hub">
      <div className="page-header">
        <div className="page-title-block">
          <span className="page-tag">
            <span className="page-tag-dot" />
            DIAGNOSTICS
          </span>
          <h1>Network Diagnostics &amp; Identity</h1>
        </div>
      </div>

      <div className="diagnostics-grid">

        {/* TCP Ping */}
        <article className="diag-card">
          <h3>TCP Ping (SYN Reachability)</h3>
          <div className="diag-controls">
            <input
              value={tcpHostInput}
              onChange={(e) => setTcpHostInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleTcpPing)}
              placeholder="Enter a hostname"
            />
            <input
              type="number"
              min="1"
              max="65535"
              value={tcpPort}
              onChange={(e) => setTcpPort(Number.parseInt(e.target.value || '443', 10))}
              placeholder="443"
              style={{ width: 90, flex: '0 0 90px' }}
            />
          </div>
          <button className="diag-run-btn" onClick={handleTcpPing}>Run TCP Ping</button>
          <pre className="diag-log-pre">
            {tcpResult ? JSON.stringify(tcpResult, null, 2) : 'No TCP ping result yet.'}
          </pre>
        </article>

        {/* MTR */}
        <article className="diag-card">
          <h3>MTR-style (Ping + Trace)</h3>
          <div className="diag-controls">
            <input
              value={mtrHostInput}
              onChange={(e) => setMtrHostInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleMtrRun)}
              placeholder="Enter a hostname"
            />
            <input
              type="number"
              min="2"
              max="30"
              value={mtrRounds}
              onChange={(e) => setMtrRounds(Number.parseInt(e.target.value || '5', 10))}
              placeholder="Rounds"
              style={{ width: 90, flex: '0 0 90px' }}
            />
          </div>
          <button className="diag-run-btn" onClick={handleMtrRun} disabled={mtrLoading}>
            {mtrLoading ? 'Running...' : 'Run MTR-style'}
          </button>
          <pre className="diag-log-pre">
            {mtrResult ? JSON.stringify(mtrResult, null, 2) : 'No MTR result yet.'}
          </pre>
        </article>

        {/* DNS Toolkit */}
        <article className="diag-card">
          <h3>DNS Toolkit</h3>
          <div className="diag-controls">
            <input
              value={dnsHostInput}
              onChange={(e) => setDnsHostInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleDnsQuery)}
              placeholder="Enter a domain"
            />
            <select
              value={dnsType}
              onChange={(e) => setDnsType(e.target.value)}
              style={{ width: 90, flex: '0 0 90px' }}
            >
              <option value="A">A</option>
              <option value="AAAA">AAAA</option>
              <option value="MX">MX</option>
              <option value="NS">NS</option>
              <option value="CNAME">CNAME</option>
              <option value="PTR">PTR</option>
            </select>
          </div>
          <button className="diag-run-btn" onClick={handleDnsQuery}>Run DNS Query</button>
          <pre className="diag-log-pre">{formatDnsResult(dnsResult)}</pre>
        </article>

        {/* Port Scanner */}
        <article className="diag-card">
          <h3>Port Scanner Lite</h3>
          <div className="diag-controls">
            <input
              value={portScanHostInput}
              onChange={(e) => setPortScanHostInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handlePortScan)}
              placeholder="Enter a hostname"
            />
            <input
              value={portListInput}
              onChange={(e) => setPortListInput(e.target.value)}
              placeholder="80,443,3389"
              style={{ width: 120, flex: '0 0 120px' }}
            />
          </div>
          <button className="diag-run-btn" onClick={handlePortScan}>Run Port Scan</button>
          <pre className="diag-log-pre">
            {portScanResult ? JSON.stringify(portScanResult, null, 2) : 'No port scan result yet.'}
          </pre>
        </article>

        {/* DNS Validation */}
        <article className="diag-card">
          <h3>DNS Validation</h3>
          <div className="diag-controls">
            <input
              value={dnsValInput}
              onChange={(e) => setDnsValInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleDnsValidate)}
              placeholder="Enter a domain"
            />
          </div>
          <button className="diag-run-btn" onClick={handleDnsValidate} disabled={dnsValLoading}>
            {dnsValLoading ? 'Validating...' : 'Validate Configuration'}
          </button>
          <div className="diag-result-container">
            <pre className="diag-log-pre">
              {dnsValResult
                ? dnsValResult.rawOutput || JSON.stringify(dnsValResult, null, 2)
                : 'No DNS Validation result yet.'}
            </pre>
            {dnsValResult?.rawOutput && (
              <button className="copy-sm-btn secondary" onClick={() => handleCopyRaw(dnsValResult.rawOutput)}>
                Copy
              </button>
            )}
          </div>
        </article>

        {/* Multi-Resolver Health */}
        <article className="diag-card">
          <h3>Multi-Resolver Health (Split DNS)</h3>
          <div className="diag-controls">
            <input
              value={dnsHealthInput}
              onChange={(e) => setDnsHealthInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleDnsHealth)}
              placeholder="Enter a domain"
            />
          </div>
          <button className="diag-run-btn" onClick={handleDnsHealth} disabled={dnsHealthLoading}>
            {dnsHealthLoading ? 'Checking...' : 'Compare Resolvers'}
          </button>
          <div className="diag-result-container">
            <pre className="diag-log-pre">
              {dnsHealthResult
                ? dnsHealthResult.rawOutput || JSON.stringify(dnsHealthResult, null, 2)
                : 'No Multi-Resolver result yet.'}
            </pre>
            {dnsHealthResult?.rawOutput && (
              <button className="copy-sm-btn secondary" onClick={() => handleCopyRaw(dnsHealthResult.rawOutput)}>
                Copy
              </button>
            )}
          </div>
        </article>

        {/* DMARC Inspector */}
        <article className="diag-card">
          <h3>DMARC Inspector</h3>
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
              <button className="copy-sm-btn secondary" onClick={() => handleCopyRaw(dmarcResult.rawOutput)}>
                Copy
              </button>
            )}
          </div>
        </article>

        {/* WHOIS Lookup */}
        <article className="diag-card">
          <h3>WHOIS Lookup</h3>
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

        {/* MAC OUI */}
        <article className="diag-card">
          <h3>MAC Address OUI Matcher</h3>
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
            <pre className="diag-log-pre">No MAC result yet.</pre>
          )}
        </article>

      </div>

      {status !== 'Ready.' && <div className="status-toast">{status}</div>}
    </section>
  );
}
