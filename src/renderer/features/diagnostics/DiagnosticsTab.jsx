import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { runOnEnter } from '../trace/TraceTab';
import { parseIntOrDefault } from '../../utils/networkUtils';

export default function DiagnosticsTab() {
  // TCP Ping
  const [tcpHostInput, setTcpHostInput] = useState('');
  const [tcpPort, setTcpPort] = useState(443);
  const [tcpResult, setTcpResult] = useState(null);
  const [tcpLoading, setTcpLoading] = useState(false);

  // MTR
  const [mtrHostInput, setMtrHostInput] = useState('');
  const [mtrRounds, setMtrRounds] = useState(5);
  const [mtrLoading, setMtrLoading] = useState(false);
  const [mtrResult, setMtrResult] = useState(null);

  // DNS Toolkit
  const [dnsHostInput, setDnsHostInput] = useState('');
  const [dnsType, setDnsType] = useState('A');
  const [dnsResult, setDnsResult] = useState(null);
  const [dnsLoading, setDnsLoading] = useState(false);

  // Port Scanner
  const [portScanHostInput, setPortScanHostInput] = useState('');
  const [portListInput, setPortListInput] = useState('22,80,443,3389');
  const [portScanResult, setPortScanResult] = useState(null);
  const [portScanLoading, setPortScanLoading] = useState(false);

  // DNS Validation
  const [dnsValInput, setDnsValInput] = useState('');
  const [dnsValLoading, setDnsValLoading] = useState(false);
  const [dnsValResult, setDnsValResult] = useState(null);

  // Multi-Resolver Health
  const [dnsHealthInput, setDnsHealthInput] = useState('');
  const [dnsHealthLoading, setDnsHealthLoading] = useState(false);
  const [dnsHealthResult, setDnsHealthResult] = useState(null);

  // DNSBL Check
  const [dnsblInput, setDnsblInput] = useState('');
  const [dnsblLoading, setDnsblLoading] = useState(false);
  const [dnsblResult, setDnsblResult] = useState(null);

  const [status, setStatus] = useState('Ready.');

  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleTcpPing = async () => {
    if (tcpLoading) return;
    const host = tcpHostInput.trim();
    if (!host) { setStatus('Enter a hostname or IP for TCP ping.'); return; }
    setTcpLoading(true);
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
    } finally {
      setTcpLoading(false);
    }
  };

  const handleMtrRun = async () => {
    if (mtrLoading) return;
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
    } catch (error) {
      setMtrResult({ error: String(error?.message || error) });
      setStatus('MTR diagnostic failed.');
    } finally {
      setMtrLoading(false);
    }
  };

  const handleDnsQuery = async () => {
    if (dnsLoading) return;
    const host = dnsHostInput.trim();
    if (!host) { setStatus('Enter a domain for DNS lookup.'); return; }
    setDnsLoading(true);
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
    } finally {
      setDnsLoading(false);
    }
  };

  const handlePortScan = async () => {
    if (portScanLoading) return;
    const host = portScanHostInput.trim();
    if (!host) { setStatus('Enter a host for port scan.'); return; }
    const ports = portListInput
      .split(/[,\s]+/)
      .map((v) => Number.parseInt(v, 10))
      .filter((v) => Number.isFinite(v) && v > 0 && v <= 65535)
      .slice(0, 32);
    if (ports.length === 0) { setStatus('Enter at least one valid port.'); return; }
    setPortScanLoading(true);
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
    } finally {
      setPortScanLoading(false);
    }
  };

  const handleDnsValidate = async () => {
    if (dnsValLoading) return;
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
      setDnsValResult({ ok: false, error: String(e?.message || e) });
      setStatus('DNS Validation runtime error.');
    } finally {
      setDnsValLoading(false);
    }
  };

  const handleDnsHealth = async () => {
    if (dnsHealthLoading) return;
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
      setDnsHealthResult({ ok: false, error: String(e?.message || e) });
      setStatus('Health Check runtime error.');
    } finally {
      setDnsHealthLoading(false);
    }
  };

  const handleDnsblCheck = async () => {
    if (dnsblLoading) return;
    const ip = dnsblInput.trim();
    if (!ip) return;
    setDnsblLoading(true);
    setDnsblResult(null);
    setStatus(`Checking ${ip} against public blacklists...`);
    try {
      const res = await invoke('dnsbl_check', { ip });
      setDnsblResult(res);
      setStatus(res.ok ? 'DNSBL check complete.' : (res.error || 'DNSBL check failed.'));
      if (res.ok) setDnsblInput('');
    } catch (e) {
      setDnsblResult({ ok: false, error: String(e?.message || e) });
      setStatus('DNSBL check runtime error.');
    } finally {
      setDnsblLoading(false);
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

  const formatDnsResult = (result) => {
    if (!result) return 'No DNS result yet.';
    if (result.error) return `Error: ${result.error}`;
    const lines = [];
    if (result.domain) lines.push(`Domain:      ${result.domain}`);
    if (result.record_type) lines.push(`Record Type: ${result.record_type}`);
    lines.push('');
    lines.push('Local Resolver:');
    if (result.local_error) {
      lines.push(`  Lookup failed: ${result.local_error}`);
    } else if (result.local?.length) {
      result.local.forEach((r) => lines.push(`  ${r}`));
    } else {
      lines.push('  (no records found)');
    }
    lines.push('');
    lines.push('Google (8.8.8.8):');
    if (result.google_error) {
      lines.push(`  Lookup failed: ${result.google_error}`);
    } else if (result.google?.length) {
      result.google.forEach((r) => lines.push(`  ${r}`));
    } else {
      lines.push('  (no records found)');
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
          <p className="diag-card-desc">
            Checks if a specific TCP port is open and reachable.
          </p>
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
              onChange={(e) => setTcpPort(parseIntOrDefault(e.target.value, 443, 1, 65535))}
              placeholder="443"
              style={{ width: 90, flex: '0 0 90px' }}
            />
          </div>
          <button className="diag-run-btn" onClick={handleTcpPing} disabled={tcpLoading}>
            {tcpLoading ? 'Pinging...' : 'Run TCP Ping'}
          </button>
          <pre className="diag-log-pre">
            {tcpResult ? JSON.stringify(tcpResult, null, 2) : 'No TCP ping result yet.'}
          </pre>
        </article>

        {/* MTR */}
        <article className="diag-card">
          <h3>MTR-style (Ping + Trace)</h3>
          <p className="diag-card-desc">
            Combines ping and traceroute to show per-hop loss and latency.
          </p>
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
              onChange={(e) => setMtrRounds(parseIntOrDefault(e.target.value, 5, 2, 30))}
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
          <p className="diag-card-desc">
            Resolves a domain's records via the local resolver and Google DNS.
          </p>
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
          <button className="diag-run-btn" onClick={handleDnsQuery} disabled={dnsLoading}>
            {dnsLoading ? 'Querying...' : 'Run DNS Query'}
          </button>
          <pre className="diag-log-pre">{formatDnsResult(dnsResult)}</pre>
        </article>

        {/* Port Scanner */}
        <article className="diag-card">
          <h3>Port Scanner Lite</h3>
          <p className="diag-card-desc">
            Sweeps a custom list of ports on a host to see which are open.
          </p>
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
          <button className="diag-run-btn" onClick={handlePortScan} disabled={portScanLoading}>
            {portScanLoading ? 'Scanning...' : 'Run Port Scan'}
          </button>
          <pre className="diag-log-pre">
            {portScanResult ? JSON.stringify(portScanResult, null, 2) : 'No port scan result yet.'}
          </pre>
        </article>

        {/* DNS Validation */}
        <article className="diag-card">
          <h3>DNS Validation</h3>
          <p className="diag-card-desc">
            Checks a domain's DNS setup for common misconfigurations.
          </p>
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
          <p className="diag-card-desc">
            Compares answers across resolvers to catch split-DNS or poisoning issues.
          </p>
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

        {/* DNSBL Check */}
        <article className="diag-card">
          <h3>DNSBL Blacklist Check</h3>
          <p className="diag-card-desc">
            Checks an IPv4 address against public DNS-based blacklists.
          </p>
          <div className="diag-controls">
            <input
              value={dnsblInput}
              onChange={(e) => setDnsblInput(e.target.value)}
              onKeyDown={(e) => runOnEnter(e, handleDnsblCheck)}
              placeholder="Enter an IPv4 address"
            />
          </div>
          <button className="diag-run-btn" onClick={handleDnsblCheck} disabled={dnsblLoading}>
            {dnsblLoading ? 'Checking...' : 'Check Blacklists'}
          </button>
          <div className="diag-result-container">
            <pre className="diag-log-pre">
              {dnsblResult
                ? dnsblResult.rawOutput || dnsblResult.error || JSON.stringify(dnsblResult, null, 2)
                : 'No DNSBL check result yet.'}
            </pre>
            {dnsblResult?.rawOutput && (
              <button className="copy-sm-btn secondary" onClick={() => handleCopyRaw(dnsblResult.rawOutput)}>
                Copy
              </button>
            )}
          </div>
        </article>

      </div>

      {status !== 'Ready.' && <div className="status-toast">{status}</div>}
    </section>
  );
}
