import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { runOnEnter } from '../trace/TraceTab';
import { parseIntOrDefault } from '../../utils/networkUtils';

export default function DiagnosticsTab() {
  // MTR
  const [mtrHostInput, setMtrHostInput] = useState('');
  const [mtrRounds, setMtrRounds] = useState(5);
  const [mtrLoading, setMtrLoading] = useState(false);
  const [mtrResult, setMtrResult] = useState(null);

  // Speed Test
  const [speedLoading, setSpeedLoading] = useState(false);
  const [speedResult, setSpeedResult] = useState(null);
  const [speedElapsed, setSpeedElapsed] = useState(0);

  useEffect(() => {
    if (!speedLoading) return undefined;
    setSpeedElapsed(0);
    const interval = setInterval(() => setSpeedElapsed((s) => s + 1), 1000);
    return () => clearInterval(interval);
  }, [speedLoading]);

  // DNS Toolkit
  const [dnsHostInput, setDnsHostInput] = useState('');
  const [dnsType, setDnsType] = useState('A');
  const [dnsResult, setDnsResult] = useState(null);
  const [dnsLoading, setDnsLoading] = useState(false);

  // Port Checker (single quick check or multi-port sweep)
  const [portScanHostInput, setPortScanHostInput] = useState('');
  const [portListInput, setPortListInput] = useState('443');
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

  const handleSpeedTest = async () => {
    if (speedLoading) return;
    setSpeedLoading(true);
    setSpeedResult(null);
    setStatus('Running speed test (download then upload)...');
    try {
      const result = await invoke('speed_test');
      setSpeedResult(result);
      setStatus(
        result.ok
          ? `Speed test complete: ${result.download_mbps?.toFixed(1)} Mbps down / ${result.upload_mbps?.toFixed(1) ?? '-'} Mbps up.`
          : result.error || 'Speed test failed.'
      );
    } catch (error) {
      setSpeedResult({ ok: false, error: String(error?.message || error) });
      setStatus('Speed test failed.');
    } finally {
      setSpeedLoading(false);
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
    setStatus(
      ports.length === 1
        ? `Checking port ${ports[0]} on ${host}...`
        : `Scanning ${ports.length} ports on ${host}...`
    );
    setPortScanResult(null);
    try {
      const result = await invoke('port_scan', { host, ports, timeoutMs: 900 });
      setPortScanResult(result);
      setStatus(ports.length === 1 ? `Port check complete on ${host}.` : `Port scan complete on ${host}.`);
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

  const formatPortScanResult = (result) => {
    if (!result) return 'No port check result yet.';
    if (result.error && !result.ports) return `Error: ${result.error}`;
    const lines = [];
    lines.push(`Host: ${result.host}`);

    // Single port: show a compact reachability summary instead of a table.
    if (result.ports.length === 1) {
      const p = result.ports[0];
      lines.push(`Port:   ${p.port}`);
      lines.push(`Status: ${p.status.toUpperCase()}`);
      lines.push(`RTT:    ${p.rtt_ms != null ? `${p.rtt_ms.toFixed(1)} ms` : '-'}`);
      return lines.join('\n');
    }

    lines.push(`Scanned ${result.ports.length} port(s):`);
    lines.push('');
    const portW = Math.max(4, ...result.ports.map((p) => String(p.port).length));
    const statusW = Math.max(6, ...result.ports.map((p) => p.status.length));
    lines.push(`  ${'PORT'.padEnd(portW)}  ${'STATUS'.padEnd(statusW)}  RTT`);
    result.ports.forEach((p) => {
      const rtt = p.rtt_ms != null ? `${p.rtt_ms.toFixed(1)} ms` : '-';
      lines.push(`  ${String(p.port).padEnd(portW)}  ${p.status.padEnd(statusW)}  ${rtt}`);
    });
    const open = result.ports.filter((p) => p.status === 'open').map((p) => p.port);
    lines.push('');
    lines.push(open.length ? `Open ports: ${open.join(', ')}` : 'Open ports: none');
    return lines.join('\n');
  };

  const formatMtrResult = (result) => {
    if (!result) return 'No MTR result yet.';
    if (result.error && !result.hops) return `Error: ${result.error}`;
    if (!result.hops?.length) return 'No hops recorded (target may be unreachable or trace timed out).';
    const lines = [];
    lines.push(`Host:   ${result.host}`);
    lines.push(`Rounds: ${result.rounds}`);
    lines.push('');
    const ipW = Math.max(15, ...result.hops.map((h) => h.ip.length));
    lines.push(`  ${'HOP'.padEnd(4)}${'IP'.padEnd(ipW)}  ${'LOSS%'.padEnd(7)}${'AVG'.padEnd(9)}${'BEST'.padEnd(9)}WORST`);
    result.hops.forEach((h) => {
      const fmt = (v) => (v != null ? `${v.toFixed(1)}ms` : '-');
      lines.push(
        `  ${String(h.hop).padEnd(4)}${h.ip.padEnd(ipW)}  ${`${h.loss_pct.toFixed(0)}%`.padEnd(7)}${fmt(h.avg_rtt).padEnd(9)}${fmt(h.best_rtt).padEnd(9)}${fmt(h.worst_rtt)}`
      );
    });
    if (result.worst_hop != null) {
      const worst = result.hops.find((h) => h.hop === result.worst_hop);
      lines.push('');
      lines.push(`Worst hop: #${result.worst_hop}${worst ? ` (${worst.ip})` : ''}`);
    }
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

        {/* Port Checker */}
        <article className="diag-card">
          <h3>Port Checker</h3>
          <p className="diag-card-desc">
            Checks TCP port reachability on a host — enter one port for a quick check, or a list to sweep multiple.
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
              placeholder="443 or 80,443,3389"
              style={{ width: 120, flex: '0 0 120px' }}
            />
          </div>
          <button className="diag-run-btn" onClick={handlePortScan} disabled={portScanLoading}>
            {portScanLoading ? 'Checking...' : 'Check Port(s)'}
          </button>
          <pre className="diag-log-pre">
            {formatPortScanResult(portScanResult)}
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
            {formatMtrResult(mtrResult)}
          </pre>
        </article>

        {/* Speed Test */}
        <article className="diag-card">
          <h3>Speed Test</h3>
          <p className="diag-card-desc">
            Download/upload throughput and latency against Cloudflare's public speed-test backend.
          </p>
          <button className="diag-run-btn" onClick={handleSpeedTest} disabled={speedLoading}>
            {speedLoading ? 'Testing...' : 'Run Speed Test'}
          </button>

          {speedLoading && (
            <span className="page-tag" style={{ marginTop: 8 }}>
              <span className="page-tag-dot" />
              {speedElapsed < 8 ? 'TESTING DOWNLOAD' : 'TESTING UPLOAD'} — {speedElapsed}s
            </span>
          )}

          {speedResult ? (
            <div className="diag-result-container">
              {speedResult.ok && (
                <div style={{ display: 'flex', gap: 6, marginBottom: 6, flexWrap: 'wrap' }}>
                  <span className="pill-stable">↓ {speedResult.download_mbps?.toFixed(1)} Mbps</span>
                  {speedResult.upload_mbps != null && (
                    <span className="pill-stable">↑ {speedResult.upload_mbps.toFixed(1)} Mbps</span>
                  )}
                  {speedResult.latency_ms != null && (
                    <span className="pill-jitter">{speedResult.latency_ms.toFixed(0)} ms</span>
                  )}
                </div>
              )}
              <pre className="diag-log-pre">
                {speedResult.raw_output || (speedResult.error ? `Error: ${speedResult.error}` : '')}
              </pre>
            </div>
          ) : (
            <pre className="diag-log-pre">No speed test result yet.</pre>
          )}
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
                ? dnsValResult.raw_output || JSON.stringify(dnsValResult, null, 2)
                : 'No DNS Validation result yet.'}
            </pre>
            {dnsValResult?.rawOutput && (
              <button className="copy-sm-btn secondary" onClick={() => handleCopyRaw(dnsValResult.raw_output)}>
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
                ? dnsHealthResult.raw_output || JSON.stringify(dnsHealthResult, null, 2)
                : 'No Multi-Resolver result yet.'}
            </pre>
            {dnsHealthResult?.rawOutput && (
              <button className="copy-sm-btn secondary" onClick={() => handleCopyRaw(dnsHealthResult.raw_output)}>
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
                ? dnsblResult.raw_output || dnsblResult.error || JSON.stringify(dnsblResult, null, 2)
                : 'No DNSBL check result yet.'}
            </pre>
            {dnsblResult?.rawOutput && (
              <button className="copy-sm-btn secondary" onClick={() => handleCopyRaw(dnsblResult.raw_output)}>
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
