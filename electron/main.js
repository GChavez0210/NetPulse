const { app, BrowserWindow, ipcMain, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');
const net = require('net');
const dns = require('dns');
const { spawn } = require('child_process');

let mainWindow;
const FLOOD_MIN_INTERVAL_MS = 200;
const FLOOD_DEFAULT_INTERVAL_MS = 500;
const FLOOD_ALLOWED_COUNTS = new Set([100, 1000]);
const FLOOD_ALLOWED_MODES = new Set(['ICMP', 'TCP']);

const floodTestState = {
  running: false,
  cancelled: false,
  target: '',
  mode: 'ICMP',
  port: null,
  count: 0,
  sent: 0,
  received: 0,
  startedAt: null,
  endedAt: null,
  ownerWebContentsId: null
};

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 720,
    minWidth: 900,
    minHeight: 560,
    icon: path.join(__dirname, '..', 'netpulse_icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  const devServerUrl = process.env.VITE_DEV_SERVER_URL;

  if (devServerUrl) {
    mainWindow.loadURL(devServerUrl);
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
  }
}

const configPath = () => path.join(app.getPath('userData'), 'settings.json');

function encryptString(plainText) {
  if (!plainText) {
    return '';
  }

  if (safeStorage.isEncryptionAvailable()) {
    return safeStorage.encryptString(plainText).toString('base64');
  }

  return Buffer.from(plainText, 'utf8').toString('base64');
}

function decryptString(payload) {
  if (!payload) {
    return '';
  }

  const raw = Buffer.from(payload, 'base64');

  if (safeStorage.isEncryptionAvailable()) {
    return safeStorage.decryptString(raw);
  }

  return raw.toString('utf8');
}

function readSettings() {
  try {
    if (!fs.existsSync(configPath())) {
      return {};
    }

    const content = fs.readFileSync(configPath(), 'utf8');
    return JSON.parse(content);
  } catch {
    return {};
  }
}

function writeSettings(settings) {
  fs.writeFileSync(configPath(), JSON.stringify(settings, null, 2), 'utf8');
}

function isValidHost(host) {
  if (typeof host !== 'string') return false;
  if (host.length < 1 || host.length > 253) return false;
  return /^[a-zA-Z0-9.-]+$/.test(host);
}

function runPing(host) {
  return new Promise((resolve) => {
    if (!isValidHost(host)) {
      resolve({ ok: false, code: -1, output: 'Invalid host.' });
      return;
    }

    const args = process.platform === 'win32' ? ['-n', '4', host] : ['-c', '4', host];
    const child = spawn('ping', args, { shell: false });

    let output = '';

    child.stdout.on('data', (chunk) => {
      output += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      output += chunk.toString();
    });

    child.on('error', (error) => {
      resolve({ ok: false, code: -1, output: error.message });
    });

    child.on('close', (code) => {
      resolve({ ok: code === 0, code: code ?? -1, output });
    });
  });
}

function parseLatencyMs(pingOutput) {
  const match = pingOutput.match(/time[=<]?\s*([\d.]+)\s*ms/i);
  if (!match) return null;
  const value = Number.parseFloat(match[1]);
  return Number.isFinite(value) ? value : null;
}

function parsePacketLoss(pingOutput) {
  const windowsMatch = pingOutput.match(
    /Packets:\s*Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)\s*\((\d+)%\s*loss\)/i
  );
  if (windowsMatch) {
    return {
      sent: Number.parseInt(windowsMatch[1], 10),
      received: Number.parseInt(windowsMatch[2], 10),
      lost: Number.parseInt(windowsMatch[3], 10),
      lossPct: Number.parseInt(windowsMatch[4], 10)
    };
  }

  const unixMatch = pingOutput.match(
    /(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received.*?(\d+(?:\.\d+)?)%\s+packet loss/i
  );
  if (unixMatch) {
    const sent = Number.parseInt(unixMatch[1], 10);
    const received = Number.parseInt(unixMatch[2], 10);
    const lossPctFloat = Number.parseFloat(unixMatch[3]);
    const lost = Number.isFinite(sent - received) ? sent - received : 0;
    return {
      sent,
      received,
      lost,
      lossPct: Number.isFinite(lossPctFloat) ? Number(lossPctFloat.toFixed(1)) : null
    };
  }

  return null;
}

function runSinglePing(host, options = {}) {
  return new Promise((resolve) => {
    if (!isValidHost(host)) {
      resolve({ ok: false, code: -1, latencyMs: null, output: 'Invalid host.' });
      return;
    }

    const packetSize = Number.parseInt(String(options.packetSize || 56), 10);
    const size = Number.isFinite(packetSize) ? Math.min(Math.max(packetSize, 1), 65000) : 56;
    const dontFragment = Boolean(options.dontFragment);

    const args =
      process.platform === 'win32'
        ? ['-n', '1', '-w', '1000', ...(dontFragment ? ['-f'] : []), '-l', String(size), host]
        : [
            '-c',
            '1',
            '-W',
            '1',
            '-s',
            String(Math.max(size - 8, 0)),
            ...(dontFragment && process.platform === 'linux' ? ['-M', 'do'] : []),
            host
          ];
    const child = spawn('ping', args, { shell: false });

    let output = '';

    child.stdout.on('data', (chunk) => {
      output += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      output += chunk.toString();
    });

    child.on('error', (error) => {
      resolve({ ok: false, code: -1, latencyMs: null, output: error.message });
    });

    child.on('close', (code) => {
      resolve({
        ok: code === 0,
        code: code ?? -1,
        latencyMs: code === 0 ? parseLatencyMs(output) : null,
        output
      });
    });
  });
}

function runTraceroute(host) {
  return new Promise((resolve) => {
    if (!isValidHost(host)) {
      resolve({ ok: false, code: -1, output: 'Invalid host.' });
      return;
    }

    const cmd = process.platform === 'win32' ? 'tracert' : 'traceroute';
    const args = process.platform === 'win32' ? ['-h', '20', host] : ['-m', '20', host];
    const child = spawn(cmd, args, { shell: false });

    let output = '';

    child.stdout.on('data', (chunk) => {
      output += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      output += chunk.toString();
    });

    child.on('error', (error) => {
      resolve({
        ok: false,
        code: -1,
        output: `Could not execute ${cmd}. ${error.message}`
      });
    });

    child.on('close', (code) => {
      resolve({ ok: code === 0, code: code ?? -1, output });
    });
  });
}

function runRapidProbe(host, timeoutMs = 300) {
  return new Promise((resolve) => {
    if (!isValidHost(host)) {
      resolve({ ok: false, latencyMs: null, output: 'Invalid host.' });
      return;
    }

    const safeTimeout = Math.min(Math.max(Number.parseInt(String(timeoutMs), 10) || 300, 100), 5000);
    const unixTimeoutSeconds = Math.max(1, Math.ceil(safeTimeout / 1000));
    const args =
      process.platform === 'win32'
        ? ['-n', '1', '-w', String(safeTimeout), host]
        : ['-c', '1', '-W', String(unixTimeoutSeconds), host];
    const child = spawn('ping', args, { shell: false });
    let output = '';

    child.stdout.on('data', (chunk) => {
      output += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      output += chunk.toString();
    });

    child.on('error', (error) => {
      resolve({ ok: false, latencyMs: null, output: String(error?.message || error || 'Probe failed.') });
    });

    child.on('close', (code) => {
      const latencyMs = code === 0 ? parseLatencyMs(output) : null;
      resolve({ ok: code === 0 && latencyMs != null, latencyMs, output });
    });
  });
}

function runTcpPing(host, port = 443, timeoutMs = 1500) {
  return new Promise((resolve) => {
    if (!isValidHost(host)) {
      resolve({ ok: false, status: 'invalid', rttMs: null, error: 'Invalid host.' });
      return;
    }

    const safePort = Math.min(Math.max(Number.parseInt(String(port), 10) || 443, 1), 65535);
    const safeTimeout = Math.min(Math.max(Number.parseInt(String(timeoutMs), 10) || 1500, 300), 10000);
    const socket = new net.Socket();
    const started = process.hrtime.bigint();
    let settled = false;

    const done = (payload) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      resolve(payload);
    };

    socket.setTimeout(safeTimeout);

    socket.on('connect', () => {
      const ended = process.hrtime.bigint();
      const rttMs = Number(ended - started) / 1e6;
      done({ ok: true, status: 'open', rttMs, port: safePort });
    });

    socket.on('timeout', () => {
      done({ ok: false, status: 'filtered', rttMs: null, port: safePort, error: 'Connection timed out.' });
    });

    socket.on('error', (error) => {
      const code = String(error?.code || '');
      if (code === 'ECONNREFUSED') {
        done({ ok: false, status: 'closed', rttMs: null, port: safePort, error: 'Port is closed.' });
        return;
      }
      done({ ok: false, status: 'filtered', rttMs: null, port: safePort, error: error.message });
    });

    socket.connect(safePort, host);
  });
}

async function runDnsQuery(domain, recordType = 'A', resolverMode = 'local') {
  if (!isValidHost(domain)) {
    return { ok: false, error: 'Invalid domain/host.' };
  }

  const type = String(recordType || 'A').toUpperCase();
  const resolver = new dns.promises.Resolver();
  if (resolverMode === 'google') {
    resolver.setServers(['8.8.8.8', '8.8.4.4']);
  }

  try {
    let result = [];
    if (type === 'A') result = await resolver.resolve4(domain);
    else if (type === 'AAAA') result = await resolver.resolve6(domain);
    else if (type === 'MX') result = await resolver.resolveMx(domain);
    else if (type === 'NS') result = await resolver.resolveNs(domain);
    else if (type === 'CNAME') result = await resolver.resolveCname(domain);
    else if (type === 'PTR') result = await resolver.reverse(domain);
    else return { ok: false, error: `Unsupported record type: ${type}` };

    return { ok: true, domain, type, resolver: resolverMode, result };
  } catch (error) {
    return { ok: false, domain, type, resolver: resolverMode, error: error.message };
  }
}

async function runDnsToolkit(domain, recordType) {
  const [local, google] = await Promise.all([runDnsQuery(domain, recordType, 'local'), runDnsQuery(domain, recordType, 'google')]);
  return { ok: local.ok || google.ok, local, google };
}

function runPortScan(host, ports = [22, 80, 443, 3389], timeoutMs = 900) {
  if (!isValidHost(host)) {
    return Promise.resolve({ ok: false, error: 'Invalid host.' });
  }

  const list = Array.from(
    new Set(
      ports
        .map((port) => Number.parseInt(String(port), 10))
        .filter((port) => Number.isFinite(port) && port >= 1 && port <= 65535)
    )
  ).slice(0, 32);

  const probePort = (port) =>
    new Promise((resolve) => {
      const socket = new net.Socket();
      let settled = false;
      const started = process.hrtime.bigint();
      const finish = (status, error) => {
        if (settled) return;
        settled = true;
        try {
          socket.destroy();
        } catch {
          // ignore
        }
        const ended = process.hrtime.bigint();
        const rttMs = Number(ended - started) / 1e6;
        resolve({ port, status, rttMs: Number(rttMs.toFixed(2)), error: error || null });
      };

      socket.setTimeout(timeoutMs);
      socket.on('connect', () => finish('open', null));
      socket.on('timeout', () => finish('filtered', 'timeout'));
      socket.on('error', (error) => finish(error?.code === 'ECONNREFUSED' ? 'closed' : 'filtered', error.message));
      socket.connect(port, host);
    });

  return Promise.all(list.map((port) => probePort(port))).then((result) => ({
    ok: true,
    host,
    result
  }));
}

function parseMtrTraceroute(output) {
  const lines = String(output || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  return lines
    .map((line) => {
      const hopMatch = line.match(/^(\d+)\s+(.*)$/);
      if (!hopMatch) return null;
      const hop = Number.parseInt(hopMatch[1], 10);
      const rest = hopMatch[2];
      const ipv4Match = rest.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      const ip = ipv4Match?.[1] || 'Unknown';
      const latencyMatches = [...rest.matchAll(/<?\s*(\d+(?:\.\d+)?)\s*ms/gi)];
      const latencies = latencyMatches.map((m) => Number.parseFloat(m[1])).filter((v) => Number.isFinite(v));
      const timedOut = rest.includes('*');
      return { hop, ip, latencies, timedOut };
    })
    .filter(Boolean);
}

async function runMtrLike(host, rounds = 5) {
  if (!isValidHost(host)) {
    return { ok: false, error: 'Invalid host.' };
  }

  const safeRounds = Math.min(Math.max(Number.parseInt(String(rounds), 10) || 5, 2), 30);
  const hopMap = new Map();

  for (let i = 0; i < safeRounds; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const run = await runTraceroute(host);
    const hops = parseMtrTraceroute(run.output);
    for (const hop of hops) {
      const key = `${hop.hop}-${hop.ip}`;
      if (!hopMap.has(key)) {
        hopMap.set(key, {
          hop: hop.hop,
          ip: hop.ip,
          sent: 0,
          received: 0,
          lossPct: 0,
          avgLatency: null,
          worstLatency: null
        });
      }
      const entry = hopMap.get(key);
      entry.sent += 1;
      if (!hop.timedOut) {
        entry.received += 1;
      }
      const valid = hop.latencies.filter((v) => Number.isFinite(v));
      if (valid.length > 0) {
        const avg = valid.reduce((a, b) => a + b, 0) / valid.length;
        entry.avgLatency = entry.avgLatency == null ? avg : (entry.avgLatency + avg) / 2;
        entry.worstLatency = Math.max(entry.worstLatency || 0, ...valid);
      }
      entry.lossPct = entry.sent > 0 ? Number((((entry.sent - entry.received) * 100) / entry.sent).toFixed(1)) : 0;
    }
  }

  const hops = Array.from(hopMap.values()).sort((a, b) => a.hop - b.hop);
  const problematicHop =
    hops
      .filter((h) => h.lossPct > 0)
      .sort((a, b) => b.lossPct - a.lossPct || (b.avgLatency || 0) - (a.avgLatency || 0))[0] || null;

  return { ok: true, host, rounds: safeRounds, hops, problematicHop };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

function chooseAdaptiveInterval(avgRtt, previousInterval) {
  if (avgRtt == null || !Number.isFinite(avgRtt)) {
    const fallback = Number.isFinite(previousInterval) ? previousInterval : FLOOD_DEFAULT_INTERVAL_MS;
    return Math.max(FLOOD_MIN_INTERVAL_MS, fallback);
  }

  let nextInterval = FLOOD_DEFAULT_INTERVAL_MS;
  if (avgRtt < 20) {
    nextInterval = 200;
  } else if (avgRtt < 100) {
    nextInterval = 300;
  } else {
    nextInterval = 500;
  }

  return Math.max(FLOOD_MIN_INTERVAL_MS, nextInterval);
}

function rollingAvg(validRtts, windowSize = 10) {
  if (!Array.isArray(validRtts) || validRtts.length === 0) {
    return null;
  }
  const safeWindow = Math.min(Math.max(Number.parseInt(String(windowSize), 10) || 10, 1), 100);
  const tail = validRtts.slice(-safeWindow);
  if (tail.length === 0) return null;
  const sum = tail.reduce((acc, value) => acc + value, 0);
  return Number.isFinite(sum) ? sum / tail.length : null;
}

function percentile(sortedValues, ratio) {
  if (!Array.isArray(sortedValues) || sortedValues.length === 0) return null;
  const idx = Math.min(sortedValues.length - 1, Math.max(0, Math.ceil(sortedValues.length * ratio) - 1));
  return sortedValues[idx];
}

function computeSummary(samples, metadata) {
  const safeSamples = Array.isArray(samples) ? samples : [];
  const sent = safeSamples.length;
  const validRtts = safeSamples.map((sample) => sample.rtt_ms).filter((value) => Number.isFinite(value));
  const received = validRtts.length;
  const lost = Math.max(sent - received, 0);
  const lossPct = sent > 0 ? Number((((lost * 100) / sent)).toFixed(2)) : 0;

  const sortedRtts = [...validRtts].sort((a, b) => a - b);
  const min = sortedRtts.length > 0 ? sortedRtts[0] : null;
  const max = sortedRtts.length > 0 ? sortedRtts[sortedRtts.length - 1] : null;
  const avg = sortedRtts.length > 0 ? sortedRtts.reduce((acc, value) => acc + value, 0) / sortedRtts.length : null;
  const p95 = percentile(sortedRtts, 0.95);

  const jitterDeltas = [];
  for (let idx = 1; idx < validRtts.length; idx += 1) {
    jitterDeltas.push(Math.abs(validRtts[idx] - validRtts[idx - 1]));
  }
  const jitter = jitterDeltas.length > 0 ? jitterDeltas.reduce((acc, value) => acc + value, 0) / jitterDeltas.length : null;

  let streak = 0;
  let lossStreakMax = 0;
  for (const sample of safeSamples) {
    if (sample.timeout) {
      streak += 1;
      lossStreakMax = Math.max(lossStreakMax, streak);
    } else {
      streak = 0;
    }
  }

  return {
    target: metadata.target,
    mode: metadata.mode,
    port: metadata.port ?? null,
    count: metadata.count,
    sent,
    received,
    loss_pct: lossPct,
    min_rtt_ms: min != null ? Number(min.toFixed(2)) : null,
    avg_rtt_ms: avg != null ? Number(avg.toFixed(2)) : null,
    max_rtt_ms: max != null ? Number(max.toFixed(2)) : null,
    jitter_ms: jitter != null ? Number(jitter.toFixed(2)) : null,
    p95_rtt_ms: p95 != null ? Number(p95.toFixed(2)) : null,
    lossStreakMax
  };
}

function notifyFloodStatus(webContents, status, message) {
  try {
    webContents.send('ping:floodStatus', { status, message: message || undefined });
  } catch {
    // Renderer may have gone away while a run is active.
  }
}

function notifyFloodSample(webContents, payload) {
  try {
    webContents.send('ping:floodSample', payload);
  } catch {
    // Renderer may have gone away while a run is active.
  }
}

function notifyFloodDone(webContents, summary) {
  try {
    webContents.send('ping:floodDone', { summary });
  } catch {
    // Renderer may have gone away while a run is active.
  }
}

function runSingleTcpProbe(host, port = 443, timeoutMs = 1000) {
  return new Promise((resolve) => {
    if (!isValidHost(host)) {
      resolve({ ok: false, rtt_ms: null, timeout: true, output: 'Invalid host.' });
      return;
    }

    const safePort = Math.min(Math.max(Number.parseInt(String(port), 10) || 443, 1), 65535);
    const safeTimeout = Math.min(Math.max(Number.parseInt(String(timeoutMs), 10) || 1000, 200), 10000);
    const socket = new net.Socket();
    const started = process.hrtime.bigint();
    let settled = false;

    const finish = (payload) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      resolve(payload);
    };

    socket.setTimeout(safeTimeout);

    socket.on('connect', () => {
      const ended = process.hrtime.bigint();
      finish({
        ok: true,
        rtt_ms: Number((Number(ended - started) / 1e6).toFixed(2)),
        timeout: false,
        output: `TCP connect success on ${host}:${safePort}`
      });
    });

    socket.on('timeout', () => {
      finish({
        ok: false,
        rtt_ms: null,
        timeout: true,
        output: `TCP timeout on ${host}:${safePort}`
      });
    });

    socket.on('error', (error) => {
      const ended = process.hrtime.bigint();
      const code = String(error?.code || '');
      if (code === 'ECONNREFUSED') {
        finish({
          ok: true,
          rtt_ms: Number((Number(ended - started) / 1e6).toFixed(2)),
          timeout: false,
          output: `TCP refused on ${host}:${safePort}`
        });
        return;
      }
      finish({
        ok: false,
        rtt_ms: null,
        timeout: true,
        output: error?.message || 'TCP probe failed.'
      });
    });

    socket.connect(safePort, host);
  });
}

async function runFloodTestLoop(webContents, options) {
  const { target, count, mode, timeoutMs, port } = options;
  const samples = [];
  const validRtts = [];
  let intervalMs = FLOOD_DEFAULT_INTERVAL_MS;

  floodTestState.running = true;
  floodTestState.cancelled = false;
  floodTestState.target = target;
  floodTestState.mode = mode;
  floodTestState.port = port ?? null;
  floodTestState.count = count;
  floodTestState.sent = 0;
  floodTestState.received = 0;
  floodTestState.startedAt = new Date().toISOString();
  floodTestState.endedAt = null;
  floodTestState.ownerWebContentsId = webContents.id;

  notifyFloodStatus(webContents, 'running', `Flood test started for ${target}.`);

  try {
    for (let seq = 1; seq <= count; seq += 1) {
      if (floodTestState.cancelled) break;

      // eslint-disable-next-line no-await-in-loop
      const probe =
        mode === 'TCP'
          ? await runSingleTcpProbe(target, port, timeoutMs)
          : await runRapidProbe(target, timeoutMs);

      const rttMs = Number.isFinite(probe.rtt_ms) ? probe.rtt_ms : probe.latencyMs;
      const timeout = !(probe.ok && Number.isFinite(rttMs));
      const sample = {
        seq,
        timestamp: new Date().toISOString(),
        rtt_ms: timeout ? null : Number(Number(rttMs).toFixed(2)),
        timeout
      };

      samples.push(sample);
      floodTestState.sent = samples.length;
      if (!timeout) {
        floodTestState.received += 1;
        validRtts.push(sample.rtt_ms);
      }

      notifyFloodSample(webContents, sample);

      const avgRtt = rollingAvg(validRtts, 10);
      intervalMs = chooseAdaptiveInterval(avgRtt, intervalMs);

      if (seq < count && !floodTestState.cancelled) {
        // eslint-disable-next-line no-await-in-loop
        await sleep(intervalMs);
      }
    }

    const summary = computeSummary(samples, {
      target,
      mode,
      port: mode === 'TCP' ? port : null,
      count
    });

    summary.startedAt = floodTestState.startedAt;
    summary.endedAt = new Date().toISOString();
    summary.status = floodTestState.cancelled ? 'cancelled' : 'done';
    summary.interval_min_ms = FLOOD_MIN_INTERVAL_MS;

    floodTestState.running = false;
    floodTestState.endedAt = summary.endedAt;
    notifyFloodDone(webContents, summary);
    notifyFloodStatus(webContents, summary.status, floodTestState.cancelled ? 'Flood test cancelled.' : 'Flood test completed.');

    return { ok: true, summary };
  } catch (error) {
    floodTestState.running = false;
    floodTestState.endedAt = new Date().toISOString();
    notifyFloodStatus(webContents, 'error', error?.message || 'Flood test failed.');
    return { ok: false, error: error?.message || 'Flood test failed.' };
  } finally {
    floodTestState.running = false;
    floodTestState.ownerWebContentsId = null;
  }
}

function sanitizeFloodStartPayload(payload) {
  const target = String(payload?.target || '').trim();
  if (!target || !isValidHost(target)) {
    return { ok: false, error: 'Invalid host.' };
  }

  const count = Number.parseInt(String(payload?.count), 10);
  if (!FLOOD_ALLOWED_COUNTS.has(count)) {
    return { ok: false, error: 'Flood test count must be 100 or 1000.' };
  }

  const mode = String(payload?.mode || 'ICMP').toUpperCase();
  if (!FLOOD_ALLOWED_MODES.has(mode)) {
    return { ok: false, error: 'Flood test mode must be ICMP or TCP.' };
  }

  const timeoutMs = Math.min(Math.max(Number.parseInt(String(payload?.timeoutMs), 10) || 1000, 300), 5000);
  const port = mode === 'TCP' ? Math.min(Math.max(Number.parseInt(String(payload?.port), 10) || 443, 1), 65535) : null;

  return {
    ok: true,
    options: { target, count, mode, timeoutMs, port }
  };
}

function runWhoisLookup(domain, providedApiKey) {
  return new Promise((resolve) => {
    if (!isValidHost(domain)) {
      resolve({ ok: false, status: 0, error: 'Invalid domain.' });
      return;
    }

    const apiKey = String(providedApiKey || '').trim();
    if (!apiKey) {
      resolve({ ok: false, status: 0, error: 'API key is required. Save it in settings first.' });
      return;
    }

    const target = `https://api.apilayer.com/whois/query?domain=${encodeURIComponent(domain)}`;
    const req = https.get(
      target,
      {
        headers: {
          apikey: apiKey,
          Accept: 'application/json'
        }
      },
      (res) => {
        let body = '';

        res.on('data', (chunk) => {
          body += chunk.toString();
        });

        res.on('end', () => {
          let payload = null;
          try {
            payload = body ? JSON.parse(body) : null;
          } catch {
            payload = null;
          }

          const ok = (res.statusCode || 0) >= 200 && (res.statusCode || 0) < 300;
          if (ok) {
            resolve({ ok: true, status: res.statusCode || 200, data: payload, raw: body });
            return;
          }

          const error =
            (payload && (payload.message || payload.error || payload.info)) ||
            `WHOIS lookup failed with status ${res.statusCode || 0}.`;
          resolve({ ok: false, status: res.statusCode || 0, error, data: payload, raw: body });
        });
      }
    );

    req.on('error', (error) => {
      resolve({ ok: false, status: 0, error: `WHOIS request failed: ${error.message}` });
    });

    req.setTimeout(15000, () => {
      req.destroy(new Error('Request timed out'));
    });
  });
}

app.whenReady().then(() => {
  createWindow();

  ipcMain.handle('ping:run', async (_event, host) => {
    return runPing(host);
  });

  ipcMain.handle('ping:sample', async (_event, host, options) => {
    return runSinglePing(host, options || {});
  });

  ipcMain.handle('ping:floodStart', async (event, payload) => {
    if (floodTestState.running) {
      notifyFloodStatus(event.sender, 'error', 'Flood test already running');
      return { ok: false, error: 'Flood test already running' };
    }

    const sanitized = sanitizeFloodStartPayload(payload);
    if (!sanitized.ok) {
      notifyFloodStatus(event.sender, 'error', sanitized.error);
      return { ok: false, error: sanitized.error };
    }

    runFloodTestLoop(event.sender, sanitized.options).catch((error) => {
      notifyFloodStatus(event.sender, 'error', error?.message || 'Flood test failed.');
    });

    return {
      ok: true,
      status: 'running',
      state: {
        running: true,
        target: sanitized.options.target,
        mode: sanitized.options.mode,
        port: sanitized.options.port,
        count: sanitized.options.count
      }
    };
  });

  ipcMain.handle('ping:floodCancel', async () => {
    if (!floodTestState.running) {
      return { ok: false, error: 'No flood test running' };
    }
    floodTestState.cancelled = true;
    return { ok: true };
  });

  ipcMain.handle('trace:run', async (_event, host) => {
    return runTraceroute(host);
  });

  ipcMain.handle('tcp:ping', async (_event, host, port, timeoutMs) => {
    return runTcpPing(host, port, timeoutMs);
  });

  ipcMain.handle('mtr:run', async (_event, host, rounds) => {
    return runMtrLike(host, rounds);
  });

  ipcMain.handle('dns:query', async (_event, domain, recordType) => {
    return runDnsToolkit(domain, recordType);
  });

  ipcMain.handle('portscan:run', async (_event, host, ports, timeoutMs) => {
    return runPortScan(host, ports, timeoutMs);
  });

  ipcMain.handle('settings:setApiKey', async (_event, apiKey) => {
    const settings = readSettings();
    settings.whoisApiKey = encryptString(String(apiKey || ''));
    writeSettings(settings);
    return { ok: true };
  });

  ipcMain.handle('settings:getApiKey', async () => {
    const settings = readSettings();
    const encryptedApiKey = settings.whoisApiKey || '';
    return decryptString(encryptedApiKey);
  });

  ipcMain.handle('whois:lookup', async (_event, domain, apiKeyInput) => {
    const settings = readSettings();
    const savedApiKey = decryptString(settings.whoisApiKey || '');
    const apiKey = String(apiKeyInput || '').trim() || savedApiKey;
    return runWhoisLookup(domain, apiKey);
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
