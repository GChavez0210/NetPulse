const { app, BrowserWindow, ipcMain, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');
const net = require('net');
const dns = require('dns');
const { spawn } = require('child_process');

let mainWindow;

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

function runRapidPing(host, count) {
  return new Promise((resolve) => {
    if (!isValidHost(host)) {
      resolve({ ok: false, code: -1, output: 'Invalid host.' });
      return;
    }

    const allowedCounts = new Set([100, 1000]);
    const packets = Number.parseInt(String(count), 10);
    if (!allowedCounts.has(packets)) {
      resolve({ ok: false, code: -1, output: 'Only 100 or 1000 packet runs are supported.' });
      return;
    }

    const args = process.platform === 'win32' ? ['-n', String(packets), host] : ['-c', String(packets), host];
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
      const stats = parsePacketLoss(output);
      resolve({
        ok: code === 0,
        code: code ?? -1,
        output,
        report: stats
          ? {
              host,
              packetsRequested: packets,
              sent: stats.sent,
              received: stats.received,
              lost: stats.lost,
              lossPct: stats.lossPct
            }
          : null
      });
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

function buildRapidPacketUpdate(line) {
  if (!line) return null;
  const cleanLine = line.trim();
  if (!cleanLine) return null;

  if (/(reply from|bytes from|icmp_seq=)/i.test(cleanLine)) {
    const latencyMatch = cleanLine.match(/time[=<]?\s*(\d+(?:\.\d+)?)\s*ms/i);
    const latencyMs = latencyMatch ? Number.parseFloat(latencyMatch[1]) : null;
    const state = latencyMs != null && latencyMs > 80 ? 'jitter' : 'success';
    return { type: 'packet', state, latencyMs, text: cleanLine };
  }

  if (
    /(timed out|request timeout|destination host unreachable|general failure|100% packet loss|packet loss 100)/i.test(cleanLine)
  ) {
    return { type: 'packet', state: 'failed', latencyMs: null, text: cleanLine };
  }

  return { type: 'meta', text: cleanLine };
}

function runRapidPingStreaming(webContents, jobId, host, count) {
  return new Promise((resolve) => {
    if (!isValidHost(host)) {
      resolve({ ok: false, code: -1, output: 'Invalid host.' });
      return;
    }

    const allowedCounts = new Set([100, 1000]);
    const packets = Number.parseInt(String(count), 10);
    if (!allowedCounts.has(packets)) {
      resolve({ ok: false, code: -1, output: 'Only 100 or 1000 packet runs are supported.' });
      return;
    }

    const sendUpdate = (payload) => {
      try {
        webContents.send('ping:rapid:update', { jobId, ...payload });
      } catch {
        // Renderer may have been destroyed; ignore to avoid crashing the process.
      }
    };

    const args = process.platform === 'win32' ? ['-n', String(packets), host] : ['-c', String(packets), host];
    const child = spawn('ping', args, { shell: false });
    let output = '';
    let packetIndex = 0;
    let stdoutBuffer = '';
    let stderrBuffer = '';

    const processLine = (line) => {
      const update = buildRapidPacketUpdate(line);
      if (!update) return;

      if (update.type === 'packet') {
        sendUpdate({
          type: 'packet',
          index: packetIndex,
          state: update.state,
          latencyMs: update.latencyMs,
          text: update.text
        });
        packetIndex += 1;
      } else {
        sendUpdate({ type: 'meta', text: update.text });
      }
    };

    child.stdout.on('data', (chunk) => {
      const raw = chunk.toString();
      output += raw;
      stdoutBuffer += raw;
      const lines = stdoutBuffer.split(/\r?\n/);
      stdoutBuffer = lines.pop() || '';
      lines.forEach(processLine);
    });

    child.stderr.on('data', (chunk) => {
      const raw = chunk.toString();
      output += raw;
      stderrBuffer += raw;
      const lines = stderrBuffer.split(/\r?\n/);
      stderrBuffer = lines.pop() || '';
      lines.forEach(processLine);
    });

    child.on('error', (error) => {
      sendUpdate({ type: 'meta', text: error.message });
      resolve({ ok: false, code: -1, output: error.message });
    });

    child.on('close', (code) => {
      if (stdoutBuffer.trim()) processLine(stdoutBuffer);
      if (stderrBuffer.trim()) processLine(stderrBuffer);

      const stats = parsePacketLoss(output);
      sendUpdate({ type: 'done' });
      resolve({
        ok: code === 0,
        code: code ?? -1,
        output,
        report: stats
          ? {
              host,
              packetsRequested: packets,
              sent: stats.sent,
              received: stats.received,
              lost: stats.lost,
              lossPct: stats.lossPct
            }
          : null
      });
    });
  });
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

  ipcMain.handle('ping:rapid', async (event, host, count, jobId) => {
    if (jobId) {
      return runRapidPingStreaming(event.sender, String(jobId), host, count);
    }
    return runRapidPing(host, count);
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
