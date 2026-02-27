# NetPulse (Electron + React + Vite)

A self-contained desktop app for network diagnostics and live performance monitoring.
Includes Apilayer WHOIS integration with local API key settings.

## Requirements

- Node.js 18+
- npm
- Visual Studio Code (recommended)

## Project Structure

- `electron/main.js`: Electron main process (window lifecycle, IPC, ping, traceroute, local settings)
- `electron/preload.js`: Secure `contextBridge` API for renderer access
- `src/renderer/App.jsx`: Main React UI (parallel ping sessions, live charts, alerts, traceroute)
- `src/renderer/main.jsx`: React entrypoint
- `src/renderer/styles.css`: Dark neumorphic and glass-style UI theme
- `vite.config.js`: Vite configuration
- `index.html`: Renderer HTML entry

## Install

```bash
npm install
```

## Development

```bash
npm run dev
```

This starts:
- Vite dev server at `http://localhost:5173`
- Electron pointing to the Vite server

## Build and Package

```bash
npm run build
```

Expected output:
- `dist/` for web assets
- `release/` for packaged desktop installers

## Implemented IPC Channels

- `ping:run`: Runs a standard ping from the main process
- `ping:sample`: Runs a single ping sample (supports packet size + DF options)
- `ping:rapid`: Runs rapid packet-loss tests (100 / 1000) with optional live stream updates
- `trace:run`: Runs traceroute (`tracert` on Windows)
- `tcp:ping`: TCP SYN-style reachability check on configurable port
- `mtr:run`: Multi-round traceroute analysis (MTR-style summary)
- `dns:query`: DNS toolkit query (A/AAAA/MX/NS/CNAME/PTR) against local + Google resolvers
- `portscan:run`: Lightweight TCP port scan for selected ports
- `whois:lookup`: Runs WHOIS queries through Apilayer from the Electron main process
- `settings:setApiKey`: Saves the WHOIS API key in local app settings
- `settings:getApiKey`: Reads the saved WHOIS API key

## UI Features

- Modern dark theme with neumorphic surfaces and glass-style chart panels
- Parallel extended ping sessions (multiple targets at the same time)
- Fixed 1-second sampling cadence per active session
- Per-session and global controls: start, pause, stop, remove, rate-limited active sessions
- Status change notifications:
  - Host down after 3 consecutive failed pings
  - Host recovered when responses resume
- Timeline event markers on ping charts (down/up transitions)
- Health-based chart colors:
  - Green: normal
  - Yellow: degraded/lost pings
  - Red: down
- Advanced latency stats: p50, p95, p99, stddev
- Multi-target latency matrix (avg/loss/jitter/status)
- TCP ping module (open/closed/filtered + RTT)
- MTR-style hop analysis with problematic hop detection
- DNS toolkit with local vs 8.8.8.8 resolver comparison
- Port scanner lite for small port lists
- Traceroute module
- WHOIS lookup module powered by `https://api.apilayer.com/whois/query`
- Local WHOIS API key input and persistence

## Security Notes

- `contextIsolation: true`
- `nodeIntegration: false`
- Host validation before ping/traceroute execution
- Uses Electron `safeStorage` when available for API key encryption

## Windows ARM64 Note (`esbuild`)

If you encounter `EFTYPE` during install (`esbuild.exe is not a valid application for this OS platform`), this project pins `esbuild@0.19.12` to avoid that issue.

Use a clean reinstall when needed:

```bash
npm run clean:install
```
