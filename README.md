# NetPulse v0.1.1 (Electron + React + Vite)

Fast, focused network troubleshooting.

## Overview

NetPulse is a desktop diagnostics suite with real-time monitoring and utility modules:

- Multi-target ping dashboard with live sparkline charts
- Packet loss test with streaming sequence map and diagnostic log
- Traceroute with parsed hop analysis and export/share
- Dedicated diagnostics hub:
  - TCP ping (SYN/connect reachability)
  - MTR-style multi-round hop analysis
  - DNS toolkit (local vs Google resolver)
  - Port scanner lite
- WHOIS lookup via Apilayer with local API key storage
- Dark/Light mode toggle

## Requirements

- Node.js 18+
- npm

## Run

Install dependencies:

```bash
npm install
```

Development mode:

```bash
npm run dev
```

## Build

```bash
npm run build
```

Build output:

- `dist/` renderer assets
- `release/` packaged desktop artifacts

Windows packaging is configured for both:

- `x64`
- `arm64`

The official app/installer icon is `netpulse_icon.ico`.

## Main Tabs

- `Ping Tests`
  - Single-IP or Bulk-IP entry mode toggle
  - Session rate limiting and duplicate target protection
  - Packet size and DF controls
  - p50/p95/p99/stddev metrics
  - timeline markers for down/recovery transitions
  - multi-target latency matrix
- `Packet Loss Check`
  - live sequence grid (success/jitter/failed)
  - loss donut + metrics stack
  - streaming diagnostic log
- `Traceroute`
  - hop cards, status bars, summary stats
  - rerun/export/share actions
- `Diagnostics`
  - dedicated diagnostics target input (separate from Ping tab)
  - TCP ping, MTR-style, DNS toolkit, port scan
- `WHOIS Lookup`
  - structured terminal-style result
  - copy/export actions
- `Settings`
  - local WHOIS API key persistence

## IPC Channels

- `ping:run`
- `ping:sample`
- `ping:rapid`
- `trace:run`
- `tcp:ping`
- `mtr:run`
- `dns:query`
- `portscan:run`
- `whois:lookup`
- `settings:setApiKey`
- `settings:getApiKey`

## Security Notes

- `contextIsolation: true`
- `nodeIntegration: false`
- Host validation before command execution
- Uses Electron `safeStorage` for API key encryption when available

## License

MIT. See [LICENSE](LICENSE).
