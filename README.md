# NetPulse v0.5.0

NetPulse is a fast, strictly local network diagnostics suite built with **Tauri 2**, **React**, and **Vite**. It interfaces directly with your operating system's native networking stack — ICMP binaries, raw TCP sockets, and DNS resolvers — to deliver precise, dependency-free telemetry in a modern dark glass desktop interface.

---

## Features

### Multi-Target Ping
- Monitor multiple hosts simultaneously via continuous ICMP sampling with live Recharts latency graphs.
- Configurable packet size and DF (Don't Fragment) flag per session.
- Per-session custom ping interval (0.5s, 1s, 2s, 5s, 10s).
- Host aliases — set a friendly display name per monitor (double-click or pencil icon).
- Drag-and-drop card reordering.
- Saved host groups (Favorites) — save the current set of targets as a named group and reload with one click; persisted across sessions.
- Audio alerts — synthesized tone plays on host up/down transitions; can be toggled on/off.
- Single and bulk IP entry modes; CSV session export (includes alias column).
- Global KPIs: active monitors, average RTT, average packet loss across all sessions.
- Per-session health pills (Stable / Jitter / Timeout) with automatic state tracking.
- In-app notifications on host up/down state transitions.

### Flood Test
- Execute high-frequency ICMP pacing tests (100 or 1000 packets) to isolate unstable links.
- Real-time per-packet sequence grid (success / jitter / failed / pending cells).
- Streaming diagnostic log and summary metrics: avg/min/max/p95 RTT, jitter, max consecutive loss streak.
- In-app notification on test completion with full summary.

### Network Topology (Traceroute)
- Visual hop-by-hop traceroute with latency status bars (good / warn / bad).
- Automatic GeoIP enrichment per hop — country, city, org, and ASN fetched in the background after the trace completes.
- CSV export of full hop analysis including geographic and ASN data.

### Advanced Analytics (7 tools)
- **TCP Ping** — SYN reachability test with RTT on any port.
- **MTR-style** — Multi-round traceroute aggregation; per-hop loss%, avg/best/worst RTT, worst-hop identification.
- **DNS Toolkit** — Query A, AAAA, MX, NS, CNAME, PTR records against both system and Google (8.8.8.8) resolvers simultaneously.
- **Port Scanner Lite** — Concurrent TCP connect scan across up to 32 ports.
- **DNS Validation** — Checks A, AAAA, NS, SOA, CAA presence with a health score (0–100).
- **Multi-Resolver Health** — Compares A/AAAA/NS records across System, Cloudflare (1.1.1.1), and Google (8.8.8.8) to detect split-horizon or poisoning.
- **DMARC Inspector** — Fetches and parses `_dmarc.<domain>` TXT records, validates policy tags.

### Registry & Hardware Identity
- **WHOIS / RDAP** — API-key-free. IPv4 addresses use the RDAP pipeline (`rdap.org`); domains follow the IANA referral chain via raw Port 43 TCP sockets to the authoritative registrar WHOIS server.
- **MAC OUI Matcher** — Sub-millisecond hardware vendor lookups against a bundled SQLite database (5.8 MB, opened read-only at startup).

### In-App Notifications
- Persistent notification panel accessible from the top nav.
- Captures ping up/down transitions, flood test completions, and traceroute completions.
- Up to 100 entries retained per session; one-click clear all.

### Settings
- Persistent JSON settings file stored in the Tauri app data directory.
- Read and written via typed `invoke()` calls; survives app restarts.
- Stores: ping favorites, audio alert preference, always-on-top state.

### Window Utilities
- **Always-on-top** — pin the window above all other applications via the pushpin button in the top-right nav; state persists across restarts.

## Architecture

NetPulse is built on **Tauri 2** — a Rust + WebView desktop framework. The Rust backend handles all privileged operations; the React frontend communicates with it exclusively via Tauri's typed `invoke()` / `listen()` IPC.

### Backend (Rust — `src-tauri/`)

| Module | Responsibility |
|---|---|
| `ping.rs` | Spawns `ping` binary; parses RTT from Windows and Unix output formats |
| `flood.rs` | Async flood loop in a `tokio::spawn` task; emits per-packet events to the frontend |
| `trace.rs` | Spawns `tracert` (via `cmd /c`) / `traceroute`; returns raw output for frontend parsing |
| `tcp.rs` | `tokio::net::TcpStream` connect with timeout; concurrent port scanning via `futures::join_all` |
| `dns.rs` | `hickory-resolver` with system, Cloudflare, and Google resolvers; DNS validation scoring; DMARC parsing; MTR aggregation |
| `whois.rs` | `reqwest` RDAP for IPs; async TCP WHOIS with IANA referral chain for domains |
| `oui.rs` | `rusqlite` read-only query on bundled OUI database via `spawn_blocking` |
| `geoip.rs` | `reqwest` lookup via `ip-api.com`; skips private/loopback addresses |
| `settings.rs` | JSON settings file read/write in the Tauri app data directory |

**Key crates:** `tauri 2`, `tokio` (full), `reqwest` (rustls-tls), `rusqlite` (bundled), `hickory-resolver`, `serde`, `futures`

### Frontend (React — `src/renderer/`)

- **Routing:** single `useState` tab switch in `App.jsx` — no router dependency. All tabs stay mounted to preserve state; inactive tabs are hidden via CSS.
- **Charts:** Recharts `LineChart` for live latency, CSS conic-gradient donut for flood loss rate.
- **Styling:** Tailwind CSS v4 (Vite plugin) + CSS custom properties design system. JetBrains Mono for all data readout, Inter for labels.
- **IPC:** `@tauri-apps/api/core` `invoke()` for request/response commands; `@tauri-apps/api/event` `listen()` for flood test push events.
- **Notifications:** in-app panel component in `App.jsx`; `addNotification` callback passed down to feature tabs.

## Installation & Development

### Prerequisites

- **Node.js** 18+
- **Rust** (via [rustup](https://rustup.rs/))

```bash
# Install Rust on Windows
winget install Rustlang.Rustup
# Restart terminal, then:
rustup default stable
```

### Development

```bash
npm install
npm run dev
```

`npm run dev` runs `tauri dev`, which starts the Vite dev server and compiles the Rust backend concurrently. The first run takes a few minutes while Cargo fetches and compiles dependencies.

### Production Build

```bash
npm run build
```

**Output:** `src-tauri/target/release/bundle/` — platform-specific installer (NSIS `.exe` on Windows, `.dmg` on macOS, `AppImage` on Linux).

*Bundling notes:* `oui-database.sqlite` is declared as a Tauri resource and opened read-only at startup via `app_handle.path().resolve(...)`. No ASAR packing or `extraResources` config needed.

## Built with AI

This application was built using an AI-assisted development workflow. AI accelerated the creation of the codebase, enabling faster iteration cycles and a consistent architecture across the project.

All system design, validation, and testing remain under developer control. The application runs locally and deterministically with no external AI services involved during normal operation.

## License

MIT. See `LICENSE` for more information.

---
*NetPulse by Gabriel Chavez • Developed in Mexico with love*
