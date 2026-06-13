# NetPulse

> Fast, focused network diagnostics — built with Tauri 2, React, and Vite.

NetPulse is a strictly local network diagnostics suite that interfaces directly with your operating system's native networking stack — ICMP binaries, raw TCP sockets, and DNS resolvers — to deliver precise, dependency-free telemetry in a modern dark-glass desktop interface.

**Current version:** v0.5.1 · **Platform:** Windows (primary), Linux & macOS (source build)

---

## Table of Contents

- [Features](#features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Cross-Platform Support](#cross-platform-support)
- [Building from Source](#building-from-source)
- [Architecture](#architecture)
- [Built with AI](#built-with-ai)
- [License](#license)

---

## Features

### 🖥 Multi-Target Ping
Monitor multiple hosts simultaneously via continuous ICMP sampling with live latency graphs.
- Configurable packet size and DF (Don't Fragment) flag per session
- Per-session custom ping interval: 0.5 s, 1 s, 2 s, 5 s, 10 s
- Host aliases — set a friendly display name per monitor (double-click or pencil icon)
- Drag-and-drop card reordering
- Saved host groups (Favorites) — save the current set of targets as a named group and reload with one click; persisted across sessions
- Audio alerts — synthesized tone on host up/down transitions; toggle on/off
- Single and bulk IP entry modes; CSV session export (includes alias column)
- Global KPIs: active monitors, average RTT, average packet loss across all sessions
- Per-session health pills (Stable / Jitter / Timeout) with automatic state tracking
- In-app notifications on host up/down state transitions

### 💥 Flood Test
Execute high-frequency ICMP pacing tests to isolate unstable links.
- 100 or 1000 packet bursts
- Real-time per-packet sequence grid (success / jitter / failed / pending cells)
- Streaming diagnostic log and summary metrics: avg / min / max / p95 RTT, jitter, max consecutive loss streak
- In-app notification on test completion with full summary

### 🗺 Network Topology (Traceroute)
Visual hop-by-hop traceroute with automatic GeoIP enrichment.
- Latency status bars per hop (good / warn / bad)
- Background GeoIP enrichment — country, city, org, and ASN fetched after the trace completes
- CSV export of full hop analysis including geographic and ASN data

### 📊 Advanced Diagnostics (8 tools)
- **TCP Ping** — SYN reachability test with RTT on any port; configurable target port (default 443)
- **MTR-style** — multi-round traceroute aggregation with configurable round count; per-hop loss %, avg / best / worst RTT, and worst-hop identification
- **DNS Toolkit** — query A, AAAA, MX, NS, CNAME, or PTR records against both the system resolver and Google (8.8.8.8) simultaneously; results shown side-by-side
- **Port Scanner Lite** — concurrent TCP connect scan across up to 32 ports at once; comma-separated port list input; 900 ms per-port timeout
- **DNS Validation** — checks for presence of A, AAAA, NS, SOA, and CAA records and produces a health score from 0–100 with per-check pass/fail detail
- **Multi-Resolver Health** — compares A, AAAA, and NS records across System, Cloudflare (1.1.1.1), and Google (8.8.8.8) resolvers to surface split-horizon configurations or DNS poisoning
- **DMARC Inspector** — fetches the `_dmarc.<domain>` TXT record, parses all policy tags (`v`, `p`, `rua`, `ruf`, `pct`, etc.), and flags missing or misconfigured values
- **WHOIS / RDAP** — API-key-free. IPv4/IPv6 addresses use the RDAP protocol with IANA bootstrapping to the correct RIR (ARIN, RIPE, APNIC, LACNIC, AFRINIC); domains follow the IANA referral chain via raw Port 43 TCP sockets to the authoritative registrar WHOIS server; results include copy and TXT export

### 🔍 Recon Toolkit (4 tools)
Passive reconnaissance tools for domains, hosts, and web targets.
- **SSL/TLS Inspector** — full certificate chain analysis: TLS version (1.2/1.3), subject, issuer, serial number, Subject Alternative Names, chain depth, expiry countdown in days, and expired/valid status pill; configurable port (default 443)
- **HTTP Headers** — sends a HEAD request (falls back to GET on 405) and displays the final URL after all redirects, HTTP status code, and the complete set of response headers
- **Tech Detect** — fingerprints a URL via response headers and HTML body patterns; identifies CMSs (WordPress, Drupal, Joomla, Ghost), e-commerce platforms (Shopify, WooCommerce, PrestaShop), JS frameworks (React, Vue, Angular, Next.js, Nuxt, Svelte), CSS frameworks (Bootstrap, Tailwind), CDNs (Cloudflare, Varnish), cloud providers (AWS, Azure), analytics tools (Google Analytics, GTM, Matomo), and more
- **MAC Address OUI Matcher** — identifies the hardware vendor from a MAC address using a bundled SQLite OUI database (~5.8 MB); sub-millisecond lookups with no internet access required; accepts colon, hyphen, or dot-separated MAC formats

### 🔔 In-App Notifications
- Persistent notification panel accessible from the top nav
- Captures ping up/down transitions, flood test completions, and traceroute completions
- Up to 100 entries retained per session; one-click clear all

### ⚙️ Settings & Window Utilities
- Persistent JSON settings file in the Tauri app data directory — survives app restarts
- Stores: ping favorites, audio alert preference, always-on-top state
- **Always-on-top** — pin the window above all other applications via the pushpin button in the top-right nav; state persists across restarts

---

## System Requirements

### Windows (pre-built installer)
| | Minimum |
|---|---|
| **OS** | Windows 10 version 1803 or later (64-bit) |
| **WebView2** | Included with Windows 11; auto-installed by the NSIS setup on Windows 10 |
| **RAM** | 150 MB available |
| **Disk** | ~30 MB for the installed app |
| **Network** | Standard TCP/IP stack; ICMP not blocked by firewall for ping/traceroute features |

### Linux & macOS (source build)
See [Building from Source](#building-from-source) for all prerequisites.

---

## Installation

### Windows — Pre-built Installer (Recommended)

1. Go to the [Releases](https://github.com/GChavez0210/NetPulse/releases) page.
2. Download `NetPulse_0.5.1_x64-setup.exe` from the latest release.
3. Run the installer — it will install NetPulse and (on Windows 10) automatically install the Microsoft WebView2 runtime if missing.
4. Launch **NetPulse** from the Start Menu or Desktop shortcut.

> **Note on firewall/ICMP:** Ping, flood test, and traceroute features require ICMP to not be blocked by your Windows Firewall or network policy. If those features return no results, check that inbound/outbound ICMP Echo is allowed.

---

## Cross-Platform Support

| Platform | Status | Notes |
|---|---|---|
| **Windows 10/11** | ✅ Full support | Primary development target; pre-built installer provided |
| **Linux** | 🟡 Source build | Requires `traceroute` package installed (`sudo apt install traceroute` on Debian/Ubuntu). All features functional. |
| **macOS** | 🟡 Source build | The "Don't Fragment" flag in Multi-Target Ping uses Linux's `-M do` syntax and will not apply on macOS (the flag is silently ignored). All other features functional. |

NetPulse is built on **Tauri 2**, which is fully cross-platform. The Rust backend uses `cfg!(target_os = "windows")` branches to switch between Windows and Unix semantics for ping, traceroute, and process flags — so the app compiles and runs correctly on all three platforms. Pre-built packages for Linux (`.AppImage`, `.deb`) and macOS (`.dmg`) are planned for a future release.

---

## Building from Source

### Prerequisites

| Tool | Version | Notes |
|---|---|---|
| **Node.js** | 18+ | [nodejs.org](https://nodejs.org/) — LTS recommended |
| **Rust & Cargo** | Stable | Via [rustup.rs](https://rustup.rs/) |
| **Tauri CLI** | Included | Installed via `npm install` |

**Installing Rust:**

```bash
# Windows (via winget)
winget install Rustlang.Rustup

# macOS / Linux
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

After installing, open a new terminal and run:
```bash
rustup default stable
```

**Linux — additional system packages:**

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y \
  libwebkit2gtk-4.1-dev \
  libgtk-3-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  traceroute

# Fedora / RHEL
sudo dnf install webkit2gtk4.1-devel gtk3-devel libappindicator-gtk3-devel librsvg2-devel traceroute
```

**macOS — no extra packages needed** beyond Xcode Command Line Tools:
```bash
xcode-select --install
```

---

### Development

```bash
git clone https://github.com/GChavez0210/NetPulse.git
cd NetPulse
npm install
npm run dev
```

`npm run dev` runs `tauri dev`, which starts the Vite dev server and compiles the Rust backend concurrently. The **first run takes several minutes** while Cargo fetches and compiles all dependencies — subsequent runs are fast.

---

### Production Build

```bash
npm run build
```

Output is placed in `src-tauri/target/release/bundle/`:

| Platform | Output |
|---|---|
| Windows | `nsis/NetPulse_x.x.x_x64-setup.exe` (NSIS installer) |
| macOS | `macos/NetPulse.app` + `.dmg` |
| Linux | `appimage/NetPulse_x.x.x_amd64.AppImage` + `.deb` |

> **Bundled resource:** `assets/oui-database.sqlite` is declared as a Tauri resource and is automatically bundled with the installer. It is opened read-only at startup — no separate setup needed.

---

## Architecture

NetPulse is built on **Tauri 2** — a Rust + WebView desktop framework. The Rust backend handles all privileged operations; the React frontend communicates with it exclusively via Tauri's typed `invoke()` / `listen()` IPC.

### Backend (Rust — `src-tauri/src/commands/`)

| Module | Responsibility |
|---|---|
| `ping.rs` | Spawns the OS `ping` binary; parses RTT from Windows and Unix output formats |
| `flood.rs` | Async flood loop in a `tokio::spawn` task; emits per-packet events to the frontend |
| `trace.rs` | Spawns `tracert` (Windows) / `traceroute` (Unix); returns raw output for frontend parsing |
| `tcp.rs` | `tokio::net::TcpStream` connect with timeout; concurrent port scanning via `futures::join_all` |
| `dns.rs` | `hickory-resolver` with system, Cloudflare, and Google resolvers; DNS validation scoring; DMARC parsing; MTR aggregation |
| `whois.rs` | `reqwest` RDAP for IPs (IANA bootstrapped); async TCP WHOIS with referral chain for domains |
| `recon.rs` | `rustls` sync TLS inspection; HTTP header fetch; crt.sh subdomain enumeration; technology fingerprinting |
| `oui.rs` | `rusqlite` read-only query on bundled OUI database via `spawn_blocking` |
| `geoip.rs` | `reqwest` lookup via `ip-api.com`; skips private/loopback addresses |
| `settings.rs` | JSON settings file read/write in the Tauri app data directory |

**Key crates:** `tauri 2`, `tokio` (full), `reqwest` (rustls-tls), `rusqlite` (bundled), `hickory-resolver`, `rustls`, `x509-parser`, `serde`, `futures`

### Frontend (React — `src/renderer/`)

- **Routing:** single `useState` tab switch in `App.jsx` — no router dependency. All tabs stay mounted to preserve state; inactive tabs are hidden via CSS.
- **Charts:** Recharts `LineChart` for live latency, CSS conic-gradient donut for flood loss rate.
- **Styling:** Tailwind CSS v4 (Vite plugin) + CSS custom properties design system. JetBrains Mono for all data readout, Inter for labels.
- **IPC:** `@tauri-apps/api/core` `invoke()` for request/response commands; `@tauri-apps/api/event` `listen()` for flood test push events.
- **Notifications:** in-app panel component in `App.jsx`; `addNotification` callback passed down to feature tabs.

---

## Built with AI

This application was built using an AI-assisted development workflow powered by **[Antigravity](https://antigravity.google/)**, **[Claude Code](https://claude.ai)** and **[Codex](https://chatgpt.com/codex)**. AI accelerated the creation of the codebase, enabling faster iteration cycles and a consistent architecture across the project.

All system design, validation, and testing remain under developer control.

---

## License

MIT. See [`LICENSE`](LICENSE) for details.

---

*NetPulse by Gabriel Chavez · Developed in Mexico 🇲🇽*
