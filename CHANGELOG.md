# Changelog

All notable changes to NetPulse are documented in this file.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [0.6.0] — 2026-08-04

A new Console tab: interactive terminal access to network devices over SSH, Telnet, and a serial console cable.

### Added
- **Console tab:** Pick a transport, fill in the connection details, and get a live terminal. Built on xterm.js, so full-screen remote programs — `vim`, `top`, paged `show run` — render properly rather than as escape-sequence noise. Output is carried as raw bytes end to end, so multi-byte UTF-8 characters split across packet boundaries are reassembled instead of corrupted.
- **SSH transport:** Password and OpenSSH private-key authentication, a proper PTY (`xterm-256color`) that tracks the window size, and keepalives. Host keys are verified against a standard OpenSSH `known_hosts` file in the app data directory: a first-time key prompts for confirmation with its SHA-256 fingerprint, and a key that has *changed* is refused outright with no override — that case is what host-key checking exists to catch.
- **Telnet transport:** Full option negotiation (ECHO, SUPPRESS-GO-AHEAD, TERMINAL-TYPE, NAWS) so window size and terminal type reach the device, with literal `0xFF` bytes escaped correctly in both directions. Reachable devices on non-standard ports are supported via the TCP port field — console servers commonly sit on 2001–2048 rather than 23.
- **Serial transport:** The path to a switch that has no IP address yet. The port dropdown lists adapters by manufacturer and product (`COM3 — FTDI FT232R USB UART`) rather than bare device paths, with a refresh button, since USB-serial adapters are plugged in and out constantly. Defaults to 9600 8N1, correct for essentially all network gear; data bits, parity, stop bits, and flow control are available under advanced settings.
- **Multiple concurrent sessions** (up to 16) as renameable tabs, each with its own terminal and scrollback. Sessions stay live while you work in other NetPulse tabs.
- **Terminal tools:** search across scrollback, copy selection, clear, and export the session transcript to a text file.
- **Allow legacy SSH algorithms:** An opt-in toggle that adds `diffie-hellman-group14-sha1`, `ssh-rsa`, CBC ciphers, and HMAC-SHA1 for older Cisco and HPE equipment that offers nothing newer. Modern algorithms stay ahead of the legacy fallbacks in the preference order, so it only widens what NetPulse will accept rather than downgrading connections that do not need it.
- **Local echo toggle (serial)** for devices that do not echo typed characters.

### Security
- Credentials are held in memory only and are never written to `settings.json` or anywhere else on disk. Passwords are zeroized after authentication, and the connection form is cleared once a session is established.
- Telnet is labeled in the UI as sending all traffic, including credentials, in cleartext.
- Console input is bounded (64 KB per chunk) and terminal dimensions are range-checked before reaching a transport.

### Fixed
- **SSH private-key authentication could never succeed.** The connect form takes pasted key material, but the backend passed that text to a loader that expects a filesystem path, so every key-based login failed with a file-not-found error. Pasted keys are now decoded directly, and a failure to read one says whether a passphrase is likely needed.
- **The remote terminal stayed 80×24 on the first session of a run,** regardless of the window size. The size measurement happened while the session was still connecting and had nowhere to report to, and nothing re-sent it afterwards — so full-screen output wrapped at 80 columns inside a much wider window until the app was manually resized.

### Build
- `libudev-dev` added to the Linux release build, required for USB serial-port enumeration.

---

## [0.5.5] — 2026-07-28

Per-tool reset controls, reply-TTL monitoring, and corrections to three diagnostics that were reporting the wrong thing.

### Added
- **Clear buttons on every Diagnostics and Recon tool:** Each of the 15 tool cards now has a trash-icon button that resets just that tool — inputs back to their defaults and results cleared. Disabled while a tool is running or when there is nothing to clear.
- **Reply TTL (Ping tab):** Ping replies now surface their TTL alongside an estimated hop count. A TTL that changes between samples is flagged, since it means the path length shifted — route flapping or an anycast change. Exported to CSV as `Reply TTL` and `TTL Changes`.
- **RTT-over-sequence chart (Flood Test):** Plots latency across the run, with the line breaking at dropped packets rather than drawing through them. Reveals patterns a grid of squares cannot — bufferbloat ramps, periodic spikes, mid-run step changes.
- **CSV export (Flood Test):** Exports every sample with sequence number, timestamp, RTT, and timeout flag, alongside the run summary. Previously the tab generating the richest dataset was the only one with no way to get it out.
- **Per-notification dismiss:** Notifications can be cleared individually, not only via Clear All.
- **Tooltips on flood sequence cells** reporting each packet's sequence number and RTT.
- **Spike Baseline metric (Flood Test)** showing the reference RTT that spike detection is measured against.

### Changed
- **Traceroute summary replaced "Average RTT"** with *To Destination* (last responding hop) and *Worst Jump* (largest hop-to-hop delta, labeled with its hop). Averaging cumulative per-hop RTTs produced a figure that described nothing physical and understated real latency. Each hop row now also shows its own delta, and the worst-jump hop is highlighted.
- **Traceroute latency bars scale to the slowest hop in the run** instead of a fixed 180 ms ceiling, which pegged every bar at 100% on any long-distance route.
- **Tool inputs persist** across runs in Diagnostics, Recon, Traceroute, and Flood Test. Previously a successful run cleared the input, discarding what you had typed.
- **Flood Test loss rate** is now a large figure rather than a donut, which rendered the meaningful 0.5–5% range as an indistinguishable sliver.
- **Flood Test shows the target host** in the results header.

### Fixed
- **Traceroute "Rerun" did nothing after a successful run.** The input was cleared on success, so Rerun immediately failed its own empty-host check. Exported CSVs also recorded an empty `targetHost` for the same reason.
- **Timed-out traceroute hops rendered as a full-width red bar,** reading as the worst latency in the route when they actually mean no data was collected. They now render as a hatched empty track.
- **Ping cards labeled packet loss as "JITTER".** The health check never examined latency variance at all — any lost packet produced a jitter verdict. Loss and jitter are now distinguished: `LOSS`, `JITTER`, `TIMEOUT`, or `STABLE`, with jitter measured from actual latency spread. CSV exports carry the corrected labels.
- **Flood Test classified packets against a fixed 80 ms threshold,** which flagged every packet on a satellite link and no packet on a LAN. Packets are now compared against the run's own baseline (median of the first 20 replies), so a 40 ms spike on a 1 ms LAN registers and a steady 600 ms satellite link does not. The legend now reads *Spike* rather than reusing "Jitter", which the adjacent Jitter/P95 metric already means in the statistical sense.
- **Flood Test gave no feedback** on export, cancel, or start failure — its status toast was rendered but never populated.

### Removed
- Dead code: an unused `jitterCount` recomputed over the full packet array on every sample, and `formatHealthLabel`, which returned a third conflicting label for the ping health state.

---

## [0.5.4] — 2026-07-18

New ISP-oriented diagnostics tools, a reorganized Diagnostics/Recon layout, and a real-data bug fix.

### Added
- **ASN / Network Lookup (Recon):** Looks up the ASN, AS name, BGP prefix, country, and registry currently announcing a given IP via Team Cymru's whois service — real-time BGP data, not just registry records.
- **BGP Looking Glass (Recon):** Queries RIPE RIS route-collector visibility for an IP/prefix via RIPEstat, showing how many peers see it and flagging conflicting origin ASNs (a route-leak/hijack signal).
- **Speed Test (Diagnostics):** Download/upload throughput and latency test against Cloudflare's public speed-test backend, using multiple parallel streams per phase so results hold up on faster links. Shows a live "testing download/upload" indicator with elapsed time while running.
- **Internet-reachability indicator (Ping tab):** The page header now polls `8.8.8.8` every 15s and shows ALL SYSTEMS READY / NO INTERNET CONNECTION / CHECKING CONNECTIVITY, replacing the static "MONITOR ACTIVE" label.
- **Single-instance enforcement:** Launching a second instance now focuses and restores the existing window instead of opening a duplicate process.
- Short descriptions on each Diagnostics tool card explaining what it checks.

### Changed
- **Diagnostics and Recon tabs reordered** by logical workflow: Diagnostics groups connectivity checks → DNS tools → reputation checks; Recon leads with WHOIS and ASN/route-visibility before certificate/HTTP/tech-fingerprinting tools.
- **TCP Ping and Port Scanner merged** into a single "Port Checker" card — one port for a quick reachability check, a list to sweep multiple — removing the redundant `tcp_ping` backend command.

### Fixed
- DNS Validation, Multi-Resolver Health, DNSBL Check, and DMARC Inspector were silently displaying raw JSON dumps instead of their intended formatted text, due to a `rawOutput`/`raw_output` field-name mismatch between the Rust backend and the frontend. All four now render correctly.
- TCP ping, port scan, and MTR results are now parsed into readable summaries instead of raw JSON dumps.

---

## [0.5.3] — 2026-07-12

Visual redesign and tray support — no changes to diagnostic behavior.

### Added
- **Tray:** The app now integrates with the system tray (Show NetPulse / Exit). Closing the window hides it to the tray instead of exiting.

### Changed
- **Theme:** Replaced the green/cyan glass theme with a flat, professional dark theme built around a new orange accent (`#F45A16`), matching the new application icon. Status colors (success/warning/danger) are now distinct from the brand accent instead of overloading it.
- **Icons:** Updated the bundled app icon (Windows `.ico`, macOS `.icns`, and generated PNG sizes) to the new NetPulse mark.
- **Buttons/tabs:** Disabled native button/tab appearance and gave hovered (non-active) nav tabs a solid background, fixing a low-contrast hover state where OS control theming could bleed through.

---

## [0.5.2] — 2026-07-02

Security, stability, and efficiency audit — no new user-facing features.

### Security
- **Fixed:** `ping`/`trace`/`flood`/`tcp` commands now validate hosts before use, rejecting leading-dash values that could be interpreted as CLI flags by the underlying `ping`/`tracert` binaries.
- **Fixed:** Migrated `hickory-resolver` 0.24 → 0.26, closing [RUSTSEC-2026-0119](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-q2qq-hmj6-3wpp) (CPU-exhaustion DoS via O(n²) DNS name compression).
- **Fixed:** Bumped `quinn-proto` to patch a separate high-severity (CVSS 7.5) remote memory-exhaustion CVE.
- **Fixed:** WHOIS rate limiter had a TOCTOU race allowing concurrent lookups to bypass the 2s throttle; now serialized with a held mutex.
- **Fixed:** DNSBL checks reported *any* lookup failure (timeouts, SERVFAIL) as "not listed"; now only genuine NXDOMAIN is treated as clean, other failures as inconclusive.

### Stability
- **Added:** A React error boundary around each tab, so a single bad payload or bug can no longer blank the entire app.
- **Fixed:** `ping_run`/`ping_sample` had no timeout and could hang indefinitely.
- **Fixed:** `flood_start` could spawn unbounded concurrent jobs sharing one cancel flag; now a second flood run is rejected while one is active.
- **Fixed:** MTR diagnostic silently swallowed errors, leaving the UI stuck on "Running…"; diagnostic and DNS panel buttons now guard against overlapping in-flight requests.
- **Fixed:** A slow, superseded GeoIP lookup batch could overwrite a newer traceroute's results, and could leave its loading indicator stuck.
- **Fixed:** `dns_query` collapsed "lookup failed" and "no records found" into the same empty, successful result; the two are now distinguished.

### Efficiency
- **Changed:** DNS resolvers and the HTTP client are now built once and reused via shared app state instead of being rebuilt (and losing caches/connection pools) on every call.
- **Changed:** Memoized the flood test's packet grid/log rendering, ping KPI aggregation, and WHOIS presentation to cut unnecessary re-renders.

---

## [0.5.1] — 2026-06-13

Release-pipeline maintenance only — no changes to application behavior.

### Changed
- **CI:** Dropped the macOS Intel (`x86_64`) build target. The `macos-13` job hung for 24 hours on the v0.5.0 run and was force-cancelled, which is why v0.5.0 shipped without a macOS Intel installer. macOS builds now target Apple Silicon (`aarch64`) only.
- **CI:** Added a 30-minute `timeout-minutes` to the release job so a hung build fails fast instead of stalling the whole release for 24 hours.
- **CI:** Opted into the Node.js 24 Actions runner ahead of the June 2026 forced cutover (carried over from v0.5.0).

---

## [0.5.0] — 2026-05-22 🎉 First Release

### Added

#### Recon Toolkit (new tab — 4 tools)
- **SSL/TLS Inspector** — full certificate chain analysis: TLS version (1.2/1.3), subject, issuer, serial number, SANs, chain depth, expiry countdown, and expired status. Runs on a dedicated blocking thread via `rustls` sync I/O to prevent async hangs on filtered ports.
- **HTTP Headers** — HEAD/GET request inspector showing final URL after redirects, HTTP status code, and all response headers in a readable table. Automatically falls back to GET if the server returns 405 for HEAD.
- **Tech Detect** — fingerprints websites via response headers and HTML body patterns. Detects CMSs (WordPress, Drupal, Joomla, Ghost), e-commerce platforms (Shopify, WooCommerce, PrestaShop), JS frameworks (React, Vue, Angular, Next.js, Nuxt, Svelte), CSS frameworks, CDNs (Cloudflare, AWS, Azure, Varnish), analytics tools (Google Analytics, GTM, Matomo), and more.
- **MAC Address OUI Matcher** — identifies hardware vendor from a MAC address using a bundled SQLite OUI database (~5.8 MB, opened read-only at startup); sub-millisecond lookups with no internet access required.

#### Network Features (prior work, included in this release)
- **Multi-Target Ping** — simultaneous continuous ICMP monitoring with live Recharts latency graphs, configurable packet size and DF flag, custom ping intervals (0.5–10 s), host aliases, drag-and-drop card reordering, named Favorites groups, audio alerts, CSV export with alias column, and global KPIs (avg RTT, avg loss, active monitors).
- **Flood Test** — high-frequency ICMP test (100 or 1000 packets) with per-packet sequence grid, streaming diagnostic log, and summary metrics (avg/min/max/p95 RTT, jitter, max consecutive loss streak).
- **Network Topology (Traceroute)** — hop-by-hop visual traceroute with latency status bars and background GeoIP enrichment (country, city, org, ASN) per hop. CSV export.
- **Advanced Diagnostics** — 8 tools in the Diagnostics tab: TCP Ping, MTR-style multi-round traceroute aggregation, DNS Toolkit (A/AAAA/MX/NS/CNAME/PTR against system + Google resolvers), Port Scanner Lite (up to 32 concurrent ports), DNS Validation (health score 0–100), Multi-Resolver Health (compares System / Cloudflare / Google resolvers), DMARC Inspector, and WHOIS / RDAP.
- **In-App Notifications** — persistent panel capturing ping up/down transitions, flood test completions, and traceroute completions. Up to 100 entries per session.
- **Settings** — persistent JSON settings file in the Tauri app data directory; survives restarts. Stores ping favorites, audio alert preference, and always-on-top state.
- **Always-on-top** — pin the window above all other applications from the top nav; state persists across restarts.

### Changed
- WHOIS reworked to use RDAP for IP addresses with full IANA bootstrapping for correct RIR resolution, replacing the previous single-endpoint approach.
- SSL inspection rewritten to use blocking `rustls` sync I/O (via `spawn_blocking`) to prevent async TLS handshake freezes on filtered or slow ports.
- crt.sh subdomain lookup redesigned with 2-attempt retry logic, HTTP 502/503/429 error messages with actionable guidance, and response body preview on JSON parse failures.
- MAC OUI Matcher UI moved from a standalone section into the Recon Toolkit tab.
- Multi-target ping feature description revised for clarity.

---

*Unreleased changes appear above this line once the next version is drafted.*
