# Changelog

All notable changes to NetPulse are documented in this file.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

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
