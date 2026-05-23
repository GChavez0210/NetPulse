# Changelog

All notable changes to NetPulse are documented in this file.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

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
