# Serving NetPulse from a Linux VM, multi-user, in the browser

Feasibility and planning notes. No implementation — this is a scoping document.

## Short answer

The UI ports almost for free. The Rust diagnostics logic ports with modest edits. What
makes this a real project is not the port: it is that NetPulse's design assumptions
invert the moment it stops being a desktop app.

Today every assumption is "one user, their own machine, their own network, their own
credentials." A shared server breaks all four at once. Three specific things carry
nearly all of the cost:

1. **Multi-tenancy in `AppState`** — the backend currently holds one global flood flag,
   one console-session map with guessable IDs, one `known_hosts` file, and one
   settings blob. All of it is written for a single user.
2. **The Console tab** — putting it on a server turns NetPulse into a privileged access
   gateway that receives, holds, and forwards other people's device credentials.
3. **Abuse surface** — ping, flood, port scan, traceroute, DNS and arbitrary HTTP
   fetches, now executed from a server's IP and network position by anyone with a
   login. That is a scan launcher and an SSRF pivot unless it is deliberately fenced.

Rough effort, one competent developer:

| Path | Effort | What you get |
|---|---|---|
| A — Remote desktop (Kasm/Guacamole/xpra) | 1–3 days | Real isolation, no code change, heavy per-user cost, desktop-in-a-tab UX |
| B — Full web port, everything included | 5–7 weeks | A true multi-user web app, including the credential-gateway problem |
| C — Web port with Console and Serial excluded | ~3 weeks | The 80% that is safe to share, desktop app stays the console tool |

**Recommendation: A to prove demand this week, then C.** Option C drops the hardest and
most security-sensitive 40% of the work and the entire compliance question, and the
desktop build keeps doing what it is already good at.

---

## What exists today

- **Frontend** — React 18 + Vite, ~5,500 lines JSX across six feature tabs, plus
  ~2,500 lines CSS. Talks to the backend through exactly three mechanisms:
  - 35 `invoke()` call sites across 10 files
  - 3 global `listen()` subscriptions, all in `FloodTestTab.jsx` (`ping:flood-sample`,
    `ping:flood-done`, `ping:flood-status`)
  - 1 `Channel<ConsoleEvent>` for console byte streaming (`ConsoleTab.jsx`)
  - 2 window-manager calls (`getCurrentWindow().setAlwaysOnTop`) in `App.jsx`
- **Backend** — ~4,500 lines Rust, 31 `#[tauri::command]` handlers registered in
  `src-tauri/src/lib.rs:131`.
- **No `localStorage` anywhere.** All persistence flows through `settings_read` /
  `settings_write` into a single `settings.json` under the app-data dir
  (`src-tauri/src/commands/settings.rs`).
- **Shared state** — one `AppState` struct (`src-tauri/src/lib.rs:9`) holding the flood
  flags, the OUI SQLite connection, the WHOIS rate-limit timestamp, DNS resolvers, an
  HTTP client, and the console session map.

The clean separation is genuinely helpful here. There is no business logic in the
frontend and no UI logic in the backend, so the seam to cut is obvious.

---

## Option A — run the desktop app, stream the desktop

Install NetPulse on the VM and put a browser-accessible remote-desktop layer in front
of it: Kasm Workspaces, Apache Guacamole, or xpra HTML5.

**Why it is worth taking seriously:** with per-session containers, each user gets a
genuinely separate NetPulse process, its own `AppState`, its own `known_hosts`, its own
settings file, and its own console sessions. Every multi-tenancy bug listed below simply
does not exist, because there is no tenancy — there are N single-user apps.

- **Effort:** 1–3 days, essentially all ops.
- **Cost:** each session runs a full WebKitGTK browser; budget ~500MB–1GB RAM per
  concurrent user. Copy/paste, file export, and terminal latency are all noticeably
  worse than a native web app.
- **Serial still works**, since it is the same machine — but every user sees and can
  grab the same physical `/dev/ttyUSB*`.

For a team of five in a NOC, this may be the whole answer. For fifty users, it is not.

---

## Option B — port it to a real web application

### B1. Transport layer

Extract the command bodies into a transport-agnostic core crate and add a second thin
adapter beside the Tauri one:

```
netpulse-core/     command logic, no tauri dependency
src-tauri/         existing desktop adapter  (thin)
netpulse-server/   new axum HTTP/WS adapter  (thin)
```

This is the structural decision that keeps the project from forking into two codebases
that drift. Do it first; it is mostly mechanical file movement.

Of the 31 commands:

- **~24 are near-mechanical.** `ping_run`, `port_scan`, `dns_*`, `whois_lookup`,
  `ssl_inspect`, `http_headers`, `tech_detect`, `asn_lookup`, `bgp_looking_glass`,
  `mac_lookup`, `geoip_lookup`, `mtr_run`, `dnsbl_check`, `speed_test` and friends are
  request-in / JSON-out. They lose the `#[tauri::command]` attribute and gain an axum
  handler. The bodies barely change.
- **7 need real rework:**
  - `flood_start` / `flood_cancel` — uses `app_handle.emit()` to broadcast globally
    (`flood.rs:202`). On a server, that broadcasts one user's flood samples to every
    connected client. Must become a per-connection WebSocket stream.
  - `console_connect` / `console_send` / `console_resize` / `console_disconnect` — see
    B3 below.
  - `settings_read` / `settings_write` — one global JSON blob must become per-user rows.
  - `export_text_file` — currently writes into the server's `~/Downloads`
    (`export.rs:47`). Must become an HTTP response with `Content-Disposition`. The
    frontend already has this fallback path in `utils/exportFile.js`, gated on
    `window.__TAURI_INTERNALS__`.
  - `serial_list_ports` — enumerates the *server's* serial adapters. See B5.

### B2. Frontend layer

Because every backend call already funnels through one `invoke(cmd, args)` signature, a
single adapter module that reimplements `invoke` over `fetch` covers all 35 call sites
with an import change rather than a rewrite. `listen()` and `Channel` both become
subscriptions on one authenticated WebSocket.

Drop or stub: `getCurrentWindow().setAlwaysOnTop` (two sites in `App.jsx`), the tray
icon, the single-instance plugin, and the close-to-tray behaviour in `lib.rs`.

Estimated frontend effort: **3–5 days**, most of it in the console terminal wiring and
in testing that the flood chart still streams smoothly over WS.

### B3. Multi-tenancy — the part that is easy to underestimate

Every item below is a correctness bug the moment there are two users, not a nice-to-have:

- **Flood is globally singleton.** `flood_running` is one `AtomicBool` guarding one
  shared `flood_cancel` flag (`flood.rs:184`). Today that is a correct guard against a
  self-race. On a server it means *the first user to start a flood test locks out
  everyone else*, and any user pressing Cancel cancels the running user's job. Needs
  per-user state plus a global concurrency ceiling.
- **Console session IDs are guessable and unowned.** IDs are `console-1`, `console-2`,
  … from a global counter (`console/mod.rs:291`), and `console_send` looks up purely by
  ID with no owner check (`session_sender`, `console/mod.rs:408`). On a shared server,
  any authenticated user can type into any other user's live SSH session by guessing a
  small integer. Needs unguessable IDs *and* an ownership check on every operation —
  the ID alone is not the fix.
- **`MAX_CONSOLE_SESSIONS = 16` is a global cap**, so one user exhausts the pool for
  everyone. Needs to be per-user.
- **`known_hosts` is a single shared file** (`console/mod.rs:310`). One user trusting a
  host key silently changes the trust decision for everyone else — which defeats the
  point of the changed-key refusal the README (correctly) advertises. Must be per-user.
- **WHOIS rate limiting is a global mutex-held sleep** (`last_whois_ms`). Correct for
  protecting the upstream registry, but with N users it becomes a serialized queue with
  no fairness. Needs a proper queue with backpressure and a per-user quota, or users
  will see WHOIS "hang" for reasons they cannot see.
- **The OUI SQLite connection is one `std::sync::Mutex<Connection>`** held across a
  blocking query inside async code. Fine at one user, a lock convoy at fifty. Wants a
  connection pool or `spawn_blocking`.
- **Process spawning does not pool.** Ping and traceroute shell out to the OS binaries
  (`ping.rs`, `trace.rs:28`). Each monitored host is a process. Fifty users with ten
  monitors each is 500 processes cycling continuously. Needs a bounded worker pool and
  a per-user monitor cap.

Estimated: **1.5–2 weeks**, and this is the work most likely to be skipped and then
found in production.

### B4. Authentication and accounts

Nothing exists today — there is no user concept anywhere in the codebase. Cheapest
credible path is a reverse proxy with forward-auth (oauth2-proxy or Authelia) in front
of the server, with the app trusting a signed identity header, plus per-user rows in
SQLite replacing the settings JSON blob. Add an admin role for the abuse controls in B6.

Estimated: **4–6 days** including per-user settings migration.

### B5. Features whose meaning changes

These are product decisions, not porting bugs, and they need an explicit answer before
you build:

- **Ping, traceroute, MTR and DNS now measure the server's vantage point**, not the
  user's. For a NOC wanting one consistent vantage point, that is an upgrade. For a
  support engineer debugging their own connectivity, it is now the wrong answer, and
  the UI should say which vantage point it is reporting from.
- **Speed Test measures the VM's bandwidth**, identically for every user, and burns
  real egress each time it runs. Consider removing it in web mode, or caching one
  result and labelling it "server uplink."
- **Serial has no sane multi-user story.** `/dev/ttyUSB0` is one physical cable on one
  machine. Options: drop the feature in web mode, or gate it to admins with an
  exclusive per-port lock and a clear "who holds this port" indicator. Do not simply
  expose it — two users on one serial console corrupt each other's sessions silently.
- **The tray icon, always-on-top, and close-to-tray** have no browser equivalent.

### B6. Security — the item that decides the size of the project

Read this section before committing to Option B.

**NetPulse is, by design, a network-attack-surface generator.** That is entirely fine on
a laptop: the blast radius is the user's own machine and their own network position, and
they are accountable for their own traffic. Move it to a server and every one of those
properties inverts.

- **It becomes an SSRF pivot and a scan launcher.** `port_scan`, `http_headers`,
  `tech_detect`, and `subdomains_lookup` fetch arbitrary caller-supplied targets from
  the server. On a cloud VM that includes RFC1918 space, internal service ports, and
  the instance metadata endpoint at `169.254.169.254`. An authenticated user — or
  anyone who phishes one account — gets to probe your internal network from a host
  that is already inside it. Mitigation is a target policy engine: deny-list link-local
  and metadata addresses by default, decide explicitly whether RFC1918 is in or out,
  and resolve-then-validate to avoid DNS rebinding.
- **Flood Test is a DoS tool with your IP on it.** High-rate ICMP, now shared, now
  attributable to your VM rather than to the person who ran it. You need per-user rate
  limits, a global ceiling, target restrictions, and an audit log that names the user
  for every job. Expect an abuse complaint eventually; make sure you can answer it.
- **The Console tab makes this a privileged access gateway.** Today credentials are
  typed on the user's own machine, held in that user's own process memory, and never
  written to disk — the README says so, and the code backs it up. Server-side, those
  same credentials travel over the network to a machine the user does not control, and
  sit in a process shared with every other user. A compromise of the VM, or of the
  process, or a session-ownership bug like the one in B3, exposes everyone's device
  passwords at once. Telnet credentials additionally leave the *server* in plaintext.
  This is no longer a diagnostics tool with an SSH tab; it is a jump host, and jump
  hosts carry audit, session-recording, and credential-vaulting expectations. This is
  the single strongest argument for Option C.
- **TLS is mandatory, not optional.** Passwords are typed into this UI, and WebSockets
  need it anyway.
- **Raw ICMP in a container** needs `NET_RAW` or a tuned `net.ipv4.ping_group_range`,
  plus the `traceroute` package installed. Granting `NET_RAW` widens what a container
  escape gets you — worth noting when the same container also holds SSH credentials.

Estimated for the abuse controls, audit log, and admin view: **~1 week**, and this is
the piece to build early rather than bolt on.

### B7. Operations

Reverse proxy with TLS, systemd unit or container, SQLite (or Postgres) for per-user
settings and audit records, log retention, backup, and a concurrency test that actually
runs twenty simulated users rather than one. Estimated: **~1 week**.

---

## Option C — the recommended shape

Ship a web build that includes Ping, Flood (rate-limited), Topology/Traceroute,
Diagnostics, and Recon. Exclude Console and Serial from the server build entirely;
the desktop app remains the tool for those, where the credential model already works.

That removes B3's hardest items (console ownership, per-user `known_hosts`, session
limits), all of B5's serial problem, and the entire credential-gateway question in B6.

Estimated: **~3 weeks** — roughly one week on the core-crate split and server shim, one
week on multi-tenancy and auth, one week on abuse controls, packaging, and testing.

---

## Suggested sequence

1. **Week 0** — stand up Option A on the VM. It answers "do people actually want this in
   a browser" for the cost of an afternoon, and it is a genuine fallback if the answer
   is "only three of us."
2. **Step 1** — split `netpulse-core` out of `src-tauri`. No behaviour change, no new
   surface, and it is a prerequisite for everything else. Reviewable on its own.
3. **Step 2** — `netpulse-server` with the ~24 stateless commands, single-user, bound to
   localhost behind an auth proxy. This is the walking skeleton.
4. **Step 3** — auth, per-user settings in SQLite, per-user flood state, WS streaming.
5. **Step 4** — target policy engine, rate limits, audit log, admin view. Before any
   non-trivial user population, not after.
6. **Step 5** — decide Console on the evidence: if it is still wanted after four weeks of
   the rest being live, build it with per-user ownership, per-user `known_hosts`, and
   session audit from the start.

## Open questions to settle before starting

- Who are the users — a trusted internal NOC, or a broader population? This changes the
  target policy from "warn" to "deny by default."
- Is the server's network vantage point the *desired* vantage point, or an accident of
  the port?
- Does the Console tab need to exist on the server at all, given the desktop app ships
  on all three platforms?
- Expected concurrent users? Under ten materially changes the recommendation toward
  Option A.
- Is there a compliance regime (SOC 2, internal privileged-access policy) that a shared
  SSH gateway would fall under?
