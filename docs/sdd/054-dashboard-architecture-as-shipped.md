# SDD-054 — Dashboard architecture as shipped (MS011 retrospective)

> Status: **implemented** — Stage-2 architectural spec documenting
> the dashboard's actual shipped state as of 2026-05-21. SDD-026
> Z-1 originally specified an 8-tab UX restructure; the PWA today
> ships a 17-panel single-page-with-anchor-nav layout. This SDD
> canonicalizes that as-shipped architecture so it isn't drift
> against SDD-026 — it's an evolution.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS011 (catalog
> `backlog/milestones/MS011-operator-dashboard-and-flex-profile.md`)
> Builds on: SDD-026 (operator-dashboard-and-flex-profile;
> original Z-vector ratification source — many Z-vectors have
> shipped at probe/discovery level)
> Companions: SDD-009 (dashboard scoping; design deferred there
> because the prior SDD predates the actual implementation)

## Problem

SDD-026 Z-1 specifies "selfdef-dashboard HTTP UI scaffold (8 tabs:
Models / Modules / Profiles / Hardware / Network / Logs / MCP /
REPL); askama+minijinja+HTMX; ZERO npm-tooling chain". As shipped:

- 17 panels (not 8), single-page-with-anchor-nav (not tabs)
- vanilla JS PWA (not askama+minijinja+HTMX) per SDD-009 + SDD-026
  Z-1 D-1 "ZERO npm-tooling chain" preserved
- Backend serves static files from `/usr/share/selfdef/dashboard/`
  via tower-http `ServeDir` (per L1-dashboard-sections.sh's
  ServeDir / nest_service / DEFAULT_DASHBOARD_DIR checks)

The 8-tab restructure ratified in SDD-026 Z-1 remains a deferred
multi-commit arc. This SDD documents the as-shipped intermediate
state so subsequent SDDs can reason about the actual surface.

## Goals

Document the as-shipped dashboard so:

1. Operators can scan the panel inventory without reading source
2. Future Stage-3 work (Z-1 full 8-tab restructure, Z-12 REPL
   embedded UI, Z-2 LM Studio Models tab) can map panels →
   tabs deterministically
3. The L1 coherence gate continues to enforce panel presence as
   drift detector

## Non-goals

- This SDD does NOT supersede SDD-026 Z-1 (the 8-tab restructure
  remains the future direction)
- It does NOT lock the as-shipped layout — it documents the
  intermediate state on the path to Z-1's final form
- It does NOT cover the Cockpit (separate physical UI; SDD-026 §
  Mission 2 surface)

## Recommended design

### Panel taxonomy (17 panels, as of commit a8cbb26)

Grouped by operator-relevance cluster:

**1. Composite top-of-page**
- `health-section` — `GET /v1/health` composite aggregate (Z-6)

**2. Four-watchdog set (MS044/MS046/MS047/MS048)**
- `friction-audit-section` — MS046 boot-time hardware-integrity gate
- `perimeter-section` — MS047 kernel-fence
- `guardian-section` — MS044 supervisor
- `scheduler-section` — MS048 Goldilocks routing

**3. Module + audit cluster**
- `modules-section` — MS006 module catalog + activation state
- `audit-chains-section` — MS009 per-watchdog audit-chain integrity
- `alerts-section` — MS027 server-side classifier

**4. Host state cluster (the MS011 Z-vector body)**
- `hardware-section` — MS010 + Z-N hardware-aware modules
- `network-section` — Z-7 internet / DNS / cloudflared / tailscale / traefik
- `storage-section` — Z-10 mount usage + log dirs
- `raid-section` — Z-9 /proc/mdstat
- `gpu-section` — Z-5 nvidia-smi watt deviance
- `cpu-section` — Z-4 governor × SMT mode classification
- `flex-profile-section` — Z-3 live delta over baseline
- `inference-backends-section` — Z-2 llama.cpp / vllm / bitnet.cpp / unsloth

**5. Findings tail**
- Findings event-list (MS005 notifier-engine surface)

### Navigation

- `<nav id="panel-nav">` strip at top of `<header>` with 16
  anchor links (one per section + the composite health row).
  Vanilla `<a href="#...">` — no JS framework
- Each panel has its own refresh button + auto-refresh interval

### Refresh interval ladder (operator-cost-tuned)

| Panel | Interval | Rationale |
|---|---|---|
| Composite health | 30 s | Top-of-page glance |
| Status (header) | 5 s | Daemon liveness |
| Friction Audit | 30 s | Rare-change boot gate |
| Perimeter | 15 s | Execve events between refreshes |
| Guardian | 30 s | Supervisor state |
| Scheduler | 10 s | High-frequency routing decisions |
| Modules | 60 s | Package-time changes |
| Audit chains | 30 s | Integrity drift |
| Alerts | 15 s | Chain-broken signals fast |
| Hardware | 5 min | Doesn't hot-swap (server caches) |
| Network | 30 s | Probes systemd + ping |
| Storage | 60 s | df + log-dir walks |
| RAID | 60 s | /proc/mdstat |
| GPU | 10 s | Watt deviance under load |
| CPU | 60 s | Operator-driven mode changes |
| Flex profile | 60 s | Operator-driven |
| Inference backends | 120 s | Install-time bound |

### CSS taxonomy (3 visual color modes)

- `fa-ok` (green) — healthy state
- `fa-degraded` (yellow) — warn state
- `fa-fail` (red) — critical state
- `fa-unknown` (gray) — series not exported / probe not run

Plus 4 watchdog-specific badge classes:
- `fa-aggregate`, `fa-override`, `fa-alert`, `fa-extended`,
  `fa-backpressure` (per four-watchdog set L1 gate)

### Service worker cache invalidation

`dashboard/service-worker.js` carries a SHELL constant (current:
`selfdef-shell-v17`). Bumped on every dashboard commit that
changes app.js / index.html / dashboard.css. The `activate` event
clears any cache that isn't the current SHELL.

### Backend → dashboard contract

Each panel calls `GET /v1/<route>` exactly once per refresh cycle.
The 17 panels collectively consume 14 distinct `/v1/*` routes —
some panels share routes (e.g. composite health + per-watchdog
panels read overlapping data) but the daemon does NOT fan-out per
panel; the dashboard caches nothing.

### L1 drift-detection gate

`scripts/test/L1-dashboard-sections.sh` enforces:

- 1 HTML `id="<panel>-section"` check per panel
- 1 HTML `id="<panel>-aggregate"` check per panel (where applicable)
- 1 JS `function refresh<Panel>()` check per panel
- 1 JS `setInterval(refresh<Panel>` check per panel
- 1 JS `get("/v1/<route>")` check per panel
- ServeDir / DEFAULT_DASHBOARD_DIR / nest_service wiring checks

## Implementation status

All 17 panels shipped end-to-end (HTML + JS + CSS + L1 gate +
backend route). 2026-05-21 session shipped 4 new panels (Flex
profile + Inference backends + Network nav-strip integration).

## Open questions

- **D-1**: Migrate to the 8-tab restructure per SDD-026 Z-1?
  **Recommendation**: yes, but as a separate arc — needs a tab
  framework choice (askama+minijinja+HTMX per SDD-026 vs
  continuing vanilla-JS-PWA). The 17 panels are stable enough
  that a tab restructure becomes an interesting categorization
  exercise + a UX win rather than a rebuild.
- **D-2**: Per-panel show/hide toggle (operator-personalization)?
  **Recommendation**: yes after D-1 — fits "everything can be
  turned on and off" from the operator's standing direction.
- **D-3**: Per-panel "drill-down" pages (a click on a panel opens
  a full-page view with extended detail + history)?
  **Recommendation**: yes for the high-information panels
  (Hardware / Modules / Alerts / Audit chains / Flex profile) but
  defer until the 8-tab structure lands.
- **D-4**: Cockpit panel parity? Tauri-shipped Cockpit (SDD-026
  Mission 2 Cockpit surface) has its own set of panels. Should
  the PWA dashboard mirror Cockpit's panel set or vice versa?
  **Recommendation**: keep separate — the PWA is for remote
  read-only operator views (over SSH-port-forward or tailscale);
  the Cockpit is for local TUI + mutation surfaces.
