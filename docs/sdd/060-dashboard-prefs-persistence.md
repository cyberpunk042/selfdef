# SDD-060 — Operator dashboard preferences (daemon-side persistence + PWA sync)

> Status: **implemented** — Stage-1 doctrine + Stage-2 HTTP surface
> + Stage-2 PWA sync ratified post-implementation. Shipped 2026-05-21
> in commits 8ffdfb8 (daemon-side `GET/PUT /v1/dashboard-prefs` + 7
> unit tests + 4 integration tests + L1 gate) and 87dcdd0 (PWA-side
> `fetchPrefsFromServer` + `syncPrefsToServer` debounced 400ms +
> service-worker SHELL v26 → v27).
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS043 (catalog row "IPS operator surface");
> closes the cross-browser/host preference-sync gap.
> Builds on: SDD-026 (operator dashboard architecture); SDD-056
> (8-tab restructure); SDD-058 (Tier-2 operator-macro auto-load —
> sibling pattern of operator-pull persistence). Layer-up pattern
> documented in `cyberpunk042/devops-solutions-information-hub`
> `wiki/lessons/01_drafts/layer-up-over-crate-already-shipped-
> promotion-pattern.md`.

## Problem

The PWA shipped three UX-mode preference surfaces in MS043 batches
10/11/12:

| Surface | Storage | Shipped |
|---|---|---|
| `selfdef.hiddenPanels` | localStorage | batch 10 (View ▾ menu) |
| `selfdef.refreshRate`  | localStorage | batch 11 (Fast/Normal/Slow/Paused) |
| `selfdef.activePreset` | localStorage | batch 12 (Default/Security/Performance/Inference/Compact) |

Each surface is keyed in the browser's `localStorage`. Consequences:

- Operator on phone PWA → laptop → different host → loses choices
  three times.
- Operator clears browser data → loses all UX customization.
- Operator opens incognito → starts from defaults.
- Operator-team scenarios (multiple humans sharing one selfdef
  daemon, each on their own browser) cannot share a baseline view.

The operator's verbatim direction (2026-05-19, sacrosanct):

> "everything can be turned on and off and there are also a tons
>  of modes and profiles."

"Everything" cannot be turned on/off durably if the on/off state
evaporates with the browser cache. The daemon must be the source
of truth.

## Contract

### C-1 — Wire format

`/etc/selfdef/dashboard-prefs.toml` (env override
`SELFDEF_DASHBOARD_PREFS_PATH`):

```toml
schema_version = "1.0.0"
hidden_panels  = ["raid-section", "storage-section"]
refresh_rate   = "slow"        # fast | normal | slow | paused
active_preset  = "security"    # one of 20: audit-trail | compact | cpu-bound | default | gpu-monitor | health-only | incident-response | inference | inference-throughput | mcp-debug | mcp-tools | models-lab | module-status | network-ops | paused-snapshot | performance | repl-session | security | storage-ops | watchdog-deep
updated_at_ms  = 1737000000000 # server-stamped on every accepted PUT
```

### C-2 — `GET /v1/dashboard-prefs`

- Missing file → **200 OK** with blank-valid body
  (`schema_version = "1.0.0"`, empty `hidden_panels`, `"normal"`,
  `"default"`, `updated_at_ms = 0`).
- Malformed file → **200 OK** with default body (we do **NOT**
  500 on disk corruption; the dashboard losing all UX state on
  one parser error is a worse failure mode than the operator
  re-PUTting their preferences).
- Well-formed file → **200 OK** with the parsed body.

### C-3 — `PUT /v1/dashboard-prefs`

Body must be a JSON object matching the `DashboardPrefs` shape minus
`updated_at_ms` (server-stamped). Validation:

| Field | Constraint | Failure code |
|---|---|---|
| `schema_version` | must equal server's `"1.0.0"` | **409 Conflict** |
| `refresh_rate`   | ∈ {fast, normal, slow, paused} | **400 Bad Request** |
| `active_preset`  | ∈ {audit-trail, compact, cpu-bound, default, gpu-monitor, health-only, incident-response, inference, inference-throughput, mcp-debug, mcp-tools, models-lab, module-status, network-ops, paused-snapshot, performance, repl-session, security, storage-ops, watchdog-deep} — 20-preset table per batch-17 expansion | **400 Bad Request** |
| `hidden_panels`  | any `Vec<String>` (no enum constraint — section IDs may grow over time) | n/a |

On success: write the validated body to the on-disk path via
**atomic temp-file-then-rename** (echoes SDD-026 Z-3 / SDD-058 D-2
"broken file MUST NOT brick the system" pattern). Server stamps
`updated_at_ms` from `SystemTime::now()`. Returns **200 OK** with
the persisted body.

### C-4 — PWA sync semantics

- `fetchPrefsFromServer()` runs once at module load, AFTER
  `switchTab(parseTab())`. Server preferences overwrite localStorage
  if reachable.
- Every `writeHiddenPanels` / `writeRefreshRate` / `writePreset`
  call schedules a PUT via `schedulePrefsSync()` (debounced 400ms).
  Burst-of-changes (operator toggling 5 checkboxes in 2s) collapses
  to ONE round-trip.
- In-flight PUT collision: a second `schedulePrefsSync()` during an
  in-flight PUT re-queues so the latest body always wins (no lost
  writes from race).
- Any fetch/PUT failure (offline / file:// / daemon down / 5xx) is
  **silent** — localStorage stays authoritative; the next change
  re-attempts.
- 400/409 (operator on stale build, unknown enum, schema mismatch)
  log a `console.warn` so the divergence is visible in DevTools.
  No infinite retry.

### C-5 — Offline-first invariant

The PWA must remain fully usable when the daemon is unreachable.
localStorage is the offline fallback; every preference handler
writes localStorage FIRST then asks for a server sync. If the
server is down, the operator's UI experience is unchanged — just
not synced.

## Decisions

### D-1 — TOML on disk, not JSON

Consistent with the rest of selfdef's on-disk config (`selfdef.toml`,
`flex-profile`, module manifests, `/etc/selfdef/modules/*.toml`).
Operator-readable + editable from a text editor. Wire format on
HTTP is JSON (axum-native + browser-native); the daemon transcodes.

### D-2 — Server wins, no timestamp arbitration on the client

Two possible models:
1. **Client-side arbitration**: client compares
   `client_updated_at_ms` with `server_updated_at_ms`, takes
   newer.
2. **Server wins**: server is source of truth; client adopts
   on fetch.

We chose model 2. Rationale: the client PUTs on every change
(debounced 400ms) so divergence windows are sub-second. A
sophisticated reconciliation model is unnecessary at this
divergence scale. If the operator changes preferences on two
browsers within the SAME 400ms window, the second PUT wins —
acceptable for view-customization preferences.

### D-3 — Malformed file → default body, not 500

A SyntaxError in `dashboard-prefs.toml` (operator hand-edited it
incorrectly, partial write crashed mid-edit, disk corruption)
must NOT 500 the dashboard. Returning the blank-valid default lets
the operator re-PUT from the UI and recover.

This echoes SDD-058 D-3 (broken `repl-macros.py` MUST NOT brick
the REPL). The "resilient default" pattern is doctrine across
operator-pull surfaces.

### D-4 — Debounce 400ms

Operator toggling visibility checkboxes naturally bursts (5-10
toggles in 1-2 seconds while configuring). Each toggle calling
`writeHiddenPanels` ⇒ one PUT would generate 5-10 round-trips +
5-10 atomic disk writes for a single semantic action. 400ms
debounce coalesces a typical burst into ONE PUT.

Trade-off: an operator who flips visibility then closes the tab
within 400ms loses the change. Acceptable — the tab-close
contract for browsers doesn't guarantee any async-work completion
either way.

### D-5 — Atomic write via temp-file-then-rename

Same primitive as `selfdef-flex-profile` (SDD-026 Z-3 mutation
surfaces). Crash mid-write leaves either the OLD file intact OR
the NEW file present; never partial.

### D-6 — `hidden_panels` is unconstrained `Vec<String>`

`refresh_rate` + `active_preset` are validated against fixed enum
tables. `hidden_panels` is NOT — section IDs may grow over time as
new dashboard panels ship. Validating against today's 16-section
table would force every section addition through this SDD.

The dashboard simply ignores unknown section IDs in
`applyHiddenPanels()` (querying `document.getElementById(id)`
returns null + the loop continues). Forward-compatible by default.

## Test plan

### Unit tests (`crates/selfdef-api/src/dashboard_prefs.rs::tests`)

7 tests covering the daemon-side primitives:

1. `default_prefs_have_sensible_defaults` — serde Default impl
2. `missing_file_returns_blank_but_valid` — GET semantics on
   missing path
3. `round_trip_via_disk` — TOML serialize → atomic_write → read
   → deserialize equality
4. `malformed_file_returns_default_not_error` — D-3 resilience
5. `valid_rates_table_matches_dashboard_factors` — coherence
   with `REFRESH_RATE_FACTORS` in `dashboard/app.js`
6. `valid_presets_table_matches_dashboard_presets` — coherence
   with `PRESETS` in `dashboard/app.js`
7. `atomic_write_creates_parent_dir` — D-5 ergonomic

### Integration tests (`crates/selfdef-api/tests/m12_api.rs`)

4 tests against the live axum router:

1. `dashboard_prefs_get_returns_default_when_file_missing` — C-2
2. `dashboard_prefs_put_rejects_unknown_refresh_rate` — C-3 400
3. `dashboard_prefs_put_rejects_unknown_active_preset` — C-3 400
4. `dashboard_prefs_put_rejects_schema_version_mismatch` — C-3 409

### L1 gate

`scripts/test/L1-api-endpoints.sh` checks the route literal exists
in `crates/selfdef-api/src/lib.rs`. Drift detector — fails CI if
the route gets removed in a refactor.

### Manual smoke (PWA side)

- Load dashboard fresh → `GET /v1/dashboard-prefs` fires, server
  defaults adopted.
- Toggle 3 visibility checkboxes within 1s → ONE PUT after 400ms.
- Switch refresh rate to Slow → PUT, server file updated.
- Switch preset to Security → PUT.
- Stop daemon → toggle visibility → localStorage updates, PUT
  fails silently, dashboard stays functional.
- Restart daemon → next visibility change PUTs the current state
  (recovery).

## Migration

None. The PWA's old localStorage state is the seed value for the
first PUT after fetchPrefsFromServer returns the default. Existing
operators see no disruption.

## Risk + benefit

**Risk**: minimal. The HTTP surface is opt-in (PWA falls back to
localStorage if daemon is unreachable). Resilience to malformed
files + missing files documented. Atomic-write primitive proven
in flex-profile.

**Benefit**: closes the cross-browser/host preference-sync gap.
The operator's UX-mode triad (visibility + refresh rate + preset)
now persists at the daemon, not per-browser. An operator-team
scenario gains a shared baseline. Mobile PWA ↔ laptop ↔ different
host all see the same view.

## Out-of-scope (future SDDs)

- **Per-operator preferences**: today the daemon serves ONE prefs
  file for all operators connected to that selfdef instance. The
  authorize-+-multi-tenant arc is a separate Stage-3 SDD when an
  operator-identity surface ships (SDD-049 authority + SDD-035
  capability-tokens are the upstream foundations).
- **Distinct dashboard URL paths**: the operator's "20 dashboards"
  verbatim direction. Per-path service worker shells +
  per-path preference files. Tractable Stage-2 once one or two
  operator-named presets prove operationally useful.
- **Schema migration tooling**: when `schema_version` rolls from
  "1.0.0" to "2.0.0", a doc + automatic-upgrade path. Today the
  daemon 409s and the operator runs a future `selfdefctl dashboard
  upgrade-prefs` CLI to convert. Defer until needed.

## Closure

MS043 evidence row now documents the daemon-side persistence +
PWA sync layer. The UX-mode triad shipped in batches 10/11/12 is
now persistent across browser/host boundaries. SDD-026 dashboard
architecture is reaffirmed (this SDD is an additive layer, not
a replacement).
