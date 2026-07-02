# Operator surfaces

selfdef ships **one super-dashboard and four individual surfaces**. They all
render the same daemon state (the API is the single source of truth — see
[HTTP API](./api.md)); they differ in where you are when you need them.

| Surface | Where | What it is | When to reach for it |
|---|---|---|---|
| **Bundled dashboard (PWA)** | `http://<host>/dashboard` (served by `selfdefd` from `/usr/share/selfdef/dashboard`) | The **super-dashboard**: ~30 sections covering daemon health, the four-watchdog set, module catalog, audit chains, alerts, hardware (CPU/GPU/RAID/storage/network), boundaries (filesystem/network/communication), authority (capability tokens, commit authority, trust scores, sandbox tiers, quarantine), flex-profile and inference backends. Installable as a PWA (works on a phone). Read by default; control actions (panic, action-run, rule-reload) require operator confirmation. | Full-fidelity overview; incident triage from anywhere the API is reachable. |
| **`selfdefctl` (CLI)** | any shell on the host | 50+ subcommands (schema introspected by `selfdef-cli-mirror`); every mutating subcommand requires an MS003 signature. Shell completions ship for bash/fish/zsh under `completions/`. | Scripting, precision, `selfdefctl notify resend`, day-to-day per the [operator cheatsheet](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator-cheatsheet.md). |
| **TUI** | `selfdefctl tui` on the host | Canonical 4-panel layout — **rules / grants / quarantine / authority** (schema in `selfdef-tui-mirror`; doctrine: "A dashboard should not show vanity graphs"). Keyboard-driven (j/k/h/l/Enter/q/?). | SSH session, no browser. |
| **Minimal web** | `https://localhost:7575` (`selfdef-web`) | The same 4 panels as the TUI, as a sovereignty-clean static bundle + SSE 2s refresh. Read-only by default; mutations gated on an operator MS003 key upload. | TUI unavailable, but you're on the host; air-gapped fallback. |
| **Grafana** | your Grafana, via the `observability` module | `selfdef.json.template` — 37 panels (Tetragon health, event/finding rates, four-watchdog trends, M060 mirror-export health, daemon liveness, federation trust) + 21 Prometheus alert rules, every alert carrying a `runbook_url` into the info-hub. See `modules/observability/README.md`. | Fleet view, history, alerting. |

Beyond the host, the **sovereign-os cockpit** renders selfdef state read-only
through the 14 `selfdef-*-mirror` crates (M060 publishers) — that is the
cross-repo view, not a selfdef surface per se.

> **PWA offline-shell caveat (bearer-token TCP):** browsers never attach
> custom headers to a service-worker script fetch, so over the plain
> bearer-token TCP transport the offline shell logs a one-time 401 and is
> skipped (registration is best-effort by design; every section still
> renders). The offline shell activates on transports where the browser
> itself can authenticate — a reverse proxy in front, or mTLS.

## Coherence guarantees (why the surfaces can't drift)

The surfaces are contract-locked, not convention-locked:

- `selfdef-ux-harness` (systemd timer + CI) validates the CLI subcommand
  list, TUI panels, minimal-web panels, and mirror-crate list against their
  schemas — 10 checks, L1.
- `scripts/test/coherence.sh` runs 13 layers in CI, including
  `L1-dashboard-sections` (every PWA section has a handler, an interval,
  and a real API endpoint) and `L1-api-metric-observability-coverage`
  (every `/metrics` family has a Grafana/alert home).
- The 4-panel layout is defined ONCE (mirror crates) and consumed by both
  the TUI and the minimal web — consumers may not synthesize panels.

If you add a surface element, the matching gate must learn about it in the
same change, or CI fails.
