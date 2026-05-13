# Documentation audit

> Scope: repo-root docs (README, ARCHITECTURE, SECURITY, CHANGELOG)
> + `docs/src/` mdbook + per-module READMEs. Per-area finding ids
> prefix `D-`.

The repo has more documentation than most projects this size,
but the documentation has accumulated drift in proportion to the
PR cadence. Three classes of issues dominate:

1. **Stale status claims** in load-bearing docs (README, modules.md).
2. **Orphan docs** under `docs/` that aren't in mdbook's
   `SUMMARY.md` outline.
3. **Stub docs** referenced from `SUMMARY.md` that are one-line
   `# TODO` placeholders.

The per-module READMEs are mostly accurate; the central docs are
the ones that lag.

---

## Repo-root docs

### README.md

Line 7:

> Status: Milestone 1 — Foundation. Scaffolding only; not runnable yet.

False. Fifteen milestones are listed as complete in the same
file. The module catalog ships nine production-ready modules. A
host can fully apply via `selfdefctl modules apply`. The status
banner is the first thing a new reader sees and it lies.
**(D-001)**

The README also doesn't list the module catalog anywhere. A
reader has to navigate to `docs/src/modules-roadmap.md` to learn
what ships. **(D-002)**

### ARCHITECTURE.md

Missing the `/metrics` endpoint (added in PR #23). The diagram
of subsystems and event flow doesn't show Prometheus as a
consumer of the API surface. **(D-003)**

The AI-machine track (tetragon substrate + agent-guard policy
bundle + observability) isn't mentioned. ARCHITECTURE.md still
reads as if the daemon is the only end-state; the module catalog
isn't surfaced. **(D-004)**

### SECURITY.md (root, duplicated as `docs/src/security.md`)

Three new attack surfaces shipped in the recent PRs are not in
the threat model:

- The `/metrics` endpoint. Even though metrics are
  lower-sensitivity than raw events, they fingerprint host
  activity. Not mentioned. **(D-005)**
- `/etc/tetragon/tetragon.tp.d/` (writable policy directory). An
  attacker with write access to this directory can inject
  TracingPolicies into the kernel. Not mentioned. **(D-006)**
- Pod-label scope in `agent-guard` v0.3.0. A compromised pod with
  the configured label fires agent-guard policies; an attacker
  who can set labels could shift which workloads fall under the
  policy. Not mentioned. **(D-007)**

### CHANGELOG.md

Ordering is correct (newest first). Two issues:

- PR #22's CHANGELOG entry lists the `observability` module
  under the AI-machine track but doesn't make the
  Prometheus/Grafana scope ("we configure, we don't install")
  explicit. A reader might assume the module deploys a
  Prometheus binary. **(D-008)**
- PR #22's entry doesn't acknowledge that the three new modules
  introduce new attack surfaces — cross-referenced with D-005,
  D-006, D-007.

---

## mdbook (`docs/src/`)

### SUMMARY.md

Every page referenced from SUMMARY.md exists, but five of them
are one-line `# TODO` stubs:

- `dev/build.md`
- `dev/collector.md`
- `ops/config.md`
- `ops/install.md`
- `ops/notifications.md`

Following the SUMMARY links from any of these is a dead end for
a new operator. **(D-009)**

### Orphan docs not in SUMMARY.md

Files exist under `docs/` (note: at the repo root, not
`docs/src/`) that the mdbook outline never references:

- `docs/api.md` — HTTP API + auth + TLS guide.
- `docs/ebpf.md` — custom eBPF programs.
- `docs/nats.md` — NATS bridge configuration.
- `docs/ssh-wrap-install.md` — SSH wrapper install guide.

These are real, useful documents. A reader who navigates mdbook
will never see them. **(D-010)**

### `docs/src/modules.md`

Lines 202–207:

> Only `detect-host` ships as a manifested module at the time of
> this writing — every other entry is `planned` or `absorbing`.

False. Every module in the catalog ships. This page predates the
module absorption blitz and was never refreshed. **(D-011)**

### `docs/src/modules-roadmap.md`

This file is the most up-to-date catalog doc. Current state
table is accurate. Two minor lags:

- Already updated through PR #25 in the previous review pass
  (good).
- The "What's there today" / "Remaining work" prose at the
  bottom still treats GPU-device-guard and pod-label scope as
  shipped, but the prose can be tightened to a single
  "everything from the original roadmap is in the catalog;
  follow-ups in `docs/review/`" pointer when this review lands.
  Cross-listed to ledger but no separate finding.

---

## Per-module READMEs

Spot-check results:

- `modules/agent-guard/README.md` — config keys match scripts;
  scope section matches the new `scope` knob; example block
  defaults match the profile files. Clean.
- `modules/tetragon/README.md` — clean except for the wrong
  collector reference flagged in the integration audit (I-006).
  Same issue here: README says "configure
  `[collectors.eventstream]`" which is incorrect. Cross-listed
  from I-006.
- `modules/observability/README.md` — README's documented
  default `scrape_targets = "localhost:2112"` (single target,
  Tetragon only) contradicts the shipped profile defaults
  (`localhost:2112, localhost:8443` — two targets). Cross-listed
  from M-005.
- `modules/observability/README.md` — dashboard panel list does
  not mention the selfdef-daemon metrics panels (events by
  class, findings by severity, store size). Cross-listed from
  M-006.
- `modules/integrity-sentinel/README.md` — config and lifecycle
  documented; matches scripts and profiles. Clean.
- `modules/vpn-bridge/README.md` — does not warn about the
  multi-instance state corruption flagged in M-008. **(D-012)**
- Other modules (bridge-l2, suricata, polarproxy, detect-host)
  — clean.

---

## Drift between repo-root and `docs/src/`

The repo-root README says the project is at Milestone 1. The
mdbook `modules-roadmap.md` says fifteen milestones plus a full
module track are shipping. Both pages are linked from the project
landing page. A new reader sees contradictory claims about
maturity. The fix is to rewrite the README status banner (D-001)
and surface the module catalog (D-002).

---

## Findings raised in this section

| Id | Severity | Surface | Summary |
| --- | --- | --- | --- |
| D-001 | important | `README.md` line 7 | Status banner says "Milestone 1 — Scaffolding only". Project ships nine production modules + full daemon. |
| D-002 | nice | `README.md` | No catalog of shipped modules; reader has to dig to `docs/src/modules-roadmap.md` to find what's available. |
| D-003 | important | `ARCHITECTURE.md` | `/metrics` endpoint missing from the architecture description. |
| D-004 | important | `ARCHITECTURE.md` | Module catalog (especially the AI-machine track) not represented. Diagram is daemon-centric and predates the modules. |
| D-005 | important | `SECURITY.md` / `docs/src/security.md` | `/metrics` endpoint not in threat model. |
| D-006 | important | `SECURITY.md` | `/etc/tetragon/tetragon.tp.d/` writable directory not in threat model — eBPF policy injection vector. |
| D-007 | important | `SECURITY.md` | Pod-label scope's reliance on label integrity not in threat model. |
| D-008 | nice | `CHANGELOG.md` PR #22 entry | Observability scope ("we configure, we don't install") implicit; should be explicit. |
| D-009 | important | `docs/src/{dev,ops}/*.md` | Five stub pages (`dev/build`, `dev/collector`, `ops/config`, `ops/install`, `ops/notifications`) are one-line TODOs but linked from SUMMARY.md. |
| D-010 | important | `docs/api.md`, `docs/ebpf.md`, `docs/nats.md`, `docs/ssh-wrap-install.md` | Real operational guides orphaned from mdbook's outline. |
| D-011 | important | `docs/src/modules.md` lines 202-207 | Stale claim that "only `detect-host` ships". Every module ships. |
| D-012 | nice | `modules/vpn-bridge/README.md` | No mention of the multi-instance state corruption risk (M-008). |
