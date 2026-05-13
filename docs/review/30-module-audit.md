# Module audit

> Scope: `modules/*` — manifest, profiles, install scripts, README.
> Per-area finding ids use the `M-` prefix; the central ledger
> (`99-findings-ledger.md`) maps each to the canonical `F-2026-NNN`.

This audit walks all 9 modules against four parallel surfaces
(manifest / profiles / install scripts / README) and flags drift.
Each module section ends with a `Findings raised`. A cross-cutting
section at the bottom captures issues that span more than one
module.

---

## modules/agent-guard

The newest and most complex module: 5 TracingPolicies, two profiles
(`audit` / `enforce`), three substitution paths (egress allowlist,
SecureMessage endpoint, GPU device + binary allowlist), and a
container-scope swap (`container` vs `pod-label`). High surface
area; correspondingly high drift risk.

### Manifest internal consistency

- `[profiles].available` matches `profiles/` filenames (`audit`,
  `enforce`).
- `provides = []` is semantically incomplete: agent-guard
  *contributes policies* to tetragon's `policy_dir`. Asymmetric
  with how every other module declares what it contributes to
  the shared catalog. Not breaking; pollutes the
  consume/provide graph readers rely on.
- `consumes = ["tetragon-tracing", "tetragon-policies"]` matches
  tetragon's `provides`.
- `requires = [{ kind = "binary", value = "tetragon" }]` —
  documented in README.

### README vs scripts

- Every documented key (`profile`, `scope`, `pod_label_key`,
  `pod_label_value`, four per-policy `*_enabled` / `*_action`
  pairs, `egress_allowlist`, `securemessage_endpoint`,
  `gpu_device_paths`, `gpu_device_allowlist`) is read by
  `toml_get` in `install/apply.sh`.

### README vs profiles

- Defaults in `profiles/audit.toml` and `profiles/enforce.toml`
  match the example block in `README.md`.

### apply.sh vs check.sh

- apply.sh writes `${POLICY_DIR}/selfdef-agent-${name}.yaml` per
  policy; check.sh verifies presence and `- action: <expected>`
  match. Symmetric.

### apply.sh vs uninstall.sh

- uninstall.sh removes all five policy filenames by hard-coded
  enumeration. Will fall behind silently if a sixth policy is
  added to the source tree without updating uninstall.sh. **(M-001)**

### Dry-run honesty

- All file writes go through `install` wrapped by `run()`. No
  naked `systemctl` calls.

### Structured-status emission

- One `emit_status` per exit path.

### Cross-module dependencies

- apply.sh reads `SELFDEF_TETRAGON_CONFIG` to discover tetragon's
  `policy_dir`, with a hard-coded fallback to
  `/etc/tetragon/tetragon.tp.d`. If tetragon was applied with a
  non-default `policy_dir` and the agent-guard environment lacks
  that env var, agent-guard writes to the wrong directory and
  the policies never load. No defensive cross-check. **(M-002)**

### Pod-scope substitution

- `render_pod_scope()` (`install/lib.sh`) replaces the
  `matchNamespaces` block with `matchPodSelector` using an awk
  state machine anchored on `matchActions:`. It assumes nothing
  intervenes between the two markers in any policy. True for the
  shipped policies; brittle for any future selector. **(M-003)**

### Findings raised

- **M-001** _nice_ — uninstall.sh enumerates policy filenames by
  hand. Adding a sixth policy without updating uninstall.sh
  leaves stale files behind. Recommend deriving the list from
  the same source-of-truth as apply.sh (e.g. `ls
  ${POLICIES_SRC}/*.yaml`).
- **M-002** _important_ — agent-guard's discovery of
  tetragon's `policy_dir` depends on `SELFDEF_TETRAGON_CONFIG`
  being readable. If operators apply agent-guard outside the
  `selfdefctl modules apply` flow (or via a misconfigured CI
  step), the env var is absent and apply.sh silently writes to
  the hard-coded fallback. Suggest a `tetragon` state file
  (e.g. `/var/lib/selfdef/tetragon/state.toml`) as the single
  source of truth that downstream modules read.
- **M-003** _nice_ — `render_pod_scope` is fragile against future
  policy structure changes. Recommend either a yaml-aware
  transform (yq / python) or an explicit `# selfdef-pod-scope-marker`
  comment in the source YAMLs that the script anchors on.

---

## modules/tetragon

Substrate-only: writes `/etc/tetragon/tetragon.yaml`, owns
`policy_dir`, exposes Prometheus on `metrics_address`. Single
profile, `default`.

### Manifest internal consistency

- `[profiles].available = ["default"]` matches filesystem.
- `provides = ["tetragon-tracing", "tetragon-policies",
  "metrics-endpoint"]` — all three are real (event_log_path,
  policy_dir, metrics endpoint).
- `requires` includes `tetragon` binary, `systemctl`, and
  `kernel-feature = "CONFIG_BPF"`. README documents the
  prerequisite-install step.

### Apply / check / uninstall symmetry

- apply.sh renders config + creates dirs + enables service
  (idempotent on byte-equal config); check.sh verifies all
  three; uninstall.sh removes config + empty policy_dir
  (preserves non-empty so peer modules' policies survive).

### Cross-module coordination

- `event_log_path` (default `/var/log/tetragon/events.json`) is
  *the* coupling point with the daemon's
  `[collectors.eventstream].paths`. **No validation that the
  daemon is configured to tail it.** README mentions it (line
  74) but only as operator responsibility — no apply-time check,
  no warning in the structured status message. **(M-004)**

### Findings raised

- **M-004** _important_ — tetragon's apply.sh doesn't surface
  the event_log_path alignment requirement in its status message
  or in any operator-visible artifact. Recommend either (a)
  including the event_log_path in the structured-status
  `message` field so the apply log carries it, or (b) a
  follow-up tooling step in `selfdefctl modules check` that
  cross-validates the daemon's eventstream paths against
  tetragon's event_log_path.

---

## modules/observability

Two profiles (`bundled`, `external`); renders Prometheus scrape
config + a Grafana dashboard JSON; reloads Prometheus in
bundled mode.

### README vs profiles drift

- `README.md` Config section shows `scrape_targets =
  "localhost:2112"` — single target, Tetragon only.
- `profiles/bundled.toml` ships `scrape_targets = "localhost:2112,
  localhost:8443"` — two targets, includes the daemon's
  /metrics.
- `profiles/external.toml` matches `bundled.toml` (two
  targets).
- `install/apply.sh` fallback when `toml_get` returns empty is
  `"localhost:2112"` (single target). **(M-005)**

### Dashboard claims vs README

- The dashboard JSON renders four Tetragon panels and three
  selfdef-daemon panels (`selfdef_events_by_class_total`,
  `selfdef_findings_by_severity_total`,
  `selfdef_store_events`). The README mentions only Tetragon
  metrics. An operator reading the README alone would not know
  to expect selfdef-daemon's `/metrics` to be reachable for the
  dashboard to render fully. **(M-006)**

### Tetragon metric name assumption

- Dashboard panel 2 uses `rate(tetragon_msg_sigkill_total[5m])`.
  This is plausible but not verified against a live Tetragon
  binary or upstream metric documentation; the value is brittle
  to Tetragon's own naming choices. **(M-007)**

### Findings raised

- **M-005** _important_ — three different default values for
  `scrape_targets` across README, both profile files, and the
  apply.sh fallback. Decide on one (the two-target version is
  the right answer post-PR #23) and reconcile.
- **M-006** _important_ — README claims to scrape Tetragon, but
  the shipped dashboard depends on selfdef-daemon's Prometheus
  exporter too. Add a "what's required" matrix to the README so
  operators know both endpoints must be live for the dashboard
  to be useful.
- **M-007** _nice_ — `tetragon_msg_sigkill_total` is an
  unverified upstream metric name. Recommend either pinning the
  Tetragon minor version in the module's prereqs README or
  adding a `selfdefctl modules check` step that scrapes
  `metrics_address` and verifies the metric is present.

---

## modules/vpn-bridge

Three profiles (`relay-via-server`, `tailscale`,
`cloudflare-tunnel`), `instanced = true`. Profile scripts live
under `install/profiles/<name>.sh`.

### Multi-instance path clobbering

- Every profile script writes nftables rules / config files to
  paths that lack instance suffixes. Example:
  `install/profiles/relay-via-server.sh` writes
  `/etc/nftables.d/selfdef-vpn-bridge.conf`. Running
  `[modules."vpn-bridge#overlay"]` alongside
  `[modules."vpn-bridge#publish"]` (both as relay-via-server)
  would have the second overwrite the first silently. **(M-008)**

The dispatcher (`install/apply.sh`) doesn't surface the
instance name to the profile scripts. There's no
`SELFDEF_INSTANCE_ID` env var carrying the suffix.

### Findings raised

- **M-008** _blocker_ — multi-instance is declared in the
  manifest (`instanced = true`) and the resolver supports it,
  but the profile scripts hard-code instance-shared paths.
  Either (a) make the dispatcher pass the instance id and have
  every profile script suffix its writes, or (b) declare
  `instanced = false` until the multi-instance promise is
  honoured. The current state is a documented feature that
  silently corrupts state.

---

## modules/integrity-sentinel

SHA256 baseline drift detection. Two profiles (`strict`,
`warn-only`). Drift optionally emits an OCSF event via
`selfdefctl events emit` when `event_stream_path` is set
(landed in PR #21).

### Internal consistency

- Profile filenames match manifest's `[profiles].available`.
- Optional notifier wiring keys (`event_stream_path`,
  `event_severity_strict`, `event_severity_warn`) are
  documented in README and read by `install/lib.sh
  emit_drift_event`.

### Findings raised

- _(none from this pass — module is consistent. Cross-cutting
  finding lives in the integration audit: the daemon's default
  eventstream `paths` doesn't include the integrity-sentinel
  default `event_stream_path`, which means the optional
  emission goes nowhere out of the box.)_

---

## modules/bridge-l2

L2 bridge + nftables FORWARD policy.

### Internal consistency

- Profiles, scripts, README all align.
- `provides = ["l2-bridge", "forward-policy"]` is consumed by
  `suricata` (`consumes = ["l2-bridge", "forward-policy"]`).
- `requires` covers `ip`, `nft`, `systemctl`, plus kernel
  features.

### Findings raised

- _(none from this pass.)_

---

## modules/suricata

Inline IDS. Depends on `bridge-l2`.

### Findings raised

- _(none from this pass — the long-standing module appears
  internally consistent.)_

---

## modules/polarproxy

TLS termination → PCAP-over-IP.

### Findings raised

- _(none from this pass.)_

---

## modules/detect-host

The daemon-as-module entry.
`install.kind = "debian-package"`, no install scripts.

### Findings raised

- The other modules implicitly depend on detect-host (without
  the daemon, no event bus, no responder, no notifier). Yet no
  module declares `depends_on = ["detect-host"]`. A operator
  who builds a host config with `[modules.suricata]` but no
  `[modules.detect-host]` gets a working suricata install
  whose events go nowhere. **(M-009)**

- **M-009** _important_ — every module that consumes the
  event-bus capability should declare `depends_on =
  ["detect-host"]` (or, equivalently, `consumes =
  ["event-bus"]`). Currently the consume/provide graph
  documents this relationship in detect-host's manifest
  (`provides = ["event-bus", "finding-store",
  "sigma-correlator"]`) but no module declares a consume side.

---

## Cross-cutting findings

### Phase ordering looks sound

| Phase | Modules |
| --- | --- |
| pre | `tetragon`, `integrity-sentinel` |
| main | `agent-guard`, `bridge-l2`, `suricata`, `polarproxy`, `vpn-bridge` |
| post | `observability` |

Cross-phase deps (main → pre is fine; main → main needs topo
sort) are well-formed by inspection. No `pre → main` violations
that the resolver would reject. _(no finding)_

### Provide / consume graph audit

Edges that resolve cleanly:

- `bridge-l2 → suricata` via `l2-bridge`, `forward-policy`
- `tetragon → agent-guard` via `tetragon-tracing`,
  `tetragon-policies`
- `tetragon → observability` via `metrics-endpoint`

Edges that *should* exist but don't:

- Every collector-using module → `detect-host` (M-009 above).
- `agent-guard → observability` is not declared, but
  observability's dashboard renders agent-guard kill-counts.
  Soft coupling; flagged for the design phase. **(M-010)**

- **M-010** _SDD-debt_ — observability's dashboard depends on
  agent-guard's policies firing (`tetragon_msg_sigkill_total`
  is meaningful only when there's a policy to kill against).
  The manifest doesn't capture this dependency. The dashboard
  would render flat panels on a host that ran only tetragon +
  observability without agent-guard. Recommend either making
  agent-guard a documented prerequisite of the dashboard
  template or splitting the dashboard into "substrate-only"
  vs "agent-guard active" variants.

### Configuration validation is uniformly weak

Every module uses the same hand-rolled `toml_get` that:

- Returns empty string for missing keys (callers must `||
  echo default`).
- Silently ignores malformed TOML (no parse error).
- Doesn't validate values (e.g. severity = "high" vs a
  typo "hgih").

Profile validation is per-module (each apply.sh has its own
`case "$PROFILE" in audit|enforce) ...`). Severity / action /
scope validation is also per-module. This is not a defect
today but is a long-term consistency tax. **(M-011)**

- **M-011** _SDD-debt_ — modules duplicate `toml_get`, run /
  log / emit_status helpers, and per-knob validation. A shared
  `selfdef-module-lib.sh` shipped in `/usr/share/selfdef/lib/`
  would reduce duplication and let one bug-fix propagate.
  Design phase: scope of shared lib + how modules opt in.

### Cleanup symmetry holds

Across every module, the uninstall scripts undo the apply
script's writes. Edge case: tetragon refuses to remove a
non-empty `policy_dir` (correct — peer modules may still own
files in there). No regressions observed.

---

## Findings raised in this section

| Id | Severity | Surface | Summary |
| --- | --- | --- | --- |
| M-001 | nice | `agent-guard/install/uninstall.sh` | Hand-enumerated policy list will drift if a sixth policy is added. |
| M-002 | important | `agent-guard/install/apply.sh` | tetragon `policy_dir` discovery depends on env var; silent fallback. |
| M-003 | nice | `agent-guard/install/lib.sh` | `render_pod_scope` awk state machine fragile against future selectors. |
| M-004 | important | `tetragon/install/apply.sh` | `event_log_path` alignment with daemon eventstream is operator-managed without surface. |
| M-005 | important | `observability/` (README + profiles + apply.sh) | Three defaults for `scrape_targets`; pick one. |
| M-006 | important | `observability/README.md` | Dashboard depends on selfdef-daemon `/metrics`; README only mentions Tetragon. |
| M-007 | nice | `observability/assets/dashboards/selfdef.json.template` | Hard-coded Tetragon metric name without an upstream-version pin. |
| M-008 | blocker | `vpn-bridge/install/profiles/*.sh` | `instanced = true` but profile scripts share state paths. Silent corruption on a multi-instance host. |
| M-009 | important | every module that uses the event bus | No explicit `depends_on = ["detect-host"]` even though every module's events go via the daemon. |
| M-010 | SDD-debt | `observability/assets/dashboards/` | Dashboard implicitly depends on agent-guard policies firing. |
| M-011 | SDD-debt | `modules/*/install/lib.sh` | Duplicated helpers; ship a shared `selfdef-module-lib.sh` and adopt across modules. |
