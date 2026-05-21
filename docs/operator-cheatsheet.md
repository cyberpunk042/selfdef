# Operator cheatsheet — selfdef + four-watchdog set

One-page printable reference for the daily-driver commands. For the
exhaustive surface, `selfdefctl --help` + the per-subcommand `--help`.

## First-time setup

```sh
sudo apt install selfdef-daemon
selfdefctl wizard                     # 5-step setup walkthrough
selfdefctl init checklist             # 12-step first-run checklist
```

## Daily-driver

```sh
selfdefctl status                     # daemon counters
selfdefctl doctor                     # cross-cutting health check
selfdefctl trio                       # four-watchdog snapshot (4 panels)
selfdefctl trio --quiet               # single-line PS1-friendly summary
selfdefctl trio --watch 5             # human watch, clear+redraw every 5s
selfdefctl trio --json --watch 5      # JSONL stream for monitoring pipelines
selfdefctl trio-tail                  # unified live OCSF tail (Ctrl-C exits)
selfdefctl alerts                     # MS027 alerts overview (CLI parity with dashboard)
selfdefctl alerts --quiet             # single-line gate-friendly: `selfdef-alerts: OK`
selfdefctl alerts --json              # jq-friendly output (worst + per-row state)
selfdefctl health                     # MS011 Z-6 composite health (one-line: is the box OK?)
selfdefctl health --quiet             # `selfdef-health: WORST` for PS1 / gates
selfdefctl health --json              # composite worst + 6 component rows
selfdefctl audit-chains               # MS009 chain integrity across 3 chained watchdogs
selfdefctl audit-chains --quiet       # `selfdef-audit-chains: WORST` exit-coded gate
selfdefctl audit-chains --json        # raw /v1/audit-chains JSON envelope
selfdefctl commit-authority types     # MS041 / SDD-043 schema discovery (8 types + 5 fields + 3 gates)
selfdefctl commit-authority validate <file>   # offline envelope validation (exit 0/1)
selfdefctl commit-authority classify <file>   # high-risk classification (exit 1 if high-risk)
selfdefctl tool-authority tools       # MS042 / SDD-050 tool-policy pipeline discovery (8 tools + 9 gates)
selfdefctl tool-authority permits <tool> <mode> <profile>   # is-authorized check (exit 0 ALLOW; 1 NOT)
selfdefctl capability-tokens verdicts # MS035 / SDD-044 5-verdict CheckVerdict ladder
selfdefctl capability-tokens schema   # Token shape + 5 companion crates + caller contract
selfdefctl filesystem-boundary doctrine  # MS037 / SDD-045 3-dir + 6-step + 5-field + 6-predicate
selfdefctl filesystem-boundary schema    # full SDD-045 contract incl. caller sequence
selfdefctl network-boundary profiles    # MS038 / SDD-046 5-profile egress ladder
selfdefctl network-boundary classify <bits>  # u8 → NetworkProfile (exit 0 OK; 1 unknown bits)
selfdefctl sandbox-tiers              # MS032 / SDD-047 5-tier ladder + 4 promotion gates
selfdefctl communication-boundary     # MS034 / SDD-048 4 transports + 8 message types
selfdefctl authority                  # MS039+MS040 / SDD-049 7 levels + 5 rings + 6 profiles + 4 gates
selfdefctl policy clusters            # MS033 / SDD-051 8 policy-cluster taxonomy
selfdefctl policy crates              # all shipped selfdef-policy-* crates grouped by cluster
selfdefctl ssh-wrap doctrine          # MS014 / SDD-052 SSH-wrap client-side defense doctrine
selfdefctl ssh-wrap install           # step-by-step PATH-shadow install instructions
selfdefctl nats                       # MS015 / SDD-053 two-way pump subject schema + modes
selfdefctl flex-profile               # MS011 Z-3 flex-profile schema (Delta + DeltaOp + RevertRecord)
```

## Per-watchdog drill-down

```sh
# friction-audit (MS046, hardware frame)
selfdefctl friction-audit show        # latest verdict per gate
selfdefctl friction-audit history     # ring buffer history
selfdefctl friction-audit replay      # re-run gate (operator-triggered)

# perimeter (MS047, kernel-fence)
selfdefctl perimeter show             # active policy + last 16 verdicts
selfdefctl perimeter history          # Sigkill verdict log
selfdefctl perimeter extend --signed <manifest>   # operator-signed extension
selfdefctl perimeter revoke <ext-id>  # revoke extension
selfdefctl perimeter check-overlap    # SDD-015 coexistence check
selfdefctl perimeter status           # SDD-015 coexistence status
selfdefctl perimeter audit-cycle replay  # chain integrity check

# guardian (MS044, supervisor)
selfdefctl guardian show              # state + last events
selfdefctl guardian history           # event log
selfdefctl guardian replay <event-id> # re-classify stored event
selfdefctl guardian rollback <event-id> # false-positive rollback

# scheduler (MS048, routing)
selfdefctl scheduler show             # state + last 16 decisions
selfdefctl scheduler history          # decision log
selfdefctl scheduler explain <req-id> # single-decision detail
selfdefctl scheduler replay <req-id> [--profile P]   # counterfactual replay
selfdefctl scheduler weights [--profile P]  # 7-axis weight matrix
selfdefctl scheduler force <req-id> --route R   # Ring 0 operator override
selfdefctl scheduler audit-cycle replay   # chain integrity check
```

## Modules (operator-activatable bundles)

```sh
selfdefctl modules list                       # all shipped modules
selfdefctl modules info <slug>                # single-module detail
selfdefctl modules show-requires <slug>       # daemon_requires
selfdefctl modules check <slug>               # health probe
selfdefctl modules apply --dry-run            # preview activation
sudo selfdefctl modules apply                 # apply active modules
sudo selfdefctl modules uninstall --confirm $(hostname)
```

## Module activation (edit `/etc/selfdef/modules.toml`)

```sh
sudo selfdefctl init modules            # writes starter modules.toml
sudoedit /etc/selfdef/modules.toml      # uncomment desired module blocks
sudo selfdefctl modules apply           # idempotent apply
```

## Four-watchdog set systemd enable

```sh
sudo systemctl enable --now sovereign-guard.service     # MS046 friction-audit
sudo systemctl enable --now selfdef-guardian.service    # MS044 guardian
sudo systemctl enable --now selfdef-scheduler.service   # MS048 scheduler
# MS047 perimeter: TracingPolicy auto-installed by postinst — no service to enable

sudo systemctl enable --now selfdef-doctor.timer        # hourly health check
journalctl -u selfdef-doctor.service -n 50              # last run output
```

## HTTP API (`/v1/*`, bearer-token-gated when TCP-bound)

```text
GET /status              daemon status + counters
GET /events              recent events
GET /findings            recent findings (Critical severity_id)
GET /events/stream       SSE live tail (per-token quota: 8)
GET /metrics             Prometheus exposition (selfdef-bus + four-watchdog)
GET /notify/ack/:token   one-click escalation ack

GET /v1/friction-audit{,/history}
GET /v1/perimeter{,/history}
GET /v1/guardian{,/history}
GET /v1/scheduler{,/history,/backpressure,/weights,/explain/:request_id}
GET /v1/modules{,/:name}
GET /v1/modules/diff                                 (MS011 Z-13 SD-R83 installed/available/orphaned)
GET /v1/modules/install-options                      (MS011 Z-13 SD-R86 dep-readiness for AVAILABLE modules)
GET /v1/modules/:name/check                          (per-module install/check.sh invocation; JSON exit + stdout/stderr)
GET /v1/alerts                                       (MS027 server-side classifier)
GET /v1/hardware{,/capabilities,/sain01}             (MS010 hardware snapshot + derived caps + sain-01 verdict)
GET /v1/network                                      (MS011 Z-7 internet/DNS/cloudflared/tailscale/traefik)
GET /v1/storage                                      (MS011 Z-10 per-mount usage + selfdef log dirs)
GET /v1/raid                                         (MS011 Z-9 software RAID arrays from /proc/mdstat)
GET /v1/gpu                                          (MS011 Z-5 nvidia-smi power-draw vs operator policy)
GET /v1/cpu                                          (MS011 Z-4 scaling_governor × SMT → named mode)
GET /v1/health                                       (MS011 Z-6 composite aggregate — "is everything OK?")
GET /v1/audit-chains                                 (MS009 composite chain-check for perimeter/guardian/scheduler)
GET /v1/commit-authority                             (MS041 / SDD-043 D-3 commit-doctrine schema discovery)
GET /v1/tool-authority                               (MS042 / SDD-050 D-2 11-crate tool-policy pipeline discovery)
GET /v1/capability-tokens                            (MS035 / SDD-044 D-2 typed-authority-handles schema discovery)
GET /v1/filesystem-boundary                          (MS037 / SDD-045 D-2 3-dir + pipeline + schema + predicates)
GET /v1/network-boundary                             (MS038 / SDD-046 D-2 5-profile egress ladder)
GET /v1/sandbox-tiers                                (MS032 / SDD-047 D-2 5-tier capability ladder + 4 gates)
GET /v1/communication-boundary                       (MS034 / SDD-048 D-2 4 transports + 8 message types)
GET /v1/authority                                    (MS039+MS040 / SDD-049 D-2 7 levels + 5 rings + 6 profiles)
GET /v1/policy                                       (MS033 / SDD-051 D-2 8 policy-cluster taxonomy + 30 crates)
GET /v1/nats                                         (MS015 / SDD-053 D-2 NATS bridge subject schema + modes)
GET /v1/mcp                                          (MS011 Z-11 / SD-R84 MCP-interop transports + framings + curation)
GET /v1/flex-profile                                 (MS011 Z-3 flex-profile schema + live state read when present)
GET /v1/inference-backends                           (MS011 Z-2 llama.cpp / vllm / bitnet.cpp / unsloth probe)
```

## Operator runbooks (info-hub `wiki/runbooks/`)

```text
friction-audit-{pcie,zfs,memory,immutability,signature}.md  (5)
perimeter-{tetragon-not-running,policy-load-failure,extension-create,sigkill-investigation,key-rotation,audit-log-corruption}.md  (6)
guardian-{not-running,socket-unreachable,false-positive-rollback,audit-log-corruption,console-alert-investigation}.md  (5)
scheduler-{not-running,backpressure-stuck-open,weight-matrix-rotation,audit-log-corruption,force-override-investigation}.md  (5)
ux-coherence-failures.md  (1)
```

## PS1 prompt integration

```sh
# Zsh:
PROMPT='%n@%m %~ $(selfdefctl trio --quiet 2>/dev/null) %# '

# Bash:
PS1='\u@\h \w $(selfdefctl trio --quiet 2>/dev/null) \$ '

# Tmux status-right:
set -g status-right '#(selfdefctl trio --quiet 2>/dev/null)'
```

## Shell gate (only run X if all watchdogs OK)

```sh
selfdefctl trio --quiet && sudo selfdefctl modules apply
```

## Dashboard PWA (operator-facing UI at `/dashboard/`)

The daemon serves a 6-panel single-page operator dashboard. Sections:

| Panel | Refresh interval | Backed by |
|---|---|---|
| Friction-audit (MS046) | 30 s | `GET /v1/friction-audit` |
| Perimeter (MS047) | 15 s | `GET /v1/perimeter` |
| Guardian (MS044) | 30 s | `GET /v1/guardian` |
| Scheduler (MS048) | 10 s | `GET /v1/scheduler` |
| Modules (MS006) | 60 s | `GET /v1/modules` |
| Alerts overview (MS027) | 15 s | `GET /metrics` — client-side parse of 9 alert-relevant series; surfaces chain-broken + counter alerts without needing an external Prometheus |

Open over UNIX socket (`unix://`) or TCP with `Authorization: Bearer
<token>`. PWA shell is offline-capable (service-worker cached) but
API responses are never cached — operators need the freshest data.

## Coherence harness (local dev / CI)

```sh
make coherence                        # 13-layer L1+L2+cargo gate (preferred)
bash scripts/test/coherence.sh        # same thing, direct invocation
```

CI runs the same harness on every push + PR + tag. See
`.github/workflows/ci.yml` (`coherence` job) +
`.github/workflows/release.yml` (pre-build gate).

## Cross-references

- Full operator surface: `selfdefctl --help`
- First-time setup: [`docs/dev/first-run.md`](dev/first-run.md)
- Operator health check: [`docs/dev/operator-health-check.md`](dev/operator-health-check.md)
- Module author contract: [`docs/dev/modules.md`](dev/modules.md)
- Security threat model: [`SECURITY.md`](../SECURITY.md)
- Architecture: [`ARCHITECTURE.md`](../ARCHITECTURE.md)
- Changelog: [`CHANGELOG.md`](../CHANGELOG.md)
