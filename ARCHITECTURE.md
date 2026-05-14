# Architecture

## Layered view

```
                ┌─────────────────────────────────────────────────────────────┐
                │                       Control plane                         │
                │   selfdefctl  ·  PWA dashboard  ·  ntfy/signal  ·  Prometheus │
                │   init · doctor · keys verify · rbac check · api rotate-token │
                └────────────────────────┬────────────────────────────────────┘
                                         │ HTTP API + /metrics  (UNIX socket or TCP+bearer)
                                         │ SIGHUP (rules) / SIGUSR2 (tokens + verifier + rules)
┌────────────────────────────────────────────────────────────────────────────┐
│                              selfdef-daemon                                │
│  ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐         │
│  │ Collectors │──▶│    Bus     │──▶│ Correlator │──▶│ Responder  │         │
│  │            │   │            │   │            │   │            │         │
│  │ • auditd   │   │  in-proc   │   │  Sigma +   │   │ • lockdown │         │
│  │ • journald │   │  broadcast │   │  windowed  │   │ • notify   │         │
│  │ • tetragon │   │  (NATS opt)│   │  rules     │   │ • snapshot │         │
│  │ • suricata │   │            │   │            │   │ • isolate  │         │
│  │ • canary   │   │            │   │  ↑ opt-in  │   │ • forensics│         │
│  │ • eventstr*│   │            │   │  signed-   │   │ • veloc.   │         │
│  │ • ebpf     │   │            │   │  rule gate │   │            │         │
│  └────────────┘   └─────┬──────┘   └─────┬──────┘   └─────┬──────┘         │
│         ↑                │                │                 │              │
│  *opt-in                 ▼                ▼                 ▼              │
│   integrity     ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│   gate          │   Store      │  │  Notifier    │  │   Actions        │   │
│                 │ SQLite + DDB │  │ ntfy/signal  │  │ nft/systemd/scripts │ │
│                 └──────────────┘  └──────────────┘  └──────────────────┘   │
│                         │                                                  │
│                         ▼                                                  │
│              ┌─────────────────────────────────┐                           │
│              │   API + /metrics + control plane│  read-cap: GET /metrics,  │
│              │   /status /events /findings     │   /status, /events …      │
│              │   /events/stream /rules/reload  │  full-cap: control verbs  │
│              │   /panic /actions/*/run         │  hot-reload tokens via    │
│              └─────────────────────────────────┘  SIGUSR2 (no restart)     │
└────────────────────────────────────────────────────────────────────────────┘

                ┌──────────────────────────────────────────────────────┐
                │                  Kernel & system                     │
                │   Tetragon · custom eBPF (aya) · auditd · AppArmor   │
                └──────────────────────────────────────────────────────┘
```

### Modules layer

Operator-activatable modules sit on top of the daemon, each
with its own apply / check / uninstall lifecycle
(`selfdefctl modules apply`). Module phases (`pre / main /
post`) order the apply across modules that share substrate.
The current catalog:

```
phase=pre        tetragon (substrate; opt-in       integrity-sentinel (drift)
                  signed-policy gate)                       │
                          │                                 │
phase=main       agent-guard (5 policies;          bridge-l2 → suricata, polarproxy
                  pod-label scope honors           vpn-bridge (per-profile
                  k8s label RBAC)                   instanced; SDD-003)
                          │
                          │
phase=post       observability (Prometheus + Grafana)
```

Every module script sources `packaging/lib/module-lib.sh`
(SDD-006 v2) for the shared helpers (`log`, `emit_status`,
`die`, `run`, `toml_get`, `module_record_file`,
`module_render_files`, `module_clear_manifest`). The library
is dispatcher-injected via `$SELFDEF_MODULE_LIB` with a
workspace-relative fallback for dev runs.

Modules emit structured-status JSON to the CLI dispatcher.
Some modules (e.g. `integrity-sentinel`) optionally emit
OCSF events via `selfdefctl events emit` into a JSONL stream
the daemon's `eventstream` collector tails — closing the
loop back into the bus. When
`[collectors.eventstream].integrity_check = true`, the
collector refuses to tail world-writable or foreign-owned
paths (SDD-004 F-2026-026 follow-up).

### Integrations layer (SDD-008 D-1)

Adapters to external services live as Rust crates under the
naming pattern `crates/selfdef-integration-<service>`. They are
architecturally distinct from modules and the distinction is
load-bearing:

```
┌─────────────────────────────────┬──────────────────────────────────┐
│  Module                         │  Integration                     │
├─────────────────────────────────┼──────────────────────────────────┤
│  installs things on the host    │  pure adapter — no install       │
│  owns service lifecycle         │  stateless or lightly stateful   │
│  mutates host topology          │  must NOT mutate host topology   │
│  has install/apply.sh           │  has no install/ directory       │
│  example: vpn-bridge, suricata  │  example: ntfy, signal, smtp     │
│  lives under modules/<name>/    │  lives under crates/selfdef-     │
│                                 │   integration-<service>/         │
└─────────────────────────────────┴──────────────────────────────────┘
```

The rule operators can rely on: **an integration crate can be
removed from the build without breaking the host.** A module
cannot — uninstalling a module is itself a lifecycle event
(`selfdefctl modules uninstall <name>`) with its own apply.sh
inverse path. If a contributor reaches for an installer inside
an integration crate, that's the structural signal the work
belongs in `modules/`, not `crates/`.

Integration crates depend only on:

- `selfdef-core` for the event types they consume
- the orchestrator trait crate (`selfdef-notifier-orchestrator`
  for outbound channels, future analogues for inbound sinks)
- one outbound transport crate (`reqwest` for HTTP, `lettre`
  for SMTP, `tokio::process::Command` for subprocess channels
  like `signal-cli`)

Integration crates do **not** depend on `selfdef-daemon`,
`selfdef-config`, or any module under `modules/`. That keeps
them swappable and individually testable.

Concrete catalog (current + planned per SDD-008 first-ship):

```
crates/selfdef-integration-ntfy       (current NtfyNotifier, refactor planned)
crates/selfdef-integration-signal     (current SignalCliNotifier, refactor planned)
crates/selfdef-integration-smtp       (first email channel — SDD-008 D-7 Q-E)
crates/selfdef-integration-twilio     (future — SDD-008 Q-D)
crates/selfdef-integration-slack      (future — SDD-008 Q-C)
crates/selfdef-integration-discord    (future)
crates/selfdef-integration-opensearch (future — observability export)
crates/selfdef-integration-loki       (future — observability export)
```

Note: the **collectors** under `crates/selfdef-collector-*` are
the inbound analogue of integrations — they bridge external
event sources (auditd, journald, eBPF, Tetragon, Suricata, the
JSONL eventstream) into the in-process bus. They predate the
SDD-008 taxonomy and stay where they are; future inbound
integrations may adopt the `selfdef-integration-*` naming if a
clean adapter shape emerges.

The contributor-facing template for new integration crates
lives at [`docs/dev/integrations.md`](docs/dev/integrations.md).

## Core principles

**Schema first.** Every collector emits an `Event` in a
single shape (OCSF-aligned). Adding a collector means parsing
its native format into that shape — nothing else in the
system changes. Adding a rule means matching against that
shape — no collector knowledge needed. This decouples the
moving parts.

**In-proc bus by default, network bus by exception.** A
single daemon hosts all the modules. Inter-module
communication is a tokio broadcast channel. When you need to
fan events out to other hosts (a log host, a correlator on
another box), you opt in to the NATS JetStream sink. Most
personal-scale deployments stay in-proc forever.

**Detection-as-code.** Rules live in `rules/`, are
version-controlled, are unit-tested against a replay corpus
in CI, and have ATT&CK mappings. The correlator hot-reloads
them on SIGHUP. New detection = a PR, not a deploy. Optional
rule signing (`[security].require_signed_rules = true`)
gates the load on a valid minisign signature
(`selfdef-signing` crate).

**Responder is dumb on purpose.** Actions are small,
idempotent, and explicit (`lockdown_egress`, `kill_pid`,
`revoke_session`, `snapshot_proc`, `notify`). The correlator
decides; the responder does. Complex playbooks compose
simple actions.

**Privilege separation.** The daemon runs unprivileged where
it can. Collectors that need capabilities (auditd:
`CAP_AUDIT_READ`, suricata socket: `CAP_NET_RAW`) have them
granted explicitly via systemd, never via setuid.

**Security features are opt-in.** Rule signing, TracingPolicy
signing, eventstream integrity, API token, RBAC posture probe
— every audit-shipped security feature defaults off. The
operator turns each on via `selfdefctl init checklist`'s
documented steps. Doctor verifies the opt-ins the operator
actually turned on, and stays silent on the rest.

## Data lifecycle

```
event happens
   │
   ▼
collector parses ─── (opt-in) eventstream integrity gate ───┐
   │                                                        │
   ▼                                                        ▼
bus broadcasts → {store, correlator}                    refuse: log warning
                          │
                          ▼
                  (opt-in) rule loaded with valid .minisig?
                          │
                          ▼
                  rule matches → action(s) emitted → responder runs
                                                       │
                                       ┌───────────────┘
                                       ▼
                         notifier sends to ntfy / signal
                         optional: snapshot, lockdown, isolate
```

Hot store: SQLite WAL, 7-30 days, indexed.
Warm store: DuckDB over Parquet, 90 days+, analytical queries.
Cold: rsync/restic-shipped Parquet to an off-host bucket —
write-once forensic record.

## Operator lifecycle

```
                        Day 0                                Day N
              ┌──────────────────────┐         ┌────────────────────────┐
              │ selfdefctl init      │         │ selfdefctl doctor      │
              │  config  → /etc      │         │  signing               │
              │  modules → /etc      │         │  api                   │
              │  checklist → stdout  │         │  eventstream           │
              └──────────┬───────────┘         │  rbac (pointer)        │
                         │                     │                        │
                         ▼                     │ exits 0 iff every      │
              ┌──────────────────────┐         │ opted-in feature       │
              │ systemctl enable     │         │ verifies clean.        │
              │ selfdefd             │         └────────────────────────┘
              └──────────┬───────────┘                    ▲
                         │                                │
                         ▼                                │
              ┌──────────────────────┐                    │
              │ selfdefctl modules   │                    │
              │ apply                │────────────────────┘
              └──────────────────────┘
```

`init` writes the minimum-viable config (every opt-in OFF);
the checklist walks the operator through each opt-in;
`doctor` verifies the result. Together: bootstrap → opt in →
verify, one verb per step. Each opt-in has a dedicated
runbook under `docs/dev/<feature>.md`.

## Self-protection of the daemon

The daemon is the most valuable target on the host. Treated
accordingly:

- Static binary, stripped, signed (cosign), reproducibly built.
- Runs as a dedicated unprivileged user with a tight systemd
  unit (see `packaging/systemd/selfdefd.service`).
- AppArmor profile restricts FS and network access.
- Configuration and rules are read-only at runtime
  (re-read on SIGHUP only). Rule loads validate detached
  minisign signatures when `[security].require_signed_rules
  = true` (SDD-004 follow-up; off by default to preserve
  the existing workflow).
- API bearer tokens hot-rotate via `selfdefctl api
  rotate-token` + SIGUSR2 — no daemon restart, no
  in-flight scrape disruption (SDD-004 F-2026-023 follow-up;
  F-2027-031 enforces mode-0600 on reload).
- The SIGUSR2 fan-out also rotates the rule-signing verifier
  (F-2027-005) and re-runs `load_rules` against the fresh
  verifier; the handler emits a one-line summary
  `tokens=ok verifier=ok rules=ok` so operators can confirm
  the rotation in one glance (F-2027-032).
- Eventstream JSONL paths are opt-in integrity-gated
  (world-writable + foreign-owner refusal at parse time;
  SDD-004 F-2026-026 follow-up; F-2027-035 hardens the check
  to `O_NOFOLLOW` open + fstat-on-FD, closing the
  stat-then-open TOCTOU window).
- State (sqlite, parquet) lives on a path the daemon can
  write but most other tools cannot.
- Long-term: ship binary on a dm-verity / systemd-sysext
  immutable layer so even root tampering is detected. (Not
  yet shipped; tracked in SECURITY.md's Known gaps.)

## SDDs

The six Phase-1 Software Design Documents under
[`docs/sdd/`](docs/sdd/) are the design-rationale layer for
every cross-cutting feature:

- [`001-ai-machine-end-to-end.md`](docs/sdd/001-ai-machine-end-to-end.md) — Tetragon collector raw subobject + agent-guard sigma rule + AI-machine pipeline test.
- [`002-defaults-that-work.md`](docs/sdd/002-defaults-that-work.md) — `[daemon_requires]` manifest contract.
- [`003-vpn-bridge-multi-instance.md`](docs/sdd/003-vpn-bridge-multi-instance.md) — per-profile `instanced` capability.
- [`004-security-threat-model.md`](docs/sdd/004-security-threat-model.md) — SECURITY.md rewrite (Assets, Adversaries, Mitigations).
- [`005-test-contract.md`](docs/sdd/005-test-contract.md) — four test categories + three shared patterns.
- [`006-shared-module-script-lib.md`](docs/sdd/006-shared-module-script-lib.md) — `packaging/lib/module-lib.sh`.

All six SDDs are `implemented`. The implementation PR for
each one carries a back-reference; the findings ledger at
[`docs/review/99-findings-ledger.md`](docs/review/99-findings-ledger.md)
maps every Phase-1 finding to its closing PR.

## Out of scope

- Multi-tenant SIEM. This is single-host (or small
  homogeneous fleet via Ansible) tooling.
- Cloud-native log shipping at scale. If you outgrow this,
  you outgrow it.
- Anything resembling offensive action against attackers.
