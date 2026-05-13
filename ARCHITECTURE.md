# Architecture

## Layered view

```
                ┌────────────────────────────────────────────────────────────┐
                │                       Control plane                        │
                │   selfdefctl  ·  PWA dashboard  ·  ntfy/signal  ·  Promet. │
                └────────────────────────┬───────────────────────────────────┘
                                         │ HTTP API + /metrics
┌────────────────────────────────────────────────────────────────────────────┐
│                              selfdef-daemon                                │
│  ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐         │
│  │ Collectors │──▶│    Bus     │──▶│ Correlator │──▶│ Responder  │         │
│  │            │   │            │   │            │   │            │         │
│  │ • auditd   │   │  in-proc   │   │  Sigma +   │   │ • lockdown │         │
│  │ • journald │   │  broadcast │   │  windowed  │   │ • notify   │         │
│  │ • tetragon │   │  (NATS opt)│   │  rules     │   │ • snapshot │         │
│  │ • suricata │   │            │   │            │   │ • isolate  │         │
│  │ • canary   │   │            │   │            │   │ • forensics│         │
│  │ • eventstr │   │            │   │            │   │ • veloc.   │         │
│  │ • ebpf     │   │            │   │            │   │            │         │
│  └────────────┘   └─────┬──────┘   └─────┬──────┘   └─────┬──────┘         │
│                         │                 │                 │              │
│                         ▼                 ▼                 ▼              │
│              ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│              │   Store      │  │  Notifier    │  │   Actions            │  │
│              │ SQLite + DDB │  │ ntfy/signal  │  │  nft/systemd/scripts │  │
│              └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                         │                                                  │
│                         ▼                                                  │
│              ┌────────────────────────┐                                    │
│              │   API + /metrics       │  bearer-token auth on TCP;         │
│              │   /status /events      │  unix-socket auth via fs perms.    │
│              │   /findings /metrics   │  Prometheus scrapes /metrics.      │
│              └────────────────────────┘                                    │
└────────────────────────────────────────────────────────────────────────────┘

                ┌──────────────────────────────────────────────────────┐
                │                  Kernel & system                     │
                │   Tetragon · custom eBPF (aya) · auditd · AppArmor   │
                └──────────────────────────────────────────────────────┘
```

### Modules layer

Operator-activatable modules sit on top of the daemon, each with its
own apply / check / uninstall lifecycle (`selfdefctl modules apply`).
Module phases (`pre / main / post`) order the apply across modules
that share substrate. The current catalog:

```
phase=pre        tetragon (substrate)        integrity-sentinel (drift)
                          │                          │
phase=main       agent-guard (5 policies)    bridge-l2 → suricata, polarproxy
                          │                  vpn-bridge (3 profiles, instanced)
                          │
phase=post       observability (Prometheus + Grafana)
```

Modules emit structured-status JSON to the CLI dispatcher. Some
modules (e.g. `integrity-sentinel`) optionally emit OCSF events via
`selfdefctl events emit` into a JSONL stream the daemon's
`eventstream` collector tails — closing the loop back into the bus.

## Core principles

**Schema first.** Every collector emits an `Event` in a single shape (OCSF-aligned).
Adding a collector means parsing its native format into that shape — nothing else
in the system changes. Adding a rule means matching against that shape — no
collector knowledge needed. This decouples the moving parts.

**In-proc bus by default, network bus by exception.** A single daemon hosts all
the modules. Inter-module communication is a tokio broadcast channel. When you
need to fan events out to other hosts (a log host, a correlator on another box),
you opt in to the NATS JetStream sink. Most personal-scale deployments stay
in-proc forever.

**Detection-as-code.** Rules live in `rules/`, are version-controlled, are
unit-tested against a replay corpus in CI, and have ATT&CK mappings. The
correlator hot-reloads them on SIGHUP. New detection = a PR, not a deploy.

**Responder is dumb on purpose.** Actions are small, idempotent, and explicit
(`lockdown_egress`, `kill_pid`, `revoke_session`, `snapshot_proc`, `notify`).
The correlator decides; the responder does. Complex playbooks compose simple
actions.

**Privilege separation.** The daemon runs unprivileged where it can. Collectors
that need capabilities (auditd: `CAP_AUDIT_READ`, suricata socket: `CAP_NET_RAW`)
have them granted explicitly via systemd, never via setuid.

## Data lifecycle

```
event happens → collector parses → bus broadcasts → {store, correlator}
                                                        │
                          ┌─────────────────────────────┘
                          ▼
                    rule matches → action(s) emitted → responder runs
                                                        │
                                          ┌─────────────┘
                                          ▼
                            notifier sends to ntfy / signal
                            optional: snapshot, lockdown, isolate
```

Hot store: SQLite WAL, 7-30 days, indexed.
Warm store: DuckDB over Parquet, 90 days+, analytical queries.
Cold: rsync/restic-shipped Parquet to an off-host bucket — write-once forensic record.

## Self-protection of the daemon

The daemon is the most valuable target on the host. Treated accordingly:

- Static binary, stripped, signed (cosign), reproducibly built.
- Runs as a dedicated unprivileged user with a tight systemd unit (see
  `packaging/systemd/selfdefd.service`).
- AppArmor profile restricts FS and network access.
- Configuration and rules are read-only at runtime (re-read on SIGHUP only).
- State (sqlite, parquet) lives on a path the daemon can write but most
  other tools cannot.
- Long-term: ship rules and binary on a dm-verity / systemd-sysext immutable
  layer so even root tampering is detected.

## Out of scope

- Multi-tenant SIEM. This is single-host (or small homogeneous fleet via
  Ansible) tooling.
- Cloud-native log shipping at scale. If you outgrow this, you outgrow it.
- Anything resembling offensive action against attackers.
