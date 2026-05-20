# SDD-029 — Guardian Daemon — Tetragon eBPF supervisor + SIGKILL + atomic ZFS audit logs

> Status: **draft** — Stage-1 (watchdog layer for SDD-027 + SDD-028)
> Owner: operator-supervised; agent-authored
> Last updated: 2026-05-20
> Implements milestone: MS044 (catalogued in `backlog/milestones/MS044-guardian-daemon-tetragon-ebpf-supervisor.md`)
> Source: `~/infohub/raw/dumps/2026-05-15-sain-01-master-spec-other-conversation-transposition.md` §10 lines 513-588 + Phase V lines 712-721 + Trinity Genesis Auditor dump 977-981
> Companions: SDD-027 (friction-audit, hardware-frame), SDD-028 (perimeter, kernel-syscall), SDD-004 (security threat model)

## Problem

Sain-01 §10 catalogs `guardian-core` — "High-Standard Native Security Watcher" — a daemon that listens on `/var/run/tetragon/tetragon.events`, classifies policy violations, and executes the verbatim 3-step response: instant SIGKILL via `podman kill`, atomic append to `tank/vault/context/security_audit.log` (ZFS `sync=always`), native console alert (`/dev/console` PC-speaker bell).

SDD-027 (friction-audit) gates at hardware-frame. SDD-028 (perimeter) gates at kernel-syscall. **Guardian is the watchdog for both** — when Tetragon itself stops (the runbooks I wrote literally reference `selfdef-guardian.service` as the supervisor), Guardian alerts. When Tetragon fires SIGKILL on a Detection 2004 event, Guardian fans out the supervisor-tier response (audit-log + console alert).

MS044 catalog defines 240 R-rows (R10321-R10560) binding the verbatim sain-01 §10 architecture, OCSF Detection 2004 + Audit 1003 emission paths, MS003 signing chain, the cross-cutting Ring 0 placement (MS039), MS024 communication boundary, MS037 filesystem boundary, MS007 typed-mirror exposure, and MS009 replay invariants.

This SDD describes the **production deliverables** for that catalog.

## Required coverage

### Deliverable 1 — Mirror crate `selfdef-guardian-mirror`

**Crate path:** `crates/selfdef-guardian-mirror/`
**License:** AGPL-3.0-or-later
**Pattern:** MS007 read-only typed-mirror (cross-references selfdef-friction-audit-mirror, selfdef-perimeter-mirror).

Exports `Verdict { event_id, action, target_pid, target_cgroup, target_container_id, target_binary_path, response_steps, ts_ms, hostname, signer_kid_policy }` and `ResponseStep { Sigkill, AuditAppend, ConsoleAlert }` per MS044 R10481-R10485 typed-mirror discipline.

### Deliverable 2 — Runtime crate `selfdef-guardian`

**Crate path:** `crates/selfdef-guardian/`

Owns the runtime authority surface:
- Tetragon UNIX-socket event ingester (`/var/run/tetragon/tetragon.events`)
- JSON event parser + violation classifier (action == "SIGKILL" OR process-related)
- 3-step response orchestrator:
  - Step 1 — `podman kill <container_id>` (when container_id present) or `kill -9 <pid>` (host scope)
  - Step 2 — atomic append to `/mnt/vault/context/security_audit.log` (O_APPEND + fsync)
  - Step 3 — console alert (write ASCII BEL `\x07` + diagnostic line to `/dev/console`)
- OCSF Detection 2004 (failure) + Audit 1003 (success) emitter
- MS003 policy-signer chain
- Circuit-breaker state machine (R10399-R10410 per catalog)

### Deliverable 3 — Systemd unit `selfdef-guardian.service`

**Path:** `packaging/systemd/selfdef-guardian.service`

Per sain-01 §10 dump 569-588 (verbatim transposition with operator-extension comments). Type=simple, Restart=always, After=tetragon.service, hardening (NoNewPrivileges, ProtectSystem=strict, etc.). The watchdog itself is supervised by systemd's `Restart=always` so a Guardian crash auto-restarts.

### Deliverable 4 — CLI subcommand `selfdefctl guardian`

**Path:** subcommand added to `crates/selfdef-cli/src/main.rs`

Subcommands:
- `selfdefctl guardian show [--json]` — daemon state + last N events processed
- `selfdefctl guardian history --limit <N>` — Guardian event log (newest-first)
- `selfdefctl guardian replay <event-id>` — re-classify a stored event (MS009 replay invariant; operator-triggered, never automatic)
- `selfdefctl guardian rollback <event-id>` — operator-signed false-positive rollback (Ring 0 + MS003)

### Deliverable 5 — Debian packaging extension

- `packaging/debian/postinst` — install systemd unit (does NOT auto-start; operator decides), pre-create `/mnt/vault/context/` if ZFS present
- `packaging/debian/postrm` — disable + stop on purge

### Deliverable 6 — Test contract

- L1 (rust-test) — `cargo test -p selfdef-guardian-mirror`, `cargo test -p selfdef-guardian` — unit coverage of Verdict validation + event classifier + responder mock
- L2 (bats) — `packaging/test/L2-guardian.bats` — postinst install + systemd unit validation
- L3 (nspawn) — `scripts/test/L3-guardian-nspawn.sh` — synthetic Tetragon event → Guardian classifier → mocked podman kill + log append
- L4 (znver5 hw) — operator-hardware-gated
- L5 (chaos) — kill Guardian mid-flight, verify systemd `Restart=always` resurrects it within 5s

### Deliverable 7 — Operator runbooks (info-hub second brain)

**Path:** `~/devops-solutions-information-hub/wiki/runbooks/`

Five runbooks:
- `guardian-not-running.md` — Guardian service stopped / crashed
- `guardian-socket-unreachable.md` — Tetragon UNIX socket missing / permissions
- `guardian-false-positive-rollback.md` — operator rollback procedure
- `guardian-audit-log-corruption.md` — ZFS log integrity recovery
- `guardian-console-alert-investigation.md` — operator triage of an alert

### Deliverable 8 — HTTP API endpoints

`GET /v1/guardian` — daemon state + last 16 events + circuit-breaker state
`GET /v1/guardian/history?limit=N` — event history

### Deliverable 9 — Sovereign-os cockpit panel

**Crate path (in sovereign-os):** `crates/sovereign-cockpit-guardian-panel/`
**Pattern:** sister to `sovereign-cockpit-friction-audit-panel` + `sovereign-cockpit-perimeter-panel`

Read-only consumer of selfdef-emitted Guardian event jsonl. Cross-repo project boundary preserved.

### Deliverable 10 — Daemon integration

`selfdefd` boot logs surface Guardian state alongside friction-audit + perimeter (sister observability point completing the three-watchdog trio).

## Cross-cutting wiring

| MS044 R-row | Bound to | This SDD section |
|---|---|---|
| R10321-R10325 | Doctrinal anchors (sain-01 §10 verbatim) | Deliverable 2 |
| R10326-R10380 | UNIX-socket event ingester + classifier | Deliverable 2 |
| R10381-R10398 | 3-step response orchestrator | Deliverable 2 |
| R10399-R10410 | Circuit-breaker state machine | Deliverable 2 |
| R10411-R10440 | Systemd unit + hardening | Deliverable 3 |
| R10441-R10470 | OCSF Detection 2004 + Audit 1003 emission | Deliverable 2 |
| R10471-R10480 | ZFS log bridge (tank/vault/context/security_audit.log) | Deliverable 2 |
| R10481-R10485 | Typed mirror crate | Deliverable 1 |
| R10486-R10510 | HTTP API + cockpit panel binding | Deliverable 8 + 9 |
| R10511-R10540 | CLI subcommand surface | Deliverable 4 |
| R10541-R10560 | Closing + cross-repo discipline | Deliverable 9 |

## Production-readiness gates

| Gate | Verification |
|---|---|
| Mirror crate compiles + tests | `cargo test -p selfdef-guardian-mirror` exit 0 |
| Runtime crate compiles + tests | `cargo test -p selfdef-guardian` exit 0 |
| Systemd unit ShellCheck/syntax clean | `systemd-analyze verify packaging/systemd/selfdef-guardian.service` exit 0 |
| CLI subcommand present | `selfdefctl guardian --help` lists 4 subcommands |
| Debian postinst extends cleanly | dpkg-deb verify + ShellCheck clean |
| OCSF emission validates against schema | sample payload validates |
| HTTP API endpoints serve | `curl /v1/guardian` returns JSON |
| Sovereign-os panel compiles + tests | `cargo test -p sovereign-cockpit-guardian-panel` exit 0 |
| 5 operator runbooks exist | `ls ~/devops-solutions-information-hub/wiki/runbooks/guardian-*.md \| wc -l` returns 5 |
| Daemon surfaces guardian state at boot | `journalctl -u selfdefd \| grep guardian` produces expected log lines |

## Implementation order

1. Deliverable 1 (mirror crate) — runtime-agnostic, no dependencies
2. Deliverable 2 (runtime crate) — depends on 1
3. Deliverable 3 (systemd unit)
4. Deliverable 5 (Debian packaging extension) — depends on 3
5. Deliverable 6-L1/L2 (rust-test + bats) — gates 1+2+3+5
6. Deliverable 4 (CLI subcommand) — depends on 1+2
7. Deliverable 8 (HTTP API endpoints) — depends on 2
8. Deliverable 10 (daemon integration) — depends on 2
9. Deliverable 9 (sovereign-os panel) — depends on 1 (mirror) — cross-repo
10. Deliverable 7 (operator runbooks) — operator-supervised authoring

This SDD authorizes Stage-2 implementation. Mark DONE only when all ten deliverables are in production.

— End of SDD-029.
