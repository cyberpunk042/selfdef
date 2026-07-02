# The four-watchdog set

Beyond the core detect→correlate→respond pipeline, selfdef runs **four
independent watchdogs** (MS046 / MS047 / MS044 / MS048). Each is its own
daemon-side subsystem with its own API endpoints, Prometheus alerts,
SHA-256-chained OCSF audit log, and info-hub runbooks. The bundled
dashboard's four-watchdog row and the Grafana template's four-watchdog
group render them side by side.

| Watchdog | Milestone | Job | API |
|---|---|---|---|
| **friction-audit** | MS046 | Boot-time hardware-integrity gate: every shipped gate (PCIe topology, memory, ZFS, signatures, immutability) must Pass — or carry an operator override — before the node is trusted. | `GET /v1/friction-audit`, `/history` |
| **perimeter** | MS047 | Real-time kernel fence: Tetragon TracingPolicy SIGKILLs `sys_execve` outside the verbatim allowlist — in-kernel, no userspace round-trip. | `GET /v1/perimeter`, `/history` |
| **guardian** | MS044 | Supervisor tier: tails the Tetragon UNIX socket (`/var/run/tetragon/tetragon.events`) and executes the 3-step response — SIGKILL (container-aware via podman) → atomic ZFS audit-log append → console bell. | `GET /v1/guardian`, `/history` |
| **scheduler** | MS048 | Goldilocks hardware-aware routing: PSI + DCGM + IPS-human-gate backpressure → scoring kernel → `Route` decision (oracle / scout / cortex / deferred), each decision audited + exported. | `GET /v1/scheduler`, `/history`, `/explain`, `/backpressure` |

## Shared discipline

Every watchdog follows the same contract, so operating one teaches all four:

- **Audit chain** — each appends OCSF lines where every line carries the
  recomputed SHA-256 of the previous line's content. Tampering, reordering,
  insertion, and head-truncation all break the chain;
  `audit_chain_check` runs on every API query and metric scrape.
  Tail-truncation is answered by real-time off-host shipping (the
  sovereign-os mirror + NATS), not by local walk.
- **Alerts + runbooks** — the `observability` module ships alert rules for
  each watchdog (failing gate / SIGKILL / failed response / sustained
  backpressure + the chain-broken alerts), every one with a `runbook_url`
  into the info-hub wiki. Start at the alert; the runbook has the
  journald signature and the remediation.
- **Mirrors** — each watchdog has a `selfdef-*-mirror` crate publishing its
  typed read-only state for the sovereign-os cockpit (M060 publishers,
  health visible in the Grafana M060 group).
- **Coherence gates** — `scripts/test/coherence.sh` locks the four-watchdog
  dashboard sections, Grafana series, alert rules, systemd hardening, and
  the cross-repo alert↔runbook binding in CI.

## Where to go deeper

- Scheduler failure modes (alert → §-by-§ remediation):
  `docs/operator/ms048-scheduler-failure-modes.md`
- Scheduler cross-repo contract: `docs/operator/ms048-scheduler-integration-contract.md`
- Guardian implementation: `scripts/guardian/guardian-core` + SDD-029
- Runbook fleet index:
  [`wiki/runbooks/_index.md`](https://github.com/cyberpunk042/devops-solutions-information-hub/blob/main/wiki/runbooks/_index.md)
  in the info-hub
