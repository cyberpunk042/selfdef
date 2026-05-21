# SDD-028 — Real-Time Security Perimeter Engine — Tetragon kernel-fence

> Status: **implemented** — MS047 reached end-to-end production
> 2026-05-20 across every layer:
>  - `crates/selfdef-perimeter` (Tetragon-fed verdict log + SHA-256
>    chained audit + signed-extension verification + coexistence
>    overlap detector per SDD-015)
>  - `selfdefctl perimeter {show, history, extend, revoke, check-
>    overlap, status, audit-cycle replay}` CLI verbs
>  - `GET /v1/perimeter{,/history}` HTTP surface
>  - Dashboard "Perimeter" panel
>  - L2 bats coverage: `packaging/test/L2-perimeter.bats`
>  - L1 coherence: `L1-perimeter-yaml-lint` + others
>  - Prometheus alerts: `SelfdefPerimeterSigkill`,
>    `SelfdefPerimeterPolicyMissing`, `SelfdefPerimeterChainBroken`
>  - Operator runbooks: `perimeter-{tetragon-not-running, policy-
>    load-failure, extension-create, sigkill-investigation,
>    key-rotation, audit-log-corruption}.md` (6 runbooks, info-hub)
> Owner: operator-supervised; agent-authored
> Last updated: 2026-05-21 (status: draft → implemented)
> Implements milestone: MS047 (catalogued in `backlog/milestones/MS047-real-time-security-perimeter-engine-tetragon-kernel-fence.md`)
> Source: `~/infohub/raw/dumps/2026-05-15-sain-01-master-spec-other-conversation-transposition.md` §6 lines 380–411
> Companions: SDD-027 (friction-audit), SDD-016 (oracle triage channel), SDD-004 (security threat model)

## Problem

Sain-01 §6 catalogs a Tetragon TracingPolicy named `sovereign-kernel-fence` that fires SIGKILL in-kernel on every `sys_execve` attempting to launch a binary not in the default allowlist `{/usr/bin/python3, /usr/bin/nvidia-smi, /usr/local/bin/vllm, /usr/bin/podman}`. Friction-audit (MS046 / SDD-027) gates at hardware-frame; the perimeter gates at kernel-syscall — they're complementary boundary organs. Without the perimeter, an attacker who survived hardware gating can still execve arbitrary binaries with whatever capabilities they hold.

MS047 catalog defines 240 R-rows binding the verbatim sain-01 §6 YAML, the OCSF Detection 2004 emission on Sigkill, the operator-signed allowlist-extension flow (MS003 multi-sig), the typed-mirror crate for cockpit + TUI binding, and the cross-cutting MS003/MS007/MS009/MS016/MS017/MS019/MS020/MS024/MS026/MS027/MS039/MS040/MS041/MS042/MS043/MS044/MS045/MS046 wiring.

This SDD describes the **production deliverables** for that catalog.

## Required coverage

### Deliverable 1 — TracingPolicy YAML `sovereign-perimeter.yaml`

**File:** `packaging/tetragon-policies/sovereign-perimeter.yaml`
**Installed to:** `/etc/tetragon/tracing-policies/sovereign-perimeter.yaml` (mode 0644, owner root:root, chattr +i applied post-install)

Verbatim transposition of sain-01 §6 with explicit operator-extension comments:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sovereign-kernel-fence"
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotIn"
        values:
        - "/usr/bin/python3"
        - "/usr/bin/nvidia-smi"
        - "/usr/local/bin/vllm"
        - "/usr/bin/podman"
      matchActions:
      - action: Sigkill
```

Operator-extensions tagged in YAML comments:
- The default allowlist is sain-01 §6 verbatim; operators extend via signed manifests at `/etc/selfdef/perimeter-extensions/*.json` (Deliverable 4)
- The policy must be loaded into Tetragon's namespace per MS047 R11117

### Deliverable 2 — Mirror crate `selfdef-perimeter-mirror`

**Crate path:** `crates/selfdef-perimeter-mirror/`
**License:** AGPL-3.0-or-later
**Pattern:** MS007 read-only typed-mirror (cross-references selfdef-friction-audit-mirror, selfdef-capability-mirror, selfdef-quarantine-mirror)

Exports `Verdict { attempted_binary_path, attempting_pid, parent_pid, cgroup, container_id, process_cmdline, ts_ms, signer_kid_policy, signer_kid_extension? }` per MS047 R11128-R11132.

### Deliverable 3 — Runtime crate `selfdef-perimeter`

**Crate path:** `crates/selfdef-perimeter/`

Owns the runtime authority surface:
- Extension manifest loader (`/etc/selfdef/perimeter-extensions/*.json`, MS003-signed, multi-sig ≥ 2, TTL ≤ 30 days)
- Tetragon UNIX-socket event ingester (MS044 Guardian Daemon consumes these too — shared upstream)
- OCSF Detection 2004 emitter per Sigkill (one event per terminated execve)
- ZFS log bridge writer (atomic append to `tank/vault/context/perimeter.log`)
- Audit chain (Merkle-style chained `prev_event_sha256`)

### Deliverable 4 — CLI subcommand `selfdefctl perimeter`

**Path:** subcommand added to `crates/selfdef-cli/src/main.rs`

Subcommands:
- `selfdefctl perimeter show [--json]` — active policy summary + last N Sigkill verdicts
- `selfdefctl perimeter history --since <duration>` — Sigkill verdict log
- `selfdefctl perimeter extend --signed <manifest>` — Ring 0 + MS003 multi-sig gated
- `selfdefctl perimeter revoke <ext-id>` — Ring 0 + MS003 sig gated
- `selfdefctl perimeter audit-cycle replay` — re-evaluate baseline against current policy (cross-ref MS009)

### Deliverable 5 — Debian packaging extension

- `packaging/debian/postinst` — copy YAML to `/etc/tetragon/tracing-policies/`, chattr +i, reload Tetragon
- `packaging/debian/postrm` — chattr -i + remove on purge
- Bash hook to verify Tetragon is running + the policy is loaded

### Deliverable 6 — Test contract

L1 (yaml-lint) — `scripts/test/L1-perimeter-yaml-lint.sh` — TracingPolicy YAML schema-valid
L2 (bats) — `packaging/test/L2-perimeter.bats` — install/uninstall flow + chattr immutability
L3 (nspawn) — `scripts/test/L3-perimeter-nspawn.sh` — Tetragon hot-reload + Sigkill verification with mocked syscall
L4 (znver5 hw) — gated on actual hardware
L5 (chaos) — kill Tetragon mid-execution, verify Guardian Daemon detects + alerts

### Deliverable 7 — Operator runbooks (info-hub second brain)

**Path:** `~/devops-solutions-information-hub/wiki/runbooks/`

Five runbooks:
- `perimeter-tetragon-not-running.md` — Tetragon stopped / crashed
- `perimeter-policy-load-failure.md` — TracingPolicy YAML rejected by Tetragon
- `perimeter-extension-create.md` — operator-signed allowlist extension procedure
- `perimeter-sigkill-investigation.md` — investigate an unexpected Sigkill
- `perimeter-key-rotation.md` — MS003 key rotation for the perimeter signer

### Deliverable 8 — HTTP API endpoints

`GET /v1/perimeter` — active policy + last 16 Sigkill verdicts + active extensions
`GET /v1/perimeter/history?limit=N` — Sigkill verdict history

### Deliverable 9 — Sovereign-os cockpit panel

**Crate path (in sovereign-os):** `crates/sovereign-cockpit-perimeter-panel/`
**Pattern:** sister to `sovereign-cockpit-friction-audit-panel`

Read-only consumer of the selfdef-emitted perimeter OCSF jsonl + extension manifest set. Cross-repo project boundary preserved (operator standing direction "Respect the projects").

### Deliverable 10 — Daemon integration

`selfdefd` boot logs surface perimeter state alongside friction-audit (sister observability point).

## Cross-cutting wiring

| MS047 R-row | Bound to | This SDD section |
|---|---|---|
| R11041-R11075 | TracingPolicy verbatim structure + behavior | Deliverable 1 |
| R11077-R11086 | Override manifest signing + audit chain | Deliverable 3 |
| R11088-R11102 | OCSF Detection emission | Deliverable 3 |
| R11103-R11109 | ZFS log bridge | Deliverable 3 |
| R11110-R11113 | Ring buffer | Deliverable 3 |
| R11114-R11121 | Tetragon ordering | Deliverable 1 + 5 |
| R11122-R11127 | Guardian Daemon (MS044) wiring | Deliverable 3 |
| R11128-R11135 | Typed mirror | Deliverable 2 |
| R11136-R11142 | Sovereign-OS panel binding | Deliverable 9 |
| R11143-R11157 | TUI / CLI surface | Deliverable 4 |
| R11176-R11240 | Failure-mode taxonomy + threat-model + test | Deliverable 6 + 7 |

## Production-readiness gates

| Gate | Verification |
|---|---|
| TracingPolicy YAML lints clean | `yamllint packaging/tetragon-policies/sovereign-perimeter.yaml` exits 0 |
| Mirror crate compiles + tests | `cargo test -p selfdef-perimeter-mirror` exit 0 |
| Runtime crate compiles + tests | `cargo test -p selfdef-perimeter` exit 0 |
| CLI subcommand present + help synopses | `selfdefctl perimeter --help` lists 5 subcommands |
| Debian postinst extends cleanly | dpkg-deb verify + ShellCheck clean |
| OCSF events emitted on Sigkill | sample payload validates against OCSF schema |
| HTTP API endpoints serve | curl /v1/perimeter returns JSON |
| Sovereign-os panel binding compiles + tests | `cargo test -p sovereign-cockpit-perimeter-panel` exit 0 |
| 5 operator runbooks exist | `ls ~/devops-solutions-information-hub/wiki/runbooks/perimeter-*.md \| wc -l` returns 5 |
| Daemon surfaces perimeter state at boot | `journalctl -u selfdefd \| grep perimeter` produces expected log lines |

## Implementation order

1. Deliverable 2 (mirror crate) — runtime-agnostic, no dependencies
2. Deliverable 1 (TracingPolicy YAML) — pairs with Deliverable 5 (postinst install)
3. Deliverable 5 (Debian packaging extension)
4. Deliverable 6-L1 (yaml-lint) — gates 1+5
5. Deliverable 3 (runtime crate) — depends on 2
6. Deliverable 4 (CLI subcommand) — depends on 2+3
7. Deliverable 6-L2/L3 (bats + nspawn)
8. Deliverable 8 (HTTP API endpoints) — depends on 3
9. Deliverable 10 (daemon integration) — depends on 3
10. Deliverable 9 (sovereign-os panel binding) — depends on 2
11. Deliverable 7 (operator runbooks) — operator-supervised authoring

This SDD authorizes Stage-2 implementation. Mark DONE only when all ten deliverables are in production.

— End of SDD-028.
