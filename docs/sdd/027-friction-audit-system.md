# SDD-027 — Friction Audit System — boot-time hardware-integrity gate

> Status: **draft** — Stage-1 (Cycle-3 forward-looking artifacts arc, branch into SAIN-01 hardware-tier defense)
> Owner: operator-supervised; agent-authored
> Last updated: 2026-05-20
> Implements milestone: MS046 (catalogued in `backlog/milestones/MS046-friction-audit-system-boot-time-hardware-integrity-gate.md`)
> Source: `~/infohub/raw/dumps/2026-05-15-sain-01-master-spec-other-conversation-transposition.md` §5 lines 338–378
> Companions: SDD-013 (deployment.target), SDD-017 (SAIN-01 hardware inventory), SDD-022 (hardware exploit doctrine)
> Cross-repo: sovereign-os M060 dashboard panel (read-only consumer); operator standing direction 2026-05-19 *"if I talk about an IPS feature its obviously not in Sovereign-OS"*

## Problem

SAIN-01 spec §5 catalogs a `/usr/local/bin/friction-audit` boot-time script that gates podman.service/docker.service startup on three hardware-integrity checks (PCIe x8/x8 bifurcation symmetry, ZFS pool health, system memory geometry). The script is the **first IPS gate** to fire on every cold boot — before any container runtime, before any model is loaded, before any operator session begins. Without it the substrate that everything else runs on is unaudited.

MS046 catalog defines 240 R-rows mapping verbatim to sain-01 §5 + cross-cutting bindings to MS003 signing, MS007 mirrors, MS009 audit-cycle, MS016 eBPF, MS020 test, MS026 OCSF, MS027 observability, MS039 Ring 0, MS040 authority profile, MS041 commit authority, MS043 TUI binding, MS044 Guardian Daemon, and sovereign-os M060/M068/M071/M072. This SDD describes the **production deliverables** for that catalog: shipped script, shipped systemd unit, shipped mirror crate, shipped CLI bindings, shipped Debian packaging, shipped tests.

Standing-rule reminder: *"DO NOT STOP AT DEFINING/REGISTERING THE REQUIREMENT and doing the scaffolds, we expect the full production progressively through the workflow"* (operator 2026-05-20).

## Required coverage

### Deliverable 1 — Bash script `friction-audit`

**File:** `packaging/scripts/friction-audit.sh`
**Installed to:** `/usr/local/bin/friction-audit` (mode 0755, owner root:root, chattr +i applied post-install)

Verbatim transposition of sain-01 §5 with operator-extensions explicitly tagged:
- Strict mode `set -euo pipefail`
- Three gates in fixed order: PCIe (exit 1) → ZFS (exit 2) → memory (exit 3, operator-extended)
- Diagnostic messages verbatim to sain-01 (PCIe failure msg lines 1-3 exact)
- Success line verbatim: `[*] Hardware Matrix Audited Successfully. Initializing System Layers.`
- Operator extensions: timeout-budget watchdog (2000 ms hard cap, exit 4), OCSF JSONL emit path `/var/log/selfdef/friction-audit.ocsf.jsonl`, optional ZFS log bridge via `tank/vault/context/friction.log` when `tank/vault` is mounted.

### Deliverable 2 — systemd unit `sovereign-guard.service`

**File:** `packaging/systemd/sovereign-guard.service`
**Installed to:** `/etc/systemd/system/sovereign-guard.service`

Verbatim transposition of sain-01 §5.2:
```
[Unit]
Description=Sovereign Platform Hardware Sanity Enforcer
After=zfs-arc-tune.service
Before=podman.service docker.service containerd.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/friction-audit
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Operator-extension: `containerd.service` added to `Before=` (sain-01 baseline covers podman/docker; kubernetes hosts also need containerd ordering — per MS046 F05438).

Drop-in directory `/etc/systemd/system/sovereign-guard.service.d/` is conventionally created for operator-signed override manifests (MS003 binding).

### Deliverable 3 — Mirror crate `selfdef-friction-audit-mirror`

**Crate path:** `crates/selfdef-friction-audit-mirror/`
**License:** AGPL-3.0-or-later (matches selfdef workspace)
**Pattern:** MS007 read-only typed-mirror (cross-references `selfdef-capability-mirror`, `selfdef-quarantine-mirror`, `selfdef-grants-mirror`, `selfdef-audit-mirror`, `selfdef-cli-mirror`)

Exports `Verdict { gate, status, ts_ms, signer_kid_policy, signer_kid_extension? }` with:
- `Gate` enum: `Pcie | Zfs | Memory | Immutability | Signature | Timeout`
- `Status` enum: `Pass | Fail(u8) | OverrideActive`
- `schema_version: &str = "1.0.0"` (selfdef pattern)
- `serde::Serialize + Deserialize` with `#[serde(rename_all = "kebab-case")]`
- `validate()` method (schema version + non-empty signer_kid_policy)
- Read-only — no setter methods exposed publicly
- Feature `sovereign-os-consumer` for downstream consumer crate gating

### Deliverable 4 — Daemon-side runtime crate `selfdef-friction-audit`

**Crate path:** `crates/selfdef-friction-audit/`

Owns the **runtime authority surface** for the gate:
- Override manifest loader (`/etc/selfdef/overrides/friction-audit-<gate>.json`) — schema-validated, MS003-signed, TTL ≤ 7 days, multi-sig ≥ 2 distinct `signer_kid` for production profile
- OCSF Detection 2004 emitter on failure, OCSF Audit 1003 emitter on success
- ZFS log bridge — write to `tank/vault/context/friction.log` atomically (cross-ref sovereign-os M071 atomic-state, M068 ZFS)
- Ring buffer at `/var/cache/selfdef/friction-audit/ring/` (1-file-per-verdict, capped 256, FIFO eviction)
- Replay validator — captures `lspci -vvv`, `zpool status -x`, `dmidecode -t memory` baseline at install time; diff at replay-cycle exposes hardware drift
- Authority gate — Ring 0 only (MS039 binding), operator-signed extension creation requires MS003 multi-sig

### Deliverable 5 — CLI subcommand `selfdefctl friction-audit`

**Path:** subcommand added to `crates/selfdef-cli/src/main.rs`

Subcommands:
- `selfdefctl friction-audit show [--json]` — latest verdict summary
- `selfdefctl friction-audit history --since <duration>` — replay verdicts within window
- `selfdefctl friction-audit replay` — re-run gate non-destructively (cross-ref MS009 audit-cycle)
- `selfdefctl friction-audit override-status` — list active operator overrides + expiry
- `selfdefctl friction-audit override-create --gate <name> --reason <text> --expires-in <duration>` — Ring 0 only, MS003 multi-sig gated
- `selfdefctl friction-audit bundle` — produce signed operator-portable diagnostic bundle
- `selfdefctl friction-audit verify-bundle <path>` — verify a bundle's signature
- Common: `--json` flag returns structured output (MS043 R10131 binding); startup p95 ≤ 50 ms (MS043 R10137 binding)

### Deliverable 6 — Debian packaging extension

**Files:**
- `packaging/debian/postinst` — add post-install hooks: copy friction-audit script to `/usr/local/bin/`, `chattr +i`, install systemd unit, `systemctl daemon-reload`, `systemctl enable sovereign-guard.service`
- `packaging/debian/postrm` — add cleanup hooks: stop unit, disable, remove `/usr/local/bin/friction-audit` (after `chattr -i`), remove unit
- `packaging/scripts/friction-audit.sh` — installed via postinst

### Deliverable 7 — Test contract

L1 (shellcheck) — `scripts/test/L1-friction-audit-shellcheck.sh` — script is shellcheck-clean
L2 (unit, bats-core) — `scripts/test/L2-friction-audit-bats.bats` — mock `lspci`/`zpool`/`dmidecode` outputs, assert exit codes 0/1/2/3 + diagnostic strings verbatim
L3 (chroot boot-replay) — `scripts/test/L3-friction-audit-systemd.sh` — install via postinst into chroot, run via systemd-nspawn, assert exit + ordering invariant
L4 (znver5 hw) — `scripts/test/L4-friction-audit-hw.sh` — gated on actual reference hardware
L5 (chaos) — `scripts/test/L5-friction-audit-chaos.sh` — kill mid-execution, verify systemd recovery

### Deliverable 8 — Operator runbooks (info-hub second-brain)

**Path:** `~/devops-solutions-information-hub/wiki/runbooks/`

Five runbooks (one per failure-mode):
- `friction-audit-pcie.md` — PCIe x8/x8 bifurcation diagnosis + remediation
- `friction-audit-zfs.md` — zpool degraded states + recovery
- `friction-audit-memory.md` — DIMM seating + slot population
- `friction-audit-immutability.md` — chattr +i + IMA-appraise verification
- `friction-audit-signature.md` — MS003 signature failure + key rotation

## Cross-cutting wiring

| MS046 R-row | Bound to | This SDD section |
|---|---|---|
| R10801..R10810 | Script existence + immutability + signing | Deliverable 1 + 6 |
| R10812..R10832 | Three gates exact behavior | Deliverable 1 |
| R10833..R10844 | Override manifests + signing | Deliverable 4 |
| R10845..R10859 | OCSF emission + ZFS log bridge | Deliverable 4 |
| R10860..R10874 | systemd unit + ordering | Deliverable 2 |
| R10875..R10889 | Override audit chain (Merkle-like) | Deliverable 4 |
| R10891..R10905 | Typed mirror crate | Deliverable 3 |
| R10906..R10925 | CLI surface | Deliverable 5 |
| R10926..R10940 | Replay validator | Deliverable 4 + 7 |
| R10941..R10980 | Cross-cutting (MS003 / MS007 / MS009 / MS017 / MS022 / MS026 / MS027 / MS039 / MS040 / MS041 / MS042 / MS043 / MS044) | Each deliverable maps row-by-row in commit messages |
| R10981..R11040 | Tests + threat-model + sub-requirements | Deliverable 7 + 8 |

## Production-readiness gates (none of these may be skipped before MS046 is marked DONE)

| Gate | Verification |
|---|---|
| Script compiles + passes shellcheck (L1) | `shellcheck packaging/scripts/friction-audit.sh` exits 0 |
| Bats unit tests pass (L2) | `bats packaging/test/L2-friction-audit.bats` returns 0 |
| Mirror crate compiles + tests pass | `cargo test -p selfdef-friction-audit-mirror` returns 0 |
| Runtime crate compiles + tests pass | `cargo test -p selfdef-friction-audit` returns 0 |
| CLI subcommands present + `--help` synopses | `selfdefctl friction-audit --help` lists 7 subcommands |
| Debian postinst extension runs cleanly | dpkg-deb build verifies postinst syntax + ShellCheck-clean |
| systemd unit ordering invariant in nspawn (L3) | drop-in chroot test verifies `Before=podman.service` is honored |
| OCSF events emitted on Pass/Fail | sample payload validates against OCSF schema |
| Override manifest validation rejects must-not-touch | unit test for legal-compliance rejection per MS046 F05498 |
| Operator runbooks exist for all 5 failure-modes (Deliverable 8) | `ls ~/devops-solutions-information-hub/wiki/runbooks/friction-audit-*.md \| wc -l` returns 5 |

## Operator-extension explicit list

Every operator-extension MUST be tagged in the artifact source comments and in this SDD section:

- `containerd.service` added to `Before=` (Deliverable 2) — beyond sain-01 baseline; supports kubernetes hosts (MS046 F05438)
- Memory failure exit code = 3 (Deliverable 1) — sain-01 §5.1 leaves threshold open; operator-extended (MS046 F05491, R10831)
- Timeout watchdog exit code = 4 (Deliverable 1) — operator-extended (MS046 F05492)
- Optional ZFS log bridge degraded fallback (`/var/log/selfdef/friction-audit-offline.jsonl`) — operator-extended for offline-survivability (MS046 R10933, F05480)
- Override manifest TTL ≤ 7 days default (Deliverable 4) — sain-01 silent; operator-extended (MS046 R10873)
- Multi-sig ≥ 2 distinct signer_kid (Deliverable 4) — operator-extended for production profile (MS046 R11080 binding to MS040 authority profile)
- 5 failure-mode operator runbooks (Deliverable 8) — operator-extended; sain-01 doesn't require runbooks

## Out of scope for this SDD

- The sovereign-os M060 cockpit panel binding for friction-audit (sovereign-os crate `sovereign-cockpit-friction-audit-panel`). That's a sovereign-os project deliverable; this SDD ships the mirror crate so the sovereign-os panel has something to bind to. Sovereign-os panel SDD is filed separately.
- L4 (znver5 hardware-conformance) and L5 (chaos) test execution. Those require the actual SAIN-01 hardware; this SDD ships the L4/L5 scripts but does not gate completion on their execution.
- Hardware-replay baseline-collection automation. The replay validator captures baselines at install time; periodic recollection is operator-triggered (per MS046 R10927).

## Implementation order

1. Deliverable 1 (script) — most-portable, no dependencies
2. Deliverable 2 (systemd unit) — pairs with 1
3. Deliverable 7-L1 (shellcheck) — gates 1+2
4. Deliverable 3 (mirror crate) — runtime-agnostic
5. Deliverable 4 (runtime crate) — depends on 3
6. Deliverable 5 (CLI subcommand) — depends on 3+4
7. Deliverable 6 (Debian postinst) — depends on 1+2
8. Deliverable 7-L2/L3 (bats + nspawn tests) — depends on 1+2+6
9. Deliverable 8 (info-hub runbooks) — operator-supervised authoring, parallel-track

This SDD authorizes Stage-2 implementation. Per operator standing direction 2026-05-20, mark DONE only when all eight deliverables are in production.

— End of SDD-027.
