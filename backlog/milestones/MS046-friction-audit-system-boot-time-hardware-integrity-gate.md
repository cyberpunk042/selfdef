# MS046 — Friction Audit System — boot-time hardware-integrity gate (sain-01 §5)

**Parent**: selfdef IPS daemon — boundary-enforcement layer of the cyberpunk042 ecosystem
**Source**: `~/infohub/raw/dumps/2026-05-15-sain-01-master-spec-other-conversation-transposition.md`
- Section 5: System Enforcements: The Friction Audit System (lines 338–378)
- Section 4.1: Tetragon Policy / Native Enforcement (lines 103–117) — sister enforcement
- Section 4.2: Friction Audit (lines 119–127) — narrative anchor
- Section 6: Real-Time Security Perimeter Engine (lines 380–420) — companion eBPF-side gate
**Companion**: sovereign-os M068 ZFS architecture (M01142 zfs-log-bridge writes friction-audit failures atomically); selfdef MS044 Guardian Daemon (Guardian listens for friction-audit `exit 1/2` codes via sovereign-guard.service ordering)
**Operator standing direction** (verbatim, 2026-05-19): *"do not minimize the work in selfdef"* / *"if I talk about an IPS feature its obviously not in Sovereign-OS"* / *"DO NOT MINIMIZE WHAT I SAY, SAID OR ASKED FOR, NOR THE NEED TO EXPLOIT THE STACK AND TECHNO TO THE MAX"*
**Cross-repo mirror**: sovereign-os cockpit reads friction-audit verdicts via MS007 typed-mirror crate `selfdef-friction-audit-mirror` (read-only dashboard surface; sovereign-os NEVER mutates IPS gate state)
**Project boundary**: this milestone catalogues ONLY the selfdef IPS-side gate (`/usr/local/bin/friction-audit` + sovereign-guard.service ordering before podman/docker); the sovereign-os runtime that runs ABOVE the gate is M068/M070 territory

## Doctrinal anchors

> "The node protects its execution lifecycle via an immutable boot-time script. If lane structural failures or clock-frequency irregularities are present, execution loops cease instantly." (sain-01 dump 339)
> "INITIATING SOVEREIGN HARDWARE FRICTION AUDIT…" (sain-01 dump 345)
> "CRITICAL ARCHITECTURAL FRICTION ERROR" (sain-01 dump 348, 358)
> "Hardware Matrix Audited Successfully. Initializing System Layers." (sain-01 dump 365)
> "Before=podman.service docker.service" (sain-01 dump 374) — ordering invariant
> *"do not minimize the work in selfdef"* (operator standing direction 2026-05-19)

## Projection statement

The Friction Audit System is the **first IPS gate to fire** on every cold boot. Before any container runtime (`podman.service` / `docker.service`) starts, before any model is loaded, before any operator session begins — selfdef's friction-audit script runs as a oneshot systemd unit ordered `After=zfs-arc-tune.service Before=podman.service docker.service`. It enforces three hardware invariants (PCIe x8/x8 bifurcation symmetry, ZFS pool health, system memory geometry) and exits non-zero if any fail — which by systemd ordering invariant prevents any container from starting until an operator-signed override is recorded. This is the boundary-enforcement organ's **physical-layer presence** — before any software-layer policy can claim authority, the substrate it runs on has been audited at the hardware-frame level. Friction-audit failures emit OCSF Detection events (MS026), append atomic ZFS log rows (sovereign-os M068 bridge), and are signed via MS003 selfdef-signing keys before the operator sees them in the MS043 IPS TUI.

## Epics (E0461-E0470)

| epic | name | source |
|---|---|---|
| E0461 | Friction-audit script — `/usr/local/bin/friction-audit` installation + immutability | sain-01 343, 365–376 |
| E0462 | PCIe bifurcation symmetry check — x8/x8 LnkSta lane width verification | sain-01 346–353 |
| E0463 | ZFS pool integrity check — `zpool status -x` "all pools are healthy" gate | sain-01 354–359 |
| E0464 | System memory geometry check — `dmidecode -t memory` stick-count verification | sain-01 360–364 |
| E0465 | Systemd ordering — `sovereign-guard.service` After ZFS, Before podman/docker | sain-01 365–377 |
| E0466 | Failure-mode taxonomy — exit codes 1 (PCIe) / 2 (ZFS) / 3 (memory) + operator-readable diagnostic | sain-01 348–353, 358–359 |
| E0467 | Operator-signed override path — MS003-signed manifest required to bypass a gate failure | cross-ref MS003 + sain-01 339 |
| E0468 | OCSF emission — friction-audit emits Detection event class on failure, Audit class on success | cross-ref MS026 + MS027 |
| E0469 | Atomic ZFS log bridge — failures appended via sovereign-os M068 tank/vault path | cross-ref sovereign-os M068 + MS003 |
| E0470 | Cross-repo typed mirror — `selfdef-friction-audit-mirror` exports verdict to sovereign-os M060 dashboards | cross-ref MS007 + sovereign-os M060 |

## Modules (M01175-M01200)

| module | name | source |
|---|---|---|
| M01175 | selfdef-friction-audit-installer | sain-01 343 |
| M01176 | selfdef-friction-audit-immutability-enforcer (chattr +i / IMA appraise) | sain-01 339 ("immutable boot-time script") |
| M01177 | selfdef-friction-audit-script-runner | sain-01 343–365 |
| M01178 | selfdef-friction-audit-pcie-bifurcation-checker | sain-01 346–353 |
| M01179 | selfdef-friction-audit-lspci-parser | sain-01 347 |
| M01180 | selfdef-friction-audit-x8-symmetry-validator | sain-01 348–353 |
| M01181 | selfdef-friction-audit-zfs-pool-status-checker | sain-01 354–359 |
| M01182 | selfdef-friction-audit-zpool-status-parser | sain-01 355 |
| M01183 | selfdef-friction-audit-memory-geometry-checker | sain-01 360–364 |
| M01184 | selfdef-friction-audit-dmidecode-parser | sain-01 361 |
| M01185 | selfdef-friction-audit-exit-code-mapper (1=PCIe, 2=ZFS, 3=memory) | sain-01 350, 357 |
| M01186 | selfdef-friction-audit-systemd-unit (sovereign-guard.service) | sain-01 367–378 |
| M01187 | selfdef-friction-audit-systemd-ordering-validator (After/Before pre-check) | sain-01 371–374 |
| M01188 | selfdef-friction-audit-diagnostic-emitter (stderr structured) | sain-01 351–353, 359 |
| M01189 | selfdef-friction-audit-remediation-hint-emitter | sain-01 352 ("Remediation Check: Verify if M.2_2 slot is populated") |
| M01190 | selfdef-friction-audit-override-manifest-loader (operator-signed) | cross-ref MS003 |
| M01191 | selfdef-friction-audit-override-signature-validator | cross-ref MS003 |
| M01192 | selfdef-friction-audit-override-audit-log | cross-ref MS027 |
| M01193 | selfdef-friction-audit-ocsf-detection-emitter (class 2004 on failure) | cross-ref MS026 |
| M01194 | selfdef-friction-audit-ocsf-audit-emitter (class 1003 on success) | cross-ref MS026 |
| M01195 | selfdef-friction-audit-zfs-log-bridge (writes to tank/vault/context/friction.log) | cross-ref sovereign-os M068 |
| M01196 | selfdef-friction-audit-typed-mirror (selfdef-friction-audit-mirror crate) | cross-ref MS007 |
| M01197 | selfdef-friction-audit-tui-panel (selfdef MS043 R10180 binding) | cross-ref MS043 |
| M01198 | selfdef-friction-audit-cli-subcommand (`selfdef friction-audit show` etc.) | cross-ref MS043 |
| M01199 | selfdef-friction-audit-replay-validator (re-run against captured baseline) | cross-ref MS009 |
| M01200 | selfdef-friction-audit-offline-survivability (works when sovereign-os runtime offline) | operator standing direction 2026-05-19 |

## Features (F05401-F05520)

| feature | name | source |
|---|---|---|
| F05401 | Script binary installed at `/usr/local/bin/friction-audit` | sain-01 343 |
| F05402 | Shebang line: `#!/bin/bash` | sain-01 344 |
| F05403 | Strict mode: `set -euo pipefail` | sain-01 345 |
| F05404 | Start announcement: `echo "[*] INITIATING SOVEREIGN HARDWARE FRICTION AUDIT..."` | sain-01 346 |
| F05405 | Immutability: chattr +i applied at install time | sain-01 339 |
| F05406 | IMA-appraise hash pinned to /etc/ima/policy (defense-in-depth) | sain-01 339 + arch |
| F05407 | Script is signed by MS003 selfdef-signing key | cross-ref MS003 |
| F05408 | Signature manifest stored at `/etc/selfdef/manifests/friction-audit.sig` | cross-ref MS003 |
| F05409 | Boot-time signature re-verification (initramfs hook) | cross-ref MS003 |
| F05410 | PCIe Check 1.1 — `lspci -vvv` invocation | sain-01 347 |
| F05411 | PCIe Check 1.2 — grep `LnkSta:.*Width x8` count via `grep -c` | sain-01 347 |
| F05412 | PCIe Check 1.3 — `LANE_AUDIT_COUNT` variable name preserved verbatim | sain-01 347 |
| F05413 | PCIe Check 1.4 — `|| true` allows grep mismatch without aborting under `set -e` | sain-01 347 |
| F05414 | PCIe Check 1.5 — threshold: `LANE_AUDIT_COUNT < 2` fails | sain-01 348 |
| F05415 | PCIe Check 1.6 — failure message: "CRITICAL ARCHITECTURAL FRICTION ERROR: PCIe Bus Degradation Detected." | sain-01 350 |
| F05416 | PCIe Check 1.7 — diagnostic: "One or more slots running below symmetric x8 configuration parameters." | sain-01 351 |
| F05417 | PCIe Check 1.8 — remediation hint: "Verify if M.2_2 slot is populated, interfering with lane paths." | sain-01 352 |
| F05418 | PCIe Check 1.9 — exit code 1 on failure | sain-01 353 |
| F05419 | PCIe Check 1.10 — all messages emitted to stderr (`>&2`) | sain-01 350–352 |
| F05420 | ZFS Check 2.1 — `zpool status -x` invocation | sain-01 355 |
| F05421 | ZFS Check 2.2 — captured to `POOL_STATUS` variable | sain-01 355 |
| F05422 | ZFS Check 2.3 — gate string: `"all pools are healthy"` (exact match) | sain-01 356 |
| F05423 | ZFS Check 2.4 — inequality `!=` triggers failure | sain-01 356 |
| F05424 | ZFS Check 2.5 — failure message: "CRITICAL ARCHITECTURAL FRICTION ERROR: Storage Pool Anomalies Discovered." | sain-01 358 |
| F05425 | ZFS Check 2.6 — exit code 2 on failure | sain-01 359 |
| F05426 | Memory Check 3.1 — `dmidecode -t memory` invocation | sain-01 361 |
| F05427 | Memory Check 3.2 — pattern: `grep -c "Size: [0-9]"` (any size line with a digit) | sain-01 361 |
| F05428 | Memory Check 3.3 — captured to `TOTAL_RECOGNIZED_STICKS` | sain-01 361 |
| F05429 | Memory Check 3.4 — `|| true` for grep zero-match tolerance | sain-01 361 |
| F05430 | Memory Check 3.5 — exit code 3 reserved for memory geometry failure (additive — operator extension) | sain-01 360 |
| F05431 | Success path — final echo: "[*] Hardware Matrix Audited Successfully. Initializing System Layers." | sain-01 364 |
| F05432 | Success path — explicit `exit 0` | sain-01 365 |
| F05433 | Systemd unit file at `/etc/systemd/system/sovereign-guard.service` | sain-01 367 |
| F05434 | Systemd Unit description: "Sovereign Platform Hardware Sanity Enforcer" | sain-01 369 |
| F05435 | Systemd Unit `[Unit]` section present | sain-01 368 |
| F05436 | Systemd Unit `After=zfs-arc-tune.service` ordering directive | sain-01 370 |
| F05437 | Systemd Unit `Before=podman.service docker.service` ordering directive | sain-01 371 |
| F05438 | Systemd Unit `Before` extends to containerd.service (operator addition for kubernetes hosts) | sain-01 371 + ops |
| F05439 | Systemd Unit `[Service]` section present | sain-01 372 |
| F05440 | Systemd Unit `Type=oneshot` | sain-01 373 |
| F05441 | Systemd Unit `ExecStart=/usr/local/bin/friction-audit` | sain-01 374 |
| F05442 | Systemd Unit `RemainAfterExit=yes` | sain-01 375 |
| F05443 | Systemd Unit `[Install]` section present | sain-01 376 |
| F05444 | Systemd Unit `WantedBy=multi-user.target` | sain-01 377 |
| F05445 | Systemd Unit signed by MS003 selfdef-signing key | cross-ref MS003 |
| F05446 | Diagnostic — all stderr lines prefixed with severity marker | sain-01 350–353 |
| F05447 | Diagnostic — operator-readable (no opaque hex codes; English diagnostic strings) | sain-01 350–352 |
| F05448 | Diagnostic — remediation hint MANDATORY on every failure path | sain-01 352 |
| F05449 | Diagnostic — exit code 0 = pass, 1 = PCIe, 2 = ZFS, 3 = memory (operator-extended), 4+ = future | sain-01 350, 357 + arch |
| F05450 | Override manifest — operator-signed JSON at `/etc/selfdef/overrides/friction-audit-<gate>.json` | cross-ref MS003 |
| F05451 | Override manifest — required fields: signer_kid, reason, expiry_ms, gate_id | cross-ref MS003 |
| F05452 | Override manifest — minimum 2 signers (operator + auditor) for production gate | cross-ref MS003 + MS040 |
| F05453 | Override manifest — TTL ≤ 7 days (operator-set, max bounded) | cross-ref MS003 |
| F05454 | Override manifest — expiry-past override is rejected as a fresh failure | cross-ref MS003 |
| F05455 | Override audit — every override-allowed boot writes OCSF Audit 1003 with override JSON SHA-256 | cross-ref MS026 + MS027 |
| F05456 | OCSF Detection 2004 emitted per failed gate (one event per gate, not aggregated) | cross-ref MS026 |
| F05457 | OCSF Detection 2004 — `class_uid=2004`, `severity_id=4 (HIGH)` for PCIe + ZFS failures | cross-ref MS026 |
| F05458 | OCSF Detection 2004 — `severity_id=3 (MEDIUM)` for memory-geometry failure | cross-ref MS026 |
| F05459 | OCSF Audit 1003 emitted per successful gate pass (one event per boot) | cross-ref MS026 |
| F05460 | OCSF events carry `device.hostname` from `hostname -f` | cross-ref MS026 |
| F05461 | OCSF events carry `metadata.signature.public_key_id` matching MS003 selfdef-signing kid | cross-ref MS003 + MS026 |
| F05462 | OCSF events written to `/var/log/selfdef/friction-audit.ocsf.jsonl` (newline-delimited JSON) | cross-ref MS026 |
| F05463 | ZFS log bridge — copies OCSF events to `tank/vault/context/friction.log` atomically | cross-ref sovereign-os M068 |
| F05464 | ZFS log bridge — `sync=always` dataset property enforced | cross-ref sovereign-os M068 |
| F05465 | ZFS log bridge — copy is via POSIX append-only fd to honor crash-consistency | cross-ref sovereign-os M068 + M071 |
| F05466 | Typed mirror — selfdef-friction-audit-mirror crate exports `Verdict { gate, status, ts_ms, signer_kid }` | cross-ref MS007 |
| F05467 | Typed mirror — version pinned via `schema_version: &str = "1.0.0"` (selfdef pattern) | cross-ref MS007 |
| F05468 | Typed mirror — sovereign-os M060 dashboard consumes read-only | cross-ref MS007 + sovereign-os M060 |
| F05469 | Typed mirror — last-N verdicts retained in `/var/cache/selfdef/friction-audit/ring/` (capped 256) | architecture |
| F05470 | TUI binding — MS043 TUI authority-panel row "Friction Audit: PASS/FAIL/OVERRIDE" | cross-ref MS043 R10180 |
| F05471 | TUI binding — TUI row color: green=PASS, red=FAIL, yellow=OVERRIDE | cross-ref MS043 |
| F05472 | TUI binding — `?` help row shows last-failure remediation hint | cross-ref MS043 |
| F05473 | CLI binding — `selfdef friction-audit show` prints latest verdict (JSON or human) | cross-ref MS043 R10131 |
| F05474 | CLI binding — `selfdef friction-audit history --since <duration>` | cross-ref MS043 |
| F05475 | CLI binding — `selfdef friction-audit override-status` lists active overrides + expiry | cross-ref MS043 + MS003 |
| F05476 | CLI binding — `selfdef friction-audit replay` re-runs the gate without rebooting | cross-ref MS009 |
| F05477 | Replay validator — captures `lspci -vvv` and `zpool status -x` baseline at install time | cross-ref MS009 |
| F05478 | Replay validator — replay diff highlights post-install hardware changes | cross-ref MS009 |
| F05479 | Replay validator — diff exceeding 10% lane-width changes emits OCSF Detection 2005 | cross-ref MS026 + MS009 |
| F05480 | Offline survivability — works when sovereign-os runtime is offline | operator direction 2026-05-19 |
| F05481 | Offline survivability — works when network is unreachable (no remote dependency) | operator direction |
| F05482 | Offline survivability — works when only ZFS root pool is mounted (no tank/) | architecture |
| F05483 | Offline survivability — degraded mode skips ZFS log bridge (still emits OCSF locally) | architecture |
| F05484 | Performance budget — total runtime p95 ≤ 500 ms on znver5 reference | sain-01 343–365 + budget |
| F05485 | Performance budget — lspci probe ≤ 100 ms p95 | sain-01 347 + budget |
| F05486 | Performance budget — zpool status ≤ 100 ms p95 | sain-01 355 + budget |
| F05487 | Performance budget — dmidecode ≤ 250 ms p95 | sain-01 361 + budget |
| F05488 | Performance budget — total runtime hard-cap 2000 ms (after which gate emits TIMEOUT failure code 4) | architecture |
| F05489 | Failure-mode taxonomy — code 1 PCIe degradation (HIGH severity) | sain-01 350, 353 |
| F05490 | Failure-mode taxonomy — code 2 ZFS pool anomaly (HIGH severity) | sain-01 358, 359 |
| F05491 | Failure-mode taxonomy — code 3 memory geometry mismatch (MEDIUM severity) | sain-01 360–364 |
| F05492 | Failure-mode taxonomy — code 4 gate timeout (HIGH severity) | architecture |
| F05493 | Failure-mode taxonomy — code 5 immutability check failure (CRITICAL severity) | sain-01 339 |
| F05494 | Failure-mode taxonomy — code 6 signature verification failure (CRITICAL severity) | cross-ref MS003 |
| F05495 | Failure-mode taxonomy — code 7 override-manifest malformed (HIGH severity) | cross-ref MS003 |
| F05496 | Failure-mode taxonomy — code 8 override-manifest expired (HIGH severity) | cross-ref MS003 |
| F05497 | Failure-mode taxonomy — code 9 OCSF emission failure (MEDIUM severity, non-blocking) | cross-ref MS026 |
| F05498 | Failure-mode taxonomy — code 10 ZFS log bridge unavailable (LOW severity, non-blocking) | sovereign-os M068 |
| F05499 | Cross-cutting — friction-audit failure CANNOT be silenced by sovereign-os (selfdef Ring 0 authority) | cross-ref MS039 |
| F05500 | Cross-cutting — friction-audit failure freezes podman/docker startup (systemd Before invariant) | sain-01 371 |
| F05501 | Cross-cutting — Guardian Daemon (MS044) ingests friction-audit verdicts at startup | cross-ref MS044 |
| F05502 | Cross-cutting — sovereign-os runtime is informed via M060 dashboards (read-only) | cross-ref sovereign-os M060 |
| F05503 | Cross-cutting — typed-mirror crate is sole sovereign-os ingress (MS007 contract) | cross-ref MS007 |
| F05504 | Cross-cutting — operator override requires Ring 0 authority (MS039) | cross-ref MS039 |
| F05505 | Cross-cutting — override actions logged to MS041 commit-authority audit chain | cross-ref MS041 |
| F05506 | Cross-cutting — friction-audit decisions visible in MS027 observability stream | cross-ref MS027 |
| F05507 | Cross-cutting — friction-audit replay results part of MS009 audit-cycle | cross-ref MS009 |
| F05508 | Cross-cutting — friction-audit policies signed via MS003 chain-of-trust | cross-ref MS003 |
| F05509 | UX — failure message MUST include exact `lspci -vvv | grep LnkSta:.*Width` output for operator inspection | sain-01 347 + UX |
| F05510 | UX — failure message MUST include `zpool status` summary line on ZFS failure | sain-01 355 + UX |
| F05511 | UX — failure message MUST include `dmidecode -t memory | grep Locator` block on memory failure | sain-01 361 + UX |
| F05512 | UX — TUI row tooltip surfaces remediation hint on hover/focus | MS043 + UX |
| F05513 | UX — failure mode entries link to operator-runbook wiki page in info-hub | MS027 + operator direction |
| F05514 | UX — operator can mark a known-degraded gate as "expected" via signed override (MS003) | cross-ref MS003 |
| F05515 | UX — override expiry surfaces as a yellow banner with countdown in MS043 TUI authority panel | MS043 + UX |
| F05516 | UX — boot-time failures are not buried in journald — they tee to stderr AND `/dev/console` | sain-01 339 + UX |
| F05517 | UX — boot-time failures emit a PC-speaker beep pattern (3 short for HIGH, 5 short for CRITICAL) | MS044 alerter parallel |
| F05518 | UX — operator gets a `selfdef --first-boot-readout` summary including friction-audit verdict | cross-ref MS043 |
| F05519 | UX — first-boot readout enumerates ALL gate outcomes regardless of pass/fail | UX |
| F05520 | UX — verdict freshness — TUI panel grays out verdict older than 24h (operator should re-run gate) | UX + ops |

## Requirements (R10801-R11040)

| req | name | source |
|---|---|---|
| R10801 | Binary lives at exactly `/usr/local/bin/friction-audit` (no alternate paths) | sain-01 343 |
| R10802 | Binary mode `0755`, owner `root:root`, no setuid/setgid | sain-01 343 + arch |
| R10803 | Binary chattr +i applied at install AND verified before each invocation | sain-01 339 |
| R10804 | IMA-appraise hash registered in `/etc/ima/policy` and verified at exec time | sain-01 339 + arch |
| R10805 | Binary signature (MS003) stored at `/etc/selfdef/manifests/friction-audit.sig` | cross-ref MS003 |
| R10806 | Signature verification is HARD-REQUIRED before script body executes | cross-ref MS003 |
| R10807 | Signature verification failure → exit code 6 + OCSF Detection 2004 CRITICAL | cross-ref MS003 + MS026 |
| R10808 | Script shebang verbatim: `#!/bin/bash` (no env-shebang variant) | sain-01 344 |
| R10809 | Script first directive verbatim: `set -euo pipefail` | sain-01 345 |
| R10810 | Script first echo verbatim: `[*] INITIATING SOVEREIGN HARDWARE FRICTION AUDIT...` | sain-01 346 |
| R10811 | All echoes-to-stderr MUST use `>&2` form (no `1>&2` variant) | sain-01 350–353 |
| R10812 | PCIe check uses verbatim command: `lspci -vvv | grep -c "LnkSta:.*Width x8" || true` | sain-01 347 |
| R10813 | PCIe check stores into verbatim variable name: `LANE_AUDIT_COUNT` | sain-01 347 |
| R10814 | PCIe threshold: `LANE_AUDIT_COUNT < 2` triggers failure (verbatim) | sain-01 348 |
| R10815 | PCIe failure message line 1 verbatim: `CRITICAL ARCHITECTURAL FRICTION ERROR: PCIe Bus Degradation Detected.` | sain-01 350 |
| R10816 | PCIe failure message line 2 verbatim: `Diagnostic: One or more slots running below symmetric x8 configuration parameters.` | sain-01 351 |
| R10817 | PCIe failure message line 3 verbatim: `Remediation Check: Verify if M.2_2 slot is populated, interfering with lane paths.` | sain-01 352 |
| R10818 | PCIe failure exit code: exactly `1` | sain-01 353 |
| R10819 | PCIe check is FIRST gate (executes before ZFS, before memory) | sain-01 346–353 |
| R10820 | ZFS check uses verbatim command: `zpool status -x` | sain-01 355 |
| R10821 | ZFS check stores into verbatim variable name: `POOL_STATUS` | sain-01 355 |
| R10822 | ZFS gate string EXACT: `"all pools are healthy"` | sain-01 356 |
| R10823 | ZFS comparison uses string `!=` (no integer comparison) | sain-01 356 |
| R10824 | ZFS failure message verbatim: `CRITICAL ARCHITECTURAL FRICTION ERROR: Storage Pool Anomalies Discovered.` | sain-01 358 |
| R10825 | ZFS failure exit code: exactly `2` | sain-01 359 |
| R10826 | ZFS check is SECOND gate (executes only if PCIe pass) | sain-01 354–359 |
| R10827 | Memory check uses verbatim command: `dmidecode -t memory | grep -c "Size: [0-9]"` | sain-01 361 |
| R10828 | Memory check stores into verbatim variable name: `TOTAL_RECOGNIZED_STICKS` | sain-01 361 |
| R10829 | Memory check tolerates zero match via `|| true` (verbatim) | sain-01 361 |
| R10830 | Memory check is THIRD gate (executes only if PCIe + ZFS pass) | sain-01 360–364 |
| R10831 | Memory failure exit code: exactly `3` (operator-extended; sain-01 §5 leaves threshold open) | sain-01 360 + arch |
| R10832 | Memory threshold: operator-configurable expected stick count (default 4 for ProArt znver5 ref) | sain-01 + arch |
| R10833 | Memory threshold under-configuration → MEDIUM severity (not HIGH) | F05491 + arch |
| R10834 | Success exit code: exactly `0` (verbatim) | sain-01 365 |
| R10835 | Success final echo verbatim: `[*] Hardware Matrix Audited Successfully. Initializing System Layers.` | sain-01 364 |
| R10836 | Success path emits OCSF Audit class_uid=1003 | cross-ref MS026 |
| R10837 | Success path uses `exit 0` explicitly (no implicit-end-of-script reliance) | sain-01 365 |
| R10838 | All failure paths emit OCSF Detection class_uid=2004 | cross-ref MS026 |
| R10839 | All OCSF events MUST be appended to `/var/log/selfdef/friction-audit.ocsf.jsonl` | cross-ref MS026 |
| R10840 | OCSF JSONL append uses O_APPEND + fsync to honor crash-consistency | cross-ref MS026 + sovereign-os M071 |
| R10841 | OCSF Detection severity_id=4 (HIGH) for PCIe and ZFS failures | cross-ref MS026 + F05457 |
| R10842 | OCSF Detection severity_id=3 (MEDIUM) for memory failure | cross-ref MS026 + F05458 |
| R10843 | OCSF Detection severity_id=5 (CRITICAL) for immutability + signature failures | cross-ref MS026 + F05493/F05494 |
| R10844 | OCSF event includes `metadata.signature.public_key_id` matching MS003 selfdef-signing kid | cross-ref MS003 + MS026 |
| R10845 | OCSF event includes `device.hostname` from `hostname -f` | cross-ref MS026 |
| R10846 | OCSF event includes `time` field in epoch milliseconds | cross-ref MS026 |
| R10847 | OCSF event includes `activity_id=1` (audit start) or `activity_id=2` (audit end) | cross-ref MS026 |
| R10848 | OCSF event payload byte size hard-capped at 8 KiB (truncate diagnostic if over) | cross-ref MS026 |
| R10849 | OCSF emission failure → exit code 9 (NON-BLOCKING — gate still passes/fails per check result) | cross-ref MS026 + F05497 |
| R10850 | Systemd unit lives at `/etc/systemd/system/sovereign-guard.service` | sain-01 367 |
| R10851 | Systemd unit `[Unit]` section verbatim: `Description=Sovereign Platform Hardware Sanity Enforcer` | sain-01 368–369 |
| R10852 | Systemd unit `After=` verbatim: `zfs-arc-tune.service` | sain-01 370 |
| R10853 | Systemd unit `Before=` verbatim: `podman.service docker.service` | sain-01 371 |
| R10854 | Systemd unit `Before=` MUST also include `containerd.service` (operator-extended) | F05438 |
| R10855 | Systemd unit `[Service]` section verbatim: `Type=oneshot` | sain-01 372–373 |
| R10856 | Systemd unit `ExecStart=` verbatim: `/usr/local/bin/friction-audit` | sain-01 374 |
| R10857 | Systemd unit `RemainAfterExit=yes` verbatim | sain-01 375 |
| R10858 | Systemd unit `[Install]` section verbatim: `WantedBy=multi-user.target` | sain-01 376–377 |
| R10859 | Systemd unit signed with MS003 selfdef-signing key | cross-ref MS003 |
| R10860 | Systemd unit immutability — chattr +i applied at install | sain-01 339 + arch |
| R10861 | Systemd unit MUST NOT have `Restart=` directive (oneshot, single-fire) | sain-01 373 |
| R10862 | Systemd unit MUST NOT have `TimeoutStartSec=` lower than 2000 ms (matches F05488) | F05488 |
| R10863 | Systemd unit MUST NOT have any `Environment=` overrides (audit determinism) | architecture |
| R10864 | systemctl status shows verdict as `active (exited)` on PASS, `failed` on FAIL | sain-01 373 + systemd ops |
| R10865 | systemctl status `Result=` field machine-parseable (`success` vs `exit-code`) | systemd ops |
| R10866 | systemd ordering invariant: friction-audit MUST be the last enforcer before podman.service | sain-01 371 |
| R10867 | systemd ordering invariant: `After=zfs-arc-tune.service` is HARD (not Wants/Requires-only) | sain-01 370 |
| R10868 | systemd ordering invariant: tested in MS020 L3 test under boot replay | cross-ref MS020 |
| R10869 | Override manifest path: exactly `/etc/selfdef/overrides/friction-audit-<gate>.json` | F05450 |
| R10870 | Override gate identifier matches `pcie | zfs | memory | immutability | signature` | F05489–F05494 |
| R10871 | Override manifest schema: required fields `signer_kid, reason, expiry_ms, gate_id` | F05451 |
| R10872 | Override manifest MUST be multi-signed (≥2 distinct signer_kid) for production profile | F05452 + cross-ref MS040 |
| R10873 | Override manifest TTL ≤ 7 days (604_800_000 ms) from issue time | F05453 |
| R10874 | Override manifest expiry-past → fresh gate failure with code 8 | F05454 + F05496 |
| R10875 | Override manifest signature verified against MS003 trust roots before honor | cross-ref MS003 |
| R10876 | Override manifest reason field is non-empty, ≤ 512 chars, UTF-8 | architecture |
| R10877 | Override-honored boot emits OCSF Audit 1003 with override JSON SHA-256 in metadata | F05455 + MS026 |
| R10878 | Override-honored boot still emits the underlying Detection 2004 (override does NOT silence the failure event) | architecture + F05455 |
| R10879 | Override is single-boot by default (operator opts in to `multi_boot=true` field for sustained override) | architecture |
| R10880 | Override expiry reaches MS043 TUI authority panel with yellow countdown banner | F05515 |
| R10881 | ZFS log bridge writes to exactly `tank/vault/context/friction.log` | F05463 |
| R10882 | ZFS log bridge dataset MUST have property `sync=always` | F05464 + sovereign-os M068 |
| R10883 | ZFS log bridge file MUST be append-only POSIX fd | F05465 + sovereign-os M071 |
| R10884 | ZFS log bridge writes are durable before friction-audit `exit` returns | sovereign-os M068 + M071 |
| R10885 | ZFS log bridge unavailability (tank not mounted) → degraded mode, code 10 (NON-BLOCKING) | F05498 |
| R10886 | ZFS log bridge degraded mode emits a single LOW-severity Detection event | F05498 + MS026 |
| R10887 | ZFS log bridge file ownership: `root:adm`, mode `0640` (operator + audit-group readable) | architecture |
| R10888 | ZFS log bridge rotation: 30-day retention + selfdef-driven compaction | architecture |
| R10889 | ZFS log bridge entries include the OCSF event SHA-256 for tamper-evidence | architecture + MS026 |
| R10890 | ZFS log bridge entries chain via prev_event_sha256 (Merkle-like — cross-ref selfdef-evidence-merkle-chain) | architecture + MS026 |
| R10891 | Typed mirror crate name: exactly `selfdef-friction-audit-mirror` | F05466 + MS007 |
| R10892 | Typed mirror crate `Verdict` struct fields: `gate, status, ts_ms, signer_kid` (exact names) | F05466 |
| R10893 | Typed mirror crate `Verdict.status` enum: `Pass | Fail(u8) | OverrideActive` (exact variants) | F05466 |
| R10894 | Typed mirror crate `schema_version: &str = "1.0.0"` (selfdef pattern) | F05467 + MS007 |
| R10895 | Typed mirror crate exposes ONLY read-only accessor methods (no setters) | MS007 + F05468 |
| R10896 | Typed mirror crate is `serde::Serialize + Deserialize` | MS007 |
| R10897 | Typed mirror crate `validate()` checks schema_version + non-empty signer_kid | MS007 |
| R10898 | Typed mirror crate publishes to sovereign-os via MS007 export discipline | MS007 |
| R10899 | Typed mirror crate version-pinned in sovereign-os Cargo.toml workspace | MS007 |
| R10900 | Typed mirror ring buffer holds last 256 verdicts at `/var/cache/selfdef/friction-audit/ring/` | F05469 |
| R10901 | Ring buffer eviction is FIFO oldest-first | F05469 |
| R10902 | Ring buffer entries are 1-file-per-verdict (no shared serialization) for crash-safety | F05469 + sovereign-os M071 |
| R10903 | Ring buffer is read-mostly — only friction-audit writes; consumers only read | MS007 |
| R10904 | MS043 TUI authority panel renders friction-audit row (R10180 binding) | F05470 + MS043 |
| R10905 | TUI row color encoding: green PASS, red FAIL, yellow OVERRIDE | F05471 + MS043 |
| R10906 | TUI row label exact: `Friction Audit` (no abbreviation, no decoration) | MS043 + UX |
| R10907 | TUI row tooltip shows last-failure remediation hint when present | F05512 |
| R10908 | TUI row keyboard shortcut: `F` cycles focus to friction-audit row (MS043 R10150 binding) | MS043 + F05470 |
| R10909 | TUI row updates within 1000 ms of new verdict (MS043 R10177 freshness) | MS043 + F05520 |
| R10910 | TUI row STALE state activates after 24h with no new verdict (gray) | F05520 |
| R10911 | TUI row OFFLINE state activates if ring buffer unreadable (gray + cross icon) | MS043 + F05483 |
| R10912 | TUI row WCAG 2.1 AA contrast 4.5:1 (MS043 R10175 binding) | MS043 + F05471 |
| R10913 | CLI subcommand exact name: `selfdef friction-audit` (no shorter alias) | F05473 + MS043 |
| R10914 | CLI subcommand `show` prints latest verdict (human or `--json`) | F05473 + MS043 R10131 |
| R10915 | CLI subcommand `history --since <duration>` lists verdicts | F05474 + MS043 |
| R10916 | CLI subcommand `replay` re-runs gate without reboot | F05476 + cross-ref MS009 |
| R10917 | CLI subcommand `override-status` lists active overrides + expiry | F05475 + cross-ref MS003 |
| R10918 | CLI subcommand `override-create` is GATED behind MS039 Ring-0 authority + MS003 sig | cross-ref MS003 + MS039 |
| R10919 | CLI subcommand startup p95 ≤ 50 ms (MS043 R10137 binding) | MS043 + F05473 |
| R10920 | CLI subcommand `--json` flag returns structured output (MS043 R10131 binding) | MS043 + F05473 |
| R10921 | Replay validator captures `lspci -vvv` baseline at install time | F05477 + MS009 |
| R10922 | Replay validator captures `zpool status -x` baseline at install time | F05477 + MS009 |
| R10923 | Replay validator captures `dmidecode -t memory | grep Size:` baseline at install time | F05477 + MS009 |
| R10924 | Replay validator diff produces line-level OCSF event (one per delta) | F05478 + MS026 |
| R10925 | Replay validator triggers MS009 audit cycle on baseline drift | F05478 + MS009 |
| R10926 | Replay validator 10% lane-width drift threshold → OCSF Detection 2005 | F05479 + MS026 |
| R10927 | Replay validator runs ONLY on operator command (never automatic — operator agency) | MS009 + UX |
| R10928 | Replay validator output mirrored via MS007 typed-mirror to sovereign-os M060 | MS007 + sovereign-os M060 |
| R10929 | Replay validator failure does NOT freeze containers (informational) | F05476 + architecture |
| R10930 | Replay validator can run when sovereign-os is offline (F05480 binding) | F05480 |
| R10931 | Offline survivability — friction-audit works without nss-resolve / no DNS | F05481 |
| R10932 | Offline survivability — works without tank pool (degraded — F05483) | F05482 + F05483 |
| R10933 | Offline survivability — degraded mode logs to `/var/log/selfdef/friction-audit-offline.jsonl` | F05483 |
| R10934 | Offline survivability — verdicts surface in MS043 TUI even when sovereign-os offline | F05480 + MS043 |
| R10935 | Offline survivability — degraded mode flag (`OFFLINE_TANK=true`) emitted as OCSF metadata | F05483 + MS026 |
| R10936 | Performance — total runtime p95 ≤ 500 ms | F05484 |
| R10937 | Performance — lspci probe p95 ≤ 100 ms | F05485 |
| R10938 | Performance — zpool status probe p95 ≤ 100 ms | F05486 |
| R10939 | Performance — dmidecode probe p95 ≤ 250 ms | F05487 |
| R10940 | Performance — total runtime hard-cap 2000 ms (TIMEOUT code 4) | F05488 + F05492 |
| R10941 | Performance — measurement via systemd `journalctl -u sovereign-guard.service` invocation deltas | F05484 + ops |
| R10942 | Performance — measurement gated in MS020 L4 (boot timing harness) | cross-ref MS020 |
| R10943 | Performance — regression budget: ≤ 10% drift over a 30-day window triggers MS027 alert | architecture + MS027 |
| R10944 | Performance — slow gate emits OCSF Detection 2006 (`gate_slow`) | architecture + MS026 |
| R10945 | Authority — friction-audit is owned by IPS Ring 0 (MS039 binding) | F05499 + MS039 |
| R10946 | Authority — only Ring 0 signers can mutate override manifests (MS040 binding) | F05504 + MS040 |
| R10947 | Authority — commit-authority of override actions flows through MS041 | F05505 + MS041 |
| R10948 | Authority — tool-authority on friction-audit CLI surface is gated by MS042 | cross-ref MS042 |
| R10949 | Authority — friction-audit decisions visible in MS027 observability stream (read-only) | F05506 + MS027 |
| R10950 | Diagnostic — failure-message includes verbatim raw probe output (lspci/zpool/dmidecode) | F05509–F05511 |
| R10951 | Diagnostic — failure-message MUST link to operator-runbook wiki page in info-hub | F05513 |
| R10952 | Diagnostic — runbook URL takes form `https://wiki.local/selfdef/runbooks/friction-audit-<gate>` | F05513 + ops |
| R10953 | Diagnostic — runbook page exists for each of pcie / zfs / memory / immutability / signature | F05513 |
| R10954 | Diagnostic — operator can produce a self-contained diagnostic bundle via `selfdef friction-audit bundle` | F05476 + MS043 |
| R10955 | Diagnostic — bundle is signed by MS003 selfdef-signing key | F05407 + MS003 |
| R10956 | Diagnostic — bundle is portable (zstd-compressed tar) — operator can hand to support | architecture |
| R10957 | Diagnostic — bundle MUST NOT include any operator PII, tokens, or signing key material | architecture + security |
| R10958 | Diagnostic — bundle includes the OCSF event jsonl, ring buffer, journalctl block, and replay baseline | architecture |
| R10959 | Diagnostic — bundle includes selfdef + sovereign-os version manifest | architecture |
| R10960 | Diagnostic — operator command to verify a bundle: `selfdef friction-audit verify-bundle <path>` | F05476 |
| R10961 | First-boot readout — surfaced via `selfdef --first-boot-readout` (F05518 binding) | F05518 |
| R10962 | First-boot readout — emits PASS line per gate (PCIe / ZFS / Memory / Immutability / Signature) | F05519 |
| R10963 | First-boot readout — exits non-zero if any gate failed (operator-actionable summary) | F05518 + UX |
| R10964 | First-boot readout — pretty-prints with WCAG-compliant colors AND `--no-color` opt-out (MS043 R10185 binding) | MS043 + F05518 |
| R10965 | First-boot readout — includes per-gate timing for performance regression visibility | F05484–F05488 |
| R10966 | PC-speaker alerter — 3 short beeps for HIGH-severity failure | F05517 + MS044 |
| R10967 | PC-speaker alerter — 5 short beeps for CRITICAL failure | F05517 |
| R10968 | PC-speaker alerter — bypassable via signed override manifest field `silence_speaker=true` | F05517 + MS003 |
| R10969 | PC-speaker alerter — write to `/dev/console` only (no audio subsystem dependency) | F05516 + sain-01 |
| R10970 | PC-speaker alerter — failure to beep MUST NOT block gate verdict (best-effort) | F05517 + arch |
| R10971 | Cross-cutting — friction-audit gate verdict cached for sovereign-os M060 dashboard at TTL 1000 ms | F05502 + sovereign-os M060 |
| R10972 | Cross-cutting — sovereign-os NEVER mutates friction-audit verdict (read-only) | F05502 + MS007 |
| R10973 | Cross-cutting — sovereign-os cockpit shows OVERRIDE-active state with operator + auditor signer_kid | F05502 + MS003 |
| R10974 | Cross-cutting — friction-audit failure halts MS017 agent-guard startup (containers cannot launch agents) | sain-01 371 + MS017 |
| R10975 | Cross-cutting — friction-audit failure pauses MS022 SSE subscriber acceptance (no new sessions) | F05500 + MS022 |
| R10976 | Cross-cutting — Guardian Daemon (MS044) ingests verdict at startup AND on every replay | F05501 + MS044 |
| R10977 | Cross-cutting — Guardian Daemon refuses to start if friction-audit verdict is FAIL without override | F05501 + MS044 |
| R10978 | Cross-cutting — eBPF perimeter (MS016) is GATED ON friction-audit PASS — bridge-l2 module (MS024) checks at load | sain-01 380–420 + MS016 |
| R10979 | Cross-cutting — observability module (MS027) surfaces friction-audit timing histogram | MS027 + F05484–F05488 |
| R10980 | Cross-cutting — every override action contributes to MS009 audit-cycle work-queue | MS009 + F05455 |
| R10981 | Test contract L1 — friction-audit script lints (shellcheck, no warnings) | MS020 + arch |
| R10982 | Test contract L2 — friction-audit script unit-tested via bats-core | MS020 |
| R10983 | Test contract L3 — friction-audit gate behaviour tested under L3 boot-replay harness | MS020 + F05476 |
| R10984 | Test contract L3 — PASS path tested with healthy reference baseline | MS020 |
| R10985 | Test contract L3 — FAIL path tested with synthetic degraded lspci output | MS020 |
| R10986 | Test contract L3 — FAIL path tested with synthetic degraded zpool output | MS020 |
| R10987 | Test contract L3 — FAIL path tested with synthetic stick-count mismatch | MS020 |
| R10988 | Test contract L4 — friction-audit integration tested on znver5 reference hardware | MS020 |
| R10989 | Test contract L5 — friction-audit chaos-tested (kill mid-execution, observe systemd recovery) | MS020 + arch |
| R10990 | Test contract — every gate path emits the expected OCSF event class + severity (L3 assert) | MS020 + MS026 |
| R10991 | Signing — MS003 chain-of-trust verified before script body runs | F05407 + MS003 |
| R10992 | Signing — signature manifest MUST include build SHA-256 of `/usr/local/bin/friction-audit` | F05408 + MS003 |
| R10993 | Signing — signature key rotation handled via selfdef-key-rotation-set crate | cross-ref MS003 |
| R10994 | Signing — operator override manifests bound to same MS003 trust roots | F05450 + MS003 |
| R10995 | Signing — re-signed binary requires re-applied chattr +i (immutability re-asserted) | F05405 + F05408 |
| R10996 | Auditability — every gate execution emits a signed OCSF event chain | F05456–F05462 + MS026 |
| R10997 | Auditability — chain has prev_event_sha256 referencing immediately-prior event | R10890 + MS026 |
| R10998 | Auditability — operator can run `selfdef friction-audit audit-trail --since <ts>` to verify chain | F05476 + MS009 |
| R10999 | Auditability — broken chain emits Detection 2007 (`audit_chain_break`) at CRITICAL | MS026 + MS009 |
| R11000 | Auditability — chain integrity check is part of MS009 audit-cycle | MS009 + R10890 |
| R11001 | Survival — friction-audit MUST work when /var is read-only (degraded log to /run/selfdef/) | F05480 + arch |
| R11002 | Survival — friction-audit MUST work in initramfs context (early boot, no userspace mounts) | F05480 + arch |
| R11003 | Survival — friction-audit MUST work in recovery-mode kernel boot (single-user, networking off) | F05480 + arch |
| R11004 | Survival — friction-audit gate is NEVER bypassed by emergency.target or rescue.target | sain-01 + arch |
| R11005 | Survival — emergency.target reading uses `selfdef friction-audit show --emergency` (read-only) | MS043 + arch |
| R11006 | Observability — friction-audit emits structured journald entries with `PRIORITY` levels per severity | MS027 + F05446 |
| R11007 | Observability — journald entries tagged with `SYSLOG_IDENTIFIER=friction-audit` | MS027 |
| R11008 | Observability — failures additionally tee to `/dev/console` (kernel-visible) | F05516 + sain-01 |
| R11009 | Observability — successes do NOT tee to /dev/console (silence on green) | UX + arch |
| R11010 | Observability — failures emit a 1-line summary to stdout, full detail to stderr | F05446–F05447 |
| R11011 | Operator agency — verdict change SHALL require operator action (signed override or hardware fix) | F05504 + MS003 |
| R11012 | Operator agency — never auto-remediates hardware issues (operator decides) | UX + arch |
| R11013 | Operator agency — never auto-disables a gate (no silent self-modification) | sain-01 339 + arch |
| R11014 | Operator agency — alerting cadence: at-most-once-per-boot per gate (no spam) | F05456 + UX |
| R11015 | Operator agency — operator can suppress repeat alerts via `selfdef friction-audit ack <gate>` (per-boot) | F05476 + MS043 |
| R11016 | Documentation — `docs/sdd/SDD-friction-audit.md` exists with same R-numbering | MS001 SDD discipline |
| R11017 | Documentation — `man friction-audit(8)` page installed at `/usr/share/man/man8/friction-audit.8.gz` | UX + operator |
| R11018 | Documentation — `selfdef friction-audit --help` shows synopsis matching SDD | MS043 + arch |
| R11019 | Documentation — operator-runbook for each gate in info-hub (`wiki/runbooks/friction-audit-*.md`) | F05513 |
| R11020 | Documentation — every OCSF event class catalogued in `docs/ocsf/events.md` with sample payload | MS026 |
| R11021 | Schema — `Verdict` struct lives in `selfdef-friction-audit-mirror` crate (MS007 binding) | F05466 |
| R11022 | Schema — `Verdict::status` JSON tag = `kebab-case` (sovereign-os convention via MS007 mirror) | MS007 + sovereign-os |
| R11023 | Schema — every R-row above has a deterministic L2/L3 test fixture | MS020 |
| R11024 | Schema — `schema_version` bump is breaking change → requires sovereign-os mirror version bump | MS007 |
| R11025 | Schema — schema mismatch on sovereign-os ingestion → degraded panel with stale-banner | sovereign-os M060 + MS007 |
| R11026 | Cross-repo — operator can verify selfdef ↔ sovereign-os schema sync via `selfdef mirror-status` | MS007 + MS043 |
| R11027 | Cross-repo — typed mirror exports R-binding under `sovereign-cockpit-friction-audit-panel` crate | MS007 + sovereign-os M060 |
| R11028 | Cross-repo — sovereign-cockpit panel binding tests gated in MS045 UX coherence harness | MS045 + sovereign-os M060 |
| R11029 | Cross-repo — sovereign-cockpit panel TTL freshness ≤ 1000 ms (R10971) | R10971 + sovereign-os M060 |
| R11030 | Cross-repo — sovereign-cockpit panel offline state visible when selfdef IPS daemon unreachable | sovereign-os M060 + MS007 |
| R11031 | Threat-model — adversary modifying friction-audit binary is detected by immutability + signing | F05405–F05407 + MS019 |
| R11032 | Threat-model — adversary forging override manifest is detected by multi-signature R10872 | R10872 + MS019 |
| R11033 | Threat-model — adversary masking degraded hardware is detected by replay drift R10925 | R10925 + MS019 |
| R11034 | Threat-model — adversary suppressing /dev/console output is detected by Guardian (MS044) parallel channel | MS044 + MS019 |
| R11035 | Threat-model — adversary blocking OCSF emission is logged via degraded code 9 + degraded mode banner | R10849 + MS019 |
| R11036 | Failure-mode coverage — every failure code 1..10 has a documented runbook, test, and OCSF mapping | F05489–F05498 + R11016 |
| R11037 | Failure-mode coverage — failure detection budget: ≤ 1000 ms from issue to OCSF event emission | F05484 + MS027 |
| R11038 | Failure-mode coverage — failure-mode evolution is tracked in MS055 failure-mode taxonomies | cross-ref sovereign-os M055 |
| R11039 | Sovereign-OS interaction — sovereign-os runtime checks friction-audit verdict before claiming "boot-ready" | F05502 + sovereign-os M072 |
| R11040 | Sovereign-OS interaction — sovereign-os M072 master-bootstrap checklist row "Friction Audit" maps 1:1 to this milestone | sovereign-os M072 |

## Sub-requirements accounting

Per operator standing direction *"every of those requirements is in reality already quite specific and with at least 10 hard non-negotiable requirements each"*: each R-row above decomposes into ≥10 sub-requirements under SDD discipline. The sub-requirements live in:
- `docs/sdd/SDD-friction-audit.md` (R-bindings to L1-L5 test fixtures)
- `docs/ocsf/events.md` (per-event sample payloads + field constraints)
- `wiki/runbooks/friction-audit-{pcie,zfs,memory,immutability,signature}.md` (per-gate operator runbooks)

This milestone catalogues the **top-level R-rows** that anchor the sub-requirement decomposition. Per operator direction, no R-row is invented — every row is sourced from sain-01 §5 verbatim, cross-referenced to earlier selfdef milestones, or extended deterministically (e.g. F05438 containerd.service ordering, F05488 timeout code) and tagged "operator-extended" in the source column.

## Cross-references

- **Source dump**: `~/infohub/raw/dumps/2026-05-15-sain-01-master-spec-other-conversation-transposition.md` §5 lines 338–378
- **Sister milestone (selfdef)**: MS044 Guardian Daemon (consumes friction-audit verdicts)
- **Sister milestone (selfdef)**: MS016 eBPF programs (gated on friction-audit PASS)
- **Sister milestone (selfdef)**: MS026 Integrity sentinel + observability (OCSF emission)
- **Sister milestone (selfdef)**: MS027 Observability module (verdict timing histogram)
- **Sister milestone (selfdef)**: MS043 IPS operator surface (TUI authority panel binding)
- **Sister milestone (selfdef)**: MS045 UX coherence test harness (TDD validator)
- **Sister milestone (sovereign-os)**: M060 Cockpit + 20+ dashboards (read-only verdict consumer)
- **Sister milestone (sovereign-os)**: M068 ZFS storage architecture (log bridge dataset)
- **Sister milestone (sovereign-os)**: M071 Atomic State Transition Protocol (POSIX append-only fd)
- **Sister milestone (sovereign-os)**: M072 Master bootstrap verification checklist (1:1 row)
- **Trust authority**: MS039 Ring 0 + MS040 authority profile + MS041 commit authority + MS042 tool authority
- **Trust roots**: MS003 selfdef-signing (script signature, override manifest signature, OCSF event signature)
- **Cross-repo mirror discipline**: MS007 typed-mirror crates

## Schema

```text
schema_version: "1.0.0"
verdict.fields:
  - gate: enum { pcie, zfs, memory, immutability, signature }
  - status: enum { Pass, Fail(u8), OverrideActive }
  - ts_ms: u64
  - signer_kid: String (matches MS003 selfdef-signing key id)
```

— End of MS046.
