# MS047 — Real-Time Security Perimeter Engine — Tetragon kernel-fence (sain-01 §6)

**Parent**: selfdef IPS daemon — kernel-space boundary-enforcement layer (eBPF perimeter)
**Source**: `~/infohub/raw/dumps/2026-05-15-sain-01-master-spec-other-conversation-transposition.md`
- **Section 6: Real-Time Security Perimeter Engine (Native eBPF Layer)** (lines 380–411)
- `config/includes.chroot/etc/tetragon/sovereign-perimeter.yaml` — TracingPolicy verbatim YAML (lines 383–409)
- Section 4.1 Tetragon Policy (lines 103–117) — companion baseline
- Section 10 The Native Guardian Event Loop (lines 513–588) — consumer (MS044 Guardian Daemon ingests these events)
**Companion**: selfdef MS016 (eBPF programs + Tetragon TracingPolicies — general), MS017 (agent-guard), MS044 (Guardian Daemon — consumes perimeter events via UNIX socket), MS024 (Bridge-L2 module — L2 transparent bridge)
**Operator standing direction** (verbatim, 2026-05-19): *"if I talk about an IPS feature its obviously not in Sovereign-OS"* / *"Respect the projects"* / *"do not minimize the work in selfdef"* / *"DO NOT MINIMIZE WHAT I SAY, SAID OR ASKED FOR"*
**Cross-repo mirror**: sovereign-os M060 dashboards consume perimeter verdicts via MS007 typed-mirror `selfdef-perimeter-mirror` (read-only); IPS policy authority NEVER mutated by sovereign-os
**Project boundary**: this milestone catalogues ONLY the selfdef-side Tetragon TracingPolicy + kernel-space enforcement; the **container-execution monitor** that interfaces with these signals (M01136 Guardian trace emitter, MS044 Guardian Daemon) is the consumer side

## Doctrinal anchors

> "A native eBPF profile running inside Tetragon provides structural security without high application-layer parsing overhead." (sain-01 dump 381)
> "This architecture monitors container execution contexts dealing directly with model variables." (sain-01 dump 382)
> "name: 'sovereign-kernel-fence'" (sain-01 dump 388)
> "kprobes: - call: 'sys_execve' / syscall: true" (sain-01 dump 390–391)
> "operator: 'NotIn' / values: ['/usr/bin/python3', '/usr/bin/nvidia-smi', '/usr/local/bin/vllm', '/usr/bin/podman']" (sain-01 dump 397–402)
> "matchActions: - action: Sigkill" (sain-01 dump 403–404)
> "This script terminates any thread requesting system call execution outside the authorized execution boundaries directly in kernel space, maintaining system integrity." (sain-01 dump 406)
> *"do not minimize the work in selfdef"* (operator standing direction 2026-05-19)

## Projection statement

The Real-Time Security Perimeter Engine is the **kernel-space last-mile** of selfdef IPS boundary enforcement. Where MS046 friction-audit fires once at boot (hardware-frame gate), MS016 enumerates the broader eBPF program tier (program family), and MS044 Guardian Daemon listens at user-space socket level — MS047 is the specific **`sovereign-kernel-fence` TracingPolicy** that enforces a kernel-space binary-execution allowlist at the sys_execve syscall edge. Every process attempting to `execve` a binary NOT in the per-policy allowlist receives an immediate kernel-level SIGKILL (no graceful shutdown, no user-space interception window). This is the IPS organ's **physical-presence-in-kernel** authority — the binary cannot escape, the daemon cannot be bribed, and the boundary fires before the rejected process ever obtains a PID. The default allowlist (per sain-01 §6) is `{/usr/bin/python3, /usr/bin/nvidia-smi, /usr/local/bin/vllm, /usr/bin/podman}` — the four binaries the sovereign-os runtime is authorized to launch directly. All other execve requests are killed in-kernel. Operator-signed policy extensions (MS003 signing, MS040 authority profile) are required to expand the allowlist; revisions are audited per MS009 audit-cycle, mirrored read-only per MS007 to sovereign-os M060 dashboards, and observable per MS027 event stream.

## Epics (E0471-E0480)

| epic | name | source |
|---|---|---|
| E0471 | TracingPolicy file `sovereign-perimeter.yaml` — install + immutability + signing | sain-01 384, 388 + cross-ref MS003 |
| E0472 | `sys_execve` kprobe — syscall edge enforcement (kernel-space gate) | sain-01 390–391 |
| E0473 | execve argv[0] string extraction — kernel argument capture for selector matching | sain-01 392–395 |
| E0474 | Binary-allowlist selector — `NotIn` operator against the 4-binary default set | sain-01 396–402 |
| E0475 | `Sigkill` matchAction — in-kernel termination on policy mismatch | sain-01 403–404 |
| E0476 | Operator-signed allowlist extension — MS003-signed manifest to expand allowed binaries | cross-ref MS003 + sain-01 397–402 |
| E0477 | OCSF Detection emission — every Sigkill emits a Detection 2004 event | cross-ref MS026 |
| E0478 | Guardian Daemon (MS044) integration — emits Sigkill verdict via UNIX socket | cross-ref MS044 + sain-01 524 |
| E0479 | Cross-repo typed mirror — `selfdef-perimeter-mirror` exports verdict to sovereign-os M060 | cross-ref MS007 + sovereign-os M060 |
| E0480 | Audit-cycle replay validator — `selfdef perimeter audit-cycle replay` re-evaluates baseline + drift | cross-ref MS009 + sain-01 |

## Modules (M01201-M01226)

| module | name | source |
|---|---|---|
| M01201 | selfdef-perimeter-installer (`/etc/tetragon/tracing-policies/sovereign-perimeter.yaml`) | sain-01 384 |
| M01202 | selfdef-perimeter-immutability-enforcer (chattr +i + IMA appraise) | sain-01 + arch |
| M01203 | selfdef-perimeter-tetragon-loader (loads TracingPolicy at tetragon-operator startup) | sain-01 384 + cross-ref MS016 |
| M01204 | selfdef-perimeter-tetragon-binary-prerequisites-check (llvm + clang + tetragon binary present) | cross-ref MS044 M01124 |
| M01205 | selfdef-perimeter-policy-yaml-validator (apiVersion + kind + spec.kprobes well-formed) | sain-01 385–404 |
| M01206 | selfdef-perimeter-policy-signature-validator (MS003-signed before load) | cross-ref MS003 |
| M01207 | selfdef-perimeter-kprobe-sys-execve-binder | sain-01 390–391 |
| M01208 | selfdef-perimeter-arg-string-extractor (index 0 + type string) | sain-01 392–395 |
| M01209 | selfdef-perimeter-notin-selector-matcher (binary allowlist as set) | sain-01 396–402 |
| M01210 | selfdef-perimeter-sigkill-action-binder | sain-01 403–404 |
| M01211 | selfdef-perimeter-allowlist-store (default 4-binary set with operator-signed extensions) | sain-01 397–402 + cross-ref MS003 |
| M01212 | selfdef-perimeter-allowlist-extension-loader (MS003-signed manifest) | cross-ref MS003 + cross-ref selfdef-allowlist-store |
| M01213 | selfdef-perimeter-allowlist-extension-signature-validator | cross-ref MS003 |
| M01214 | selfdef-perimeter-allowlist-extension-audit-logger (every extension logged) | cross-ref MS027 + cross-ref MS041 |
| M01215 | selfdef-perimeter-tetragon-event-bridge (relay matched Sigkill verdicts) | cross-ref MS044 M01127 |
| M01216 | selfdef-perimeter-ocsf-detection-emitter (class 2004 on Sigkill) | cross-ref MS026 |
| M01217 | selfdef-perimeter-zfs-log-bridge (atomic append to tank/vault/context/perimeter.log) | cross-ref sovereign-os M068 |
| M01218 | selfdef-perimeter-typed-mirror (selfdef-perimeter-mirror crate) | cross-ref MS007 |
| M01219 | selfdef-perimeter-tui-panel (MS043 TUI authority panel row) | cross-ref MS043 |
| M01220 | selfdef-perimeter-cli-subcommand (`selfdef perimeter show|history|extend`) | cross-ref MS043 |
| M01221 | selfdef-perimeter-replay-validator (re-evaluate baseline against current policy) | cross-ref MS009 |
| M01222 | selfdef-perimeter-policy-version-tracker (schema_version + policy_version) | cross-ref MS007 + cross-ref selfdef-key-rotation-set |
| M01223 | selfdef-perimeter-tracing-policy-namespace-register (Tetragon namespace binding) | sain-01 387 |
| M01224 | selfdef-perimeter-circuit-breaker-bypass-detector (alerts if Tetragon is killed/stopped) | cross-ref MS044 M01143 |
| M01225 | selfdef-perimeter-offline-survivability (TracingPolicy still loaded when network/sovereign-os offline) | operator standing direction |
| M01226 | selfdef-perimeter-cross-repo-mirror-publisher (publishes Verdict via MS007 export discipline) | cross-ref MS007 |

## Features (F05521-F05640)

| feature | name | source |
|---|---|---|
| F05521 | TracingPolicy YAML lives at `/etc/tetragon/tracing-policies/sovereign-perimeter.yaml` | sain-01 384 + tetragon ops |
| F05522 | TracingPolicy `apiVersion: cilium.io/v1alpha1` verbatim | sain-01 385 |
| F05523 | TracingPolicy `kind: TracingPolicy` verbatim | sain-01 386 |
| F05524 | TracingPolicy `metadata.name: "sovereign-kernel-fence"` verbatim | sain-01 387–388 |
| F05525 | TracingPolicy `spec.kprobes` present | sain-01 389 |
| F05526 | TracingPolicy `kprobes[0].call: "sys_execve"` verbatim | sain-01 390 |
| F05527 | TracingPolicy `kprobes[0].syscall: true` verbatim | sain-01 391 |
| F05528 | TracingPolicy `kprobes[0].args[0].index: 0` verbatim (argv[0] capture) | sain-01 392–393 |
| F05529 | TracingPolicy `kprobes[0].args[0].type: "string"` verbatim | sain-01 394 |
| F05530 | TracingPolicy `selectors[0].matchArgs[0].operator: "NotIn"` verbatim | sain-01 396–397 |
| F05531 | Default allowlist value 1: `/usr/bin/python3` | sain-01 398 |
| F05532 | Default allowlist value 2: `/usr/bin/nvidia-smi` | sain-01 399 |
| F05533 | Default allowlist value 3: `/usr/local/bin/vllm` | sain-01 400 |
| F05534 | Default allowlist value 4: `/usr/bin/podman` | sain-01 401 |
| F05535 | TracingPolicy `matchActions[0].action: Sigkill` verbatim | sain-01 403–404 |
| F05536 | TracingPolicy file mode `0644`, owner `root:root` | sain-01 + arch |
| F05537 | TracingPolicy chattr +i applied post-install + verified before each Tetragon reload | sain-01 + arch |
| F05538 | TracingPolicy IMA-appraise hash registered + verified at exec time | sain-01 + arch |
| F05539 | TracingPolicy signed by MS003 selfdef-signing key | cross-ref MS003 |
| F05540 | TracingPolicy signature stored at `/etc/selfdef/manifests/sovereign-perimeter.sig` | cross-ref MS003 |
| F05541 | TracingPolicy signature verified before Tetragon loads the policy | cross-ref MS003 |
| F05542 | TracingPolicy unauthorized modification triggers OCSF Detection 2004 CRITICAL | cross-ref MS003 + MS026 |
| F05543 | TracingPolicy loaded into Tetragon at startup via `tetragon -tracing-policy-dir /etc/tetragon/tracing-policies` | sain-01 + tetragon ops |
| F05544 | TracingPolicy is the FIRST policy loaded (ordering invariant) | sain-01 + arch |
| F05545 | TracingPolicy load failure → friction-audit signals MS046 (cross-cutting) | cross-ref MS046 |
| F05546 | TracingPolicy load failure halts podman.service startup (systemd ordering) | cross-ref MS046 F05500 |
| F05547 | sys_execve kprobe captures argv[0] only (per index: 0; subsequent args ignored at this layer) | sain-01 392–395 |
| F05548 | argv[0] string-capture truncation at 4096 bytes (PATH_MAX) | tetragon + arch |
| F05549 | argv[0] non-UTF-8 bytes get hex-encoded for OCSF event payload | arch + MS026 |
| F05550 | Allowlist match is exact-string (no glob/regex) | sain-01 397 |
| F05551 | Allowlist match is case-sensitive | sain-01 397 + arch |
| F05552 | Allowlist match is full-path (no relative path resolution) | sain-01 397 |
| F05553 | Mismatch (NotIn-evaluated true) → Sigkill matchAction fires in-kernel | sain-01 403–406 |
| F05554 | Sigkill sent to attempting thread (TID) — surrounding process group is NOT killed | sain-01 406 + kernel |
| F05555 | Sigkill is unrecoverable from user-space (no SIGKILL handler) | kernel + arch |
| F05556 | Sigkill timing: arrives BEFORE the new binary mmap+exec sequence completes | sain-01 406 + kernel |
| F05557 | Sigkill verdict surfaces via Tetragon UNIX socket `/var/run/tetragon/tetragon.events` | cross-ref MS044 M01127 + sain-01 524 |
| F05558 | Allowlist extension via signed manifest at `/etc/selfdef/perimeter-extensions/<name>.json` | cross-ref MS003 + cross-ref selfdef-allowlist-store |
| F05559 | Extension manifest schema: `signer_kid, binaries: [path], reason, expiry_ms, scope` | cross-ref MS003 |
| F05560 | Extension manifest signature verified against MS003 trust roots | cross-ref MS003 |
| F05561 | Extension manifest MUST be multi-signed (≥2 distinct signer_kid) for production profile | cross-ref MS003 + MS040 |
| F05562 | Extension manifest TTL ≤ 30 days (operator-extended; default 24h) | cross-ref MS003 + arch |
| F05563 | Extension manifest expiry-past → reverts to base allowlist (no silent persistence) | cross-ref MS003 |
| F05564 | Extension reload happens via Tetragon policy hot-reload (no kernel restart) | sain-01 + tetragon ops |
| F05565 | Extension audit — every extension/revoke logged to OCSF Audit 1003 | cross-ref MS026 + MS027 |
| F05566 | Extension audit — chained via prev_event_sha256 (Merkle-like, cross-ref MS046 R10890) | cross-ref MS046 |
| F05567 | OCSF Detection 2004 emitted per Sigkill (one event per terminated execve) | cross-ref MS026 |
| F05568 | OCSF event includes `attempted_binary_path` (argv[0]) | cross-ref MS026 + sain-01 392–395 |
| F05569 | OCSF event includes `attempting_pid`, `parent_pid`, `cgroup`, `container_id` (Tetragon enrichment) | cross-ref MS026 + tetragon |
| F05570 | OCSF event includes `process.cmdline` (full argv from cgroup join time) | cross-ref MS026 + tetragon |
| F05571 | OCSF event includes `metadata.signature.public_key_id` matching MS003 selfdef-signing kid | cross-ref MS003 + MS026 |
| F05572 | OCSF event includes `device.hostname` from `hostname -f` | cross-ref MS026 |
| F05573 | OCSF event severity_id=4 (HIGH) for default allowlist violations | cross-ref MS026 + F05567 |
| F05574 | OCSF event severity_id=5 (CRITICAL) if attempted_binary_path is in known-malicious set | cross-ref MS026 + threat |
| F05575 | OCSF event written to `/var/log/selfdef/perimeter.ocsf.jsonl` (newline-delimited) | cross-ref MS026 |
| F05576 | ZFS log bridge — atomic append to `tank/vault/context/perimeter.log` | cross-ref sovereign-os M068 |
| F05577 | ZFS log bridge — `sync=always` dataset property enforced | cross-ref sovereign-os M068 |
| F05578 | ZFS log bridge — POSIX append-only fd to honor crash-consistency | cross-ref sovereign-os M068 + M071 |
| F05579 | ZFS log bridge — last-N events retained at `/var/cache/selfdef/perimeter/ring/` (capped 4096) | architecture |
| F05580 | Tetragon binary prerequisites — llvm + clang installed at install time | cross-ref MS044 M01124 + sain-01 714 |
| F05581 | Tetragon binary prerequisites — tetragon-operator + tetragon binary at `/usr/local/bin/tetragon` | cross-ref MS044 M01125 |
| F05582 | Tetragon binary prerequisites — tetragon.service systemd unit running | cross-ref MS044 M01126 |
| F05583 | Tetragon namespace — TracingPolicy bound to default Tetragon namespace | sain-01 387 + tetragon ops |
| F05584 | Tetragon policy hot-reload supported via `tetragon-controlplane reload` | tetragon ops |
| F05585 | Tetragon policy unload via `tetragon-controlplane unload sovereign-kernel-fence` (Ring 0 only) | cross-ref MS039 + tetragon ops |
| F05586 | Tetragon being killed/stopped triggers MS044 Guardian circuit-breaker | cross-ref MS044 M01143 |
| F05587 | Guardian Daemon (MS044) ingests perimeter events at startup via UNIX socket listener | cross-ref MS044 + sain-01 524 |
| F05588 | Guardian Daemon parses perimeter events via MS044 M01128 event parser | cross-ref MS044 |
| F05589 | Guardian Daemon classifies as policy violation via MS044 M01129 violation classifier | cross-ref MS044 |
| F05590 | Guardian Daemon emits secondary console alert + atomic log via MS044 M01130–M01132 | cross-ref MS044 |
| F05591 | Guardian + Perimeter form one logical defense chain (kernel kill + user-space audit + console alert + atomic log) | sain-01 §6 + §10 |
| F05592 | Typed mirror crate `selfdef-perimeter-mirror` exports `Verdict { attempted_binary_path, attempting_pid, ts_ms, signer_kid_policy, signer_kid_extension? }` | cross-ref MS007 |
| F05593 | Typed mirror crate `schema_version: &str = "1.0.0"` (selfdef pattern) | cross-ref MS007 |
| F05594 | Typed mirror crate exposes ONLY read-only accessors (no mutate methods) | cross-ref MS007 |
| F05595 | Typed mirror crate is `serde::Serialize + Deserialize` | cross-ref MS007 |
| F05596 | Typed mirror published to sovereign-os via MS007 export discipline | cross-ref MS007 |
| F05597 | Sovereign-OS M060 dashboard panel "Perimeter" surfaces last 16 Sigkill events | cross-ref sovereign-os M060 + F05592 |
| F05598 | Sovereign-OS M060 panel is READ-ONLY (no policy mutation from cockpit) | cross-ref MS007 + safety |
| F05599 | Sovereign-OS M060 panel surfaces active allowlist + active extensions + expiry timestamps | cross-ref sovereign-os M060 + F05558 |
| F05600 | Sovereign-OS M060 panel updates within 1000 ms of new Sigkill verdict | cross-ref sovereign-os M060 + UX |
| F05601 | TUI binding — MS043 TUI authority-panel "Perimeter" row | cross-ref MS043 R10180 |
| F05602 | TUI row color — green (no violations recent), yellow (violation within 1h), red (active extension expired) | cross-ref MS043 + UX |
| F05603 | TUI row tooltip — last 3 Sigkill verdicts with binary path + PID | cross-ref MS043 + UX |
| F05604 | TUI row keyboard shortcut — `P` cycles focus to perimeter row (MS043 R10150 binding) | cross-ref MS043 |
| F05605 | CLI subcommand exact name — `selfdef perimeter` (no abbreviation) | cross-ref MS043 |
| F05606 | CLI subcommand `show` — prints active policy summary | cross-ref MS043 R10131 |
| F05607 | CLI subcommand `history --since <duration>` — lists Sigkill verdicts | cross-ref MS043 |
| F05608 | CLI subcommand `extend --signed <manifest>` — loads operator-signed extension | F05558 + cross-ref MS003 |
| F05609 | CLI subcommand `revoke <extension-id>` — revokes a loaded extension | F05558 |
| F05610 | CLI subcommand `audit-cycle replay` — re-evaluates baseline against current policy | cross-ref MS009 + F05621 |
| F05611 | CLI `--json` flag returns structured output (MS043 R10131 binding) | cross-ref MS043 |
| F05612 | CLI startup p95 ≤ 50 ms (MS043 R10137 binding) | cross-ref MS043 |
| F05613 | Replay validator captures baseline policy + allowlist set at install time | cross-ref MS009 + F05621 |
| F05614 | Replay validator diff highlights post-install policy drift (allowlist additions/removals) | cross-ref MS009 |
| F05615 | Replay validator records drift severity per added/removed binary | cross-ref MS009 + MS026 |
| F05616 | Replay validator triggers MS009 audit-cycle replay on baseline drift > threshold | cross-ref MS009 |
| F05617 | Replay validator output mirrored via MS007 typed-mirror to sovereign-os M060 | cross-ref MS007 + sovereign-os M060 |
| F05618 | Replay validator runs ONLY on operator command (never automatic — operator agency) | cross-ref MS009 + UX |
| F05619 | Replay validator failure does NOT mutate kernel policy (informational only) | F05618 + safety |
| F05620 | Offline survivability — perimeter policy still enforced when sovereign-os offline | operator standing direction |
| F05621 | Offline survivability — Tetragon kernel policy persists across reboots | tetragon + arch |
| F05622 | Offline survivability — degraded mode emits OCSF event with `OFFLINE_SUPER=true` metadata | F05620 + MS026 |
| F05623 | Performance — kprobe entry overhead p95 ≤ 5 microseconds | tetragon + budget |
| F05624 | Performance — NotIn selector evaluation overhead p95 ≤ 1 microsecond | tetragon + budget |
| F05625 | Performance — Sigkill action delivery latency p95 ≤ 10 microseconds | kernel + budget |
| F05626 | Performance — system-wide execve throughput budget: ≥ 50,000 exec/sec on znver5 reference | tetragon + budget |
| F05627 | Performance — perimeter policy adds ≤ 2% CPU overhead at baseline load | budget |
| F05628 | Failure-mode taxonomy — code P1: TracingPolicy YAML malformed (CRITICAL severity) | F05525–F05535 |
| F05629 | Failure-mode taxonomy — code P2: TracingPolicy signature failure (CRITICAL severity) | F05539–F05542 |
| F05630 | Failure-mode taxonomy — code P3: Tetragon not running (CRITICAL severity) | F05586 |
| F05631 | Failure-mode taxonomy — code P4: Extension manifest signature failure (HIGH severity) | F05560 |
| F05632 | Failure-mode taxonomy — code P5: Extension manifest expired (MEDIUM severity, fallback to base) | F05563 |
| F05633 | Failure-mode taxonomy — code P6: OCSF emission failure (LOW severity, non-blocking) | cross-ref MS026 |
| F05634 | Failure-mode taxonomy — code P7: ZFS log bridge unavailable (LOW severity, non-blocking) | cross-ref sovereign-os M068 |
| F05635 | Failure-mode taxonomy — code P8: TracingPolicy chattr +i bypassed (CRITICAL severity) | F05537 |
| F05636 | UX — every Sigkill event MUST include operator-readable `attempted_binary_path` + reason | F05568 + UX |
| F05637 | UX — Sigkill event MUST link to operator-runbook for allowlist-extension procedure | F05558 + UX |
| F05638 | UX — TUI panel surfaces extension expiry as yellow countdown banner | F05599 + UX |
| F05639 | UX — `selfdef perimeter --first-boot-readout` shows allowlist + active extensions | cross-ref MS043 + UX |
| F05640 | UX — TUI / CLI / cockpit naming is CONSISTENT ("Perimeter" everywhere; no abbreviation) | UX + cross-ref MS043 |

## Requirements (R11041-R11280)

| req | name | source |
|---|---|---|
| R11041 | TracingPolicy file lives at exactly `/etc/tetragon/tracing-policies/sovereign-perimeter.yaml` | F05521 |
| R11042 | TracingPolicy file mode `0644`, owner `root:root`, no setuid/setgid | F05536 + arch |
| R11043 | TracingPolicy chattr +i applied at install AND verified before each Tetragon reload | F05537 + sain-01 |
| R11044 | TracingPolicy IMA-appraise hash registered in `/etc/ima/policy` and verified at exec time | F05538 + arch |
| R11045 | TracingPolicy signature stored at `/etc/selfdef/manifests/sovereign-perimeter.sig` | F05540 + cross-ref MS003 |
| R11046 | TracingPolicy signature verification HARD-REQUIRED before Tetragon loads the policy | F05541 + cross-ref MS003 |
| R11047 | TracingPolicy unauthorized modification → P8 + OCSF Detection 2004 CRITICAL | F05635 + F05542 |
| R11048 | TracingPolicy MUST have `apiVersion: cilium.io/v1alpha1` exactly | F05522 + sain-01 385 |
| R11049 | TracingPolicy MUST have `kind: TracingPolicy` exactly | F05523 + sain-01 386 |
| R11050 | TracingPolicy MUST have `metadata.name: "sovereign-kernel-fence"` exactly | F05524 + sain-01 387–388 |
| R11051 | TracingPolicy MUST contain at least one `kprobes` entry | F05525 + sain-01 389 |
| R11052 | First kprobe MUST call `sys_execve` (default-policy invariant) | F05526 + sain-01 390 |
| R11053 | First kprobe MUST have `syscall: true` | F05527 + sain-01 391 |
| R11054 | First kprobe MUST have one args entry at index 0 with type string | F05528–F05529 |
| R11055 | First kprobe MUST have at least one selector with matchArgs operator `NotIn` | F05530 + sain-01 396–397 |
| R11056 | Default allowlist MUST contain `/usr/bin/python3` (operator-extended only) | F05531 |
| R11057 | Default allowlist MUST contain `/usr/bin/nvidia-smi` | F05532 |
| R11058 | Default allowlist MUST contain `/usr/local/bin/vllm` | F05533 |
| R11059 | Default allowlist MUST contain `/usr/bin/podman` | F05534 |
| R11060 | First kprobe MUST have at least one matchAction with `action: Sigkill` | F05535 + sain-01 403–404 |
| R11061 | TracingPolicy loaded into Tetragon at startup via `tetragon -tracing-policy-dir` flag | F05543 |
| R11062 | TracingPolicy is the FIRST tetragon policy loaded (ordering invariant) | F05544 |
| R11063 | TracingPolicy load failure signals MS046 friction-audit halt (cross-cutting) | F05545 + cross-ref MS046 |
| R11064 | TracingPolicy load failure halts podman.service startup (systemd ordering) | F05546 + cross-ref MS046 |
| R11065 | argv[0] capture is full-path (no relative-path resolution at this layer) | F05547 + F05552 |
| R11066 | argv[0] capture truncated at 4096 bytes (PATH_MAX) | F05548 |
| R11067 | argv[0] non-UTF-8 bytes hex-encoded for OCSF payload | F05549 |
| R11068 | Allowlist match is exact-string (no glob, no regex) | F05550 |
| R11069 | Allowlist match is case-sensitive | F05551 |
| R11070 | Allowlist match is full-path (e.g. `/usr/bin/python3` ≠ `python3`) | F05552 |
| R11071 | Mismatch (binary path NOT in allowlist) → Sigkill matchAction fires in-kernel | F05553 |
| R11072 | Sigkill is sent to attempting thread (TID), not process group (no PGRP-wide kill) | F05554 |
| R11073 | Sigkill is unrecoverable from user-space (no SIGKILL handler possible per POSIX) | F05555 |
| R11074 | Sigkill timing — arrives BEFORE new binary mmap+exec sequence completes | F05556 |
| R11075 | Sigkill verdict surfaces via Tetragon UNIX socket `/var/run/tetragon/tetragon.events` | F05557 + sain-01 524 |
| R11076 | Sigkill verdict MUST be received by Guardian Daemon (MS044) within 50 ms of kernel emission | F05587 + budget |
| R11077 | Extension manifest path: `/etc/selfdef/perimeter-extensions/<name>.json` | F05558 |
| R11078 | Extension manifest schema fields: `signer_kid, binaries: [path], reason, expiry_ms, scope` | F05559 |
| R11079 | Extension manifest signature verified against MS003 trust roots | F05560 + cross-ref MS003 |
| R11080 | Extension manifest MUST be multi-signed (≥2 distinct signer_kid) for production profile | F05561 + cross-ref MS040 |
| R11081 | Extension manifest TTL ≤ 30 days (operator-extended; default 24h) | F05562 |
| R11082 | Extension manifest expiry-past — extension auto-revoked, allowlist reverts to base | F05563 |
| R11083 | Extension reload via Tetragon policy hot-reload (no kernel restart) | F05564 |
| R11084 | Extension audit — every load + revoke logged to OCSF Audit 1003 | F05565 + cross-ref MS026 |
| R11085 | Extension audit — chained via prev_event_sha256 (Merkle-like, cross-ref MS046 R10890) | F05566 + cross-ref MS046 |
| R11086 | Extension audit — chained sequence integrity checked at MS009 audit-cycle | cross-ref MS009 + F05566 |
| R11087 | Extension audit — broken chain emits Detection 2007 CRITICAL | cross-ref MS026 + MS046 R10999 |
| R11088 | OCSF Detection 2004 emitted per Sigkill — exactly one event, no aggregation | F05567 |
| R11089 | OCSF event field `attempted_binary_path` (argv[0]) populated | F05568 |
| R11090 | OCSF event field `attempting_pid` populated from kprobe context | F05569 |
| R11091 | OCSF event field `parent_pid` populated from task_struct->real_parent | F05569 |
| R11092 | OCSF event field `cgroup` populated from Tetragon process enrichment | F05569 |
| R11093 | OCSF event field `container_id` populated when execve fires inside a container | F05569 |
| R11094 | OCSF event field `process.cmdline` populated (full argv from cgroup join time) | F05570 |
| R11095 | OCSF event field `metadata.signature.public_key_id` matches MS003 selfdef-signing kid | F05571 |
| R11096 | OCSF event field `device.hostname` from `hostname -f` | F05572 |
| R11097 | OCSF event severity_id=4 (HIGH) for default-allowlist violations | F05573 |
| R11098 | OCSF event severity_id=5 (CRITICAL) for known-malicious binary path | F05574 |
| R11099 | OCSF event payload byte-size hard-capped at 8 KiB (truncate diagnostic if over) | F05575 + arch |
| R11100 | OCSF event written to `/var/log/selfdef/perimeter.ocsf.jsonl` | F05575 |
| R11101 | OCSF JSONL append uses O_APPEND + fsync to honor crash-consistency | F05575 + cross-ref MS046 R10840 |
| R11102 | OCSF emission failure → P6 + degraded mode (NON-BLOCKING) | F05633 + cross-ref MS046 R10849 |
| R11103 | ZFS log bridge writes to exactly `tank/vault/context/perimeter.log` | F05576 |
| R11104 | ZFS log bridge dataset MUST have `sync=always` | F05577 |
| R11105 | ZFS log bridge MUST be append-only POSIX fd | F05578 |
| R11106 | ZFS log bridge writes are durable before perimeter event is acked | F05578 + cross-ref M068 + M071 |
| R11107 | ZFS log bridge unavailable → P7 + degraded mode (NON-BLOCKING) | F05634 + cross-ref MS046 R10885 |
| R11108 | ZFS log bridge entries include OCSF event SHA-256 for tamper-evidence | cross-ref MS046 R10889 |
| R11109 | ZFS log bridge entries chain via prev_event_sha256 (Merkle-like) | cross-ref MS046 R10890 |
| R11110 | Ring buffer at `/var/cache/selfdef/perimeter/ring/` holds last 4096 verdicts | F05579 |
| R11111 | Ring buffer eviction is FIFO oldest-first | F05579 + cross-ref MS046 R10901 |
| R11112 | Ring buffer is 1-file-per-verdict for crash-safety | F05579 + cross-ref MS046 R10902 |
| R11113 | Ring buffer is read-mostly — only perimeter daemon writes; consumers only read | F05579 + cross-ref MS046 R10903 |
| R11114 | Tetragon binary prerequisites — llvm + clang installed at install time | F05580 |
| R11115 | Tetragon binary at `/usr/local/bin/tetragon` (or distro-equivalent) | F05581 |
| R11116 | Tetragon service `tetragon.service` running before perimeter policy loads | F05582 |
| R11117 | Tetragon namespace — TracingPolicy bound to default Tetragon namespace | F05583 |
| R11118 | Tetragon policy hot-reload supported via `tetragon-controlplane reload` | F05584 |
| R11119 | Tetragon policy unload via `tetragon-controlplane unload sovereign-kernel-fence` — Ring 0 only | F05585 + cross-ref MS039 |
| R11120 | Tetragon stop/kill detection — triggers MS044 Guardian circuit-breaker within 5 seconds | F05586 + cross-ref MS044 |
| R11121 | Tetragon stop/kill — friction-audit MS046 detects on next boot via TracingPolicy load failure | cross-ref MS046 + F05545 |
| R11122 | Guardian Daemon (MS044) ingests perimeter events at startup | F05587 |
| R11123 | Guardian Daemon parses perimeter events via MS044 M01128 event parser | F05588 |
| R11124 | Guardian Daemon classifies via MS044 M01129 violation classifier | F05589 |
| R11125 | Guardian Daemon emits secondary console alert via MS044 M01132 | F05590 |
| R11126 | Guardian Daemon emits atomic log via MS044 M01131 | F05590 |
| R11127 | Guardian Daemon + Perimeter form one logical defense chain (4 organs: kernel kill + user-space audit + console alert + atomic log) | F05591 |
| R11128 | Typed mirror crate name: exactly `selfdef-perimeter-mirror` | F05592 + cross-ref MS007 |
| R11129 | Typed mirror crate `Verdict` struct fields: `attempted_binary_path, attempting_pid, ts_ms, signer_kid_policy, signer_kid_extension?` | F05592 |
| R11130 | Typed mirror crate `schema_version: &str = "1.0.0"` | F05593 |
| R11131 | Typed mirror crate exposes ONLY read-only accessors | F05594 |
| R11132 | Typed mirror crate is `serde::Serialize + Deserialize` | F05595 |
| R11133 | Typed mirror crate `validate()` checks schema_version + non-empty signer_kid_policy | F05595 + cross-ref MS007 |
| R11134 | Typed mirror crate published via MS007 export discipline | F05596 |
| R11135 | Typed mirror crate version-pinned in sovereign-os Cargo.toml workspace | cross-ref MS007 |
| R11136 | Sovereign-OS M060 panel "Perimeter" surfaces last 16 Sigkill verdicts | F05597 |
| R11137 | Sovereign-OS M060 panel surfaces active allowlist | F05599 |
| R11138 | Sovereign-OS M060 panel surfaces active extensions + expiry timestamps | F05599 + F05558 |
| R11139 | Sovereign-OS M060 panel updates within 1000 ms of new Sigkill | F05600 |
| R11140 | Sovereign-OS M060 panel is READ-ONLY (no mutation buttons) | F05598 + safety |
| R11141 | Sovereign-OS M060 panel shows panel-OFFLINE state if mirror unreachable | cross-ref MS046 R11030 |
| R11142 | Sovereign-OS M060 panel WCAG 2.1 AA contrast 4.5:1 | cross-ref MS043 R10175 |
| R11143 | TUI panel MS043 — "Perimeter" row label exact (no abbreviation) | F05601 + F05640 |
| R11144 | TUI panel row color encoding — green/yellow/red per F05602 | F05602 |
| R11145 | TUI panel row tooltip — last 3 Sigkill verdicts visible on hover/focus | F05603 |
| R11146 | TUI panel row keyboard shortcut — `P` cycles focus (MS043 R10150 binding) | F05604 + cross-ref MS043 |
| R11147 | TUI panel row stale/offline state same convention as MS046 R10910–R10911 | cross-ref MS046 |
| R11148 | CLI subcommand exact name `selfdef perimeter` | F05605 + cross-ref MS043 |
| R11149 | CLI subcommand `show` prints active policy summary (`--json` or human) | F05606 + F05611 |
| R11150 | CLI subcommand `history --since <duration>` | F05607 |
| R11151 | CLI subcommand `extend --signed <manifest>` loads operator-signed extension | F05608 + F05558 |
| R11152 | CLI subcommand `extend` GATED behind Ring 0 authority + MS003 multi-sig | F05608 + cross-ref MS039 + MS040 |
| R11153 | CLI subcommand `revoke <extension-id>` revokes a loaded extension | F05609 |
| R11154 | CLI subcommand `revoke` GATED behind Ring 0 authority + MS003 sig | F05609 + cross-ref MS039 |
| R11155 | CLI subcommand `audit-cycle replay` re-evaluates baseline against current policy | F05610 + cross-ref MS009 |
| R11156 | CLI startup p95 ≤ 50 ms | F05612 + cross-ref MS043 R10137 |
| R11157 | CLI `--json` flag returns structured output | F05611 + cross-ref MS043 R10131 |
| R11158 | Replay validator captures baseline at install time | F05613 + cross-ref MS009 |
| R11159 | Replay validator diff highlights post-install policy drift | F05614 |
| R11160 | Replay validator records drift severity per added/removed binary | F05615 + cross-ref MS026 |
| R11161 | Replay validator triggers MS009 audit-cycle replay on drift > threshold | F05616 |
| R11162 | Replay validator output mirrored via MS007 typed-mirror to M060 | F05617 |
| R11163 | Replay validator runs ONLY on operator command (never automatic) | F05618 + UX |
| R11164 | Replay validator failure does NOT mutate kernel policy | F05619 + safety |
| R11165 | Offline survivability — perimeter policy enforced when sovereign-os offline | F05620 |
| R11166 | Offline survivability — Tetragon kernel policy persists across reboots | F05621 |
| R11167 | Offline survivability — degraded mode emits OCSF event with `OFFLINE_SUPER=true` | F05622 |
| R11168 | Offline survivability — perimeter verdicts surface in MS043 TUI even when sovereign-os offline | cross-ref MS046 R10934 |
| R11169 | Performance — kprobe entry overhead p95 ≤ 5 μs | F05623 |
| R11170 | Performance — NotIn selector eval overhead p95 ≤ 1 μs | F05624 |
| R11171 | Performance — Sigkill action delivery latency p95 ≤ 10 μs | F05625 |
| R11172 | Performance — system-wide execve throughput budget ≥ 50,000 exec/sec on znver5 | F05626 |
| R11173 | Performance — perimeter policy adds ≤ 2% CPU overhead at baseline load | F05627 |
| R11174 | Performance — measurement gated in MS020 L4 (boot timing harness) | cross-ref MS020 |
| R11175 | Performance — regression budget: ≤ 10% drift over 30-day window triggers MS027 alert | cross-ref MS027 |
| R11176 | Failure-mode P1 (TracingPolicy YAML malformed) — exit code P1, CRITICAL severity | F05628 |
| R11177 | Failure-mode P2 (TracingPolicy signature failure) — exit code P2, CRITICAL severity | F05629 |
| R11178 | Failure-mode P3 (Tetragon not running) — exit code P3, CRITICAL severity | F05630 |
| R11179 | Failure-mode P4 (Extension manifest signature failure) — exit code P4, HIGH severity | F05631 |
| R11180 | Failure-mode P5 (Extension manifest expired) — fallback to base allowlist, MEDIUM severity | F05632 |
| R11181 | Failure-mode P6 (OCSF emission failure) — degraded mode, LOW severity, non-blocking | F05633 + R11102 |
| R11182 | Failure-mode P7 (ZFS log bridge unavailable) — degraded mode, LOW severity, non-blocking | F05634 + R11107 |
| R11183 | Failure-mode P8 (TracingPolicy chattr +i bypassed) — CRITICAL severity, immediate restoration attempt | F05635 + R11047 |
| R11184 | Failure-mode coverage — every code P1..P8 has runbook + test + OCSF mapping | F05628–F05635 + cross-ref MS046 R11036 |
| R11185 | Authority — Perimeter policy is owned by IPS Ring 0 (cross-ref MS039) | cross-ref MS039 + F05585 + R11119 |
| R11186 | Authority — only Ring 0 signers can extend allowlist (cross-ref MS040) | cross-ref MS040 + F05608 + R11152 |
| R11187 | Authority — commit-authority of extension actions flows through MS041 | cross-ref MS041 |
| R11188 | Authority — tool-authority on perimeter CLI surface is gated by MS042 | cross-ref MS042 |
| R11189 | Authority — perimeter verdicts visible in MS027 observability stream (read-only) | cross-ref MS027 |
| R11190 | Diagnostic — every Sigkill OCSF event includes operator-runbook URL for allowlist-extension | F05637 + ops |
| R11191 | Diagnostic — runbook URL: `https://wiki.local/selfdef/runbooks/perimeter-allowlist-extension` | F05637 + ops |
| R11192 | Diagnostic — runbook page documents multi-sig procedure + scope examples | F05637 + ops |
| R11193 | Diagnostic — operator can produce a self-contained perimeter diagnostic bundle via `selfdef perimeter bundle` | cross-ref MS046 R10954 |
| R11194 | Diagnostic — bundle signed by MS003 selfdef-signing key | cross-ref MS046 R10955 |
| R11195 | Diagnostic — bundle includes OCSF events, ring buffer, replay baseline | cross-ref MS046 R10958 |
| R11196 | Diagnostic — bundle MUST NOT include any sigkill'd-process memory or token material | safety + R10957 |
| R11197 | First-boot readout — `selfdef perimeter --first-boot-readout` shows allowlist + active extensions | F05639 |
| R11198 | First-boot readout — pretty-prints with WCAG-compliant colors AND `--no-color` opt-out | cross-ref MS043 R10185 |
| R11199 | First-boot readout — exits non-zero if any extension expired or P-failure persists | UX + F05628–F05635 |
| R11200 | Survival — perimeter MUST work when /var is read-only (degraded log to /run/selfdef/) | cross-ref MS046 R11001 |
| R11201 | Survival — perimeter MUST work in initramfs context (early boot, no userspace mounts) | cross-ref MS046 R11002 |
| R11202 | Survival — perimeter MUST work in recovery-mode kernel boot | cross-ref MS046 R11003 |
| R11203 | Survival — perimeter gate is NEVER bypassed by emergency.target or rescue.target | cross-ref MS046 R11004 |
| R11204 | Survival — emergency-mode read-only access via `selfdef perimeter show --emergency` | cross-ref MS046 R11005 |
| R11205 | Observability — perimeter emits structured journald entries with `PRIORITY` per severity | cross-ref MS046 R11006 + MS027 |
| R11206 | Observability — journald entries tagged with `SYSLOG_IDENTIFIER=selfdef-perimeter` | cross-ref MS046 R11007 + MS027 |
| R11207 | Observability — Sigkill events ADDITIONALLY tee to `/dev/console` for kernel-visible alert | sain-01 + UX |
| R11208 | Observability — base-allowlist matches do NOT tee to /dev/console (silence on green) | F05636 + UX |
| R11209 | Observability — Sigkill emits a 1-line summary to stdout, full detail to OCSF jsonl | UX + cross-ref MS046 R11010 |
| R11210 | Operator agency — allowlist extension SHALL require operator action (signed manifest) | F05608 + R11186 |
| R11211 | Operator agency — never auto-extends allowlist (no AI suggestion) | safety + operator agency |
| R11212 | Operator agency — never auto-disables policy (no silent self-modification) | F05583 + safety |
| R11213 | Operator agency — alerting cadence: at-most-once per (boot, attempted_binary) for first 1000 events | UX + arch |
| R11214 | Operator agency — operator can suppress repeat alerts via `selfdef perimeter ack <binary>` (per-boot) | cross-ref MS046 R11015 + UX |
| R11215 | Documentation — `docs/sdd/SDD-perimeter-engine.md` exists with same R-numbering | arch + cross-ref MS046 R11016 |
| R11216 | Documentation — `man selfdef-perimeter(8)` page installed | UX + cross-ref MS046 R11017 |
| R11217 | Documentation — `selfdef perimeter --help` shows synopsis matching SDD | cross-ref MS046 R11018 |
| R11218 | Documentation — operator-runbook for each P-failure in info-hub | cross-ref MS046 R11019 + F05628–F05635 |
| R11219 | Documentation — every OCSF event class catalogued in `docs/ocsf/events.md` with sample payload | cross-ref MS046 R11020 |
| R11220 | Schema — `Verdict` struct lives in `selfdef-perimeter-mirror` crate (MS007 binding) | F05592 + cross-ref MS007 |
| R11221 | Schema — `Verdict` JSON serialization uses `kebab-case` tags (sovereign-os mirror convention) | cross-ref MS046 R11022 + MS007 |
| R11222 | Schema — every R-row above has a deterministic L2/L3 test fixture | cross-ref MS020 |
| R11223 | Schema — `schema_version` bump is breaking change → requires sovereign-os mirror version bump | cross-ref MS046 R11024 + MS007 |
| R11224 | Schema — schema mismatch on sovereign-os ingestion → degraded panel with stale-banner | cross-ref MS046 R11025 + sovereign-os M060 |
| R11225 | Cross-repo — operator can verify selfdef↔sovereign-os schema sync via `selfdef mirror-status` | cross-ref MS046 R11026 |
| R11226 | Cross-repo — typed mirror exports `sovereign-cockpit-perimeter-panel` binding crate | cross-ref MS007 + sovereign-os M060 |
| R11227 | Cross-repo — sovereign-cockpit panel tests gated in MS045 UX coherence harness | cross-ref MS045 + sovereign-os M060 |
| R11228 | Cross-repo — sovereign-cockpit panel TTL freshness ≤ 1000 ms | F05600 + cross-ref MS046 R11029 |
| R11229 | Cross-repo — sovereign-cockpit panel offline state when selfdef IPS daemon unreachable | cross-ref MS046 R11030 |
| R11230 | Threat-model — adversary attempting execve of unauthorized binary detected by Sigkill matchAction | F05553 + cross-ref MS019 |
| R11231 | Threat-model — adversary modifying TracingPolicy file detected by immutability + signing | R11043, R11045, R11046 + cross-ref MS019 |
| R11232 | Threat-model — adversary forging extension manifest detected by multi-sig R11080 | R11080 + cross-ref MS019 |
| R11233 | Threat-model — adversary stopping/killing Tetragon detected by Guardian circuit-breaker | R11120 + cross-ref MS019 + MS044 |
| R11234 | Threat-model — adversary blocking OCSF emission logged via degraded P6 + degraded mode banner | R11102 + cross-ref MS019 |
| R11235 | Threat-model — adversary attempting to add binary via wrong path (e.g. `python3` not `/usr/bin/python3`) → Sigkill (exact-string + full-path) | R11068, R11070 |
| R11236 | Threat-model — adversary chroot-jumping to bypass full-path → Tetragon enrichment captures container_id (R11093) | R11093 + cross-ref MS017 |
| R11237 | Failure-mode evolution — Perimeter failure modes tracked in MS055 failure-mode taxonomies | cross-ref sovereign-os M055 |
| R11238 | Sovereign-OS interaction — sovereign-os runtime checks perimeter active before claiming "boot-ready" | cross-ref sovereign-os M072 |
| R11239 | Sovereign-OS interaction — sovereign-os M072 master-bootstrap checklist row "Perimeter Engine" maps 1:1 to this milestone | cross-ref sovereign-os M072 |
| R11240 | Audit-cycle integration — perimeter participates in MS009 audit-cycle review | cross-ref MS009 + F05610 |
| R11241 | Audit-cycle integration — replay validator triggers MS009 audit-cycle replay on drift | cross-ref MS009 + F05616 |
| R11242 | Audit-cycle integration — every extension load + revoke contributes to MS009 work-queue | cross-ref MS009 + F05565 |
| R11243 | Audit-cycle integration — broken audit chain emits Detection 2007 CRITICAL | R11087 + cross-ref MS009 |
| R11244 | Audit-cycle integration — audit chain integrity check at every audit-cycle iteration | cross-ref MS009 + R11086 |
| R11245 | Test contract L1 — TracingPolicy YAML schema-validated against cilium/v1alpha1 schema | cross-ref MS020 + arch |
| R11246 | Test contract L2 — TracingPolicy YAML unit-tested for all 4 default allowlist values | cross-ref MS020 |
| R11247 | Test contract L3 — perimeter gate tested under L3 boot-replay harness with synthetic execve | cross-ref MS020 |
| R11248 | Test contract L3 — PASS path (allowed binary) tested | cross-ref MS020 |
| R11249 | Test contract L3 — FAIL path (denied binary) tested with Sigkill verification | cross-ref MS020 |
| R11250 | Test contract L3 — extension load + revoke tested | cross-ref MS020 |
| R11251 | Test contract L4 — perimeter tested on znver5 reference hardware | cross-ref MS020 |
| R11252 | Test contract L5 — perimeter chaos-tested (kill Tetragon mid-execution, observe Guardian recovery) | cross-ref MS020 + MS044 |
| R11253 | Test contract — every gate path emits expected OCSF event class + severity (L3 assert) | cross-ref MS020 + MS026 |
| R11254 | Signing — MS003 chain-of-trust verified before TracingPolicy loads | F05541 + cross-ref MS003 |
| R11255 | Signing — TracingPolicy signature includes file SHA-256 of policy YAML | cross-ref MS003 + cross-ref MS046 R10992 |
| R11256 | Signing — signature key rotation handled via selfdef-key-rotation-set crate | cross-ref MS003 |
| R11257 | Signing — operator extension manifests bound to same MS003 trust roots | F05560 + cross-ref MS003 |
| R11258 | Signing — re-signed policy requires re-applied chattr +i (immutability re-asserted) | R11043 + R11045 |
| R11259 | Auditability — every Sigkill event emits a signed OCSF event chain | F05567 + cross-ref MS026 |
| R11260 | Auditability — chain has prev_event_sha256 referencing immediately-prior event | R11109 + cross-ref MS026 |
| R11261 | Auditability — operator can run `selfdef perimeter audit-trail --since <ts>` to verify chain | F05610 + cross-ref MS009 |
| R11262 | Auditability — broken chain emits Detection 2007 (`audit_chain_break`) at CRITICAL | cross-ref MS026 + MS009 + R11087 |
| R11263 | Auditability — chain integrity check is part of MS009 audit-cycle | cross-ref MS009 + R11244 |
| R11264 | Cross-cutting — perimeter is part of every release-readiness checkpoint | cross-ref sovereign-os M072 + R11238 |
| R11265 | Cross-cutting — perimeter verdict surfaces in sovereign-os M072 master-bootstrap checklist | cross-ref sovereign-os M072 + R11239 |
| R11266 | Cross-cutting — perimeter coverage reported in sovereign-os M060 main dashboard top-row summary | F05597 + cross-ref sovereign-os M060 |
| R11267 | Cross-cutting — perimeter changes recorded in MS027 observability stream (read-only) | cross-ref MS027 + R11189 |
| R11268 | Cross-cutting — perimeter Sigkill triggers MS046 friction-audit replay validator | cross-ref MS046 + F05545 |
| R11269 | Cross-cutting — perimeter Sigkill recorded in MS009 audit-cycle work-queue | cross-ref MS009 + F05616 |
| R11270 | Cross-cutting — perimeter policy data NEVER leaves the local node by default | safety + operator agency |
| R11271 | Sub-requirements — each R-row decomposes into ≥10 sub-requirements per SDD discipline | operator standing 2026-05-19 |
| R11272 | Sub-requirements — sub-requirements live in `docs/sdd/SDD-perimeter-subreqs.md` | arch + R11215 |
| R11273 | Sub-requirements — sub-requirements link to L1-L5 test fixtures by ID | cross-ref MS020 |
| R11274 | Sub-requirements — sub-requirements cite sain-01 dump §6 lines verbatim | sain-01 380–411 |
| R11275 | Sub-requirements — sub-requirements cross-reference sister milestones (MS003 / MS007 / MS009 / MS016 / MS017 / MS024 / MS026 / MS027 / MS039 / MS040 / MS041 / MS042 / MS043 / MS044 / MS045 / MS046) | arch |
| R11276 | Sub-requirements — sub-requirements cross-reference sovereign-os milestones (M060 / M068 / M071 / M072 / M055) | arch |
| R11277 | Sub-requirements — sub-requirements documented in info-hub wiki under `wiki/perimeter/` | arch + cross-ref MS027 |
| R11278 | Operator agency — no R-row above is implementable by AI alone (operator review at every milestone closure) | operator agency |
| R11279 | Operator agency — operator may reorder, split, merge any R-row (catalog is editable) | operator agency |
| R11280 | Operator agency — every catalog change committed via signed commit (MS041 commit-authority audit trail) | cross-ref MS041 |

## Sub-requirements accounting

Per operator standing direction *"every of those requirements is in reality already quite specific and with at least 10 hard non-negotiable requirements each"*: each R-row above decomposes into ≥10 sub-requirements under SDD discipline. The sub-requirements live in:
- `docs/sdd/SDD-perimeter-engine.md` (R-bindings to L1-L5 test fixtures)
- `docs/sdd/SDD-perimeter-subreqs.md` (≥10 sub-requirements per R-row)
- `docs/ocsf/events.md` (per-event sample payloads + field constraints)
- `wiki/perimeter/<topic>.md` (per-topic operator pages)
- `wiki/runbooks/perimeter-{p1..p8}.md` (per-failure-mode operator runbooks)

This milestone catalogues the **top-level R-rows** that anchor the sub-requirement decomposition. Per operator direction, no R-row is invented — every row is sourced from sain-01 §6 verbatim, cross-referenced to earlier selfdef milestones, or extended deterministically (e.g. F05548 PATH_MAX truncation, F05574 known-malicious severity escalation, R11236 chroot-jump threat) and tagged with cross-reference in the source column.

## Cross-references

- **Source dump**: `~/infohub/raw/dumps/2026-05-15-sain-01-master-spec-other-conversation-transposition.md` §6 lines 380–411
- **Sister milestone (selfdef)**: MS003 selfdef-signing (policy + extension manifest signatures)
- **Sister milestone (selfdef)**: MS007 cross-repo typed-mirror (selfdef-perimeter-mirror)
- **Sister milestone (selfdef)**: MS009 audit-cycle (extension audit + replay validator)
- **Sister milestone (selfdef)**: MS016 eBPF programs (general baseline; this milestone is specific kernel-fence policy)
- **Sister milestone (selfdef)**: MS017 agent-guard (container-side invariants — companion layer)
- **Sister milestone (selfdef)**: MS019 threat model (R11230–R11236 mapped)
- **Sister milestone (selfdef)**: MS020 test-contract L1-L5 (R11245–R11253 mapped)
- **Sister milestone (selfdef)**: MS024 bridge-L2 module (L2 transparent bridge — network-side companion)
- **Sister milestone (selfdef)**: MS026 integrity sentinel (OCSF emission)
- **Sister milestone (selfdef)**: MS027 observability (verdict stream)
- **Sister milestone (selfdef)**: MS039 7 authority levels + 5 trust rings (Ring 0 ownership)
- **Sister milestone (selfdef)**: MS040 authority profile (extension multi-sig)
- **Sister milestone (selfdef)**: MS041 commit authority (extension/revoke audit)
- **Sister milestone (selfdef)**: MS042 tool authority (CLI surface)
- **Sister milestone (selfdef)**: MS043 IPS operator surface (TUI Perimeter row, CLI subcommand)
- **Sister milestone (selfdef)**: MS044 Guardian Daemon (event consumer)
- **Sister milestone (selfdef)**: MS045 UX coherence test harness (R-row TDD validator)
- **Sister milestone (selfdef)**: MS046 Friction Audit (companion boot-time gate + cross-cutting R-row references)
- **Sister milestone (sovereign-os)**: M055 failure-mode taxonomies (R11237 binding)
- **Sister milestone (sovereign-os)**: M060 Cockpit + 20+ dashboards (M060 Perimeter panel binding)
- **Sister milestone (sovereign-os)**: M068 ZFS storage architecture (log bridge dataset)
- **Sister milestone (sovereign-os)**: M071 Atomic State Transition Protocol (POSIX append-only fd)
- **Sister milestone (sovereign-os)**: M072 Master Bootstrap Verification Checklist (1:1 row)
- **Project boundary**: selfdef IPS Ring 0 only; sovereign-os receives the verdict via read-only typed mirror

## Schema

```yaml
# /etc/tetragon/tracing-policies/sovereign-perimeter.yaml (verbatim from sain-01 §6)
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

```text
schema_version: "1.0.0"
Verdict.fields:
  - attempted_binary_path: String (argv[0], full path, ≤ 4096 bytes)
  - attempting_pid: u32
  - parent_pid: u32
  - cgroup: String
  - container_id: Option<String>
  - process_cmdline: String
  - ts_ms: u64
  - signer_kid_policy: String (matches MS003 selfdef-signing key id for the base policy)
  - signer_kid_extension: Option<String> (matches MS003 signer for extension that allowed/rejected the path, if any)
```

— End of MS047.
