# SDD-032 — eBPF substrate + Tetragon TracingPolicy ledger — MS016

> Status: **draft** — Stage-2 architectural spec retrofitted for the
> in-tree MS016 eBPF substrate. The substrate ships in production
> (3 baseline probes + 5 TracingPolicies under modules/agent-guard/
> + collector pair); this SDD canonicalizes its design so subsequent
> milestones (MS017 agent-guard, MS044 guardian, MS047 perimeter)
> can cite it as the shared kernel-visibility contract.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS016 (catalog `backlog/milestones/MS016-ebpf-programs-tetragon-tracingpolicies.md`)
> Companions: SDD-028 (perimeter engine, downstream consumer),
> SDD-029 (guardian daemon, downstream consumer), the agent-guard
> module under `modules/agent-guard/` (5 TracingPolicies, MS017
> downstream consumer).

## Problem

The four-watchdog set + agent-guard module + selfdef-daemon all need
**kernel-visible process / file / network telemetry** as their
ground-truth event source. Without an in-tree eBPF substrate, every
downstream layer would re-implement its own kernel hook surface, fragment
the OCSF event contract, and diverge on capability requirements.

This SDD canonicalizes the substrate that already ships under
`bpf/selfdef-bpf/` + `crates/selfdef-ebpf-{common,collector-ebpf}/` +
`crates/selfdef-collector-tetragon/` + `rules/tetragon/` so future
work can build on a documented contract instead of guessing from the
code.

## Operator directive — verbatim (sacrosanct)

> "DO NOT MINIMIZE WHAT I SAY, SAID OR ASKED FOR, NOR THE NEED TO
>  EXPLOIT THE STACK AND TECHNO TO THE MAX, avx-plus-plus base reason
>  being. DO NOT STOP AT DEFINING/REGISTERING THE REQUIREMENT and
>  doing the scaffolds, we expect the full production progressively
>  through the workflow. SDD does not stop at the shell nor the core
>  it drive from it through all the layers."

Translation for MS016: kernel-side visibility must be SHIPPED + the
TracingPolicy ledger + collector pair + xtask + systemd capability
drop-in + daemon config block + graceful-degradation behavior must
ALL be in operator hands. Sub-features like LSM file_open path
capture remain honestly deferred per operator's "do not invent crap"
discipline.

## Substrate inventory (shipped, as of 2026-05-21)

| Artifact | Path | What it is |
|---|---|---|
| Out-of-workspace BPF crate | `bpf/selfdef-bpf/` | Kernel-side eBPF programs in Rust (aya-ebpf) — own `[workspace]`, target `bpfel-unknown-none`, profile dev=release (verifier requirements) |
| Shared types | `crates/selfdef-ebpf-common/` (179 LOC) | `features=["ebpf"]` for kernel-space; default features for userspace. Reserved type slots for deferred probes. |
| Userspace decoder | `crates/selfdef-collector-ebpf/` (555 LOC) | aya runtime + ringbuf decoder + event publisher; publishes `source="selfdef.ebpf"` events |
| Tetragon ingester | `crates/selfdef-collector-tetragon/` (415 LOC + `tests/`) | Consumes Tetragon JSON event stream, republishes to selfdef bus with `source="selfdef.tetragon"` + `policy_name=<TracingPolicy name>` |
| TracingPolicy ledger | `rules/tetragon/` | `README.md` + `observe-sensitive-files.yaml`. Operator-author-extensible. |
| Capability drop-in | `packaging/systemd/selfdefd.service.d/ebpf.conf` | Raises `CAP_BPF` + `CAP_PERFMON` + `LimitMEMLOCK=infinity` |
| xtask verbs | `xtask/src/main.rs` | `build-bpf [--release]`, `install-bpf [<dest>]` — default install path `/usr/lib/selfdef/selfdef.bpf.o` |
| TracingPolicies (downstream, MS017) | `modules/agent-guard/policies/*.yaml` | 5 policies: container-shell-guard, egress-guard, etc-write-guard, gpu-device-guard, securemessage-guard |

## Required coverage (Stage-2 acceptance)

### Deliverable 1 — Three baseline probes (M10)

| Probe | Hook | Capture surface | Status |
|---|---|---|---|
| `execve_enter` | `tracepoint:syscalls:sys_enter_execve` | pid / tgid / ppid / uid / gid / comm + argv up to 16 entries / 256 bytes + `argv_truncated` flag | shipping (full) |
| `file_open` | `lsm/file_open` | pid / uid / comm / flags | shipping (no path capture — see deferrals) |
| `do_unlinkat` | `kprobe:do_unlinkat` | pid / uid / comm | shipping (no path capture — see deferrals) |

**Acceptance gate**: loader logs the 3 startup markers ("loading BPF
object path=...", "attached tracepoint: syscalls/sys_enter_execve",
"draining BPF ring buffer") visible via
`journalctl -u selfdefd -f | grep -i ebpf`.

### Deliverable 2 — Five Tetragon TracingPolicies (under MS017)

| Policy | Scope | Profile-controlled action |
|---|---|---|
| `etc-write-guard` | `/etc/` write attempts | audit (audit profile) / killProcess (enforce profile) |
| `container-shell-guard` | shell spawn inside container | audit / killProcess |
| `egress-guard` | network egress | audit / killProcess; egress_allowlist override |
| `securemessage-guard` | OCSF SecureMessage emission | always Post (forced regardless of profile) |
| `gpu-device-guard` | GPU device touch | audit / killProcess |

These ship via the `modules/agent-guard/` module (SDD-032 D2 ↔ MS017),
with operator-config `audit | enforce` profile + per-policy
enable/disable toggle + per-policy action override.

### Deliverable 3 — Honest deferrals (5 future probes)

Catalog row M00419 enumerates 5 future eBPF programs:
**proc-ancestry**, **hidden-process**, **ld-preload-watch**,
**kmod-watch**, **tcp-fingerprint**. The substrate's extension
pattern (drop a `#[tracepoint]` / `#[lsm]` / `#[kprobe]` handler in
`bpf/selfdef-bpf/src/`, rebuild via `cargo xtask build-bpf --release`,
list new event kind in `EventKind`) means each adds ~1-2 days of
work + a deserializer in `selfdef-collector-ebpf`. They are NOT
Stage-2 acceptance; they ship as the operator prioritizes them.

Sub-feature deferrals on the 3 shipping probes:
- **argv capture from execve** — already shipping. No deferral.
- **LSM `file_open` path capture** — requires CO-RE `bpf_d_path` over
  `file->f_path`. Deferred until verifier-friendly bounds are worked
  out for the LSM context.
- **`do_unlinkat` path capture** — same rationale as `file_open`.

### Deliverable 4 — Daemon config block

The daemon honors `[collectors.ebpf]` in `/etc/selfdef/selfdef.toml`:

```toml
[collectors.ebpf]
enabled              = true
program_path         = "/usr/lib/selfdef/selfdef.bpf.o"
enable_execve        = true
enable_lsm_open      = false   # opt-in; needs CONFIG_BPF_LSM=y + bpf in CONFIG_LSM
enable_kprobe_unlink = false   # opt-in; noisy by default
```

Graceful degradation: if `program_path` is absent at startup,
collector logs a warning and runs idle (daemon stays up; other
collectors keep working). This lets the SAME daemon binary ship
to hosts with and without eBPF support — config drives the
difference.

### Deliverable 5 — Capability minimum (no full root)

The drop-in `packaging/systemd/selfdefd.service.d/ebpf.conf`:

```ini
[Service]
AmbientCapabilities=CAP_BPF CAP_PERFMON
CapabilityBoundingSet=CAP_BPF CAP_PERFMON
LimitMEMLOCK=infinity
```

The drop-in lands at `/etc/systemd/system/selfdefd.service.d/ebpf.conf`
after `systemctl daemon-reload` + `systemctl restart selfdefd`. The
daemon itself does NOT need to run as root — just CAP_BPF + CAP_PERFMON.

### Deliverable 6 — Tetragon TracingPolicy ledger contract

`rules/tetragon/*.yaml` is the **selfdef-owned** TracingPolicy ledger.
The `agent-guard` module's 5 policies are owned by MS017 and live
under `modules/agent-guard/policies/`. These are **different**
ledgers, both consumed by Tetragon's policy_dir, but with different
authorship rules:

- `rules/tetragon/` — daemon-shipped observers (e.g.
  `observe-sensitive-files.yaml`). Operator-author-extensible per
  the `rules/tetragon/README.md` contract.
- `modules/agent-guard/policies/` — module-shipped enforcers. Rendered
  per-host by `agent-guard/install/apply.sh` with profile + per-policy
  toggles + per-policy action overrides spliced in.

Both land in Tetragon's `policy_dir` (default
`/etc/tetragon/tetragon.tp.d`), but the policy_name field discriminates
which selfdef sub-system owns the signal downstream.

## Production-readiness gates

| Gate | Verification |
|---|---|
| BPF crate compiles | `cargo xtask build-bpf --release` exit 0 |
| Substrate runs without LSM | daemon starts cleanly with `enable_lsm_open=false` (default) |
| Substrate degrades gracefully without BPF object | daemon starts + emits warning when `program_path` absent |
| Tetragon collector ingests events | `selfdef-collector-tetragon/tests/` integration tests pass |
| Shared types compile on both sides | `cargo build -p selfdef-ebpf-common --features ebpf` AND `--no-default-features` both exit 0 |
| TracingPolicy ledger structural | `rules/tetragon/README.md` documents contract; every `*.yaml` in `rules/tetragon/` parses as Kubernetes object (kind, metadata.name, spec) |
| MS017 agent-guard L2 coverage | `bats packaging/test/L2-agent-guard.bats` exit 0 (25 tests) |

## Cross-references

- MS017 (agent-guard module — downstream consumer of the substrate):
  `backlog/milestones/MS017-agent-guard-host-level-invariants-on-ai-agents.md`
- MS044 (guardian daemon — Tetragon supervisor): `docs/sdd/029-guardian-daemon.md`
- MS047 (perimeter engine — kernel-fence via Tetragon TracingPolicies):
  `docs/sdd/028-perimeter-engine.md`
- Module tests (L2 bats suites): `packaging/test/L2-agent-guard.bats`,
  `packaging/test/L2-tetragon.bats`
- `docs/src/dev/ebpf.md` — operator-facing eBPF surface doc (the
  authoritative operator runbook for enabling + troubleshooting eBPF)
- `selfdef-ebpf/README.md` — planned-programs roadmap (5 future
  probes)
- xtask verbs: `xtask/src/main.rs:build_bpf` + `install_bpf`

## Implementation order (retrospective — already shipped)

1. ✅ Shared types crate (`selfdef-ebpf-common`)
2. ✅ Out-of-workspace BPF crate (`bpf/selfdef-bpf/`)
3. ✅ Three baseline probes (execve_enter / file_open / do_unlinkat)
4. ✅ xtask verbs (build-bpf / install-bpf)
5. ✅ Userspace ringbuf decoder + collector
   (`selfdef-collector-ebpf`)
6. ✅ Tetragon event ingester (`selfdef-collector-tetragon`)
7. ✅ Systemd capability drop-in (`selfdefd.service.d/ebpf.conf`)
8. ✅ Daemon `[collectors.ebpf]` config block + graceful degradation
9. ✅ TracingPolicy ledger (`rules/tetragon/`)
10. ✅ MS017 agent-guard module — 5 TracingPolicies + apply.sh wiring
11. ✅ L2 bats coverage for both substrate (tetragon module) + 
    consumer (agent-guard module)

## Authorization for Stage-3+ work

This SDD authorizes downstream work that depends on the substrate:

- MS017 agent-guard policy additions (drop a new YAML into
  `modules/agent-guard/policies/` + extend the L2 test)
- MS016 deferred probes (drop a new `#[tracepoint]` / `#[lsm]` /
  `#[kprobe]` in `bpf/selfdef-bpf/src/` + extend `EventKind` +
  add userspace decoder)
- Tetragon ledger extensions (drop a new YAML into `rules/tetragon/`
  + verify it appears in the daemon's collected stream)

Mark a downstream item DONE only when it reaches production per the
operator's standing direction ("you cannot mark something done if it
hasn't reached Prod").

— End of SDD-032 / MS016 Stage-2.
