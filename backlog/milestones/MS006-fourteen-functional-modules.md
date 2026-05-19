# MS006 — 14 functional modules — agent-guard / bitnet-gpu-inference / bridge-l2 / detect-host / hardware-tune-cache / integrity-sentinel / observability / polarproxy / slm-cpu-loop / suricata / tensor-parallel-inference / tetragon / vpn-bridge / wasm-aot-cache

> Parent: `backlog/milestones/INDEX.md` row MS006.
> Source: `modules/` directory (14 modules, empirically verified via `ls modules/`) + per-module `module.toml` + `README.md`.

## Epics (E0056–E0070)

| Epic ID | Phrase | Source |
|---|---|---|
| E0056 | 14-module functional catalog — operator-selectable per-module install | `modules/*` (14 dirs) |
| E0057 | agent-guard — Tetragon TracingPolicies for AI agents in Docker/Podman/containerd | `modules/agent-guard` |
| E0058 | bitnet-gpu-inference — host provisioning for GPU-side BitNet ternary inference (SD-R28) | `modules/bitnet-gpu-inference` |
| E0059 | bridge-l2 — transparent Layer-2 bridge + nftables FORWARD chain (foundation module) | `modules/bridge-l2` |
| E0060 | detect-host — selfdef daemon packaged as installable module (substrate that every other module feeds into) | `modules/detect-host` |
| E0061 | hardware-tune-cache — caches `selfdefctl hardware tune` flags to `/etc/selfdef/hardware-tune.env` (SD-R23) | `modules/hardware-tune-cache` |
| E0062 | integrity-sentinel — SHA256 baseline of policy artifacts + fail-closed drift detection | `modules/integrity-sentinel` |
| E0063 | observability — Prometheus scrape config + Grafana dashboard for selfdef stack | `modules/observability` |
| E0064 | polarproxy — transparent PolarProxy TLS termination + PCAP-over-IP on tcp/4430 | `modules/polarproxy` |
| E0065 | slm-cpu-loop — SLM-on-CPU agent loop pinned to CCD-0 (Phi-4-mini / Qwen3-1.7B class, SD-R72) | `modules/slm-cpu-loop` |
| E0066 | suricata — inline IDS with bridge-l2 FORWARD hook + eve.json → daemon event bus | `modules/suricata` |
| E0067 | tensor-parallel-inference — tensor-parallel splits across GPUs (SD-R51 ALL-semantics + SD-R55 signing, SD-R58) | `modules/tensor-parallel-inference` |
| E0068 | tetragon — substrate for Tetragon observability+enforcement (config + policy drop dir + metrics endpoint) | `modules/tetragon` |
| E0069 | vpn-bridge — remote-network connectivity for hosts behind their own router/firewall | `modules/vpn-bridge` |
| E0070 | wasm-aot-cache — AOT-compiled WASM cache for downstream WASM-plugin tier | `modules/wasm-aot-cache` |

## Modules (M00133–M00160)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00133 | agent-guard TracingPolicy — `no-etc-write` (containers cannot write `/etc/` outside container) | `modules/agent-guard` policies | E0057 |
| M00134 | agent-guard TracingPolicy — `no-shell-exec` (no shell exec inside container) | `modules/agent-guard` policies | E0057 |
| M00135 | agent-guard TracingPolicy — `allowlisted-egress` (network egress allowlist per container) | `modules/agent-guard` policies | E0057 |
| M00136 | agent-guard TracingPolicy — `gpu-device-allowlist` (gpu device-node allowlist per container) | `modules/agent-guard` policies | E0057 |
| M00137 | agent-guard mode — `audit` (observe + log only) | `modules/agent-guard` modes | E0057 |
| M00138 | agent-guard mode — `enforce` (kill on violation) | `modules/agent-guard` modes | E0057 |
| M00139 | agent-guard k8s scoping — optional pod-label scoping | `modules/agent-guard` k8s | E0057 |
| M00140 | bitnet-gpu-inference runtime — per-GPU schedule hints + env-file | `modules/bitnet-gpu-inference` | E0058 |
| M00141 | bridge-l2 — `br0` ownership + FORWARD policy chain | `modules/bridge-l2` | E0059 |
| M00142 | bridge-l2 hook attachment — exposes hook for `suricata` + `polarproxy` modules | `modules/bridge-l2` hooks | E0059 |
| M00143 | detect-host substrate — installs selfdef-daemon (collectors + correlator + responder + notifier + store + api) | `modules/detect-host` | E0060 |
| M00144 | hardware-tune-cache — emits `/etc/selfdef/hardware-tune.env` for downstream builds | `modules/hardware-tune-cache` | E0061 |
| M00145 | integrity-sentinel baseline — SHA256 of every policy artifact | `modules/integrity-sentinel` | E0062 |
| M00146 | integrity-sentinel verify — fail-closed drift detection (modified / removed / new) | `modules/integrity-sentinel` | E0062 |
| M00147 | observability Prometheus scrape config — `selfdef.yml` for Tetragon metrics endpoint | `modules/observability` | E0063 |
| M00148 | observability Grafana dashboard — selfdef stack overview | `modules/observability` | E0063 |
| M00149 | polarproxy TLS termination — transparent re-encryption pipeline | `modules/polarproxy` | E0064 |
| M00150 | polarproxy PCAP-over-IP emit — tcp/4430 sink | `modules/polarproxy` | E0064 |
| M00151 | slm-cpu-loop pinning — CCD-0 core affinity for low-latency background agent | `modules/slm-cpu-loop` | E0065 |
| M00152 | slm-cpu-loop model catalog — Phi-4-mini / Qwen3-1.7B class | `modules/slm-cpu-loop` | E0065 |
| M00153 | suricata inline attachment mode 1 — bridge-l2 FORWARD hook | `modules/suricata` | E0066 |
| M00154 | suricata inline attachment mode 2 — NFQUEUE-based attachment | `modules/suricata` | E0066 |
| M00155 | tensor-parallel-inference splits — every GPU hosts a slice | `modules/tensor-parallel-inference` | E0067 |
| M00156 | tetragon config — main config + TracingPolicy drop directory `/etc/tetragon/tracingpolicies.d/` | `modules/tetragon` | E0068 |
| M00157 | tetragon metrics endpoint — Prometheus scrape target | `modules/tetragon` | E0068 |
| M00158 | vpn-bridge WireGuard tunnel — operator-configured remote-network bridge | `modules/vpn-bridge` | E0069 |
| M00159 | vpn-bridge multi-instance — multiple tunnels per host (SDD-003 honesty) | `modules/vpn-bridge` + SDD-003 | E0069 |
| M00160 | wasm-aot-cache — AOT-compile cache for `wasmtime compile` artifacts | `modules/wasm-aot-cache` | E0070 |

## Features (F00601–F00720)

| F ID | Phrase | Source | Parent module | Category | Opt-in |
|---|---|---|---|---|---|
| F00601 | Toggle module — agent-guard | modules.toml | E0057 | mode | true |
| F00602 | Toggle module — bitnet-gpu-inference | modules.toml | E0058 | mode | true |
| F00603 | Toggle module — bridge-l2 | modules.toml | E0059 | mode | true |
| F00604 | Toggle module — detect-host | modules.toml | E0060 | mode | true |
| F00605 | Toggle module — hardware-tune-cache | modules.toml | E0061 | mode | true |
| F00606 | Toggle module — integrity-sentinel | modules.toml | E0062 | mode | true |
| F00607 | Toggle module — observability | modules.toml | E0063 | mode | true |
| F00608 | Toggle module — polarproxy | modules.toml | E0064 | mode | true |
| F00609 | Toggle module — slm-cpu-loop | modules.toml | E0065 | mode | true |
| F00610 | Toggle module — suricata | modules.toml | E0066 | mode | true |
| F00611 | Toggle module — tensor-parallel-inference | modules.toml | E0067 | mode | true |
| F00612 | Toggle module — tetragon | modules.toml | E0068 | mode | true |
| F00613 | Toggle module — vpn-bridge | modules.toml | E0069 | mode | true |
| F00614 | Toggle module — wasm-aot-cache | modules.toml | E0070 | mode | true |
| F00615 | Profile knob — `modules.enabled = csv` | `crates/selfdef-config` | E0056 | profile | true |
| F00616 | Env var `SELFDEF_MODULES_ENABLED` | `crates/selfdef-config` | E0056 | env_var | true |
| F00617 | CLI `selfdefctl modules list` | `crates/selfdef-cli` | E0056 | cli_verb | true |
| F00618 | CLI `selfdefctl modules apply` | `crates/selfdef-cli` | E0056 | cli_verb | true |
| F00619 | CLI `selfdefctl modules apply --dry-run` | `crates/selfdef-cli` | E0056 | cli_verb | true |
| F00620 | CLI `selfdefctl modules apply --diff` | `crates/selfdef-cli` | E0056 | cli_verb | true |
| F00621 | CLI `selfdefctl modules status` (per-module health + last-apply timestamp) | `crates/selfdef-cli` | E0056 | cli_verb | true |
| F00622 | API `GET /v1/modules` (lists 14 modules + state + dependencies + last-apply) | `crates/selfdef-api` | E0056 | api_endpoint | true |
| F00623 | API `POST /v1/modules/apply` (operator-triggered apply with dry-run option) | `crates/selfdef-api` | E0056 | api_endpoint | true |
| F00624 | Dashboard — per-module status tiles (running / installed / disabled / errored / drift-detected) | `dashboard/` | E0056 | dashboard | true |
| F00625 | Dashboard — module dependency graph (operator-discoverable install ordering) | `dashboard/` | E0056 | dashboard | true |
| F00626 | Module dependency — `detect-host` is required by every other module that emits events | per-module module.toml | M00143 | composite | false |
| F00627 | Module dependency — `tetragon` is required by `agent-guard` | per-module module.toml | M00133 | composite | false |
| F00628 | Module dependency — `bridge-l2` is required by `suricata` + `polarproxy` | per-module module.toml | M00141 | composite | false |
| F00629 | agent-guard policy — no-etc-write (audit + enforce) | `modules/agent-guard` | M00133 | composite | true |
| F00630 | agent-guard policy — no-shell-exec (audit + enforce) | `modules/agent-guard` | M00134 | composite | true |
| F00631 | agent-guard policy — allowlisted-egress (audit + enforce) | `modules/agent-guard` | M00135 | composite | true |
| F00632 | agent-guard policy — gpu-device-allowlist (audit + enforce) | `modules/agent-guard` | M00136 | composite | true |
| F00633 | agent-guard mode — audit (default) | `modules/agent-guard` | M00137 | mode | true |
| F00634 | agent-guard mode — enforce (operator-opt-in) | `modules/agent-guard` | M00138 | mode | true |
| F00635 | agent-guard k8s pod-label scoping | `modules/agent-guard` | M00139 | profile | true |
| F00636 | bitnet-gpu-inference per-GPU env-file | `modules/bitnet-gpu-inference` | M00140 | composite | true |
| F00637 | bitnet-gpu-inference per-GPU schedule hints | `modules/bitnet-gpu-inference` | M00140 | composite | true |
| F00638 | bridge-l2 — `br0` device creation + management | `modules/bridge-l2` | M00141 | composite | false |
| F00639 | bridge-l2 — operator-overrideable bridge device name | `crates/selfdef-config` | M00141 | profile | true |
| F00640 | bridge-l2 — nftables FORWARD policy table installation | `modules/bridge-l2` | M00141 | composite | false |
| F00641 | bridge-l2 — hook chain for downstream modules | `modules/bridge-l2` | M00142 | composite | false |
| F00642 | detect-host — installs selfdef-daemon systemd unit | `modules/detect-host` | M00143 | composite | false |
| F00643 | detect-host — verifies daemon health after install | `modules/detect-host` | M00143 | composite | false |
| F00644 | hardware-tune-cache — writes `/etc/selfdef/hardware-tune.env` | `modules/hardware-tune-cache` | M00144 | composite | false |
| F00645 | hardware-tune-cache — operator-overrideable env-file path | `crates/selfdef-config` | M00144 | profile | true |
| F00646 | hardware-tune-cache — refreshed on `selfdefctl hardware tune --apply` | `crates/selfdef-cli` | M00144 | composite | true |
| F00647 | integrity-sentinel — SHA256 baseline file at `/var/lib/selfdef/integrity.sha256` | `modules/integrity-sentinel` | M00145 | composite | false |
| F00648 | integrity-sentinel — operator-overrideable baseline path | `crates/selfdef-config` | M00145 | profile | true |
| F00649 | integrity-sentinel — tracked-glob list operator-extensible | `crates/selfdef-config` | M00145 | profile | true |
| F00650 | integrity-sentinel — fail-closed by default (drift makes `modules apply` exit non-zero) | `modules/integrity-sentinel` | M00146 | composite | false |
| F00651 | integrity-sentinel — `selfdefctl integrity verify` operator-facing verb | `crates/selfdef-cli` | M00146 | cli_verb | true |
| F00652 | integrity-sentinel — `selfdefctl integrity rebaseline` operator-facing verb (triple-gated) | `crates/selfdef-cli` | M00145 | cli_verb | true |
| F00653 | observability — `selfdef.yml` Prometheus scrape config | `modules/observability` | M00147 | composite | false |
| F00654 | observability — Grafana dashboard JSON shipped | `modules/observability` | M00148 | composite | true |
| F00655 | observability — operator-tunable scrape interval | `crates/selfdef-config` | M00147 | profile | true |
| F00656 | observability — operator-tunable Prometheus endpoint URL | `crates/selfdef-config` | M00147 | profile | true |
| F00657 | polarproxy — TLS termination + re-encryption | `modules/polarproxy` | M00149 | composite | true |
| F00658 | polarproxy — PCAP-over-IP emit on tcp/4430 | `modules/polarproxy` | M00150 | composite | true |
| F00659 | polarproxy — operator-tunable PCAP port | `crates/selfdef-config` | M00150 | profile | true |
| F00660 | polarproxy — CA cert install path operator-tunable | `crates/selfdef-config` | M00149 | profile | true |
| F00661 | slm-cpu-loop — CCD-0 core pin (numactl --cpunodebind) | `modules/slm-cpu-loop` | M00151 | composite | false |
| F00662 | slm-cpu-loop — operator-overrideable core pin (default CCD-0) | `crates/selfdef-config` | M00151 | profile | true |
| F00663 | slm-cpu-loop — Phi-4-mini default model | `modules/slm-cpu-loop` | M00152 | composite | true |
| F00664 | slm-cpu-loop — Qwen3-1.7B alternative model | `modules/slm-cpu-loop` | M00152 | composite | true |
| F00665 | slm-cpu-loop — operator-overrideable model path | `crates/selfdef-config` | M00152 | profile | true |
| F00666 | suricata — inline attachment via bridge-l2 FORWARD hook | `modules/suricata` | M00153 | mode | true |
| F00667 | suricata — inline attachment via NFQUEUE | `modules/suricata` | M00154 | mode | true |
| F00668 | suricata — operator-selectable attachment mode | `crates/selfdef-config` | E0066 | profile | true |
| F00669 | suricata — reuses selfdef-collector-suricata for eve.json ingest | `crates/selfdef-collector-suricata` | E0066 | composite | false |
| F00670 | tensor-parallel-inference — per-GPU slice provisioning | `modules/tensor-parallel-inference` | M00155 | composite | true |
| F00671 | tensor-parallel-inference — SD-R51 ALL-semantics enforcement | `modules/tensor-parallel-inference` | M00155 | composite | false |
| F00672 | tensor-parallel-inference — SD-R55 signing composition | `modules/tensor-parallel-inference` | M00155 | composite | false |
| F00673 | tetragon — main config at `/etc/tetragon/tetragon.yaml` | `modules/tetragon` | M00156 | composite | false |
| F00674 | tetragon — TracingPolicy drop directory `/etc/tetragon/tracingpolicies.d/` | `modules/tetragon` | M00156 | composite | false |
| F00675 | tetragon — Prometheus metrics endpoint exposed | `modules/tetragon` | M00157 | composite | false |
| F00676 | tetragon — operator-supplied binary path (module stays simple) | `modules/tetragon` | E0068 | composite | true |
| F00677 | vpn-bridge — WireGuard tunnel install + key generation | `modules/vpn-bridge` | M00158 | composite | true |
| F00678 | vpn-bridge — operator-supplied peer config | `crates/selfdef-config` | M00158 | profile | true |
| F00679 | vpn-bridge — multi-instance support (SDD-003 honesty) | `modules/vpn-bridge` + SDD-003 | M00159 | composite | true |
| F00680 | vpn-bridge — per-instance interface name `wg0` / `wg1` / ... | `crates/selfdef-config` | M00159 | profile | true |
| F00681 | wasm-aot-cache — `wasmtime compile` artifact cache directory | `modules/wasm-aot-cache` | M00160 | composite | true |
| F00682 | wasm-aot-cache — operator-overrideable cache path | `crates/selfdef-config` | M00160 | profile | true |
| F00683 | wasm-aot-cache — cache eviction policy operator-tunable | `crates/selfdef-config` | M00160 | profile | true |
| F00684 | Modules apply ordering — topological sort by dependency | `crates/selfdef-cli` | E0056 | composite | false |
| F00685 | Modules apply rollback — on partial failure, rollback applied modules | `crates/selfdef-cli` | E0056 | composite | true |
| F00686 | Modules apply lock — single in-flight apply at a time (mutex) | `crates/selfdef-cli` | E0056 | composite | false |
| F00687 | Modules apply audit trail — every apply logged to `selfdef-store` actions table | `crates/selfdef-store` | E0056 | composite | false |
| F00688 | Modules per-module README.md describing scope + dependencies + env vars + apply/check/uninstall scripts | `modules/<name>/README.md` | E0056 | composite | true |
| F00689 | Modules per-module `module.toml` with name / version / summary / category | `modules/<name>/module.toml` | E0056 | composite | false |
| F00690 | Modules per-module install/apply.sh script (idempotent) | `modules/<name>/install/apply.sh` | E0056 | composite | false |
| F00691 | Modules per-module install/check.sh script (drift detection) | `modules/<name>/install/check.sh` | E0056 | composite | false |
| F00692 | Modules per-module install/uninstall.sh script (reversible) | `modules/<name>/install/uninstall.sh` | E0056 | composite | false |
| F00693 | Modules apply emits per-module Prometheus metric `selfdef_module_apply_total{module,outcome}` | `crates/selfdef-cli` | E0056 | observability_metric | true |
| F00694 | Modules apply emits per-module Prometheus metric `selfdef_module_state{module,state}` | `crates/selfdef-cli` | E0056 | observability_metric | true |
| F00695 | Modules apply respects systemd unit hardening | `packaging/systemd/` | E0056 | composite | false |
| F00696 | Modules apply respects AppArmor profile | `packaging/apparmor/` | E0056 | composite | false |
| F00697 | Modules apply respects cgroup v2 slice | `packaging/systemd/` | E0056 | composite | false |
| F00698 | Modules per-module `category` taxonomy — security / network / inference / hardware / observability / vpn | `modules/<name>/module.toml` | E0056 | composite | true |
| F00699 | Modules per-module `dependencies = [<module>]` field in module.toml | `modules/<name>/module.toml` | E0056 | composite | true |
| F00700 | Modules per-module `default = bool` in module.toml (auto-enable on fresh install) | `modules/<name>/module.toml` | E0056 | composite | true |
| F00701 | Test — modules apply ordering respects dependency topology | tests/ | F00684 | test | false |
| F00702 | Test — modules apply rollback restores prior state on partial failure | tests/ | F00685 | test | false |
| F00703 | Test — modules apply lock prevents concurrent apply | tests/ | F00686 | test | false |
| F00704 | Test — modules apply audit trail records every apply with operator + timestamp + outcome | tests/ | F00687 | test | false |
| F00705 | Test — per-module install/check.sh detects drift correctly | tests/ | F00691 | test | false |
| F00706 | Test — per-module install/uninstall.sh fully reverses install/apply.sh | tests/ | F00692 | test | false |
| F00707 | Test — agent-guard 4 policies (no-etc-write / no-shell-exec / allowlisted-egress / gpu-device-allowlist) all loaded by tetragon | tests/ | M00133-M00136 | test | false |
| F00708 | Test — agent-guard enforce mode kills container on violation | tests/ | M00138 | test | false |
| F00709 | Test — bridge-l2 FORWARD hook chain exposes hook for suricata + polarproxy | tests/ | M00142 | test | false |
| F00710 | Test — detect-host substrate installs selfdef-daemon + verifies health | tests/ | M00143 | test | false |
| F00711 | Test — integrity-sentinel baseline + verify round-trip detects modified file | tests/ | M00146 | test | false |
| F00712 | Test — integrity-sentinel detects removed file | tests/ | M00146 | test | false |
| F00713 | Test — integrity-sentinel detects new file matching tracked glob | tests/ | M00146 | test | false |
| F00714 | Test — observability Prometheus scrape config is valid YAML + Grafana dashboard imports cleanly | tests/ | M00147 + M00148 | test | false |
| F00715 | Test — polarproxy PCAP-over-IP emits on tcp/4430 on synthetic TLS flow | tests/ | M00150 | test | false |
| F00716 | Test — slm-cpu-loop pins to CCD-0 cores verified via cpuset inspection | tests/ | M00151 | test | false |
| F00717 | Test — suricata inline attachment (bridge-l2 mode) fires SID 2100498 canary | tests/ | M00153 | test | false |
| F00718 | Test — tensor-parallel-inference SD-R51 ALL-semantics enforcement test | tests/ | M00155 | test | false |
| F00719 | Test — vpn-bridge multi-instance test (wg0 + wg1 simultaneously) | tests/ | M00159 | test | false |
| F00720 | Test — wasm-aot-cache hit rate measurable + eviction policy honored | tests/ | M00160 | test | false |

## Requirements (R01201–R01440)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R01201 | Functional module catalog has exactly 14 modules (agent-guard / bitnet-gpu-inference / bridge-l2 / detect-host / hardware-tune-cache / integrity-sentinel / observability / polarproxy / slm-cpu-loop / suricata / tensor-parallel-inference / tetragon / vpn-bridge / wasm-aot-cache) | repo `modules/*` | E0056 | non-negotiable | false | 10 |
| R01202 | Each module lives in its own `modules/<name>/` directory | repo | E0056 | non-negotiable | false | 10 |
| R01203 | Each module has a `README.md` documenting scope + dependencies | repo | F00688 | non-negotiable | true | 10 |
| R01204 | Each module has a `module.toml` with name / version / summary / category | repo | F00689 | non-negotiable | false | 10 |
| R01205 | Each module has `install/apply.sh` idempotent installer | repo | F00690 | non-negotiable | false | 10 |
| R01206 | Each module has `install/check.sh` drift detector | repo | F00691 | non-negotiable | false | 10 |
| R01207 | Each module has `install/uninstall.sh` reversible uninstaller | repo | F00692 | non-negotiable | false | 10 |
| R01208 | Each module is operator-toggleable via modules.toml | `crates/selfdef-config` | E0056 | non-negotiable | true | 10 |
| R01209 | Modules apply ordering respects dependency topology | `crates/selfdef-cli` | F00684 | non-negotiable | false | 10 |
| R01210 | Modules apply rollback restores prior state on partial failure | `crates/selfdef-cli` | F00685 | non-negotiable | true | 10 |
| R01211 | Modules apply lock prevents concurrent apply (mutex) | `crates/selfdef-cli` | F00686 | non-negotiable | false | 10 |
| R01212 | Modules apply audit trail records every apply in `selfdef-store` actions table | `crates/selfdef-store` | F00687 | non-negotiable | false | 10 |
| R01213 | Modules apply emits `selfdef_module_apply_total{module,outcome}` metric | `crates/selfdef-cli` | F00693 | non-negotiable | true | 10 |
| R01214 | Modules apply emits `selfdef_module_state{module,state}` metric | `crates/selfdef-cli` | F00694 | non-negotiable | true | 10 |
| R01215 | agent-guard provides Tetragon TracingPolicies for AI agents in Docker / Podman / containerd containers | `modules/agent-guard` | E0057 | non-negotiable | false | 10 |
| R01216 | agent-guard policy — no-etc-write (containers cannot write `/etc/`) | `modules/agent-guard` | M00133 | non-negotiable | true | 10 |
| R01217 | agent-guard policy — no-shell-exec (no shell exec inside container) | `modules/agent-guard` | M00134 | non-negotiable | true | 10 |
| R01218 | agent-guard policy — allowlisted-egress (network egress allowlist per container) | `modules/agent-guard` | M00135 | non-negotiable | true | 10 |
| R01219 | agent-guard policy — gpu-device-allowlist (gpu device-node allowlist per container) | `modules/agent-guard` | M00136 | non-negotiable | true | 10 |
| R01220 | agent-guard mode — `audit` (observe + log only; default) | `modules/agent-guard` | M00137 | non-negotiable | true | 10 |
| R01221 | agent-guard mode — `enforce` (kill on violation; operator-opt-in) | `modules/agent-guard` | M00138 | non-negotiable | true | 10 |
| R01222 | agent-guard k8s pod-label scoping (optional) | `modules/agent-guard` | M00139 | non-negotiable | true | 10 |
| R01223 | agent-guard depends on tetragon module | `modules/agent-guard/module.toml` | F00627 | non-negotiable | false | 10 |
| R01224 | bitnet-gpu-inference provisions host for GPU-side BitNet ternary inference (SD-R28) | `modules/bitnet-gpu-inference` | E0058 | non-negotiable | true | 10 |
| R01225 | bitnet-gpu-inference emits per-GPU env-file | `modules/bitnet-gpu-inference` | M00140 | non-negotiable | true | 10 |
| R01226 | bitnet-gpu-inference emits per-GPU schedule hints | `modules/bitnet-gpu-inference` | M00140 | non-negotiable | true | 10 |
| R01227 | bitnet-gpu-inference category = `inference` | `modules/bitnet-gpu-inference/module.toml` | F00698 | non-negotiable | false | 10 |
| R01228 | bridge-l2 owns `br0` bridge device | `modules/bridge-l2` | M00141 | non-negotiable | false | 10 |
| R01229 | bridge-l2 bridge device name operator-overrideable | `crates/selfdef-config` | F00639 | non-negotiable | true | 10 |
| R01230 | bridge-l2 installs nftables FORWARD policy table | `modules/bridge-l2` | M00141 | non-negotiable | false | 10 |
| R01231 | bridge-l2 exposes hook chain for downstream modules | `modules/bridge-l2` | M00142 | non-negotiable | false | 10 |
| R01232 | bridge-l2 is foundation module (required by suricata + polarproxy) | `modules/bridge-l2/module.toml` | F00628 | non-negotiable | false | 10 |
| R01233 | detect-host packages selfdef-daemon as installable module | `modules/detect-host` | E0060 | non-negotiable | false | 10 |
| R01234 | detect-host installs daemon (collectors + correlator + responder + notifier + store + api) | `modules/detect-host` | M00143 | non-negotiable | false | 10 |
| R01235 | detect-host verifies daemon health after install | `modules/detect-host` | F00643 | non-negotiable | false | 10 |
| R01236 | detect-host is the substrate every other module feeds into | `modules/detect-host` | E0060 | non-negotiable | false | 10 |
| R01237 | hardware-tune-cache caches `selfdefctl hardware tune` flags (SD-R23) | `modules/hardware-tune-cache` | E0061 | non-negotiable | true | 10 |
| R01238 | hardware-tune-cache writes `/etc/selfdef/hardware-tune.env` | `modules/hardware-tune-cache` | M00144 | non-negotiable | false | 10 |
| R01239 | hardware-tune-cache env-file path operator-overrideable | `crates/selfdef-config` | F00645 | non-negotiable | true | 10 |
| R01240 | hardware-tune-cache refreshed on `selfdefctl hardware tune --apply` | `crates/selfdef-cli` | F00646 | non-negotiable | true | 10 |
| R01241 | hardware-tune-cache category = `hardware` | `modules/hardware-tune-cache/module.toml` | F00698 | non-negotiable | false | 10 |
| R01242 | integrity-sentinel records SHA256 baseline of policy artifacts | `modules/integrity-sentinel` | M00145 | non-negotiable | false | 10 |
| R01243 | integrity-sentinel verifies host still matches baseline | `modules/integrity-sentinel` | M00146 | non-negotiable | false | 10 |
| R01244 | integrity-sentinel is fail-closed by default | `modules/integrity-sentinel` | F00650 | non-negotiable | false | 10 |
| R01245 | integrity-sentinel — any drift makes `selfdefctl modules apply` exit non-zero | `modules/integrity-sentinel` | F00650 | non-negotiable | false | 10 |
| R01246 | integrity-sentinel baseline file at `/var/lib/selfdef/integrity.sha256` | `modules/integrity-sentinel` | F00647 | non-negotiable | true | 10 |
| R01247 | integrity-sentinel tracked-glob list operator-extensible | `crates/selfdef-config` | F00649 | non-negotiable | true | 10 |
| R01248 | integrity-sentinel `selfdefctl integrity verify` operator-facing verb | `crates/selfdef-cli` | F00651 | non-negotiable | true | 10 |
| R01249 | integrity-sentinel `selfdefctl integrity rebaseline` triple-gated verb | `crates/selfdef-cli` | F00652 | non-negotiable | true | 10 |
| R01250 | observability provides Prometheus scrape config + Grafana dashboard | `modules/observability` | E0063 | non-negotiable | false | 10 |
| R01251 | observability — `selfdef.yml` Prometheus scrape config | `modules/observability` | M00147 | non-negotiable | false | 10 |
| R01252 | observability — Grafana dashboard JSON shipped | `modules/observability` | M00148 | non-negotiable | true | 10 |
| R01253 | observability — scrape interval operator-tunable | `crates/selfdef-config` | F00655 | non-negotiable | true | 10 |
| R01254 | observability — Prometheus endpoint URL operator-tunable | `crates/selfdef-config` | F00656 | non-negotiable | true | 10 |
| R01255 | polarproxy provides transparent TLS termination + re-encryption | `modules/polarproxy` | E0064 | non-negotiable | true | 10 |
| R01256 | polarproxy emits PCAP-over-IP on tcp/4430 | `modules/polarproxy` | M00150 | non-negotiable | true | 10 |
| R01257 | polarproxy PCAP port operator-tunable (default 4430) | `crates/selfdef-config` | F00659 | non-negotiable | true | 10 |
| R01258 | polarproxy CA cert install path operator-tunable | `crates/selfdef-config` | F00660 | non-negotiable | true | 10 |
| R01259 | polarproxy depends on bridge-l2 module | `modules/polarproxy/module.toml` | F00628 | non-negotiable | false | 10 |
| R01260 | slm-cpu-loop pins SLM-on-CPU agent loop to CCD-0 (SD-R72) | `modules/slm-cpu-loop` | E0065 | non-negotiable | true | 10 |
| R01261 | slm-cpu-loop supports Phi-4-mini default model | `modules/slm-cpu-loop` | F00663 | non-negotiable | true | 10 |
| R01262 | slm-cpu-loop supports Qwen3-1.7B alternative | `modules/slm-cpu-loop` | F00664 | non-negotiable | true | 10 |
| R01263 | slm-cpu-loop core pin operator-overrideable | `crates/selfdef-config` | F00662 | non-negotiable | true | 10 |
| R01264 | slm-cpu-loop model path operator-overrideable | `crates/selfdef-config` | F00665 | non-negotiable | true | 10 |
| R01265 | slm-cpu-loop category = `inference` | `modules/slm-cpu-loop/module.toml` | F00698 | non-negotiable | false | 10 |
| R01266 | suricata provides inline IDS via Suricata | `modules/suricata` | E0066 | non-negotiable | true | 10 |
| R01267 | suricata supports attachment mode 1 — bridge-l2 FORWARD hook | `modules/suricata` | M00153 | non-negotiable | true | 10 |
| R01268 | suricata supports attachment mode 2 — NFQUEUE-based | `modules/suricata` | M00154 | non-negotiable | true | 10 |
| R01269 | suricata attachment mode operator-selectable per host | `crates/selfdef-config` | F00668 | non-negotiable | true | 10 |
| R01270 | suricata depends on bridge-l2 module | `modules/suricata/module.toml` | F00628 | non-negotiable | false | 10 |
| R01271 | suricata reuses selfdef-collector-suricata for eve.json ingest | `crates/selfdef-collector-suricata` | F00669 | non-negotiable | false | 10 |
| R01272 | tensor-parallel-inference provisions tensor-parallel splits (every GPU hosts a slice; SD-R58) | `modules/tensor-parallel-inference` | E0067 | non-negotiable | true | 10 |
| R01273 | tensor-parallel-inference demonstrates SD-R51 ALL-semantics | `modules/tensor-parallel-inference` | F00671 | non-negotiable | false | 10 |
| R01274 | tensor-parallel-inference demonstrates SD-R55 signing composition | `modules/tensor-parallel-inference` | F00672 | non-negotiable | false | 10 |
| R01275 | tensor-parallel-inference category = `inference` | `modules/tensor-parallel-inference/module.toml` | F00698 | non-negotiable | false | 10 |
| R01276 | tetragon owns Tetragon main config + TracingPolicy drop directory + Prometheus metrics endpoint | `modules/tetragon` | E0068 | non-negotiable | false | 10 |
| R01277 | tetragon main config at `/etc/tetragon/tetragon.yaml` | `modules/tetragon` | M00156 | non-negotiable | false | 10 |
| R01278 | tetragon TracingPolicy drop directory at `/etc/tetragon/tracingpolicies.d/` | `modules/tetragon` | M00156 | non-negotiable | false | 10 |
| R01279 | tetragon Prometheus metrics endpoint exposed | `modules/tetragon` | M00157 | non-negotiable | false | 10 |
| R01280 | tetragon does NOT own any policies (those come from policy modules like agent-guard) | `modules/tetragon/README.md` | E0068 | non-negotiable | false | 10 |
| R01281 | tetragon does NOT install the Tetragon binary (operator does that out-of-band) | `modules/tetragon/README.md` | F00676 | non-negotiable | false | 10 |
| R01282 | tetragon stays simple — uses whichever Tetragon build the host has | `modules/tetragon/README.md` | F00676 | non-negotiable | false | 10 |
| R01283 | vpn-bridge provides remote-network connectivity for hosts behind their own router/firewall | `modules/vpn-bridge` | E0069 | non-negotiable | true | 10 |
| R01284 | vpn-bridge installs WireGuard tunnel + generates keys | `modules/vpn-bridge` | M00158 | non-negotiable | true | 10 |
| R01285 | vpn-bridge peer config operator-supplied | `crates/selfdef-config` | F00678 | non-negotiable | true | 10 |
| R01286 | vpn-bridge supports multi-instance (SDD-003 honesty — multiple tunnels per host) | `modules/vpn-bridge` + SDD-003 | M00159 | non-negotiable | true | 10 |
| R01287 | vpn-bridge per-instance interface name operator-supplied (wg0 / wg1 / ...) | `crates/selfdef-config` | F00680 | non-negotiable | true | 10 |
| R01288 | vpn-bridge category = `vpn` | `modules/vpn-bridge/module.toml` | F00698 | non-negotiable | false | 10 |
| R01289 | wasm-aot-cache caches AOT-compiled WASM artifacts | `modules/wasm-aot-cache` | E0070 | non-negotiable | true | 10 |
| R01290 | wasm-aot-cache cache directory operator-overrideable | `crates/selfdef-config` | F00682 | non-negotiable | true | 10 |
| R01291 | wasm-aot-cache eviction policy operator-tunable | `crates/selfdef-config` | F00683 | non-negotiable | true | 10 |
| R01292 | CLI `selfdefctl modules list` operator-facing | `crates/selfdef-cli` | F00617 | non-negotiable | true | 10 |
| R01293 | CLI `selfdefctl modules apply` operator-facing | `crates/selfdef-cli` | F00618 | non-negotiable | true | 10 |
| R01294 | CLI `selfdefctl modules apply --dry-run` previews changes | `crates/selfdef-cli` | F00619 | non-negotiable | true | 10 |
| R01295 | CLI `selfdefctl modules apply --diff` shows per-module diff | `crates/selfdef-cli` | F00620 | non-negotiable | true | 10 |
| R01296 | CLI `selfdefctl modules status` per-module health + last-apply timestamp | `crates/selfdef-cli` | F00621 | non-negotiable | true | 10 |
| R01297 | API `GET /v1/modules` lists 14 modules + state + dependencies + last-apply | `crates/selfdef-api` | F00622 | non-negotiable | true | 10 |
| R01298 | API `POST /v1/modules/apply` operator-triggered apply with dry-run option | `crates/selfdef-api` | F00623 | non-negotiable | true | 10 |
| R01299 | Dashboard — per-module status tiles | `dashboard/` | F00624 | non-negotiable | true | 10 |
| R01300 | Dashboard — module dependency graph | `dashboard/` | F00625 | non-negotiable | true | 10 |
| R01301 | Profile knob — `modules.enabled = csv` | `crates/selfdef-config` | F00615 | non-negotiable | true | 10 |
| R01302 | Env var `SELFDEF_MODULES_ENABLED` | `crates/selfdef-config` | F00616 | non-negotiable | true | 10 |
| R01303 | Operator can disable any module via modules.toml | `crates/selfdef-config` | E0056 | non-negotiable | true | 10 |
| R01304 | Operator can enable any subset of 14 modules independently (respecting dependencies) | `crates/selfdef-config` | E0056 | non-negotiable | true | 10 |
| R01305 | Test — modules apply ordering respects dependency topology | tests/ | F00701 | non-negotiable | false | 10 |
| R01306 | Test — modules apply rollback restores prior state on partial failure | tests/ | F00702 | non-negotiable | false | 10 |
| R01307 | Test — modules apply lock prevents concurrent apply | tests/ | F00703 | non-negotiable | false | 10 |
| R01308 | Test — modules apply audit trail records every apply | tests/ | F00704 | non-negotiable | false | 10 |
| R01309 | Test — per-module install/check.sh detects drift correctly | tests/ | F00705 | non-negotiable | false | 10 |
| R01310 | Test — per-module install/uninstall.sh fully reverses install/apply.sh | tests/ | F00706 | non-negotiable | false | 10 |
| R01311 | Test — agent-guard 4 policies all loaded by tetragon | tests/ | F00707 | non-negotiable | false | 10 |
| R01312 | Test — agent-guard enforce mode kills container on violation | tests/ | F00708 | non-negotiable | false | 10 |
| R01313 | Test — bridge-l2 FORWARD hook chain exposes hook for suricata + polarproxy | tests/ | F00709 | non-negotiable | false | 10 |
| R01314 | Test — detect-host substrate installs selfdef-daemon + verifies health | tests/ | F00710 | non-negotiable | false | 10 |
| R01315 | Test — integrity-sentinel baseline + verify detects modified file | tests/ | F00711 | non-negotiable | false | 10 |
| R01316 | Test — integrity-sentinel detects removed file | tests/ | F00712 | non-negotiable | false | 10 |
| R01317 | Test — integrity-sentinel detects new file matching tracked glob | tests/ | F00713 | non-negotiable | false | 10 |
| R01318 | Test — observability Prometheus scrape config valid YAML + Grafana imports cleanly | tests/ | F00714 | non-negotiable | false | 10 |
| R01319 | Test — polarproxy PCAP-over-IP emits on tcp/4430 on synthetic TLS flow | tests/ | F00715 | non-negotiable | false | 10 |
| R01320 | Test — slm-cpu-loop pins to CCD-0 cores verified via cpuset inspection | tests/ | F00716 | non-negotiable | false | 10 |
| R01321 | Test — suricata inline attachment fires SID 2100498 canary | tests/ | F00717 | non-negotiable | false | 10 |
| R01322 | Test — tensor-parallel-inference SD-R51 ALL-semantics enforcement | tests/ | F00718 | non-negotiable | false | 10 |
| R01323 | Test — vpn-bridge multi-instance test (wg0 + wg1 simultaneously) | tests/ | F00719 | non-negotiable | false | 10 |
| R01324 | Test — wasm-aot-cache hit rate measurable + eviction policy honored | tests/ | F00720 | non-negotiable | false | 10 |
| R01325 | Each module integrates with `selfdef-daemon` (event flow per MS001) | `crates/selfdef-daemon` | E0056 | non-negotiable | false | 10 |
| R01326 | Each module integrates with `selfdef-store` (audit trail per MS003) | `crates/selfdef-store` | F00687 | non-negotiable | false | 10 |
| R01327 | Each module integrates with `selfdef-cli` (CLI verbs per MS001) | `crates/selfdef-cli` | E0056 | non-negotiable | false | 10 |
| R01328 | Each module integrates with `selfdef-api` (REST API per MS001) | `crates/selfdef-api` | E0056 | non-negotiable | false | 10 |
| R01329 | Each module integrates with `selfdef-config` (operator config per MS001) | `crates/selfdef-config` | E0056 | non-negotiable | false | 10 |
| R01330 | Each module respects systemd unit hardening per MS001 R00055-R00063 | `packaging/systemd/` | F00695 | non-negotiable | false | 10 |
| R01331 | Each module respects AppArmor profile per MS001 R00064 | `packaging/apparmor/` | F00696 | non-negotiable | false | 10 |
| R01332 | Each module respects cgroup v2 slice per MS001 R00065 | `packaging/systemd/` | F00697 | non-negotiable | false | 10 |
| R01333 | UX — `selfdefctl modules list` output ≤ 1 screen on green case | `crates/selfdef-cli` | F00617 | preferable | true | 10 |
| R01334 | UX — `selfdefctl modules list` groups modules by category (security / network / inference / hardware / observability / vpn) | `crates/selfdef-cli` | F00617 | non-negotiable | true | 10 |
| R01335 | UX — `selfdefctl modules status` shows per-module health + last-apply with actionable error on failure | `crates/selfdef-cli` | F00621 | non-negotiable | true | 10 |
| R01336 | UX — operator-readable next-step on each module-apply failure | `crates/selfdef-cli` | E0056 | non-negotiable | true | 10 |
| R01337 | UX — Dashboard surfaces module drift detection as red tile with operator-next-step | `dashboard/` | M00146 | non-negotiable | true | 10 |
| R01338 | UX — Dashboard surfaces module dependency graph operator-discoverable | `dashboard/` | F00625 | non-negotiable | true | 10 |
| R01339 | UX — `selfdefctl --json` output available for every modules verb | `crates/selfdef-cli` | E0056 | non-negotiable | true | 10 |
| R01340 | UX — `selfdefctl modules apply --dry-run` shows operator-readable preview before commit | `crates/selfdef-cli` | F00619 | non-negotiable | true | 10 |
| R01341 | Project boundary — modules are IPS / host-security / inference-host-provisioning scope (selfdef); sovereign-os runtime has its own module/profile system per M015 | this milestone | E0056 | non-negotiable | false | 10 |
| R01342 | Project boundary — selfdef inference modules (bitnet-gpu-inference / slm-cpu-loop / tensor-parallel-inference / wasm-aot-cache) PROVISION the host hardware; sovereign-os runtime CONSUMES the provisioned env | this milestone | E0067 | non-negotiable | false | 10 |
| R01343 | Project boundary — sovereign-os NEVER imports selfdef module crate code directly | architecture | E0056 | non-negotiable | false | 10 |
| R01344 | Project boundary — modules.toml is selfdef-domain only; sovereign-os has its own SFIF stage gate | architecture | E0056 | non-negotiable | false | 10 |
| R01345 | Module taxonomy — security: agent-guard / detect-host / integrity-sentinel / tetragon / suricata / polarproxy | this milestone | F00698 | non-negotiable | true | 10 |
| R01346 | Module taxonomy — network: bridge-l2 / vpn-bridge | this milestone | F00698 | non-negotiable | true | 10 |
| R01347 | Module taxonomy — inference: bitnet-gpu-inference / slm-cpu-loop / tensor-parallel-inference | this milestone | F00698 | non-negotiable | true | 10 |
| R01348 | Module taxonomy — hardware: hardware-tune-cache | this milestone | F00698 | non-negotiable | true | 10 |
| R01349 | Module taxonomy — observability: observability | this milestone | F00698 | non-negotiable | true | 10 |
| R01350 | Module taxonomy — utility/cache: wasm-aot-cache | this milestone | F00698 | non-negotiable | true | 10 |
| R01351 | Each module's `category` field operator-discoverable via `selfdefctl modules list --by-category` | `crates/selfdef-cli` | F00698 | non-negotiable | true | 10 |
| R01352 | Each module's `default = bool` operator-discoverable | `modules/<name>/module.toml` | F00700 | non-negotiable | true | 10 |
| R01353 | Default — agent-guard `default = false` (operator opt-in for enforce mode) | `modules/agent-guard/module.toml` | F00700 | non-negotiable | true | 10 |
| R01354 | Default — bitnet-gpu-inference `default = false` (operator opt-in for GPU inference) | `modules/bitnet-gpu-inference/module.toml` | F00700 | non-negotiable | true | 10 |
| R01355 | Default — bridge-l2 `default = false` (operator opt-in for transparent bridge) | `modules/bridge-l2/module.toml` | F00700 | non-negotiable | true | 10 |
| R01356 | Default — detect-host `default = true` (foundational; required by event-emitting modules) | `modules/detect-host/module.toml` | F00700 | non-negotiable | true | 10 |
| R01357 | Default — hardware-tune-cache `default = false` (operator opt-in for tuned-compile-flags persistence) | `modules/hardware-tune-cache/module.toml` | F00700 | non-negotiable | true | 10 |
| R01358 | Default — integrity-sentinel `default = false` (operator opt-in for fail-closed drift detection) | `modules/integrity-sentinel/module.toml` | F00700 | non-negotiable | true | 10 |
| R01359 | Default — observability `default = false` (operator opt-in for Prometheus+Grafana) | `modules/observability/module.toml` | F00700 | non-negotiable | true | 10 |
| R01360 | Default — polarproxy `default = false` (operator opt-in for TLS termination) | `modules/polarproxy/module.toml` | F00700 | non-negotiable | true | 10 |
| R01361 | Default — slm-cpu-loop `default = false` (operator opt-in for SLM-on-CPU agent loop) | `modules/slm-cpu-loop/module.toml` | F00700 | non-negotiable | true | 10 |
| R01362 | Default — suricata `default = false` (operator opt-in for inline IDS) | `modules/suricata/module.toml` | F00700 | non-negotiable | true | 10 |
| R01363 | Default — tensor-parallel-inference `default = false` (operator opt-in for tensor-parallel splits) | `modules/tensor-parallel-inference/module.toml` | F00700 | non-negotiable | true | 10 |
| R01364 | Default — tetragon `default = false` (operator opt-in for Tetragon substrate) | `modules/tetragon/module.toml` | F00700 | non-negotiable | true | 10 |
| R01365 | Default — vpn-bridge `default = false` (operator opt-in for WireGuard tunnel) | `modules/vpn-bridge/module.toml` | F00700 | non-negotiable | true | 10 |
| R01366 | Default — wasm-aot-cache `default = false` (operator opt-in for WASM AOT cache) | `modules/wasm-aot-cache/module.toml` | F00700 | non-negotiable | true | 10 |
| R01367 | L1 lint — every module has README.md | tests/lint | F00688 | non-negotiable | false | 10 |
| R01368 | L1 lint — every module has module.toml | tests/lint | F00689 | non-negotiable | false | 10 |
| R01369 | L1 lint — every module has install/apply.sh | tests/lint | F00690 | non-negotiable | false | 10 |
| R01370 | L1 lint — every module has install/check.sh | tests/lint | F00691 | non-negotiable | false | 10 |
| R01371 | L1 lint — every module has install/uninstall.sh | tests/lint | F00692 | non-negotiable | false | 10 |
| R01372 | L1 lint — every module's apply.sh is idempotent (running twice = no change) | tests/lint | F00690 | non-negotiable | false | 10 |
| R01373 | L3 smoke — daemon starts with all 14 modules enabled + healthy | tests/ | E0056 | non-negotiable | false | 10 |
| R01374 | L3 smoke — daemon starts with all 14 modules disabled + healthy | tests/ | E0056 | non-negotiable | false | 10 |
| R01375 | L5 real-substrate — modules apply on real Debian 13 VM (agent-guard + bridge-l2 + detect-host + tetragon enabled) | tests/ | E0056 | non-negotiable | false | 10 |
| R01376 | Each module supports SDD-005 L1-L5 layered test harness | SDD-005 | E0056 | non-negotiable | false | 10 |
| R01377 | Each module supports SDD-006 shared module-script lib | SDD-006 | E0056 | non-negotiable | false | 10 |
| R01378 | Each module respects SDD-004 threat model (per-module commit safety) | SDD-004 | E0056 | non-negotiable | false | 10 |
| R01379 | Each module supports SDD-029 round-ledger doctrine | SDD-029 | E0056 | non-negotiable | false | 10 |
| R01380 | Operator can hot-reload module config without daemon restart | `crates/selfdef-config` | E0056 | non-negotiable | true | 10 |
| R01381 | Operator can selectively re-apply a single module via `selfdefctl modules apply --only <name>` | `crates/selfdef-cli` | E0056 | non-negotiable | true | 10 |
| R01382 | Operator can preview a single module's actions via `selfdefctl modules apply --only <name> --dry-run` | `crates/selfdef-cli` | E0056 | non-negotiable | true | 10 |
| R01383 | Operator can uninstall a single module via `selfdefctl modules uninstall <name>` | `crates/selfdef-cli` | F00692 | non-negotiable | true | 10 |
| R01384 | Operator can request module status via `selfdefctl modules status <name>` | `crates/selfdef-cli` | F00621 | non-negotiable | true | 10 |
| R01385 | agent-guard runtime — operator can toggle each of 4 policies between audit / enforce independently | `crates/selfdef-config` | M00137 + M00138 | non-negotiable | true | 10 |
| R01386 | agent-guard runtime — emits per-policy Prometheus metric `selfdef_agent_guard_violations_total{policy,action}` | `modules/agent-guard` | M00133 | non-negotiable | true | 10 |
| R01387 | bitnet-gpu-inference runtime — emits per-GPU schedule-hint metric | `modules/bitnet-gpu-inference` | M00140 | non-negotiable | true | 10 |
| R01388 | bridge-l2 runtime — emits FORWARD-chain rule-fire-count metric | `modules/bridge-l2` | M00141 | non-negotiable | true | 10 |
| R01389 | detect-host runtime — verifies all 7 selfdef-daemon subprocess slots are up | `modules/detect-host` | M00143 | non-negotiable | false | 10 |
| R01390 | hardware-tune-cache runtime — emits env-file write timestamp metric | `modules/hardware-tune-cache` | M00144 | non-negotiable | true | 10 |
| R01391 | integrity-sentinel runtime — emits drift-detection-event-count metric `selfdef_integrity_drift_total{kind}` | `modules/integrity-sentinel` | M00146 | non-negotiable | true | 10 |
| R01392 | observability runtime — emits Prometheus scrape-target-up gauge | `modules/observability` | M00147 | non-negotiable | true | 10 |
| R01393 | polarproxy runtime — emits TLS-flow-count + PCAP-bytes-emitted metric | `modules/polarproxy` | M00150 | non-negotiable | true | 10 |
| R01394 | slm-cpu-loop runtime — emits agent-tick-rate metric | `modules/slm-cpu-loop` | M00151 | non-negotiable | true | 10 |
| R01395 | suricata runtime — emits alert-rate metric (per SID + severity) | `modules/suricata` | M00153 | non-negotiable | true | 10 |
| R01396 | tensor-parallel-inference runtime — emits per-GPU slice-utilization metric | `modules/tensor-parallel-inference` | M00155 | non-negotiable | true | 10 |
| R01397 | tetragon runtime — emits TracingPolicy-loaded-count metric | `modules/tetragon` | M00156 | non-negotiable | true | 10 |
| R01398 | vpn-bridge runtime — emits per-tunnel-uptime + per-tunnel-rx/tx-bytes metric | `modules/vpn-bridge` | M00158 | non-negotiable | true | 10 |
| R01399 | wasm-aot-cache runtime — emits cache-hit + cache-miss + cache-evict-count metric | `modules/wasm-aot-cache` | M00160 | non-negotiable | true | 10 |
| R01400 | Anti-pattern — modules apply NEVER mutates state without operator triple-gate (`--apply` flag) | `crates/selfdef-cli` | E0056 | non-negotiable | false | 10 |
| R01401 | Anti-pattern — modules apply NEVER ships state that bypasses integrity-sentinel baseline | `modules/integrity-sentinel` | M00146 | non-negotiable | false | 10 |
| R01402 | Anti-pattern — modules apply NEVER installs systemd unit without ProtectSystem=strict | `packaging/systemd/` | E0056 | non-negotiable | false | 10 |
| R01403 | Anti-pattern — modules apply NEVER installs systemd unit without NoNewPrivileges=true | `packaging/systemd/` | E0056 | non-negotiable | false | 10 |
| R01404 | Anti-pattern — modules apply NEVER opens listening port without operator-discoverable port declaration | per-module module.toml | E0056 | non-negotiable | false | 10 |
| R01405 | Anti-pattern — modules apply NEVER mutates `/etc/` outside `/etc/selfdef/` without operator triple-gate | `crates/selfdef-cli` | E0056 | non-negotiable | false | 10 |
| R01406 | Anti-pattern — agent-guard policy NEVER auto-enforces without operator opt-in | `modules/agent-guard` | M00137 | non-negotiable | false | 10 |
| R01407 | Anti-pattern — bridge-l2 NEVER installs br0 without operator opt-in (`default = false`) | `modules/bridge-l2` | R01355 | non-negotiable | false | 10 |
| R01408 | Anti-pattern — suricata NEVER drops traffic without operator opt-in | `modules/suricata` | E0066 | non-negotiable | false | 10 |
| R01409 | Anti-pattern — polarproxy NEVER terminates TLS without operator opt-in + CA installed | `modules/polarproxy` | M00149 | non-negotiable | false | 10 |
| R01410 | Anti-pattern — integrity-sentinel NEVER auto-rebaselines (operator triple-gate required) | `modules/integrity-sentinel` | F00652 | non-negotiable | false | 10 |
| R01411 | Anti-pattern — vpn-bridge NEVER auto-connects to peer without operator-supplied config | `modules/vpn-bridge` | R01285 | non-negotiable | false | 10 |
| R01412 | Documentation — top-level README.md lists all 14 modules with one-line description + category | `README.md` | E0056 | non-negotiable | true | 10 |
| R01413 | Documentation — every module has README.md describing scope + dependencies + env vars + apply/check/uninstall behaviors | per-module README.md | F00688 | non-negotiable | true | 10 |
| R01414 | Documentation — module dependency graph documented at top-level docs/ | `docs/` | F00625 | non-negotiable | true | 10 |
| R01415 | Documentation — module-author guide at `docs/contributing/module-author-guide.md` (how to add a 15th module) | `docs/` | E0056 | non-negotiable | true | 10 |
| R01416 | Documentation — operator-facing quickstart at top-level README.md shows day-0 (`init` → `apply`) flow | `README.md` | E0056 | non-negotiable | false | 10 |
| R01417 | Modules apply respects `selfdefctl init modules` ordering (idempotent first-run) | `crates/selfdef-cli` | E0056 | non-negotiable | false | 10 |
| R01418 | Modules apply rolling-upgrade support — operator can upgrade one module at a time | `crates/selfdef-cli` | E0056 | preferable | true | 10 |
| R01419 | Modules apply rollback works across all 14 modules (operator can rollback to previous module-state) | `crates/selfdef-cli` | F00685 | non-negotiable | true | 10 |
| R01420 | Operator can pin a module's version via `modules.toml [<module>] version = "<X.Y.Z>"` | `crates/selfdef-config` | E0056 | preferable | true | 10 |
| R01421 | Operator can disable a module's default policies while keeping module enabled (per-policy toggle) | `crates/selfdef-config` | M00137 | preferable | true | 10 |
| R01422 | Operator can override any module's default env-file path | `crates/selfdef-config` | E0056 | non-negotiable | true | 10 |
| R01423 | Operator can scope a module to specific hosts via host-filter expressions in modules.toml | `crates/selfdef-config` | E0056 | preferable | true | 10 |
| R01424 | Operator can scope a module to specific containers via container-filter expressions | `crates/selfdef-config` | M00139 | preferable | true | 10 |
| R01425 | Operator can compose modules into bundles (e.g. `bundle.security = [agent-guard, integrity-sentinel, tetragon]`) | `crates/selfdef-config` | E0056 | preferable | true | 10 |
| R01426 | Bundle apply respects per-bundle dependency ordering | `crates/selfdef-cli` | R01425 | preferable | true | 10 |
| R01427 | Modules support hot-reload — config-only changes do not require daemon restart | `crates/selfdef-config` | E0056 | preferable | true | 10 |
| R01428 | Modules support warm-reload — daemon restart preserves module-installed system state | `crates/selfdef-cli` | E0056 | non-negotiable | false | 10 |
| R01429 | Modules support cold-reload — full uninstall + reinstall reproduces system state | `crates/selfdef-cli` | E0056 | non-negotiable | false | 10 |
| R01430 | Operator can audit module-applied changes via `selfdefctl modules audit --since <ts>` | `crates/selfdef-cli` | F00687 | non-negotiable | true | 10 |
| R01431 | Operator can export module config via `selfdefctl modules export > modules-backup.toml` | `crates/selfdef-cli` | E0056 | preferable | true | 10 |
| R01432 | Operator can import module config via `selfdefctl modules import modules-backup.toml` | `crates/selfdef-cli` | E0056 | preferable | true | 10 |
| R01433 | Operator can diff current vs imported config via `selfdefctl modules diff <path>` | `crates/selfdef-cli` | F00620 | preferable | true | 10 |
| R01434 | Composite — 14 functional modules implement the IPS substrate that the MS001 daemon orchestrates | this milestone | E0056 | non-negotiable | false | 10 |
| R01435 | Composite — Each module's events flow through the MS002 collector fabric | MS002 | E0056 | non-negotiable | false | 10 |
| R01436 | Composite — Each module's verdicts flow through the MS003 correlator + responder + signing pipeline | MS003 | E0056 | non-negotiable | false | 10 |
| R01437 | Composite — Each module's notifications flow through the MS004 14 channel adapters | MS004 | E0056 | non-negotiable | false | 10 |
| R01438 | Composite — Each module's notifications are routed by the MS005 notifier engine + orchestrator | MS005 | E0056 | non-negotiable | false | 10 |
| R01439 | Composite — Each module's apply audit trail lives in MS003 selfdef-store actions table | MS003 | F00687 | non-negotiable | false | 10 |
| R01440 | Composite — End of 14-module functional catalog; remaining 36 selfdef milestones cover SDD-charter / SSH-wrap / NATS / eBPF / agent-guard internals / VPN-bridge / threat-model / test-contract / shared-module-script-lib / SSE quota / polarproxy internals / bridge-l2 internals / detect-host internals / integrity-sentinel internals / observability internals / 4 inference-module internals / sandbox-tiers / policy-and-trace / communication / capability-tokens / tool-sandboxes / filesystem / network / authority / commit / tool boundaries | INDEX.md | E0056 | non-negotiable | false | 10 |

— End of MS006 milestone file.
