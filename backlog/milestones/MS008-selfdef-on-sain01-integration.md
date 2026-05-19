# MS008 — selfdef-on-SAIN-01 integration

> Parent: `backlog/milestones/INDEX.md` row MS008.
> Source: `docs/sdd/010-selfdef-on-sain01.md` (scoping stub) + `docs/sdd/012-selfdef-on-sain01-integration-design.md` (design closing SDD-010 Q-A..Q-H) + `docs/sdd/017-sain01-hardware-inventory.md` (hardware inventory awareness) + `crates/selfdef-hardware` + info-hub SAIN-01 milestone (cyberpunk042/devops-solutions-information-hub PRs #2-#6, 11 epics covering SAIN-01 hardware spec).

## Epics (E0081–E0090)

| Epic ID | Phrase | Source |
|---|---|---|
| E0081 | SDD-010 SAIN-01 deployment integration — requirements + scope (scoping stub) | SDD-010 |
| E0082 | SDD-012 SAIN-01 integration design — closes SDD-010 Q-A..Q-H (proposes concrete resolutions) | SDD-012 |
| E0083 | SDD-017 SAIN-01 hardware-inventory awareness — discover hardware at startup; surface via `selfdefctl hardware` | SDD-017 + `crates/selfdef-hardware` |
| E0084 | SAIN-01 hardware spec — AVX-512 (Ryzen 9 9900X / Zen 5) + RTX PRO 6000 Blackwell (96GB) + RTX 3090 (24GB) + 256GB DDR5 + dual NVMe + dual NIC + ProArt X870E-Creator WIFI | info-hub SAIN-01 + SDD-012 + SDD-017 |
| E0085 | SAIN-01 procurement gates — hardware on order + Oracle Core model selection (Ling-2.6-flash / Nemotron-3-Nano-Omni) + operator authorization | SDD-010 + info-hub E110 |
| E0086 | Hardware-aware policy authoring — agent-guard policies assert on GPU device nodes / memory bandwidth / AVX-512 capability with operator-discoverable validation | SDD-017 + `modules/agent-guard` |
| E0087 | SAIN-01 deployment profile — selfdef on SAIN-01 specific tunings (workload-mode-aware caches / thermal-aware AVX-512 dispatch / dual-GPU sandbox split) | SDD-012 + sovereign-os profiles/sain-01.yaml |
| E0088 | SAIN-01 cross-repo binding — selfdef-on-sain01 consumes sovereign-os runtime per typed-mirror cross-repo doctrine (MS007) | MS007 + SDD-038 |
| E0089 | SAIN-01 Trinity inference stack integration — selfdef-collector-eventstream re-ingests sovereign-os runtime trace; selfdef-responder rolls back via ZFS snapshots | SDD-012 + sovereign-os Trinity (Pulse / Logic / Oracle Core) |
| E0090 | SAIN-01 master-spec coverage — `cyberpunk042/devops-solutions-information-hub` SAIN-01 milestone (11 epics, ~440KB) covers full master-spec catalog | info-hub SAIN-01 milestone |

## Modules (M00187–M00212)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00187 | SDD-010 scope axis 1 — hardware-aware module configuration (auto-detect GPUs / RAM / NIC capabilities) | SDD-010 | E0081 |
| M00188 | SDD-010 scope axis 2 — Trinity inference stack integration (Pulse=AVX-512 CPU; Logic Engine=3090; Oracle Core=Blackwell) | SDD-010 | E0081 |
| M00189 | SDD-010 scope axis 3 — selfdef-responder ZFS snapshot integration | SDD-010 | E0081 |
| M00190 | SDD-010 scope axis 4 — selfdef-collector-suricata + bridge-l2 transparent inspection on dual-NIC | SDD-010 | E0081 |
| M00191 | SDD-010 scope axis 5 — agent-guard host-level invariants for sovereign-os inference daemons | SDD-010 | E0081 |
| M00192 | SDD-010 scope axis 6 — Trinity-tier model serving guardrails (per-tier capability tokens) | SDD-010 | E0081 |
| M00193 | SDD-010 scope axis 7 — operator-discoverable `selfdefctl sain01` health/posture verb | SDD-010 | E0081 |
| M00194 | SDD-010 scope axis 8 — selfdef-on-sain01 deployment template + Ansible playbook | SDD-010 | E0081 |
| M00195 | SDD-012 Q-A resolution — deployment target type (sain-01 declarative profile in `selfdef-config`) | SDD-012 Q-A | E0082 |
| M00196 | SDD-012 Q-B resolution — Trinity inference stack discovery (sovereign-osctl trinity status JSON consumed by selfdef-collector-eventstream) | SDD-012 Q-B | E0082 |
| M00197 | SDD-012 Q-C resolution — Pulse-Engine integration (AVX-512 CPU compute monitored via DCGM-equivalent metrics) | SDD-012 Q-C | E0082 |
| M00198 | SDD-012 Q-D resolution — Logic-Engine integration (3090 VFIO sandbox boundary enforced by agent-guard) | SDD-012 Q-D | E0082 |
| M00199 | SDD-012 Q-E resolution — Oracle Core integration (Blackwell oracle traces via selfdef-collector-eventstream re-ingest) | SDD-012 Q-E | E0082 |
| M00200 | SDD-012 Q-F resolution — workload-mode coordination (selfdef accepts sovereign-osctl workload-mode set; respects ZFS-snapshot freeze during oc-burst) | SDD-012 Q-F | E0082 |
| M00201 | SDD-012 Q-G resolution — operator-pull dashboard surfaces (selfdef dashboard tiles for sovereign-os trinity state) | SDD-012 Q-G | E0082 |
| M00202 | SDD-012 Q-H resolution — image bundle (selfdef ships on the same mkosi-on-Debian-13 image as sovereign-os, opt-in via `selfdef` profile flag) | SDD-012 Q-H | E0082 |
| M00203 | SDD-017 hardware inventory — `selfdef-hardware` crate (auto-detect at startup) | `crates/selfdef-hardware` | E0083 |
| M00204 | SDD-017 inventory — GPU device-node discovery (/dev/nvidia0=PRO 6000; /dev/nvidia1=3090) | `crates/selfdef-hardware` | E0083 |
| M00205 | SDD-017 inventory — CPU AVX-512 capability detection (CPUID + ZenVer parsing) | `crates/selfdef-hardware` | E0083 |
| M00206 | SDD-017 inventory — Memory bandwidth probe (DDR5 6400 measurement) | `crates/selfdef-hardware` | E0083 |
| M00207 | SDD-017 inventory — NVMe layout discovery (dual-NVMe ZFS stripe vs mirror) | `crates/selfdef-hardware` | E0083 |
| M00208 | SDD-017 inventory — NIC discovery (dual-NIC bridge candidates) | `crates/selfdef-hardware` | E0083 |
| M00209 | SDD-017 inventory — Motherboard fingerprint (ProArt X870E-Creator WIFI BIOS recipe) | `crates/selfdef-hardware` | E0083 |
| M00210 | Hardware-aware policy schema — agent-guard policy asserts on inventory facts (`gpu_device == /dev/nvidia1 → 3090-sandbox-policy`) | SDD-017 + `modules/agent-guard` | E0086 |
| M00211 | Hardware-aware policy validation — operator-readable error when inventory doesn't match policy assertion | SDD-017 | E0086 |
| M00212 | SAIN-01 master-spec inventory — info-hub `cyberpunk042/devops-solutions-information-hub` SAIN-01 milestone 11 epics (~440KB) is the canonical hardware-spec source | info-hub SAIN-01 milestone | E0090 |

## Features (F00841–F00960)

| F ID | Phrase | Source | Parent module | Category | Opt-in |
|---|---|---|---|---|---|
| F00841 | SAIN-01 procurement gate — hardware on order (operator-side trigger) | SDD-010 | E0085 | composite | true |
| F00842 | SAIN-01 procurement gate — Oracle Core model selection (Ling-2.6-flash / Nemotron-3-Nano-Omni / both) | SDD-010 + info-hub E110 | E0085 | composite | true |
| F00843 | SAIN-01 procurement gate — operator authorization to commit selfdef impl effort | SDD-010 | E0085 | composite | true |
| F00844 | SDD-010 design-deferred posture — no impl effort spent before integration design lands | SDD-010 | E0081 | composite | false |
| F00845 | SDD-010 scope axis — hardware-aware module config | SDD-010 | M00187 | composite | true |
| F00846 | SDD-010 scope axis — Trinity inference stack integration | SDD-010 | M00188 | composite | true |
| F00847 | SDD-010 scope axis — ZFS snapshot responder integration | SDD-010 | M00189 | composite | true |
| F00848 | SDD-010 scope axis — dual-NIC bridge-l2 transparent inspection | SDD-010 | M00190 | composite | true |
| F00849 | SDD-010 scope axis — agent-guard for sovereign-os inference daemons | SDD-010 | M00191 | composite | true |
| F00850 | SDD-010 scope axis — Trinity-tier model serving guardrails | SDD-010 | M00192 | composite | true |
| F00851 | SDD-010 scope axis — `selfdefctl sain01` health/posture verb | SDD-010 | M00193 | cli_verb | true |
| F00852 | SDD-010 scope axis — deployment template + Ansible playbook | SDD-010 | M00194 | composite | true |
| F00853 | SDD-012 design resolution Q-A — deployment.target = sain-01 declarative profile | SDD-012 | M00195 | composite | true |
| F00854 | SDD-012 design resolution Q-B — Trinity stack discovery via sovereign-osctl trinity status JSON | SDD-012 | M00196 | composite | true |
| F00855 | SDD-012 design resolution Q-C — Pulse-Engine AVX-512 monitoring | SDD-012 | M00197 | composite | true |
| F00856 | SDD-012 design resolution Q-D — Logic-Engine 3090 VFIO boundary enforced by agent-guard | SDD-012 | M00198 | composite | true |
| F00857 | SDD-012 design resolution Q-E — Oracle Core Blackwell trace re-ingest via selfdef-collector-eventstream | SDD-012 | M00199 | composite | true |
| F00858 | SDD-012 design resolution Q-F — workload-mode coordination + oc-burst ZFS-snapshot freeze | SDD-012 | M00200 | composite | true |
| F00859 | SDD-012 design resolution Q-G — operator-pull dashboard surfaces for Trinity state | SDD-012 | M00201 | composite | true |
| F00860 | SDD-012 design resolution Q-H — image bundle on same mkosi-Debian-13 image as sovereign-os | SDD-012 | M00202 | composite | true |
| F00861 | SDD-017 — `selfdef-hardware` crate auto-detects hardware at daemon startup | SDD-017 | M00203 | composite | false |
| F00862 | SDD-017 GPU inventory — `/dev/nvidia0` = RTX PRO 6000 Blackwell (96GB) | SDD-017 | M00204 | composite | true |
| F00863 | SDD-017 GPU inventory — `/dev/nvidia1` = RTX 3090 (24GB) | SDD-017 | M00204 | composite | true |
| F00864 | SDD-017 CPU inventory — AVX-512 capability flags (CPUID parse) | SDD-017 | M00205 | composite | false |
| F00865 | SDD-017 CPU inventory — Ryzen 9 9900X / Zen 5 detection | SDD-017 | M00205 | composite | true |
| F00866 | SDD-017 memory inventory — DDR5 6400 MT/s probe | SDD-017 | M00206 | composite | true |
| F00867 | SDD-017 memory inventory — 256GB total RAM detection | SDD-017 | M00206 | composite | true |
| F00868 | SDD-017 NVMe inventory — dual-NVMe layout (ZFS stripe vs mirror) | SDD-017 | M00207 | composite | true |
| F00869 | SDD-017 NIC inventory — dual-NIC discovery | SDD-017 | M00208 | composite | true |
| F00870 | SDD-017 motherboard inventory — ProArt X870E-Creator WIFI BIOS recipe | SDD-017 | M00209 | composite | true |
| F00871 | `selfdefctl hardware show` — operator-discoverable inventory display | `crates/selfdef-cli` | M00203 | cli_verb | true |
| F00872 | `selfdefctl hardware diff` — compares discovered vs operator-declared expected | `crates/selfdef-cli` | M00203 | cli_verb | true |
| F00873 | `selfdefctl hardware export --format json` — JSON export of inventory | `crates/selfdef-cli` | M00203 | cli_verb | true |
| F00874 | API `GET /v1/hardware/inventory` — JSON hardware-inventory endpoint | `crates/selfdef-api` | M00203 | api_endpoint | true |
| F00875 | API `GET /v1/hardware/sain01-status` — SAIN-01-specific posture check | `crates/selfdef-api` | M00193 | api_endpoint | true |
| F00876 | `selfdefctl sain01 status` — SAIN-01 posture verb (Trinity stack health + hardware match + policy posture) | `crates/selfdef-cli` | M00193 | cli_verb | true |
| F00877 | `selfdefctl sain01 verify` — SAIN-01 master-spec compliance check | `crates/selfdef-cli` | M00193 | cli_verb | true |
| F00878 | `selfdefctl sain01 deploy --dry-run` — preview SAIN-01 deployment | `crates/selfdef-cli` | M00194 | cli_verb | true |
| F00879 | Hardware-aware policy assertion — `gpu_device == /dev/nvidia1 → 3090-sandbox-policy` | SDD-017 | M00210 | composite | true |
| F00880 | Hardware-aware policy assertion — `cpu_avx512_zen5 → AVX-512 batch policy` | SDD-017 | M00210 | composite | true |
| F00881 | Hardware-aware policy assertion — `ram_gb >= 256 → high-RAM workload policy` | SDD-017 | M00210 | composite | true |
| F00882 | Hardware-aware policy assertion — `nic_count >= 2 → bridge-l2-eligible` | SDD-017 | M00210 | composite | true |
| F00883 | Hardware-aware policy validation — operator-readable error when inventory mismatch | SDD-017 | M00211 | composite | false |
| F00884 | Hardware-aware policy graceful-no-op when inventory lacks asserted capability | SDD-017 | M00211 | composite | true |
| F00885 | Trinity stack integration — Pulse-Engine (AVX-512 CPU compute) selfdef-eventstream re-ingest | SDD-012 | E0089 | composite | true |
| F00886 | Trinity stack integration — Logic Engine (3090) selfdef-eventstream re-ingest | SDD-012 | E0089 | composite | true |
| F00887 | Trinity stack integration — Oracle Core (Blackwell) selfdef-eventstream re-ingest | SDD-012 | E0089 | composite | true |
| F00888 | Trinity stack rollback — selfdef-responder triggers ZFS snapshot rollback when Trinity verdict reaches `Malicious` | SDD-012 + MS003 | E0089 | composite | true |
| F00889 | Dashboard — SAIN-01 hardware-inventory tile (live discovered hardware) | `dashboard/` | M00203 | dashboard | true |
| F00890 | Dashboard — SAIN-01 Trinity stack overview (Pulse + Logic + Oracle live state) | `dashboard/` | E0089 | dashboard | true |
| F00891 | Dashboard — SAIN-01 master-spec compliance status (green/yellow/red per axis) | `dashboard/` | E0084 | dashboard | true |
| F00892 | Dashboard — `selfdefctl sain01 verify` results visualizer | `dashboard/` | M00193 | dashboard | true |
| F00893 | Workload-mode coordination — selfdef accepts sovereign-osctl `workload-mode set <mode>` | SDD-012 Q-F | M00200 | composite | true |
| F00894 | Workload-mode coordination — selfdef respects ZFS snapshot freeze during `oc-burst` mode | SDD-012 Q-F | M00200 | composite | true |
| F00895 | Workload-mode coordination — selfdef adjusts collector rate-limit per workload mode | SDD-012 Q-F | M00200 | composite | true |
| F00896 | SAIN-01 deployment Ansible playbook — `ansible/sain01/site.yml` | `ansible/sain01/` | M00194 | composite | true |
| F00897 | SAIN-01 deployment systemd unit — `selfdefd@sain01.service` template | `packaging/systemd/` | M00194 | composite | true |
| F00898 | SAIN-01 deployment AppArmor profile — `selfdefd-sain01` (stricter than default) | `packaging/apparmor/` | M00194 | composite | true |
| F00899 | SAIN-01 deployment cgroup v2 slice — `selfdef-sain01.slice` (operator-tunable resource caps) | `packaging/systemd/` | M00194 | composite | true |
| F00900 | SAIN-01 deployment ZFS dataset — `tank/selfdef-sain01` (snapshots before responder actions) | SDD-012 + MS003 | E0089 | composite | true |
| F00901 | Cross-repo binding — selfdef-on-sain01 consumes sovereign-os runtime via typed-mirror crates only (MS007) | MS007 + SDD-038 | E0088 | composite | false |
| F00902 | Cross-repo binding — NO direct sovereign-os crate import from selfdef-on-sain01 | architecture | E0088 | composite | false |
| F00903 | Cross-repo binding — Oracle-Triage integration (MS004 E0036) is the only runtime bridge | MS004 E0036 + SDD-038 | E0088 | composite | false |
| F00904 | Cross-repo binding — selfdef-collector-eventstream re-ingests sovereign-os runtime via documented HTTP/JSON contract | SDD-012 + SDD-038 | E0088 | composite | true |
| F00905 | info-hub SAIN-01 milestone — `cyberpunk042/devops-solutions-information-hub` PRs #2-#6 (11 epics, ~440KB) | info-hub | E0090 | composite | false |
| F00906 | info-hub SAIN-01 milestone — operator-source-of-truth for master-spec | info-hub | E0090 | composite | false |
| F00907 | SAIN-01 master-spec — Ryzen 9 9900X CPU | info-hub SAIN-01 + SDD-017 | M00205 | composite | false |
| F00908 | SAIN-01 master-spec — Zen 5 architecture | info-hub SAIN-01 | M00205 | composite | false |
| F00909 | SAIN-01 master-spec — RTX PRO 6000 Blackwell (96GB) | info-hub SAIN-01 | M00204 | composite | false |
| F00910 | SAIN-01 master-spec — RTX 3090 (24GB) | info-hub SAIN-01 | M00204 | composite | false |
| F00911 | SAIN-01 master-spec — 256GB DDR5 6400 CL42 RAM (2× CMK128GX5M2B6400C42 kits) | info-hub SAIN-01 + SDD-017 | M00206 | composite | false |
| F00912 | SAIN-01 master-spec — 2× Samsung 990 EVO Plus 2TB Gen4 x4 / Gen5 x2 NVMe | info-hub SAIN-01 + SDD-017 | M00207 | composite | false |
| F00913 | SAIN-01 master-spec — ASUS ProArt X870E-Creator WIFI motherboard | info-hub SAIN-01 + SDD-017 | M00209 | composite | false |
| F00914 | SAIN-01 master-spec — be Quiet! Dark Power Pro 13 1600W PSU (ATX 3.1 Titanium with OC-mode switch) | info-hub SAIN-01 | E0084 | composite | true |
| F00915 | SAIN-01 master-spec — SMT2200C UPS (2200VA/1980W) | info-hub SAIN-01 | E0084 | composite | true |
| F00916 | SAIN-01 master-spec — Intel i226-V dual-NIC | info-hub SAIN-01 + SDD-017 | M00208 | composite | true |
| F00917 | SAIN-01 master-spec compliance check — operator-discoverable per-component verify | `crates/selfdef-cli` | F00877 | composite | true |
| F00918 | SAIN-01 master-spec compliance — operator-readable diff when hardware differs from declared spec | `crates/selfdef-cli` | F00877 | composite | true |
| F00919 | SAIN-01 master-spec compliance — operator-readable warning when running on non-SAIN-01 hardware | `crates/selfdef-cli` | F00877 | composite | true |
| F00920 | Metric `selfdef_hardware_inventory_discovered_total{component}` | `crates/selfdef-hardware` | M00203 | observability_metric | true |
| F00921 | Metric `selfdef_sain01_compliance_status{component,status}` | `crates/selfdef-cli` | F00877 | observability_metric | true |
| F00922 | Metric `selfdef_trinity_eventstream_ingest_total{tier,outcome}` | `crates/selfdef-collector-eventstream` | E0089 | observability_metric | true |
| F00923 | Test — `selfdef-hardware` crate discovers GPU device nodes on stock SAIN-01 hardware | tests/ | M00203 | test | false |
| F00924 | Test — `selfdef-hardware` crate detects AVX-512 capability flags correctly | tests/ | M00205 | test | false |
| F00925 | Test — `selfdef-hardware` crate detects DDR5 memory bandwidth | tests/ | M00206 | test | false |
| F00926 | Test — Hardware-aware policy refuses assertion that doesn't match inventory | tests/ | M00210 | test | false |
| F00927 | Test — Hardware-aware policy graceful-no-op when inventory lacks asserted capability | tests/ | M00211 | test | false |
| F00928 | Test — Trinity-stack eventstream re-ingest end-to-end on synthetic sovereign-os runtime | tests/ | E0089 | test | false |
| F00929 | Test — SAIN-01 master-spec compliance verifier produces operator-readable report | tests/ | F00917 | test | false |
| F00930 | Test — `selfdefctl sain01 deploy --dry-run` previews Ansible playbook + systemd + AppArmor + ZFS dataset | tests/ | F00878 | test | false |
| F00931 | UX — `selfdefctl sain01 status` output ≤ 1 screen on green case | `crates/selfdef-cli` | F00876 | preferable | true |
| F00932 | UX — `selfdefctl sain01 status` groups SAIN-01 axes (hardware / Trinity / policies / responder) | `crates/selfdef-cli` | F00876 | non-negotiable | true |
| F00933 | UX — operator-discoverable next-step on each SAIN-01 compliance failure | `crates/selfdef-cli` | F00877 | non-negotiable | true |
| F00934 | UX — `selfdefctl --json` output available for every sain01 verb | `crates/selfdef-cli` | M00193 | non-negotiable | true |
| F00935 | UX — Dashboard SAIN-01 master-spec compliance tile shows per-axis green/yellow/red | `dashboard/` | F00891 | non-negotiable | true |
| F00936 | UX — Dashboard SAIN-01 hardware-inventory tile shows live discovered hardware | `dashboard/` | F00889 | non-negotiable | true |
| F00937 | UX — Dashboard SAIN-01 Trinity stack tile shows live Pulse + Logic + Oracle state | `dashboard/` | F00890 | non-negotiable | true |
| F00938 | UX — Dashboard SAIN-01 verify-results tile shows operator-readable verification report | `dashboard/` | F00892 | non-negotiable | true |
| F00939 | SAIN-01 deployment SDD references — `docs/sdd/010-selfdef-on-sain01.md` (scoping stub) | docs/sdd/ | E0081 | composite | false |
| F00940 | SAIN-01 deployment SDD references — `docs/sdd/012-selfdef-on-sain01-integration-design.md` (closes Q-A..Q-H) | docs/sdd/ | E0082 | composite | false |
| F00941 | SAIN-01 deployment SDD references — `docs/sdd/017-sain01-hardware-inventory.md` (hardware inventory awareness) | docs/sdd/ | E0083 | composite | false |
| F00942 | SAIN-01 deployment SDD references — `docs/sdd/013-deployment-target-config.md` (deployment.target sain-01 declarative profile) | docs/sdd/ | M00195 | composite | true |
| F00943 | SAIN-01 deployment SDD references — `docs/sdd/015-perimeter-coexistence.md` (perimeter scope inside SAIN-01 host) | docs/sdd/ | M00190 | composite | true |
| F00944 | SAIN-01 deployment SDD references — `docs/sdd/018-hardware-aware-modules-and-tune-surface.md` (hardware-aware modules + tune surface) | docs/sdd/ | E0086 | composite | true |
| F00945 | SAIN-01 deployment SDD references — `docs/sdd/022-hardware-exploit-doctrine.md` (hardware-exploit-to-the-max research loop) | docs/sdd/ | E0086 | composite | true |
| F00946 | SAIN-01 deployment SDD references — `docs/sdd/023-cross-repo-model-taxonomy-mirror.md` (model taxonomy mirror via cross-repo binding) | docs/sdd/ + MS007 | E0088 | composite | true |
| F00947 | SAIN-01 deployment SDD references — `docs/sdd/026-operator-dashboard-and-flex-profile.md` (operator dashboard + flex profile per SAIN-01) | docs/sdd/ | F00889 | composite | true |
| F00948 | SAIN-01 cycle-vector tracking — `docs/sdd/019-cycle3-forward-looking-spec.md` (cycle 3 vectors) | docs/sdd/ | E0090 | composite | true |
| F00949 | SAIN-01 cycle-vector tracking — `docs/sdd/020-cycle3-vectors.md` | docs/sdd/ | E0090 | composite | true |
| F00950 | SAIN-01 cycle-vector tracking — `docs/sdd/021-cycle4-vectors.md` | docs/sdd/ | E0090 | composite | true |
| F00951 | SAIN-01 cycle-vector tracking — `docs/sdd/024-cycle5-vectors.md` | docs/sdd/ | E0090 | composite | true |
| F00952 | SAIN-01 cycle-vector tracking — `docs/sdd/025-cycle6-vectors.md` | docs/sdd/ | E0090 | composite | true |
| F00953 | Profile knob — `deployment.target = sain-01 \| default \| custom` | `crates/selfdef-config` | M00195 | profile | true |
| F00954 | Env var `SELFDEF_DEPLOYMENT_TARGET` | `crates/selfdef-config` | M00195 | env_var | true |
| F00955 | CLI `--deployment-target <name>` | `crates/selfdef-cli` | M00195 | cli_verb | true |
| F00956 | Composite — SAIN-01 deployment-target profile activates: hardware-aware modules + Trinity eventstream + workload-mode coordination + responder ZFS snapshots + dashboard tiles | this milestone | E0087 | composite | true |
| F00957 | Composite — selfdef-on-sain01 NEVER imports sovereign-os crate code directly (cross-repo only via MS007 typed mirrors) | architecture | E0088 | composite | false |
| F00958 | Composite — Oracle-Triage integration (MS004 E0036) is the only runtime cross-repo bridge | MS004 E0036 | E0088 | composite | false |
| F00959 | Composite — SAIN-01 deployment integrates with MS001 daemon + MS002 collectors + MS003 correlator+responder+signing + MS004 14 integrations + MS005 notifier engine+orchestrator + MS006 14 functional modules + MS007 8/8 typed mirrors | MS001-MS007 | E0087 | composite | false |
| F00960 | Composite — selfdef-on-sain01 is the canonical deployment target for the operator's primary AI workstation | this milestone | E0084 | composite | false |

## Requirements (R01681–R01920)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R01681 | SDD-010 captures selfdef-on-SAIN-01 deployment integration requirements + scope (scoping stub) | SDD-010 | E0081 | non-negotiable | false | 10 |
| R01682 | SDD-010 design + impl deferred to separate design conversation, gated on 3 triggers | SDD-010 | E0085 | non-negotiable | false | 10 |
| R01683 | SDD-010 trigger 1 — SAIN-01 hardware procurement progressing (operator-side decision) | SDD-010 | F00841 | non-negotiable | true | 10 |
| R01684 | SDD-010 trigger 2 — Oracle Core model selection (Ling-2.6-flash / Nemotron-3-Nano-Omni / both — info-hub E110) | SDD-010 + info-hub E110 | F00842 | non-negotiable | true | 10 |
| R01685 | SDD-010 trigger 3 — operator authorization to commit selfdef impl effort | SDD-010 | F00843 | non-negotiable | true | 10 |
| R01686 | SDD-010 intentionally does NOT pick implementation choices | SDD-010 | F00844 | non-negotiable | false | 10 |
| R01687 | SDD-010 captures integration scope-of-required-coverage for stable requirements baseline | SDD-010 | E0081 | non-negotiable | false | 10 |
| R01688 | SDD-010 scope axis 1 — hardware-aware module configuration | SDD-010 | M00187 | non-negotiable | true | 10 |
| R01689 | SDD-010 scope axis 2 — Trinity inference stack integration | SDD-010 | M00188 | non-negotiable | true | 10 |
| R01690 | SDD-010 scope axis 3 — selfdef-responder ZFS snapshot integration | SDD-010 | M00189 | non-negotiable | true | 10 |
| R01691 | SDD-010 scope axis 4 — selfdef-collector-suricata + bridge-l2 transparent inspection on dual-NIC | SDD-010 | M00190 | non-negotiable | true | 10 |
| R01692 | SDD-010 scope axis 5 — agent-guard host-level invariants for sovereign-os inference daemons | SDD-010 | M00191 | non-negotiable | true | 10 |
| R01693 | SDD-010 scope axis 6 — Trinity-tier model serving guardrails | SDD-010 | M00192 | non-negotiable | true | 10 |
| R01694 | SDD-010 scope axis 7 — operator-discoverable `selfdefctl sain01` health/posture verb | SDD-010 | M00193 | non-negotiable | true | 10 |
| R01695 | SDD-010 scope axis 8 — selfdef-on-sain01 deployment template + Ansible playbook | SDD-010 | M00194 | non-negotiable | true | 10 |
| R01696 | SDD-012 closes SDD-010 Q-A..Q-H — proposes concrete resolutions | SDD-012 | E0082 | non-negotiable | false | 10 |
| R01697 | SDD-012 resolution Q-A — deployment.target = sain-01 declarative profile in selfdef-config | SDD-012 Q-A | M00195 | non-negotiable | true | 10 |
| R01698 | SDD-012 resolution Q-B — Trinity stack discovery via sovereign-osctl trinity status JSON | SDD-012 Q-B | M00196 | non-negotiable | true | 10 |
| R01699 | SDD-012 resolution Q-C — Pulse-Engine AVX-512 CPU monitoring | SDD-012 Q-C | M00197 | non-negotiable | true | 10 |
| R01700 | SDD-012 resolution Q-D — Logic-Engine 3090 VFIO boundary enforced by agent-guard | SDD-012 Q-D | M00198 | non-negotiable | true | 10 |
| R01701 | SDD-012 resolution Q-E — Oracle Core Blackwell trace re-ingest via selfdef-collector-eventstream | SDD-012 Q-E | M00199 | non-negotiable | true | 10 |
| R01702 | SDD-012 resolution Q-F — workload-mode coordination + oc-burst ZFS-snapshot freeze | SDD-012 Q-F | M00200 | non-negotiable | true | 10 |
| R01703 | SDD-012 resolution Q-G — operator-pull dashboard surfaces for Trinity state | SDD-012 Q-G | M00201 | non-negotiable | true | 10 |
| R01704 | SDD-012 resolution Q-H — image bundle on same mkosi-Debian-13 image as sovereign-os | SDD-012 Q-H | M00202 | non-negotiable | true | 10 |
| R01705 | SDD-017 — `selfdef-hardware` crate auto-detects hardware at daemon startup | SDD-017 | M00203 | non-negotiable | false | 10 |
| R01706 | SDD-017 GPU device-node discovery — `/dev/nvidia0` = RTX PRO 6000 Blackwell | SDD-017 | F00862 | non-negotiable | true | 10 |
| R01707 | SDD-017 GPU device-node discovery — `/dev/nvidia1` = RTX 3090 | SDD-017 | F00863 | non-negotiable | true | 10 |
| R01708 | SDD-017 CPU inventory — AVX-512 capability flags via CPUID | SDD-017 | F00864 | non-negotiable | false | 10 |
| R01709 | SDD-017 CPU inventory — Ryzen 9 9900X / Zen 5 detection | SDD-017 | F00865 | non-negotiable | true | 10 |
| R01710 | SDD-017 memory inventory — DDR5 6400 MT/s probe | SDD-017 | F00866 | non-negotiable | true | 10 |
| R01711 | SDD-017 memory inventory — 256GB total RAM detection | SDD-017 | F00867 | non-negotiable | true | 10 |
| R01712 | SDD-017 NVMe inventory — dual-NVMe layout (ZFS stripe vs mirror) | SDD-017 | F00868 | non-negotiable | true | 10 |
| R01713 | SDD-017 NIC inventory — dual-NIC discovery | SDD-017 | F00869 | non-negotiable | true | 10 |
| R01714 | SDD-017 motherboard inventory — ProArt X870E-Creator WIFI BIOS recipe | SDD-017 | F00870 | non-negotiable | true | 10 |
| R01715 | `selfdefctl hardware show` operator-discoverable inventory verb | `crates/selfdef-cli` | F00871 | non-negotiable | true | 10 |
| R01716 | `selfdefctl hardware diff` compares discovered vs operator-declared expected | `crates/selfdef-cli` | F00872 | non-negotiable | true | 10 |
| R01717 | `selfdefctl hardware export --format json` JSON export of inventory | `crates/selfdef-cli` | F00873 | non-negotiable | true | 10 |
| R01718 | API `GET /v1/hardware/inventory` JSON hardware-inventory endpoint | `crates/selfdef-api` | F00874 | non-negotiable | true | 10 |
| R01719 | API `GET /v1/hardware/sain01-status` SAIN-01-specific posture check | `crates/selfdef-api` | F00875 | non-negotiable | true | 10 |
| R01720 | `selfdefctl sain01 status` SAIN-01 posture verb | `crates/selfdef-cli` | F00876 | non-negotiable | true | 10 |
| R01721 | `selfdefctl sain01 verify` SAIN-01 master-spec compliance check | `crates/selfdef-cli` | F00877 | non-negotiable | true | 10 |
| R01722 | `selfdefctl sain01 deploy --dry-run` preview SAIN-01 deployment | `crates/selfdef-cli` | F00878 | non-negotiable | true | 10 |
| R01723 | Hardware-aware policy assertion — `gpu_device == /dev/nvidia1 → 3090-sandbox-policy` | SDD-017 | F00879 | non-negotiable | true | 10 |
| R01724 | Hardware-aware policy assertion — `cpu_avx512_zen5 → AVX-512 batch policy` | SDD-017 | F00880 | non-negotiable | true | 10 |
| R01725 | Hardware-aware policy assertion — `ram_gb >= 256 → high-RAM workload policy` | SDD-017 | F00881 | non-negotiable | true | 10 |
| R01726 | Hardware-aware policy assertion — `nic_count >= 2 → bridge-l2-eligible` | SDD-017 | F00882 | non-negotiable | true | 10 |
| R01727 | Hardware-aware policy validation — operator-readable error when inventory mismatch | SDD-017 | F00883 | non-negotiable | false | 10 |
| R01728 | Hardware-aware policy graceful-no-op when inventory lacks asserted capability | SDD-017 | F00884 | non-negotiable | true | 10 |
| R01729 | Trinity Pulse-Engine selfdef-eventstream re-ingest | SDD-012 | F00885 | non-negotiable | true | 10 |
| R01730 | Trinity Logic-Engine selfdef-eventstream re-ingest | SDD-012 | F00886 | non-negotiable | true | 10 |
| R01731 | Trinity Oracle Core selfdef-eventstream re-ingest | SDD-012 | F00887 | non-negotiable | true | 10 |
| R01732 | Trinity rollback — selfdef-responder triggers ZFS snapshot rollback on `Malicious` verdict | SDD-012 + MS003 | F00888 | non-negotiable | true | 10 |
| R01733 | Workload-mode — selfdef accepts sovereign-osctl `workload-mode set <mode>` | SDD-012 Q-F | F00893 | non-negotiable | true | 10 |
| R01734 | Workload-mode — selfdef respects ZFS snapshot freeze during `oc-burst` | SDD-012 Q-F | F00894 | non-negotiable | true | 10 |
| R01735 | Workload-mode — selfdef adjusts collector rate-limit per workload mode | SDD-012 Q-F | F00895 | non-negotiable | true | 10 |
| R01736 | SAIN-01 deployment — Ansible playbook at `ansible/sain01/site.yml` | `ansible/sain01/` | F00896 | non-negotiable | true | 10 |
| R01737 | SAIN-01 deployment — systemd unit `selfdefd@sain01.service` template | `packaging/systemd/` | F00897 | non-negotiable | true | 10 |
| R01738 | SAIN-01 deployment — AppArmor profile `selfdefd-sain01` (stricter than default) | `packaging/apparmor/` | F00898 | non-negotiable | true | 10 |
| R01739 | SAIN-01 deployment — cgroup v2 slice `selfdef-sain01.slice` | `packaging/systemd/` | F00899 | non-negotiable | true | 10 |
| R01740 | SAIN-01 deployment — ZFS dataset `tank/selfdef-sain01` | SDD-012 + MS003 | F00900 | non-negotiable | true | 10 |
| R01741 | Project boundary — selfdef-on-sain01 consumes sovereign-os runtime via typed-mirror crates only (MS007) | MS007 + SDD-038 | F00901 | non-negotiable | false | 10 |
| R01742 | Project boundary — NO direct sovereign-os crate import from selfdef-on-sain01 | architecture | F00902 | non-negotiable | false | 10 |
| R01743 | Project boundary — Oracle-Triage (MS004 E0036) is the only runtime bridge | MS004 E0036 + SDD-038 | F00903 | non-negotiable | false | 10 |
| R01744 | Project boundary — selfdef-collector-eventstream re-ingests sovereign-os runtime via documented HTTP/JSON contract | SDD-012 + SDD-038 | F00904 | non-negotiable | true | 10 |
| R01745 | info-hub SAIN-01 milestone — `cyberpunk042/devops-solutions-information-hub` PRs #2-#6 (11 epics, ~440KB) | info-hub | F00905 | non-negotiable | false | 10 |
| R01746 | info-hub SAIN-01 milestone — operator-source-of-truth for master-spec | info-hub | F00906 | non-negotiable | false | 10 |
| R01747 | SAIN-01 master-spec — Ryzen 9 9900X CPU | info-hub SAIN-01 + SDD-017 | F00907 | non-negotiable | false | 10 |
| R01748 | SAIN-01 master-spec — Zen 5 architecture | info-hub SAIN-01 | F00908 | non-negotiable | false | 10 |
| R01749 | SAIN-01 master-spec — RTX PRO 6000 Blackwell (96GB) | info-hub SAIN-01 | F00909 | non-negotiable | false | 10 |
| R01750 | SAIN-01 master-spec — RTX 3090 (24GB) | info-hub SAIN-01 | F00910 | non-negotiable | false | 10 |
| R01751 | SAIN-01 master-spec — 256GB DDR5 6400 CL42 RAM (2× CMK128GX5M2B6400C42) | info-hub SAIN-01 + SDD-017 | F00911 | non-negotiable | false | 10 |
| R01752 | SAIN-01 master-spec — 2× Samsung 990 EVO Plus 2TB NVMe | info-hub SAIN-01 + SDD-017 | F00912 | non-negotiable | false | 10 |
| R01753 | SAIN-01 master-spec — ASUS ProArt X870E-Creator WIFI motherboard | info-hub SAIN-01 + SDD-017 | F00913 | non-negotiable | false | 10 |
| R01754 | SAIN-01 master-spec — be Quiet! Dark Power Pro 13 1600W PSU | info-hub SAIN-01 | F00914 | non-negotiable | true | 10 |
| R01755 | SAIN-01 master-spec — SMT2200C UPS | info-hub SAIN-01 | F00915 | non-negotiable | true | 10 |
| R01756 | SAIN-01 master-spec — Intel i226-V dual-NIC | info-hub SAIN-01 + SDD-017 | F00916 | non-negotiable | true | 10 |
| R01757 | SAIN-01 master-spec compliance — operator-discoverable per-component verify | `crates/selfdef-cli` | F00917 | non-negotiable | true | 10 |
| R01758 | SAIN-01 master-spec compliance — operator-readable diff when hardware differs | `crates/selfdef-cli` | F00918 | non-negotiable | true | 10 |
| R01759 | SAIN-01 master-spec compliance — operator-readable warning when running on non-SAIN-01 hardware | `crates/selfdef-cli` | F00919 | non-negotiable | true | 10 |
| R01760 | Metric `selfdef_hardware_inventory_discovered_total{component}` | `crates/selfdef-hardware` | F00920 | non-negotiable | true | 10 |
| R01761 | Metric `selfdef_sain01_compliance_status{component,status}` | `crates/selfdef-cli` | F00921 | non-negotiable | true | 10 |
| R01762 | Metric `selfdef_trinity_eventstream_ingest_total{tier,outcome}` | `crates/selfdef-collector-eventstream` | F00922 | non-negotiable | true | 10 |
| R01763 | Dashboard — SAIN-01 hardware-inventory tile | `dashboard/` | F00889 | non-negotiable | true | 10 |
| R01764 | Dashboard — SAIN-01 Trinity stack overview | `dashboard/` | F00890 | non-negotiable | true | 10 |
| R01765 | Dashboard — SAIN-01 master-spec compliance status | `dashboard/` | F00891 | non-negotiable | true | 10 |
| R01766 | Dashboard — `selfdefctl sain01 verify` results visualizer | `dashboard/` | F00892 | non-negotiable | true | 10 |
| R01767 | Profile knob — `deployment.target = sain-01 \| default \| custom` | `crates/selfdef-config` | F00953 | non-negotiable | true | 10 |
| R01768 | Env var `SELFDEF_DEPLOYMENT_TARGET` | `crates/selfdef-config` | F00954 | non-negotiable | true | 10 |
| R01769 | CLI `--deployment-target <name>` | `crates/selfdef-cli` | F00955 | non-negotiable | true | 10 |
| R01770 | Test — `selfdef-hardware` discovers GPU device nodes on SAIN-01 hardware | tests/ | F00923 | non-negotiable | false | 10 |
| R01771 | Test — `selfdef-hardware` detects AVX-512 capability flags correctly | tests/ | F00924 | non-negotiable | false | 10 |
| R01772 | Test — `selfdef-hardware` detects DDR5 memory bandwidth | tests/ | F00925 | non-negotiable | false | 10 |
| R01773 | Test — Hardware-aware policy refuses assertion not matching inventory | tests/ | F00926 | non-negotiable | false | 10 |
| R01774 | Test — Hardware-aware policy graceful-no-op when capability missing | tests/ | F00927 | non-negotiable | false | 10 |
| R01775 | Test — Trinity-stack eventstream re-ingest end-to-end | tests/ | F00928 | non-negotiable | false | 10 |
| R01776 | Test — SAIN-01 master-spec compliance verifier produces operator-readable report | tests/ | F00929 | non-negotiable | false | 10 |
| R01777 | Test — `selfdefctl sain01 deploy --dry-run` previews Ansible + systemd + AppArmor + ZFS | tests/ | F00930 | non-negotiable | false | 10 |
| R01778 | UX — `selfdefctl sain01 status` output ≤ 1 screen on green case | `crates/selfdef-cli` | F00931 | preferable | true | 10 |
| R01779 | UX — `selfdefctl sain01 status` groups axes (hardware / Trinity / policies / responder) | `crates/selfdef-cli` | F00932 | non-negotiable | true | 10 |
| R01780 | UX — operator-discoverable next-step on each SAIN-01 compliance failure | `crates/selfdef-cli` | F00933 | non-negotiable | true | 10 |
| R01781 | UX — `selfdefctl --json` output available for every sain01 verb | `crates/selfdef-cli` | F00934 | non-negotiable | true | 10 |
| R01782 | UX — Dashboard SAIN-01 compliance tile per-axis green/yellow/red | `dashboard/` | F00935 | non-negotiable | true | 10 |
| R01783 | UX — Dashboard SAIN-01 hardware-inventory tile live | `dashboard/` | F00936 | non-negotiable | true | 10 |
| R01784 | UX — Dashboard SAIN-01 Trinity tile live | `dashboard/` | F00937 | non-negotiable | true | 10 |
| R01785 | UX — Dashboard SAIN-01 verify-results tile operator-readable | `dashboard/` | F00938 | non-negotiable | true | 10 |
| R01786 | Documentation — SDD-010 scoping stub at `docs/sdd/010-selfdef-on-sain01.md` | docs/sdd/ | F00939 | non-negotiable | false | 10 |
| R01787 | Documentation — SDD-012 integration design at `docs/sdd/012-selfdef-on-sain01-integration-design.md` | docs/sdd/ | F00940 | non-negotiable | false | 10 |
| R01788 | Documentation — SDD-017 hardware inventory at `docs/sdd/017-sain01-hardware-inventory.md` | docs/sdd/ | F00941 | non-negotiable | false | 10 |
| R01789 | Documentation — SDD-013 deployment-target config at `docs/sdd/013-deployment-target-config.md` | docs/sdd/ | F00942 | non-negotiable | true | 10 |
| R01790 | Documentation — SDD-015 perimeter coexistence at `docs/sdd/015-perimeter-coexistence.md` | docs/sdd/ | F00943 | non-negotiable | true | 10 |
| R01791 | Documentation — SDD-018 hardware-aware modules at `docs/sdd/018-hardware-aware-modules-and-tune-surface.md` | docs/sdd/ | F00944 | non-negotiable | true | 10 |
| R01792 | Documentation — SDD-022 hardware-exploit doctrine at `docs/sdd/022-hardware-exploit-doctrine.md` | docs/sdd/ | F00945 | non-negotiable | true | 10 |
| R01793 | Documentation — SDD-023 cross-repo model taxonomy mirror at `docs/sdd/023-cross-repo-model-taxonomy-mirror.md` | docs/sdd/ + MS007 | F00946 | non-negotiable | true | 10 |
| R01794 | Documentation — SDD-026 operator dashboard + flex profile at `docs/sdd/026-operator-dashboard-and-flex-profile.md` | docs/sdd/ | F00947 | non-negotiable | true | 10 |
| R01795 | Cycle-vector tracking — SDD-019 cycle 3 forward-looking spec | docs/sdd/ | F00948 | non-negotiable | true | 10 |
| R01796 | Cycle-vector tracking — SDD-020 cycle 3 vectors | docs/sdd/ | F00949 | non-negotiable | true | 10 |
| R01797 | Cycle-vector tracking — SDD-021 cycle 4 vectors | docs/sdd/ | F00950 | non-negotiable | true | 10 |
| R01798 | Cycle-vector tracking — SDD-024 cycle 5 vectors | docs/sdd/ | F00951 | non-negotiable | true | 10 |
| R01799 | Cycle-vector tracking — SDD-025 cycle 6 vectors | docs/sdd/ | F00952 | non-negotiable | true | 10 |
| R01800 | SAIN-01 deployment activation — selfdef-config `deployment.target = sain-01` activates hardware-aware modules + Trinity eventstream + workload-mode coordination + responder ZFS snapshots + dashboard tiles | this milestone | F00956 | non-negotiable | true | 10 |
| R01801 | SAIN-01 integration depends on MS001 daemon core | MS001 | E0087 | non-negotiable | false | 10 |
| R01802 | SAIN-01 integration depends on MS002 collector fabric (eventstream re-ingest) | MS002 | E0087 | non-negotiable | false | 10 |
| R01803 | SAIN-01 integration depends on MS003 correlator + responder + signing (ZFS snapshot rollback) | MS003 | E0087 | non-negotiable | false | 10 |
| R01804 | SAIN-01 integration depends on MS004 14 integrations (Oracle-Triage cross-repo bridge) | MS004 | E0087 | non-negotiable | false | 10 |
| R01805 | SAIN-01 integration depends on MS005 notifier engine + orchestrator | MS005 | E0087 | non-negotiable | false | 10 |
| R01806 | SAIN-01 integration depends on MS006 14 functional modules (agent-guard / hardware-tune-cache / etc) | MS006 | E0087 | non-negotiable | false | 10 |
| R01807 | SAIN-01 integration depends on MS007 8/8 typed-mirror cross-repo crates | MS007 | E0088 | non-negotiable | false | 10 |
| R01808 | SAIN-01 integration L1 lint — every SDD-010 scope axis has at least one acceptance assertion | tests/lint | E0081 | non-negotiable | false | 10 |
| R01809 | SAIN-01 integration L1 lint — every SDD-012 Q-A..Q-H resolution has at least one acceptance assertion | tests/lint | E0082 | non-negotiable | false | 10 |
| R01810 | SAIN-01 integration L3 smoke — `selfdef-hardware` inventory matches expected SAIN-01 spec on real hardware | tests/ | M00203 | non-negotiable | false | 10 |
| R01811 | SAIN-01 integration L3 smoke — Trinity-stack eventstream re-ingest delivers events within 5s | tests/ | E0089 | non-negotiable | false | 10 |
| R01812 | SAIN-01 integration L5 real-substrate — selfdef-on-sain01 deployment runs end-to-end on real SAIN-01 hardware once procured | tests/ | E0090 | non-negotiable | false | 10 |
| R01813 | SAIN-01 procurement state — operator-discoverable via `selfdefctl sain01 status --procurement` | `crates/selfdef-cli` | E0085 | non-negotiable | true | 10 |
| R01814 | SAIN-01 procurement state — operator-discoverable Oracle Core model choice (Ling-2.6-flash / Nemotron-3-Nano-Omni / both / undecided) | `crates/selfdef-cli` | E0085 | non-negotiable | true | 10 |
| R01815 | SAIN-01 procurement state — operator-discoverable authorization status (authorized / pending / declined) | `crates/selfdef-cli` | E0085 | non-negotiable | true | 10 |
| R01816 | Anti-pattern — selfdef-on-sain01 NEVER auto-applies sovereign-os state mutations | architecture | F00902 | non-negotiable | false | 10 |
| R01817 | Anti-pattern — selfdef-on-sain01 NEVER assumes hardware match (always probes) | M00203 | M00211 | non-negotiable | false | 10 |
| R01818 | Anti-pattern — selfdef-on-sain01 NEVER promotes Trinity Verdict without ZFS snapshot guard | SDD-012 Q-F | F00888 | non-negotiable | false | 10 |
| R01819 | Anti-pattern — selfdef-on-sain01 NEVER bypasses operator-confirmation for triple-gated rollback | MS003 + SDD-012 | F00888 | non-negotiable | false | 10 |
| R01820 | Anti-pattern — selfdef-on-sain01 NEVER imports sovereign-os crate code directly | architecture | F00902 | non-negotiable | false | 10 |
| R01821 | Anti-pattern — selfdef-on-sain01 NEVER mutates `/etc/` outside `/etc/selfdef/` without operator triple-gate | architecture | M00194 | non-negotiable | false | 10 |
| R01822 | Default — `deployment.target = default` (NOT sain-01 on fresh install; operator opt-in) | `crates/selfdef-config` | F00953 | non-negotiable | true | 10 |
| R01823 | Default — selfdef-on-sain01 requires explicit `selfdefctl modules apply --profile sain-01` first | `crates/selfdef-cli` | F00956 | non-negotiable | true | 10 |
| R01824 | Default — Trinity-stack eventstream re-ingest disabled on fresh install (operator opt-in via Q-E) | `crates/selfdef-config` | F00857 | non-negotiable | true | 10 |
| R01825 | Default — Workload-mode coordination disabled on fresh install (operator opt-in via Q-F) | `crates/selfdef-config` | F00858 | non-negotiable | true | 10 |
| R01826 | Hardware-inventory cache — discovered hardware cached at `/var/lib/selfdef/hardware-inventory.json` | `crates/selfdef-hardware` | M00203 | non-negotiable | true | 10 |
| R01827 | Hardware-inventory cache — refresh on `selfdefctl hardware refresh` (triple-gate not required; read-only) | `crates/selfdef-cli` | M00203 | non-negotiable | true | 10 |
| R01828 | Hardware-inventory cache — operator-tunable refresh-interval | `crates/selfdef-config` | M00203 | non-negotiable | true | 10 |
| R01829 | Hardware-inventory cache — operator-readable diff on refresh (changed components flagged) | `crates/selfdef-cli` | F00872 | non-negotiable | true | 10 |
| R01830 | SAIN-01 dashboard tile color rule — green when all axes pass; yellow when ≥1 advisory; red when ≥1 critical | `dashboard/` | F00891 | non-negotiable | true | 10 |
| R01831 | SAIN-01 dashboard tile drill-down — clicking a yellow/red axis surfaces operator-readable next-step | `dashboard/` | F00891 | non-negotiable | true | 10 |
| R01832 | SAIN-01 Ansible playbook idempotent — running twice produces no changes | `ansible/sain01/site.yml` | F00896 | non-negotiable | false | 10 |
| R01833 | SAIN-01 Ansible playbook operator-discoverable — operator-readable `--check` mode preview | `ansible/sain01/site.yml` | F00896 | non-negotiable | true | 10 |
| R01834 | SAIN-01 Ansible playbook records every action to `selfdef-store` actions table | `ansible/sain01/site.yml` + `crates/selfdef-store` | F00896 | non-negotiable | false | 10 |
| R01835 | SAIN-01 systemd unit `selfdefd@sain01.service` honors per-instance config at `/etc/selfdef/sain01/` | `packaging/systemd/` | F00897 | non-negotiable | true | 10 |
| R01836 | SAIN-01 AppArmor profile blocks `/etc/` writes outside `/etc/selfdef/sain01/` | `packaging/apparmor/` | F00898 | non-negotiable | false | 10 |
| R01837 | SAIN-01 cgroup v2 slice caps memory at operator-tunable threshold (default 8GB) | `packaging/systemd/` | F00899 | non-negotiable | true | 10 |
| R01838 | SAIN-01 ZFS dataset operator-tunable retention (default keep last 30 snapshots) | SDD-012 + MS003 | F00900 | non-negotiable | true | 10 |
| R01839 | SAIN-01 cross-repo binding integration — selfdef-collector-eventstream uses MS007 typed mirror for sovereign-os contract | MS007 + SDD-038 | F00904 | non-negotiable | false | 10 |
| R01840 | SAIN-01 cross-repo binding integration — Oracle-Triage (MS004 E0036) uses MS007 typed mirror | MS004 + MS007 + SDD-038 | F00903 | non-negotiable | false | 10 |
| R01841 | Composite — SAIN-01 integration represents the operator's primary AI workstation deployment target | this milestone | F00960 | non-negotiable | false | 10 |
| R01842 | Composite — SAIN-01 integration is the canonical end-to-end IPS pipeline deployed on operator's real hardware | this milestone | E0084 | non-negotiable | false | 10 |
| R01843 | Composite — SAIN-01 integration bridges selfdef (IPS substrate) and sovereign-os (AI workstation runtime) via SDD-038 typed-mirror cross-repo doctrine | this milestone + MS007 + SDD-038 | E0088 | non-negotiable | false | 10 |
| R01844 | Composite — SAIN-01 integration validates the operator-stated 'two ultimate solutions' work together on real hardware | this milestone | E0090 | non-negotiable | false | 10 |
| R01845 | Composite — SAIN-01 master-spec is operator-source-of-truth in info-hub PRs #2-#6 (11 epics, ~440KB); selfdef-on-sain01 consumes that spec without redefining it | info-hub SAIN-01 | F00906 | non-negotiable | false | 10 |
| R01846 | SAIN-01 integration honors operator directive — "Knowledge is the second-brain / information-hub" (master-spec lives in info-hub; this milestone is the IPS-scope realization) | operator directive 2026-05-19 | F00906 | non-negotiable | false | 10 |
| R01847 | SAIN-01 integration honors operator directive — "if I talk about an IPS feature its obviously not in Sovereign-OS" (IPS-scope only) | operator directive 2026-05-19 | F00901 | non-negotiable | false | 10 |
| R01848 | SAIN-01 integration honors operator directive — "Do not minimize the work in selfdef" (full coverage of 8 SDD-010 axes + 8 SDD-012 resolutions + 7 SDD-017 inventory facts) | operator directive 2026-05-19 | E0081 | non-negotiable | false | 10 |
| R01849 | SAIN-01 integration honors operator directive — "respect the projects" (selfdef-on-sain01 implements IPS-scope; sovereign-os runtime is separate) | operator directive 2026-05-19 | F00901 | non-negotiable | false | 10 |
| R01850 | SAIN-01 integration honors operator directive — "they combine but keep in mind they are also independent" (cross-repo binding via MS007 typed mirrors; not a single repo) | operator directive 2026-05-19 | E0088 | non-negotiable | false | 10 |
| R01851 | SAIN-01 cycle-vector continuity — SDD-019 → SDD-025 documents 4 cycles (cycle 3 → cycle 6) of operator-driven iteration; future cycles continue the pattern | docs/sdd/ | F00952 | non-negotiable | true | 10 |
| R01852 | SAIN-01 perimeter coexistence — SDD-015 documents how selfdef's perimeter scope coexists with sovereign-os AI inference | docs/sdd/015 | F00943 | non-negotiable | true | 10 |
| R01853 | SAIN-01 hardware-aware modules — SDD-018 documents tune-surface for AVX-512 / RTX PRO 6000 / RTX 3090 / DDR5 6400 specific tuning | docs/sdd/018 | F00944 | non-negotiable | true | 10 |
| R01854 | SAIN-01 hardware-exploit doctrine — SDD-022 documents hardware-exploit-to-the-max research loop (continuously evolving SDD + TDD as new BitNet / DFlash / VPDPBUSD findings land) | docs/sdd/022 | F00945 | non-negotiable | true | 10 |
| R01855 | SAIN-01 cross-repo model taxonomy mirror — SDD-023 documents how sovereign-os model registry mirrors into selfdef as typed catalog | docs/sdd/023 + MS007 | F00946 | non-negotiable | true | 10 |
| R01856 | SAIN-01 operator dashboard — SDD-026 documents flex profile for operator dashboard on SAIN-01 hardware | docs/sdd/026 | F00947 | non-negotiable | true | 10 |
| R01857 | SAIN-01 deployment-target config — SDD-013 documents declarative profile `deployment.target = sain-01` | docs/sdd/013 | F00942 | non-negotiable | true | 10 |
| R01858 | SAIN-01 hardware-tune-cache module — MS006 module `hardware-tune-cache` writes `/etc/selfdef/hardware-tune.env` consumed by SAIN-01 build pipelines | MS006 | E0087 | non-negotiable | true | 10 |
| R01859 | SAIN-01 agent-guard module — MS006 module `agent-guard` enforces host-level invariants on sovereign-os inference daemons | MS006 + SDD-012 Q-D | E0087 | non-negotiable | true | 10 |
| R01860 | SAIN-01 bridge-l2 module — MS006 module `bridge-l2` provides FORWARD hook for SAIN-01 dual-NIC transparent inspection | MS006 + SDD-012 | E0087 | non-negotiable | true | 10 |
| R01861 | SAIN-01 suricata module — MS006 module `suricata` runs inline IDS on SAIN-01 bridge-l2 FORWARD hook | MS006 + SDD-012 | E0087 | non-negotiable | true | 10 |
| R01862 | SAIN-01 bitnet-gpu-inference module — MS006 module `bitnet-gpu-inference` provisions host for BitNet ternary inference on RTX PRO 6000 / RTX 3090 | MS006 + SDD-022 | E0087 | non-negotiable | true | 10 |
| R01863 | SAIN-01 slm-cpu-loop module — MS006 module `slm-cpu-loop` pins SLM-on-CPU agent loop to Ryzen 9 9900X CCD-0 cores | MS006 + SDD-022 | E0087 | non-negotiable | true | 10 |
| R01864 | SAIN-01 tensor-parallel-inference module — MS006 module `tensor-parallel-inference` provisions per-GPU slices on RTX PRO 6000 + RTX 3090 | MS006 + SDD-022 | E0087 | non-negotiable | true | 10 |
| R01865 | SAIN-01 wasm-aot-cache module — MS006 module `wasm-aot-cache` caches AOT-compiled WASM artifacts for downstream WASM-plugin tier | MS006 + sovereign-os M023 | E0087 | non-negotiable | true | 10 |
| R01866 | SAIN-01 polarproxy module — MS006 module `polarproxy` provides TLS termination + PCAP-over-IP on SAIN-01 dual-NIC | MS006 + SDD-012 | E0087 | non-negotiable | true | 10 |
| R01867 | SAIN-01 vpn-bridge module — MS006 module `vpn-bridge` provides WireGuard tunnel for remote-network connectivity from SAIN-01 host | MS006 | E0087 | non-negotiable | true | 10 |
| R01868 | SAIN-01 observability module — MS006 module `observability` provides Prometheus scrape + Grafana dashboard for selfdef stack on SAIN-01 | MS006 + SDD-026 | E0087 | non-negotiable | true | 10 |
| R01869 | SAIN-01 integrity-sentinel module — MS006 module `integrity-sentinel` fail-closed-on-drift detection on SAIN-01 policy artifacts | MS006 | E0087 | non-negotiable | true | 10 |
| R01870 | SAIN-01 detect-host module — MS006 module `detect-host` packages selfdef-daemon as installable module for SAIN-01 | MS006 | E0087 | non-negotiable | true | 10 |
| R01871 | SAIN-01 tetragon module — MS006 module `tetragon` provides Tetragon substrate for SAIN-01 (main config + TracingPolicy drop dir + Prometheus metrics) | MS006 + SDD-012 Q-D | E0087 | non-negotiable | true | 10 |
| R01872 | SAIN-01 cycle-vector continuity — SDD-024 cycle 5 vectors land hardware-aware modules + AVX-512 utilization probe + 1-bit/ternary ZMM utilization | docs/sdd/024 | F00951 | non-negotiable | true | 10 |
| R01873 | SAIN-01 cycle-vector continuity — SDD-025 cycle 6 vectors land Trinity-tier model serving guardrails + RLM context engine consumer surfaces | docs/sdd/025 | F00952 | non-negotiable | true | 10 |
| R01874 | SAIN-01 future cycles — each new cycle adds vectors that extend the IPS-scope without redefining sovereign-os runtime scope | docs/sdd/ | E0090 | non-negotiable | false | 10 |
| R01875 | SAIN-01 future cycles — operator-discoverable cycle pointer at `docs/sdd/` next-cycle-spec | docs/sdd/ | E0090 | non-negotiable | true | 10 |
| R01876 | SAIN-01 operator-pull dashboard — SDD-026 dashboard surfaces Trinity stack health on SAIN-01 hardware | SDD-026 | F00890 | non-negotiable | true | 10 |
| R01877 | SAIN-01 operator-pull dashboard — SDD-026 dashboard surfaces hardware-inventory live state | SDD-026 | F00889 | non-negotiable | true | 10 |
| R01878 | SAIN-01 operator-pull dashboard — SDD-026 dashboard surfaces master-spec compliance per-axis | SDD-026 | F00891 | non-negotiable | true | 10 |
| R01879 | SAIN-01 operator-pull dashboard — SDD-026 dashboard surfaces SAIN-01 verify-results | SDD-026 | F00892 | non-negotiable | true | 10 |
| R01880 | SAIN-01 operator-pull dashboard — SDD-026 dashboard surfaces flex profile selector (multiple SAIN-01 sub-profiles for different workloads) | SDD-026 | F00890 | non-negotiable | true | 10 |
| R01881 | Composite — MS008 ships the SAIN-01 integration spec; impl gated on procurement | this milestone | E0085 | non-negotiable | false | 10 |
| R01882 | Composite — MS008 spec is comprehensive enough that impl can begin the moment hardware + image are ready | this milestone + SDD-012 | E0082 | non-negotiable | false | 10 |
| R01883 | Composite — MS008 catalog identification phase is COMPLETE for selfdef-on-sain01 axis | this milestone | E0081 | non-negotiable | false | 10 |
| R01884 | Composite — MS008 SDD references trace to 11 SDD documents (010 / 012 / 013 / 015 / 017 / 018 / 019 / 020 / 021 / 022 / 023 / 024 / 025 / 026) | docs/sdd/ | E0081 | non-negotiable | false | 10 |
| R01885 | Composite — MS008 integrates with MS001-MS007 to form the selfdef-on-SAIN-01 substrate | MS001-MS007 | E0087 | non-negotiable | false | 10 |
| R01886 | SAIN-01 integration is a Stage-2 selfdef milestone (Stage-1 was selfdef-side fabric across MS001-MS007; Stage-2 is the deployment target) | this milestone | E0081 | non-negotiable | false | 10 |
| R01887 | SAIN-01 integration is mandatory for the operator's "two ultimate solutions" goal (selfdef + sovereign-os deployed on SAIN-01 = the operator-stated primary deployment) | operator directive 2026-05-19 | E0084 | non-negotiable | false | 10 |
| R01888 | SAIN-01 integration is the IPS-side complement to sovereign-os M003 hardware-topology + M040 hyper-features + M044 sovereign-OS substrate milestones | sovereign-os M003 / M040 / M044 | E0088 | non-negotiable | true | 10 |
| R01889 | SAIN-01 integration ships with the sovereign-os Debian 13 / Ubuntu 24 base image — selfdef is opt-in via `selfdef` profile flag | SDD-012 Q-H + sovereign-os M044 | F00860 | non-negotiable | true | 10 |
| R01890 | SAIN-01 integration honors the operator's standing directive that all 5 ecosystem repos (info-hub / selfdef / sovereign-os / root-ghostproxy / devops-expert-local-ai) carry the bulletproof Claude Code env-bootstrap bundle | operator directive 2026-05-19 | E0088 | non-negotiable | false | 10 |
| R01891 | SAIN-01 integration cross-checks against operator's standing directive R102/R103 (cross-repo saturation invariant 8/8 SATURATED) | MS001 R102 + MS001 R103 | E0088 | non-negotiable | false | 10 |
| R01892 | SAIN-01 integration test orchestration — `selfdefctl sain01 verify --strict` runs all 8 SDD-010 axes + all 8 SDD-012 Q-A..Q-H + all 7 SDD-017 inventory facts | `crates/selfdef-cli` | F00877 | non-negotiable | true | 10 |
| R01893 | SAIN-01 integration test orchestration — failure surfaces operator-readable next-step per axis | `crates/selfdef-cli` | F00933 | non-negotiable | true | 10 |
| R01894 | SAIN-01 integration test orchestration — pass status persists to `selfdef-store` actions table | `crates/selfdef-store` | F00877 | non-negotiable | true | 10 |
| R01895 | SAIN-01 integration test orchestration — operator-discoverable trend (compliance status over time) | `dashboard/` | F00891 | non-negotiable | true | 10 |
| R01896 | SAIN-01 integration governance — operator approves each new SDD-010 scope axis before authoring | architecture | E0081 | non-negotiable | false | 10 |
| R01897 | SAIN-01 integration governance — operator approves each new SDD-012 Q resolution before promoting from `review` to `locked` | SDD-012 | E0082 | non-negotiable | false | 10 |
| R01898 | SAIN-01 integration governance — Phase audit gate locks SDD-012 resolutions | SDD-012 | E0082 | non-negotiable | true | 10 |
| R01899 | SAIN-01 integration governance — every cycle-vector SDD reviewed at Phase audit | docs/sdd/019-025 | E0090 | non-negotiable | true | 10 |
| R01900 | SAIN-01 integration governance — operator-pending-decision queue carries open resolutions | architecture | E0085 | non-negotiable | true | 10 |
| R01901 | SAIN-01 integration scaffolding — `selfdefctl sain01 scaffold` generates per-axis boilerplate (Ansible task + systemd template + AppArmor block + ZFS dataset declaration) | `crates/selfdef-cli` | M00194 | preferable | true | 10 |
| R01902 | SAIN-01 integration scaffolding — operator-discoverable next-step on each scaffolded axis | `crates/selfdef-cli` | M00194 | preferable | true | 10 |
| R01903 | SAIN-01 integration scaffolding — every scaffold emits operator-readable diff before commit | `crates/selfdef-cli` | M00194 | preferable | true | 10 |
| R01904 | SAIN-01 integration profile composition — selfdef-on-sain01 + sovereign-os runtime profiles compose on same Debian 13 image | SDD-012 Q-H | F00860 | non-negotiable | true | 10 |
| R01905 | SAIN-01 integration profile composition — operator can deploy selfdef-only, sovereign-only, or selfdef+sovereign on same SAIN-01 host | SDD-012 | F00956 | non-negotiable | true | 10 |
| R01906 | SAIN-01 integration profile composition — `selfdefctl modules apply --profile sain-01` activates the SAIN-01-specific module set | `crates/selfdef-cli` | F00956 | non-negotiable | true | 10 |
| R01907 | SAIN-01 integration profile composition — operator can layer custom profile on top of sain-01 base (`selfdefctl modules apply --profile sain-01 --overlay <name>`) | `crates/selfdef-cli` | F00956 | preferable | true | 10 |
| R01908 | SAIN-01 integration profile composition — operator-discoverable per-profile diff | `crates/selfdef-cli` | F00956 | non-negotiable | true | 10 |
| R01909 | SAIN-01 integration profile composition — profile changes audited to `selfdef-store` actions table | `crates/selfdef-store` | F00956 | non-negotiable | false | 10 |
| R01910 | SAIN-01 integration profile composition — profile changes notified per SDD-008 routing (`source=selfdef-modules severity=info`) | SDD-008 | F00956 | non-negotiable | true | 10 |
| R01911 | SAIN-01 integration is forward-compatible with future SAIN-N (e.g. SAIN-02 with different hardware) — same SDD framework, different `deployment.target` profile | this milestone | F00953 | non-negotiable | true | 10 |
| R01912 | SAIN-01 integration is forward-compatible with operator's "many SAIN deployments" goal (operator may deploy SAIN-01a / SAIN-01b / SAIN-02 etc) | this milestone | F00953 | non-negotiable | true | 10 |
| R01913 | SAIN-01 integration registry — operator-discoverable list of deployed SAIN hosts via `selfdefctl sain01 hosts list` | `crates/selfdef-cli` | E0085 | preferable | true | 10 |
| R01914 | SAIN-01 integration registry — per-host status (procurement / image / deployed / running / errored / decommissioned) | `crates/selfdef-cli` | E0085 | preferable | true | 10 |
| R01915 | SAIN-01 integration registry — operator-supplied per-host metadata (name / role / location) | `crates/selfdef-config` | E0085 | preferable | true | 10 |
| R01916 | SAIN-01 integration registry — operator-readable per-host history (deploy / upgrade / rollback / decommission events) | `crates/selfdef-store` | E0085 | preferable | true | 10 |
| R01917 | SAIN-01 integration documentation — operator-facing deployment guide at `docs/operator/sain01-deployment-guide.md` | `docs/operator/` | E0081 | non-negotiable | true | 10 |
| R01918 | SAIN-01 integration documentation — operator-facing master-spec reference at `docs/operator/sain01-master-spec.md` | `docs/operator/` | F00906 | non-negotiable | true | 10 |
| R01919 | SAIN-01 integration documentation — agent-author guide at `docs/contributing/sain01-extension.md` for adding new SAIN-01 axes | `docs/contributing/` | E0081 | non-negotiable | true | 10 |
| R01920 | Composite — MS008 selfdef-on-SAIN-01 integration is the catalog representation of the operator's primary deployment goal; impl gated on procurement + Oracle Core selection + operator authorization | this milestone | E0085 | non-negotiable | false | 10 |

— End of MS008 milestone file.
