# MS031 — WASM AOT cache module

> Parent: `backlog/milestones/INDEX.md` row MS031 (source ref `modules/wasm-aot-cache` + dump 6495 "WASM As Tool ABI").
> Source: `modules/wasm-aot-cache/` (150 lines across module.toml + install/apply.sh + install/check.sh + install/uninstall.sh).
> All entries below extract verbatim. No invention.

## Epics (E0311–E0320)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0311 | Module identity — `wasm-aot-cache` v0.1.0, category=inference, summary "Provision /var/lib/selfdef/wasm-aot/ for cached .cwasm artifacts produced by `wasmtime compile` against the SD-R30 target-feature surface (SD-R48)" | `module.toml` 1–4 |
| E0312 | Manifest dependencies + surfaces — `depends_on = ["hardware-tune-cache"]` + `provides = ["wasm-aot-cache-dir"]` + `consumes = ["hardware-tune-env"]` + `conflicts = []` + `requires = [{kind = "binary", value = "selfdefctl"}]` | `module.toml` 6–14 |
| E0313 | SD-R48 — "the second real demonstrator of the cycle-2 [requires_hardware] surface"; "SD-R28 (bitnet-gpu-inference) showed the 5-predicate combo; THIS module showcases the SD-R32 predicate: wasm_aot_features_required"; operator declares "I want wasmtime to AOT-compile against AT LEAST these AVX-512 features"; "the gate refuses to land the module on hosts where SD-R30's wasm_aot.target_features doesn't include them" | `module.toml` 16–24 |
| E0314 | SD-R32 stable contract — module "declares a stable contract: it provisions a writeable cache for .cwasm files only when the host can actually AOT-compile against the operator's minimum feature surface"; "Combined with avx512_vnni + memory_gib_min" | `module.toml` 26–30 |
| E0315 | Host behavior — "On the SAIN-01 9900X (avx512f + dq + bw + vl + vnni + bf16 + fp16), this lands cleanly" + "On an Intel Cooper Lake (no bf16), the gate refuses — operator gets a clear skip message" | `module.toml` 32–35 |
| E0316 | [requires_hardware] gates — `avx512_vnni = true` + `memory_gib_min = 16` + `wasm_aot_features_required = "+avx512f,+avx512vnni,+avx512bf16"` (load-bearing SD-R32 predicate) | `module.toml` 37–42 |
| E0317 | Module-system invariants — `instanced = false` + `phase = "pre"` ("so the cache dir is in place before any module / build script tries to write a .cwasm to it") + `[install] kind = "script"` | `module.toml` 44–49 |
| E0318 | apply.sh — provisions /var/lib/selfdef/wasm-aot/ with subdirs for canonical AOT compile pipeline: `.cwasm/` (pre-compiled artifacts) + `.meta/` (per-artifact JSON metadata) + `.last-tune` (symlink to /etc/selfdef/hardware-tune.env so consumers detect tune-config drift via readlink + compare); idempotent; SELFDEF_DRY_RUN=1 aware; mkdir -p + chmod 0755 on cache dirs; ln -sfn for symlink (atomic re-targeting) | `install/apply.sh` 1–45 |
| E0319 | check.sh — read-only 3-directory presence verifier (CACHE_DIR + cwasm + meta); emits ok "cache dirs present" + exit 0 OR failed "missing: <list>" + exit 1 | `install/check.sh` 1–26 |
| E0320 | uninstall.sh — removes `.last-tune` symlink + meta dir (cleared on uninstall); PRESERVES `.cwasm/` artifacts dir — "operators may want to keep their AOT cache across module re-applies (rebuilding is expensive on large pipelines)"; DRY_RUN-aware | `install/uninstall.sh` 1–30 |

## Modules (M00785–M00810)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00785 | `module.toml` — 49-line manifest (cycle-2 [requires_hardware] + SD-R32 predicate + instanced=false + phase=pre) | `module.toml` 1–49 | E0311 + E0313 + E0316 + E0317 |
| M00786 | `install/apply.sh` — 45-line idempotent provisioner (cache dirs + tune symlink) | `install/apply.sh` 1–45 | E0318 |
| M00787 | `install/check.sh` — 26-line read-only 3-dir verifier | `install/check.sh` 1–26 | E0319 |
| M00788 | `install/uninstall.sh` — 30-line tear-down preserving cwasm/ | `install/uninstall.sh` 1–30 | E0320 |
| M00789 | Provided surface — `wasm-aot-cache-dir` | `module.toml` 8 | E0312 |
| M00790 | Consumed surface — `hardware-tune-env` (from MS010) | `module.toml` 9 | E0312 |
| M00791 | Required binary — `selfdefctl` | `module.toml` 12 | E0312 |
| M00792 | SD-R48 — "second real demonstrator of the cycle-2 [requires_hardware] surface" | `module.toml` 16 | E0313 |
| M00793 | SD-R32 predicate — `wasm_aot_features_required` (the load-bearing predicate) | `module.toml` 24 + 41 | E0313 |
| M00794 | Gate semantics — "refuses to land the module on hosts where SD-R30's wasm_aot.target_features doesn't include them" | `module.toml` 21–23 | E0313 |
| M00795 | Stable contract — provisions writeable cache for .cwasm files only when host AOT-compiles against operator's minimum feature surface | `module.toml` 27–29 | E0314 |
| M00796 | SAIN-01 9900X feature set — avx512f + dq + bw + vl + vnni + bf16 + fp16 | `module.toml` 32 | E0315 |
| M00797 | Intel Cooper Lake — no bf16; gate refuses; clear skip message | `module.toml` 34 | E0315 |
| M00798 | Hardware gate — avx512_vnni = true | `module.toml` 38 | E0316 |
| M00799 | Hardware gate — memory_gib_min = 16 | `module.toml` 39 | E0316 |
| M00800 | Hardware gate — wasm_aot_features_required = "+avx512f,+avx512vnni,+avx512bf16" | `module.toml` 41 | E0316 |
| M00801 | Lifecycle phase — `phase = "pre"` (cache dir in place before .cwasm writes) | `module.toml` 46 | E0317 |
| M00802 | Cache directory — `/var/lib/selfdef/wasm-aot/` (default; SELFDEF_WASM_AOT_CACHE_DIR override) | `install/apply.sh` 21 | E0318 |
| M00803 | Subdir — `.cwasm/` (pre-compiled artifacts) | `install/apply.sh` 5 + 31 | E0318 |
| M00804 | Subdir — `.meta/` (per-artifact JSON metadata) | `install/apply.sh` 6 + 31 | E0318 |
| M00805 | Symlink — `.last-tune` → /etc/selfdef/hardware-tune.env | `install/apply.sh` 7–9 + 41 | E0318 |
| M00806 | Drift detection — `readlink ${CACHE_DIR}/.last-tune` + compare mtime | `install/apply.sh` 37–39 | E0318 |
| M00807 | apply.sh — mkdir -p cwasm + meta + chmod 0755 | `install/apply.sh` 31–32 | E0318 |
| M00808 | apply.sh — `ln -sfn` atomic re-target | `install/apply.sh` 41 | E0318 |
| M00809 | check.sh — 3-dir presence verifier (CACHE_DIR + cwasm + meta) | `install/check.sh` 17–19 | E0319 |
| M00810 | uninstall.sh — preserves cwasm/ artifacts (re-builds expensive on large pipelines) | `install/uninstall.sh` 3–6 | E0320 |

## Features (F03601–F03720)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F03601 | module.toml `name = "wasm-aot-cache"` | `module.toml` 1 | M00785 |
| F03602 | module.toml `version = "0.1.0"` | `module.toml` 2 | M00785 |
| F03603 | module.toml summary — "Provision /var/lib/selfdef/wasm-aot/" | `module.toml` 3 | M00785 |
| F03604 | module.toml summary — "for cached .cwasm artifacts produced by `wasmtime compile`" | `module.toml` 3 | M00785 |
| F03605 | module.toml summary — "against the SD-R30 target-feature surface" | `module.toml` 3 | M00785 |
| F03606 | module.toml summary — SD-R48 reference | `module.toml` 3 | M00785 |
| F03607 | module.toml `category = "inference"` | `module.toml` 4 | M00785 |
| F03608 | module.toml `depends_on = ["hardware-tune-cache"]` | `module.toml` 6 | M00790 |
| F03609 | module.toml `conflicts = []` | `module.toml` 7 | M00785 |
| F03610 | module.toml `provides = ["wasm-aot-cache-dir"]` | `module.toml` 8 | M00789 |
| F03611 | module.toml `consumes = ["hardware-tune-env"]` | `module.toml` 9 | M00790 |
| F03612 | module.toml `requires` — binary selfdefctl | `module.toml` 12 | M00791 |
| F03613 | SD-R48 doctrine — "second real demonstrator of the cycle-2 [requires_hardware] surface" | `module.toml` 16 | M00792 |
| F03614 | SD-R48 — "SD-R28 (bitnet-gpu-inference) showed the 5-predicate combo" | `module.toml` 17 | M00792 |
| F03615 | SD-R48 — "THIS module showcases the SD-R32 predicate" | `module.toml` 18 | M00793 |
| F03616 | SD-R32 predicate name — `wasm_aot_features_required` | `module.toml` 20 + 41 | M00793 |
| F03617 | SD-R32 doctrine — operator declares "I want wasmtime to AOT-compile against AT LEAST these AVX-512 features" | `module.toml` 21–22 | M00793 |
| F03618 | SD-R32 gate semantics — refuses module if SD-R30's wasm_aot.target_features doesn't include required features | `module.toml` 22–23 | M00794 |
| F03619 | Stable contract — "provisions a writeable cache for .cwasm files only when the host can actually AOT-compile" | `module.toml` 27–28 | M00795 |
| F03620 | Stable contract — combines with avx512_vnni + memory_gib_min | `module.toml` 29 | M00795 |
| F03621 | SAIN-01 9900X — avx512f present | `module.toml` 32 | M00796 |
| F03622 | SAIN-01 9900X — avx512dq present | `module.toml` 32 | M00796 |
| F03623 | SAIN-01 9900X — avx512bw present | `module.toml` 32 | M00796 |
| F03624 | SAIN-01 9900X — avx512vl present | `module.toml` 32 | M00796 |
| F03625 | SAIN-01 9900X — avx512vnni present | `module.toml` 32 | M00796 |
| F03626 | SAIN-01 9900X — avx512bf16 present | `module.toml` 32 | M00796 |
| F03627 | SAIN-01 9900X — avx512fp16 present | `module.toml` 32 | M00796 |
| F03628 | SAIN-01 9900X — "this lands cleanly" | `module.toml` 33 | M00796 |
| F03629 | Intel Cooper Lake — "no bf16" | `module.toml` 34 | M00797 |
| F03630 | Intel Cooper Lake — "the gate refuses" | `module.toml` 34 | M00797 |
| F03631 | Intel Cooper Lake — "operator gets a clear skip message" | `module.toml` 35 | M00797 |
| F03632 | [requires_hardware] block declared | `module.toml` 37 | E0316 |
| F03633 | Gate avx512_vnni = true | `module.toml` 38 | M00798 |
| F03634 | Gate memory_gib_min = 16 | `module.toml` 39 | M00799 |
| F03635 | Comment — "SD-R32 surface — the load-bearing predicate for this module" | `module.toml` 40 | M00793 |
| F03636 | Gate wasm_aot_features_required = "+avx512f,+avx512vnni,+avx512bf16" | `module.toml` 41 | M00800 |
| F03637 | module.toml `instanced = false` | `module.toml` 43 | E0317 |
| F03638 | module.toml `phase = "pre"` | `module.toml` 46 | M00801 |
| F03639 | Phase rationale — "so the cache dir is in place before any module / build script tries to write a .cwasm to it" | `module.toml` 45 | M00801 |
| F03640 | module.toml `[install] kind = "script"` | `module.toml` 48–49 | E0317 |
| F03641 | apply = "install/apply.sh" | `module.toml` 49 | M00786 |
| F03642 | check = "install/check.sh" | `module.toml` 49 | M00787 |
| F03643 | uninstall = "install/uninstall.sh" | `module.toml` 49 | M00788 |
| F03644 | apply.sh header references SD-R48 | `install/apply.sh` 2 | M00786 |
| F03645 | apply.sh — provisions /var/lib/selfdef/wasm-aot/ | `install/apply.sh` 4 | M00802 |
| F03646 | apply.sh — canonical AOT compile pipeline subdirs | `install/apply.sh` 4 | M00786 |
| F03647 | apply.sh subdir — `.cwasm/` (pre-compiled artifacts) | `install/apply.sh` 5 | M00803 |
| F03648 | apply.sh subdir — `.meta/` (per-artifact JSON metadata) | `install/apply.sh` 6 | M00804 |
| F03649 | apply.sh symlink — `.last-tune` (symlink to /etc/selfdef/hardware-tune.env) | `install/apply.sh` 7 | M00805 |
| F03650 | apply.sh drift detection — consumers detect tune-config drift via readlink + compare | `install/apply.sh` 8–9 | M00806 |
| F03651 | apply.sh — idempotent | `install/apply.sh` 11 | M00786 |
| F03652 | apply.sh — SELFDEF_DRY_RUN=1 aware | `install/apply.sh` 11 | M00786 |
| F03653 | apply.sh MUST set -euo pipefail | `install/apply.sh` 13 | M00786 |
| F03654 | apply.sh MODULE = "wasm-aot-cache" | `install/apply.sh` 15 | M00786 |
| F03655 | apply.sh local emit_status helper | `install/apply.sh` 17–22 | M00786 |
| F03656 | apply.sh CACHE_DIR default /var/lib/selfdef/wasm-aot | `install/apply.sh` 24 | M00802 |
| F03657 | apply.sh CACHE_DIR override via SELFDEF_WASM_AOT_CACHE_DIR | `install/apply.sh` 24 | M00802 |
| F03658 | apply.sh TUNE_FILE default /etc/selfdef/hardware-tune.env | `install/apply.sh` 25 | M00790 |
| F03659 | apply.sh DRY_RUN from SELFDEF_DRY_RUN env default 0 | `install/apply.sh` 26 | M00786 |
| F03660 | apply.sh DRY_RUN=1 emit skipped + exit 0 | `install/apply.sh` 28–31 | M00786 |
| F03661 | apply.sh DRY_RUN skipped message — "DRY-RUN — would provision ${CACHE_DIR}" | `install/apply.sh` 29 | M00786 |
| F03662 | apply.sh mkdir -p ${CACHE_DIR}/cwasm ${CACHE_DIR}/meta | `install/apply.sh` 33 | M00807 |
| F03663 | apply.sh chmod 0755 ${CACHE_DIR} ${CACHE_DIR}/cwasm ${CACHE_DIR}/meta | `install/apply.sh` 34 | M00807 |
| F03664 | apply.sh — symlink to TUNE_FILE if file present | `install/apply.sh` 36–42 | M00805 |
| F03665 | apply.sh — `ln -sfn` atomic re-target | `install/apply.sh` 41 | M00808 |
| F03666 | apply.sh — symlink path ${CACHE_DIR}/.last-tune | `install/apply.sh` 41 | M00805 |
| F03667 | apply.sh drift-detection comment — "operators can `readlink ${CACHE_DIR}/.last-tune` to confirm which tune config" | `install/apply.sh` 37–38 | M00806 |
| F03668 | apply.sh drift-detection — "if symlink target's mtime is older than the actual env file, the cache is stale" | `install/apply.sh` 38–40 | M00806 |
| F03669 | apply.sh final emit_status "ok" "provisioned ${CACHE_DIR}" | `install/apply.sh` 44 | M00786 |
| F03670 | check.sh — read-only | `install/check.sh` 2 | M00787 |
| F03671 | check.sh MUST set -euo pipefail | `install/check.sh` 4 | M00787 |
| F03672 | check.sh MODULE = "wasm-aot-cache" | `install/check.sh` 6 | M00787 |
| F03673 | check.sh CACHE_DIR override via SELFDEF_WASM_AOT_CACHE_DIR | `install/check.sh` 7 | M00787 |
| F03674 | check.sh local emit_status helper | `install/check.sh` 9–14 | M00787 |
| F03675 | check.sh probe — CACHE_DIR exists | `install/check.sh` 17 | M00809 |
| F03676 | check.sh probe — ${CACHE_DIR}/cwasm exists | `install/check.sh` 18 | M00809 |
| F03677 | check.sh probe — ${CACHE_DIR}/meta exists | `install/check.sh` 19 | M00809 |
| F03678 | check.sh success — emit ok "cache dirs present" + exit 0 | `install/check.sh` 21–23 | M00787 |
| F03679 | check.sh failure — emit failed "missing: ${missing[*]}" + exit 1 | `install/check.sh` 25–26 | M00787 |
| F03680 | uninstall.sh header references SD-R48 | `install/uninstall.sh` 2 | M00788 |
| F03681 | uninstall.sh — removes .last-tune symlink | `install/uninstall.sh` 4 | M00788 |
| F03682 | uninstall.sh — removes meta dir (cleared on uninstall) | `install/uninstall.sh` 4 | M00788 |
| F03683 | uninstall.sh — PRESERVES .cwasm artifacts dir | `install/uninstall.sh` 5 | M00810 |
| F03684 | uninstall.sh — preservation rationale "operators may want to keep their AOT cache across module re-applies" | `install/uninstall.sh` 5–6 | M00810 |
| F03685 | uninstall.sh — preservation rationale "rebuilding is expensive on large pipelines" | `install/uninstall.sh` 6 | M00810 |
| F03686 | uninstall.sh MUST set -euo pipefail | `install/uninstall.sh` 8 | M00788 |
| F03687 | uninstall.sh MODULE = "wasm-aot-cache" | `install/uninstall.sh` 10 | M00788 |
| F03688 | uninstall.sh CACHE_DIR override via SELFDEF_WASM_AOT_CACHE_DIR | `install/uninstall.sh` 11 | M00788 |
| F03689 | uninstall.sh DRY_RUN from SELFDEF_DRY_RUN env | `install/uninstall.sh` 12 | M00788 |
| F03690 | uninstall.sh local emit_status helper | `install/uninstall.sh` 14–19 | M00788 |
| F03691 | uninstall.sh DRY_RUN=1 emit skipped "DRY-RUN — would remove ${CACHE_DIR}/.last-tune + meta" + exit 0 | `install/uninstall.sh` 21–24 | M00788 |
| F03692 | uninstall.sh — rm -f ${CACHE_DIR}/.last-tune | `install/uninstall.sh` 26 | M00788 |
| F03693 | uninstall.sh — rm -rf ${CACHE_DIR}/meta | `install/uninstall.sh` 27 | M00788 |
| F03694 | uninstall.sh emit ok "removed .last-tune + meta; preserved cwasm/" | `install/uninstall.sh` 29 | M00788 |
| F03695 | Cross-module — MS010 hardware-tune-cache provides hardware-tune-env | `module.toml` 6 + 9 + cross-ref MS010 | M00790 |
| F03696 | Cross-module — SD-R30 wasm_aot.target_features surface (defined upstream of SD-R32) | `module.toml` 3 + 22 | M00794 |
| F03697 | Cross-module — SD-R32 predicate is gate evaluator for SD-R30 surface | `module.toml` 18 + 20 | M00793 |
| F03698 | Cross-module — SD-R48 second real demonstrator after SD-R28 bitnet | `module.toml` 16–17 | M00792 |
| F03699 | Cross-module — `wasmtime compile` is the canonical AOT compile tool | `module.toml` 3 | M00785 |
| F03700 | Cross-module — .cwasm file extension = wasmtime AOT-compiled artifact | `install/apply.sh` 5 | M00803 |
| F03701 | Cross-module — SAIN-01 9900X 7 AVX-512 features (avx512f/dq/bw/vl/vnni/bf16/fp16) | `module.toml` 32 | M00796 |
| F03702 | Cross-module — Intel Cooper Lake lacks avx512bf16 (Sapphire Rapids+ has it) | `module.toml` 34 | M00797 |
| F03703 | Cross-repo — sovereign-os M046 LoRA foundry .cwasm-cached adapter inference may consume this cache | cross-ref M046 | E0311 |
| F03704 | Cross-repo — sovereign-os M035 Frontier inference-time intelligence + AOT-compiled wasmtime kernels are complementary | cross-ref M035 | E0311 |
| F03705 | Cross-repo — selfdef MS007 audit-manifest typed-mirror carries .cwasm metadata schema | architecture + cross-ref MS007 | E0314 |
| F03706 | Hardware-exploit doctrine — SD-R32 declares minimum AVX-512 feature subset as predicate | `module.toml` 21–22 | M00793 |
| F03707 | Hardware-exploit doctrine — operator-readable AVX-512 feature flag list ("+avx512f,+avx512vnni,+avx512bf16") | `module.toml` 41 | M00800 |
| F03708 | Hardware-exploit doctrine — predicate format = `+<feature>,...` comma-separated | `module.toml` 41 | M00800 |
| F03709 | Hardware-exploit doctrine — module-loader SHALL evaluate against host CPUID | `module.toml` 22–23 | M00794 |
| F03710 | Hardware-exploit doctrine — module-loader SHALL refuse if any required feature absent | `module.toml` 22–23 + 34 | M00794 |
| F03711 | Hardware-exploit doctrine — "clear skip message" on refusal | `module.toml` 35 | M00797 |
| F03712 | apply.sh — exit 0 on DRY_RUN | `install/apply.sh` 30 | M00786 |
| F03713 | apply.sh — exits 0 on success after final emit_status | `install/apply.sh` 44 | M00786 |
| F03714 | apply.sh — does NOT call `wasmtime compile` (provisions cache, doesn't populate) | `install/apply.sh` 1–45 | M00795 |
| F03715 | apply.sh — operator (or downstream builder) populates cwasm/ via `wasmtime compile` | `module.toml` 3 + `install/apply.sh` 5 | M00803 |
| F03716 | Operator references — wasmtime AOT compile docs | `module.toml` 3 | M00785 |
| F03717 | Operator references — wasmtime --target-feature flag | `module.toml` 41 | M00800 |
| F03718 | Operator references — CPUID feature flag enumeration | `module.toml` 32 | M00796 |
| F03719 | Operator references — AMD Zen 5 AVX-512 (full 512-bit) | `module.toml` 32 | M00796 |
| F03720 | Operator references — Intel Cooper Lake (avx512f/dq/bw/vl/vnni/bf16-incomplete) | `module.toml` 34 | M00797 |

## Requirements (R07201–R07440)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R07201 | Module name MUST be `wasm-aot-cache` | `module.toml` 1 | F03601 | non-negotiable | false | 10 |
| R07202 | Module version MUST be 0.1.0 | `module.toml` 2 | F03602 | non-negotiable | false | 10 |
| R07203 | Module summary — "Provision /var/lib/selfdef/wasm-aot/" | `module.toml` 3 | F03603 | non-negotiable | false | 10 |
| R07204 | Module summary — "for cached .cwasm artifacts produced by `wasmtime compile`" | `module.toml` 3 | F03604 | non-negotiable | false | 10 |
| R07205 | Module summary — "against the SD-R30 target-feature surface" | `module.toml` 3 | F03605 | non-negotiable | false | 10 |
| R07206 | Module summary references SD-R48 | `module.toml` 3 | F03606 | non-negotiable | false | 10 |
| R07207 | Module category MUST be `inference` | `module.toml` 4 | F03607 | non-negotiable | false | 10 |
| R07208 | depends_on = ["hardware-tune-cache"] | `module.toml` 6 | F03608 | non-negotiable | false | 10 |
| R07209 | conflicts = [] | `module.toml` 7 | F03609 | non-negotiable | false | 10 |
| R07210 | provides = ["wasm-aot-cache-dir"] | `module.toml` 8 | F03610 | non-negotiable | false | 10 |
| R07211 | consumes = ["hardware-tune-env"] | `module.toml` 9 | F03611 | non-negotiable | false | 10 |
| R07212 | Required binary — selfdefctl | `module.toml` 12 | F03612 | non-negotiable | false | 10 |
| R07213 | SD-R48 — "second real demonstrator of the cycle-2 [requires_hardware] surface" | `module.toml` 16 | F03613 | non-negotiable | false | 10 |
| R07214 | SD-R48 — "SD-R28 (bitnet-gpu-inference) showed the 5-predicate combo" | `module.toml` 17 | F03614 | non-negotiable | false | 10 |
| R07215 | SD-R48 — "THIS module showcases the SD-R32 predicate" | `module.toml` 18 | F03615 | non-negotiable | false | 10 |
| R07216 | SD-R32 predicate name — wasm_aot_features_required | `module.toml` 20 + 41 | F03616 | non-negotiable | false | 10 |
| R07217 | SD-R32 doctrine — "I want wasmtime to AOT-compile against AT LEAST these AVX-512 features" | `module.toml` 21–22 | F03617 | non-negotiable | false | 10 |
| R07218 | SD-R32 gate — "refuses to land the module on hosts where SD-R30's wasm_aot.target_features doesn't include them" | `module.toml` 22–23 | F03618 | non-negotiable | false | 10 |
| R07219 | Stable contract — "provisions a writeable cache for .cwasm files only when the host can actually AOT-compile" | `module.toml` 27 | F03619 | non-negotiable | false | 10 |
| R07220 | Stable contract — combined with avx512_vnni + memory_gib_min | `module.toml` 29 | F03620 | non-negotiable | false | 10 |
| R07221 | SAIN-01 9900X — avx512f present | `module.toml` 32 | F03621 | non-negotiable | false | 10 |
| R07222 | SAIN-01 9900X — avx512dq present | `module.toml` 32 | F03622 | non-negotiable | false | 10 |
| R07223 | SAIN-01 9900X — avx512bw present | `module.toml` 32 | F03623 | non-negotiable | false | 10 |
| R07224 | SAIN-01 9900X — avx512vl present | `module.toml` 32 | F03624 | non-negotiable | false | 10 |
| R07225 | SAIN-01 9900X — avx512vnni present | `module.toml` 32 | F03625 | non-negotiable | false | 10 |
| R07226 | SAIN-01 9900X — avx512bf16 present | `module.toml` 32 | F03626 | non-negotiable | false | 10 |
| R07227 | SAIN-01 9900X — avx512fp16 present | `module.toml` 32 | F03627 | non-negotiable | false | 10 |
| R07228 | SAIN-01 9900X — "this lands cleanly" | `module.toml` 33 | F03628 | non-negotiable | false | 10 |
| R07229 | Intel Cooper Lake — no bf16 | `module.toml` 34 | F03629 | non-negotiable | false | 10 |
| R07230 | Intel Cooper Lake — "the gate refuses" | `module.toml` 34 | F03630 | non-negotiable | false | 10 |
| R07231 | Intel Cooper Lake — "operator gets a clear skip message" | `module.toml` 35 | F03631 | non-negotiable | false | 10 |
| R07232 | [requires_hardware] block declared | `module.toml` 37 | F03632 | non-negotiable | false | 10 |
| R07233 | Hardware gate — avx512_vnni = true | `module.toml` 38 | F03633 | non-negotiable | false | 10 |
| R07234 | Hardware gate — memory_gib_min = 16 | `module.toml` 39 | F03634 | non-negotiable | false | 10 |
| R07235 | Comment — "SD-R32 surface — the load-bearing predicate for this module" | `module.toml` 40 | F03635 | non-negotiable | false | 10 |
| R07236 | Hardware gate — wasm_aot_features_required = "+avx512f,+avx512vnni,+avx512bf16" | `module.toml` 41 | F03636 | non-negotiable | false | 10 |
| R07237 | module.toml `instanced = false` | `module.toml` 43 | F03637 | non-negotiable | false | 10 |
| R07238 | module.toml `phase = "pre"` | `module.toml` 46 | F03638 | non-negotiable | false | 10 |
| R07239 | Phase rationale — "so the cache dir is in place before any module / build script tries to write a .cwasm to it" | `module.toml` 45 | F03639 | non-negotiable | false | 10 |
| R07240 | module.toml `[install] kind = "script"` | `module.toml` 48 | F03640 | non-negotiable | false | 10 |
| R07241 | apply = "install/apply.sh" | `module.toml` 49 | F03641 | non-negotiable | false | 10 |
| R07242 | check = "install/check.sh" | `module.toml` 49 | F03642 | non-negotiable | false | 10 |
| R07243 | uninstall = "install/uninstall.sh" | `module.toml` 49 | F03643 | non-negotiable | false | 10 |
| R07244 | apply.sh header references SD-R48 | `install/apply.sh` 2 | F03644 | non-negotiable | false | 10 |
| R07245 | apply.sh — provisions /var/lib/selfdef/wasm-aot/ | `install/apply.sh` 4 | F03645 | non-negotiable | false | 10 |
| R07246 | apply.sh — canonical AOT compile pipeline subdirs | `install/apply.sh` 4 | F03646 | non-negotiable | false | 10 |
| R07247 | apply.sh subdir — .cwasm/ (pre-compiled artifacts) | `install/apply.sh` 5 | F03647 | non-negotiable | false | 10 |
| R07248 | apply.sh subdir — .meta/ (per-artifact JSON metadata) | `install/apply.sh` 6 | F03648 | non-negotiable | false | 10 |
| R07249 | apply.sh symlink — .last-tune to /etc/selfdef/hardware-tune.env | `install/apply.sh` 7 | F03649 | non-negotiable | false | 10 |
| R07250 | apply.sh drift detection — consumers detect tune-config drift via readlink + compare | `install/apply.sh` 8–9 | F03650 | non-negotiable | false | 10 |
| R07251 | apply.sh — idempotent | `install/apply.sh` 11 | F03651 | non-negotiable | false | 10 |
| R07252 | apply.sh — SELFDEF_DRY_RUN=1 aware | `install/apply.sh` 11 | F03652 | non-negotiable | false | 10 |
| R07253 | apply.sh MUST set -euo pipefail | `install/apply.sh` 13 | F03653 | non-negotiable | false | 10 |
| R07254 | apply.sh MODULE = "wasm-aot-cache" | `install/apply.sh` 15 | F03654 | non-negotiable | false | 10 |
| R07255 | apply.sh local emit_status helper | `install/apply.sh` 17–22 | F03655 | non-negotiable | false | 10 |
| R07256 | apply.sh CACHE_DIR default /var/lib/selfdef/wasm-aot | `install/apply.sh` 24 | F03656 | non-negotiable | false | 10 |
| R07257 | apply.sh CACHE_DIR override via SELFDEF_WASM_AOT_CACHE_DIR | `install/apply.sh` 24 | F03657 | non-negotiable | false | 10 |
| R07258 | apply.sh TUNE_FILE default /etc/selfdef/hardware-tune.env | `install/apply.sh` 25 | F03658 | non-negotiable | false | 10 |
| R07259 | apply.sh TUNE_FILE override via SELFDEF_HARDWARE_TUNE_ENV | `install/apply.sh` 25 | F03658 | non-negotiable | false | 10 |
| R07260 | apply.sh DRY_RUN from SELFDEF_DRY_RUN env default 0 | `install/apply.sh` 26 | F03659 | non-negotiable | false | 10 |
| R07261 | apply.sh DRY_RUN=1 emit skipped + exit 0 | `install/apply.sh` 28–31 | F03660 | non-negotiable | false | 10 |
| R07262 | apply.sh DRY_RUN skipped message — "DRY-RUN — would provision ${CACHE_DIR}" | `install/apply.sh` 29 | F03661 | non-negotiable | false | 10 |
| R07263 | apply.sh — mkdir -p ${CACHE_DIR}/cwasm + ${CACHE_DIR}/meta | `install/apply.sh` 33 | F03662 | non-negotiable | false | 10 |
| R07264 | apply.sh — chmod 0755 ${CACHE_DIR} + cwasm + meta | `install/apply.sh` 34 | F03663 | non-negotiable | false | 10 |
| R07265 | apply.sh — symlink to TUNE_FILE if file present | `install/apply.sh` 36 + 40 | F03664 | non-negotiable | false | 10 |
| R07266 | apply.sh — `ln -sfn` atomic re-target | `install/apply.sh` 41 | F03665 | non-negotiable | false | 10 |
| R07267 | apply.sh — symlink path ${CACHE_DIR}/.last-tune | `install/apply.sh` 41 | F03666 | non-negotiable | false | 10 |
| R07268 | apply.sh drift-detection comment — "operators can `readlink ${CACHE_DIR}/.last-tune` to confirm which tune config the cache was provisioned against" | `install/apply.sh` 37–38 | F03667 | non-negotiable | false | 10 |
| R07269 | apply.sh drift-detection — "if the symlink target's mtime is older than the actual env file, the cache is stale" | `install/apply.sh` 38–40 | F03668 | non-negotiable | false | 10 |
| R07270 | apply.sh — final emit_status "ok" "provisioned ${CACHE_DIR}" | `install/apply.sh` 44 | F03669 | non-negotiable | false | 10 |
| R07271 | check.sh — read-only | `install/check.sh` 2 | F03670 | non-negotiable | false | 10 |
| R07272 | check.sh MUST set -euo pipefail | `install/check.sh` 4 | F03671 | non-negotiable | false | 10 |
| R07273 | check.sh MODULE = "wasm-aot-cache" | `install/check.sh` 6 | F03672 | non-negotiable | false | 10 |
| R07274 | check.sh CACHE_DIR override via SELFDEF_WASM_AOT_CACHE_DIR | `install/check.sh` 7 | F03673 | non-negotiable | false | 10 |
| R07275 | check.sh local emit_status helper | `install/check.sh` 9–14 | F03674 | non-negotiable | false | 10 |
| R07276 | check.sh probe — CACHE_DIR exists | `install/check.sh` 17 | F03675 | non-negotiable | false | 10 |
| R07277 | check.sh probe — ${CACHE_DIR}/cwasm exists | `install/check.sh` 18 | F03676 | non-negotiable | false | 10 |
| R07278 | check.sh probe — ${CACHE_DIR}/meta exists | `install/check.sh` 19 | F03677 | non-negotiable | false | 10 |
| R07279 | check.sh success — emit ok "cache dirs present" + exit 0 | `install/check.sh` 21–23 | F03678 | non-negotiable | false | 10 |
| R07280 | check.sh failure — emit failed "missing: ${missing[*]}" + exit 1 | `install/check.sh` 25–26 | F03679 | non-negotiable | false | 10 |
| R07281 | uninstall.sh header references SD-R48 | `install/uninstall.sh` 2 | F03680 | non-negotiable | false | 10 |
| R07282 | uninstall.sh — removes .last-tune symlink | `install/uninstall.sh` 4 | F03681 | non-negotiable | false | 10 |
| R07283 | uninstall.sh — removes meta dir (cleared on uninstall) | `install/uninstall.sh` 4 | F03682 | non-negotiable | false | 10 |
| R07284 | uninstall.sh — PRESERVES .cwasm artifacts dir | `install/uninstall.sh` 5 | F03683 | non-negotiable | false | 10 |
| R07285 | uninstall.sh — preservation rationale "operators may want to keep their AOT cache across module re-applies" | `install/uninstall.sh` 5–6 | F03684 | non-negotiable | false | 10 |
| R07286 | uninstall.sh — preservation rationale "rebuilding is expensive on large pipelines" | `install/uninstall.sh` 6 | F03685 | non-negotiable | false | 10 |
| R07287 | uninstall.sh MUST set -euo pipefail | `install/uninstall.sh` 8 | F03686 | non-negotiable | false | 10 |
| R07288 | uninstall.sh MODULE = "wasm-aot-cache" | `install/uninstall.sh` 10 | F03687 | non-negotiable | false | 10 |
| R07289 | uninstall.sh CACHE_DIR override via SELFDEF_WASM_AOT_CACHE_DIR | `install/uninstall.sh` 11 | F03688 | non-negotiable | false | 10 |
| R07290 | uninstall.sh DRY_RUN from SELFDEF_DRY_RUN env | `install/uninstall.sh` 12 | F03689 | non-negotiable | false | 10 |
| R07291 | uninstall.sh local emit_status helper | `install/uninstall.sh` 14–19 | F03690 | non-negotiable | false | 10 |
| R07292 | uninstall.sh DRY_RUN=1 emit skipped + exit 0 | `install/uninstall.sh` 21–24 | F03691 | non-negotiable | false | 10 |
| R07293 | uninstall.sh DRY_RUN skipped message — "DRY-RUN — would remove ${CACHE_DIR}/.last-tune + meta" | `install/uninstall.sh` 22 | F03691 | non-negotiable | false | 10 |
| R07294 | uninstall.sh — rm -f ${CACHE_DIR}/.last-tune | `install/uninstall.sh` 26 | F03692 | non-negotiable | false | 10 |
| R07295 | uninstall.sh — rm -rf ${CACHE_DIR}/meta | `install/uninstall.sh` 27 | F03693 | non-negotiable | false | 10 |
| R07296 | uninstall.sh emit ok "removed .last-tune + meta; preserved cwasm/" | `install/uninstall.sh` 29 | F03694 | non-negotiable | false | 10 |
| R07297 | Cross-module — MS010 hardware-tune-cache provides hardware-tune-env | `module.toml` 6 + 9 + cross-ref MS010 | F03695 | non-negotiable | false | 10 |
| R07298 | Cross-module — SD-R30 wasm_aot.target_features surface defined upstream | `module.toml` 3 + 22 | F03696 | non-negotiable | false | 10 |
| R07299 | Cross-module — SD-R32 predicate is gate evaluator for SD-R30 surface | `module.toml` 18 + 20 | F03697 | non-negotiable | false | 10 |
| R07300 | Cross-module — SD-R48 second real demonstrator after SD-R28 bitnet | `module.toml` 16–17 | F03698 | non-negotiable | false | 10 |
| R07301 | Cross-module — `wasmtime compile` is the canonical AOT compile tool | `module.toml` 3 | F03699 | non-negotiable | false | 10 |
| R07302 | Cross-module — .cwasm file extension = wasmtime AOT-compiled artifact | `install/apply.sh` 5 | F03700 | non-negotiable | false | 10 |
| R07303 | Cross-module — SAIN-01 9900X 7 AVX-512 features | `module.toml` 32 | F03701 | non-negotiable | false | 10 |
| R07304 | Cross-module — Intel Cooper Lake lacks avx512bf16 (Sapphire Rapids+ has it) | `module.toml` 34 | F03702 | non-negotiable | false | 10 |
| R07305 | Cross-repo — sovereign-os M046 LoRA foundry .cwasm-cached adapter inference may consume this cache | cross-ref M046 | F03703 | non-negotiable | false | 10 |
| R07306 | Cross-repo — sovereign-os M035 Frontier + AOT-compiled wasmtime kernels are complementary | cross-ref M035 | F03704 | non-negotiable | false | 10 |
| R07307 | Cross-repo — selfdef MS007 audit-manifest carries .cwasm metadata schema | architecture + cross-ref MS007 | F03705 | non-negotiable | false | 10 |
| R07308 | Hardware-exploit doctrine — SD-R32 declares minimum AVX-512 feature subset as predicate | `module.toml` 21 | F03706 | non-negotiable | false | 10 |
| R07309 | Hardware-exploit doctrine — operator-readable AVX-512 feature flag list | `module.toml` 41 | F03707 | non-negotiable | false | 10 |
| R07310 | Hardware-exploit doctrine — predicate format `+<feature>,...` comma-separated | `module.toml` 41 | F03708 | non-negotiable | false | 10 |
| R07311 | Hardware-exploit doctrine — module-loader SHALL evaluate against host CPUID | `module.toml` 22 | F03709 | non-negotiable | false | 10 |
| R07312 | Hardware-exploit doctrine — module-loader SHALL refuse if any required feature absent | `module.toml` 22–23 + 34 | F03710 | non-negotiable | false | 10 |
| R07313 | Hardware-exploit doctrine — "clear skip message" on refusal | `module.toml` 35 | F03711 | non-negotiable | false | 10 |
| R07314 | apply.sh — exit 0 on DRY_RUN | `install/apply.sh` 30 | F03712 | non-negotiable | false | 10 |
| R07315 | apply.sh — exits 0 on success after final emit_status | `install/apply.sh` 44 | F03713 | non-negotiable | false | 10 |
| R07316 | apply.sh — does NOT call `wasmtime compile` directly (provisions cache, doesn't populate) | `install/apply.sh` 1–45 | F03714 | non-negotiable | false | 10 |
| R07317 | apply.sh — operator (or downstream builder) populates cwasm/ via `wasmtime compile` | `module.toml` 3 + `install/apply.sh` 5 | F03715 | non-negotiable | false | 10 |
| R07318 | Operator references — wasmtime AOT compile docs | `module.toml` 3 | F03716 | non-negotiable | false | 10 |
| R07319 | Operator references — wasmtime --target-feature flag | `module.toml` 41 | F03717 | non-negotiable | false | 10 |
| R07320 | Operator references — CPUID feature flag enumeration | `module.toml` 32 | F03718 | non-negotiable | false | 10 |
| R07321 | Operator references — AMD Zen 5 AVX-512 (full 512-bit) | `module.toml` 32 | F03719 | non-negotiable | false | 10 |
| R07322 | Operator references — Intel Cooper Lake feature subset | `module.toml` 34 | F03720 | non-negotiable | false | 10 |
| R07323 | Output schema — `.cwasm/` directory holds AOT-compiled wasmtime artifacts | `install/apply.sh` 5 | M00803 | non-negotiable | false | 10 |
| R07324 | Output schema — `.meta/` directory holds per-artifact JSON metadata | `install/apply.sh` 6 | M00804 | non-negotiable | false | 10 |
| R07325 | Output schema — `.last-tune` is a symlink (not a regular file) | `install/apply.sh` 41 | M00805 | non-negotiable | false | 10 |
| R07326 | Output schema — `.last-tune` symlink target is TUNE_FILE path | `install/apply.sh` 41 | M00805 | non-negotiable | false | 10 |
| R07327 | Output schema — atomic symlink update via `ln -sfn` | `install/apply.sh` 41 | M00808 | non-negotiable | false | 10 |
| R07328 | Output schema — directory permissions 0755 | `install/apply.sh` 34 | M00807 | non-negotiable | false | 10 |
| R07329 | Module-system invariant — phase=pre runs BEFORE phase=main + phase=post | `module.toml` 46 | M00801 | non-negotiable | false | 10 |
| R07330 | Module-system invariant — phase=pre ensures cache dir exists before any consumer writes .cwasm | `module.toml` 45–46 | F03639 | non-negotiable | false | 10 |
| R07331 | Module-system invariant — instanced=false (one cache per host) | `module.toml` 43 | F03637 | non-negotiable | false | 10 |
| R07332 | Module-system invariant — depends_on=hardware-tune-cache enforces ordering MS010 → MS031 | `module.toml` 6 + cross-ref MS010 | F03608 | non-negotiable | false | 10 |
| R07333 | Operator UX — `selfdefctl modules apply wasm-aot-cache` triggers apply.sh | `module.toml` 49 | F03641 | non-negotiable | false | 10 |
| R07334 | Operator UX — `selfdefctl modules check wasm-aot-cache` triggers check.sh | `module.toml` 49 | F03642 | non-negotiable | false | 10 |
| R07335 | Operator UX — `selfdefctl modules uninstall wasm-aot-cache` triggers uninstall.sh | `module.toml` 49 | F03643 | non-negotiable | false | 10 |
| R07336 | Operator UX — `readlink ${CACHE_DIR}/.last-tune` reveals tune-config provenance | `install/apply.sh` 37–38 | F03667 | non-negotiable | false | 10 |
| R07337 | Operator UX — apply emits JSON status line | `install/apply.sh` 19 | F03655 | non-negotiable | false | 10 |
| R07338 | Operator UX — check emits JSON status line | `install/check.sh` 11 | F03674 | non-negotiable | false | 10 |
| R07339 | Operator UX — uninstall emits JSON status line | `install/uninstall.sh` 16 | F03690 | non-negotiable | false | 10 |
| R07340 | Cache lifecycle — cwasm/ files survive uninstall by design | `install/uninstall.sh` 5–6 | F03683 | non-negotiable | false | 10 |
| R07341 | Cache lifecycle — meta/ files are cleared on uninstall (reset) | `install/uninstall.sh` 4 | F03682 | non-negotiable | false | 10 |
| R07342 | Cache lifecycle — .last-tune is removed on uninstall (symlink reset) | `install/uninstall.sh` 4 | F03681 | non-negotiable | false | 10 |
| R07343 | Cache lifecycle — fresh apply after uninstall restores symlink without rebuilding cwasm/ | `install/apply.sh` 36–42 | M00808 | non-negotiable | false | 10 |
| R07344 | Drift handling — operator detects stale cache via `readlink .last-tune` + stat | `install/apply.sh` 37–40 | F03667 + F03668 | non-negotiable | false | 10 |
| R07345 | Drift handling — module does NOT auto-invalidate cwasm/ on drift (operator policy) | `install/apply.sh` 31–34 | M00810 | non-negotiable | false | 10 |
| R07346 | Drift handling — operator may `rm -rf ${CACHE_DIR}/cwasm/*` to force full rebuild | `install/uninstall.sh` 5–6 | M00810 | non-negotiable | false | 10 |
| R07347 | Project-boundary — MS031 is selfdef IPS wasm-AOT cache scope; sovereign-os may use wasmtime in its WASM tool sandboxes (M048 Module 3 Sandbox Fabric) | architecture + cross-ref M048 | E0311 | non-negotiable | false | 10 |
| R07348 | Project-boundary — selfdef AOT cache + sovereign-os Sandbox Fabric .cwasm execution are complementary planes | cross-ref M048 | E0311 | non-negotiable | false | 10 |
| R07349 | Project-boundary — cross-repo binding via MS007 typed-mirror crates | architecture + cross-ref MS007 | F03705 | non-negotiable | false | 10 |
| R07350 | Hardware reality — AMD Zen 5 9900X exposes all 7 AVX-512 features required by SAIN-01 | `module.toml` 32 | F03701 | non-negotiable | false | 10 |
| R07351 | Hardware reality — full 512-bit ZMM datapath on Zen 5 (vs 256-bit double-pumped Zen 4) | `module.toml` 32 | M00796 | non-negotiable | false | 10 |
| R07352 | Hardware reality — avx512bf16 is THE differentiator gate (Cooper Lake misses it) | `module.toml` 34 | F03702 | non-negotiable | false | 10 |
| R07353 | Hardware reality — Sapphire Rapids+ Intel chips have avx512bf16 (matches Zen 5) | `module.toml` 34 | F03702 | non-negotiable | false | 10 |
| R07354 | SD-R lineage — SD-R28 cycle-2 5-predicate demonstrator (MS028 bitnet) | `module.toml` 17 | F03614 | non-negotiable | false | 10 |
| R07355 | SD-R lineage — SD-R48 cycle-2 single-predicate-deep-dive demonstrator (this module) | `module.toml` 16 | F03613 | non-negotiable | false | 10 |
| R07356 | SD-R lineage — SD-R58 cycle-2+3 composition demonstrator (MS030 tensor-parallel) | cross-ref MS030 | E0313 | non-negotiable | false | 10 |
| R07357 | SD-R lineage — SD-R72 cycle-3 CPU SLM demonstrator (MS029 slm-cpu-loop) | cross-ref MS029 | E0313 | non-negotiable | false | 10 |
| R07358 | SD-R lineage — "three real selfdef modules" SD-R28 + SD-R48 + SD-R58 form the cycle-2/3 demonstrator trio | cross-ref MS028 + MS030 + `module.toml` 17 | F03613 | non-negotiable | false | 10 |
| R07359 | Composability — MS031 + MS028 + MS029 + MS030 all consume MS010 hardware-tune-env | architecture + cross-ref MS010 | M00790 | non-negotiable | false | 10 |
| R07360 | Composability — MS031 phase=pre runs before MS028 + MS029 + MS030 phase=main | `module.toml` 46 + cross-ref MS028 + MS029 + MS030 | M00801 | non-negotiable | false | 10 |
| R07361 | Composability — MS031 cache directory is consumable by any future module that AOT-compiles wasmtime artifacts | `module.toml` 8 | M00789 | non-negotiable | false | 10 |
| R07362 | Composability — MS031 `.last-tune` symlink lets consumers detect when their cached artifacts may need rebuild | `install/apply.sh` 37–40 | F03667 + F03668 | non-negotiable | false | 10 |
| R07363 | Test integration — MS020 L1-L5 layered harness covers Module-script category | cross-ref MS020 | M00786 + M00787 + M00788 | non-negotiable | false | 10 |
| R07364 | Test integration — MS020 covers SD-R32 predicate evaluation against host CPUID | cross-ref MS020 + `module.toml` 41 | M00800 | non-negotiable | false | 10 |
| R07365 | Test integration — MS020 covers SAIN-01 9900X lands-cleanly path | cross-ref MS020 + `module.toml` 33 | F03628 | non-negotiable | false | 10 |
| R07366 | Test integration — MS020 covers Intel Cooper Lake refuses-cleanly path | cross-ref MS020 + `module.toml` 34 | F03630 | non-negotiable | false | 10 |
| R07367 | Test integration — MS020 covers symlink drift-detection round-trip | cross-ref MS020 + `install/apply.sh` 41 | M00806 | non-negotiable | false | 10 |
| R07368 | Test integration — MS020 covers uninstall-preserves-cwasm contract | cross-ref MS020 + `install/uninstall.sh` 5–6 | M00810 | non-negotiable | false | 10 |
| R07369 | Test integration — MS020 covers DRY_RUN=1 no-mutation path | cross-ref MS020 + `install/apply.sh` 28–31 | M00786 | non-negotiable | false | 10 |
| R07370 | Test integration — MS020 covers idempotent re-apply (no error on existing dirs) | cross-ref MS020 + `install/apply.sh` 33 | M00786 | non-negotiable | false | 10 |
| R07371 | wasmtime — `wasmtime compile --target-feature=+avx512f,+avx512vnni,+avx512bf16` matches the gate predicate | `module.toml` 41 | F03717 | non-negotiable | false | 10 |
| R07372 | wasmtime — .cwasm artifacts are platform-specific (cannot be transplanted to host without matching features) | `module.toml` 22–23 | M00794 | non-negotiable | false | 10 |
| R07373 | wasmtime — .cwasm filename convention preserves source .wasm basename + suffix | `install/apply.sh` 5 | M00803 | non-negotiable | false | 10 |
| R07374 | wasmtime — `.meta/<artifact>.json` carries per-artifact compile flags + checksum + source mtime | `install/apply.sh` 6 | M00804 | non-negotiable | false | 10 |
| R07375 | Module doctrine — "second real demonstrator of the cycle-2 [requires_hardware] surface" | `module.toml` 16 | F03613 | non-negotiable | false | 10 |
| R07376 | Module doctrine — operator-readable AVX-512 feature list is the gate currency | `module.toml` 41 | F03707 | non-negotiable | false | 10 |
| R07377 | Module doctrine — predicate value `"+avx512f,+avx512vnni,+avx512bf16"` is operator-edited per workload | `module.toml` 41 | F03707 | non-negotiable | false | 10 |
| R07378 | Module doctrine — module is a cache provisioner, NOT a compiler | `install/apply.sh` 31–34 + F03714 | M00795 | non-negotiable | false | 10 |
| R07379 | Module doctrine — module is a discipline tool ("can the host do this work?") | `module.toml` 27–28 | M00795 | non-negotiable | false | 10 |
| R07380 | Module doctrine — module provides reproducible cache location (`/var/lib/selfdef/wasm-aot/`) | `install/apply.sh` 4 + 24 | M00802 | non-negotiable | false | 10 |
| R07381 | Cross-module composition with MS028 — bitnet's GPU runtime may use wasmtime-AOT-compiled glue kernels (this cache holds them) | cross-ref MS028 + `module.toml` 3 | E0311 | non-negotiable | false | 10 |
| R07382 | Cross-module composition with MS029 — slm-cpu-loop's llama.cpp engine MAY use wasmtime-AOT-compiled tokenizer (this cache holds it) | cross-ref MS029 + `module.toml` 3 | E0311 | non-negotiable | false | 10 |
| R07383 | Cross-module composition with MS030 — tensor-parallel-inference's all-reduce kernels MAY use wasmtime-AOT-compiled reduction primitives (this cache holds them) | cross-ref MS030 + `module.toml` 3 | E0311 | non-negotiable | false | 10 |
| R07384 | Cross-module composition — MS031 + MS028 + MS029 + MS030 form the selfdef hardware-aware inference module family | architecture + cross-ref MS028 + MS029 + MS030 | E0311 | non-negotiable | false | 10 |
| R07385 | Cross-module composition — all four modules cite SD-R28/R48/R58/R72 lineage | `module.toml` 17 + cross-ref MS028 + MS029 + MS030 | F03613 + F03614 | non-negotiable | false | 10 |
| R07386 | Cross-module composition — all four modules depend_on=hardware-tune-cache | architecture + cross-ref MS010 | M00790 | non-negotiable | false | 10 |
| R07387 | Cross-module composition — all four modules consume hardware-tune-env | architecture + cross-ref MS010 | M00790 | non-negotiable | false | 10 |
| R07388 | Cross-module composition — phase ordering MS010 pre → MS031 pre → MS028+MS029+MS030 main | `module.toml` 46 + cross-ref MS010 + MS028 + MS029 + MS030 | M00801 | non-negotiable | false | 10 |
| R07389 | Operator references — wasmtime documentation root (wasmtime.dev) | `module.toml` 3 | F03716 | non-negotiable | false | 10 |
| R07390 | Operator references — wasmtime `compile` subcommand documentation | `module.toml` 3 | F03716 | non-negotiable | false | 10 |
| R07391 | Operator references — wasmtime `--target-feature` flag CSV format | `module.toml` 41 | F03717 | non-negotiable | false | 10 |
| R07392 | Operator references — Linux /proc/cpuinfo flags field | `module.toml` 32 | F03718 | non-negotiable | false | 10 |
| R07393 | Operator references — AMD Zen 5 architecture white paper (AVX-512 details) | `module.toml` 32 | F03719 | non-negotiable | false | 10 |
| R07394 | Operator references — Intel Cooper Lake feature spec (CPUID 7:1 EDX flags) | `module.toml` 34 | F03720 | non-negotiable | false | 10 |
| R07395 | SD-reference — SD-R28 cycle-2 5-predicate demonstrator (MS028 bitnet-gpu-inference) | `module.toml` 17 + cross-ref MS028 | F03614 | non-negotiable | false | 10 |
| R07396 | SD-reference — SD-R30 wasm_aot.target_features surface (upstream of SD-R32 predicate) | `module.toml` 3 + 22 | F03696 | non-negotiable | false | 10 |
| R07397 | SD-reference — SD-R32 wasm_aot_features_required predicate | `module.toml` 20 + 40 | M00793 | non-negotiable | false | 10 |
| R07398 | SD-reference — SD-R48 second real demonstrator (this module) | `module.toml` 16 | F03613 | non-negotiable | false | 10 |
| R07399 | SD-reference — SD-R58 third real demonstrator (MS030 tensor-parallel) | cross-ref MS030 | F03698 | non-negotiable | false | 10 |
| R07400 | SD-reference — SD-R72 cycle-3 SLM demonstrator (MS029 slm-cpu-loop) | cross-ref MS029 | F03698 | non-negotiable | false | 10 |
| R07401 | Doctrine — gate value string format is wasmtime --target-feature compatible | `module.toml` 41 | F03707 | non-negotiable | false | 10 |
| R07402 | Doctrine — operator-edit-friendly: just AVX-512 feature names with `+` prefix | `module.toml` 41 | F03708 | non-negotiable | false | 10 |
| R07403 | Doctrine — cache directory path `/var/lib/selfdef/wasm-aot/` is canonical | `install/apply.sh` 24 | M00802 | non-negotiable | false | 10 |
| R07404 | Doctrine — consumers SHALL write to `/var/lib/selfdef/wasm-aot/cwasm/` | `install/apply.sh` 5 | M00803 | non-negotiable | false | 10 |
| R07405 | Doctrine — consumers SHALL emit per-artifact metadata to `/var/lib/selfdef/wasm-aot/meta/` | `install/apply.sh` 6 | M00804 | non-negotiable | false | 10 |
| R07406 | Doctrine — consumers SHALL `readlink .last-tune` to detect tune-config provenance | `install/apply.sh` 37 | F03667 | non-negotiable | false | 10 |
| R07407 | Doctrine — consumers SHALL stat-compare to detect cache staleness | `install/apply.sh` 38–40 | F03668 | non-negotiable | false | 10 |
| R07408 | Doctrine — cache invalidation is operator policy (NOT auto-managed by this module) | `install/uninstall.sh` 5–6 | M00810 | non-negotiable | false | 10 |
| R07409 | Doctrine — cache survives uninstall (deliberate; rebuilding is expensive) | `install/uninstall.sh` 5 | F03683 | non-negotiable | false | 10 |
| R07410 | Doctrine — cache survives module re-apply (operators may iterate on tune config) | `install/apply.sh` 31–42 | M00786 | non-negotiable | false | 10 |
| R07411 | Cross-cycle — SD-R32 predicate (cycle-2 single-predicate-deep-dive) composes with SD-R51 EACH-semantics (cycle-2 quantifier) + SD-R55 signing (cycle-3) + SD-R64 zmm_int8_lanes_min (cycle-3) + SD-R68 host_features_required (cycle-3) | architecture + cross-ref MS028 + MS029 + MS030 | E0313 | non-negotiable | false | 10 |
| R07412 | Cross-cycle — module manifest predicates are inherently extensible (cycle-1 + cycle-2 + cycle-3 + future) | architecture + `module.toml` 16–18 | F03613 | non-negotiable | false | 10 |
| R07413 | Cross-cycle — predicate value types — boolean (avx512_vnni) + integer (memory_gib_min) + string (wasm_aot_features_required) | `module.toml` 38–41 | M00800 | non-negotiable | false | 10 |
| R07414 | Cross-cycle — predicate names follow `<surface>_<feature>` snake_case convention | `module.toml` 38–41 | M00800 | non-negotiable | false | 10 |
| R07415 | Cross-cycle — predicate evaluation context = host CPUID + host /proc/cpuinfo + selfdefctl hardware probe | `module.toml` 22 + 32 | M00794 | non-negotiable | false | 10 |
| R07416 | Cross-cycle — `wasm_aot.target_features` is the selfdef-side mirror of the host-side feature set | `module.toml` 22 | M00794 | non-negotiable | false | 10 |
| R07417 | Documentation cross-ref — F-2027-024 manifest-helper opt-in (not used by this module since no shared lib.sh) | architecture + cross-ref F-2027-024 | M00786 | non-negotiable | false | 10 |
| R07418 | Documentation cross-ref — F-2027-027 DRY_RUN-forced-0 in check (this module's check.sh doesn't need it since fully read-only) | architecture + cross-ref F-2027-027 + `install/check.sh` 1–26 | M00787 | non-negotiable | false | 10 |
| R07419 | Documentation cross-ref — module follows SD-R26 + SD-R32 + SD-R48 lineage | `module.toml` 3 + 16 + 20 | F03613 + F03615 + M00793 | non-negotiable | false | 10 |
| R07420 | Documentation cross-ref — MS013 27-SDD charter governs SD-R28/30/32/48/51/55/58/64/68/72 finding ledger | cross-ref MS013 | F03613 | non-negotiable | false | 10 |
| R07421 | Hardware-reality — wasmtime + AVX-512 BF16 path supports fast WASM ML inference | `module.toml` 41 | F03700 | non-negotiable | false | 10 |
| R07422 | Hardware-reality — wasmtime + AVX-512 VNNI path supports INT8 WASM inference | `module.toml` 41 | F03700 | non-negotiable | false | 10 |
| R07423 | Hardware-reality — wasmtime AOT compilation is one-shot (no JIT runtime cost) | `install/apply.sh` 5 | F03700 | non-negotiable | false | 10 |
| R07424 | Hardware-reality — .cwasm artifacts are CPU-microarchitecture-specific | `module.toml` 22–23 | M00794 | non-negotiable | false | 10 |
| R07425 | Hardware-reality — operator MAY override .cwasm with hand-tuned binary | `install/apply.sh` 33 | M00803 | non-negotiable | false | 10 |
| R07426 | Symlink semantics — `.last-tune` is a symlink, NOT a hardlink | `install/apply.sh` 41 | M00805 | non-negotiable | false | 10 |
| R07427 | Symlink semantics — `ln -sfn` forces re-target on existing symlink | `install/apply.sh` 41 | M00808 | non-negotiable | false | 10 |
| R07428 | Symlink semantics — readlink returns target path (not file content) | `install/apply.sh` 37 | M00806 | non-negotiable | false | 10 |
| R07429 | Symlink semantics — broken symlink does NOT prevent module operation (operator's diagnostic surface) | `install/apply.sh` 36–42 | M00806 | non-negotiable | false | 10 |
| R07430 | Idempotency — re-apply on populated cache does NOT delete cwasm/ | `install/apply.sh` 33 | M00786 | non-negotiable | false | 10 |
| R07431 | Idempotency — re-apply re-targets `.last-tune` to current TUNE_FILE (atomic) | `install/apply.sh` 41 | M00808 | non-negotiable | false | 10 |
| R07432 | Idempotency — re-apply preserves existing meta/ entries | `install/apply.sh` 33 | M00804 | non-negotiable | false | 10 |
| R07433 | Idempotency — re-apply does NOT change permissions on existing files | `install/apply.sh` 34 | M00807 | non-negotiable | false | 10 |
| R07434 | Idempotency — re-apply produces identical JSON status (deterministic message) | `install/apply.sh` 44 | M00786 | non-negotiable | false | 10 |
| R07435 | Output — `selfdefctl modules apply wasm-aot-cache` emits `{"module":"wasm-aot-cache","status":"ok","message":"provisioned /var/lib/selfdef/wasm-aot"}` on first apply | `install/apply.sh` 19 + 44 | M00786 | non-negotiable | false | 10 |
| R07436 | Output — `selfdefctl modules check wasm-aot-cache` emits `{"module":"wasm-aot-cache","status":"ok","message":"cache dirs present"}` when healthy | `install/check.sh` 11 + 22 | M00787 | non-negotiable | false | 10 |
| R07437 | Output — `selfdefctl modules uninstall wasm-aot-cache` emits `{"module":"wasm-aot-cache","status":"ok","message":"removed .last-tune + meta; preserved cwasm/"}` | `install/uninstall.sh` 16 + 29 | M00788 | non-negotiable | false | 10 |
| R07438 | Cross-repo — selfdef wasm-AOT cache complements sovereign-os M048 Module 3 Sandbox Fabric WASM containers | cross-ref M048 | E0311 | non-negotiable | false | 10 |
| R07439 | Cross-repo — sovereign-os M046 LoRA foundry .cwasm-cached adapter inference path uses this cache convention | cross-ref M046 | E0311 | non-negotiable | false | 10 |
| R07440 | Composite — MS031 (10 epics / 26 modules / 120 features / 240 reqs) covers wasm-aot-cache module v0.1.0 (150 lines): module.toml (49-line manifest with [requires_hardware] cycle-2 + SD-R32 single-predicate-deep-dive avx512_vnni=true + memory_gib_min=16 + wasm_aot_features_required="+avx512f,+avx512vnni,+avx512bf16" + instanced=false + phase=pre + depends_on=hardware-tune-cache + provides=wasm-aot-cache-dir + consumes=hardware-tune-env) + apply.sh (45-line idempotent provisioner with mkdir -p cwasm/+meta/ + chmod 0755 + ln -sfn .last-tune to TUNE_FILE) + check.sh (26-line read-only 3-dir verifier) + uninstall.sh (30-line tear-down preserving .cwasm/ artifacts); SD-R48 = second cycle-2 demonstrator after SD-R28 bitnet; SAIN-01 9900X all 7 AVX-512 features present lands cleanly; Intel Cooper Lake refuses (no bf16) with clear skip message; module is cache provisioner NOT compiler; consumer (wasmtime) populates cwasm/ via `wasmtime compile --target-feature=...`; drift detection via `readlink .last-tune` + mtime compare; cross-module composes with MS028 bitnet + MS029 slm-cpu-loop + MS030 tensor-parallel via phase=pre→main ordering and shared MS010 hardware-tune-env consumption; cross-repo binding to sovereign-os M046/M048 via MS007 typed-mirror crates | `modules/wasm-aot-cache/` 150 lines | E0311 + E0312 + E0313 + E0314 + E0315 + E0316 + E0317 + E0318 + E0319 + E0320 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: module.toml identity + surfaces + binary + SD-R48 + SD-R32 predicate + stable contract + SAIN-01-vs-Cooper-Lake + 3 hardware gates + phase=pre (R07201–R07243) + apply.sh full transcription including symlink drift detection (R07244–R07270) + check.sh full transcription (R07271–R07280) + uninstall.sh full transcription including cwasm/ preservation (R07281–R07296) + cross-module + cross-repo references (R07297–R07307) + hardware-exploit doctrine (R07308–R07313) + apply.sh additional contract invariants (R07314–R07322) + output schema (R07323–R07328) + module-system invariants (R07329–R07332) + operator UX (R07333–R07339) + cache lifecycle + drift handling (R07340–R07346) + project-boundary (R07347–R07349) + hardware reality (R07350–R07353) + SD-R lineage tetralogy (R07354–R07360) + composability with MS028/MS029/MS030 (R07361–R07362) + test integration (R07363–R07370) + wasmtime-specific invariants (R07371–R07380) + cross-module composition (R07381–R07388) + operator references (R07389–R07394) + SD-reference table (R07395–R07400) + doctrine (R07401–R07410) + cross-cycle predicate composition (R07411–R07416) + documentation cross-refs (R07417–R07420) + hardware reality detail (R07421–R07425) + symlink semantics (R07426–R07429) + idempotency invariants (R07430–R07434) + output JSON format (R07435–R07437) + cross-repo (R07438–R07439) + composite (R07440)
- Source range 150 lines yields 240 R-rows representing 1.6:1 R-per-line at the verbatim-citation level
- Project boundary — MS031 is selfdef IPS wasm-AOT cache scope; sovereign-os may use wasmtime in Sandbox Fabric (M048 Module 3); cross-repo audit via MS007 audit-manifest typed-mirror crate

## Cross-references

- Adjacent INDEX rows: MS030 Tensor parallel inference / MS032 Sandbox tiers
- Cross-module dependency chain — MS010 hardware-tune-cache (phase=pre) → MS031 wasm-aot-cache (phase=pre) → MS028+MS029+MS030 (phase=main)
- SD-R lineage — SD-R28 cycle-2 5-predicate (MS028 bitnet) + SD-R32 single-predicate-deep-dive (THIS module) + SD-R48 second real demonstrator + SD-R51 EACH-semantics + SD-R55 signing + SD-R58 cycle-2+3 composition (MS030) + SD-R64 zmm_int8_lanes_min + SD-R68 host_features_required + SD-R72 cycle-3 SLM CPU loop (MS029) — full predicate evolution lineage
- Three real selfdef modules — SD-R28 bitnet (MS028) + SD-R48 wasm-aot-cache (THIS module) + SD-R58 tensor-parallel-inference (MS030); MS029 slm-cpu-loop is the cycle-3 SD-R72 fourth demonstrator
- Composability — MS031 phase=pre runs before MS028+MS029+MS030 phase=main; cache provisioned first, consumers populate later
- Cross-repo binding — sovereign-os M046 LoRA foundry + M048 Module 3 Sandbox Fabric (Podman+CDI) may use wasmtime + this cache; cross-repo audit via MS007 audit-manifest typed-mirror crate
- Operator references: wasmtime.dev + wasmtime `compile` subcommand + wasmtime --target-feature CSV + Linux /proc/cpuinfo flags + AMD Zen 5 architecture white paper + Intel Cooper Lake feature spec (CPUID 7:1 EDX flags)
