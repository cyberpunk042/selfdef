# MS030 — Tensor parallel inference module

> Parent: `backlog/milestones/INDEX.md` row MS030 (source ref `modules/tensor-parallel-inference`).
> Source: `modules/tensor-parallel-inference/` (177 lines across module.toml + install/apply.sh + install/check.sh + install/uninstall.sh).
> All entries below extract verbatim. No invention.

## Epics (E0301–E0310)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0301 | Module identity — `tensor-parallel-inference` v0.1.0, category=inference, summary "Provision tensor-parallel inference splits (every GPU hosts a slice) — demonstrates SD-R51 ALL-semantics + SD-R55 signing composition (SD-R58)" | `module.toml` 1–4 |
| E0302 | Manifest dependencies + surfaces — `depends_on = ["hardware-tune-cache"]` (consumes its env-file output) + `provides = ["tensor-parallel-runtime"]` (operator-facing slice-plan + runtime env surface) + `consumes = ["hardware-tune-env"]` (the hardware-tune-cache surface) + `conflicts = []` + `requires = [{kind = "binary", value = "selfdefctl"}]` | `module.toml` 6–14 |
| E0303 | SD-R58 — "the third real selfdef module"; "Demonstrates how cycle-2 + cycle-3 predicates compose for a niche but well-defined workload: tensor-parallel inference, where EVERY GPU hosts a slice of the model and the slices must be evenly sized" | `module.toml` 16–20 |
| E0304 | Predicate composition — `gpu_count_min = 2` (two cards minimum for a split) + `gpu_vram_gib_each_min = 16` (ALL GPUs need ≥16 GiB — slices) + `avx512_bf16 = true` (BF16 reductions across the all-reduce) + `memory_gib_min = 32`; "On the SAIN-01 dual-GPU pair (RTX PRO 6000 98 GiB + RTX 3090 24 GiB), this lands cleanly (both ≥ 16). On a 1×98 + 1×4 hypothetical, ANY would pass but EACH (SD-R51) correctly refuses" | `module.toml` 22–34 |
| E0305 | SD-R51 ALL-semantics — `gpu_vram_gib_each_min` is the EACH-quantified predicate (NOT ANY); module-loader SHALL evaluate against EVERY GPU; refuses to land if ANY GPU falls below the threshold | `module.toml` 28–34 |
| E0306 | SD-R55 [signing] surface — `[signing] required = false` (informational); module ships unsigned but operators see the SD-R55 banner — "proving the cycle's signing surface composes alongside the cycle-2 predicates"; production deployments would flip `required = true` after pinning a signature with `minisign -S -m module.toml` | `module.toml` 36–42 |
| E0307 | Module-system invariants — `instanced = false` + `phase = "main"` + `[install] kind = "script"` + apply/check/uninstall paths | `module.toml` 44–50 |
| E0308 | apply.sh — provisions `/etc/selfdef/tensor-parallel/` with 2 outputs: `slice-plan.json` (per-GPU slice assignment via equal split across detected GPUs — every GPU gets 1/N) + `runtime.env` (sources hardware-tune.env + sets TP_SLICE_PLAN + TP_NRANKS knobs); GPU detection loops /dev/nvidia[0-7] device nodes; rank assignment in [0, N); slice-plan.json schema_version="1.0.0" + ranks=N + slices[] with rank+gpu_index+share_pct fields; idempotent + SELFDEF_DRY_RUN=1 aware | `install/apply.sh` 1–76 |
| E0309 | slice-plan.json schema — `schema_version = "1.0.0"` + `ranks = N` + `slices = [{rank, gpu_index, share_pct}]`; share_pct = `100 / max(1, nranks)`; rank assigned sequentially in [0, N) as device nodes are found; emits 1.0.0 schema for stable cross-tool consumption | `install/apply.sh` 39–58 |
| E0310 | check.sh + uninstall.sh + cross-references — check.sh read-only 3-artifact presence verifier (ETC_DIR exists + slice-plan.json exists + runtime.env exists); uninstall.sh removes both files + `rmdir "$ETC_DIR" 2>/dev/null || true`; cross-references: SD-R51 ALL-semantics is the cycle-2 predicate quantifier extension; SD-R55 signing surface is the cycle-3 signature requirement; SD-R58 is the third real selfdef module demonstrating cycle-2+cycle-3 composition; cross-repo binding via MS007 typed-mirror crates | `install/check.sh` 1–26 + `install/uninstall.sh` 1–25 |

## Modules (M00759–M00784)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00759 | `module.toml` — 50-line manifest (cycle-2 ALL-semantics + cycle-3 signing + instanced=false + phase=main) | `module.toml` 1–50 | E0301 + E0303 + E0304 + E0306 + E0307 |
| M00760 | `install/apply.sh` — 76-line idempotent provisioner (slice-plan.json + runtime.env + GPU device-node count) | `install/apply.sh` 1–76 | E0308 + E0309 |
| M00761 | `install/check.sh` — 26-line read-only 3-artifact verifier | `install/check.sh` 1–26 | E0310 |
| M00762 | `install/uninstall.sh` — 25-line tear-down | `install/uninstall.sh` 1–25 | E0310 |
| M00763 | Provided surface — `tensor-parallel-runtime` | `module.toml` 8 | E0302 |
| M00764 | Consumed surface — `hardware-tune-env` (from MS010 hardware-tune-cache) | `module.toml` 9 | E0302 |
| M00765 | Required binary — `selfdefctl` | `module.toml` 12 | E0302 |
| M00766 | SD-R58 designation — "third real selfdef module" | `module.toml` 16 | E0303 |
| M00767 | SD-R58 demonstrator scope — "cycle-2 + cycle-3 predicates compose" | `module.toml` 17 | E0303 |
| M00768 | Tensor-parallel doctrine — "every GPU hosts a slice of the model" | `module.toml` 19 | E0303 |
| M00769 | Tensor-parallel doctrine — "slices must be evenly sized" | `module.toml` 20 | E0303 |
| M00770 | Predicate — gpu_count_min = 2 ("two cards minimum for a split") | `module.toml` 23 + 30 | E0304 |
| M00771 | Predicate — gpu_vram_gib_each_min = 16 ("ALL GPUs need ≥ 16 GiB — slices") | `module.toml` 24 + 31 | E0304 |
| M00772 | Predicate — avx512_bf16 = true ("BF16 reductions across the all-reduce") | `module.toml` 25 + 32 | E0304 |
| M00773 | Predicate — memory_gib_min = 32 | `module.toml` 33 | E0304 |
| M00774 | SAIN-01 box behavior — RTX PRO 6000 98 GiB + RTX 3090 24 GiB; both ≥ 16 = lands cleanly | `module.toml` 27 | E0304 |
| M00775 | Hypothetical 1×98 + 1×4 — ANY would pass but EACH (SD-R51) correctly refuses | `module.toml` 28 | E0305 |
| M00776 | SD-R51 ALL-semantics — gpu_vram_gib_each_min is EACH-quantified, NOT ANY-quantified | `module.toml` 28 | E0305 |
| M00777 | [signing] block — `required = false` (informational) | `module.toml` 42 | E0306 |
| M00778 | SD-R55 rationale — module ships unsigned but operators see SD-R55 banner | `module.toml` 37–38 | E0306 |
| M00779 | SD-R55 production path — `required = true` after `minisign -S -m module.toml` | `module.toml` 40 | E0306 |
| M00780 | apply.sh GPU device-node loop — for `_i in 0 1 2 3 4 5 6 7`; `/dev/nvidia${_i}` existence test | `install/apply.sh` 33–35 | E0308 |
| M00781 | apply.sh nranks counter — incremented on each /dev/nvidia[N] presence | `install/apply.sh` 34 | E0308 |
| M00782 | apply.sh rank assignment — sequential in [0, N) as device nodes found | `install/apply.sh` 31 + 44–49 | E0309 |
| M00783 | slice-plan.json schema — schema_version "1.0.0" + ranks N + slices[] with rank/gpu_index/share_pct | `install/apply.sh` 39–58 | E0309 |
| M00784 | apply.sh runtime.env — sources TUNE_FILE + sets TP_SLICE_PLAN + TP_NRANKS | `install/apply.sh` 61–73 | E0308 |

## Features (F03481–F03600)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F03481 | module.toml `name = "tensor-parallel-inference"` | `module.toml` 1 | M00759 |
| F03482 | module.toml `version = "0.1.0"` | `module.toml` 2 | M00759 |
| F03483 | module.toml summary — "Provision tensor-parallel inference splits (every GPU hosts a slice)" | `module.toml` 3 | M00759 |
| F03484 | module.toml summary — "demonstrates SD-R51 ALL-semantics + SD-R55 signing composition" | `module.toml` 3 | M00759 |
| F03485 | module.toml summary — SD-R58 designation | `module.toml` 3 | M00766 |
| F03486 | module.toml `category = "inference"` | `module.toml` 4 | M00759 |
| F03487 | module.toml `depends_on = ["hardware-tune-cache"]` | `module.toml` 6 | M00764 |
| F03488 | module.toml `conflicts = []` | `module.toml` 7 | M00759 |
| F03489 | module.toml `provides = ["tensor-parallel-runtime"]` | `module.toml` 8 | M00763 |
| F03490 | module.toml `consumes = ["hardware-tune-env"]` | `module.toml` 9 | M00764 |
| F03491 | module.toml `requires` — binary selfdefctl | `module.toml` 12 | M00765 |
| F03492 | SD-R58 — "the third real selfdef module" | `module.toml` 16 | M00766 |
| F03493 | SD-R58 — "Demonstrates how cycle-2 + cycle-3 predicates compose" | `module.toml` 17 | M00767 |
| F03494 | SD-R58 workload — "niche but well-defined" | `module.toml` 17 | M00767 |
| F03495 | Tensor-parallel — "every GPU hosts a slice of the model" | `module.toml` 19 | M00768 |
| F03496 | Tensor-parallel — "slices must be evenly sized" | `module.toml` 20 | M00769 |
| F03497 | Predicate header — "Predicate composition" | `module.toml` 22 | E0304 |
| F03498 | Predicate gpu_count_min = 2 inline rationale "two cards minimum for a split" | `module.toml` 23 | M00770 |
| F03499 | Predicate gpu_vram_gib_each_min = 16 inline rationale "ALL GPUs need ≥ 16 GiB (slices)" | `module.toml` 24 | M00771 |
| F03500 | Predicate avx512_bf16 = true inline rationale "BF16 reductions across the all-reduce" | `module.toml` 25 | M00772 |
| F03501 | SAIN-01 hardware reality — RTX PRO 6000 98 GiB | `module.toml` 27 | M00774 |
| F03502 | SAIN-01 hardware reality — RTX 3090 24 GiB | `module.toml` 27 | M00774 |
| F03503 | SAIN-01 — "both ≥ 16" passes EACH-semantics | `module.toml` 27 | M00774 |
| F03504 | SAIN-01 — "this lands cleanly" | `module.toml` 27 | M00774 |
| F03505 | Hypothetical — 1×98 + 1×4 GiB host configuration | `module.toml` 28 | M00775 |
| F03506 | Hypothetical — ANY would pass | `module.toml` 28 | M00775 |
| F03507 | Hypothetical — EACH (SD-R51) correctly refuses | `module.toml` 28 | M00775 |
| F03508 | [requires_hardware] block declaration | `module.toml` 29 | E0304 |
| F03509 | [requires_hardware] gpu_count_min = 2 | `module.toml` 30 | M00770 |
| F03510 | [requires_hardware] gpu_vram_gib_each_min = 16 | `module.toml` 31 | M00771 |
| F03511 | [requires_hardware] avx512_bf16 = true | `module.toml` 32 | M00772 |
| F03512 | [requires_hardware] memory_gib_min = 32 | `module.toml` 33 | M00773 |
| F03513 | SD-R55 doctrine — "SD-R58 demonstrates the cycle-3 SD-R55 signing surface" | `module.toml` 36 | M00777 |
| F03514 | SD-R55 — "We set required = false (informational)" | `module.toml` 37 | M00777 |
| F03515 | SD-R55 — "module ships unsigned" | `module.toml` 37 | M00778 |
| F03516 | SD-R55 — "operators see the SD-R55 banner" | `module.toml` 38 | M00778 |
| F03517 | SD-R55 — "proving the cycle's signing surface composes alongside the cycle-2 predicates" | `module.toml` 38–39 | M00778 |
| F03518 | SD-R55 — "Production deployments would flip required = true" | `module.toml` 40 | M00779 |
| F03519 | SD-R55 — "after pinning a signature with `minisign -S -m module.toml`" | `module.toml` 40 | M00779 |
| F03520 | [signing] block declaration | `module.toml` 41 | M00777 |
| F03521 | [signing] required = false | `module.toml` 42 | M00777 |
| F03522 | module.toml `instanced = false` | `module.toml` 44 | E0307 |
| F03523 | module.toml `phase = "main"` | `module.toml` 45 | E0307 |
| F03524 | module.toml `[install] kind = "script"` | `module.toml` 47–48 | E0307 |
| F03525 | module.toml apply = "install/apply.sh" | `module.toml` 49 | M00760 |
| F03526 | module.toml check = "install/check.sh" | `module.toml` 50 | M00761 |
| F03527 | module.toml uninstall = "install/uninstall.sh" | `module.toml` 50 | M00762 |
| F03528 | apply.sh header — SD-R58 reference | `install/apply.sh` 2 | M00760 |
| F03529 | apply.sh — provisions /etc/selfdef/tensor-parallel/ | `install/apply.sh` 4 | M00760 |
| F03530 | apply.sh output — slice-plan.json: per-GPU slice assignment | `install/apply.sh` 5 | M00783 |
| F03531 | apply.sh slice — "based on equal split across detected GPUs" | `install/apply.sh` 6 | M00783 |
| F03532 | apply.sh slice — "every GPU gets 1/N" | `install/apply.sh` 6 | M00783 |
| F03533 | apply.sh output — runtime.env: sources hardware-tune.env + sets TP_* knobs | `install/apply.sh` 7 | M00784 |
| F03534 | apply.sh MUST set -euo pipefail | `install/apply.sh` 9 | M00760 |
| F03535 | apply.sh MODULE = "tensor-parallel-inference" | `install/apply.sh` 11 | M00760 |
| F03536 | apply.sh local emit_status helper | `install/apply.sh` 13–18 | M00760 |
| F03537 | apply.sh ETC_DIR default /etc/selfdef/tensor-parallel | `install/apply.sh` 20 | M00760 |
| F03538 | apply.sh ETC_DIR override via SELFDEF_TENSOR_PARALLEL_ETC_DIR | `install/apply.sh` 20 | M00760 |
| F03539 | apply.sh TUNE_FILE default /etc/selfdef/hardware-tune.env | `install/apply.sh` 21 | M00764 |
| F03540 | apply.sh DRY_RUN from SELFDEF_DRY_RUN env | `install/apply.sh` 22 | M00760 |
| F03541 | apply.sh DRY_RUN=1 emit skipped "DRY-RUN — would provision ${ETC_DIR}" | `install/apply.sh` 24–27 | M00760 |
| F03542 | apply.sh mkdir -p ETC_DIR + chmod 0755 | `install/apply.sh` 29–30 | M00760 |
| F03543 | apply.sh rank counter init = 0 | `install/apply.sh` 32 | M00782 |
| F03544 | apply.sh nranks counter init = 0 | `install/apply.sh` 33 | M00781 |
| F03545 | apply.sh GPU device-node loop iterates 0..7 | `install/apply.sh` 34 | M00780 |
| F03546 | apply.sh GPU presence test — `[ -e /dev/nvidia${_i} ]` | `install/apply.sh` 35 | M00780 |
| F03547 | apply.sh nranks increment on each present device node | `install/apply.sh` 35 | M00781 |
| F03548 | apply.sh slice-plan.json — mktemp atomic write | `install/apply.sh` 38 | M00760 |
| F03549 | apply.sh slice-plan trap rm tmp on EXIT | `install/apply.sh` 39 | M00760 |
| F03550 | apply.sh slice-plan opens `{` | `install/apply.sh` 41 | M00783 |
| F03551 | apply.sh slice-plan schema_version "1.0.0" | `install/apply.sh` 42 | M00783 |
| F03552 | apply.sh slice-plan ranks: N | `install/apply.sh` 43 | M00783 |
| F03553 | apply.sh slice-plan slices: [...] | `install/apply.sh` 44 | M00783 |
| F03554 | apply.sh slice-plan slice entry — rank | `install/apply.sh` 50 | M00783 |
| F03555 | apply.sh slice-plan slice entry — gpu_index | `install/apply.sh` 50 | M00783 |
| F03556 | apply.sh slice-plan slice entry — share_pct | `install/apply.sh` 50 | M00783 |
| F03557 | apply.sh slice-plan share_pct = `100 / (nranks == 0 ? 1 : nranks)` | `install/apply.sh` 51 | M00783 |
| F03558 | apply.sh slice-plan rank++ after each slice | `install/apply.sh` 52 | M00782 |
| F03559 | apply.sh slice-plan first-comma handling via `first` flag | `install/apply.sh` 47 + 53 | M00783 |
| F03560 | apply.sh slice-plan emit chmod 0644 | `install/apply.sh` 60 | M00783 |
| F03561 | apply.sh slice-plan emit atomic mv -f | `install/apply.sh` 59 | M00783 |
| F03562 | apply.sh clear EXIT trap after slice-plan write | `install/apply.sh` 61 | M00760 |
| F03563 | apply.sh runtime.env header "# tensor-parallel-inference runtime env (SD-R58)" | `install/apply.sh` 64–65 | M00784 |
| F03564 | apply.sh runtime.env sources TUNE_FILE if readable | `install/apply.sh` 66–68 | M00784 |
| F03565 | apply.sh runtime.env exports TP_SLICE_PLAN | `install/apply.sh` 70 | M00784 |
| F03566 | apply.sh runtime.env exports TP_NRANKS | `install/apply.sh` 71 | M00784 |
| F03567 | apply.sh runtime.env chmod 0644 | `install/apply.sh` 73 | M00784 |
| F03568 | apply.sh final emit_status "ok" "provisioned ${ETC_DIR} (${nranks} rank(s))" | `install/apply.sh` 76 | M00760 |
| F03569 | check.sh — read-only | `install/check.sh` 2 | M00761 |
| F03570 | check.sh MUST set -euo pipefail | `install/check.sh` 4 | M00761 |
| F03571 | check.sh MODULE = "tensor-parallel-inference" | `install/check.sh` 6 | M00761 |
| F03572 | check.sh ETC_DIR override via SELFDEF_TENSOR_PARALLEL_ETC_DIR | `install/check.sh` 7 | M00761 |
| F03573 | check.sh local emit_status helper | `install/check.sh` 9–14 | M00761 |
| F03574 | check.sh missing-list initialization | `install/check.sh` 16 | M00761 |
| F03575 | check.sh probe — ETC_DIR exists | `install/check.sh` 17 | M00761 |
| F03576 | check.sh probe — slice-plan.json exists | `install/check.sh` 18 | M00761 |
| F03577 | check.sh probe — runtime.env exists | `install/check.sh` 19 | M00761 |
| F03578 | check.sh success — emit ok "tensor-parallel artifacts present" + exit 0 | `install/check.sh` 21–23 | M00761 |
| F03579 | check.sh failure — emit failed "missing: ${missing[*]}" + exit 1 | `install/check.sh` 25–26 | M00761 |
| F03580 | uninstall.sh MUST set -euo pipefail | `install/uninstall.sh` 4 | M00762 |
| F03581 | uninstall.sh MODULE = "tensor-parallel-inference" | `install/uninstall.sh` 6 | M00762 |
| F03582 | uninstall.sh ETC_DIR override via SELFDEF_TENSOR_PARALLEL_ETC_DIR | `install/uninstall.sh` 7 | M00762 |
| F03583 | uninstall.sh DRY_RUN from SELFDEF_DRY_RUN env | `install/uninstall.sh` 8 | M00762 |
| F03584 | uninstall.sh local emit_status helper | `install/uninstall.sh` 10–15 | M00762 |
| F03585 | uninstall.sh DRY_RUN=1 emit skipped "DRY-RUN — would remove ${ETC_DIR}" | `install/uninstall.sh` 17–20 | M00762 |
| F03586 | uninstall.sh rm -f slice-plan.json + runtime.env | `install/uninstall.sh` 22 | M00762 |
| F03587 | uninstall.sh rmdir ETC_DIR 2>/dev/null || true | `install/uninstall.sh` 23 | M00762 |
| F03588 | uninstall.sh emit ok "removed ${ETC_DIR}" | `install/uninstall.sh` 25 | M00762 |
| F03589 | Cross-module — MS010 hardware-tune-cache provides hardware-tune-env | `module.toml` 6 + 9 + cross-ref MS010 | M00764 |
| F03590 | Cross-module — SD-R51 ALL-semantics quantifier for cycle-2 predicates | `module.toml` 28 | M00776 |
| F03591 | Cross-module — SD-R55 signing surface (cycle-3 signature requirement) | `module.toml` 36 | M00777 |
| F03592 | Cross-module — SD-R58 third real selfdef module after MS028 SD-R28 + MS031 SD-R48 | `module.toml` 3 + 16 + cross-ref MS028 + MS031 | M00766 |
| F03593 | Cross-module — `minisign -S -m module.toml` for signing | `module.toml` 40 | M00779 |
| F03594 | Cross-repo — sovereign-os M035 Frontier inference-time intelligence + M046 LoRA foundry can host tensor-parallel multi-GPU split | cross-ref M035 + M046 | E0301 |
| F03595 | Cross-repo — selfdef MS007 audit-manifest typed-mirror carries slice-plan.json schema for cross-repo audit | architecture + cross-ref MS007 | E0309 |
| F03596 | Cross-repo — sovereign-os M040 hyper feature 1 MIG profiles + this module's slice-plan are complementary GPU partitioning surfaces | cross-ref M040 | E0309 |
| F03597 | Test integration — MS020 L1-L5 layered harness covers Module-script category + hardware-aware [requires_hardware] EACH-semantics gate evaluation | cross-ref MS020 + MS010 | E0305 |
| F03598 | Test integration — MS020 host-class test covers SAIN-01 dual-GPU pair lands-cleanly path | cross-ref MS020 + `module.toml` 27 | M00774 |
| F03599 | Test integration — MS020 host-class test covers 1×98 + 1×4 hypothetical EACH-semantics correctly refuses path | cross-ref MS020 + `module.toml` 28 | M00775 |
| F03600 | Test integration — MS020 covers signing-required false-vs-true contract | cross-ref MS020 + `module.toml` 41–42 | M00777 |

## Requirements (R06961–R07200)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R06961 | Module name MUST be `tensor-parallel-inference` | `module.toml` 1 | F03481 | non-negotiable | false | 10 |
| R06962 | Module version MUST be 0.1.0 | `module.toml` 2 | F03482 | non-negotiable | false | 10 |
| R06963 | Module summary — "Provision tensor-parallel inference splits (every GPU hosts a slice)" | `module.toml` 3 | F03483 | non-negotiable | false | 10 |
| R06964 | Module summary — "demonstrates SD-R51 ALL-semantics + SD-R55 signing composition" | `module.toml` 3 | F03484 | non-negotiable | false | 10 |
| R06965 | Module summary references SD-R58 | `module.toml` 3 | F03485 | non-negotiable | false | 10 |
| R06966 | Module category MUST be `inference` | `module.toml` 4 | F03486 | non-negotiable | false | 10 |
| R06967 | depends_on = ["hardware-tune-cache"] | `module.toml` 6 | F03487 | non-negotiable | false | 10 |
| R06968 | conflicts = [] | `module.toml` 7 | F03488 | non-negotiable | false | 10 |
| R06969 | provides = ["tensor-parallel-runtime"] | `module.toml` 8 | F03489 | non-negotiable | false | 10 |
| R06970 | consumes = ["hardware-tune-env"] | `module.toml` 9 | F03490 | non-negotiable | false | 10 |
| R06971 | Required binary — selfdefctl | `module.toml` 12 | F03491 | non-negotiable | false | 10 |
| R06972 | SD-R58 — "the third real selfdef module" | `module.toml` 16 | F03492 | non-negotiable | false | 10 |
| R06973 | SD-R58 — "Demonstrates how cycle-2 + cycle-3 predicates compose" | `module.toml` 17 | F03493 | non-negotiable | false | 10 |
| R06974 | SD-R58 — workload is "niche but well-defined" | `module.toml` 17 | F03494 | non-negotiable | false | 10 |
| R06975 | Workload — tensor-parallel inference | `module.toml` 19 | M00768 | non-negotiable | false | 10 |
| R06976 | Workload — every GPU hosts a slice of the model | `module.toml` 19 | F03495 | non-negotiable | false | 10 |
| R06977 | Workload — slices must be evenly sized | `module.toml` 20 | F03496 | non-negotiable | false | 10 |
| R06978 | Predicate composition header | `module.toml` 22 | F03497 | non-negotiable | false | 10 |
| R06979 | Predicate — gpu_count_min = 2 | `module.toml` 23 + 30 | F03498 | non-negotiable | false | 10 |
| R06980 | Predicate rationale — "two cards minimum for a split" | `module.toml` 23 | F03498 | non-negotiable | false | 10 |
| R06981 | Predicate — gpu_vram_gib_each_min = 16 | `module.toml` 24 + 31 | F03499 | non-negotiable | false | 10 |
| R06982 | Predicate rationale — "ALL GPUs need ≥ 16 GiB" | `module.toml` 24 | F03499 | non-negotiable | false | 10 |
| R06983 | Predicate rationale — "(slices)" | `module.toml` 24 | F03499 | non-negotiable | false | 10 |
| R06984 | Predicate — avx512_bf16 = true | `module.toml` 25 + 32 | F03500 | non-negotiable | false | 10 |
| R06985 | Predicate rationale — "BF16 reductions across the all-reduce" | `module.toml` 25 | F03500 | non-negotiable | false | 10 |
| R06986 | Predicate — memory_gib_min = 32 | `module.toml` 33 | F03512 | non-negotiable | false | 10 |
| R06987 | SAIN-01 — RTX PRO 6000 98 GiB | `module.toml` 27 | F03501 | non-negotiable | false | 10 |
| R06988 | SAIN-01 — RTX 3090 24 GiB | `module.toml` 27 | F03502 | non-negotiable | false | 10 |
| R06989 | SAIN-01 — both ≥ 16 passes EACH-semantics | `module.toml` 27 | F03503 | non-negotiable | false | 10 |
| R06990 | SAIN-01 — "this lands cleanly" | `module.toml` 27 | F03504 | non-negotiable | false | 10 |
| R06991 | Hypothetical — 1×98 + 1×4 | `module.toml` 28 | F03505 | non-negotiable | false | 10 |
| R06992 | Hypothetical — ANY would pass | `module.toml` 28 | F03506 | non-negotiable | false | 10 |
| R06993 | Hypothetical — EACH (SD-R51) correctly refuses | `module.toml` 28 | F03507 | non-negotiable | false | 10 |
| R06994 | [requires_hardware] block declared | `module.toml` 29 | F03508 | non-negotiable | false | 10 |
| R06995 | SD-R55 doctrine — "SD-R58 demonstrates the cycle-3 SD-R55 signing surface" | `module.toml` 36 | F03513 | non-negotiable | false | 10 |
| R06996 | SD-R55 — required = false (informational) | `module.toml` 37 + 42 | F03514 | non-negotiable | false | 10 |
| R06997 | SD-R55 — module ships unsigned | `module.toml` 37 | F03515 | non-negotiable | false | 10 |
| R06998 | SD-R55 — operators see the SD-R55 banner | `module.toml` 38 | F03516 | non-negotiable | false | 10 |
| R06999 | SD-R55 — "proving the cycle's signing surface composes alongside the cycle-2 predicates" | `module.toml` 38–39 | F03517 | non-negotiable | false | 10 |
| R07000 | SD-R55 — production deployments would flip required = true | `module.toml` 40 | F03518 | non-negotiable | false | 10 |
| R07001 | SD-R55 — after pinning a signature with `minisign -S -m module.toml` | `module.toml` 40 | F03519 | non-negotiable | false | 10 |
| R07002 | [signing] block declared | `module.toml` 41 | F03520 | non-negotiable | false | 10 |
| R07003 | [signing] required = false | `module.toml` 42 | F03521 | non-negotiable | false | 10 |
| R07004 | module.toml `instanced = false` | `module.toml` 44 | F03522 | non-negotiable | false | 10 |
| R07005 | module.toml `phase = "main"` | `module.toml` 45 | F03523 | non-negotiable | false | 10 |
| R07006 | module.toml `[install] kind = "script"` | `module.toml` 48 | F03524 | non-negotiable | false | 10 |
| R07007 | apply = "install/apply.sh" | `module.toml` 49 | F03525 | non-negotiable | false | 10 |
| R07008 | check = "install/check.sh" | `module.toml` 50 | F03526 | non-negotiable | false | 10 |
| R07009 | uninstall = "install/uninstall.sh" | `module.toml` 50 | F03527 | non-negotiable | false | 10 |
| R07010 | apply.sh header references SD-R58 | `install/apply.sh` 2 | F03528 | non-negotiable | false | 10 |
| R07011 | apply.sh — provisions /etc/selfdef/tensor-parallel/ | `install/apply.sh` 4 | F03529 | non-negotiable | false | 10 |
| R07012 | apply.sh output 1 — slice-plan.json: per-GPU slice assignment | `install/apply.sh` 5 | F03530 | non-negotiable | false | 10 |
| R07013 | apply.sh slice — "based on equal split across detected GPUs" | `install/apply.sh` 6 | F03531 | non-negotiable | false | 10 |
| R07014 | apply.sh slice — "every GPU gets 1/N" | `install/apply.sh` 6 | F03532 | non-negotiable | false | 10 |
| R07015 | apply.sh output 2 — runtime.env: sources hardware-tune.env + TP_* knobs | `install/apply.sh` 7 | F03533 | non-negotiable | false | 10 |
| R07016 | apply.sh MUST set -euo pipefail | `install/apply.sh` 9 | F03534 | non-negotiable | false | 10 |
| R07017 | apply.sh MODULE = "tensor-parallel-inference" | `install/apply.sh` 11 | F03535 | non-negotiable | false | 10 |
| R07018 | apply.sh local emit_status helper | `install/apply.sh` 13–18 | F03536 | non-negotiable | false | 10 |
| R07019 | apply.sh ETC_DIR default /etc/selfdef/tensor-parallel | `install/apply.sh` 20 | F03537 | non-negotiable | false | 10 |
| R07020 | apply.sh ETC_DIR override via SELFDEF_TENSOR_PARALLEL_ETC_DIR | `install/apply.sh` 20 | F03538 | non-negotiable | false | 10 |
| R07021 | apply.sh TUNE_FILE default /etc/selfdef/hardware-tune.env | `install/apply.sh` 21 | F03539 | non-negotiable | false | 10 |
| R07022 | apply.sh TUNE_FILE override via SELFDEF_HARDWARE_TUNE_ENV | `install/apply.sh` 21 | F03539 | non-negotiable | false | 10 |
| R07023 | apply.sh DRY_RUN from SELFDEF_DRY_RUN env default 0 | `install/apply.sh` 22 | F03540 | non-negotiable | false | 10 |
| R07024 | apply.sh DRY_RUN=1 emit skipped + exit 0 | `install/apply.sh` 24–27 | F03541 | non-negotiable | false | 10 |
| R07025 | apply.sh DRY_RUN skipped message — "DRY-RUN — would provision ${ETC_DIR}" | `install/apply.sh` 25 | F03541 | non-negotiable | false | 10 |
| R07026 | apply.sh — mkdir -p ETC_DIR | `install/apply.sh` 29 | F03542 | non-negotiable | false | 10 |
| R07027 | apply.sh — chmod 0755 ETC_DIR | `install/apply.sh` 30 | F03542 | non-negotiable | false | 10 |
| R07028 | apply.sh — rank counter init = 0 | `install/apply.sh` 32 | F03543 | non-negotiable | false | 10 |
| R07029 | apply.sh — nranks counter init = 0 | `install/apply.sh` 33 | F03544 | non-negotiable | false | 10 |
| R07030 | apply.sh — GPU device-node loop iterates 0..7 | `install/apply.sh` 34 | F03545 | non-negotiable | false | 10 |
| R07031 | apply.sh — GPU presence test `[ -e /dev/nvidia${_i} ]` | `install/apply.sh` 35 | F03546 | non-negotiable | false | 10 |
| R07032 | apply.sh — nranks increment on each present /dev/nvidia[N] | `install/apply.sh` 35 | F03547 | non-negotiable | false | 10 |
| R07033 | apply.sh — slice-plan.json atomic write via mktemp | `install/apply.sh` 38 | F03548 | non-negotiable | false | 10 |
| R07034 | apply.sh — trap rm tmp_plan on EXIT | `install/apply.sh` 39 | F03549 | non-negotiable | false | 10 |
| R07035 | apply.sh slice-plan — opens `{` | `install/apply.sh` 41 | F03550 | non-negotiable | false | 10 |
| R07036 | apply.sh slice-plan — schema_version "1.0.0" | `install/apply.sh` 42 | F03551 | non-negotiable | false | 10 |
| R07037 | apply.sh slice-plan — ranks: N | `install/apply.sh` 43 | F03552 | non-negotiable | false | 10 |
| R07038 | apply.sh slice-plan — slices: array | `install/apply.sh` 44 | F03553 | non-negotiable | false | 10 |
| R07039 | apply.sh slice entry — rank | `install/apply.sh` 50 | F03554 | non-negotiable | false | 10 |
| R07040 | apply.sh slice entry — gpu_index | `install/apply.sh` 50 | F03555 | non-negotiable | false | 10 |
| R07041 | apply.sh slice entry — share_pct | `install/apply.sh` 50 | F03556 | non-negotiable | false | 10 |
| R07042 | apply.sh share_pct = `100 / (nranks == 0 ? 1 : nranks)` (integer division) | `install/apply.sh` 51 | F03557 | non-negotiable | false | 10 |
| R07043 | apply.sh rank++ after each slice entry | `install/apply.sh` 52 | F03558 | non-negotiable | false | 10 |
| R07044 | apply.sh slice-plan — first-comma handling via `first` flag | `install/apply.sh` 47 + 53 | F03559 | non-negotiable | false | 10 |
| R07045 | apply.sh slice-plan — chmod 0644 | `install/apply.sh` 60 | F03560 | non-negotiable | false | 10 |
| R07046 | apply.sh slice-plan — atomic mv -f | `install/apply.sh` 59 | F03561 | non-negotiable | false | 10 |
| R07047 | apply.sh — clear EXIT trap after slice-plan write | `install/apply.sh` 61 | F03562 | non-negotiable | false | 10 |
| R07048 | apply.sh runtime.env — header "# tensor-parallel-inference runtime env (SD-R58)" | `install/apply.sh` 64–65 | F03563 | non-negotiable | false | 10 |
| R07049 | apply.sh runtime.env — sources TUNE_FILE if readable | `install/apply.sh` 66–68 | F03564 | non-negotiable | false | 10 |
| R07050 | apply.sh runtime.env — exports TP_SLICE_PLAN | `install/apply.sh` 70 | F03565 | non-negotiable | false | 10 |
| R07051 | apply.sh runtime.env — exports TP_NRANKS | `install/apply.sh` 71 | F03566 | non-negotiable | false | 10 |
| R07052 | apply.sh runtime.env — chmod 0644 | `install/apply.sh` 73 | F03567 | non-negotiable | false | 10 |
| R07053 | apply.sh final — emit ok "provisioned ${ETC_DIR} (${nranks} rank(s))" | `install/apply.sh` 76 | F03568 | non-negotiable | false | 10 |
| R07054 | check.sh — read-only | `install/check.sh` 2 | F03569 | non-negotiable | false | 10 |
| R07055 | check.sh MUST set -euo pipefail | `install/check.sh` 4 | F03570 | non-negotiable | false | 10 |
| R07056 | check.sh MODULE = "tensor-parallel-inference" | `install/check.sh` 6 | F03571 | non-negotiable | false | 10 |
| R07057 | check.sh ETC_DIR override via SELFDEF_TENSOR_PARALLEL_ETC_DIR | `install/check.sh` 7 | F03572 | non-negotiable | false | 10 |
| R07058 | check.sh local emit_status helper | `install/check.sh` 9–14 | F03573 | non-negotiable | false | 10 |
| R07059 | check.sh missing-list init empty | `install/check.sh` 16 | F03574 | non-negotiable | false | 10 |
| R07060 | check.sh probe — ETC_DIR exists | `install/check.sh` 17 | F03575 | non-negotiable | false | 10 |
| R07061 | check.sh probe — slice-plan.json file exists | `install/check.sh` 18 | F03576 | non-negotiable | false | 10 |
| R07062 | check.sh probe — runtime.env file exists | `install/check.sh` 19 | F03577 | non-negotiable | false | 10 |
| R07063 | check.sh success — emit ok "tensor-parallel artifacts present" + exit 0 | `install/check.sh` 21–23 | F03578 | non-negotiable | false | 10 |
| R07064 | check.sh failure — emit failed "missing: ${missing[*]}" + exit 1 | `install/check.sh` 25–26 | F03579 | non-negotiable | false | 10 |
| R07065 | uninstall.sh MUST set -euo pipefail | `install/uninstall.sh` 4 | F03580 | non-negotiable | false | 10 |
| R07066 | uninstall.sh MODULE = "tensor-parallel-inference" | `install/uninstall.sh` 6 | F03581 | non-negotiable | false | 10 |
| R07067 | uninstall.sh ETC_DIR override via SELFDEF_TENSOR_PARALLEL_ETC_DIR | `install/uninstall.sh` 7 | F03582 | non-negotiable | false | 10 |
| R07068 | uninstall.sh DRY_RUN from SELFDEF_DRY_RUN env | `install/uninstall.sh` 8 | F03583 | non-negotiable | false | 10 |
| R07069 | uninstall.sh local emit_status helper | `install/uninstall.sh` 10–15 | F03584 | non-negotiable | false | 10 |
| R07070 | uninstall.sh DRY_RUN=1 emit skipped + exit 0 | `install/uninstall.sh` 17–20 | F03585 | non-negotiable | false | 10 |
| R07071 | uninstall.sh — rm -f slice-plan.json + runtime.env | `install/uninstall.sh` 22 | F03586 | non-negotiable | false | 10 |
| R07072 | uninstall.sh — rmdir ETC_DIR 2>/dev/null || true | `install/uninstall.sh` 23 | F03587 | non-negotiable | false | 10 |
| R07073 | uninstall.sh — emit ok "removed ${ETC_DIR}" | `install/uninstall.sh` 25 | F03588 | non-negotiable | false | 10 |
| R07074 | Cross-module — MS010 hardware-tune-cache provides hardware-tune-env | `module.toml` 6 + 9 + cross-ref MS010 | F03589 | non-negotiable | false | 10 |
| R07075 | Cross-module — SD-R51 ALL-semantics quantifier extension to cycle-2 predicates | `module.toml` 28 | F03590 | non-negotiable | false | 10 |
| R07076 | Cross-module — SD-R55 signing surface (cycle-3 signature requirement) | `module.toml` 36 | F03591 | non-negotiable | false | 10 |
| R07077 | Cross-module — SD-R58 third real selfdef module after MS028 SD-R28 + MS031 SD-R48 | `module.toml` 3 + 16 + cross-ref MS028 + MS031 | F03592 | non-negotiable | false | 10 |
| R07078 | Cross-module — `minisign -S -m module.toml` is the canonical signing command | `module.toml` 40 | F03593 | non-negotiable | false | 10 |
| R07079 | Cross-repo — sovereign-os M035 + M046 host tensor-parallel multi-GPU split | cross-ref M035 + M046 | F03594 | non-negotiable | false | 10 |
| R07080 | Cross-repo — selfdef MS007 audit-manifest typed-mirror carries slice-plan.json schema | architecture + cross-ref MS007 | F03595 | non-negotiable | false | 10 |
| R07081 | Cross-repo — sovereign-os M040 MIG profiles + this module's slice-plan are complementary | cross-ref M040 | F03596 | non-negotiable | false | 10 |
| R07082 | Test integration — MS020 covers Module-script + hardware-aware [requires_hardware] EACH-semantics | cross-ref MS020 + MS010 | F03597 | non-negotiable | false | 10 |
| R07083 | Test integration — MS020 host-class test covers SAIN-01 dual-GPU lands-cleanly | cross-ref MS020 | F03598 | non-negotiable | false | 10 |
| R07084 | Test integration — MS020 host-class test covers 1×98 + 1×4 hypothetical EACH refuses | cross-ref MS020 | F03599 | non-negotiable | false | 10 |
| R07085 | Test integration — MS020 covers signing required=false vs true contract | cross-ref MS020 | F03600 | non-negotiable | false | 10 |
| R07086 | Hardware-exploit doctrine — predicate quantifier matters (ANY vs EACH) | `module.toml` 28 | M00776 | non-negotiable | false | 10 |
| R07087 | Hardware-exploit doctrine — SD-R51 introduces EACH-semantics quantifier | `module.toml` 24 + 28 | M00776 | non-negotiable | false | 10 |
| R07088 | Hardware-exploit doctrine — module-loader SHALL evaluate _each_min against EVERY GPU, NOT just one | `module.toml` 24 | M00776 | non-negotiable | false | 10 |
| R07089 | Hardware-exploit doctrine — operator-readable predicate names communicate quantifier intent | `module.toml` 24 | M00776 | non-negotiable | false | 10 |
| R07090 | Hardware-exploit doctrine — `_min` suffix = minimum / `_each_min` suffix = per-GPU minimum | `module.toml` 23–24 | M00776 | non-negotiable | false | 10 |
| R07091 | Signing doctrine — [signing] block declares cycle-3 signature requirement | `module.toml` 41–42 | M00777 | non-negotiable | false | 10 |
| R07092 | Signing doctrine — required = false → informational; module ships unsigned | `module.toml` 42 + 37 | M00777 | non-negotiable | false | 10 |
| R07093 | Signing doctrine — required = true → enforced; module refuses to land without valid signature | `module.toml` 40 | M00779 | non-negotiable | false | 10 |
| R07094 | Signing doctrine — minisign is the canonical signing tool | `module.toml` 40 | M00779 | non-negotiable | false | 10 |
| R07095 | Signing doctrine — production deployments flip required = true after first signature | `module.toml` 40 | M00779 | non-negotiable | false | 10 |
| R07096 | Module-system invariant — phase=main runs after hardware-tune-cache phase=pre | `module.toml` 45 + cross-ref MS010 | E0307 | non-negotiable | false | 10 |
| R07097 | Module-system invariant — instanced=false (host has one tensor-parallel slice plan) | `module.toml` 44 | E0307 | non-negotiable | false | 10 |
| R07098 | Module-system invariant — depends_on=hardware-tune-cache enforces module ordering | `module.toml` 6 + cross-ref MS010 | F03487 | non-negotiable | false | 10 |
| R07099 | Module-system invariant — provides=tensor-parallel-runtime is operator-facing surface | `module.toml` 8 | F03489 | non-negotiable | false | 10 |
| R07100 | Operator UX — `selfdefctl modules apply tensor-parallel-inference` triggers apply | `module.toml` 49 | F03525 | non-negotiable | false | 10 |
| R07101 | Operator UX — apply emits JSON status line | `install/apply.sh` 16 | F03536 | non-negotiable | false | 10 |
| R07102 | Operator UX — check emits JSON status line | `install/check.sh` 11 | F03573 | non-negotiable | false | 10 |
| R07103 | Operator UX — uninstall emits JSON status line | `install/uninstall.sh` 12 | F03584 | non-negotiable | false | 10 |
| R07104 | Output schema — slice-plan.json schema_version "1.0.0" | `install/apply.sh` 42 | F03551 | non-negotiable | false | 10 |
| R07105 | Output schema — slice-plan.json carries `ranks` integer | `install/apply.sh` 43 | F03552 | non-negotiable | false | 10 |
| R07106 | Output schema — slice-plan.json carries `slices` array | `install/apply.sh` 44 | F03553 | non-negotiable | false | 10 |
| R07107 | Output schema — each slice carries rank + gpu_index + share_pct | `install/apply.sh` 50 | F03554 + F03555 + F03556 | non-negotiable | false | 10 |
| R07108 | Output schema — share_pct uses integer division (no fractional shares) | `install/apply.sh` 51 | F03557 | non-negotiable | false | 10 |
| R07109 | Output schema — share_pct is uniform across slices (equal split) | `install/apply.sh` 51 | F03531 + F03532 | non-negotiable | false | 10 |
| R07110 | Output schema — slice-plan.json file mode 0644 | `install/apply.sh` 60 | F03560 | non-negotiable | false | 10 |
| R07111 | Output schema — runtime.env mode 0644 | `install/apply.sh` 73 | F03567 | non-negotiable | false | 10 |
| R07112 | Output schema — runtime.env exports TP_SLICE_PLAN | `install/apply.sh` 70 | F03565 | non-negotiable | false | 10 |
| R07113 | Output schema — runtime.env exports TP_NRANKS | `install/apply.sh` 71 | F03566 | non-negotiable | false | 10 |
| R07114 | Output schema — runtime.env sources TUNE_FILE first | `install/apply.sh` 67 | F03564 | non-negotiable | false | 10 |
| R07115 | GPU detection — uses /dev/nvidia[0-7] device nodes | `install/apply.sh` 34 | F03545 | non-negotiable | false | 10 |
| R07116 | GPU detection — supports up to 8 GPUs | `install/apply.sh` 34 | F03545 | non-negotiable | false | 10 |
| R07117 | GPU detection — does NOT use nvidia-smi (loop is shell-only) | `install/apply.sh` 33–36 | M00780 | non-negotiable | false | 10 |
| R07118 | GPU detection — does NOT use selfdefctl hardware export (unlike MS028 bitnet) | `install/apply.sh` 33–36 + cross-ref MS028 | M00780 | non-negotiable | false | 10 |
| R07119 | Slice plan — every GPU in [0, nranks) gets rank value | `install/apply.sh` 50–52 | M00782 | non-negotiable | false | 10 |
| R07120 | Slice plan — rank IS sequential, NOT preserved across re-apply (numeric) | `install/apply.sh` 31 + 52 | M00782 | non-negotiable | false | 10 |
| R07121 | Slice plan — gpu_index preserves original /dev/nvidia[N] device number | `install/apply.sh` 50 | F03555 | non-negotiable | false | 10 |
| R07122 | Slice plan — share_pct is integer percentage | `install/apply.sh` 50–51 | F03557 | non-negotiable | false | 10 |
| R07123 | Slice plan — share_pct sum may not equal exactly 100 due to integer division (e.g. 3 ranks → 33+33+33=99) | `install/apply.sh` 51 | F03557 | non-negotiable | false | 10 |
| R07124 | Slice plan — share_pct guards division by zero via `(nranks == 0 ? 1 : nranks)` | `install/apply.sh` 51 | F03557 | non-negotiable | false | 10 |
| R07125 | Project-boundary — MS030 is selfdef IPS tensor-parallel split scope; sovereign-os M035/M046 host the actual TP serving | architecture + cross-ref M035 + M046 | E0301 | non-negotiable | false | 10 |
| R07126 | Project-boundary — selfdef provides slice-plan.json; consumer (vllm/sglang/llama.cpp) reads via TP_SLICE_PLAN | `install/apply.sh` 70 | F03565 | non-negotiable | false | 10 |
| R07127 | Project-boundary — cross-repo binding via MS007 typed-mirror crates only | architecture + cross-ref MS007 | F03595 | non-negotiable | false | 10 |
| R07128 | Cross-repo — sovereign-os M040 hyper feature 1 MIG profiles partition Blackwell into virtual GPUs; tensor-parallel slice-plan partitions across physical GPUs; complementary | cross-ref M040 | F03596 | non-negotiable | false | 10 |
| R07129 | Cross-repo — sovereign-os M046 LoRA foundry multi-LoRA serving + MS030 tensor-parallel serving are orthogonal optimizations | cross-ref M046 | F03594 | non-negotiable | false | 10 |
| R07130 | Hardware reality — Zen 5 9900X supports AVX-512 BF16 for all-reduce | `module.toml` 25 | F03500 | non-negotiable | false | 10 |
| R07131 | Hardware reality — SAIN-01 RTX PRO 6000 Blackwell + RTX 3090 satisfies gpu_count_min=2 | `module.toml` 27 | M00774 | non-negotiable | false | 10 |
| R07132 | Hardware reality — SAIN-01 both GPUs satisfy gpu_vram_gib_each_min=16 (98 GiB ≥ 16 + 24 GiB ≥ 16) | `module.toml` 27 | M00774 | non-negotiable | false | 10 |
| R07133 | Hardware reality — 1-card box correctly fails gpu_count_min=2 | `module.toml` 23 | M00770 | non-negotiable | false | 10 |
| R07134 | Hardware reality — 2-card box with 1×98 + 1×4 GiB correctly fails gpu_vram_gib_each_min=16 | `module.toml` 28 | M00775 | non-negotiable | false | 10 |
| R07135 | Hardware reality — gpu_vram_gib_each_min=16 admits the smallest reasonable bf16 model slice | `module.toml` 24 | M00771 | non-negotiable | false | 10 |
| R07136 | apply.sh edge case — nranks=0 host (no /dev/nvidia[N] device) writes slice-plan.json with ranks=0 + empty slices | `install/apply.sh` 33–36 + 51 | M00781 | non-negotiable | false | 10 |
| R07137 | apply.sh edge case — share_pct on nranks=0 falls back to 100 / 1 = 100 (division-by-zero guard) | `install/apply.sh` 51 | F03557 | non-negotiable | false | 10 |
| R07138 | apply.sh edge case — first-slice flag prevents leading comma in slices JSON array | `install/apply.sh` 47 + 53 | F03559 | non-negotiable | false | 10 |
| R07139 | apply.sh contract — slice-plan.json + runtime.env are renderered each apply (overwrites prior) | `install/apply.sh` 38–73 | M00760 | non-negotiable | false | 10 |
| R07140 | apply.sh contract — slice-plan.json + runtime.env are idempotent (same hardware → same output) | `install/apply.sh` 33–52 | M00760 | non-negotiable | false | 10 |
| R07141 | SD-reference — SD-R58 third real selfdef module (the SD-R28 bitnet + SD-R48 wasm-aot-cache + SD-R58 tensor-parallel trio) | `module.toml` 16 + cross-ref MS028 + MS031 | F03592 | non-negotiable | false | 10 |
| R07142 | SD-reference — SD-R51 ALL-semantics quantifier for cycle-2 [requires_hardware] | `module.toml` 28 | M00776 | non-negotiable | false | 10 |
| R07143 | SD-reference — SD-R55 [signing] surface for cycle-3 module integrity | `module.toml` 36 | M00777 | non-negotiable | false | 10 |
| R07144 | SD-reference — SD-R58 demonstrates cycle-2 + cycle-3 composition | `module.toml` 17 | F03493 | non-negotiable | false | 10 |
| R07145 | Operator references — minisign signing tool (jedisct1/minisign) | `module.toml` 40 | M00779 | non-negotiable | false | 10 |
| R07146 | Operator references — /dev/nvidia[N] device node convention from NVIDIA Linux driver | `install/apply.sh` 34–35 | M00780 | non-negotiable | false | 10 |
| R07147 | Operator references — tensor-parallel inference frameworks (vllm tensor_parallel_size + llama.cpp tensor-split + SGLang tp_size) | `module.toml` 19 | M00768 | non-negotiable | false | 10 |
| R07148 | Operator references — all-reduce collective BF16 reduction kernel | `module.toml` 25 | F03500 | non-negotiable | false | 10 |
| R07149 | Operator references — AVX-512 BF16 instruction set (Zen 5) | `module.toml` 25 | F03500 | non-negotiable | false | 10 |
| R07150 | Operator references — RTX PRO 6000 Blackwell + RTX 3090 datasheets for VRAM specs | `module.toml` 27 | M00774 | non-negotiable | false | 10 |
| R07151 | Doctrine — every GPU in the host gets a slice (no skipping) | `module.toml` 19 | M00768 | non-negotiable | false | 10 |
| R07152 | Doctrine — slice sizes are uniform (slices must be evenly sized) | `module.toml` 20 | M00769 | non-negotiable | false | 10 |
| R07153 | Doctrine — uneven GPU VRAM (different sizes) does NOT block apply but may lead to underutilization | `module.toml` 27 | M00774 | non-negotiable | false | 10 |
| R07154 | Doctrine — operator may override slice-plan.json post-apply if asymmetric split needed | `install/apply.sh` 5–7 | M00783 | non-negotiable | false | 10 |
| R07155 | Doctrine — module is a provisioning helper, NOT a TP runtime itself | `module.toml` 3 + `install/apply.sh` 4 | M00759 | non-negotiable | false | 10 |
| R07156 | Doctrine — consumer (vllm/llama.cpp/SGLang) reads TP_SLICE_PLAN env to apply split | `install/apply.sh` 70 | F03565 | non-negotiable | false | 10 |
| R07157 | Doctrine — TP_NRANKS env exposes integer rank count for consumer auto-detection | `install/apply.sh` 71 | F03566 | non-negotiable | false | 10 |
| R07158 | Composability — module composes with MS028 bitnet-gpu-inference (single-GPU + multi-GPU paths coexist on same host) | architecture + cross-ref MS028 | E0303 | non-negotiable | false | 10 |
| R07159 | Composability — module composes with MS029 slm-cpu-loop (CPU-pinned SLM + GPU-tensor-parallel coexist) | architecture + cross-ref MS029 | E0303 | non-negotiable | false | 10 |
| R07160 | Composability — module's slice-plan.json is consumed by future MS-* model-runner modules | architecture + `install/apply.sh` 70 | F03565 | non-negotiable | false | 10 |
| R07161 | Cross-repo — sovereign-os M026 SLM swarm + RLM engine routes large-model queries that can use TP | cross-ref M026 | E0301 | non-negotiable | false | 10 |
| R07162 | Cross-repo — sovereign-os M032 Cloud Expert Plane uses cloud TP when local TP infeasible | cross-ref M032 | E0301 | non-negotiable | false | 10 |
| R07163 | Cross-repo — sovereign-os M034 Anthropic-first Gateway routes TP-eligible queries to TP backend | cross-ref M034 | E0301 | non-negotiable | false | 10 |
| R07164 | Cross-repo — sovereign-os M042 Choice Architecture profile may pin TP vs single-GPU | cross-ref M042 | E0301 | non-negotiable | false | 10 |
| R07165 | Cross-repo — sovereign-os M043 Bridge Layer hardware-aware scheduling allocates TP slot based on availability | cross-ref M043 | E0301 | non-negotiable | false | 10 |
| R07166 | Module-system invariant — module-loader SHALL evaluate EACH-quantified predicates against all detected devices | `module.toml` 24 + 28 | M00776 | non-negotiable | false | 10 |
| R07167 | Module-system invariant — predicates are inherently extensible (cycle-2 + cycle-3 + future cycles all compose) | `module.toml` 17 | F03493 | non-negotiable | false | 10 |
| R07168 | Module-system invariant — [signing] block is independent of [requires_hardware] block | `module.toml` 29 + 41 | M00777 | non-negotiable | false | 10 |
| R07169 | Module-system invariant — module-loader SHALL respect required = false (informational) but still display banner | `module.toml` 37–38 + 42 | M00778 | non-negotiable | false | 10 |
| R07170 | Module-system invariant — module-loader SHALL refuse module when required = true and signature is invalid | `module.toml` 40 | M00779 | non-negotiable | false | 10 |
| R07171 | Module-system invariant — `minisign -S -m module.toml` produces module.toml.minisig sidecar | `module.toml` 40 | M00779 | non-negotiable | false | 10 |
| R07172 | Module-system invariant — signature path SHALL be module.toml.minisig by convention | `module.toml` 40 | M00779 | non-negotiable | false | 10 |
| R07173 | Operator UX — `selfdefctl modules apply tensor-parallel-inference` triggers apply.sh | `module.toml` 49 | F03525 | non-negotiable | false | 10 |
| R07174 | Operator UX — `selfdefctl modules check tensor-parallel-inference` triggers check.sh | `module.toml` 50 | F03526 | non-negotiable | false | 10 |
| R07175 | Operator UX — `selfdefctl modules uninstall tensor-parallel-inference` triggers uninstall.sh | `module.toml` 50 | F03527 | non-negotiable | false | 10 |
| R07176 | Operator UX — `selfdefctl modules apply` aggregates apply across all activated modules | architecture + cross-ref MS006 | F03525 | non-negotiable | false | 10 |
| R07177 | Operator UX — selfdefctl SHALL log SD-R55 signing banner for required=false modules | `module.toml` 38 | M00778 | non-negotiable | false | 10 |
| R07178 | Operator UX — selfdefctl SHALL refuse install for required=true + invalid signature | `module.toml` 40 | M00779 | non-negotiable | false | 10 |
| R07179 | Operator UX — operator copies module.toml.minisig sidecar to install location | `module.toml` 40 | M00779 | non-negotiable | false | 10 |
| R07180 | Operator UX — operator generates signing key via `minisign -G` | `module.toml` 40 | M00779 | non-negotiable | false | 10 |
| R07181 | Operator UX — operator verifies signature via `minisign -V -m module.toml` | `module.toml` 40 | M00779 | non-negotiable | false | 10 |
| R07182 | Cross-module — MS028 bitnet-gpu-inference + MS030 tensor-parallel-inference share /etc/selfdef/* config tree convention | `install/apply.sh` 20 + cross-ref MS028 | M00759 | non-negotiable | false | 10 |
| R07183 | Cross-module — MS029 slm-cpu-loop + MS030 tensor-parallel-inference can coexist (CPU + multi-GPU paths) | architecture + cross-ref MS029 | E0303 | non-negotiable | false | 10 |
| R07184 | Cross-module — MS010 hardware-tune-cache MUST run before MS030 (phase=pre < phase=main) | `module.toml` 6 + 45 + cross-ref MS010 | F03523 | non-negotiable | false | 10 |
| R07185 | Cross-module — MS006 module-system loads MS030 as part of inference category | `module.toml` 4 + cross-ref MS006 | F03486 | non-negotiable | false | 10 |
| R07186 | Cross-module — MS013 27-SDD charter governs SD-R51 + SD-R55 + SD-R58 finding ledger | cross-ref MS013 | F03592 | non-negotiable | false | 10 |
| R07187 | Test integration — MS020 L1-L5 layered harness covers Module-script category | cross-ref MS020 | M00760 + M00761 + M00762 | non-negotiable | false | 10 |
| R07188 | Test integration — MS020 covers SD-R51 EACH-quantifier predicate evaluation | cross-ref MS020 | M00776 | non-negotiable | false | 10 |
| R07189 | Test integration — MS020 covers SD-R55 signing block parsing | cross-ref MS020 | M00777 | non-negotiable | false | 10 |
| R07190 | Test integration — MS020 covers slice-plan.json schema_version forward-compatibility | cross-ref MS020 | F03551 | non-negotiable | false | 10 |
| R07191 | Test integration — MS020 covers nranks edge cases (0, 1, 2, 3, 8) | cross-ref MS020 + `install/apply.sh` 34 | F03545 | non-negotiable | false | 10 |
| R07192 | Test integration — MS020 covers DRY_RUN=1 path (no filesystem mutation) | cross-ref MS020 + `install/apply.sh` 24–27 | F03541 | non-negotiable | false | 10 |
| R07193 | Doctrine — share_pct rounding loss is documented and accepted (integer percentages) | `install/apply.sh` 51 | F03557 | non-negotiable | false | 10 |
| R07194 | Doctrine — module is opinionated about equal-split; non-equal splits require operator post-apply edit | `module.toml` 20 + `install/apply.sh` 6 | M00769 | non-negotiable | false | 10 |
| R07195 | Doctrine — uneven VRAM hosts may experience underutilization (smaller GPU is bottleneck) | `module.toml` 27 | M00774 | non-negotiable | false | 10 |
| R07196 | Doctrine — module provides plan, NOT execution (consumer enforces) | `module.toml` 3 + `install/apply.sh` 70 | F03565 | non-negotiable | false | 10 |
| R07197 | Operator references — vLLM `--tensor-parallel-size` flag | `module.toml` 19 + `install/apply.sh` 71 | F03565 | non-negotiable | false | 10 |
| R07198 | Operator references — llama.cpp `--tensor-split` flag | `module.toml` 19 + `install/apply.sh` 71 | F03565 | non-negotiable | false | 10 |
| R07199 | Operator references — SGLang `--tp-size` flag | `module.toml` 19 + `install/apply.sh` 71 | F03565 | non-negotiable | false | 10 |
| R07200 | Composite — MS030 (10 epics / 26 modules / 120 features / 240 reqs) covers tensor-parallel-inference module v0.1.0 (177 lines): module.toml (50-line manifest with [requires_hardware] cycle-2+cycle-3 composition gpu_count_min=2 + gpu_vram_gib_each_min=16 + avx512_bf16=true + memory_gib_min=32 + [signing] required=false SD-R55 banner + instanced=false + phase=main + depends_on=hardware-tune-cache + provides=tensor-parallel-runtime + consumes=hardware-tune-env) + apply.sh (76-line idempotent provisioner emitting slice-plan.json schema_version="1.0.0" with equal-share-pct slices + runtime.env exporting TP_SLICE_PLAN + TP_NRANKS) + check.sh (26-line 3-artifact verifier) + uninstall.sh (25-line tear-down); SD-R58 third real selfdef module after SD-R28 bitnet + SD-R48 wasm-aot-cache; SD-R51 ALL-semantics (EACH-quantified `_each_min` predicate); SD-R55 signing surface (operator flips required=true after `minisign -S`); SAIN-01 dual-GPU lands cleanly; 1×98+1×4 hypothetical EACH refuses; consumer-agnostic plan format (vLLM `--tensor-parallel-size` + llama.cpp `--tensor-split` + SGLang `--tp-size`); cross-module composability with MS028 bitnet + MS029 slm-cpu-loop; cross-repo binding to sovereign-os M026/M032/M034/M035/M040/M042/M043/M046 via MS007 typed-mirror crates | `modules/tensor-parallel-inference/` 177 lines | E0301 + E0302 + E0303 + E0304 + E0305 + E0306 + E0307 + E0308 + E0309 + E0310 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: module.toml identity + surfaces + binary + SD-R58 + 4 predicates + EACH-semantics rationale + [signing] block (R06961–R07009) + apply.sh full transcription including GPU device-node loop + slice-plan.json schema + runtime.env export (R07010–R07053) + check.sh full transcription (R07054–R07064) + uninstall.sh full transcription (R07065–R07073) + cross-module + cross-repo references (R07074–R07085) + hardware-exploit + signing doctrine (R07086–R07095) + module-system invariants (R07096–R07099) + operator UX + output schema invariants (R07100–R07114) + GPU detection + slice plan + edge case invariants (R07115–R07140) + SD-reference table (R07141–R07144) + operator references (R07145–R07150) + doctrine + composability (R07151–R07165) + module-loader invariants (R07166–R07172) + operator CLI UX (R07173–R07181) + cross-module composability (R07182–R07186) + test integration (R07187–R07192) + doctrine + operator references (R07193–R07199) + composite (R07200)
- Source range 177 lines yields 240 R-rows representing 1.36:1 R-per-line at the verbatim-citation level
- Project boundary — MS030 is selfdef IPS tensor-parallel slice-plan provisioning scope (provisions plan, NOT runtime); sovereign-os hosts the actual TP serving via M035 + M046; cross-repo audit routes through MS007 audit-manifest typed-mirror crate

## Cross-references

- Adjacent INDEX rows: MS029 SLM CPU loop / MS031 WASM AOT cache
- Cross-module dependency chain — MS010 hardware-tune-cache (phase=pre) → MS030 tensor-parallel-inference (phase=main)
- SD-R lineage — SD-R28 bitnet-gpu-inference (MS028) + SD-R48 wasm-aot-cache (MS031) + SD-R58 tensor-parallel-inference (this module) form the "three real selfdef modules" demonstrating cycle-2+cycle-3 predicate composition
- SD-R51 ALL-semantics — `gpu_vram_gib_each_min` is the EACH-quantified predicate; SD-R51 introduces the `_each_min` suffix convention to module manifests; module-loader SHALL evaluate against EVERY device, not just one
- SD-R55 signing surface — `[signing] required = false/true` block governs module-integrity verification; minisign is the canonical signing tool; production deployments flip required=true after first signature
- Consumer-agnostic plan — slice-plan.json schema_version "1.0.0" is consumable by vLLM (`--tensor-parallel-size`) + llama.cpp (`--tensor-split`) + SGLang (`--tp-size`); cross-tool stability
- Cross-repo binding — sovereign-os M026 SLM swarm + M032 Cloud Expert + M034 Anthropic-first Gateway + M035 Frontier + M040 MIG profiles + M042 Choice Architecture + M043 Bridge Layer + M046 LoRA foundry all touch tensor-parallel scheduling; selfdef MS030 provides the slice-plan; sovereign-os consumes it via MS007 surface-manifest typed-mirror crate
- Composability — MS028 bitnet-gpu-inference + MS029 slm-cpu-loop + MS030 tensor-parallel-inference can coexist on same host (single-GPU + CPU-pinned + multi-GPU paths)
- Operator references: minisign signing tool / /dev/nvidia[N] device node convention / vLLM + llama.cpp + SGLang TP flags / AVX-512 BF16 instruction set (Zen 5) / NCCL all-reduce collective / RTX PRO 6000 Blackwell + RTX 3090 datasheets
