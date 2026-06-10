#!/usr/bin/env bash
# scripts/test/coherence.sh — MS045 SDD-030 Deliverable 1
#
# Single entry-point for the IPS UX coherence harness. Runs every L1
# gate + every L2 bats suite + the three-watchdog-trio cargo-test set,
# in order, and exits non-zero on any layer failure.
#
# Source: SDD-030 Deliverable 1 / MS045 R-rows
# Run: bash scripts/test/coherence.sh
#
# Operator runbook on failure:
#   ~/devops-solutions-information-hub/wiki/runbooks/ux-coherence-failures.md
set -uo pipefail
# NOTE: not `set -e` — we accumulate failures across layers and report
# all of them, rather than failing on the first.

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_ROOT}" || { echo "cd ${REPO_ROOT} failed" >&2; exit 2; }

# SDD-080: the L2 watchdog suites create benign config fixtures in a
# temp dir owned by whoever runs the harness. The watchdogs flag any
# config NOT owned by the expected owner (default root) as a tamper
# signal — correct in production where /etc configs are root-owned, but
# a false positive under a non-root CI runner (e.g. GitHub's `runner`),
# where every fixture is owned by that user. Declare the harness runner
# as the expected owner so the benign-path assertions are hermetic under
# any runner. Production behaviour is unchanged: the watchdogs still
# default to `root` when this env var is unset.
export SELFDEF_WATCHDOG_EXPECTED_OWNER="${SELFDEF_WATCHDOG_EXPECTED_OWNER:-$(id -un)}"

# --- Layer ledger -----------------------------------------------------
declare -a LAYER_NAMES=()
declare -a LAYER_STATUS=()

run_layer() {
    local name="$1"
    shift
    echo
    echo "════════════════════════════════════════════════════════════════"
    echo "[${name}]"
    echo "════════════════════════════════════════════════════════════════"
    if "$@"; then
        LAYER_NAMES+=("${name}")
        LAYER_STATUS+=("PASS")
    else
        LAYER_NAMES+=("${name}")
        LAYER_STATUS+=("FAIL")
    fi
}

# --- L1 gates ---------------------------------------------------------

run_layer "L1: perimeter YAML lint" \
    bash scripts/test/L1-perimeter-yaml-lint.sh

run_layer "L1: YAML parse + real-bug scan (all sigma/policy/template YAML)" \
    bash scripts/test/L1-yaml-parse-scan.sh

run_layer "L1: JSON parse + dup-key scan (schemas / fixtures / manifest)" \
    bash scripts/test/L1-json-parse-scan.sh

run_layer "L1: CLI surface (subverb counts)" \
    bash scripts/test/L1-cli-surface.sh

run_layer "L1: HTTP API endpoint declarations" \
    bash scripts/test/L1-api-endpoints.sh

run_layer "L1: dashboard sections (four-watchdog set UX surface)" \
    bash scripts/test/L1-dashboard-sections.sh

run_layer "L1: Grafana template (MS027 four-watchdog series)" \
    bash scripts/test/L1-grafana-template.sh

run_layer "L1: API metric observability coverage (every /metrics family has a home)" \
    bash scripts/test/L1-api-metric-observability-coverage.sh

run_layer "L1: Prometheus alert rules (MS027 four-watchdog alerts)" \
    bash scripts/test/L1-prometheus-alerts.sh

run_layer "L1: operator cheatsheet (daily-driver doc coverage)" \
    bash scripts/test/L1-operator-cheatsheet.sh

run_layer "L1: module-system contracts (14 modules cross-wired)" \
    bash scripts/test/L1-module-contracts.sh

run_layer "L1: module requires ↔ binary coherence (every \`|| die\` binary is declared)" \
    bash scripts/test/L1-module-requires-binary-coherence.sh

run_layer "L1: systemd unit + timer hardening (guardian + ux-harness; MS044 R10411-R10440 + MS045 R10738)" \
    bash scripts/test/L1-systemd-hardening.sh

run_layer "L1: cross-repo alert ↔ runbook binding (MS048 runbook ↔ sovereign-os scheduler alerts)" \
    bash scripts/test/L1-cross-repo-alert-runbook-binding.sh

run_layer "L1: mirror schema-version coherence (14 selfdef-*-mirror crates + 10 sovereign-os consumers in lockstep)" \
    bash scripts/test/L1-mirror-schema-version-coherence.sh

run_layer "L1: doctrine verbatim preservation (DOCTRINE_* constants + cross-crate name-collision coherence)" \
    bash scripts/test/L1-doctrine-verbatim-preservation.sh

run_layer "L1: SDD header shape integrity (# SDD-NNN heading + Status + no number collisions across 78 SDDs)" \
    bash scripts/test/L1-sdd-header-shape.sh

run_layer "L1: Decision schema cross-repo (selfdef-scheduler-mirror fields the sovereign-os bridge consumes)" \
    bash scripts/test/L1-decision-schema-cross-repo.sh

run_layer "L1: backlog/INDEX.md ↔ filesystem coherence (48 milestones × 3 gates — links resolve / files indexed / R-row counts match)" \
    bash scripts/test/L1-backlog-index-coherence.sh

run_layer "L1: info-hub doc references (cross-repo deep-link integrity; skips when info-hub not adjacent)" \
    bash scripts/test/L1-info-hub-doc-references.sh

run_layer "L1: textfile observer R171 hardening (29 selfdef-*-textfile.service × 9 clauses = 261 assertions)" \
    bash scripts/test/L1-textfile-observer-hardening.sh

run_layer "L1: textfile observer timer fleet (29 timers × 5 cadence clauses + pairing + OnBootSec uniqueness)" \
    bash scripts/test/L1-textfile-observer-timer-fleet.sh

run_layer "L1: module-lib version coherence (SDD-061; library v4 must satisfy all 182 consumers)" \
    bash scripts/test/L1-module-lib-version-coherence.sh

run_layer "L1: sigma rule ↔ test pairing (22 rules ↔ 22 .tests.yaml × 3 invariants)" \
    bash scripts/test/L1-sigma-rule-test-pairing.sh

run_layer "L1: non-observer service hardening fleet (9 daemon-layer .service × 9 R171 baseline clauses = 81 assertions)" \
    bash scripts/test/L1-nonobserver-service-hardening-fleet.sh

run_layer "L1: non-observer doctor timer fleet (4 doctor timers × 5 contract clauses + cadence-aware Persistent gate)" \
    bash scripts/test/L1-nonobserver-doctor-timer-fleet.sh

run_layer "L1: TracingPolicy YAML fleet (every Tetragon policy under packaging/tetragon-policies/ + rules/tetragon/)" \
    bash scripts/test/L1-tracingpolicy-yaml-fleet.sh

run_layer "L1: AppArmor profile integrity (selfdefd envelope: allow rules + deny rules + operator hints, 26 assertions)" \
    bash scripts/test/L1-apparmor-profile-integrity.sh

run_layer "L1: JSON Schema fleet integrity (docs/schemas/*.schema.json — \$schema + \$id + title + required + additionalProperties=false)" \
    bash scripts/test/L1-json-schema-fleet.sh

run_layer "L1: systemd drop-in integrity (selfdefd.service.d/ebpf.conf: 3 required caps + no escalation)" \
    bash scripts/test/L1-systemd-dropin-integrity.sh

run_layer "L1: module operator-config-key discoverability (toml_get keys documented in profiles)" \
    bash scripts/test/L1-module-config-key-discoverability.sh

run_layer "L1: cross-repo mirror artifact filename binding (cockpit consumers)" \
    bash scripts/test/L1-mirror-artifact-filename-binding.sh

run_layer "L1: info-hub runbook ⇄ selfdefctl verb binding (operator remediation)" \
    bash scripts/test/L1-runbook-cli-verb-binding.sh

run_layer "L1: CLI test-helper dedup (module_*.rs consume common/mod.rs; F-2026-060)" \
    bash scripts/test/L1-test-helper-dedup-coherence.sh

run_layer "L1: coherence harness self-coverage (every L1-*.sh is wired here)" \
    bash scripts/test/L1-coherence-harness-coverage.sh

run_layer "L1: shellcheck scan (parse errors / real bugs across all .sh)" \
    bash scripts/test/L1-shellcheck-scan.sh

run_layer "L1: ruff (python lint — guardian-core / ux-harness / tests)" \
    bash scripts/test/L1-ruff-python.sh

run_layer "L2: python suites (guardian / adversary / replay / ux-harness)" \
    python3 -m unittest \
        tests.integration.test_guardian_core \
        tests.adversary.test_ms042_mismatch_scenarios \
        tests.replay.test_audit_chain_continuity \
        tests.ux-harness.test_ux_harness_l1

# --- L2 observability pytest suite ------------------------------------
# tests/observability/ is pytest-style (parametrize + bare asserts), which
# `python3 -m unittest` CANNOT collect — so without this layer the whole
# ~190-test alert/dashboard/SHIPPED contract suite runs NOWHERE in CI (it
# was orphaned: present, green-by-assumption, never executed — and real
# drift accumulated unseen). Run it via pytest; self-skip (not fail) when
# pytest isn't installed so the harness still works on a bats-only box.
if python3 -c 'import pytest' 2>/dev/null; then
    # Operator visibility for the cross-repo lockstep suites
    # (tests/observability/*_partner_repo_lockstep.py): they read
    # $SOVEREIGN_OS_REPO_ROOT and SKIP silently when it's unset or points at a
    # missing tree. Report ENFORCED-vs-SKIP up front so a failed/absent partner
    # checkout can't read as a pass — the "false confidence" trap (sovereign-os
    # test.yml documents the same). Tolerant: a SKIP is no regression.
    _lockstep_n="$(grep -rl SOVEREIGN_OS_REPO_ROOT tests/observability --include='*.py' 2>/dev/null | wc -l | tr -d ' ')"
    if [ -n "${SOVEREIGN_OS_REPO_ROOT:-}" ] && [ -d "${SOVEREIGN_OS_REPO_ROOT}/crates" ]; then
        echo "  cross-repo lockstep: partner present → ${_lockstep_n} suite file(s) ENFORCED against ${SOVEREIGN_OS_REPO_ROOT}"
    else
        echo "  cross-repo lockstep: partner unavailable (SOVEREIGN_OS_REPO_ROOT unset/missing) → ${_lockstep_n} suite file(s) will SKIP (no regression)"
    fi
    # Every pytest-style test dir/file NOT covered by the unittest layer
    # above. Keep this in sync with tests/observability/
    # test_no_orphaned_pytest_tests.py, which fails if a new pytest-style
    # test file lands outside this set (so an orphan can't recur).
    run_layer "L2: observability + corpus pytest suites (alerts/dashboard/SHIPPED + rule-corpus)" \
        python3 -m pytest tests/observability/ \
            tests/replay/test_rule_corpus_coverage.py -q
else
    LAYER_NAMES+=("L2: observability pytest")
    LAYER_STATUS+=("SKIP")
    echo "[L2: observability pytest] SKIPPED — pytest not installed"
fi

# --- L2 gates (bats) --------------------------------------------------

if command -v bats >/dev/null 2>&1; then
    for bats_file in packaging/test/L2-*.bats; do
        [ -f "${bats_file}" ] || continue
        run_layer "L2: $(basename "${bats_file}" .bats)" \
            bats "${bats_file}"
    done
else
    LAYER_NAMES+=("L2: bats")
    LAYER_STATUS+=("SKIP")
    echo "[L2: bats] SKIPPED — bats-core not installed"
fi

# --- Cargo unit tests for the three-watchdog trio ---------------------

run_layer "cargo: four-watchdog set unit suites" \
    cargo test --quiet \
        -p selfdef-friction-audit-mirror \
        -p selfdef-friction-audit \
        -p selfdef-perimeter-mirror \
        -p selfdef-perimeter \
        -p selfdef-guardian-mirror \
        -p selfdef-guardian \
        -p selfdef-scheduler-mirror \
        -p selfdef-scheduler \
        -p selfdef-api

# --- Summary ----------------------------------------------------------

echo
echo "════════════════════════════════════════════════════════════════"
echo "Coherence harness summary"
echo "════════════════════════════════════════════════════════════════"
overall_fail=0
for i in "${!LAYER_NAMES[@]}"; do
    name="${LAYER_NAMES[${i}]}"
    status="${LAYER_STATUS[${i}]}"
    printf "  %-6s  %s\n" "${status}" "${name}"
    if [[ "${status}" == "FAIL" ]]; then
        overall_fail=$((overall_fail + 1))
    fi
done

if [[ "${overall_fail}" -gt 0 ]]; then
    echo
    echo "RESULT: ${overall_fail} layer(s) failed."
    echo "Runbook: ~/devops-solutions-information-hub/wiki/runbooks/ux-coherence-failures.md"
    exit 1
fi

echo
echo "RESULT: all layers PASS."
exit 0
