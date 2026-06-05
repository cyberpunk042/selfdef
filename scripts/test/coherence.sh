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

run_layer "L1: Prometheus alert rules (MS027 four-watchdog alerts)" \
    bash scripts/test/L1-prometheus-alerts.sh

run_layer "L1: operator cheatsheet (daily-driver doc coverage)" \
    bash scripts/test/L1-operator-cheatsheet.sh

run_layer "L1: module-system contracts (14 modules cross-wired)" \
    bash scripts/test/L1-module-contracts.sh

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
