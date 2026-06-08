#!/usr/bin/env bash
# L1-coherence-harness-coverage.sh — coherence self-coverage gate
#
# coherence.sh runs its L1 gates from an EXPLICIT hardcoded list (one
# `run_layer ... bash scripts/test/L1-*.sh` line per gate), whereas the
# L2 bats suites are auto-discovered via glob. The hardcoded L1 list has
# a silent-drift failure mode: an author adds a new scripts/test/L1-*.sh
# gate but forgets to wire it into coherence.sh. The gate then exists,
# looks like coverage, and NEVER RUNS — the §1g minimization: a coverage
# surface the operator built that silently does nothing.
#
# This gate freezes coherence ⇄ L1-suite completeness in both directions:
#   1. Every scripts/test/L1-*.sh on disk is referenced in coherence.sh
#      (no orphan / never-run gate).
#   2. Every L1-*.sh that coherence.sh references actually exists on disk
#      (no dangling run_layer line).
#
# Run: bash scripts/test/L1-coherence-harness-coverage.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_ROOT}" || { echo "cd ${REPO_ROOT} failed" >&2; exit 2; }

COHERENCE="scripts/test/coherence.sh"
TEST_DIR="scripts/test"

if [[ ! -f "${COHERENCE}" ]]; then
    echo "L1-coherence-harness-coverage FAIL: ${COHERENCE} not found" >&2
    exit 1
fi

failures=0

# L1 suites present on disk.
mapfile -t on_disk < <(
    find "${TEST_DIR}" -maxdepth 1 -name 'L1-*.sh' -printf '%f\n' | sort -u
)
# L1 suites referenced by coherence.sh.
mapfile -t referenced < <(
    grep -oE 'L1-[a-z0-9-]+\.sh' "${COHERENCE}" | sort -u
)

ref_set=" ${referenced[*]} "

# Gate 1: every on-disk L1 suite is wired into coherence.
for f in "${on_disk[@]}"; do
    if [[ "${ref_set}" != *" ${f} "* ]]; then
        echo "  FAIL ${f}: exists in ${TEST_DIR}/ but is NOT run by ${COHERENCE} (orphan gate — silently never runs). Add a run_layer line."
        failures=$((failures + 1))
    fi
done

# Gate 2: every coherence-referenced L1 suite exists on disk.
for f in "${referenced[@]}"; do
    if [[ ! -f "${TEST_DIR}/${f}" ]]; then
        echo "  FAIL ${f}: referenced by ${COHERENCE} but does not exist (dangling run_layer line). Fix the path or remove the line."
        failures=$((failures + 1))
    fi
done

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-coherence-harness-coverage FAIL: ${failures} coverage gap(s)"
    exit 1
fi

echo "L1-coherence-harness-coverage PASS: ${#on_disk[@]} L1 suites; coherence.sh runs every one + references no missing suite"
