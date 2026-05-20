#!/usr/bin/env bash
# L1-cli-surface.sh — MS045 SDD-030 Deliverable 2
#
# Verifies that selfdefctl's CLI surface matches what the SDDs promise.
# Each SDD declares a specific subverb count for its operator-facing
# command; this gate fails if those counts drift.
#
# This is a STATIC check — it invokes `--help` only, so it is safe to
# run anywhere the selfdefctl binary builds. No daemon, no privileges,
# no side effects.
#
# Source: SDD-030 Deliverable 2 / MS045 R-rows
# Run: bash scripts/test/L1-cli-surface.sh
set -euo pipefail

# Locate the binary — prefer release, fall back to debug.
BINARY="${SELFDEFCTL:-}"
if [[ -z "${BINARY}" ]]; then
    if [[ -x ./target/release/selfdefctl ]]; then
        BINARY="./target/release/selfdefctl"
    elif [[ -x ./target/debug/selfdefctl ]]; then
        BINARY="./target/debug/selfdefctl"
    else
        echo "L1-cli-surface FAIL: selfdefctl binary not built. Run 'cargo build -p selfdef-cli' first." >&2
        exit 1
    fi
fi

# Subverb-count gate. Each row: <command> <expected_count> <sdd> <runbook-pointer>.
# Count is taken from `--help` output filtered to lines that look like
# subverb rows (2 leading spaces + lowercase identifier). The 'help'
# row is auto-emitted by clap and is EXCLUDED from the count (it's not
# an SDD-spec'd subverb).
check_subverbs() {
    local command="$1"
    local expected="$2"
    local sdd="$3"
    local got
    got="$("${BINARY}" "${command}" --help 2>&1 \
        | awk '/^Commands:/{flag=1; next} /^$/{flag=0} flag' \
        | grep -cE "^  [a-z]" || true)"
    # Drop the 'help' row from the count if present (clap always emits it).
    local help_present
    help_present="$("${BINARY}" "${command}" --help 2>&1 \
        | grep -cE "^  help " || true)"
    got=$((got - help_present))
    if [[ "${got}" -ne "${expected}" ]]; then
        echo "  FAIL ${command}: expected ${expected} subverbs (${sdd}), got ${got}"
        return 1
    fi
    echo "  PASS ${command}: ${got} subverbs (${sdd})"
}

echo "L1-cli-surface: checking selfdefctl subverb counts (binary: ${BINARY})"

failures=0
check_subverbs "friction-audit"  3 "SDD-027" || failures=$((failures + 1))
check_subverbs "perimeter"       7 "SDD-028" || failures=$((failures + 1))
check_subverbs "guardian"        4 "SDD-029" || failures=$((failures + 1))

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-cli-surface FAIL: ${failures} subverb-count drift(s) detected"
    echo "  See ~/devops-solutions-information-hub/wiki/runbooks/ux-coherence-failures.md for fix procedure."
    exit 1
fi

echo "L1-cli-surface PASS: all subverb counts match SDD-promised baselines"
