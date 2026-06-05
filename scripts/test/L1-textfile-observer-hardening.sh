#!/usr/bin/env bash
# L1-textfile-observer-hardening.sh — generalized R171 hardening gate
# for the selfdef textfile-observer fleet.
#
# packaging/systemd/selfdef-*-textfile.service is the canonical observer
# pattern (29 units as of this commit). Each runs a one-shot script
# every 60s to emit Prometheus textfile gauges for one IPS surface
# (apparmor profile-enforcement / auth events / blockset / capability
# drops / etc). The bridge-l2 sample header verbatim documents the
# contract: "same R171 hardening posture + atomic-write convention".
#
# None of those 29 units was pinned by the existing L1-systemd-
# hardening.sh (which targets the 4 daemon-layer units). A silent
# regression of any clause on any observer widens that observer's host
# surface; with 29 observers the probability is low per-unit but high
# aggregate.
#
# This gate walks selfdef-*-textfile.service and asserts the 9 common
# R171 clauses present on every observer. Distinguishes from the
# daemon-layer gate by NOT asserting Description / ExecStart / User
# (those vary per observer); it ONLY asserts the hardening clauses that
# are observer-invariant.
#
# Run with: bash scripts/test/L1-textfile-observer-hardening.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SYSTEMD_DIR="${REPO_ROOT}/packaging/systemd"

# The 9 R171 clauses every textfile observer MUST carry. Each clause
# bounds a specific escape pattern; silent regression widens the
# observer's host surface (and aggregated across 29 units, the blast
# radius is large).
declare -a R171_CLAUSES=(
    "NoNewPrivileges=true|no setuid escape"
    "ProtectSystem=strict|full root read-only"
    "ProtectKernelTunables=true|no /proc/sys writes"
    "ProtectControlGroups=true|no cgroup escape"
    "LockPersonality=true|no personality(2) pivot"
    "RestrictNamespaces=true|no namespace pivot"
    "RestrictRealtime=true|no SCHED_FIFO escape"
    "RestrictSUIDSGID=true|no setuid file creation"
    "SystemCallArchitectures=native|no 32-bit syscall pivot"
)

# Per-unit exemption list (observers that legitimately don't carry one
# of the R171 clauses — e.g. they need a feature the clause restricts).
# Format: <unit-basename>|<clause-key-without-=true>
# Currently empty — the L1 gate's job is to surface real exemptions
# back to the operator if any get added. Adding without operator
# approval would be unilateral scope-overstep.
declare -a EXEMPT=()

is_exempt() {
    local unit="$1" clause_key="$2"
    for row in "${EXEMPT[@]}"; do
        IFS='|' read -r ex_unit ex_clause <<< "${row}"
        if [[ "${ex_unit}" == "${unit}" && "${ex_clause}" == "${clause_key}" ]]; then
            return 0
        fi
    done
    return 1
}

failures=0
units_checked=0
total_assertions=0

# Collect the observer fleet. Selfdef-*-textfile.service is the
# canonical pattern; the four daemon-layer units I covered separately
# in L1-systemd-hardening.sh are excluded here so each gate has
# disjoint scope.
shopt -s nullglob
observers=("${SYSTEMD_DIR}"/selfdef-*-textfile.service)
shopt -u nullglob

if [[ "${#observers[@]}" -eq 0 ]]; then
    echo "L1-textfile-observer-hardening PASS: no observers found at ${SYSTEMD_DIR}/selfdef-*-textfile.service"
    exit 0
fi

echo "▶ Walking ${#observers[@]} textfile observer .service files for R171 hardening clauses..."

for unit in "${observers[@]}"; do
    unit_name=$(basename "${unit}")
    units_checked=$((units_checked + 1))
    unit_failures=0
    for clause_row in "${R171_CLAUSES[@]}"; do
        IFS='|' read -r clause description <<< "${clause_row}"
        clause_key=$(echo "${clause}" | cut -d= -f1)
        total_assertions=$((total_assertions + 1))
        if is_exempt "${unit_name}" "${clause_key}"; then
            echo "  EXEMPT ${unit_name}: ${clause_key} (registered exemption)"
            continue
        fi
        if grep -qE "^${clause}\$" "${unit}"; then
            : # silent PASS to keep output bounded; per-unit summary follows
        else
            echo "  FAIL ${unit_name}: ${clause_key} (${description}) missing"
            failures=$((failures + 1))
            unit_failures=$((unit_failures + 1))
        fi
    done
    if [[ "${unit_failures}" -eq 0 ]]; then
        echo "  PASS ${unit_name}: all 9 R171 clauses present"
    fi
done

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-textfile-observer-hardening FAIL: ${failures} clause violation(s) across ${units_checked} observer(s) (${total_assertions} total assertions)"
    exit 1
fi

echo "L1-textfile-observer-hardening PASS: ${units_checked} observers × 9 R171 clauses = ${total_assertions} assertions all present"
