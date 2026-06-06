#!/usr/bin/env bash
# L1-nonobserver-service-hardening-fleet.sh — generalized R171
# hardening gate for the non-observer selfdef systemd service fleet.
#
# L1-systemd-hardening.sh pins 4 daemon-layer units explicitly
# (guardian-core, ux-harness, scheduler-textfile, scheduler). The
# non-observer fleet has 8 more daemon-layer services that follow
# the same R171 baseline (per their own header comments — "system-
# analyze security recommends these for any system-level oneshot
# enforcer" / similar). Per-unit explicit pinning was the right
# call for the 4 named units (each has distinct semantic
# distinguishers — Ring 0 vs not, network vs not, etc.); a
# fleet-level gate is the right call for the broader cluster
# whose hardening posture is uniform.
#
# This gate walks the non-textfile-observer .service files and
# asserts the 9 R171 baseline clauses present on each. EXEMPT
# mechanism for any unit that legitimately can't carry a clause.
#
# Scope: packaging/systemd/selfdef-*.service AND
# packaging/systemd/sovereign-guard.service (the latter is the
# friction-audit boot-enforcer; ships in the same packaging
# bundle).
#
# Excluded: the 29 *-textfile.service observers (handled by
# L1-textfile-observer-hardening.sh — disjoint scope).
#
# Run with: bash scripts/test/L1-nonobserver-service-hardening-fleet.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SYSTEMD_DIR="${REPO_ROOT}/packaging/systemd"

# 9 R171 baseline clauses every daemon-layer service MUST carry.
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

# EXEMPT mechanism — registered exemptions for units that legitimately
# can't carry a clause. Format: <unit-basename>|<clause-key>.
# Currently empty; the gate's job is to surface real exemption
# requests back to the operator if needed.
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

# Walk non-observer .service files. The textfile observers are
# L1-textfile-observer-hardening.sh's scope; the daemon-layer-explicit
# 4 are L1-systemd-hardening.sh's scope but we re-walk them here
# anyway — the fleet gate's invariant should hold uniformly.
shopt -s nullglob
candidates=()
for f in "${SYSTEMD_DIR}"/selfdef-*.service "${SYSTEMD_DIR}"/selfdefd.service "${SYSTEMD_DIR}"/sovereign-guard.service; do
    [[ -f "${f}" ]] || continue
    name=$(basename "${f}")
    # Skip the textfile-observer fleet (disjoint scope)
    if [[ "${name}" == *-textfile.service ]]; then
        continue
    fi
    candidates+=("${f}")
done
shopt -u nullglob

if [[ "${#candidates[@]}" -eq 0 ]]; then
    echo "L1-nonobserver-service-hardening-fleet PASS: no non-observer services found"
    exit 0
fi

echo "▶ Walking ${#candidates[@]} non-observer service files for R171 baseline..."

for unit in "${candidates[@]}"; do
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
            : # silent PASS — rollup at end
        else
            echo "  FAIL ${unit_name}: ${clause_key} (${description}) missing"
            failures=$((failures + 1))
            unit_failures=$((unit_failures + 1))
        fi
    done
    if [[ "${unit_failures}" -eq 0 ]]; then
        echo "  PASS ${unit_name}: all 9 R171 baseline clauses present"
    fi
done

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-nonobserver-service-hardening-fleet FAIL: ${failures} clause violation(s) across ${units_checked} service(s) (${total_assertions} total assertions)"
    exit 1
fi

echo "L1-nonobserver-service-hardening-fleet PASS: ${units_checked} services × 9 R171 baseline clauses = ${total_assertions} assertions all present"
