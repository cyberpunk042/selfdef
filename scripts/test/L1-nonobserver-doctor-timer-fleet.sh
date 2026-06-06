#!/usr/bin/env bash
# L1-nonobserver-doctor-timer-fleet.sh — doctor timer fleet contract gate.
#
# 4 doctor timers ship in packaging/systemd/selfdef-*-doctor.timer
# (cli-mirror, doctor, four-watchdog, m060). Each pairs to its
# matching .service and fires periodically. Contract:
#
#   1. [Timer] section present
#   2. OnBootSec= set (timer fires on boot, not only after first
#      systemctl start)
#   3. OnUnitActiveSec= set (recurring cadence — value uniformity
#      NOT asserted because doctor cadences legitimately vary:
#      selfdef-doctor=1h, others=60s)
#   4. Unit=<sibling>.service (each timer pairs to a real .service)
#   5. WantedBy=timers.target
#   6. Persistent=true REQUIRED IFF OnUnitActiveSec >= 5min
#      (matching the operator-stated pattern from L1-systemd-hardening
#      for selfdef-scheduler-textfile: "Persistent semantically useless
#      for 60s cadence because next fire is at most 60s away" — only
#      sub-5min cadences are exempt from the Persistent requirement)
#
# Disjoint scope from L1-textfile-observer-timer-fleet.sh (29 timers).
#
# Run with: bash scripts/test/L1-nonobserver-doctor-timer-fleet.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SYSTEMD_DIR="${REPO_ROOT}/packaging/systemd"

failures=0
units_checked=0

# Convert systemd time literal (1h / 1min / 60s / 60sec etc) to seconds.
# Output: integer seconds, or empty on parse failure.
time_to_seconds() {
    local v="$1"
    local num="${v%%[a-z]*}"
    local unit="${v##*[0-9]}"
    case "${unit}" in
        s|sec) echo "${num}" ;;
        min|m) echo "$(( num * 60 ))" ;;
        h)     echo "$(( num * 3600 ))" ;;
        d)     echo "$(( num * 86400 ))" ;;
        "")    echo "${num}" ;; # bare integer = seconds
        *)     echo "" ;;
    esac
}

# Walk doctor timers (non-observer fleet — observers covered by
# L1-textfile-observer-timer-fleet.sh).
shopt -s nullglob
timers=("${SYSTEMD_DIR}"/selfdef-*-doctor.timer "${SYSTEMD_DIR}"/selfdef-doctor.timer)
shopt -u nullglob

# Deduplicate (the second glob may overlap with the first)
declare -A seen
unique_timers=()
for t in "${timers[@]}"; do
    if [[ -z "${seen[${t}]:-}" ]]; then
        seen["${t}"]=1
        unique_timers+=("${t}")
    fi
done

if [[ "${#unique_timers[@]}" -eq 0 ]]; then
    echo "L1-nonobserver-doctor-timer-fleet PASS: no doctor timers found at ${SYSTEMD_DIR}/selfdef-*-doctor.timer"
    exit 0
fi

echo "▶ Walking ${#unique_timers[@]} doctor timers for contract clauses..."

for timer in "${unique_timers[@]}"; do
    name=$(basename "${timer}")
    stem=$(basename "${timer}" .timer)
    units_checked=$((units_checked + 1))
    sibling_service="${SYSTEMD_DIR}/${stem}.service"
    unit_failures=0

    # Gate 1: [Timer] section
    grep -qE '^\[Timer\]' "${timer}" || {
        echo "  FAIL ${name}: missing [Timer] section"
        unit_failures=$((unit_failures + 1))
    }

    # Gate 2: OnBootSec set
    grep -qE '^OnBootSec=[0-9]+(s|sec|min|m|h|d)?' "${timer}" || {
        echo "  FAIL ${name}: OnBootSec= not set (timer won't fire on boot)"
        unit_failures=$((unit_failures + 1))
    }

    # Gate 3: OnUnitActiveSec set, capture value for Persistent decision
    active_line=$(grep -E '^OnUnitActiveSec=[0-9]+(s|sec|min|m|h|d)?' "${timer}" | head -1 || true)
    if [[ -z "${active_line}" ]]; then
        echo "  FAIL ${name}: OnUnitActiveSec= not set (no recurring cadence)"
        unit_failures=$((unit_failures + 1))
        active_seconds=""
    else
        active_value="${active_line#OnUnitActiveSec=}"
        active_seconds=$(time_to_seconds "${active_value}")
    fi

    # Gate 4: Unit pairs to its sibling .service
    if ! grep -qE "^Unit=${stem}\\.service" "${timer}"; then
        echo "  FAIL ${name}: Unit= doesn't pair to ${stem}.service"
        unit_failures=$((unit_failures + 1))
    fi
    # And: that .service must actually exist
    if [[ ! -f "${sibling_service}" ]]; then
        echo "  FAIL ${name}: paired service ${stem}.service doesn't exist (timer fires nothing)"
        unit_failures=$((unit_failures + 1))
    fi

    # Gate 5: WantedBy=timers.target
    grep -qE '^WantedBy=timers\.target' "${timer}" || {
        echo "  FAIL ${name}: WantedBy != timers.target"
        unit_failures=$((unit_failures + 1))
    }

    # Gate 6: Persistent=true REQUIRED iff cadence >= 5min (300s).
    # 60s-cadence timers explicitly don't need Persistent per the
    # operator-stated pattern (scheduler-textfile precedent).
    if [[ -n "${active_seconds}" && "${active_seconds}" -ge 300 ]]; then
        if ! grep -qE '^Persistent=true' "${timer}"; then
            echo "  FAIL ${name}: OnUnitActiveSec=${active_value} (>= 5min) requires Persistent=true (silent drop of missed runs)"
            unit_failures=$((unit_failures + 1))
        fi
    fi

    if [[ "${unit_failures}" -eq 0 ]]; then
        echo "  PASS ${name}: cadence ${active_value:-?} — all 5 contract clauses (+Persistent gate) present"
    fi
    failures=$((failures + unit_failures))
done

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-nonobserver-doctor-timer-fleet FAIL: ${failures} contract violation(s) across ${units_checked} timer(s)"
    exit 1
fi

echo "L1-nonobserver-doctor-timer-fleet PASS: ${units_checked} doctor timers — all contract clauses (cadence-aware Persistent gate) coherent"
