#!/usr/bin/env bash
# L1-textfile-observer-timer-fleet.sh — contract gate for the 29
# selfdef-*-textfile.timer fleet.
#
# Companion to L1-textfile-observer-hardening.sh: that one pins the
# .service hardening clauses; this one pins the .timer cadence
# invariants. Five contracts every timer must satisfy:
#
#   1. [Timer] section present
#   2. OnBootSec set (each observer fires on boot, not only after
#      first systemctl start)
#   3. OnUnitActiveSec=60s (the canonical observer cadence)
#   4. Unit=<sibling>.service (each timer pairs to its matching service)
#   5. WantedBy=timers.target
#
# Additionally: every observer must have BOTH a .service AND a .timer
# (a service without a timer never fires; a timer without a service
# fires nothing).
#
# AND: OnBootSec values across the fleet must be UNIQUE — the
# observer family staggers boot-time activations to prevent
# thundering-herd against /sys + /proc + nvidia-smi on every fresh
# host boot (operator-observed pattern: each sibling carries a
# distinct OnBootSec like "19th sibling. OnBootSec=570s — distinct
# from the prior 18 siblings").
#
# Run with: bash scripts/test/L1-textfile-observer-timer-fleet.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SYSTEMD_DIR="${REPO_ROOT}/packaging/systemd"

failures=0
units_checked=0

# --- Gate 1: service ↔ timer pairing ---
echo "▶ Gate 1: every selfdef-*-textfile observer has both .service and .timer"
shopt -s nullglob
services=("${SYSTEMD_DIR}"/selfdef-*-textfile.service)
timers=("${SYSTEMD_DIR}"/selfdef-*-textfile.timer)
shopt -u nullglob

declare -A service_set
declare -A timer_set
for s in "${services[@]}"; do
    stem=$(basename "${s}" .service)
    service_set["${stem}"]=1
done
for t in "${timers[@]}"; do
    stem=$(basename "${t}" .timer)
    timer_set["${stem}"]=1
done

for stem in "${!service_set[@]}"; do
    if [[ -z "${timer_set[${stem}]:-}" ]]; then
        echo "  FAIL ${stem}.service exists but ${stem}.timer is missing — service never fires"
        failures=$((failures + 1))
    fi
done
for stem in "${!timer_set[@]}"; do
    if [[ -z "${service_set[${stem}]:-}" ]]; then
        echo "  FAIL ${stem}.timer exists but ${stem}.service is missing — timer fires nothing"
        failures=$((failures + 1))
    fi
done

echo "  PASS ${#service_set[@]} services ↔ ${#timer_set[@]} timers paired"

# --- Gate 2: per-timer contract assertions ---
echo "▶ Gate 2: each timer carries the 5 cadence contract clauses"

declare -A onboot_to_unit
for timer in "${timers[@]}"; do
    name=$(basename "${timer}")
    stem=$(basename "${timer}" .timer)
    units_checked=$((units_checked + 1))
    unit_failures=0

    grep -qE '^\[Timer\]' "${timer}" || {
        echo "  FAIL ${name}: missing [Timer] section"
        unit_failures=$((unit_failures + 1))
    }

    # OnBootSec must be set
    onboot_line=$(grep -E '^OnBootSec=[0-9]+(s|sec|min|m|h)?' "${timer}" || true)
    if [[ -z "${onboot_line}" ]]; then
        echo "  FAIL ${name}: OnBootSec= not set (observer won't fire on boot)"
        unit_failures=$((unit_failures + 1))
    else
        # Record OnBootSec for cross-fleet uniqueness check (Gate 3)
        onboot_value=$(echo "${onboot_line}" | cut -d= -f2-)
        if [[ -n "${onboot_to_unit[${onboot_value}]:-}" ]]; then
            echo "  FAIL ${name}: OnBootSec=${onboot_value} collides with ${onboot_to_unit[${onboot_value}]} (thundering-herd at boot)"
            unit_failures=$((unit_failures + 1))
            failures=$((failures + 1))
        else
            onboot_to_unit["${onboot_value}"]="${name}"
        fi
    fi

    grep -qE '^OnUnitActiveSec=60s' "${timer}" || {
        echo "  FAIL ${name}: OnUnitActiveSec != 60s (breaks canonical observer cadence)"
        unit_failures=$((unit_failures + 1))
    }

    grep -qE "^Unit=${stem}\\.service" "${timer}" || {
        echo "  FAIL ${name}: Unit= doesn't pair to ${stem}.service"
        unit_failures=$((unit_failures + 1))
    }

    grep -qE '^WantedBy=timers\.target' "${timer}" || {
        echo "  FAIL ${name}: WantedBy != timers.target"
        unit_failures=$((unit_failures + 1))
    }

    if [[ "${unit_failures}" -eq 0 ]]; then
        : # silent PASS, fleet rollup at the end
    else
        failures=$((failures + unit_failures))
    fi
done

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-textfile-observer-timer-fleet FAIL: ${failures} contract violation(s) across ${units_checked} timer(s)"
    exit 1
fi

echo "L1-textfile-observer-timer-fleet PASS: ${units_checked} timers — pairing + 5 cadence clauses + OnBootSec uniqueness all coherent"
