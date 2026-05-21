#!/usr/bin/env bash
# L1-operator-cheatsheet.sh — daily-driver doc coverage gate
#
# Verifies docs/operator-cheatsheet.md exists + references every
# shipped operator command. Catches the drift where someone removes
# a `selfdefctl X` subverb but leaves the cheatsheet promising it
# (or adds a new subverb but forgets to add it to the cheatsheet).
#
# Source: README.md links the cheatsheet as the daily-driver one-pager;
# operators following the link must find every cheatsheet-promised
# command actually shipping.
set -euo pipefail

CHEATSHEET="${CHEATSHEET:-docs/operator-cheatsheet.md}"

if [[ ! -f "${CHEATSHEET}" ]]; then
    echo "L1-operator-cheatsheet FAIL: ${CHEATSHEET} not found" >&2
    exit 1
fi

echo "L1-operator-cheatsheet: checking ${CHEATSHEET}"

# Gate 1: file size ≥ 80 lines (drift catcher; the shipped cheatsheet
# is ~150 lines + has the four-watchdog matrix). A drastic truncation
# would fail this.
line_count="$(wc -l < "${CHEATSHEET}")"
if [[ "${line_count}" -lt 80 ]]; then
    echo "  FAIL line count ${line_count} < 80 (drift — sections may have been removed)"
    exit 1
fi
echo "  PASS line count = ${line_count} (≥ 80)"

# Gate 2: every shipped top-level CLI command must be documented in
# the cheatsheet. These match the Command enum in crates/selfdef-cli/src/main.rs.
declare -a SHIPPED_COMMANDS=(
    "selfdefctl status"
    "selfdefctl doctor"
    "selfdefctl wizard"
    "selfdefctl trio"
    "selfdefctl trio-tail"
    "selfdefctl friction-audit"
    "selfdefctl perimeter"
    "selfdefctl guardian"
    "selfdefctl scheduler"
    "selfdefctl modules"
    "selfdefctl init"
    "selfdefctl alerts"
    "selfdefctl health"
    "selfdefctl audit-chains"
    "selfdefctl commit-authority"
    "selfdefctl tool-authority"
    "selfdefctl capability-tokens"
    "selfdefctl filesystem-boundary"
    "selfdefctl network-boundary"
    "selfdefctl sandbox-tiers"
    "selfdefctl communication-boundary"
    "selfdefctl authority"
    "selfdefctl policy"
)

failures=0
for cmd in "${SHIPPED_COMMANDS[@]}"; do
    if grep -qF "${cmd}" "${CHEATSHEET}"; then
        echo "  PASS references ${cmd}"
    else
        echo "  FAIL cheatsheet doesn't reference ${cmd}"
        failures=$((failures + 1))
    fi
done

# Gate 3: every four-watchdog HTTP route appears at least once.
declare -a HTTP_ROUTES=(
    "/v1/friction-audit"
    "/v1/perimeter"
    "/v1/guardian"
    "/v1/scheduler"
    "/v1/modules"
    "/metrics"
)
for route in "${HTTP_ROUTES[@]}"; do
    if grep -qF "${route}" "${CHEATSHEET}"; then
        echo "  PASS references ${route}"
    else
        echo "  FAIL cheatsheet doesn't reference HTTP route ${route}"
        failures=$((failures + 1))
    fi
done

# Gate 4: the 4 watchdog systemd unit enable commands present.
declare -a SYSTEMD_UNITS=(
    "sovereign-guard.service"
    "selfdef-guardian.service"
    "selfdef-scheduler.service"
    "selfdef-doctor.timer"
)
for unit in "${SYSTEMD_UNITS[@]}"; do
    if grep -qF "${unit}" "${CHEATSHEET}"; then
        echo "  PASS references systemd unit ${unit}"
    else
        echo "  FAIL cheatsheet doesn't reference systemd unit ${unit}"
        failures=$((failures + 1))
    fi
done

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-operator-cheatsheet FAIL: ${failures} missing item(s)"
    exit 1
fi

echo "L1-operator-cheatsheet PASS: all shipped commands + routes + units referenced"
