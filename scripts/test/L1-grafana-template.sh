#!/usr/bin/env bash
# L1-grafana-template.sh — MS027 + four-watchdog Grafana panel-set gate
#
# Verifies the bundled Grafana dashboard template:
#   1. parses as valid JSON
#   2. has the expected total panel count
#   3. references every SDD-promised four-watchdog metric series
#
# Static check — reads modules/observability/assets/dashboards/selfdef.json.template
# directly; no Grafana/Prometheus instance needed.
#
# Source: MS027 catalog + SDD-027/SDD-028/SDD-029/SDD-031 emission contracts
# Run: bash scripts/test/L1-grafana-template.sh
set -euo pipefail

TEMPLATE="${TEMPLATE:-modules/observability/assets/dashboards/selfdef.json.template}"

if [[ ! -f "${TEMPLATE}" ]]; then
    echo "L1-grafana-template FAIL: ${TEMPLATE} not found" >&2
    exit 1
fi

echo "L1-grafana-template: checking ${TEMPLATE}"

# Gate 1: parses as JSON.
if ! python3 -c "import json; json.load(open('${TEMPLATE}'))" 2>/dev/null; then
    echo "  FAIL JSON parse — re-run with: python3 -c \"import json; json.load(open('${TEMPLATE}'))\""
    exit 1
fi
echo "  PASS JSON parses"

# Gate 2: total panel count >= 17 (7 original + 1 row + 9 four-watchdog).
panel_count="$(python3 -c "import json; print(len(json.load(open('${TEMPLATE}'))['panels']))")"
if [[ "${panel_count}" -lt 17 ]]; then
    echo "  FAIL panel count ${panel_count} < 17 (drift; the 9 four-watchdog panels may have been removed)"
    exit 1
fi
echo "  PASS panel count = ${panel_count} (≥ 17)"

# Gate 3: every four-watchdog metric series referenced by at least one
# panel's expr field. Each row pairs a series with its source SDD.
declare -a SERIES=(
    "selfdef_friction_audit_failing_total|SDD-027"
    "selfdef_friction_audit_overrides_total|SDD-027"
    "selfdef_perimeter_sigkills_total|SDD-028"
    "selfdef_perimeter_extensions_total|SDD-028"
    "selfdef_perimeter_policy_present|SDD-028"
    "selfdef_perimeter_audit_chain_events|SDD-028"
    "selfdef_guardian_failed_responses_total|SDD-029"
    "selfdef_guardian_tetragon_socket_present|SDD-029"
    "selfdef_guardian_audit_chain_events|SDD-029"
    "selfdef_scheduler_backpressured_decisions_total|SDD-031"
    "selfdef_scheduler_audit_chain_events|SDD-031"
)

failures=0
for entry in "${SERIES[@]}"; do
    series="${entry%%|*}"
    sdd="${entry##*|}"
    if grep -q "\"${series}\"" "${TEMPLATE}"; then
        echo "  PASS series ${series} (${sdd})"
    else
        echo "  FAIL series ${series} (${sdd}) — declared by MS027+watchdog catalog but absent"
        failures=$((failures + 1))
    fi
done

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-grafana-template FAIL: ${failures} missing series"
    exit 1
fi

echo "L1-grafana-template PASS: all four-watchdog series + metadata locked"
