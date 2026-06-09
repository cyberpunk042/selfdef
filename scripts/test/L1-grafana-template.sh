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

# Gate 2: total panel count >= 30 (additive lock per operator's
# "adding ≠ discarding" rule — each canonically-shipped panel RATCHETS
# the floor forward so a regression that silently drops a panel lands red).
#
# Composition (empirically verified 2026-06-06 via JSON enumeration):
#   - 3 row dividers (section headers)
#   - 18 stat panels (single-value health: each 4-watchdog gauge + each
#     module shipped/active count + the M060 mirror-export indicators
#     + the SDD-062 watchdog-alert-finding stat)
#   - 1 table panel (decision-finding stream)
#   - 8 timeseries panels (per-watchdog time-windowed trends + M060
#     mirror-export rate + the watchdog-alert-finding-by-rule trend)
#   = 30 total.
# Earlier floors: 17 (original) → 20 (MS006 modules added) → 30
# (M060 + SDD-062 + IPS-authority surfaces added).
panel_count="$(python3 -c "import json; print(len(json.load(open('${TEMPLATE}'))['panels']))")"
if [[ "${panel_count}" -lt 30 ]]; then
    echo "  FAIL panel count ${panel_count} < 30 (drift; 3 rows + 18 stat + 1 table + 8 timeseries expected)"
    exit 1
fi
echo "  PASS panel count = ${panel_count} (≥ 30)"

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
    "selfdef_modules_shipped_total|MS006"
    "selfdef_modules_active_total|MS006"
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

# Gate 4: every metric a panel's PromQL expr QUERIES must actually be
# emitted by a producer. Gate 3 only checks the reverse (named series HAVE
# a panel); it does not catch a panel querying a typo'd / renamed / removed
# metric, which renders a silently-EMPTY panel — no data, no signal, the
# observability failure the cockpit exists to prevent. Mirrors the alert
# dead-metric gate (L1-prometheus-alerts Gate 4b). Metrics are pulled from
# panel `targets[].expr` only (titles/descriptions may name series in prose).
expr_metrics="$(python3 -c "
import json, re
d = json.load(open('${TEMPLATE}'))
mets = set()
def walk(panels):
    for p in panels:
        for t in (p.get('targets') or []):
            mets.update(re.findall(r'selfdef_[a-z_0-9]+', t.get('expr', '')))
        if p.get('panels'):
            walk(p['panels'])
walk(d.get('panels') or [])
print('\n'.join(sorted(mets)))
")"
if [[ -z "${expr_metrics}" ]]; then
    echo "  FAIL no selfdef_* metrics found in any panel expr (template shape changed?)"
    exit 1
fi
dead=0
for m in ${expr_metrics}; do
    hits="$(grep -rlE "${m}" crates packaging/scripts modules 2>/dev/null \
        --include=*.rs --include=*.sh --include=*.py \
        | grep -vE '/tests?/|\.json\.template' | head -1)"
    if [[ -n "${hits}" ]]; then
        echo "  PASS panel metric ${m} is emitted by a producer"
    else
        echo "  FAIL panel metric ${m} is NOT emitted anywhere — silently-empty panel"
        dead=$((dead + 1))
    fi
done
if [[ "${dead}" -gt 0 ]]; then
    echo "L1-grafana-template FAIL: ${dead} panel(s) query an unemitted (dead) metric"
    exit 1
fi

echo "L1-grafana-template PASS: all four-watchdog series + metadata + panel-metric emission locked"
