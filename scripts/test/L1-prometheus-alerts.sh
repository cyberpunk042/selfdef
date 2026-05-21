#!/usr/bin/env bash
# L1-prometheus-alerts.sh — MS027 four-watchdog Prometheus alert rules gate
#
# Verifies the bundled Prometheus alerting rules template:
#   1. parses as valid YAML
#   2. has the expected total alert count
#   3. references the SDD-promised metric series (consumed from
#      selfdef-api::watchdog_metrics emission)
#   4. each alert has a runbook_url pointing into the info-hub wiki
#
# Static check — reads modules/observability/assets/alerts/selfdef.yml.template
#
# Source: MS027 catalog + SDD-027/028/029/031 emission contracts
# Run: bash scripts/test/L1-prometheus-alerts.sh
set -euo pipefail

ALERTS="${ALERTS:-modules/observability/assets/alerts/selfdef.yml.template}"

if [[ ! -f "${ALERTS}" ]]; then
    echo "L1-prometheus-alerts FAIL: ${ALERTS} not found" >&2
    exit 1
fi

echo "L1-prometheus-alerts: checking ${ALERTS}"

# Gate 1: parses as YAML.
if ! python3 -c "import yaml; yaml.safe_load(open('${ALERTS}'))" 2>/dev/null; then
    echo "  FAIL YAML parse"
    exit 1
fi
echo "  PASS YAML parses"

# Gate 2: alert count >= 9 (one for each documented failure mode).
alert_count="$(python3 -c "import yaml; d=yaml.safe_load(open('${ALERTS}')); print(sum(len(g['rules']) for g in d['groups']))")"
if [[ "${alert_count}" -lt 9 ]]; then
    echo "  FAIL alert count ${alert_count} < 9 (drift; the 4-watchdog alerts may have been removed)"
    exit 1
fi
echo "  PASS alert count = ${alert_count} (≥ 9)"

# Gate 3: every alert references a runbook_url in the info-hub.
missing_runbook="$(python3 -c "
import yaml
d = yaml.safe_load(open('${ALERTS}'))
bad = []
for g in d['groups']:
    for r in g['rules']:
        url = (r.get('annotations') or {}).get('runbook_url', '')
        if 'devops-solutions-information-hub' not in url or 'wiki/runbooks' not in url:
            bad.append(r['alert'])
print(','.join(bad))
")"
if [[ -n "${missing_runbook}" ]]; then
    echo "  FAIL alerts without info-hub runbook_url: ${missing_runbook}"
    exit 1
fi
echo "  PASS all alerts carry info-hub wiki/runbooks/ runbook_url"

# Gate 3b: when the info-hub clone is available locally, verify every
# runbook_url's target file actually exists. Drift catcher — the
# perimeter-chain-broken alert was previously pointing at the wrong
# (existing) runbook; this gate would catch the case where an alert
# points at a non-existent runbook entirely. Skipped cleanly in CI
# where the sister repo isn't checked out.
INFOHUB_RUNBOOKS="${INFOHUB_RUNBOOKS:-${HOME}/devops-solutions-information-hub/wiki/runbooks}"
if [[ -d "${INFOHUB_RUNBOOKS}" ]]; then
    missing_files="$(python3 -c "
import yaml, os
d = yaml.safe_load(open('${ALERTS}'))
bad = []
for g in d['groups']:
    for r in g['rules']:
        url = (r.get('annotations') or {}).get('runbook_url', '')
        # extract basename after wiki/runbooks/
        marker = 'wiki/runbooks/'
        i = url.find(marker)
        if i < 0:
            continue
        fname = url[i + len(marker):]
        path = os.path.join('${INFOHUB_RUNBOOKS}', fname)
        if not os.path.isfile(path):
            bad.append(r['alert'] + ' -> ' + fname)
print('\n'.join(bad))
")"
    if [[ -n "${missing_files}" ]]; then
        echo "  FAIL alerts whose runbook_url target does not exist in info-hub:"
        echo "${missing_files}" | sed 's/^/        /'
        exit 1
    fi
    echo "  PASS all runbook_url targets exist in ${INFOHUB_RUNBOOKS}"
else
    echo "  SKIP runbook-file existence check (${INFOHUB_RUNBOOKS} not present; set INFOHUB_RUNBOOKS to enable)"
fi

# Gate 4: every SDD-promised emission series referenced by ≥ 1 alert expr.
declare -a SERIES=(
    "selfdef_friction_audit_failing_total"
    "selfdef_perimeter_sigkills_total"
    "selfdef_perimeter_policy_present"
    "selfdef_perimeter_audit_chain_events"
    "selfdef_guardian_failed_responses_total"
    "selfdef_guardian_tetragon_socket_present"
    "selfdef_guardian_audit_chain_events"
    "selfdef_scheduler_backpressured_decisions_total"
    "selfdef_scheduler_audit_chain_events"
)

failures=0
for series in "${SERIES[@]}"; do
    if grep -q "${series}" "${ALERTS}"; then
        echo "  PASS series ${series} referenced"
    else
        echo "  FAIL series ${series} not referenced by any alert"
        failures=$((failures + 1))
    fi
done

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-prometheus-alerts FAIL: ${failures} missing series"
    exit 1
fi

# Gate 5: modules/observability/install/apply.sh wires the alert
# template into the deployment path. Drift catcher.
APPLY_SH="${APPLY_SH:-modules/observability/install/apply.sh}"
if [[ -f "${APPLY_SH}" ]]; then
    if grep -q "alerts/selfdef.yml.template" "${APPLY_SH}"; then
        echo "  PASS apply.sh references the alerts template"
    else
        echo "  FAIL apply.sh does not reference alerts/selfdef.yml.template"
        exit 1
    fi
    if grep -q "ALERTS_DST" "${APPLY_SH}"; then
        echo "  PASS apply.sh has ALERTS_DST destination variable"
    else
        echo "  FAIL apply.sh missing ALERTS_DST variable"
        exit 1
    fi
fi

echo "L1-prometheus-alerts PASS: all four-watchdog series + runbook_urls + apply.sh wiring locked"
