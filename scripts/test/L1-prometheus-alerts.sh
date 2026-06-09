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

# Gate 2: alert count >= 15 (additive lock; per operator's "adding ≠ discarding"
# rule each canonically-shipped alert RATCHETS the floor forward — the lock
# guards against silent removal of any alert in the set):
#   -  9 four-watchdog set + 2 MS011 Z-10 storage = 11 (the original lock)
#   -  3 M060 mirror-export (SelfdefM060Publish{Failing,Stale,Wedged}, 2026-06-05)
#   -  1 detection-watchdog finding (SelfdefWatchdogAlertFinding, SDD-062)
#   = 15 total.
# Bumping the floor catches any future regression that drops one of these
# 15 alerts. New alerts ratchet the floor further (always ADD, never DROP).
alert_count="$(python3 -c "import yaml; d=yaml.safe_load(open('${ALERTS}')); print(sum(len(g['rules']) for g in d['groups']))")"
if [[ "${alert_count}" -lt 15 ]]; then
    echo "  FAIL alert count ${alert_count} < 15 (drift; expected 11 four-watchdog/storage + 3 M060 + 1 detection-watchdog = 15)"
    exit 1
fi
echo "  PASS alert count = ${alert_count} (≥ 15)"

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
    # Path-specific advisory list — known-pending info-hub merges that
    # should NOT break CI but should surface on every commit so the
    # operator sees the cross-repo state divergence each run. Mirrors the
    # advisory-pattern in L1-info-hub-doc-references.sh (the same
    # dispensation: info-hub work goes through PR review per operator's
    # standing direction; selfdef's alert URLs can land on main pointing
    # at runbooks staged in an unmerged PR without that being a defect
    # in either repo in isolation).
    #
    # Format: <runbook-filename>|<reason>
    ADVISORY_RUNBOOKS=(
        "m060-mirror-export-publish-anomalies.md|on info-hub PR #17 (branch claude/recover-projects-b0oT6) awaiting operator merge"
        "selfdef-watchdog-alert-finding.md|on info-hub PR #17 (branch claude/recover-projects-b0oT6) awaiting operator merge"
    )
    eval_result="$(python3 -c "
import yaml, os
d = yaml.safe_load(open('${ALERTS}'))
advisory_set = {
$(for row in "${ADVISORY_RUNBOOKS[@]}"; do
    IFS='|' read -r p reason <<< "${row}"
    printf '    %s: %s,\n' "${p@Q}" "${reason@Q}"
done)
}
hard_bad = []
advisory_bad = []
for g in d['groups']:
    for r in g['rules']:
        url = (r.get('annotations') or {}).get('runbook_url', '')
        marker = 'wiki/runbooks/'
        i = url.find(marker)
        if i < 0:
            continue
        fname = url[i + len(marker):]
        path = os.path.join('${INFOHUB_RUNBOOKS}', fname)
        if os.path.isfile(path):
            continue
        if fname in advisory_set:
            advisory_bad.append('{} -> {} (advisory: {})'.format(r['alert'], fname, advisory_set[fname]))
        else:
            hard_bad.append('{} -> {}'.format(r['alert'], fname))
print('HARD:' + '|'.join(hard_bad))
print('ADV:' + '|'.join(advisory_bad))
")"
    hard_missing="$(printf '%s' "${eval_result}" | awk -F'HARD:' '/^HARD:/{print $2}')"
    adv_missing="$(printf '%s' "${eval_result}" | awk -F'ADV:' '/^ADV:/{print $2}')"
    if [[ -n "${hard_missing}" ]]; then
        echo "  FAIL alerts whose runbook_url target does not exist in info-hub:"
        printf '%s\n' "${hard_missing}" | tr '|' '\n' | sed 's/^/        /'
        exit 1
    fi
    if [[ -n "${adv_missing}" ]]; then
        echo "  ADVISORY runbook(s) pending info-hub merge (does NOT fail CI):"
        printf '%s\n' "${adv_missing}" | tr '|' '\n' | sed 's/^/        /'
    fi
    echo "  PASS all runbook_url targets exist OR are operator-advised pending (${INFOHUB_RUNBOOKS})"
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

# Gate 4b: every metric an alert EXPR fires on must actually be emitted
# somewhere in the producer (a crate or a textfile-emitter script). Gate 4
# only checks the reverse (the 9 named series HAVE an alert); it does not
# catch an alert that references a typo'd / renamed / removed metric, which
# would be a silently-DEAD alert (never fires, no signal). This is the
# verification gate for "every alert fires on a real series". Metrics are
# pulled from `expr:` lines only (description prose mentions series like
# selfdef_events_* that aren't alert conditions).
expr_metrics="$(grep -E '^\s*expr:' "${ALERTS}" | grep -oE 'selfdef_[a-z_0-9]+' | sort -u)"
if [[ -z "${expr_metrics}" ]]; then
    echo "  FAIL no selfdef_* metrics found in any alert expr (template shape changed?)"
    exit 1
fi
dead=0
for m in ${expr_metrics}; do
    # List producer files (crate sources + textfile-emitter scripts + module
    # assets) that emit this series, excluding test files and the alerts
    # template itself (the consumer).
    hits="$(grep -rlE "${m}" crates packaging/scripts modules 2>/dev/null \
        --include=*.rs --include=*.sh --include=*.py \
        | grep -vE '/tests?/|selfdef\.yml\.template' | head -1)"
    if [[ -n "${hits}" ]]; then
        echo "  PASS expr metric ${m} is emitted by a producer (${hits})"
    else
        echo "  FAIL expr metric ${m} is NOT emitted anywhere — silently-dead alert"
        dead=$((dead + 1))
    fi
done
if [[ "${dead}" -gt 0 ]]; then
    echo "L1-prometheus-alerts FAIL: ${dead} alert(s) reference an unemitted (dead) metric"
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
